#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

usage() {
  echo "usage: $0 --template ISO --manifest JSON --manage-origin URL --token-file FILE --output FILE [--published-predecessor-inputs JSON] [--retain-fixture DIRECTORY] [--require-candidate-runtime | --prepublication-candidate] [--induce-preflight-retry]" >&2
  exit 2
}

repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
template=""
manifest=""
manage_origin=""
token_file=""
output=""
published_predecessor_inputs=""
predecessor_identity=""
fixture_dir=""
require_candidate_runtime=false
prepublication_candidate=false
induce_preflight_retry=false
while (($#)); do
  case "$1" in
    --template) template="${2:-}"; shift 2 ;;
    --manifest) manifest="${2:-}"; shift 2 ;;
    --manage-origin) manage_origin="${2:-}"; shift 2 ;;
    --token-file) token_file="${2:-}"; shift 2 ;;
    --predecessor-identity) predecessor_identity="${2:-}"; shift 2 ;;
    --published-predecessor-inputs) published_predecessor_inputs="${2:-}"; shift 2 ;;
    --retain-fixture) fixture_dir="${2:-}"; shift 2 ;;
    --require-candidate-runtime) require_candidate_runtime=true; shift ;;
    --prepublication-candidate) prepublication_candidate=true; shift ;;
    --induce-preflight-retry) induce_preflight_retry=true; shift ;;
    --output) output="${2:-}"; shift 2 ;;
    *) usage ;;
  esac
done
if [[ "$prepublication_candidate" = true ]] \
  && { [[ "$require_candidate_runtime" = true ]] || [[ -n "$published_predecessor_inputs" ]]; }; then
  echo 'error: prepublication deferral applies only to an unpublished candidate' >&2
  exit 1
fi
test -f "$template" && test -f "$manifest" && test -f "$token_file" && test -n "$output"
if [[ -n "$fixture_dir" ]]; then
  [[ "$fixture_dir" = /* ]] && test ! -e "$fixture_dir" && test ! -L "$fixture_dir"
fi
python3 -B "$repository_root/nixos-appliance/qualification/development-scope.py" verify \
  --state-dir "${CYBEX_JAMES_QUALIFICATION_STATE:?set the owned development fixture directory}" \
  --manage-origin "$manage_origin" \
  --bridge "${CYBEX_JAMES_QUALIFICATION_BRIDGE:?set the owned development bridge}"
for command_name in curl git ip jq python3 qemu-system-x86_64 truncate sha256sum openssl ssh-keygen ssh rg; do
  command -v "$command_name" >/dev/null || { echo "error: missing $command_name" >&2; exit 1; }
done
python3 -B "$repository_root/tools/james-release.py" validate-manage-origin \
  --expected-manage-origin "$manage_origin" >/dev/null
test "$(jq -er '.installer_iso_template_v3.manage_origin' "$manifest")" = \
  "$manage_origin"
# New candidates must bind the same exact James source used by this harness.
# Legacy descriptors remain supported only when verifying published predecessors.
source_revision="$(git -C "$repository_root" rev-parse HEAD)"
qualification_kind=candidate
if [[ -n "$published_predecessor_inputs" ]]; then
  echo 'error: use a separately verified NixOS predecessor; Ubuntu is reinstall-only' >&2
  exit 1
fi
if [[ -n "$predecessor_identity" ]]; then
  test "$(jq -er '.schema' "$predecessor_identity")" = cybex.james.nixos-qualification-predecessor.v1
  test "$(jq -er '.manifest_sha256' "$predecessor_identity")" = "$(sha256sum "$manifest" | awk '{print $1}')"
  qualification_kind=predecessor
fi
jq -e --arg source_revision "$source_revision" --argjson predecessor "$([[ -n "$predecessor_identity" ]] && echo true || echo false)" '
  .appliance_release_v1
  | .schema == "cybex.james.appliance-release.v3"
    and (.source_revision == $source_revision or $predecessor == true)
' "$manifest" >/dev/null || {
  echo 'error: qualification requires the exact source-bound V3 candidate' >&2
  exit 1
}
bridge="${CYBEX_JAMES_QUALIFICATION_BRIDGE:?set the isolated qualification bridge}"
hardware="$(python3 -B "$repository_root/nixos-appliance/qualification/development-scope.py" hardware \
  --state-dir "$CYBEX_JAMES_QUALIFICATION_STATE" --manage-origin "$manage_origin" --bridge "$bridge" --role appliance)"
appliance_mac="$(jq -er '.mac' <<<"$hardware")"
appliance_serial="$(jq -er '.serial' <<<"$hardware")"
appliance_uuid="$(jq -er '.uuid' <<<"$hardware")"
management_cidr="${CYBEX_JAMES_QUALIFICATION_MANAGEMENT_CIDR:?set the qualification Management CIDR}"
memory_mib="${CYBEX_JAMES_QUALIFICATION_MEMORY_MIB:-18432}"
[[ "$memory_mib" =~ ^[0-9]+$ ]] && ((memory_mib >= 16384 && memory_mib <= 65536))
token="$(tr -d '\r\n' < "$token_file")"
test -n "$token"
release_version="$(jq -er '.version' "$manifest")"
system_closure_sha256="$(jq -er '.appliance_release_v1.system_closure.sha256' "$manifest")"
has_predecessor="${CYBEX_JAMES_HAS_PREDECESSOR:?set the governed predecessor state}"
case "$has_predecessor" in
  true|false) ;;
  *) echo 'error: invalid governed predecessor state' >&2; exit 1 ;;
esac

if [[ "$induce_preflight_retry" = true ]]; then
  test ! -e "$CYBEX_JAMES_QUALIFICATION_STATE/q03-diagnostics"
  test ! -e "$CYBEX_JAMES_QUALIFICATION_STATE/q03-preflight-retry.json"
fi
work_dir="$(mktemp -d)"
qemu_pid=""
tap_name=""
package_server_pid=""
session_id=""
lifecycle_succeeded=false
personalized="$work_dir/personalized.iso"
cleanup() {
  if [[ -n "$qemu_pid" ]] && kill -0 "$qemu_pid" 2>/dev/null; then
    kill "$qemu_pid" 2>/dev/null || true
    wait "$qemu_pid" 2>/dev/null || true
  fi
  if [[ -n "$tap_name" ]]; then
    python3 -B "$repository_root/nixos-appliance/qualification/development-scope.py" tap-delete \
      --state-dir "$CYBEX_JAMES_QUALIFICATION_STATE" --manage-origin "$manage_origin" \
      --bridge "$bridge" --role appliance
  fi
  if [[ -n "$package_server_pid" ]] && kill -0 "$package_server_pid" 2>/dev/null; then
    kill "$package_server_pid" 2>/dev/null || true
    wait "$package_server_pid" 2>/dev/null || true
  fi
  if [[ -n "$session_id" && "$lifecycle_succeeded" != true ]]; then
    cleanup_session="$work_dir/cleanup-session.json"
    if api GET "/v1/james/provisioning-sessions/$session_id" > "$cleanup_session" 2>/dev/null \
      && [[ "$(jq -r '.destructive_started_at // ""' "$cleanup_session")" = "" ]] \
      && [[ "$(jq -r '.state' "$cleanup_session")" =~ ^(created|claimed|awaiting_approval|approved|failed)$ ]]
    then
      api POST "/v1/james/provisioning-sessions/$session_id/revoke" >/dev/null 2>&1 || true
    fi
  fi
  if [[ -f "$personalized" ]]; then
    shred -u -n 1 -z -- "$personalized" 2>/dev/null || rm -f -- "$personalized"
  fi
  if [[ "$lifecycle_succeeded" = true && -n "$fixture_dir" ]]; then
    # Stop the VM before handing off its disk. The update wrapper owns the next
    # boot and final cleanup; no daemon or stale device-ID variable is retained.
    mkdir -m 0700 -- "$fixture_dir"
    mv -- "$work_dir/appliance.raw" "$work_dir/OVMF_VARS.fd" "$fixture_dir/"
    jq -n --arg device_id "$device_id" --arg bridge "$bridge" \
      --argjson hardware "$hardware" \
      --arg manifest_sha256 "$(sha256sum "$manifest" | awk '{print $1}')" \
      '{schema:"cybex.james.qualification-fixture.v1",device_id:$device_id,
        bridge:$bridge,manifest_sha256:$manifest_sha256} + $hardware' \
      > "$fixture_dir/fixture.json"
  fi
  if [[ "$lifecycle_succeeded" != true && -n "${CYBEX_JAMES_QUALIFICATION_FAILURE_DIRECTORY:-}" && -f "$work_dir/appliance.raw" ]]; then
    # Private local diagnostics only. The owner removes these with the private
    # database; they must never be uploaded as public qualification evidence.
    mkdir -m 0700 -- "$CYBEX_JAMES_QUALIFICATION_FAILURE_DIRECTORY"
    mv -- "$work_dir/appliance.raw" "$work_dir/OVMF_VARS.fd" "$work_dir/serial.log" "$CYBEX_JAMES_QUALIFICATION_FAILURE_DIRECTORY/"
  fi
  if [[ -n "$session_id" && -f "$work_dir/serial.log" ]]; then
    cp -- "$work_dir/serial.log" "$(dirname -- "$output")/serial-$session_id.log"
    chmod 0600 "$(dirname -- "$output")/serial-$session_id.log"
  fi
  if [[ "$induce_preflight_retry" = true ]]; then
    diagnostics="$CYBEX_JAMES_QUALIFICATION_STATE/q03-diagnostics"
    mkdir -m 0700 -- "$diagnostics"
    for name in fault-responses.jsonl retry-attempt.json initial-approved.json initial-approval.json reapproved.json preflight-failed-serial.log; do
      if [[ -f "$work_dir/$name" ]]; then cp -- "$work_dir/$name" "$diagnostics/$name"; fi
    done
  fi
  rm -rf -- "$work_dir"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

api() {
  local method="$1" path="$2" body="${3:-}"
  if [[ -S "$CYBEX_JAMES_QUALIFICATION_STATE/manage.sock" ]]; then
    local rpc_args=(--state-dir "$CYBEX_JAMES_QUALIFICATION_STATE" api --path "$path")
    if [[ -n "$body" ]]; then rpc_args+=(--body "$body"); fi
    python3 -B "$repository_root/nixos-appliance/qualification/isolated_manage_rpc.py" "${rpc_args[@]}"
    return
  fi
  PYTHONPATH="$repository_root/nixos-appliance/qualification" python3 -B -c 'import sys; from isolated_fixture import SCOPE; SCOPE["development_origin"](sys.argv[1])' "$manage_origin"
  local response="$work_dir/api-response.json"
  local attempt=1 max_attempts=1 status http_code
  local curl_args=(-4 --fail --silent --show-error --proto '=https' --tlsv1.2
    --noproxy '*' --connect-timeout 15 --max-time 120 --output "$response"
    --write-out '%{http_code}' --request "$method"
    --header "Authorization: Bearer $token")
  # Read-only polling can tolerate a gateway disconnect. Never retry mutations:
  # their response may have been lost after the server accepted the operation.
  if [[ "$method" = GET ]]; then
    max_attempts=4
  fi
  if [[ -n "$body" ]]; then
    curl_args+=(--header 'Content-Type: application/json' --data-binary "$body")
  fi
  while ((attempt <= max_attempts)); do
    rm -f -- "$response"
    if http_code="$(curl "${curl_args[@]}" "$manage_origin$path")"; then
      status=0
    else
      status=$?
    fi
    if ((status == 0)) && [[ "$http_code" =~ ^2[0-9][0-9]$ ]]; then
      cat -- "$response"
      rm -f -- "$response"
      return 0
    fi
    # Curl 22 identifies an HTTP failure; all other listed codes are bounded
    # connection, timeout, incomplete-response, or TLS-handshake failures.
    if ((attempt == max_attempts)) || {
      [[ "$status" = 22 ]] && [[ ! "$http_code" =~ ^(408|429|502|503|504|525)$ ]]
    } || {
      [[ "$status" != 22 ]] && [[ ! "$status" =~ ^(6|7|18|28|35|52|55|56|92)$ ]]
    }; then
      rm -f -- "$response"
      ((status == 0)) && status=22 # Redirects are refused rather than followed.
      return "$status"
    fi
    rm -f -- "$response"
    sleep 1
    ((attempt += 1))
  done
}

check_delivery_policy() {
  local delivery_policy="$work_dir/delivery-policy.json"
  api GET '/v1/james/delivery-policy' > "$delivery_policy"
  test "$(jq -er '.allow_james_source_builds' "$delivery_policy")" = false
  test "$(jq -er '.source_builds_allowed' "$delivery_policy")" = false
}
check_delivery_policy

# Capture exact released revisions before package staging or VM work. The same
# read-only admission runs in Manage readiness. Never reset built-ins to v1.
blueprints="$work_dir/blueprints.json"
python3 -B "$repository_root/nixos-appliance/qualification/blueprint-catalog.py" \
  --manage-origin "$manage_origin" --token-file "$token_file" --state-dir "$CYBEX_JAMES_QUALIFICATION_STATE" \
  --tiling-blueprint "${CYBEX_JAMES_QUALIFICATION_TILING_BLUEPRINT:-qualification_tiling}" \
  > "$blueprints"

package_delivery="$(jq -er '.installer_iso_template_v3.package_delivery // "embedded"' "$manifest")"
package_transport_url=""
installer_iso_transport_url=""
case "$package_delivery" in
  embedded) ;;
  system-closure-v1)
    package_filename="cybex-james-appliance-closure-$release_version-x86_64-linux.tar.zst"
    signed_package_url="$(jq -er '.appliance_release_v1.system_closure.url' "$manifest")"
    [[ "$signed_package_url" = */"$package_filename" ]]
    manifest_directory="$(cd -- "$(dirname -- "$manifest")" && pwd -P)"
    package_snapshot="$manifest_directory/$package_filename"
    test -f "$package_snapshot" && test ! -L "$package_snapshot"
    test "$(stat -c '%s' "$package_snapshot")" = \
      "$(jq -er '.appliance_release_v1.system_closure.size_bytes' "$manifest")"
    test "$(sha256sum "$package_snapshot" | awk '{print $1}')" = \
      "$(jq -er '.appliance_release_v1.system_closure.sha256' "$manifest")"

    if [[ -S "$CYBEX_JAMES_QUALIFICATION_STATE/manage.sock" ]]; then
      [[ "$induce_preflight_retry" = false ]] || {
        echo 'error: isolated artifact transport does not support fault injection' >&2
        exit 1
      }
      installer_transports="$(python3 -B "$repository_root/nixos-appliance/qualification/isolated_manage_rpc.py" \
        --state-dir "$CYBEX_JAMES_QUALIFICATION_STATE" installer-transports \
        --manifest-sha256 "$(sha256sum "$manifest" | awk '{print $1}')")"
      package_transport_url="$(jq -er .package_transport_url <<<"$installer_transports")"
      installer_iso_transport_url="$(jq -er .installer_iso_transport_url <<<"$installer_transports")"
    else
    mapfile -t bridge_addresses < <(
      ip -4 -o address show dev "$bridge" scope global \
        | awk '{sub(/\/.*/, "", $4); print $4}'
    )
    bridge_ipv4="${CYBEX_JAMES_QUALIFICATION_PACKAGE_BIND_ADDRESS:-}"
    if [[ -n "$bridge_ipv4" ]]; then
      printf '%s\n' "${bridge_addresses[@]}" | grep -Fx "$bridge_ipv4" >/dev/null
    else
      for candidate in "${bridge_addresses[@]}"; do
        if python3 -B -c \
          'import ipaddress,sys; a=ipaddress.ip_address(sys.argv[1]); raise SystemExit(not (a.version == 4 and a.is_private and not a.is_loopback))' \
          "$candidate"
        then
          bridge_ipv4="$candidate"
          break
        fi
      done
    fi
    test -n "$bridge_ipv4" || {
      echo "error: qualification bridge $bridge has no private IPv4 address" >&2
      exit 1
    }
    python3 -B -c \
      'import ipaddress,sys; a=ipaddress.ip_address(sys.argv[1]); raise SystemExit(not (a.version == 4 and a.is_private and not a.is_loopback))' \
      "$bridge_ipv4"

    package_port_file="$work_dir/package-server.port"
    if [[ "$induce_preflight_retry" = true ]]; then
      printf 'corrupt\n' > "$work_dir/fault-control"
      python3 -B "$repository_root/nixos-appliance/qualification/serve-faulted-closure.py" \
        --bind "$bridge_ipv4" --file "$package_snapshot" --sha256 "$system_closure_sha256" \
        --size "$(stat -c '%s' "$package_snapshot")" --port-file "$package_port_file" \
        --control "$work_dir/fault-control" --receipts "$work_dir/fault-responses.jsonl" &
    else
      python3 -B "$repository_root/nixos-appliance/qualification/serve-system-closure.py" \
        --bind "$bridge_ipv4" --file "$package_snapshot" --port-file "$package_port_file" &
    fi
    package_server_pid=$!
    for _attempt in $(seq 1 100); do
      [[ -s "$package_port_file" ]] && break
      kill -0 "$package_server_pid"
      sleep 0.1
    done
    package_port="$(tr -d '\r\n' < "$package_port_file")"
    [[ "$package_port" =~ ^[1-9][0-9]{0,4}$ ]] && ((package_port <= 65535))
    package_transport_url="http://$bridge_ipv4:$package_port/$package_filename"
    curl --fail --silent --show-error --proto '=http' --head \
      "$package_transport_url" >/dev/null
    fi
    ;;
  *)
    echo "error: unsupported installer package delivery contract: $package_delivery" >&2
    exit 1
    ;;
esac

create_response="$work_dir/create.json"
if [[ -n "$package_transport_url" ]]; then
  create_body="$(jq -c --arg package_transport_url "$package_transport_url" \
    '{label:"release qualification",qualification_candidate:{release_version:.version,installer_iso_template_v3:.installer_iso_template_v3,appliance_release_v1:.appliance_release_v1,package_transport_url:$package_transport_url}}' \
    "$manifest")"
else
  create_body="$(jq -c '
    . as $manifest
    | {label:"release qualification",qualification_candidate:{release_version:$manifest.version,installer_iso_template_v3:$manifest.installer_iso_template_v3}}
    | if ($manifest | has("appliance_release_v1"))
      then .qualification_candidate.appliance_release_v1 = $manifest.appliance_release_v1
      else .
      end' "$manifest")"
fi
if [[ -n "$installer_iso_transport_url" ]]; then
  create_body="$(jq -c --arg url "$installer_iso_transport_url" \
    '.qualification_candidate.installer_iso_transport_url = $url' <<<"$create_body")"
fi
api POST /v1/james/provisioning-sessions "$create_body" > "$create_response"
session_id="$(jq -er '.session.id' "$create_response")"
if [[ -n "${CYBEX_JAMES_QUALIFICATION_SESSION_RECEIPT:-}" ]]; then
  test ! -e "$CYBEX_JAMES_QUALIFICATION_SESSION_RECEIPT"
  jq -n --arg session_id "$session_id" '{session_id:$session_id}' > "$CYBEX_JAMES_QUALIFICATION_SESSION_RECEIPT"
  chmod 0600 "$CYBEX_JAMES_QUALIFICATION_SESSION_RECEIPT"
fi
media_secret="$(jq -er '.media_secret' "$create_response")"
download_path="$(jq -er '.download_path' "$create_response")"
[[ "$download_path" = "/v1/james/provisioning-sessions/$session_id/appliance-iso" ]]
personalization_path="$(jq -er '.personalization_path' "$create_response")"
[[ "$personalization_path" = "/v1/james/provisioning-sessions/$session_id/personalization-envelope" ]]

headers="$work_dir/download.headers"
envelope="$work_dir/personalization-envelope.bin"
if [[ -S "$CYBEX_JAMES_QUALIFICATION_STATE/manage.sock" ]]; then
  printf '%s\n' "$media_secret" | python3 -B "$repository_root/nixos-appliance/qualification/isolated_manage_rpc.py" \
    --state-dir "$CYBEX_JAMES_QUALIFICATION_STATE" personalize --path "$personalization_path" --output "$envelope" --headers-output "$headers"
else
curl --fail --silent --show-error --proto '=https' --tlsv1.2 \
  --header "Authorization: Bearer $token" \
  --header "X-Cybex-James-Provisioning-Secret: $media_secret" \
  --dump-header "$headers" --output "$envelope" "$manage_origin$personalization_path"
fi
test "$(stat -c '%s' "$envelope")" -eq 8192
cp --reflink=auto -- "$template" "$personalized"
chmod 0600 "$personalized"
personalization_offset="$(jq -er '.installer_iso_template_v3.personalization_offset' "$manifest")"
dd if="$envelope" of="$personalized" bs=1 seek="$personalization_offset" conv=notrunc status=none
rm -f -- "$envelope"
verification="$work_dir/media-verification.json"
CYBEX_JAMES_MEDIA_SECRET="$media_secret" \
  python3 -B "$repository_root/nixos-appliance/qualification/verify-personalized-media.py" \
    --iso "$personalized" --manifest "$manifest" --headers "$headers" \
    --session-id "$session_id" > "$verification"
unset media_secret
rm -f "$create_response"

disk="$work_dir/appliance.raw"
truncate -s 160G "$disk"
preapproval_digest="$(python3 -B "$repository_root/nixos-appliance/qualification/disk-fingerprint.py" "$disk")"
vars_template="${CYBEX_JAMES_OVMF_VARS:-/usr/share/OVMF/OVMF_VARS_4M.fd}"
code="${CYBEX_JAMES_OVMF_CODE:-/usr/share/OVMF/OVMF_CODE_4M.fd}"
test -f "$vars_template" && test -f "$code"
cp -- "$vars_template" "$work_dir/OVMF_VARS.fd"

start_qemu() {
  tap_name="$(python3 -B "$repository_root/nixos-appliance/qualification/development-scope.py" tap-create \
    --state-dir "$CYBEX_JAMES_QUALIFICATION_STATE" --manage-origin "$manage_origin" --bridge "$bridge" --role appliance)"
  qemu-system-x86_64 \
    -enable-kvm -machine q35 -cpu host -smp 4 -m "$memory_mib" -uuid "$appliance_uuid" \
    -drive "if=pflash,format=raw,unit=0,readonly=on,file=$code" \
    -drive "if=pflash,format=raw,unit=1,file=$work_dir/OVMF_VARS.fd" \
    -drive "if=none,id=system,format=raw,file=$disk,cache=none" \
    -device virtio-scsi-pci,id=scsi0 -device "scsi-hd,drive=system,serial=$appliance_serial" \
    -drive "if=none,id=installer,media=cdrom,readonly=on,format=raw,file=$personalized" \
    -device ide-cd,drive=installer \
    -netdev "tap,id=net0,ifname=$tap_name,script=no,downscript=no" -device "virtio-net-pci,netdev=net0,mac=$appliance_mac" \
    -device i6300esb -watchdog-action reset \
    -boot "once=d,menu=off" -display none -serial "file:$work_dir/serial.log" \
    -qmp "unix:$work_dir/qmp.sock,server=on,wait=off" &
  qemu_pid=$!
}

start_qemu

session="$work_dir/session.json"
claimed=false
for _attempt in $(seq 1 180); do
  api GET "/v1/james/provisioning-sessions/$session_id" > "$session"
  state="$(jq -er '.state' "$session")"
  if [[ "$state" = awaiting_approval ]]; then claimed=true; break; fi
  [[ "$state" != failed && "$state" != revoked && "$state" != expired ]]
  kill -0 "$qemu_pid"
  sleep 5
done
test "$claimed" = true
test "$(jq -r '.inventory.secure_boot' "$session")" = false
test "$(jq -er '.inventory.boot_mode' "$session")" = uefi
test "$(jq -er '.blockers | length' "$session")" = 0
test "$(jq -er '[.inventory.disks[] | select(.eligible == true)] | length' "$session")" = 1
test "$(python3 -B "$repository_root/nixos-appliance/qualification/disk-fingerprint.py" "$disk")" = "$preapproval_digest"

# Suspend the owned guest before recording fresh inventory and approving its
# disk. It cannot consume the plan while the development allowlist is refreshed.
qualification_guest_control() {
  python3 -B - "$repository_root/nixos-appliance/qualification" "$work_dir/qmp.sock" "$1" <<'PY'
import sys
sys.path.insert(0, sys.argv[1])
from isolated_fixture import QMP
monitor = QMP(sys.argv[2])
try:
    monitor.call(sys.argv[3])
    status = monitor.call('query-status')
    if status['running'] != (sys.argv[3] == 'cont'):
        raise ValueError('Owned guest did not enter the requested approval boundary')
finally:
    monitor.socket.close()
PY
}
if [[ -n "${CYBEX_JAMES_QUALIFICATION_ALLOW_DEVICE_HELPER:-}" ]]; then
  qualification_guest_control stop
  "$CYBEX_JAMES_QUALIFICATION_ALLOW_DEVICE_HELPER" --prepare \
    --state-dir "$CYBEX_JAMES_QUALIFICATION_STATE" --session-id "$session_id"
fi

revision="$(jq -er '.session_revision' "$session")"
inventory_sha="$(jq -er '.inventory_sha256' "$session")"
disk_id="$(jq -er '.inventory.disks[] | select(.eligible == true) | .id' "$session")"
interface_id="$(jq -er '.inventory.ethernet_interfaces[] | select(.link_up == true) | .id' "$session" | head -n 1)"
session_suffix="${session_id%%-*}"
approve_body="$(jq -cn \
  --argjson revision "$revision" --arg inventory "$inventory_sha" \
  --arg disk "$disk_id" --arg interface "$interface_id" --arg cidr "$management_cidr" \
  --arg display_name "James release qualification $release_version $session_suffix" \
  --argjson weekday "$(date -u +%w)" --arg start "$(date -u +%H:%M)" \
  '{session_revision:$revision,inventory_sha256:$inventory,display_name:$display_name,target_disk_id:$disk,network:{mode:"dhcp",interface_id:$interface,address_cidr:null,gateway:null,dns_servers:[]},maintenance_window:{timezone:"UTC",weekday:$weekday,start:$start,duration_minutes:240},management_cidrs:[$cidr]}')"
printf '%s\n' "$approve_body" > "$work_dir/initial-approval.json"
api POST "/v1/james/provisioning-sessions/$session_id/approve" "$approve_body" > "$work_dir/initial-approved.json"
if [[ -S "$CYBEX_JAMES_QUALIFICATION_STATE/manage.sock" ]]; then
  python3 -B "$repository_root/nixos-appliance/qualification/isolated_manage_rpc.py" \
    --state-dir "$CYBEX_JAMES_QUALIFICATION_STATE" allow-device --session-id "$session_id"
fi
if [[ -n "${CYBEX_JAMES_QUALIFICATION_ALLOW_DEVICE_HELPER:-}" ]]; then
  "$CYBEX_JAMES_QUALIFICATION_ALLOW_DEVICE_HELPER" \
    --state-dir "$CYBEX_JAMES_QUALIFICATION_STATE" --session-id "$session_id"
  qualification_guest_control cont
fi

if [[ "$induce_preflight_retry" = true ]]; then
  # The ordinary installer must reject altered response bytes before seq1/seq2
  # authorize any target write. Only this owned guest and transport are affected.
  python3 -B "$repository_root/nixos-appliance/qualification/preflight_retry.py" begin \
    --state-dir "$CYBEX_JAMES_QUALIFICATION_STATE" --session-id "$session_id" \
    --initial "$work_dir/initial-approved.json" --qmp "$work_dir/qmp.sock" \
    --disk "$disk" --disk-digest "$preapproval_digest" --iso "$personalized" \
    --responses "$work_dir/fault-responses.jsonl" --receipt "$work_dir/retry-attempt.json"
  # This is an actual same-media cold restart, not a new ISO or replacement disk.
  # begin left the exact guest paused; no graceful flush can hide a disk write.
  kill -KILL "$qemu_pid"
  wait "$qemu_pid" 2>/dev/null || [[ "$?" = 137 ]]
  qemu_pid=""
  python3 -B "$repository_root/nixos-appliance/qualification/development-scope.py" tap-delete \
    --state-dir "$CYBEX_JAMES_QUALIFICATION_STATE" --manage-origin "$manage_origin" \
    --bridge "$bridge" --role appliance
  tap_name=""
  mv "$work_dir/serial.log" "$work_dir/preflight-failed-serial.log"
  rm -f "$work_dir/qmp.sock"
  restarted_at="$(date -u +'%Y-%m-%dT%H:%M:%S.%NZ')"
  start_qemu
  python3 -B "$repository_root/nixos-appliance/qualification/preflight_retry.py" approve \
    --state-dir "$CYBEX_JAMES_QUALIFICATION_STATE" --session-id "$session_id" \
    --initial "$work_dir/initial-approved.json" --qmp "$work_dir/qmp.sock" \
    --disk "$disk" --iso "$personalized" --receipt "$work_dir/retry-attempt.json" \
    --approval "$work_dir/initial-approval.json" --reapproved "$work_dir/reapproved.json" \
    --control "$work_dir/fault-control" --restarted-at "$restarted_at"
fi

ready=false
reboot_deadline=0
pre_destructive_deadline=$((SECONDS + 300))
for _attempt in $(seq 1 1080); do
  api GET "/v1/james/provisioning-sessions/$session_id" > "$session"
  state="$(jq -er '.state' "$session")"
  if [[ "$state" = ready ]]; then ready=true; break; fi
  if [[ -s "$work_dir/serial.log" ]] \
    && grep -aF 'An error occurred. Press enter to start a shell' "$work_dir/serial.log" >/dev/null
  then
    echo 'error: installer entered a fatal recovery shell' >&2
    echo 'bounded qualification serial console follows:' >&2
    tail -n 500 "$work_dir/serial.log" >&2
    exit 1
  fi
  if [[ "$state" = failed || "$state" = revoked || "$state" = expired ]]; then
    jq '{state,failure_code,failure_message,progress}' "$session" >&2
    exit 1
  fi
  if [[ "$state" = approved ]] \
    && [[ "$(jq -r '.destructive_started_at // ""' "$session")" = "" ]] \
    && ((SECONDS >= pre_destructive_deadline))
  then
    echo 'error: approved James candidate did not acknowledge its plan before the qualification deadline' >&2
    jq '{state,heartbeat_at,destructive_started_at,progress,failure_code,failure_message}' "$session" >&2
    if [[ -s "$work_dir/serial.log" ]]; then
      echo 'bounded qualification serial console follows:' >&2
      tail -n 500 "$work_dir/serial.log" >&2
    fi
    exit 1
  fi
  if [[ "$state" = rebooting && "$reboot_deadline" -eq 0 ]]; then
    reboot_deadline=$((SECONDS + 300))
  fi
  if ((reboot_deadline > 0 && SECONDS >= reboot_deadline))
  then
    echo 'error: James did not report Ready within five minutes of requesting reboot; inspect installed boot and first-boot service evidence; qualification will not force a restart or remove media' >&2
    jq '{state,heartbeat_at,progress,failure_code,failure_message}' "$session" >&2
    if [[ -s "$work_dir/serial.log" ]]; then
      echo 'bounded qualification serial console follows:' >&2
      tail -n 500 "$work_dir/serial.log" >&2
    fi
    exit 1
  fi
  kill -0 "$qemu_pid"
  sleep 5
done
test "$ready" = true

device_id="$(jq -er '.reserved_device_id' "$session")"
nodes="$work_dir/nodes.json"
node="$work_dir/node.json"
appliance_projection_ready=false
for _attempt in $(seq 1 120); do
  api GET '/v1/james/nodes?limit=100&offset=0' > "$nodes"
  jq -e --arg device "$device_id" '.nodes[] | select(.device_id == $device)' "$nodes" > "$node" || true
  if [[ -s "$node" ]] \
    && [[ "$(jq -er '.appliance_base_os' "$node")" = nixos ]] \
    && [[ "$(jq -er '.appliance_base_os_version' "$node")" = "$(jq -er '.appliance_release_v1.base_os_version' "$manifest")" ]] \
    && [[ "$(jq -r '.appliance_secure_boot' "$node")" = false ]] \
    && [[ "$(jq -er '.appliance_boot_mode' "$node")" = uefi ]] \
    && [[ "$(jq -er '.at_rest_protection' "$node")" = none ]] \
    && [[ "$(jq -er '.appliance_local_health.status' "$node")" = healthy ]] \
    && [[ -n "$(jq -er '.kernel_version' "$node")" ]] \
    && [[ -n "$(jq -er '.system_generation' "$node")" ]] \
    && [[ "$(jq -er '.system_toplevel' "$node")" = "$(jq -er '.appliance_release_v1.system_toplevel' "$manifest")" ]] \
    && [[ "$(jq -er '.system_closure_sha256' "$node")" = "$system_closure_sha256" ]] \
    && [[ "$(jq -er '.nixpkgs_revision' "$node")" = "$(jq -er '.appliance_release_v1.nixpkgs_revision' "$manifest")" ]]
  then
    appliance_projection_ready=true
    break
  fi
  kill -0 "$qemu_pid"
  sleep 5
done
test "$appliance_projection_ready" = true

# Product-level greenfield contract: the exact candidate must converge with
# the organization's untouched built-ins under the default source-disabled
# delivery policy. Checking node-scoped jobs prevents an artifact retained on
# another James from making this freshly installed disk appear qualified.
check_delivery_policy

runtime_status="$work_dir/workstation-runtime.json"
runtime_operational=false
runtime_converged=false
runtime_prepublication_deferred=false
if [[ "$prepublication_candidate" = true ]]; then
  api GET "/v1/james/nodes/$device_id/workstation-netboot" > "$runtime_status"
  test "$(jq -er '.state' "$runtime_status")" = absent
  test "$(jq -er '.operational' "$runtime_status")" = false
  test "$(jq -er '.converged' "$runtime_status")" = false
  test "$(jq -r '.desired // ""' "$runtime_status")" = ""
  test "$(jq -r '.active // ""' "$runtime_status")" = ""
  # Manage binds runtimes to the exact appliance release. Even with a published
  # predecessor, a new candidate disk cannot acquire its matching runtime until
  # immutable staging. Delivery remains mandatory in the cold phase before the
  # prerelease can become stable. No predecessor state is fabricated here.
  runtime_prepublication_deferred=true
else
  for _attempt in $(seq 1 720); do
    api GET "/v1/james/nodes/$device_id/workstation-netboot" > "$runtime_status"
    if [[ "$(jq -er '.operational' "$runtime_status")" = true ]] \
      && [[ "$(jq -er '.converged' "$runtime_status")" = true ]]
    then
      runtime_operational=true
      runtime_converged=true
      break
    fi
    if [[ "$(jq -er '.state' "$runtime_status")" = failed ]] \
      && [[ "$(jq -er '.operational' "$runtime_status")" = false ]]
    then
      echo 'error: fresh James has no verified usable workstation runtime' >&2
      jq '{state,operational,converged,failure_code,failure_message}' \
        "$runtime_status" >&2
      exit 1
    fi
    kill -0 "$qemu_pid"
    sleep 5
  done
  test "$runtime_operational" = true
  test "$runtime_converged" = true
fi
if [[ "$require_candidate_runtime" = true ]]; then
  # Used after immutable publication with a cold disk. Before publication the
  # normal compatibility lifecycle truthfully exercises the selected predecessor.
  test "$runtime_operational" = true
  for projection in active desired; do
    test "$(jq -er --arg p "$projection" '.[$p].bundle_sha256' "$runtime_status")" = \
      "$(jq -er '.workstation_netboot.sha256' "$manifest")"
    test "$(jq -er --arg p "$projection" '.[$p].runtime_version' "$runtime_status")" = \
      "$(jq -er '.workstation_netboot.runtime_version' "$manifest")"
  done
fi

build_jobs="$work_dir/build-jobs.json"
builtins_deliverable=false
if [[ "$runtime_prepublication_deferred" = false ]]; then
for _attempt in $(seq 1 720); do
  api GET "/v1/james/nodes/$device_id/build/jobs?limit=200&offset=0" > "$build_jobs"
  source_blocked_builtin_job="$(jq -c --slurpfile blueprints "$blueprints" '
    [.jobs[]
      | select(.status == "failed")
      | select(.cache_metadata.error_kind == "source_build_blocked")
      | select(.build_spec.blueprint_revision_id as $revision
          | $blueprints[0].blueprints
          | any(.current_revision_id == $revision))]
    | first // empty
  ' "$build_jobs")"
  if [[ -n "$source_blocked_builtin_job" ]]; then
    echo 'error: an official built-in Blueprint violates the source-free release contract' >&2
    jq '{blueprint_id:.build_spec.blueprint_id,
         blueprint_revision_id:.build_spec.blueprint_revision_id,status,error,
         error_kind:.cache_metadata.error_kind,
         source_build_candidates:.cache_metadata.source_build_candidates}' \
      <<<"$source_blocked_builtin_job" >&2
    exit 1
  fi
  if jq -e --slurpfile blueprints "$blueprints" '
      ($blueprints[0].blueprints | map(.slug)) as $expected
      | ([.jobs[]
          | select(.status == "succeeded")
          | .build_spec.blueprint_revision_id as $revision
          | $blueprints[0].blueprints[]
          | select(.current_revision_id == $revision)
          | .slug] | unique | sort) == ($expected | sort)
    ' "$build_jobs" >/dev/null
  then
    all_cached=true
    while IFS=$'\t' read -r blueprint_id revision_id; do
      cache_status="$work_dir/cache-status-$blueprint_id.json"
      api GET "/v1/blueprints/$blueprint_id/james-cache?revision_id=$revision_id" \
        > "$cache_status"
      if [[ "$(jq -er '.cached' "$cache_status")" != true ]] \
        || [[ "$(jq -er '.required_replicas > 0 and .ready_replicas == .required_replicas' "$cache_status")" != true ]]
      then
        all_cached=false
      fi
    done < <(jq -r '.blueprints[]
      | [.id,.current_revision_id] | @tsv' "$blueprints")
    if [[ "$all_cached" = true ]]; then
      builtins_deliverable=true
      break
    fi
  fi
  kill -0 "$qemu_pid"
  sleep 5
done
if [[ "$builtins_deliverable" != true ]]; then
  echo 'error: official built-in Blueprints did not converge on the new James' >&2
  jq --slurpfile blueprints "$blueprints" '
    [.jobs[]
      | select(.build_spec.blueprint_revision_id as $revision
          | $blueprints[0].blueprints
          | any(.current_revision_id == $revision))
      | {blueprint_id:.build_spec.blueprint_id,
         blueprint_revision_id:.build_spec.blueprint_revision_id,status,error,
         error_kind:.cache_metadata.error_kind,
         source_build_candidates:.cache_metadata.source_build_candidates}]
    | .[:20]
  ' "$build_jobs" >&2
  exit 1
fi
fi

network_change="$work_dir/network-change.json"
network_body="$(jq -cn --arg interface "$interface_id" \
  '{network:{mode:"dhcp",interface_id:$interface,address_cidr:null,gateway:null,dns_servers:[]}}')"
api POST "/v1/james/nodes/$device_id/network-changes" "$network_body" > "$network_change"
network_change_id="$(jq -er '.id' "$network_change")"
test "$(jq -er '.state' "$network_change")" = requested
network_acknowledged=false
for _attempt in $(seq 1 120); do
  api GET '/v1/james/nodes?limit=100&offset=0' > "$nodes"
  jq -e --arg device "$device_id" '.nodes[] | select(.device_id == $device)' "$nodes" > "$node"
  reported_change_id="$(jq -r '.appliance_network.network_change.change_id // ""' "$node")"
  reported_change_status="$(jq -r '.appliance_network.network_change.status // "idle"' "$node")"
  if [[ "$reported_change_id" = "$network_change_id" && "$reported_change_status" = acknowledged ]]; then
    network_acknowledged=true
    break
  fi
  [[ "$reported_change_status" != failed && "$reported_change_status" != rolled_back ]]
  kill -0 "$qemu_pid"
  sleep 5
done
test "$network_acknowledged" = true

ssh-keygen -q -t ed25519 -N '' -C qualification -f "$work_dir/operator-key"
certificate_response="$work_dir/ssh-certificate.json"
certificate_request="$(jq -cn \
  --arg public_key "$(cat "$work_dir/operator-key.pub")" \
  '{public_key:$public_key,reason:"exact candidate release qualification",validity_minutes:5,allow_forwarding:false}')"
api POST "/v1/james/nodes/$device_id/ssh-certificates" "$certificate_request" > "$certificate_response"
test "$(jq -er '.principal' "$certificate_response")" = "$device_id"
valid_after="$(date -u -d "$(jq -er '.valid_after' "$certificate_response")" +%s)"
valid_before="$(date -u -d "$(jq -er '.valid_before' "$certificate_response")" +%s)"
test "$((valid_before - valid_after))" -le 300
jq -er '.certificate' "$certificate_response" > "$work_dir/operator-key-cert.pub"
ssh-keygen -Lf "$work_dir/operator-key-cert.pub" > "$work_dir/certificate-inspection.txt"
grep -E "^[[:space:]]+${device_id}[[:space:]]*$" "$work_dir/certificate-inspection.txt" >/dev/null
if grep -F 'permit-agent-forwarding' "$work_dir/certificate-inspection.txt" >/dev/null \
  || grep -F 'permit-port-forwarding' "$work_dir/certificate-inspection.txt" >/dev/null
then
  echo 'error: non-forwarding qualification certificate contains forwarding extensions' >&2
  exit 1
fi
# Target only the new fixture address on the owned bridge. A compromised
# report cannot redirect this authenticated test to an existing appliance.
ssh_host="$(python3 - "$node" "$CYBEX_JAMES_QUALIFICATION_STATE/scope.json" <<'PYSSH'
import ipaddress,json,sys,urllib.parse
node=json.load(open(sys.argv[1])); scope=json.load(open(sys.argv[2]))
host=urllib.parse.urlsplit(node['public_base_url']).hostname
address=ipaddress.ip_address(host)
if address.version != 4 or address not in ipaddress.ip_interface(scope['subnet']).network:
    raise SystemExit('SSH target is outside the disposable bridge')
print(address)
PYSSH
)"
ssh_options=(-o BatchMode=yes -o IdentitiesOnly=yes -o ConnectTimeout=10
  -o StrictHostKeyChecking=accept-new -o "UserKnownHostsFile=$work_dir/known-hosts"
  -i "$work_dir/operator-key" -o "CertificateFile=$work_dir/operator-key-cert.pub")
ssh "${ssh_options[@]}" "cybex-support@$ssh_host" 'test "$(id -un)" = cybex-support'
if ssh "${ssh_options[@]}" "root@$ssh_host" true > "$work_dir/root-login.log" 2>&1; then
  echo 'error: direct root login was accepted' >&2; exit 1
fi
rg -q 'Permission denied' "$work_dir/root-login.log"
if ssh "${ssh_options[@]}" -o PubkeyAuthentication=no -o PreferredAuthentications=password,keyboard-interactive \
  "cybex-support@$ssh_host" true > "$work_dir/password-login.log" 2>&1; then
  echo 'error: password login was accepted' >&2; exit 1
fi
rg -q 'Permission denied' "$work_dir/password-login.log"
rm -f -- "$work_dir/operator-key" "$work_dir/operator-key.pub" \
  "$work_dir/operator-key-cert.pub" "$certificate_response" "$work_dir/certificate-inspection.txt"

# Fail closed if policy, authoring or a released revision moved during this run.
check_delivery_policy
python3 -B "$repository_root/nixos-appliance/qualification/blueprint-catalog.py" \
  --manage-origin "$manage_origin" --token-file "$token_file" --state-dir "$CYBEX_JAMES_QUALIFICATION_STATE" \
  --tiling-blueprint "${CYBEX_JAMES_QUALIFICATION_TILING_BLUEPRINT:-qualification_tiling}" \
  --baseline "$blueprints" >/dev/null

template_sha="$(jq -er '.template_sha256' "$verification")"
personalized_sha="$(jq -er '.personalized_sha256' "$verification")"
jq -n \
  --slurpfile qualified_blueprints "$blueprints" \
  --arg qualification_kind "$qualification_kind" \
  --arg qualified_manifest_sha256 "$(sha256sum "$manifest" | awk '{print $1}')" \
  --arg harness_revision "$source_revision" \
  --arg schema 'cybex.james.nixos-appliance-qualification.v1' \
  --arg release_version "$release_version" \
  --arg system_closure_sha256 "$system_closure_sha256" \
  --arg system_toplevel "$(jq -er '.system_toplevel' "$node")" \
  --arg nixpkgs_revision "$(jq -er '.nixpkgs_revision' "$node")" \
  --arg manage_source_revision "$(jq -er '.appliance_release_v1.manage_source_revision' "$manifest")" \
  --arg system_generation "$(jq -er '.system_generation | tostring' "$node")" \
  --arg session_id "$session_id" --arg template_sha256 "$template_sha" \
  --arg device_id "$device_id" \
  --argjson candidate_runtime_required "$require_candidate_runtime" \
  --arg personalized_sha256 "$personalized_sha" \
  --argjson workstation_runtime_operational "$runtime_operational" \
  --argjson workstation_runtime_converged "$runtime_converged" \
  --argjson workstation_runtime_prepublication_deferred "$runtime_prepublication_deferred" \
  --argjson builtins_deliverable "$builtins_deliverable" \
  --arg completed_at "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
  '{schema:$schema,ok:true,release_version:$release_version,
    harness_revision:$harness_revision,qualification_kind:$qualification_kind,
    qualified_manifest_sha256:$qualified_manifest_sha256,qualified_blueprints:$qualified_blueprints[0],
    base_os:"nixos",system_toplevel:$system_toplevel,nixpkgs_revision:$nixpkgs_revision,
    manage_source_revision:$manage_source_revision,
    system_closure_sha256:$system_closure_sha256,system_generation:$system_generation,
    session_id:$session_id,device_id:$device_id,template_sha256:$template_sha256,
    candidate_runtime_required:$candidate_runtime_required,
    personalized_sha256:$personalized_sha256,secure_boot:false,
    no_disk_write_before_approval:true,identity_rotation:true,
    installed_media_left_attached:true,appliance_projection_healthy:true,
    workstation_runtime_operational:$workstation_runtime_operational,
    workstation_runtime_converged:$workstation_runtime_converged,
    workstation_runtime_prepublication_deferred:$workstation_runtime_prepublication_deferred,
    builtin_blueprints_source_free:$builtins_deliverable,
    builtin_blueprints_deliverable:$builtins_deliverable,
    builtin_blueprints_qualified_on_new_james:$builtins_deliverable,
    builtin_blueprints_prepublication_deferred:$workstation_runtime_prepublication_deferred,
    two_phase_network_acknowledged:true,exact_principal_ssh_certificate:true,
    ssh_login_verified:true,ssh_root_rejected:true,ssh_password_rejected:true,
    final_state:"ready",completed_at:$completed_at}' \
  > "$output"
chmod 0600 "$output"
if [[ "$induce_preflight_retry" = true ]]; then
  python3 -B "$repository_root/nixos-appliance/qualification/preflight_retry.py" complete \
    --state-dir "$CYBEX_JAMES_QUALIFICATION_STATE" --session-id "$session_id" \
    --receipt "$work_dir/retry-attempt.json" --reapproved "$work_dir/reapproved.json" \
    --lifecycle "$output" --responses "$work_dir/fault-responses.jsonl" \
    --output "$CYBEX_JAMES_QUALIFICATION_STATE/q03-preflight-retry.json"
fi
lifecycle_succeeded=true
