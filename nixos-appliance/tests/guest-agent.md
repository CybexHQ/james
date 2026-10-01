# Installed QEMU guest agent

`nixos-appliance/system.nix` enables the standard NixOS
`services.qemuGuest` module. `default.nix` imports this module for the installed
system, and the same resulting closure is used for fresh installation and
signed-generation updates. This is not an installer-only package or an
imperative change to a running appliance profile.

The pinned NixOS module supplies `qemu-guest-agent.service` and its packaged
`qemu-ga`. A udev rule starts the service only when the virtio port named
`org.qemu.guest_agent.0` appears; there is no unconditional `multi-user.target`
startup. Runtime state lives in `/run/qemu-ga`. Physical appliances without the
channel do not start the service. The hypervisor must provide the channel.

The channel is a privileged management interface controlled by the trusted
hypervisor. Release-signature checks protect system-generation updates; they do
not constrain QGA RPC commands or replace hypervisor access controls. Keep guest
execution/file-transfer authority private and limited to the approved VM scope.

## Source verification

From the repository root:

```sh
python3 -B -m unittest discover -s nixos-appliance/tests -p 'test_guest_agent.py' -v
nix-instantiate --eval --strict --json --expr \
  'import ./nixos-appliance/tests/guest-agent-evaluation.nix {}'
```

The test evaluates the real installed `system.nix` with the repository's pinned
nixpkgs and the existing console evaluation seam's explicitly test-only package
and public-key placeholders. It does not compile those placeholders, build a
release, sign anything, or supply production identity. Checks cover the guest
agent's package command, channel-specific activation, ephemeral runtime state,
STATE/control/status mounts, EFI boot selection, release-signature policy,
state version, and the workstation agent's existing cache seed.

Nix is required for real module evaluation; the Python wrapper explicitly skips
when Nix is absent. This evaluation is not a complete production-input closure
build or proof of a working hypervisor transport.

## Immutable-generation boundary

Changing this source creates a **new candidate closure**, not a modification of
an already signed generation. Existing signed releases, EFI/TPM identity,
STATE data and generation history remain untouched. Do not rebind a published
version, alter release JSON, rebuild a live signed profile, or bypass update
verification to enable QGA. Qualification and explicitly scoped approval must
precede any deployment. This source change does not promote or select a global
release for other organizations.

After reviewed/committed candidate sources and proper version selection, the
existing unsigned-only wrapper is the build entrypoint (public inputs only):

```sh
bash nixos-appliance/build-closure.sh \
  --manage-source-dir "$MANAGE_SOURCE" --manage-source-revision "$MANAGE_REVISION" \
  --source-revision "$NEST_REVISION" --expected-manage-origin "$MANAGE_ORIGIN" \
  --source-date-epoch "$SOURCE_DATE_EPOCH" \
  --release-public-key "$RELEASE_PUBLIC_KEY" \
  --provisioning-public-key "$PROVISIONING_PUBLIC_KEY" \
  --unsigned-output-dir "$CACHE_OUTPUT"
```

Remaining gates: a full closure evaluation/build with exact production candidate
inputs, existing install/update/rollback qualification, and actual QGA ping
through the channel after installation and reboot/update while confirming
identity and STATE continuity. No signing or deployment is part of this patch.
Use the committed Nest source timestamp (`git show -s --format=%ct "$NEST_REVISION"`)
for `SOURCE_DATE_EPOCH`; the unsigned wrapper requires this explicit public input.
