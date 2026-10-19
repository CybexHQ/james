# shellcheck shell=bash
# Hold host capacity from The Beast's shared CI admission budget for the rest
# of the calling step. Builds and fixtures here run directly on the host, so
# without a reservation CI admits VMs beside them and overcommits memory.
# `ci-platform reserve` waits for the budget, prints one line once admitted and
# holds the lease until its stdin closes: the coproc pipe closes when this step
# shell exits, however it exits. Run as the CI state owner, never with sudo.
reserve_ci_host_capacity() {
  local purpose="$1" memory_gib="$2" cpus="$3" wait_seconds="${4:-7200}" reservation
  coproc CI_HOST_RESERVATION {
    exec ci-platform reserve --purpose "$purpose" --memory-gib "$memory_gib" \
      --cpus "$cpus" --wait-seconds "$wait_seconds"
  }
  if ! read -r -u "${CI_HOST_RESERVATION[0]}" reservation; then
    echo "CI host capacity reservation failed: $purpose" >&2
    return 1
  fi
  printf 'Reserved CI host capacity: %s\n' "$reservation"
}
