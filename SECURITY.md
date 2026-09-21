# Security

## Supported platform

The NixOS appliance installed from a personalized current James ISO is the
replacement platform. Ubuntu state-schema V1/V2 appliances receive no in-place
NixOS update and must be reinstalled by a human. The old pre-provisioning NixOS
and Proxmox/LXC implementations are unsupported. This branch's qualification
ledger determines release readiness; a source change is not a published update.

## Trust boundaries

- The offline ISO template and release descriptors are signed by the James
  release key. The template signature binds the canonical Management origin;
  build, signing, qualification, and verification compare it with an explicit
  governed expectation rather than trusting artifact URLs or bootstrap output.
- The fixed personalization slot contains a bounded, signed, single-use V2
  provisioning envelope.
- Provisioning activates the reserved device identity before the installed
  service starts; the service does not accept install codes or pairing codes.
- Agent requests are signed by the activated device key.
- Appliance system closures and network changes are signed, journaled, and
  fail closed. The archive, every compressed/uncompressed NAR, complete reference
  graph and embedded source are verified before import or destructive work.
- The root updater copies unprivileged requests into private staging and verifies
  them again. Only root-owned STATE receipts authorize profile/EFI mutation,
  commit and rollback. A writable inbox is never boot authority.
- James is an allowed, unprivileged Nix-daemon client, never a trusted user.
  No release or provisioning private key enters the Nix store or installer ISO.
- Secure Boot is turned off and reported as firmware information. It is not the
  artifact trust boundary. STATE is unencrypted; physical disk access exposes
  identity and data.
- SSH access uses the configured SSH CA and the exact reserved device ID as the
  principal.
- Workstation netboot bundles are immutable and signature-verified before
  publication. An optional qualification `bundle_transport_url` is restricted to
  a canonical RFC1918 IPv4 HTTP endpoint with the exact signed filename, without
  proxies or redirects. It cannot inherit the legacy private-URL signature bypass;
  retry and resume identities bind its hash while the signed identity stays intact.

The bootstrap validates envelope canonicalization, signatures, session state,
target-disk identity, and network plan before destructive installation. It
does not write the target disk before approval.

Secrets must not be stored in repository files, command lines, logs, release
manifests, or qualification evidence. Production signing keys and provisioning
credentials are supplied through protected deployment facilities.

## Reporting vulnerabilities

Report suspected vulnerabilities privately to the Cybex security contact. Do
not include production credentials or personal data. Include the affected
release, reproduction conditions, and whether firmware, provisioning,
updates, network changes, or netboot publication are involved.
