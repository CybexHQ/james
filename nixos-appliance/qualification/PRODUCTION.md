# NixOS production qualification

The supported appliance is NixOS James V3. Ubuntu appliance builders, installed
runtime scripts, and qualification runners are retired. The PXE handoff shared
with the Rust service lives in `assets/autoexec.ipxe`. Historical signed descriptors
remain readable for publication ancestry; they are never upgrade fixtures or new
production candidates. Existing Ubuntu installations require human reinstallation.

The protected release workflow builds and signs immutable production-bound
artifacts, qualifies them, stages an immutable prerelease, independently downloads
its published bytes, and repeats cold appliance and workstation acceptance.
Coordinated releases require a separate exact-candidate promotion action.
`release/coordinated.json` uses `cybex.coordinated-release.v2` and
`appliance_family: nixos`; it has no Ubuntu snapshot input.

## Isolated management service

Both qualification jobs use `production-release-qualification`. Configure:

- `CYBEX_JAMES_QUALIFICATION_MANAGE_ORIGIN`: `https://manage.cybex.net`.
- `CYBEX_JAMES_QUALIFICATION_CONFIG`: absolute path to a dedicated root-private
  fixture template, in the format accepted by `isolated_manage_config.py`.
- `CYBEX_JAMES_QUALIFICATION_STATE_ROOT`: an existing root-owned 0700 directory.
- `CYBEX_JAMES_QUALIFICATION_SUBNET`: an unused private IPv4 /24 with its gateway.
- `CYBEX_JAMES_NIXOS_QUALIFICATION_PREDECESSOR_DIR` and
  `CYBEX_JAMES_NIXOS_QUALIFICATION_PREDECESSOR_MANIFEST_SHA256`: the independently
  signed NixOS upgrade baseline. The baseline must admit the production origin and
  fixture provisioning key, and precede the candidate version. For initial NixOS
  production qualification this is a separately built, signed private baseline;
  an Ubuntu release or a development-origin NixOS ISO is not a substitute.

The template retains the existing v2 configuration schema. It pins the database
and TLS image digests, names the canonical development source checkout, supplies
an unused disjoint private /28 backend subnet, and references a dedicated TLS
certificate/key and provisioning seed alongside the template. It permits either
no upstream downloads or the exact reviewed host set
`api.github.com`, `cache.nixos.org`, `codeload.github.com`, and `github.com`.
Full workstation qualification needs that set for pinned nixpkgs and signed
binary-cache dependencies. The certificate must validate normally for the exact
artifact origin and the signer must appear in both signed ISO descriptors.
Template image/source fields are replaced with the exact verified candidate
revision and image IDs by `prepare-fixture-config.py` before fixture startup.
No signing key enters a Nix derivation, image build argument, or public receipt.

Each phase owns fresh Docker containers and state, a fresh organization/session,
an Incus bridge, and disposable QEMU machines. The retained `isolated_manage.Owner`
verifies its container and network identities on every operation. Host callers use
a root-private Unix socket to that Owner. The Owner's TLS transport connects to an
explicit private IP, verifies the normal hostname/certificate chain and exact
certificate fingerprint, and reads a fixture-specific challenge on the same
connection before sending credentials. It never resolves the public origin or
follows credential-bearing redirects. Guest DNS and default-deny confinement are
verified before any TAP is admitted. Internal Docker containers receive only a
host route to the private DNS peer, never a default route. A retained TCP
forwarder connects the private host TLS listener to the exact owned TLS container;
Docker internal networks do not expose published ports. TLS remains end to end
between management callers and that container. For the reviewed upstream set,
DNS still points only at the private peer. The retained forwarder parses a bounded
TLS ClientHello and routes approved SNI names to public IPv4 addresses on port 443;
it rejects unknown names and any nonpublic DNS answer. TLS and normal upstream
certificate validation remain end to end. Management SNI always selects the owned
container and never public DNS. Firewall rules do not open direct guest egress.
Cleanup closes every forwarding socket. Changing a hostname allowlist alone cannot
turn a development run into production qualification.

The fixture builds its Manage images from the candidate's committed development
revision. The older NixOS appliance is exercised against that current Manage
harness with its separately pinned compatibility projection. Cold qualification
uses only the independently downloaded candidate, with no warm predecessor cache.
The fresh fixture completes Default Policy sign-in setup with an ephemeral local
account and creates a separate Tiling/Deno profile; Standard and Dock retain
their seeded current revisions. The fixture uses Secure Boot-capable OVMF with
unenrolled keys, so enforcement is explicitly disabled. SSH selects the observed
interface by the owned MAC and private subnet; an unset desired service URL is
not a guest address.
Fresh isolated guests can lag the issuer clock by a few seconds without public
NTP. The positive SSH check polls actual certificate acceptance for at most ten
seconds, bounded by certificate expiry, with at most one retry after three
seconds to avoid OpenSSH authentication penalties; other failures stop immediately. The
certificate interval and root/password rejection checks remain unchanged.
Source-free delivery, real appliance install,
upgrade/rollback, managed workstation reboots, and exact compliance remain gates.

Production evidence includes `cybex.james.isolated-qualification.v1`, the artifact
origin, exact Manage revision, owned fixture identity, and proof that the live
production service was not the target. Appliance and workstation receipts must
bind the same fixture. The producer, promoter, and Manage coordinator use the
job name `Verify published NixOS release in an isolated fixture`.

## Recovery

No canceled Ubuntu workflow is resumed. Manage keeps new retry journals under
`components/nixos-v1`; old journals, bundles, tags and published bytes remain
historical evidence. A failed NixOS run retains its own exact run/attempt and
candidate identities. Never infer qualification from a completed build or relabel
development evidence as production evidence.

Warm and cold jobs keep acceptance documents in separate evidence directories
named with both the GitHub run ID and attempt. The runner requires a new directory
and rejects an existing path before starting qualification; retries never overwrite
or reuse earlier acceptance evidence. On success, failure, or cancellation, the
sudo runner returns directory ownership to the invoking user so normal temporary
directory cleanup can remove it. Partial files remain private and are not uploaded.
If an older run left the shared `cybex-james-evidence` or
`cybex-james-cold-evidence` directory owned by root, retain any needed diagnostics
and remove only that confirmed inactive output through local maintenance. New
attempts use distinct paths and do not depend on deleting historical evidence.

Cleanup stops only owned children and containers, verifies exact network/TAP
ownership, removes disposable database state, and retains bounded evidence. Failed
fixture configuration directories are retained for diagnosis; they contain private
credentials and must not be uploaded. After successful qualification, remove the
owned temporary image-build checkout/configuration and unused build images through
the corresponding maintenance operation. Persistent production databases, services,
trust configuration and installed devices are outside fixture cleanup.

Isolated production qualification stages authenticated workstation runtime bundles privately.
Warm installation requires the exact selected runtime and all three built-in
profiles to deliver successfully; it does not claim prepublication runtime absence.
Independent cold appliance and workstation qualification remains mandatory after staging.

Upgrade and rollback qualification use the retained verified guest artifact listener
on port18082, bound to the exact selected candidate manifest. They do not start
an additional download listener outside the isolated fixture network policy.
