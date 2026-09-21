# Workstation bundle fixture transport

James advertises additive capability `workstation_netboot_transport_v1`.
Protocol 4, runtime compatibility epoch 1, and the signed workstation descriptor
remain unchanged. Manage may add optional `bundle_transport_url` to the unsigned
`workstation_netboot` desired-state wrapper alongside `compatibility_epoch`,
`reconcile_generation`, and `descriptor`. Omission or null uses the signed URL.
Older James versions must never receive the override: Manage emits it only for
explicitly allowlisted qualification devices advertising the capability.

The override must be exactly
`http://<RFC1918-IPv4-literal>:<explicit-port>/<signed-bundle-filename>`.
Ports are canonical decimal 1–65535, including explicit port 80. James rejects
loopback, IPv6, DNS names, public/special addresses, credentials, encoded paths,
extra path segments, query strings, fragments, whitespace, and parser-normalized
spellings. The filename must match the desired signed descriptor, not a latest
release selected independently. HTTP requests disable proxies and redirects.

James verifies the original descriptor with normal signature and HTTPS identity
policy before accepting the transport, even when the historical development
`allow_private_release_urls` flag is enabled. The override does not authorize
private source archives. Existing packaged-source verification, generation and
version watermarks, signed length/hash, archive, manifest and component checks
remain mandatory. Transport validation precedes network I/O and also runs before
reuse of a complete staged download.

Only retry bookkeeping and partial-download identity include the transport hash.
Changing the override cannot inherit a terminal retry hold or resume bytes from
another descriptor/transport pair; superseded same-bundle partials are removed.
The stored active descriptor, version/descriptor watermarks and runtime report
continue to identify the original signed artifact. No transport URL is signed or
reported as the artifact URL. Changing transport alone does not require changing
runtime SemVer or reconcile generation, and cannot lower either watermark.

This capability enables isolated qualification; source/unit tests do not assert
that an offline fixture, release, or production deployment has been qualified.
