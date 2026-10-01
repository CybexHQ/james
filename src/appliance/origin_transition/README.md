# Origin transition verification foundation

This module is intentionally **not connected to update admission, daemon DTOs,
capability advertisement, CLI commands, or origin projection**. Existing
same-origin equality checks and legacy update input bounds are unchanged.

`verify_binding` re-verifies the original NixOS install plan with its historical
signature/hash rules, including the original signer still being package-trusted.
It binds protected local organization, session, device, permanent private-key
public fingerprint and original authenticated origin. A protected existing
binding is write-once in its entirety; a protected signed schedule must agree on
incarnation. No reservation or first-incarnation input exists.

`verify_bundle` consumes an already bounded byte snapshot (maximum 8 MiB), not a
pathname or URL. It checks strict C wire objects, the exact retained release key,
the original R/LF/base64 release pair, both independently signed compatibility
assets, all four manifest signatures on each side and their exact cross-links.
Its opaque result retains the exact input bytes. It does not verify/import
closure payloads, prove an actual boot, persist state, or admit a transition.

`verify_acknowledgement` verifies management authority and exact root-request
correspondence. Its result does **not** prove TLS reachability or authorize COMMIT.

## Required callers in the next reviewed slice

- Under the existing root maintenance lock, take a bounded nofollow regular-file
  snapshot, apply ownership/ancestor/hardlink protections and protect the retained
  receipt. Never reopen daemon evidence after verification. Use the new 8 MiB
  bound only on an explicitly capability-negotiated path; do not widen the legacy
  `StoredUpdate` reader or send optional extensions to legacy peers.
- Build the contexts only from protected original installed identity, verified
  source receipt and actual booted generation, plus the authenticated exact update
  request. Source and target origins are exact reviewed environment inputs.
- Enforce the permanent revision/digest/attempt watermark, equal-revision active
  recovery versus terminal no-op, and active-attempt exclusion. Atomically seal
  admission before PREPARE and check expiry again at that boundary. This module
  alone intentionally provides no durable replay resistance.
- Independently import/verify the real closure and its migration inventory;
  inspect immutable candidate identity/compiled origin and retain only sealed B.
- Generate/store each boot's nonce and request from actual target generation,
  closure and toplevel. Root must contact the target directly with verifying TLS,
  no proxy/redirect/CA or daemon transport override. A daemon-staged signed ack
  remains insufficient. Seal COMMIT before making the candidate default.
- Reconcile authenticated boot/origin projections before first-boot validation or
  service exposure, preserve independent network projections, and distinguish a
  postcommit retained-B boot from precommit rollback.

## Fixtures

`vectors-v1.json` is the unchanged shared PUBLIC signature fixture, SHA-256
`54a2db1de704df7c900bcaccf186a192acbfbb3c70a9423dbd163ca0f7cf7dac`.
Its placeholder release identities must fail evidence verification.

`release-fixture.json` contains disposable PUBLIC test signing material and
metadata. The original release-tool message generators and validators produced
and independently checked both sets of manifest signatures and compatibility
signatures. Test-only artifact bytes are not bootable NixOS closures and cannot
serve as lifecycle qualification. Mutation tests re-sign outer compatibility and
pair objects while corrupting leaf signatures, so rejection cannot be explained
by stale outer hashes alone. No production keys, release artifacts or signatures
were used or changed.
