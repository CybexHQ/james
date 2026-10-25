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

## Transition-v1 origin profile

`origin-profile-v1.json` is the separate proposed narrowing addendum, copied
byte-for-byte from the shared profile. It requires independent SPEC and QUALITY
review; it does not revise the original contract or shared signature vectors.
This module intentionally does **not** claim complete legacy origin parity:

- Keep canonical ASCII DNS/IPv4 and unscoped, non-IPv4-mapped IPv6, with exact
  lowercase compressed spelling, HTTPS and nondefault canonical ports.
- Reject **all** IPv4-mapped IPv6 spellings (hexadecimal and dotted tails) and
  all scoped IPv6 (raw `%` and encoded `%25` zones). Legacy Python formatting
  varies by supported runtime version; runtime selection is not protocol policy.
- Apply the same profile to source/target signed objects, contact requests and
  release/evidence crosslinks. Compare signed text exactly; never normalize it.
- Ordinary legacy release tooling and deployed same-origin update validation
  remain unchanged. **Legacy releases outside this profile cannot use the new
  transition-v1 protocol.** Do not relabel their signed origins. Mapped/scoped
  support requires a separately reviewed future profile. Known Manage/dev
  `cybex.net` to `tiaris.com` migration DNS origins are supported.

The profile is a grammar, not a transport allowlist or deployment approval.
Exact environment binding and all caller requirements below remain mandatory.

ISO provisioning-key metadata follows the historical canonical-base64 plus
`trust/ed25519-weak-public-keys.txt` deny-set semantics, including all fourteen
encodings. An arbitrary non-denied encoding is not thereby an authenticated
signer: actual evidence signers still require parsed non-weak keys and strict
signature verification. Do not replace the metadata rule with a different
library's point-validity rule.

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

`origin-profile-v1.json` has SHA-256
`fe129ccdfe5ffa633df3a46a7a18eca940c1e3f68ff049b457ee0a49d86ef956`.
Rust consumes its exact vectors in the primitive, every signed-object origin,
contact request and re-signed source/target evidence tests. `legacy_oracle.py`
is test-only: it explicitly excludes mapped/scoped origins before invoking the
unchanged authoritative Python validator, and separately checks every accepted
vector directly with that validator. The key regression sends its actual
re-signed ISO/compatibility/pair fixtures to this oracle for OpenSSL signature,
raw-hash and legacy semantic checks. Other leaf signatures remain unchanged.

Tests require Python >= 3.11 and OpenSSL, already used by release-tool tests:

```sh
cargo test --offline --locked -j2 origin_transition -- --nocapture
NEST_TRANSITION_TEST_PYTHON=python3.11 cargo test --offline --locked -j2 fully_signed_iso_keys_follow_legacy_deny_set -- --nocapture
python3.13 -B src/appliance/origin_transition/legacy_oracle.py --profile-only
```

Correction verification exercised Python **3.11.15, 3.13.5 and 3.13.14**: all
26 profile vectors matched (9 accepted), and all 32 re-signed key cases matched
(14 deny encodings on both sides rejected, strong-key and non-denied off-curve
metadata controls accepted on both sides). These particular interpreters all
accepted the dotted mapped and raw/encoded scoped legacy origins and rejected
the hexadecimal mapped legacy origin. This observation is not a version-based
protocol rule or a claim about untested interpreter patch versions.
