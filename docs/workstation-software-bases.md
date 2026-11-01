# Workstation software bases

A workstation software base is one reviewed nixpkgs commit that Nest builds
Tiaris workstation closures on. The Linux kernel and every app on a
workstation come from it, so kernel and app updates reach computers as a new
base: Tiaris Manage prepares each released Blueprint again on the new base and
the administrator installs it now, in a maintenance window or at next startup
(see Manage's `docs/software-updates.md`).

## What Nest reports

Every Nest report carries `workstation_nixpkgs_commits`: the commits this Nest
can build. Manage offers a base to an organization only when every online
builder Nest reports its commit, and tells the administrator which Nest needs
an update otherwise. Nests that predate the field build only the commit they
were released with.

To a Tiaris that accepts Nest protocol 5 (its compatibility range includes 5;
`protocol/compatibility.json` is byte-identical with Manage's: Tiaris stays
protocol 4 and accepts Nest protocols 4 and 5), the report is protocol 5:
`workstation_nixpkgs_commits` lists the release pins, the newest ready
detected commit and every ready detected commit a Blueprint job this Nest
still holds uses. Two fields are added:

```json
{"detected_nixpkgs_commits": [
   {"commit": "6f06d204…", "channel": "nixos-26.05", "last_modified": "2026-10-29T17:25:25Z",
    "nar_hash": "sha256-…", "kernel_version": "6.18.59", "state": "blocked",
    "reason": "source_build_required", "detected_at": "2026-10-31T03:12:00Z"}],
 "software_update_checked_at": "2026-10-31T03:12:00Z"}
```

- `detected_nixpkgs_commits` is always the Nest's full current list (at most
  32: ready commits a Blueprint job still uses first, then the newest); each
  report replaces the previous one in Manage. When the Nest cannot read its
  records it omits the field rather than send an empty list. `reason` is set
  only for blocked commits; the names behind it stay in the Nest's record.
- `software_update_checked_at` is when a channel check last completed,
  whether or not it found a new commit; a failed check does not move it.

A protocol-4 Tiaris gets today's report: the release pins only.

## Detected commits (Nest-driven updates)

Nest checks its NixOS channel itself (Manage
`docs/design/nest-driven-software-updates.md`, sections 1 to 3). No person
reviews an update: the reviewed content of a new commit is derived from that
commit and the shipped Tiaris source alone, anchored on what the release pin
admits.

- **When.** Once a day at a random minute between 01:00 and 05:00 in the
  update-schedule time zone (UTC without a schedule), and when Manage's Nest
  configuration carries a newer `software_update_check_requested_at`. The
  channel is `software_update_channel`, default `nixos-26.05`; Nest refuses any
  channel of another NixOS release, and a commit whose `lib.trivial.release`
  differs is never recorded. Only Nests with Blueprint targets that report to
  Manage check.
- **Fetch.** `https://channels.nixos.org/<channel>/git-revision` names the
  commit. `nix flake metadata` records its `lastModified` and `narHash`; every
  later fetch uses `github:NixOS/nixpkgs/<commit>?narHash=<recorded>`: the
  check, Blueprint jobs, their package-version probe and the `nixpkgs_flake`
  in their result metadata.
- **Provenance.** Through the GitHub API, the commit must be on the
  channel's branch of NixOS/nixpkgs (`compare/<commit>...<channel>` is
  `identical` or `ahead`: the commit is the branch tip or an ancestor of it)
  and descend from the release pin (`compare/<pin>...<commit>` is `ahead`). A
  fork-only commit diverges from the branch. Any failure, including the
  API's rate limit, records `blocked`, `provenance_unverified`.
- **Retries and time.** A recorded commit is evaluated again when its
  evaluation, provenance or disk check failed at least a day ago, and when
  it is blocked and another Nest build or shipped Tiaris source evaluated it
  (an update may ship the references or reviewed content it lacked); a
  request from Manage repeats only the channel lookup. One commit's
  evaluation is bounded to 60 minutes (`evaluation_failed`, `time limit`).
- **Disk.** The check needs 4 GiB free in the build work directory
  (`insufficient_disk` otherwise, retried daily). Each dry run keeps its
  isolated store (a nixpkgs source of about 330 MB) only while it runs: the
  local work, derivation records and source-file hashes are kept, the store
  is removed, and classification runs from them. The 6f06d204 check peaked
  at 652 MB. Its work directory is removed on every exit, including a
  timeout; interrupted check directories and isolated stores are removed at
  startup.
- **Commit identities.** `src/software_updates/identities.nix` evaluates every
  identity of `COMMIT_IDENTITIES` from the same nixpkgs attribute; at 74cc63f
  it reproduces all 40 compiled paths exactly. The derived profile maps each
  built-in store item to the commit's one-to-one, renders the commit's
  revision and NixOS version label (`26.05.<yyyymmdd>.<short rev>`) back to the
  pin's before fingerprinting, and renders a built-in provider the commit
  replaced to text no reviewed script contains.
- **References.** Only configurations of the shipped Tiaris source: each
  reference Blueprint in `deploy/nixos/reference-blueprints/<name>/`
  (`blueprint.nix` and `desktop.nix`, the built-in Blueprints' compiler
  exports; at most 16), configured exactly like a Blueprint job, plus the
  plain Taskbar and Dock profiles of `tiaris-blueprints.nix`. Organization
  Blueprint jobs are never an input. A Tiaris source without reference
  Blueprints records `blocked`, `reference_blueprints_missing`.
- **Counterparts.** Each reference is dry-run in isolated stores at the pin
  (built-in profile) and at the commit. Every local derivation admitted on
  its own at the pin gets a counterpart: the derivation of the same role (its
  package name, the name up to its version as Nix's `parseDrvName` splits
  it, after the version label is rendered back) in the same reference at the
  commit, with the same builder and attribute names. Several derivations of
  one role pair only when their attributes, with whole store paths set
  aside, match one to one. The counterpart's script fingerprint pairs (and
  `/etc` zone-independent pairs), stock materializer commands and changed
  reviewed builder files used on both sides become reviewed content **of that
  role only**, recorded against the pin content they replace. A Blueprint job
  at the commit is then admitted under exactly the pin's rules, each
  derivation seeing only its own role's content. The pin admits the NixOS
  system closure (`nixos-system-<host>`) by its store-normalized script
  alone, since its executables follow the configuration; its counterpart
  maps that half, in one `nixos-system` role whatever the host name, so an
  organization Blueprint built from the same modules as a reference is
  admitted with its own host name, activation script and App List.

  Why this keeps the trust boundary: every input of the commit's profile is
  the shipped Tiaris source and nixpkgs at that commit, pinned by `narHash`
  and verified to be on the channel's branch after the release pin. A
  Blueprint can neither contribute content nor use one role's content for
  another derivation; what the references do not cover stays rejected, as at
  the pin. Store paths are not normalized beyond their hashes.
- **Tiaris packages.** Manage's `tiaris-workstation-cache-seeds.nix` (agent,
  gsettings helpers, patched Avahi), evaluated with the commit's nixpkgs and
  the shipped Tiaris source, is dry-run in an isolated store. Its local build
  closure may compile at the commit: the top-level packages and every local
  derivation they reach (vendored crates, per-crate builds, patches,
  generated schemas). At most 256 derivations
  (`MAX_TIARIS_PACKAGE_DERIVATIONS`), otherwise `source_build_required`.
  Fixed-output derivations must pass the ordinary fetch rule; local work the
  closure does not reach is not admitted.
- **Readiness.** The commit's dry run of each reference is classified again
  with the full profile (no second evaluation). Every derivation the pin
  admitted in that reference must be admitted at the commit; roles the pin
  did not cover there stay uncovered and are not the commit's regression.
  The outcome is `build_script_changed` (a local script with no counterpart,
  or a changed builder file no counterpart vouches for),
  `source_build_required` (first 50 derivations that would compile),
  `evaluation_failed`, or `ready`.
- **Stored profile.** A ready commit stores its identities, counterpart
  content and Tiaris package derivations with a profile schema version and
  the deriving Nest build (version, release, source and Tiaris source
  revisions). A profile from another schema or build admits nothing and is
  reported `blocked`, `rederivation_pending`, and left out of
  `workstation_nixpkgs_commits`, until Nest derives it again (at startup
  after an update, then at most two per check).
- **Where it is kept.** Not in SQLite: NixOS appliances refuse an update
  whose migration inventory differs from the installed release's, so the
  schema stays that of the published releases (`release/sqlite-migrations.sha256`).
  Each commit is one record `software-updates/detected/<commit>.json` and the
  check state `software-updates/check-state.json` under the Nest state
  directory (`/var/lib/tiaris-nest/state/agent`), written atomically (0600,
  never through a link, size-bounded, `{schema, version, data}`;
  `src/state_files.rs`). A record that is missing, corrupt, or breaks a rule
  the old table enforced (state, reason, profile present when ready, its own
  commit) is treated as absent: the commit is evaluated again and admits
  nothing meanwhile. A stored profile is validated as strictly as before when
  it is used. At most 64 records are kept: every ready commit a Blueprint job
  uses, then the newest.
- **Admission.** A Blueprint job is admitted at the release pin or at a ready
  detected commit (`target_not_allowed` otherwise). A job without a
  Blueprint is admitted at its target flake's nixpkgs pin, and a
  `nixpkgs_commit` it names must be that pin. The preflight selects its
  profile by the admitted commit: the built-in profile at the built-in
  commit, the persisted profile at a ready detected commit, and none
  otherwise, which stops a source-disabled job with `source_build_blocked`.
- **A Blueprint that blocks at the commit.** Its job fails with
  `error_kind: source_build_blocked` and `source_build_candidates` (the
  first 50 derivations it would compile or that have no reviewed
  counterpart); its result metadata names the job's Blueprint and revision
  and `nixpkgs_revision`/`nixpkgs_flake` of the commit, narHash-pinned. A job
  at a commit that is not ready fails with `target_not_allowed`.

The first real channel commit, 6f06d204 (2026-10-29), evaluated with the
pin's Nix 2.34.7: with the Tiaris source as shipped today (no reference
Blueprints) it is `reference_blueprints_missing`. With
`deploy/nixos/reference-blueprints/{taskbar,dock}` from Manage's compiler
exports it is `ready`: 308 counterpart pairs (11 role-scoped fingerprint
pairs for changed `etc`, `system-units`, `user-units`, `udev-rules`,
`fc-cache`, Firefox and the system closure), a Tiaris package closure of 35
derivations, and every derivation the pin admits in each reference admitted.

## Scanning update candidates

Once a detected commit is ready, Manage prepares an update-only candidate of
each released Blueprint (the same release on the new commit) and Nest builds
it like any Blueprint job. When the candidate's closure is built, Nest scans
it (`src/software_updates/findings.rs`, Manage design section 4):

- **Release.** The closure of the release the candidate was prepared from,
  named by the job's `software_update.release_blueprint_revision_id` (a
  field of the build job, next to `build_spec`). A candidate without it is
  `skipped` (`missing_release_hint`) and scanned once Manage names the
  release; Nest never guesses a baseline. Manage prepares Blueprints for
  computers per hardware cohort (installer-target jobs), so these are
  candidates and releases too: a candidate is compared with the release of
  its own kind and, where one was built, its own hardware cohort (hardware
  module and driver policy), otherwise of any cohort. One scan covers a
  commit and revision.
- **Closures.** Nest serves finished closures from its cache and drops a
  job's out-link when it ends, so the nightly garbage collection removes the
  closure and its derivations from the store. A release or candidate whose
  closure or derivations are gone is built again from its own job, with the
  same validation, admission, memory lease and source policy as its worker,
  into the job's out-link, which is removed once the scan is done. While the
  Nest has no memory for that build the scan waits; a failed build fails the
  scan with the closure's reason.
- **Scan.** One `vulnix --json --closure` run over the release and the
  candidate: their runtime closures, matched by package name and version.
  vulnix refreshes its NVD database (at most every two hours) before it
  scans and commits to it on every run, so separate runs could judge the two
  by different data; one run cannot. Each finding names its derivation and
  belongs to the closure whose derivations include it (a recorded deriver in
  the store, or a valid derivation declaring the path); a finding of neither
  counts as the candidate's, so it never shows as fixed. vulnix runs at
  nice 19 and idle I/O priority with 8 GiB of address space and 40 minutes;
  its NVD database is cached in `<data_dir>/vulnix`
  (`/var/lib/tiaris-nest/state/agent/vulnix`, about 200 MB; the first download
  took 50 seconds and 2.5 GiB resident on The Beast). vulnix silently skips
  closure paths whose derivation is not in the store, so a closure in which
  fewer than 90% of paths have one fails instead of reporting too few fixes.
  `nix path-info`, `nix-store`, `nix derivation show` and `nix eval` run at
  the same priority and memory limit. Scans wait while a build runs; a build
  that starts before the vulnix run defers the scan without recording it.
- **Findings.** The release's advisories the candidate no longer has, most
  severe first, at most 500, with `severity` from the CVSS v3 base score
  (critical ≥ 9.0, important ≥ 7.0, moderate ≥ 4.0, otherwise low; an
  unscored advisory is moderate, as in `tools/software-base.py`). `summary`
  is the start of the NVD description.
- **Package status.** For each App List package ref of the job
  (`software_package_refs`) Nest evaluates `(package.out or package).outPath`
  at the narHash-pinned commit, as Manage's cache catalog does (all refs at
  once, or one by one when that fails), and asks cache.nixos.org, then the Tiaris software cache with the
  token Manage sent: `public_cache`, `software_cache`, or
  `preparation_required` (also when this Nest has no software-cache access).
  A ref that does not evaluate, or whose cache gives another answer than
  found or absent, is left out, so Manage keeps its compiled catalog for it.
  A lookup that decides none of the refs is a failed scan
  (`package_status_unavailable`) and is retried.
  Manage replaces a Nest's status list for a commit with each finding it
  stores, so every finding of a commit carries the status of all scanned refs
  at that commit (at most 128).
- **Once per candidate.** One scan per commit and Blueprint revision. A
  failure (`release_closure_unavailable`, `closure_unavailable`,
  `derivations_unavailable`, `scan_failed`, `package_status_unavailable`) is
  logged and kept with its detail in its scan record
  (`software-updates/scans/<commit>.<revision>.json`, next to
  `software-updates/candidate-hints.json` with the releases Manage named);
  it produces no finding and never blocks a build. It is retried at most
  daily, three attempts in all. A corrupt scan record is no scan: the
  candidate is scanned again. Scans of jobs Nest no longer holds are removed,
  and at most 1024 are kept.

To a protocol-5 Tiaris each report carries the successful scans of
candidates Nest still holds at commits it reports ready, newest first (at most
256 and 4 MiB together); they are the first lane dropped when a report would
exceed its size limit. Manage stores them idempotently:

```json
{"software_update_findings": [
   {"commit": "6f06d204…", "blueprint_revision_id": "<candidate revision>",
    "scanned_at": "2026-10-31T05:10:00Z",
    "advisories": [{"id": "CVE-2026-5450", "package": "glibc", "severity": "critical",
                    "score": 9.8, "summary": "…", "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-5450"}],
    "package_delivery": [{"ref": "firefox", "status": "public_cache"},
                         {"ref": "google-chrome", "status": "software_cache"}]}]}
```

## Publishing a base

`tools/software-base.py` drafts, signs and publishes the signed
`tiaris.software-base.v1` documents Manage accepts.

```sh
# Security fixes are the advisories of the previous base's reference closure
# that the new base no longer has: scan both with `vulnix --json`.
python3 tools/software-base.py draft \
  --commit <40-hex commit> --base-id nixos-26.05-2026-10-23 \
  --title "Security update · 23 October" --captured-at 2026-10-23T06:00:00Z \
  --support-ends-at 2026-12-31T23:59:59Z --evaluate-kernel --previous-kernel 6.12.48 \
  --previous-vulnix previous.json --vulnix current.json \
  --supersedes nixos-26.05-2026-10-16 > draft.json
# Review draft.json: title, summary, advisories and highlights are what
# administrators read. Then sign with the release key and publish.
python3 tools/software-base.py sign --private-key release-key.pem \
  --trusted-public-key "$TIARIS_NEST_UPDATE_TRUSTED_PUBLIC_KEY" --output-dir signed draft.json
python3 tools/software-base.py feed --output dist/tiaris-software-bases.json signed/*.json
python3 tools/software-base.py verify \
  --trusted-public-key "$TIARIS_NEST_UPDATE_TRUSTED_PUBLIC_KEY" dist/tiaris-software-bases.json
```

The signed bytes are `TIARIS-SOFTWARE-BASE-V1\n` followed by the canonical
JSON (sorted keys, compact, UTF-8) of the document without `signature`. Manage
fetches `tiaris-software-bases.json` from the latest release of this repository
every six hours, and platform administrators can import a feed or document
directly (`POST /v1/software-bases/import`). The feed is cumulative: list every
base the release can build, not only the newest.

## Tracking the channel

The `Software base tracker` workflow runs daily (and on demand) and calls
`tools/software-base-tracker.py check`. When `nixos-26.05` names a commit that
no published base carries, it:

- evaluates a reference set of workstation packages (kernel, desktops, common
  apps, system services) at the newest published base and at the channel
  commit, and reads their runtime closures from cache.nixos.org narinfo
  metadata without downloading anything;
- scans both closures with vulnix in the same run and keeps only findings whose
  outputs are in the runtime closure, so build-only tools are not counted;
- writes an unsigned draft whose advisories are the vulnerabilities the new
  commit no longer has, with `kind` and `severity` set from them;
- opens one review issue per commit, titled with its severity, for example
  `[critical] Security software base candidate: nixos-26.05 6f06d204d8f2 (422 fixes)`.
  The draft is the run's `software-base-draft` artifact.

vulnix matches advisories by package name and version, so review them before
approving. The tracker never signs: reviewing the commit (below), setting
`approved_at` and signing the draft remain the Cybex approval.

```sh
python3 tools/software-base-tracker.py check --output-dir out \
  [--feed tiaris-software-bases.json] [--vulnix PATH]
```

## Building a second commit

A base is useful only once Nest can build it, and Nest builds without compiling
from source. Its source-build preflight (`src/build.rs`) accepts a derivation
that would build locally only when it is one of the reviewed materializers:
exact stdenv, bash, perl, link-farm and substitution builder store paths,
reviewed tool inputs, and the normalized fingerprints of the NixOS and desktop
generator scripts of the built-in Blueprints. All of these values belong to
nixpkgs `74cc63f`, and `build_target` refuses any Blueprint job whose commit is
not the configured target's (`target_not_allowed`).

Supporting more than one commit therefore needs, in this order:

1. **Per-commit build profiles.** Done: the preflight asks a
   `WorkstationBuildProfile` (`src/build/profile.rs`), selected from
   `spec.nixpkgs_commit`, for every commit identity: the stdenv variants and
   bash, the link-farm and substitution builders, the reviewed tool inputs and
   the security-wrapper include path (`COMMIT_IDENTITIES`). Checks name each
   identity by its `74cc63f` path; the built-in profile returns those bytes
   unchanged, and a path outside the table never matches. Reviewed content
   stays commit-independent: store-normalized fingerprints, stock commands
   and the builder file hashes. A profile fingerprints a script as the
   reviewed script it renders, so its executable-pinned half admits exactly
   that commit's tool providers.
2. **Admission per profile.** Done for detected commits: `build_target`
   admits a ready detected commit and `workstation_nixpkgs_commits` reports it
   (above). Installed Nests need no `config.toml` change.
3. **Seed outputs per commit.** Done for detected commits: the top-level
   Tiaris package derivations of the commit are admitted to compile and their
   outputs are signed with the Nest cache key like any built output.
   `nixos-appliance/workstation-cache-seeds.nix` still carries the pin's.
   The Tiaris software cache (`https://cache.tiaris.com`, Manage
   `docs/software-cache.md`) carries the rest Nest would otherwise prepare:
   unfree apps, NVIDIA's driver and the directory sign-in stacks. Nest lists it
   after cache.nixos.org and authenticates with the token Manage sends; build
   it for a new commit before that base becomes the default.
4. **Review each new commit.** Done for detected commits without a person:
   counterparts of what the pin admitted are the review (above). A commit
   blocked with `build_script_changed` names the content without a
   counterpart; only a Tiaris release can admit that.
5. **Publish with the release.** Add `tiaris-software-bases.json` to the
   release workflow next to `tiaris-nest-release-compatibility.json`: sign it in
   the signing step, include it in `SHA256SUMS`, the qualification bundle and
   the published assets, and verify it with `software-base.py verify`.

Until then, Manage shows the built-in base only and offers no update.
