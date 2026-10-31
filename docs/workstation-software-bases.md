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

To a Tiaris that accepts Nest protocol 5 (its compatibility range includes 5),
the report is protocol 5: `workstation_nixpkgs_commits` lists the release pins,
the newest ready detected commit and every ready detected commit a Blueprint
job this Nest still holds uses, and `detected_nixpkgs_commits` lists the
newest 32 detected commits:

```json
{"commit": "6f06d204…", "channel": "nixos-26.05", "last_modified": "2026-10-29T17:25:25Z",
 "nar_hash": "sha256-…", "kernel_version": "6.18.59", "state": "blocked",
 "reason": "build_script_changed", "reason_details": ["wrapper.c"],
 "detected_at": "2026-10-31T03:12:00Z"}
```

`reason` and `reason_details` (at most 50 names) are omitted for ready
commits. A protocol-4 Tiaris gets today's report: the release pins only.

## Detected commits (Nest-driven updates)

Nest checks its NixOS channel itself (Manage
`docs/design/nest-driven-software-updates.md`, sections 1 to 3). No person
reviews an update: the reviewed content of a new commit is derived from that
commit, anchored on what the Nest already admitted at its release pin.

- **When.** Once a day at a random minute between 01:00 and 05:00 in the
  update-schedule time zone (UTC without a schedule), and when Manage's Nest
  configuration carries a newer `software_update_check_requested_at`. The
  channel is `software_update_channel`, default `nixos-26.05`; Nest refuses any
  channel of another NixOS release, and a commit whose `lib.trivial.release`
  differs is never recorded. Only Nests with Blueprint targets that report to
  Manage check.
- **Fetch.** `https://channels.nixos.org/<channel>/git-revision` names the
  commit. `nix flake metadata` records its `lastModified` and `narHash`; every
  later fetch, including Blueprint jobs at the commit, uses
  `github:NixOS/nixpkgs/<commit>?narHash=<recorded>`. A commit already handled
  is skipped (an on-demand check retries one whose evaluation failed);
  network errors record nothing.
- **Commit identities.** `src/software_updates/identities.nix` evaluates every
  identity of `COMMIT_IDENTITIES` from the same nixpkgs attribute; at 74cc63f
  it reproduces all 40 compiled paths exactly. The derived profile maps each
  built-in store item to the commit's one-to-one and renders the commit's
  revision and NixOS version label (`26.05.<yyyymmdd>.<short rev>`) back to
  the pin's before fingerprinting.
- **Reference jobs.** The newest succeeded source-disabled job of each
  Blueprint this Nest built at its pin (at most 8). Without such jobs Nest
  uses the bare Taskbar and Dock profiles, which are not the configurations
  the built-in fingerprints were recorded from: their `/etc` and unit link
  farms are not admitted at the pin, so such a Nest's commits block until it
  has built a Blueprint.
- **Counterparts.** Each reference job is dry-run in isolated stores at the
  pin (built-in profile) and with only nixpkgs replaced at the commit. Every
  local derivation admitted on its own at the pin gets a counterpart: the
  derivation of the same package name (the name up to its version, as Nix's
  `parseDrvName` splits it, after the version label is rendered back) in the
  same job at the commit, with the same builder and attribute names. Several
  derivations of one name pair only when their attributes, with whole store
  paths set aside, match one to one. Each counterpart's content becomes
  reviewed content of the commit's profile, recorded against the pin content
  it replaces:
  - its script fingerprint pairs (and `/etc` zone-independent pairs);
  - its stock materializer commands;
  - the hash at the commit of a reviewed builder file (`source-stdenv.sh`,
    `default-builder.sh`, `substitute.sh`, `builder.pl`, `wrapper.c`) that
    both the pin derivation and its counterpart use.

  A Blueprint job at the commit is then admitted under exactly the pin's
  rules against that profile.

  Why this keeps the trust boundary: everything in the commit's profile is
  produced by nixpkgs at that commit (pinned by `narHash`) from job inputs
  that were already admitted at the pin. A Blueprint cannot add a script, a
  materializer or a builder file that was not admitted at the pin. A
  derivation class or generator without a pin counterpart stays rejected.
  Store paths are not normalized beyond their hashes; the counterpart
  replaces that.
- **Tiaris packages.** Manage's `tiaris-workstation-cache-seeds.nix` (agent,
  gsettings helpers, patched Avahi), evaluated with the commit's nixpkgs and
  the Tiaris source shipped with this Nest (`system-identity.json`). Only
  these top-level derivations may compile at the commit. Every other input
  of theirs (vendored crates, patches, generated schemas) must be cached or
  admitted by the ordinary rules.
- **Readiness.** Every reference job is dry-run again at the commit with the
  full profile:
  - `blocked`, `build_script_changed`: a local script with no pin
    counterpart (rejected on its own, not merely waiting for another
    rejected derivation), or a changed builder file no counterpart vouches
    for;
  - otherwise `blocked`, `source_build_required`, with the first 50
    derivations that would compile;
  - `blocked`, `evaluation_failed`, when evaluation or a dry run fails;
  - otherwise `ready`. The identities, counterpart content and Tiaris
    package derivations are stored with the record
    (`detected_nixpkgs_commits.profile`).
- **Admission.** A Blueprint job is admitted at the release pin or at a
  ready detected commit (`target_not_allowed` otherwise). A job without a
  Blueprint is admitted at its target flake's nixpkgs pin, and a
  `nixpkgs_commit` it names must be that pin. The preflight selects its
  profile by the admitted commit, never by the job's text: the built-in
  profile at the built-in commit, the persisted profile at a ready detected
  commit, and none otherwise, which stops a source-disabled job with
  `source_build_blocked`. A derived profile renders a built-in provider the
  commit replaced to text no reviewed script contains, so a script cannot
  use the pin's providers in place of the commit's.

The first real channel commit, 6f06d204 (2026-10-29), evaluated with the
pin's Nix 2.34.7 and the Taskbar compiler export as the reference job:
107 counterparts, among them changed `etc`, `system-units`, `user-units`,
`udev-rules`, `fc-cache`, Firefox and the system closure (package version
bumps and a new `gnome-session-monitor` user unit). It is blocked only by
`tiaris-observer-shell-schemas`, the gsettings helper's schema input: it
compiles at the commit, and it is not a top-level Tiaris package.

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
