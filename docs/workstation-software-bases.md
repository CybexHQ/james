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
`docs/design/nest-driven-software-updates.md`, sections 1 to 3):

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
- **Build profile.** `src/software_updates/identities.nix` evaluates every
  commit identity of `COMMIT_IDENTITIES` from the same nixpkgs attribute; at
  74cc63f it reproduces all 40 compiled paths exactly. It also hashes the
  reviewed builder files (`source-stdenv.sh`, `default-builder.sh`,
  `substitute.sh`, the replaced `builder.pl` and `wrapper.c`). The derived
  profile maps each built-in store item to the commit's one-to-one and renders
  the commit's revision and NixOS version label
  (`26.05.<yyyymmdd>.<short rev>`) back to the pin's, so reviewed scripts are
  fingerprinted exactly as the pin's: only the commit's own providers pass the
  executable-pinned half.
- **Tiaris packages.** Manage's `tiaris-workstation-cache-seeds.nix` (agent,
  gsettings helpers, patched Avahi), evaluated with the commit's nixpkgs and
  the Tiaris source shipped with this Nest (`system-identity.json`), is
  dry-run in an isolated store. The derivations it would compile (at most 512)
  are the only real compiles the commit admits; the preflight admits exactly
  these derivations at that commit and no other.
- **Readiness.** The newest succeeded source-disabled job of each Blueprint
  this Nest built at its pin (at most 8) is prepared again with only nixpkgs
  replaced and dry-run in an isolated store with the derived profile. Without
  such jobs Nest dry-runs the bare Taskbar and Dock profiles. The commit is:
  - `blocked`, `build_script_changed`, with the names of reviewed builder
    files whose bytes changed and of local scripts rejected on their own (not
    merely waiting for another rejected derivation);
  - otherwise `blocked`, `source_build_required`, with the first 50
    derivations that would compile;
  - `blocked`, `evaluation_failed`, when evaluation or a dry run fails;
  - otherwise `ready`. The derived profile and Tiaris package derivations are
    stored with the record (`detected_nixpkgs_commits` table).
- **Admission.** `build_target` admits a Blueprint job at the release pin or
  at a ready detected commit (`target_not_allowed` otherwise); the preflight
  selects the commit's profile by `spec.nixpkgs_commit`.

What the first real channel commit shows: at 6f06d204 (2026-10-29, evaluated
with the pin's Nix 2.34.7) every identity derives, and 42 Tiaris package
derivations would compile. It is `build_script_changed`: `wrapper.c` changed,
`user-units` gained `gnome-session-monitor.service`, and `etc`,
`system-units` and the system closure name newer package versions (systemd
260.5, kernel 6.18.59, pipewire, cacert, tzdata). Store-path normalization
covers hashes, not names, so a version bump of a package these assembly
scripts list changes their reviewed content. Until a Tiaris release reviews
such changes, most channel commits will be blocked.

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
3. **Seed outputs per commit.** Done for detected commits: the Tiaris package
   derivations of the commit are admitted to compile and their outputs are
   signed with the Nest cache key like any built output.
   `nixos-appliance/workstation-cache-seeds.nix` still carries the pin's.
   The Tiaris software cache (`https://cache.tiaris.com`, Manage
   `docs/software-cache.md`) carries the rest Nest would otherwise prepare:
   unfree apps, NVIDIA's driver and the directory sign-in stacks. Nest lists it
   after cache.nixos.org and authenticates with the token Manage sends; build
   it for a new commit before that base becomes the default.
4. **Review each new commit.** A commit blocked with `build_script_changed`
   names the scripts and builder files that changed. Review them against the
   previous profile and record the new fingerprints in a Tiaris release.
5. **Publish with the release.** Add `tiaris-software-bases.json` to the
   release workflow next to `tiaris-nest-release-compatibility.json`: sign it in
   the signing step, include it in `SHA256SUMS`, the qualification bundle and
   the published assets, and verify it with `software-base.py verify`.

Until then, Manage shows the built-in base only and offers no update.
