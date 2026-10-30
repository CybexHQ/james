# Workstation software bases

A workstation software base is one reviewed nixpkgs commit that Nest builds
Tiaris workstation closures on. The Linux kernel and every app on a
workstation come from it, so kernel and app updates reach computers as a new
base: Tiaris Manage prepares each released Blueprint again on the new base and
the administrator installs it now, in a maintenance window or at next startup
(see Manage's `docs/software-updates.md`).

## What Nest reports

Every Nest report carries `workstation_nixpkgs_commits`: the pinned commits of
its Blueprint build targets (`config::workstation_nixpkgs_commits`). Manage
offers a base to an organization only when every online builder Nest reports
its commit, and tells the administrator which Nest needs an update otherwise.
Nests that predate the field build only the commit they were released with.

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

1. **Per-commit build profiles.** Move the 88 commit-specific constants
   (`TRUSTED_*`, `PINNED_*`, the reviewed tool-input lists and
   `PINNED_DESKTOP_NIXOS_GENERATOR_FINGERPRINTS`) into a
   `ReviewedWorkstationPin` value per commit, select it from
   `spec.nixpkgs_commit`, and pass it to the about twenty preflight functions
   that use them. The existing values become the `74cc63f` profile unchanged,
   so current builds keep exactly today's checks.
2. **Admission per profile.** Write one governed Blueprint target per reviewed
   profile (`governed_blueprint_build_target`, `storage::nest_config` and the
   appliance update path that preserves `config.toml`), so
   `workstation_nixpkgs_commits` lists each one and `build_target` admits a job
   only for a commit with a profile.
3. **Seed outputs per commit.** `nixos-appliance/workstation-cache-seeds.nix`
   carries the custom workstation outputs that are absent from
   cache.nixos.org, built at the Nest pin. Build them for every reviewed
   workstation commit (the Manage seed module, evaluated with each commit's
   nixpkgs), so a source-disabled build at a new commit finds them.
4. **Review each new commit.** Run a source-disabled qualification build of the
   built-in Blueprints at the new commit. Every derivation the preflight
   refuses is reported in `source_build_candidates`; review the changed
   scripts against the previous profile (most differ only in store paths) and
   record the new profile. This review is the Cybex approval the software base
   document then signs.
5. **Publish with the release.** Add `tiaris-software-bases.json` to the
   release workflow next to `tiaris-nest-release-compatibility.json`: sign it in
   the signing step, include it in `SHA256SUMS`, the qualification bundle and
   the published assets, and verify it with `software-base.py verify`.

Until then, Manage shows the built-in base only and offers no update.
