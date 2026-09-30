# Historical isolated Manage image experiments

These inactive source archives preserve two detached-worktree experiments reviewed
against James main `5643a38f315e46106a6884574b2fa55a26897e22` on 2026-09-30.
They are source records, not qualification results or supported build entry points.
No fixture configuration, credentials, private runtime state, or release evidence
is included. The original spelling and APIs are preserved in the archived bytes.

## Offline images prototype

`offline-images-source` originated at
`308e2b49de3f201afccbd2f1f193c79b6163ec3b`. Its artifact coordination,
per-release image checks, release selection, and explicit transport environment
were integrated by `c2a9fbef432ec2eb8826ea71e6796da3dec726b7` and subsequently
extended on main. The dirty prototype matches that integrated implementation
except that it omits the later `fchmod` fix and the accompanying umask regression
test. Restoring the prototype would remove those fixes.

The minimal historical patch is therefore relative to the integrated commit
`c2a9fbef432ec2eb8826ea71e6796da3dec726b7`, rather than duplicating its already
committed implementation. The manifest records both bases and the exact hashes of
all four source files observed in the original dirty worktree. Applying the patch
to its reconstruction base reproduces all four files.

## Separate image builder prototype

`isolated-manage-images-source` originated at
`033566055cd4a6171f5b84d24099c939a41e023d`. Its separate Python builder was
superseded by the production fixture preparation flow introduced in
`3eaf215992e6b526e0222490a778303c7dcbae39`, now maintained in
`nixos-appliance/qualification/prepare-fixture-config.py`. Its unique experiment
separated the signed full compatibility-contract hash from a smaller compiled
projection and tested source, signature, image-label, and failed-build cleanup
checks. That projection experiment was never integrated into the live James
fixture harness.

This prototype also predates the Tiaris rebrand and later cold-only qualification,
source admission, upstream networking, and fixture cleanup behavior. It requires
distinct predecessor/candidate images even when their compatibility projections
can share an image. Its model tests do not establish real build or qualification
success. It should not be applied directly to current main.

The historical patch records four tracked-file changes against the exact original
base. The two new Python files are preserved byte-for-byte under `source/` with
`.txt` appended to their original filenames. Applying that patch to the recorded
base and copying those text files back to their manifest paths reproduces all six
modified or untracked source files. The manifests retain original modes and
SHA-256 checksums; the `.txt` files remain inactive in this repository.

Both reconstruction bases are already reachable from main. The historical
patches omit context lines and require `git apply --unidiff-zero`; their manifests
bind the exact base and reconstructed source contents. Verification checked patch
application and every reconstructed source checksum. The original private
snapshots and worktrees were retained while this archive was prepared.
