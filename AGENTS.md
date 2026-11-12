# Agent instructions

## Testing (fast testing)
- After a change, run `fast-test` in the repository folder. It tests only what changed since `main` (commits,
  staged and unstaged edits, new files): quick tests here on The Dragon, heavy ones (VMs, Nix, databases, wide
  changes) on The Beast by itself. `fast-test --dry-run` shows what it would run and why.
- Exit 0 passed, 1 failed, 2 couldn't run (say so; don't run the full suite here instead). When it fails, its output
  ends with the failing step's last lines; the whole log is in `.git/fast-test/`.
- Don't run the full test suite and don't wait for GitHub CI. `fast-test --full` runs everything on The Beast, only
  when someone asks for it.
- A failing test runs once more before it counts as failing (fast-test does this itself). Never skip or weaken a test
  to make it pass.
- Every night The Beast runs the full suite of `main`; failures are reported in the morning.
