# Contributing to Busbar

The rules for how a change lands live in one place:
[docs/design/BUSBAR-1.6.0.md, Part 6, "How work lands"](docs/design/BUSBAR-1.6.0.md#how-work-lands-the-pr-flow-and-the-rules-every-contributor-follows).
This page is the short version. Where the two differ, Part 6 wins.

## Ground rules

- Be respectful and constructive in all project spaces.
- By contributing, you agree your contributions are licensed under the project's
  [Apache-2.0](LICENSE) license.
- Security issues go through [SECURITY.md](SECURITY.md), **not** public issues.

## How a change lands

1. Branch `lane-<name>` from `origin/predev`.
2. Before you ship, run the local pre-flight and nothing heavier:

   ```bash
   cargo fmt --all
   cargo metadata --format-version 1 >/dev/null   # refreshes a stale Cargo.lock
   cargo xtask gate abi-header --write            # regenerates the C header
   ```

   Builds, tests, clippy, the gates and the oracle run in CI (`.github/workflows/promote.yml`).
3. Ship it: `cargo xtask ship "<PR title>" [--body <file>]`. It merges `origin/predev`, runs the
   pre-flight, commits its changes, pushes, opens (or reuses) the PR into `predev` and turns on
   auto-merge. Then stop; CI is the proof and a red comes back as a task.
4. The PR body says what changed, why, and the ruling or issue it implements. No AI attribution.

## Fixing a defect: the remediation contract and what every PR is held to

- Red-before-green: every behaviour change ships a test that fails without it. Tests live in their
  own files, not inline in production code.
- Customer-visible bytes stay 1.5.5's. Never bless a golden or a ratchet; `golden/1.5.5` is
  read-only.
- A `$` (money) change is its own PR.
- No `_ =>` catch-all arms in the disposition/breaker `match` statements: the exhaustive match is
  how the compiler proves every failure mode is handled. A backend is ejected for upstream faults,
  never for a client-supplied 4xx.
- `git -C` only, no `git stash`, no force-push except `--force-with-lease` on your own branch.
- Fixing a defect: read
  [docs/testing.md § The remediation contract](docs/testing.md#the-remediation-contract). Fix the
  class at its choke point with one class-level test, and name the RED-before in the PR.
- A design question the spec does not answer: open a `needs-owner` issue with a proposed option.

## Cutting a release

After tagging, run `tests/migration-corpus/refresh.sh` so the new release's `config.yaml` joins the
corpus (see `tests/migration-corpus/README.md`).
