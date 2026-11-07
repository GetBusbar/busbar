# Contributing to Busbar

Build on current `dev`; its source is the current architecture. Follow the owner's
current change and publication instructions. [CoreFix.md](CoreFix.md) is the proposed
forward redesign, not a description of already implemented behavior. GitHub Actions
is retired; GitHub is the public code mirror.

## Ground rules

- Be respectful and constructive in all project spaces.
- By contributing, you agree your contributions are licensed under the project's
  [Apache-2.0](LICENSE) license.
- Security issues go through [SECURITY.md](SECURITY.md), **not** public issues.

## How a change lands

1. Branch `lane-<name>` from `origin/dev`. `predev` is retired.
2. Before you ship, format, lint and run the few tests directly covering the change. Full
   behavior suites, the assembled oracle and supply-chain checks run in CI. Follow the current
   owner-authorized runner path for the branch; a local quick check is not final certification.

   ```bash
   cargo fmt --all
   cargo metadata --format-version 1 >/dev/null   # refreshes a stale Cargo.lock
   ```

   Final CI evidence binds fmt, clippy/workspace lints, behavior tests, the assembled 1.5.5 oracle,
   and supply-chain checks (both `cargo deny` and `cargo vet`) to the actual final product revision.
3. When authorized to commit/push, push the lane and open a PR into `dev`. Inspect the CI result
   and fix actual failures. QA/main promotion and signed publication require the owner's authority.
4. The PR body says what changed, why, and the ruling or issue it implements. No AI attribution.

## Fixing a defect: the remediation contract and what every PR is held to

- Red-before-green: every behaviour change ships a test that fails without it. Tests live in their
  own files, not inline in production code.
- Preserve current dev behavior except for the change being implemented. Historical
  1.5.5 fixtures are compatibility evidence, not architecture to restore. Do not rewrite
  historical fixtures to conceal a regression.
- A `$` (money) change is its own PR.
- No `_ =>` catch-all arms in the disposition/breaker `match` statements: the exhaustive match is
  how the compiler proves every failure mode is handled. A backend is ejected for upstream faults,
  never for a client-supplied 4xx.
- `git -C` only, no `git stash`, no force-push except `--force-with-lease` on your own branch.
- Fixing a defect: read
  [docs/testing.md § The remediation contract](docs/testing.md#the-remediation-contract). Fix the
  class at its choke point with one class-level test, and name the RED-before in the PR.
- Bring unresolved design questions to the owner with the current code and a concrete proposal.

## Cutting a release

After tagging, run `tests/migration-corpus/refresh.sh` so the new release's `config.yaml` joins the
corpus (see `tests/migration-corpus/README.md`).
