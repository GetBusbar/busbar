# Contributing to Busbar

By contributing, you agree your contributions are licensed under the project's
[Apache-2.0](LICENSE) license.

## Ground rules

- Be respectful and constructive in all project spaces.
- By contributing, you agree your contributions are licensed under the project's
  [Apache-2.0](LICENSE) license.
- Security issues go through [SECURITY.md](SECURITY.md), **not** public issues.

## Build and test on a fresh checkout

The toolchain is pinned by `rust-toolchain.toml`; `rustup` installs it on the first `cargo` call in the
checkout. A C compiler (`cc`) is needed to build the crypto backend (AWS-LC). Then:

```bash
cargo build --locked -p busbar --bin busbar          # the core binary, target/debug/busbar
cargo test --locked -p <crate>                        # one crate's tests
cargo install cargo-nextest --locked                  # the runner CI uses
cargo nextest run --locked --workspace --features busbar-kernel/openapi-schema,busbar-core-admin/openapi-schema
cargo test --locked --workspace --doc --features busbar-kernel/openapi-schema,busbar-core-admin/openapi-schema
```

The last two are what CI's `test` job runs. [Testing](docs/testing.md) says where each kind of test
lives, and [What CI checks](docs/ci.md) lists every check a change is held to, on every change and on
a release.

## How a change lands

1. Branch `lane-<name>` from `origin/dev`. `predev` is retired.
2. Before you ship, format, lint and run the few tests directly covering the change. Full
   behavior suites and supply-chain checks run in CI. Follow the current
   owner-authorized runner path for the branch; a local quick check is not final certification.

   ```bash
   cargo fmt --all
   cargo metadata --format-version 1 >/dev/null   # refreshes a stale Cargo.lock
   ```

   Final CI evidence binds fmt, clippy/workspace lints, behavior tests,
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
- Fixing a defect: a finding with a sibling is a missing choke point, not one bug. Fix the class at its
  choke point (the one place every sibling passes through), route every sibling through it, attach ONE
  class-level test there, and name the RED-before in the PR. A later sibling of an already fixed family
  means the class was never fixed: build the choke point that should have been built.
- Bring unresolved design questions to the owner with the current code and a concrete proposal.

## Cutting a release

After tagging, run `tests/migration-corpus/refresh.sh` so the new release's `config.yaml` joins the
corpus (see `tests/migration-corpus/README.md`).
