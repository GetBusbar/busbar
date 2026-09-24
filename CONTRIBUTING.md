# Contributing to Busbar

Thanks for your interest in improving Busbar. This document covers how to build,
test, and submit changes.


## Cutting a release: refresh the migration corpus

After tagging, run `tests/migration-corpus/refresh.sh` so the new release's `config.yaml` joins the
corpus. `crates/busbar/tests/migration_corpus.rs` then asserts, on every CI run, that a config from
that version still migrates to whatever the current shape is.

The point is that the guarantee grows automatically: an operator on any released version can run
`busbar --migrate-config` and get something that boots. See
`tests/migration-corpus/README.md` for why it holds real shipped files rather than fixtures.

## Ground rules

- Be respectful and constructive in all project spaces.
- By contributing, you agree your contributions are licensed under the project's
  [Apache-2.0](LICENSE) license.
- Security issues go through [SECURITY.md](SECURITY.md), **not** public issues.

## Development setup

Busbar is a single Rust binary. You need a recent stable toolchain
(`rustup` recommended).

```bash
cargo build              # debug build
cargo test               # run tests
cargo clippy --all-targets -- -D warnings   # lints must be clean
cargo fmt --all          # format before committing
```

Run locally against the shipped example config (two YAML files; keys are supplied
via the env vars named in `config.yaml`):

```bash
export BUSBAR_CLIENT_TOKEN=dev-token
export ANTHROPIC_KEY=sk-ant-...      # any provider key referenced by config.yaml
BUSBAR_PROVIDERS=./providers.yaml BUSBAR_CONFIG=./config.yaml cargo run
curl -s localhost:8080/healthz
curl -s -H "Authorization: Bearer $BUSBAR_CLIENT_TOKEN" localhost:8080/stats | jq
```

See [docs/configuration.md](docs/configuration.md) for the full config reference.

## Before you open a pull request

1. **`cargo fmt --all`** — code must be rustfmt-clean.
2. **`cargo clippy --all-targets -- -D warnings`** — no warnings.
3. **`cargo build && cargo test`** — green.
4. Add or update tests for any behavior change. The circuit-breaker disposition
   logic in particular should be covered by tests, not just inspection.
5. **No `_ =>` catch-all arms** in disposition/breaker `match` statements — the
   exhaustive match is how the compiler enforces that every failure mode is
   handled. This is a project invariant.
6. **`cargo xtask gate structure-lint`** — green, and
   `cargo xtask gate structure-lint --selftest` before you believe it. Beyond code
   layout it enforces the remediation contract's choke-point registry.
7. Update documentation when you change behavior or config.

## Fixing a defect: the remediation contract

Read [docs/testing.md § The remediation contract](docs/testing.md#the-remediation-contract)
before fixing a bug. In short:

- **A finding with a sibling is not a bug — it is a missing choke point.** If the
  same mistake is possible at a second call site, fix the class, not the instance.
- **The fix is the choke point + ONE class-level test**, not N patched instances
  with N tests.
- **A repeat sibling means the class was never fixed**: the previous
  remediation patched an instance instead of the class.
- A defect test must be **contract-derived**, **RED-demonstrated**, or
  **cross-checked by an independent oracle** — a `assert_eq!(actual, <inline
  constant>)` that restates the implementation guards nothing.

Your changeset should name the choke point it attaches to, its one class-level
test, and the RED-before note (`RED at <sha>: <failure line>`).

## Commit & PR conventions

- Keep commits focused; squash noisy WIP commits before opening the PR.
- Write a clear PR description: what changed, why, and how it was verified.
- Reference any related issue.
- Stage files by name; avoid sweeping `git add -A` that pulls in unrelated changes.

### Committing while somebody else is working the same checkout

`git add -A` is not the only way to take work that is not yours, and the
alternatives have their own edges. If more than one person (or agent) is editing
one working tree at once, read all three of these before you commit.

**1. `git add -A` takes whatever is on disk, including a staged rename you did
not make.** A `git mv` stages immediately, so an unrelated `git add -A` in
another shell can carry your half-finished file move into someone else's commit.
The file lands at its new path with its old contents and no `mod` declaration
updated — which is how `crates/busbar-contract/src/records.rs` arrived in the
tree as an orphan that broke `cargo check -p busbar-kernel-ledger` with `E0583`.
Stage by explicit path, every time.

**2. `git commit -o <paths>` takes WORKTREE content for those paths — including
edits that are not yours.** `--only` disregards the index and commits what is on
disk, so if another agent has edited one of your files since you last looked,
their work ships inside your commit. Before committing a shared file, diff it:

```sh
git diff HEAD -- <path> | grep -E '^[-+]' | grep -vE '^[-+]\s*(//|$)'
```

A non-comment hunk you do not recognise is somebody else's. A surface-line count
that moves when you only edited comments is the same signal from the other
direction — a comment-only edit must measure zero.

**3. The plumbing route (`commit-tree` + `update-ref`) leaves the shared index
holding a REVERT of the commit you just made.** This is the dangerous one,
because nothing warns you.

Building a commit in a private index is the safe way to commit a surgical blob
without touching the worktree:

```sh
export GIT_INDEX_FILE=/tmp/mywork.index
git read-tree HEAD
git update-index --add --cacheinfo 100644,<blob>,<path>   # repeat per path
tree=$(git write-tree)
commit=$(git commit-tree "$tree" -p "$old_head" -F msg.txt)
# compare-and-swap so a concurrent commit cannot be lost:
git update-ref -m "<why>" refs/heads/<branch> "$commit" "$old_head"
```

**The footgun:** `update-ref` moves the branch but does not touch the *shared*
index, which is still populated against the OLD head. Your paths therefore show
as `MM` — and the staged half is the pre-commit content, i.e. an undo of your
own commit. A bare `git commit` run in that state publishes that revert.

Detect it immediately after `update-ref`:

```sh
git diff --cached --stat -- <your paths>     # MUST be empty
```

If it is not empty, fix the index only, naming **only your own paths**:

```sh
git reset HEAD -- <your paths>               # index only; worktree untouched
```

Never `git reset` without paths here, and never `git reset --hard`: other
people's staged files live in that same index and a bare reset unstages all of
them. `git stash` is worse — it sweeps every uncommitted change in the tree into
your stash, including work you cannot see. Do not use it in a shared checkout.

## Architecture

The circuit breaker — the upstream-vs-client failure taxonomy — is the core of the
project; changes there deserve extra care and review. A backend is ejected for
*upstream* faults but never for *client-supplied* 4xx.

## Questions

Open a discussion or issue. We're happy to help you get oriented.
