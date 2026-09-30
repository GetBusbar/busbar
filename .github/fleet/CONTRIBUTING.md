# Contributing to @@repo@@

Thanks for your interest in improving `@@repo@@`.

## Ground rules

- Be respectful and constructive in all project spaces (see
  [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)).
- By contributing, you agree your contributions are licensed under the project's
  [Apache-2.0](LICENSE) license.
- Security issues go through [SECURITY.md](SECURITY.md), **not** public issues.

## Layout

Every busbar plugin repo has the same shape. This one is a two-crate Cargo workspace:
`@@stem@@/` holds the plugin's logic and `@@stem@@-plugin/` is the thin `cdylib` that
packages it as a droppable `kind: @@kind@@` plugin. busbar itself is a git dependency
pinned to the commit in `.busbar-ref`. The CI, release and lint configuration are
rendered from [busbar's plugin registry](https://github.com/GetBusbar/busbar/blob/main/plugins.yaml);
change them there, not here.

## Before you open a pull request

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

The README's Tests section names any live backend the full suite needs. Add or update
tests for any behavior change, and update the README when you change behavior or
config. Keep commits focused and describe what changed, why, and how it was verified.
