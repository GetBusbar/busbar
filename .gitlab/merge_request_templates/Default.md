<!-- Thanks for contributing to Busbar! -->

## What & why

<!-- What does this change do, and why? Link any related issue (e.g. Closes #123). -->

## How it was verified

<!-- Commands run, manual testing, new/updated tests. -->

## Checklist

- [ ] `cargo fmt --all` — formatted
- [ ] `cargo clippy --all-targets -- -D warnings` — clean
- [ ] `cargo build && cargo test` — green
- [ ] Tests added/updated for behavior changes
- [ ] No `_ =>` catch-all arms in disposition/breaker `match` statements
- [ ] Docs updated if behavior or config changed
