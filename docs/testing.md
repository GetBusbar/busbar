# Testing

How to run Busbar's tests on a fresh checkout, and where each kind of test lives. What CI runs on
every change, and which of its jobs block, is on [What CI checks](ci.md).

## Run the tests

The toolchain is pinned by `rust-toolchain.toml`; `rustup` installs it on the first `cargo` call in
the checkout. A C compiler (`cc`) is needed to build the crypto backend (AWS-LC).

```bash
cargo build --locked -p busbar --bin busbar          # the core binary, target/debug/busbar
cargo test --locked -p <crate>                        # one crate's tests
cargo install cargo-nextest --locked                  # the runner CI uses
cargo nextest run --locked --workspace --features busbar-kernel/openapi-schema,busbar-core-admin/openapi-schema
cargo test --locked --workspace --doc --features busbar-kernel/openapi-schema,busbar-core-admin/openapi-schema
```

The last two are what CI's `test` job runs. CI also runs formatting, lints with warnings denied,
the supply-chain checks (`cargo deny`, `osv-scanner`, `cargo vet`) and the conformance suites; the
exact list is in [What CI checks](ci.md).

## Where tests live

- **Unit and crate tests** sit in each crate, in their own test files rather than inline in
  production code.
- **Root and distribution tests** exercise the `busbar` binary: the `busbar` crate's own tests and
  `dist/default/tests`.
- **The upgrade oracle** judges a 1.6.0 build against recordings of the published 1.5.5 binary.
  Its corpus and the signed accepted differences are in [testing/shadow-oracle](../testing/shadow-oracle);
  the [migration guide](migration-1.6.md) describes the differences an operator sees.
- **Conformance and evidence rigs** run official third-party suites against a built binary, with a
  known-good control leg beside the subject leg. [testing/README.md](../testing/README.md) lists them.
- **Plugins** test themselves in their own repositories against a published core, never against
  another plugin.

## What a test is held to

A behavior change ships a test that fails without it: the failing test is committed first, then the
fix. A test is never weakened to make a change pass; a test that asserts something the design no
longer wants is changed to assert what it does want, and the change is recorded in the commit.
See [CONTRIBUTING](../CONTRIBUTING.md).
