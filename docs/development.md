# Development, onboarding & workflow

Developer-facing guide to building, testing, and extending busbar. For the
operator/runtime view see [operations.md](operations.md) and
[configuration.md](configuration.md). Current dev source is the architecture;
[CoreFix.md](../CoreFix.md) describes the proposed changes and crate ownership.

Contribution mechanics (PR checklist, formatting, the exhaustive-match invariant)
live in [CONTRIBUTING.md](../CONTRIBUTING.md), this doc covers the codebase map
and the two common extension tasks.

---

## Current 1.6.0 ownership

The composition root is `crates/busbar/src/root/`; `dist/default/Cargo.toml` assembles the shipping
plugin set. `busbar-kernel` owns neutral admission, routing and governance, `busbar-contract` owns
shared types and the memory ABI, `busbar-core-connector` owns connections, and `plugin-loader`
owns native loading. Protocol intelligence belongs to plane, transport and connector plugins,
not a new registry or protocol handler inside core. Add a protocol in its owning plugin using
[the SDK migration guide](plugin-sdk-migration-1.6.md) and [the plugin guide](plugins.md).

## Build / test / lint

Use the repository's pinned toolchain. Locally run formatting, linting and only the tests directly
covering the change; CI runs the full suites. Build the actual default distribution when checking
the assembled product, since the core-only binary deliberately links no production plugins.

```bash
cargo build                                   # core workspace debug build
cargo build --release --locked --manifest-path dist/default/Cargo.toml --target-dir target
# assembled release binary -> target/release/busbar
cargo test -p <changed-package> <test-filter>  # only the directly affected cases locally
cargo clippy --all-targets -- -D warnings     # lints must be clean (treat warnings as errors)
cargo fmt --all                               # format (rustfmt.toml in repo)
```

### The settings-leak lint

`cargo xtask gate settings-leak` enforces one rule: **an admin READ may serve an
opaque `settings:` bag's KEY NAMES, never its values.** Those bags carry
`SecretRef`s (an OIDC `client_secret`, a hook `licenseKey`, a store `url` with a
password), and the same defect has now been found in four independently written
projections, each with a doc comment asserting the bag was safe.

Its **scan root is the whole `crates/busbar/src` tree** (minus test trees), not
just `admin/**`. An admin handler serializes whatever type it is handed, and that
type may be declared anywhere in the engine. `hooks/wire.rs`'s `StatusReply`,
the hook's echo of the *resolved* bag, is exactly such a type and was the third
of the four leaks. The **boundary is the engine crate**: an admin projection is
built here. The sibling wire/ABI crates (`busbar-api`, `plugin-abi`,
`secret-ref`) define the ABI-level bag types themselves, have no admin surface,
and cannot serve an HTTP read, so they are out of scope by construction.

If you are adding a `settings`-shaped field or JSON member, either project
`admin::v1::service::settings_keys(&…)` / redact with
`service::redact_settings_bags(&mut value)`, or mark the line. Marking is
reserved for an inbound request body, a response envelope whose nested bags are
already redacted, or a non-projection engine type (an operator config struct, an
inbound wire reply):

```rust
// settings-leak-lint: allow [...]
```

Run `cargo xtask gate settings-leak --selftest` before trusting its verdict; CI
runs both.

### The blocking-FFI lint

`cargo xtask gate blocking-ffi` enforces one rule: **a synchronous call into a
dlopened plugin never runs on a Tokio worker.** Every plugin call is a C-ABI hop
into out-of-tree code with real network I/O behind it (an LDAP/AD bind, a Vault
fetch, a JWKS round trip), and the data-plane workers are single-threaded
(`current_thread`) runtimes, so **one** inline call in an `async fn` stalls that
entire worker — every connection it owns — for the plugin's full timeout, with no
sibling thread to steal the work. The same defect has now been found in five
independently written places, the last of them on `/auth/token`, which is mounted
on the data router and bypassed by the auth middleware, so an *unauthenticated*
caller chose the concurrency.

The scanner tracks brace depth (to know when it is inside an `async fn`) and
paren depth (so an offload opener, whether `spawn_blocking`, `Txn::read_store` /
`store_write`, `hooks::offload_bounded`, or `auth::token::offload_login_call`,
covers its whole argument list, braced block or not). In-file `#[cfg(test)]`
modules are exempt: test code serves no traffic.

If you are adding a plugin call, route it through the offload seam that already
exists for its kind, and **bound it**. `spawn_blocking` alone just moves the
exhaustion to the calling runtime's blocking pool (each data-plane runtime and the
control runtime has its own, capped at 512 threads), so take a semaphore permit and
**fail closed** when you cannot get one. Only a boot-time call, or one in an
`async fn` that is provably driven off the worker pool, may be marked, and the
marker must carry a reason naming which call and where:

```rust
// blocking-ffi-lint: allow [...]
```

Run `cargo xtask gate blocking-ffi --selftest` before trusting its verdict; CI
runs both.

### The audit ledger

`cargo xtask ledger` owns `qa/audit-ledger.json`, the register of every
production-code scope (one entry per crate/tooling directory the tree
implies), its audit history, and whether anything it found is still open.
`cargo xtask ledger --check` is the gate: it goes RED on incomplete coverage
(a tracked file no scope claims), a scope the tree implies that the register
does not carry, an unreadable or stale record, or a scope with a HIGH/MEDIUM
finding recorded and no fix stamped. It reads GREEN once coverage is complete
and nothing is open.

To keep the register in step with the tree:

```bash
cargo xtask ledger sync --write     # add/drop scopes as crates come and go
cargo xtask ledger status           # print the table, write qa/evidence/AUDIT-STATUS.md
cargo xtask ledger next             # the worklist, worst-covered first
```

To record a completed audit round against a scope:

```bash
cargo xtask ledger record --scope <path> --round <n> --result <zero|findings|in_progress> \
  --report <what the round found, in prose> --auditor <who> [--counts HIGH=1,MEDIUM=2] [--at <rev>]
```

`--report` describes the *behaviour* the round found, not the round itself — it
is written straight into the register, a file customers can read, and is
refused if it cites an internal round/finding id, a bare commit hash, or a
document the reader cannot open. Once a `findings` scope's issues are fixed,
close it with:

```bash
cargo xtask ledger fixed --scope <path> [--commit <rev>]
```

`fixed` refuses to stamp a scope whose recorded hash is not the tree its round
actually read, so a fix can only be claimed against evidence that was really
measured. A code move that is not a code change (a rename or a crate fold) is
carried across with `cargo xtask ledger move <old-id> <new-id>`, never a hand
edit of the JSON — `move` is the only command that may relocate a record, and
it refuses whenever a plain rename would launder history instead of describing
it. Full usage: `cargo xtask ledger` with no arguments.

The register's own rules are proven by `cargo test -p xtask --lib audit`; run
it before trusting `--check`'s verdict, exactly as with the lints above.

The test suite is **in-crate**: a shared
`#[cfg(test)] mod test_support` provides the `MockServer` harness, and each module
carries its own `#[cfg(test)] mod tests`. There are no `tests/` integration
binaries: everything runs under `cargo test`. See [testing.md](testing.md).

---

## Running locally

Busbar reads two YAML files, located via CLI flags (with an env/config fallback):

| File | Flag | Fallback | Default |
|---|---|---|---|
| Provider catalog | `--providers <path>` | `providers_file:` in config.yaml | `providers.yaml` next to config.yaml |
| Your deployment | `-c`/`--config <path>` | `BUSBAR_CONFIG` env | `/etc/busbar/config.yaml` |

Both files support `${VAR}` interpolation expanded at load time; an unset
referenced variable is a hard startup failure. Provider keys are supplied via the
env vars (or files/secret plugins) named by each provider's `api_key` secret reference, never written into the files.

```bash
export BUSBAR_CLIENT_TOKEN=dev-token
export ANTHROPIC_KEY=sk-ant-...
BUSBAR_CONFIG=./config.yaml cargo run
curl -s localhost:8080/healthz
curl -s -H "Authorization: Bearer $BUSBAR_CLIENT_TOKEN" localhost:8080/stats | jq
```

Full field reference: [configuration.md](configuration.md).

---

## Extending behavior

Implement protocol behavior in its owning plane/transport plugin and authentication
or provider lookup in the appropriate auth/secret plugin. Use the current
[plugin contract and SDK guide](plugin-sdk-migration-1.6.md). Core mediates calls
between kinds; an implementation must not import or select another plugin.
For configuration and upstream examples, use [configuration.md](configuration.md).
The old monolith's `ProtocolWriter` and in-core protocol-directory recipes are retired.

## Coding conventions observed

These are conventions visible in the code; treat the [CONTRIBUTING.md](../CONTRIBUTING.md)
checklist as authoritative.

- **SPDX header.** Every `src/**/*.rs` file (including each `proto/<name>/` module) starts with
  `// SPDX-License-Identifier: Apache-2.0` + `// Copyright (C) 2026 Busbar Inc and contributors`.
- **No `_ =>` catch-all in the disposition/breaker matches.** The exhaustive match
  on `StatusClass`/`Disposition` is how the compiler enforces that every failure
  mode is handled; the arms even use `unreachable!()` for classes that cannot
  reach a given arm. This is a stated project invariant (CONTRIBUTING.md, "Fixing a defect: the
  remediation contract").
- **`error_map` is data, not code.** Provider quirks belong in YAML, not in a
  match arm.
- **Test time is injectable, not real.** Breaker/FSM logic reads time via
  `store::now()` (the public crate function), which `InMemoryStore` internally
  wraps in a private `now_secs()` that, under `#[cfg(test)]`, is shadowed to
  delegate to `now_for_test()`; tests inject time via `store::set_now_for_test`.
  Don't call `SystemTime::now()` directly in breaker-adjacent code.
- **`#[cfg_attr(not(test), allow(dead_code))]`** marks the lane-default breaker
  methods that release code reaches only via the `_in` variants but tests exercise
  directly: keep that pattern when adding parallel default/`_in` methods.

- **No `memchr` dependency.** Byte scanning (e.g. the SSE frame splitting and
  translation-body boundary scans) is done with plain slice iteration, not the
  `memchr` crate. Keep it that way, don't add `memchr` (or pull it in transitively
  for scanning) when a small hand-rolled scan will do.
