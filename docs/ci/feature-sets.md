# Feature sets — every cargo feature in this workspace, and the CI leg that compiles it

A cargo feature nothing builds is a feature that is already broken and nobody knows. The failure is
silent in the exact way a missing gate is silent: the code behind `#[cfg(feature = "…")]` is not
compiled, so it is not type-checked, so it does not have to be valid Rust. It rots at the speed the
rest of the tree moves, and the first person to turn the feature on pays the whole bill at once.

That is not hypothetical here. `busbar-core`'s WebSocket-arrival mount is behind `duplex-ws`; the
root binary's duplex serve leg is behind its own root feature on the plane-extraction line. The root
one was default-OFF and named by NO CI job, and it stopped compiling for days without a single red
run. Nothing about that is specific to duplex: **every non-default feature in this workspace has the
same exposure unless some job names it.**

This document is the measurement that closes it, and the `feature-sets` xtask gate is what stops the
measurement from going stale.

## The counts

| | count |
| --- | --- |
| features declared across the workspace (`[features]` keys, excluding `default` itself) | 67 |
| reachable from the declaring crate's own `default` | 21 |
| **non-default** | **46** |
| non-default, built by some integration-line CI leg BEFORE this change | 39 |
| non-default, built by NO CI leg before this change | **7** |
| non-default, built after this change | **46** |
| dead / never referenced, therefore deleted | **0** — see "Nothing was dead", below |
| H2 rig scenarios in the tree | 12 |
| H2 rig scenarios run by any job BEFORE this change | **0** |
| H2 rig scenarios run after this change | **12** |

"Built by some CI leg" is measured, not assumed: for each cargo invocation any workflow on the
integration line (`ci.yml`, `a2a-conformance.yml`, `mcp-conformance.yml`, `voice-conformance.yml`
and the scripts they call) issues, the enabled-feature set was resolved with
`cargo tree -f '{p}|{f}'` — cargo's own resolver, not a reading of the manifests — and unioned. The
seven below are what the union did not contain.

## The seven that nothing built

| feature | what is behind it |
| --- | --- |
| `busbar/test-harness` | `crates/busbar/src/root/harness.rs` — the fixture surface a DEPENDENCY build (not a `cfg(test)` build) reaches. `#[cfg(any(test, feature = "test-harness"))]`, so the workspace test build compiles it under `test` and the FEATURE arm was never once exercised. |
| `busbar-core/timing` | forwards `busbar-timing/timing`. The forward itself is the thing that can rot: a rename in `busbar-timing` makes this line invalid and nothing reads it. |
| `busbar-llm/timing` | same, plus `busbar-llm-codec/timing`. |
| `busbar-llm-codec/timing` | same. |
| `busbar-llm/auth-admin-tokens` | `crates/busbar-llm/src/engine/tests/forward_pool_integration_tests.rs:1788` — an admin-token path in the forward-pool suite, compiled by nothing. |
| `busbar-llm/webhook-receiver` | `crates/busbar-llm/src/openai_responses_webhook.rs` — a LIVE HTTP route mount (`build_routes`, the `PLANE_DECL.routes` contribution) plus `crates/busbar-llm/src/lib.rs:241`. This is shipped product code behind an off-by-default flag, and it was not compiled anywhere. |
| `busbar-mcp-codec/test-support` | `subscribe.rs`, `invoke.rs`, `sanitize.rs`, `outputschema.rs` — `#[cfg(any(test, feature = "test-support"))]`. Same shape as `busbar/test-harness`: the `test` arm is compiled, the `feature` arm is not, and the two are not the same build. |

## Nothing was dead

The brief said a feature nothing turns on is legacy and gets deleted rather than covered. Two
features have an EMPTY body and no `#[cfg]` in their own crate —
`busbar-llm-codec/openapi-schema` and `busbar-substrate/plane-llm` — and both are nevertheless
TURNED ON by a forward from another crate (`busbar-llm/openapi-schema` and `busbar-core/plane-llm`
respectively). A declared-and-empty feature that another manifest names is a load-bearing forward
target, not legacy: deleting it makes the naming manifest fail to resolve. Every other non-default
feature gates real `#[cfg]`-ed code. **Nothing in this tree qualified for deletion, so nothing was
deleted.**

## The new leg

`ci.yml` job `feature-sets`, one matrix row per feature set, same runner label
(`[self-hosted, linux, x64, busbar-xl]`) and the same pinned toolchain
(`dtolnay/rust-toolchain@…` 1.98.0) as the `check` job. Each row runs, with that row's features on:

```
cargo clippy --workspace --all-targets --features "<set>" --locked -- -D warnings
cargo test   <the owning crates> --features "<set>" --locked
```

`cargo clippy --all-targets` IS `cargo check --workspace --all-targets`, plus lints: it runs the
same front end over the same target set and then refuses on warnings. Running both would compile the
workspace twice per row for one extra bit of information (none). The rows are deliberately SEPARATE
rather than one union row — a union row proves only that the features compile TOGETHER, which is not
the build anyone ships.

| row | features | tests |
| --- | --- | --- |
| `root-test-harness` | `busbar/test-harness` | `-p busbar` |
| `timing` | `busbar-core/timing,busbar-llm/timing,busbar-llm-codec/timing` | `-p busbar-core -p busbar-llm -p busbar-llm-codec -p busbar-timing` |
| `llm-auth-admin-tokens` | `busbar-llm/auth-admin-tokens` | `-p busbar-llm` |
| `llm-webhook-receiver` | `busbar-llm/webhook-receiver` | `-p busbar-llm` |
| `mcp-codec-test-support` | `busbar-mcp-codec/test-support` | `-p busbar-mcp-codec` |
| `core-duplex-ws` | `busbar-core/duplex-ws` | `-p busbar-core` |

`core-duplex-ws` is in the matrix even though `duplex-ws` is reachable from the root binary's
default `plane-voice` today, because that reachability is a property of a DEFAULT — and the exposure
this whole document is about is a default moving. A row that NAMES the feature is coverage that
survives the default being flipped; reachability is not.

## The cost

Measured on the development host (4 build jobs, `--locked`, a target directory the baseline had
just populated, and a machine running other work at the same time — so these are DELTAS, not CI
figures):

| step | wall clock |
| --- | --- |
| `cargo clippy --workspace --all-targets --locked -- -D warnings`, default features, cold | 191 s |
| row `root-test-harness`, incremental on that | 4 s |
| row `timing`, incremental | 32 s |
| row `llm-auth-admin-tokens`, incremental | 23 s |
| row `llm-webhook-receiver`, incremental | 25 s |
| row `mcp-codec-test-support`, incremental | 27 s |
| row `core-duplex-ws`, incremental | 0 s — already enabled by the root default, nothing recompiled |

**The honest CI number.** A matrix row is its own GitHub job with its own `Swatinem/rust-cache`
entry, so it does NOT get the incremental figure above on a cold cache: a cold row is a full
workspace clippy, i.e. the 191 s line, plus its crate test binaries. Warm — the ordinary case, since
the cache key is the lockfile and the lockfile rarely moves — a row is the incremental figure plus
cache restore. So: **six rows, each between ~0.5 and ~4 minutes of runner time warm and up to a
default-leg's compile cold.** They run in PARALLEL with each other and with the rest of the
workflow, so the added WALL CLOCK of a green CI run is ONE row, not six; the added RUNNER MINUTES
are the sum. On the `busbar-xl` self-hosted class with `sccache` in front of it, that is a small
fraction of what the `check` job alone already spends (~13 min warm, ~40 cold).

**What the first run bought.** The `llm-auth-admin-tokens` row was RED the first time it was ever
run: `crates/busbar-llm/src/engine/tests/forward_pool_integration_tests.rs:1807` bound
`let (host, rt) = …` and used neither, which `-D warnings` refuses. That code had been behind
`#[cfg(feature = "auth-admin-tokens")]`, compiled by nothing, for as long as the feature has
existed. It is fixed in the same landing (`(_host, _rt)`, matching its own sibling test 115 lines
below). That is the whole argument for this job, paid on day one.

## The gate

`cargo xtask gate feature-sets` derives the non-default feature list from the member manifests and
requires each one to appear in `ci.yml` — either in the `feature-sets` matrix `features:` values, or
in a written declaration:

```text
# feature-covered: <pkg>/<feature> -- <job-key> -- <reason, at least 30 characters>
```

so that a feature added to any crate is RED until somebody says, in the workflow file, which job
builds it. A declaration that names a feature which no longer exists is red too: a stale exemption
outlives the feature it excused and then silently excuses the next one to take the name.

### The second axis the same gate holds: rig scenarios

A feature nothing builds and an executable scenario nothing runs are the same defect. The eighth row
of the gate walks `scripts/mcp-subject/` and `scripts/a2a-subject/` for `h2-*.sh` — the twelve H2
gating scenarios `qa/teller-steps.json` cites as the proof of a Teller step — and requires each one
to be NAMED by a step of `ci.yml`. `cargo xtask gate teller-steps` already asserts that a cell names
a real script; naming a file is not running it, and no job in any workflow ran one.

`ci.yml`'s new `plane-rigs` job runs all twelve, one named step each, fast tier, after the matrix
self-test and the release build the rigs boot. It is one step per scenario rather than a
`for f in scripts/*-subject/h2-*.sh` loop on purpose: a loop names none of them, and a glob expands
on the runner where nobody reads the expansion, so a rig added tomorrow would be covered by a loop
that never listed it with no diff to show the difference. The rig row counts steps against the
directory listing, which only works if the steps are lines.

## What this does NOT hold

The declarations for features covered by `check` through `--all-targets` DEV-DEPENDENCY
UNIFICATION — `busbar-core/test-support`, `busbar-a2a/test-support` and the nine others marked
`(incidental)` in the table — are claims the gate accepts on the declaration's word. That coverage
is real today and is one dev-dependency edit away from evaporating without a red. Closing it needs
the gate to RESOLVE each declared job's feature set (a `cargo tree -f '{p}|{f}'` per leg) rather
than read a comment; that belongs in this gate, as a second row, and it is not here.

## The table

Covering leg is the FIRST leg that compiles the feature; several are compiled by more than one.

| feature | class | covering CI leg (after this change) | built before? |
| --- | --- | --- | --- |
| `busbar/auth-admin-tokens` | default | `check` — the workspace default build | — |
| `busbar/hooks-ranking` | default | `check` — the workspace default build | — |
| `busbar/loom-model` | non-default | `txn-guards` (`scripts/loom.sh`) | yes |
| `busbar/openapi-schema` | non-default | `openapi-schema` | yes |
| `busbar/plane-a2a` | default | `check` — the workspace default build | — |
| `busbar/plane-mcp` | default | `check` — the workspace default build | — |
| `busbar/plane-voice` | default | `check` — the workspace default build | — |
| `busbar/proto-llm` | default | `check` — the workspace default build | — |
| `busbar/root-a2a` | default | `check` — the workspace default build | — |
| `busbar/root-admin` | default | `check` — the workspace default build | — |
| `busbar/root-llm` | default | `check` — the workspace default build | — |
| `busbar/root-mcp` | default | `check` — the workspace default build | — |
| `busbar/root-voice` | default | `check` — the workspace default build | — |
| `busbar/test-harness` | non-default | `feature-sets` (this change) | NO |
| `busbar-a2a/auth-admin-tokens` | non-default | `check` — `--all-targets` dev-dep unification | yes (incidental) |
| `busbar-a2a/openapi-schema` | non-default | `openapi-schema` | yes |
| `busbar-a2a/test-support` | non-default | `check` — `--all-targets` dev-dep unification | yes (incidental) |
| `busbar-a2a-codec/test-support` | non-default | `check` — `--all-targets` dev-dep unification | yes (incidental) |
| `busbar-core/auth-admin-tokens` | default | `check` — the workspace default build | — |
| `busbar-core/card-signing` | default | `check` — the workspace default build | — |
| `busbar-core/duplex-ws` | non-default | `check` — reached from a workspace default | yes |
| `busbar-core/egress-auth-gate` | default | `check` — the workspace default build | — |
| `busbar-core/egress-seam` | default | `check` — the workspace default build | — |
| `busbar-core/egress-stream` | default | `check` — the workspace default build | — |
| `busbar-core/hooks-ranking` | default | `check` — the workspace default build | — |
| `busbar-core/jsonrpc-ingress` | default | `check` — the workspace default build | — |
| `busbar-core/loom-model` | non-default | `txn-guards` (`scripts/loom.sh`) | yes |
| `busbar-core/openapi-schema` | non-default | `openapi-schema` | yes |
| `busbar-core/plane-a2a` | default | `check` — the workspace default build | — |
| `busbar-core/plane-llm` | default | `check` — the workspace default build | — |
| `busbar-core/plane-mcp` | default | `check` — the workspace default build | — |
| `busbar-core/plane-voice` | non-default | `check` — reached from a workspace default | yes |
| `busbar-core/test-support` | non-default | `check` — `--all-targets` dev-dep unification | yes (incidental) |
| `busbar-core/timing` | non-default | `feature-sets` (this change) | NO |
| `busbar-llm/auth-admin-tokens` | non-default | `feature-sets` (this change) | NO |
| `busbar-llm/openapi-schema` | non-default | `openapi-schema` | yes |
| `busbar-llm/teller-waist` | non-default | `check` step "LLM teller-step tests" | yes |
| `busbar-llm/test-support` | non-default | `check` — `--all-targets` dev-dep unification | yes (incidental) |
| `busbar-llm/timing` | non-default | `feature-sets` (this change) | NO |
| `busbar-llm/webhook-receiver` | non-default | `feature-sets` (this change) | NO |
| `busbar-llm-codec/openapi-schema` | non-default | `openapi-schema` | yes |
| `busbar-llm-codec/test-support` | non-default | `check` — `--all-targets` dev-dep unification | yes (incidental) |
| `busbar-llm-codec/timing` | non-default | `feature-sets` (this change) | NO |
| `busbar-mcp/auth-admin-tokens` | non-default | `check` — `--all-targets` dev-dep unification | yes (incidental) |
| `busbar-mcp/openapi-schema` | non-default | `openapi-schema` | yes |
| `busbar-mcp/test-support` | non-default | `check` — `--all-targets` dev-dep unification | yes (incidental) |
| `busbar-mcp-codec/test-support` | non-default | `feature-sets` (this change) | NO |
| `busbar-plugin-testkit/store` | non-default | `check` — `--all-targets` dev-dep unification | yes (incidental) |
| `busbar-substrate/dispatch` | non-default | `check` — reached from a workspace default | yes |
| `busbar-substrate/openapi-schema` | non-default | `openapi-schema` | yes |
| `busbar-substrate/plane-a2a` | non-default | `check` — reached from a workspace default | yes |
| `busbar-substrate/plane-llm` | non-default | `check` — reached from a workspace default | yes |
| `busbar-substrate/plane-mcp` | non-default | `check` — reached from a workspace default | yes |
| `busbar-substrate/plane-voice` | non-default | `check` — reached from a workspace default | yes |
| `busbar-substrate/relay` | non-default | `check` — reached from a workspace default | yes |
| `busbar-substrate/runtime` | non-default | `check` — reached from a workspace default | yes |
| `busbar-substrate/test-support` | non-default | `check` — `--all-targets` dev-dep unification | yes (incidental) |
| `busbar-substrate-values/dispatch` | non-default | `check` — reached from a workspace default | yes |
| `busbar-substrate-values/relay` | non-default | `check` — reached from a workspace default | yes |
| `busbar-substrate-values/runtime` | non-default | `check` — reached from a workspace default | yes |
| `busbar-substrate-values/test-support` | non-default | `check` — `--all-targets` dev-dep unification | yes (incidental) |
| `busbar-timing/timing` | non-default | `check` step "Timing implementation tests" | yes |
| `busbar-unit-auth/sha256` | non-default | `check` — reached from a workspace default | yes |
| `busbar-voice/openapi-schema` | non-default | `openapi-schema` | yes |
| `busbar-voice/runtime` | non-default | `check` — reached from a workspace default | yes |
| `busbar-voice/test-support` | non-default | `check` step "Voice runtime tests" | yes |
| `busbar-voice-codec/runtime` | non-default | `check` — reached from a workspace default | yes |
