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

**That measurement is no longer a measurement somebody took once.** It is the gate's ninth row, run
on every push: see "How coverage is proven" below.

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

Nine rows, each able to go red on its own:

| row | what it holds |
| --- | --- |
| `feature-sets:manifests-read` | every workspace member manifest was read; a reader that lost its input has no features and no features are covered by anything |
| `feature-sets:feature-floor` | at least 30 non-default features were discovered; "every feature is covered" is vacuously true over none |
| `feature-sets:matrix-present` | `ci.yml` carries the `feature-sets` job and its matrix names features |
| `feature-sets:every-non-default-feature-is-built` | every non-default feature is in that matrix or carries a declaration |
| `feature-sets:declaration-names-a-live-feature` | a declaration names a feature that still exists and is still non-default |
| `feature-sets:declaration-names-a-live-job` | the job a declaration names is a job `ci.yml` defines |
| `feature-sets:declaration-reason` | a declaration carries a reason of at least 30 characters |
| `feature-sets:every-h2-rig-is-run-by-a-named-step` | every `h2-*.sh` scenario in the tree is named by a step of `ci.yml` |
| `feature-sets:the-named-leg-really-enables-the-feature` | **the claim is checked, not read** — the leg a matrix row or a declaration names is resolved by cargo and has to enable the feature |

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

## How coverage is proven

The rows above ask whether a feature is NAMED by a leg. The ninth row asks whether the named leg
really enables it, and it asks cargo.

For every matrix row of `feature-sets` and every `# feature-covered:` declaration, the gate

1. **derives the leg's cargo invocations from `ci.yml`** — the job's own block, plus the text of
   every `scripts/*.sh` that block runs (`txn-guards`' cargo line lives in `scripts/loom.sh`, not in
   the workflow), with `${{ matrix.* }}` substituted per matrix row so a row reads as the concrete
   commands it issues;
2. **resolves each one** with

   ```
   cargo tree --locked --offline -e features[,no-dev] -f '{p}|{f}'
   ```

   carrying that invocation's package selection (`--workspace` / `-p …`), its `--features` and its
   `--no-default-features`;
3. **requires the claimed feature to be in the union** of what those invocations enable.

**The edge kinds are the whole mechanism.** Cargo's v2 resolver unifies a dev-dependency's features
into a build only when dev targets are built. So an invocation that builds them — `--all-targets`,
`--tests`, `--benches`, or `cargo test`/`cargo bench`, which build them by definition — resolves
under `-e features`, and an invocation that does not resolves under `-e features,no-dev`. That one
flag is the difference between `busbar-core/test-support` being enabled and not, which is exactly
the coverage the eleven `(incidental)` declarations rest on. The gate now resolves them the way the
job builds them.

**Why `cargo tree` and not `cargo metadata`.** `cargo metadata` reports a manifest's *declared*
feature table and the whole dependency graph. It does not report which features a particular
package-selection-plus-`--features` actually turns on; getting that out of it means reimplementing
cargo's feature resolver, including the dev-unification rule above — and a gate that reimplements the
resolver is a gate that disagrees with cargo the first time cargo changes. `cargo tree -f '{p}|{f}'`
is the resolver answering directly: one line per resolved package with the features it ended up
with. It is a resolve, not a build — no codegen, ~0.2 s per invocation.

**Determinism.** `--locked` pins every version to the committed `Cargo.lock`, so the answer is a
function of files that are in the repository and reviewed with the change that moves them.
`--offline` turns "did not need the network" from a hope into a refusal: a resolve that would have
reached a registry fails loudly rather than quietly answering from an index that is not the one the
next run will see. Given the same manifests and the same lockfile, every leg resolves to the same
bytes on every box. `ci.yml`'s `structure-lint` job runs `cargo fetch --locked` before the gate so
that `--offline` is a promise the environment can keep; `--locked` means that fetch can download
nothing the lockfile does not already pin.

**What is deliberately not derived.** An invocation carrying an unexpanded `${…}` (a value only the
runner has) or a `--manifest-path` (the plugin-pack builds a *different* repository's checkout) is
reported as out of this repository's reach and contributes nothing. That is the conservative
direction: an invocation the gate cannot read can only make a claim harder to satisfy, never easier.
The count is printed on the PASS line too, because a number that grows is the sign that the workflow
has moved its builds somewhere this reader no longer follows.

**Cost.** 46 claims over 9 legs = 28 cargo resolutions, memoised per process; about 3 s for a gate
run and 4.3 s / 381 work units for the whole self-test, against a 9 000-unit budget.

### The two reds it was proven against

* *A declaration that names a leg which does not build the feature.* A well-formed line —
  `busbar-core/loom-model -- openapi-schema -- …`: real non-default feature, real job, long enough
  reason, rule 4 already discharged by the feature's genuine declaration — and false. Only resolving
  `openapi-schema`'s own cargo lines (`-p busbar -p busbar-core --features openapi-schema`) finds
  that out. Red, naming the feature, the leg and the first command it resolved.
* *The dev-dependency deletion this row was built for.* `busbar-plugin-testkit/store` is enabled by
  exactly two edges: `crates/store-memory` and `crates/store-example-plugin` naming
  `busbar-plugin-testkit = { …, features = ["store"] }` in their `[dev-dependencies]`. Deleting both
  lines **on disk** makes the row red on the real tree, naming the feature and the `check` leg,
  while every other row of the gate stays green — which is precisely the state rules 1–8 could not
  see. Inside the self-test the same defect is planted on the resolver's ANSWER rather than on a
  manifest, and that is a property of what is being planted rather than a shortcut: an overlay is an
  in-memory view and `cargo tree` reads the disk, so an overlaid `Cargo.toml` would change nothing
  about what cargo says. The fixture takes the leg's real resolution and strikes the feature out of
  it — byte-for-byte what cargo prints once those two lines are gone.

## What this does NOT hold

The ninth row resolves the legs `ci.yml` describes. It does not resolve the legs of
`a2a-conformance.yml`, `mcp-conformance.yml` or `voice-conformance.yml`: no declaration names a job
in those workflows today, and rule 6 keeps it that way (a declaration may only name a job `ci.yml`
defines). A declaration that wanted to rest on a conformance workflow would have to extend the
reader first.

It resolves what a leg ENABLES, not what a leg RUNS. A matrix row that compiled a feature and then
lost its `cargo test` line would still satisfy this row; the tests are asserted by the row's own
`tests:` value being passed to `cargo test`, which is a line a reviewer reads, not a thing this gate
measures.

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
