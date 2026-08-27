# Plane (MCP + A2A) Test Re-Architecture — Design Plan

> INTENDED DESTINATION: `/Users/matthew/Developer/busbarAI/busbarAI-private/PLANE-TEST-ARCHITECTURE-PLAN.md`
> (written here inside the isolated worktree because the private repo is outside it; move on landing).

Status: **APPROVED + PARTIALLY IMPLEMENTED.** Production build green; test-side curation incomplete
(see the IMPLEMENTATION STATUS section at the very bottom for exactly what remains).

Owner revision applied: **no new `busbar-plane-tests` crate.** Core's cross-plane integration tests
stay in `busbar-core` and reach the REAL planes through `busbar-a2a`/`busbar-mcp` added as
`[dev-dependencies]` (with `test-support`) — a legal dev-dep back-edge, not a build cycle. Each plane
crate's App-tests run in its OWN crate under `feature = "test-support"`. `test_support` stays neutral
(the `pub install_plane_runtime` + sibling seams); each plane's `testkit` builds/installs its own plane.

---

## IMPLEMENTATION STATUS (read this first)

### DONE and PRODUCTION-GREEN (`cargo build --workspace` passes)
- `busbar-a2a` test refs renamed `crate::<core>` → `busbar_core::<core>` (commit 1).
- Core plane test-seams widened to `pub` under test-support; `plane::store::encode` kept `pub(crate)`
  (tamper discipline, D5) (commit 2).
- **Core `test_support::TestApp` fully DE-PLANED**: plane-typed fields/methods removed; NEUTRAL seams
  added — `install_plane_runtime`, `mount_plane`/`admit_plane`, `set_mcp_container_hooks`/
  `set_a2a_container_hooks`, `set_agent_defs_any`, `on_built`, and a type-erased `plane_scratch` +
  `register_plane_finalizer` seam that preserves the fluent `.mcp(cfg).mcp_server(...).build()` chain.
- **`busbar_mcp::testkit` + `busbar_a2a::testkit`** (feature `test-support`): extension traits
  (`TestAppMcpExt`/`TestAppA2aExt`) carrying the moved builders + build-time finalizers that construct
  the real plane runtime and install it through the neutral seams. `prefresh_mcp_sightings` relocated
  to `busbar_mcp::testkit`.
- **`#[path]` dual-compile shims DELETED** from `busbar-core/src/lib.rs`.
- **Both `build.rs` DELETED**; all ~139 `#[cfg(all(test, not(busbar_*_native)))]` sites re-gated to
  `#[cfg(all(test, feature = "test-support"))]` (uniform mapping `not(busbar_*_native)` →
  `feature="test-support"`, bare `busbar_*_native` → `not(feature="test-support")`); the
  `busbar_*_native` check-cfg removed from `busbar-core/Cargo.toml`.
- Plane registry: the `#[cfg(test)]` hard-coded mcp/a2a rows removed; replaced with a test-support
  `register_test_plane` seam each testkit calls (folded into `plane_decls()` on read).
- Core `[dev-dependencies]` now include `busbar-a2a`/`busbar-mcp` with `test-support` (the back-edge).
- Curated pub seam `base_data_route_table_view(&App)` replaces the a2a ingress test's reach into the
  `pub(crate)` router fn + `CoreRoute` types; a2a `ingress_tests` rewritten to it.
- `busbar-a2a` dev-deps added (reqwest/json, rcgen, rustls, rustls-pki-types, store-memory,
  secret-ref, plugin-sign) — the crates its own test suite names now that it no longer dual-compiles.

### REMAINING (test-side only; `cargo test --workspace` NOT yet green)
The structural cut is complete; what's left is mechanical TEST-SUPPORT SURFACE curation, quantified
from real compiler output (`cargo test -p busbar-a2a --features test-support --no-run` → ~169 errors,
all of two kinds), plus the same pass for mcp and core's tests.rs:
1. **`#[cfg(test)]` → `#[cfg(any(test, feature = "test-support"))]`** on the core test helpers the
   plane suites use (they were reachable only because the dual-compile put core in `test` mode). Seen:
   `taskstore::{aim_global_task_sink, verify_task_event_rows, with_global_task_host, TASKS_SINK_LOCK,
   event_ledger}`, `test_support::{metric_sum, test_hook_env}`, the `metrics::*` constants
   (`PLANE_REQUESTS_TOTAL`, `UPSTREAM_*`, `EV_*`), `Store`/`MemoryStore` test re-exports, etc.
2. **`pub(crate)` → `pub` (under test-support)** on the ~30 core items the plane tests call by method:
   App accessors (`public_url`, `store`, `governance`, `submit`, `set_sink`, breaker `state_at`/
   `transition`), `SecretResolver::builtins_only`, auth `get_scoped`/`get_unscoped`/`new_with_signer`/
   `mint_signed`, `TokenSigner::new`, `wire_format_names`, the `named_map`/`prometheus` modules, the
   `HookKind`/`UserAccess`/`PromptAccess` enums, `NewKeySpec`, etc. (Items inside `plane::taskstore`/
   `plane::store` can be plain `pub` — the module is already `pub` only under test-support.)
3. Repeat (1)+(2) for **busbar-mcp**; add its missing **dev-deps** the same way a2a got them.
4. **Core `src/tests/tests.rs`**: rewrite the ~40 `crate::a2a`/`crate::mcp` refs to `busbar_a2a::`/
   `busbar_mcp::` (dev-deps make them nameable) + `use` the testkits; MOVE the handful of
   deep-plane-internal tests (e.g. the config-swap test reading `mcp::runtime().pool.children`) INTO
   the owning plane crate (they need pub(crate) internals no curated surface should expose), keeping
   only genuinely cross-plane tests in core.
5. Add the **fail-loud canary** per plane crate (a `#[cfg(feature="test-support")]` test asserting the
   App-suite compiled in) and run **THE GATE**: `cargo test --workspace -- --list` name-set diff vs the
   captured baseline (6397 tests) — must be identical.

### BLOCKER found during curation — needs A6 coordination
Converting `taskstore::verify_task_event_rows` (an item the a2a suite needs) to the test-support
surface transitively pulls in `crate::plane_host::journal::set_stream_sink_for_test`, which is
`#[cfg(test)]` in **`plane_host/journal.rs`** — a file this task's SCOPE GUARD forbids touching (the
parallel **A6** analysis owns it). So the remaining `#[cfg(test)]`→`#[cfg(any(test, test-support))]`
pass CANNOT be completed on the taskstore/journal path without A6 either (a) making that seam
test-support-visible, or (b) agreeing this task may edit that one gate. Flag for the owner/A6 before
finishing curation step (1). (Reverted the taskstore cfg-conversion that surfaced this, to keep
`busbar-core` lib test-support green.)

### The pragmatic curation lever discovered
`cargo build --workspace` is GREEN, so the risky structural work is DONE and only additive widening
remains. The fastest convergence is compiler-driven: run the per-plane `--features test-support
--no-run`, batch-fix each distinct `is private` / `cannot find` item, repeat. Guard against
OVER-widening (a `pub` fn must not expose a `pub(crate)` type → `private_interfaces` under -D warnings;
prefer testkit constructor helpers over widening config-struct FIELDS).

---

Author: Matthew Jackson <matthew@pq.io>
Base: `origin/dev` @ `4329f146` (busbar 1.6.0). Worktree: `agent-ac4d29a133c5d87a9`.

---

## 1. The problem, stated precisely

Both protocol planes were extracted into their own crates (`busbar-mcp`, `busbar-a2a`).
Their source is *sealed* — the default build has **no `busbar-core` in the closure**;
every former `busbar_core::` reach is served by `busbar-substrate` / `busbar-api`. Good.

But the plane crates keep an `optional` dependency on `busbar-core`, pulled **only** by
their `test-support` feature, because their `&App`-typed test helpers
(`mcp::resource`/`runtime`, `A2aPlane::from_config`, and ~139 App-needing test modules)
name `busbar_core::state::App`. Today those helpers/tests do **not** run in the plane
crate's own test binary. Instead:

- Each plane crate's `build.rs` emits a build-script cfg **unconditionally** when it
  builds *as a crate*: `busbar_mcp_native` / `busbar_a2a_native`.
- Every App-needing test is gated `#[cfg(all(test, not(busbar_*_native)))]` — so it is
  **skipped in the plane crate's own binary** (native is set) …
- … and busbar-core's **own** lib test binary **dual-compiles the plane sources back in**
  via `crates/busbar-core/src/lib.rs`:

  ```rust
  #[cfg(any(test, feature = "test-support"))]
  #[path = "../../busbar-a2a/src/a2a/mod.rs"]
  pub mod a2a;
  #[cfg(any(test, feature = "test-support"))]
  #[path = "../../busbar-mcp/src/mcp/mod.rs"]
  pub mod mcp;
  ```

  Under core's build, `busbar_*_native` is **not** set, so `not(busbar_*_native)` is true and
  the App-needing tests **run there**, against core's real `TestApp` fixtures (`crate::` == core,
  the plane types are `crate::a2a::…`/`crate::mcp::…`).

**Why it feels backwards:** the engine crate reaches back into its plugins' *source* to
test itself. A reviewer reads `#[path = "../../busbar-a2a/src/a2a/mod.rs"]` in the engine and
sees the plugin boundary violated for tests.

### Measured baseline (ground truth via `cargo test … -- --list`)

| Test binary | Tests listed | Meaning |
|---|---|---|
| `busbar-core --lib` | **4801** | all of core's own tests **plus** the entire dual-compiled A2A + MCP App-test population |
| `busbar-a2a --lib` (native) | **0** | *every* a2a test is `not(busbar_a2a_native)` → all skipped in its own binary |
| `busbar-mcp --lib` (native) | **22** | only the 22 native-safe tests run; the rest are `not(busbar_mcp_native)` → run in core |

So essentially **the entire A2A suite and ~95% of the MCP plane suite run ONLY inside
busbar-core's dual-compiled test binary today.** That is the population we must preserve.

`#[cfg]` site counts to be re-gated: **72 in busbar-mcp, 67 in busbar-a2a** (many mark whole
`#[path]` test modules, so they expand to far more than 139 test functions).

### What is NOT part of this problem (scope correction)

The `crates/busbar-core/src/plane/tests/*` suite (`calllog_tests`, `taskstore_tests`,
`event_ledger`, `store_seam_tests`, …) tests **core's own** plane store/ledger modules
(`crate::plane::store`, `crate::plane::calllog`) — these live in **busbar-core**, not in the
a2a/mcp crates, and do **not** reference `crate::a2a`/`crate::mcp`. They use core-private
`crate::plane::store::encode` for tamper simulation. **They do not need to move** and are not
part of the dual-compile problem. (The task brief anticipated calllog as "the genuinely hard
public-seam case after the move" — that only bites if those tests move to an external crate.
Under this design they stay in core, so the tamper discipline is untouched and no new public
seam on `store::encode` is required.) They **do** interact with the parallel **A4** change,
which relocates `plane/calllog.rs` + `plane/provenance.rs` out of the `plane::` namespace —
see §6.

The only busbar-core files that reference the dual-compiled plane are exactly two:
- `crates/busbar-core/src/test_support/mod.rs` (the `TestApp` plane builders) — 30+ refs
- `crates/busbar-core/src/tests/tests.rs` (cross-plane integration tests) — ~40 refs

---

## 2. Foundation is already in place (verified)

- `App::plane_slot(key) -> Option<&Arc<dyn Any + Send + Sync>>` is **already `pub`** — the
  neutral, type-erased **read** seam exists (`src/state.rs:791`).
- Plane runtimes are already stored **type-erased** in the App's plane slot and read back by
  the plane crates' neutral accessors (`busbar_mcp::mcp::resource(&app)`,
  `busbar_a2a::a2a::runtime(&app)`), which are written against `busbar_core::App` and compile
  in any build where busbar-core is in the closure.
- **Verified:** `cargo build -p busbar-a2a --features test-support` and
  `cargo build -p busbar-mcp --features test-support` both compile cleanly today. So a
  downstream crate that turns on `test-support` gets: real `busbar_core::App`, the plane
  constructors, and the neutral accessors — with **one** copy of each plane crate, so
  `PlaneDecl`/runtime **type identity is consistent** (the historic reason dual-compile was
  "needed" — two divergent copies — does not arise when there is a single external copy).

The only thing missing is a *home* where busbar-core is in the closure **and** the plane
crate's `pub(crate)` test internals are reachable. That home is **the plane crate's own test
binary built with `--features test-support`** — which today it never is.

---

## 3. Target architecture

Three moving parts. No engine-reaches-into-plugin-source anywhere.

### 3a. busbar-core: a real, public `test-support` fixture API (plane-agnostic)

- Promote the `test_support` fixture surface from `pub(crate)` to **`pub`**, gated behind the
  existing `#[cfg(any(test, feature = "test-support"))]` / `feature = "test-support"`. This
  covers `TestApp` and its builders, `MockServer`, `MockServerState`, `LaneSpec`, etc.
- Make `TestApp::install_plane_runtime(key: &str, rt: Arc<dyn Any + Send + Sync>)` **`pub`** —
  the neutral, plane-agnostic install seam (mirror of the already-public `plane_slot` read
  seam). This is the ONE edge a plane's test-kit uses to seat its runtime.
- **Remove from core** the plane-*type-naming* builder methods that only exist because of the
  dual-compile: `build_a2a_plane_runtime`, `mcp_runtime_direct`, `install_plane_runtimes`,
  `agent_def`, `mcp(cfg)`, the mcp demotion-hydrate helper, and the two `mcp_sightings`/
  catalogue helpers at the bottom of `test_support/mod.rs`. These name `crate::mcp`/`crate::a2a`,
  which will no longer exist in core once the dual-compile is gone. They move to the plane
  crates (§3b).
- **Delete** the two `#[path = "../../busbar-*/src/*/mod.rs"] pub mod a2a|mcp;` shims from
  `src/lib.rs` and the `check-cfg = ['cfg(busbar_mcp_native)', 'cfg(busbar_a2a_native)']` line
  from `Cargo.toml`.

### 3b. busbar-mcp / busbar-a2a: run their own App-tests, own their test-kit

- Add a `testkit` module (feature `test-support`) providing the plane-specific `TestApp`
  extension that was removed from core — e.g.:
  ```rust
  // busbar_mcp::testkit
  pub trait TestAppMcpExt {
      fn with_mcp(self, cfg: &McpCfg) -> Self;              // was TestApp::mcp
      fn install_mcp_runtime(&self, rt: Arc<McpResource>);  // builds + install_plane_runtime(PLANE_DECL.key, rt)
  }
  impl TestAppMcpExt for busbar_core::test_support::TestApp { … }
  ```
  and the A2A analogue (`with_agent_def`, `install_a2a_runtime`, using `A2aPlane::from_config`
  and `install_plane_runtime(a2a::PLANE_DECL.key, …)`). These name the plane types — legal,
  because they live **in the plane crate**.
- Re-gate every `#[cfg(all(test, not(busbar_*_native)))]` → `#[cfg(all(test, feature = "test-support"))]`
  (72 mcp + 67 a2a sites). Same for the `cfg_attr(any(not(test), busbar_*_native), allow(dead_code))`
  variants → key them on `not(feature = "test-support")`.
- **Delete** `build.rs` in both plane crates (its sole job is emitting the native cfg) and the
  `check-cfg` lines in their `Cargo.toml`. Remove the crate-root `cfg_attr(all(test,
  busbar_*_native), allow(dead_code))`.
- Result: `cargo test -p busbar-mcp --features test-support` and
  `cargo test -p busbar-a2a --features test-support` compile with busbar-core in the closure
  and **run the full App-needing plane suite in-crate**, against `busbar_core::test_support::TestApp`.

### 3c. New crate `busbar-plane-tests` (dev/integration crate, `publish = false`)

- Deps (tests-only): `busbar-core` (test-support), `busbar-mcp` (test-support),
  `busbar-a2a` (test-support), plus the store/mock helpers.
- Hosts the **cross-plane** integration tests that currently live in
  `busbar-core/src/tests/tests.rs` and reference `crate::a2a` **and/or** `crate::mcp` together:
  the config-swap tests, the `plane_slot ↔ typed accessor` identity tests, the
  App-slot/registry install tests, and any test that builds a `TestApp` with `agents:`/`mcp:`
  config and downcasts a runtime out. These become `busbar_core::test_support::TestApp` +
  `busbar_mcp::testkit` + `busbar_a2a::testkit` against the real, singly-linked planes.
- Core's tests.rs keeps only the plane-agnostic tests (config grammar, ingress/routing,
  registry that don't name a plane type).

### 3d. Verify / CI convention change

Because the App-tests now live behind `feature = "test-support"`, the per-crate commands must
carry the feature:
```
cargo test -p busbar-mcp --features test-support
cargo test -p busbar-a2a --features test-support
cargo test -p busbar-plane-tests
```
`cargo test --workspace` will pull `busbar-plane-tests` (which turns on test-support on both
planes), so the workspace run exercises the full population. Bare `cargo test -p busbar-mcp`
(no feature) legitimately runs only the 22 native-safe tests — this is honest, but it is a
**semantics change** to that command (see Decision D2).

---

## 4. Net-zero test accounting (the win condition)

Nothing may be silently dropped. The migration is a **relocation**, proven by:

| Population | Before (home) | After (home) |
|---|---|---|
| core's own non-plane tests | core `--lib` (subset of 4801) | core `--lib` (unchanged) |
| MCP App-needing tests | core `--lib` (dual-compiled) | `busbar-mcp --features test-support` |
| A2A App-needing tests | core `--lib` (dual-compiled) | `busbar-a2a --features test-support` |
| MCP native-safe tests | `busbar-mcp --lib` (22) | `busbar-mcp --lib` (22, unchanged) |
| cross-plane integration tests | core `--lib` (tests.rs) | `busbar-plane-tests` |

Implementation must diff `-- --list` output before/after and assert the **union of test names
is identical** (a name-set diff, not just a count, so a rename can't hide a drop). Expected:
core `--lib` shrinks by the plane population; the sum across the new homes restores it exactly.

---

## 5. Staging (each stage independently green)

1. **Core test_support → public, plane-agnostic.** Promote visibility; make
   `install_plane_runtime` pub. *Keep* the dual-compile for now. Green.
2. **Plane test-kits.** Add `busbar_mcp::testkit` / `busbar_a2a::testkit` (feature-gated).
   Green (unused yet).
3. **New `busbar-plane-tests` crate**, wired into the workspace. Move ONE cross-plane test as a
   tracer; prove it runs against singly-linked planes. Green.
4. **Re-gate the planes** `not(busbar_*_native)` → `feature = "test-support"`, delete the
   build scripts + check-cfgs — one plane at a time, watching the transition carefully.
5. **Cut the dual-compile.** Delete the `#[path]` shims + core's plane-typed builders + move the
   remaining cross-plane tests to `busbar-plane-tests`. Green — full name-set parity asserted.
6. **Verify matrix** (see §8) + fmt/clippy (default and `--no-default-features`).

Stages 1–3 are additive and reversible. The irreversible cut is stage 5; do not start it until
the owner signs off on the decisions in §7.

---

## 6. Coordination with parallel changes (SCOPE GUARD)

- **A4** relocates `plane/calllog.rs` + `plane/provenance.rs` out of `plane::`. This plan does
  **not** move those modules and does **not** move their tests out of core — the calllog/
  taskstore tests stay in busbar-core and keep using core-private `crate::plane::store::encode`.
  The only overlap: if A4 changes the module path, the calllog test files' `use` paths update —
  but that is A4's edit. **No conflict expected**; the two are orthogonal (this change never
  touches `plane/store.rs`, `calllog.rs`, `provenance.rs`).
- **A6** touches `auditlog.rs`, `audit/mod.rs`, `plane_host/journal.rs` — untouched here.

---

## 7. Decisions for owner review (why this plan STOPS here)

**D1 — Public `test_support` surface.** Promoting the whole fixture surface (TestApp,
MockServer, LaneSpec, ~hundreds of `pub(crate)` items) to `pub` behind `feature = "test-support"`
is a real, reviewer-visible API commitment even though `publish = false`. Alternatives:
(a) blanket-promote (least churn, widest surface); (b) a curated `pub` facade re-exporting only
what the plane test-kits need (smaller surface, more upfront curation). **Recommend (b)** for a
"world-class enterprise" posture, but it needs the owner's taste on the supported surface.

**D2 — `cargo test -p busbar-mcp` semantics.** After the cut, the bare per-crate command runs
only the native-safe tests (22 for mcp, 0 for a2a); the full suite needs
`--features test-support`. CI and any docs/scripts invoking bare per-crate tests must be
updated or the App-tests silently vanish. *Owner must accept the convention change.*

**D3 — Delete the `busbar_*_native` build scripts.** Reversible, but a large mechanical diff
(~139 cfg sites + 2 build.rs + Cargo check-cfgs). Confirm the owner wants the native cfg gone
entirely rather than kept as a belt-and-braces alias.

**D4 — New workspace crate `busbar-plane-tests`.** Low risk, reversible. Confirm crate name and
that App-*unit*-tests stay in-crate (moving them out is impossible without weakening
`pub(crate)` on plane internals); only cross-plane integration tests live in the new crate.

**D5 — Scope correction on calllog.** Confirm §1/§6: calllog/taskstore tests stay in core and
need no new public seam on `store::encode`. Moving them out would reintroduce the "public
tamper seam" problem as a separate, harder design. *Recommend NOT moving them.*

---

## 8. Verify matrix (post-implementation)

```
cargo build -p busbar-hook-test-plugin        # cdylib FIRST (hook tests panic otherwise)
cargo build --workspace
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo clippy --no-default-features --locked -- -D warnings
cargo fmt --check
cargo test --workspace                         # name-set parity vs baseline
cargo test -p busbar-a2a --features test-support
cargo test -p busbar-mcp --features test-support
cargo test -p busbar-plane-tests
```
Invariant: the **union of test names** across all binaries equals the pre-change union; core
`--lib` shrinks by exactly the plane population that reappears in the plane/plane-tests binaries.
