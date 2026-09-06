# The LLM plane's test-fixture seam — what still binds `busbar-llm` to `busbar-core`

Status: 1.6.0, wave D, task C9e. Companion to `1.6.0-llm-plane-abi-purity.md` (production scope) and
`plane-extraction-design.md` §2.1 item 2 (the reverse edge). This page is the TEST-scope half: what
the LLM plane's own test binary still names of the engine, why, and the only ladder that ends at
zero.

## 0. The measurement, not the impression

`scripts/plane-purity-lint.sh --strict` counts, per plane crate, the lines of that crate's OWN test
code that name `busbar_core::`. The same number is `ports-only-tests:<crate>` in
`scripts/construction-gate.sh`. For `busbar-llm` the walk is `877 → 565 → 23 → 20`.

The twenty lines that remain are not a long tail of sloppiness. They are four distinct shapes, and
each shape has a different reason for existing. Counting them as one number hides that, which is why
C9 has looked one repoint away from done for three waves running.

| shape | lines | what it names | why it is still core's |
| --- | ---: | --- | --- |
| the fixture glob | 1 | `busbar_core::test_support::*` | `TestApp` builds core's `App` |
| the request log | 3 | `proxy::reqlog::{RequestRecord, REQUESTS, …}` | sits on core's `audit::Chain` |
| the auth chain | 5 | `auth::AuthMiddleware::new_builtin` | builds core's middleware over core's `App` |
| the served handlers | 11 | `ingress::*`, `state::CurrentApp`, `admin::v1::service::*`, `config::RootCfg`, `config_validate::validate`, `plane::config::{Tools,Agents}Section`, `store::{HealthState, LaneData}` | each is an `App`-shaped call or an `App`-shaped document |

## 1. What the neutral fixture can and cannot be

The substrate already owns two test doubles a plane can drive with no engine at all:

* `busbar_substrate::testkit::fixture_host::FixtureHost` — an in-memory `EngineHost`. It models the
  breaker cells, the operator hook gate/rewrite chains, the per-key metering ledger and the cost
  leases. Everything else on the seam answers its documented empty value. `busbar-voice` is at
  test-reach 0 on exactly this, and carries no `busbar-core` edge at all.
* `busbar_substrate::testkit::loopback_http::MockServer` — a real loopback listener a plane points a
  lane at.

A `SUBSTRATE_ENGINE_KIT` — a substrate-owned `EngineTestKit` over those two — is buildable for every
verb on the seam that is APP-FREE. It is not buildable for `EngineTestKit::new_app`, and that is the
whole of C9e. `new_app` hands back a `Box<dyn TestAppKit>` whose `build` yields an `EngineApp`, and
`EngineApp::router` is `crate::build_router(app)` — the production HTTP stack with the real auth
middleware, the real governance guards and the real admin contract table mounted on it. A substrate
implementation of that is not a fixture; it is a second engine.

This is the load-bearing distinction, and it is measurable rather than a matter of taste:

* **39 of the LLM plane's test files** stand a `TestApp` up and serve requests through its router.
* **Zero** of the remaining tail lines are reachable by widening `FixtureHost`. Each names a type
  whose fields are `pub(crate)` on core's `App`, its in-memory store, or its config root.

So `busbar-voice`'s route — swap the engine for `FixtureHost` — does not generalise to `busbar-llm`.
Voice has no served-App tests to lose. The LLM plane's money-path tests ARE served-App tests: their
subject is what the engine bills, refuses and logs for a real request over a real router.

## 2. Why "move the App-bound tests into busbar-core" is not the answer either

The obvious escape is to declare those 39 files core integration tests in the wrong crate and move
them. They are not, and the tree says so. Their subject is `busbar-llm`'s own relocated money-path
engine, reached through its own internals:

| symbol | uses in the LLM test tree | visibility |
| --- | ---: | --- |
| `crate::engine::test_host_rt` | 243 | `pub(crate)` |
| `crate::engine::WeightedLane` | 126 | `pub(crate)` |
| `crate::engine::forward_with_pool` | 12 | `pub(crate)` |
| `crate::engine::AppEngineExt` | 11 | `pub(crate)` |

There are 355 `pub(crate)` items under `crates/busbar-llm/src`. Relocating these tests to
`busbar-core` or to `crates/busbar/tests/` means publishing the LLM plane's engine internals so a
foreign crate can name them. That trades a test-only dev edge for a permanent public surface on the
plugin — a strictly worse position for the same gate number, and it contradicts
`plane-extraction-design.md` §2.1 item 1, which puts a plane's tests in the plane crate on purpose.

A test that needs the plane's private engine AND the engine's real App belongs in the plane crate
with a core dev-dep. That is what it is today.

## 3. The seam that is genuinely available now

What the tail lines have in common is that most of them name a piece of core VOCABULARY, not a piece
of core BEHAVIOUR. Vocabulary has a neutral home available today; behaviour does not. Two moves
follow from that, and only two:

**Move A — relocate the neutral vocabulary by identity.** A core type whose whole content is neutral
belongs at its neutral home, with core re-exporting it so no caller changes. `CallerToken` is the
worked example landed with this page: an `Option<String>` newtype plus a redacting `Debug`, the twin
of `busbar_api::AuthPrincipal`, moved to `busbar_api::auth` beside it. Three test lines went away and
no behaviour did — the type is the same type. The remaining candidates of this shape, in descending
yield, are `store::{HealthState, LaneData}` (blocked: `pub(crate)` fields on core's live in-memory
store), `plane::config::{Tools,Agents}Section` (blocked: `Box<dyn PlaneCfg>` over core's section
registry) and `config::RootCfg` (blocked: it is the engine's resolved config root).

**Move B — widen the kit rather than the import.** Where the fact under test is core's BEHAVIOUR, the
sanctioned shape is already in the tree: a verb on `busbar_substrate::testkit::engine_kit::
EngineTestKit`, which the plane reaches through the one binding line. This is how `busbar-mcp` sits
at 1 and `busbar-a2a` at 3. Applied to the LLM tail it collapses `reqlog` (3), the admin service
verbs (2) and the config-validate line (1) into kit methods, and the auth chain (5) into a
`use_builtin_auth` setter on `TestAppKit`. It does NOT touch the eleven served-handler lines, because
a verb that hands back an axum handler is not object-safe in any useful way.

The floor Move A + Move B reach together is **1** — the fixture glob at `lib.rs:161-162`, which is
`TestApp`, which is core's `App`. Not zero.

## 4. The ladder to zero, in order

Zero is reachable, but it is not a fixture problem and it is not one task. In order, cheapest first:

1. **C9e (this page).** Move A on `CallerToken` (landed), then Move B on `reqlog` / admin service /
   `config_validate` / the auth chain. Lands the plane at test-reach 1 with no behaviour change and
   no assertion weakened.
2. **The served-handler eleven.** These follow the ingress arrivals: once
   `busbar_substrate::ingress::arrival::ArrivalHost` covers the ad-hoc and path-model entry points
   the tests call directly, the tests call the seam instead of `busbar_core::ingress::adhoc`, and
   `CurrentApp` goes with them.
3. **The glob.** `TestApp` stops naming core exactly when core's `App` does — i.e. at the composition
   -root endgame (`1.6.0-composition-root-plan.md` S6, wave D16/D33), where the engine is assembled
   from the substrate and `busbar-core` is deleted. `ports-only-tests:busbar-llm = 0` is a
   CONSEQUENCE of that step, not a prerequisite for it.

The honest statement of C9's remainder is therefore: **the LLM plane's core dev-dependency is held
open by one line, and that line is the App fixture, and the App fixture is core.** Every ratchet
below 1 is real work on the tail; the last one down to 0 is the deletion, and no neutral fixture
substitutes for it without deleting the assertions that make the money path provable.

## 5. Rules this page fixes

* A new test file in `busbar-llm` adds **zero** `busbar_core::` lines. Use `crate::test_support`,
  `crate::engine::test_host_rt`, and the engine kit.
* A ceiling in `qa/plane-purity-strict.toml` / `qa/construction.toml` moves DOWN to the measured
  count and never up. A ratchet that has to rise is a regression, not a re-baseline.
* A tail line is never retired by pointing an assertion at `FixtureHost` when the assertion's subject
  is what the real engine did. A capture that noops is not a proof; it is a deleted proof with the
  test name left behind.
