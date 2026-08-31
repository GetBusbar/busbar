# Testing strategy

How Busbar is tested, and how to add a test. Companion to
[development.md](development.md) (build/lint commands) and
[internals.md](internals.md) (the systems under test). The disposition taxonomy
is [ADR-0002](adr/0002-circuit-breaker.md).

## Shape of the suite

All tests are **in-crate** and run under `cargo test`. There is no `tests/`
directory of integration binaries. Two patterns:

- **Per-module `#[cfg(test)] mod tests`**: unit tests next to the code they cover
  (`store/` breaker FSM, `breaker.rs` classification, `sigv4.rs` against AWS's
  published worked example, `governance/` key/budget/rate, `config/` parsing,
  `ingress/` affinity, `proto/` translation round-trips, etc.). Most modules keep
  their tests in a `tests/` submodule (e.g. `store/tests/`, `governance/tests/`).
- **The `test_support/` harness**: a shared `#[cfg(test)] mod test_support`
  with the `MockServer` mock-upstream and the `TestApp` / `LaneSpec` builders used
  by the end-to-end forwarding tests.

## The MockServer harness (`crates/busbar/src/test_support/mod.rs`)

`MockServer` is a real axum server bound to `127.0.0.1:0` (ephemeral port) that
serves every upstream path through one handler: `/v1/messages` and
`/v1/chat/completions` have named routes, and a catch-all `.fallback` routes all
other paths (Bedrock `/model/{model}/converse[-stream]`, Gemini
`/v1beta/models/...`, Cohere `/v2/chat`) through the same handler. You program its
responses ahead of time by pushing onto a shared `MockServerState`:

- **`MockServerState`** holds a `Mutex<Vec<MockResponse>>` (LIFO: `push` then
  `pop` per request), plus the **last seen** auth header and request body for
  assertions (`get_last_auth_header`, `get_last_request_body`).
- **`MockResponse`** variants model upstream behaviors: `Ok { status, body }`,
  `RateLimit { status, provider_signal, retry_after }` (`retry_after:
  Option<u64>` emits a `Retry-After: <n>` header in whole seconds when set),
  `Billing { status, code, message }`, `Auth { status }`,
  `ServerError { status, body }`,
  `Sse { events, abort_at_index }` (the `abort_at_index` simulates a mid-stream
  upstream abort: it sends N events then an SSE `error` frame with no `[DONE]`,
  exercising the after-first-byte path),
  `SseTransportError { ok_events }` (emits the `ok_events` real SSE frames then
  makes the body stream yield an `Err`, a true mid-stream **transport** failure
  that exercises `FirstByteBody`'s `Err` arm rather than a clean SSE `error`
  text frame), and
  `EventStream { frames, amzn_request_id }` (a native AWS binary
  `application/vnd.amazon.eventstream` body as a real Bedrock ConverseStream
  backend emits: `frames` is the ordered `(event_type, json_payload)` sequence
  encoded via `eventstream::encode_frame`, and `amzn_request_id` is served as
  the `x-amzn-RequestId` header for testing same-protocol Bedrock passthrough).

```rust
let state = Arc::new(MockServerState::new());
state.push(MockResponse::ServerError {            // popped first
    status: StatusCode::INTERNAL_SERVER_ERROR,
    body: json!({ "error": "server error" }),
});
let server = MockServer::new(state.clone()).await;
// server.base_url() -> "http://127.0.0.1:<port>"
// ... drive a request ...
server.shutdown().await;                          // aborts the task
```

## Injecting time into the breaker FSM

Breaker/cooldown tests must not depend on wall-clock. The breaker reads time via
`store::now()` (the crate function in `crates/busbar/src/store/mod.rs`), which under
`#[cfg(test)]` is shadowed inside `InMemoryStore` (`store/in_memory.rs`) to delegate
to a thread-local `now_for_test()`:

- `set_now_for_test(t)` pins the test clock to `t` (epoch seconds).
- `now_for_test()` returns the pinned value (falling back to real `now()` if
  unset).

So a cooldown test sets the clock, records a failure, advances the clock past the
cooldown, and asserts the lane becomes usable again, all deterministically. The
store also exposes `#[cfg(test)]` lane-indexed handles (`open_state`,
`closed_state`, `open_state_with_retry_after`, `try_acquire_probe`, `clear_probe`,
`record_outcome_error_with_time`, `record_outcome_success_with_time`) to seed the
default cell's FSM/window directly without HTTP.

## The disposition matrix

The Stage 1b/Stage 2 pipeline (`breaker.rs`) is covered both as unit tests (raw
error → `StatusClass` → `Disposition`) and end-to-end via the `MockResponse`
variants that map onto each class: `Billing`/`Auth` → `HardDown`,
`RateLimit`/`ServerError` → `TransientUpstream`, an `Ok` with a context-length
provider code → `ContextLength`, and a plain 4xx → `ClientFault`. Because the
disposition `match` is exhaustive (no `_ =>`), adding a `StatusClass` forces a new
test arm to compile. Verify the **lane-effect** in each case: client faults and
context-length must **not** move the breaker (assert `streak`/`err` unchanged via
`/stats`-style `snapshot`), hard-down/transient must.

## Governance tests

`governance/tests/` runs against `GovState` and a `Store` backend directly, not
through HTTP. The backend is the compiled-in `MemoryStore` (`busbar-store-memory`),
built with `Arc::new(MemoryStore::new())` and wrapped in `GovState::new(store, None)`
(no durable file). Tests cover key CRUD via `create_key`, budget-window period math,
atomic charge-and-cap through `try_charge_request_within_budget` plus `refund_request`
(and the concurrent-overshoot guard on the store's `charge_within_budget`), the derived
token cost model (`gov.rate_card` / `budget_groups` / `price_per_request_cents` against a
`CostModel`), and metering accrual via `record_metering`. (`busbar-store-sqlite`'s own
`SqliteStore::open_in_memory()` round-trips live in that plugin crate's tests, not here.)

## Writing a new forwarding integration test

Drive `forward_with_pool` (or one of its `_keyed` / `_parsed` variants) against a
`MockServer`. Don't hand-write an `App` literal: the struct carries many hook/gate
fields and grows over releases, so build it with the `TestApp` builder in
`test_support/mod.rs`, which fills the rest from defaults. A lane is described by a
`LaneSpec` (model, protocol, upstream base URL, plus optional overrides). The empty
auth chain is the default when you set no `.auth(...)` (there is no `AuthMode`; the
old `mode: none`/`passthrough` distinction is now `.upstream_creds(...)`).

```rust
use crate::test_support::{LaneSpec, MockResponse, MockServer, MockServerState, TestApp};

#[tokio::test]
async fn my_forwarding_test() {
    crate::metrics::init();                       // so the forward path's counters record

    let state = Arc::new(MockServerState::new());
    state.push(MockResponse::Ok {
        status: StatusCode::OK,
        body: json!({ "content": ["Hello"], "model": "test" }),
    });
    let server = MockServer::new(state.clone()).await;

    // Build the App: one lane pointing at the mock, one pool over lane 0. Auth
    // defaults to the empty chain; governance/cost default to off.
    let app = TestApp::new()
        .lane(LaneSpec::new(
            "m",
            crate::proto::Protocol::anthropic(),
            &server.base_url(),
        ))
        .pool("default", &[(0, 1)])               // (lane_index, weight)
        .build();

    let body = serde_json::to_vec(&json!({
        "model": "m", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 100
    })).unwrap();
    let resp = forward_with_pool(
        app.clone(),
        vec![crate::state::WeightedLane { reasoning: None, idx: 0, weight: 1, attempt_timeout_ms: None }],
        body.into(),
        None,                    // caller_token (passthrough only)
        "default",               // pool name -> picks the per-pool breaker cell
        None,                    // affinity key
        "anthropic",             // ingress protocol
        crate::handlers::CHAT,   // the operation (Op)
        None,                    // usage sink (governance off)
    )
    .await;

    assert_eq!(resp.status().as_u16(), 200);
    server.shutdown().await;
}
```

`TestApp` exposes builder methods for the other seams: `.governance(...)`, `.cost(...)`,
`.failover(...)`, `.fallback_pool(...)`, `.on_exhausted(...)`, `.upstream_creds(...)`,
and `.hook(...)` / `.global_hook(...)`. See `crates/busbar/src/proxy/tests/` (e.g.
`forward_once_pool_cell_tests.rs`) for complete worked tests using exactly this shape.

Patterns this enables:

- **Failover**: give a pool two members backed by two `MockServer`s; push a
  `ServerError`/`RateLimit` on the first and an `Ok` on the second; assert the
  request still 200s and the first lane's breaker moved.
- **Cross-protocol**: set the lane's `protocol` to OpenAI and call with
  `ingress_protocol = "anthropic"`; assert the upstream `get_last_request_body`
  is OpenAI-shaped and the translated response preserves `model`.
- **Streaming + after-first-byte**: push `MockResponse::Sse { abort_at_index:
  Some(n) }`; assert the client gets the first n events then an SSE `error` frame
  (no failover) and the breaker records the fault.
- **Mid-stream transport error**: push `MockResponse::SseTransportError {
  ok_events }`; the body yields the real frames then an `Err`, exercising the
  after-first-byte mid-stream error path (`FirstByteBody`'s `Err` arm), which
  appends the ingress protocol's native mid-stream error frame after the
  already-sent frames.
- **Bedrock ConverseStream passthrough**: push `MockResponse::EventStream {
  frames, amzn_request_id }` with a Bedrock-protocol lane and a Bedrock ingress;
  assert the same-protocol path relays the binary event-stream verbatim,
  preserves the `application/vnd.amazon.eventstream` content type, and forwards
  the upstream `x-amzn-RequestId` rather than synthesizing a fresh one.
  Note: `MockServer`'s catch-all `.fallback` serves every path, so Bedrock's
  native egress path (`/model/{model}/converse-stream`) reaches the handler with
  no path override needed. Some existing lanes still set `.path("/v1/messages")`;
  that override is now optional (any path resolves to the same handler), since the
  same-protocol relay keys off the upstream Content-Type, not the URL. See
  `test_bedrock_same_protocol_stream_passthrough_forwards_upstream_request_id`
  in `crates/busbar/src/ingress/tests/tests.rs` for the full pattern.
- **on_exhausted**: populate `on_exhausted_cfgs` with `LeastBad` /
  `FallbackPool(..)` and pre-trip all members; assert the configured behavior
  (and loop-guarding for fallback chains).
- **Reading body bytes** in assertions: collect the response body with
  `http_body_util::BodyExt`'s `.collect().await`.

> Reminder: collect response bodies and assert metrics via
> `crate::metrics::render()`; call `crate::metrics::init()` once at the top of any
> test that exercises the forward path or its counters won't be installed.

---

# The remediation contract

This is the part of the strategy that decides **what a fix looks like**. It is
enforced by `scripts/structure-lint.sh` (the choke-point registry), not by
review discipline alone.

## The three rules

1. **A finding with a sibling is not a bug. It is a missing choke point.**
   If the same mistake is possible at a second call site, the defect is not the
   instance you found; it is that there are N places where the class can be got
   wrong. The unit of remediation is the choke point, not the instance.
2. **The fix is the choke point + ONE class-level test.** You introduce (or
   confirm) the single point every sibling passes through, route all of them
   through it, and attach exactly one test *there*. You do **not** patch N
   instances with N tests. That is N new places for the same mistake to recur.
3. **A repeat sibling means the class was never fixed.** If a later review finds
   another member of an already-remediated family, the previous remediation
   patched an instance instead of the class. Build the choke point that should
   have been built the first time, and route the whole family through it.

## The choke-point registry

`scripts/structure-lint.sh` carries a declarative `CHOKE_POINTS` table: one row
per choke point, with the owner, the class-level test, the patterns that bypass
it, and the allowed exceptions. **The table is the complete map**: if a hazard
class has a single point of truth in this tree, it is a row. Adding the next one
is a one-row addition: no new scanner, no new loop.

| Choke point | Owner (the correct implementation) | Enforced by | The ONE class-level test |
|---|---|---|---|
| **A: persistence** | `crates/busbar/src/durable.rs` (`durable::write` / `write_with`; `AppHandle::commit_and_swap` for persist-then-swap) | registry row `A-persistence`: a hand-rolled `std::fs::rename(` or `.sync_all(` outside `durable.rs` is `DURABLE-BYPASS` | `durable.rs::fault_matrix_returns_err_untouched_target_no_temp_leak`: every fallible step × injected errno, asserting the target is untouched and no temp leaks |
| **B: plugin FFI/ABI** | `crates/plugin-sdk/src/boundary.rs`, reached only via `export_*_plugin!` | registry row `B-plugin-export`: a hand-written `#[no_mangle]` outside the SDK macro is `EXPORT-BYPASS` (plus the duplicate-symbol link error a second `busbar_*` export triggers) | `plugin-sdk/tests/boundary_class.rs::null_out_pointer_never_leaks` (with the panic / unsupported / drop cases beside it) |
| **C: admin config mutation** | `crates/busbar/src/admin/v1/json/txn.rs` (`config_transaction`) | registry row `C-config-mutation`: naming `CONFIG_MUTATION_LOCK`, or calling `handle.swap(` / `.commit_and_swap(` outside `txn.rs` (`state.rs` defines them), is `MUTATION-BYPASS`. Backed by `scripts/txn-fence.sh` (compile fence) and `scripts/loom.sh` | `admin/v1/json/tests/txn_tests.rs::concurrent_transactions_never_lose_a_swap` |
| **D: OpenAPI error taxonomy** | `crates/busbar/src/admin/v1/contract/taxonomy.rs` (`declared_errors`, of which `openapi.json` is a *projection*) | **differently enforced**: there is no pattern to ban. The v1 router's recording layer **panics** on an under-claim at the moment of emission; the class test fails on the over-claim. The registry row still lists it (`rules = -`) so the table stays a complete map | `admin/tests/tests.rs::declared_error_set_is_exactly_what_the_handlers_emit`: registry == declaration, so under- **and** over-claim both fail |

| **H: the operator-authored ask** | `crates/busbar/src/mcp/callerask.rs` — `CallerAsk` lives in the private `authored` submodule, fields private to it, one constructor `from_config(&str, &AskEntryCfg)` | **half compiler, half registry.** Outside `authored` the fields do not exist, so no struct literal, no `From` impl and no field assignment can produce a `CallerAsk` from anything but operator config — the conversion cannot be *written*. Registry row `H-operator-authored-ask` closes the residual: an `AskEntryCfg` assembled in code rather than deserialised is `ASK-NOT-OPERATOR-AUTHORED` | `mcp/tests/callerask_tests.rs::the_asks_params_are_the_operators_bytes_and_nothing_else` |
| **I: the trust comparison** | `crates/busbar/src/trust/mod.rs` (`Approval::serves`), whose `pin` / `capabilities` / `suspension` fields are private to that module | registry row `I-trust-serve-derivation` bans re-deriving the answer inline from the raw registration fields (`schema_hash.is_some()`, `.pin.is_none()`, …) — `TRUST-COMPARISON-BYPASS`. The **positive** half is census row `trust-serve-decision`: exactly one `fn serves(` in the tree, where *zero* is `SUBJECT-MISSING` rather than a pass | `mcp/tests/trust_gate_tests.rs::the_routed_gate_answers_exactly_what_the_deleted_inline_decision_answered` |

(Rows E, F and G are in `CHOKE_POINTS` but not yet in this table — pre-existing
drift, noted here rather than left to be rediscovered.)

The lint asserts the class test still exists for **every** row, including D. A
choke point whose one test was deleted or renamed is a choke point nothing
proves, so `MISSING-CLASS-TEST` fails the build.

### Adding a choke point

Append one row to `CHOKE_POINTS` in `scripts/structure-lint.sh`:

```
'<id>|<TAG>|<owner file (what)>|<path>::<class test fn>|<remedy line>|<ere>>><what it is>>><allowed,paths>;<more rules>|<one-line rationale>'
```

Use `-` for the rules field when the choke point is enforced by the compiler or
at runtime rather than by grep (row D). Then plant a violation, confirm the lint
fails with your `TAG`, and remove it. A rule nobody has seen fire is a rule
that may not work.

## Checker rigor: R1 / R2 / R3

A self-check that cannot fail is worse than no check: it reports green while
asserting nothing. Three rules govern how tests and checkers are built.

### R1: Independent re-derivation (the RAW-source oracle)

The **expected** side of any cross-surface assertion must be re-derived from the
**raw source of record**, through a code path **disjoint** from the code under
test. Never compute both sides via the same accessor.

*Mechanical disjointness test:* if you can textually substitute the expected
expression into the actual expression and the assertion becomes `x == x`, it is
tautological, and that is a failure **of the checker**, not a passing test.

Raw sources of record in this tree:

- **persistence** → the bytes actually on disk after the swap (re-read the
  file), not the in-memory value that was written.
- **admin / OpenAPI taxonomy** → the frozen wire table in
  `admin/v1/contract/tests/tests.rs` plus the committed `openapi.json`, not the
  Rust enum re-serialized by the same code that serves it.
- **circuit breaker** → the store's observable state (`cell_open` / the probe
  holder), not a re-call of the transition function.

*Same-formatter corollary:* when the assertion is over rendered output, format
the oracle with the surface's own formatter. Derivation must be disjoint;
formatting must be shared. Comparing a differently-formatted oracle tests the
formatter, not the value.

### R2: Coverage assertion (inert branches are banned)

Every check-branch must be exercised by at least one fixture in the same run. A
branch reached by zero fixtures asserts nothing while reporting green, and is
itself a hard failure. In Rust the analogue is per-branch coverage over the
choke-point modules plus an "every enum variant has a behavioral test" census.
An exhaustive `match` (e.g. the `StatusClass → Disposition` taxonomy of
[ADR-0002](adr/0002-circuit-breaker.md)) makes the compiler the existence guard,
so only the behavioral arm needs asserting.

### R3: A defect test must not encode the defect

A code-vs-test comparison cannot catch a test that agrees with a broken
implementation: the test *is* the spec in that framing. (The archetype: the
`secrets:` tests once asserted that a `vault` module was **rejected**, locking
in a regression that broke a shipped feature. Green test, broken product.)

**A defect-fixing test is not accepted unless it satisfies at least one of:**

1. **Contract-derived**: expected values read out of the committed contract
   artifact (the frozen wire table, `openapi.json`, `declared_errors`), not
   restated inline. Encoding a wrong behavior would then also have to corrupt
   the contract, which is one reviewable diff instead of a silent per-test lie.
2. **RED-demonstrated**: shown failing on the pre-fix commit and passing after,
   recorded in the changeset as `RED at <sha>: <failure line>`. A test that was
   never RED against the bug it claims to guard may be encoding it.
3. **Independent-oracle cross-checked**: asserted against a second,
   independently-authored surface computing the same fact (the `openapi-schema`
   feature's emitted doc versus the served error responses), so neither side can
   silently encode the bug without the other disagreeing.

A hand-written `assert_eq!(actual, <inline constant>)` that merely restates what
the code does satisfies none of the three and is a **self-agreeing test**.

## Changeset discipline

Every defect-fixing changeset records three things:

- the **choke point** it attaches to (an id from the registry, or the new row it
  adds),
- the **one class-level test**, and
- the **RED-before note**: `RED at <sha>: <failure line>`.

A changeset that adds a per-instance test without naming a choke point is a
latent process failure and is rejected in review.
