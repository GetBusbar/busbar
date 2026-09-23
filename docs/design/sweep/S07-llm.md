# S07-llm — the LLM plugin crate, swept

Slice: `crates/busbar-llm` (83 files). Denominator: `/Users/matthew/Developer/GetBusbar/.sweep/S07-llm.txt`.
X-id block: X-1600 .. X-1699.

All paths in the table below are repo-relative. The slice was swept in three passes over disjoint
thirds of the denominator (21 + 31 + 31 = 83). **Every one of the 8 FINDING rows was independently
re-run and re-verified at the top level before being written here** — no finding in this report rests
on a delegated claim alone. Two delegated claims did not survive that re-verification and were
corrected; both corrections are recorded in the rows they affect.

## Standing facts this slice established before any file was judged

**THIS IS THE ONE PLANE THE ORACLE CAN SEE — 149 declared cells, 140 witnessed, 9 NOT.** That is the
opposite posture from S08-a2a (468 declared, 0 witnessed), and it is why behavioural drift in this
crate is detectable at all. Measured, with a positive control and with one false start corrected:

```
$ python3 -c "import json;d=json.load(open('testing/shadow-oracle/cells.json'));print(d['counts']['by_plane'])"
{'a2a': 468, 'core': 789, 'llm': 149, 'mcp': 912}
$ ls testing/shadow-oracle/golden/1.5.5/cells | grep -c '^llm'
133
$ ls testing/shadow-oracle/golden/1.5.5/cells | grep -c '^teller'
7                       # 133 + 7 = 140 witnessed
$ ls testing/shadow-oracle/golden/1.5.5/cells | grep -c '^a2a'
0                       # POSITIVE CONTROL: the same command shape returns 0 for the blind plane
```

The 149 splits `142` dialect cells (`llm|…`) plus `7` teller cells (`teller|…`, `plane: llm`,
`family: teller`) — the teller-waist step cells, and all 7 ARE witnessed.

**A FALSE ZERO I PRODUCED AND KILLED, recorded because the CONTRACT asks for it.** My first
declared-vs-witnessed diff compared declared ids (`llm|anthropic|anthropic|request|ok`) against
golden filenames (`llm__anthropic__anthropic__request__ok.json`) without normalizing the separator,
and reported **"declared-but-unwitnessed: 149"** — i.e. that NOTHING was witnessed, in the one plane
that is. The separator normalization plus a positive control (a cell known to be witnessed must be
found by the same lookup) gives the real answer:

```
$ python3 …  norm = id.replace('|','__') ;  missing = [i for i in ids if norm[i] not in golden]
declared llm cells   : 142
witnessed (golden)   : 133
declared-unwitnessed : 9
control (should be True): True
```

**THE 9 UNWITNESSED CELLS ARE NOT SCATTERED — 6 OF THEM ARE ONE BEHAVIOUR, ON EVERY DIALECT:**

```
llm|anthropic|anthropic|request|stream_upstream_error      llm|gemini|gemini|request|stream_upstream_error
llm|bedrock|bedrock|request|stream_upstream_error          llm|openai|openai|request|stream_upstream_error
llm|cohere|cohere|request|stream_upstream_error            llm|responses|responses|request|stream_upstream_error
llm|bedrock|bedrock|request|ok_cachepoint_document         llm|responses|responses|request|ok_citation
llm|gemini|gemini|request|ok_tool_use_tokens
```

The mid-stream-error path — a stream that dies after a 2xx head — has **zero 1.5.5 witness on all six
dialects**. It is simultaneously a customer surface (the client sees a truncated stream) and a money
surface (`billing_failed`, the `Partial` finish class, and whether a died-mid-body stream is charged).
Raised as **X-1604**, out of slice, PARK. See "Out of slice" at the end.

**`construction:plane-no-money` IS RED TODAY, AND ITS ONE OFFENDER IS NOT IN THIS SLICE.** The task
brief pointed at `crates/busbar-llm/src/unit/meter.rs:490`. Verified — `priced_from_ms: 0` is there,
a plane-side unit module naming a price. But it is **not a discovery**: `qa/construction.toml:1737-1740`
already names that exact file, line and symbol, states that the row "stays RED at 1", and explains why
it is deliberately not allowlisted. `meter.rs` is also **not in the S07-llm denominator** (the slice
holds `unit/{arrival,authenticate,chain,mod,route}.rs` and `unit/tests/*`, not `meter.rs`,
`approve.rs` or `walk.rs`). No X-id raised: re-reporting an owner-documented standing red as a new
finding would be noise. Recorded here so the next reader does not re-derive it a third time.

**THE `teller-waist` CODE SHIPS, DESPITE ITS OWN MANIFEST COMMENT.** `crates/busbar-llm/Cargo.toml:71`
says the `unit/` directory is "DEFAULT OFF … compiles to nothing". That is true of `busbar-llm`'s own
default and **false for the shipped binary**: `busbar/Cargo.toml:280` has
`root-llm = ["proto-llm", "busbar-llm?/teller-waist"]` and `root-llm` is in `busbar`'s default, so the
weak-`?` forward activates. This is already logged as **ENG28 (OPEN)** in `docs/design/1.6.0-LEDGER.md:713`,
proven there by a deliberate-type-error plant rather than by reading `cargo tree`. No new X-id. It
matters to this slice because it is what makes `unit/*.rs` PRODUCTION code rather than dark code, and
every `unit/` verdict below was judged on that basis.

## Verdicts

| FILE | VERDICT | EVIDENCE | ROWS |
|---|---|---|---|
| crates/busbar-llm/src/arrival.rs | CLEAN | Read 606L. `git grep -n "arrival::" crates/busbar-llm/src/lib.rs` → `PATH_INGRESS`/`BODY_INGRESS` bind all 8 arrival fns (gemini/bedrock path + 6 body). Every `PathArrivalFacts` arm answered, incl. the documented-unreachable `BodyModel` arm. | - |
| crates/busbar-llm/src/engine/attempt/assemble.rs | CLEAN | Read 334L. `git grep -n "pub(crate) mod assemble" engine/attempt/mod.rs` → declared. `inject_openai_stream_include_usage{,_pristine}` re-exported at attempt/mod.rs:30-32, consumed by engine_tests/inject_include_usage_tests.rs. No f64; every error path returns explicit `Err(Response)`. | - |
| crates/busbar-llm/src/engine/attempt/classify.rs | CLEAN | Read 364L. `git grep -n "pub enum Disposition" crates/busbar-contract/src/upstream.rs` → 4 variants; `classify_error`'s match is exhaustive over all 4. `mod tests;` at :363 → tests/classify.rs. | - |
| crates/busbar-llm/src/engine/attempt/mod.rs | CLEAN | Read 234L. Declares assemble/buffered/classify/respond/send; `ls engine/attempt/` confirms all 5 present. Sole upstream-send site; every early return drops the permit / releases the probe guard explicitly. | - |
| crates/busbar-llm/src/engine/attempt/send.rs | CLEAN | Read 76L. `SendOutcome`/`EgressSendError` both consumed in attempt/mod.rs. No arithmetic beyond a guarded `.max(1)` floor. | - |
| crates/busbar-llm/src/engine/attempt/tests/classify.rs | CLEAN | Read 43L. 2 tests, each with paired positive+negative assertions (case-fold accept AND illegal-name reject). | - |
| crates/busbar-llm/src/engine/build_runtime.rs | CLEAN | Read 400L. `git grep -n "build_runtime::\(build_runtime\|resolve_provider\|viewer\)" crates/busbar-llm/src/lib.rs` → all 3 fn-pointers wired into `PLANE_DECL` (:274/:275/:284), none left `None`. | - |
| crates/busbar-llm/src/engine/engine_tests/crossproto_delivery_billing_tests.rs | FINDING | Read 306L — 3 real money-differential tests (22-token bill; 0-token non-delivery ×2; refund assertions). `git grep -n "crates/busbar-core/src" -- 'crates/busbar-llm/**/*.rs'` → :4 names `crates/busbar-core/src/proxy/engine/mod.rs`; `ls -d crates/busbar-core` → No such file or directory. | X-1600 |
| crates/busbar-llm/src/engine/engine_tests/future_size_probe.rs | CLEAN | Read 63L. Real byte-size tripwire: `size_of_val(&fut) <= FORWARD_FUTURE_MAX_BYTES` (3800) — goes red on a future-size regression. | - |
| crates/busbar-llm/src/engine/engine_tests/inject_include_usage_tests.rs | FINDING | Read 204L — 9 tests, real (JSON-pointer checks, duplicate-key byte scans, byte-identical splice proofs). Same grep as above → :4 names the deleted `crates/busbar-core/src/proxy/engine/mod.rs`; real definition is `attempt/assemble.rs`. | X-1600 |
| crates/busbar-llm/src/engine/engine_tests/send_envelope_tests.rs | CLEAN | Read 170L. Black-hole-socket tests assert `status().is_server_error()` AND `app.store.snapshot(0,now()).err == 1` — the breaker mutation, not just the status. | - |
| crates/busbar-llm/src/engine/engine_tests/stream_deadline_tests.rs | CLEAN | Read 147L. Differential at two configured deadlines (`cut_after(7)==7s`, `cut_after(23)==23s`) — rules out an idle-timer false positive. | - |
| crates/busbar-llm/src/engine/exhaustion/least_bad.rs | CLEAN | Read 104L. `Err(())` from `dispatch_degraded` maps to `handle_status_503(…)`; no failure is swallowed — every exit renders a client-visible outcome. | - |
| crates/busbar-llm/src/engine/exhaustion/mod.rs | CLEAN | Read 337L. `handle_exhaustion_for_pool` matches all 4 `OnExhausted` modes; `dispatch_degraded` exhaustive over `AttemptOutcome`'s 3 variants. | - |
| crates/busbar-llm/src/engine/exhaustion/queue.rs | CLEAN | Read 194L. Every loop exit (deadline win / semaphore closed / breaker denied) ends in a real response or a controlled `continue`. Reads `request_ctx.excluded_reasons` at :58 in production (see X-1601). | - |
| crates/busbar-llm/src/engine/health.rs | CLEAN | Read 540L. Exhaustive `match disposition` over all 4 variants; `read_capped_error_body` bounds an unbounded-allocation surface; `mod tests;` at :539. | - |
| crates/busbar-llm/src/engine/hooks.rs | CLEAN | Read 1073L in sections. `grep -n "allow(dead_code)\|unwrap()\|expect(\"" hooks.rs` → 0 hits (control: `git grep -c "unwrap()"` finds many in sibling test files, so the pattern is not glob-eaten). `git grep -n "decide_policy_order(\|apply_global_rewrites(\|capture_stage_shape("` → all 3 called from production pipeline.rs / unit/route.rs. | - |
| crates/busbar-llm/src/engine/lazy_body.rs | CLEAN | Read 327L. `git grep -n "LazyBody::parse\|from_value\|ensure_dom(\|ensure_ir(\|head_provably_pristine("` → every method has a production caller (pipeline.rs, native_ingress.rs, unit/arrival.rs, unit/route.rs), none test-only. | - |
| crates/busbar-llm/src/engine/mod.rs | CLEAN | Read 252L. Every `#[path]`-declared test mod (39) has a backing file: `while read f; do test -f "$f" \|\| echo MISSING; done` → no MISSING lines. Every `pub(crate) mod` submodule exists on disk. | - |
| crates/busbar-llm/src/engine/response_body.rs | CLEAN | Read 998L in sections. One `#[allow(dead_code)]` on `UsageSink.admit` (:45) — traced and legitimate: populated with a real `Some(handle)` at native_ingress.rs:428/:518 and unit/admit.rs:175; it is an RAII-Drop-only field, never read by design, and documented as such. | - |
| crates/busbar-llm/src/engine/select.rs | FINDING | Read 629L. :48 carries `#[cfg_attr(not(test), allow(dead_code))]` on `excluded_reasons` with the comment "Consumed by the queue/least_bad/Retry-After wiring in a later phase". `git grep -n "excluded_reasons"` → **production** read at `exhaustion/queue.rs:58` (`for (lane, reason) in &request_ctx.excluded_reasons`), inside a plain async fn, not test-gated. | X-1601 |
| crates/busbar-llm/src/engine/tables.rs | FINDING | Read 612L. :56 `#[allow(dead_code)] pub(crate) max: usize,` with no justifying comment. `git grep -n "\.max\b" -- 'crates/busbar-llm/**/*.rs' \| grep -v "\.max("` → rc=1, zero reads. Populated at build_runtime.rs:226 (`max: li.max_concurrent`). Real cap lives in `busbar_kernel::store::LaneRuntime` built at appbuild.rs:704-705. | X-1602 |
| crates/busbar-llm/src/engine/tests/alloc_gate_tests.rs | CLEAN | Read 456L. 4 real allocation-count gates (`TRANSLATE_WRITE_ALLOCS == 0`; per-dialect seam-vs-direct parity ×6; `FORWARD_PASSTHROUGH_MAX_ALLOCS <= 107`; scaling delta) backed by `CountingJemalloc`. Gated `#[cfg(all(test, not(target_env="msvc")))]` at engine/mod.rs:250. | - |
| crates/busbar-llm/src/engine/tests/attempt_timeout_precedence_tests.rs | CLEAN | Read 107L. 6 tests with precise numeric assertions; `attempt_cap` budget floor clamps to 1ms, never 0. | - |
| crates/busbar-llm/src/engine/tests/auth_dispatch_tests.rs | CLEAN | 1485L, `grep -c "#\[tokio::test\]\|#\[test\]"` → 15, 39 asserts. Read `test_governance_revoked_signed_token_key_rejected` in full — real before/after differential (200 pre-revoke → 401 post-revoke) over a live socket. | - |
| crates/busbar-llm/src/engine/tests/auth_style_tests.rs | CLEAN | Read 245L. Backslash-authority desync regression (`host_from_base` vs WHATWG parser), keyless-lane no-auth-header proof, SigV4 canonical-vs-wire path parity. | - |
| crates/busbar-llm/src/engine/tests/client_header_forwarding_tests.rs | CLEAN | Read 433L in sections. 9 tests; `client_anthropic_beta_does_not_leak_to_openai_upstream` and `no_client_beta_leaves_egress_unchanged` both assert explicit `None`/`is_some()` on the mock upstream's received headers. | - |
| crates/busbar-llm/src/engine/tests/egress_differential_tests.rs | CLEAN | Read 391L in sections. 5 tests over a two-stack (owned-hyper vs pinned-reqwest) differential harness against live TLS/mTLS/redirect fixtures; compares structural `Outcome` enums + request-line counts (SSRF-class second-hop guard). | - |
| crates/busbar-llm/src/engine/tests/egress_dropped_controls_audit_tests.rs | CLEAN | Read 175L. 3 tests asserting presence AND absence of specific audit-ring entries with exact `resource`/`outcome` field values. | - |
| crates/busbar-llm/src/engine/tests/forward_once_pool_cell_tests.rs | CLEAN | Read 643L in sections. Real breaker before/after assertions on the correct per-pool cell vs the default `""` cell. | - |
| crates/busbar-llm/src/engine/tests/forward_pool_integration_tests.rs | CLEAN | `grep -c` → 88 tests / 263 asserts; `grep -n "assert!(true)\|assert_eq!(1, 1)\|todo!()\|unimplemented!"` → 0. Sampled `test_cross_protocol_nonstream_records_tokens_for_tpm` (200 then 429 after TPM token recording, live governed round-trip) and `test_bounded_max_concurrent_still_enforces_the_cap`. | - |
| crates/busbar-llm/src/engine/tests/gate_policy_503_literals_tests.rs | CLEAN | Read 235L. 6 tests pinning 4 distinct client-visible 503 literals to their producing hook seat, plus a pairwise-distinctness proof. | - |
| crates/busbar-llm/src/engine/tests/health_tests.rs | FINDING | `git grep -n 'path = "tests/health_tests.rs"' engine/health.rs` → :539 reachable. 16 tests, real asserts. `git grep -n "crates/busbar-core/src" -- 'crates/busbar-llm/**/*.rs'` → :4 names `crates/busbar-core/src/health.rs`; `ls -d crates/busbar-core` → No such file or directory. | X-1600 |
| crates/busbar-llm/src/engine/tests/hook_non_chat_projection_tests.rs | CLEAN | Declared engine/mod.rs:167. Read 172L, 8 tests; each asserts real content (`gate_view(&f).contains(…)`, OPAQUE_CONTENT_MARKER, Absent-semantics). | - |
| crates/busbar-llm/src/engine/tests/hook_opt_in_projection_tests.rs | CLEAN | Declared engine/mod.rs:170. 26 tests / 105 asserts; `grep -n 'assert!(true)'` → none. | - |
| crates/busbar-llm/src/engine/tests/hook_seam_tests.rs | CLEAN | Declared engine/mod.rs:173. 2445L, 45 tests. Sampled `max_tokens_saturates_not_wraps` — checks `None` AND `assert_ne!` against the wrap value. | - |
| crates/busbar-llm/src/engine/tests/hook_seat_order_tests.rs | CLEAN | Declared engine/mod.rs:176. Read 344L, 2 tests: end-to-end billing/refund proof — admission kept + spend refunded on gate reject; billed-once + ordered seats on the served path. Both directions present. | - |
| crates/busbar-llm/src/engine/tests/ingress_integration_tests.rs | CLEAN | Declared engine/mod.rs:182. 6687L, 108 tests. `#[ignore = "timing gate…"]` at :2232 is CI-wired, not orphaned: `ci.yml:2502` runs `cargo test --release --locked timing_gate -- --ignored`, and xtask/src/full_gate.rs:201. Sampled `test_unpriced_passthrough_model_rejected_when_rate_card_present` (asserts the rejection AND that a priced lane still admits). | - |
| crates/busbar-llm/src/engine/tests/ingress_reject_response_tests.rs | CLEAN | Declared engine/mod.rs:185. Read 59L, 2 tests: asserts the leak is ABSENT (`!detail.contains("Verb")`), deliberately not a vacuous `contains`. | - |
| crates/busbar-llm/src/engine/tests/lane_availability_proptest_tests.rs | CLEAN | Declared engine/mod.rs:188 (mod name `lane_availability_proptest`). Read 745L: proptest plus an explicit teeth test `invariant_rejects_park_then_serve_primary_witness` proving the assertion fn can itself fail; budget contract over all 4 `OnExhausted` policies. | - |
| crates/busbar-llm/src/engine/tests/lazy_body_tests.rs | FINDING | `git grep -n 'path = "tests/lazy_body_tests.rs"' engine/lazy_body.rs` → :326 reachable. 28 assert sites, real head/DOM divergence + malformed-body parity. Same busbar-core grep → :4 names `crates/busbar-core/src/proxy/lazy_body.rs`, a deleted path. | X-1600 |
| crates/busbar-llm/src/engine/tests/legacy_forward_once.rs | CLEAN | `git grep -n legacy_forward_once` → declared `#[path]` from attempt_identity_tests.rs:25, itself declared at engine/attempt/mod.rs:233; `legacy::forward_once(` called at :550. `#![allow(dead_code)]` is intentional — it is the identity-oracle twin, not orphaned code. | - |
| crates/busbar-llm/src/engine/tests/mid_stream_error_tests.rs | CLEAN | Declared engine/mod.rs:191. `test_mid_stream_generic_detail_has_no_leak_markers` checks an explicit LEAK_MARKERS list against every client-facing fallback across 6 dialects incl. the Gemini array-stream framer and Cohere message-end. (Behaviour is tested here but UNWITNESSED by the oracle — see X-1604.) | - |
| crates/busbar-llm/src/engine/tests/multi_candidate_degrade_tests.rs | CLEAN | Declared engine/mod.rs:194. Drives the real `translate_request_cross_protocol`; asserts precise translated-body shape (`n` dropped for Anthropic egress, messages present). | - |
| crates/busbar-llm/src/engine/tests/on_exhausted_tests.rs | CLEAN | Declared engine/mod.rs:197. 1697L, 35 tests; `grep -n '#\[ignore\|todo!\|unimplemented!\|FIXME'` → none. Includes a self-referential fallback-loop guard and a negative regression control (`tripped_member_still_falls_back_to_overflow`). | - |
| crates/busbar-llm/src/engine/tests/ordered_walk_tests.rs | CLEAN | Declared engine/mod.rs:200. Real weight/drain/sticky-affinity assertions; `excluded_reasons_records_at_capacity` asserts the taxonomy this slice's X-1601 concerns. | - |
| crates/busbar-llm/src/engine/tests/pool_upstream_creds_tests.rs | CLEAN | Declared engine/mod.rs:203. Read 84L, 2 tests covering both the fast path (no override) and full lookup (override present) with distinct per-pool assertions. | - |
| crates/busbar-llm/src/engine/tests/probe_guard_tests.rs | CLEAN | Declared engine/mod.rs:206. Read 119L, 3 tests: armed-drop-releases, disarmed-drop-holds, stalled/superseded-epoch no-op — real race coverage against `HealthState`. | - |
| crates/busbar-llm/src/engine/tests/probe_release_owner_tests.rs | FINDING | Declared engine/mod.rs:209; the test itself is a real end-to-end race proof. Header claims "The four post-`.await` single-flight-probe release sites in `engine/mod.rs`". `grep -n "release_probe" crates/busbar-llm/src/engine/mod.rs` → rc=1, ZERO hits. Real sites: exhaustion/mod.rs:240, pipeline.rs:2047, plus the Drop in select.rs:254. | X-1603 |
| crates/busbar-llm/src/engine/tests/reqlog_dispatch_tests.rs | CLEAN | Declared engine/mod.rs:212. Cross-checked the doc's own falsifiability claim: `git grep -n "fn finish_inner"` → busbar-kernel/src/ingress/mod.rs:571, and `REQUESTS.record(…)` at :648 inside it. Both tests drive a real request and verify the hash chain (`verify_principal_chain`). | - |
| crates/busbar-llm/src/engine/tests/request_short_circuit_tests.rs | CLEAN | Declared engine/mod.rs:215. 11 tests; `assert_ne!` used 4× for negative fidelity alongside positive byte-identity checks. | - |
| crates/busbar-llm/src/engine/tests/reroute_pool_tests.rs | CLEAN | Declared engine/mod.rs:218. Verified the shared-seam claim: `git grep -n "fn walk_with" crates/busbar-kernel/src` → failover/mod.rs:658; sibling files exist under busbar-mcp and busbar-a2a as the header claims. | - |
| crates/busbar-llm/src/engine/tests/responses_ingress_stream_tests.rs | CLEAN | Declared engine/mod.rs:221. Money-adjacent and NON-zero: asserts `usage.tokens == IN_TOK+OUT_TOK` (18) and `input_tokens==11`/`output_tokens==7` across 6 egress dialects. This is the positive control for the bills-zero test below. | - |
| crates/busbar-llm/src/engine/tests/route_deadline_tests.rs | CLEAN | Declared engine/mod.rs:224. Distinguishes two distinct 503 shapes (deadline vs exhaustion terminal) on kind/detail/headers. | - |
| crates/busbar-llm/src/engine/tests/runtime_carry_tests.rs | CLEAN | Declared engine/mod.rs:227. Read 106L, 2 tests: pointer-identity proofs with a positive half (carries) and a negative half (must NOT carry) for both the probe schedule and the client pool. | - |
| crates/busbar-llm/src/engine/tests/scrape_queued_depth_tests.rs | CLEAN | Declared engine/mod.rs:230. Read 61L: asserts the gauge reads `Some(1.0)` while parked and `Some(0.0)` after drop — explicitly not a literal-zero check. | - |
| crates/busbar-llm/src/engine/tests/signal_catalog_tests.rs | CLEAN | Declared engine/mod.rs:233. Real declared-vs-undeclared signal gating via a capturing policy. | - |
| crates/busbar-llm/src/engine/tests/stop_sequence_cap_degrade_tests.rs | CLEAN | Declared engine/mod.rs:236. Precise value assertion: `stop_sequences == ["a","b","c","d","e"]`, clamped to Cohere's cap of 5. | - |
| crates/busbar-llm/src/engine/tests/stream_no_usage_bills_zero_tests.rs | CLEAN | Declared engine/mod.rs:239. Read 180L over 6 dialects: asserts `usage.tokens==0`, `spend_cents==0` AND `row.requests==1` (a non-zero component in the same test), against a LIVE rate card (input_utok=2.0/output_utok=6.0) so a broken zero-guard would be caught. Not instrument-blind. | - |
| crates/busbar-llm/src/engine/tests/translate_offload_tests.rs | CLEAN | Declared engine/mod.rs:242. Threshold claim cross-checked: `git grep -n TRANSLATE_OFFLOAD_THRESHOLD` → attempt/assemble.rs:18 `= 128 * 1024`, matching the test's 300 KiB body / 128 KiB assertion. | - |
| crates/busbar-llm/src/engine/tests/usage_tap_tests.rs | CLEAN | Declared engine/mod.rs:245. 8 tests. Money-critical and genuinely two-sided: `test_nonstream_token_fee_uses_charged_at_window_not_clock` (1000 tokens in the right window AND `== 0` in the wrong one), `..._saturates_no_panic_on_overflow` (u64::MAX+5), `ledger_prices_an_aliased_lane_at_the_rate_card` (`spend_cents == 100` exact). | - |
| crates/busbar-llm/src/engine/tests/wire_tests.rs | FINDING | `git grep -n 'path = "tests/wire_tests.rs"' engine/wire.rs` → :849 reachable. Real 2×2 gate matrix + a golden `client_fault_kind` table cross-checked against `StatusClass`. Same busbar-core grep → :4 names `crates/busbar-core/src/proxy/wire.rs`, a deleted path. | X-1600 |
| crates/busbar-llm/src/engine/wire.rs | CLEAN | Production scrutiny. `grep -n "\.unwrap()\|f64\|\.expect(\|panic!\|unreachable!"` → 0 hits. Money-vocabulary grep hits only `KIND_RATE_LIMIT` and doc prose — no money arithmetic here. Every `pub(crate)` item has a non-test caller (spot-verified `shape_cross_protocol_error` ← attempt/classify.rs:151, `client_fault_kind` ← :236). Every serialization-failure path returns a shaped error, never an empty body. | - |
| crates/busbar-llm/src/lib.rs | CLEAN | Read 367L. `PLANE_DECL` fields all accounted for; `build_runtime`/`viewer`/`resolve_provider` are `Some(…)`, the `None`s are the documented fallback-plane stance. `wire_format_names` is the registry fn itself, pinned by-pointer at tests/plane_decl_identity_tests.rs. | - |
| crates/busbar-llm/src/multipart_model_tests.rs | CLEAN | Read 94L. Declared `#[path]` at native_ingress.rs:998. 4 tests incl. the decoy-model security case (`a_decoy_model_inside_another_parts_value_does_not_win`) and the two-model→None refusal — both assert the billed model equals the served model. | - |
| crates/busbar-llm/src/native_ingress.rs | CLEAN | Read 999L. The money path: `usage_sink` built only when `(governance, key)` are both present; `admission_door` refusal returns before any charge; `finish_admitted_via_audit` carries the `charged` flag. `multipart_model` walks boundaries rather than scanning — no billed/served divergence. | - |
| crates/busbar-llm/src/testkit.rs | CLEAN | Read 44L. `install_test_seams` registers protocol+plane+path/body ingress+completion ingress+stream-translator factory — the same 5 writes production `main.rs` makes. `#[cfg(any(test, feature="test-support"))]` gated at lib.rs:361. | - |
| crates/busbar-llm/src/tests/arrival_tests.rs | CLEAN | Read 360L. Declared `#[path]` at arrival.rs:605. Drives both dialect URL parses over a reduced `ParseHost`; the `#[cfg(feature="teller-waist")]` two-step identity test compares handler resolution BY POINTER against the live lookup. | - |
| crates/busbar-llm/src/tests/plane_decl_identity_tests.rs | CLEAN | Read 17L. Declared at lib.rs:361. Asserts `PLANE_DECL.wire_format_names as usize == known_protocols as usize` — a restated dialect list is a different fn pointer and fails. A real instrument. | - |
| crates/busbar-llm/src/tests/webhook_tests.rs | CLEAN | Read 273L. Declared `#[path]` at openai_responses_webhook.rs:368. Real auth verification: tampered body, wrong secret, unsigned, non-v1 token, rotation window, malformed secret → each asserts a specific `WebhookReject`. A verify that can fail. | - |
| crates/busbar-llm/src/unit/arrival.rs | CLEAN | Read 314L. Closed 3-reason refusal set; each `(status, kind, message)` triple is the 1.5.5 literal, pinned against the live site by tests/arrival.rs. Renders nothing itself — returns `RefusalOutcome` for the audit terminal. | - |
| crates/busbar-llm/src/unit/authenticate.rs | CLEAN | Read 79L. Empty refusal set, and that is honest: the 401 is the middleware's (`resolve_data_plane_identity`). `anonymous_actor_id()` READS `AuthPrincipal(None).actor_id()` rather than respelling "anonymous". | - |
| crates/busbar-llm/src/unit/chain.rs | CLEAN | Read 55L. `#![cfg(test)]` file whose only content is the `#[path]` to tests/chain.rs; the doubled gate is deliberate and documented (tree scanners classify by `*/tests/*` and `#[cfg(test)] mod`, which a file-level inner attribute is not). | - |
| crates/busbar-llm/src/unit/mod.rs | CLEAN | Read 82L. Every step module declared; `audit` is unconditional by design (the legacy path posts through its neutral half with the waist down), the rest are `#[cfg(feature="teller-waist")]` — which ships (see standing facts). | - |
| crates/busbar-llm/src/unit/route.rs | CLEAN | Read 501L. `git grep -n "unit::route"` → driven by unit/walk.rs:631/:653, itself driven by `crates/busbar/src/root/units_llm.rs:93`. Records `accrued` BEFORE the sink moves into the walk; the candidate-miss arm refuses with the sink handed BACK unspent rather than dropping it. | - |
| crates/busbar-llm/src/unit/tests/admit.rs | CLEAN | Read 368L. Two-leg money identity: live door then step, asserting the ledger moves by the same delta on all three figures — `(1,1,1)` → `(2,2,2)` — plus an over-budget leg proving 429 with all counters untouched and nothing to refund. | - |
| crates/busbar-llm/src/unit/tests/arrival.rs | CLEAN | Read 437L. Runs the whole recorded request corpus (`assert!(out.len() > 40)` guards corpus shrinkage) and compares step vs live parse; every refusal rendered through the terminal is compared to the legacy bytes with only the synthesized request-id normalized. | - |
| crates/busbar-llm/src/unit/tests/audit.rs | CLEAN | Read 665L. Byte-identity table over 8 refusal classes × 6 dialects (`assert_eq!(classes.len(), 8)` guards the table); asserts the two doors post DIFFERENT evidence for the SAME bytes, and that every chain written verifies. | - |
| crates/busbar-llm/src/unit/tests/authenticate.rs | CLEAN | Read 92L. Pins both arms against the live accessor, and `no_input_the_middleware_can_leave_makes_this_step_refuse` makes the empty refusal set a measured claim rather than a comment. | - |
| crates/busbar-llm/src/unit/tests/chain.rs | CLEAN | Read 1976L in sections. The rehearsal: legacy vs chained legs over shared fixtures. `the_chain_leaves_the_money_where_the_legacy_plane_leaves_it` asserts exact ledger tokens + metering rows across streamed/buffered/failed/refused/post-door ends. All 8 named seam gaps are marked CLOSED, matching the TRACKER. | - |
| crates/busbar-llm/src/unit/tests/decode.rs | CLEAN | Read 555L. Model ladder vs live ladder over the whole corpus; the two 404s are asserted DISTINCT (`assert_ne!`) so collapsing them is red; ordering pin proves body-model answers handler-miss before parse-miss. | - |
| crates/busbar-llm/src/unit/tests/route.rs | CLEAN | Read 814L. 12-case live-vs-step identity (`assert_eq!(cases, 12)` guards table collapse) comparing status/headers/body/breaker/cooldown/budget/upstream body/correlation-id draw; separate pick-order case; zero-intern + 1-alloc leg-naming gate. | - |
| crates/busbar-llm/src/unit/tests/verify.rs | CLEAN | Read 333L. Three guards pinned byte-for-byte to the live envelopes; asserts the pool ACL answers BEFORE the pricing gate (so an unauthorized caller cannot learn which names are priced); cyclic fallback terminates; membership probe allocates 0. | - |

## ROWS RAISED

### X-1600 · Five test files name `crates/busbar-core/src/...`, a crate that no longer exists
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:
```
$ git grep -n "crates/busbar-core/src" -- 'crates/busbar-llm/**/*.rs'
engine/engine_tests/crossproto_delivery_billing_tests.rs:4://! `crates/busbar-core/src/proxy/engine/mod.rs`: a buffered cross-protocol response whose delivery
engine/engine_tests/inject_include_usage_tests.rs:4://! Tests for `crates/busbar-core/src/proxy/engine/mod.rs`.
engine/tests/health_tests.rs:4://! Tests for `crates/busbar-core/src/health.rs`.
engine/tests/lazy_body_tests.rs:4://! Tests for `crates/busbar-core/src/proxy/lazy_body.rs`.
engine/tests/wire_tests.rs:4://! Tests for `crates/busbar-core/src/proxy/wire.rs`.
$ ls -d crates/busbar-core
ls: crates/busbar-core: No such file or directory
$ ls -d crates/busbar-core*
crates/busbar-core-admin   crates/busbar-core-connsec
$ ls -d crates/busbar-kernel            # POSITIVE CONTROL: the successor crate does exist
crates/busbar-kernel
$ git ls-files -- 'crates/busbar-core/src/proxy/*' | wc -l
0
$ git ls-files -- 'crates/busbar-llm/src/engine/*' | wc -l    # control: the glob form itself works
72
```
A NOTE ON THE COUNT. My first pass used the narrower pattern `crates/busbar-core/src/proxy` and
returned **four** files; `health_tests.rs` names `crates/busbar-core/src/health.rs` and was missed.
The delegated pass that first flagged `health_tests.rs` also mislabelled three of these five as
"outside this slice" — all five are in the S07-llm denominator. Both errors corrected here; the
verified set is exactly five, and the widened grep above is the one to trust.
ACTION:    Repoint each of the five `//!` headers at the live file — `engine/attempt/buffered.rs`
           (`translate_response_cross_protocol`) and `engine/attempt/assemble.rs`
           (`inject_openai_stream_include_usage`) for the two `engine_tests/` files, and
           `engine/health.rs` / `engine/lazy_body.rs` / `engine/wire.rs` for the other three.
           Documentation-only; no behaviour changes.

### X-1601 · `select.rs`'s `excluded_reasons` is already consumed in production, but is still marked and commented as if it is not
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:
```
$ sed -n '46,49p' crates/busbar-llm/src/engine/select.rs
    // Consumed by the queue/least_bad/Retry-After wiring in a later phase; populated and asserted by
    // the taxonomy/refactor unit tests now — silence the release-build dead-code lint meanwhile.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) excluded_reasons: Vec<(usize, busbar_kernel::store::Unavailable)>,
$ git grep -n "excluded_reasons" -- 'crates/busbar-llm/**/*.rs'
engine/exhaustion/queue.rs:58:    for (lane, reason) in &request_ctx.excluded_reasons {
engine/select.rs:49 / :102 / :396 / :397        (decl, init, clear, extend)
engine/tests/ordered_walk_tests.rs:349…432      (taxonomy assertions)
$ sed -n '50,62p' crates/busbar-llm/src/engine/exhaustion/queue.rs
… ) -> Response {                                  # a plain async fn, NOT #[cfg(test)]
    for (lane, reason) in &request_ctx.excluded_reasons {
        if matches!(reason, Unavailable::AtCapacity { .. }) && !at_cap_lanes.contains(lane) {
```
The `queue` third of the comment's three claimed consumers is wired TODAY and reads the field
unconditionally on the request path. The `least_bad` and `Retry-After` thirds are genuinely still
unwired — they rank on cooldown instead, a separate mechanism. So the attribute is vestigial (a real
non-test reader exists, so removing it cannot produce a dead-code warning) and the comment
misdescribes the current wiring state in the direction that hides work already done.
ACTION:    Drop the `#[cfg_attr(not(test), allow(dead_code))]`; rewrite the comment to say `queue.rs`
           consumes it now. Separately, get an owner ruling on whether wiring `least_bad`/`retry_after`
           to this same taxonomy was ABANDONED in favour of the cooldown ranking (in which case the
           sentence should stop promising it) or is still outstanding.

### X-1602 · `tables.rs`'s `Lane.max` is populated from config at boot and read by nothing
CLASS:     missing-code
CERTAINTY: VERIFIED
EVIDENCE:
```
$ sed -n '55,57p' crates/busbar-llm/src/engine/tables.rs
    #[allow(dead_code)]
    pub(crate) max: usize,
$ git grep -n "\.max\b" -- 'crates/busbar-llm/**/*.rs' | grep -v "\.max(" | grep -v max_concurrent
                                        # rc=1, no output — zero reads anywhere in the plane
$ git grep -c "\.unwrap()" -- 'crates/busbar-llm/src/engine/tests/alloc_gate_tests.rs'
3                                       # POSITIVE CONTROL: this grep shape does find things
$ git grep -n "max_concurrent" -- 'crates/busbar-llm/src/engine/build_runtime.rs'
226:            max: li.max_concurrent,          # populated here, at table build
$ sed -n '696,705p' crates/busbar-kernel/src/appbuild.rs
        let max_concurrent = mc.max_concurrent.unwrap_or(tokio::sync::Semaphore::MAX_PERMITS);
        lanes_data.push(LaneData { … max: max_concurrent,
            sem: std::sync::Arc::new(tokio::sync::Semaphore::new(max_concurrent)), …
$ git grep -n "ls.max" -- 'crates/busbar-kernel/src/store/in_memory/availability.rs'
318 / 706 / 761 / 764 / 768 / 773        # the REAL cap: at_capacity, inflight, available
```
Two copies of one config number resolved down two paths. The enforced one is
`busbar_kernel::store::LaneRuntime.max` + its semaphore, built in `appbuild.rs` and proven by
`forward_pool_integration_tests.rs::test_bounded_max_concurrent_still_enforces_the_cap`. The plane's
`tables::Lane.max` is filled and never read.
SEVERITY, STATED HONESTLY. I tested the sharper hypothesis — that the two copies disagree on the
omitted-cap default, where the kernel means UNBOUNDED (`MAX_PERMITS`) and a raw `0` would mean
"nothing may run" — and it is FALSE: `appbuild.rs:805` feeds the plane `max_concurrent: ld.max`, the
ALREADY-RESOLVED value, so the copies agree today. This is a dead duplicate, not a live bug. It is
reported because it is precisely the CONTRACT's "capability constructed but never wired" shape, and
because a second copy of a capacity number that nothing reads is the usual way the two later drift.
ACTION:    Owner call — either delete `Lane.max` and its `#[allow(dead_code)]`, or give it a real
           reader (e.g. surface the configured cap through `EngineTablesView` for `/stats`
           diagnostics). Deleting is the smaller edit and loses nothing measurable.

### X-1603 · `probe_release_owner_tests.rs` locates its subject in a file that contains none of it
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:
```
$ sed -n '1,3p' crates/busbar-llm/src/engine/tests/probe_release_owner_tests.rs
//! The four post-`.await` single-flight-probe release sites in `engine/mod.rs`
//! (the ClientFault disposition and the three passthrough/context-length abandon arms) must use the
//! OWNER-CHECKED `release_probe_owned_in`, not the unowned `release_probe_in` …
$ grep -n "release_probe" crates/busbar-llm/src/engine/mod.rs
                                        # rc=1 — ZERO occurrences in the named file
$ git grep -n "release_probe_owned_in" -- 'crates/busbar-llm/**/*.rs'
engine/exhaustion/mod.rs:240:   host.lane_store().release_probe_owned_in(pool, i, epoch);
engine/pipeline.rs:2047:            .release_probe_owned_in(pool_name, i, epoch);
engine/select.rs:254:               .release_probe_owned_in(self.pool, self.lane, self.probe_epoch);   # ProbeGuard::drop
$ git log --oneline -- crates/busbar-llm/src/engine/exhaustion/mod.rs | head -2
b51638680 busbar-llm: ONE attempt seam; the degraded-path twin deleted
4e3b2b9c8 refactor(llm): decompose request-path functions under the 200-line gate ceiling
```
The test itself is sound — a real end-to-end race proof that drives one gated request through
`forward_with_pool` and wins a second probe on the same cell while the first is parked. Only its
header has drifted: the request-path decomposition moved the release sites out of `engine/mod.rs`
into `exhaustion/mod.rs` and `pipeline.rs`, with the ClientFault case now covered by
`ProbeGuard::drop` in `select.rs` rather than by an explicit call.
SECONDARY, DEMOTED. The header's arithmetic ("four sites … three abandon arms") does not match what
I can find: two explicit call sites plus one Drop. I did not establish whether the fourth is
double-counted, folded into the Drop, or genuinely missing, so this half is **ADJUDICATE**, not
VERIFIED, and must not be promoted without re-running the proof.
ACTION:    Repoint the header at `exhaustion/mod.rs` / `pipeline.rs` / `select.rs`, and re-audit the
           "four sites / three abandon arms" count against current code — if a fourth site is
           genuinely gone, the sentence should say three, and if one is unguarded, that is a real bug
           behind this row rather than a comment fix.

### X-1604 · OUT OF SLICE — the only plane the oracle witnesses has a six-dialect hole on exactly the mid-stream-error path
CLASS:     customer-surface
CERTAINTY: PARK
EVIDENCE:
```
$ python3 …  ids=[c['id'] for c in cells if c['id'].startswith('llm')]
             missing=[i for i in ids if i.replace('|','__') not in golden]
declared llm cells   : 142
witnessed (golden)   : 133
declared-unwitnessed : 9
control (should be True): True          # a known-witnessed cell IS found by the same lookup
   MISSING: llm|anthropic|anthropic|request|stream_upstream_error
   MISSING: llm|bedrock|bedrock|request|stream_upstream_error
   MISSING: llm|cohere|cohere|request|stream_upstream_error
   MISSING: llm|gemini|gemini|request|stream_upstream_error
   MISSING: llm|openai|openai|request|stream_upstream_error
   MISSING: llm|responses|responses|request|stream_upstream_error
   MISSING: llm|bedrock|bedrock|request|ok_cachepoint_document
   MISSING: llm|gemini|gemini|request|ok_tool_use_tokens
   MISSING: llm|responses|responses|request|ok_citation
```
Six of the nine are one behaviour on all six dialects: a stream that fails AFTER a 2xx head. That
path is both a customer surface (a truncated stream the client must interpret) and a money surface
(`billing_failed`, the `Partial` finish class, and whether a died-mid-body stream is charged) — and
it is the one behaviour in this plane with no 1.5.5 byte-witness anywhere. In-repo coverage does
exist and is good (`engine/tests/mid_stream_error_tests.rs`, and `unit/tests/audit.rs` seals
`Partial` from the tap), so this is an ORACLE gap, not an untested path.
PARKED, NOT ACTED ON. The oracle is never waived and I did not record, bless or regenerate anything.
Whether these nine cells should be witnessed, retired, or marked structurally-unwitnessable is a
release-gate ruling that belongs to the oracle's owner, and `testing/shadow-oracle/cells.json` is
outside the S07-llm denominator.
ACTION:    Owner ruling. Either record the nine against 1.5.5, or mark them explicitly
           unwitnessable with a reason in `cells.json` so the gap stops reading as an accident.

## TALLY
```
files in slice:  83      (= wc -l /Users/matthew/Developer/GetBusbar/.sweep/S07-llm.txt)
verdict lines:   83
CLEAN:           75
FINDING:          8      rows raised: 5  (X-1600 cited on 5 files; X-1601, X-1602, X-1603 on 1 each;
                                          X-1604 is out-of-slice and cited on no file row)
DELETABLE:        0
UNREADABLE:       0
```

## Out of slice — proved here, NOT acted on
1. **`testing/shadow-oracle/cells.json` + `testing/shadow-oracle/golden/1.5.5/cells/`** — the nine
   declared-but-unwitnessed llm cells of **X-1604**, six of them the same `stream_upstream_error`
   behaviour on every dialect. Nothing recorded, blessed or regenerated.
2. **`crates/busbar-llm/src/unit/meter.rs:490`** — `priced_from_ms: 0`, the live
   `construction:plane-no-money` red. Confirmed present and real, but already documented at length at
   `qa/construction.toml:1737-1740`, which names this file, line and symbol and states the row stays
   red at 1. The file is NOT in this slice's denominator (nor are `unit/approve.rs`, `unit/walk.rs`,
   or `unit/tests/{meter,approve,walk}.rs`). Whoever owns those files should confirm they are in some
   slice — on the denominator I was handed, they are unswept.
3. **`crates/busbar-llm/Cargo.toml:71` vs `crates/busbar/Cargo.toml:280`** — the manifest comment
   says the `teller-waist` `unit/` directory "compiles to nothing" while `root-llm` (in `busbar`'s
   default) forwards it on, so it ships. Already **ENG28, OPEN** in `docs/design/1.6.0-LEDGER.md:713`,
   proven there by a compile-error plant. Not re-raised; noted because every `unit/*` verdict above
   depends on it.
4. **A zsh false zero worth adding to the CONTRACT's list.** A delegated pass reported that
   `git grep … -- $FILES`, where `$FILES` is a multi-line variable expanded UNQUOTED, silently matches
   nothing in zsh — zsh does not word-split unquoted parameters the way bash does, so the whole list
   collapses into one bogus pathspec and returns rc=0 with no output. It was caught only because the
   run failed to find a known-real `#[ignore]` positive control. Use `while IFS= read -r f` instead.
   This is a new member of the documented zsh false-zero family, not one of the ten already listed.
