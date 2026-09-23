# S12-MONEY — sweep verdicts

Slice: `busbar-substrate-values`, `busbar-kernel-ledger`, `busbar-kernel-budget`,
`busbar-kernel-scope`. **72 files.** X-id block X-2100..X-2199 (25 used).

Spec rows read before judging any arithmetic: #10, #42, #44, #59, #71, #77, #79, #81
(`docs/design/BUSBAR-1.6.0.md:328,367,369,391,409,420,423,425`).

Read-and-report only. No source edited. **No billed byte self-approved** — every money row is
`PARK` with cell, diff, root cause and recommendation.

## The model this slice judged against
LEDGER <> MONEY. Planes write the ledger; money is a VIEW on the ledger times a ratecard. Money is
never wrong — the ledger or the ratecard is wrong. #44 was read narrowly and deliberately: only a
per-N-units **division** term takes banker's (half-to-even); card-build-time quantization stays
half-away-from-zero. #42 was read as written: an unpriced class **REFUSES** — neither a saturation
to `u64::MAX` nor a fall to `0` is the ruled answer, and a silent `0` is legal **only** when the
rate card is ABSENT.

| FILE | VERDICT | EVIDENCE | ROWS |
| --- | --- | --- | --- |
| `crates/busbar-substrate-values/Cargo.toml` | FINDING | `ls -d crates/busbar-contract-transport` → *No such file or directory*, yet L32-34 is a comment block describing a dependency edge on it with **no dep line under it**. `git grep -n '^name = "busbar-substrate"' -- '*/Cargo.toml'` → rc=1 (control `'^name = "busbar-substrate'` → only `busbar-substrate-values`), yet L7/L81 name it as a live package. `git grep -n 'feature = "relay"' -- 'crates/busbar-substrate-values/*'` → 1 hit at `src/lib.rs:85`, NOT in `transport.rs` as L80-83 claims (control `feature = "dispatch"` → 2 hits incl. `transport.rs:12`). | X-2118 |
| `crates/busbar-substrate-values/src/breaker.rs` | CLEAN | `git grep -n "breaker::classify"` → ships at `busbar-kernel/src/failover/mod.rs:256`, `store/planes.rs:256`. Every `StatusClass::*` variant has a non-test construction site. `parse_retry_after` has no local ceiling but the consumer caps it (`busbar-kernel-breaker/src/cell.rs:388` `ra.min(max_honored_retry_after_secs)`). No underflow: `total_len` is range-checked before `total_len - MIN_FRAME_BYTES` by `||` short-circuit. | - |
| `crates/busbar-substrate-values/src/diagnostics/tests.rs` | FINDING | `sed -n '133,136p;149,152p'` → the golden's repair instruction is `UPDATE_DIAGNOSTICS=1 cargo test -p busbar-substrate diagnostics::tests`; `git grep -n '^name = "busbar-substrate"' -- '*/Cargo.toml'` → rc=1, so that command exits *"package ID specification did not match any packages"*. The gate CAN go red (`git grep -n "UPDATE_DIAGNOSTICS" -- .github scripts xtask qa` → rc=1, i.e. never auto-blessed; control `UPDATE_` in `.github` → 4 hits). Catalog invariants themselves are sound and carry positive controls. | X-2125 |
| `crates/busbar-substrate-values/src/eventstream.rs` | CLEAN | `git grep -nF "eventstream::encode_frame"` → ships at `busbar-llm-codec/src/bedrock/mod.rs:1545`, `proto_stream.rs:677`; `drain_frames_checked` → `proto_stream.rs:758`; `DrainStatus::MalformedPrelude` consumed at `:788`. `drain_frames` correctly gated `#[cfg(any(test, feature="test-support"))]`. Slice index `rem[PRELUDE_LEN+headers_len .. total_len-CRC_BYTES]` provably cannot panic given the L113 guard. | - |
| `crates/busbar-substrate-values/src/handlers.rs` | FINDING | `sed -n '405,415p'` → the `translate_response` trait contract states a read-succeeded-but-undelivered 404/500 *"still bills"*. `sed -n '95,108p' src/wire.rs` and the shipping caller `sed -n '530,548p' crates/busbar-llm/src/engine/attempt/buffered.rs` both state the OPPOSITE (bill only on `StreamFrames \| Typed \| Json`; leave the guard armed to refund). Also `grep -n 'pub struct OpDispatch\|pub fn op_for\|pub fn chat\|pub fn protocol_error'` → `:535,609,629,645`, all four defined HERE while `:19-20` says they *"STAY in core"*. | X-2120, X-2119 |
| `crates/busbar-substrate-values/src/ir/egress_prep.rs` | CLEAN | `git grep -n "EgressPrep"` → constructed in shipping code. Pure primitive struct; `grep -nE 'f64\|f32'` → rc=1 (control `src/billing.rs` → 3 hits). | - |
| `crates/busbar-substrate-values/src/ir/handle.rs` | CLEAN | The `IrHandle` trait is implemented by 5 shipping crates (`busbar-llm-codec/src/chat_handle.rs:13`, `openai_chat/handler.rs:21`, `busbar-mcp/src/codec/invoke.rs:5`, …). `sealed::Sealed`'s `#[allow(dead_code)]` is deliberate and documented. | - |
| `crates/busbar-substrate-values/src/ir/invoke.rs` | CLEAN | `git grep -n "InvokeReq"` → constructed at `busbar-mcp/src/codec/invoke.rs:39` (ships). `shape()` accumulates `system_chars` in the same walk as `text_chars`, so no second-pass drift. No float, no money arithmetic. | - |
| `crates/busbar-substrate-values/src/ir/mod.rs` | CLEAN | Every declared submodule exists on disk (`egress_prep facts handle invoke neutral_handles subscribe`); `#[path]`-aware module scan → 0 dangling. | - |
| `crates/busbar-substrate-values/src/ir/neutral_handles.rs` | CLEAN | All four handle types constructed in shipping code (`busbar-mcp/src/codec/invoke.rs:39,46`, `codec/subscribe.rs:96,102`). Doc L5 still says the types live in `busbar-substrate` — dead crate name, folded into X-2118's class. | - |
| `crates/busbar-substrate-values/src/ir/subscribe.rs` | CLEAN | `git grep -n "SubscribeReq"` → `busbar-mcp/src/codec/subscribe.rs:96` (ships). `SubscribeIntent::{Register,Deregister}` both constructed. | - |
| `crates/busbar-substrate-values/src/ir/tests/neutral_handles.rs` | FINDING | `:19-33` takes `addr_of!(req.arguments)` then asserts it equals `addr_of!(handle.0.arguments)` where `handle = InvokeReqHandle(Arc::clone(&req))` — both deref the SAME `Arc` allocation, so the assertion is true by construction and no source change can make it red. Same shape at `:52`. The sibling `Arc::strong_count == before + 1` assertions DO carry real signal, so this is a dead sub-assertion inside a live test. Separately `InvokeRespHandle::billing()` — the file's money-bearing half — has no assertion anywhere. | X-2126 |
| `crates/busbar-substrate-values/src/json.rs` | CLEAN | `git grep -nF "json::parse_str"` → `cohere/reader.rs:415,1228`, `gemini/mod.rs:754,2048`; `json::to_string` → `busbar-kernel/src/proxy/mod.rs:139`. `exceeds_max_depth` is string-aware and escape-aware; `MAX_JSON_DEPTH = 128` (`:25`) bracketed both ways by `depth_guard_tests`. The *gate* over this seam has a hole — X-2113, raised against `src/tests/json.rs`. | - |
| `crates/busbar-substrate-values/src/lossless.rs` | CLEAN | `git grep -n "lossless::SourceScopedExtra"` → 5 shipping users (`busbar-llm-codec/src/ir/{audio,embeddings,image,moderation,rerank}.rs`). The alias itself ships; it is its TEST that is vacuous (X-2114). | - |
| `crates/busbar-substrate-values/src/proxy/mod.rs` | FINDING | `git grep -nF "ERR_DEGRADED_NON2XX" -- '*.rs'` → 4 hits: the definition (`:234`), a `pub use` (`busbar-llm/src/engine/mod.rs:113`) and two call sites BOTH inside `busbar-llm/src/engine/tests/legacy_forward_once.rs:477,535`, a test-only file. POSITIVE CONTROL `git grep -nF "ERR_NET_CONNECT" \| grep -v tests` → real shipping call site at `attempt/classify.rs:62`. Also absent from the fixed label vocabulary `busbar-kernel/src/telemetry.rs:523-531 REASONS` while its siblings are present. All other pub items proven live per-item. | X-2122 |
| `crates/busbar-substrate-values/src/proxy/sse.rs` | CLEAN | `git grep -nF ".pending()"` → the documented ceiling check is wired at `busbar-a2a/src/a2a/relay.rs:2236`. `SseReader`/`sse_data` used at `relay.rs:767,1136,2088`, `grpc.rs:698`. Rewind proof: a 4-byte terminator starting before `scanned-3` lies wholly inside the scanned region, so `TERMINATOR_REWIND = 3` suffices. `:8` names the dead crate `busbar-core` in prose (folded into X-2118's class, non-executable). | - |
| `crates/busbar-substrate-values/src/sigv4.rs` | FINDING | `grep -n "in_quotes" src/sigv4.rs` → `:149,152,154` (quoted-string space preservation present here); the same grep on `crates/busbar-kernel-identity/src/egress_auth/sigv4/mod.rs` → **rc=1, absent**. Conversely `grep -n "merged\|push(',')"` → rc=1 here, but `:157-167` in the identity copy (AWS duplicate-header comma-join present only there). Two shipping signers, each holding a signature-affecting fix the other lacks. Verify path otherwise sound: 13 distinct `return Err(VerifyError…)` arms; `VerifyError` is fieldless so no secret reaches an error string. | X-2121 |
| `crates/busbar-substrate-values/src/testkit/warn_capture.rs` | FINDING | `:6-7` asserts *"a test binary only ever links ONE of them"*. `git ls-files \| grep -i warn_capture` → TWO files (`busbar-kernel/src/test_support/warn_capture.rs` and this one), each with its own `static GATE: OnceLock<CaptureGate>` (`busbar-kernel/…:174`). `grep -n 'test-support' crates/busbar-kernel/Cargo.toml` → `:308` dev-dep pulls this crate in, and `busbar-kernel/src/lib.rs:318` declares `pub mod test_support` — so `cargo test -p busbar-kernel` links BOTH gates. Secondary: `GateHold::drop` (`:215-228`) releases without an `owner == current thread` check. | X-2123 |
| `crates/busbar-substrate-values/src/tests/billing_duration_tests.rs` | FINDING | Declared `src/billing.rs:193-194`. `sed -n '103,106p' src/billing.rs` claims the identity was *"checked over 200,009 values spanning zero to a thousand hours"*. The loops at `:60-79` sum to `10_000 + 100_000 + 2_999 = 112,999`, and `3_600_000_000` micros = 3,600 s = **one hour**, not a thousand. Re-running the file's own xorshift gives max drawn = 3,599,995,958 micros. | X-2110, X-2111 |
| `crates/busbar-substrate-values/src/tests/breaker_tests.rs` | CLEAN | 19 tests / 40 assertions. The uncoded-log scan at `:350` carries its OWN positive control (`:325` asserts 5 true + 5 false cases of the predicate). Independently confirmed green for the right reason: `grep -rnE '(^\|[^a-zA-Z0-9_:])(tracing::)?(warn\|error)!\(' src/ \| grep -v tests` → rc=1 while `grep -rn 'diag_warn!\|diag_error!'` → 4 real coded sites. | - |
| `crates/busbar-substrate-values/src/tests/depth_guard_tests.rs` | CLEAN | Brackets the limit BOTH ways: `[`×128 must pass, `[`×129 must fail (`MAX_JSON_DEPTH = 128`, `src/json.rs:25`). Also asserts brackets inside string literals do not count. A real NO exists. | - |
| `crates/busbar-substrate-values/src/tests/egress_wire_tests.rs` | CLEAN | Both tests are exhaustive matches with `panic!` on every wrong arm — no silent-pass arm exists. `InvokeReqHandle` overrides only `verb`/`facts`, so the test genuinely exercises the `write_egress_request` trait default it claims to. | - |
| `crates/busbar-substrate-values/src/tests/eventstream_tests.rs` | CLEAN | 31 tests / 116 assertions. The empty-string family is not blind: `event_type_for_frame` is asserted `""` at `:159,184,234` AND `"messageStart"`/`"throttlingException"`/… at `:175,202,207,222,230,264,272,307,353` — the discriminator is live. The timing test at `:877` self-withdraws below 1 ms and bounds at 8× (log-midpoint of linear 4× and quadratic 16×), so it can produce a NO. | - |
| `crates/busbar-substrate-values/src/tests/json.rs` | FINDING | `:39` — the source-scanning gate matches ONLY `serde_json::to_vec` and `serde_json::from_slice`, but the seam it guards is sonic-rs (`grep -c 'sonic_rs::' src/json.rs` → 12). A direct `sonic_rs::from_slice`, or a `serde_json::from_str`, outside the seam bypasses the depth guard and this gate never sees it. Latent today: `grep -rn 'sonic_rs::' src/ \| grep -v '^src/json.rs:'` → rc=1. | X-2113 |
| `crates/busbar-substrate-values/src/tests/lib.rs` | CLEAN | Declared `src/lib.rs:131-132`. One test, but a real one: a `Barrier` closes the "it never ran" false-pass, then asserts BOTH `!acquired` while held AND `acquired` after drop. Since `src/lib.rs:126-128` made `test_support` a re-export of `testkit`, the property now holds by construction — it is an explicit regression guard against re-forking, which is the defect it was written for. | - |
| `crates/busbar-substrate-values/src/tests/lossless_tests.rs` | FINDING | `grep -nE '^\s*(pub )?(const )?fn \|^\s*impl \|^\s*const \|^\s*static ' src/lossless.rs` → **rc=1, no output**; positive control same pattern on `src/media.rs` → 6. The subject is one `pub type` alias, so both assertions (insert `"logprobs"` then find it; miss `"gadget"`) test `std::collections::BTreeMap`, not this crate. Neither can fail for any map type. | X-2114 |
| `crates/busbar-substrate-values/src/tests/media_tests.rs` | FINDING | Strong file otherwise (6 tests / 25 assertions, RFC 4648 §10 vectors, terminal-padding cases). But `git grep -n 'is_well_formed' -- 'crates/busbar-substrate-values/**'` → defined `src/media.rs:141` (`pub(crate)`), callers are ONLY `:19,26,35` of this test file. Zero production callers, while the test's own message says raw PCM without params is *"silently lossy"* — and it is, at runtime, because nothing consults the predicate. | X-2112 |
| `crates/busbar-substrate-values/src/tests/proto_2.rs` | CLEAN | 3 tests / 23 assertions, all exact-value `assert_eq!` including the `None` cases (`:20,24,28`) that discriminate "not yet a frame" from "framed". | - |
| `crates/busbar-substrate-values/src/tests/proto_strip_tests.rs` | CLEAN | Refusal test over 3 truncated inputs PLUS a companion proving the well-formed case still strips byte-for-byte (`assert_eq!(out, r#"{"a":1,"b":2}"#)`) — so a stripper that refused everything would go red. | - |
| `crates/busbar-substrate-values/src/tests/screening_tests.rs` | CLEAN | Declared `src/ir/facts.rs:487-488` via `#[path = "../tests/screening_tests.rs"]` — note a reachability grep anchored on `path = "tests/` misses this and returns a false zero. Defends against counter-blindness explicitly: `:16` pins `take_data_renders() == 7` BEFORE the memo test asserts `== 1`, so the counter is proven to move. | - |
| `crates/busbar-substrate-values/src/tests/sigv4_tests.rs` | CLEAN | 30 tests / 81 assertions. The verify can fail ELEVEN distinct ways (wrong secret, tampered signature, tampered body hash, expired date, missing signed header, unsigned host, datestamp≠amzdate, stripped `SignedHeaders`, wrong sort, missing date, unknown-key dummy secret). AWS's published example vector reproduced exactly at `:658`. Skew boundary bracketed at `−1 / == / +60`. Does NOT cover the two edge cases X-2121 turns on. | - |
| `crates/busbar-substrate-values/src/tests/sse_tests.rs` | CLEAN | Declared `src/proxy/sse.rs:182-183` (again `../tests/…`). 6 tests / 18 assertions; exact framed-output equality for all 8 terminator pairings, exact `pending()` residue, and two cost assertions read via take-and-reset. | - |
| `crates/busbar-substrate-values/src/tests/warn_capture_tests.rs` | FINDING | `:22-27` constructs one `WarnCapture` then asserts `LevelFilter::current() >= Level::WARN` — but that flag is set inside `ensure_capture_interest()` behind `static ONCE: std::sync::Once` (`src/testkit/warn_capture.rs:157-166`). `WarnCapture` is also constructed at `sse_tests.rs:18`, `breaker_tests.rs:270`, `tests/lib.rs:18,30` in the same 113-test binary, so whichever runs first fires the `Once` and this test's own constructor contributes nothing to the condition it asserts. | X-2115 |
| `crates/busbar-substrate-values/src/transport.rs` | FINDING | `ls -d crates/busbar-contract-transport` → *No such file or directory*, yet `:4-5` says the axis was *"RELOCATED to `busbar-contract-transport`"*; the `pub use` actually resolves into `busbar-contract` (`crates/busbar-contract/src/transport/transport.rs:136,206` present). `:8-9` lists the SAME path `busbar_substrate_values::transport::…` twice — a rename applied to one side of a two-sided sentence. | X-2124 |
| `crates/busbar-substrate-values/src/wire.rs` | CLEAN | `git grep -n "WireBody::typed"` → `openai_chat/handler.rs:425,589`; `EgressCtx` → `busbar-kernel/src/handlers/mod.rs:98`; `TranslatedResponse::StreamFrames` → `busbar-llm/src/engine/attempt/buffered.rs:538,563`. This file is the CORRECT side of the X-2120 money contradiction, verified against `buffered.rs:533-545`. | - |
| `crates/busbar-kernel-ledger/Cargo.toml` | FINDING | `git grep -n "busbar-unit-cost\|busbar-caps" crates/busbar-kernel-ledger/Cargo.toml` → 3 hits naming crates that no longer exist (`busbar-caps`, `busbar-unit-cost`) as this crate's deps; actual `[dependencies]` are `busbar-contract` + `sha2`. Dev-dep on `busbar-kernel-budget` IS live: `git grep -n "RateNanos" crates/busbar-kernel-ledger/` → `tests/rate_conversion_agreement.rs:36,44`. | X-2108 |
| `crates/busbar-kernel-ledger/src/cost/history.rs` | CLEAN | Read 297/297. Resolution rule is highest covering `seq` (`:270-276`), `card_at` returns `Option` — `git grep -n "None means no entry covers" src/cost/history.rs` → `:268` "a hole, which is a refusal and never a zero". `append` assigns `seq = entries.len()` so `snapshot`'s `partition_point` precondition (sorted by seq) holds by construction. Matches #79 (dated history, back-dated amendment out-ranks rather than edits). | - |
| `crates/busbar-kernel-ledger/src/cost/tests/currency_tests.rs` | CLEAN | Read `:155-195`. The one `assert_eq!(…amount_nanos, 0)` (`:179`) is NOT a blessed silent zero — the same test asserts `fee_line.unpriced`, `read.fee_unpriced`, and that settlement `price_fail_closed` returns `Err(Unpriceable::FeeUnpriced)`. This is #42 done correctly: a visible zero plus a refusal. | - |
| `crates/busbar-kernel-ledger/src/cost/tests/derive_tests.rs` | CLEAN | `grep -c "#\[test\]"` → 15, `grep -c "#\[ignore"` → 0. Assertion-free-test scanner (brace-matched bodies, `assert\|panic!\|expect(\|matches!`) → 0 hits; positive control found 8 tests in the same scan of `lane_tests.rs`. | - |
| `crates/busbar-kernel-ledger/src/cost/tests/history_tests.rs` | CLEAN | `grep -c "#\[test\]"` → 10, ignore=0. Exercises `Author::Opening/Config/Amend` (`:28,35,68,196,245`) — all three arms constructed, so no unreachable author arm. | - |
| `crates/busbar-kernel-ledger/src/cost/tests/identity_tests.rs` | CLEAN | `grep -c "#\[test\]"` → 4, ignore=0; assertion-free scan → 0. | - |
| `crates/busbar-kernel-ledger/src/cost/tests/mod.rs` | CLEAN | Helper-only module (tests=0). Unused-helper scan: 8 helpers, all referenced elsewhere in the two money crates → 0 unused. | - |
| `crates/busbar-kernel-ledger/src/cost/tests/posting_tests.rs` | CLEAN | `grep -c "#\[test\]"` → 21, ignore=0. Covers the one banker's-rounding site (`cost/posting.rs:343-352`, `(remainder*2).cmp(&n)` → half-to-even), which is the single #44 per-N-units division term in the tree. | - |
| `crates/busbar-kernel-ledger/src/digest.rs` | CLEAN | Read 19/19. One hash fn, one caller-facing hex wrapper; `git grep -n "sha256" crates/busbar-kernel-ledger/src` → only `digest.rs` + `checkpoint.rs:277,307`, so the "exactly one call site" claim in its own header holds. | - |
| `crates/busbar-kernel-ledger/src/legacy.rs` | CLEAN | Read 182/182. Best-effort dual-write by design (header `:19-24`); `LegacyWriteError::Unavailable` is the only arm and is emitted by integrator impls, not here. `opening_balances` empty-head → empty list is the documented, ruled behaviour (a migration may not refuse). | - |
| `crates/busbar-kernel-ledger/src/lib.rs` | CLEAN | Read 124/124. Every `pub use` resolves to a declared `mod`; module-declaration scanner over the 4 crates reported only `lib.rs` itself unmatched (expected for a crate root). | - |
| `crates/busbar-kernel-ledger/src/tests/fixtures.rs` | CLEAN | Unused-helper scan: 10 helpers, 0 unused (each `fn` name re-grepped across both money crates excluding its own definition). | - |
| `crates/busbar-kernel-ledger/src/tests/identity_tests.rs` | CLEAN | `grep -c "#\[test\]"` → 10, ignore=0; assertion-free scan → 0. | - |
| `crates/busbar-kernel-ledger/src/tests/migration_tests.rs` | CLEAN | `grep -c "#\[test\]"` → 17, ignore=0; assertion-free scan → 0. | - |
| `crates/busbar-kernel-ledger/src/tests/mod.rs` | CLEAN | Declaration hub (tests=0, 0 helpers). Every `#[path]`/`mod` target in it resolves to a file present on disk (module-reachability scanner → 0 dangling). | - |
| `crates/busbar-kernel-ledger/src/tests/recompute_tests.rs` | CLEAN | `grep -c "#\[test\]"` → 23, ignore=0; assertion-free scan → 0. | - |
| `crates/busbar-kernel-ledger/src/tests/settle_tests.rs` | CLEAN | `grep -c "#\[test\]"` → 15, ignore=0; assertion-free scan → 0. | - |
| `crates/busbar-kernel-ledger/src/tests/statement_tests.rs` | CLEAN | `grep -c "#\[test\]"` → 9, ignore=0; assertion-free scan → 0. | - |
| `crates/busbar-kernel-ledger/src/tests/totals_tests.rs` | CLEAN | `grep -c "#\[test\]"` → 6, ignore=0; assertion-free scan → 0. | - |
| `crates/busbar-kernel-ledger/src/usage/lane.rs` | FINDING | Read 135/135. `:119-129` picks the disputed lane by `policy.price_of(a).cmp(&policy.price_of(b))`; `price_of` (`usage/evidence.rs:181-183`) is `.unwrap_or(0)` — an UNPRICED lane sorts as cheapest and WINS. `lane_prices` is card-populated in production (`busbar/src/root/policy.rs:129`) and an unpriced lane is reachable (`busbar/src/root/tests/policy.rs:70`). | X-2102 |
| `crates/busbar-kernel-ledger/src/usage/mod.rs` | CLEAN | Read 59/59. All six submodules declared; every `pub use` name resolves. `WHOLE_BP` used by `meter.rs:229`. | - |
| `crates/busbar-kernel-ledger/src/usage/settlement.rs` | FINDING | Read 227/227. `git grep -nE "UnitEndKind\|SettleFlag\|locator_required\|kernel_floor\|checkpointed_accrual" -- . \| grep -v "^crates/busbar-kernel-ledger/"` → **0 hits** (the `DurabilityLost` hits outside are `busbar_contract::caps::DurabilityLost`, a different type). Positive control `MeterPolicy\|KernelCounts` same shape → hits in `busbar/src/root/policy.rs`, `kernel.rs`. The settlement table ships to nobody; only `requests_settled` has a caller (`busbar-kernel/src/teller.rs:1314`). | X-2106 |
| `crates/busbar-kernel-ledger/src/usage/tests/lane_tests.rs` | FINDING | Read 152/152. `an_unpriced_lane_is_the_cheapest_candidate` (`:141-152`) ASSERTS `check.lane == Some("nobody-prices-this")` — the test pins the behaviour #42 forbids, so the rule cannot be corrected without this test going red. | X-2103 |
| `crates/busbar-kernel-ledger/src/usage/tests/meter_tests.rs` | CLEAN | `grep -c "#\[test\]"` → 14, ignore=0; assertion-free scan → 0. Covers `beyond_tolerance` cross-multiplication (`meter.rs:222-231`), which is integer and division-free — no #44 exposure. | - |
| `crates/busbar-kernel-ledger/src/usage/tests/mod.rs` | CLEAN | Helper hub (tests=0). Unused-helper scan: 10 helpers, 0 unused. | - |
| `crates/busbar-kernel-ledger/src/usage/tests/series_tests.rs` | CLEAN | `grep -c "#\[test\]"` → 5, ignore=0; assertion-free scan → 0. | - |
| `crates/busbar-kernel-ledger/src/usage/tests/settlement_tests.rs` | FINDING | `grep -c "#\[test\]"` → 17, ignore=0. All 17 are the ONLY callers of the settlement table (see X-2106) — they exercise a module no shipping path reaches, so the table's 17 green rows are evidence about dead code. | X-2106 |
| `crates/busbar-kernel-ledger/src/verify.rs` | FINDING | Read 178/178. (a) `git grep -n "AnchorHeadDiffers" -- .` → exactly 2 hits, both in this file (`:35` decl, `:76` Display); positive control `CheckpointEdited` → 4 hits incl. construction at `:120`. (b) `git grep -n "VerifyFinding\|AllWindowsOpen\|busbar_kernel_ledger::verify"` → every hit inside this crate (lib.rs re-export, verify.rs, checkpoint_tests.rs); positive control `busbar_kernel_ledger::usage` → real callers in `busbar/src/root/`. | X-2104, X-2105 |
| `crates/busbar-kernel-budget/Cargo.toml` | FINDING | `git grep -n "busbar-unit-admission\|busbar-unit-cost" crates/busbar-kernel-budget/Cargo.toml` → `:1`, `:35` name crates that no longer exist; the real dep is `busbar-kernel-ledger`. | X-2108 |
| `crates/busbar-kernel-budget/src/cells.rs` | FINDING | Read 288/288. `evict_coldest_model` (`:183-197`) moves the evicted model's counts into `self.evicted`. `git grep -n "evicted" crates/busbar-kernel-budget/` → read ONLY by `total_tokens` (`:140`) and `total_tier` (`:150`), the CAP counters. `model_views()` (`:130-132`) — the sole pricing input at `decide.rs:360,467` and `governance/state.rs:1614,1691,1971` — iterates `self.models` only and never `self.evicted`. Evicted tokens are therefore counted for caps and **priced at nothing**. | X-2100 |
| `crates/busbar-kernel-budget/src/tests/cells.rs` | FINDING | Read `:200-280`. `an_all_time_cell_caps_the_models_it_interns_and_keeps_the_token_truth` asserts `total_tokens()==1_000` (the cap truth) and never calls `derive_spend_cents`; `git grep -n "derive_spend" crates/busbar-kernel-budget/src/tests/` → no hit in this file. The spend consequence of eviction is unmeasured, and the fixture uses `no_card(0)` so it would read 0 even if it were. | X-2101 |
| `crates/busbar-kernel-budget/src/tests/hold.rs` | CLEAN | `grep -c "#\[test\]"` → 11, ignore=0. The four literal-zero assertions (`:143,246,249,295`) are headroom/overdraft exhaustion states, each paired with a non-zero control in the same test (positive control: 4 non-zero amount assertions in this file). | - |
| `crates/busbar-kernel-budget/src/tests/leases.rs` | CLEAN | `grep -c "#\[test\]"` → 4, ignore=0; assertion-free scan → 0. | - |
| `crates/busbar-kernel-budget/src/tests/mod.rs` | CLEAN | Helper hub (tests=0). Unused-helper scan: 13 helpers, 0 unused. | - |
| `crates/busbar-kernel-budget/src/tests/ported.rs` | CLEAN | `grep -c "#\[test\]"` → 28, ignore=0; assertion-free scan → 0. These are the 1.5.5-behaviour ports the budget crate's manifest claims exist; the count is non-zero so the claim is not hollow. | - |
| `crates/busbar-kernel-budget/src/tests/price.rs` | CLEAN | Read `:150-226`. Strong instrument: the refusal row (`:170-184`, unpriced ⇒ `i64::MAX`), the explicit-free control (`:191-209`, named zero row ⇒ fee only, does NOT block) and the billing-off control (`:213-226`, no card ⇒ silent 0 legal). All three arms of #42 are separated and each can go red. | - |
| `crates/busbar-kernel-scope/Cargo.toml` | FINDING | `sed -n '270,358p' crates/busbar-kernel-scope/src/lib.rs \| grep -oE "Scope::(ReadOnly\|Full)" \| sort \| uniq -c` → 34 ReadOnly / 32 Full, and `grep -cE "^\s*op\("` → 66 rows. The manifest's "66 operations, 34 read-only / 32 full" claim is **EXACT**. Only defect is the stale crate names at `:1` (`busbar-unit-scope`) and `:7` (`busbar-caps`; real dep is `busbar-contract`). | X-2108 |
## ROWS RAISED

### X-2100 · Evicted model tokens are counted for caps and priced at nothing — a silent under-bill
CLASS:     money
CERTAINTY: PARK  *(billed byte — owner ruling required; the code-structure proof below is VERIFIED)*
CELL:      `crates/busbar-kernel-budget/src/cells.rs:183-197` (`evict_coldest_model`), read by
           `:130-132` (`model_views`) vs `:137-153` (`total_tokens`/`total_tier`).
EVIDENCE:
```
$ git grep -n "evicted" -- crates/busbar-kernel-budget/
cells.rs:79:    evicted: BTreeMap<String, u64>,
cells.rs:140:            .fold(units_total(&self.evicted), |acc, m| {      <- total_tokens (CAP)
cells.rs:150:            .fold(self.evicted.get(unit).copied().unwrap_or(0), |acc, m| {  <- total_tier (CAP)
cells.rs:193:                let slot = self.evicted.entry(k).or_insert(0);  <- the only write
$ git grep -n "model_views" -- 'crates/**'
cells.rs:130:    pub fn model_views(&self) -> impl Iterator<Item = (&str, &BTreeMap<String, u64>)> {
decide.rs:360 / decide.rs:467 / governance/state.rs:1614,1691,1971   <- the ONLY pricing inputs
```
`model_views()` returns `self.models.iter()` — it never reads `self.evicted`. `derive_spend_cents`
(`price.rs:222-246`) and `derive_spend_micros` consume only `model_views()`.
DIFF:      For a bucket that has interned `MAX_MODELS_PER_CELL = 128` (`cells.rs:39`) distinct model
           names, every further intern evicts the coldest. The evicted model's accrued tokens remain
           in `total_tokens()` (so the TOKEN cap still bites) but leave the spend derivation
           entirely. Derived spend drops by exactly `Σ evicted_units × rate(evicted_model)`; the
           invoice and the token counter now disagree about the same rows.
ROOT CAUSE: the bound was added for MEMORY (the model name is caller-supplied — `decide.rs:530-544`
           `record_usage(.., model: &str, ..)` flows straight to `accrue`), and the fix chose to
           preserve the CAP truth while discarding the ATTRIBUTION the price needs. `cells.rs:175-182`
           states the trade in its own words: *"a count with no name left cannot be priced, so an
           evicted model's tokens stop contributing to the spend derivation."* That is a silent zero
           on a node whose rate card is PRESENT — the one thing #42 (`BUSBAR-1.6.0.md:367`) confines
           to a card that is ABSENT, and #77(5) (`:420`) requires free to be an EXPLICIT zero row.
           Note the adversarial path is self-limiting, not free: junk model names are unpriced, so
           while interned they make `derive_spend_cents` return `i64::MAX` and BLOCK (`price.rs:232`).
           The certain, non-adversarial harm is a legitimate deployment routing >128 priced model
           names (e.g. dated variants) through one bucket.
ACTION:    Do not price from `model_views()` alone. Either (a) refuse to evict a model that carries
           unbilled units — flush/settle it first, so no priced quantity ever loses its name; or
           (b) make the evicted tally an EXPLICIT unpriced line that `derive_spend_cents` sees and
           fails closed on, exactly as `model_unpriced` already does (`price.rs:230-232`). Option (b)
           is the smaller change and matches the posture the same file already takes. **Owner
           ruling required: this changes billed amounts.**

### X-2101 · The eviction test measures the cap truth and never prices the cell
CLASS:     instrument-blind
CERTAINTY: VERIFIED
CELL:      `crates/busbar-kernel-budget/src/tests/cells.rs:210-253`
EVIDENCE:
```
$ sed -n '210,253p' crates/busbar-kernel-budget/src/tests/cells.rs
  ... assert_eq!(cell.model_views().count(), MAX_MODELS_PER_CELL)
  ... assert_eq!(cell.total_tokens(), 1_000, "every accrued token still counts toward the token caps")
  ... assert_eq!(cell.total_input(), 1_000, "and toward the per-tier ones")
$ git grep -n "derive_spend" -- crates/busbar-kernel-budget/src/tests/
tests/mod.rs:291 / tests/price.rs:87,180,206,222      <- never tests/cells.rs
```
The test's own docstring names the defect (*"What is given up is the per-model ATTRIBUTION of the
coldest name, which is what the derived spend reads"*) and then asserts only the half that still
works. Its fixture is `no_card(0)`, so even an added pricing assertion would read 0.
ACTION:    Add the red half: build the cell with `Pricer::with_card`, accrue a PRICED model, evict it
           with `MAX_MODELS_PER_CELL` further names, and assert `derive_spend_cents` still charges for
           the evicted model's tokens. That test fails today and is the proof for X-2100.

### X-2102 · `cross_check_lane` prefers an UNPRICED lane as "cheapest"; #42 says unpriced REFUSES
CLASS:     money
CERTAINTY: PARK  *(billed byte / needs an owner ruling; the mechanism below is VERIFIED)*
CELL:      `crates/busbar-kernel-ledger/src/usage/lane.rs:119-132`; root cause at
           `crates/busbar-kernel-ledger/src/usage/evidence.rs:181-183` (OUT OF SLICE).
EVIDENCE:
```
$ sed -n '181,183p' crates/busbar-kernel-ledger/src/usage/evidence.rs
    pub fn price_of(&self, lane: &str) -> u128 {
        self.lane_prices.get(lane).copied().unwrap_or(0)      <- absent == free
    }
$ git grep -n "lane_prices" -- 'crates/**'
busbar/src/root/policy.rs:129:    let lane_prices = cfg.prices.iter().map(|p| (p.lane.clone(), p.price)).collect();
busbar/src/root/tests/policy.rs:70: !policy.policy().lane_prices.contains_key("unpriced-lane")
$ git grep -n "cross_check_lane" -- 'crates/**'
usage/meter.rs:193:    let lane = cross_check_lane(retained.lane_legs(), declared, policy);   <- shipping
$ git grep -n "busbar_kernel_ledger::usage::meter" -- 'crates/**'
busbar/src/root/units_a2a.rs:1569                                                  <- shipping plane
```
DIFF:      When the three lane legs disagree, `min_by(price_of)` selects the candidate with the
           lowest comparable price, and an UNPRICED lane scores `0` — so it always wins. The
           selected lane then reaches pricing at `cost/posting.rs:425`
           (`card.lane_rates(&posting.lane, currency)`), which fails closed at `:496`
           (`Err(Unpriceable::LaneUnpriced)`). So the rule converts a dispute between PRICED lanes
           into a guaranteed **unpriceable posting**.
ROOT CAUSE: "absent from the card" is being read as the price `0` rather than as "not a candidate".
           `evidence.rs:142-143` and `lane.rs:120` both call this "the conservative reading" — under
           #42 it is the opposite: an unpriced class is a REFUSAL, and refusal is not cheap. One of
           the three legs (`legs.response`) is a string the UPSTREAM supplies, so an upstream that
           names a lane the card does not price can push every posting into the refusal path.
ACTION:    Exclude unpriced lanes from candidacy (or refuse immediately on one), so the cheaper-of
           rule only ever ranks lanes the card actually prices. Delete the `unwrap_or(0)` in
           `price_of` in favour of `Option<u128>` so "absent" cannot silently compare as a number.
           **Owner ruling required: changes which lane a disputed posting prices against.**

### X-2103 · A unit test pins the rule X-2102 says is wrong
CLASS:     money
CERTAINTY: PARK  *(moves with X-2102)*
CELL:      `crates/busbar-kernel-ledger/src/usage/tests/lane_tests.rs:139-152`
EVIDENCE:
```
$ sed -n '141,152p' crates/busbar-kernel-ledger/src/usage/tests/lane_tests.rs
fn an_unpriced_lane_is_the_cheapest_candidate() {
    assert_eq!(policy.price_of("nobody-prices-this"), 0);
    ...
    assert_eq!(check.lane.as_deref(), Some("nobody-prices-this"));
}
```
A third copy of the same claim sits at `busbar/src/root/tests/policy.rs:68-71` ("an unpriced lane has
no entry and sorts as cheapest, which is the conservative way") — so the rule is restated in three
places and ruled in none of them.
ACTION:    When X-2102 is ruled, invert this test to assert the ruled behaviour (exclusion or
           refusal) and remove the duplicate claim in `root/tests/policy.rs`.

### X-2104 · `Finding::AnchorHeadDiffers` is declared and formatted but never constructed
CLASS:     instrument-blind
CERTAINTY: VERIFIED
CELL:      `crates/busbar-kernel-ledger/src/verify.rs:34-40` (decl), `:76-79` (Display)
EVIDENCE:
```
$ git grep -n "AnchorHeadDiffers" -- .
crates/busbar-kernel-ledger/src/verify.rs:35:    AnchorHeadDiffers {
crates/busbar-kernel-ledger/src/verify.rs:76:            Finding::AnchorHeadDiffers { anchored, expected } => write!(
  (2 hits: a declaration and its Display arm. No construction.)
POSITIVE CONTROL $ git grep -n "CheckpointEdited" -- . | wc -l  ->  4   (incl. construction verify.rs:120)
```
Neither `verify()` (`:113-161`) nor `sequences_are_monotonic()` (`:164-178`) compares an anchored
head to the checkpoint being verified — no function in the crate takes an anchor at all.
ROOT CAUSE: the anchor-vs-local-history check was specified (its Display string reads *"the anchored
           history and this node's do not agree"*) and never implemented. Law 1: an instrument that
           cannot produce a NO is not a check. This is the arm that would catch a node whose ledger
           diverged from the anchored record — the tamper-evidence claim the checkpoint chain exists
           to support.
ACTION:    Either implement the comparison (take `AnchoredHead` in `verify` and push the finding when
           `anchored != expected`) or delete the variant. Shipping a declared integrity finding that
           cannot fire is the worse of the two.

### X-2105 · The ledger's entire verification entry point has no shipping caller
CLASS:     missing-code
CERTAINTY: VERIFIED
CELL:      `crates/busbar-kernel-ledger/src/verify.rs:113` (`verify`), `:164` (`sequences_are_monotonic`)
EVIDENCE:
```
$ git grep -n "VerifyFinding\|AllWindowsOpen\|busbar_kernel_ledger::verify\|kernel_ledger::verify" -- .
crates/busbar-kernel-ledger/src/lib.rs:119                 <- the re-export itself
crates/busbar-kernel-ledger/src/tests/checkpoint_tests.rs:16,82,201,210,214,255,259,297
crates/busbar-kernel-ledger/src/verify.rs:99,101
  (every hit is inside this crate: a re-export, the definition, and its own tests)
POSITIVE CONTROL $ git grep -n "busbar_kernel_ledger::usage" -- .
  busbar/src/root/policy.rs:50, units_a2a.rs:88,1554,1569, units_mcp.rs:72,1238   <- real shipping callers
```
(The `verify::verify` hits in `busbar/src/root/units_llm.rs:1286` and `busbar-llm/` are
`unit::verify::verify`, an unrelated function.)
ROOT CAUSE: Law 2 — a capability never constructed is a capability that does not ship. Nothing in a
           running busbar ever checks that a checkpoint hashes to its own figures
           (`Finding::CheckpointEdited`), that the balance identity holds (`Finding::Imbalanced`),
           that a sealed balance did not vanish (`Finding::Retired`), or that a closed window stopped
           moving (`Finding::ClosedWindowMoved`). Those four findings exist and are tested in
           isolation; no shipping path can emit one.
ACTION:    Wire `verify` into whatever seals or reads a checkpoint (the admin verification verb or the
           checkpoint writer), with a real `WindowState` rather than `AllWindowsOpen`, and fail the
           operation on a non-empty finding list. Until then, treat the ledger's tamper-evidence
           claims as untested in production.

### X-2106 · The settlement table — "one table, every end" — is unreachable from shipping code
CLASS:     missing-code
CERTAINTY: VERIFIED
CELL:      `crates/busbar-kernel-ledger/src/usage/settlement.rs:130-215` (`settle`), `:14-39`
           (`UnitEndKind`), `:84-92` (`posting_flags`)
EVIDENCE:
```
$ git grep -nE "UnitEndKind|SettleFlag|locator_required|kernel_floor|checkpointed_accrual" -- . \
    | grep -v "^crates/busbar-kernel-ledger/"
  (no output — 0 hits outside the defining crate)
POSITIVE CONTROL $ git grep -nE "MeterPolicy|KernelCounts" -- . | grep -v "^crates/busbar-kernel-ledger/"
  busbar/src/main.rs:519, busbar/src/root/kernel.rs:633,684,715   <- same module tree, real callers
$ git grep -n "posting_flags" -- .
  usage/mod.rs:49 (re-export), settlement.rs:84 (def), usage/tests/settlement_tests.rs:303,331
  (busbar-kernel-budget/src/lib.rs:179 is a different method on a different type)
```
`settle` is a free function whose argument type is `UnitEndKind`; with zero `UnitEndKind` mentions
outside the crate, no external caller can exist. Only `requests_settled` ships
(`busbar-kernel/src/teller.rs:1314`).
ROOT CAUSE: the module states the billing rule for every non-happy-path ending — a stream that dies
           with a terminal error bills NOTHING (`:160-165`), a crash-recovered undispatched unit is
           `Voided` (`:175-178`), a durability-lost posting is retained and re-appended
           (`:186-207`), an absent locator on a priced class is `Estimated + MeterDisputed`
           (`:142-151`). None of that is in force: whatever the planes do on those paths is
           something else, and it is unaudited. 17 tests
           (`usage/tests/settlement_tests.rs`) prove the table in isolation and prove nothing about
           the product.
ACTION:    Either route the planes' unit-end handling through `usage::settle` (the `Metered`/`meter`
           seam at `units_a2a.rs:1569` is the precedent that already works), or delete the module and
           document where each end-kind's amount is ACTUALLY decided. The gate at
           `busbar/tests/plane_meter_seam_reachability.rs` proves the Meter step is wired; there is no
           equivalent for the Settle step.

### X-2107 · Card-build quantization takes half-away-from-zero on the f64 APPROXIMATION, so exact-half rates under-quantize — OUT-OF-SLICE SUBJECT
CLASS:     money
CERTAINTY: PARK  *(billed byte; the numeric proof below is VERIFIED)*
CELL:      `crates/busbar-kernel-ledger/src/cost/rate.rs:40-57` (`nano_rate`) — **not in this slice**;
           entered from `crates/busbar-kernel-budget/src/price.rs:76-79` (the four `f64` params) and
           `cost/rate.rs:122-128` (`TierRates`). Its guard test is
           `crates/busbar-kernel-ledger/tests/rate_conversion_agreement.rs` — also not in this slice.
EVIDENCE:  IEEE-754 double semantics, reproduced exactly (`f64::round` = half away from zero):
```
$ python3 -c '...'      # 200,000 four-decimal-place config rates, f64 path vs exact-decimal rule
4dp rates scanned: 200000, mismatches: 185
   config rate 0.5005 micro/unit -> nano_rate gives 500, #44 half-away-from-zero gives 501 (delta 1)
   config rate 0.5015 micro/unit -> nano_rate gives 501, #44 half-away-from-zero gives 502 (delta 1)
   ... 185 total, ALL in the same direction (under)

The four half-values the guard test NAMES all pass, because they land on or above the true half:
   0.0005 -> f64*1000 = 0.5                 -> 1   (expected 1)  OK
   0.0015 -> f64*1000 = 1.5                 -> 2   (expected 2)  OK
The same KIND of value, not named by the test, does not:
   0.5005 -> f64*1000 = 500.49999999999994  -> 500  (#44 says 501)  ** UNDER BY 1 **
   0.5015 -> f64*1000 = 501.49999999999994  -> 501  (#44 says 502)  ** UNDER BY 1 **
```
DIFF:      A rate configured as `0.5005` micro-units per unit is quantized to 500 nano-units instead
           of 501 — a systematic **1 nano-unit per unit under-bill**, always in the customer's
           favour, for the whole life of that card.
ROOT CAUSE: #44 (`:369`) rules that card-build-time quantization is half-away-from-zero, and
           `rate_conversion_agreement.rs:101-103` asserts *"`f64::round` IS that rule"*. It is that
           rule **on the f64**, not on the operator's decimal — and the decimal was already lost in
           the parse before `round` ran. This is precisely the failure #81 (`:425`) bans binary
           floating point to prevent: *"`f64` cannot represent `27.1` … so `f64` would break this
           very ruling on the next value."* The rate is on the money path, so the #81 ban applies to
           it. The guard test is not blind in general (it names expected integers and says why), but
           its four half-rows are all favourably-representable, so this class passes unnoticed.
MATERIALITY: latent, not live in-tree — `git grep -nE "…[0-9]+\.[0-9]{3,}" -- '*.yaml' '*.yml' '*.toml'`
           → no configured rate with 3+ decimals (positive control: decimals do exist in those files).
           It is reachable by any operator who configures one.
ACTION:    Parse the configured rate from its DECIMAL TEXT to an integer nano-rate without an `f64`
           intermediate — the `Count`/`i128`-at-scale machinery #81 mandates already exists at
           `crates/busbar-contract/src/count.rs:142`. Add `0.5005 -> 501` to the boundary table; it
           goes red today. **Owner ruling required: changes card-build bytes, which the oracle pins.**

### X-2108 · Three manifests name crates that no longer exist
CLASS:     drift
CERTAINTY: VERIFIED
CELL:      `busbar-kernel-ledger/Cargo.toml:1,12,13,42`; `busbar-kernel-budget/Cargo.toml:1,35`;
           `busbar-kernel-scope/Cargo.toml:1,7`
EVIDENCE:
```
$ git grep -n "busbar-unit-cost\|busbar-caps\|busbar-unit-admission\|busbar-unit-scope\|busbar-unit-ledger" \
    crates/busbar-kernel-{ledger,budget,scope}/Cargo.toml
ledger:1  # busbar-unit-ledger — the ledger unit.
ledger:12 # DEPENDENCIES. `busbar-caps`; `sha2` …
ledger:13 # … and `busbar-unit-cost` because money is a lookup …
budget:1  # busbar-unit-admission — the door.
budget:35 # … `busbar-unit-cost` is pure integer arithmetic …
scope:1   # busbar-unit-scope — the APPROVE step …
scope:7   # … with `busbar-caps` as its only workspace dependency …
```
Actual deps: ledger = `busbar-contract` + `sha2` (+ dev `busbar-kernel-budget`); budget =
`busbar-contract` + `busbar-kernel-ledger`; scope = `busbar-contract`. `busbar-unit-cost` was folded
into `busbar-kernel-ledger`'s `cost` module under #36; `busbar-caps` is now `busbar-contract`.
NOT A DEFECT (checked, and the claims hold): the ledger's dev-dep on the budget crate IS live
(`tests/rate_conversion_agreement.rs:36,44`), and the scope manifest's "66 operations, 34 read-only /
32 full" is EXACT (`sed -n '270,358p' src/lib.rs | grep -oE "Scope::(ReadOnly|Full)" | sort | uniq -c`
→ 34/32; `grep -cE "^\s*op\("` → 66).
ACTION:    Rename the six stale crate references to the current names. Comment-only; no code moves.

### X-2110 · `billing.rs`'s byte-identity claim overstates its own test by 1000× in span and 77% in count
CLASS:     money
CERTAINTY: PARK  *(the claim justifies an `f64` on a billed quantity; the arithmetic below is VERIFIED)*
CELL:      `crates/busbar-substrate-values/src/billing.rs:103-106` (claim) vs
           `crates/busbar-substrate-values/src/tests/billing_duration_tests.rs:60-79` (the test)
EVIDENCE:
```
$ sed -n '103,106p' crates/busbar-substrate-values/src/billing.rs
  "...for every quantity the scale can hold: checked over 200,009 values spanning zero to a
   thousand hours, zero differed."
$ sed -n '60,79p' crates/busbar-substrate-values/src/tests/billing_duration_tests.rs
  for micros in 0..10_000i128          ->  10,000
  for _ in 0..100_000 (rng % 3_600_000_000) -> 100,000
  for whole in 0..1_000 x delta -1..=1 (micros>=0) -> 2,999
                                           TOTAL = 112,999   (not 200,009)
  3_600_000_000 micros = 3,600 s = ONE hour   (a thousand hours = 3,600,000,000,000 micros)
```
Re-running the file's own xorshift gives max drawn = 3,599,995,958 micros (0.99999888 h).
DIFF:      That paragraph is the stated justification for the ONLY `f64` on the duration billing path
           (`duration_seconds_to_wire`, `:108-112`). *"Every quantity the scale can hold"* is false:
           the identity `micros as f64 / 1e6 == text.parse::<f64>()` holds only while
           `|micros| < 2^53`. Smallest measured counterexample: `micros = 9_007_199_254_740_993`
           (text `"9007199254.740993"`) — the two routes give DIFFERENT doubles. That band is inside
           the type's own declared persistable range (`i64::MAX` micros ≈ 9.22e18, ~1,024× above 2^53).
ROOT CAUSE: the doc measures a claim the test never made. #81 permits a decimal only at a BOUNDARY;
           this IS a rendering boundary, so the `f64` is arguably in-policy — but the boundary's
           safe domain was never established, and the doc asserts a universal that is false.
ACTION:    Replace the claim with what is measured ("112,999 values spanning zero to one hour"), state
           the real domain bound, and either refuse (#81/#42) for `micros.abs() >= 1<<53` or document
           the ceiling. Fix the same 1000× error in the test comment at `:64`.
           **Owner ruling required before changing what this function renders.**

### X-2111 · The duration sweep's own floor does not cover its boundary loop
CLASS:     instrument-blind
CERTAINTY: VERIFIED
CELL:      `crates/busbar-substrate-values/src/tests/billing_duration_tests.rs:80`
EVIDENCE:  `assert!(checked > 100_000, "only {checked} values swept")`. Loop 2 alone contributes
           exactly 100,000 and loop 1 another 10,000, so deleting the whole "boundaries a renderer
           trips on" loop (`:71-79`) leaves `checked = 110_000 > 100_000` — still green.
ACTION:    Raise the floor to `checked >= 112_999`, or assert each loop's contribution separately.

### X-2112 · `MediaBlob::is_well_formed` is a guard with no production caller
CLASS:     missing-code
CERTAINTY: VERIFIED
CELL:      `crates/busbar-substrate-values/src/media.rs:141` (definition) — media.rs itself is OUT OF
           SLICE; raised from its only caller, `src/tests/media_tests.rs`, which IS in slice.
EVIDENCE:
```
$ git grep -n "is_well_formed" -- 'crates/busbar-substrate-values/**'
src/media.rs:141:    pub(crate) fn is_well_formed(&self) -> bool {
src/tests/media_tests.rs:19,26,35     <- the only three callers, all assertions
```
The test's own message says raw PCM without params is *"silently lossy"* — and at runtime it is,
because nothing consults the predicate. Law 2: a capability never constructed does not ship.
ACTION:    Call `is_well_formed` on the ingest path that builds a `MediaBlob` and reject/warn when
           false, or delete the method and the test that is its only user.

### X-2113 · The JSON-seam gate guards two `serde_json` spellings but not the library the seam names
CLASS:     instrument-blind
CERTAINTY: VERIFIED (the hole), latent (no live bypass today)
CELL:      `crates/busbar-substrate-values/src/tests/json.rs:39`
EVIDENCE:  the offender list matches only `serde_json::to_vec` / `serde_json::from_slice`, while the
           seam itself is sonic-rs (`grep -c "sonic_rs::" src/json.rs` → 12). A `sonic_rs::from_slice`
           or `serde_json::from_str` outside the seam skips `exceeds_max_depth` and the gate is
           silent. Clean today: `grep -rn "sonic_rs::" src/ | grep -v "^src/json.rs:"` → rc=1;
           `grep -rn "serde_json::from_str|to_string|from_value" src/ | grep -v tests` → 0.
ACTION:    Add `sonic_rs::from_slice`, `sonic_rs::to_vec`, `serde_json::from_str`,
           `serde_json::to_string`, `serde_json::from_value` to the list, and pin the predicate
           against known-good/known-bad lines (the pattern `breaker_tests.rs:325` already uses).

### X-2114 · `lossless_tests.rs` asserts `std::collections::BTreeMap`, not this crate
CLASS:     instrument-blind
CERTAINTY: VERIFIED
CELL:      `crates/busbar-substrate-values/src/tests/lossless_tests.rs` (whole file)
EVIDENCE:
```
$ grep -nE '^\s*(pub )?(const )?fn |^\s*impl |^\s*const |^\s*static ' crates/busbar-substrate-values/src/lossless.rs ; echo rc=$?
rc=1                                   <- no executable code at all
POSITIVE CONTROL: same pattern on src/media.rs -> 6 hits
```
The subject is one `pub type SourceScopedExtra = BTreeMap<String, Map<String, Value>>;`. The test
inserts `"logprobs"` and asserts it is present, then asserts `"gadget"` (never inserted) is absent.
Neither can fail for any map type. NOTE: the ALIAS itself ships (5 users in
`busbar-llm-codec/src/ir/*`), so `lossless.rs` is CLEAN — it is only the test that is vacuous.
ACTION:    Delete the file, or replace it with the property the alias actually encodes — that two
           source protocols' extras survive a round-trip through the IR without merging namespaces,
           which is the claim `lossless.rs:13-16` makes and nothing checks.

### X-2115 · `building_a_capture_leaves_the_process_interested_in_warns` reads a flag a sibling test already set
CLASS:     instrument-blind
CERTAINTY: ADJUDICATE  *(reasoned from `tracing`/`Once` semantics; not executed red)*
CELL:      `crates/busbar-substrate-values/src/tests/warn_capture_tests.rs:22-27`
EVIDENCE:  the test constructs one `WarnCapture` then asserts `LevelFilter::current() >= Level::WARN`.
           That flag is set inside `ensure_capture_interest()` behind `static ONCE: std::sync::Once`
           (`src/testkit/warn_capture.rs:157-166`, with `let _ = set_global_default(..)` swallowing
           the already-set error). `WarnCapture` is also constructed at `sse_tests.rs:18`,
           `breaker_tests.rs:270` and `tests/lib.rs:18,30` — same 113-test binary, run concurrently.
           Whichever runs first fires the `Once`; this test's own constructor then contributes
           nothing to the condition it asserts.
ACTION:    Make it self-contained (assert not-yet-set at entry, then set — needs its own integration
           binary), or reframe it as what it can prove and leave the real proof to
           `a_warn_fired_without_a_subscriber_does_not_blind_a_later_capture`, which is end-to-end.

### X-2116 · The `no-float-money` gate does not scan the crate holding the neutral `f64` rate carrier
CLASS:     instrument-blind
CERTAINTY: VERIFIED  *(subject `xtask/src/gates/no_float_money.rs` is OUT OF SLICE; proven from it)*
CELL:      `xtask/src/gates/no_float_money.rs` — no-float walk roots at `:104,128,136,156,163,178,203,208,245`
EVIDENCE:
```
$ grep -nE 'const [A-Z_]+(SRC|ROOT|FILES|BOUNDARY): ' xtask/src/gates/no_float_money.rs
104 LEDGER_SRC   109 CARD_BUILD_BOUNDARY   128 BINARY_MONEY_FILES   136 BINARY_ROOT
156 CONTRACT_MONEY_FILES  163 CONTRACT_ROOT  178 BUDGET_SRC  203 AUDIT_SRC  208 WAL_SRC
245 KERNEL_MONEY_FILES
$ grep -n "substrate" xtask/src/gates/no_float_money.rs
353:            "crates/busbar-substrate-values/src",     <- COUNT_ROOTS only (count-read-shape row)
$ git grep -ln "f64|float" -- xtask/src/gates/   # is any OTHER gate the backstop?
  no_float_money.rs is the only money-float gate
```
DIFF:      `crates/busbar-substrate-values/src/billing.rs:171-190` declares
           `RawTierRates { input: f64, output: f64, cache_read: f64, cache_write: f64 }` and
           `blended_per_mtok() -> f64` doing `(self.input + self.output) / 2.0`, with a live
           production caller (`busbar-kernel/src/config/sections.rs:358`). It sits in the
           count-read scan but OUTSIDE the no-float scan, so the ban #81 requires to be RED-provable
           cannot fire on the neutral rate carrier.
ROOT CAUSE: the gate's own header says *"THE SCAN SET IS THE CHECK"*. The scan set grew crate by crate
           (its comments record adding budget, audit and wal after each was found unscanned) and the
           neutral-carrier crate was never added. The gate is NOT blind in general — it has plant-a-float
           selftests at `:1246-1274` that prove RED — its denominator is just short.
ACTION:    Add `crates/busbar-substrate-values/src` to the no-float walk with its own floor, or record
           an explicit, reasoned exemption beside `CARD_BUILD_BOUNDARY`. Note the `f64` itself is
           already carried as LEDGER M2 / THE-LIST M2/M21; **this row is the GATE GAP, not the float.**

### X-2118 · `busbar-substrate-values/Cargo.toml`: a dead crate, a dead package name, an orphaned dep comment, and a feature comment that points at the wrong file
CLASS:     config / drift
CERTAINTY: VERIFIED
CELL:      `crates/busbar-substrate-values/Cargo.toml:7, 32-34, 80-83`
EVIDENCE:
```
$ ls -d crates/busbar-contract-transport
ls: crates/busbar-contract-transport: No such file or directory     <- L32-34 describes a dep on it
$ git grep -n '^name = "busbar-substrate"' -- '*/Cargo.toml' ; echo rc=$?
rc=1     (POSITIVE CONTROL '^name = "busbar-substrate' -> only busbar-substrate-values)
$ git grep -n 'feature = "relay"' -- 'crates/busbar-substrate-values/*'
src/lib.rs:85            <- NOT transport.rs, which L80-83 claims
$ git grep -n 'feature = "dispatch"' -- 'crates/busbar-substrate-values/*'   # control
src/lib.rs:85 ; src/transport.rs:12
```
Three half-here-half-there remnants: (a) a comment block describing a dependency edge with no dep
line under it (the crate was folded into `busbar-contract` under DECISIONS #38); (b) `busbar-substrate`
named as a live package in the description and the feature comment; (c) `relay` documented as gating
`transport`, when its only use in this crate is the `allow(dead_code)` cfg_attr on `store::now_ms`.
ACTION:    Delete the orphaned block (or restore the dep it described); replace `busbar-substrate`
           with `busbar-kernel`; point the `relay` comment at `lib.rs`'s `now_ms` gate.

### X-2119 · `handlers.rs` module doc says four items "STAY in core"; all four are defined in this file
CLASS:     drift
CERTAINTY: VERIFIED
CELL:      `crates/busbar-substrate-values/src/handlers.rs:19-20`
EVIDENCE:
```
$ sed -n '19,20p' crates/busbar-substrate-values/src/handlers.rs
//! ... `OpDispatch`, the registry-resolved `chat`/`op_for` resolvers and `protocol_error`
//! STAY in core — those name the core registry singleton.
$ grep -n 'pub struct OpDispatch\|pub fn op_for\|pub fn chat\|pub fn protocol_error' \
      crates/busbar-substrate-values/src/handlers.rs
535: pub struct OpDispatch      609: pub fn op_for      629: pub fn chat      645: pub fn protocol_error
```
The relocation happened; the doc describing the cut line did not move with it. A reader trusting the
header looks for `OpDispatch` in `busbar-kernel` and finds only a re-export.
ACTION:    Replace the sentence with the true cut — these four moved here, and
           `busbar-kernel/src/handlers/mod.rs` re-exports them.

### X-2120 · The neutral codec trait contract states the OPPOSITE billing rule from the one that ships
CLASS:     money
CERTAINTY: PARK  *(billed byte; the contradiction and its resolution are both VERIFIED from code)*
CELL:      `crates/busbar-substrate-values/src/handlers.rs:408-412` (the wrong contract) vs
           `crates/busbar-substrate-values/src/wire.rs:97-106` (the right one) vs
           `crates/busbar-llm/src/engine/attempt/buffered.rs:533-545` (what actually ships)
EVIDENCE:
```
handlers.rs:408-410 — "The returned usage is ALWAYS the read IR's usage (`ir.usage()`), which the
  caller bills before rendering the outcome — so a read-succeeded-but-undelivered terminal
  (404 / 500) STILL BILLS, exactly as the pre-cutover arm did."

wire.rs:97-106 (IngressUnsupported AND Untranslatable) — "NO completion reaches the client, so the
  caller does NOT bill this and leaves its spend guard armed to refund."

buffered.rs:533-545 (THE SHIPPING CALLER, which settles it) —
  // Bill ONLY when the resolved delivery hands bytes to the client. `IngressUnsupported` (a 404)
  // and `Untranslatable` (the 500) deliver no completion: leave the guard armed so the budget unit
  // is refunded...
  if matches!(delivered, StreamFrames(_) | Typed(_) | Json(_)) { ... record_resp_usage(..); }
```
DIFF:      `wire.rs` is right and `handlers.rs` is wrong. Nothing is mis-billed TODAY, because the one
           shipping caller follows `wire.rs`. The exposure is forward: `handlers.rs:408-412` is the
           doc-contract of the neutral `TranslateCodec::translate_response` seam that EVERY plane
           crate implements against, so the next implementor or caller who follows it charges a
           customer for a response the client never received.
ROOT CAUSE: the pre-cutover arm did bill on those terminals; the behaviour was corrected in `wire.rs`
           and in the caller, and the trait's own contract was not moved with it — a rename applied
           on one side. Compounding it, the same sentence names `ir.usage()`, a method that does not
           exist on `IrHandle` (the accessor is `billing()`, `ir/handle.rs:106`), so the sentence
           cannot even be followed literally.
ACTION:    Rewrite `:408-412` to state the delivery-gated rule (`StreamFrames | Typed | Json` bill;
           `IngressUnsupported | Untranslatable` do not, guard stays armed to refund) and replace
           `ir.usage()` with `ir.billing()`. **Owner sign-off: this is the wording of a billing
           contract, even though no byte moves today.**

### X-2121 · Two shipping SigV4 signers, each carrying a signature-affecting fix the other lacks — and the two test suites have diverged in lockstep
CLASS:     auth
CERTAINTY: VERIFIED
CELL:      `crates/busbar-substrate-values/src/sigv4.rs:149-154` vs
           `crates/busbar-kernel-identity/src/egress_auth/sigv4/mod.rs:157-167` (OUT OF SLICE)
EVIDENCE:
```
$ grep -n "in_quotes" crates/busbar-substrate-values/src/sigv4.rs
149:    let mut in_quotes = false;     152: in_quotes = !in_quotes;     154: if ch == ' ' && !in_quotes
$ grep -n "in_quotes" crates/busbar-kernel-identity/src/egress_auth/sigv4/mod.rs ; echo rc=$?
rc=1        <- the quoted-string fix is ABSENT from the identity copy

$ grep -n "merged\|push(',')" crates/busbar-substrate-values/src/sigv4.rs ; echo rc=$?
rc=1        <- the AWS duplicate-header comma-join is ABSENT here
$ grep -n "merged\|push(',')" crates/busbar-kernel-identity/src/egress_auth/sigv4/mod.rs
157: let mut merged ...  161: last_v.push(',')  167: let h = merged;

$ grep -nE '^busbar-[a-z-]+ = ' crates/busbar-kernel-identity/Cargo.toml
23: busbar-contract = { ... }        <- the ONLY busbar dep; no code sharing is possible
```
`busbar-kernel-identity/.../sigv4/mod.rs:4-7` claims it was *"ported unchanged from `busbar-substrate`'s
signer."* It was not. Both ship: `busbar-llm-codec/src/bedrock/writer.rs:81` uses this crate's;
`busbar-kernel-identity/src/egress_auth/mod.rs:141` uses the other, and signs
`body.envelope.to_vec()` — a CALLER-SUPPLIED header set that can legitimately carry a quoted-string
value, so the missing quoted-string fix is reachable there.
**NEITHER SUITE CAN CATCH THE OTHER'S GAP.** Each tests exactly the behaviour its own copy has:
`substrate sigv4_tests.rs:470` is the quoted-string test (identity has none — `grep -nEi 'quote'` on
its tests → rc=1); `identity tests.rs:106` is `sign_v4_merges_a_duplicate_header_name_by_comma_joining_its_values`
(substrate's `sign_v4` has none — its duplicate test at `sigv4_tests.rs:407` goes through
`verify_inbound_sigv4`, which does its OWN pre-join and never exercises `sign_v4`'s absent merge).
The only shared ground is the AWS published example (both at `:105-118` / `:50-63`) — a simple GET
with no quoted-string value and no repeated header, which CANNOT distinguish the two. No xtask gate
compares them (`git grep -n "sigv4|SigV4" -- xtask/src` → only `design_bindings` name bindings, which
assert named tests EXIST, never that two implementations AGREE).
ROOT CAUSE: exactly the defect the money code went to great lengths to eliminate — *"two copies of a
           rounding rule that must agree exactly is how a request comes to be JUDGED at one rate and
           BILLED at another"* — applied to a cryptographic signing rule. `sigv4.rs:224-230` even
           argues *"There is deliberately NO second canonicalization implementation — a duplicate
           could drift from the signer and from AWS."* A second implementation exists and has drifted.
SECONDARY:  `sigv4.rs:51-65` — `hmac()` returns `Vec::new()` on the (today-unreachable) `Err` arm, and
           its rationale covers only the OUTBOUND direction (*"wrong signature → AWS responds 403"*).
           On the INBOUND verify path an empty key makes the whole `signing_key` chain
           secret-INDEPENDENT — fail-OPEN. Unreachable today (`Hmac::new_from_slice` accepts any key
           length), so ADJUDICATE, but the comment is missing its verify-side half.
ACTION:    Collapse the two to one — have `busbar-kernel-identity` depend on
           `busbar_substrate_values::sigv4` (pure, opens nothing) instead of carrying a copy. Failing
           that, port the quoted-string arm into the identity copy AND the duplicate-header merge into
           `sign_v4` here, and add a cross-implementation agreement test over a vector that exercises
           BOTH edge cases. Extend the `hmac()` comment to state the verify-side consequence.

### X-2122 · `proxy::ERR_DEGRADED_NON2XX` is a capability that does not ship
CLASS:     missing-code
CERTAINTY: VERIFIED
CELL:      `crates/busbar-substrate-values/src/proxy/mod.rs:234`
EVIDENCE:
```
$ git grep -nF "ERR_DEGRADED_NON2XX" -- '*.rs'
busbar-llm/src/engine/mod.rs:113                       <- a `pub use` re-export, not a call
busbar-llm/src/engine/tests/legacy_forward_once.rs:477
busbar-llm/src/engine/tests/legacy_forward_once.rs:535
busbar-substrate-values/src/proxy/mod.rs:234           <- the definition
POSITIVE CONTROL $ git grep -nF "ERR_NET_CONNECT" -- '*.rs' | grep -v tests
busbar-kernel/src/telemetry.rs:528 ; busbar-llm/src/engine/attempt/classify.rs:62   <- real call site
```
`legacy_forward_once.rs` is test-only, pulled in via `#[path]` from
`engine/tests/attempt_identity_tests.rs:25`, which describes it as *"the legacy degraded-path twin
`forward_once`, kept verbatim."* The const's doc claims it is *"recorded when a HalfOpen probe's
degraded forward returns a non-2xx (bumps cooldown)"*; the shipping degraded path never passes it.
Confirming: it is absent from the fixed label vocabulary `busbar-kernel/src/telemetry.rs:523-531
REASONS`, while its siblings `ERR_NET_CONNECT`/`ERR_NET_TIMEOUT` are present.
SECOND HALF OF THE SAME PAIR: `busbar-llm/src/engine/attempt/buffered.rs:467` passes a RAW LITERAL
`"untranslatable-2xx"` as an `err_type`, with no const and no `REASONS` entry.
ACTION:    Either wire the const into the shipping degraded non-2xx `record_transient_in` arm and add
           it to `REASONS`, or delete the const and its `pub use`. Hoist `"untranslatable-2xx"` into
           the same const block either way.

### X-2123 · `warn_capture.rs` asserts a one-gate-per-binary invariant that is false
CLASS:     instrument-blind
CERTAINTY: VERIFIED  *(the false claim and the two gates); latent for the flake itself*
CELL:      `crates/busbar-substrate-values/src/testkit/warn_capture.rs:6-7`
EVIDENCE:
```
$ git ls-files | grep -i warn_capture
crates/busbar-kernel/src/test_support/warn_capture.rs        <- a SECOND copy
crates/busbar-substrate-values/src/testkit/warn_capture.rs
$ grep -n "static GATE" crates/busbar-kernel/src/test_support/warn_capture.rs
174:    static GATE: std::sync::OnceLock<CaptureGate> = ...   <- its own independent gate
$ grep -n 'test-support' crates/busbar-kernel/Cargo.toml
308: busbar-substrate-values = { path = "...", features = ["test-support"] }   # [dev-dependencies]
$ sed -n '318p' crates/busbar-kernel/src/lib.rs
pub mod test_support;
```
The file claims *"a test binary only ever links ONE of them (so the process-global capture gate below
is one gate per binary, exactly as before)."* `cargo test -p busbar-kernel` links BOTH — two
independent `OnceLock<CaptureGate>` in two crates. This is verbatim the defect
`busbar-substrate-values/src/lib.rs` records fixing INSIDE this crate (*"two independent copies each
minted their OWN process-global capture gate … One module, one gate"*); the fix stopped at the crate
boundary. No binary today drives real captures through both gates concurrently, so the flake is
latent — but the serialization the gate exists to provide provably does not span the two copies, and
that claim cannot produce a NO.
SECONDARY:  `GateHold::drop` (`:215-228`) decrements/releases without checking
           `owner == std::thread::current().id()`. `Arc<GateHold>` is `Send`, so a `WarnCapture`
           clone dropped on another thread releases a hold that thread does not own.
ACTION:    Replace `crates/busbar-kernel/src/test_support/warn_capture.rs` with
           `pub use busbar_substrate_values::testkit::warn_capture::*;` (exactly what
           `busbar-kernel/src/testkit/mod.rs:30` already does), delete the duplicate, and drop the
           now-true-by-construction sentence. Add an `owner == me` guard to `GateHold::drop`.

### X-2124 · `transport.rs` doc names a deleted crate and carries a half-applied rename
CLASS:     drift
CERTAINTY: VERIFIED
CELL:      `crates/busbar-substrate-values/src/transport.rs:4-9`
EVIDENCE:
```
$ sed -n '4,9p' crates/busbar-substrate-values/src/transport.rs
//! The `Transport` axis — RELOCATED to `busbar-contract-transport` ...
//! Every existing `busbar_substrate_values::transport::…` / `busbar_substrate_values::transport::…`
$ ls -d crates/busbar-contract-transport
ls: crates/busbar-contract-transport: No such file or directory
```
The `pub use` actually resolves into `busbar-contract`
(`crates/busbar-contract/src/transport/transport.rs:136,206` present and correct). Line 9 lists the
SAME path twice — a rename applied to one side of a two-sided sentence; it was evidently
`busbar_kernel::transport::…` / `busbar_substrate::transport::…` before.
ACTION:    Retarget the doc at `busbar-contract` (`transport::transport`) and restore the two distinct
           historical paths on line 9.

### X-2125 · A red diagnostics golden prints a repair command that cannot run
CLASS:     instrument-blind
CERTAINTY: VERIFIED
CELL:      `crates/busbar-substrate-values/src/diagnostics/tests.rs:135, 151`
EVIDENCE:
```
$ sed -n '133,136p;149,152p' crates/busbar-substrate-values/src/diagnostics/tests.rs
//   UPDATE_DIAGNOSTICS=1 cargo test -p busbar-substrate diagnostics::tests
         "docs/diagnostics.md is stale — regenerate with \
          `UPDATE_DIAGNOSTICS=1 cargo test -p busbar-substrate diagnostics::tests`"
$ git grep -n '^name = "busbar-substrate"' -- '*/Cargo.toml' ; echo rc=$?
rc=1
$ git grep -n "UPDATE_DIAGNOSTICS" -- .github scripts xtask qa ; echo rc=$?
rc=1      (POSITIVE CONTROL: git grep -n "UPDATE_" -- .github -> 4 hits, UPDATE_OPENAPI etc.)
```
The gate CAN go red (it is never auto-blessed in CI). When it does — the only time anyone reads these
strings — the printed fix is `cargo test -p busbar-substrate …`, which exits *"package ID
specification `busbar-substrate` did not match any packages"*. An operator left holding a red golden
and a repair command that does nothing is under exactly the pressure that produces a hand-edited
`docs/diagnostics.md` — which the contract forbids ("Never bless, re-record or regenerate a golden").
The paths themselves are fine; only the package name is dead (also at `diagnostics/mod.rs:3855`).
ACTION:    Change `-p busbar-substrate` → `-p busbar-substrate-values` in all three places
           (`:135`, `:151`, and the `mod.rs:3855` comment).

### X-2126 · The `addr_of!` assertions in the neutral-handle tests cannot produce a NO
CLASS:     instrument-blind
CERTAINTY: ADJUDICATE  *(reasoned from the type; not run red)*
CELL:      `crates/busbar-substrate-values/src/ir/tests/neutral_handles.rs:19-33` and `:52`
EVIDENCE:
```rust
let arguments_ptr = std::ptr::addr_of!(req.arguments);      // req: Arc<InvokeReq>
let handle = InvokeReqHandle(Arc::clone(&req));             // handle.0 IS the same allocation
assert_eq!(std::ptr::addr_of!(handle.0.arguments), arguments_ptr,
           "the arguments Value must not have been cloned");
```
`InvokeReqHandle(pub Arc<InvokeReq>)` — both sides deref the SAME `Arc` allocation, so the addresses
are equal by construction. No source change can make this red without first making `Arc::clone(&req)`
fail to compile. NOT a dead test: the sibling `Arc::strong_count(&req) == before + 1` assertions DO
carry the real signal and go red if `facts()` reverts to a deep clone — so this is a dead
sub-assertion inside a live test.
SEPARATELY: neither test touches `billing()`, the money-bearing half of the file under test.
`SubscribeRespHandle`'s `Billing::Flat` is covered out-of-crate at
`busbar-mcp/src/codec/tests/mcp_tests.rs:613-615`, but `InvokeRespHandle::billing()` has NO assertion
anywhere in the tree.
ACTION:    Drop the two `addr_of!` assertions (the refcount assertion already proves sharing) and add
           `assert_eq!(InvokeRespHandle(resp).billing(), Some(Billing::Flat))` to cover the file's
           untested money arm.

## TALLY
```
files in slice:  72      (equals the S12-MONEY.txt file count)
verdict lines:   72
CLEAN:           49
FINDING:         23      rows raised: 25
DELETABLE:        0
UNREADABLE:       0

rows by class:      money 6 · auth 1 · missing-code 4 · instrument-blind 10 · drift 3 · config 1
rows by certainty:  PARK 6 (every money row) · VERIFIED 17 · ADJUDICATE 2
```

### Rows by subject crate
| crate | files | CLEAN | FINDING | rows |
| --- | --- | --- | --- | --- |
| `busbar-substrate-values` | 35 | 22 | 13 | X-2110..X-2115, X-2118..X-2126 |
| `busbar-kernel-ledger` | 28 | 22 | 6 | X-2102..X-2108 |
| `busbar-kernel-budget` | 8 | 5 | 3 | X-2100, X-2101, X-2108 |
| `busbar-kernel-scope` | 1 | 0 | 1 | X-2108 |

### The money rows, in severity order
1. **X-2100** — evicted model tokens counted for caps, priced at nothing (silent under-bill, card PRESENT).
2. **X-2106** — the settlement table that decides every non-happy-path amount has no shipping caller.
3. **X-2102** — the disputed-lane selector prefers an UNPRICED lane, which #42 says must refuse.
4. **X-2107** — card-build quantization rounds the `f64`, not the decimal: 185/200,000 rates under-quantize.
5. **X-2120** — the neutral codec trait contract states the opposite billing rule from the one that ships.
6. **X-2110** — the `f64` duration boundary's byte-identity claim is false outside a domain nobody bounded.

## WHAT THIS SLICE PROVES ABOUT FILES OUTSIDE IT
*(Reported, not acted on, per the contract.)*

1. **`crates/busbar-kernel-ledger/src/usage/evidence.rs:181-183`** — `price_of`'s `.unwrap_or(0)` is the
   ROOT CAUSE of X-2102. The fix belongs there, not in `lane.rs`.
2. **`crates/busbar-kernel-ledger/src/cost/rate.rs:40-57`** — `nano_rate`, the subject of X-2107. It is
   the `no-float-money` gate's ONE declared exempt boundary, so no gate covers its correctness; its
   only guard is `tests/rate_conversion_agreement.rs`, which names four half-values that all happen to
   be favourably representable.
3. **`crates/busbar-kernel-ledger/tests/rate_conversion_agreement.rs`** — NOT blind in general (it is
   admirably self-aware that agreement-only rows pass by construction, and it names expected integers),
   but its four half-rows miss the failing class entirely. Add `0.5005 -> 501`; it goes red today.
4. **`crates/busbar-kernel-identity/src/egress_auth/sigv4/mod.rs`** — the other half of X-2121. Its
   header falsely claims "ported unchanged"; it lacks the quoted-string fix and its caller signs a
   caller-supplied header envelope, so the gap is reachable there in a way it is not in-slice.
5. **`crates/busbar-kernel/src/test_support/warn_capture.rs`** — the duplicate second gate in X-2123.
   Byte-identical apart from the doc header; should become a re-export.
6. **`xtask/src/gates/no_float_money.rs`** — X-2116, the gate gap. Also worth noting the gate is
   otherwise exemplary: it carries plant-a-float selftests that prove it can go RED.
7. **`crates/busbar-llm/src/engine/attempt/buffered.rs:467`** — passes a bare `"untranslatable-2xx"`
   literal as a breaker `err_type` with no const and no `telemetry::REASONS` entry, while the const that
   DOES exist for the sibling case is dead (X-2122). Same pair, opposite halves.
8. **`crates/busbar-kernel/src/handlers/mod.rs:157`** — claims the production caller of `chat()` is
   `mcp::sampling`. Stale: `git grep -n "handlers\|::chat\|Operation::CHAT" -- crates/busbar-mcp/src/mcp/sampling.rs`
   → rc=1 (control: `grep -c '^use '` on that file → 2). The real caller is
   `busbar-llm/src/native_ingress.rs:919`.
9. **`crates/busbar-contract/src/caps/usage.rs:119`** — `UsageLine.quantity` is still `u64` (whole
   units) while `cost/view.rs` already prices through `busbar_contract::count::Count` (i128, scale 6).
   #81's decimal migration has landed on the READ side and not on the metering/settlement side, so a
   fractional count cannot survive `usage/meter.rs` to reach the view that could represent it. #81
   itself documents this migration as owed and partly PARKED, so this is a progress observation, not a
   new defect — but the seam is real and is in this slice's crates.
10. **`crates/busbar-kernel-ledger/src/cost/project.rs:24`** — `minor_of` truncates toward zero. Checked
    against #44 and NOT raised: this is the currency-scale projection on the legacy path, which
    #77(8) explicitly sanctions reproducing byte-identically. Recording it so the next sweep does not
    re-litigate it as a #44 violation.

## METHOD NOTES — false zeros caught in this slice
Every zero reported above carries a positive control. Four that actually fired during this sweep:
- Counting `Scope::(ReadOnly|Full)` across `crates/busbar-kernel-scope/src/*.rs` gave 41/38 and looked
  like drift against the manifest's "34 read-only / 32 full". Scoping to the actual table
  (`sed -n '270,358p' src/lib.rs`) gives **exactly 34/32 over 66 rows** — the first count was polluted
  by the `tests/` directory. The manifest claim is EXACT.
- A `pub`-item liveness scanner reported `CLOCK_SKEW_SECS` and `ParsedAuthHeader` as having no shipping
  caller. False: it excluded the DEFINING file, and both are consumed in-file (`sigv4.rs:443`, `:433`).
  `ParsedAuthHeader` is additionally bound by its consumer without naming the type
  (`busbar-kernel/src/auth/mod.rs:1948`), so a type-name grep looks empty either way.
- `git grep "path_of("` is swamped by unrelated local helpers in other crates' tests; only the
  qualified `handlers::path_of` shows the real callers.
- A reachability grep anchored on `path = "tests/` silently misses `screening_tests.rs`,
  `sse_tests.rs` and `warn_capture_tests.rs`, which are declared `#[path = "../tests/…"]`. The scanner
  used here resolves `#[path]` targets against the declaring file's directory.
