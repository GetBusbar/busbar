# S14-kernel-sub — busbar-kernel-egress / -identity / -audit / -wal

Slice: 71 tracked files. X-id block: X-2300 .. X-2399.

## How this slice was measured

Every crate in the slice was built and its whole suite run in an isolated target
directory, so nothing below is inferred from reading alone:

```
$ CARGO_TARGET_DIR=/Users/matthew/Developer/GetBusbar/.sweep/target-S14 \
  cargo test -p busbar-kernel-egress -p busbar-kernel-identity \
             -p busbar-kernel-audit -p busbar-kernel-wal --no-fail-fast
exit=0
busbar_kernel_audit      126 passed; 0 failed; 0 ignored
busbar_kernel_egress     212 passed  (+ breaker_adapter 9, prose 5, swrr_allocation 1)
busbar_kernel_identity    97 passed
busbar_kernel_wal         58 passed
Doc-tests busbar_kernel_audit 1 passed   (a compile-fail doctest)
```

**Reachability, all 64 `.rs` files.** A script resolved every file in the slice to the
`mod` declaration that brings it in (POSIX ERE `[[:space:]]`, never `\s` — `git grep -E '\s'`
is the false zero this repo has already been bitten by), plus `#[path = "..."]` forms, plus
cargo's automatic `crates/*/tests/*.rs` targets:

```
RESOLVED: 64 UNRESOLVED: 0
CONTROL  bogus 'mod zzz_not_a_module;'      -> 0 hits (expected)
CONTROL  'mod recipe;'                      -> crates/busbar-kernel-audit/src/lib.rs:84
```

Two near-misses that looked like orphans and are not — both resolved by `#[path]`, both
controlled:
`crates/busbar-kernel-egress/src/tests/arity_tests.rs` is not in `src/tests/mod.rs`; it is
declared at `src/arity.rs:94`. `crates/busbar-kernel-audit/src/tests/break_reporting_tests.rs`
is not in `src/tests/mod.rs`; it is declared at `src/tests/record_tests.rs:677`.

**All four Cargo.tomls are workspace members** (`Cargo.toml:22,26,28,29`).

**The NAT64 fix the brief asked about is PRESENT and defended.**
`git grep -n "64:ff9b" -- '*.rs'` returns 50 lines. The judgement lives at
`crates/busbar-kernel-egress/src/trust/net.rs:273-296` (`NAT64_WELL_KNOWN`/`NAT64_LOCAL_USE`,
covering RFC 6052 `64:ff9b::/96` *and* RFC 8215 `64:ff9b:1::/48` including the non-zero-padded
instantiation), and the instrument that would go red without it is
`crates/busbar-kernel-egress/src/trust/tests/net_tests.rs:220`
`nat64_embedded_ipv4_is_judged_by_the_shared_predicates` — which asserts the positive cases,
the negative case (`64:ff9b::1:0:a9fe:a9fe` must decode to `None`, i.e. a non-zero middle in
the *well-known* prefix is NOT an embedding), and the end-to-end refusal through
`resolve_and_pin(..., allow_private = true)` as `AddressRefusal::CloudMetadataAddress`.
It passes. Nothing was lost in a fold.

**Instrument blindness.** No `#[ignore]` anywhere in the slice (positive control: the pattern
exists at `crates/busbar-kernel/src/store/tests/tests.rs:2105`, so the zero is a measurement).
No `assert!(true)` / tautology. No `#[test]` body without an assertion (scripted scan over all
64 files). No test whose only assertion is `is_some()`/`is_ok()`. Every check in the slice has
a named input that makes it reject; those inputs are named per file below.

---

| FILE | VERDICT | EVIDENCE | ROWS |
| --- | --- | --- | --- |
| crates/busbar-kernel-egress/Cargo.toml | FINDING | `grep -n 'busbar-caps\|busbar-unit-' Cargo.toml` -> lines 1, 21, 44 name `busbar-unit-egress`, `busbar-caps`, `busbar-unit-breaker`. `ls -d crates/busbar-caps` -> "No such file or directory". `[dependencies]` is `busbar-contract` + `futures` only. Manifest prose describes a dependency graph that does not exist. | X-2305 |
| crates/busbar-kernel-egress/src/attempt.rs | FINDING | Read 773 lines. `SendOutcome::AttemptTimeout(u64)` (l.139) is consumed at l.312 into `attempt_timeout(&hop, _ms, now)` (l.482) whose parameter is `_ms` — the cap value is carried through an enum payload and dropped. `assemble` (l.375) hands `encode_envelope` a `fields` vec that includes `("signature", ..)` (l.394) but hands `lane_matches_seal` only `&request.fields`, which does not. Reject path proven present: `lane_matches_seal` returns `Err(Shed::internal())` on a duplicate lane field and on a value != the sealed lane. | X-2307 |
| crates/busbar-kernel-egress/src/race.rs | CLEAN | `git grep -n 'with_deadline\|deadline_first'` -> production callers at `attempt.rs:485,495,508,526,706` and `exhaustion.rs:433`. `block_on` is used only by `src/tests/mod.rs:113`, and its own doc (l.86) declares that: "This exists for the crate's own tests and for a caller that has no runtime of its own." Bias is exercised by `deadline_tests`. | - |
| crates/busbar-kernel-egress/src/tests/allocation_tests.rs | CLEAN | Read all 155 lines; 5 tests, all exact `assert_eq!` on measured values (pool-name count 2, credit count 68, an 18-step pinned rotation `[0,1,0,2,0,1,0,1,0,0,1,0,2,0,1,0,1,0]`, an arena-address identity). Red input: change the floor's key shape and `pool_names` becomes 68. All pass. | - |
| crates/busbar-kernel-egress/src/tests/arity_tests.rs | CLEAN | Read all 52 lines. Declared at `src/arity.rs:94-95` via `#[path]` (so NOT orphaned despite absence from `src/tests/mod.rs`). 4 tests, all with a reject arm: `on_primary_unavailable(Arity::ExactlyOne, 7, BreakerOpen)` must equal `Reroute::Refuse(PinnedRefusal{pinned:7,..})`. | - |
| crates/busbar-kernel-egress/src/tests/deadline_tests.rs | CLEAN | 8 tests, 7 carrying a refusal assertion. Rejecting inputs present by name: `a_spent_deadline_refuses_before_the_first_attempt`, `a_spent_deadline_refuses_before_a_streaming_attempt_too`, `an_upstream_that_says_nothing_is_cut_by_the_per_attempt_cap`, `the_stream_ceiling_bounds_the_whole_answer_not_each_frame`. All pass in the run above. | - |
| crates/busbar-kernel-egress/src/tests/exhaustion_tests.rs | CLEAN | 23 tests, 20 carrying a refusal assertion, incl. `a_pool_with_no_members_at_all_refuses`, `a_spill_at_an_unconfigured_pool_refuses_with_the_floor`, `a_spill_that_comes_back_round_terminates`, `the_last_resort_sheds_when_every_member_is_saturated`. Not blind. | - |
| crates/busbar-kernel-egress/src/tests/mod.rs | CLEAN | Read all 213 lines. Declares 6 test modules + `harness`; `arity_tests` is deliberately elsewhere (`src/arity.rs:94`). Mints the `Pass<Route>` through `KernelSeal::acquire_for_kernel()` (l.147) rather than forging one — the test-only seal, exactly as the dev-dependency comment in Cargo.toml says. | - |
| crates/busbar-kernel-egress/src/tests/pick_order_tests.rs | CLEAN | 13 tests, 6 carrying a refusal/exclusion assertion. Scripted scan: no assertion-free test, no `is_some()`-only test. All pass. | - |
| crates/busbar-kernel-egress/src/tests/probe_tests.rs | CLEAN | 10 tests, 10 carrying a negative assertion (the probe-ownership battery is entirely about what must NOT happen: `the_last_resort_owns_no_probe`, release-on-drop, owner-checked release). All pass. | - |
| crates/busbar-kernel-egress/src/tests/walk_tests.rs | CLEAN | 23 tests, 21 carrying a refusal assertion. All pass. | - |
| crates/busbar-kernel-egress/src/trust/arity.rs | FINDING | `git grep -rn 'arity::select\|trust::Arity\|ArityRefusal' -- crates xtask` excluding this file and its own test file returns exactly ONE line: `src/trust/mod.rs:75` (the `pub use`). Positive control on the same command: `git grep -c ArityRefusal <this file>` -> 14. The module doc (l.20) names its consumer — "the A2A catalogue's select" — and that consumer, `crates/busbar-a2a/src/a2a/receive.rs:302`, hand-rolls `match ids.len() { 1 => .., 0 => .., n => .. }` instead. | X-2300 |
| crates/busbar-kernel-egress/src/trust/counterparty.rs | FINDING | `git grep -n 'counterparty_admit\|CounterpartyFacts\|CounterpartyRefusal' -- crates xtask` outside this file returns only `src/trust/mod.rs:76` (the `pub use`) and `src/trust/tests/counterparty_tests.rs`. The gate this module claims to be — "the ordered gate a catalogue's `admit` runs" — is actually served by `busbar_kernel::trust::validate::validate_request`, called at `crates/busbar-a2a/src/a2a/registry.rs:344`. | X-2302 |
| crates/busbar-kernel-egress/src/trust/destination.rs | FINDING | `git grep -n lane_index -- crates xtask` -> 7 lines, none of them a construction of this `Candidate` (the other hits are a test fixture's own field and `units_mcp.rs`'s unrelated `fn lane_index`). `git grep -E 'trust::Candidate\|destination::Candidate'` -> rc=1, 0 hits, controlled by the same grep finding the 7 `lane_index` lines. The rest of the file is live and correct: all 8 `OriginKind` variants are constructed via the mapping at `crates/busbar/src/root/units_a2a.rs:1827-1834`, and `kind_rule_passes`'s Upstream arm calls all six conjuncts. | X-2301 |
| crates/busbar-kernel-egress/src/trust/guard.rs | CLEAN | Read all 164 lines. Each of the three guards has a constructed rejecting input in `trust/tests/guard_tests.rs`: `a_key_restricted_to_another_pool_is_refused` (403/Permission), `a_reachable_fallback_pool_the_key_may_not_use_is_refused`, `an_unpriced_arbitrary_name_is_a_bad_request` (400/InvalidRequest). `the_guards_run_in_order_pool_then_fallback_then_price` pins the ordering, `the_fallback_walk_terminates_on_a_cycle` pins the visited-set. `RefusalKind::reason()` maps to two distinct `ReasonCode`s, both asserted. | - |
| crates/busbar-kernel-egress/src/trust/mod.rs | FINDING | Read all 99 lines. Lines 75, 76 and 77-79 re-export three surfaces this sweep proved have no shipping constructor (`arity::{select,Arity,ArityRefusal,Selection}`, `counterparty::*`, `destination::Candidate`). The re-export is what keeps them looking live to a reader. | X-2300, X-2301, X-2302 |
| crates/busbar-kernel-egress/src/trust/swrr.rs | FINDING | `select_weighted` is live (`trust/order.rs:298,302`). But `git grep -n '\.reset(\|\.credit('` shows `SwrrState::reset` and `SwrrState::credit` reached only from `trust/tests/swrr_tests.rs:107,56,86,98,108`. `reset`'s doc (l.52) states its caller — "what a recovery does when a lane rejoins" — and no recovery calls it. The weight-zero rule the module header claims is enforced is genuinely enforced, at `trust/lane.rs:98` (`if candidate.weight == 0 { return false }`). | X-2310 |
| crates/busbar-kernel-egress/src/trust/tests/arity_tests.rs | FINDING | Read all 86 lines. 6 tests, all with reject arms (`Err(ArityRefusal::NoCandidate)`, `Err(ArityRefusal::Ambiguous{..})`). The suite is well built; its subject is not reachable from any shipping path (X-2300), so it proves a capability that does not ship. | X-2300 |
| crates/busbar-kernel-egress/src/trust/tests/counterparty_tests.rs | FINDING | Read all 71 lines. 4 tests, each pinning one of the four ordered refusals and its `ReasonCode`. Same shape as above: a complete instrument over a gate with no shipping caller (X-2302). | X-2302 |
| crates/busbar-kernel-egress/src/trust/tests/guard_tests.rs | CLEAN | 13 tests, 11 carrying a refusal assertion; names listed under `guard.rs` above. Covers the inert-with-no-key posture and the `None`-vs-empty-list distinction that `PoolView::key_scopes` exists for. All pass. | - |
| crates/busbar-kernel-egress/src/trust/tests/net_tests.rs | CLEAN | 50 tests, 40 carrying a refusal assertion — the largest instrument in the slice and the one the brief asked about. Read lines 200-290 in full: the NAT64 battery asserts metadata/internal classification for the RFC 6052 and both RFC 8215 forms, asserts `embedded_ipv4("64:ff9b::1:0:a9fe:a9fe") == None` (the must-NOT-unwrap case), and drives `resolve_and_pin` end to end under `allow_private=true` expecting `AddressRefusal::CloudMetadataAddress`. All 50 pass. | - |
| crates/busbar-kernel-egress/src/trust/tests/swrr_tests.rs | CLEAN | Read; 7 tests. Rejecting input present: `select_weighted(.., &all_drained, ..)` must be `None` (l.24) — the all-weight-zero case the module header says degenerates into "first candidate wins" without the filter. Credits-sum-to-zero is asserted at l.56. All pass. | - |
| crates/busbar-kernel-egress/src/trust/tests/unit_tests.rs | CLEAN | 13 tests, 9 carrying a refusal assertion. The sealed-answer battery: `the_pool_allow_list_refuses_at_the_verify_step`, `an_unpriced_name_refuses_for_having_no_rate`, `a_name_answering_with_the_metadata_address_is_not_sealed`, `a_loopback_answer_is_excluded_while_the_ordinary_upstream_still_seals`, `a_unit_price_over_the_cards_maximum_is_not_sealed`, and the one that pins the deliberate non-refusal `an_all_excluded_pool_still_proceeds_with_an_empty_set`. | - |
| crates/busbar-kernel-egress/src/trust/unit.rs | CLEAN | Read all 83 lines. `Trust::verify` is constructed in shipping code: `crates/busbar/src/root/kernel.rs:67` and `crates/busbar/src/root/units_mcp.rs:70` both import it. The verify can refuse (`destination_guard` -> `Decision::refuse`) and the refusing input is constructed by `trust/tests/unit_tests.rs`. The breaker is asked through the same `BreakerQuery` the pre-walk uses, and the test that would go red if the two diverged exists (`a_breaker_open_lane_is_excluded_at_the_seal_exactly_as_the_pre_walk_excludes_it`). | - |
| crates/busbar-kernel-egress/tests/breaker_adapter.rs | FINDING | Runs as a cargo auto test target (9 passed). The seam proof itself is sound. But l.19 asserts in prose that busbar-kernel-breaker's "`Cargo.toml` allows only `busbar-caps`", and `sed -n '/\[dependencies\]/,/^\[/p' crates/busbar-kernel-breaker/Cargo.toml` -> `busbar-contract = { path = "../busbar-contract" }`. l.188 repeats "Both crates name the same `busbar-caps` `Pass<Route>`". `busbar-caps` is not in the workspace. | X-2305 |
| crates/busbar-kernel-egress/tests/prose.rs | FINDING | Read all 172 lines. Two defects. (1) `the_unit_names_only_the_contract_and_the_capability_crate`'s allow-list (l.69-73) is `["busbar-caps","busbar-contract","busbar-contract-transport"]`; `ls -d crates/busbar-caps crates/busbar-contract-transport` -> "No such file or directory" for both, so the gate pre-authorises two crates that do not exist. (2) `every_seam_the_integrator_binds_says_so` (l.115-122) enumerates 6 traits, but `grep -n '^pub trait ' src/ports.rs` -> 7 (`Breaker, PermitHandle, Capacity, EgressAuth, Journal, Clock, Telemetry`). `PermitHandle` is unchecked. The gate is NOT blind (deleting a `// contract:` marker from a listed trait goes red) but it under-covers its own subject by one seam. | X-2306 |
| crates/busbar-kernel-egress/tests/swrr_allocation.rs | CLEAN | Read all 115 lines. Runs as a cargo auto test target (1 passed). It is the only place in the slice with a global counting allocator, correctly isolated in its own test binary because the crate `#![forbid(unsafe_code)]`. Red input: re-key `SwrrState` by `(String, usize)` and the warm-selection allocation count stops being 0. | - |
| crates/busbar-kernel-identity/Cargo.toml | FINDING | `grep -n 'busbar-caps\|busbar-unit-'` -> l.1 `busbar-unit-auth`, l.6 "the only edge out of this crate is `busbar-caps`", l.24 `busbar-unit-egress-auth`. Actual `[dependencies]`: `busbar-contract`, `sha2`, `hex`, `hmac`. The `[dev-dependencies]` section (l.38-42) has a comment describing a dependency and then declares NOTHING — an empty section under three lines of prose about what it contains. | X-2305 |
| crates/busbar-kernel-identity/src/challenge.rs | FINDING | `git grep -n ChallengeBounds -- crates` -> 3 files: this one, the `pub use` in `lib.rs:62`, and `src/tests/unit_tests.rs`. Nothing else in the workspace constructs a `Challenge`. `From<&Challenge> for busbar_contract::Challenge` (l.73) hard-codes `state: ChallengeState(Vec::new())` while the same impl's doc says what crosses is "the bytes, the state the next round's proof carries back, and how many rounds are left" — the local `Challenge` has no state field to carry. | X-2303 |
| crates/busbar-kernel-identity/src/egress_auth/sigv4/mod.rs | FINDING | `sign_v4`/`format_amz_time`/`sha256_hex`/`SIGV4_*` are live via `egress_auth/mod.rs:131-159`. `pub fn uri_encode_path` (l.64) is not: `git grep -n uri_encode_path -- crates` shows the only callers are its own `tests.rs` and, separately, `busbar_substrate_values::sigv4::uri_encode_path` at `busbar-llm/src/engine/egress.rs:215,216`. Three copies of the SigV4 canonicaliser exist (`busbar-kernel-identity`, `busbar-substrate-values`, `busbar-kernel/src/sigv4`); this crate's copy of the path encoder is the one nothing calls. | X-2304 |
| crates/busbar-kernel-identity/src/egress_auth/sigv4/tests.rs | CLEAN | Read all 179 lines. 8 tests. It looks like a "0 negative assertion" file to a scanner, and it is not blind: `sign_v4_matches_aws_published_example` pins the signature to AWS's own documented `5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7`, and `sign_v4_merges_a_duplicate_header_name_by_comma_joining_its_values` pins the duplicate-header rule by differential comparison. Any change to the framing, the key chain or the header canonicaliser goes red. | - |
| crates/busbar-kernel-identity/src/egress_auth/tests.rs | CLEAN | 13 tests, 9 carrying a refusal assertion, incl. the "un-encodable key yields the no-header decoration" path and the SET-not-append rule for `x-amz-date`/`x-amz-content-sha256` that a retried leg would otherwise double-sign. All pass. | - |
| crates/busbar-kernel-identity/src/lib.rs | FINDING | Read all 70 lines. `pub use challenge::{Challenge, ChallengeBounds}` (l.62) and `pub use exchange::{BrowserAction, AUTH_TOKEN_PATH}` (l.63) publish two surfaces this sweep proved have no caller outside the crate's own tests. The module list itself is complete and every declared module resolves. | X-2303, X-2312 |
| crates/busbar-kernel-identity/src/module.rs | CLEAN | Read all 40 lines. Three-arm `AuthOutcome`, all three constructed and discriminated in `chain.rs` and proven apart by `chain_tests::test_reject_stops_the_chain` / `test_nonempty_chain_fails_closed_on_all_pass`. The load-bearing `cacheable()` default of `false` is pinned by `chain_tests::test_cacheable_defaults_to_false`. | - |
| crates/busbar-kernel-identity/src/principal.rs | CLEAN | Read all 82 lines. `RESERVED_ID_PREFIXES` is enforced at `unit.rs:129` and the rejecting input is constructed by `unit_tests::a_module_may_not_synthesize_a_reserved_identity`; the deliberate exemption is pinned by `the_reserved_id_rule_binds_modules_and_not_the_engines_own_key_arm`. `ANONYMOUS` renders through `actor_id()` and is pinned by `anonymous_renders_as_the_literal_word`. | - |
| crates/busbar-kernel-identity/src/tests/cache_tests.rs | CLEAN | 12 tests, 10 carrying a negative assertion. The cache is auth-adjacent and the battery proves the refusals, not just the hits: `a_reject_is_never_cached`, `a_rejected_chain_admits_nothing_to_the_cache`, `an_unauthenticated_chain_admits_nothing_to_the_cache`, `pass_churn_cannot_evict_an_identity`, `a_flush_landing_mid_authentication_drops_the_insert`. All pass. | - |
| crates/busbar-kernel-identity/src/tests/carrier_tests.rs | CLEAN | 13 tests. Credential-extraction surface; the rejecting inputs are constructed: `test_extract_bearer_token_no_bearer`, `test_extract_bearer_token_malformed_no_panic`, `test_extract_client_token_empty_carrier_falls_through`, two `non_bearer_authorization_falls_through_to_*`, and `test_caller_token_debug_redacts_value` (a secret-in-a-log check with a real red arm). | - |
| crates/busbar-kernel-identity/src/tests/chain_tests.rs | CLEAN | 20 tests, 19 carrying a refusal assertion — the densest reject coverage in the slice. `test_keys_arm_with_no_verifier_denies`, `test_governance_rejects_empty_token_even_if_a_verifier_exists`, `test_audience_bound_token_is_rejected_on_the_data_plane`, `test_nonempty_chain_fails_closed_on_all_pass`, `an_open_door_is_not_revoked_by_a_colliding_string`. The verify can fail, and the inputs that make it fail are all present. | - |
| crates/busbar-kernel-identity/src/tests/exchange_tests.rs | FINDING | Read. 5 tests over `crate::exchange::{dispatch, is_bypassed, BrowserAction, AUTH_TOKEN_PATH}`. `git grep -n 'is_bypassed('` -> the ONLY callers are `src/exchange.rs:72` (the definition) and this file. The live auth-bypass rule is `busbar_kernel::auth::exchange::AUTH_TOKEN_PATH`, mounted at `crates/busbar-kernel/src/router.rs:389,395` and `plugin_routes.rs:74`. This suite hardens a second, unreachable copy of a security rule. | X-2312 |
| crates/busbar-kernel-identity/src/tests/unit_tests.rs | FINDING | Read. 13 tests, 13 carrying a refusal assertion — an excellent instrument. Three of them (`a_challenge_is_only_offered_inside_a_handshake_unit`, `an_exhausted_exchange_ends_the_unit`, `a_challenge_advances_within_its_bounds_and_then_stops`) are the only place in the workspace that ever passes `Some(challenge)` to `Auth::resolve`. | X-2303 |
| crates/busbar-kernel-identity/src/unit.rs | FINDING | Read all 146 lines. `Auth::resolve` IS live (4 shipping call sites). But `git grep -n 'auth.resolve\|\.auth\.resolve'` shows all four — `units_a2a.rs:1296`, `units_admin/mod.rs:2162`, `units_mcp.rs:366`, `units_voice.rs:1452` — pass `None` for `pending`. The arm at l.85-92, and with it `ReasonCode::ChallengeExhausted`, cannot fire in production. Five planes render that reason (`busbar-plane-llm/src/plane.rs:196` maps it to 401) for a refusal nothing can produce. | X-2303 |
| crates/busbar-kernel-audit/Cargo.toml | FINDING | `grep -n 'busbar-caps\|busbar-unit-'` -> l.1 `busbar-unit-audit`, l.10 `#   busbar-caps  the audit unit is a unit; sealing a record takes the token`. `ls -d crates/busbar-caps` -> no such directory. Actual deps: `busbar-contract`, `sha2`, `serde`, `ed25519-dalek`, `zeroize` — all five present and all five used. | X-2305 |
| crates/busbar-kernel-audit/src/heads.rs | FINDING | Read all 187 lines. Per-symbol grep: `anchors()`, `tip()`, `sample_seconds()`, `anchor_at()` are read by `expose.rs:347,247,343,281` — live. `HeadHistory::len()` has ZERO callers anywhere (`git grep 'heads().len()'` -> 0 hits; control: the same shape `heads().is_empty()` hits `sign_tests.rs:539`). `HEAD_SAMPLE_SECONDS` is referenced only by `lib.rs:92`'s `pub use` and its own `new()`. There is also no `heads_tests` module — `src/tests/mod.rs` declares 7 modules and none is for this file; its only coverage rides inside `sign_tests.rs`. | X-2308 |
| crates/busbar-kernel-audit/src/legacy/chain.rs | CLEAN | Read all 507 lines. `walk()` can produce all four `ChainBreakKind`s and each has a constructed input in the suite: `legacy_chain_tests` / `amend_tests::editing_an_amendment_is_caught` (DigestMismatch), `removing_an_amendment_from_the_middle_is_caught` (LinkMismatch), `truncating_the_tail_of_an_amendment_run_is_caught_against_the_chain_head` (SequenceBreak), and the foreign-scope arm. The empty-list `Ok` at l.451 is a stated limit, not a loophole, and `verify_window`'s looser anchor is a separate entry point (l.437) rather than a lenient default. The link is checked before the digest, deliberately. | - |
| crates/busbar-kernel-audit/src/legacy/mod.rs | CLEAN | Read all 23 lines. Every name in both `pub use` blocks resolves to `chain.rs`/`entry.rs`; `git grep` confirms the `AUDIT_SCHEME_*`, `OUTCOME_*` and `ADMIN_LOG` constants are consumed from `crates/busbar/src/root/units_admin/mod.rs:2679,2736,2737` and `units_mcp.rs:61`. | - |
| crates/busbar-kernel-audit/src/lib.rs | CLEAN | Read all 110 lines. All 7 modules declared; every `pub use` name resolves. The crate is reachable from a shipping binary: `crates/busbar/Cargo.toml` depends on it and `crates/busbar/src/root/{durability,units_a2a,units_admin/mod,units_mcp}.rs` construct `AuditChain`, `AuditInputs`, `Subject`, `OpClassId`, `AuditKeySet` and call `expose::{head_body,range_body,keys_body}`. | - |
| crates/busbar-kernel-audit/src/recipe.rs | CLEAN | Read all 269 lines, then checked the recipe against the record by script: every field of `What` (6), `OutcomeFacts` (6), `Amount` (8), `Controls` (9), `HookApplied` (2) and `AuditRecord` appears in `digest_fields`. The two omissions are correct and I verified why: `hash`/`signature` are derived from the digest, and `key_id` is `key_id_of(public_key)` (`sign.rs:171`) so a tampered `key_id` either misses the key-set lookup (`sign.rs:356`) or fails the signature over `signing_preimage(digest)`. Repeated groups are length-prefixed by count. The instrument is `published_recipe_tests::the_recomputation_rejects_the_published_example_with_one_cosmetic_field_altered`. | - |
| crates/busbar-kernel-audit/src/tests/amend_tests.rs | CLEAN | 20 tests, 11 carrying a refusal assertion, including four tamper cases (`editing_an_amendment_is_caught`, `removing_an_amendment_from_the_middle_is_caught`, `truncating_the_head_of_an_amendment_run_is_caught`, `truncating_the_tail_...`) and the money-adjacent `a_delta_too_large_for_the_range_saturates_instead_of_wrapping`. | - |
| crates/busbar-kernel-audit/src/tests/break_reporting_tests.rs | CLEAN | 12 tests, 7 carrying a refusal assertion. Declared via `#[path = "break_reporting_tests.rs"]` at `record_tests.rs:677` — it is compiled and it did run (present in the 126-test audit binary). | - |
| crates/busbar-kernel-audit/src/tests/digest_framing_tests.rs | CLEAN | 12 tests. This is the instrument for the pipe-join field-injection fix and it has the hardest possible red arm: `two_mutations_that_collide_under_the_pipe_join_have_distinct_length_framed_digests` and `the_collision_pair_does_not_survive_a_records_own_scheme_2_tag` construct an actual colliding pair. `a_scheme_one_record_digests_to_the_exact_bytes_it_always_did` pins the on-disk framing so the migration this crate may never make quietly cannot be made. | - |
| crates/busbar-kernel-audit/src/tests/legacy_chain_tests.rs | CLEAN | 17 tests, 8 carrying a refusal assertion. Covers all four `ChainBreakKind` arms plus the `from_persisted` / `from_persisted_unverified` split. | - |
| crates/busbar-kernel-audit/src/tests/legacy_ring_tests.rs | CLEAN | 20 tests, 10 carrying a refusal assertion. The thousand-entry ring, the restore-verifies-before-it-seeds rule and the genesis empty-string previous hash. | - |
| crates/busbar-kernel-audit/src/tests/mod.rs | CLEAN | Read all 12 lines. 7 `mod` declarations; `ls` of the directory shows 8 test files, and the 8th (`break_reporting_tests.rs`) is declared by `#[path]` from `record_tests.rs:677` — verified by `git grep -rn break_reporting`, which returns rc=0 with that hit (control: `git grep -rn amend_tests` returns the `mod.rs:6` line). No orphan. | - |
| crates/busbar-kernel-audit/src/tests/published_recipe_tests.rs | CLEAN | Read the test list. This is the strongest instrument in the slice: it parses the published `docs/audit-chain-digest-v1.md` table and recomputes the digest from the DOCUMENT rather than from the code (`the_check_never_reaches_the_code_it_is_checking`), reproduces the published example's signature from the published key set, and carries its own red proof (`the_recomputation_rejects_the_published_example_with_one_cosmetic_field_altered`). | - |
| crates/busbar-kernel-audit/src/tests/record_tests.rs | CLEAN | 15 tests, 10 carrying a refusal assertion, plus a compile-fail doctest at `record.rs:271` that ran and passed. Declares `break_reporting_tests` by `#[path]` at l.677. | - |
| crates/busbar-kernel-audit/src/tests/sign_tests.rs | CLEAN | 24 tests, 11 carrying a refusal assertion. Covers the head history (`anchors()`, `anchor_at(3)`, `HeadHistory::every(0)` over 50 seals, the append-only series) as well as the ed25519 path. This is also the only coverage `heads.rs` has (see X-2308). | - |
| crates/busbar-kernel-wal/Cargo.toml | FINDING | `grep -n 'busbar-caps\|busbar-unit-'` -> l.1 `busbar-unit-wal`, l.8 "`busbar-caps`, because the one thing the log hands back on a failure is a `DurabilityLost`". `ls -d crates/busbar-caps` -> no such directory; the actual dep is `busbar-contract`. Both real deps (`busbar-contract`, `sha2`) are used. | X-2305 |
| crates/busbar-kernel-wal/src/lib.rs | CLEAN | Read all 107 lines. All 7 modules declared; every `pub use` name resolves. `MAX_RECORD_BYTES` is defined here and is the only item this file owns. The crate is reachable: `crates/busbar/Cargo.toml`, `crates/plugin-loader/Cargo.toml`, `crates/plugin-sdk/Cargo.toml` depend on it, and `crates/busbar/src/root/durability.rs:764,766` constructs the journal both ways. | - |
| crates/busbar-kernel-wal/src/record.rs | CLEAN | Read all 258 lines. `frame_digest` covers `frame[0..64]` and `frame[96..512]`, skipping exactly the 32-byte digest field at 64..96 — verified by arithmetic against `DIGEST_OFFSET=64`, `FRAME_HEADER_BYTES=96`. All five `FrameError` arms are reachable and each has a constructed input in `record_layout.rs`: `a_frame_from_a_layout_this_build_does_not_know_stops_the_scan` (UnknownVersion), `a_frame_whose_payload_length_is_impossible_is_refused_before_it_is_used` (PayloadTooLong), `a_frame_claiming_a_part_outside_its_own_count_is_refused` (BadParts), `editing_any_byte_of_a_frame_is_caught` (DigestMismatch), `zeros_are_read_as_the_end_of_the_writes_and_not_as_damage` (NotAFrame). Every `FrameHeader` field is read by `recover.rs` (`more_parts` at :115, `part_count` at :83,96,104, `payload_len` via the payload slice). | - |
| crates/busbar-kernel-wal/src/ship.rs | FINDING | Read all 107 lines. `Shipper` and `NullShipper` are live (`main.rs:495`, `durability.rs:714`, `kernel.rs:805`, and the real one at `main.rs:931` via `StoreAdapter::shipper()` — I checked, so this is NOT a no-store-durability hole). `BufferShipper`, the only implementation in the tree that actually retains records, is constructed only by `src/tests/no_disk.rs:68` and `crates/busbar/src/root/tests/durability.rs:559`. In a `publish = false` crate a `pub` type with no in-tree production constructor is a capability that does not ship. | X-2309 |
| crates/busbar-kernel-wal/src/tests/bounds.rs | CLEAN | Read all 143 lines. 3 tests, no `Err` arms, and NOT blind: each asserts a hard bound that a regression breaks (`tracked_identities() <= 64` over 3200 records, `factory.segment_count() == 1` after >4 rolls, and a re-offer from behind a roll yielding `appended == 0`). Each also asserts its own precondition (`segments_used() > 1`) so the bound cannot pass vacuously. | - |
| crates/busbar-kernel-wal/src/tests/fixtures.rs | CLEAN | Read the declaration list and grepped each fixture: `durability_token` (8 files), `records` (8), `cwd_segment_names` (3), `TempDir` (4), `FaultyFactory` (4), `Fault` (4). Nothing here is unused. `FaultyFactory`/`FaultSwitch` are what make the poison rule testable — a factory that fails its sync on demand. | - |
| crates/busbar-kernel-wal/src/tests/idempotence.rs | CLEAN | 6 tests, 3 carrying a negative assertion. Rejecting inputs constructed: `a_reappended_identity_is_passed_over_however_much_its_body_disagrees`, `a_batch_that_repeats_an_identity_within_itself_writes_it_once_and_counts_the_rest`, `an_on_disk_reappend_that_the_log_already_holds_offers_the_store_nothing`. | - |
| crates/busbar-kernel-wal/src/tests/journal_chain.rs | CLEAN | 16 tests, 10 carrying a refusal assertion. Four tamper cases (`chain_verification_catches_a_removed_record`, `_a_mutated_body`, `_a_mutated_header`, `_a_gap_in_the_numbering`) plus the overflow-break battery. | - |
| crates/busbar-kernel-wal/src/tests/kill_at_every_offset.rs | CLEAN | Read the test list. 5 tests. `a_cut_at_every_byte_offset_recovers_the_longest_complete_prefix` is a total sweep over the crash points — exactly what the lib.rs claim ("there is no interesting subset of the offsets a crash can stop at, so none is chosen") promises. `a_single_flipped_byte_anywhere_stops_the_scan_at_that_record` is the red arm. | - |
| crates/busbar-kernel-wal/src/tests/mod.rs | CLEAN | Read all 14 lines. 9 `mod` declarations; `ls` of the directory shows exactly those 9 files plus `mod.rs`. No orphan, nothing undeclared. | - |
| crates/busbar-kernel-wal/src/tests/no_disk.rs | CLEAN | Read all 116 lines. 4 tests, no `Err` arms, and NOT blind: `a_memory_buffered_log_creates_no_file_anywhere` asserts a temp directory is still empty after 32 records across 8 batches AND that the cwd's `<index>.wal` name set is unchanged, and the module header explains why the cwd check is a name set rather than a count. `a_log_in_a_directory_does_write_files_there_and_nowhere_else` is the other half. | - |
| crates/busbar-kernel-wal/src/tests/poison.rs | CLEAN | 11 tests, 9 carrying a refusal assertion — the durability battery. `an_error_at_the_sync_point_poisons_the_segment`, `an_error_at_the_write_itself_poisons_the_segment_too`, `a_poisoned_segment_never_takes_another_write`, `a_store_that_refuses_a_memory_buffered_batch_is_a_durability_loss` (the mode difference, asserted), `a_store_that_refuses_an_on_disk_batch_does_not_fail_the_commit` (the other posture), `the_on_disk_catch_up_queue_is_bounded_and_says_what_it_gave_up_on`. | - |
| crates/busbar-kernel-wal/src/tests/record_layout.rs | CLEAN | Read the test list. 10 tests, 6 carrying a refusal assertion; the five `FrameError` arms are each constructed (named under `record.rs` above). `the_header_leaves_the_documented_amount_of_room_for_a_payload` and `every_frame_is_the_same_size_whatever_the_body_is` pin the on-medium layout. | - |
| crates/busbar-kernel-wal/src/tests/restart_after_a_roll.rs | CLEAN | 3 tests, no `Err` arms, and NOT blind: each asserts the resumed head is the END of the log rather than the middle — the exact defect `open_tail`'s "highest index, not index zero" rule exists for — and `a_restart_steps_back_over_a_segment_a_roll_opened_and_never_wrote_to` constructs the crash-in-the-roll-window case. `journal.log().segments_used() > 1` guards against a vacuous pass. | - |
| crates/busbar-kernel-wal/src/wal.rs | FINDING | Read all 580 lines. The append path, the poison rule, `open_tail` and the idempotence bound are all correct and all exercised. Three accessors are not wired to anything: `git grep -n '\.shipper()' -- crates/busbar-kernel-wal crates/busbar` returns ONE line, `main.rs:931`, which is `StoreAdapter::shipper()` and not this method — `Wal::shipper()` has zero callers including tests. `owed_to_store()` and `store_debt_dropped()` are read only by `tests/poison.rs:222,224,319,335,227`, though `store_debt_dropped`'s doc states its purpose as operator-facing ("so a node can say how far its store is behind"); no node reads it. | X-2311 |

---

## ROWS RAISED

### X-2300 · The arity-posture seat is never constructed, and the consumer it names hand-rolls it
CLASS:     missing-code
CERTAINTY: VERIFIED
EVIDENCE:
```
$ git grep -rn "arity::select\|trust::arity\|trust::Arity\|trust::Selection\|ArityRefusal" -- crates xtask \
    | grep -v "src/trust/arity.rs" | grep -v "src/trust/tests/arity_tests.rs"
crates/busbar-kernel-egress/src/trust/mod.rs:75:pub use arity::{select, Arity, ArityRefusal, Selection};
rc=0
# positive control, same pattern, on a file that has it:
$ git grep -c "ArityRefusal" -- crates/busbar-kernel-egress/src/trust/arity.rs
crates/busbar-kernel-egress/src/trust/arity.rs:14
```
`select`, `Arity`, `Selection` and `ArityRefusal` have exactly one reference outside their own
file and their own test file, and it is the `pub use`. The module doc names its intended
consumer at `arity.rs:20`: "This is the 'exactly-one-agent-or-refuse-503' decision the A2A
catalogue's select needs." That function exists — `crates/busbar-a2a/src/a2a/receive.rs:302` —
and re-implements the posture inline:
```
    match ids.len() {
        1 => Ok(ids.remove(0)),
        0 => Err(.. UnsupportedOperation ..),
        n => Err(.. InvalidParams, "{n} agents ... the ids are: {}" ..),
    }
```
including the "carry the ambiguous set so the caller can see which" behaviour that
`ArityRefusal::Ambiguous` was built for. Both halves exist; neither knows about the other.
ACTION:    Either make `a2a::receive::select` call `busbar_kernel_egress::trust::arity::select`
           with `Arity::ExactlyOne` and render `ArityRefusal` into the two A2A errors, or delete
           `src/trust/arity.rs`, its `pub use` at `trust/mod.rs:75`, its `mod arity;` at
           `trust/mod.rs:65`, and `src/trust/tests/arity_tests.rs`. Do not leave both.

### X-2301 · `trust::destination::Candidate` is constructed nowhere, not even in tests
CLASS:     missing-code
CERTAINTY: VERIFIED
EVIDENCE:
```
$ git grep -n "lane_index" -- crates xtask
crates/busbar-kernel-egress/src/trust/destination.rs:53:    pub lane_index: Option<usize>,
crates/busbar-kernel-egress/src/trust/tests/destination_tests.rs:62:    pub(crate) lane_index: usize,       <- a different struct, the test's own fixture
crates/busbar-kernel-egress/src/trust/tests/destination_tests.rs:83,163                 (same fixture)
crates/busbar-kernel/src/test_support/mod.rs:1265                                        (a doc comment)
crates/busbar/src/root/units_mcp.rs:455,577                                              (an unrelated `fn lane_index`)
$ git grep -E "trust::Candidate|destination::Candidate" -- crates
rc=1   # zero hits; the grep above proves the command is not silently dying
```
`pub struct Candidate { facts, lane_index }` and its `pub fn lane()` (destination.rs:49-62)
are re-exported at `trust/mod.rs:78` and constructed by nothing. The `lane_index: Option<usize>`
field is the tell: the shipping path carries the lane through
`DestinationFacts::lane() -> Option<LaneId>` (used at `trust/unit.rs:77`) and never needs a
table position at this seat.
ACTION:    Delete `Candidate` and its `impl` from `src/trust/destination.rs`, and drop
           `Candidate` from the `pub use destination::{...}` list at `trust/mod.rs:78`.

### X-2302 · The counterparty-admit gate is never constructed; the real gate is elsewhere
CLASS:     auth
CERTAINTY: VERIFIED
EVIDENCE:
```
$ git grep -n "counterparty_admit\|CounterpartyFacts\|CounterpartyRefusal" -- crates xtask
crates/busbar-kernel-egress/src/trust/mod.rs:76:pub use counterparty::{admit as counterparty_admit, CounterpartyFacts, CounterpartyRefusal};
crates/busbar-kernel-egress/src/trust/tests/counterparty_tests.rs:6,12,20,26,32,...
(and the definitions in src/trust/counterparty.rs)
```
The module header says this seat IS the A2A catalogue's `admit`. The A2A catalogue's `admit`
is at `crates/busbar-a2a/src/a2a/registry.rs:344` and delegates to
`busbar_kernel::trust::validate::validate_request(&Ask { principal, now, grants, approval,
sighting, capability, generation })`, mapping `Refusal::{NotGranted, EgressDenied,
IdentityNotLive, NotServing}` onto its own `Excluded` variants. So the four ordered checks are
implemented twice — once where they run and once here, where nothing calls them. The risk is
the same as any duplicated auth rule: a future hardening applied to this copy changes nothing.
ACTION:    Delete `src/trust/counterparty.rs`, its `mod`/`pub use` at `trust/mod.rs:66,76`, and
           `src/trust/tests/counterparty_tests.rs`; or, if the intent is for the egress unit to
           own the gate, make `registry.rs:344` call it and delete the duplicate in
           `busbar_kernel::trust::validate`. One of the two, not both.

### X-2303 · The bounded challenge never ships: `ChallengeExhausted` cannot be produced, and `ChallengeState` is always empty
CLASS:     auth
CERTAINTY: VERIFIED
EVIDENCE:
```
$ git grep -n "ChallengeBounds" -- crates
crates/busbar-kernel-identity/src/challenge.rs:19,39
crates/busbar-kernel-identity/src/lib.rs:62                (the pub use)
crates/busbar-kernel-identity/src/tests/unit_tests.rs:11,101,146,163
# -> `Challenge::open` is called by nothing outside the crate's own unit tests.

$ git grep -n "\.resolve(" -- crates | grep -iE "auth|identity" | grep -v tests
crates/busbar/src/root/units_a2a.rs:1296          -> pending = None
crates/busbar/src/root/units_admin/mod.rs:2162    -> pending = None  ("No challenge is ever pending on this plane")
crates/busbar/src/root/units_mcp.rs:366           -> pending = None  ("This plane opens no handshake unit")
crates/busbar/src/root/units_voice.rs:1452        -> pending = None
# all four shipping call sites pass None.

$ git grep -n "ChallengeExhausted" -- crates
crates/busbar-kernel-identity/src/unit.rs:88                     the only producer
crates/busbar-kernel-identity/src/tests/unit_tests.rs:155        the only test that reaches it
crates/busbar-plane-llm/src/plane.rs:196                         renders it as 401
crates/busbar-plane-{a2a,mcp,decision}/src/plane.rs              render it
```
Three separate halves are missing. (1) `Auth::resolve`'s challenge arm (`unit.rs:85-92`) is
guarded by `if let Some(challenge) = pending`, and no shipping caller ever supplies one — so
`ReasonCode::ChallengeExhausted` is a refusal four planes render and nothing can emit.
`units_voice.rs:1439` does compute `in_handshake: self.shape.is_handshake()`, which is the one
place the flag is real; it still cannot matter, because `pending` is `None` on the same call.
(2) `Challenge::open` / `ChallengeBounds` are constructed only by tests.
(3) `impl From<&Challenge> for busbar_contract::Challenge` (`challenge.rs:73`) hard-codes
`state: ChallengeState(Vec::new())` while its own doc says the state is "what the next round's
proof carries back". The local `Challenge` has no state field, so the multi-round channel the
contract declares is wired to a constant empty vector. `busbar-kernel/tests/common/mod.rs:357`
does the same; the only non-empty `ChallengeState` in the tree is a contract-crate test fixture.
ACTION:    Decide whether the handshake challenge is in 1.6.0. If it is: give
           `identity::Challenge` a `state` field, populate it in the `From` impl, and make the
           voice plane (the one plane with a real `in_handshake`) carry a `pending` challenge
           across rounds. If it is not: delete `src/challenge.rs`, the `pub use` at `lib.rs:62`,
           the `pending`/`in_handshake` parameters of `Auth::resolve`, the three challenge tests
           in `tests/unit_tests.rs`, and `ReasonCode::ChallengeExhausted` together with its four
           plane renderings. Shipping a 401 nothing can raise is the worst of the three options.

### X-2304 · A third copy of the SigV4 path canonicaliser, and this one has no caller
CLASS:     auth
CERTAINTY: VERIFIED
EVIDENCE:
```
$ git grep -n "uri_encode_path" -- crates
crates/busbar-kernel-identity/src/egress_auth/sigv4/mod.rs:64     the definition
crates/busbar-kernel-identity/src/egress_auth/sigv4/tests.rs:15-28  its only callers
crates/busbar-llm/src/engine/egress.rs:215,216   busbar_substrate_values::sigv4::uri_encode_path
crates/busbar-llm-codec/src/bedrock/tests/tests.rs:55             ditto
crates/busbar-kernel/src/auth/mod.rs:2032        crate::sigv4::uri_encode_path  (a third copy)
```
`egress_auth::decorate` (`egress_auth/mod.rs:141`) hands `sign_v4` a `body.canonical_uri` the
plane supplies pre-encoded, so this crate's own encoder is never reached. The signer's
correctness is not in question — `sign_v4_matches_aws_published_example` pins it to AWS's
published signature — but the tree now carries three implementations of the same SigV4
canonicalisation (`busbar-kernel-identity`, `busbar-substrate-values`, `busbar-kernel::sigv4`)
and only the ones outside this crate are on a request path. A future fix to the double-encode
rule applied here would silently not apply.
ACTION:    Delete `uri_encode_path` (and its two tests) from
           `src/egress_auth/sigv4/mod.rs`, or point `busbar-llm`'s `engine/egress.rs` at this
           copy and delete `busbar_substrate_values::sigv4::uri_encode_path`. Out of scope for
           this slice but worth an owner ruling: three copies of a signer is three places to fix
           a signing bug.

### X-2305 · All four manifests describe a dependency on a crate that does not exist
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:
```
$ ls -d crates/busbar-caps crates/busbar-contract-transport
ls: crates/busbar-caps: No such file or directory
ls: crates/busbar-contract-transport: No such file or directory
$ ls -d crates/busbar-contract          # control
crates/busbar-contract
$ grep -n "busbar-caps\|busbar-unit-" crates/busbar-kernel-{egress,identity,audit,wal}/Cargo.toml
busbar-kernel-egress/Cargo.toml:1   # busbar-unit-egress — the egress unit ...
busbar-kernel-egress/Cargo.toml:21  ... and `busbar-caps` for the capability tokens that seal the step.
busbar-kernel-egress/Cargo.toml:44  # Test-only. `busbar-unit-breaker` is never named by this crate's library code
busbar-kernel-identity/Cargo.toml:1 # busbar-unit-auth — the authenticate step, as a unit.
busbar-kernel-identity/Cargo.toml:6 # the only edge out of this crate is `busbar-caps`, which is where the token ...
busbar-kernel-audit/Cargo.toml:1    # busbar-unit-audit — the audit unit.
busbar-kernel-audit/Cargo.toml:10   #   busbar-caps  the audit unit is a unit; sealing a record takes the token ...
busbar-kernel-wal/Cargo.toml:1      # busbar-unit-wal — the write-ahead log unit.
busbar-kernel-wal/Cargo.toml:8      # DEPENDENCIES. `busbar-caps`, because the one thing the log hands back ...
```
The `[package] name` fields are all correct (`busbar-kernel-*`); only the prose drifted when
`busbar-caps` was folded into `busbar-contract` and the crates were renamed. Two live artefacts
repeat the stale name and are not comments:
`crates/busbar-kernel-egress/tests/prose.rs:70` (an allow-list entry — see X-2306) and
`crates/busbar-kernel-egress/tests/breaker_adapter.rs:19,188`, which asserts in prose that
busbar-kernel-breaker's manifest "allows only `busbar-caps`" when its one dependency is
`busbar-contract`. `crates/busbar-kernel-identity/Cargo.toml:38-42` additionally has a
`[dev-dependencies]` header with three lines of comment and no dependency under it.
ACTION:    Replace `busbar-caps` with `busbar-contract` and `busbar-unit-<x>` with
           `busbar-kernel-<x>` in the four manifest headers and in `breaker_adapter.rs:19,188`.
           Delete the empty `[dev-dependencies]` block in `busbar-kernel-identity/Cargo.toml`.

### X-2306 · The egress prose gate pre-authorises two non-existent crates and checks 6 of its 7 seams
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:
```
$ sed -n '69,73p' crates/busbar-kernel-egress/tests/prose.rs
    let allowed = [
        "busbar-caps",
        "busbar-contract",
        "busbar-contract-transport",
    ];
$ ls -d crates/busbar-caps crates/busbar-contract-transport   -> neither exists (see X-2305)

$ grep -n "^pub trait " crates/busbar-kernel-egress/src/ports.rs
159:pub trait Breaker: Send + Sync {
266:pub trait PermitHandle: std::fmt::Debug + Send + Sync {
275:pub trait Capacity: Send + Sync {
302:pub trait EgressAuth: Send + Sync {
361:pub trait Journal: Send + Sync {
394:pub trait Clock: Send + Sync {
412:pub trait Telemetry: Send + Sync {
$ sed -n '115,122p' crates/busbar-kernel-egress/tests/prose.rs
    for seam in [ "pub trait Breaker", "pub trait Capacity", "pub trait EgressAuth",
                  "pub trait Journal", "pub trait Clock", "pub trait Telemetry", ] {
```
Seven `pub trait`s, six checked. `PermitHandle` happens to carry its `// contract:` marker
(`ports.rs:264`) so the gate is not currently lying, but the list is hand-maintained: a new
seam added to `ports.rs` without a marker is not caught unless somebody also remembers to edit
this file. That is the "gate whose subject moved" shape — the file's own module doc says the
point is that "the list of work is readable off the source rather than out of a hand-off note",
and the list is in fact in a hand-maintained note. The gate is NOT blind: deleting
`// contract:` from any listed trait's doc block does go red.
ACTION:    Derive the seam list from `ports.rs` (scan for `^pub trait ` and require the marker
           on each) instead of hard-coding six names; and reduce the dependency allow-list to
           the crates that exist.

### X-2307 · The attempt carries a timeout value it discards, and cross-checks a field set smaller than the one it encodes
CLASS:     missing-code
CERTAINTY: ADJUDICATE
EVIDENCE:
```
$ sed -n '136,142p' crates/busbar-kernel-egress/src/attempt.rs
    /// The per-attempt cap fired before any answer arrived.
    AttemptTimeout(u64),
$ sed -n '312,316p'  crates/busbar-kernel-egress/src/attempt.rs
        SendOutcome::AttemptTimeout(ms) => { journal.abandon(); drop(permit);
            return attempt_timeout(&hop, ms, now); }
$ sed -n '482,483p'  crates/busbar-kernel-egress/src/attempt.rs
fn attempt_timeout(hop: &Hop<'_>, _ms: u64, now: u64) -> AttemptOutcome {
```
The cap that fired is threaded through an enum payload and a function parameter only to land in
`_ms`. Nothing records it — not the telemetry call on the next line, not the `Disposition`, not
the `err_type`. Either the value should reach `Telemetry::upstream_failure` / the shed's retry
hint, or the payload and the parameter should go.

Second half, same file:
```
$ sed -n '390,400p' crates/busbar-kernel-egress/src/attempt.rs
    let mut fields: Vec<(&str, &[u8])> = request.fields.iter().map(...).collect();
    if let Some(signature) = &request.body_signature { fields.push(("signature", signature.as_slice())); }
    let bytes = hop.transport.encode_envelope(&fields, request.body, ctx.arena())...;
    lane_cross_check(hop, &request)?;
```
`encode_envelope` is given N+1 entries; `lane_matches_seal` is given `&request.fields`, which is
N. The doc two paragraphs above says the check must "run the lane cross-check over the same
bytes it hands to `write`". Exploitability is narrow — it requires a transport whose configured
`lane_field` is spelled `signature` — which is why this is ADJUDICATE rather than VERIFIED. The
check itself is not blind: `lane_matches_seal` returns `Err(Shed::internal())` for a duplicate
carrying entry and for a value that is not the sealed lane, both constructed in the walk tests.
ACTION:    Pass the post-signature `fields` to `lane_matches_seal` so the checked set is the
           encoded set; and either emit `ms` from `attempt_timeout` or drop it from
           `SendOutcome::AttemptTimeout`.

### X-2308 · `HeadHistory::len()` has no caller, the sample constant has no reader, and the file has no test module
CLASS:     missing-code
CERTAINTY: VERIFIED
EVIDENCE:
```
$ git grep -n "heads()\.len()\|history.len()\|history.is_empty()" -- crates
crates/busbar-kernel-ledger/src/cost/tests/history_tests.rs:72,112      <- a different `history`
crates/busbar/src/root/{tests/kernel.rs:522, units_admin/tests/units_admin.rs:...}  <- ditto
# no hit is a HeadHistory. Control, same command shape:
$ git grep -n "heads()\.is_empty()" -- crates
crates/busbar-kernel-audit/src/tests/sign_tests.rs:539
$ git grep -n "HEAD_SAMPLE_SECONDS" -- crates
crates/busbar-kernel-audit/src/lib.rs:92:pub use heads::{HeadHistory, SignedHead, HEAD_SAMPLE_SECONDS};
$ grep -nE "^mod " crates/busbar-kernel-audit/src/tests/mod.rs
amend_tests digest_framing_tests legacy_chain_tests legacy_ring_tests published_recipe_tests record_tests sign_tests
```
`HeadHistory::len()` (heads.rs:178) is called by nothing, including tests — note it is
`#[must_use]` and allocates (`self.anchors().len()`), so it is not free. `HEAD_SAMPLE_SECONDS`
is published but read only by `HeadHistory::new()` inside the same file, so an operator cannot
discover the sampling rate from the constant. And the module that the file's own header calls
the guarantee against permanent anchor loss has no test module of its own; its coverage is
incidental to `sign_tests.rs`.
ACTION:    Delete `HeadHistory::len()` (`is_empty()` has a caller and stays), and add a
           `heads_tests` module to `src/tests/mod.rs` covering `anchors()`'s tip-dedup branch
           and `anchor_at()`'s boundary — the two pieces of logic `expose.rs` depends on.

### X-2309 · `BufferShipper` is the only retaining `Shipper` and only tests construct it
CLASS:     missing-code
CERTAINTY: VERIFIED
EVIDENCE:
```
$ git grep -n "BufferShipper" -- crates
crates/busbar-kernel-wal/src/lib.rs:97                       (pub use)
crates/busbar-kernel-wal/src/ship.rs:80,84,88,99             (definition)
crates/busbar-kernel-wal/src/tests/no_disk.rs:68             (a test)
crates/busbar/src/root/tests/durability.rs:559               (a test)
```
Checked the durability wiring before raising this, because the memory-buffered posture claims
"the store is where durability comes from": the production `Shipper` binding is real —
`crates/busbar/src/main.rs:931` passes `adapter.shipper()` from
`plugin_loader::store_adapter::StoreAdapter`, and `NullShipper` is used only where
`root/durability.rs:699-707` documents that there is no store to ship to. So this is NOT a
durability hole. What it is: a `pub` type in a `publish = false` crate whose doc describes a
deployment shape ("what a memory-buffered node's store looks like when the store is itself in
memory") that no composition root ever builds.
ACTION:    Either bind it — make the no-store fallback in `root/durability.rs:709` use a
           `BufferShipper` so a memory-buffered node's records are at least readable for the
           life of the process — or move it behind `#[cfg(test)]`/a `test-support` feature so
           the crate's public surface stops advertising a posture nothing composes.

### X-2310 · `SwrrState::reset` names a recovery caller that does not exist
CLASS:     missing-code
CERTAINTY: VERIFIED
EVIDENCE:
```
$ git grep -n "\.reset(\|\.credit(" -- crates | grep -i swrr
crates/busbar-kernel-egress/src/trust/tests/swrr_tests.rs:107:    swrr.reset("p", 0);
crates/busbar-kernel-egress/src/trust/tests/swrr_tests.rs:56,86,98,108  (credit)
crates/busbar-kernel/src/store/in_memory/mod.rs:431:  c.swrr().reset();   <- a different type's reset
$ sed -n '52,53p' crates/busbar-kernel-egress/src/trust/swrr.rs
    /// Clear one lane's credit — what a recovery does when a lane rejoins, so it starts level rather
    /// than owed.
```
The recovery the doc names is not in the tree: `trust/order.rs` calls `select_weighted` and
nothing else on `SwrrState`. A lane that was breaker-open for a cooldown therefore rejoins the
rotation carrying whatever credit it had, which is exactly the "starts owed" state the method
exists to prevent. `credit()` is honestly documented as "for tests and for the operator's own
report" and no operator report reads it either.
ACTION:    Call `SwrrState::reset(pool, lane)` from wherever a lane transitions out of
           breaker-open / back into admissibility, or delete `reset` and demote `credit` to
           `pub(crate)`. Note the parallel: `crates/busbar-kernel-egress/src/select.rs`'s
           `WeightedFloor` is the shipping rotation and may have the same gap — outside this
           slice, flagged not acted on.

### X-2311 · Three `Wal` accessors are wired to nothing, one of them to no caller at all
CLASS:     missing-code
CERTAINTY: VERIFIED
EVIDENCE:
```
$ git grep -n "\.shipper()" -- crates/busbar-kernel-wal crates/busbar
crates/busbar/src/main.rs:931:        adapter.shipper(),      <- StoreAdapter::shipper, not Wal::shipper
# control, the method exists:
$ git grep -cn "fn shipper" crates/busbar-kernel-wal/src/wal.rs
crates/busbar-kernel-wal/src/wal.rs:1
$ git grep -n "owed_to_store\|store_debt_dropped" -- crates | grep -v "src/wal.rs"
crates/busbar-kernel-wal/src/tests/poison.rs:222,224,227,319,335      (tests only)
```
`Wal::shipper()` ("The shipper, so a caller can look at what was handed over") has zero callers
anywhere. `owed_to_store()` and `store_debt_dropped()` are read only by the poison battery,
while `store_debt_dropped`'s own doc states an operator purpose — "so a node can say how far its
store is behind and how much of the catch-up it has given up on" — that no surface delivers.
Contrast `owed()`, `next_free_seq()`, `read_back()`, `recovered()` and `forget_owed()`, which
are all read by `journal.rs:724,866,1010,1016,977,966,782` and are correctly wired.
ACTION:    Delete `Wal::shipper()`. Either surface `owed_to_store().len()` and
           `store_debt_dropped()` on the node's status/metrics read, or drop the operator claim
           from their docs so the promise matches the wiring.

### X-2312 · The auth-token bypass rule exists twice; the identity unit's copy is unreachable
CLASS:     auth
CERTAINTY: VERIFIED
EVIDENCE:
```
$ git grep -n "is_bypassed(" -- crates
crates/busbar-kernel-identity/src/exchange.rs:72           the definition
crates/busbar-kernel-identity/src/tests/exchange_tests.rs:17,18,19,20,21   its only callers
$ git grep -n "AUTH_TOKEN_PATH" -- crates
crates/busbar-kernel-identity/src/exchange.rs / lib.rs:63 / tests/exchange_tests.rs
crates/busbar-kernel/src/auth/exchange.rs:33:pub(crate) const AUTH_TOKEN_PATH: &str = "/auth/token";
crates/busbar-kernel/src/plugin_routes.rs:74
crates/busbar-kernel/src/router.rs:389,395
```
`busbar_kernel_identity::exchange` publishes `dispatch`, `is_bypassed`, `BrowserAction` and
`AUTH_TOKEN_PATH`, and `lib.rs:63` re-exports two of them. Nothing outside the crate's own
tests calls any of it. The bypass that actually runs is `busbar_kernel::auth::exchange`'s,
mounted by `router.rs:389,395`. This is a middleware-bypass rule — the exact-match check that
stops `/auth/token/steal` and `/auth/tokens` from inheriting the exemption — and it is
implemented and tested in a place that does not decide anything. `exchange_tests.rs` asserts
all four near-miss paths are refused, against the copy that is never asked.
ACTION:    Make `busbar_kernel::auth::exchange` call
           `busbar_kernel_identity::exchange::is_bypassed` (the identity unit is the authenticate
           step and owns this question), or delete `src/exchange.rs`, the `pub use` at
           `lib.rs:63`, `mod exchange;` at `lib.rs:53`, and `src/tests/exchange_tests.rs`.
           Leaving two copies of a bypass rule is how a hardening gets applied to the wrong one.

---

## TALLY

```
files in slice:  71
verdict lines:   71
CLEAN:           48
FINDING:         23      rows raised: 13   (X-2300 .. X-2312)
DELETABLE:        0
UNREADABLE:       0
```

Rows by class: auth 4 (X-2302, X-2303, X-2304, X-2312) · missing-code 6 (X-2300, X-2301, X-2308,
X-2309, X-2310, X-2311) · instrument-blind 1 (X-2306) · drift 1 (X-2305) · and X-2307 spans
missing-code. By certainty: VERIFIED 12, ADJUDICATE 1 (X-2307), PARK 0.

## What this slice proves about files OUTSIDE it (stated, not acted on)

- `crates/busbar-a2a/src/a2a/receive.rs:302` — `select` re-implements the arity posture that
  `busbar_kernel_egress::trust::arity` exists to be (X-2300).
- `crates/busbar-a2a/src/a2a/registry.rs:344` — the live counterparty gate, which makes
  `trust/counterparty.rs` a duplicate (X-2302).
- `crates/busbar-kernel/src/auth/exchange.rs:33` + `router.rs:389,395` — the live auth-token
  bypass, which makes `identity::exchange` a duplicate (X-2312).
- `crates/busbar-kernel-egress/src/ports.rs` declares 7 `pub trait` seams; the prose gate names
  6. `PermitHandle` is unchecked (X-2306).
- `crates/busbar-kernel-identity/src/egress_auth/mod.rs:178` — `continue_handshake` is a `pub fn`
  whose own doc says "No shipped scheme reaches this path"; it returns a zero-budget handshake so
  it fails closed. Same shape as X-2303 and in the same crate, but the file is not in this slice.
- Three SigV4 implementations coexist: `busbar-kernel-identity/src/egress_auth/sigv4`,
  `busbar-substrate-values/src/sigv4.rs`, `busbar-kernel/src/sigv4`. Only the latter two are on a
  request path (X-2304).
- `crates/busbar-kernel-egress/src/select.rs`'s `WeightedFloor` is the shipping rotation and may
  have the same never-reset-on-rejoin gap as `SwrrState` (X-2310). Not verified; flagged.
- `crates/busbar-kernel-audit/src/legacy/entry.rs` holds `AUDIT_ACTIONS: [&str; 33]`. Not in this
  slice, and I did not measure how many of the 33 are emitted — but it is the natural home of the
  "24 dead scopes" the brief mentions, and it deserves a per-name emission check.
- `crates/busbar/src/root/durability.rs:699-712` and `crates/busbar/src/main.rs:913-941` — I
  traced these to clear X-2309 of being a durability hole. The store-backed path is real
  (`adapter.shipper()`); the `NullShipper` path is the documented no-store fallback.
