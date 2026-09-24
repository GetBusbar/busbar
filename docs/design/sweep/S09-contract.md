# S09-contract — the PLUGIN SEAM (`busbar-contract`, `busbar-plugin`)

Slice file count: **75**. Denominator: `.sweep/S09-contract.txt`. X-id block: X-1800 .. X-1899.

Binding reading before judging: spec Part 2 rows **#2** (a plugin is compiled-in OR dropped-in over
the SAME contract, and communicates ONLY over the ABI), **#3** (SEVEN kinds: store, secret, auth,
hook, export, PLANE, TRANSPORT) and **#30** (TWO LANES on ONE seam — HOT/POD `repr(C)` for
plane+transport, COLD/JSON for the other five; **each kind is bound to exactly one lane**; the older
"every plugin has both ABIs" is SUPERSEDED). A kind having ONE lane is therefore NOT a gap. A kind
with no both-ways proof (compiled-in and dropped-in compared) IS.

Builds were run in an isolated target dir per the contract:
`CARGO_TARGET_DIR=/Users/matthew/Developer/GetBusbar/.sweep/target-S09-contract`.

**Working-tree caveat, recorded once and not repeated per line.** Two artefacts in this tree at
sweep time are ANOTHER agent's red-before-green probes, not HEAD and not mine — I did not touch
them:
`git status --porcelain -- crates/busbar-contract/` →
`M crates/busbar-contract/src/caps/fixtures/lint_rules.rs` (appends
`pub fn p4() { let _ = Grant::<Sign>::mint(&seal); }`) and `?? crates/busbar-contract/src/zzz_f5.rs`.
`lint_rules.rs` is `include!`d by `caps/tests/mod.rs:15`, so **the `busbar-contract` LIB-TEST target
does not compile in this tree** (`error[E0433]: cannot find type 'Grant' ... lint_rules.rs:105`).
Every `src/**/tests/*.rs` verdict below is therefore judged by reading plus `git diff` against HEAD
(all of them pristine), not by a green run. `zzz_f5.rs` is undeclared in `lib.rs` and compiles into
nothing. All 24 `busbar-contract` INTEGRATION test targets and the whole `busbar-plugin` suite were
run and are reported from their real output.

| FILE | VERDICT | EVIDENCE | ROWS |
|------|---------|----------|------|
| crates/busbar-contract/Cargo.toml | CLEAN | `grep -n "busbar-contract" Cargo.toml` → workspace member (line 16). `[dependencies]` = serde, futures, smallvec, zeroize only; `git grep -n 'feature = "dispatch"' -- crates/busbar-contract/` returned 0 until re-run as `cfg(any(feature = ...))` (a false zero I controlled away) — the real form at `transport/transport.rs:204,282` is live, and the chain `busbar-kernel/plane-mcp -> dispatch -> busbar-substrate-values/dispatch -> busbar-contract/dispatch` is complete. The `test-seal = []` key here is legitimate (#65); the defect is the gate that never learned about it — see X-1800. | - |
| crates/busbar-contract/src/authz.rs | FINDING | `git grep -n "Grants(s.bit())" -- crates/` → `busbar-contract/src/authz.rs:109` AND `busbar-kernel-scope/src/lib.rs:145`. `grep -n "pub enum Scope\|pub struct Grants" crates/busbar-kernel-scope/src/lib.rs` → `66:pub enum Scope` `140:pub struct Grants(u8)` — a second, independent copy of the lattice this file's own doc says nobody may reinvent. `git grep -n "From<busbar_contract::authz::Scope>" -- crates/` → rc=1, no bridge. | X-1813 |
| crates/busbar-contract/src/caps/canary.rs | FINDING | `git grep -n "\.balanced()" -- crates/` → 12 hits, ALL in test files (`caps/tests/*`, `busbar-kernel/tests/loop_battery.rs`, `busbar-kernel/tests/table_and_pump.rs`). Positive control: the same grep finds `draft_accepted`/`hold_opened`/`accrual_taken` in PRODUCTION at `busbar-kernel/src/teller.rs`. The counters are incremented on every real unit and the two-sided check is never evaluated outside CI. | X-1808 |
| crates/busbar-contract/src/caps/capability.rs | CLEAN | Ten sealed markers. Checked each is actually minted: `for c in Admittance Dial Consumption WriteMoney DurableWrite Sign KeyHandle AdminVerb Recover Exit; do git grep -w "Grant<$c>\|<$c>" -- 'crates/*.rs' ...` → every one has ≥5 non-test files; positive control `git grep -c "Grant<Nonexistent>"` → rc=1. | - |
| crates/busbar-contract/src/caps/decision.rs | FINDING | Walked every `ReasonCode` variant: `git grep -c "ReasonCode::$r" -- 'crates/*.rs'` → **five return zero files workspace-wide**: `BodyTooLarge`, `TierMismatch`, `Replayed`, `DestinationBudgetExhausted`, `SecretPlaceholder`. Re-checked bare-word (`git grep -w`) to exclude a glob-import path (`git grep -n "use .*ReasonCode::\*"` → rc=1, none exist): the only bare hits are the `RefusalReason::X` RENDER arms in the five plane crates. Control: `ReasonCode::OverBudget` → 8 non-test files. The `From<ReasonCode> for RefusalReason` map itself is injective (`... \| sort \| uniq -d` → empty). | X-1805 |
| crates/busbar-contract/src/caps/egress.rs | FINDING | This file defines `VerifiedDestination`, `SecretSlot`, `SecretOnce`, `AuthDecoration`; `src/dest.rs` defines FOUR TYPES WITH THE SAME NAMES. `grep -n "pub use" crates/busbar-contract/src/caps/mod.rs` → `85:pub use egress::{AuthDecoration, SecretOnce, SecretSlot, TransportKeyHandle, VerifiedDestination}`; `sed -n '68,72p' src/lib.rs` → `pub use dest::{AuthDecoration, ..., SecretOnce, SecretSlot, TransportKeyHandle, ..., VerifiedDestination, ...}`. `git grep -n "From<VerifiedDestination>\|caps::VerifiedDestination> for"` → rc=1: no bridge. `git grep -n "SecretOnce::mint\|\.matches(" -- crates/ \| grep -i secretonce` → `matches()` has zero production callers. | X-1801 X-1802 X-1803 X-1804 |
| crates/busbar-contract/src/caps/step.rs | CLEAN | Ten sealed step markers; `StepName::ALL` has 10 entries and `Step::NAME`'s match is compiler-forced. `git grep -w under_hold` → production caller `busbar-kernel/src/teller.rs`. `Verify::Facts = Vec<VerifiedDestination>` resolves to the `caps` copy (`use crate::caps::{..., VerifiedDestination}` line 15) — evidence for X-1801, not a defect of this file. | - |
| crates/busbar-contract/src/caps/tests/the_posting_arithmetic.rs | CLEAN | `git diff --stat` → pristine vs HEAD. 13 `#[test]`, 87 assert-family calls, 0 `#[ignore]`, no early `return`. Target blocked only by the foreign working-tree artefact in the header caveat. | - |
| crates/busbar-contract/src/caps/tests/what_the_record_reads.rs | CLEAN | pristine vs HEAD; 12 tests / 65 asserts. Contains the only `Canary::balanced()` and `SecretOnce::matches()` exercises in the crate — the evidence behind X-1808 and X-1804, not a defect here. | - |
| crates/busbar-contract/src/caps/tests/what_the_usage_report_says.rs | CLEAN | pristine vs HEAD; 7 tests / 45 asserts. Exercises `Usage::report`/`estimate`/`total` including the `MAX_USAGE_LINES` refusal, so the bound can go red. | - |
| crates/busbar-contract/src/caps/usage.rs | CLEAN | Money-adjacent and correct: `quantity: u64`, `total()` uses `saturating_add` and its doc explicitly denies being money; no `f64` (`grep -c f64` → 0). `is_kernel_derived` has no external caller but is reached via `is_reported` in the same file (`busbar-kernel-ledger/src/usage/meter.rs` calls `is_reported`/`is_floor`). `MAX_USAGE_LINES` is the crate's single ceiling, re-exported not re-spelled. | - |
| crates/busbar-contract/src/civil.rs | CLEAN | Hinnant `civil_from_days` verbatim; `div_euclid`/`rem_euclid` so the signed split has no special case. `git grep -l -w rfc3339_from_secs` → `busbar-a2a/src/a2a/pushdeliver.rs` (production); `civil_from_days` → 5 non-test crates. `mod tests` declared at line 48. | - |
| crates/busbar-contract/src/config.rs | CLEAN | `ModelCfg` is `deny_unknown_fields`; `neg1()` is reached as the serde default and named by `busbar-kernel/src/config/{mod,providers}.rs` + `config_validate`. `UpstreamCreds` carries `Serialize` for the per-entry document round-trip the overlay needs. No `f64`. | - |
| crates/busbar-contract/src/dest.rs | FINDING | The load-bearing half of the duplicate pair. `grep -n "use crate::dest::" crates/busbar-contract/src/transport/mod.rs` → `25:use crate::dest::{TransportKeyHandle, VerifiedDestination}` — so `Transport::dial(&self, dest: &VerifiedDestination, ...)` takes THIS type, while `busbar-kernel-egress/src/trust/unit.rs:6` does `use busbar_contract::caps::VerifiedDestination` and seals THAT one. Non-test consumers are disjoint sets (see X-1801). Constructors take `&dyn KernelSeal`, which `caps/token.rs:204,286` implements for ALL `Pass<S>` and ALL `Grant<C>` — see X-1803. | X-1801 X-1802 X-1803 X-1804 |
| crates/busbar-contract/src/duration.rs | CLEAN | `n.checked_mul(mult).filter(\|v\| *v <= 10*365*86_400)` — bounded, no overflow. Hand-walked the edges: empty input, leading non-digit, `"7 d"` and `"12x3d"` all return `Err`. `git grep -l -w parse_duration_secs` → 14 files incl. `busbar-kernel/src/appbuild.rs`, `busbar-mcp/src/mcp/config.rs`. | - |
| crates/busbar-contract/src/grammar.rs | CLEAN | The overlap decider is total and conservative-yes, and it CAN say no: `path_overlaps` returns `x == y` for two `ExactPath`, `header_overlaps` returns `false` for two different header names. `one_level_under("/api","/apikeys")` → false (boundary required, hand-verified). `cargo test -p busbar-contract --test grammar_overlaps` → `17 passed; 0 failed` (35.80s). `grep -c 'f64\|unwrap()\|panic!'` → 0/0/0. | - |
| crates/busbar-contract/src/signal.rs | FINDING | `git grep -n "requested.wants(" -- crates/ \| grep -v tests` → exactly TWO compute sites, both in `busbar-llm/src/engine/hooks.rs:683,697` (`CandidateBreakerState`, `CandidateErrorRate`). The other eight of `Signal::ALL` have no compute fn, and `git grep -n "unwired\|not wired" -- crates/busbar-kernel/src crates/busbar-llm/src \| grep -i signal` → empty: nothing diagnoses a hook that declares one. Separately, the module doc at line 31 names `crate::hooks`, which is not a module of this crate (`grep -oE 'crate::[a-z_]+' \| grep -vE "^crate::(<the 26 real mods>)$"`). | X-1814 X-1817 |
| crates/busbar-contract/src/surface.rs | CLEAN | One const. `git grep -n ADMIN_PREFIX -- crates/` → read by `busbar-core-admin/src/admin_codec/claims.rs:11` with a `const _: () = assert!(matches!(ADMIN_PREFIX.as_bytes(), b"/api/v1/admin"))` guarding the hand transcription the doc admits to. | - |
| crates/busbar-contract/src/tests/count_tests.rs | CLEAN | pristine vs HEAD; 29 tests / 158 asserts; 0 `#[ignore]`; declared at `count.rs:764`. | - |
| crates/busbar-contract/src/tests/records_tests.rs | CLEAN | pristine vs HEAD; 28 tests / 154 asserts; declared at `records.rs:1513`. The three `skip`-shaped hits are prose, not control flow (`grep -n 'return;$'` → none). | - |
| crates/busbar-contract/src/tests/redacted_no_serde.rs | CLEAN | A genuine compile-time fence with its own positive control: the autoref-specialization probe is run over `String` (which IS `Serialize`/`Deserialize`) as well as over `Redacted`, so the `false` it asserts is measured rather than vacuous. Declared at `redacted.rs:148` under `#[cfg(test)]`. | - |
| crates/busbar-contract/src/tests/redacted_tests.rs | CLEAN | pristine; 6 tests / 18 asserts; declared at `redacted.rs:142`. Covers `constant_time_eq` and the zeroize-on-drop path. | - |
| crates/busbar-contract/src/tests/signal_tests.rs | CLEAN | pristine; 7 tests / 24 asserts; declared at `signal.rs:253`. Walks `Signal::ALL` for name/bit uniqueness and pins `name()` against the serde derive, so a variant added without an `ALL` entry goes red. | - |
| crates/busbar-contract/src/transport/dest.rs | CLEAN | `UpstreamAddress` is two shapes plus a claim-driven `extras` map; `missing()` is the refusing half and `Debug`/`Serialize` are hand-written so the `Program` arm's environment prints names-and-lengths, never values. `grep -c 'f64\|unwrap()\|panic!'` → 0/0/0. Reachability probe showed no item with zero non-test users. | - |
| crates/busbar-contract/src/transport/driver.rs | CLEAN | `UnitDriver` is object-safe and IMPLEMENTED in production: `git grep -n "impl.*UnitDriver for"` → `busbar/src/root/transports.rs:498` (the composition root) plus the crate's own `Detached`. `busbar-transport-http/src/mount.rs:247` holds `&dyn UnitDriver`. `Outcome` is a closed eight-word list every wire can spell. | - |
| crates/busbar-contract/src/transport/registry.rs | FINDING | `git grep -n -w check_composition -- 'crates/*.rs'` → the ONLY callers are `crates/busbar-contract/tests/transport_registry.rs`; no composition root, no boot path. Same for `Registered` (never constructed outside that test), `facts::undeclared` (only `tests/boot_cells.rs` + `tests/reserved_keys_and_closed_codes.rs`), `facts::is_reserved` and `status_ns::is_reserved`. Positive control in the same command: `TRANSPORT_ABI` IS named in production by `busbar-transport-{grpc,http,sse,stdio,...}/src/meta.rs`. | X-1806 |
| crates/busbar-contract/src/transport/surface.rs | FINDING | `git grep -n -w check_surface -- 'crates/*.rs'` → `transport/mod.rs` (re-export), `busbar-contract/tests/wire_surface.rs`, `busbar-plane-a2a/src/tests/surface.rs` — all tests. `grep -n check_surface crates/busbar-transport-http/src/mount.rs crates/busbar-transport-grpc/src/mount.rs crates/busbar/src/root/transports.rs` → rc=1. Control: `grep -c WireSurface crates/busbar-transport-http/src/mount.rs` → 6, so the mount builders DO hold the surface; they just never check it. `template_is_wellformed` has zero non-test readers. | X-1807 |
| crates/busbar-contract/src/transport/tests/redaction_tests.rs | CLEAN | pristine; 2 tests / 4 asserts; declared at `transport/trust.rs:126` as `mod redaction_tests`. Asserts the trust-seam carriers print nothing. | - |
| crates/busbar-contract/src/transport/tests/transport_tests.rs | CLEAN | pristine; declared at `transport/transport.rs:298`. Body is `#[cfg(any(feature = "dispatch", feature = "runtime"))]` — matching the axis it tests, and the feature chain that arms it is live (`busbar-kernel/plane-mcp`), so this is a gated test with a real enabler, not a dead one. | - |
| crates/busbar-contract/src/transport/transport.rs | FINDING | Three doc references to `crate::egress::duplex_ws` (lines 191, 214, 288) and one to `crate::ingress::duplex_ws` (line 189). Neither module exists in this crate: `grep -oE '^pub mod [a-z_]+' src/lib.rs` lists 26 modules and neither `egress` nor `ingress` is among them — they are `busbar-substrate` modules that came along with the #38 fold. Backticked-not-bracketed, so the `doc-links` gate cannot see them. Logic itself is sound (`Transport::ALL` covers all six; `upstream_wire` returns `None` for the three A2A bindings by design). | X-1815 |
| crates/busbar-contract/src/transport/wire.rs | FINDING | `Encode` has four variants; checked each: `git grep -l "Encode::Unrepresentable"` → 12 files incl. 5 plane crates and 2 transports; `Encode::ScratchExhausted` → 15; `Encode::Poisoned` → 2; **`Encode::SecretPlaceholder` → 1, and it is `crates/busbar-contract/tests/reserved_keys_and_closed_codes.rs`.** The encode-side half of the secret-placeholder enforcement is never raised, matching the `ReasonCode` and `SecretOnce::matches` halves. `Decode`'s four variants are all constructed in production. | X-1804 |
| crates/busbar-contract/src/upstream.rs | CLEAN | Nine status classes × four dispositions, generated from one macro table so a row adds itself to `ALL`, `token`, `parse` and `disposition` at once. `parse` returns `None` off-vocabulary (it can say no). `cargo test -p busbar-contract --test upstream_table` → `6 passed; 0 failed`. No `f64` on the `Billing` path — the class is a label, not an amount. | - |
| crates/busbar-contract/src/verb_store.rs | CLEAN | The seam is answered on both ends: `git grep -l -w chain_break/store_restore/reseal_epoch_floor/replay_new_verb/commit_new_verb_replay` → `plugin-loader/src/store_adapter.rs` (the adapter), `busbar-core-admin/src/verbs.rs` (the caller) and `busbar/src/root/kernel.rs` (`impl busbar_contract::verb_store::Store for RefusingStore`, the fail-closed default). `IDEMPOTENCY_TTL_SECS` is re-exported by `busbar-core-admin/src/idempotency.rs:27` rather than re-spelled. | - |
| crates/busbar-contract/tests/ack_wire.rs | CLEAN | `cargo test -p busbar-contract --test ack_wire` → `2 passed; 0 failed`. Pins `Ack`'s snake_case tokens in BOTH directions, so a `rename_all` regression or a dropped `Deserialize` goes red. | - |
| crates/busbar-contract/tests/adversarial.rs | CLEAN | `--test adversarial` → `7 passed; 0 failed`. Deterministic hostile-input table over the JSON scanner; every row asserts both "no panic" and "Found never names bytes outside the input". | - |
| crates/busbar-contract/tests/boot_cells.rs | CLEAN | `--test boot_cells` → `5 passed; 0 failed`. Each of the fourteen claim rungs asserts an accept AND a reject, so a predicate that accepted everything fails. | - |
| crates/busbar-contract/tests/bounded_allocations.rs | CLEAN | `--test bounded_allocations` → `1 passed; 0 failed`. Own binary with a counting `#[global_allocator]` and a single test, because the counter is global — the stated reason is the correct one. | - |
| crates/busbar-contract/tests/capability_binding_zero_cost.rs | CLEAN | `--test capability_binding_zero_cost` → `1 passed; 0 failed`. The `== 0` assertion is proven RED-able by the `BUSBAR_ALLOC_INJECT` knob that allocates inside the armed region on purpose — a positive control built into the instrument. | - |
| crates/busbar-contract/tests/destination_kinds.rs | CLEAN | `--test destination_kinds` → `2 passed; 0 failed`. Uses `dest::VerifiedDestination::seal(&seal(), facts, "http", Some(17))` — i.e. the LOOSE constructor; that is evidence for X-1801/X-1803, not a defect of the test. | - |
| crates/busbar-contract/tests/feature_invariance.rs | FINDING | **MEASURED RED AT HEAD.** `CARGO_TARGET_DIR=.../target-S09-contract cargo test -p busbar-contract --test feature_invariance` → `4 passed; 2 failed`. (1) `the_crate_declares_no_features` panics: *"the contract declares feature \"test-seal\" beyond the neutral transport-axis gates"*. (2) `no_item_is_conditionally_compiled` panics naming `src/caps/token.rs:274`, `src/caps/token.rs:277`, `src/plugin.rs:245`. `git diff --stat -- crates/busbar-contract/tests/feature_invariance.rs crates/busbar-contract/Cargo.toml crates/busbar-contract/src/caps/token.rs crates/busbar-contract/src/plugin.rs` → empty, so all four inputs are pristine and the red is HEAD's, not this tree's. Also carries `const BELOW_THE_CONTRACT: [&str; 1] = ["busbar-grammar"]`, a crate that no longer exists. | X-1800 X-1816 |
| crates/busbar-contract/tests/finish_class.rs | CLEAN | `--test finish_class` → `2 passed; 0 failed`. One mapping in one place, replacing five plane transcriptions. | - |
| crates/busbar-contract/tests/grammar_overlaps.rs | CLEAN | `--test grammar_overlaps` → `17 passed; 0 failed` in 35.80s (the cross-product walk is genuinely exhaustive, which is why it is slow). Asserts reflexivity and symmetry across every form pair. | - |
| crates/busbar-contract/tests/handles_and_handoff.rs | CLEAN | `--test handles_and_handoff` → `5 passed; 0 failed`. Reads back the three handle facts (bound address, peer, handing-up layer) that were previously reachable and never asserted. | - |
| crates/busbar-contract/tests/json_scanner.rs | CLEAN | `--test json_scanner` → `16 passed; 0 failed`. | - |
| crates/busbar-contract/tests/mutation_hardening.rs | FINDING | `--test mutation_hardening` → `8 passed; 0 failed`, so the instrument works. But its header (line 3) reads *"Mutation-hardening tests for `busbar-grammar`"* — `ls -d crates/busbar-grammar` → *No such file or directory* (control: `ls -d crates/busbar-contract` succeeds). The grammar folded into this crate as `json_grammar` under #40; the file's own subject has been renamed out from under its header. | X-1816 |
| crates/busbar-contract/tests/open_shapes.rs | CLEAN | `--test open_shapes` → `5 passed; 0 failed`. Plants a `quic` family this tree does not have and asserts every reader answers it without an edit — an open-shape proof that can fail. | - |
| crates/busbar-contract/tests/reserved_keys_and_closed_codes.rs | CLEAN | `--test reserved_keys_and_closed_codes` → `12 passed; 0 failed`. This is the only file in the workspace that names `Encode::SecretPlaceholder`; that is the finding's evidence (X-1804), and pinning a closed code is exactly this test's job. | - |
| crates/busbar-contract/tests/root_paths.rs | CLEAN | `--test root_paths` → `2 passed; 0 failed`. Asserts the seven names a plugin author needs are reachable from the crate root, so a re-export dropped in a refactor goes red. | - |
| crates/busbar-contract/tests/secret_carriers_print_nothing.rs | CLEAN | `--test secret_carriers_print_nothing` → `6 passed; 0 failed`. Covers `SecretOnce`, `Redacted`, `TransportKeyHandle` and `UpstreamAddress::Program`'s environment. | - |
| crates/busbar-contract/tests/test_seal_is_dev_only.rs | CLEAN | `--test test_seal_is_dev_only` → `1 passed; 0 failed`. Two built-in positive controls, both load-bearing: `found.len() > 10` (a broken manifest walk fails instead of passing vacuously) and `dev_edges > 0` (if nothing enables the feature on a dev edge the test says it proved nothing). Section tracking correctly treats `[target.'cfg(..)'.dev-dependencies]` as dev. | - |
| crates/busbar-contract/tests/transport_registry.rs | CLEAN | `--test transport_registry` → `8 passed; 0 failed`; exercises all three `CompositionError` arms. The test is sound; what is missing is any production caller of the function it tests — that row sits on `transport/registry.rs` (X-1806), not here. | - |
| crates/busbar-contract/tests/unit_driver.rs | CLEAN | `--test unit_driver` → `7 passed; 0 failed`. Pins object-safety (`let driver: &dyn UnitDriver = &Detached;`), which is the property the transports depend on. | - |
| crates/busbar-contract/tests/upstream_address_prints_no_secret.rs | CLEAN | `--test upstream_address_prints_no_secret` → `3 passed; 0 failed`. Asserts the `Program` environment renders names and lengths, never values, in both `Debug` and serde. | - |
| crates/busbar-contract/tests/upstream_address.rs | CLEAN | `--test upstream_address` → `4 passed; 0 failed`. Covers `extra`/`missing`, including the refusal path a transport needs to fail closed on an undeclared key. | - |
| crates/busbar-contract/tests/upstream_table.rs | CLEAN | `--test upstream_table` → `6 passed; 0 failed`. Pins the 9×4 cardinality the outside renderers match exhaustively. | - |
| crates/busbar-contract/tests/vocabulary_cap.rs | CLEAN | `--test vocabulary_cap` → `1 passed; 0 failed`. Own binary because the vocabulary is one per process; proves the ceiling holds in an image with no composition root to freeze it. | - |
| crates/busbar-contract/tests/vocabulary_freeze.rs | CLEAN | `--test vocabulary_freeze` → `1 passed; 0 failed`. Asserts a novel key after freeze is REFUSED, not idempotently accepted — the distinction the interner's leak hazard turns on. | - |
| crates/busbar-contract/tests/wire_surface.rs | CLEAN | `--test wire_surface` → `19 passed; 0 failed`. The most thorough test in the crate and the only caller of `check_surface`; the missing production call is X-1807 on `transport/surface.rs`. | - |
| crates/busbar-plugin/Cargo.toml | CLEAN | `grep -n busbar-plugin Cargo.toml` → workspace member (line 37). Deps are exactly `busbar-api` + serde + serde_json, matching the header's claim that the crate's external surface is the COLD lane's. The `(was 'busbar-plugin-abi')` / `(was 'busbar-plane-abi')` notes are past-tense provenance, not live paths — correct. `cargo test -q -p busbar-plugin` builds and runs. | - |
| crates/busbar-plugin/src/cold/endpoint.rs | FINDING | `git grep -n "safe_relay_status\|safe_status" -- crates/` → 11 hits, ALL inside `busbar-plugin` (definition, one `cold/auth.rs` delegate, and `cold/tests/endpoint_tests.rs`). The real host relay is `crates/busbar-kernel/src/plugin_routes.rs:563`: `let status = StatusCode::from_u16(resp.status).unwrap_or(StatusCode::BAD_GATEWAY);` — it never calls the conversion this file's doc calls *"THE conversion a host relay must use"*. Behavioural gap: `from_u16` accepts `100..=999`, `safe_relay_status` accepts `100..=599`, so a plugin-chosen `600..=999` is relayed verbatim instead of becoming `502`. | X-1812 |
| crates/busbar-plugin/src/cold/export.rs | CLEAN | Every declared item is consumed in shipping code: `EXPORT_ABI_VERSION` → `plugin-loader/src/registry.rs` + `plugin-sdk`; `ExportStream::{default_fields,pinned_fields}` → `busbar-kernel/src/export/projection.rs:469,481,510,545,597`; `ExportField::bit` → `projection.rs:167,190` as `1u64 << f.bit()` with `ALL.len() == 40 < 64` (pinned by the module's own test). `ExportRequest`/`ExportResponse` are exercised over the real dlopen seam by `export-example-plugin`. | - |
| crates/busbar-plugin/src/cold/hook.rs | CLEAN | Every request variant has a dispatch arm in `plugin-sdk/src/lib.rs:816,817`; `HookReply::Failed` is both emitted and consumed (`plugin-loader/src/hook.rs:192,216`) and is the arm that closes the fail-open the doc describes. The externally-tagged encoding asymmetry with `HookRequest` is deliberate and pinned by `hook_reply_json_encoding_is_pinned`. | - |
| crates/busbar-plugin/src/cold/observe.rs | CLEAN | `Observations::into_envelope` → `plugin-sdk`; `Envelope::is_bare` → `plugin-loader/src/observe.rs`; `PluginMetric`/`PluginDiagnostic`/`DiagLevel` → `busbar-kernel/src/observe.rs` + `export-example-plugin`. The `f64` fields are telemetry, not ledger: they are the hook kind's frozen metric shape, host-validated for finiteness, and no arithmetic here reaches a posting (`git grep` finds no ledger crate reading `PluginMetric`). | - |
| crates/busbar-plugin/src/cold/tests/auth_tests.rs | FINDING | Read in full: 10 tests / 61 asserts, all JSON round-trip and shape pins on `AuthRequest`/`AuthResponse`/`Identity` — in-crate only. There is no compiled-in-vs-dropped-in comparison for `kind: auth` anywhere: `ls crates/ \| grep auth` finds `auth-static-plugin`, whose `open` is private and which has no path dependency from `plugin-loader/Cargo.toml`, and `grep -n "macro_rules! export_" crates/plugin-sdk/src/lib.rs` shows `export_auth_plugin!` emits no `dispatch_compiled_in` twin (only `export_export_plugin!` does). Spec #2 names this absence explicitly; this file is where the missing witness would be mirrored from. Header also names `crates/plugin-abi/src/auth.rs`, which does not exist. | X-1811 X-1818 |
| crates/busbar-plugin/src/cold/tests/endpoint_tests.rs | CLEAN | 5 tests / 19 asserts; declared at `endpoint.rs:151`. Green in `cargo test -q -p busbar-plugin` (88 passed). Contains the only exercises of `safe_relay_status` — the evidence for X-1812, not a fault here. | - |
| crates/busbar-plugin/src/cold/tests/export_tests.rs | FINDING | 11 tests / 48 asserts; green. Asserts `f.bit() < 64` and `pinned_fields ⊆ default_fields`, both real. Header names `crates/plugin-abi/src/export.rs`, a path that does not exist (`ls -d crates/plugin-abi` → No such file or directory). | X-1818 |
| crates/busbar-plugin/src/cold/tests/hook_tests.rs | FINDING | 5 tests / 23 asserts; green; pins the three literal `HookReply` JSON forms a non-Rust author must match. Header names `crates/plugin-abi/src/hook.rs`. | X-1818 |
| crates/busbar-plugin/src/cold/tests/lib_tests.rs | FINDING | 6 tests / 23 asserts; green; declared at `cold/mod.rs:699`. Header names `crates/plugin-abi/src/lib.rs`. | X-1818 |
| crates/busbar-plugin/src/cold/tests/observe_tests.rs | CLEAN | 13 tests / 50 asserts; declared at `observe.rs:419`; green. Covers the drop-one-malformed-entry rule that the raw-`Value` wire exists to make possible. | - |
| crates/busbar-plugin/src/hot/mod.rs | FINDING | Per #3 the seventh kind is TRANSPORT and per #30 it is bound to the HOT/POD lane. This module declares exactly one cdylib entrypoint — `symbol::PLANE_DECL = b"busbar_plane_decl\0"` — and no transport twin: `git grep -n "TRANSPORT_DECL\|busbar_transport" -- crates/` → rc=1 (control: `PLANE_DECL` → 68 files). The cold kind table has six constants and no `TRANSPORT`/`TRANSPORT_NUL` (`git grep -n 'TRANSPORT: &str' -- crates/` finds only `busbar-core-admin/src/admin_codec/claims.rs`, an unrelated `"http"`). `git grep -c "repr(C)" -- crates/busbar-contract/src/transport/` → rc=1, zero: the transport contract is an async Rust trait (`Fut<'a,T> = Pin<Box<dyn Future…>>`) that cannot cross a C ABI at all. Also cites `scripts/plane-abi-neutrality.sh`, which does not exist. | X-1810 X-1819 |
| crates/busbar-plugin/src/hot/tests/decl_tests.rs | CLEAN | 4 tests / 15 asserts; declared at `decl.rs:301`; green. Exercises `IngressCarrier::bit` and the `provided_carriers` mask including a zero-check. | - |
| crates/busbar-plugin/src/hot/tests/host_tests.rs | CLEAN | 15 tests / 49 asserts; declared at `host.rs:1364`; green (14 run, 1 ignored). The one `#[ignore]` is the wall-clock/alloc bench and it IS run: `grep -n -- "--ignored" qa/segments.toml` → line 256 runs exactly that test name with `--test-threads=1`. Its `plane-abi-spike` references are `git show 527bdbf96^:…` citations of a deleted commit, which is provenance, not drift. | - |
| crates/busbar-plugin/src/hot/tests/workitem_tests.rs | CLEAN | 4 tests / 10 asserts; declared at `workitem.rs:181`; green. | - |
| crates/busbar-plugin/src/lib.rs | FINDING | The shared root is sound: `check_preamble` is fail-closed on magic and MAJOR and accepts a differing MINOR; `read_sized_field!` clamps the peer's self-attested size through `honoured_size` before `field_present`, uses `addr_of!` + `read_unaligned` and never forms a reference over a short buffer. `CountingAlloc` is correctly `#[cfg(test)]`-only. The defect is a citation: lines 43 and 291 name `scripts/plane-abi-neutrality.sh` as the CI witness; `ls scripts/plane-abi-neutrality.sh` → No such file (control: `ls scripts/` lists 20+ other scripts). The witness is real but lives at `cargo xtask gate plane-abi-neutrality` (`.github/workflows/ci.yml:690-692`). | X-1819 |
| crates/busbar-plugin/tests/layout_golden.rs | FINDING | The gate itself is well built — a missing/empty golden is an explicit FAILURE, not a self-seed, and `BUSBAR_UPDATE_GOLDEN` returns before asserting. But it is incomplete. Diffed the recorded set against the real one: `cut -d. -f1 tests/golden/abi-layout.golden \| sort -u` yields 44 names; `git grep -A3 "#\[repr(C" -- crates/busbar-plugin/src/hot/{decl,host,pod,workitem}.rs \| grep -oE "pub struct [A-Za-z]+" \| sort -u` yields 46. The two missing are **`HostCtx`** and **`CostSettleOut`**. `grep -c "HostCtx\|CostSettleOut" tests/golden/abi-layout.golden` → 0 (control: `grep -c "^Usage\." ` → 17). | X-1809 |

## ROWS RAISED

### X-1800 · the contract's feature-invariance gate is RED at HEAD: #65 added `test-seal` and never told the gate
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:  `CARGO_TARGET_DIR=/Users/matthew/Developer/GetBusbar/.sweep/target-S09-contract cargo test -p busbar-contract --test feature_invariance`
```
running 6 tests
test the_crate_declares_no_features ... FAILED
test no_item_is_conditionally_compiled ... FAILED
test result: FAILED. 4 passed; 2 failed; 0 ignored

---- the_crate_declares_no_features stdout ----
panicked at crates/busbar-contract/tests/feature_invariance.rs:49:13:
the contract declares feature "test-seal" beyond the neutral transport-axis gates, so its
plugin-visible surface is not one surface

---- no_item_is_conditionally_compiled stdout ----
panicked at crates/busbar-contract/tests/feature_invariance.rs:93:5:
conditionally compiled items on the contract surface:
["…/src/caps/token.rs:274", "…/src/caps/token.rs:277", "…/src/plugin.rs:245"]
```
All four inputs are pristine vs HEAD — `git diff --stat -- crates/busbar-contract/tests/feature_invariance.rs crates/busbar-contract/Cargo.toml crates/busbar-contract/src/caps/token.rs crates/busbar-contract/src/plugin.rs` prints nothing — so this is HEAD's red, not this working tree's. The gate's allow-list is `const NEUTRAL_TRANSPORT_FEATURES: [&str; 2] = ["dispatch", "runtime"]`; #65 added a third feature and three `#[cfg(feature = "test-seal")]` sites and updated neither the constant nor the two exemption checks. The rule is still the right rule — `test-seal` genuinely is a feature, and `tests/test_seal_is_dev_only.rs` is the gate that actually polices it — so the fix is to name the exemption, not to delete the check.
ACTION:    In `crates/busbar-contract/tests/feature_invariance.rs`: add a second constant, e.g. `const TEST_ONLY_FEATURES: [&str; 1] = ["test-seal"];`, accept it in `the_crate_declares_no_features`'s key check (still asserting the value is `[]`), and skip lines containing `feature = "test-seal"` in `no_item_is_conditionally_compiled`, with a comment pointing at `tests/test_seal_is_dev_only.rs` as the gate that carries the real obligation. Do NOT widen `NEUTRAL_TRANSPORT_FEATURES` — that would say `test-seal` is a neutral transport gate, which it is not.

### X-1801 · ONE seam, TWO `VerifiedDestination` types, and nothing converts between them
CLASS:     abi
CERTAINTY: VERIFIED
EVIDENCE:  `busbar-contract` defines the name twice and exports both:
```
$ grep -n "pub use egress" crates/busbar-contract/src/caps/mod.rs
85:pub use egress::{AuthDecoration, SecretOnce, SecretSlot, TransportKeyHandle, VerifiedDestination};
$ sed -n '68,72p' crates/busbar-contract/src/lib.rs
pub use dest::{ … SecretOnce, SecretSlot, TransportKeyHandle, UpstreamAddress, VerifiedDestination, VetoCode };
```
`caps::egress::VerifiedDestination` is `struct { lane: LaneId }`, sealed by `seal(&Grant<Dial>, LaneId)`.
`dest::VerifiedDestination` is `struct { facts, transport, budget_remaining }`, sealed by `seal(&dyn KernelSeal, DestinationFacts, &'static str, Option<i64>)`.
The two halves of the dial seam use DIFFERENT ones:
```
$ grep -n "use crate::dest::" crates/busbar-contract/src/transport/mod.rs
25:use crate::dest::{TransportKeyHandle, VerifiedDestination};      # so Transport::dial takes dest::
$ grep -n "use busbar_contract::caps::VerifiedDestination" crates/busbar-kernel-egress/src/trust/unit.rs
6:use busbar_contract::caps::VerifiedDestination;                    # the TRUST UNIT seals caps::
```
Non-test consumer sets are disjoint — `caps::` → `busbar-kernel-egress/src/trust/unit.rs`, `busbar-kernel-identity/src/egress_auth/mod.rs`, `busbar/src/root/{kernel,units_a2a,units_admin,units_llm,units_voice}.rs`; `dest::` → `busbar-kernel-egress/src/{attempt,trust/net}.rs`, `busbar-transport-{http,sse,tcp,tls}/src/transport.rs`. And there is no bridge: `git grep -n "From<VerifiedDestination>\|caps::VerifiedDestination> for\|dest::VerifiedDestination> for" -- crates/` → rc=1.
`caps::step::Verify::Facts = Vec<VerifiedDestination>` resolves to the `caps` copy, so the verify step's declared output type is not the type `Transport::dial` accepts. "Only a verified destination can be dialled" is written twice and joined nowhere.
ACTION:    Owner ruling on which shape is canonical, then delete the other and re-point its users. The `dest` shape carries the facts the transports actually need; the `caps` shape carries the `Grant<Dial>` ceiling the trust unit actually enforces. Recommended: keep ONE struct in `dest.rs` with the `dest` fields, change its `seal` to take `&Grant<Dial>` (closing X-1803 in the same edit), make `caps::egress` a `pub use crate::dest::VerifiedDestination;` re-export exactly as it already does for `TransportKeyHandle` at `caps/egress.rs:133`, and delete `caps/egress.rs`'s own `struct VerifiedDestination` + `impl`.

### X-1802 · `SecretOnce`, `SecretSlot` and `AuthDecoration` are duplicated across the same two modules
CLASS:     auth
CERTAINTY: VERIFIED
EVIDENCE:  Same two export lists as X-1801. Concretely for the secret-carrying one:
```
caps/egress.rs:  pub fn mint(_token: &Grant<AdminVerb>, nonce: u128, unit: UnitKey, target: impl Into<String>) -> Self
dest.rs:         pub fn mint(_seal: &dyn KernelSeal, nonce: u128, target: &'static str) -> Self
```
`git grep -n "SecretOnce::mint" -- crates/` shows production uses only the four-argument `caps` form (`busbar-core-admin/src/verbs.rs:285`), while `crates/busbar-contract/tests/secret_carriers_print_nothing.rs:115` exercises the three-argument `dest` form. `caps/egress.rs:133` already re-exports `TransportKeyHandle` from the root instead of redefining it, which proves the intended pattern and that these three were simply not folded the same way. `AuthDecoration` differs additionally by lifetime (`dest.rs` has `AuthDecoration<'u>`, `caps/egress.rs` has none), so the two cannot even be unified by a type alias without picking one.
ACTION:    Fold with X-1801 in one edit: keep one definition per name (in `dest.rs`), give each the `Grant<C>` constructor the capability discipline intends (`Grant<AdminVerb>` for `SecretOnce`, `Grant<Sign>` for `SecretSlot`/`AuthDecoration`), and reduce `caps/egress.rs` to `pub use` re-exports plus its module doc.

### X-1803 · `&dyn KernelSeal` carries no per-capability ceiling: any `Pass` or `Grant` opens every sealed constructor
CLASS:     auth
CERTAINTY: VERIFIED
EVIDENCE:  The trait is blanket-implemented over both proof families:
```
$ sed -n '202,208p;284,290p' crates/busbar-contract/src/caps/token.rs
impl<S: Step> crate::plugin::sealed::KernelSealed for Pass<S> {}
impl<S: Step> crate::plugin::KernelSeal for Pass<S> { fn seal_origin(&self) -> &'static str { "Pass" } }
impl<C: Capability> crate::plugin::sealed::KernelSealed for Grant<C> {}
impl<C: Capability> crate::plugin::KernelSeal for Grant<C> { fn seal_origin(&self) -> &'static str { "Grant" } }
```
So every `&dyn KernelSeal` parameter accepts ANY of the ten grants and ANY of the ten passes. The three constructors that take one are `dest::VerifiedDestination::seal` ("Trust-unit-only; the seal is what says so" — it does not say so), `dest::SecretOnce::mint` ("Verbs unit only") and `dest::TransportKeyHandle::issue`. The last is claimed the other way round in two places:
```
$ sed -n '131p' crates/busbar-contract/src/caps/egress.rs
/// its Grant<KeyHandle> by the loop. `TransportKeyHandle::issue` takes that grant, so this is
$ sed -n '237p' crates/busbar-unit-transport-key/src/lib.rs
/// `TransportKeyHandle::issue` demands a [`Grant<KeyHandle>`], which only the kernel lends to this
```
`issue`'s real signature is `pub fn issue(_token: &dyn KernelSeal, slot: u64, fingerprint: &'static str)`. In practice the auth unit (which legitimately holds `Pass<Authenticate>`) can seal its own destination and skip every check the trust unit's per-kind rule performs. This is a ceiling that the type system is asked to enforce, believed to enforce, and does not.
CAVEAT: `KernelSeal` remains genuinely sealed against out-of-crate forgery — `caps/token.rs`'s `compile_fail` fixtures and `tests/test_seal_is_dev_only.rs` both hold. The gap is WITHIN the holder set, not outside it.
ACTION:    Change the three `dest.rs` constructors from `&dyn KernelSeal` to the specific grant each one's doc already names: `seal(&Grant<Dial>, …)`, `SecretOnce::mint(&Grant<AdminVerb>, …)`, `TransportKeyHandle::issue(&Grant<KeyHandle>, …)`. `busbar-contract` cannot name `Grant` from `dest.rs` today only because of module ordering, not a dependency — `caps` is in this same crate — so the edit is local. Test fixtures that pass a bare seal move onto `Grant::<C>::mint(&seal)`, which every `caps/tests` file already does.

### X-1804 · the minted-secret-placeholder enforcement is fully declared and never executed
CLASS:     auth
CERTAINTY: VERIFIED
EVIDENCE:  The mint ships; the check does not.
```
$ git grep -n "SecretOnce::mint" -- crates/ | grep -v tests
crates/busbar-core-admin/src/verbs.rs:285:            secret: SecretOnce::mint(admin, nonce, unit, target),
$ git grep -n "\.matches(" -- crates/ | grep -iE "once|secret"      # every caller of SecretOnce::matches
crates/busbar-contract/src/caps/tests/mod.rs:657,658
crates/busbar-contract/src/caps/tests/what_the_record_reads.rs:297,298
crates/busbar-core-admin/src/tests/verbs_tests.rs:504,508,512,561
$ git grep -n "once.target()\|once.unit()\|secret.target()\|secret.unit()" -- crates/
crates/busbar-contract/src/caps/tests/what_the_record_reads.rs:295,296,308     # tests only
$ git grep -c "ReasonCode::SecretPlaceholder" -- 'crates/*.rs'                 # rc=1, zero files
$ git grep -l "Encode::SecretPlaceholder" -- 'crates/*.rs'
crates/busbar-contract/tests/reserved_keys_and_closed_codes.rs                 # the pin, not an emitter
```
Positive controls from the same commands: `Encode::ScratchExhausted` is named by 15 files including five plane crates and five transports; `ReasonCode::OverBudget` by 8 non-test files.
So the documented invariant — *"If the encoded bytes do not contain it exactly once at that location, the unit fails and the mint is reversed"* (`caps/egress.rs:137-140`) — has no code path. Nothing compares the nonce against the encoded bytes, nothing reads the declared target, and the two error codes reserved for the failure (`ReasonCode::SecretPlaceholder`, `Encode::SecretPlaceholder`) can never be raised. Every plane carries a `RefusalReason::SecretPlaceholder` render arm for a refusal that cannot occur.
CONSEQUENCE, stated plainly: a credential-minting admin verb's freshly minted secret is returned with no structural guarantee that it appeared exactly once at one declared place — the guarantee that was supposed to stop it leaking into a log, a fact, or a second copy of the response.
ACTION:    Two halves, in order. (1) In the encode step, after the response bytes are rendered and before they leave, scan for the minted nonce: count occurrences, compare position against `SecretOnce::target()`, and on anything other than exactly-one-at-target return `Err(Encode::SecretPlaceholder)` so the unit refuses with `ReasonCode::SecretPlaceholder` and the mint is reversed. (2) Add the red arm to `crates/busbar-core-admin/src/tests/verbs_tests.rs`: mint a placeholder, render a response containing it twice (and one containing it at the wrong pointer), and assert both refuse. Until (2) exists, (1) is another declaration.

### X-1805 · five `ReasonCode` variants are never constructed anywhere in the workspace
CLASS:     missing-code
CERTAINTY: VERIFIED
EVIDENCE:  Walked all 42 variants of the closed vocabulary:
```
$ for r in $(sed -n '114,207p' crates/busbar-contract/src/caps/decision.rs \
      | grep -oE '^    [A-Z][A-Za-z]+ =>' | sed 's/ =>//' | tr -d ' '); do
    printf '%-30s %s\n' "$r" "$(git grep -c "ReasonCode::$r" -- 'crates/*.rs' | wc -l)"; done
BodyTooLarge                   0
TierMismatch                   0
Replayed                       0
DestinationBudgetExhausted     0
SecretPlaceholder              0
…
OverBudget                     8        # control
NoDestination                 10        # control
```
Re-checked without the `ReasonCode::` prefix (`git grep -w`) to exclude a glob import — `git grep -n "use .*ReasonCode::\*" -- crates/` → rc=1, there are none — and the only bare hits for the five are `RefusalReason::X` arms inside the five plane crates' render matches, plus `busbar-contract/src/unit.rs`'s declarations. None of them is a construction.
So five refusals are declared, mapped, rendered by every plane, and unreachable. `Refusal::new(ReasonCode::BodyTooLarge)` — the arrival gate's size refusal — is one of them, which is worth a second look: the kernel either refuses an oversized body under a different code or does not refuse it at that step at all.
ACTION:    Per variant, decide and act: (a) wire the refusal at the step that owns it — `BodyTooLarge` at arrival, `TierMismatch` in `busbar-kernel-budget/src/chain.rs` (which already has its OWN `ChainError::TierMismatch` and does not translate it), `Replayed` in the idempotency probe (`busbar-core-admin/src/verbs.rs` already has `MintOutcome::Replayed` and does not translate it), `DestinationBudgetExhausted` in the egress walk, `SecretPlaceholder` per X-1804; or (b) remove the variant, which is a compile-forced edit at every plane renderer — exactly the property the enum's doc says it is for. Do not leave them as five render arms nothing can reach.

### X-1806 · the transport composition and reserved-fact boot checks have no production caller
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:
```
$ git grep -n -w check_composition -- 'crates/*.rs'
crates/busbar-contract/src/lib.rs:101:            (re-export)
crates/busbar-contract/src/transport/mod.rs:62:  (re-export)
crates/busbar-contract/tests/transport_registry.rs:45,55,74,86,94   (the only calls)
$ git grep -n -w Registered -- 'crates/*.rs' | grep -v busbar-contract/src
crates/busbar-contract/tests/transport_registry.rs:13,21            (never constructed elsewhere)
$ git grep -n "facts::undeclared\|facts::is_reserved\|status_ns::is_reserved" -- 'crates/*.rs'
crates/busbar-contract/tests/boot_cells.rs, tests/reserved_keys_and_closed_codes.rs, tests/open_shapes.rs
$ git grep -n TRANSPORT_ABI -- 'crates/*.rs' | grep meta.rs        # POSITIVE CONTROL
crates/busbar-transport-{grpc,http,sse,stdio,...}/src/meta.rs      # this one IS named in production
```
The doc on `check_composition` says *"Run once, at boot, after configuration is read"* and on `facts::undeclared` *"Run at registration"*. Neither runs. `crates/busbar/src/root/transports.rs` is the composition root that registers transports and it calls neither. So `COMPOSES_OVER` is still what the module header calls it — "a declaration nothing checks" — and a transport composed over a layer it never declared, or declaring a layer nobody registered, boots silently. The instrument exists, is correct, and is not connected.
ACTION:    In `crates/busbar/src/root/transports.rs`, build a `Vec<Registered>` as each transport is wired (`key` from `TransportMeta::KEY`, `composes_over` from `TransportMeta::COMPOSES_OVER`, `composed_over` from the instance's `composed_over()`), call `check_composition` once after the registry is complete, and fail the boot on `Err`. In the same place, call `facts::undeclared(TRANSPORT_FACTS, published)` per transport at registration and refuse a reserved key published but not declared. Prove both red first by registering a transport with a bogus `composes_over`.

### X-1807 · `check_surface` never runs when a mount is built
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:
```
$ git grep -n -w check_surface -- 'crates/*.rs'
crates/busbar-contract/src/transport/mod.rs:62      (re-export)
crates/busbar-contract/tests/wire_surface.rs        (test)
crates/busbar-plane-a2a/src/tests/surface.rs        (test)
$ grep -n check_surface crates/busbar-transport-http/src/mount.rs \
      crates/busbar-transport-grpc/src/mount.rs crates/busbar/src/root/transports.rs
$ echo $?
1
$ grep -c WireSurface crates/busbar-transport-http/src/mount.rs     # POSITIVE CONTROL
6
```
The doc says *"Run once, when the mount is built, and before a byte is accepted."* The two mount builders hold the `WireSurface` (6 references in the http one), resolve targets and services against it in production (`resolve_target`, `resolve_service`, `binding_at` all have real callers there), and never validate it. The three properties the check exists for — every operation reachable, no two reachable the same way, every template in the grammar — are therefore unenforced on a real node, including the `MAX_CAPTURES` ceiling whose doc says a template exceeding it "is refused by `check_surface` at boot rather than truncated at serve time". Nothing refuses it. `template_is_wellformed` has zero non-test readers for the same reason.
ACTION:    Call `check_surface(&surface)` at the top of the mount builders in `crates/busbar-transport-http/src/mount.rs` and `crates/busbar-transport-grpc/src/mount.rs` and propagate `SurfaceError` as a boot failure. Red-first: give a fixture surface two operations at one address and assert the mount refuses.

### X-1808 · the money-conservation canary increments in production and is checked only in CI
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:
```
$ git grep -n "\.balanced()" -- crates/
crates/busbar-contract/src/caps/tests/mod.rs:754,759,771
crates/busbar-contract/src/caps/tests/what_the_record_reads.rs:142
crates/busbar-kernel/tests/loop_battery.rs:373,443,699
crates/busbar-kernel/tests/table_and_pump.rs:885,891,897,903
$ git grep -l -w "draft_accepted\|hold_opened\|accrual_taken" -- 'crates/*.rs' | grep -v tests
crates/busbar-kernel/src/teller.rs                              # POSITIVE CONTROL: the increments DO ship
$ git grep -n -w CanaryBreak -- 'crates/*.rs' | grep -v caps/canary.rs
crates/busbar-contract/src/caps/mod.rs:79                       # re-export only; the Display/Error impls never render
```
`Canary` itself is threaded through production (`busbar-kernel/src/{teller,tick,recovery}.rs`), so every real unit pays for the four atomic increments. `balanced()` and `counts()` are never called outside tests, so the invariant *drafts accepted == holds opened + accruals == settlements* is asserted only by the proof battery on synthetic runs. A live node that leaked a settlement would carry the evidence in four atomics and never look at them. Note the caps module's own summary table (`caps/mod.rs:54`) claims this instrument runs at "runtime + CI"; the runtime half is not there.
ACTION:    Give the canary a runtime reader with a real consequence. Minimum: expose `counts()` as four gauges on the existing metrics surface so an operator can see a divergence, and call `balanced()` on the drain path (where the run IS quiet, which is the precondition the doc states) and refuse a clean shutdown on `Err(CanaryBreak)`. Then correct `caps/mod.rs:54` to match whatever is actually wired.

### X-1809 · the ABI layout golden does not pin `HostCtx` or `CostSettleOut`
CLASS:     abi
CERTAINTY: VERIFIED
EVIDENCE:
```
$ cut -d. -f1 crates/busbar-plugin/tests/golden/abi-layout.golden | sort -u | wc -l
44
$ git grep -A3 "#\[repr(C" -- crates/busbar-plugin/src/hot/decl.rs crates/busbar-plugin/src/hot/host.rs \
      crates/busbar-plugin/src/hot/pod.rs crates/busbar-plugin/src/hot/workitem.rs \
  | grep -oE "pub (struct|enum) [A-Za-z]+" | sed 's/pub \(struct\|enum\) //' | sort -u | wc -l
46
$ grep -c "HostCtx\|CostSettleOut" crates/busbar-plugin/tests/golden/abi-layout.golden
0
$ grep -c "^Usage\." crates/busbar-plugin/tests/golden/abi-layout.golden      # POSITIVE CONTROL
17
$ sed -n '58,60p' crates/busbar-plugin/src/hot/host.rs
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct HostCtx {
$ sed -n '2034,2036p' crates/busbar-plugin/src/hot/pod.rs
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CostSettleOut {
```
Both cross the boundary. `HostCtx` is the opaque host handle every hot-lane slot is entered with — `crates/busbar-plugin/src/lib.rs:76-81` records that airlock minor 20→21 exists *specifically* because `HostCtx` gained a `generation` stamp and a `kind` tag so the host can reject a stale handle instead of dereferencing it. That is a use-after-free guard whose field offsets nothing pins: reorder `generation` and `kind` and the golden stays green while the guard reads the wrong bytes. `CostSettleOut` is the `cost_settle` out-param carrying the post-accrual budget state a plane reads to decide whether to hard-close a live carrier — a money-path POD, also unpinned.
The test is otherwise a model gate (a missing or empty golden is an explicit failure, not a self-seed), which is exactly why the two omissions matter: everything else about it invites trust.
ACTION:    Add two `record!` blocks to `compute_layout()` in `crates/busbar-plugin/tests/layout_golden.rs` — `record!(s, HostCtx, [ …every field… ])` and `record!(s, CostSettleOut, [ …every field… ])` — then re-seed ONCE with `BUSBAR_UPDATE_GOLDEN=1 cargo test -p busbar-plugin` and commit the enlarged golden. Seeding here is legitimate because it is an ADDITION to the gate's coverage, not a re-blessing of a changed layout; the existing 44 struct blocks must diff clean in the same run, which is the check that the re-seed changed nothing else. Consider also a completeness assertion — walk the `repr(C)` set and fail if any name is absent from the golden — so the next POD cannot be added without being pinned.

### X-1810 · the TRANSPORT kind has no ABI: no hot entrypoint, no kind constant, no `repr(C)` surface
CLASS:     abi
CERTAINTY: VERIFIED
EVIDENCE:  Spec #3 fixes seven kinds and names TRANSPORT among them ("if core lacks that carrier, you install the transport plugin too"); spec #30 binds transport to the HOT/POD lane. None of the three things that would make that true exists.
```
$ git grep -n "TRANSPORT_DECL\|busbar_transport_decl" -- crates/ ; echo rc=$?
rc=1
$ git grep -n "PLANE_DECL" -- crates/ | wc -l                       # POSITIVE CONTROL
68
$ sed -n '88,124p' crates/busbar-plugin/src/cold/mod.rs             # the kind table
pub const STORE / SECRET / AUTH / HOOK / EXPORT / PLANE  (+ the six *_NUL siblings)
                                                                     # six kinds; no TRANSPORT
$ git grep -c "repr(C)" -- crates/busbar-contract/src/transport/ ; echo rc=$?
rc=1                                                                 # zero
$ git grep -c "repr(C)" -- crates/busbar-plugin/src/hot/            # POSITIVE CONTROL
crates/busbar-plugin/src/hot/pod.rs:40  (and 6 more files)
$ grep -n "macro_rules! export_" crates/plugin-sdk/src/lib.rs
export_auth_plugin / export_login_plugin / export_export_plugin / export_hook_plugin /
export_plugin / export_secret_plugin / export_store_plugin / export_plane     # no export_transport
```
What exists instead is a compiled-in-only Rust trait. `crates/busbar-contract/src/transport/mod.rs` declares `pub trait Transport: Plugin + Send + Sync + 'static` whose methods return `Fut<'a, T> = Pin<Box<dyn Future<Output = …> + Send + 'a>>` and `FrameStream = Pin<Box<dyn Stream<…>>>` — shapes that cannot cross a C ABI at all — and its module header states the position outright: *"Transports are in-tree only and never dynamically loaded"*, repeated at `plugin.rs:33` (*"Moves bytes. In-tree only, inside the trusted computing base."*).
That is a direct contradiction of spec #2 requirement (1) — compiled-in OR dropped-in over the SAME contract, one loading path — and of #30's lane assignment. It is NOT the superseded "both ABIs per plugin" complaint: transport has ZERO lanes, not one.
Meanwhile `busbar_contract::plugin::Kind` DOES enumerate seven including `Transport`, with a `TransportKind` marker, so the kind exists as structure everywhere except on the seam it names.
ACTION:    Owner ruling required — this is a scope question, not a code question. Either (a) TRANSPORT is a real dropped-in kind, in which case it needs `hot::symbol::TRANSPORT_DECL`, a `#[repr(C)] TransportDecl` vtable, `cold::kind::{TRANSPORT, TRANSPORT_NUL}` for the shared manifest/trust pipeline, an `export_transport!` SDK macro and a loader arm; or (b) TRANSPORT is deliberately in-TCB-only for 1.6.0, in which case #3's seven-kind row and #30's HOT-lane assignment must be amended to say so, because today three binding rows and the code disagree. PARK the choice; do not close it by editing either side alone.

### X-1811 · the auth kind still has no both-ways proof, and this is the file it would live beside
CLASS:     abi
CERTAINTY: VERIFIED
EVIDENCE:  Spec #2 names this absence in full and lists the five steps that close it. Re-measured, all five still open:
```
$ grep -n "macro_rules! export_auth_plugin" -A 40 crates/plugin-sdk/src/lib.rs | grep -c dispatch_compiled_in
0
$ grep -n "dispatch_export_enveloped\|dispatch_auth_enveloped" crates/plugin-sdk/src/lib.rs
962:pub fn dispatch_export_enveloped(          # export has one; auth has no twin
$ grep -n "pub fn open" crates/auth-static-plugin/src/lib.rs ; echo rc=$?
rc=1                                          # still private
$ grep -n "auth-static-plugin" crates/plugin-loader/Cargo.toml ; echo rc=$?
rc=1                                          # no path dependency, so no compiled-in arm can link
$ ls crates/plugin-loader/src/tests/ | grep auth ; echo rc=$?
rc=1                                          # no auth_conformance_tests.rs
$ ls crates/plugin-loader/src/tests/export_conformance_tests.rs   # POSITIVE CONTROL: export has one
```
This file (`cold/tests/auth_tests.rs`) is the auth kind's entire in-tree test surface: 10 tests, all JSON round-trip and shape pins on `AuthRequest`/`AuthResponse`/`Identity`, none of which crosses a boundary. Under #2 the enforcing witness is the export-conformance file's shape — link the crate, dispatch through its own `dispatch_compiled_in`, `dlopen` the same crate's cdylib, compare the two folds — and for auth it does not exist at any tag.
ACTION:    Exactly the ordered five from #2, no substitutions: (1) `crates/plugin-sdk/src/lib.rs` — add `dispatch_auth_enveloped`, the auth twin of `dispatch_export_enveloped`; (2) same file — make `export_auth_plugin!` emit a `dispatch_compiled_in` twin of its `busbar_call` symbol; (3) `crates/auth-static-plugin/src/lib.rs` — make `open` public; (4) `crates/plugin-loader/Cargo.toml` — add the path dependency (worthless without 1-3); (5) `crates/plugin-loader/src/tests/auth_conformance_tests.rs` — new, modelled on the export file, with a named RED arm and no silent CI skip. `14a49131d`'s rule applies throughout: adding the artefact is not the witness.

### X-1812 · the plugin-response status clamp ships only to its own tests; the real relay uses the raw value
CLASS:     customer-surface
CERTAINTY: VERIFIED
EVIDENCE:
```
$ git grep -n "safe_relay_status\|safe_status" -- crates/
crates/busbar-plugin/src/cold/auth.rs:260,265,266          (a delegate, also unused outside)
crates/busbar-plugin/src/cold/endpoint.rs:133,141,145,146  (definition)
crates/busbar-plugin/src/cold/tests/endpoint_tests.rs:81,90,92,96  (the ONLY callers)
$ grep -n "from_u16(resp.status)" crates/busbar-kernel/src/plugin_routes.rs
563:    let status = StatusCode::from_u16(resp.status).unwrap_or(StatusCode::BAD_GATEWAY);
```
`plugin_routes.rs:563` is the host relay for a matched plugin route — the one site this function's doc was written for: *"THE conversion a host relay must use instead of `StatusCode::from_u16(self.status).unwrap()`."* It uses neither. The `unwrap_or` prevents the panic the doc is most worried about, so this is not a crash; the residue is the range. `StatusCode::from_u16` accepts `100..=999`; `safe_relay_status` accepts `100..=599` and maps everything else to `502`. A plugin returning `600`–`999` therefore reaches the client verbatim as a nonstandard status instead of the neutral "the plugin misbehaved" `502` the contract promises.
ACTION:    In `crates/busbar-kernel/src/plugin_routes.rs:563` use `StatusCode::from_u16(resp.safe_status()).unwrap_or(StatusCode::BAD_GATEWAY)`. Red-first: add a case to `crates/busbar-kernel/src/export/tests/prometheus_tests.rs` (or the plugin-routes tests) with a fake dispatch returning `status: 999` and assert the relayed status is `502`.

### X-1813 · two independent copies of the `Scope`/`Grants` authorization lattice
CLASS:     auth
CERTAINTY: VERIFIED
EVIDENCE:
```
$ git grep -n "Grants(s.bit())" -- crates/
crates/busbar-contract/src/authz.rs:109
crates/busbar-kernel-scope/src/lib.rs:145
$ grep -n "pub enum Scope\|pub struct Grants\|pub use busbar_contract" crates/busbar-kernel-scope/src/lib.rs
66:pub enum Scope {
140:pub struct Grants(u8);
202:pub use busbar_contract::surface::ADMIN_PREFIX;        # the edge to the contract ALREADY EXISTS
$ git grep -n "From<busbar_contract::authz::Scope>\|authz::Scope>" -- crates/busbar-kernel-scope/ crates/busbar/
$ echo $?
1                                                          # no conversion in either direction
```
Line for line the same model: same two variants, same `as_str`/`parse` tokens, same `allows`, same `ALL`, same `bit`, same `dominates`, same `meet`, same `Grants` bitset with the same four methods. Both are live and their consumers are split — `busbar_contract::authz` is used by `busbar-kernel`'s `auth/mod.rs`, `config/parse.rs` and `config_validate/mod.rs`; `busbar_kernel_scope`'s copy by the composition root (`busbar/src/root/{policy,units_a2a,units_admin,units_mcp,units_voice}.rs`).
Because they are distinct Rust types there is no silent cross-wiring today — a mismatch would not compile. The hazard is drift, and it is the specific drift `authz.rs`'s own module doc forbids: *"A served control surface (or any other surface with the same two-rung read/write shape) names this directly instead of reinventing it."* A third rung, or a change to `meet`, applied to one copy and not the other gives the operator two different answers to "may this principal do this" depending on which half of the tree asks. Neither file mentions the other.
CERTAINTY NOTE: VERIFIED as duplication; the severity ruling (is this a live authz hole or only a maintenance hazard) is the owner's.
ACTION:    Delete `crates/busbar-kernel-scope/src/lib.rs`'s `Scope` and `Grants` and replace with `pub use busbar_contract::authz::{Grants, Scope};` beside the `ADMIN_PREFIX` re-export at line 202 — the crate already depends on `busbar-contract` (`Cargo.toml:29`), so this costs no new edge. Keep `busbar-kernel-scope`'s surface-specific parts (`TRANSPORT_HANDSHAKE`, `KERNEL_GRANTED_DATA_LISTENER_ROUTES`, `admin_required_scope`, `ADMIN_SCOPE_TABLE`), which is exactly the split `authz.rs`'s "what is deliberately NOT here" paragraph describes.

### X-1814 · eight of the ten catalog signals have no compute function and nothing tells the operator
CLASS:     customer-surface
CERTAINTY: ADJUDICATE
EVIDENCE:
```
$ git grep -n "requested.wants(" -- crates/ | grep -v '_tests\.rs\|/tests/'
crates/busbar-llm/src/engine/hooks.rs:683:  if requested.wants(busbar_api::Signal::CandidateBreakerState) {
crates/busbar-llm/src/engine/hooks.rs:697:  if requested.wants(busbar_api::Signal::CandidateErrorRate) {
$ git grep -n "unwired\|not wired\|no compute" -- crates/busbar-kernel/src crates/busbar-llm/src | grep -i signal
$ echo $?
1
```
`Signal::ALL` has ten entries; two are computed and both only on the LLM plane's decide path. Of the other eight, the five `Request*` entries are documented as still riding as core projection fields (defensible), but `RoutingPolicy` ("Reserved … not wired yet"), `CandidateLatencyP95Ms` (`TODO(latency-p95)`) and `ResponseTokensOut` (`TODO(outcome-signals)`) have no value source at all. A hook declares these by name in its signed manifest; `RequestedSignals` accepts the declaration, sets the bit, and the bag simply never gets an entry. No boot diagnostic, no warn, no manifest-time refusal.
Marked ADJUDICATE rather than VERIFIED because the reservation itself is deliberate and documented — the defect is the missing feedback, and whether that is owed to a plugin author is an owner call.
ACTION:    At plugin load, after a hook's declared signal set is parsed, compare it against the set the engine can actually compute and emit one operator diagnostic naming each declared-but-unwired signal (the diagnostics catalogue already carries this shape). Alternatively add a `Signal::is_wired()` the loader consults. Either way, do not leave a declarable config key that silently produces nothing.

### X-1815 · `transport/transport.rs` documents four paths that are not modules of this crate
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:
```
$ MODS=$(grep -oE '^pub mod [a-z_]+' crates/busbar-contract/src/lib.rs | awk '{print $3}' | tr '\n' '|' | sed 's/|$//')
$ git grep -ohE 'crate::[a-z_]+' -- crates/busbar-contract/src/ | sort -u | grep -vE "^crate::($MODS)$"
crate::constant_time_eq      # a real crate-root fn
crate::egress                # NOT a module of busbar-contract
crate::failover              # NOT a module
crate::hooks                 # NOT a module
crate::ingress               # NOT a module
crate::json_grammar          # pub(crate), real
crate::trust                 # only transport::trust exists
$ git grep -n "crate::egress\|crate::ingress" -- crates/busbar-contract/src/
crates/busbar-contract/src/transport/transport.rs:189,191,214,288
```
All four are in `transport/transport.rs` and all four name `busbar-substrate` modules (`egress::duplex_ws`, `ingress::duplex_ws`) that travelled here as prose with the `busbar-contract-transport` fold (#38) and were never re-pointed. They are backticked rather than bracketed, so `rustdoc -D broken_intra_doc_links` — the `doc-links` CI job — cannot see them; a reader following the doc for how `Transport::WebSocket` resolves to a real socket looks for a module this crate does not have.
ACTION:    Re-point the four to their real homes (`busbar_substrate::egress::duplex_ws` / `busbar_substrate::ingress::duplex_ws`, or whichever crate owns them post-fold) in `crates/busbar-contract/src/transport/transport.rs` lines 189, 191, 214, 288. While there, `src/vocab.rs` carries the same defect for `crate::failover` and `crate::trust::validate` — out of my slice, noted not acted.

### X-1816 · `busbar-grammar` is named as a live crate in two contract test files
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:
```
$ ls -d crates/busbar-grammar
ls: crates/busbar-grammar: No such file or directory
$ ls -d crates/busbar-contract                                   # POSITIVE CONTROL
crates/busbar-contract
$ git grep -n "busbar-grammar" -- crates/busbar-contract/
crates/busbar-contract/Cargo.toml:24:   "…folded in from the former `busbar-grammar` crate, DECISIONS #40…"   (past tense — fine)
crates/busbar-contract/tests/feature_invariance.rs:  BELOW_THE_CONTRACT = ["busbar-grammar"]  + its doc
crates/busbar-contract/tests/mutation_hardening.rs:3: "Mutation-hardening tests for `busbar-grammar`."
```
Two live claims. `feature_invariance.rs`'s `const BELOW_THE_CONTRACT: [&str; 1] = ["busbar-grammar"]` is the manifest allow-list that decides which workspace crates `busbar-contract` may depend on; its sole entry is a crate that cannot be depended on because it does not exist, so the allow-list is effectively empty and its accompanying doc paragraph describes an arrangement that ended at the #40 fold. `mutation_hardening.rs`'s header declares a subject that moved into this crate as `json_grammar`. The tests still pass (`--test feature_invariance` fails for X-1800's reasons, not this one; `--test mutation_hardening` → `8 passed`), so this is documentation drift with no runtime effect — but the allow-list is the kind of thing a future reader will trust.
ACTION:    In `crates/busbar-contract/tests/feature_invariance.rs`, change `BELOW_THE_CONTRACT` to an empty array (`[&str; 0]`) and rewrite its doc to say the contract now depends on NO workspace crate, which is the stronger and current truth. In `crates/busbar-contract/tests/mutation_hardening.rs` line 3, change the subject to `busbar_contract::json_grammar`.

### X-1817 · `signal.rs` documents `crate::hooks`, which is not a module of this crate
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:  Same module-set diff as X-1815:
```
$ git grep -n "crate::hooks" -- crates/busbar-contract/src/
crates/busbar-contract/src/signal.rs:31:   "…see `crate::hooks`/`busbar::config::HookStage`'s own doc comment)."
```
`grep -oE '^pub mod [a-z_]+' crates/busbar-contract/src/lib.rs` lists 26 modules; `hooks` is not among them. The `HookStage` vocabulary the sentence sends the reader to lives in `busbar-api`/`busbar-kernel`, not here.
ACTION:    Re-point to the real path (`busbar_api::hooks::HookStage`) in `crates/busbar-contract/src/signal.rs:31`.

### X-1818 · four cold-lane test headers name `crates/plugin-abi`, a directory that does not exist
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:
```
$ ls -d crates/plugin-abi
ls: crates/plugin-abi: No such file or directory
$ git grep -n "plugin-abi" crates/busbar-plugin/src/cold/tests/*.rs
auth_tests.rs:4://! Tests for `crates/plugin-abi/src/auth.rs`.
hook_tests.rs:4://! Tests for `crates/plugin-abi/src/hook.rs`.
export_tests.rs:4://! Tests for `crates/plugin-abi/src/export.rs`.
lib_tests.rs:4://! Tests for `crates/plugin-abi/src/lib.rs`.
```
These are present-tense "Tests for <path>" statements, distinct from the deliberate past-tense provenance notes in `crates/busbar-plugin/Cargo.toml:8` and `src/lib.rs:10` ("(was `busbar-plugin-abi`)"), which are correct and should stay. The four subjects now live at `crates/busbar-plugin/src/cold/{auth,hook,export,mod}.rs`.
ACTION:    Rewrite the four header lines to name the real files. Note that `lib_tests.rs`'s subject is `cold/mod.rs`, not a `lib.rs` — it is declared from `cold/mod.rs:699` — so that one is a rename plus a correction.

### X-1819 · the HOT lane's neutrality witness is cited at a path that does not exist
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:
```
$ ls -la scripts/plane-abi-neutrality.sh
ls: scripts/plane-abi-neutrality.sh: No such file or directory
$ ls scripts/ | wc -l                                            # POSITIVE CONTROL: the dir is full
      60+
$ git grep -n "plane-abi-neutrality.sh" -- crates/
crates/busbar-plugin/src/lib.rs:43
crates/busbar-plugin/src/hot/mod.rs:31
```
Both citations are load-bearing prose — they are the sentence that tells a reader the neutrality LAW (spec Part 4's neutrality witness) is machine-enforced rather than aspirational. The enforcement is real, but it moved: `.github/workflows/ci.yml:690-692` runs `cargo xtask gate plane-abi-neutrality --selftest` and then the blocking gate, implemented at `xtask/src/gates/plane_abi_neutrality.rs`, whose own header says *"The successor to `scripts/plane-abi-neutrality.sh`, rule for rule"* and which carries a `plane-abi-neutrality:hot-lane-present` row so an emptied or moved lane goes red rather than silently green. So this is drift only — the instrument is healthy — but a reader checking the claim finds nothing at the named path and has no way to know the gate exists.
ACTION:    Replace `scripts/plane-abi-neutrality.sh` with `cargo xtask gate plane-abi-neutrality` in `crates/busbar-plugin/src/lib.rs:43` and `crates/busbar-plugin/src/hot/mod.rs:31`.

## TALLY
```
files in slice:  75
verdict lines:   75
CLEAN:           55
FINDING:         20      rows raised: 20   (X-1800 .. X-1819)
DELETABLE:        0
UNREADABLE:       0
```

Rows by class: abi 4 (X-1801, X-1809, X-1810, X-1811) · auth 4 (X-1802, X-1803, X-1804, X-1813) ·
instrument-blind 4 (X-1800, X-1806, X-1807, X-1808) · missing-code 1 (X-1805) ·
customer-surface 2 (X-1812, X-1814) · drift 5 (X-1815, X-1816, X-1817, X-1818, X-1819).

Rows by certainty: VERIFIED 18 · ADJUDICATE 1 (X-1814) · PARK 1 (X-1810 — the TRANSPORT-kind
scope question needs an owner ruling; the measurement under it is VERIFIED).

## WHAT THIS SLICE PROVES ABOUT FILES OUTSIDE IT — reported, not acted on
- `crates/busbar-contract/src/caps/fixtures/lint_rules.rs` and `crates/busbar-contract/src/zzz_f5.rs`
  are another agent's uncommitted probe artefacts (a forged `Grant::<Sign>::mint` appended to the
  blanket-excluded fixture file, and an `f64` money function in an undeclared module). The first
  breaks the `busbar-contract` LIB-TEST target in this tree. Not HEAD, not mine, untouched.
- `crates/busbar-kernel-scope/src/lib.rs` holds the duplicate authorization lattice (X-1813) and is
  where that fix lands.
- `crates/busbar-kernel/src/plugin_routes.rs:563` is the relay that skips the status clamp (X-1812).
- `crates/busbar/src/root/transports.rs` is the composition root that should call
  `check_composition` (X-1806); `crates/busbar-transport-{http,grpc}/src/mount.rs` are the mounts
  that should call `check_surface` (X-1807).
- `crates/busbar-contract/src/unit.rs` carries the `RefusalReason` twins of the five unreachable
  `ReasonCode` variants, and all five plane crates carry render arms for them (X-1805).
- `crates/busbar-unit-transport-key/src/lib.rs:237` states that `TransportKeyHandle::issue`
  "demands a `Grant<KeyHandle>`". It does not — it takes `&dyn KernelSeal` (X-1803).
- `crates/busbar-contract/src/caps/mod.rs:54` lists the canary's enforcement as "runtime + CI"; only
  CI is real (X-1808).
- `crates/busbar-contract/src/vocab.rs` carries the same dead-module doc drift as X-1815
  (`crate::failover`, `crate::trust::validate`).
- `crates/busbar-substrate-values/Cargo.toml:81` says the `dispatch`/`runtime` cfg sites were
  "RELOCATED to `busbar-contract-transport`", a crate deleted by the #38 fold; they are in
  `busbar-contract` now.
- `xtask/src/gates/hot_path_alloc.rs:24` and `hot_path_perf.rs:30` both state that
  `crates/busbar-plugin/src/hot/host.rs` "has no production caller yet". It does:
  `crates/busbar-kernel/src/{calllog,plane/auditlog,plane_host/breaker,egress/seam}.rs` all name
  `busbar_plugin::hot::host::HostCtx` / `PlaneHostVtable`. Worth a look from whoever owns xtask.
