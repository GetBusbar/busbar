# SWEEP S02 — kernel-b (`crates/busbar-kernel`, second half)

> Slice file: `/Users/matthew/Developer/GetBusbar/.sweep/S02-kernel-b.txt` — **155 files**.
> X-id block: **X-1100 .. X-1199**. Read-and-report only; no source was edited.

## The instrument battery run against EVERY file in the slice

Each row's EVIDENCE column reports what these returned for that file. Every zero below is
controlled — the control command and its non-zero answer is named beside it.

| # | Command (run with `/usr/bin/grep`; zsh does NOT word-split `$var`, so every list was fed by `while IFS= read -r`) | Control |
|---|---|---|
| R | reachability, resolved EXACTLY: a parser walks every `.rs` under `crates/busbar-kernel/src`, collects each `#[path="p"] mod`/`mod X;` and resolves it the way rustc does (`#[path]` is relative to the DIRECTORY OF THE DECLARING FILE; a bare `mod X;` in `a/b.rs` resolves to `a/b/X.rs`). A first-grep-hit column was WRONG for every same-basename file (this crate has two files each named `observe_tests.rs`, `registry_tests.rs`, `limits_tests.rs` and `tls_tests.rs`, each verified with `find crates/busbar-kernel/src -name '<x>.rs' | wc -l` -> 2) and was rebuilt. **155/155 resolved, 0 UNDECLARED.** | fed the resolver `plane_host/not_a_real_module.rs`: `resolved: 156 UNDECLARED: 1`. It can return a NO. |
| V | plane/vendor vocabulary: `grep -icE '(^\|[^a-zA-Z0-9_])(llm\|mcp\|a2a\|voice\|jev\|openai\|anthropic\|gemini\|bedrock\|cohere)([^a-zA-Z0-9_]\|$)' <f>` | same regex on `crates/busbar-llm/src/lib.rs` -> **47** |
| F | floats on a money path: `grep -cE '\bf64\b\|\bf32\b' <f>` (BSD grep BRE/ERE `\b` proven live: `grep -c '\bfault_of\b' breaker.rs` -> 3) | slice total -> **32**, all located |
| D | never-constructed marker: `grep -cE 'allow\(dead_code\)' <f>`, then per-symbol `grep -rn '<sym>(' crates/` minus test paths | `set_now_for_test` -> prod=0/all=110 |
| S | stubs & muted instruments: `grep -cE 'unimplemented!\|todo!\(\|FIXME\|XXX\|#\[ignore\]' <f>` | repo-wide `unimplemented!` -> **65** (all in `busbar-plugin`'s ABI stubs) |

`R`/`V`/`F`/`D`/`S` appear in every EVIDENCE cell as `R=<decl site> V=n F=n D=n S=n`. Anything beyond
that battery is spelled out in the cell.

## VERDICTS — one line per file, in slice order

| FILE | VERDICT | EVIDENCE | ROWS |
|---|---|---|---|
| `crates/busbar-kernel/src/limits/tests/limits_tests.rs` | CLEAN | R=`limits/mod.rs:150` V=0 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/net_guard.rs` | CLEAN | R=`lib.rs:255` V=3 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/oauth_as/config.rs` | CLEAN | R=`oauth_as/mod.rs:90` V=5 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/oauth_as/mod.rs` | CLEAN | R=`lib.rs:256` V=6 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/oauth_as/seam.rs` | CLEAN | R=`oauth_as/mod.rs:91` V=2 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/oauth_as/tests/config_tests.rs` | CLEAN | R=`oauth_as/config.rs:286` V=1 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/observability.rs` | CLEAN | R=`lib.rs:257` V=0 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/observe.rs` | FINDING | R=`metrics.rs:734` V=0 F=0 D=1 S=0; read 108-120 + 200-220: LEDGER doc states '(A `prune` on config reload ... is OWED ... the ledger would retain a dead plugin's budget for the process lifetime)'; `grep -rn 'forget_cardinality' crates/` -> 8 hits, all `#[cfg(test)]` callers | X-1111 |
| `crates/busbar-kernel/src/plane_host/breaker.rs` | CLEAN | R=`plane_host/mod.rs:29` V=4 F=0 D=6 S=0 | - |
| `crates/busbar-kernel/src/plane_host/build_input.rs` | FINDING | R=`plane_host/mod.rs:1943` V=8 F=2 D=0 S=0; read 1-30 + 160-180 + 300-320: module doc 'THE NEUTRAL LLM-RUNTIME BUILD CARRIER ... handed to the LLM plane's `build_runtime`'; `pub cost_per_mtok: Option<f64>` documented as 'rate-card-derived cost per Mtok, resolved core-side'. `grep -c 'f64' ` -> 2 | X-1109 |
| `crates/busbar-kernel/src/plane_host/cost_host.rs` | FINDING | R=`plane_host/mod.rs:32` V=2 F=0 D=0 S=0; `grep -rn 'reserve_lease|settle_lease|settled_of|close_lease'` -> every non-test caller is `plane_host/mod.rs:605-626` (the `MeteringHost` impl); `grep -rn '\.refund|refund:' crates/` -> the only site touching `Settlement.refund` in production is `cost_host.rs:128 let _refund = settlement.refund;` | X-1100, X-1102 |
| `crates/busbar-kernel/src/plane_host/creds.rs` | CLEAN | R=`plane_host/mod.rs:33` V=0 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/plane_host/dispatch.rs` | FINDING | R=`plane_host/mod.rs:34` V=5 F=0 D=0 S=0; read 295-380: `gate_scan` calls `gate_scan_inner(host, chunk, NO_GATES)` with `const NO_GATES: &[(u16, ResolvedPolicy)] = &[]`; `grep -rn 'gate_scan_inner'` -> 3 hits, the only non-empty gate set comes from `tests/dispatch_tests.rs:334` | X-1104, X-1113 |
| `crates/busbar-kernel/src/plane_host/egress_tests.rs` | CLEAN | R=`plane_host/egress.rs:1623` V=1 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/plane_host/egress.rs` | FINDING | R=`plane_host/mod.rs:35` V=15 F=0 D=11 S=0; read 68-90 + 270-280: `allowlist_scope` bits are read straight off the plane-supplied `EgressDesc` (`scope & SCOPE_ALLOW_PRIVATE`, `scope & SCOPE_ALLOW_PLAINTEXT`) with the file's own note 'resolving the scope id against operator config is not yet wired'; `const EGRESS_TIMEOUT: Duration = from_secs(30)` with 'Phase 2 derives this from the App's resolved upstream limits' | X-1105, X-1110 |
| `crates/busbar-kernel/src/plane_host/engine_view.rs` | CLEAN | R=`plane_host/mod.rs:1947` V=6 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/plane_host/identity_admit.rs` | CLEAN | R=`plane_host/mod.rs:45` V=0 F=0 D=1 S=0 | - |
| `crates/busbar-kernel/src/plane_host/pipe_tests.rs` | CLEAN | R=`plane_host/pipe.rs:450` V=0 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/plane_host/pipe.rs` | CLEAN | R=`plane_host/mod.rs:47` V=0 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/plane_host/slots_through.rs` | CLEAN | R=`plane_host/mod.rs:1961` V=0 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/plane_host/spki.rs` | CLEAN | R=`plane_host/mod.rs:1962` V=4 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/plane_host/tests/breaker_tests.rs` | CLEAN | R=`plane_host/breaker.rs:461` V=1 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/plane_host/tests/build_input_tests.rs` | CLEAN | R=`plane_host/build_input.rs:338` V=0 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/plane_host/tests/cost_host_tests.rs` | FINDING | R=`plane_host/cost_host.rs:223` V=0 F=0 D=0 S=0; read 195-262: `close_lease_applies_the_refund_of_the_unspent_reserve` calls `close_lease(id)` twice and asserts only `Some(700)`/`None`; the refund assertions at 210-225 are on a `CostHold` the test builds itself | X-1101 |
| `crates/busbar-kernel/src/plane_host/tests/creds_tests.rs` | CLEAN | R=`plane_host/creds.rs:171` V=0 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/plane_host/tests/dispatch_tests.rs` | FINDING | R=`plane_host/dispatch.rs:604` V=0 F=0 D=0 S=0; read 11-16: `fn durable_scope_stub_constructs() { let _ = DurableScope::new(); }` -- zero assert/expect/should_panic in the body | X-1112 |
| `crates/busbar-kernel/src/plane_host/tests/egress_trust_tests.rs` | CLEAN | R=`plane_host/egress_trust.rs:113` V=2 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/plane_host/tests/gauntlet_session_tests.rs` | CLEAN | R=`plane_host/mod.rs:3465` V=0 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/plane_host/tests/govern_tests.rs` | CLEAN | R=`plane_host/govern.rs:374` V=4 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/plane_host/tests/identity_admit_tests.rs` | CLEAN | R=`plane_host/identity_admit.rs:166` V=0 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/plane_host/tests/identity_tests.rs` | CLEAN | R=`plane_host/identity.rs:129` V=1 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/plane_host/tests/journal_tests.rs` | CLEAN | R=`plane_host/journal.rs:1182` V=4 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/plane_host/tests/mod_tests.rs` | CLEAN | R=`plane_host/mod.rs:1937` V=8 F=4 D=0 S=0 | - |
| `crates/busbar-kernel/src/plane_host/tests/plane_answer_tests.rs` | CLEAN | R=`plane_host/mod.rs:3469` V=0 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/plane_host/tests/scope_tests.rs` | CLEAN | R=`plane_host/scope.rs:604` V=0 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/plane_host/tests/trust_anchor_tests.rs` | CLEAN | R=`plane_host/trust_anchor.rs:75` V=1 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/plane_host/tests/trust_tests.rs` | CLEAN | R=`plane_host/trust.rs:664` V=5 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/plane_host/trust_anchor.rs` | CLEAN | R=`plane_host/mod.rs:1963` V=2 F=0 D=1 S=0 | - |
| `crates/busbar-kernel/src/plane_host/trust.rs` | FINDING | R=`plane_host/mod.rs:49` V=11 F=0 D=2 S=0; `grep -rnE '^\s*pub? *mod a2a' crates/busbar-kernel/src` -> 0 (positive control `pub mod plane;` -> 1); `grep -rn 'verify_decide_due' crates/` -> the only live caller is `verify_decide_q` at :327 with `operator_sync=false`; busbar-a2a's `verify.rs:330`/`verbs.rs:293` call `reverify::due` directly | X-1107 |
| `crates/busbar-kernel/src/plane_host/vtable.rs` | FINDING | R=`plane_host/mod.rs:50` V=3 F=2 D=0 S=3; read 30-115: the table advertises `gate_scan: Some(super::dispatch::gate_scan)` under 'WIRED capability slots ... no `unimplemented!()` stub remains'; the slot it names is hardwired to an empty gate set (see X-1104) | X-1104 |
| `crates/busbar-kernel/src/plane_routes.rs` | CLEAN | R=`lib.rs:314` V=3 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/plane/approvals.rs` | CLEAN | R=`plane/mod.rs:93` V=3 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/plane/auditlog.rs` | FINDING | R=`plane/mod.rs:94` V=0 F=0 D=3 S=0; `grep -rn 'mirror(' --include='*.rs' crates/ | grep -v '^ *//'` -> 2 hits: this file's own def at :983 and an unrelated MCP test FN NAME; `grep -n 'emit(' auditlog.rs` -> :743 (def) and :992 (inside `mirror`). Positive control: `grep -rn 'auditlog::emit_admin_hostless_now'` -> 3 | X-1103 |
| `crates/busbar-kernel/src/plane/calllog.rs` | CLEAN | R=`plane/mod.rs:883` V=0 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/plane/observe.rs` | CLEAN | R=`plane/mod.rs:97` V=1 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/plane/quarantine.rs` | CLEAN | R=`plane/mod.rs:98` V=0 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/plane/tests/askstate_tests.rs` | CLEAN | R=`plane/approvals.rs:230` V=0 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/plane/tests/auditlog_tests.rs` | CLEAN | R=`plane/auditlog.rs:1096` V=0 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/plane/tests/config_tests.rs` | CLEAN | R=`plane/config.rs:511` V=3 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/plane/tests/cost_tests.rs` | CLEAN | R=`plane/cost.rs:405` V=0 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/plane/tests/demotion_tests.rs` | CLEAN | R=`plane/quarantine.rs:222` V=0 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/plane/tests/handle_engine_tests.rs` | CLEAN | R=`plane/handle_engine.rs:1137` V=0 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/plane/tests/sections_tests.rs` | CLEAN | R=`plane/mod.rs:879` V=2 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/plane/tests/store_seam_tests.rs` | CLEAN | R=`plane/store.rs:80` V=0 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/proto/detect.rs` | CLEAN | R=`proto/mod.rs:223` V=0 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/proto/mod.rs` | CLEAN | R=`lib.rs:285` V=10 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/proto/registry.rs` | CLEAN | R=`proto/mod.rs:226` V=0 F=0 D=1 S=0 | - |
| `crates/busbar-kernel/src/proto/stream_translator.rs` | CLEAN | R=`proto/mod.rs:173` V=0 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/proto/tests/registry_builtins.rs` | FINDING | R=`proto/registry.rs:92` V=8 F=0 D=0 S=0; `grep -rn 'TEST_BUILTIN_DECLS' --include='*.rs' crates/` -> 2 hits (its own def + `proto/registry.rs:97`). No test pins it against `busbar_llm::DECLS`, which `crates/busbar/src/main.rs:211` installs by slice | X-1106 |
| `crates/busbar-kernel/src/proto/tests/stream_factory_fixture.rs` | CLEAN | R=`proto/mod.rs:181` V=2 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/proxy/mod.rs` | CLEAN | R=`lib.rs:286` V=6 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/proxy/proxy_vocab.rs` | CLEAN | R=`proxy/mod.rs:11` V=2 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/proxy/reqlog.rs` | CLEAN | R=`proxy/mod.rs:51` V=1 F=0 D=3 S=0 | - |
| `crates/busbar-kernel/src/proxy/tests/reqlog_tests.rs` | CLEAN | R=`proxy/reqlog.rs:413` V=0 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/rate_apply.rs` | CLEAN | R=`lib.rs:315` V=0 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/ratelimit.rs` | CLEAN | R=`lib.rs:290` V=0 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/reply.rs` | CLEAN | R=`lib.rs:138` V=0 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/router.rs` | CLEAN | R=`lib.rs:345` V=4 F=2 D=2 S=0 | - |
| `crates/busbar-kernel/src/session/tests/session_tests.rs` | CLEAN | R=`session/mod.rs:218` V=6 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/state.rs` | CLEAN | R=`lib.rs:305` V=0 F=0 D=18 S=0 | - |
| `crates/busbar-kernel/src/store/mod.rs` | CLEAN | R=`lib.rs:306` V=0 F=0 D=2 S=0 | - |
| `crates/busbar-kernel/src/store/planes.rs` | CLEAN | R=`store/mod.rs:155` V=0 F=0 D=4 S=0 | - |
| `crates/busbar-kernel/src/store/tests/planes_tests.rs` | CLEAN | R=`store/planes.rs:399` V=0 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/store/tests/tests.rs` | CLEAN | R=`store/mod.rs:163` V=0 F=2 D=0 S=2 | - |
| `crates/busbar-kernel/src/store/vocab.rs` | CLEAN | R=`store/mod.rs:167` V=9 F=5 D=10 S=0 | - |
| `crates/busbar-kernel/src/taxonomy.rs` | FINDING | R=`lib.rs:301` V=0 F=0 D=0 S=0; read in full: module doc says '`main.rs` references them via `crate::taxonomy::ERR_TYPE_*`', but the consts are `pub(crate)` in busbar-kernel and `crates/busbar/src/main.rs` cannot name them; `grep -rn 'crate::taxonomy::' crates/` -> callers are `ingress/dispatch.rs`, `ingress/arrival_host.rs`, `router.rs`, `tests/tests.rs` only | X-1117 |
| `crates/busbar-kernel/src/telemetry.rs` | CLEAN | R=`lib.rs:316` V=0 F=6 D=0 S=0 | - |
| `crates/busbar-kernel/src/test_support/engine_kit_plus.rs` | CLEAN | R=`test_support/mod.rs:2292` V=0 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/test_support/engine_kit.rs` | CLEAN | R=`test_support/mod.rs:2288` V=0 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/test_support/fixtures.rs` | CLEAN | R=`test_support/mod.rs:2333` V=8 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/test_support/mod.rs` | CLEAN | R=`lib.rs:318` V=64 F=4 D=6 S=0 | - |
| `crates/busbar-kernel/src/testkit/engine_kit_plus.rs` | CLEAN | R=`testkit/mod.rs:53` V=0 F=2 D=0 S=0 | - |
| `crates/busbar-kernel/src/testkit/engine_kit.rs` | CLEAN | R=`testkit/mod.rs:47` V=2 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/testkit/loopback_http.rs` | CLEAN | R=`testkit/mod.rs:38` V=0 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/testkit/metrics_capture.rs` | CLEAN | R=`testkit/mod.rs:41` V=0 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/testkit/mod.rs` | CLEAN | R=`lib.rs:320` V=4 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/testkit/tests/fixture_host_tests.rs` | CLEAN | R=`testkit/fixture_host.rs:938` V=0 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/tests/admin_verbs.rs` | CLEAN | R=`admin_verbs.rs:300` V=0 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/tests/alarm_silence_tests.rs` | CLEAN | R=`lib.rs:336` V=0 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/tests/audit_ring_tests.rs` | CLEAN | R=`audit_ring.rs:375` V=0 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/tests/auth_cache_tests.rs` | CLEAN | R=`auth_cache.rs:230` V=0 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/tests/billing_tests.rs` | CLEAN | R=`billing.rs:19` V=0 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/tests/call_binding_tests.rs` | CLEAN | R=`teller.rs:1375` V=0 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/tests/calllog_tests.rs` | CLEAN | R=`calllog.rs:1063` V=3 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/tests/catalogue_tests.rs` | CLEAN | R=`catalogue.rs:17` V=5 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/tests/detached_tests.rs` | CLEAN | R=`detached.rs:139` V=0 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/tests/drain_facade_tests.rs` | CLEAN | R=`lib.rs:342` V=0 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/tests/inflight_tests.rs` | CLEAN | R=`inflight.rs:917` V=0 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/tests/key_expires_at_tests.rs` | CLEAN | R=`governance/mod.rs:1303` V=0 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/tests/lineage_tests.rs` | CLEAN | R=`lineage.rs:102` V=4 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/tests/mask_tests.rs` | CLEAN | R=`mask.rs:373` V=0 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/tests/metrics_tests.rs` | CLEAN | R=`metrics.rs:644` V=0 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/tests/net_guard_fetch_tests.rs` | CLEAN | R=`net_guard.rs:115` V=7 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/tests/net_guard_tests.rs` | CLEAN | R=`net_guard.rs:111` V=7 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/tests/observability_tests.rs` | CLEAN | R=`observability.rs:824` V=1 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/tests/observe_tests.rs` | FINDING | R=`observe.rs:472` V=0 F=0 D=0 S=0; `sed -n '255,266p' | grep -cE 'assert|expect|panic|unwrap'` -> 1, and that one hit is the word 'panic' inside a comment (positive control: the neighbouring test body -> 2 real hits). `hook_envelope_metrics_are_carried_but_not_folded` has no assertion at all | X-1114 |
| `crates/busbar-kernel/src/tests/operation_tests.rs` | CLEAN | R=`lib.rs:269` V=12 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/tests/plugin_routes_tests.rs` | CLEAN | R=`plugin_routes.rs:593` V=0 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/tests/profile_tests.rs` | CLEAN | R=`profile.rs:338` V=0 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/tests/proto.rs` | CLEAN | R=`proto/mod.rs:363` V=0 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/tests/rate_apply.rs` | CLEAN | R=`rate_apply.rs:120` V=0 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/tests/ratelimit_tests.rs` | CLEAN | R=`ratelimit.rs:243` V=0 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/tests/registry_tests.rs` | CLEAN | R=`registry.rs:546` V=0 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/tests/telemetry_tests.rs` | CLEAN | R=`telemetry.rs:416` V=17 F=1 D=0 S=0 | - |
| `crates/busbar-kernel/src/tests/teller_verified_destination_tests.rs` | CLEAN | R=`teller.rs:1379` V=0 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/tests/tests.rs` | CLEAN | R=`lib.rs:347` V=64 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/tests/tls_tests.rs` | CLEAN | R=`tls.rs:818` V=0 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/tests/transport_tests.rs` | CLEAN | R=`lib.rs:326` V=11 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/topology/mod.rs` | CLEAN | R=`lib.rs:322` V=0 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/topology/worker_shard_tests.rs` | CLEAN | R=`topology/mod.rs:169` V=0 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/trust/declared.rs` | FINDING | R=`trust/mod.rs:457` V=6 F=0 D=0 S=0; read :70 -> intra-doc link ``[`crate::a2a::pin::CardPin::Unpinned`]``; `grep -rnE '^\s*pub? *mod a2a' crates/busbar-kernel/src` -> 0. `grep -rn 'cargo doc|RUSTDOCFLAGS' .github/workflows/ xtask/src/ scripts/` -> 0 (positive control `grep -rln 'cargo clippy' .github/workflows/` -> 3+) | X-1108 |
| `crates/busbar-kernel/src/trust/tests/declared_tests.rs` | CLEAN | R=`trust/declared.rs:147` V=4 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/trust/tests/genericity_tests.rs` | CLEAN | R=`trust/mod.rs:477` V=10 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/trust/tests/lifecycle_tests.rs` | CLEAN | R=`trust/mod.rs:473` V=2 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/trust/tests/reverify_tests.rs` | CLEAN | R=`trust/reverify.rs:10` V=4 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/trust/tests/reverify.rs` | CLEAN | R=`trust/reverify.rs:204` V=0 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/trust/tests/validate_tests.rs` | CLEAN | R=`trust/validate.rs:32` V=0 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/src/trust/tests/verify_edge_tests.rs` | FINDING | R=`trust/verify.rs:19` V=8 F=0 D=0 S=0; sub-audit read in full: header :8-12 'Nothing here is a protocol fact'; nearest-to-refusal case is the backwards-clock refetch at :153-164 (a freshness-timing property). No verify-refuses case | X-1116 |
| `crates/busbar-kernel/src/trust/tests/verify_tests.rs` | FINDING | R=`trust/verify.rs:15` V=1 F=0 D=0 S=0; sub-audit read in full: every assertion is on `fetches.load(SeqCst)` counts; no bad-signature / expired / wrong-key / wrong-subject refusal case. File header :4-12 states the refusal 'is proven on each plane consumer's own request path' | X-1116 |
| `crates/busbar-kernel/src/trust/validate.rs` | CLEAN | R=`trust/mod.rs:30` V=2 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/tests/admin_planeverbs_cross_plane.rs` | CLEAN | R=`cargo integration-test target (tests/ root, auto-discovered)` V=12 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/tests/alarm_silence_cross_plane.rs` | CLEAN | R=`cargo integration-test target (tests/ root, auto-discovered)` V=2 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/tests/auth_cross_plane.rs` | CLEAN | R=`cargo integration-test target (tests/ root, auto-discovered)` V=1 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/tests/common/mod.rs` | CLEAN | R=``mod common;` in tests/loop_battery.rs, tests/recovery_and_ticks.rs, tests/table_and_pump.rs` V=0 F=0 D=1 S=0 | - |
| `crates/busbar-kernel/tests/config_cross_plane.rs` | CLEAN | R=`cargo integration-test target (tests/ root, auto-discovered)` V=16 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/tests/config_migrate_cross_plane.rs` | CLEAN | R=`cargo integration-test target (tests/ root, auto-discovered)` V=7 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/tests/config_validate_cross_plane.rs` | CLEAN | R=`cargo integration-test target (tests/ root, auto-discovered)` V=4 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/tests/endpoints_cross_plane.rs` | CLEAN | R=`cargo integration-test target (tests/ root, auto-discovered)` V=11 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/tests/key_expires_at_cross_plane.rs` | CLEAN | R=`cargo integration-test target (tests/ root, auto-discovered)` V=1 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/tests/mask.rs` | FINDING | R=`cargo integration-test target (tests/ root, auto-discovered)` V=0 F=0 D=0 S=0; `grep -rn 'FixedScratch' --include='*.rs' crates/` -> 21 hits; every use site outside `src/mask.rs` is this file (:12,:218,:236,:255). `src/mask.rs:78` labels the type 'DEAD -- see the module docs' | X-1115 |
| `crates/busbar-kernel/tests/metrics_cross_plane.rs` | CLEAN | R=`cargo integration-test target (tests/ root, auto-discovered)` V=0 F=2 D=0 S=0 | - |
| `crates/busbar-kernel/tests/named_map_cross_plane.rs` | CLEAN | R=`cargo integration-test target (tests/ root, auto-discovered)` V=0 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/tests/plane_config_cross_plane.rs` | CLEAN | R=`cargo integration-test target (tests/ root, auto-discovered)` V=25 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/tests/plane_dispatch_cross_plane.rs` | CLEAN | R=`cargo integration-test target (tests/ root, auto-discovered)` V=90 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/tests/plane_host_dispatch_cross_plane.rs` | CLEAN | R=`cargo integration-test target (tests/ root, auto-discovered)` V=0 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/tests/plane_integration.rs` | CLEAN | R=`cargo integration-test target (tests/ root, auto-discovered)` V=106 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/tests/record_legs.rs` | CLEAN | R=`cargo integration-test target (tests/ root, auto-discovered)` V=0 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/tests/recovery_and_ticks.rs` | CLEAN | R=`cargo integration-test target (tests/ root, auto-discovered)` V=0 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/tests/registry_and_claims.rs` | CLEAN | R=`cargo integration-test target (tests/ root, auto-discovered)` V=0 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/tests/registry_cross_plane.rs` | CLEAN | R=`cargo integration-test target (tests/ root, auto-discovered)` V=70 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/tests/reply_legs.rs` | CLEAN | R=`cargo integration-test target (tests/ root, auto-discovered)` V=0 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/tests/scratch.rs` | CLEAN | R=`cargo integration-test target (tests/ root, auto-discovered)` V=0 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/tests/settlement_table.rs` | CLEAN | R=`cargo integration-test target (tests/ root, auto-discovered)` V=0 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/tests/slices_and_leases.rs` | CLEAN | R=`cargo integration-test target (tests/ root, auto-discovered)` V=0 F=0 D=0 S=0 | - |
| `crates/busbar-kernel/tests/spentledger_cross_plane.rs` | CLEAN | R=`cargo integration-test target (tests/ root, auto-discovered)` V=5 F=0 D=0 S=0 | - |

## ROWS RAISED

### X-1100 · the metering lease debits nothing and credits nothing — `close_lease` reconciles a refund into a discarded binding
CLASS:     money
CERTAINTY: VERIFIED
EVIDENCE:
```
$ /usr/bin/grep -rn "\.refund\b\|refund:" --include='*.rs' crates/
crates/busbar-kernel/src/plane/cost.rs:292:    pub refund: CostAmount,          <- the declaration
crates/busbar-kernel/src/plane/tests/cost_tests.rs:164,176,185,193            <- test assertions
crates/busbar-kernel/src/plane_host/tests/cost_host_tests.rs:215,225          <- test assertions
crates/busbar-kernel/src/plane_host/cost_host.rs:128:    let _refund = settlement.refund;   <- the ONLY production site
```
`crates/busbar-kernel/src/plane/cost.rs:320-326` states the contract this host registry is the caller
of: *"the caller applies `reserved` to its budget cell at `CostHold::reserve` and the `Settlement` at
`CostHold::finalize`."* `cost_host.rs::register()` (line 49) applies nothing at reserve;
`cost_host.rs::close_lease()` (line 118) computes `settlement.refund` and drops it into `_refund`,
with its own comment conceding *"the moment a real budget cell is wired, credit `settlement.refund`
to it at THIS point."* The settled total `close_lease` returns travels to
`MeteringHost::cost_close` (`plane_host/mod.rs:625`) and both of its production callers discard it
(`crates/busbar-voice/src/runtime/metering.rs:218` and `:417`, `let _ = host.cost_close(...)`).

Net: a reserve-then-settle session accrues money into a process-global `HashMap<u64, CostHold>` and
the whole accrual is destroyed at close. Nothing is ever written to a ledger, and nothing is ever
debited from a grant. Control: `grep -cniE 'budget|grant|ledger|spend|book' cost_host.rs` -> 10, all
in prose; the same regex on `plane/cost.rs` -> 28, where the arithmetic actually lives.
Blast radius today is bounded — the only consumer is `busbar-voice`, and `plane-voice` is NOT in
`busbar-kernel`'s default feature set — which is why this is a PARK-adjacent row rather than a
shipped mis-bill. It is still a book with no ledger behind it.
ACTION:    Either (a) thread the real budget/grant cell through `register`/`close_lease` so the
           reserve debits and the `Settlement` (ledgered_total + refund) is applied at close, or
           (b) delete the `Settlement.refund` field and say out loud in `CostHold`'s doc that this
           lease is an in-memory exhaustion gauge and not an accounting record. Do not leave the
           third state, where the type documents an accounting contract nobody honours.

### X-1101 · `close_lease_applies_the_refund_of_the_unspent_reserve` asserts the refund on a CostHold it built itself
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:
```
$ sed -n '195,231p' crates/busbar-kernel/src/plane_host/tests/cost_host_tests.rs
fn close_lease_applies_the_refund_of_the_unspent_reserve() {
    let id = reserve_lease(1_000, 200, Some(10_000)).expect("opens");
    assert_eq!(settle_lease(id, 700), Some(false), ...);
    assert_eq!(close_lease(id), Some(700), "close ledgers the EXACT settled sum, ...");
    let refunded = CostHold::reserve(CostAmount(1_000), CostAmount(200), Some(CostAmount(10_000)));
    let mut refunded = refunded;
    refunded.settle_partial(CostAmount(700));
    assert_eq!(refunded.finalize().refund, CostAmount(500), "refund = ...");
    ...
    assert_eq!(close_lease(id), None, "no double refund on a second close");
}
```
The only two observations of `close_lease` are `Some(700)` and `None`. The refund assertion at
:213-217 is taken on `refunded`, a second `CostHold` the test constructs three lines earlier and
finalizes itself. Delete `cost_host.rs:128` (`let _refund = settlement.refund;`) — the binding is
`_`-prefixed and nothing else in the module reads it — and this test still passes. The test's own
name is the claim it cannot make; it is the instrument that was supposed to catch X-1100 and cannot.
ACTION:    Once X-1100 is closed, assert the refund THROUGH `close_lease` (return it, or observe the
           budget cell it credited). Until then, rename the test to what it measures
           (`close_lease_ledgers_the_exact_settled_sum_not_the_reserve`) so it stops standing in for
           a check nobody is running.

### X-1102 · a plane mints its own metering ceiling — `cap_present == false` opens an unbounded lease and the host never refuses
CLASS:     auth
CERTAINTY: VERIFIED
EVIDENCE:
```
$ sed -n '236,242p' crates/busbar-kernel/src/plane_host/tests/cost_host_tests.rs
    assert_eq!(reserve_lease(100, 0, Some(0)), None, "refuse-all denies");
    let unc = reserve_lease(0, 0, None).expect("uncapped opens");
    assert_eq!(settle_lease(unc, u128::from(u64::MAX)), Some(false));
    assert_eq!(settle_lease(unc, u128::from(u64::MAX)), Some(false));
    assert_eq!(close_lease(unc), Some(u128::from(u64::MAX) * 2));
```
The suite itself proves it: a lease opened with no cap accepts two settles of `u64::MAX` nanodollars
each without ever reporting exhaustion. `cap_nanos`/`cap_present` are fields of the
plane-constructed `EgressDesc`-style call (`cost_host.rs:141-152`), so the CALLER BEING METERED
chooses whether there is a ceiling at all; `CostHold::is_exhausted` is `matches!(self.cap, Some(cap)
if self.settled >= cap)` — always `false` for `None`. Core consults no grant, no per-office budget
and no operator config on this path (see X-1100: there is no cell to consult). This is the contract's
"a capability minted without a ceiling", in the one slot whose entire purpose is a ceiling.
ACTION:    Owner ruling needed on the policy, then code: clamp `cap_nanos` host-side against the
           caller's resolved grant (min(plane-requested, host-known)), and make `cap_present ==
           false` mean "the host's own ceiling" rather than "no ceiling". If an uncapped lease is
           genuinely intended for some caller class, that class has to be named host-side, not
           chosen by the plane.

### X-1103 · the durable-audit dual-write is dead: `plane::auditlog::mirror` has zero callers and `emit`'s only caller is `mirror`
CLASS:     missing-code
CERTAINTY: VERIFIED
EVIDENCE:
```
$ /usr/bin/grep -rn "mirror(" --include='*.rs' crates/ | /usr/bin/grep -vE ':[0-9]+: *(//|///|//!|\*)'
crates/busbar-mcp/src/mcp/client/tests/wire_tests.rs:71:fn the_mirrored_headers_agree_with_the_body_they_mirror() {   <- a test FN NAME, not a call
crates/busbar-kernel/src/plane/auditlog.rs:983:pub(crate) fn mirror(                                          <- the definition
$ /usr/bin/grep -n "emit(" crates/busbar-kernel/src/plane/auditlog.rs
743:pub(crate) fn emit(host: HostCtx, scope: &str, suffix: Vec<u8>) {
992:    crate::plane_host::with_dispatch_scope(app, |host, _| emit(host, ADMIN_LOG, suffix));   <- inside mirror
$ /usr/bin/grep -n "mirror(\|emit(" crates/busbar-kernel/src/plane/tests/auditlog_tests.rs
(no output — not even the tests reach them)
POSITIVE CONTROL
$ /usr/bin/grep -rn "auditlog::emit_admin_hostless_now" --include='*.rs' crates/ | wc -l
3
```
Both functions carry a `#[allow(dead_code)]` whose comment asserts the opposite of the measurement:
`:742` *"wired at the converted admin/plane call sites; no caller until then"* and `:982` *"called
from the plane-gated audit sites; no caller with every plane compiled out"*. The live audit path is
`audit_ring.rs:295 -> auditlog::emit_admin_hostless(...)` (line 903), which reaches the journal via
its own `drain_pending_audit`/`enqueue_pending_audit`. So the journal IS written — but by the other
function. `emit` (52 lines, including the `WRITE_FAILED_LATCHED` transition diagnostic and the
`journal_append_scoped` seam call) and `mirror` are an unreached pair sitting in the Audit step of
the governance workflow, with a comment telling the next reader they are wired.
ACTION:    Decide which of the two is the surviving writer. Either wire `mirror` at the admin/plane
           mutation sites it was built for, or delete `emit`+`mirror` and their `#[allow(dead_code)]`
           lies and let `emit_admin_hostless` be the single documented journal writer.

### X-1104 · `gate_scan` — the streaming content-governance slot — is hardwired to an empty gate set and cannot Block on content
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:
```
$ sed -n '309,316p' crates/busbar-kernel/src/plane_host/dispatch.rs
pub(crate) extern "C-unwind" fn gate_scan(host: HostCtx, chunk: *const ContentChunk) -> GateDecision {
    // No gate is wired to this seam yet (Phase 2 resolves the real per-session/per-container set).
    const NO_GATES: &[(u16, crate::hooks::ResolvedPolicy)] = &[];
    gate_scan_inner(host, chunk, NO_GATES)
}
$ /usr/bin/grep -rn "gate_scan_inner" --include='*.rs' crates/
dispatch.rs:315 (the empty-set call) | dispatch.rs:321 (the def) | tests/dispatch_tests.rs:334 (the ONLY non-empty set)
$ /usr/bin/grep -n "pub struct ContentChunk" -A 18 crates/busbar-plugin/src/hot/pod.rs
  fields: size, version, is_final, _reserved, session_id, offset, data_ptr, data_len
```
Three facts together: (1) the shipped slot passes a `const` empty slice, so
`crate::hooks::gate::decide` takes its `gates.is_empty()` early-out and returns `Proceed` every time;
(2) the chunk bytes are read into `let _data: &[u8]` at :337 and never looked at; (3) the frozen
`ContentChunk` POD carries **no `plane_key` and no `container`**, which is exactly the pair the
working sibling `gate_decide` uses to select a real gate set (`dispatch.rs:479-484`,
`app.plane_gates(plane_key).and_then(|g| g.get(container))`). So the slot's only reachable `Block`
paths are a stale `HostCtx`, a null chunk, and a caught panic — never an operator's policy.
`vtable.rs:71` nonetheless publishes it as a WIRED capability slot under the module claim that
"every slot is wired — ZERO `unimplemented!()` stubs remain", and the suite proves the
`Reject -> Block` mapping only by calling the private `gate_scan_inner` with a set the shipped
entry point cannot produce.
ACTION:    This needs an ABI decision before it needs code: `ContentChunk` must carry the
           `(plane_key, container)` selector (a POD minor bump) before the host can resolve a gate
           set for a chunk. Until it does, `vtable.rs`'s "every slot wired" sentence must be
           corrected to name `gate_scan` as declared-but-inert, so the next reader does not take the
           table at its word.

### X-1105 · the plane, not the host, decides whether an egress may reach a private address or a plaintext endpoint
CLASS:     auth
CERTAINTY: VERIFIED
EVIDENCE:
```
$ sed -n '77,89p' crates/busbar-kernel/src/plane_host/egress.rs
// `allowlist_scope` is "the host-defined allowlist scope this egress is checked against" — so the
// host, not the plane, decides whether a scope may reach a private/loopback or plaintext endpoint.
// These convention bits are read directly; resolving the scope id against operator config is not yet
// wired. The guard stays FAIL-CLOSED by default: a scope of 0 reaches neither.
const SCOPE_ALLOW_PRIVATE: u32 = 1 << 0;
const SCOPE_ALLOW_PLAINTEXT: u32 = 1 << 1;
$ sed -n '276,279p' crates/busbar-kernel/src/plane_host/egress.rs
        allow_private: scope & SCOPE_ALLOW_PRIVATE != 0,
        allow_plaintext: scope & SCOPE_ALLOW_PLAINTEXT != 0,
$ /usr/bin/grep -n "d.allowlist_scope" crates/busbar-kernel/src/plane_host/egress.rs
1340:            EgressKind::OneShot => open_http(scope, d, d.allowlist_scope, out),
```
`d` is the `EgressDesc` the CALLER handed over the ABI. For an in-core caller the bits are built
from a core-owned `FetchSpec` (`egress/seam.rs:118`, `scope_bits(spec.allow_private,
spec.allow_plaintext)`) and the model holds. For a dropped-in plane — the entire point of the hot
seam — the plane fills the POD itself, and the host honours the bits verbatim because, in the file's
own words, the scope id is never resolved against operator config. The comment states the intended
invariant and the code implements its inverse. Mitigation that keeps this off the critical list: the
cloud-metadata refusal in `net_guard` is unconditional and cannot be waived by a scope bit
(`egress.rs:85-86` says so, and `net_guard.rs:47` re-exports the one judge).
ACTION:    Resolve `EgressDesc::allowlist_scope` against operator config host-side before reading
           the bits — the plane names a scope ID, the HOST looks up what that scope is permitted —
           or, if that lookup is out of reach for 1.6.0, mask the plane-supplied bits to 0 for any
           caller the host did not build the desc for, so the fail-closed default actually applies to
           the callers it was written for.

### X-1106 · `TEST_BUILTIN_DECLS` restates `busbar_llm::DECLS`' order by hand, and nothing pins the two together
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:
```
$ /usr/bin/grep -rn "TEST_BUILTIN_DECLS" --include='*.rs' crates/
crates/busbar-kernel/src/proto/registry.rs:97:    test_builtins::TEST_BUILTIN_DECLS
crates/busbar-kernel/src/proto/tests/registry_builtins.rs:26:pub static TEST_BUILTIN_DECLS: &[&ProtocolDecl] = &[
$ sed -n '188,223p' crates/busbar/src/main.rs
    installed.extend_from_slice(busbar_llm::DECLS);      <- production takes the slice WHOLE
    installed.push(&busbar_mcp::PROTO_DECL);
```
The fixture spells the six dialects out one by one (`&busbar_llm::anthropic::DECL`,
`::openai_chat::DECL`, `::gemini::DECL`, `::bedrock::DECL`, `::openai_responses::DECL`,
`::cohere::DECL`) and its own header calls the order *"the same sequence the composition root
installs in production"*. Two references to the symbol exist in the whole workspace — the definition
and the one reader — so there is no assertion anywhere tying the hand-written order to the slice
production actually installs. The order is not cosmetic: `proto/mod.rs:281-289` records that
`telemetry` indexes its per-protocol metric families by POSITION in the derived list, and
`config_validate` renders its "must be one of:" tail in the same order. Reorder `busbar_llm::DECLS`
or add a dialect and core's entire test binary keeps measuring the old order while the binary ships
the new one.
ACTION:    Build the fixture FROM the slice instead of beside it — `TEST_BUILTIN_DECLS` as a
           `LazyLock<Vec<&ProtocolDecl>>` over `busbar_llm::DECLS` then `&busbar_mcp::PROTO_DECL` —
           or, minimally, add a test asserting `TEST_BUILTIN_DECLS[..6]` is pointer-equal to
           `busbar_llm::DECLS`.

### X-1107 · `verify_decide_due`'s doc names two callers in a module this crate does not have, and its `operator_sync` argument is dead on every live path
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:
```
$ sed -n '278,281p' crates/busbar-kernel/src/plane_host/trust.rs
/// `reverify::due`. The plane's a2a re-verify job (`crate::a2a::verify::reverify_once`) and the
/// operator `sync` verb (`crate::a2a::verbs::sync`) funnel through here, so the a2a plane never
/// reaches `crate::trust::reverify::due` itself post-extraction — only this host veneer does.
$ /usr/bin/grep -rnE "^\s*pub? *mod a2a" --include='*.rs' crates/busbar-kernel/src | wc -l
0                                  (POSITIVE CONTROL: "^\s*pub mod plane;" -> 1)
$ /usr/bin/grep -rn "verify_decide_due" --include='*.rs' crates/
... the only call is crates/busbar-kernel/src/plane_host/trust.rs:327, inside verify_decide_q
$ /usr/bin/grep -rn "reverify::due" --include='*.rs' crates/busbar-a2a/src
crates/busbar-a2a/src/a2a/verify.rs:330:    let due = reverify::due(     <- calls the primitive DIRECTLY
crates/busbar-a2a/src/a2a/verbs.rs:293:    let due = reverify::due(      <- calls the primitive DIRECTLY
```
Both halves of the doc's claim are false: `crate::a2a` is not a module of `busbar-kernel` (the plane
was extracted to `busbar-a2a`), and the two functions it names bypass the veneer entirely —
`busbar-a2a/src/a2a/verify.rs:327` even says so, calling this veneer *"the retired
`verify_decide_due`"*. Consequence beyond the prose: the sole surviving caller is `verify_decide_q`
at :327, which hardcodes `operator_sync = false`, so the `operator_sync` parameter is dead and the
`Due::OperatorSync` arm is unreachable through the host seam. A fourth argument no live call can
vary is an argument that stopped being a decision.
ACTION:    Rewrite :277-283 to say what is true (the veneer serves the FFI `verify_decide` slot and
           nothing else) and drop the `operator_sync` parameter, or restore a caller that passes
           `true`. Same sweep should catch the sibling stale reference at
           `crates/busbar-kernel/src/governance/signing.rs:196` — OUT OF THIS SLICE, see below.

### X-1108 · a broken intra-doc link to `crate::a2a::pin::CardPin`, in a repo with no rustdoc gate to catch it
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:
```
$ sed -n '69,73p' crates/busbar-kernel/src/trust/declared.rs
    /// ruling: A2A names it out loud ([`crate::a2a::pin::CardPin::Unpinned`]) so a registration list
$ /usr/bin/grep -rnE "^\s*pub? *mod a2a" --include='*.rs' crates/busbar-kernel/src | wc -l
0
$ /usr/bin/grep -rn "cargo doc\|RUSTDOCFLAGS\|broken_intra_doc_links" .github/workflows/ xtask/src/ scripts/
(no output)
POSITIVE CONTROL for that grep
$ /usr/bin/grep -rln "cargo clippy" .github/workflows/ | head -3
.github/workflows/sched-monthly-refresh.yml
.github/workflows/release-stage.yml
.github/workflows/plugin-ci.yml
$ /usr/bin/grep -n "rustdoc\|broken_intra" crates/busbar-kernel/src/lib.rs Cargo.toml
(no output — the lint is neither allowed nor denied anywhere)
```
`[`…`]` is intra-doc-link syntax, not a code span, so rustdoc would emit `unresolved link` for it —
except that nothing in the 29 workflow files, in `xtask`, or in `scripts/` ever runs rustdoc. The
defect and the missing instrument are one finding: a neutral crate's public rustdoc names a plane
module that does not exist, and there is no command in this repo that can return a NO about it.
ACTION:    Two edits. (1) Replace the link with a plain code span (or point it at
           `busbar_a2a::a2a::pin::CardPin`, which does exist) here and at `governance/signing.rs:196`.
           (2) Add a `doc-links` job — `RUSTDOCFLAGS="-D warnings -D rustdoc::broken_intra_doc_links"
           cargo doc --workspace --no-deps` — to `ci.yml`. Until (2) lands, (1) is unenforced and will
           recur; this crate is 175k lines of heavily cross-referenced prose.

### X-1109 · `PlaneBuildInput` is an LLM-plane-shaped DTO living in core, and it carries a rate-card-derived price as an `f64`
CLASS:     customer-surface
CERTAINTY: PARK
EVIDENCE:
```
$ sed -n '4,8p' crates/busbar-kernel/src/plane_host/build_input.rs
//! THE NEUTRAL LLM-RUNTIME BUILD CARRIER (1.6.0 money-path Phase 3-4 C) — the single-compiled DTO
//! `busbar-core`'s `appbuild` populates from the already-resolved `RootCfg` and hands to the LLM
//! plane's `build_runtime` seam ...
$ sed -n '175,177p' crates/busbar-kernel/src/plane_host/build_input.rs
    /// The member's rate-card-derived cost per Mtok, resolved core-side (the plane has no rate card).
    pub cost_per_mtok: Option<f64>,
$ /usr/bin/grep -rn "cost_per_mtok" --include='*.rs' crates/ | wc -l
40   (declared also at crates/api/src/hooks.rs:146 and crates/busbar-kernel/src/hooks/wire.rs:577 — the PLUGIN ABI)
```
Two distinct things, one row because they live in one struct and one owner ruling settles both.
(a) The type names are neutral (`PlaneBuildInput`, `LaneInput`, `PoolInput`) but the SHAPE is one
plane's — lanes, pools, models, providers, upstream models, reasoning budgets, max output tokens —
and the module doc and the struct doc both name the LLM plane as the consumer. Under DECISIONS #1
("Core names ZERO plane types") the question is whether a structurally plane-specific carrier in a
`Family::Neutral` crate is a violation or an accepted transitional seam; that is an owner call, not
an agent's. (b) `cost_per_mtok` is a PRICE — the doc says rate-card-derived — carried as `f64`,
against PART 0's "Integer-only, unitless, no floats" and #42/#43's "a price is the answer to a
question, never a fact in a row". It is used as a RANKING signal (`cheapest`), not as a billed
amount, which is the argument for it; it is also already frozen into the plugin ABI at
`crates/api/src/hooks.rs:146`, which makes changing it a billed-byte decision.
ACTION:    Owner ruling. If the f64 ranking signal stands, write the exemption down beside the field
           (why a price on the ranking path is not a money byte) so the next auditor does not
           re-raise it. If it does not, the integer successor has to move in lockstep across
           `busbar-api`, `hooks-ranking`, `busbar-kernel/src/hooks/wire.rs` and this carrier, and
           `#46`'s "empty/unknown price ⇒ sorted LAST, never 0" has to be re-proven on the new type.

### X-1110 · the plane-host egress hop ignores `limits.upstream_request_timeout_secs` and uses a fixed 30s
CLASS:     config
CERTAINTY: VERIFIED
EVIDENCE:
```
$ sed -n '68,72p' crates/busbar-kernel/src/plane_host/egress.rs
/// One governed hop's end-to-end ceiling. Bounds `send()` so a wedged upstream cannot pin the
/// streaming task forever. Phase 2 derives this from the App's resolved upstream limits
/// ([`crate::state::UpstreamClientSettings`]); the scaffold uses a fixed, conservative ceiling.
const EGRESS_TIMEOUT: Duration = Duration::from_secs(30);
```
`upstream_request_timeout_secs` IS resolved and IS carried — `plane_host/build_input.rs:290-295`
documents it as part of the warm-client reuse key, and says a config apply that changes it "must
REBUILD the sharded upstream client so the new deadline takes effect, not silently reuse the prior
client and pin the old timeout until restart". That reasoning applies verbatim here and is not
applied: an operator who raises the timeout gets the new deadline on the LLM path and 30s on every
plane-host governed hop. A config key that one path reads and a sibling path hardcodes past.
ACTION:    Read the ceiling off `state.app`'s resolved limits inside `egress_open` (the `HostState`
           is already recovered there) instead of the module const, or document in `limits.rs` that
           the key governs the LLM upstream only and that plane-host egress has its own fixed bound.

### X-1111 · the plugin cardinality ledger is never pruned, and its reclaim function is `#[cfg(test)]`
CLASS:     missing-code
CERTAINTY: ADJUDICATE
EVIDENCE:
```
$ sed -n '112,118p' crates/busbar-kernel/src/observe.rs
/// Process-global and never pruned on its own, ... (A `prune` on config reload, the shape
/// `hooks::scrape::prune_absent` already has, is OWED for the case of an operator churning plugin
/// NAMES across reloads — the ledger would retain a dead plugin's budget for the process lifetime.)
$ /usr/bin/grep -rn "forget_cardinality" --include='*.rs' crates/
observe.rs:213 (the #[cfg(test)] definition) + 7 call sites, every one in a test module
```
This is the honest version of the pattern X-1103 is the dishonest version of: the reclaim exists, it
is `#[cfg(test)]` rather than `#[allow(dead_code)]`, and the doc at :204-210 explains exactly why
("an `allow(dead_code)` on a production function is a claim that something will use it later, which
nothing checks"). Raised because the sweep is a TODO list and this is a real one, not because the
file is misleading. Bounded by construction — plugins come from the signed directory and each holds
at most `MAX_SERIES_PER_PLUGIN × MAX_LABEL_SETS_PER_SERIES` u64 fingerprints — so it is a slow leak
under name churn, not an unbounded one.
ACTION:    Add the `prune_absent`-shaped sweep on config reload and let `forget_cardinality` lose its
           `#[cfg(test)]` and gain its production caller, exactly as its own doc prescribes.

### X-1112 · `durable_scope_stub_constructs` has no assertion
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:
```
$ sed -n '11,16p' crates/busbar-kernel/src/plane_host/tests/dispatch_tests.rs
// The durable-scope type is named by this family but exercised only through the process-lifetime
// registry the wired slots use; assert it constructs so a rider extending it stays append-only.
#[test]
fn durable_scope_stub_constructs() {
    let _ = DurableScope::new();
}
```
The comment says "assert it constructs"; the body binds the value to `_` and inspects nothing. The
only way this can return a NO is if `DurableScope::new()` panics outright. It cannot detect the
append-only regression it names.
ACTION:    Assert a property of the constructed scope (that it registers nothing, that its handle set
           is empty, that its size is what the rider expects) or delete the test — a construction
           that only has to not panic is already covered by every other test that builds one.

### X-1113 · `gate_scan` mints a fresh tokio runtime per content chunk, on the seam the <1µs budget is measured on
CLASS:     abi
CERTAINTY: ADJUDICATE
EVIDENCE:
```
$ sed -n '348,380p' crates/busbar-kernel/src/plane_host/dispatch.rs
/// ... the gate runs on a fresh current-thread runtime. Phase 2 threads the host's own runtime
/// handle here instead of minting one per scan.
fn run_content_gate(gates: &[(u16, crate::hooks::ResolvedPolicy)]) -> GateVerdict {
    ...
    match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(rt) => rt.block_on(crate::hooks::gate::decide(gates, &subject)), ...
```
The runtime is built BEFORE `decide` is called, so the empty-gate early-out (X-1104) does not save
it: every `gate_scan` call on a streaming path pays a full `tokio::runtime::Builder::build()`.
DECISIONS PART 3 §2 sets a sub-microsecond budget for the hot seam and `benches/plane_host_vtable_perf.rs`
asserts a p50/p99 delta under 1µs — a per-call runtime construction is orders of magnitude over that,
and the bench does not exercise this slot. Marked ADJUDICATE rather than VERIFIED because I did not
measure it; the code shape is not in dispute, the budget breach is inferred from it.
ACTION:    Fold into the X-1104 fix: when `gate_scan` gets a real gate set it must also get the host's
           runtime handle (as `gate_decide_over` already does via `spawn_blocking`), not mint one.
           Until then, keep the empty-set early-out BEFORE `run_content_gate`, so the shipped slot
           does not pay for a gate it cannot run.

### X-1114 · `hook_envelope_metrics_are_carried_but_not_folded` asserts nothing
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:
```
$ sed -n '255,266p' crates/busbar-kernel/src/tests/observe_tests.rs | /usr/bin/grep -cE 'assert|expect|panic|unwrap'
1                 <- and that one hit is the word "panic" inside the comment "// Must not panic, must not emit."
POSITIVE CONTROL (the neighbouring test body, same command)
$ sed -n '230,254p' crates/busbar-kernel/src/tests/observe_tests.rs | /usr/bin/grep -cE 'assert|expect|panic|unwrap'
2
```
`KernelPluginObserver::observe` returns `()` (`observe.rs:245-250`), so the call's result cannot be
inspected even in principle, and the test never installs a local recorder to prove the ABSENCE of
emission — which is the whole claim in its name. The mechanism it says it cannot use
(`metrics::with_local_recorder`) is used two files over in the same test binary
(`src/tests/metrics_tests.rs:568,579`). A regression that started folding hook-kind metrics — the
exact freeze this test guards — passes it unchanged.
ACTION:    Install a local recorder, call `observe` with the HOOK kind, and assert the recorder saw
           zero samples; that is the NO this test was written to produce.

### X-1115 · `tests/mask.rs` is the sole consumer of `mask::FixedScratch`, which its own source labels DEAD
CLASS:     missing-code
CERTAINTY: VERIFIED
EVIDENCE:
```
$ /usr/bin/grep -rn "FixedScratch" --include='*.rs' crates/ | wc -l
21
$ /usr/bin/grep -rn "FixedScratch" --include='*.rs' crates/ | /usr/bin/grep -v "crates/busbar-kernel/src/mask.rs"
crates/busbar-kernel/tests/mask.rs:12:use busbar_kernel::mask::FixedScratch;
crates/busbar-kernel/tests/mask.rs:218,236,255:    let mut fixed = FixedScratch::new();
$ sed -n '78,79p' crates/busbar-kernel/src/mask.rs
/// DEAD — see the module docs. There is no free. There is only [`FixedScratch::reset`] ...
```
`src/mask.rs:4,9-14` records that `FixedScratch` is the pre-DECISIONS-#41 allocator superseded by
`crate::scratch::ScratchPad` and "should be deleted once that cutover lands". The cutover HAS landed
— `ScratchPad` is live and has its own suite at `crates/busbar-kernel/tests/scratch.rs`. What keeps
the dead type compiling is this test file: three of its test functions are the only construction
sites left in the workspace. A test that exists to keep dead code alive is a capability that does not
ship being counted as one that does.
ACTION:    Delete `FixedScratch`, `FixedScratchFull`, `FIXED_SCRATCH_BYTES` and the three test
           functions in `tests/mask.rs` that drive them (the rest of `tests/mask.rs` tests
           `CredentialSlab` and stays). Route this through the DELETE-LIST rather than doing it here.

### X-1116 · the core trust-verify suites contain no refusal case — the NO lives only in the plane crates
CLASS:     instrument-blind
CERTAINTY: ADJUDICATE
EVIDENCE:
```
$ sed -n '4,12p' crates/busbar-kernel/src/trust/tests/verify_tests.rs
//! ... The fail-closed REFUSAL is a plane integration property ... and is proven on each plane
//! consumer's own request path; here we prove the load-lever the spec turns on.
$ sed -n '8,12p' crates/busbar-kernel/src/trust/tests/verify_edge_tests.rs
//! ... Nothing here is a protocol fact ...
```
Sub-audit read both files in full: every assertion in `verify_tests.rs` is on
`fetches.load(SeqCst)` counts; `verify_edge_tests.rs`'s nearest-to-refusal case is the
backwards-clock refetch at :153-164, a freshness-timing property. Neither contains a bad-signature,
expired-cert, wrong-key or wrong-subject case. The refusals DO exist — verified at
`crates/busbar-a2a/src/a2a/tests/{verify_tests,jws_tests,inbound_jws_tests}.rs` and
`crates/busbar-mcp/src/mcp/tests/callerask_tests.rs` — so this is a documented split, not an absent
check. Raised as ADJUDICATE because the split means `busbar_kernel::trust::verify` has no
crate-local proof that it refuses anything, and the plane crates that hold that proof are exactly
the things 1.6.0 is making droppable: delete every plane and the kernel's verify path keeps a green
suite with no refusal in it.
ACTION:    Owner/architect call on whether a neutral crate may delegate its own fail-closed proof to
           a droppable plugin. If not, add one crate-local negative (a forged artifact that
           `VerifyGate` must refuse) so the kernel's verify keeps a NO of its own after the plane
           fold. Note the same question applies to the `plane-delete-test --all` posture.

### X-1117 · `taxonomy.rs` names `main.rs` as a consumer of items `main.rs` cannot reach
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:
```
$ sed -n '4,8p' crates/busbar-kernel/src/taxonomy.rs
//! `busbar_kernel::proto`, so every caller of the admin surface and every plugin's error
//! surface draw from the same vocabulary instead of each keeping its own copy. `main.rs`
//! references them via `crate::taxonomy::ERR_TYPE_*`.
$ /usr/bin/grep -n "pub(crate) const ERR_TYPE" crates/busbar-kernel/src/taxonomy.rs
20:pub(crate) const ERR_TYPE_NOT_FOUND: &str = ...
21:pub(crate) const ERR_TYPE_INVALID_REQUEST: &str = ...
$ /usr/bin/grep -rn "crate::taxonomy::" --include='*.rs' crates/
ingress/dispatch.rs:42,52,143 | ingress/arrival_host.rs:90 | router.rs:80 | tests/tests.rs:466,496,518
```
The consts are `pub(crate)` to `busbar-kernel`; `crates/busbar/src/main.rs` is a different crate and
cannot name them, and does not. The real consumers are the three the SECOND paragraph of the same
doc lists correctly (`ingress::dispatch`, `ingress::arrival_host`, `router`). One sentence survived a
crate split that made it impossible. Small, but it is the class: a doc that tells the next reader
where a symbol is used, wrongly.
ACTION:    Delete the "`main.rs` references them" sentence; the paragraph below it already states the
           truth.

## TALLY
```
files in slice:  155      (= wc -l < /Users/matthew/Developer/GetBusbar/.sweep/S02-kernel-b.txt)
verdict lines:   155
CLEAN:           138
FINDING:          17      rows raised: 18   (X-1100 .. X-1117; X-1104 and X-1116 each span two files)
DELETABLE:         0
UNREADABLE:        0
```
Row census by class: money 1 (X-1100) · auth 2 (X-1102, X-1105) · instrument-blind 5 (X-1101, X-1104,
X-1112, X-1114, X-1116) · missing-code 3 (X-1103, X-1111, X-1115) · drift 4 (X-1106, X-1107, X-1108,
X-1117) · config 1 (X-1110) · abi 1 (X-1113) · customer-surface 1 (X-1109).
By certainty: VERIFIED 13 · ADJUDICATE 4 · PARK 1.

## WHAT THIS SLICE PROVES ABOUT FILES OUTSIDE IT — reported, not acted on

1. **`crates/busbar-kernel/src/governance/signing.rs:196`** carries the same broken intra-doc link
   as X-1108: ``[`crate::a2a::sign::CARD_SIGNING_DOMAIN`]`` in a crate with no `mod a2a`
   (`grep -rnE "^\s*pub? *mod a2a" crates/busbar-kernel/src` -> 0). Fix it in the same pass.
2. **There is no rustdoc job anywhere in this repository.**
   `grep -rn "cargo doc\|RUSTDOCFLAGS\|broken_intra_doc_links" .github/workflows/ xtask/src/ scripts/`
   returns nothing across all 28 workflow files (`ls .github/workflows/*.yml | wc -l` -> 28) (control: `cargo clippy` is present in 3+ of them).
   Every intra-doc link in 175k lines of `busbar-kernel` prose is unmeasured. This is a CI gap, not a
   kernel-b file.
3. **`crates/busbar-kernel/src/plane_host/mod.rs:13-15`** (NOT in this slice — mine starts at its
   submodules) states *"ADDITIVE and UNUSED: nothing in the engine calls the plane seam yet."* It is
   false: `plane/auditlog.rs:146,870,992,1071` and `calllog.rs:177,194,987,1051` call
   `with_dispatch_scope` on production paths. The sentence should go before someone trusts it while
   deciding what is safe to change.
4. **`crates/busbar-kernel/src/trust/mod.rs:4-11,20-22`** describes a `busbar_substrate_values::trust`
   glob re-export that no longer exists (`grep -n busbar_substrate crates/busbar-kernel/src/trust/mod.rs`
   -> no match); the types are defined in-file under a "merged from busbar-substrate" banner. Stale
   prose, live code. Note: `trust/tests/genericity_tests.rs:229` does `include_str!("../mod.rs")` and
   scans it — the instrument is sound, it is scanning the right file.
5. **`crates/busbar-kernel/Cargo.toml`** (not in this slice) still declares a `plane-voice` feature and
   a `busbar-voice` edge. PART 0 of the spec is explicit that the fourth plane is **streaming**, not
   voice, and `crates/busbar-plane-streaming` exists alongside `crates/busbar-voice`. Every consumer
   of the metering-lease seam in X-1100/X-1102 is `busbar-voice`. Whichever crate survives the rename
   owns those money rows.
6. **`crates/hooks-ranking/src/lib.rs:168`** ranks `cheapest` by `rank_ascending_by(candidates, |c|
   c.cost_per_mtok)`. DECISIONS #46 requires "empty/unknown price ⇒ sorted LAST, never 0". Whether
   `None` sorts last in that helper is worth one grep by whoever owns S17 — it is adjacent to X-1109
   but the code is out of my slice and I did not verify it.
7. **`crates/busbar/src/root/tests/kernel.rs:573,577` and `crates/busbar-kernel/src/governance/tests/tests.rs:5324`**
   assert on SOURCE TEXT (`body.contains("install_rate_apply")`,
   `body.contains("effective_from_at(crate::store::now_ms())")`). Those instruments go red on a
   reformat and stay green on a behavioural regression. Out of slice; flagging the shape.

## NOTES ON THE SWEEP ITSELF

- `crates/busbar-kernel × plane` is a ratchet row in `qa/kind-isolation.toml:1219` at **3047**, so
  plane/vendor vocabulary in this crate is known, measured debt. I did not raise 3047 rows. I measured
  V per file (the table) and raised a row only where a plane noun is load-bearing rather than prose:
  X-1109 (an LLM-shaped DTO in core) and X-1107/X-1108 (references to a plane module that does not
  exist). The single production site naming vendor dialects, `proto/mod.rs:253-258`, is behind
  `#[cfg(any(test, feature = "test-support"))]` and is CLEAN.
- Every "0" in this report carries its control. Two false zeros were caught and corrected mid-sweep:
  zsh does not word-split an unquoted `$var` in a `for` loop (the first per-file scan silently passed
  all 155 paths as ONE argument and returned `0`), and `grep -i OWED` matches `allowed`/`borrowed`.
- Nothing in this slice was edited. No golden, no `accepted-differences.json`, no `qa/*.toml` ratchet,
  and no `openapi.json` was touched or regenerated.
