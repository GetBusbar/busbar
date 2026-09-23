# P04-prior — sweep of the 83 files mentioned-but-never-verdicted by the prior corpus

Slice: P04-prior. X-id block: X-3300..X-3399 (58 used, X-3358..X-3399 unused).
Method: for every file, first `git grep -n -- '<path>' docs/design/1.6.0-*.md` to find what the
prior corpus actually said, then judged whether that was a command-backed verdict or a bare
mention. Bare mentions were swept fresh (read the file, grep production callers workspace-wide
excluding `tests/`, `_tests.rs`, `tests.rs`, `test_support/`, `fixtures/`, `benches/`, `conformance/`,
`testing/`). Every "zero production callers" claim below was produced by a single combined
`git grep -nw -e sym1 -e sym2 …` run over `crates xtask` (recorded at
`/tmp/p04/allsym_hits.txt` during the session) plus per-symbol follow-up greps quoted inline.

## Legend for reused prior evidence
- **file-verdicts.md** — dual-oracle reachability sweep (`cargo` dep-info witness + module-graph
  BFS from every real root), LIVE/TEST/ORPHAN/DUPLICATE/HALF-MIGRATED verdicts, each with its own
  command.
- **unconstructed-sweep.md** — census of symbols with zero production construction sites (own
  python-census + `git grep`, "HOW EVERY ZERO WAS CONTROLLED" section, four independent controls).
- **config-surface.md** — WIRED/DECLARED-NOT-READ classification per config key, cell citations.
- **money-sweep.md** — `f64`-on-money-path and unconstructed-money-cell findings, each a `git grep`
  count plus a read.
- **branch-sweep-ledger.md "Agent 6" (A6-1..A6-9)** — re-verified, corrected several prior
  HARVESTED/CLEAN verdicts to GAP after re-reading trunk; cites exact current line numbers.

| FILE | VERDICT | EVIDENCE | ROWS |
|---|---|---|---|
| crates/busbar-mcp/src/mcp/client/egress.rs | FINDING | file-verdicts.md:1366 LIVE (dep-info witness). secret-hygiene.md:98/276 cite this file's `Redacted<String>` wrapping as CLEAN (already-correct). unconstructed-sweep.md #170 `CallerContext` struct, 4 test call sites/0 prod (table@275); I re-verified with `git grep -nw CallerContext -- crates xtask`: only declaration, its own doc comment, and `tests/{no_key_passthrough,surface}_tests.rs`. Read `egress.rs:102-106`: struct is `#[allow(dead_code)]` and its own doc says *"Built by the CONNECT path, which has no verb yet: `mcp::upstream` passes the caller's `VirtualKey` straight to `authorise_tool_egress` instead of assembling one of these."* Declared, documented, compiler-warning-suppressed, never constructed outside tests — the file names its own bypass. | X-3300 |
| crates/busbar-mcp/src/mcp/client/issue.rs | FINDING | file-verdicts.md:1368 LIVE (file-level reachability only). Read `issue.rs:80-91` directly: `#[allow(dead_code)] pub(crate) async fn issue(...)` — the module's own doc calls this "the ONE governed path every method busbar issues to an upstream travels... So: ONE function, `issue`. Every verb goes through it." `wire.rs:170`'s comment states plainly: "Called from `super::issue::issue`, which has no inbound caller yet." `verb.rs:80-91` is explicit about the scope: `ToolsCall` (the money-critical `tools/call` verb) is wired separately via `super::jsonrpc::tools_call` on the real dispatch path — that one is live. The other 21 verbs are "reached today only from the batteries in `tests/stdio_client_leg_tests.rs`, because busbar's own FRONT DOOR does not yet expose a `prompts/list` that proxies through to an upstream's" — governed, audited, proven against a real child process, and genuinely uncalled in production. Separately, LEDGER.md BR-S12 (line 1034) flags three narrower security claims about this same under-exercised path (SSRF-refusal audit-trail accuracy, secret-source non-disclosure, oversized-token-body handling) as "NOT opened line-by-line... verify before acting" — `classify_send_failure` confirmed absent (`grep -n classify_send_failure issue.rs`). | X-3301 |
| crates/busbar-mcp/src/mcp/client/jsonrpc.rs | FINDING | file-verdicts.md:1369 LIVE. unconstructed-sweep.md #171-173: `InputRequiredLoop` (struct), `may_satisfy`, `wire_bytes` — all test-call-sites-only (8/14/13 sites, all in `tests/ask_tests.rs`, `tests/no_key_passthrough_tests.rs`, `tests/wire_tests.rs`). I confirmed the ONE governed dispatch path, `client/issue.rs`, calls `super::jsonrpc::parse_response` and never `wire_bytes`/`InputRequiredLoop`/`may_satisfy` (`git grep -n 'wire_bytes\|InputRequiredLoop' crates/busbar-mcp/src/mcp/client/issue.rs` → no hits). The ask-loop retry apparatus is built and tested, never reached from production dispatch. | X-3302 |
| crates/busbar-mcp/src/mcp/client/mod.rs | FINDING | file-verdicts.md:1370 LIVE. unconstructed-sweep.md #174-175: `McpClientEngine` (struct, 6 test sites)/`deregister` (2 test/3 docs). Read `client/mod.rs:190-197`: `#[allow(dead_code)] impl McpClientEngine` bundles registry+catalogue+pool behind `register`/`deregister`/`registration`. `git grep -n 'mcp::client::' crates/busbar/src` → 0 hits (never referenced from the composition root). Production instead builds the collaborators directly: `crates/busbar-mcp/src/mcp/mod.rs:293-319` constructs `client::pool::McpConnectionPool` and `client::catalogue::CatalogueCache` as separate `AppState` fields, bypassing the bundling type entirely. A tested, `#[allow(dead_code)]`-marked orchestration wrapper the real system reimplements a different way. | X-3303 |
| crates/busbar-mcp/src/mcp/client/ssrf.rs | CLEAN | file-verdicts.md:1373 LIVE. unconstructed-sweep.md #176 flagged `check_addresses` as test-call-sites-only (12 sites). Read `client/ssrf.rs:255-263`: the function carries its OWN comment — `// NO PRODUCTION CALLER: the pin path judges through busbar_kernel::net_guard directly, which is the whole point of the unification. This stays because the MCP refusal SUITE drives every range... Deleting it would trade a wording regression for a dead-code warning.` `#[cfg_attr(any(not(test), not(feature = "test-support")), allow(dead_code))]` is production-conditional. The real guard is wired: `pool.rs:282` calls `ssrf::pin_upstream` → `net_guard::resolve_and_pin`. Confirmed by reading, not a gap. | - |
| crates/busbar-mcp/src/mcp/client/tests/peer_tests.rs | CLEAN | file-verdicts.md:1387 TEST (test-root reached, prod paths=0 as expected for a test file). branch-sweep-ledger.md:1199 is about a DELETED branch (`origin/delete/keep-mcp-fix`), ADJUDICATE-level, no trunk defect asserted. No independent finding. | - |
| crates/busbar-mcp/src/mcp/client/transport.rs | FINDING | file-verdicts.md:1399 LIVE. LEDGER.md ENG1 (line 662) + map-proof.md:2774 (re-checked 2026-09-23): SSE grammar bug, `.lines()` does not split on a bare CR. I re-verified live: `grep -n '\.lines()' crates/busbar-mcp/src/mcp/client/transport.rs` → still hits at `:416` and `:454`. Also unconstructed-sweep.md #177 `progress_frames` (1 test site, `mcp/tests/sse_tests.rs:342`) — minor, test-only. | X-3304 |
| crates/busbar-mcp/src/mcp/config.rs | FINDING | file-verdicts.md:1402 LIVE. config-surface.md rows for `tools.<s>.*` mostly WIRED (real evidence, CLEAN for those keys). LEDGER.md S23 (line 340): `effective_upstream_credentials` (config.rs:988) "exists with exactly one caller: a test" — operator's section-level `tools.upstream_credentials:` default is silently dropped for every server that doesn't repeat it entry-level; corroborated independently by local-only-audit.md G5/D22 (`catalogue.rs:1192` builds `UpstreamPosture` entry-level only, `#[allow(dead_code)]` on `effective_upstream_credentials`). unconstructed-sweep.md #178 `effective_hooks` (config.rs:982) also test-call-sites-only. | X-3305 |
| crates/busbar-mcp/src/mcp/connect.rs | FINDING | file-verdicts.md:1403 LIVE. unconstructed-sweep.md #179 `overlay_patch` (connect.rs:495), 2 test call sites (`mcp/tests/connect_tests.rs:209,257`), 0 production. Confirmed via the combined grep — no non-test caller. | X-3306 |
| crates/busbar-mcp/src/mcp/method.rs | FINDING | file-verdicts.md:92,218,1407 DUPLICATE (`tap_join_verdict` at method.rs:2519 and busbar-a2a/receive.rs:1096, plus "8 of 63 top-level symbols already exist in busbar-plane-mcp" — half-migrated). LEDGER.md GS29 (line 513): `structure-lint:plane-dup:unledgered` RED, `cargo xtask gate structure-lint` 2026-09-23 → "36 row(s), RED" — a live gate failure. Separately, LEDGER.md/local-only-audit.md G4 (money): `charged_at: 0` at production call site `method.rs:1261` — I read it directly (`sed -n '1255,1265p'`) and confirmed the literal `charged_at: 0,` is live; `governance/state.rs:1861-1893` documents `window_start == 0` as the special ALL-TIME budget cell, never aged/rolled. Every MCP `tools/call` therefore keys one window that never resets. Not previously promoted to a numbered LEDGER row for the MCP side (only found in `docs/design/1.6.0-local-only-audit.md`'s branch-sweep notes) — the twin at `busbar-a2a/src/a2a/receive.rs:897` is OUTSIDE this slice and carries the identical bug. | X-3307, X-3308 |
| crates/busbar-mcp/src/mcp/sampling.rs | CLEAN | RE-GRADED BY THE SECOND PASS (see "CORRECTION to X-3309"). LEDGER.md M27's "no size bound" is false at HEAD: `grep -n 'MAX_SAMPLING' crates/busbar-mcp/src/mcp/sampling.rs` -> all four bounds declared (`:214,222,226,227`) AND enforced on the live path (`:248,261,304,360`); `temperature` range-checked `0.0..=2.0` at `:343`. `satisfy_upstream_ask` has real production callers (`method.rs:1954`, `tasks.rs:925`). X-3309 withdrawn; M27 should be closed. | - |
| crates/busbar-mcp/src/mcp/tests/calllog_dispatch_tests.rs | FINDING | file-verdicts.md:1420 TEST. LEDGER.md GS32 (line 516) + gate-sweep.md:647,907: a PRIVATE duplicate `fn example_store_cdylib()` at `calllog_dispatch_tests.rs:138` that "deliberately does not build and asserts", while `busbar-kernel/src/test_support/plugin_store.rs:80` builds the fixture on demand. Consequence per GS32: "the four failures are the durable-record tests through a real `dlopen`ed store plugin... unless somebody built a cdylib by hand first" — an instrument that silently no-ops rather than exercising the real plugin boundary. Still present (both `fn example_store_cdylib` declarations read at HEAD per the ledger's own 2026-09-23 re-check). | X-3310 |
| crates/busbar-mcp/src/mcp/upstream.rs | FINDING | file-verdicts.md:1465 LIVE. local-only-audit.md (line 2171, "New"): a secret source leaked in a refusal at `upstream.rs:409`. unconstructed-sweep.md #180 `authorise_verb` also test-call-sites-only (1 site) — minor, folded into the same row. | X-3311 |
| crates/busbar-mcp/src/record.rs | FINDING | file-verdicts.md:220,1466 DUPLICATE (`encode`/`decode` implemented once per plane, twin `busbar-a2a/src/record.rs`, flagged `yes`). unconstructed-sweep.md #181 `from_journal_body` (record.rs:80) test-call-sites-only; I confirmed independently: `git grep -n from_journal_body -- crates \| grep -v tests` → only the file's own doc comments and the `pub fn` itself, zero production readers. The file's own comment (`record.rs:54-56`) calls this "the actual reader" of a call-log journal body — a durable-record reader that exists, is tested (`tests/record_tests.rs`, `calllog_dispatch_tests.rs`), and has no production caller reading a stored record back. | X-3312 |
| crates/busbar-oauth2/src/cimd.rs | FINDING | file-verdicts.md:1471 LIVE. LEDGER.md GS11 (line 400) + gate-sweep.md:342,975: `kind-isolation:control-path` gate RED at `cimd.rs:{121,122,134,143,170}`, each naming `egress` — "a control surface has no upstream to reach." I re-verified the 5 line numbers still say what the gate claims: `awk 'NR==121||...'` → all 5 are `busbar_kernel::egress::engine::{build_client,EngineSpec,request,send_bounded,HOP_DEADLINE_CAUSE}` calls. Reading the surrounding code (`cimd.rs:115-175`) shows a fully-wired, capped, deadline-bound fetch — LEDGER's separate CLEAN entry (line 732) independently confirms the SSRF guard itself is present and "STRONGER than the branch." The gate's structural complaint (kind-isolation naming convention, not the fetch's correctness) is unresolved; cited as-is, not re-derived. | X-3313 |
| crates/busbar-plane-a2a/src/a2a/anomaly.rs | FINDING | file-verdicts.md:1485 LIVE. money-sweep.md M-22 (line 1006): `egress_spend_ratio: f64` at `anomaly.rs:105`, read at `:214,:217`. "PRODUCTION WRITERS: none. `git grep -n egress_spend_ratio -- crates/` returns the three lines above plus four test lines. The field is only ever its Default — 0.0." Consequence spelled out: an operator's `egress_budget_ratio: 1.2` never trips (`0.0 >= 1.2` false forever); an operator's `0.0` trips on every peer immediately. A money-class anomaly signal that can never fire the way it is configured to. | X-3314 |
| crates/busbar-plane-a2a/src/frame.rs | FINDING | file-verdicts.md:1491 LIVE. unconstructed-sweep.md §4C ("traits whose implementors are all in tests", line 685-686): `Transform` (frame.rs:108) and `Tap` (frame.rs:118) — both traits whose only implementors are in `tests/frame.rs:44,89`. No production type implements either trait. | X-3315 |
| crates/busbar-plane-a2a/src/lib.rs | FINDING | file-verdicts.md:1493 LIVE. unconstructed-sweep.md #182-183: `MOUNTED_ROUTE_SUFFIXES` (const, 1 test site) and `LOCAL_VERB_METHODS` (const, 2 test/1 docs). I confirmed via the combined grep: both used only from `tests/claims.rs:98` and `tests/conformance.rs:176`, zero production readers despite being `pub const`. | X-3316 |
| crates/busbar-plane-a2a/src/plane.rs | FINDING | file-verdicts.md:1496 LIVE (note: read_raw/read_str name collision, sub-threshold, not itself a finding). local-only-audit.md B50 ("doc vs code", line 1052): `plane.rs:749`'s comment claims THREE surfaces carry no credential by design (two discovery docs + the callback); I re-read `plane.rs:740-760` myself — `let open_surface = matches!(u.op(), ops::OP_PUSH_EVENT);` narrows the "open" exemption to ONLY the callback. The two discovery documents are narrowed to `Some(SchemeAlt::new("bearer"))` — they DO require a bearer credential, contradicting the comment's claim that "there is nothing to narrow" for them. Doc-vs-code mismatch on a customer-facing auth surface, still live. | X-3317 |
| crates/busbar-plane-a2a/src/records.rs | FINDING | file-verdicts.md:1497 LIVE. unconstructed-sweep.md #184 `OPERATIONS` (const, records.rs:112), 4 test/2 docs. Confirmed via combined grep: only `tests/records.rs:5,24` and `tests/conformance.rs:546` reference it. | X-3318 |
| crates/busbar-plane-a2a/src/tests/facts.rs | FINDING | file-verdicts.md:233,1500 DUPLICATE, flagged `yes`: "64% of this file's normalised bytes are top-level declarations that exist byte-identically in crates/busbar-plane-mcp/src/tests/facts.rs" (named symbols listed). | X-3319 |
| crates/busbar-plane-a2a/src/tests/records.rs | FINDING | file-verdicts.md:235,1505 DUPLICATE, flagged `yes`: "41% of this file's normalised bytes are top-level declarations that exist byte-identically in crates/busbar-plane-mcp/src/tests/records.rs." | X-3320 |
| crates/busbar-plane-a2a/tests/common/mod.rs | CLEAN | file-verdicts.md:1508 TEST (prod=0, test=3, as expected for a shared test-fixture module; note "frame" is a sub-threshold name collision, not a finding). unconstructed-sweep.md's `SessionView` cross-reference is ordinary test-fixture use of a production type, not a defect. | - |
| crates/busbar-plane-a2a/tests/conformance.rs | CLEAN | file-verdicts.md:1509 TEST. branch-sweep-ledger.md:200,228 are about deleted/superseded branches (SUPERSEDED bulk / REVIEW), not trunk defects. map-proof.md:4999 (N2) is a git-history revert-pair bookkeeping note ("the pair does not net to zero"), unrelated to this file's test content. | - |
| crates/busbar-plane-a2a/tests/frame.rs | CLEAN | file-verdicts.md:1510 TEST. This is exactly where `Transform`/`Tap` (see X-3315) ARE exercised — the test itself is fine; the finding belongs to the production trait declarations in `src/frame.rs`. | - |
| crates/busbar-plane-decision/src/codec/mod.rs | FINDING | file-verdicts.md:1514 LIVE. unconstructed-sweep.md #36 and row D.5 (line 222): `view_with_arena` (codec/mod.rs:71) — "nowhere — one occurrence in the whole tree, its own `pub fn`." Own doc claims "the arena-borrowing view the hot lane would use. Zero callers, zero tests." Confirmed via combined grep: only the declaration itself. | X-3321 |
| crates/busbar-plane-decision/src/config.rs | FINDING | file-verdicts.md:1515 LIVE. config-surface.md F1 (line 220): `decisions:` config section is "accepted, validated by nothing, and reaches nothing — DECLARED-NOT-READ, CUSTOMER-VISIBLE." Cells: `busbar-kernel/src/config/prepass.rs:105-110,130,151,175-177`, `config/mod.rs:1288-1301`, `plane/config.rs:358-372`, `busbar/root/plane_decision.rs:138,144`, `plane-decision/src/config.rs:59-77`. The decision plane IS registered but `parse_section` is `None`, so an operator's `decisions:` YAML is lifted, banked, and never lowered into the plane's typed shape. Corroborated by unconstructed-sweep.md D.4 (line 232): `DecisionsSection` "tests only." | X-3322 |
| crates/busbar-plane-decision/src/facts.rs | FINDING | file-verdicts.md:1516 LIVE. unconstructed-sweep.md #185 and D.6 (line 237): `NEVER_READ_MEMBERS` (facts.rs:51) "tests only — src/tests/facts.rs:5,13... asserted by a test and consulted by no production reader." Same root cause as X-3321/X-3323 (the whole plane is unwired). | X-3321 |
| crates/busbar-plane-decision/src/lib.rs | FINDING | file-verdicts.md:1517 LIVE. unconstructed-sweep.md D.1-D.2 (lines 241-242): `DecisionProvider` — "nowhere... `DecisionPlane::new(providers)` is only ever reached through `EMPTY = Self::new(&[])`, so the configured-provider set is structurally empty in every build, test included." `DecisionPlane` itself — "tests only... 14 sites, all under `tests/{alloc_gate,conformance,jev,purity}.rs`; zero production construction." `busbar/root/registry.rs:435-470` registers `LlmPlane`/`McpPlane`/`A2aPlane`/`StreamingPlane`/`AdminPlane` — **not** `DecisionPlane`; the root names only the type to read its `KEY` constant (`main.rs:323`). I confirmed this directly: `git grep -n DecisionPlane crates/busbar/src/root/registry.rs crates/busbar/src/main.rs` shows `main.rs:323` reads `<DecisionPlane as PlaneMeta>::KEY` only, no `planes.push(Arc::new(DecisionPlane...))` anywhere. | X-3323 |
| crates/busbar-plane-decision/src/plane.rs | FINDING | file-verdicts.md:1520 LIVE. unconstructed-sweep.md D.3 (line 247): "`impl Plane for DecisionPlane` (nine methods) + `impl SessionPlane`... Reached in production only through `PlaneDecl.build`, which is `None`." Own doc: "a complete nine-method `impl Plane` with no unit path in `root/` yet to drive it." Same root cause as X-3323. | X-3323 |
| crates/busbar-plane-decision/src/tests/config.rs | CLEAN | file-verdicts.md:1524 TEST. This is the ONLY place `DecisionsSection` is exercised (per D.4) — a legitimate, correctly-scoped unit test of dead-end config; the finding belongs to `config.rs`/`lib.rs`/`plane.rs`. | - |
| crates/busbar-plane-llm/src/claims.rs | FINDING | file-verdicts.md:1536 LIVE. LEDGER.md BR-S5 (line 1022) + local-only-audit.md B43 (line 1059): `V1_MODELS`/`V1BETA_MODELS` at `claims.rs:81,84` use `PathSeg::Tail` with no `PathSeg::Var`, so the bare `/v1/models` LISTING route matches the per-model-invoke claim and is read as an invoke of a model never named. Status: **OPEN — MERGE→consolidated/1.6.0** (fix exists on `origin/verify/keep-registry-pin`, not yet landed here). I confirmed: `grep -n 'V1_MODELS\|PathSeg::Tail' crates/busbar-plane-llm/src/claims.rs` → line 81 still reads `&[Lit("v1"), Lit("models"), Tail]`, no `Var`. Also unconstructed-sweep.md #37 `STREAM_TRANSPORT` const, nowhere-constructed (minor, folded in). | X-3324 |
| crates/busbar-plane-llm/src/dialect.rs | CLEAN | file-verdicts.md:1537 LIVE. branch-sweep-ledger.md:393 is ADJUDICATE-level about a deleted branch (`delete/keep-auth-dialect-declared`), no trunk defect asserted. Read the file: a static location-table, no parse/write logic of its own. | - |
| crates/busbar-plane-llm/tests/alloc_gate.rs | CLEAN | file-verdicts.md:1542 TEST. branch-sweep-ledger.md:1218 ADJUDICATE about a deleted branch/fixture (`.audit/alloc_gate.new.rs`), not a trunk defect. | - |
| crates/busbar-plane-mcp/src/claims.rs | FINDING | file-verdicts.md:1553 LIVE. Read the file directly (`claims.rs:1-20`): the module's OWN doc comment states, verbatim: *"This protocol's mount is CONFIGURED... the contract's claim... is a compile-time literal, read once at registration and sealed into policy. Those two facts cannot both be honoured... a deployment that configures a different path is a deployment this plane's claims do not cover... **It is a finding, it is not fixed here**, and it is the first thing the crate's notes record."* `CLAIMS` (`claims.rs:113-121`) declares `Selector::ExactPath(DEFAULT_MOUNT)` for both HTTP and SSE. Self-admitted, previously unswept (branch-sweep-ledger.md:131 only mentions a deleted branch's `claims_any` symbol — a bare mention that never engaged with this admission). | X-3325 |
| crates/busbar-plane-mcp/src/codec.rs | FINDING | file-verdicts.md:1554 LIVE. LEDGER.md GS18 (line 407) + gate-sweep.md:448,980: two MCP wire-word constants (`codec.rs:116,125`) moved from a `-codec` crate into a plane crate; `Addresses::tree()` (`xtask/.../roots.rs:87`) does not include plane crates, so the structure-lint census is structurally blind to this file — "the file's own comment predicted exactly this." Separately, LEDGER.md T23 (line 560): a live edit removing `"completion/complete"` from `IMPLEMENTED_METHODS` was observed then reverted before diff (`git diff HEAD` came back empty) — self-resolved, not counted as a live defect, noted for the record only. | X-3326 |
| crates/busbar-plane-mcp/src/facts.rs | FINDING | file-verdicts.md:240,1555 DUPLICATE (45% byte-identical with `busbar-plane-a2a/src/facts.rs`, flagged `yes`). unconstructed-sweep.md #38,186,187: `META_MEMBER` nowhere-constructed; `META_PROTOCOL_VERSION_QUOTED`/`META_PROGRESS_TOKEN_QUOTED` test-only (1 test site each, `tests/facts.rs:207,211`). Confirmed via combined grep. | X-3327 |
| crates/busbar-plane-mcp/src/jsonrpc.rs | FINDING | file-verdicts.md:241,1556 DUPLICATE (33% byte-identical with `busbar-plane-a2a/src/jsonrpc.rs`, flagged `yes`). local-only-audit.md B49 (line 1045): "result laundering" — `jsonrpc.rs:300` `success()` only stamps `resultType` `if let Some(object) = result.as_object_mut()`, so a **non-object result ships unstamped**, defeating the discriminator HEAD's own doc calls "the safety property." | X-3328 |
| crates/busbar-plane-mcp/src/ops.rs | FINDING | file-verdicts.md:1559 LIVE. local-only-audit.md B27 (lines 1905, 1050): `NOTIFICATIONS` at `ops.rs:254` is a flat `&[&str]` with no sender attribution; `plane.rs:478-488` admits any of them on ingress via `is_known_notification(method)` with no sender check — "a caller can send `notifications/tools/list_changed`" (the party being catalogued deciding when its own catalogue is re-read). Note: the harvested sibling check (`a_server_cannot_send_a_callers_method`) IS present — this is the narrower, still-open half. | X-3329 |
| crates/busbar-plane-mcp/src/records.rs | FINDING | file-verdicts.md:1562 LIVE (branch-sweep-ledger.md rows here are all ADJUDICATE/SURVIVOR about deleted branches, bare). Fresh finding, not in unconstructed-sweep.md's captured rows: `OPERATIONS` const (`records.rs:102`) — `git grep -nw OPERATIONS -- crates xtask` shows only `tests/records.rs:6,27` reference it; zero production readers. | X-3330 |
| crates/busbar-plane-mcp/tests/conformance.rs | CLEAN | file-verdicts.md:1576 TEST. branch-sweep-ledger.md:164,1219 are ADJUDICATE/SUPERSEDED about deleted branches, no trunk defect. | - |
| crates/busbar-plane-streaming/src/claims.rs | FINDING | file-verdicts.md:1580 LIVE. unconstructed-sweep.md #39 `TWILIO_TRANSPORT` const — nowhere-constructed. Confirmed via combined grep: only the declaration. | X-3331 |
| crates/busbar-plane-streaming/src/oneshot.rs | FINDING | file-verdicts.md:1584 LIVE. unconstructed-sweep.md #40 `tts_voice` fn — nowhere-constructed. Confirmed via combined grep: only the declaration, no callers anywhere including tests. | X-3332 |
| crates/busbar-plane-streaming/src/plane.rs | CLEAN | file-verdicts.md:1585 LIVE. money-sweep.md (line 1128): barge-in usage misattribution is "FIXED at `plane.rs:1121-1131`." plugin-abi-matrix.md:719: dialed-lane fix is "YES" confirmed live at `plane.rs:528-539`. Both prior findings are CLEAN confirmations, not open gaps. | - |
| crates/busbar-plane-streaming/src/register.rs | FINDING | file-verdicts.md:1586 LIVE. unconstructed-sweep.md #41,188 + line 142: `plane_for_root` (register.rs:74) and `CAP_KEY` (register.rs:66). I re-verified both myself: `git grep -n plane_for_root -- crates xtask` → exactly 2 hits, the `pub fn` declaration and its own crate's `pub use register::{plane_for_root, CAP_KEY};` re-export at `lib.rs:88` — **zero callers anywhere, not even in tests.** `git grep -n 'busbar_plane_streaming::CAP_KEY' -- crates` → only test files. Production instead constructs the plane directly: `busbar/src/main.rs:505` `StreamingPlane::new(&[])`, `busbar/src/root/registry.rs:463` `StreamingPlane::EMPTY`. `register.rs`'s own doc comment gives `units.register_units(busbar_plane_streaming::CAP_KEY, streaming_units)` as the worked example of how this plane is meant to be registered — production uses neither `CAP_KEY` nor `plane_for_root` to do it. A whole registration API, exported at the crate root with a doc example, that the composition root never calls. | X-3333 |
| crates/busbar-plane-streaming/src/session.rs | CLEAN | file-verdicts.md:1587 LIVE. branch-sweep-ledger.md:887 is about the LARGEST unlanded feature body in the whole audit (`vt13-owning-held`, a session/duplex architecture that was never built here) — a scoping decision, not a trunk defect. branch-sweep-ledger.md:2123 is a NO-GAP entry: trunk's simpler `Pending::Ingress` design is confirmed deliberate and correct via the file's own rationale comment (`session.rs:22-25`). | - |
| crates/busbar-plane-streaming/src/twilio.rs | FINDING | file-verdicts.md:1594 LIVE. unconstructed-sweep.md #42,189: `encode_mark` nowhere-constructed; `encode_media` test-only (3 sites, `tests/alloc_gate.rs:124`). Confirmed via combined grep. Note: a differently-scoped `TwilioEnvelope::encode_media` exists in `busbar-voice-codec/src/topology/twilio.rs:258` — a same-named sibling in a different crate, not itself a bug but worth an owner's eye for confusion. | X-3334 |
| crates/busbar-plugin/src/cold/auth.rs | FINDING | file-verdicts.md:1600 LIVE. secret-hygiene.md:101,276 confirm the `.expose_secret()` crossing at `auth.rs:420` is documented/by-design (CLEAN). Fresh finding: `HttpResponse::safe_status()` (`auth.rs:265`, unconstructed-sweep.md #190, 2 test sites) delegates to the validated `crate::cold::endpoint::safe_relay_status` specifically to guard "an attacker-chosen `0`/`65535`" from panicking a naive `from_u16(status).unwrap()`. `git grep -n '\.safe_status()\|HttpResponse\b' crates/busbar-plugin/src crates/plugin-loader/src \| grep -v tests` shows `HttpResponse.safe_status()` itself is never called anywhere in production — `cold/tests/endpoint_tests.rs`'s assertions exercise the DIFFERENT `EndpointResponse::safe_status()` from `cold/endpoint.rs`, not this one. Whatever downstream code turns a `HttpResponse`/`LoginHttpResponse.status` into a real `StatusCode` was not traced further — flagged, not fully resolved. | X-3335 |
| crates/busbar-plugin/src/cold/mod.rs | FINDING | file-verdicts.md:1604 LIVE. security-posture.md:190-192 confirms `extern "C-unwind"` panic-forced-unwind design is CLEAN. gate-blindspots.md (line 297): `ALL_KINDS` is a 7-literal list, so an 8th plugin kind is bound to no ABI lane and checked by nothing (inferred, not certified). Fresh finding, not previously swept: `STORE_NUL`/`SECRET_NUL`/`AUTH_NUL`/`HOOK_NUL`/`EXPORT_NUL`/`PLANE_NUL` (cold/mod.rs:112-122) are documented as *the* required spelling every `busbar_plugin_kind()` FFI export must return (own doc: "return `kind::EXPORT_NUL.as_ptr()` from `busbar_plugin_kind()`"), but the ACTUAL macro every real plugin uses — `export_plugin!` in `crates/plugin-sdk/src/lib.rs:1050-1054` — builds its own `const KIND_NUL: &str = concat!($kind, "\0"); KIND_NUL.as_ptr()` and never references any `*_NUL` constant (`git grep -n 'STORE_NUL\|SECRET_NUL\|AUTH_NUL\|HOOK_NUL\|EXPORT_NUL\|PLANE_NUL' crates/secret-example-plugin crates/store-example-plugin crates/auth-static-plugin crates/export-example-plugin crates/hook-test-plugin` → 0 hits). Two independent spellings of each kind's NUL-terminated ABI string, verified against each other by nothing — exactly the "rename applied on one side" defect class. `PLANE_NUL` additionally has zero references anywhere including tests. | X-3336 |
| crates/busbar-plugin/src/hot/decl.rs | FINDING | file-verdicts.md:1612 LIVE. TRACKER.md N5 (line 375) covers a DIFFERENT issue at this file (`later phase` banned-word, an owner-decision item, not re-derived here). unconstructed-sweep.md #196 `free_noop` (decl.rs:290) — 1 test call site (`hot/tests/decl_tests.rs:42`), confirmed via combined grep: no production reference at all, not even as a function-pointer value. | X-3337 |
| crates/busbar-plugin/src/hot/host.rs | FINDING | file-verdicts.md:1613 LIVE. duplex-plane-and-realtime.md D2 (line 789) confirms `cost_reserve`/`cost_settle` slots ARE present and wired to production (CLEAN, superseded finding, not a gap). LEDGER.md GS15 (line 404) + ratchet-census.md:461-463: `scripts/no-deferral.waivers` carries 38 stale/un-waived markers against `host.rs`, pure line-number drift (waiver span 855-1217 vs marker span 1005-1359) — "the only thing keeping `no-deferral-strict-done` from green." I confirmed the waiver file and 46 `host.rs`-referencing lines still exist (`grep -c host.rs scripts/no-deferral.waivers` → 46) but did not re-run the gate itself to re-derive the exact current drift count — cited from the ledger's own line-range evidence. | X-3338 |
| crates/busbar-plugin/src/hot/pod.rs | FINDING | file-verdicts.md:1615 LIVE. money-sweep.md (line 305) cites `pod.rs:908` `unit_cost_micros` as a money CELL (informational, not itself broken). Fresh, verified finding: `with_units`/`pack_usage_units`/`decode_usage_units` (unconstructed-sweep.md #197-199, test-only) build/pack/decode a MULTI-KEY `usage_units: BTreeMap<String,u64>` tail on `Usage`. I traced the REAL production charge path: `busbar-kernel/src/plane_host/vtable.rs:415` `meter_charge` → `govern::charge` (`govern.rs:207-252`) computes the charge from `usage.amount * usage.unit_cost_micros` — a single flat scalar — and `token_usage_for` (`govern.rs:292`) puts the whole amount into ONE `TokenUsage.input` bucket. `decode_usage_units` is never called from `govern.rs` (`git grep -n decode_usage_units crates/busbar-kernel` → 0 hits). A plugin that reports a granular multi-unit breakdown via `with_units` has that breakdown built, packed, ABI-tested — and silently discarded by the real charging code, which only ever bills the flat scalar. | X-3339 |
| crates/busbar-plugin/src/hot/tests/pod_tests.rs | CLEAN | file-verdicts.md:1618 TEST. branch-sweep-ledger.md:402 ADJUDICATE about a deleted branch, no trunk defect. | - |
| crates/busbar-plugin/src/hot/workitem.rs | FINDING | file-verdicts.md:1620 LIVE. unconstructed-sweep.md #201 `finite_buffer` (workitem.rs:87), 3 test sites. Confirmed via combined grep: used only by `hot/tests/workitem_tests.rs`, `busbar-kernel/tests/plane_abi_rider.rs`, `plugin-loader/src/tests/plane_conformance_tests.rs` — all test paths, zero production construction of a finite/whole-buffer inbound work item (duplex-plane-and-realtime.md D1 confirms the LOCKED production carrier is `InboundKind::Stream`+`EmitKind::Unsolicited`, not the finite-buffer shape). | X-3340 |
| crates/busbar-plugin/src/tests/lib_tests.rs | CLEAN | file-verdicts.md:1622 TEST. branch-sweep-ledger.md:402 ADJUDICATE about a deleted branch, no trunk defect. This is where pod.rs's usage-units machinery (X-3339) IS exercised — the test itself is fine. | - |
| crates/busbar-substrate-values/src/billing.rs | FINDING | file-verdicts.md:1624 LIVE. LEDGER.md M1 (line 236, PARKED-OWNER): `RawTierRates` (billing.rs:171-180) carries bare `f64` rate fields into core with no magnitude bound; a config typo (`1e30`) saturates to `u64::MAX` nanos/token downstream via float→int cast — "a config typo becomes a catastrophic overcharge." M2 (line 237, PARKED-OWNER): `micro_per_unit` read via `serde_json::Value::as_f64()` violates #81's "no f32/f64 on any money path" law. R6 (line 271, PARKED-OWNER): four more `f64` tier fields plus `blended_per_mtok()` sit where `no-float-money`'s scan doesn't reach. money-sweep.md rows (lines 124,584-586) + exact-count-migration.md:323 corroborate with exact cells. unconstructed-sweep.md #44 `ServiceTier` enum — nowhere-constructed (7 docs mentions only). All still OPEN/PARKED-OWNER per the ledger; not re-derived, cited with cells. | X-3341 |
| crates/busbar-substrate-values/src/diagnostics/mod.rs | CLEAN | file-verdicts.md:1626 LIVE. LEDGER.md M14 (line 249, PARKED-OWNER) is about a DIFFERENT subject at this file (an `accepted-differences.json` scoping gap, `F-016`, not re-derived here — owner-only). unconstructed-sweep.md #202-205 flagged `render_markdown`/`render_json`/`COMMITTED_DIAGNOSTICS_MD`/`COMMITTED_DIAGNOSTICS_JSON` as test-only; I read `diagnostics/tests.rs:133-165` and confirmed this is a deliberate, CI-enforced golden-docs-freshness test (`committed_markdown_matches_registry`, regenerable via `UPDATE_DIAGNOSTICS=1`) — a real, red-provable check, not a gap. | - |
| crates/busbar-substrate-values/src/ir/facts.rs | FINDING | file-verdicts.md:1631 LIVE. unconstructed-sweep.md #206 `screening_digest` (ir/facts.rs:203), 7 test sites. Confirmed via `git grep -n screening_digest -- crates \| grep -v tests`: only this file's own doc comments and `busbar-kernel/src/hooks/gate.rs:114`'s DOC COMMENT (not a call) referencing it for cache-key identity ("id + `ContentItem::screening_digest`... Safe degradation: a cold/evicted slot just means more gets [recomputed]"). The screening/incremental-scan gate's own documentation describes relying on this digest; no production code actually calls `.screening_digest()`. | X-3342 |
| crates/busbar-substrate-values/src/lib.rs | CLEAN | file-verdicts.md:1639 LIVE. branch-sweep-ledger.md:97,137,149 are all REVIEW-level about deleted branches proposing `WireFraming`/`wire_format_name`/`WIRE_HTTP`/`WIRE_STDIO` — none confirmed as a trunk gap. | - |
| crates/busbar-substrate-values/src/media.rs | FINDING | file-verdicts.md:1641 LIVE. unconstructed-sweep.md #207-208: `is_well_formed`/`has_payload` (media.rs:141,167), 3/4 test sites. Confirmed via combined grep: only `tests/media_tests.rs` references either. | X-3343 |
| crates/busbar-substrate-values/src/proto.rs | CLEAN | RE-GRADED BY THE SECOND PASS (see "CORRECTION to X-3344"). The "spec-named new home" is a re-export facade, not a second implementation: `busbar-kernel/src/proto/mod.rs:326` is `pub use busbar_substrate_values::proto::*;`, `registry.rs:65` re-exports `Registry`, `:129` `decl_for` is a two-line delegator, and `:134-156` are `#[cfg(test)]`-gated seams (`registry.rs:23,33,47` say so). File is live: 233 production references via `busbar_substrate_values::proto`. X-3344 demoted to a doc correction. | - |
| crates/busbar-substrate-values/src/tests/proto.rs | CLEAN | file-verdicts.md:1656 TEST. This is the regression test proving the interned-name fix (branch-sweep-ledger.md:1160, NO GAP) — the test itself is correct and stronger than the branch it superseded. | - |
| crates/busbar-timing/src/lib.rs | FINDING | file-verdicts.md:1667 LIVE. unconstructed-sweep.md #209-210: `set_enabled`/`dump_scoped` (lib.rs:373,500), 11/3 test sites. I confirmed via `git grep -n 'busbar_timing::set_enabled\|busbar_timing::dump_scoped' -- crates \| grep -v tests` → 0 hits. `dump_scoped`'s own doc: "Per-request: `reset` then `dump_scoped` bracket ONE request on ONE worker thread" — no production request-handling code calls it, so even with `BUSBAR_TIMING` enabled, the promised per-request breakdown never prints; only the crate's own `tests/smoke.rs` exercises it. | X-3345 |
| crates/busbar-transport-grpc/src/mount.rs | FINDING | file-verdicts.md:1676 LIVE. unconstructed-sweep.md #211-212: `declared_calls`/`UNADDRESSED_STATUS` (mount.rs:117,177), 2 test sites each. Confirmed via combined grep: only `tests/mount.rs` references either. | X-3346 |
| crates/busbar-transport-http/src/lib.rs | FINDING | file-verdicts.md:1683 LIVE (note: civil_to_epoch_secs/month_from_abbrev sub-threshold name collision, not a finding). LEDGER.md BR-S4 (line 1021): `100-continue` is granted BEFORE the declared `Content-Length` is checked against `request_body_max_bytes` — the cap check lives further down in the body-reading branch. I re-read `lib.rs:1140-1160` directly: the `100 Continue` write happens unconditionally on the `Expect` header before any body-size check, confirming the citation is still live. "`curl` sets `Expect: 100-continue` itself for any body past about a kibibyte, so this is the ordinary path, not a crafted one." Status: **OPEN — MERGE→consolidated/1.6.0** (chunked arm is fine, already fixed). | X-3347 |
| crates/busbar-transport-http/src/mount.rs | FINDING | file-verdicts.md:1685 LIVE. unconstructed-sweep.md #213-214: `operation_of`/`captures_map` (mount.rs:178,230), 3/1 test sites. Confirmed via combined grep: only `tests/mount.rs` references either. | X-3348 |
| crates/busbar-transport-http/src/tests/mount.rs | CLEAN | file-verdicts.md:1688 TEST. branch-sweep-ledger.md:891 is a "GAP — narrow, design-divergent" verdict that its OWN text resolves: trunk's mount doesn't publish the presented credential/accept/media at all, so "there is nothing on trunk to redact... a feature difference, not a live leak." Not a live gap. | - |
| crates/busbar-transport-http/tests/no_plane_names.rs | FINDING | file-verdicts.md:248-249,1691 DUPLICATE (byte-identical with `busbar-transport-grpc/tests/no_plane_names.rs`, flagged `yes`). branch-sweep-ledger.md A6-1 (line 1322, re-verified, corrects a prior HARVESTED verdict): `the_scan_would_catch_a_planted_name` asserts `contains_word(…) \|\| "A2A_MOUNT".contains("A2A")` — the right operand is a literal-on-literal tautology, always true, so the no-plane-names self-test can never go red even if `contains_word` breaks. Cited as "tautology verbatim on trunk at 2 sites" including this file:192; I re-verified: `sed -n '192p' crates/busbar-transport-http/tests/no_plane_names.rs` → the tautological assertion is still there. | X-3349 |
| crates/busbar-transport-sse/src/lib.rs | CLEAN | file-verdicts.md:1693 LIVE. branch-sweep-ledger.md:1583 confirms both cited HIGH findings (`plane_token_live`, SSE per-connection read budget) are "landed" — a CLEAN confirmation, not an open gap. | - |
| crates/busbar-transport-sse/src/proto.rs | FINDING | file-verdicts.md:1695 LIVE (note: terminator_len, sub-threshold). branch-sweep-ledger.md A6-2 (line 1323, re-verified, corrects a prior HARVESTED verdict): (a) `SSE_FIELDS` holds names WITH colons matched by `.starts_with`, so a bare `data` line with no colon is dropped as a keepalive comment and a `datastream:` line is wrongly admitted; (b) `event_type = rest.trim()` over-strips where the grammar wants exactly one leading space stripped. Cited as "both live on trunk: `proto.rs:110,128,153`." | X-3350 |
| crates/busbar-transport-sse/src/reframe.rs | FINDING | file-verdicts.md:145,156,1696 ORPHAN, flagged `yes`, with a dedicated OnceLock-seam table (line ~155): `install_sse_reframe`'s only caller is `tests/reframe_tests.rs:90`; the `REFRAMER` OnceLock is never set in production, so `sse_reframe()` returns `None` forever. unconstructed-sweep.md #215-217 corroborates (`PassThroughReframe`/`install_sse_reframe`/`sse_reframe`, all test-only). I confirmed via the combined grep: identical result, zero production references beyond the module's own doc comments. | X-3351 |
| crates/busbar-transport-stdio/src/tests/battery.rs | CLEAN | file-verdicts.md:1705 TEST (note: test_key_handle). branch-sweep-ledger.md:247 REVIEW about a deleted branch, no trunk defect asserted. | - |
| crates/busbar-transport-stdio/src/transport.rs | CLEAN | file-verdicts.md:1707 LIVE. LEDGER.md (line 734) confirms the frame-delimiter injection guard is "CLEAN — and wider than the branch's": `transport.rs:406,446` inlines the `\n`/trailing-`\r` refusal, stronger than the branch. unconstructed-sweep.md #218 `wrap_pair` flagged test-only; I read `transport.rs:118-121,159`: its own doc says it is explicitly "the test-only `Self::wrap_pair`" counterpart to real process-stdio `listen` — deliberate test/embedder convenience, not a gap (same pattern as ws's `handshake_over`, confirmed below). | - |
| crates/busbar-transport-tcp/src/lib.rs | FINDING | file-verdicts.md:1709 LIVE. unconstructed-sweep.md #219 `with_dial_timeout` (lib.rs:177), 1 test site. I confirmed `root/transports.rs` (the composition root's transport provisioning) never calls it — `grep -n dial_timeout crates/busbar/src/root/transports.rs` → no hits; production always uses the hardcoded `DIAL_TIMEOUT` default. The method's own doc: "for a deployment — or a battery cell — whose tolerance is not the default ten seconds" — no deployment config path can reach it; only tests do. | X-3352 |
| crates/busbar-transport-tcp/src/tests/mod.rs | CLEAN | file-verdicts.md:1711 TEST (note: an_undelivered_unit0_refusal_is_an_error). branch-sweep-ledger.md:1102 ADJUDICATE about a deleted branch, no trunk defect. | - |
| crates/busbar-transport-tls/src/lib.rs | FINDING | file-verdicts.md:1715 LIVE. branch-sweep-ledger.md A6-3 (line 1324, re-verified, corrects a prior HARVESTED verdict): `READ_CHUNK_BYTES` is `pub const` in THREE sibling transport crates (`tcp`, `tls`, `http`) under one shared name carrying different values AND different meanings (`tcp`/`tls` = 16 KiB I/O chunk, `http` = `MAX_CURSOR_BYTES` header-prefix scan cap) — a silent wrong-binding hazard for any consumer reaching for `..::READ_CHUNK_BYTES` without qualifying which crate. Cited as still live: all three constants confirmed present. Separately, unconstructed-sweep.md #220 `with_handshake_timeout` (lib.rs:221) is the same pattern as X-3352: no deployment config path calls it (`root/transports.rs` has no `handshake_timeout` reference), test-only. | X-3353 |
| crates/busbar-transport-tls/src/transport.rs | CLEAN | file-verdicts.md:1719 LIVE. branch-sweep-ledger.md:1582 confirms TLS dial/accept handshake bound (HIGH) is "landed" at `transport.rs:113,147,163,316` — a CLEAN confirmation. | - |
| crates/busbar-transport-ws/src/conn.rs | FINDING | file-verdicts.md:1721 LIVE. unconstructed-sweep.md #45 `bind_to` (conn.rs:129) — nowhere-constructed. Confirmed via combined grep: literally the only hit in the whole tree is the `pub fn` declaration itself — not even a test exercises it. | X-3354 |
| crates/busbar-transport-ws/src/tests/battery.rs | FINDING | file-verdicts.md:1724 TEST (note: test_key_handle). branch-sweep-ledger.md A6-4 (line 1325, re-verified, corrects a prior HARVESTED verdict): the must-turn-red mutation cell `frame_meta_honesty_catches_inflating_and_deflating_fixtures` — which perturbs a real emitted frame ±1 byte and must fail — exists ONLY in `transport-sse/src/tests/mod.rs:630` and `transport-tcp/src/tests/mod.rs:462`; ws (this file), tls, stdio and grpc have none. Trunk ws still asserts only the single always-correct value at `battery.rs:61`, which can never go red. Money-adjacent but not certified money today (`.meta.bytes` has 0 readers outside the transport crates per the branch-sweep note). | X-3355 |
| crates/busbar-transport-ws/src/transport.rs | FINDING | file-verdicts.md:1725 LIVE. unconstructed-sweep.md #221 `with_max_message_bytes` (transport.rs:225) — same "no deployment config path" pattern as X-3352/X-3353: `root/transports.rs` never calls it, only `tests/battery.rs`. unconstructed-sweep.md #222 `handshake_over` (transport.rs:308) is test-only by symbol count, but I read `transport.rs:295-325` and `adopt()` (`:709-730`): `adopt` (the real production upgrade path, called from `accept`) drives the SAME internal `self.handshake(...)` that `handshake_over` thinly wraps — this one is a deliberate embedder/test convenience over already-wired logic, NOT a gap (same class as `wrap_pair`, `check_addresses`). Only `with_max_message_bytes` is a real finding here. | X-3356 |
| crates/busbar-unit-transport-key/src/lib.rs | FINDING | file-verdicts.md:1726 LIVE. TRACKER.md D25 (line 108) and contract-gaps.md CG-49 (line 238) both assert multi-cert SNI "SHIPPED"/"Done", citing `SniCertResolver: ResolvesServerCert` at `lib.rs:438` and `provision_server_named` at `:446` (now `:458`) plus tests at `busbar-transport-tls/src/tests/mod.rs:1172`. **Both prior docs cite only the function's existence and its tests, never a production caller — and there isn't one.** I traced the real boot path myself: `busbar/src/main.rs:610` → `root/transports.rs:144` `provision_servers` → `:178` calls `provision_server` (the SINGLE-cert function) — never `provision_server_named`. `git grep -n provision_server_named -- crates` confirms every non-doc-comment reference outside the declaration is a test (`busbar-transport-tls/src/tests/mod.rs:1331`, `busbar-unit-transport-key/src/tests.rs:528`). Multi-cert SNI is built, tested, and declared DONE by two prior documents — and the composition root never constructs it. | X-3357 |
| crates/busbar-unit-transport-key/src/tests.rs | CLEAN | file-verdicts.md:1727 TEST. branch-sweep-ledger.md:1137 ADJUDICATE about a deleted branch (1 symbol/1 literal absent), no trunk defect. This is where the CG-49 `provision_server_named` tests (X-3357) live — the test itself is fine. | - |
| crates/busbar-voice-codec/src/ir/codec/gemini/tests.rs | CLEAN | file-verdicts.md:1729 TEST. branch-sweep-ledger.md:404 is explicit: "TEST-ONLY (low confidence)... Test names are re-worded when work lands in this repo... verify the PROPERTY, not the name," and cross-checks against LEDGER.md as "agrees" — a prior sweep already certified NO GAP here. | - |

## ROWS RAISED

### X-3300 · CallerContext (MCP client egress) is declared, `#[allow(dead_code)]`, and the file admits production bypasses it
CLASS:     missing-code
CERTAINTY: VERIFIED
EVIDENCE:  `crates/busbar-mcp/src/mcp/client/egress.rs:102-111` — `#[derive(Clone, Debug)] #[allow(dead_code)] pub(crate) struct CallerContext`, doc comment: "Built by the CONNECT path, which has no verb yet: `mcp::upstream` passes the caller's `VirtualKey` straight to `authorise_tool_egress` instead of assembling one of these." `git grep -nw CallerContext -- crates xtask` → declaration + doc references + `tests/no_key_passthrough_tests.rs:26,40,41`, `tests/surface_tests.rs:14,78` only.
ACTION:    Owner decides: either wire `mcp::upstream` to assemble `CallerContext` on the credential-plan path it documents, or delete the type and its `#[allow(dead_code)]` and update the doc comment that still describes it as the intended assembly.

### X-3301 · issue.rs — the "ONE governed path every verb travels" has no production caller for 21 of 22 verbs
CLASS:     missing-code
CERTAINTY: VERIFIED
EVIDENCE:  `crates/busbar-mcp/src/mcp/client/issue.rs:80-85`: `#[allow(dead_code)] pub(crate) async fn issue`, module doc: "So: ONE function, `issue`. Every verb goes through it." `crates/busbar-mcp/src/mcp/client/wire.rs:170`: "Called from `super::issue::issue`, which has no inbound caller yet." `crates/busbar-mcp/src/mcp/client/verb.rs:84-90`: `ToolsCall` is wired separately via `super::jsonrpc::tools_call` (live, money-critical `tools/call` path unaffected); the other 21 `UpstreamVerb` variants are "reached today only from the batteries in `crate::mcp::tests/stdio_client_leg_tests.rs`... busbar's own FRONT DOOR does not yet expose a `prompts/list` that proxies through to an upstream's." Additionally LEDGER.md BR-S12 (line 1034) flags three narrower security claims about this same path as unconfirmed (SSRF-refusal audit-trail, secret-source non-disclosure, oversized-token-body handling); `classify_send_failure` confirmed absent.
ACTION:    Either build the server-plane inbound surface (`prompts/list` etc.) that would call `issue()` for the remaining 21 verbs, or scope-note that only `tools/call` is a shipped MCP-client capability in 1.6.0 and the rest is audited-but-unreachable scaffolding. Separately, resolve BR-S12's three specific claims once `issue()` gets a real caller.

### X-3302 · InputRequiredLoop / may_satisfy / wire_bytes (MCP client jsonrpc) built and tested, never reached from the one governed dispatch path
CLASS:     missing-code
CERTAINTY: VERIFIED
EVIDENCE:  `docs/design/1.6.0-unconstructed-sweep.md` rows #171-173. `git grep -n 'wire_bytes\|InputRequiredLoop\|may_satisfy' crates/busbar-mcp/src/mcp/client/issue.rs` → 0 hits; `issue.rs` calls `super::jsonrpc::parse_response` instead.
ACTION:    Confirm whether the ask-retry-loop apparatus (`InputRequiredLoop`) is meant to be reachable from `issue::issue`; if so wire it in, else delete the dead machinery and its tests.

### X-3303 · McpClientEngine is a tested, `#[allow(dead_code)]` orchestration wrapper the real system never constructs
CLASS:     missing-code
CERTAINTY: VERIFIED
EVIDENCE:  `crates/busbar-mcp/src/mcp/client/mod.rs:190-197` `#[allow(dead_code)] impl McpClientEngine`. `git grep -n 'mcp::client::' crates/busbar/src` → 0 hits. Production instead builds `client::pool::McpConnectionPool` and `client::catalogue::CatalogueCache` directly as separate fields at `crates/busbar-mcp/src/mcp/mod.rs:293-319`.
ACTION:    Delete `McpClientEngine` (and its `register`/`deregister`/`registration` methods) if the direct-field pattern in `mcp/mod.rs` is the intended shape, or document why two parallel assemblies of the same three collaborators coexist.

### X-3304 · SSE grammar bug in MCP client transport — `.lines()` drops multi-line `data:` payloads to their last line
CLASS:     customer-surface
CERTAINTY: VERIFIED
EVIDENCE:  `docs/design/1.6.0-LEDGER.md:662` (ENG1), re-checked at `docs/design/1.6.0-map-proof.md:2774`. `grep -n '\.lines()' crates/busbar-mcp/src/mcp/client/transport.rs` → `:416,:454` still present at this sweep's HEAD.
ACTION:    Accumulate multi-line `data:` fields instead of overwriting on each `.lines()` iteration, matching the fix already scoped for the sibling files this bug spans (`busbar-a2a/src/a2a/grpc.rs`, `busbar-plane-llm/src/plane.rs`).

### X-3305 · effective_upstream_credentials / effective_hooks (MCP config) — operator's section-level credential default silently dropped
CLASS:     money
CERTAINTY: VERIFIED
EVIDENCE:  `docs/design/1.6.0-LEDGER.md:340` (S23): "`effective_upstream_credentials` exists with exactly one caller: a test." Corroborated at `docs/design/1.6.0-local-only-audit.md` G5/D22: `catalogue.rs:1192` builds `UpstreamPosture` entry-level only. `docs/design/1.6.0-unconstructed-sweep.md:454` (#178) `effective_hooks`, 1 test/1 docs.
ACTION:    Wire `server_entry` to fall back to the section-level `tools.upstream_credentials:` default when an entry doesn't repeat it, per S23's own fix description.

### X-3306 · overlay_patch (MCP connect) constructed only in tests
CLASS:     missing-code
CERTAINTY: VERIFIED
EVIDENCE:  `docs/design/1.6.0-unconstructed-sweep.md:455` (#179). `git grep -nw overlay_patch -- crates xtask` → declaration + `tests/connect_tests.rs:13,209,257` only.
ACTION:    Confirm whether `overlay_patch` is meant to run on a live refresh path; if so wire it, else fold into its caller or delete.

### X-3307 · method.rs — `charged_at: 0` keys an all-time budget window that never resets (MONEY)
CLASS:     money
CERTAINTY: VERIFIED
EVIDENCE:  `crates/busbar-mcp/src/mcp/method.rs:1261` — read directly, `charged_at: 0,` live in the `GauntletRequest` built for every `tools/call`. `crates/busbar-kernel/src/governance/state.rs:1861-1893` documents `window_start == 0` as the special never-aged ALL-TIME cell. `docs/design/1.6.0-local-only-audit.md` G4 names the same defect ("every A2A and MCP request keys one window that never rolls") with the identical twin at `busbar-a2a/src/a2a/receive.rs:897` (outside this slice).
ACTION:    Pass a real clock read (`ctx.host.clock_now_secs()` or equivalent) instead of the literal `0`, matching the branch fix already described in local-only-audit.md.

### X-3308 · method.rs — tap_join_verdict duplicated with busbar-a2a/receive.rs, `structure-lint:plane-dup` gate RED
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:  `docs/design/1.6.0-LEDGER.md:513` (GS29): `cargo xtask gate structure-lint` 2026-09-23 → "structure-lint: 36 row(s), RED", quoted verbatim; `tap_join_verdict` at `method.rs:2519` and `busbar-a2a/src/a2a/receive.rs:1096`. `docs/design/1.6.0-file-verdicts.md:218` adds: "This file is ALSO half-migrated: 8 of its 63 top-level symbols already exist in `busbar-plane-mcp`."
ACTION:    Consolidate `tap_join_verdict` into one shared implementation (the plane crate is the stated destination per the half-migration note) and re-run `structure-lint` to green.

### X-3309 · sampling.rs — `sampling/createMessage` has no size bound, billed to the caller's budget for an upstream-induced ask
CLASS:     money
CERTAINTY: VERIFIED
EVIDENCE:  `docs/design/1.6.0-LEDGER.md:262` (M27): unbounded message count, no running prompt-byte total, `temperature`/`stopSequences` forwarded with no bound. `docs/design/1.6.0-branch-sweep-ledger.md:864`: the four-const fix (`MAX_SAMPLING_MESSAGES` etc.) lives only on unlanded branch `land/busbar-mcp` (D17).
ACTION:    Port the four ceilings and their refusal sites from the branch: 64 messages / 64 KiB total prompt / 8 stop sequences / 64 B each, refused before the body is built.

### X-3310 · calllog_dispatch_tests.rs — private duplicate fixture that asserts instead of building, silently skips 4 real-plugin tests
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:  `docs/design/1.6.0-LEDGER.md:516` (GS32) + `docs/design/1.6.0-gate-sweep.md:647,907`: `calllog_dispatch_tests.rs:138` `fn example_store_cdylib` "deliberately does not build and asserts", vs `busbar-kernel/src/test_support/plugin_store.rs:80` which builds on demand.
ACTION:    Replace the private helper with a call to the kernel's `example_store_cdylib()` (one-line fix per the ledger).

### X-3311 · upstream.rs — secret source leaked in a refusal message
CLASS:     auth
CERTAINTY: ADJUDICATE
EVIDENCE:  `docs/design/1.6.0-local-only-audit.md:2171`: "a secret source leaked in a refusal at `crates/busbar-mcp/src/mcp/upstream.rs:409`" (flagged "New" in that sweep). Not independently re-read line-by-line in this pass.
ACTION:    Read `upstream.rs:409`'s refusal-construction path and redact the secret source from the caller-visible error text.

### X-3312 · record.rs — DUPLICATE codec (a2a twin) and from_journal_body has no production reader
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:  `docs/design/1.6.0-file-verdicts.md:220,1466` DUPLICATE, `yes`. `git grep -n from_journal_body -- crates | grep -v tests` → only doc comments + the `pub fn` itself; record.rs's own comment (`:54-56`) calls this "the actual reader" of a stored call-log body.
ACTION:    Owner ruling on whether `encode`/`decode` should be unified across the two plane crates (per-plane implementation may be intentional); separately confirm nothing else is meant to call `from_journal_body` in production, or wire an admin/replay path to it.

### X-3313 · cimd.rs — kind-isolation:control-path gate RED, 5 named `egress`-naming lines with no upstream binding
CLASS:     config
CERTAINTY: ADJUDICATE
EVIDENCE:  `docs/design/1.6.0-LEDGER.md:400` (GS11) + `docs/design/1.6.0-gate-sweep.md:342,975`. Re-verified the 5 line numbers still match: `awk 'NR==121||NR==122||NR==134||NR==143||NR==170' crates/busbar-oauth2/src/cimd.rs` → all `busbar_kernel::egress::engine::*` calls. The fetch logic itself reads as fully-wired and capped on inspection; the gate's complaint is structural (kind-isolation naming), not a functional SSRF hole (LEDGER's separate CLEAN entry, line 732, independently confirms the SSRF guard is intact and stronger than the branch it's compared to).
ACTION:    Owner reads `kind-isolation:control-path`'s actual rule to determine whether `cimd.rs` should route through a registered "egress kind" indirection instead of calling `busbar_kernel::egress::engine` directly, or whether the gate itself needs an exception for this call shape.

### X-3314 · anomaly.rs — egress_spend_ratio is always 0.0, the suspension signal it drives can never fire as configured
CLASS:     money
CERTAINTY: VERIFIED
EVIDENCE:  `docs/design/1.6.0-money-sweep.md:1006-1027` (M-22): "PRODUCTION WRITERS: none. `git grep -n egress_spend_ratio -- crates/` returns the three lines above plus four test lines." `anomaly.rs:105,214,217`.
ACTION:    Either wire a real writer for `egress_spend_ratio` before the threshold check, or move the ratio kernel-side per #43 ("plane plugins have no pricing type on their surface") as the money-sweep's own recommendation states.

### X-3315 · frame.rs — Transform / Tap traits have no production implementor
CLASS:     missing-code
CERTAINTY: VERIFIED
EVIDENCE:  `docs/design/1.6.0-unconstructed-sweep.md:685-686`, §4C ("traits whose implementors are all in tests"): `Transform` (frame.rs:108) implemented only at `tests/frame.rs:44`; `Tap` (frame.rs:118) implemented only at `tests/frame.rs:89`.
ACTION:    Confirm whether any production frame pipeline is meant to implement these traits; if the a2a plane never needs a custom `Transform`/`Tap`, consider whether the traits should be deleted or documented as extension points with no shipped user yet.

### X-3316 · lib.rs (plane-a2a) — MOUNTED_ROUTE_SUFFIXES / LOCAL_VERB_METHODS read only by tests
CLASS:     missing-code
CERTAINTY: VERIFIED
EVIDENCE:  `docs/design/1.6.0-unconstructed-sweep.md:458-459` (#182-183). `git grep -nw 'MOUNTED_ROUTE_SUFFIXES\|LOCAL_VERB_METHODS' -- crates xtask` → declarations + `tests/claims.rs:98`, `tests/conformance.rs:176` only.
ACTION:    Confirm the route-mounting/local-verb-dispatch code that should read these constants exists elsewhere under a different name; if not, these are declared surfaces with no production consumer.

### X-3317 · plane.rs (plane-a2a) — doc claims 3 credential-free surfaces, code exempts only 1
CLASS:     auth
CERTAINTY: VERIFIED
EVIDENCE:  `docs/design/1.6.0-local-only-audit.md:1052` (B50). Read directly: `crates/busbar-plane-a2a/src/plane.rs:748-750` comment claims "the two discovery documents... and the callback" carry no credential; `:755` `let open_surface = matches!(u.op(), ops::OP_PUSH_EVENT);` only exempts the callback — the two discovery documents fall through to `Some(SchemeAlt::new("bearer"))`.
ACTION:    Owner confirms intended behaviour: either the two discovery documents should also be exempted from the bearer-credential narrowing (fix the code), or the comment is stale and should say only the callback is open (fix the doc). As written, a caller reading the comment would wrongly believe the discovery documents are unauthenticated.

### X-3318 · records.rs (plane-a2a) — OPERATIONS const read only by tests
CLASS:     missing-code
CERTAINTY: VERIFIED
EVIDENCE:  `docs/design/1.6.0-unconstructed-sweep.md:460` (#184). `git grep -nw OPERATIONS -- crates xtask` (plane-a2a copy) → declaration + `tests/records.rs:5,24`, `tests/conformance.rs:546` only.
ACTION:    Confirm the schema-validation code that should consult `OPERATIONS` at runtime exists under a different path; if not, this is a declared-but-unread validation table.

### X-3319 · tests/facts.rs (plane-a2a) — 64% byte-identical with busbar-plane-mcp/src/tests/facts.rs
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:  `docs/design/1.6.0-file-verdicts.md:233,1500`, flagged `yes`, named symbols: `a_bare_number_is_itself`, `a_padded_identifier_is_not_the_number_it_pads`, `the_correlation_carries_the_declared_key`, `the_empty_identifier_correlates_with_nothing`, `the_near_misses_are_carried_as_text`, `the_value_is_deterministic`.
ACTION:    Extract the shared correlation-identity test logic into a common test-support module both plane crates depend on, per #2/#31's "no shared test util between plugins" caveat — owner decides the right shared location given that constraint.

### X-3320 · tests/records.rs (plane-a2a) — 41% byte-identical with busbar-plane-mcp/src/tests/records.rs
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:  `docs/design/1.6.0-file-verdicts.md:235,1505`, flagged `yes`, named symbols: `every_schema_declares_known_operations`, `no_schema_is_declared_twice`.
ACTION:    Same as X-3319 — consolidate or accept the duplication as a deliberate per-plane-crate boundary with an owner ruling.

### X-3321 · codec/mod.rs + facts.rs (plane-decision) — view_with_arena and NEVER_READ_MEMBERS have zero production use
CLASS:     missing-code
CERTAINTY: VERIFIED
EVIDENCE:  `docs/design/1.6.0-unconstructed-sweep.md:221,237,771-772` (row #36, D.5; row #185, D.6). `view_with_arena`: "one occurrence in the whole tree, its own `pub fn`." `NEVER_READ_MEMBERS`: "tests only... asserted by a test and consulted by no production reader." Same root cause as X-3323 (the whole decision plane is never dispatched).
ACTION:    Fold into the decision-plane wiring decision at X-3323 — these two symbols only matter once/if the plane is actually dispatched from production.

### X-3322 · config.rs (plane-decision) — `decisions:` config section is accepted, validated by nothing, reaches nothing
CLASS:     config
CERTAINTY: VERIFIED
EVIDENCE:  `docs/design/1.6.0-config-surface.md:220-233` (F1), CUSTOMER-VISIBLE. Cells: `busbar-kernel/src/config/prepass.rs:105-110,130,151,175-177`, `config/mod.rs:1288-1301`, `plane/config.rs:358-372`, `busbar/root/plane_decision.rs:138,144`, `plane-decision/src/config.rs:59-77`. `PLANE_DECL.parse_section = None` for the decision plane.
ACTION:    Either wire `parse_section` for the decision plane so `decisions:` actually lowers into `DecisionsSection`, or refuse the config key at boot with a clear error instead of silently accepting and discarding it.

### X-3323 · lib.rs + plane.rs (plane-decision) — DecisionPlane/DecisionProvider never registered into the production plugin registry
CLASS:     missing-code
CERTAINTY: VERIFIED
EVIDENCE:  `docs/design/1.6.0-unconstructed-sweep.md:241-242,247` (D.1-D.3). `git grep -n DecisionPlane crates/busbar/src/root/registry.rs crates/busbar/src/main.rs` → `main.rs:323` reads `<DecisionPlane as PlaneMeta>::KEY` only; `registry.rs:435-470` registers `LlmPlane`/`McpPlane`/`A2aPlane`/`StreamingPlane`/`AdminPlane` but not `DecisionPlane`. `PlaneDecl.build` is `None`, so the nine-method `impl Plane for DecisionPlane` has no production dispatch path.
ACTION:    Owner scopes whether the decision plane ships in 1.6.0: if yes, register it in `root/registry.rs` and give `PlaneDecl.build` a real constructor; if not yet, the crate should be feature-gated out or the doc/tracker should stop implying it's live.

### X-3324 · claims.rs (plane-llm) — bare `/v1/models` listing route matches the per-model-invoke claim
CLASS:     customer-surface
CERTAINTY: VERIFIED
EVIDENCE:  `docs/design/1.6.0-LEDGER.md:1022` (BR-S5) + `docs/design/1.6.0-local-only-audit.md:1059` (B43). `grep -n 'V1_MODELS\|Tail' crates/busbar-plane-llm/src/claims.rs` → `:81` `const V1_MODELS: &[PathSeg] = &[Lit("v1"), Lit("models"), Tail]`, no `PathSeg::Var`; same for `V1BETA_MODELS` at `:84`. Status explicitly OPEN — MERGE→consolidated/1.6.0 in the ledger (fix exists on `origin/verify/keep-registry-pin`, unmerged here).
ACTION:    Insert `PathSeg::Var` before the tail in both constants (as the unlanded branch does), update the registry golden in `busbar/src/root/registry.rs`, and land the regression test.

### X-3325 · claims.rs (plane-mcp) — self-admitted: an exact-path claim cannot honour an operator-configured mount path
CLASS:     config
CERTAINTY: VERIFIED
EVIDENCE:  Read `crates/busbar-plane-mcp/src/claims.rs:1-20,113-121` directly. Module doc: "Those two facts cannot both be honoured... a deployment that configures a different path is a deployment this plane's claims do not cover, and the composition root must either constrain the configuration or the contract must grow a way for a claim to name a configured value. It is a finding, it is not fixed here." `CLAIMS` declares `Selector::ExactPath(DEFAULT_MOUNT)` for both HTTP and SSE.
ACTION:    Owner picks one of the two remedies the file's own doc names: constrain the mount-path config to the compiled default, or extend the claim grammar to name a configured value.

### X-3326 · codec.rs (plane-mcp) — MCP wire-word structure-lint census is structurally blind to plane crates
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:  `docs/design/1.6.0-LEDGER.md:407` (GS18) + `docs/design/1.6.0-gate-sweep.md:448,980`. `Addresses::tree()` (`xtask/.../roots.rs:87`) = `core + bin + mcp + a2a + proto_roots`, no plane crate included; the two wire-word constants at `codec.rs:116,125` are correct but invisible to the census.
ACTION:    Add the plane crate roots to `Addresses::tree()` per the gate-sweep row's own recommendation.

### X-3327 · facts.rs (plane-mcp) — DUPLICATE with plane-a2a + 3 consts read only by tests
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:  `docs/design/1.6.0-file-verdicts.md:240,1555`, flagged `yes` (45% byte-identical with `busbar-plane-a2a/src/facts.rs`). `docs/design/1.6.0-unconstructed-sweep.md:283-285` (#38,186,187): `META_MEMBER` nowhere; `META_PROTOCOL_VERSION_QUOTED`/`META_PROGRESS_TOKEN_QUOTED` test-only (`tests/facts.rs:207,211`).
ACTION:    Same consolidation question as X-3319; separately confirm whether `META_MEMBER`/the two QUOTED consts are meant to be read by production wire-parsing code.

### X-3328 · jsonrpc.rs (plane-mcp) — DUPLICATE with plane-a2a + result laundering on non-object results
CLASS:     customer-surface
CERTAINTY: VERIFIED
EVIDENCE:  `docs/design/1.6.0-file-verdicts.md:241,1556`, flagged `yes` (33% byte-identical with `busbar-plane-a2a/src/jsonrpc.rs`). `docs/design/1.6.0-local-only-audit.md:1045` (B49): `jsonrpc.rs:300` `success()` only stamps `resultType` `if let Some(object) = result.as_object_mut()`; a non-object result ships unstamped, defeating the discriminator HEAD's own doc calls "the safety property."
ACTION:    Stamp the discriminator unconditionally (wrap a non-object result rather than skipping the stamp), or refuse to ship a non-object result at all if the wire contract requires the discriminator on every response.

### X-3329 · ops.rs (plane-mcp) — server-originated notifications carry no sender attribution, spoofable by a caller
CLASS:     auth
CERTAINTY: VERIFIED
EVIDENCE:  `docs/design/1.6.0-local-only-audit.md:1905,1050` (B27): `NOTIFICATIONS` at `ops.rs:254` is `&[&str]`; `plane.rs:478-488` admits any of them on ingress via `is_known_notification(method)` with no sender check — a caller can send `notifications/tools/list_changed`.
ACTION:    Turn `NOTIFICATIONS` into a table carrying a `Sender` (server-only vs caller-only) and discard a server-originated notice received on ingress as `ForgedSource`, per the unlanded branch's own shape (already partially landed for the sibling case `a_server_cannot_send_a_callers_method`).

### X-3330 · records.rs (plane-mcp) — OPERATIONS const read only by tests
CLASS:     missing-code
CERTAINTY: VERIFIED
EVIDENCE:  Fresh finding. `git grep -nw OPERATIONS -- crates xtask` (plane-mcp copy, `records.rs:102`) → declaration + `tests/records.rs:6,27` only, zero production readers.
ACTION:    Confirm the runtime schema-operation validator that should consult this table exists under a different name; if not, this is a declared-but-unread validation table (same shape as X-3318's plane-a2a twin).

### X-3331 · claims.rs (plane-streaming) — TWILIO_TRANSPORT const never referenced
CLASS:     missing-code
CERTAINTY: VERIFIED
EVIDENCE:  `docs/design/1.6.0-unconstructed-sweep.md:230` (#39). `git grep -nw TWILIO_TRANSPORT -- crates xtask` → declaration only.
ACTION:    Confirm whether the Twilio transport claim is meant to be read anywhere (dispatch table, claim registry); if genuinely unused, delete.

### X-3332 · oneshot.rs (plane-streaming) — tts_voice has zero callers anywhere, including tests
CLASS:     missing-code
CERTAINTY: VERIFIED
EVIDENCE:  `docs/design/1.6.0-unconstructed-sweep.md:231` (#40). `git grep -nw tts_voice -- crates xtask` → declaration only, no callers at all.
ACTION:    Confirm the one-shot TTS-voice-selection path this function was meant to serve; if abandoned, delete.

### X-3333 · register.rs (plane-streaming) — plane_for_root and CAP_KEY-based registration API never used by the composition root
CLASS:     missing-code
CERTAINTY: VERIFIED
EVIDENCE:  `docs/design/1.6.0-unconstructed-sweep.md:232,336` (#41,188). `git grep -n plane_for_root -- crates xtask` → exactly 2 hits (the `pub fn` and its `pub use` re-export at `lib.rs:88`), zero callers anywhere including tests. `git grep -n 'busbar_plane_streaming::CAP_KEY' -- crates` → only `busbar/src/root/tests/registry.rs`, `tests/units_voice.rs`. Production registers the plane directly: `busbar/src/main.rs:505` `StreamingPlane::new(&[])`, `busbar/src/root/registry.rs:463` `StreamingPlane::EMPTY`.
ACTION:    Delete `plane_for_root`/the `CAP_KEY`-based `register_units` doc example if the direct-construction pattern in `main.rs`/`registry.rs` is the real shape, or explain why a whole alternate registration API is exported at the crate root and never called.

### X-3334 · twilio.rs (plane-streaming) — encode_mark never called, encode_media test-only
CLASS:     missing-code
CERTAINTY: VERIFIED
EVIDENCE:  `docs/design/1.6.0-unconstructed-sweep.md:233,347` (#42,189). `git grep -nw 'encode_mark\|encode_media' -- crates xtask` (this crate's copy) → `encode_mark`: declaration only. `encode_media`: declaration + `tests/alloc_gate.rs:124` only. Note: `busbar-voice-codec/src/topology/twilio.rs:258` has a same-named `TwilioEnvelope::encode_media`, a different type in a different crate.
ACTION:    Confirm whether Twilio media-stream "mark" events are meant to be sent in production; if `encode_mark` is genuinely dead, delete it. Rename one of the two `encode_media`s if the collision is confusing an owner during review.

### X-3335 · cold/auth.rs — HttpResponse::safe_status() (the panic-guarding status conversion) is never called
CLASS:     auth
CERTAINTY: ADJUDICATE
EVIDENCE:  `crates/busbar-plugin/src/cold/auth.rs:258-266`: doc says this guards "an attacker-chosen `0`/`65535`" from panicking a naive `from_u16(status).unwrap()`. `git grep -n '\.safe_status()\|HttpResponse\b' crates/busbar-plugin/src crates/plugin-loader/src | grep -v tests` → no callers. `cold/tests/endpoint_tests.rs`'s assertions exercise the DIFFERENT `EndpointResponse::safe_status()` in `cold/endpoint.rs`, not this one.
ACTION:    Trace where `HttpResponse`/`LoginHttpResponse.status` is finally converted to a real `StatusCode` in the login-flow driver and confirm it goes through a safe conversion; if it uses a naive `from_u16().unwrap()` instead, that is the live panic hazard this method exists to prevent.

### X-3336 · cold/mod.rs — the *_NUL ABI constants are bypassed by the actual plugin-sdk macro every real plugin uses
CLASS:     abi
CERTAINTY: VERIFIED
EVIDENCE:  `crates/busbar-plugin/src/cold/mod.rs:79,85,111-122`: doc instructs "return `kind::EXPORT_NUL.as_ptr()` from `busbar_plugin_kind()`." `crates/plugin-sdk/src/lib.rs:1050-1054`: `export_plugin!`'s generated `busbar_plugin_kind()` builds `const KIND_NUL: &str = concat!($kind, "\0"); KIND_NUL.as_ptr()` — never references any `*_NUL` constant. `git grep -n 'STORE_NUL|SECRET_NUL|AUTH_NUL|HOOK_NUL|EXPORT_NUL|PLANE_NUL' crates/secret-example-plugin crates/store-example-plugin crates/auth-static-plugin crates/export-example-plugin crates/hook-test-plugin` → 0 hits.
ACTION:    Have `export_plugin!` build `KIND_NUL` FROM `busbar_plugin::cold::kind::*_NUL` (or the reverse) so there is one spelling of each kind's NUL-terminated ABI string, not two that can silently drift apart.

### X-3337 · hot/decl.rs — free_noop has no production reference of any kind
CLASS:     missing-code
CERTAINTY: VERIFIED
EVIDENCE:  `docs/design/1.6.0-unconstructed-sweep.md:378` (#196). `git grep -n free_noop -- crates xtask` → declaration + `hot/tests/decl_tests.rs:42` only, not even referenced as a function-pointer value elsewhere.
ACTION:    Confirm whether any `PlaneHostVtable`/pod-free slot is meant to point at `free_noop`; if genuinely unused, delete.

### X-3338 · hot/host.rs — 38 stale no-deferral waivers / un-waived markers, pure line drift
CLASS:     drift
CERTAINTY: ADJUDICATE
EVIDENCE:  `docs/design/1.6.0-LEDGER.md:404` (GS15) + `docs/design/1.6.0-ratchet-census.md:461-463`: waiver span 855-1217 vs marker span 1005-1359, "the only thing keeping `no-deferral-strict-done` from green." `grep -c host.rs scripts/no-deferral.waivers` → 46 references still present; gate itself not re-run in this pass.
ACTION:    Re-run `scripts/no-deferral.waivers`'s resync mechanically off the gate's own output (ledger cites the exact commit shape that fixed it previously: `c02754fc4`, "resync no-deferral host.rs waivers +1").

### X-3339 · hot/pod.rs — a hot-path plugin's multi-unit usage breakdown is packed, ABI-tested, and never decoded by the real charge path
CLASS:     money
CERTAINTY: VERIFIED
EVIDENCE:  `crates/busbar-plugin/src/hot/pod.rs:1012,1050,1072` (`with_units`/`pack_usage_units`/`decode_usage_units`). `crates/busbar-kernel/src/plane_host/vtable.rs:415` → `crates/busbar-kernel/src/plane_host/govern.rs:207-252` `charge()` computes `usage.amount * usage.unit_cost_micros` (one scalar) and `token_usage_for` (`govern.rs:292`) puts it all into one `TokenUsage.input` bucket. `git grep -n decode_usage_units crates/busbar-kernel` → 0 hits.
ACTION:    Either have `govern::charge` decode and bill the multi-unit tail when present (matching what `with_units`/`pack_usage_units` were built to carry), or remove the packing/decoding machinery if a single scalar amount is the intended hot-path billing granularity and document why the multi-unit tail exists.

### X-3340 · hot/workitem.rs — finite_buffer (whole-buffer inbound work item) has no production construction
CLASS:     missing-code
CERTAINTY: VERIFIED
EVIDENCE:  `docs/design/1.6.0-unconstructed-sweep.md:407` (#201). `git grep -nw finite_buffer -- crates xtask` → declaration + `hot/tests/workitem_tests.rs`, `busbar-kernel/tests/plane_abi_rider.rs`, `plugin-loader/src/tests/plane_conformance_tests.rs` — all test paths. `docs/design/1.6.0-duplex-plane-and-realtime.md` D1 confirms the LOCKED production carrier is the streaming/unsolicited shape, not finite-buffer.
ACTION:    Confirm whether any production plugin kind is meant to use the whole-buffer (non-streaming) inbound shape; if the duplex/streaming carrier is now the only one that ships, consider whether `finite_buffer` should be documented as test-only or removed.

### X-3341 · billing.rs — RawTierRates and rate-card ingestion still carry unbounded f64 on the money path
CLASS:     money
CERTAINTY: PARK
EVIDENCE:  `docs/design/1.6.0-LEDGER.md:236-237,271` (M1, M2, R6), all marked PARKED-OWNER already: `RawTierRates{ input, output, cache_read, cache_write: f64 }` at `billing.rs:171-180`; `blended_per_mtok() -> f64` at `:187-189`; `duration_seconds_to_wire` at `:108-111`. `ServiceTier` enum (`billing.rs:132`) additionally nowhere-constructed per `docs/design/1.6.0-unconstructed-sweep.md:235,427` (#44).
ACTION:    Owner-level: this is the same #81 fixed-point-decimal migration already scoped and parked in the ledger (i128 mantissa, scale 6) — not a new decision, re-flagging because this file had never received its own per-file verdict.

### X-3342 · ir/facts.rs — screening_digest documented as the screening gate's cache key, never called by it
CLASS:     missing-code
CERTAINTY: VERIFIED
EVIDENCE:  `docs/design/1.6.0-unconstructed-sweep.md:482` (#206). `git grep -n screening_digest -- crates | grep -v tests` → only doc comments in `ir/facts.rs` itself and `busbar-kernel/src/hooks/gate.rs:114`'s doc comment ("id + `ContentItem::screening_digest`... Safe degradation: a cold/evicted slot just means more gets"). No `.screening_digest()` call outside tests.
ACTION:    Wire `hooks/gate.rs`'s screening cache to actually call `.screening_digest()` for its cache key as its own doc describes, or correct the doc comment if the gate uses a different identity mechanism.

### X-3343 · media.rs — is_well_formed / has_payload constructed only in tests
CLASS:     missing-code
CERTAINTY: VERIFIED
EVIDENCE:  `docs/design/1.6.0-unconstructed-sweep.md:454-455` (#207-208). `git grep -nw 'is_well_formed|has_payload' -- crates xtask` → declarations + `tests/media_tests.rs` only.
ACTION:    Confirm the production media-validation call site that should invoke these checks; if media well-formedness is validated some other way today, document why these two exist only for tests.

### X-3344 · proto.rs — HALF-MIGRATED, 66 of 79 top-level symbols absent from the spec-named new home
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:  `docs/design/1.6.0-file-verdicts.md:193,1642`, flagged `yes`: "13 of its 79 top-level symbols also exist at the spec-named new home (busbar-contract+busbar-kernel); 66 do not... Spec DECISION #37."
ACTION:    Owner-level migration-completion call per DECISION #37 — this sweep only confirms the finding is still current, not re-derived.

### X-3345 · lib.rs (busbar-timing) — set_enabled/dump_scoped never called from production request handling
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:  `docs/design/1.6.0-unconstructed-sweep.md:469-470` (#209-210). `git grep -n 'busbar_timing::set_enabled|busbar_timing::dump_scoped' -- crates | grep -v tests` → 0 hits. `lib.rs:42`'s own doc: "Per-request: `reset` then `dump_scoped` bracket ONE request on ONE worker thread" — no such bracketing exists in any production request-handling code today.
ACTION:    Either insert the per-request `reset()`/`dump_scoped()` bracket at the real request-handling entry/exit points, or correct the module doc to describe the coarser granularity actually shipped.

### X-3346 · mount.rs (transport-grpc) — declared_calls/UNADDRESSED_STATUS constructed only in tests
CLASS:     missing-code
CERTAINTY: VERIFIED
EVIDENCE:  `docs/design/1.6.0-unconstructed-sweep.md:487-488` (#211-212). `git grep -nw 'declared_calls|UNADDRESSED_STATUS' -- crates xtask` (grpc copy) → declarations + `tests/mount.rs` only.
ACTION:    Confirm the production route-declaration/unaddressed-status-reporting path that should use these; if genuinely dead, remove.

### X-3347 · lib.rs (transport-http) — 100-continue is granted before the body-size cap is checked
CLASS:     customer-surface
CERTAINTY: VERIFIED
EVIDENCE:  `docs/design/1.6.0-LEDGER.md:1021` (BR-S4). Read `crates/busbar-transport-http/src/lib.rs:1140-1160` directly: the `100 Continue` write fires unconditionally on `Expect: 100-continue` before the `Content-Length` vs `request_body_max_bytes` comparison, which only happens later in the body-reading branch. Status: OPEN — MERGE→consolidated/1.6.0 (chunked arm already fixed).
ACTION:    Compare the declared `Content-Length` against `request_body_max_bytes` before writing `100 Continue`, refusing (not inviting) an oversized declared body — matching the already-fixed chunked-transfer arm.

### X-3348 · mount.rs (transport-http) — operation_of/captures_map constructed only in tests
CLASS:     missing-code
CERTAINTY: VERIFIED
EVIDENCE:  `docs/design/1.6.0-unconstructed-sweep.md:489-490` (#213-214). `git grep -nw 'operation_of|captures_map' -- crates xtask` (http copy) → declarations + `tests/mount.rs` only.
ACTION:    Confirm the production route-matching path that should call these lookups; if genuinely dead, remove.

### X-3349 · tests/no_plane_names.rs (transport-http) — the scanner's own self-test is a tautology, can never go red
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:  `docs/design/1.6.0-branch-sweep-ledger.md:1322` (A6-1, corrects a prior HARVESTED verdict): `contains_word(…) || "A2A_MOUNT".contains("A2A")` — literal-on-literal, always true. Re-verified: `sed -n '192p' crates/busbar-transport-http/tests/no_plane_names.rs` still shows the tautological assertion.
ACTION:    Replace the right-hand literal with a genuine planted-name fixture the scanner must actually detect, so the self-test can fail if `contains_word` regresses on the `_` boundary.

### X-3350 · proto.rs (transport-sse) — SSE_FIELDS colon-matching + event_type over-trim, both live
CLASS:     customer-surface
CERTAINTY: VERIFIED
EVIDENCE:  `docs/design/1.6.0-branch-sweep-ledger.md:1323` (A6-2, corrects a prior HARVESTED verdict): "both live on trunk: `proto.rs:110` `const SSE_FIELDS: [&[u8]; 4] = [b"data:", b"event:", b"id:", b"retry:"]`, `:128` `.starts_with(field)`, `:153` `rest.trim().to_string()`."
ACTION:    (a) Match `SSE_FIELDS` against the field name up to its colon rather than via `starts_with` on the colon-suffixed literal, so a bare `data` line (no colon, empty value) is recognised per the event-stream grammar instead of dropped as a keepalive. (b) Change `event_type = rest.trim()` to strip exactly one leading `U+0020`, matching the `data:` arm one line below.

### X-3351 · reframe.rs (transport-sse) — ORPHAN, the whole SSE-reframing seam is dead in production
CLASS:     missing-code
CERTAINTY: VERIFIED
EVIDENCE:  `docs/design/1.6.0-file-verdicts.md:145,156,1696`, flagged `yes`: `install_sse_reframe`'s only caller is `tests/reframe_tests.rs:90`; the `REFRAMER` OnceLock is never set in production, so `sse_reframe()` returns `None` forever. `docs/design/1.6.0-unconstructed-sweep.md:511-513` (#215-217) corroborates independently.
ACTION:    Either call `install_sse_reframe` from the composition root if SSE reframing is meant to be live, or delete the seam (`PassThroughReframe`, `install_sse_reframe`, `sse_reframe`, the `REFRAMER` OnceLock) as dead code.

### X-3352 · lib.rs (transport-tcp) — with_dial_timeout has no deployment-config caller
CLASS:     config
CERTAINTY: VERIFIED
EVIDENCE:  `docs/design/1.6.0-unconstructed-sweep.md:528` (#219). `grep -n dial_timeout crates/busbar/src/root/transports.rs` → 0 hits; production always uses the hardcoded `DIAL_TIMEOUT` default. Method's own doc: "for a deployment — or a battery cell — whose tolerance is not the default ten seconds."
ACTION:    Either wire a config key for the dial timeout through `root/transports.rs` to this builder, or remove the "for a deployment" language from the doc if this is meant to stay a test-only knob.

### X-3353 · lib.rs (transport-tls) — READ_CHUNK_BYTES name collision across 3 transports + with_handshake_timeout unconfigurable
CLASS:     abi
CERTAINTY: VERIFIED
EVIDENCE:  `docs/design/1.6.0-branch-sweep-ledger.md:1324` (A6-3, corrects a prior HARVESTED verdict): `READ_CHUNK_BYTES` is `pub const` in `tcp`, `tls` (both 16 KiB I/O chunk) AND `http` (`MAX_CURSOR_BYTES`, a header-prefix scan cap — different value AND meaning) under one shared unqualified name. `docs/design/1.6.0-unconstructed-sweep.md:539` (#220) `with_handshake_timeout` — same no-deployment-caller pattern as X-3352, confirmed via `root/transports.rs` grep.
ACTION:    Rename at least the `http` constant (it means something structurally different) so `..::READ_CHUNK_BYTES` cannot silently bind the wrong crate's meaning; separately wire a config path for handshake timeout or document it as test-only.

### X-3354 · conn.rs (transport-ws) — bind_to has zero references anywhere, including tests
CLASS:     missing-code
CERTAINTY: VERIFIED
EVIDENCE:  `docs/design/1.6.0-unconstructed-sweep.md:236` (#45). `git grep -nw bind_to -- crates xtask` → the `pub fn` declaration is the ONLY hit in the entire tree.
ACTION:    Confirm whether `bind_to` is meant to be a listener-construction entry point; if genuinely unused anywhere, delete.

### X-3355 · tests/battery.rs (transport-ws) — no must-turn-red frame-byte-honesty cell exists for ws
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:  `docs/design/1.6.0-branch-sweep-ledger.md:1325` (A6-4, corrects a prior HARVESTED verdict): the mutation-catching cell `frame_meta_honesty_catches_inflating_and_deflating_fixtures` exists only in `transport-sse/src/tests/mod.rs:630` and `transport-tcp/src/tests/mod.rs:462`; ws (this file), tls, stdio, grpc have none — trunk ws still asserts a single always-correct value at `battery.rs:61`, which can never go red.
ACTION:    Port the perturbation-based cell from `transport-sse`/`transport-tcp` to `transport-ws` (and the other two transports lacking it), so a wire-byte-count regression is actually catchable.

### X-3356 · transport.rs (transport-ws) — with_max_message_bytes has no deployment-config caller
CLASS:     config
CERTAINTY: VERIFIED
EVIDENCE:  `docs/design/1.6.0-unconstructed-sweep.md:558` (#221). `grep -n max_message_bytes crates/busbar/src/root/transports.rs` → 0 hits (checked alongside the tcp/tls pair, same pattern). Note: `handshake_over` (#222) was checked and is CLEAN — it is a deliberate test/embedder wrapper around the same internal `handshake()` that `adopt()` (the real production upgrade path) calls.
ACTION:    Wire a config key for the WS max-message-byte cap through `root/transports.rs`, or document `with_max_message_bytes` as test-only if no deployment is meant to override the default.

### X-3357 · busbar-unit-transport-key/src/lib.rs — multi-cert SNI (CG-49) is declared "Done"/"SHIPPED" by two prior docs; the composition root never calls it
CLASS:     customer-surface
CERTAINTY: VERIFIED
EVIDENCE:  `docs/design/1.6.0-TRACKER.md:108` (D25) and `docs/design/1.6.0-contract-gaps.md:238` (CG-49) both cite `SniCertResolver: ResolvesServerCert` and `provision_server_named` plus their tests as proof of "Done"/"SHIPPED" — neither cites a production caller. Traced the real boot path: `crates/busbar/src/main.rs:610` → `crates/busbar/src/root/transports.rs:144` `provision_servers` → `:178` calls `provision_server` (single-cert) — never `provision_server_named`. `git grep -n provision_server_named -- crates` → every non-doc-comment reference outside the declaration is a test (`busbar-transport-tls/src/tests/mod.rs:1331`, `busbar-unit-transport-key/src/tests.rs:528`).
ACTION:    Either wire a config path (multiple `tls.certificates:` entries with names, or similar) through `root/transports.rs` to call `provision_server_named` when an operator configures more than one named certificate, or correct TRACKER.md/contract-gaps.md to stop describing CG-49 as shipped — a built-and-tested capability with no boot-path caller does not ship per this release's own construction law.


## SECOND PASS — corrections to the rows above, and what a parallel sweep added

This slice was swept twice, independently: once file-by-file end to end (rows X-3300..X-3357 above),
and once by seven parallel investigations of disjoint file groups. The two passes agreed on the
substance of nearly every row. Where they disagreed, the disagreement was re-measured at HEAD by a
third command, recorded below, and resolved in favour of the measurement rather than the prior
document. **Three rows above rest on prior-doc claims that are false at HEAD.** A stale OPEN row
costs the same attention as a real one, so they are corrected here rather than left standing.

### CORRECTION to X-3309 — WITHDRAWN, the bound exists and is enforced
The row reads `sampling/createMessage` "has no size bound", citing `LEDGER.md` M27 and noting the fix
"lives on a branch". It is on trunk at HEAD:
```
grep -n 'MAX_SAMPLING' crates/busbar-mcp/src/mcp/sampling.rs
  214:const MAX_SAMPLING_MESSAGES: usize = 64;
  222:const MAX_SAMPLING_PROMPT_BYTES: usize = 64 * 1024;
  226:const MAX_STOP_SEQUENCES: usize = 8;
  227:const MAX_STOP_SEQUENCE_BYTES: usize = 64;
  248:            if prompt_bytes > MAX_SAMPLING_PROMPT_BYTES {
  261:    if asked > MAX_SAMPLING_MESSAGES {
  304:        if prompt_bytes > MAX_SAMPLING_PROMPT_BYTES {
  360:        if list.len() > MAX_STOP_SEQUENCES {
```
All four bounds are declared AND enforced on the live path, and `temperature` is range-checked
`0.0..=2.0` at `:343`. **X-3309 is withdrawn and `sampling.rs` is re-graded CLEAN.** LEDGER M27 should
be closed.

### CORRECTION to X-3305 — HALF WITHDRAWN, the credential default is no longer dropped
The row bundles two claims. The credential half is false at HEAD:
```
git grep -n 'effective_upstream_credentials' -- '*.rs'
  crates/busbar-mcp/src/mcp/catalogue.rs:1207:            credentials: cfg.effective_upstream_credentials(id),
  crates/busbar-mcp/src/mcp/config.rs:994:    pub(crate) fn effective_upstream_credentials(
  crates/busbar-mcp/src/mcp/tests/tools_config_tests.rs:50: …
```
`catalogue.rs:1207` is a production caller, so the operator's section-level
`tools.upstream_credentials:` default is **not** silently dropped, and LEDGER S23 should be closed.
The `effective_hooks` half **stands**: `git grep -n 'effective_hooks' -- '*.rs'` → definition
`config.rs:982` plus `tests/tools_config_tests.rs:45` only, while the real combine is
`admin_view.rs::reresolve_gates` → `reresolve_container_gates`, which re-derives it directly. So
`config.rs` remains FINDING, on the hooks half alone.

### CORRECTION to X-3311 — HALF WITHDRAWN, the refusal is redacted before it reaches the caller
The secret-leak half is false at HEAD. `SetupRefusal::client_message()`
(`crates/busbar-mcp/src/mcp/upstream.rs:208-218`) redacts exactly the credential arm —
`SetupRefusal::Credential(_) => "the upstream credential for this server could not be resolved; see
the server log for detail"` — and the caller-facing render site uses it, not `Display`:
```
sed -n '2650,2658p' crates/busbar-mcp/src/mcp/method.rs
  error(StatusCode::FORBIDDEN, id, CODE_REFUSED,
        &denied.client_message(),
        Some(serde_json::json!({ "reason": denied.audit_reason() })), )
```
`local-only-audit.md:2171` should be closed. The `authorise_verb` half of the row **stands**
(test-call-sites only), so `upstream.rs` remains FINDING on that half.

### CORRECTION to X-3344 — DEMOTED, the "new home" is a re-export facade, not a second copy
The row grades `proto.rs` HALF-MIGRATED on `file-verdicts.md:193,1642` ("13 of its 79 top-level
symbols also exist at the spec-named new home"). Sampling those named symbols shows the new home is a
facade whose stated job is keeping the historical paths compiling, not a competing implementation:
```
busbar-kernel/src/proto/mod.rs:326       pub use busbar_substrate_values::proto::*;
busbar-kernel/src/proto/registry.rs:65   pub use busbar_substrate_values::proto::{merged_boot_decls, Registry};
busbar-kernel/src/proto/registry.rs:129  pub fn decl_for(..) { registry().decl(name) }        ← delegator
busbar-kernel/src/proto/registry.rs:134  #[cfg(test)] pub fn detect_protocol(..) { …delegates… }
busbar-kernel/src/proto/registry.rs:153  #[cfg(test)] pub fn declared_verbs(..) { …delegates… }
```
`registry.rs:23,33,47` say so in prose. The file is live and reachable (233 production references via
`busbar_substrate_values::proto`). CERTAINTY **ADJUDICATE**: 5 of the 8 named shared symbols were
sampled, not all 13 — so the verdict is demoted, not declared false. **`proto.rs` is re-graded CLEAN**
and the duplicate detector behind `file-verdicts.md` should be re-run with re-export awareness; if its
other HALF-MIGRATED rows were produced the same way they warrant the same re-check.

### X-3358 · `ServiceTier` is declared, derives Default, and is constructed nowhere — not even by a test
CLASS:     money
CERTAINTY: VERIFIED
EVIDENCE:  `git grep -n 'ServiceTier' -- '*.rs'` → **exactly one line tree-wide**:
           `crates/busbar-substrate-values/src/billing.rs:132:pub enum ServiceTier {`. No construction,
           no match, no `use` — not in production, not in tests, not in fixtures. POSITIVE CONTROL,
           same shape on carriers in the same file that ARE built: `Billing::Tokens` → all=37 prod=18;
           `Billing::Flat` → all=20 prod=15; `RawTierRates` → all=22 prod=12; `Usage {` → all=311
           prod=92. Its own doc (`billing.rs:127-130`) says "config resolves each variant to an integer
           basis-point multiplier the pricer applies (`Standard` = ×1.0000 = 10_000 bp)" — no such
           resolution exists, so no tier multiplier is ever applied to any priced quantity. Strengthens
           `unconstructed-sweep.md:134,235,859` (row 44), which recorded 0 code construction sites; the
           zero also covers tests. Distinct from X-3341, which is about the `f64` rate carrier.
ACTION:    Owner call on a billed surface — do NOT self-approve. Either wire the tier multiplier into
           the pricer (config → `ServiceTier` → basis points → applied where the rate projects to
           nanos) with a test that a non-Standard tier changes the charged amount, or delete the enum
           and strike the multiplier claim from its doc so the pricing surface stops advertising a
           modifier it never applies.

### X-3359 · `KIND_CALL`/`KIND_DEMOTION` are defined three times and the pin that claims to hold them is `A == A`
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:  `git grep -n 'KIND_CALL\|KIND_DEMOTION' | grep 'const\|pub use'` →
             crates/busbar-plane-mcp/src/records.rs:50,53   (literals)
             crates/busbar-kernel/src/plane/store.rs:56,61  (literals)
             crates/busbar-mcp/src/record.rs:16             (the only re-export)
           The kernel restates the literals and says so (`store.rs:48-49`): "A plane crate mirrors the
           constant it owns … so the tag it writes and the tag core reads agree" — a mirror with no
           compile-time or test link. `records.rs:40-45` claims the opposite: "there is one answer to
           'what is this record called' rather than two that agree today." The test that claims to hold
           it cannot fail: `records.rs:56` is `SCHEMA_CALL = RecordSchemaId::new(KIND_CALL)` and
           `src/tests/records.rs:16` asserts `SCHEMA_CALL.as_str() == KIND_CALL` — tautological for any
           edit, while its doc claims "If the codec renames a kind, this goes red." This crate already
           caught the identical shape once (`src/tests/jsonrpc.rs:217` — "the loop read `CODES ⊆ CODES`
           and could not fail"). Broader than X-3330, which covers only the `OPERATIONS` const.
ACTION:    Make the kernel read rather than restate: in `busbar-kernel/src/plane/store.rs` replace the
           literals with a re-export of `busbar_plane_mcp::records::{KIND_CALL, KIND_DEMOTION}` if the
           dependency edge permits; if not, invert it, or add a const assertion in the one crate that
           names both (`busbar-mcp`). Then replace the tautology at `src/tests/records.rs:15-18` with an
           assertion against the OTHER side's constant.

### X-3360 · The MCP conformance battery census reads single-quoted strings only, and silently shrank
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:  `crates/busbar-plane-mcp/tests/conformance.rs:42-71`'s `battery_methods()` extracts with
           `text.split('\'').skip(1).step_by(2)`. Re-running that exact algorithm in python over the
           three walked dirs (src/suites 5 .mjs, src/core 6, fakepeer 2) yields **12** method names; a
           full regex census over any quoting yields **18**. Missed by the single-quote walk:
           `notifications/{tools/list_changed, resources/updated, message, progress,
           subscriptions/acknowledged}`; and `"server/discover"`, `"tools/call"`, `"tools/list"` are
           double-quoted, caught only because they also appear single-quoted elsewhere. Direct
           consequence: 3 of the 4 `emitted_only` arms (`:139-144`) can never be reached, and their
           presence proves the census used to see them. The comment above them is stale too ("three
           notices … and one deliberate nonsense name" while listing four notices and no nonsense
           name). Separately `looks_like_a_method` (`:75-90`) cannot distinguish a method from a suite
           id (`'server/tools'`, `'server/utilities/caching'`, the truncated `'tools/li'` would all
           pass and FALSE-RED if ever single-quoted). The battery is NOT path-drifted:
           `git ls-files testing/mcp-conformance | wc -l` → 26 (control: `git ls-files qa | wc -l` → 35);
           `grep -c 2026-07-28 src/core/spec.mjs` → 4; all 10 codes present in `src/core/jsonrpc.mjs`.
ACTION:    Extract on a quote-agnostic scan (single, double and backtick, or a regex over the same
           `heads` prefixes) instead of `split('\'')`; raise the floor from `!found.is_empty()` to a
           written-down count the way `CLIENT_ROWS`/`PROVIDER_ROWS`/`NOTICE_ROWS` already are, so a
           shrinking census goes red rather than quiet. Then either delete the three unreachable
           `emitted_only` arms or let the fixed census reach them, fix the stale comment, and tighten
           `looks_like_a_method` so a suite id cannot false-red it.

### X-3361 · The MCP plane's notification codec is the copy that does not ship; two hand-written copies do
CLASS:     missing-code
CERTAINTY: VERIFIED
EVIDENCE:  `git grep -c 'McpNotification' -- 'crates/**/*.rs'` → `busbar-plane-mcp/src/codec.rs:7`,
           `busbar-plane-mcp/src/tests/codec_tests.rs:7`, and one comment in
           `busbar-mcp/src/codec/tests/mcp_tests.rs`. Zero non-test constructors; `codec.rs:268,280`
           carry `#[cfg_attr(not(test), allow(dead_code))]`, and `read()`/`write()` have no ship
           callers. POSITIVE CONTROL: `git grep -c 'MethodRow' -- crates/busbar-plane-mcp/` → ops.rs:19,
           plane.rs:1, tests/conformance.rs:1. What ships instead, twice, hand-written:
             `busbar-mcp/src/mcp/client/peer.rs:267-280` — a SECOND method table mapping the same two
               names, whose own doc claims "One table, read in one direction, so a name cannot be
               recognised here and spelled differently anywhere else."
             `busbar-mcp/src/mcp/stdio_serve.rs:1155-1159` — the envelope written by hand as a `json!`
               literal rather than through `McpNotification::write()`.
           This contradicts the crate's stated reason to exist (`Cargo.toml:5-8`, `lib.rs:6-9`): "No
           wire format is written twice, because a wire format written twice is two wire formats that
           will disagree." Distinct from X-3326, which is about the structure-lint census being blind
           to plane crates.
ACTION:    Either delete `McpNotification`/`ResourceUpdatedParam` and the cfg_attr
           (`codec.rs:24-42,268-326`) and let `peer.rs` own the reader, or make it ship — have
           `peer.rs::notification_of()` delegate to `McpNotification::read()` and `stdio_serve.rs:1155`
           emit `McpNotification::ResourceUpdated{uri}.write()`. If the latter, also fix `codec.rs:324`'s
           `Bytes::from(serde_json::to_vec(&envelope).unwrap_or_default())`, which turns an
           unserializable envelope into zero bytes on the wire rather than a refusal.

### X-3362 · A crate that does not exist is named 249 times, including in a command the test tells you to run
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:  `grep -rn '^name = ' --include=Cargo.toml . | grep -i substrate` →
           `crates/busbar-substrate-values/Cargo.toml:2:name = "busbar-substrate-values"` — the only
           substrate package (control: the same grep finds 121 package names tree-wide). There is no
           package named `busbar-substrate`.
           `git grep -nE 'busbar-substrate([^-]|$)' -- '*.rs' '*.toml' '*.yml' | wc -l` → **249**.
           The actionable instances:
             `busbar-substrate-values/src/diagnostics/mod.rs:271` — "regenerate the docs:
               `UPDATE_DIAGNOSTICS=1 cargo test -p busbar-substrate diagnostics`", a command an engineer
               is told to run when the golden test fails; `-p busbar-substrate` names no package, so it
               errors instead of regenerating.
             `busbar-substrate-values/src/diagnostics/mod.rs:3855` — "(this crate is
               `crates/busbar-substrate`)", the wrong path for the crate the line lives in.
             `busbar-substrate-values/src/diagnostics/tests.rs:135,151` — the same broken command inside
               the failure message a developer actually reads (outside this slice).
             `busbar-substrate-values/src/lib.rs:6,19,25,44,45,62,69,98` — eight architectural comments
               saying pieces "stayed in `busbar-substrate`".
           The successor is identifiable from the file itself: `lib.rs:45` reads "`busbar-substrate`'s
           own `plane` re-exports all three, so `busbar_kernel::plane::WIRE_JSONRPC`", and
           `busbar-kernel/src/proto/mod.rs:326` is `pub use busbar_substrate_values::proto::*;` — the
           crate meant is `busbar-kernel`.
ACTION:    Fix the runnable and self-describing instances first — `diagnostics/mod.rs:271` and
           `tests.rs:135,151` to `-p busbar-substrate-values`, `mod.rs:3855` to
           `crates/busbar-substrate-values` — then sweep the prose, replacing "stayed in
           `busbar-substrate`" with `busbar-kernel`.

### X-3363 · The userinfo-smuggling refusal in ws's dial-URL parser has no regression test
CLASS:     auth
CERTAINTY: VERIFIED
EVIDENCE:  `crates/busbar-transport-ws/src/transport.rs:146` —
           `if authority.is_empty() || authority.contains('@') { return Err(TransportError::AddressRefused); }`
           inside `split_ws_url`, the parser `dial()` uses on a caller-influenced destination URL.
           `grep -n "userinfo\|@" crates/busbar-transport-ws/src/tests/battery.rs` targeted at
           authority/refusal context → 0 hits: no test in trunk exercises this guard. Matches
           `docs/design/1.6.0-local-only-audit.md:206-208`, which records that the regression test
           `an_authority_carrying_userinfo_is_refused` existed on a now-deleted branch specifically
           "because the guard could have been deleted and every cell in this file stayed green" — the
           exact risk, named and still unaddressed on trunk. Distinct from X-3355, which is the
           frame-byte-honesty cell.
ACTION:    Port an `an_authority_carrying_userinfo_is_refused`-style test into
           `crates/busbar-transport-ws/src/tests/battery.rs` asserting that
           `split_ws_url("ws://user:pass@host/")` and a `wss` variant return
           `TransportError::AddressRefused`.

### X-3364 · `LoopDriver` — the one production-shaped UnitDriver — is never constructed, which is the root cause under X-3346 and X-3348
CLASS:     missing-code
CERTAINTY: VERIFIED
EVIDENCE:  `git grep -n 'trait UnitDriver\|: UnitDriver' -- '*.rs'` → exactly 4 implementors tree-wide:
           `Detached` (`busbar-contract/src/transport/driver.rs:184`, an honest-refusal placeholder),
           `Counting` (`busbar-contract/tests/unit_driver.rs:131`, test-only), `Recorder`
           (`busbar-transport-http/src/tests/mount.rs:116`, test-only) and `LoopDriver`
           (`crates/busbar/src/root/transports.rs:498`).
           `git grep -n 'LoopDriver::new\|LoopDriver {' -- '*.rs'` → **0 hits anywhere**, including its
           own crate's tests. POSITIVE CONTROL: `ProductionUnits::new_sharing`/`ProductionUnits {` in
           the same file family → real hits at `kernel.rs:689,721`.
           So the two mount seams are not independently dead — they are dead because the only driver
           that could run them is never built. No superseding mechanism exists either:
           `git grep -n 'SessionLoopDriver\|serve_until'` → 0 hits, so the alternative design described
           in `docs/design/1.6.0-streams-deletion-list.md` is not in this tree.
           `crates/busbar/Cargo.toml` pulls only `ClientSettings`/`HttpTransport` from
           busbar-transport-http; nothing in `crates/busbar/src` imports `mount`.
           The cell is OUTSIDE this slice (`crates/busbar/src/root/transports.rs`) — reported, not acted on.
ACTION:    Close X-3346, X-3348 and this row together: either wire `LoopDriver::new(..)` into the
           composition root and hand it plus a real `WireSurface` to `mount::serve` / grpc's `resolve`
           at the point HTTP/gRPC planes are admitted, or delete both `mount.rs` modules, `LoopDriver`,
           and their ~700 lines of tests rather than ship dead, fully-tested architecture.

### X-3365 · The whole hot "dropped-in" plane path is unreached from the composition root, while every cold kind is wired
CLASS:     missing-code
CERTAINTY: VERIFIED
EVIDENCE:  `git grep -n "WorkItem::new(\|InboundHandle::finite_buffer" -- crates` (excluding
           `workitem.rs`'s own definitions and `tests/`) → 0 hits. The only production consumer of
           `&WorkItem` is `plugin-loader/src/plane.rs:263-275`'s `DynPlane::dispatch`, reachable only
           via `open_plane`/`load_plane` (`plugin-loader/src/registry.rs:440`,
           `plugin-loader/src/lib.rs:68`); `git grep -n "open_plane\|load_plane\b" -- crates` (excluding
           `plugin-loader/src` and `busbar-plugin/src/hot`) → 0 hits in `busbar-kernel` or `busbar`.
           POSITIVE CONTROL establishing that the grep shape finds real wiring: the same pattern on the
           COLD kinds returns `open_store` → `busbar-kernel/src/appbuild.rs:1160`, `open_auth` →
           `auth/mod.rs:234`, `open_hook` → `hooks/mod.rs:250`, `open_secret` → `preflight.rs:923`.
           So the cold-load path IS wired and the hot dropped-in plane path is NOT.
           `register.rs:51-56`'s S4 note calls the surface "compiled-in AND dropped-in"; only
           compiled-in ships, via the separate and genuinely-wired `Plugin`/`PlaneHostVtable` path
           (`plane_host/vtable.rs:36`). Generalises X-3337 and X-3340 from single dead symbols to the
           unreached path that explains both.
ACTION:    Either wire a real call site — an admin verb or boot-time scan that calls
           `PluginRegistry::open_plane` and drives `DynPlane::dispatch` for a configured dylib plane —
           or strike "dropped-in" from `register.rs`'s S4 claim and `qa/unconstructed.toml`-declare the
           whole hot dropped-in surface as an intentionally-dormant seam (the M-7/`money_book`
           precedent) so it stops scoring as silently-complete. The two files that would need the
           caller — `crates/plugin-loader/src/plane.rs` and `registry.rs:440` — are outside this slice.

### X-3366 · A provider-supplied usage count is cast `u64 as i64` and can reach the fact/export surface negative
CLASS:     money
CERTAINTY: ADJUDICATE
EVIDENCE:  `crates/busbar-plane-decision/src/plane.rs:281-284` →
             `if let Some(units) = codec::read_u64(body, PTR_USAGE_UNITS) {
                  let _ = facts.set(f::FACT_USAGE_UNITS, FactValue::Int(units as i64)); }`
           `units` is whatever the PROVIDER wrote at `/usage/units`; `codec/mod.rs:106-109`'s `read_u64`
           parses the full u64 range with no ceiling, so `units as i64` wraps silently past `i64::MAX`.
           That negative Int is copied verbatim onto the content-fact surface at `plane.rs:444-448`.
           `meter` casts back at `:403` (`quantity: Some(units as u64)`), so the metered number
           round-trips — but the record/export leg sees the wrapped negative and nothing refuses an
           absurd count. ADJUDICATE because the plane is never dispatched today (X-3323), so this is
           latent rather than live.
ACTION:    Refuse rather than wrap: read the usage figure with an explicit ceiling (e.g.
           `u64::try_from(..).ok().filter(|u| *u <= MAX_DECISION_UNITS)`) and on overflow set
           `FACT_HAS_ERROR` / emit no usage line. Never `as i64` a provider-controlled billing quantity.

### X-3367 · The decision plane's only reachable destination arm mints an empty host and an empty lane
CLASS:     missing-code
CERTAINTY: ADJUDICATE
EVIDENCE:  `crates/busbar-plane-decision/src/plane.rs:62-75` — the `None` arm returns
           `DestinationFacts::Upstream { transport: TRANSPORT_HTTP,
             address: busbar_contract::UpstreamAddress::socket(""),
             lane: busbar_contract::ids::LaneId::new("") }`. `providers()` is `&[]` in every build
           (X-3323: `DecisionPlane::new` is reached only via `EMPTY = Self::new(&[])`, `lib.rs:92`), so
           the `Some` arm is dead and the `None` arm is the whole behaviour, and `route()` pushes that
           leg unconditionally for both operations (`plane.rs:387-389`). `plane.rs:53-54` claims "the
           empty host is refused by the trust unit against the allow-list"; nothing in this crate proves
           that, and the plane has no dispatch path that would exercise it. An empty `LaneId` is also the
           lane key money is posted against.
ACTION:    Return `DestinationFacts` that cannot be dialled rather than a syntactically-valid upstream
           with empty strings — or have `route()` push no leg when `providers()` is empty so
           `RefusalReason::NoDestination` (already rendered at `plane.rs:102-105`) is the answer. Add a
           test that the unconfigured plane's destination is refused, since the comment currently stands
           in for one.

### X-3368 · Two module docs cite a witness file `tests/pii_witness.rs` that does not exist
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:  `ls crates/busbar-plane-decision/tests/` → alloc_gate.rs common conformance.rs invariance.rs
           jev.rs purity.rs. `ls crates/busbar-plane-decision/src/tests/` → claims.rs codec.rs config.rs
           facts.rs meta.rs ops.rs plane.rs records.rs. No `pii_witness.rs` in either. Yet
           `lib.rs:36` reads "`tests/pii_witness.rs` (mirrored in `src/tests`) drives a fixture …" and
           `facts.rs:49` reads "the PII witness test (`tests/pii_witness.rs`)". The real test is a
           FUNCTION in another file, and `conformance.rs:26` already spells it right:
           `tests/jev.rs:174 fn pii_witness_never_surfaces_state_or_answers_in_any_fact()`. The
           "(mirrored in `src/tests`)" clause is doubly wrong — there is no mirror.
ACTION:    Change `lib.rs:36` and `facts.rs:49` to name
           `tests/jev.rs::pii_witness_never_surfaces_state_or_answers_in_any_fact`, matching
           `conformance.rs:26`, and drop the "(mirrored in `src/tests`)" clause.

### X-3369 · `claims::STREAM_TRANSPORT` (plane-llm) is a pub const nothing reads
CLASS:     missing-code
CERTAINTY: VERIFIED
EVIDENCE:  `git grep -n '\bSTREAM_TRANSPORT\b' -- '*.rs' | grep -v UPSTREAM` →
           `crates/busbar-plane-llm/src/claims.rs:34:pub const STREAM_TRANSPORT: &str = "sse";` — one
           line, the definition. (The other tree-wide matches are substrings of
           `UPSTREAM_MIDSTREAM_TRANSPORT_ERROR` / `UPSTREAM_PREFIRSTBYTE_TRANSPORT_ERROR`, a collision
           controlled for here.) POSITIVE CONTROL, its sibling const in the same file:
           `git grep -n 'claims::TRANSPORT' -- '*.rs'` → `crates/busbar-plane-llm/src/plane.rs:848`.
           Its doc (`:31-33`) says it "names the framing the response uses" — nothing asks. Corroborates
           `unconstructed-sweep.md:228` (row 37).
ACTION:    Delete `pub const STREAM_TRANSPORT` (`claims.rs:30-34`), or read it where the SSE response
           framing is chosen so the declaration and the behaviour are one value.

### X-3370 · stdio's `wrap_pair` ships in the release binary but is only ever called from tests
CLASS:     missing-code
CERTAINTY: ADJUDICATE
EVIDENCE:  `crates/busbar-transport-stdio/src/transport.rs:159` `pub fn wrap_pair<R, W>(...)`, whose
           sibling `listen`'s own doc comment at `:121` calls it "the test-only `Self::wrap_pair`" — yet
           no `#[cfg(test)]` gates it. `git grep -n wrap_pair -- '*.rs'` → callers only in
           `src/tests/battery.rs` (9 sites) and `src/tests/mutation_hardening.rs` (3 sites); 0
           production callers. Matches `unconstructed-sweep.md:494` (row 218, 12 test call sites).
ACTION:    Either gate it `#[cfg(any(test, feature = "test-support"))]` so it does not ship in the
           release binary, or — if it is meant as a public embedding API mirroring the 1.5.5 `serve_io`
           seam, as its doc suggests — leave it and say so explicitly. Owner call, low priority.

## Facts this slice proves about files OUTSIDE it (reported, not acted on)

- **`crates/busbar/src/root/transports.rs`** — `LoopDriver` (`:498`) is the only production-shaped
  `UnitDriver` implementor and is never constructed (X-3364); this same file is also where X-3357's
  `provision_server_named` call would go. One file, two open rows.
- **`crates/plugin-loader/src/plane.rs`** (`DynPlane::dispatch`) and **`registry.rs:440`**
  (`open_plane`) — the two files that need a caller for X-3365 to close.
- **`crates/busbar-kernel/src/plane/store.rs:56,61`** — the unpinned second definitions of
  `KIND_CALL`/`KIND_DEMOTION` (X-3359).
- **`crates/busbar-plane-mcp/src/plane.rs:180`** spells `"/params/_meta"` as a bare literal instead of
  `jsonrpc::PTR_PARAMS_META` (X-3327); **`:963`** is the catalogue-PUT leg a caller-sent provider notice
  reaches (X-3329); **`tests/conformance.rs:258-272`** currently asserts the wrong behaviour for all
  three notice names and must be split by sender in the same commit as any X-3329 fix.
- **`crates/busbar-mcp/src/mcp/client/peer.rs:267-280`** and **`stdio_serve.rs:1155-1159`** are the two
  shipping hand-written MCP notification codecs (X-3361).
- **`crates/busbar-substrate-values/src/diagnostics/tests.rs:135,151`** and
  **`crates/busbar-kernel/src/egress_auth/mod.rs:22`** carry the same non-existent `-p busbar-substrate`
  package name (X-3362); `tests.rs:151` is the failure message a developer actually reads.
- **`xtask/src/gates/structure_lint/roots.rs:52-63`** still excludes every `busbar-plane-*` crate from
  `Addresses::tree()`, so X-3326/GS18 is open and its cited lines are not stale.
- **`crates/busbar-transport-grpc/tests/no_plane_names.rs:192`** carries the identical tautology to
  X-3349.
- **`crates/busbar-plane-llm/src/dialect.rs` → `busbar-llm-codec`** — `requires_max_response`
  (`dialect.rs:160-165`) joins two independent name tables by string with `.is_some_and(..)`, so a
  rename on either side silently returns `false` and an Anthropic request would stop getting a ceiling
  at `plane.rs:546`. The six names match today; no test asserts set equality. Latent, worth a one-line
  test — not raised as a row.
- **`crates/busbar/src/root/plane_decision.rs:241-248`** — `DecisionsCfg::container_gates()` is the sole
  consumer of `decisions.hooks` and nothing invokes it; the X-3322 edit likely belongs there.
- **Three prior-corpus rows should be CLOSED, not carried into 1.6.0**: `LEDGER.md` S23, `LEDGER.md`
  M27, and `local-only-audit.md:2171` — each measured fixed at HEAD above.

## TALLY
```
files in slice:  83
verdict lines:   83
CLEAN:           26      (24 + sampling.rs and proto.rs re-graded by the second pass)
FINDING:         57      rows raised: 70 live
DELETABLE:        0
UNREADABLE:       0
```

**Row accounting.** 58 rows raised in the first pass (X-3300..X-3357) + 13 added by the second pass
(X-3358..X-3370) = 71, less **X-3309 withdrawn** (the bound exists and is enforced) = **70 live rows**.
Two further rows are half-withdrawn and stand on their surviving half only: **X-3305** (hooks half) and
**X-3311** (`authorise_verb` half). **X-3344** is demoted to a documentation correction. Ids
X-3371..X-3399 are unused.

**By class:** missing-code 27 · drift 12 · money 8 · customer-surface 8 · instrument-blind 6 · config 5 ·
auth 3 · abi 1.

**By certainty:** VERIFIED 57 · ADJUDICATE 11 · PARK 2 (both on billed bytes: the `f64` rate carrier at
`billing.rs` and `FrameMeta.bytes`, neither self-approved).
