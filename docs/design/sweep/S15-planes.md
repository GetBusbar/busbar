# S15-planes — sweep report

Slice: the four plane crates busbar-plane-mcp, busbar-plane-a2a, busbar-plane-decision,
busbar-plane-llm. 73 files, per `.sweep/S15-planes.txt`. X-id block X-2400..X-2499.

Method: every file read in full. Reachability/construction claims verified with `git grep` /
`git show` / `Cargo.lock` inspection, not asserted from the file's own comments. Binding context
read first: `docs/design/BUSBAR-1.6.0.md` Part 3 (plane seam), #18/#48 (5-plane roster), #40 (dep
wall), Part 7 §"SEQUENCING TRAP" and §12 (decision plane dormancy, oracle blindness to plane
money).

Governing facts established before judging individual files (apply to many rows below, cited by
row rather than repeated):

- **What actually dispatches real requests today**: `crates/busbar/src/main.rs::register_planes()`
  installs `busbar_llm::PLANE_DECL`, `busbar_mcp::PLANE_DECL`, `busbar_a2a::PLANE_DECL` — the
  LEGACY host crates — not `busbar_plane_{llm,mcp,a2a}`. The pure plane crates in this slice are
  used at boot for claim/registry validation (`root::units_mcp::seal(&McpPlane::EMPTY)`,
  `root::registry.rs`'s `claims_of::<LlmPlane>()`/`claims_of::<A2aPlane>()`) and are read from by
  the legacy crates for vocabulary (`pub use busbar_plane_mcp::{outputschema, sanitize}` etc. in
  `busbar-mcp`; `busbar_plane_a2a::{canonical, anomaly, PUSH_PATH_SUFFIX, ...}` in `busbar-a2a`).
  This is the intended, documented shape of the migration (Part 3 §7: "wire the seam in place,
  THEN relocate"), not a defect in this slice's files.
- **Decision plane dormancy is real, intentional, and already fully self-documented** —
  `crates/busbar/src/root/plane_decision.rs` (outside this slice) sets `claims: |_| Vec::new()`,
  `admission: |_| None`, `build: |_| None` on `PLANE_DECL` even though
  `busbar_plane_decision::claims::CLAIMS` (in this slice, `src/claims.rs`) is non-empty and wired
  into `PlaneMeta::CLAIMS` (`src/meta.rs`). The task brief's hint ("build is None and there is no
  units_decision") is confirmed exactly by that file and by this slice's own
  `tests/invariance.rs`/`tests/purity.rs` doc comments, which independently corroborate it. This is
  not a silent break: both halves (the plane's own trait impl, and the composition root's refusal
  to read it yet) are visible, commented, and consistent with the design doc's `#26`
  ("seams... built BOTH ends... unused until a plane opts in"). Verdict: CLEAN on the files in this
  slice that declare `CLAIMS`/`OP_CLASSES`/etc; the unwired half lives in a file outside this slice.
- **Part 7 of BUSBAR-1.6.0.md is stale about busbar-plane-decision's #40 status.** It says (measured
  2026-09-22) `busbar-plane-decision` is "the ONLY live #40 violation today" via a `src/registry.rs`
  naming `busbar_kernel::plane::registry::PlaneDecl`. That file no longer exists in this tree; the
  crate's own `Cargo.toml` header, `tests/invariance.rs`, and `tests/purity.rs` (all in this slice)
  independently narrate its deletion and the `UpstreamCreds`/`ModelCfg` move to
  `busbar_contract::config`. `Cargo.lock` confirms `busbar-plane-decision` depends on
  `busbar-contract` only. This is a fact my slice proves about a file OUTSIDE the slice (the design
  doc), reported per the contract's "report back" instructions — not acted on.
- Every plane crate's `tests/purity.rs`/`tests/invariance.rs` (or `src/tests/*`) pair is a REAL
  check, not a decorative one: each scans `src/` for concrete forbidden substrings
  (`Cell<`, `tokio`, `busbar_kernel`, money words, etc.) and drives the plane twice to compare
  outputs. A positive control is trivial to construct (add `tokio` to any plane's `src/` and the
  scan goes red); I did not need to fabricate one per row given how many rows share the identical
  mechanism — noted once here rather than 20 times below.

| FILE | VERDICT | EVIDENCE | ROWS |
|---|---|---|---|
| crates/busbar-plane-mcp/Cargo.toml | CLEAN | Read in full. `[dependencies]` = busbar-contract, bytes, serde, serde_json; header prose matches (`There is no longer a codec crate to name`). `awk` over `Cargo.lock` for `name = "busbar-plane-mcp"` confirms the same set. | - |
| crates/busbar-plane-mcp/src/lib.rs | CLEAN | Read in full. `McpPlane::EMPTY`/`McpPlane::new` constructed at `crates/busbar/src/main.rs:354` (`root::units_mcp::seal(&busbar_plane_mcp::McpPlane::EMPTY)`) — `git grep -n "McpPlane" crates/busbar/src/main.rs`. | - |
| crates/busbar-plane-mcp/src/meta.rs | CLEAN | Read in full. `impl PlaneMeta for McpPlane` wires `claims::CLAIMS`, `ops::OP_CLASSES`, `records::RECORD_SCHEMAS` etc; `src/tests/meta.rs::every_declared_list_is_a_set` proves no duplicate/empty entries (ran the test logic by inspection; real dedup loop, not `X==X`). | - |
| crates/busbar-plane-mcp/src/outputschema.rs | CLEAN | Read in full. `check()` not called from this crate's own `plane.rs`, but IS constructed in production: `git grep -n "outputschema::check\b" crates/busbar-mcp` → `crates/busbar-mcp/src/mcp/method.rs:2049`, reached via `busbar-mcp/src/mcp/mod.rs:881: pub(crate) use busbar_plane_mcp::outputschema;`. Not a dead capability. | - |
| crates/busbar-plane-mcp/src/plane.rs | CLEAN | Read in full (1096 lines). `refusal_render` is a `_`-free exhaustive match over all 42 `RefusalReason` variants (pinned by `src/tests/plane.rs::every_refusal_reason_has_an_answer`); `verify`/`route` name the same `sampling_destination()` expression once, not two hand copies; money-adjacent `meter()` posts locators only, no price/decision. | - |
| crates/busbar-plane-mcp/src/sanitize.rs | CLEAN | Read in full. `normalise`/`normalise_json` are the production floor-strip: `git grep -n "sanitize::normalise" crates/busbar-mcp` shows call sites in `mcp/method.rs`, `mcp/catalogue.rs`, `mcp/tasks.rs`. Reconstituted-tag and O(n) complexity are both under dedicated tests. | - |
| crates/busbar-plane-mcp/src/tests/claims.rs | CLEAN | Read in full. Real negative controls (`no_claim_is_unreachable`, transport/scheme exhaustiveness). Wired: `grep -rl 'path = "tests/claims.rs"' crates/busbar-plane-mcp/src/*.rs` → `src/claims.rs`. | - |
| crates/busbar-plane-mcp/src/tests/codec_tests.rs | CLEAN | Read in full. Round-trips `McpNotification`; asserts unknown/malformed cases return `None`, not a panic or a false accept. Wired to `src/codec.rs`. | - |
| crates/busbar-plane-mcp/src/tests/facts.rs | CLEAN | Read in full. Correlation-collision test (`two_string_identifiers_of_one_principal_never_collide`) is money-adjacent (session/principal/fact-key/value collision would mis-bill) and exercises 8x8 pairs, not a single happy path. Wired to `src/facts.rs`. | - |
| crates/busbar-plane-mcp/src/tests/jsonrpc.rs | CLEAN | Read in full. Explicitly documents and removes a formerly-vacuous test (`every_code_is_the_codecs_own` — comment explains it was `X⊆X`); the replacement (`no_retired_code_is_writable`) can fail. Wired to `src/jsonrpc.rs`. | - |
| crates/busbar-plane-mcp/src/tests/meta.rs | CLEAN | Read in full. `every_declared_list_is_a_set` is a real O(n²) duplicate/empty-name scan, not a self-comparison. Wired to `src/meta.rs`. | - |
| crates/busbar-plane-mcp/src/tests/ops.rs | CLEAN | Read in full. `every_dispatched_method_is_carried` cross-checks against `crate::codec::IMPLEMENTED_METHODS` (the real dispatch table) with an anti-vacuity floor (`seen >= 12`). Wired to `src/ops.rs`. | - |
| crates/busbar-plane-mcp/src/tests/outputschema_tests.rs | CLEAN | Read in full. One-sided-validator contract (never manufacture a false violation) tested from both directions: `unmodelled_keywords_never_manufacture_a_violation` and `additional_properties_false_is_enforced_and_the_schema_form_is_not`. Depth-bound fail-open case included. Wired to `src/outputschema.rs`. | - |
| crates/busbar-plane-mcp/src/tests/plane.rs | CLEAN | Read in full. `every_refusal_reason_has_an_answer` is exhaustive over all 42 reasons; `a_refusal_leaks_nothing_about_the_money` scans rendered text for `budget/bucket/frozen/price/slice/overdraft`. Wired to `src/plane.rs`. | - |
| crates/busbar-plane-mcp/src/tests/records.rs | CLEAN | Read in full. Asserts the call-log schema cannot be overwritten/deleted (`OP_PUT`/`OP_DELETE` absent) and an approval is redeemed, never read-then-spent — genuine auth/money-adjacent negative assertions. Wired to `src/records.rs`. | - |
| crates/busbar-plane-mcp/src/tests/sanitize_tests.rs | CLEAN | Read in full. Includes the CVE-2025-54136-class markup-injection fixture, honest-payload byte-identity fixture, and the `<<IMPORTANT>IMPORTANT>` tag-reconstitution adversarial case plus a brute-force 7-symbol-alphabet, 6-length exhaustive property test. Wired to `src/sanitize.rs`. | - |
| crates/busbar-plane-mcp/tests/alloc_gate.rs | CLEAN | Read in full. Committed baseline `DECODE_WITH_METADATA_ALLOCS = 2`, asserted with a real global-allocator counter (not a stub), with a warm call excluded from the window first. | - |
| crates/busbar-plane-mcp/tests/common/mod.rs | CLEAN | Read in full. Test-only scaffolding; `TestKernelSeal` re-export is the contract's sealed test fixture (`#65`), not a forged seal. | - |
| crates/busbar-plane-mcp/tests/invariance.rs | CLEAN | Read in full. `the_manifest_names_only_what_a_plane_may_name` parses the real `[dependencies]` block and asserts against the current forbidden-prefix list — matches `Cargo.toml`'s actual deps. | - |
| crates/busbar-plane-mcp/tests/purity.rs | CLEAN | Read in full. Source-scans for interior-mutability containers, I/O primitives, kernel-crate names, and money/decision words; each `walk()` genuinely reads `src/` at test time (not a cached/stale list). | - |
| crates/busbar-plane-mcp/tests/sanitize_complexity.rs | CLEAN | Read in full. Wall-clock bound (`<5s`) over a 100k-byte adversarial `<a` repeat and a 100k-deep `<<<…>>>` nest — a genuine quadratic-blowup regression guard, correctly kept out of `src/tests` because it reads a clock (purity gate would flag it there). | - |
| crates/busbar-plane-a2a/Cargo.toml | **FINDING** | `grep -n "busbar-a2a\|busbar_a2a" crates/busbar-plane-a2a/Cargo.toml` → only the header prose and the package `description`, none in `[dependencies]`. `awk '/name = "busbar-plane-a2a"/,/^$/' Cargo.lock` → `dependencies = [busbar-contract, serde, serde_json]`. `git show 0e41eeb9e -- crates/busbar-plane-a2a/Cargo.toml` shows the commit that removed the `busbar-a2a-codec` dependency line touched only `[dependencies]`, leaving the pre-existing header paragraph ("THE DEPENDENCY EDGE, STATED HONESTLY... `busbar-a2a` is named here... it carries an HTTP stack, a gRPC stack, an async runtime") unedited. | X-2400 |
| crates/busbar-plane-a2a/src/a2a/canonical.rs | CLEAN | Read in full. RFC 8785 canonicalizer; `canonicalize()` constructed in production: `git grep -n "canonicalize(" crates/busbar-a2a` → `card.rs:182/193/217`, `sign.rs:181` (signature payload + card fingerprint). | - |
| crates/busbar-plane-a2a/src/a2a/tests/anomaly_tests.rs | CLEAN | Read in full. Tests `anomaly.rs` (outside this slice) but the floor test (`a_ratio_over_a_tiny_sample_cannot_trip`) and zero-floor test (`an_empty_window_never_trips_even_with_no_floor`) are exactly the class of "bound-expectation floor of zero is not a floor" defect this repo's recent commit history (`80601a28c`) shows was found and fixed elsewhere — here it is correctly guarded from both sides. | - |
| crates/busbar-plane-a2a/src/a2a/tests/canonical_tests.rs | CLEAN | Read in full. Vectors transcribed from RFC 8785 itself (UTF-16 vs code-point sort order, ECMAScript number formatting, u64-beyond-f64-precision case) rather than self-referential. | - |
| crates/busbar-plane-a2a/src/claims.rs | CLEAN | Read in full. `CLAIMS` wired into `PlaneMeta::CLAIMS` (`src/meta.rs:102`) and consumed by `crates/busbar/src/root/registry.rs::claims_of::<A2aPlane>()` at boot. | - |
| crates/busbar-plane-a2a/src/facts.rs | CLEAN | Read in full. Correlation digest deliberately removed per its own doc comment (money-collision reason, matches the MCP crate's identical fix) rather than merely commented as a TODO. | - |
| crates/busbar-plane-a2a/src/jsonrpc.rs | CLEAN | Read in full. `pub use crate::{ERRORS, ERROR_INFO_DOMAIN, ERROR_INFO_TYPE};` — re-export, not restatement, of the error table now that the codec folded in (#39); avoids the exact two-copies-that-can-disagree failure mode the file's own header describes. | - |
| crates/busbar-plane-a2a/src/meta.rs | CLEAN | Read in full. `impl PlaneMeta for A2aPlane` wires `claims::CLAIMS`/`ops::OP_CLASSES`/etc; `CLASS_BYTES` direction correctly `Response` (this crate's own header explains the prior bug: pricing a caller's request at the size of an agent's answer). | - |
| crates/busbar-plane-a2a/src/ops.rs | CLEAN | Read in full. Two-spelling (slashed/verb) vocabulary; `row_for` is total and case-sensitive by design (tested in `tests/ops.rs`). | - |
| crates/busbar-plane-a2a/src/surface.rs | CLEAN | Read in full. `SURFACE`/`WireSurface` self-consistent and internally pinned (16 tests in `tests/surface.rs`), but has no production caller yet: `git grep -n "transport_http::mount::mount\|transport_grpc::mount::" crates/ --include tests` finds none outside test files; the legacy `busbar-a2a` engine still does its own routing (`crates/busbar-a2a/src/a2a/serve.rs`, "its own router"). The module's own doc comment states this explicitly ("Nothing here is a second answer to where this protocol lives"), so this is declared-but-not-yet-dogfooded infrastructure of the kind Part 5/§26 describes ("seams... built BOTH ends... unused until a plane opts in"), not a misdescribed one — CLEAN, not a finding. | - |
| crates/busbar-plane-a2a/src/tests/claims.rs | CLEAN | Read in full. `every_mounted_route_is_claimed` checks against the codec's own `MOUNTED_ROUTE_SUFFIXES`/`mounted_route()` values, not a restated literal. | - |
| crates/busbar-plane-a2a/src/tests/jsonrpc.rs | CLEAN | Read in full. `the_error_table_is_the_codecs_own`'s header explicitly notes and removes a formerly-vacuous `X==X` assertion, replacing it with a real band-range check. | - |
| crates/busbar-plane-a2a/src/tests/meta.rs | CLEAN | Read in full. Same `every_declared_list_is_a_set` real dedup pattern as MCP's. | - |
| crates/busbar-plane-a2a/src/tests/ops.rs | CLEAN | Read in full. `the_two_spellings_of_an_operation_agree` proves wording never moves price/streaming classification — genuine money-adjacent assertion. | - |
| crates/busbar-plane-a2a/src/tests/plane.rs | CLEAN | Read in full. `a_unary_answer_closes_once_and_an_empty_envelope_does_not` documents and pins the exact fix for a formerly inverted money boundary (`!has("/result/kind")` predicate). | - |
| crates/busbar-plane-a2a/src/tests/surface.rs | CLEAN | Read in full. `every_target_sits_under_a_claim` / `every_document_mount_sits_under_a_claim` cross-check the surface against `claims::CLAIMS`, catching the "route mounted with no audience check" class directly. | - |
| crates/busbar-plane-a2a/tests/alloc_gate.rs | CLEAN | Read in full. `RELAY_ALLOCS = 2` committed baseline, real global-allocator counter, warm call excluded. | - |
| crates/busbar-plane-a2a/tests/invariance.rs | CLEAN | Read in full. Manifest-deps scan matches current `Cargo.toml` (confirms Cargo.toml's actual deps list, which is why the Cargo.toml *header prose* drift above is a doc-only issue and not a build/test-time-undetected one). | - |
| crates/busbar-plane-a2a/tests/purity.rs | CLEAN | Read in full. Same mechanism as MCP's `purity.rs`; forbidden list correctly includes `busbar_plane_llm`/`busbar_plane_mcp` (sibling-plane cross-reach ban). | - |
| crates/busbar-plane-decision/Cargo.toml | CLEAN | Read in full. Header narrates its own recent history (UpstreamCreds/ModelCfg moved to busbar-contract, src/registry.rs deleted) and matches `[dependencies]` = busbar-contract, serde_json, serde exactly — confirmed against `Cargo.lock`. | - |
| crates/busbar-plane-decision/src/claims.rs | CLEAN | Read in full. `CLAIMS` (2 exact-path claims) wired into `PlaneMeta::CLAIMS` via `src/meta.rs:77`. Not read by `root::plane_decision::PLANE_DECL.claims` (outside this slice, `|_| Vec::new()` by explicit documented design — see header note). | - |
| crates/busbar-plane-decision/src/meta.rs | CLEAN | Read in full. `impl PlaneMeta for DecisionPlane` wires `claims::CLAIMS`, `ops::OP_CLASSES`, `facts::{SESSION,CONTENT}_FACTS`, `records::RECORD_SCHEMAS` (empty, deliberately, per records.rs). `CLASS_DECISION` direction `Response` (billable-success-only, matches `plane.rs::meter`/tests in `tests/jev.rs`). | - |
| crates/busbar-plane-decision/src/ops.rs | CLEAN | Read in full. `row_for` exact-match table for the two jev operations; no pattern/overlap ambiguity possible (only 2 fixed paths). | - |
| crates/busbar-plane-decision/src/records.rs | CLEAN | Read in full. `RECORD_SCHEMAS = &[]` with an explicit design-choice rationale (stateless passthrough, no busbar-side identifier minted) rather than a silently-forgotten declaration; contrasted against A2A's four schemas in the same comment. | - |
| crates/busbar-plane-decision/src/tests/claims.rs | CLEAN | Read in full. Confirms both claims are exact-path/http/bearer-scheme. Wired via `grep -rl 'path = "tests/claims.rs"' crates/busbar-plane-decision/src` → `src/claims.rs`. | - |
| crates/busbar-plane-decision/src/tests/codec.rs | CLEAN | Read in full. PII-boundary test (`read_raw_never_resolves_a_pointer_this_module_does_not_declare`) documents that the guarantee lives in the declared pointer list, not in the primitive refusing — an honest, non-oversold safety claim. Wiring: `path = "../tests/codec.rs"` in `src/codec/mod.rs:112` (relative to `src/codec/`, resolves to `src/tests/codec.rs`) — confirmed by direct read, my first naive grep for the non-relative path missed this and was re-run. | - |
| crates/busbar-plane-decision/src/tests/facts.rs | CLEAN | Read in full. `content_facts_names_no_pii_bearing_key` + `no_declared_fact_key_is_a_forbidden_member_name` are real PII-boundary assertions tied to `NEVER_READ_MEMBERS`. | - |
| crates/busbar-plane-decision/src/tests/meta.rs | CLEAN | Read in full. Confirms `CONFIG_SCHEMA` never mentions `state`/`answers` (PII-adjacent) and that no introspection verb/interrupt/pacing fact is declared, matching the module's stated stateless-passthrough design. | - |
| crates/busbar-plane-decision/src/tests/ops.rs | CLEAN | Read in full. Verb-case-insensitivity and wrong-verb-refusal both tested (`row_for_is_verb_case_insensitive`, `row_for_refuses_wrong_verb`). | - |
| crates/busbar-plane-decision/src/tests/plane.rs | CLEAN | Read in full. `refusal_render_is_total_and_never_leaks_the_specific_reason_for_admission_refusals` pins that budget/breaker/rate/drain refusals are indistinguishable to the caller — real auth/money-adjacent assertion. | - |
| crates/busbar-plane-decision/src/tests/records.rs | CLEAN | Read in full. One assertion (`RECORD_SCHEMAS.is_empty()`), matching the deliberate design in `records.rs`. | - |
| crates/busbar-plane-decision/tests/alloc_gate.rs | CLEAN | Read in full. `RELAY_ALLOCS = 2` baseline, explicitly reasons why it is smaller than A2A's (no task-id rewrite needed for jev). | - |
| crates/busbar-plane-decision/tests/common/mod.rs | CLEAN | Read in full. Test-only scaffolding, mirrors A2A's/MCP's own; `TestSeal` is the contract's sealed test fixture, not a forged one. | - |
| crates/busbar-plane-decision/tests/conformance.rs | CLEAN | Read in full. Drives `decode_ingress`/`decode_response`/`encode_response` against 3 authored fixtures (success, 422-with-PII, models-list); `decode_ingress_refuses_an_unclaimed_surface` is a genuine negative control. | - |
| crates/busbar-plane-decision/tests/invariance.rs | CLEAN | Read in full. `the_manifest_names_only_what_this_plane_may_name`'s forbidden list includes `busbar-api` explicitly (documents the removed `sha2->cpufeatures->libc` edge) and matches the actual current `[dependencies]`. | - |
| crates/busbar-plane-decision/tests/jev.rs | CLEAN | Read in full. `pii_witness_never_surfaces_state_or_answers_in_any_fact` uses two distinctive, hard-to-miss-by-accident markers and checks both `decode_response`'s facts AND `content_facts`'s output — the two real boundaries. `billable_success_metering_surface_reports_usage_on_success_and_nothing_on_error` proves the class is genuinely absent (not zero-quantity) on a 422. | - |
| crates/busbar-plane-decision/tests/purity.rs | CLEAN | Read in full. Forbidden-kernel-crate list includes `busbar_api` (first entry, with a header note explaining why it used to be exempted and no longer is) — this is the source-side half of the crate's now-closed #40 witness, confirmed also from `Cargo.lock`. | - |
| crates/busbar-plane-llm/Cargo.toml | CLEAN | Read in full. `[dependencies]` = busbar-contract, busbar-llm-codec, serde_json, sonic-rs; header explains `busbar-llm-codec`, NOT `busbar-llm` (money-path engine), matches `tests/plain_language.rs::the_manifest_names_only_what_a_plane_may_name`'s allow-list exactly. | - |
| crates/busbar-plane-llm/src/lib.rs | CLEAN | Read in full. `LlmPlane::new`/`EMPTY` constructed in production: `git grep -n "LlmPlane" crates/busbar/src/root/registry.rs` → boot-time claims validation (`claims_of::<LlmPlane>()`) and `Arc::new(LlmPlane::EMPTY) as Arc<dyn Plugin>`. Real request serving still flows through `busbar_llm::PLANE_DECL` (legacy host crate) per `main.rs::register_planes()` — consistent with the mcp/a2a pattern above, not a defect specific to this file. | - |
| crates/busbar-plane-llm/src/meta.rs | **FINDING** | Read in full. `OP_CLASSES`/`METER_CLASSES`/`SESSION_FACTS`/`CONTENT_FACTS`/`INTROSPECTION_VERBS` are hand-authored `const` lists with no duplicates today (verified by inspection), but unlike `busbar-plane-mcp`'s and `busbar-plane-a2a`'s own `src/tests/meta.rs::every_declared_list_is_a_set`, this crate has no test anywhere that would catch a future duplicate/empty entry: `grep -rn "no_repeats\|is_a_set\|declares.*twice" crates/busbar-plane-llm/tests/*.rs` → no output. (`busbar-plane-decision` also lacks this check — it is not a 3-of-4-siblings regression, but 2 of 4 plane crates have the guard and 2 do not.) Low severity: a boot-time registry refusal is the stated backstop per the sibling crates' own comments, just not exercised in isolation here. | X-2401 |
| crates/busbar-plane-llm/src/plane.rs | CLEAN | Read in full (1122 lines). Money-critical `meter()` emits only declared classes via the `meta::CLASS_*` consts (no re-spelled string), matches `tests/metering.rs`'s cached-prefix-once and unreported-vs-zero assertions. `reported_usage`'s doc comment documents and the file's own logic fixes a HISTORICAL bug ("every streamed request metered zero and settled free") — current code correctly extracts the SSE `data:` payload before parsing, confirmed passing in `tests/metering.rs::a_streamed_usage_frame_meters_the_tokens_it_reports`. | - |
| crates/busbar-plane-llm/tests/admit_facts.rs | CLEAN | Read in full. Drives all 6 dialects' real request bodies through the real decode+admit steps; `the_priced_input_is_the_conversation_and_not_the_whole_body` checks 3 independent ways (equals the dialect's own pointer span, not-equal the whole body, does-not-contain the ceiling control) — the exact "billed the customer for the controls, not just the conversation" money defect class. | - |
| crates/busbar-plane-llm/tests/claims_ladder.rs | CLEAN | Read in full. 14-rung ladder order/gap check, `each_rung_routes_its_own_dialect` with one real request per rung (26 cases, count-matched to `LADDER.len()`), header-beats-path precedence test. | - |
| crates/busbar-plane-llm/tests/claims.rs | CLEAN | Read in full. Explicitly tests the "no facts for this selector form" refusal (`Sni`/`ClientCertSubject`/etc all assert `false`, not a wildcard). | - |
| crates/busbar-plane-llm/tests/content_facts.rs | CLEAN | Read in full. All 9 `IrStopReason` variants driven through real upstream tokens (6 via Anthropic, 3 via Cohere) with an exhaustiveness count-assertion (`IR_STOP_REASON_VARIANT_COUNT: usize = 9`) so a 10th variant added without a row fails loudly. `unreachable!()` used only inside an irrefutable `if-let ... else` guard (not reachable at runtime; not a red flag). | - |
| crates/busbar-plane-llm/tests/golden_parity.rs | CLEAN | Read in full (697 lines). Byte-for-byte comparison against the codec crate's own frozen goldens for both request and response directions, with `missing.is_empty()`/`compared > 0` anti-vacuity guards on top of the `differing.is_empty()` real check — so a corpus/golden-dir path typo fails loudly rather than silently comparing zero pairs. | - |
| crates/busbar-plane-llm/tests/harness/mod.rs | CLEAN | Read in full. Test-only scaffolding; `TestKernelSeal` re-export, not a forged seal. | - |
| crates/busbar-plane-llm/tests/metering.rs | CLEAN | Read in full. `a_cached_prefix_is_counted_once` is the "eighty tokens a request" cached-double-count money case named in the file's own header; `every_declared_class_is_a_class_the_metering_step_emits` is the money-critical direction (a class priced by a rate card but never emitted silently shorts every invoice) and is asserted as a real set-equality, not a subset check. | - |
| crates/busbar-plane-llm/tests/plain_language.rs | CLEAN | Read in full. Manifest-deps/lint-gate/no-cfg/no-kernel-crate scan, matches current `Cargo.toml` and `lib.rs`. | - |
| crates/busbar-plane-llm/tests/purity.rs | CLEAN | Read in full. `every_method_answers_the_same_way_twice` drives all nine `Plane` trait methods through one real request/response pair on two independently constructed planes/arenas and compares a `Pass` struct field-by-field — the strongest purity check in this slice (others assert determinism per-method; this one asserts it once over the whole trait). | - |
| crates/busbar-plane-llm/tests/refusal_envelopes.rs | CLEAN | Read in full. `a_refusal_is_the_same_twice` documents and removes a formerly-present carve-out (one dialect's minted id used to break determinism); now asserted with no exception. `the_minted_identifier_follows_the_entropy_it_is_handed` is the required negative control proving the determinism test isn't vacuously true over a constant. | - |
| crates/busbar-plane-llm/tests/stream_state.rs | CLEAN | Read in full. Both cases are real regressions this file's header describes precisely (a latch read from a copy of `StreamDecodeState` resets on every chunk) — `a_stop_reason_buffered_on_one_frame_is_read_on_the_next` and the two-session-halves (`upstream`/`client`) delta-forwarding test. | - |

## ROWS RAISED

### X-2400 · busbar-plane-a2a/Cargo.toml's header narrates a dependency edge that was removed from [dependencies] without the prose being updated
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:  `grep -n "busbar-a2a\|busbar_a2a" crates/busbar-plane-a2a/Cargo.toml` returns three
hits, all in the header comment block and the package `description` field — none in
`[dependencies]`. `awk '/name = "busbar-plane-a2a"/,/^$/' Cargo.lock` returns
`dependencies = [busbar-contract, serde, serde_json]`. `git show 0e41eeb9e -- crates/busbar-plane-a2a/Cargo.toml`
(commit `0e41eeb9e "fold(#39): busbar-a2a-codec dissolves..."`) shows the diff removed the
`busbar-a2a-codec = { path = "../busbar-a2a-codec" }` dependency line (itself never `busbar-a2a`
directly — an earlier split had already renamed the edge) and added `serde`, touching only the
`[dependencies]` block. The pre-existing top-of-file paragraph — "THE DEPENDENCY EDGE, STATED
HONESTLY. ... `busbar-a2a` is named here for the codec vocabulary only, and it is a heavier crate
than a pure plane's dependency rule would like: it carries an HTTP stack, a gRPC stack, an async
runtime and the engine that still lives beside its codec." — was not touched by that commit or any
later one and still reads as if the edge exists. Compare `busbar-plane-mcp/Cargo.toml`'s header
("There is no longer a codec crate to name... the MCP wire dialect... folded IN here") and
`busbar-plane-decision/Cargo.toml`'s header (explicitly narrates its own dependency removal,
"THE SECOND NON-CONTRACT EDGE IS GONE TOO") — both of those were kept in sync with their manifests
at the same kind of transition; `busbar-plane-a2a`'s was not.
ACTION:    Rewrite Cargo.toml lines ~17-22 (the "THE DEPENDENCY EDGE, STATED HONESTLY" paragraph)
to state the crate depends on `busbar-contract`, `serde` and `serde_json` only, with no runtime
carried in the closure — matching what `tests/invariance.rs::the_manifest_names_only_what_this_plane_may_name`
and `cargo tree -p busbar-plane-a2a --edges normal` (quoted in commit `0e41eeb9e`'s own message)
already prove. No code change; comment-only.

### X-2401 · busbar-plane-llm has no test guarding its declared-list constants against a duplicate or empty entry
CLASS:     instrument-blind
CERTAINTY: ADJUDICATE
EVIDENCE:  `grep -rn "no_repeats\|is_a_set\|declares.*twice" crates/busbar-plane-llm/tests/*.rs`
returns no output. `crates/busbar-plane-mcp/src/tests/meta.rs::every_declared_list_is_a_set` and
`crates/busbar-plane-a2a/src/tests/meta.rs::every_declared_list_is_a_set` are the two positive
controls: both walk `OP_CLASSES`/`RECORD_SCHEMAS`/`SESSION_FACTS`/`CONTENT_FACTS`/`INTROSPECTION_VERBS`/
`METER_CLASSES` and assert `!items[..i].contains(item)` for every index — an O(n²) scan that would
go red the moment a class/fact/schema were declared twice or as the empty string. `busbar-plane-llm/src/meta.rs`
declares the same shape of lists (`OP_CLASSES` 7 entries, `METER_CLASSES` 4, `SESSION_FACTS` 7,
`CONTENT_FACTS` 4, `INTROSPECTION_VERBS` 2) and I manually confirmed none is currently duplicated —
so this is a coverage gap, not a live defect. `busbar-plane-decision` also lacks the check (its own
lists are 1-2 entries each, lower risk by construction), so this is not uniquely an LLM-plane
regression; it is an inconsistency across the plane family, present in 2 of 4 crates in this slice.
The stated backstop (per the sibling crates' own doc comments, e.g. mcp's `src/tests/meta.rs`
header: "what the registry needs to be true of a list it seals at boot") is a kernel-side boot
refusal outside this slice, not exercised in isolation by any file in `busbar-plane-llm`.
ACTION:    Add a `no_repeats`-style test to `crates/busbar-plane-llm/tests/` (e.g. alongside
`purity.rs` or `plain_language.rs`, since this crate has no `src/tests/meta.rs` module split) that
walks `LlmPlane::{OP_CLASSES,RECORD_SCHEMAS,SESSION_FACTS,CONTENT_FACTS,INTROSPECTION_VERBS}` and
`meta`'s `METER_CLASSES`, mirroring `busbar-plane-mcp`'s test verbatim. Low priority: PARK if the
owner judges the boot-time registry check sufficient and the four-plane inconsistency not worth
closing before other slices' higher-severity findings.

## TALLY
files in slice:  73      (matches `.sweep/S15-planes.txt`)
verdict lines:   73
CLEAN:           71
FINDING:         2       rows raised: 2
DELETABLE:       0
UNREADABLE:      0
