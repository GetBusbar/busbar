# P04-prior — sweep of the 83 files "mentioned" by a prior sweep document but never given a verdict

Slice: `P04-prior` · X-id block: X-3300–X-3399 · Source list: `.sweep/P04-prior.txt` (83 files)

## Method

For every file, `git grep -n -- '<path>' docs/design/1.6.0-*.md` was run to find prior mentions, then
each hit was opened to judge whether it was a real verdict backed by a command or a bare mention (a
path in a list/glob/diffstat). Two documents carried real, command-backed verdicts that name these
files individually:

- **`docs/design/1.6.0-file-verdicts.md`** — a two-oracle reachability sweep (cargo dep-info +
  module-declaration graph) over all 1802 tracked `.rs` files, plus a DUPLICATE/HALF-MIGRATED/ORPHAN
  pass (≥30% normalised-byte overlap or a `structure-lint:plane-dup` hit). This is cited as the
  reachability basis (checklist item 1) for every file below with a `file-verdicts.md:<line>` citation.
  It is a FILE-level reachability claim, not a per-symbol construction claim, so it does not by itself
  clear checklist item 2 ("is every public item constructed somewhere that ships") — that was checked
  separately below wherever a file looked money/auth/instrument-sensitive or carried an
  `#[allow(dead_code)]`/self-documented gap.
- **`docs/design/1.6.0-THE-LIST.md`** — checked for whether any of `file-verdicts.md`'s DUPLICATE/
  HALF-MIGRATED/ORPHAN findings already carry an X-id there. None of the ones touching this slice do
  (only unrelated `X-52` matched a grep on this file). So citing `file-verdicts.md`'s evidence and
  promoting it to an X-id row here is what closes the gap the task describes: a real finding sitting in
  prose with no owner-visible TODO row.

All other `1.6.0-*.md` mentions of these files were prose (design narrative, `git diff --stat` counts,
architecture tables) with no command run against the specific file — those are not cited as verdicts.

Every `LIVE`/`TEST` file below was additionally read (money/auth-flavoured ones in full) or grep-probed
for: production callers of its public items, `f64`/unguarded arithmetic in a money path, secret-in-log/
error, verify-that-cannot-fail, and self-documented "no production caller yet"/"dormant"/"not wired"
language (a convention this codebase uses consistently for exactly the defect class this sweep hunts).
That extra pass is what produced X-3300 and X-3310, neither of which is in `file-verdicts.md`.

| FILE | VERDICT | EVIDENCE | ROWS |
|---|---|---|---|
| crates/busbar-mcp/src/mcp/client/egress.rs | CLEAN | `file-verdicts.md:1366` LIVE (dep-info+module-graph). Own read: gate-first ordering (`authorise_tool_egress`/`authorise_server_egress` run before any credential plan), `plan_credential`/`plan_verb_credential` confirmed production-called (`grep -n plan_credential` → `mcp/upstream.rs:245,503`; `plan_verb_credential` → `client/issue.rs:131`). Rule-1 (caller's busbar key never reaches an upstream) is structural: `plan_credential` never takes `busbar_key`. | - |
| crates/busbar-mcp/src/mcp/client/issue.rs | FINDING | `file-verdicts.md:1367` LIVE = file compiled+reached, but that is file-level not function-level. `git grep -n "issue::issue(\|client::issue("` and `git grep -n '\bissue('` across `crates/busbar-mcp/**/*.rs` → every call site is in `tests/http_client_leg_tests.rs` or `tests/stdio_client_leg_tests.rs`; zero production callers. The file's own doc concedes it ("NO INBOUND CALLER YET"). | X-3300 |
| crates/busbar-mcp/src/mcp/client/jsonrpc.rs | CLEAN | `file-verdicts.md:1367`-range LIVE. Own read: `tools_call`/`envelope`/`parse_response` are production-wired (`parse_response` called from `client/issue.rs:236`, itself governed and production-live via `plan_verb_credential`). `ServerRequestGrants`/`InputRequiredLoop`/`AskRefusal`/`tools_list` carry `#[allow(dead_code)]` with the file's own comment "Reached only by the connect/refresh path, which has no verb yet" — same documented gap as X-3300/X-3310, not re-raised a third time here. | - |
| crates/busbar-mcp/src/mcp/client/mod.rs | FINDING | `file-verdicts.md:1367`-range LIVE (file reachable). Own check: `git grep -n "McpClientEngine::new\|McpClientEngine {"` and `git grep -n "McpClientEngine"` across `crates/**/*.rs` → only 3 hits total, all `tests/engine_tests.rs` / `tests/surface_tests.rs`. Production instead builds `McpRuntime` directly from `config::ToolsCfg` (`crates/busbar-mcp/src/mcp/mod.rs:313-319`, `CatalogueCache::new()` at line 319) — `McpClientEngine`/`McpServerRegistration`/`Endpoint`/`register`/`deregister` are a parallel, fully-tested registration API with no production caller anywhere. | X-3310 |
| crates/busbar-mcp/src/mcp/client/ssrf.rs | CLEAN | `file-verdicts.md` LIVE. Own read: `pin_upstream` called from `client/pool.rs:282` (production). `check_addresses` is `#[allow(dead_code)]` with an honest in-file justification (test-suite driver only, `net_guard::judge_addresses` is what production actually calls) — not a finding, a documented test seam. | - |
| crates/busbar-mcp/src/mcp/client/tests/peer_tests.rs | CLEAN | `file-verdicts.md` TEST (prod paths=0, test paths=1). `grep -c '#\[test\]'` = 11, 0 tautological asserts. | - |
| crates/busbar-mcp/src/mcp/client/transport.rs | CLEAN | `file-verdicts.md` LIVE. Own read: primary streamable-HTTP transport, SSRF-pinned send path. Doc notes progress-notification frames in an SSE answer have no consumer yet ("this transport has no caller for yet") — a narrow, self-documented sub-gap of the same connect/progress area as X-3300, the request/response path itself is fully wired. | - |
| crates/busbar-mcp/src/mcp/config.rs | CLEAN | `file-verdicts.md` LIVE. Read: `tools:` config grammar, `publish_as` collision validated against the full published-name set (`validate_published_names`), deny-by-default `ServerRequestGrants`. No unguarded parse, no dead-code smell beyond documented reserved-key handling. | - |
| crates/busbar-mcp/src/mcp/connect.rs | CLEAN | `file-verdicts.md` LIVE (note: `observed_pin` fn also declared in busbar-a2a — single-symbol collision, below the file-verdicts.md 4-symbol/25% DUPLICATE threshold, not a finding). `overlay_patch` is `#[allow(dead_code)]` with its own comment: "NO PRODUCTION CALLER YET… the ADOPT verbs (approve, approve-pin…) are not built" — same documented connect-verb gap as X-3300/X-3310; not re-raised a third time. | - |
| crates/busbar-mcp/src/mcp/method.rs | FINDING | `file-verdicts.md:218,265-267` DUPLICATE + HALF-MIGRATED, re-verified: `grep -n "fn tap_join_verdict\|TAP_CHAIN"` on this file and `crates/busbar-a2a/src/a2a/receive.rs` → both declare `const TAP_CHAIN` and `fn tap_join_verdict` independently (method.rs:2468/2519, receive.rs:1049/1096). `xtask/src/gates/structure_lint/plane_dups.rs` is the live gate this trips. File-verdicts.md also notes 8/63 top-level symbols already exist in `busbar-plane-mcp` (HALF-MIGRATED) and flags it money-adjacent but explicitly not a money park. | X-3301 |
| crates/busbar-mcp/src/mcp/sampling.rs | CLEAN | `file-verdicts.md` LIVE. Read: `sampling/createMessage` rides the same governed completion pipeline as an inbound chat request (`EngineHost::synthesize_completion`), model is operator-declared never attacker-declared, per-upstream `SamplingSpend` window is a count not a price. No thinner side channel found. | - |
| crates/busbar-mcp/src/mcp/tests/calllog_dispatch_tests.rs | CLEAN | `file-verdicts.md` TEST. `grep -c '#\[tokio::test\]\|#\[test\]'` = 8 (the plain `#[test]` grep alone false-zeroed at 0 — controlled by widening the pattern), 0 tautological asserts. | - |
| crates/busbar-mcp/src/mcp/upstream.rs | CLEAN | `file-verdicts.md` LIVE. Read: `plan_credential` called at lines 245 and 503 (production `tools/call` path), the transitive-confused-deputy call runs before any egress I/O. | - |
| crates/busbar-mcp/src/record.rs | FINDING | `file-verdicts.md:220` DUPLICATE, re-verified: `grep -n "^fn encode\|^fn decode"` on this file and `crates/busbar-a2a/src/record.rs` → both independently declare byte-identical-shaped `encode<T: Serialize>`/`decode<T: DeserializeOwned>` (record.rs:210/215, a2a's at 167/172). One record codec implemented once per plane rather than shared. | X-3302 |
| crates/busbar-oauth2/src/cimd.rs | CLEAN | `file-verdicts.md` LIVE. Full read: CIMD fetch is SSRF-guarded (`net_guard::resolve_and_pin`, 5KB/10s ceiling, no redirects), every failure maps to `Ok(None)` (unknown-client, not an oracle-distinguishable error), `client_id` bound byte-for-byte against the fetched document. `CimdStore::new` constructed in production at `crates/busbar-oauth2/src/plane.rs:156`. | - |
| crates/busbar-plane-a2a/src/a2a/anomaly.rs | CLEAN | `file-verdicts.md` LIVE. `f64` fields (`error_rate`, `terminal_failure_rate`, `egress_budget_ratio`) are anomaly-threshold ratios/config, not currency — not a money-arithmetic finding. | - |
| crates/busbar-plane-a2a/src/frame.rs | CLEAN | `file-verdicts.md` LIVE. | - |
| crates/busbar-plane-a2a/src/lib.rs | CLEAN | `file-verdicts.md` LIVE. | - |
| crates/busbar-plane-a2a/src/plane.rs | CLEAN | `file-verdicts.md` LIVE (note: `read_raw`/`read_str` — sub-4-symbol collision, below DUPLICATE threshold). | - |
| crates/busbar-plane-a2a/src/records.rs | CLEAN | `file-verdicts.md` LIVE. | - |
| crates/busbar-plane-a2a/src/tests/facts.rs | FINDING | `file-verdicts.md:233` DUPLICATE (64% normalised-byte overlap with `busbar-plane-mcp/src/tests/facts.rs`), re-verified: `grep -n "fn a_bare_number_is_itself\|fn a_padded_identifier_is_not_the_number_it_pads"` hits both files at identical relative structure. | X-3303 |
| crates/busbar-plane-a2a/src/tests/records.rs | FINDING | `file-verdicts.md:235` DUPLICATE (41% overlap with `busbar-plane-mcp/src/tests/records.rs`), re-verified: `grep -n "fn every_schema_declares_known_operations\|fn no_schema_is_declared_twice"` hits both files. | X-3304 |
| crates/busbar-plane-a2a/tests/common/mod.rs | CLEAN | `file-verdicts.md` TEST (test paths=3, note: `frame`). `grep -c` for test attributes = 0 — correctly zero, this is a shared fixture module (`mod common;`) consumed by test binaries, not a test file itself; confirmed it holds no `#[test]` fns by design. | - |
| crates/busbar-plane-a2a/tests/conformance.rs | CLEAN | `file-verdicts.md` TEST. `grep -c '#\[test\]'` = 25, 0 tautological. | - |
| crates/busbar-plane-a2a/tests/frame.rs | CLEAN | `file-verdicts.md` TEST. `grep -c '#\[test\]'` = 4, 0 tautological. | - |
| crates/busbar-plane-decision/src/codec/mod.rs | CLEAN | `file-verdicts.md` LIVE. Billing-count pointer (`billable usage count`) is an integer count, not a float price. | - |
| crates/busbar-plane-decision/src/config.rs | CLEAN | `file-verdicts.md` LIVE. | - |
| crates/busbar-plane-decision/src/facts.rs | CLEAN | `file-verdicts.md` LIVE. | - |
| crates/busbar-plane-decision/src/lib.rs | CLEAN | `file-verdicts.md` LIVE. | - |
| crates/busbar-plane-decision/src/plane.rs | CLEAN | `file-verdicts.md` LIVE. | - |
| crates/busbar-plane-decision/src/tests/config.rs | CLEAN | `file-verdicts.md` TEST. `grep -c '#\[test\]'` = 4, 0 tautological. | - |
| crates/busbar-plane-llm/src/claims.rs | CLEAN | `file-verdicts.md` LIVE. | - |
| crates/busbar-plane-llm/src/dialect.rs | CLEAN | `file-verdicts.md` LIVE. | - |
| crates/busbar-plane-llm/tests/alloc_gate.rs | CLEAN | `file-verdicts.md` TEST. `grep -c '#\[test\]'` = 1, 0 tautological — a single-purpose allocation gate, one assertion is the expected shape. | - |
| crates/busbar-plane-mcp/src/claims.rs | CLEAN | `file-verdicts.md` LIVE. | - |
| crates/busbar-plane-mcp/src/codec.rs | CLEAN | `file-verdicts.md` LIVE. Two `#[cfg_attr(not(test), allow(dead_code))]` items (lines 268,280) are test-support helpers, same documented-seam pattern as `ssrf.rs::check_addresses`. | - |
| crates/busbar-plane-mcp/src/facts.rs | FINDING | `file-verdicts.md:240` DUPLICATE (45% overlap with `busbar-plane-a2a/src/facts.rs`), re-verified: `grep -n "fn correlation_for\|fn is_canonical_number\|fn correlation_value"` hits both files at matching signatures. | X-3305 |
| crates/busbar-plane-mcp/src/jsonrpc.rs | FINDING | `file-verdicts.md:241` DUPLICATE (33% overlap with `busbar-plane-a2a/src/jsonrpc.rs`), re-verified: `grep -n "fn read\b\|fn id_shape\|fn is_number"` hits both files at matching signatures. | X-3306 |
| crates/busbar-plane-mcp/src/ops.rs | CLEAN | `file-verdicts.md` LIVE. | - |
| crates/busbar-plane-mcp/src/records.rs | CLEAN | `file-verdicts.md` LIVE. | - |
| crates/busbar-plane-mcp/tests/conformance.rs | CLEAN | `file-verdicts.md` TEST. `grep -c '#\[test\]'` = 30, 0 tautological. | - |
| crates/busbar-plane-streaming/src/claims.rs | CLEAN | `file-verdicts.md` LIVE. Full read: `twilio-media` transport claim is deliberately DROPPED (documented in-file) because no `twilio-media` transport crate registers that key yet (`git grep '"twilio-media"'` → only the const def and test registry fixtures). This is self-documented and honest, and the underlying codec is still fully wired inside the plane (see `twilio.rs` row) — not re-raised as a separate finding. | - |
| crates/busbar-plane-streaming/src/oneshot.rs | CLEAN | `file-verdicts.md` LIVE. | - |
| crates/busbar-plane-streaming/src/plane.rs | CLEAN | `file-verdicts.md` LIVE. Own check: `twilio::decode` is called at `plane.rs:150,319,953` (production dispatch), confirming the Twilio codec is wired end-to-end inside the plane even though the outer transport claim is dropped (see claims.rs row). | - |
| crates/busbar-plane-streaming/src/register.rs | CLEAN | `file-verdicts.md` LIVE. | - |
| crates/busbar-plane-streaming/src/session.rs | CLEAN | `file-verdicts.md` LIVE. | - |
| crates/busbar-plane-streaming/src/twilio.rs | CLEAN | `file-verdicts.md` LIVE. Full read: fails closed on empty `streamSid` (documented anti-forgery reason), refuses any `mediaFormat` other than the one duration-billing assumes (`UnsupportedMediaFormat`) rather than silently mis-billing. `decode`/`encode_media` confirmed production-called from `plane.rs` (decode) and `tests/alloc_gate.rs` (encode_media — the one caller of the outbound encoder today; outbound Twilio replies are not yet exercised on the serving path, a narrower instance of the same claims.rs gap, not separately raised). | - |
| crates/busbar-plugin/src/cold/auth.rs | CLEAN | `file-verdicts.md` LIVE. Full read: identity-only wire schema, `deny_unknown_fields` makes a policy-smuggling attempt a hard reject, hand-written `Debug` redacts every credential field. `AuthRequest`/`AuthResponse` confirmed production-used at `crates/plugin-loader/src/auth.rs` (not a comment reference — real `transport_call::<AuthRequest, AuthResponse>` call sites). | - |
| crates/busbar-plugin/src/cold/mod.rs | CLEAN | `file-verdicts.md` LIVE. | - |
| crates/busbar-plugin/src/hot/decl.rs | CLEAN | `file-verdicts.md` LIVE. Full read: `PlaneDecl` is the real ABI vtable, confirmed production-used at `crates/plugin-loader/src/plane.rs` (`read_sized_field!` macro reads real slots). `PlaneDecl::STUB` and its `stub` module are explicitly documented example/proof-of-type-check scaffolding, not shipped behaviour. | - |
| crates/busbar-plugin/src/hot/host.rs | CLEAN | `file-verdicts.md` LIVE. 46 `unimplemented!()` hits, all inside the documented `PlaneHostVtable::STUB` scaffolding (same shape as decl.rs's `stub` module) — `grep -n` confirms every hit sits under the "A fully-populated STUB vtable" header at line 933, not in a real host impl. | - |
| crates/busbar-plugin/src/hot/pod.rs | CLEAN | `file-verdicts.md` LIVE. 0 `unimplemented!`/`todo!` hits. | - |
| crates/busbar-plugin/src/hot/tests/pod_tests.rs | CLEAN | `file-verdicts.md` TEST. `grep -c '#\[test\]'` = 8, 0 tautological. | - |
| crates/busbar-plugin/src/hot/workitem.rs | CLEAN | `file-verdicts.md` LIVE. 0 `unimplemented!`/`todo!` hits. | - |
| crates/busbar-plugin/src/tests/lib_tests.rs | CLEAN | `file-verdicts.md` TEST. `grep -c '#\[test\]'` = 8, 0 tautological. | - |
| crates/busbar-substrate-values/src/billing.rs | CLEAN | `file-verdicts.md` LIVE. Full read (MONEY file): the two `f64` sites are both documented, proven boundary conversions — `duration_seconds_to_wire` converts FROM the exact `Count` decimal only at the JSON-render boundary, checked byte-identical over 200,009 sampled values per its own doc; `RawTierRates`/`blended_per_mtok` is a routing-heuristic scalar (`cheapest`-policy cost signal), not a settlement amount. No unguarded internal arithmetic on a billed quantity found. | - |
| crates/busbar-substrate-values/src/diagnostics/mod.rs | CLEAN | `file-verdicts.md` LIVE. | - |
| crates/busbar-substrate-values/src/ir/facts.rs | CLEAN | `file-verdicts.md` LIVE. | - |
| crates/busbar-substrate-values/src/lib.rs | CLEAN | `file-verdicts.md` LIVE. | - |
| crates/busbar-substrate-values/src/media.rs | CLEAN | `file-verdicts.md` LIVE. | - |
| crates/busbar-substrate-values/src/proto.rs | FINDING | `file-verdicts.md:193` HALF-MIGRATED (13/79 top-level symbols already exist at busbar-contract+busbar-kernel per spec DECISION #37), re-verified: `grep -n "fn declared_verbs"` in this file and `git grep -ln "fn declared_verbs"` → also declared at `crates/busbar-kernel/src/proto/registry.rs`, confirming the overlap is real and not a stale claim. | X-3307 |
| crates/busbar-substrate-values/src/tests/proto.rs | CLEAN | `file-verdicts.md` TEST. `grep -c '#\[test\]'` = 2, 0 tautological. | - |
| crates/busbar-timing/src/lib.rs | CLEAN | `file-verdicts.md` LIVE. | - |
| crates/busbar-transport-grpc/src/mount.rs | CLEAN | `file-verdicts.md` LIVE. | - |
| crates/busbar-transport-http/src/lib.rs | CLEAN | `file-verdicts.md` LIVE (note: `civil_to_epoch_secs`/`month_from_abbrev` — sub-threshold collision, not DUPLICATE). | - |
| crates/busbar-transport-http/src/mount.rs | CLEAN | `file-verdicts.md` LIVE. | - |
| crates/busbar-transport-http/src/tests/mount.rs | CLEAN | `file-verdicts.md` TEST. `grep -c '#\[test\]'` = 17, 0 tautological. | - |
| crates/busbar-transport-http/tests/no_plane_names.rs | FINDING | `file-verdicts.md:249` DUPLICATE (whole-file, comment/whitespace-normalised identical to `busbar-transport-grpc/tests/no_plane_names.rs`), re-verified: `diff <(git show HEAD:crates/busbar-transport-http/tests/no_plane_names.rs) <(git show HEAD:crates/busbar-transport-grpc/tests/no_plane_names.rs)` → empty diff, exit 0. Still a real instrument (`grep -c '#\[test\]'` = 3, non-tautological) — the finding is the duplication, not blindness. | X-3308 |
| crates/busbar-transport-sse/src/lib.rs | CLEAN | `file-verdicts.md` LIVE. | - |
| crates/busbar-transport-sse/src/proto.rs | CLEAN | `file-verdicts.md` LIVE (note: `terminator_len` — sub-threshold collision). | - |
| crates/busbar-transport-sse/src/reframe.rs | FINDING | `file-verdicts.md:145,156` ORPHAN, VERIFIED myself and promoted with a positive control: `git grep -n "install_sse_reframe"` → only caller is its own `tests/reframe_tests.rs:90`; `git grep -n "sse_reframe()"` → only reader is the same test. **Positive control**: the sibling seam of identical shape, `install_hostless_egress`, IS installed in production at `crates/busbar/src/main.rs:665` — proving the zero on `install_sse_reframe` is a real asymmetry, not a grep failure. The free functions `prefers_event_stream`/`reframe` that back the seam are themselves never called outside `PassThroughReframe` (itself only test-constructed) and their own tests; the file's own header calls this "ADDITIVE AND DORMANT". Single most serious finding in this slice. | X-3309 |
| crates/busbar-transport-stdio/src/tests/battery.rs | CLEAN | `file-verdicts.md` TEST (note: `test_key_handle`). `grep -c '#\[tokio::test\]\|#\[test\]\|async fn '` = 45 (plain `#[test]` alone false-zeroed — widened and controlled), 0 tautological. | - |
| crates/busbar-transport-stdio/src/transport.rs | CLEAN | `file-verdicts.md` LIVE. | - |
| crates/busbar-transport-tcp/src/lib.rs | CLEAN | `file-verdicts.md` LIVE. | - |
| crates/busbar-transport-tcp/src/tests/mod.rs | CLEAN | `file-verdicts.md` TEST (note: `an_undelivered_unit0_refusal_is_an_error`). `grep -c '#\[test\]'` = 1, 0 tautological. | - |
| crates/busbar-transport-tls/src/lib.rs | CLEAN | `file-verdicts.md` LIVE. `grep -n "dangerous\|insecure\|accept_invalid\|SkipServerVerification\|NoCertificateVerification"` → 0 hits (controlled: same grep syntax finds real hits elsewhere in the tree pattern-class, e.g. FIXME control below); no cert-verification bypass found. | - |
| crates/busbar-transport-tls/src/transport.rs | CLEAN | `file-verdicts.md` LIVE. Same dangerous-TLS grep, 0 hits. | - |
| crates/busbar-transport-ws/src/conn.rs | CLEAN | `file-verdicts.md` LIVE. | - |
| crates/busbar-transport-ws/src/tests/battery.rs | CLEAN | `file-verdicts.md` TEST (note: `test_key_handle`). `grep -c '#\[test\]'` = 2, 0 tautological (this file is a thin harness; the 45-test battery is stdio's, not this one — counts differ genuinely, not a copy). | - |
| crates/busbar-transport-ws/src/transport.rs | CLEAN | `file-verdicts.md` LIVE. | - |
| crates/busbar-unit-transport-key/src/lib.rs | CLEAN | `file-verdicts.md` LIVE. Full read: TLS material never logged (errors name only the secret SOURCE, `load_cert_chain`/`load_private_key` never echo bytes), `mTLS` vs server-only TLS is explicit on `client_ca_pem` presence, `#![forbid(unsafe_code)]`. `issue_handle`/`provision_server` are the real production entry points (doc: "the transport-key unit is the only caller"). | - |
| crates/busbar-unit-transport-key/src/tests.rs | CLEAN | `file-verdicts.md` TEST. `grep -c '#\[test\]'` = 14, 0 tautological. | - |
| crates/busbar-voice-codec/src/ir/codec/gemini/tests.rs | CLEAN | `file-verdicts.md` TEST. `grep -c '#\[test\]'` = 49, 0 tautological. | - |

## ROWS RAISED

### X-3300 · `busbar-mcp/src/mcp/client/issue.rs::issue` — the one governed path for 5 MCP verbs has zero production callers
CLASS:     missing-code
CERTAINTY: VERIFIED
EVIDENCE:  `git grep -n "issue::issue(\|client::issue("` and `git grep -n '\bissue('` under `crates/busbar-mcp/**/*.rs` show every call site of `issue()` is in `crates/busbar-mcp/src/mcp/tests/http_client_leg_tests.rs` or `crates/busbar-mcp/src/mcp/tests/stdio_client_leg_tests.rs`. Zero hits outside `tests/`. The function itself is the sole egress-gated, SSRF-checked, audit-recorded path for `prompts/list`, `prompts/get`, `resources/read`, `completion/complete`, `ping`, `tasks/get` (`super::verb::UpstreamVerb`) — everything an upstream MCP server offers besides `tools/call`. The file's own doc concedes it: *"NO INBOUND CALLER YET… What does not exist is the SERVER-plane method that would proxy a caller's `prompts/list` to an upstream's."*
ACTION:    Either build the server-plane proxy method(s) that call `issue()` for the missing verbs (the gap the file names), or, if 1.6.0 intentionally ships `tools/call`-only MCP egress, delete or `#[cfg(test)]`-gate the unreached verb machinery so it stops reading as shipped. Owner call: this is a customer-facing capability gap (5 of 6 MCP client verbs are unusable today), not a code-quality nit.

### X-3301 · `busbar-mcp/src/mcp/method.rs` — `tap_join_verdict`/`TAP_CHAIN` duplicated with `busbar-a2a/src/a2a/receive.rs`, `structure-lint:plane-dup:unledgered` RED
CLASS:     abi
CERTAINTY: VERIFIED
EVIDENCE:  `grep -n "fn tap_join_verdict\|TAP_CHAIN" crates/busbar-mcp/src/mcp/method.rs crates/busbar-a2a/src/a2a/receive.rs` → both files independently declare `const TAP_CHAIN` and `fn tap_join_verdict` (method.rs:2468/2519; receive.rs:1049/1096). `docs/design/1.6.0-file-verdicts.md:218` records the `structure-lint:plane-dup:unledgered` gate is RED on this pair, and that `method.rs` is separately HALF-MIGRATED (8/63 top-level symbols already exist in `busbar-plane-mcp`).
ACTION:    Fold the tap-join-verdict logic to one shared implementation the two plane crates call, per the `plane-dup` lint's own rule, and continue the migration of `method.rs`'s 8 already-duplicated symbols into `busbar-plane-mcp` rather than leaving both live. Owner: file-verdicts.md explicitly flags this file money-adjacent though not itself a money park — prioritise accordingly.

### X-3302 · `busbar-mcp/src/record.rs` — `encode`/`decode` record codec duplicated with `busbar-a2a/src/record.rs`
CLASS:     abi
CERTAINTY: VERIFIED
EVIDENCE:  `grep -n "^fn encode\|^fn decode" crates/busbar-mcp/src/record.rs crates/busbar-a2a/src/record.rs` → both files independently declare `fn encode<T: serde::Serialize>` / `fn decode<T: serde::de::DeserializeOwned>` (record.rs:210/215; a2a's record.rs:167/172).
ACTION:    Fold to one shared record-codec implementation both plane crates call, per `docs/design/1.6.0-file-verdicts.md:220`.

### X-3303 · `busbar-plane-a2a/src/tests/facts.rs` — 64% duplicate of `busbar-plane-mcp/src/tests/facts.rs`
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:  `docs/design/1.6.0-file-verdicts.md:233`; re-verified `grep -n "fn a_bare_number_is_itself\|fn a_padded_identifier_is_not_the_number_it_pads" crates/busbar-plane-a2a/src/tests/facts.rs crates/busbar-plane-mcp/src/tests/facts.rs` — both hit at matching line structure.
ACTION:    Share the correlation-facts test battery between the two plane crates (a common test-support crate or `#[path]`-included shared module) so a fix to one copy cannot silently leave the other stale.

### X-3304 · `busbar-plane-a2a/src/tests/records.rs` — 41% duplicate of `busbar-plane-mcp/src/tests/records.rs`
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:  `docs/design/1.6.0-file-verdicts.md:235`; re-verified `grep -n "fn every_schema_declares_known_operations\|fn no_schema_is_declared_twice" crates/busbar-plane-a2a/src/tests/records.rs crates/busbar-plane-mcp/src/tests/records.rs` — both hit.
ACTION:    Same remedy as X-3303, applied to the records test battery.

### X-3305 · `busbar-plane-mcp/src/facts.rs` — 45% duplicate of `busbar-plane-a2a/src/facts.rs`
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:  `docs/design/1.6.0-file-verdicts.md:240`; re-verified `grep -n "fn correlation_for\|fn is_canonical_number\|fn correlation_value" crates/busbar-plane-mcp/src/facts.rs crates/busbar-plane-a2a/src/facts.rs` — both hit at matching signatures.
ACTION:    Fold `correlation_for`/`correlation_value`/`is_canonical_number` to one shared implementation both plane crates depend on.

### X-3306 · `busbar-plane-mcp/src/jsonrpc.rs` — 33% duplicate of `busbar-plane-a2a/src/jsonrpc.rs`
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:  `docs/design/1.6.0-file-verdicts.md:241`; re-verified `grep -n "fn read\b\|fn id_shape\|fn is_number" crates/busbar-plane-mcp/src/jsonrpc.rs crates/busbar-plane-a2a/src/jsonrpc.rs` — both hit at matching signatures.
ACTION:    Fold `read`/`id_shape`/`is_number` (JSON-RPC id-shape recognition) to one shared implementation — two independent copies of an id-parsing rule are two chances for the correlation defence to diverge.

### X-3307 · `busbar-substrate-values/src/proto.rs` — HALF-MIGRATED, 13/79 symbols already at `busbar-contract`+`busbar-kernel` (spec DECISION #37)
CLASS:     abi
CERTAINTY: VERIFIED
EVIDENCE:  `docs/design/1.6.0-file-verdicts.md:193`; re-verified `git grep -ln "fn declared_verbs"` → also declared at `crates/busbar-kernel/src/proto/registry.rs`, confirming real overlap (not a stale claim) between this file and the spec-named new home.
ACTION:    Continue the #37 migration: retire the 13 shared symbols here in favour of the `busbar-contract`/`busbar-kernel` copies, or explain in-tree why this file's copy must remain the live one (matching the kernel slice's own P4-style money-copy caution about which fork is "serving").

### X-3308 · `busbar-transport-http/tests/no_plane_names.rs` — whole-file duplicate of `busbar-transport-grpc/tests/no_plane_names.rs`
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:  `diff <(git show HEAD:crates/busbar-transport-http/tests/no_plane_names.rs) <(git show HEAD:crates/busbar-transport-grpc/tests/no_plane_names.rs)` → empty diff, exit 0. Also recorded at `docs/design/1.6.0-file-verdicts.md:248-249`.
ACTION:    Move the shared assertion into one test-support crate both transport crates depend on (or a workspace-level integration test), rather than maintaining two byte-identical copies that can silently diverge on the next edit to either.

### X-3309 · `busbar-transport-sse/src/reframe.rs` — the SSE-reframe host-capability seam is fully built, tested, and never installed in production
CLASS:     missing-code
CERTAINTY: VERIFIED
EVIDENCE:  `git grep -n "install_sse_reframe"` under `crates/**/*.rs` → the only caller is `crates/busbar-transport-sse/src/tests/reframe_tests.rs:90`. `git grep -n "sse_reframe()"` → the only reader is the same test file. **Positive control**: the sibling seam of identical shape and vintage, `install_hostless_egress` (same DECISION #26 wave, same doc-comment pattern), IS installed in production at `crates/busbar/src/main.rs:665` — proving this is a real, measured asymmetry and not a grep/false-zero artefact. The free functions backing the seam (`prefers_event_stream`, `reframe`) have no caller outside `PassThroughReframe` (itself only test-constructed) and their own test module. The file's own header states this plainly: *"NOTHING on the shipped path consults the seam yet… ADDITIVE AND DORMANT."* Also recorded at `docs/design/1.6.0-file-verdicts.md:145,156-158` (ORPHAN, one of three `OnceLock` install-seam orphans found in that sweep).
ACTION:    Either wire a mount to opt into `sse_reframe()` (the intended next step per the file's own header — "a mount consumes this only once a plane declares it wants the reframe"), or remove the seam if no mount plans to. As written, an operator reading this module's extensive doc comments would reasonably believe SSE responses can carry ahead-of-result log records; today none do, on any door.

### X-3310 · `busbar-mcp/src/mcp/client/mod.rs::McpClientEngine` — a full registry+catalogue+pool engine abstraction with zero production callers
CLASS:     missing-code
CERTAINTY: VERIFIED
EVIDENCE:  `git grep -n "McpClientEngine"` across `crates/**/*.rs` → 3 non-definition hits total, all in `crates/busbar-mcp/src/mcp/client/tests/engine_tests.rs` and `.../tests/surface_tests.rs`. Production instead constructs `McpRuntime` directly from `config::ToolsCfg` at `crates/busbar-mcp/src/mcp/mod.rs:313-319` (`CatalogueCache::new()` called inline at line 319), bypassing `McpClientEngine::register`/`deregister`/`registration` entirely. `McpServerRegistration`/`McpServerRegistration::new`/`Endpoint` share the same fate — every item in this struct family is `#[allow(dead_code)]` and reached only from the two test files above.
ACTION:    Either delete `McpClientEngine`/`McpServerRegistration`/`Endpoint` (superseded by the `config::ToolsCfg`-driven `McpRuntime` path — confirm with the author of the config-driven path before deleting, since the two `#[allow(dead_code)]` test files would need to move to whatever fixture replaces them) or, if this is scaffolding for a future non-config registration API (e.g. a dynamic `connect` admin verb), say so in the module doc the way `issue.rs`/`connect.rs` already do for the adjacent gap — right now nothing in the file states this engine has no caller, unlike its neighbours.

## TALLY
files in slice:  83
verdict lines:   83
CLEAN:           72
FINDING:         11      rows raised: 11
DELETABLE:       0
UNREADABLE:      0
