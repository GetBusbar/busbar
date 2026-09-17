# busbar 1.6.0 — open-HIGH drive log

Branch `integration/oracle-phase0`. This log records the drive against the open HIGH audit
findings: what was root-caused and fixed in place, and what is PARKED for owner sign-off per
DECISIONS #10 (a genuine change to a money/user-visible byte is never self-fixed — it is parked
with cell + exact diff + root-cause + recommendation, and the shadow-oracle against the 1.5.5
golden is the arbiter).

Every finding below was re-read against the live code first; all six were confirmed STILL
PRESENT (none stale/already-fixed).

## FIXED

### busbar-unit-breaker — no-response upstream failure never trips the breaker  (SHA 3cbf9b1e4)

- **Cell:** `crates/busbar-unit-breaker/src/classify.rs` `normalize_raw_error`, Step-2 status ladder.
- **Root cause:** a transport failure with no HTTP/gRPC response (`port.rs` builds
  `RawUpstreamError { http_status: http_status.unwrap_or(0), .. }` when `status.code == None`)
  arrives as `http_status == 0`, which matched none of the ladder arms and fell through to the
  final `else` — the arm meant for an *unexpected 2xx/3xx success* — and was classified
  `StatusClass::ClientError` → `Disposition::ClientFault` → `Outcome::RecordNothing`. A
  destination that failed this way was never recorded against its cell and kept taking full
  traffic.
- **Why this is a required correctness change, not a divergence:** 1.5.5's legacy breaker
  (`crates/busbar-a2a/src/a2a/relay.rs` `classify_hop`) maps a `RelayRefusal::Transport` — the
  no-response failure — to `StatusClass::Network` (a transient upstream failure that trips the
  cell). The units-extraction breaker regressed that. The fix restores 1.5.5 behaviour; the
  disposition drives the breaker cell / failover only, not any money byte of the current unit.
- **Fix:** added an explicit `http_status == 0 => StatusClass::Network` arm (TransientUpstream →
  `Outcome::Transient`, which trips the cell), leaving the unexpected-2xx/3xx case as
  `ClientError`. Corrected `tests/port.rs::no_code_at_all_*`, which had asserted — and falsely
  attributed to 1.5.5 — the regressed no-penalty behaviour.

## PARKED — owner / shadow-oracle sign-off (DECISIONS #10)

All five change a **user-visible wire byte or a metering-unit (money) boundary** in the new
plane-extraction crates. Their byte-faithful target vs the 1.5.5 golden is decided by the
shadow-oracle (linux-gated), which is not runnable in this worktree, and no mechanical 1.5.5
mirror exists to copy (the legacy a2a refusal path renders through scattered HTTP-status /
admission-specific paths in `busbar-a2a/src/a2a/receive.rs`, not a single kernel-`RefusalReason`
→ JSON-RPC table). Each is real and reproduced; none is forced.

### P1 — busbar-plane-a2a: 33 of 42 refusal reasons collapse to JSON-RPC internal error
- **Cell:** `crates/busbar-plane-a2a/src/plane.rs` `refusal_render` (lines ~179-207).
- **Diff of behaviour:** only 9 of the 42 `busbar_contract::unit::RefusalReason` variants are
  mapped; the `_` arm sends `CODE_INTERNAL` (-32603) for the rest — so `RateLimited`,
  `BreakerOpen`, `Drain`, `OverBudget`, `GroupFrozen`, `PoolNotPermitted`, `Replayed`, … all
  reach the caller as a node/internal fault.
- **Root cause:** incomplete match with a catch-all; the "kind skeleton" requires an exhaustive
  mapping so a new reason cannot silently collapse.
- **Recommendation:** make the match exhaustive (remove `_`), mapping each reason to its correct
  A2A JSON-RPC code — validate the exact codes/messages against the 1.5.5 shadow-oracle golden
  before landing (these are client-visible protocol bytes).

### P2 — busbar-plane-mcp: same refusal collapse (33 of 42 → internal)
- **Cell:** `crates/busbar-plane-mcp/src/plane.rs` `refusal_render` (lines ~351-379).
- Same root cause and recommendation as P1, against the MCP wire code table.

### P3 — busbar-plane-a2a: unary answers never end their metering unit; empty envelopes do
- **Cell:** `crates/busbar-plane-a2a/src/plane.rs` `decode_response`, line ~565:
  `let terminal = is_error || final_event || !has(body, "/result/kind");`
- **Diff of behaviour:** terminality is keyed on the *absence* of `/result/kind`. A real unary
  Task/Message answer *carries* a `kind`, so `terminal == false` → emitted as
  `Progress::Frame`/`TurnComplete` and the metering unit is never ended. An envelope with neither
  result nor error has no `kind`, so `terminal == true` → billed `Complete`. Backwards.
- **Root cause:** wrong terminality predicate.
- **Why parked:** the unit boundary is a money event (unit closure/billing). Fix likely keys
  terminality on the presence of a `result` (unary answer) or a streaming `final:true`, not on
  the absence of `kind` — but the resulting metering bytes must be proven against the 1.5.5
  oracle golden.

### P4 — busbar-plane-mcp: an answer with neither result nor error is billed complete
- **Cell:** `crates/busbar-plane-mcp/src/plane.rs` `decode_response`, terminal-class decision
  (lines ~614-637). `is_error = has(PTR_ERROR)`; a document with neither `result` nor `error`
  falls to `FinishClass::Complete` → `Progress::Terminal`.
- **Root cause:** never checks that a `result` member is actually present.
- **Recommendation / parked reason:** same metering-boundary/money concern as P3; oracle-gated.

### P5 — busbar-plane-voice: streamed tool-call arguments are discarded
- **Cell:** `crates/busbar-plane-voice/src/plane.rs` `progress_from_server_event`
  (lines ~1013-1059). `IrDuplexTool::CallOpen` mints the `tool_call` unit with `body_ir:
  Ir::empty()` and only name+call_id facts; `CallArgs { json_delta }` and `CallClose` fall into
  the `Tool(_)` catch-all and are dropped. No accumulation buffer exists, so a tool call reaches
  its executor with a name and an id and **no arguments** — contradicting the `ToolExecutor` doc
  contract in `tools.rs`.
- **Root cause:** the argument-accumulation-across-frames + emit-on-close path was never
  implemented (the module doc calls it intentional-for-now).
- **Why parked:** architectural — needs cross-frame state to buffer `json_delta` and emit the
  `(name, arguments)` executor call on `CallClose`; the executor result feeds back to the model
  (user-visible). Needs owner direction on the tool-execution wiring, then oracle validation.

### P6 — busbar-llm-codec: provider usage shortfall computed, threaded, read by nobody
- **Cell:** `crates/busbar-llm-codec/src/gemini/mod.rs` `gemini_usage_identity_note` produces
  `UsageIdentityNote { reported_total, summed_total, unaccounted, .. }`; folded in
  `proto_stream.rs::merge_trailing_usage` (line ~1539) into `acc.usage_identity_note`; declared
  in `ir/types.rs`. Metering reads `IrUsage::to_token_usage` (ir/types.rs ~1098), which uses only
  the per-bucket totals. No consumer ever reads the note or its `unaccounted` shortfall (its own
  doc says populating it "can never change what busbar bills").
- **Diff of behaviour:** a Gemini turn whose provider `totalTokenCount` exceeds the summed
  buckets is metered on the smaller bucket total.
- **Why parked (money-path):** billing on the summed buckets vs the provider-reported total is a
  money decision. Recommendation: confirm against the 1.5.5 oracle golden whether 1.5.5 billed on
  summed buckets (if so, current behaviour is 1.5.5-faithful and the real defect is the dead
  diagnostic note — wire it to diagnostics or remove it, both byte-safe); otherwise the owner
  decides whether to bill the reported total (a money-byte change).
