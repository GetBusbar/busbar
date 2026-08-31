# Busbar diagnostics catalog

Every operator-facing log line from busbar carries a stable `BUSBAR-NNNN` code in its `diag` field. Find the code below for what it means, whether it needs action, and what to do. This page is generated from the code — do not edit by hand.

Codes are grouped by class (the thousands digit).

## 2xxx — Audit chain

<a id="mcp-calllog-chain-verify-failed"></a>
### BUSBAR-2040 — MCP per-call log failed hash-chain verification on restore (tamper evidence)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `mcp-calllog-chain-verify-failed`

The persisted MCP per-call log was read at boot but does NOT verify against its own hash chain, which is tamper evidence — a persisted call record was altered out from under busbar, or its store is corrupt. The records are still restored and the chain resumes from the broken tail, because refusing to restore would let anyone able to write to the store DELETE a caller's history by corrupting one record.

**What to do:** Treat the durable governance store as compromised until explained: capture it for forensic review before it is overwritten, then restore from a trusted backup once the cause is understood.

## 7xxx — Plane protocols

<a id="mcp-calllog-empty-chains"></a>
### BUSBAR-7060 — Durable MCP call log enumerates principals with NO records

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `mcp-calllog-empty-chains`

At boot the durable MCP per-call log named one or more principals but returned no records for them, so their chains reopen at seq 1. The verifier cannot distinguish this from a caller's evidence being deleted wholesale, so it is surfaced rather than summed silently into the restored total.

**What to do:** Confirm whether these principals were expected to have call history. If they were, treat the durable governance store as possibly tampered and capture it for review before it is overwritten.

<a id="mcp-calllog-unread"></a>
### BUSBAR-7061 — Durable MCP per-call log could not be read at boot

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `mcp-calllog-unread`

The durable MCP per-call log could not be read back at boot, so the persisted tail is unknown and a principal that already has rows in the store may reopen its chain at seq 1 and collide with a persisted sequence number.

**What to do:** Check the durable governance store's health and connectivity. Once it answers, restart so the per-call chains restore from a known tail.

<a id="mcp-demotions-restored"></a>
### BUSBAR-7062 — MCP upstream demotions restored from the durable store

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `mcp-demotions-restored`

One or more MCP upstream servers were quarantined before the last restart and their demotion records were replayed from the durable governance store, so they are refused until an operator works the change or a sweep observes them serving what was approved.

**What to do:** Investigate why each named server was demoted and either remediate it or clear its demotion. Until then, requests routed to it are refused by design.

<a id="mcp-stdio-read-error"></a>
### BUSBAR-7063 — MCP stdio serve read error on stdin (session ending)

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `mcp-stdio-read-error`

The MCP stdio server hit a read error on stdin and is shutting the session down. This is the expected outcome when the peer closes the pipe, so it is logged at debug rather than as an operator alert.

**What to do:** None — self-heals. Expected when a stdio MCP client disconnects.

<a id="mcp-ask-recogniser-missed"></a>
### BUSBAR-7064 — MCP input-required result reached the terminal check (ask recogniser missed)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `mcp-ask-recogniser-missed`

An upstream MCP tool returned an input-required result that reached the terminal check without the ask recogniser catching it — an internal invariant breach, since such a result should have been recognised and handled earlier. The call is refused rather than handing the caller an upstream's demand for a secret.

**What to do:** Report the named tool and field: the ask-recognition path has a gap that let an input-required shape through. This is a code-level fix, not an operator misconfig.

<a id="mcp-output-schema-violation"></a>
### BUSBAR-7065 — MCP upstream structuredContent violates the published outputSchema

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `mcp-output-schema-violation`

An upstream MCP tool returned `structuredContent` that does not validate against the tool's own published `outputSchema`, so the result is refused. This is an upstream contract violation that can recur per request, so it is logged at debug to avoid spam.

**What to do:** If a specific tool trips this repeatedly, report the schema mismatch to that MCP server's operator. No local action is needed.

<a id="mcp-toolcall-refused"></a>
### BUSBAR-7066 — MCP tools/call refused by policy

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `mcp-toolcall-refused`

An MCP `tools/call` was refused by busbar's policy (budget, gate, or capability). This is a routine per-request governance outcome, logged at debug so a busy caller cannot spam the operator log.

**What to do:** None — self-heals. The refusal reason is recorded in the audit and call log if a specific caller needs to be understood.

<a id="mcp-toolcall-upstream-failed"></a>
### BUSBAR-7067 — MCP tools/call upstream failed

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `mcp-toolcall-upstream-failed`

An MCP `tools/call` was dispatched and the upstream server failed to execute it. This is reported to the model as a tool execution error (not a busbar refusal) and can recur per request, so it is logged at debug.

**What to do:** None locally — self-heals. If a specific upstream fails persistently, check that server's health.

<a id="mcp-toolcall-refused-pre-upstream"></a>
### BUSBAR-7068 — MCP tools/call refused before the upstream

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `mcp-toolcall-refused-pre-upstream`

An MCP `tools/call` was refused before it reached the upstream (a pre-dispatch policy denial). Routine per-request governance, logged at debug to avoid spamming the operator log under load.

**What to do:** None — self-heals. The refusal reason is in the audit and call log.

<a id="mcp-caller-ask-refused"></a>
### BUSBAR-7069 — MCP caller-ask refused

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `mcp-caller-ask-refused`

A caller's MCP ask for a capability was refused by policy. This is a routine per-request governance outcome, logged at debug so it cannot spam the operator log.

**What to do:** None — self-heals. The refusal reason is recorded in the audit and call log.

