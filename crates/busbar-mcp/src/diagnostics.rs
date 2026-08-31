// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! MCP plane diagnostics — the `MCP_*` catalog entries this crate OWNS.
//!
//! These consts were plane-specific vocabulary living in the neutral
//! `busbar_substrate::diagnostics` catalog; the plane extraction relocated them here so the neutral
//! crate names no `MCP_*` diagnostic. Each keeps its stable `BUSBAR-NNNN` number and slug — the
//! move preserves identity, it does not renumber: codes are REGISTERED, never collapsed.
//!
//! [`DIAGNOSTICS`] is the slice the composition root hands to
//! [`install_diagnostics`](busbar_substrate::diagnostics::install_diagnostics) so these codes join
//! the runtime catalog (`REGISTRY ∪ installed`) and resolve through `by_code`. The `busbar` binary
//! names one stable path: `busbar-mcp::DIAGNOSTICS`.

use busbar_substrate::diagnostics::{Class, Diagnostic, Severity};

pub const MCP_CALLLOG_CHAIN_VERIFY_FAILED: Diagnostic = Diagnostic {
    code: 2040,
    class: Class::Audit,
    slug: "mcp-calllog-chain-verify-failed",
    title: "MCP per-call log failed hash-chain verification on restore (tamper evidence)",
    severity: Severity::Actionable,
    summary: "The persisted MCP per-call log was read at boot but does NOT verify against its own \
              hash chain, which is tamper evidence — a persisted call record was altered out from \
              under busbar, or its store is corrupt. The records are still restored and the chain \
              resumes from the broken tail, because refusing to restore would let anyone able to \
              write to the store DELETE a caller's history by corrupting one record.",
    action: "Treat the durable governance store as compromised until explained: capture it for \
             forensic review before it is overwritten, then restore from a trusted backup once the \
             cause is understood.",
    since: "1.6.0",
    retired: false,
};

pub const MCP_CALLLOG_EMPTY_CHAINS: Diagnostic = Diagnostic {
    code: 7060,
    class: Class::Plane,
    slug: "mcp-calllog-empty-chains",
    title: "Durable MCP call log enumerates principals with NO records",
    severity: Severity::Actionable,
    summary: "At boot the durable MCP per-call log named one or more principals but returned no \
              records for them, so their chains reopen at seq 1. The verifier cannot distinguish \
              this from a caller's evidence being deleted wholesale, so it is surfaced rather than \
              summed silently into the restored total.",
    action: "Confirm whether these principals were expected to have call history. If they were, \
             treat the durable governance store as possibly tampered and capture it for review \
             before it is overwritten.",
    since: "1.6.0",
    retired: false,
};

pub const MCP_CALLLOG_UNREAD: Diagnostic = Diagnostic {
    code: 7061,
    class: Class::Plane,
    slug: "mcp-calllog-unread",
    title: "Durable MCP per-call log could not be read at boot",
    severity: Severity::Actionable,
    summary:
        "The durable MCP per-call log could not be read back at boot, so the persisted tail is \
              unknown and a principal that already has rows in the store may reopen its chain at \
              seq 1 and collide with a persisted sequence number.",
    action:
        "Check the durable governance store's health and connectivity. Once it answers, restart \
             so the per-call chains restore from a known tail.",
    since: "1.6.0",
    retired: false,
};

pub const MCP_DEMOTIONS_RESTORED: Diagnostic = Diagnostic {
    code: 7062,
    class: Class::Plane,
    slug: "mcp-demotions-restored",
    title: "MCP upstream demotions restored from the durable store",
    severity: Severity::Actionable,
    summary: "One or more MCP upstream servers were quarantined before the last restart and their \
              demotion records were replayed from the durable governance store, so they are refused \
              until an operator works the change or a sweep observes them serving what was approved.",
    action: "Investigate why each named server was demoted and either remediate it or clear its \
             demotion. Until then, requests routed to it are refused by design.",
    since: "1.6.0",
    retired: false,
};

pub const MCP_STDIO_READ_ERROR: Diagnostic = Diagnostic {
    code: 7063,
    class: Class::Plane,
    slug: "mcp-stdio-read-error",
    title: "MCP stdio serve read error on stdin (session ending)",
    severity: Severity::BenignRecurring,
    summary: "The MCP stdio server hit a read error on stdin and is shutting the session down. This \
              is the expected outcome when the peer closes the pipe, so it is logged at debug rather \
              than as an operator alert.",
    action: "None — self-heals. Expected when a stdio MCP client disconnects.",
    since: "1.6.0",
    retired: false,
};

pub const MCP_ASK_RECOGNISER_MISSED: Diagnostic = Diagnostic {
    code: 7064,
    class: Class::Plane,
    slug: "mcp-ask-recogniser-missed",
    title: "MCP input-required result reached the terminal check (ask recogniser missed)",
    severity: Severity::Actionable,
    summary:
        "An upstream MCP tool returned an input-required result that reached the terminal check \
              without the ask recogniser catching it — an internal invariant breach, since such a \
              result should have been recognised and handled earlier. The call is refused rather \
              than handing the caller an upstream's demand for a secret.",
    action: "Report the named tool and field: the ask-recognition path has a gap that let an \
             input-required shape through. This is a code-level fix, not an operator misconfig.",
    since: "1.6.0",
    retired: false,
};

pub const MCP_OUTPUT_SCHEMA_VIOLATION: Diagnostic = Diagnostic {
    code: 7065,
    class: Class::Plane,
    slug: "mcp-output-schema-violation",
    title: "MCP upstream structuredContent violates the published outputSchema",
    severity: Severity::BenignRecurring,
    summary: "An upstream MCP tool returned `structuredContent` that does not validate against the \
              tool's own published `outputSchema`, so the result is refused. This is an upstream \
              contract violation that can recur per request, so it is logged at debug to avoid spam.",
    action: "If a specific tool trips this repeatedly, report the schema mismatch to that MCP \
             server's operator. No local action is needed.",
    since: "1.6.0",
    retired: false,
};

pub const MCP_TOOLCALL_REFUSED: Diagnostic = Diagnostic {
    code: 7066,
    class: Class::Plane,
    slug: "mcp-toolcall-refused",
    title: "MCP tools/call refused by policy",
    severity: Severity::BenignRecurring,
    summary:
        "An MCP `tools/call` was refused by busbar's policy (budget, gate, or capability). This \
              is a routine per-request governance outcome, logged at debug so a busy caller cannot \
              spam the operator log.",
    action: "None — self-heals. The refusal reason is recorded in the audit and call log if a \
             specific caller needs to be understood.",
    since: "1.6.0",
    retired: false,
};

pub const MCP_TOOLCALL_UPSTREAM_FAILED: Diagnostic = Diagnostic {
    code: 7067,
    class: Class::Plane,
    slug: "mcp-toolcall-upstream-failed",
    title: "MCP tools/call upstream failed",
    severity: Severity::BenignRecurring,
    summary:
        "An MCP `tools/call` was dispatched and the upstream server failed to execute it. This \
              is reported to the model as a tool execution error (not a busbar refusal) and can \
              recur per request, so it is logged at debug.",
    action: "None locally — self-heals. If a specific upstream fails persistently, check that \
             server's health.",
    since: "1.6.0",
    retired: false,
};

pub const MCP_TOOLCALL_REFUSED_PRE_UPSTREAM: Diagnostic = Diagnostic {
    code: 7068,
    class: Class::Plane,
    slug: "mcp-toolcall-refused-pre-upstream",
    title: "MCP tools/call refused before the upstream",
    severity: Severity::BenignRecurring,
    summary:
        "An MCP `tools/call` was refused before it reached the upstream (a pre-dispatch policy \
              denial). Routine per-request governance, logged at debug to avoid spamming the \
              operator log under load.",
    action: "None — self-heals. The refusal reason is in the audit and call log.",
    since: "1.6.0",
    retired: false,
};

pub const MCP_CALLER_ASK_REFUSED: Diagnostic = Diagnostic {
    code: 7069,
    class: Class::Plane,
    slug: "mcp-caller-ask-refused",
    title: "MCP caller-ask refused",
    severity: Severity::BenignRecurring,
    summary: "A caller's MCP ask for a capability was refused by policy. This is a routine \
              per-request governance outcome, logged at debug so it cannot spam the operator log.",
    action: "None — self-heals. The refusal reason is recorded in the audit and call log.",
    since: "1.6.0",
    retired: false,
};

/// MCP'S PLANE-CONTRIBUTED DIAGNOSTICS — the `&'static [&'static Diagnostic]` the composition
/// root installs via `install_diagnostics`. Ascending by code, mirroring the neutral `REGISTRY`.
pub static DIAGNOSTICS: &[&Diagnostic] = &[
    &MCP_CALLLOG_CHAIN_VERIFY_FAILED,
    &MCP_CALLLOG_EMPTY_CHAINS,
    &MCP_CALLLOG_UNREAD,
    &MCP_DEMOTIONS_RESTORED,
    &MCP_STDIO_READ_ERROR,
    &MCP_ASK_RECOGNISER_MISSED,
    &MCP_OUTPUT_SCHEMA_VIOLATION,
    &MCP_TOOLCALL_REFUSED,
    &MCP_TOOLCALL_UPSTREAM_FAILED,
    &MCP_TOOLCALL_REFUSED_PRE_UPSTREAM,
    &MCP_CALLER_ASK_REFUSED,
];

#[cfg(test)]
#[path = "mcp/tests/diagnostics_tests.rs"]
mod diagnostics_tests;
