// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The protocol handlers — the design's middle, in one module:
//!
//! `Router → RequestHandler → OperationHandler → IR`
//!
//! - [`RequestHandler`](busbar_contract::codec::RequestHandler) — ONE per protocol (`openai.rs`, `anthropic.rs`, …). Dumb and
//!   protocol-specific: reads path+body to decide WHICH operation a request asks for
//!   (`resolve_operation`), owns the `(protocol, operation) → path template` (`upstream_path`), and
//!   holds its row of the support matrix (`operation_handler`; `None` = the no-handler 404).
//! - [`OperationHandler`](busbar_contract::codec::OperationHandler) — ONE per (protocol × operation). A pure codec: wire ↔ IR, both
//!   directions, plus the operation-capability surface the engine reads. It never routes, fails
//!   over, checks auth, bills, or knows another protocol exists.
//! - The kernel resolves neither: a plane matches its own claimed routes and its dialects resolve
//!   their own handlers inside it (spec Part 1, Law 5).
//!
//! Adding a protocol: a Router ID line, a `RequestHandler` impl here, its OperationHandlers, and a
//! `CELLS` table naming the verbs it speaks. Adding an OPERATION: an OperationHandler plus a row in
//! the `CELLS` table of each protocol that speaks it — a row, not a match arm, and only in the
//! protocols that speak it, because a verb is that protocol's vocabulary and not a core enum's
//! variant (see [`Cell`](busbar_contract::codec::Cell), and `operation.rs` for what the core kept: the SHAPE). Adding a
//! TRANSPORT: a variant in `transport.rs` and an arrival that frames these same codecs — no codec
//! changes, because a codec never learns which channel it is speaking over. Nothing else moves.
//!
//! THE CODEC-CELL SHAPES LIVE IN THE CONTRACT (`busbar_contract::codec`, #83a SD-2b): the
//! `OperationHandler` / `RequestHandler` traits, the `Cell` / `cell_of` / `path_of` row helpers and
//! the `IngressReject` / `CodecError` reject enums, named there by every caller. The cross-dialect
//! translate pipeline is the LLM plane's own, and a plane renders its own refusals and reads its
//! own far end's errors through its door (spec Part 3 section 12): the kernel frames no codec
//! cell, reads no codec's usage and resolves no error vocabulary. What lives HERE is the host's
//! usage-tap fault reporting the install arms.

// EVERY LLM DIALECT'S HANDLER LIVES IN THE the retired engine crate PLUGIN CRATE — anthropic, openai-chat,
// gemini, bedrock, cohere and openai-responses — each in its own dialect module's `handler.rs`.
// The kernel holds no protocol registry: a plane resolves its own dialects' handlers.
// `ChatOperation` RELOCATED to the plugin too at the G6 A4b dissolve (`the retired engine crate/src/chat_handle.rs`): once
// `IrReq`/`IrResp` dissolved onto `Box<dyn IrHandle>`, the chat codec names the concrete chat IR
// that now lives in the plugin, so it cannot stay in core. Core names no chat codec.
// THE EXTRACTED MCP PROTOCOL CODEC lives wholly in the `busbar-mcp` plugin crate
// (`crates/busbar-mcp/src/codec`). Its `#[path]` witness re-include into core (which let the
// pre-extraction fixture surface reach the real MCP codec from inside core's own test binary, back
// when a `ProtocolDecl` was a `busbar-core` type an external crate could not hand to the registry)
// was DELETED: `ProtocolDecl` now lives in `busbar-substrate`, so core's test binary reads
// `busbar_mcp::PROTO_DECL` directly (dev-dependency). That protocol's plane is its own door
// plane, outside this crate.

// THE USAGE-TAP FAULT COUNT (row 155): a plane returns a usage-tap fault as data on its door's
// answer (`abi::plane::OnPieceOut::tap_fault`), and the kernel counts it here on
// `busbar_kernel::snapshot::BILLING_TAP_DECODE_FAIL_TOTAL`, warning once per `(protocol, reason)`.

/// Process-lifetime warn-once latch for the usage-tap decode fault class, keyed `protocol:reason`. A
/// live protocol/dialect the tap reader cannot decode fails on EVERY 2xx body of that shape, so an
/// unlatched `warn!` spams per request; [`BILLING_TAP_DECODE_FAIL_TOTAL`](crate::snapshot::BILLING_TAP_DECODE_FAIL_TOTAL) carries the per-request
/// volume. This records the fault (increments the counter) and returns `true` only the FIRST time a
/// given `(protocol, reason)` is seen, so the caller warns once and logs `debug!` thereafter.
pub fn usage_tap_decode_fail_should_warn(protocol: &str, reason: &'static str) -> bool {
    metrics::counter!(
        crate::snapshot::BILLING_TAP_DECODE_FAIL_TOTAL,
        "protocol" => protocol.to_string(),
        "reason" => reason,
    )
    .increment(1);
    static SEEN: std::sync::LazyLock<std::sync::Mutex<std::collections::HashSet<String>>> =
        std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashSet::new()));
    let mut seen = SEEN.lock().unwrap_or_else(|e| e.into_inner());
    seen.insert(format!("{protocol}:{reason}"))
}

/// COUNT ONE USAGE-TAP FAULT a plane's answer carried for a unit read in `protocol`: one increment
/// of [`BILLING_TAP_DECODE_FAIL_TOTAL`](crate::snapshot::BILLING_TAP_DECODE_FAIL_TOTAL) under
/// `reason`, warned the first time the `(protocol, reason)` is seen and logged at debug after. The
/// request billed 0 tokens for its tap; the plane names the fault, the kernel counts it.
pub fn usage_tap_fault(protocol: &str, reason: &'static str) {
    if usage_tap_decode_fail_should_warn(protocol, reason) {
        crate::diagnostics::diag_warn!(
            crate::diagnostics::USAGE_TAP_DECODE_FAILED,
            protocol = protocol,
            reason = reason,
            "usage tap: a same-protocol 2xx body's usage could not be read; \
             billing 0 tokens for this request"
        );
    } else {
        crate::diagnostics::diag_debug!(
            crate::diagnostics::USAGE_TAP_DECODE_FAILED,
            protocol = protocol,
            reason = reason,
            "usage tap: a same-protocol 2xx body's usage still could not be read; \
             billing 0 tokens for this request"
        );
    }
}

// The handler test modules (`use super::*`) name the verb vocabulary; production code here spells
// it by path.
#[cfg(test)]
use crate::operation::OpVerb;

#[cfg(test)]
#[path = "tests/contract_tests.rs"]
mod contract_tests;
