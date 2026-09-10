// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! LAYER 1 — TOOL-CALL (full normalization; the moat). Design `plane4-duplex-session.md`.
//!
//! The one layer where the IR genuinely reshapes the wire, and the whole reason a governed plane
//! beats a dumb WS pipe: tools execute server-side, under governance, and the browser is never trusted
//! to author them.

use bytes::Bytes;

/// THE CORRELATION ABSTRACTION for one in-flight tool call — NOT the wire `call_id`.
///
/// Modeled on the LLM plane's `IrDelta::InputJsonDelta` id-remap move (`plane4-duplex-session.md`): a
/// `CallRef → (client_call_id, upstream_call_id)` table held in the session scope lets a client whose
/// dialect correlates a call by ID be bridged to an upstream whose dialect correlates it by NAME.
///
/// An opaque newtype over a monotonic per-session counter, minted in
/// [`crate::ir::codec::DecodeState`]. The `CallRef ↔ call_id` map lives there; each tool IR variant
/// ALSO carries the raw wire `call_id` so the stateless writer can re-frame `function_call_output`
/// without consulting the map.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CallRef(pub u64);

/// THE NEUTRAL TOOL-CALL IR — busbar-owned, and it names no dialect's noun. Modeled on
/// `IrDelta::InputJsonDelta`. `call_ref` is the join key across every variant; `call_id` is the raw
/// dialect id the wire correlates on (kept so a stateless writer can re-frame the result).
///
/// The tool loop this normalizes, in whatever tokens a dialect spells it: the model ANNOUNCES a call,
/// then STREAMS its arguments to a close; busbar executes the tool server-side, under governance, and
/// writes the RESULT back followed by a request for the next turn. A tool-call turn often produces no
/// media at all until that result is fed back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IrDuplexTool {
    /// A function call was ANNOUNCED by the model (server→client). Carries the tool name.
    CallOpen {
        /// The correlation handle minted for this call.
        call_ref: CallRef,
        /// The raw wire id the dialect correlates on.
        call_id: String,
        /// The tool name the model wants to invoke.
        name: String,
    },
    /// A STREAMED argument delta (server→client) — opaque JSON bytes appended to the call's arguments.
    CallArgs {
        /// The call this delta belongs to.
        call_ref: CallRef,
        /// The raw wire id the dialect correlates on.
        call_id: String,
        /// One chunk of the streamed argument JSON, verbatim.
        json_delta: Bytes,
    },
    /// Arguments are COMPLETE (server→client) — the model has finished streaming this call's args.
    CallClose {
        /// The call whose arguments are now complete.
        call_ref: CallRef,
        /// The raw wire id the dialect correlates on.
        call_id: String,
    },
    /// busbar's SERVER-SIDE RESULT (client→server) — authored by the plane after governance, never by
    /// the browser. Written back to the upstream as the dialect's own result item, then a turn request.
    CallResult {
        /// The call this result answers.
        call_ref: CallRef,
        /// The raw wire id the dialect correlates on.
        call_id: String,
        /// The tool NAME the result answers for, remembered from the call that opened it. Gemini's
        /// result item REQUIRES a name where another dialect's carries none, so the
        /// name rides the IR rather than being looked up by a writer that is deliberately stateless.
        /// EMPTY when the result answers a call this session never saw announced — a name nobody told
        /// us is not a name to invent, so it is simply omitted from the wire.
        name: String,
        /// The tool's opaque output payload.
        output: Bytes,
    },
}

impl IrDuplexTool {
    /// The correlation handle common to every variant.
    #[must_use]
    pub fn call_ref(&self) -> CallRef {
        match self {
            IrDuplexTool::CallOpen { call_ref, .. }
            | IrDuplexTool::CallArgs { call_ref, .. }
            | IrDuplexTool::CallClose { call_ref, .. }
            | IrDuplexTool::CallResult { call_ref, .. } => *call_ref,
        }
    }

    /// The raw dialect `call_id` common to every variant.
    #[must_use]
    pub fn call_id(&self) -> &str {
        match self {
            IrDuplexTool::CallOpen { call_id, .. }
            | IrDuplexTool::CallArgs { call_id, .. }
            | IrDuplexTool::CallClose { call_id, .. }
            | IrDuplexTool::CallResult { call_id, .. } => call_id,
        }
    }
}
