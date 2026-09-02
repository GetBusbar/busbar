// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! LAYER 1 — TOOL-CALL (full normalization; the moat). Design §2.2.
//!
//! The one layer where the IR genuinely reshapes the wire, and the whole reason a governed plane
//! beats a dumb WS pipe: tools execute server-side, under governance, and the browser is never trusted
//! to author them.

use bytes::Bytes;

/// THE CORRELATION ABSTRACTION for one in-flight tool call — NOT the wire `call_id`.
///
/// Modeled on the LLM plane's `IrDelta::InputJsonDelta` id-remap move (§2.2): a
/// `CallRef → (client_call_id, upstream_call_id)` table held in the session scope lets a client that
/// speaks OpenAI `call_id` be bridged to a Gemini Live tool-call that correlates by NAME, not id.
///
/// SKELETON: an opaque newtype over a monotonic per-session counter; the remap table is future work.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CallRef(pub u64);

/// THE NEUTRAL TOOL-CALL IR — busbar-owned, names no OpenAI noun in core. Modeled on
/// `IrDelta::InputJsonDelta`. `call_ref` is the join key across every variant.
///
/// The Realtime tool loop this normalizes: the model streams
/// `response.function_call_arguments.delta` → `…done`; busbar executes the tool server-side and
/// returns `conversation.item.create{ function_call_output }` then `response.create`. A tool-call turn
/// often produces NO audio until the result is fed back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IrDuplexTool {
    /// A function call was ANNOUNCED by the model (server→client). Carries the tool name.
    CallOpen {
        /// The correlation handle minted for this call.
        call_ref: CallRef,
        /// The tool name the model wants to invoke.
        name: String,
    },
    /// A STREAMED argument delta (server→client) — opaque JSON bytes appended to the call's arguments.
    CallArgs {
        /// The call this delta belongs to.
        call_ref: CallRef,
        /// One chunk of the streamed argument JSON, verbatim.
        json_delta: Bytes,
    },
    /// Arguments are COMPLETE (server→client) — the model has finished streaming this call's args.
    CallClose {
        /// The call whose arguments are now complete.
        call_ref: CallRef,
    },
    /// busbar's SERVER-SIDE RESULT (client→server) — authored by the plane after governance, never by
    /// the browser. Written back to the upstream as `function_call_output` + `response.create`.
    CallResult {
        /// The call this result answers.
        call_ref: CallRef,
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
            | IrDuplexTool::CallClose { call_ref }
            | IrDuplexTool::CallResult { call_ref, .. } => *call_ref,
        }
    }
}
