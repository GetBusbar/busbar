// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TWO EVENT UNIONS — the four layers projected onto the two directions of travel. Design §2.6.
//!
//! [`IrServerEvent`] is the SIBLING of `busbar-llm`'s `IrStreamEvent` (server→client, response-shaped),
//! NOT an extension of it. [`IrClientEvent`] is the genuine net-new IR work: a client→server event
//! vocabulary that has NO analog anywhere in the tree today (the LLM request path is whole-JSON
//! `IrRequest`, not a stream of events).

use crate::ir::control::IrDuplexControl;
use crate::ir::media::IrAudioFrame;
use crate::ir::tool::IrDuplexTool;
use crate::ir::usage::IrDuplexUsage;

/// CLIENT → SERVER events (§2.6). The union of the client-originated cases across the four layers.
/// **This vocabulary has no analog anywhere in the tree today** — building it is the net-new IR work.
#[derive(Debug, Clone, PartialEq)]
pub enum IrClientEvent {
    /// An uplink audio frame (`dir: Up`).
    AudioFrame(IrAudioFrame),
    /// A session-control / config event the client sent (reconciled against the locked config).
    Control(IrDuplexControl),
    /// A server-side tool RESULT the plane authored back toward the upstream (`CallResult`).
    Tool(IrDuplexTool),
}

/// SERVER → CLIENT events (§2.6). The union of the server-originated cases across the four layers —
/// the sibling of `IrStreamEvent`, plane-owned.
#[derive(Debug, Clone, PartialEq)]
pub enum IrServerEvent {
    /// A tool-call announcement / argument delta / close (`CallOpen` / `CallArgs` / `CallClose`).
    Tool(IrDuplexTool),
    /// The user began speaking — barge-in trigger (`input_audio_buffer.speech_started`).
    SpeechStarted,
    /// The user stopped speaking (`input_audio_buffer.speech_stopped`).
    SpeechStopped,
    /// A downlink audio frame (`dir: Down`).
    AudioFrame(IrAudioFrame),
    /// Extracted usage for a completed turn (`response.done.usage`).
    Usage(IrDuplexUsage),
    /// A rate-limit update (`rate_limits.updated`) — extraction-only.
    RateLimits,
    /// An upstream error surfaced on the session.
    Error {
        /// A stable, dialect-normalized error code.
        code: String,
        /// A human-readable message.
        message: String,
    },
}
