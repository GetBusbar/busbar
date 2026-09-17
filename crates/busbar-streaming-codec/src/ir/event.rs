// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TWO EVENT UNIONS — the four layers projected onto the two directions of travel. Design `plane4-duplex-session.md`.
//!
//! [`IrServerEvent`] is the SIBLING of `busbar-llm`'s `IrStreamEvent` (server→client, response-shaped),
//! NOT an extension of it. [`IrClientEvent`] is the genuine net-new IR work: a client→server event
//! vocabulary that has NO analog anywhere in the tree today (the LLM request path is whole-JSON
//! `IrRequest`, not a stream of events).

use crate::ir::control::IrDuplexControl;
use crate::ir::media::IrAudioFrame;
use crate::ir::tool::IrDuplexTool;
use crate::ir::usage::IrDuplexUsage;

/// CLIENT → SERVER events (`plane4-duplex-session.md`). The union of the client-originated cases across the four layers.
/// **This vocabulary has no analog anywhere in the tree today** — building it is the net-new IR work.
#[derive(Debug, Clone, PartialEq)]
pub enum IrClientEvent {
    /// An uplink audio frame (`dir: Up`) — `input_audio_buffer.append`.
    AudioFrame(IrAudioFrame),
    /// A session-control / config event the client sent (reconciled against the locked config).
    Control(IrDuplexControl),
    /// A server-side tool RESULT the plane authored back toward the upstream (`CallResult`).
    Tool(IrDuplexTool),
}

/// SERVER → CLIENT events (`plane4-duplex-session.md`). The union of the server-originated cases across the four layers —
/// the sibling of `IrStreamEvent`, plane-owned.
#[derive(Debug, Clone, PartialEq)]
pub enum IrServerEvent {
    /// The upstream acknowledged the session and returned its resolved config — `session.created`.
    /// Carried VERBATIM as opaque JSON (it holds server-assigned fields — `id`, `model`, `expires_at`
    /// — beyond the writable `SessionConfig` subset).
    SessionCreated {
        /// The resolved `session` object, opaque.
        session: serde_json::Value,
    },
    /// A tool-call announcement / argument delta / close (`CallOpen` / `CallArgs` / `CallClose`).
    Tool(IrDuplexTool),
    /// The user began speaking — barge-in trigger (`input_audio_buffer.speech_started`).
    SpeechStarted {
        /// Uplink-buffer offset (ms) where speech began.
        audio_start_ms: u64,
        /// The conversation item the buffered speech is being attributed to.
        item_id: String,
    },
    /// The user stopped speaking (`input_audio_buffer.speech_stopped`). `audio_end_ms` is the carrier
    /// the truncate math reads to bound the just-heard turn.
    SpeechStopped {
        /// Uplink-buffer offset (ms) where speech ended.
        audio_end_ms: u64,
        /// The conversation item the buffered speech is being attributed to.
        item_id: String,
    },
    /// A downlink audio frame (`dir: Down`) — `response.output_audio.delta`.
    AudioFrame(IrAudioFrame),
    /// The downlink audio for an item is complete — `response.output_audio.done`.
    AudioDone {
        /// The item whose audio just completed.
        item_id: String,
    },
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
