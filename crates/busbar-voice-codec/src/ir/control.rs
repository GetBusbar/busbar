// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! LAYER 2 — CONTROL / CONFIG (translatable; bites only cross-dialect). Design `plane4-duplex-session.md` §2.3.
//!
//! The session-control events are IR-translatable, but the translation only MATTERS cross-dialect
//! (OpenAI Realtime ⇄ Gemini Live). Same-dialect they are verbatim carriage (Layer-3 discipline). Two
//! load-bearing points the shapes below encode: instruction/tool locking is a control-layer invariant
//! (a client-originated `SessionConfigure` is a HINT reconciled against the locked config, never
//! trusted blind), and barge-in `audio_played_ms` is PLANE-COMPUTED IR state, not a wire field.

use crate::ir::config::SessionConfig;
use serde::{Deserialize, Serialize};

/// SEMANTIC-VAD EAGERNESS — how eagerly the model judges end-of-turn. The GA `semantic_vad` knob,
/// a closed set of dialect tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Eagerness {
    /// Waits longest before closing a turn.
    Low,
    /// The middle setting.
    Medium,
    /// Closes a turn quickly.
    High,
    /// Let the model pick.
    Auto,
}

fn default_threshold() -> f32 {
    0.5
}
fn default_prefix_padding_ms() -> u32 {
    300
}
fn default_silence_duration_ms() -> u32 {
    200
}
fn default_true() -> bool {
    true
}

/// VOICE-ACTIVITY-DETECTION config — the plane's neutral VAD surface. Its serde shape IS the GA
/// `turn_detection` object (tagged on `type`): `server_vad` with the threshold/padding/silence knobs,
/// or `semantic_vad` with an eagerness. VAD DISABLED is not a variant here — it is the ABSENCE of a
/// `turn_detection` (a `null` on the wire, `None` at [`SessionConfig::turn_detection`]).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum IrVad {
    /// Server-side voice-activity detection with amplitude threshold and silence windows.
    ServerVad {
        /// Activation threshold (0.0–1.0).
        #[serde(default = "default_threshold")]
        threshold: f32,
        /// Audio (ms) retained BEFORE detected speech, folded into the turn.
        #[serde(default = "default_prefix_padding_ms")]
        prefix_padding_ms: u32,
        /// Trailing silence (ms) that ends a turn.
        #[serde(default = "default_silence_duration_ms")]
        silence_duration_ms: u32,
        /// Whether the server auto-issues `response.create` at end-of-turn.
        #[serde(default = "default_true")]
        create_response: bool,
        /// Whether a new detected turn interrupts an in-flight response (barge-in).
        #[serde(default = "default_true")]
        interrupt_response: bool,
    },
    /// Semantic (model-judged) end-of-turn detection with an eagerness knob.
    SemanticVad {
        /// How eagerly the model closes a turn.
        eagerness: Eagerness,
    },
}

/// THE NEUTRAL CONTROL / CONFIG IR (`plane4-duplex-session.md` §2.3). Translatable, but same-dialect it is verbatim carriage.
#[derive(Debug, Clone, PartialEq)]
pub enum IrDuplexControl {
    /// Configure the session — the authoritative copy the plane holds server-side and re-applies; a
    /// client-originated one is a hint reconciled against the lock, never trusted blind. Carries the
    /// full typed GA `session` object ([`SessionConfig`]).
    SessionConfigure {
        /// The GA `session` config object.
        config: SessionConfig,
    },
    /// Ask the upstream to begin generating a response. Carries the optional per-response override
    /// object (`response.create`'s `response` field), verbatim.
    ResponseCreate {
        /// The optional per-response override object, opaque.
        response: Option<serde_json::Value>,
    },
    /// Cancel the in-flight response (e.g. on barge-in) — `response.cancel`.
    ResponseCancel,
    /// Commit the buffered uplink audio as a user turn — `input_audio_buffer.commit`.
    InputAudioCommit,
    /// Discard the buffered uplink audio — `input_audio_buffer.clear`.
    InputAudioClear,
    /// Inject a conversation item (a non-tool message) — `conversation.item.create` whose `item` is
    /// carried VERBATIM as opaque JSON (a `function_call_output` item is modeled instead as
    /// [`crate::ir::tool::IrDuplexTool::CallResult`]).
    ItemCreate {
        /// The `item` object, opaque.
        item: serde_json::Value,
    },
    /// Delete a conversation item — `conversation.item.delete`.
    ItemDelete {
        /// The item to delete.
        item_ref: String,
    },
    /// Barge-in bookkeeping (`plane4-duplex-session.md` §2.3): truncate a played item at the audio the user ACTUALLY heard —
    /// `conversation.item.truncate`. `audio_played_ms` is plane-computed state (busbar tracks playback
    /// position on WebSocket, where the server emits audio faster than realtime), NOT a field copied
    /// off the wire; it maps to/from the wire's `audio_end_ms`.
    ItemTruncate {
        /// The conversation item being truncated.
        item_ref: String,
        /// Which content part of the item (the wire `content_index`).
        content_index: u32,
        /// Milliseconds of audio the user actually heard before the barge-in.
        audio_played_ms: u64,
    },
}
