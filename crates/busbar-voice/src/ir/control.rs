// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! LAYER 2 — CONTROL / CONFIG (translatable; bites only cross-dialect). Design §2.3.
//!
//! The session-control events are IR-translatable, but the translation only MATTERS cross-dialect
//! (OpenAI Realtime ⇄ Gemini Live). Same-dialect they are verbatim carriage (Layer-3 discipline). Two
//! load-bearing points the shapes below encode: instruction/tool locking is a control-layer invariant
//! (a client-originated `SessionConfigure` is a HINT reconciled against the locked config, never
//! trusted blind), and barge-in `audio_played_ms` is PLANE-COMPUTED IR state, not a wire field.

/// VOICE-ACTIVITY-DETECTION config — the plane's neutral VAD surface (`server_vad`
/// threshold/`silence_duration_ms`, `semantic_vad` eagerness). SKELETON: a stub the cross-dialect
/// translation (§9.3) will populate.
#[derive(Debug, Clone, PartialEq)]
pub enum IrVad {
    /// Server-side voice-activity detection with a threshold and a trailing-silence window.
    ServerVad {
        /// Activation threshold (0.0–1.0), dialect-normalized.
        threshold: f32,
        /// Trailing silence, in milliseconds, that ends a turn.
        silence_duration_ms: u32,
    },
    /// Semantic (model-judged) end-of-turn detection with an eagerness knob.
    SemanticVad {
        /// How eagerly the model closes a turn, dialect-normalized.
        eagerness: f32,
    },
    /// VAD disabled — the client drives turn boundaries explicitly.
    Disabled,
}

/// THE NEUTRAL CONTROL / CONFIG IR (§2.3). Translatable, but same-dialect it is verbatim carriage.
#[derive(Debug, Clone, PartialEq)]
pub enum IrDuplexControl {
    /// Configure the session — the authoritative copy the plane holds server-side and re-applies; a
    /// client-originated one is a hint reconciled against the lock, never trusted blind.
    SessionConfigure {
        /// System instructions the plane locks (the browser cannot override them).
        instructions: String,
        /// The tool set the plane locks.
        tools: Vec<String>,
        /// Voice-activity-detection config for this session.
        vad: IrVad,
        /// Requested modalities (e.g. `audio`, `text`), dialect-normalized.
        modalities: Vec<String>,
        /// Negotiated audio format (e.g. `pcm16`, `g711_ulaw`), dialect-normalized.
        audio_fmt: String,
    },
    /// Ask the upstream to begin generating a response.
    ResponseCreate {
        /// Modalities the response may use.
        modalities: Vec<String>,
    },
    /// Cancel the in-flight response (e.g. on barge-in).
    ResponseCancel,
    /// Barge-in bookkeeping (§2.3): truncate a played item at the audio the user ACTUALLY heard.
    /// `audio_played_ms` is plane-computed state (busbar tracks playback position on WebSocket, where
    /// the server emits audio faster than realtime), NOT a field copied off the wire.
    ItemTruncate {
        /// The conversation item being truncated.
        item_ref: String,
        /// Milliseconds of audio the user actually heard before the barge-in.
        audio_played_ms: u64,
    },
}
