// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! LAYER 2 — CONTROL / CONFIG (translatable; bites only cross-dialect). Design `plane4-duplex-session.md`.
//!
//! The session-control events are IR-translatable, but the translation only MATTERS cross-dialect —
//! same-dialect they are verbatim carriage (Layer-3 discipline). Two
//! load-bearing points the shapes below encode: instruction/tool locking is a control-layer invariant
//! (a client-originated `SessionConfigure` is a HINT reconciled against the locked config, never
//! trusted blind), and barge-in `played_ms` is PLANE-COMPUTED IR state, not a wire field.

use crate::ir::config::SessionConfig;
use serde::{Deserialize, Serialize};

/// MODEL-JUDGED END-OF-TURN EAGERNESS — how eagerly the model closes a turn. A closed set whose serde
/// spellings ARE pinned wire tokens: renaming a variant here moves bytes.
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

/// TURN DETECTION — the plane's neutral surface for who decides a turn ended. Its serde shape is the
/// PINNED `turn_detection` object (tagged on `type`): a server-side detector with the
/// threshold/padding/silence knobs, or a model-judged one with an eagerness. Both variant names and
/// both tags are wire, not IR, and do not move. DISABLED is not a variant here — it is the ABSENCE of a
/// detector (a `null` on the wire, `None` at [`SessionConfig::turn_detection`]).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum IrTurnDetection {
    /// Server-side voice-activity detection with amplitude threshold and silence windows.
    ServerVad {
        /// Activation threshold (0.0–1.0).
        #[serde(default = "default_threshold")]
        threshold: f32,
        /// Uplink media (ms) retained BEFORE the detected activity, folded into the turn.
        #[serde(default = "default_prefix_padding_ms")]
        prefix_padding_ms: u32,
        /// Trailing silence (ms) that ends a turn.
        #[serde(default = "default_silence_duration_ms")]
        silence_duration_ms: u32,
        /// Whether the server auto-issues a turn request at end-of-turn.
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

/// THE NEUTRAL CONTROL / CONFIG IR (`plane4-duplex-session.md`). Translatable, but same-dialect it is verbatim carriage.
#[derive(Debug, Clone, PartialEq)]
pub enum IrDuplexControl {
    /// Configure the session — the authoritative copy the plane holds server-side and re-applies; a
    /// client-originated one is a hint reconciled against the lock, never trusted blind. Carries the
    /// full typed session object ([`SessionConfig`]).
    SessionConfigure {
        /// The session config object.
        config: SessionConfig,
    },
    /// Ask the upstream to begin generating a turn. Carries the optional per-turn override object
    /// a dialect states beside the request, verbatim: the IR does not model what is in it, because
    /// what may be overridden on one turn is the one thing every dialect spells differently.
    TurnRequest {
        /// The optional per-turn override object, opaque.
        overrides: Option<serde_json::Value>,
    },
    /// Cancel the in-flight turn (e.g. on barge-in).
    TurnCancel,
    /// Commit the buffered uplink media as a client turn.
    UplinkCommit,
    /// Discard the buffered uplink media.
    UplinkClear,
    /// Inject a conversation item (a non-tool message) whose `item` is carried VERBATIM as opaque
    /// JSON (a tool RESULT item is modeled instead as
    /// [`crate::ir::tool::IrDuplexTool::CallResult`]).
    ItemInject {
        /// The `item` object, opaque.
        item: serde_json::Value,
    },
    /// Remove a conversation item.
    ItemRemove {
        /// The item to remove.
        item_ref: String,
    },
    /// Barge-in bookkeeping (`plane4-duplex-session.md`): truncate a played item at the media the
    /// client ACTUALLY received. `played_ms` is plane-computed state (busbar tracks playback position
    /// on a socket where the server emits media faster than realtime), NOT a field copied off the
    /// wire; a dialect maps it to and from whatever offset its own truncate names.
    ItemTruncate {
        /// The conversation item being truncated.
        item_ref: String,
        /// Which content part of the item.
        content_index: u32,
        /// Milliseconds of media the client actually got before the barge-in.
        played_ms: u64,
    },
}
