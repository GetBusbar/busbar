// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE `streams:` SECTION — the voice plane's config grammar, and the one place its values are read.
//!
//! ## The section IS the plane
//!
//! `streams:` is the fourth plane noun beside `pools:` / `tools:` / `agents:`, and — like them —
//! there is no `plane:`/`bind:`/`target:` selector: writing a `streams:` block IS declaring the voice
//! plane's configuration. It is a SINGULAR typed section, not a named-definition map: a deployment has
//! ONE live-voice posture, so the section is one object (the locked session defaults + the three
//! session ceilings), never a map of registrations. That is why it is not in `NamedMapSection`.
//!
//! ## The VAD/session grammar is REUSED, not restated
//!
//! Its media/VAD/session shape IS the GA `session` object ([`SessionConfig`], which already carries
//! `turn_detection: Option<IrVad>` with the `server_vad` knobs threshold / prefix_padding_ms /
//! silence_duration_ms / create_response / interrupt_response). The plane adds only the three
//! plane-imposed ceilings — session wall-clock, context window, per-response output tokens — as the
//! sole NEW scalars. No second copy of the VAD grammar exists to drift from the wire one.
//!
//! The session wall-clock ceiling is OPTIONAL and has no default (OWNER RULING Q21a): absent, a session
//! runs as long as its sockets stay up, exactly as in 1.5.5; present, it is a positive number of
//! seconds and the plane closes a session at it.
//!
//! ## It IS in the config-schema tracked set
//!
//! Exactly like `tools:`/`agents:`, this file is fingerprinted by `cargo xtask gate config-schema` (it is a
//! `SOURCES` entry). Both the `streams` key of `DeployCfg`'s neutral declared-section carrier AND this
//! per-key grammar — the three plane-imposed session ceilings — are covered by the additive-only gate,
//! so a deployment's live-voice CEILINGS cannot be retyped or removed without the gate flagging it.

use crate::codec::ir::config::SessionConfig;
use crate::codec::ir::control::IrVad;
use serde::{Deserialize, Serialize};

/// Context-window ceiling default — 32768 tokens.
fn default_context_window_tokens() -> u32 {
    32_768
}
/// Per-response output-token ceiling default — 4096 tokens.
fn default_max_output_tokens() -> u32 {
    4096
}

/// THE LOCKED SESSION DEFAULTS an absent `streams.session:` opens with.
///
/// The IR's own `IrVad::ServerVad` wire default is `silence_duration_ms = 200` (`ir/control.rs`),
/// which is what a RAW wire decode round-trip must keep. The `streams:`-LEVEL default is 500ms — a
/// plane posture, not a wire fact — so it is synthesized HERE (when the operator writes no
/// `turn_detection`) rather than by changing the IR's own default, keeping the two distinct.
fn default_session() -> SessionConfig {
    SessionConfig {
        // `Some(Some(..))` — a CONFIGURED detector. The outer `Some` says the operator default names
        // turn detection at all (see `SessionConfig::turn_detection`'s three states).
        turn_detection: Some(Some(IrVad::ServerVad {
            threshold: 0.5,
            prefix_padding_ms: 300,
            silence_duration_ms: 500,
            create_response: true,
            interrupt_response: true,
        })),
        ..SessionConfig::default()
    }
}

/// THE `streams:` SECTION — the voice plane's owned config. Its VAD/session/media shape IS the GA
/// `session` object ([`SessionConfig`]); the three limits are the only plane-imposed ceilings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)] // a typo'd key is refused HERE exactly as the file refuses it
pub struct StreamsCfg {
    /// The locked session defaults every live session opens with (media formats, voice, instructions,
    /// turn_detection/VAD, tool set, per-response max_output_tokens). Absent ⇒ [`default_session`]
    /// (server_vad, 500ms silence).
    #[serde(default = "default_session")]
    pub session: SessionConfig,
    /// Hard session wall-clock ceiling, in seconds. OPTIONAL, with no default: absent ⇒ no ceiling.
    /// Zero is refused at parse (a ceiling that closes every session at its open is not a ceiling),
    /// and so is a negative figure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_max_secs: Option<std::num::NonZeroU32>,
    /// Context-window ceiling. Default 32768.
    #[serde(default = "default_context_window_tokens")]
    pub context_window_tokens: u32,
    /// Output-token ceiling per response. Default 4096.
    #[serde(default = "default_max_output_tokens")]
    pub max_output_tokens: u32,
}

// MANUAL `Default`, not derived: the serde field defaults above are non-trivial (the three ceilings
// and the synthesized `server_vad`), and `#[derive(Default)]` would give `0`/`SessionConfig::default`
// instead — so `StreamsCfg::default()` (what `streams_default_section` returns for an ABSENT section)
// would NOT equal the parse of an empty `streams: {}`. Spelling it by hand keeps those two byte-equal.
impl Default for StreamsCfg {
    fn default() -> Self {
        StreamsCfg {
            session: default_session(),
            session_max_secs: None,
            context_window_tokens: default_context_window_tokens(),
            max_output_tokens: default_max_output_tokens(),
        }
    }
}

#[cfg(test)]
#[path = "tests/config_tests.rs"]
mod tests;
