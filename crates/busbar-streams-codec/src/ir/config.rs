// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SESSION CONFIG OBJECT — the typed shape a session PATCH carries up and a session OPEN echoes
//! back down. Design `plane4-duplex-session.md`.
//!
//! This is the ONE place in the plane where a serde-derived struct models the wire directly, rather
//! than the hand-mapped `serde_json::Value` dispatch the event codec uses. The justification is the
//! LLM-plane precedent: serde-derive is reserved for CONFIG shapes (stable, named, closed field sets),
//! while streaming EVENTS are hand-mapped. A session object is exactly a config shape.
//!
//! This typed config IS the plane's neutral session-config IR — the cross-dialect superset the dialects
//! (`plane4-duplex-session.md`) read and write, now that the plane has earned a superset at its second
//! wire format. SAY THE RESIDUE PLAINLY: the serde spellings below are PINNED WIRE, inherited from the
//! first dialect this plane spoke, and the session-parameter projector renders them as the bytes an
//! operator's gate is matched against. A field name here does not move without moving those bytes, so
//! the neutralisation that reached every other type in this crate stops at this struct's derive. The
//! field set is modeled faithfully so a
//! decode→encode round-trip is JSON-stable (opaque `tools` / `tool_choice` ride as `serde_json::Value`;
//! the plane locks and reconciles them but never reshapes them).

use crate::ir::control::IrTurnDetection;
use crate::ir::media::MediaFormat;
use serde::{Deserialize, Deserializer, Serialize};

/// Deserialize a PRESENT key into `Some(_)`, so an `Option<Option<T>>` field can tell an absent key
/// (`None`, supplied by `#[serde(default)]` because this function is never called) from an explicit
/// `null` (`Some(None)`). Without it serde consumes a wire `null` at the outer `Option` and both
/// states arrive as `None`.
fn deserialize_some<'de, T: Deserialize<'de>, D: Deserializer<'de>>(
    d: D,
) -> Result<Option<T>, D::Error> {
    T::deserialize(d).map(Some)
}

/// THE OUTPUT-TOKEN CAP FIELD — either an explicit cap or the `"inf"` sentinel (uncapped). A
/// bespoke (de)serialize keeps the int-or-string wire union without dragging an untagged-enum null
/// ambiguity into the config.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaxOutputTokens {
    /// An explicit output-token ceiling for a response.
    Limit(u32),
    /// The `"inf"` sentinel — no plane-imposed ceiling.
    Inf,
}

impl Serialize for MaxOutputTokens {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            MaxOutputTokens::Limit(n) => s.serialize_u32(*n),
            MaxOutputTokens::Inf => s.serialize_str("inf"),
        }
    }
}

impl<'de> Deserialize<'de> for MaxOutputTokens {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;
        match serde_json::Value::deserialize(d)? {
            serde_json::Value::String(s) if s == "inf" => Ok(MaxOutputTokens::Inf),
            serde_json::Value::Number(n) => n
                .as_u64()
                .and_then(|v| u32::try_from(v).ok())
                .map(MaxOutputTokens::Limit)
                .ok_or_else(|| D::Error::custom("max_output_tokens out of u32 range")),
            other => Err(D::Error::custom(format!(
                "max_output_tokens must be a u32 or \"inf\", got {other}"
            ))),
        }
    }
}

/// serde glue for the optional negotiated audio formats — the enum carries its own dialect tokens
/// (`pcm16` / `g711_ulaw`), so a small module bridges `Option<MediaFormat>` to the wire string.
mod opt_audio_fmt {
    use super::MediaFormat;
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(
        v: &Option<MediaFormat>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        match v {
            Some(f) => s.serialize_str(f.wire_name()),
            None => s.serialize_none(),
        }
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Option<MediaFormat>, D::Error> {
        use serde::de::Error as _;
        match Option::<String>::deserialize(d)? {
            None => Ok(None),
            Some(s) => MediaFormat::from_wire(&s)
                .map(Some)
                .ok_or_else(|| D::Error::custom(format!("unknown audio format: {s}"))),
        }
    }
}

/// THE SESSION CONFIG OBJECT (`plane4-duplex-session.md`). Every field is optional on the wire (a partial
/// patch names only what it changes), so absent keys decode to `None`/empty and are omitted on
/// re-encode — keeping a partial patch JSON-stable. `turn_detection` is the ONE field with THREE wire
/// states rather than two, because the wire gives `null` its own meaning: see the field.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct SessionConfig {
    /// THE UPSTREAM MODEL ID the session targets. A dialect that settles the model SERVER-SIDE names it
    /// only on the open it echoes back, never on the writable patch, so it stays `None` there; a dialect
    /// that lets the client state it up front carries it in its own setup. Modeled here as the
    /// genuinely-shared field the SECOND dialect earned into the superset IR
    /// (`plane4-duplex-session.md`). Optional — a patch that omits it decodes to `None` and is skipped
    /// on re-encode, so a round-trip through a dialect that never says it is unaffected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Requested modalities (e.g. `["audio", "text"]`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub modalities: Vec<String>,
    /// System instructions the plane locks (the browser cannot override them).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instructions: Option<String>,
    /// The synthesis voice (e.g. `alloy`, `marin`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub voice: Option<String>,
    /// Negotiated INPUT (uplink) audio format.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "opt_audio_fmt"
    )]
    pub input_audio_format: Option<MediaFormat>,
    /// Negotiated OUTPUT (downlink) audio format — the format the truncate math measures against.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "opt_audio_fmt"
    )]
    pub output_audio_format: Option<MediaFormat>,
    /// Turn-detection config — THREE-STATE, because the wire gives each state a different meaning and a
    /// partial patch names only what it changes:
    ///
    /// - `None` — the key was ABSENT. The patch says nothing about turn detection, so re-encoding
    ///   omits the key and whatever the session already had keeps applying.
    /// - `Some(None)` — the key was an explicit `null`. That is the wire's "no detector"; the client
    ///   drives turn boundaries. Re-encoded as `null`.
    /// - `Some(Some(vad))` — a configured detector, re-encoded verbatim.
    ///
    /// Collapsing absent and `null` into one `None` (which is what a plain `Option` does) makes a
    /// patch that merely renames the voice re-frame upstream with `"turn_detection": null`, which
    /// silently DISABLES server VAD — the upstream then waits for a client-driven turn that a
    /// VAD-expecting client never sends, and the model never answers. The `deserialize_some` shim is
    /// required: serde maps a wire `null` onto the OUTER `Option` by default, which would collapse
    /// the two states again no matter how the field is typed.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_some"
    )]
    pub turn_detection: Option<Option<IrTurnDetection>>,
    /// The tool set, carried VERBATIM as opaque JSON (the plane locks the set but never reshapes a
    /// definition — `plane4-duplex-session.md`'s moat normalizes call CORRELATION, not the argument/definition bytes).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<serde_json::Value>,
    /// Tool-choice policy (`"auto"` / `"none"` / `"required"` / a forced-call object), opaque.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_choice: Option<serde_json::Value>,
    /// Per-response output-token ceiling, or `"inf"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_output_tokens: Option<MaxOutputTokens>,
}

/// THE LOCKED CONFIG a carrier (µ-law telephony) leg opens with: `g711_ulaw` on BOTH the input and
/// the output audio format, so the 8 kHz µ-law carrier passes straight through with no resample.
///
/// It lives beside the type rather than beside one of its callers because there are now two: the
/// 1.5.x mount that locks a media leg with it, and the plane's own session-parameter projector,
/// which has to render the SAME bytes an operator's configured gate already matches. Two spellings
/// of one posture would be two answers, and the one that drifted would be the one a deployment's
/// gate stopped recognising.
#[must_use]
pub fn g711_config() -> SessionConfig {
    SessionConfig {
        input_audio_format: Some(MediaFormat::G711Ulaw),
        output_audio_format: Some(MediaFormat::G711Ulaw),
        ..SessionConfig::default()
    }
}

/// THE LOCKED SESSION DEFAULTS a session opens with when the deployment configures none.
///
/// The IR's own `IrTurnDetection::ServerVad` wire default is `silence_duration_ms = 200`, which is what a RAW
/// wire decode round-trip must keep. The SECTION-level default is 500 ms — a posture, not a wire
/// fact — so it is synthesized here rather than by changing the wire default, keeping the two
/// distinct. Same reason as [`g711_config`] for living here: the mount's default and the projector's
/// have to be one value.
#[must_use]
pub fn default_session() -> SessionConfig {
    SessionConfig {
        // `Some(Some(..))` — a CONFIGURED detector. The outer `Some` says the default names turn
        // detection at all (see `SessionConfig::turn_detection`'s three states).
        turn_detection: Some(Some(IrTurnDetection::ServerVad {
            threshold: 0.5,
            prefix_padding_ms: 300,
            silence_duration_ms: 500,
            create_response: true,
            interrupt_response: true,
        })),
        ..SessionConfig::default()
    }
}
