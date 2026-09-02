// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE GA `session` CONFIG OBJECT — the typed shape carried by `session.update` (client→server) and
//! echoed by `session.created` (server→client). Design §2.3.
//!
//! This is the ONE place in the plane where a serde-derived struct models the wire directly, rather
//! than the hand-mapped `serde_json::Value` dispatch the event codec uses. The justification is the
//! LLM-plane precedent: serde-derive is reserved for CONFIG shapes (stable, named, closed field sets),
//! while streaming EVENTS are hand-mapped. The Realtime `session` object is exactly a config shape.
//!
//! While OpenAI Realtime is the sole dialect (`codec: None`, §1.4) this typed config IS the neutral
//! IR — there is no cross-dialect superset to normalize into yet. The GA field set is modeled
//! faithfully so a decode→encode round-trip is JSON-stable (opaque `tools` / `tool_choice` ride as
//! `serde_json::Value`; the plane locks and reconciles them but never reshapes them).

use crate::ir::control::IrVad;
use crate::ir::media::AudioFormat;
use serde::{Deserialize, Serialize};

/// THE GA `max_output_tokens` FIELD — either an explicit cap or the `"inf"` sentinel (uncapped). A
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
/// (`pcm16` / `g711_ulaw`), so a small module bridges `Option<AudioFormat>` to the wire string.
mod opt_audio_fmt {
    use super::AudioFormat;
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(
        v: &Option<AudioFormat>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        match v {
            Some(f) => s.serialize_str(f.wire_name()),
            None => s.serialize_none(),
        }
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Option<AudioFormat>, D::Error> {
        use serde::de::Error as _;
        match Option::<String>::deserialize(d)? {
            None => Ok(None),
            Some(s) => AudioFormat::from_wire(&s)
                .map(Some)
                .ok_or_else(|| D::Error::custom(format!("unknown audio format: {s}"))),
        }
    }
}

/// THE GA `session` CONFIG OBJECT (§2.3). Every field is optional on the wire (a partial
/// `session.update` patches only what it names), so absent keys decode to `None`/empty and are
/// omitted on re-encode — keeping a partial patch JSON-stable. `turn_detection` is the ONE field
/// serialized even when absent: GA distinguishes `null` (VAD disabled) from omitted, so `None` maps
/// to explicit `null`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct SessionConfig {
    /// THE UPSTREAM MODEL ID the session targets. OpenAI Realtime carries this SERVER-SIDE (it appears
    /// on `session.created`, not the writable `session.update` patch), so it stays `None` for the
    /// OpenAI dialect; Gemini Live carries it as `setup.model`. Modeled here as the genuinely-shared
    /// field the SECOND dialect (Gemini) earns into the superset IR (§1.4). Optional — an OpenAI
    /// `session.update` omits it (decodes to `None`, skipped on re-encode, so the OpenAI round-trip is
    /// unaffected).
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
    pub input_audio_format: Option<AudioFormat>,
    /// Negotiated OUTPUT (downlink) audio format — the format the truncate math measures against.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "opt_audio_fmt"
    )]
    pub output_audio_format: Option<AudioFormat>,
    /// Voice-activity-detection config. `None` ⇒ explicit `null` on the wire = VAD disabled (the
    /// client drives turn boundaries).
    #[serde(default)]
    pub turn_detection: Option<IrVad>,
    /// The tool set, carried VERBATIM as opaque JSON (the plane locks the set but never reshapes a
    /// definition — §2.2's moat normalizes call CORRELATION, not the argument/definition bytes).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<serde_json::Value>,
    /// Tool-choice policy (`"auto"` / `"none"` / `"required"` / a forced-call object), opaque.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_choice: Option<serde_json::Value>,
    /// Per-response output-token ceiling, or `"inf"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_output_tokens: Option<MaxOutputTokens>,
}
