//! What this plane declares about itself.
//!
//! Everything here is a constant, because everything here is read once at registration and sealed
//! into policy. The meter-class list, in particular, is the exact list
//! `docs/design/ARCHITECTURE.md`'s protocol-inventory table names for the `voice` row —
//! `audio_tokens_in/out, text_tokens_in/text_tokens_out, cached_tokens, audio_seconds_in,
//! tool_calls` — and no other class is declared, because the table names that list and no other.
//!
//! In particular the table names `audio_seconds_in` and no outbound twin. Metering the downlink by
//! duration would be a second reading of the same audio the `audio_tokens_out` class already prices,
//! so the absent class is the table's decision and not an omission this module quietly fills in.

use busbar_contract::ids::{
    AdminVerbId, ClassDirection, MeterClassDecl, MeterClassId, OpClassId, RecordSchemaId,
};
use busbar_contract::plane::PlaneMeta;

use crate::claims;
use crate::VoicePlane;

/// The family every token-shaped meter class rolls up into, the same family
/// `busbar-plane-llm` uses for its own token classes.
const TOKEN_FAMILY: &str = "token";

/// The family the duration-shaped class rolls up into.
const DURATION_FAMILY: &str = "duration";

/// The family the count-shaped class rolls up into.
const COUNT_FAMILY: &str = "count";

/// Bytes per token, as the default divisor for the token classes.
///
/// This exists so a class cap works with no rate card configured at all — the same reasoning
/// `busbar-plane-llm` states for its own default. It sizes a HOLD; the metering step settles
/// against what [`busbar_voice_codec::ir::IrDuplexUsage`] actually reports.
const BYTES_PER_TOKEN: u32 = 4;

/// Milliseconds per unit for the duration class's default divisor: one, because this plane's own
/// bookkeeping already reports the class in its own unit (milliseconds admitted), not in bytes a
/// divisor would have to convert.
const MS_PER_UNIT: u32 = 1;

/// One tool call per unit, for the same reason.
const CALLS_PER_UNIT: u32 = 1;

/// The meter classes this plane declares.
///
/// **Text is an in/out pair, and which half a duplex turn's emitted text lands in is a money
/// question.** This module used to declare one `text_tokens` class in the input direction, which
/// meant a turn's model-emitted text priced under the same class as the transcript that prompted it
/// — at the input rate, on a rate card where the two rates differ. That is settled: the
/// architecture's own inventory row for this plane names `text_tokens_in` and `text_tokens_out`
/// separately, and model-emitted text prices under `text_tokens_out`, an OUTPUT class, never the
/// input one. The class label is what selects the unit price, so a mislabelled direction is a
/// mispriced turn rather than a cosmetic one.
const METER_CLASSES: &[MeterClassDecl] = &[
    MeterClassDecl {
        key: MeterClassId::new("audio_tokens_in"),
        family: TOKEN_FAMILY,
        direction: ClassDirection::Input,
        default_divisor: BYTES_PER_TOKEN,
    },
    MeterClassDecl {
        key: MeterClassId::new("audio_tokens_out"),
        family: TOKEN_FAMILY,
        direction: ClassDirection::Response,
        default_divisor: BYTES_PER_TOKEN,
    },
    MeterClassDecl {
        key: MeterClassId::new("text_tokens_in"),
        family: TOKEN_FAMILY,
        direction: ClassDirection::Input,
        default_divisor: BYTES_PER_TOKEN,
    },
    MeterClassDecl {
        key: MeterClassId::new("text_tokens_out"),
        family: TOKEN_FAMILY,
        direction: ClassDirection::Response,
        default_divisor: BYTES_PER_TOKEN,
    },
    MeterClassDecl {
        key: MeterClassId::new("cached_tokens"),
        family: TOKEN_FAMILY,
        direction: ClassDirection::CacheRead,
        default_divisor: BYTES_PER_TOKEN,
    },
    MeterClassDecl {
        key: MeterClassId::new("audio_seconds_in"),
        family: DURATION_FAMILY,
        direction: ClassDirection::Input,
        default_divisor: MS_PER_UNIT,
    },
    MeterClassDecl {
        key: MeterClassId::new("tool_calls"),
        family: COUNT_FAMILY,
        direction: ClassDirection::Response,
        default_divisor: CALLS_PER_UNIT,
    },
];

/// The name a session's opening unit is audited and priced under.
///
/// The audit record's shape is fixed for every plane and a plane contributes exactly two ids to it:
/// an operation class and a finish class. So "a session opened" is not an event kind of its own — it
/// is *this* operation class on the unit that opened it, which is why the name is declared here
/// beside the other four rather than invented at the point a record is sealed.
pub const OP_SESSION_OPEN: OpClassId = OpClassId::new("voice.session.open");

/// The operation classes a unit of this plane can be.
///
/// Five classes: the unit that opens a session, a duplex turn (the unit shape for the two duplex
/// dialects and for telephony, which is ingress-only into one), the two one-shot operations, and a
/// provider tool call — the last one is what a `Progress::OneShot` a provider pushes mid-session is
/// priced as (see `crate::plane`'s `decode_response` for the mapping this plane makes from
/// `IrDuplexTool::CallOpen` onto it).
const OP_CLASSES: &[OpClassId] = &[
    OP_SESSION_OPEN,
    OpClassId::new("duplex_turn"),
    OpClassId::new("transcribe"),
    OpClassId::new("tts"),
    OpClassId::new("tool_call"),
];

/// The fact key under which the decode step reports which dialect a session or one-shot unit is.
pub const FACT_DIALECT: &str = "dialect";
/// The fact key under which a tool-call unit reports the tool name.
pub const FACT_TOOL_NAME: &str = "tool_name";
/// The fact key under which a tool-call unit reports the upstream's own call id.
pub const FACT_CALL_ID: &str = "call_id";
/// The fact key under which a response reports the audio input milliseconds this plane admitted
/// since the turn opened — this plane's own derived quantity, not one `IrDuplexUsage` carries.
pub const FACT_AUDIO_MS_IN: &str = "audio_ms_in";
/// The fact key under which a response reports how many tool calls opened since the turn opened —
/// this plane's own derived count, not one `IrDuplexUsage` carries.
pub const FACT_TOOL_CALLS: &str = "tool_calls";
/// The fact key under which a response reports the four token classes `IrDuplexUsage` carries.
pub const FACT_AUDIO_TOKENS_IN: &str = "audio_tokens_in";
/// See [`FACT_AUDIO_TOKENS_IN`].
pub const FACT_AUDIO_TOKENS_OUT: &str = "audio_tokens_out";
/// The fact key under which a response reports the text tokens the turn consumed.
pub const FACT_TEXT_TOKENS_IN: &str = "text_tokens_in";
/// The fact key under which a response reports the text tokens the model EMITTED. Separate from
/// [`FACT_TEXT_TOKENS_IN`] because the two price under different classes at different rates.
pub const FACT_TEXT_TOKENS_OUT: &str = "text_tokens_out";
/// See [`FACT_AUDIO_TOKENS_IN`].
pub const FACT_CACHED_TOKENS: &str = "cached_tokens";
/// The fact key under which a response reports an upstream error's stable code.
pub const FACT_ERROR_CODE: &str = "error_code";
/// The fact key under which a response reports an upstream error's message.
pub const FACT_ERROR_MESSAGE: &str = "error_message";

/// The fact key this plane's `INTERRUPT_FACT` names — written wherever a barge-in truncation is
/// established, in either direction: when the client (or the plane, synthesizing on the client's
/// behalf from an upstream's `SpeechStarted`) sends an
/// `IrDuplexControl::ItemTruncate { audio_played_ms, .. }`. The value written is the
/// `audio_played_ms` figure itself, as `FactValue::Int`. See `crate::plane`'s `decode_ingress` (the
/// client-authored case) and `decode_response` (the plane-synthesized case, on an upstream's
/// `SpeechStarted`).
pub const FACT_INTERRUPT_AUDIO_PLAYED_MS: &str = "voice.interrupt.audio_played_ms";

/// The fact key this plane's `EGRESS_PACING_FACT` names — written on every downlink audio frame
/// this plane relays, carrying [`busbar_voice_codec::ir::codec::DecodeState::played_ms`]'s running total
/// at the moment the frame was relayed. The kernel's outbound write path uses this to pace delivery
/// against how much the client has actually played out, the same bookkeeping the barge-in truncate
/// arithmetic reads. See `crate::plane`'s `decode_response`.
pub const EGRESS_PACING_FACT_KEY: &str = "voice.pacing.played_ms";

/// The session fact keys this plane writes.
///
/// The dialect is a session fact for the same reason `busbar-plane-llm` declares its own dialect
/// fact one: a session that changed dialect mid-stream would be a different priced thing.
const SESSION_FACTS: &[&str] = &[FACT_DIALECT];

/// The content fact keys this plane produces.
const CONTENT_FACTS: &[&str] = &[
    FACT_AUDIO_MS_IN,
    FACT_TOOL_CALLS,
    FACT_AUDIO_TOKENS_IN,
    FACT_AUDIO_TOKENS_OUT,
    FACT_TEXT_TOKENS_IN,
    FACT_TEXT_TOKENS_OUT,
    FACT_CACHED_TOKENS,
];

/// The read-only introspection verb that lists the dialects this plane speaks.
pub const VERB_DIALECTS: AdminVerbId = AdminVerbId::new("dialects");

/// The verbs this plane answers.
///
/// Kept small and read-only, the same restraint `busbar-plane-llm` states for its own verb list: an
/// admin verb answers a question about what the plane is, never a question about a live session's
/// content.
const INTROSPECTION_VERBS: &[AdminVerbId] = &[VERB_DIALECTS];

/// The schema of this plane's own configuration block.
const CONFIG_SCHEMA: &str = r#"{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "lanes": { "type": "array", "items": { "type": "string" } },
    "default_dialect": { "type": "string" }
  }
}"#;

impl PlaneMeta for VoicePlane {
    const KEY: &'static str = "voice";
    const CLAIMS: &'static [busbar_contract::grammar::Claim] = claims::CLAIMS;
    const OP_CLASSES: &'static [OpClassId] = OP_CLASSES;
    const METER_CLASSES: &'static [MeterClassDecl] = METER_CLASSES;
    const SESSION_FACTS: &'static [&'static str] = SESSION_FACTS;
    const CONTENT_FACTS: &'static [&'static str] = CONTENT_FACTS;
    // This plane keeps no kernel-held durable records: everything it knows about an open turn lives
    // in the session's codec state (`crate::session::VoiceSessionState`), which the kernel already
    // holds per connection. A future durable session-resume feature (Gemini's
    // `SessionResumptionUpdate`, OpenAI's session reconnect) would be the reason to declare one; it
    // is not built here, so none is declared rather than declaring one unused.
    const RECORD_SCHEMAS: &'static [RecordSchemaId] = &[];
    const INTROSPECTION_VERBS: &'static [AdminVerbId] = INTROSPECTION_VERBS;
    // See `FACT_INTERRUPT_AUDIO_PLAYED_MS` and `EGRESS_PACING_FACT_KEY` above for where each is
    // written. Unlike `busbar-plane-llm` (request-and-answer, no frame ever supersedes an open one,
    // no pacing), this plane's two duplex dialects have both: barge-in supersedes an open turn, and
    // downlink audio must be paced against playback position.
    const INTERRUPT_FACT: Option<&'static str> = Some(FACT_INTERRUPT_AUDIO_PLAYED_MS);
    const EGRESS_PACING_FACT: Option<&'static str> = Some(EGRESS_PACING_FACT_KEY);
    const CONFIG_SCHEMA: &'static str = CONFIG_SCHEMA;
}
