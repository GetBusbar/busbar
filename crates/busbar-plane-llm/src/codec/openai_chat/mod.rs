// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! OpenAI protocol reader/writer implementation.

use crate::codec::dialect::ir_parse_error;
use crate::codec::ir::{IrStreamEvent, IrUsage};
use crate::codec::keys;
use busbar_contract::http::StatusCode;
// The openai-family error helpers (`bearer_error_code`/`context_length_prose_scan`) now live
// in the neutral substrate; name them there so this plugin reaches no `busbar-core` path for them.
use crate::codec::dialect::{bearer_error_code, context_length_prose_scan};
// The neutral canonical error-type vocabulary lives in the substrate; read it there, not via core's
// re-export, so this plugin names no `busbar-core` implementation path for it.
use busbar_contract::protocol::*;
use busbar_contract::protocol::{
    ERR_TYPE_AUTHENTICATION, ERR_TYPE_INSUFFICIENT_QUOTA, ERR_TYPE_INVALID_REQUEST,
    ERR_TYPE_NOT_FOUND, ERR_TYPE_OVERLOADED, ERR_TYPE_PERMISSION, ERR_TYPE_RATE_LIMIT,
    ERR_TYPE_SERVER_ERROR,
};
#[cfg(test)]
use busbar_contract::upstream::CanonicalSignal;
use busbar_contract::upstream::StatusClass;
// G6 A4b: the wire-codec surface (ProtocolReader/Writer/Protocol/StreamFraming/ToolIdRemap/
// protocol_for) relocated to this plugin's `proto_codec`; reach it RELATIVELY so it resolves both
// standalone (crate::codec::proto_codec) and netted into core (core::proto::proto_codec).
#[allow(unused_imports)]
// used standalone; redundant with the `busbar_contract::protocol::*` glob when netted into core
use super::proto_codec::*;
use crate::codec::usage_count::{CountRead, CountSlot, UsageCount};
use busbar_contract::ir::egress_prep::{LaneCaps, MaxOutputKey};
// See the anthropic dialect for the rationale: an explicit import of the codec surface so it binds to
// THIS crate's own `proto_codec` rather than the `busbar_contract::protocol::*` glob.
#[allow(unused_imports)]
use super::proto_codec::{Protocol, ProtocolReader, ProtocolWriter, StreamFraming};

#[rustfmt::skip]
#[path = "map.gen.rs"]
mod map;
pub mod handler;
mod reader;
pub(crate) mod slots;
mod writer;

/// Build this dialect's wire codec — the [`ProtocolDecl::codec`] constructor. A fresh instance per
/// resolution, exactly as the registry's field doc requires.
pub fn protocol() -> Protocol {
    Protocol::new(VENDOR_NAME, OpenAiReader, OpenAiWriter)
}

/// The [`ProtocolDecl::models_list_envelope`] builder: OpenAI's `GET /v1/models` shape. Each name
/// becomes an OpenAI `model` object (`owned_by: "busbar"`, `created: 0`), wrapped in the SDK's
/// `{ "object": "list", "data": [...] }` list envelope that `client.models.list()` deserialises.
/// Cohere's SDK carries no reliable discovery fingerprint and receives this shape too (documented).
fn models_list_envelope(names: &[&str]) -> serde_json::Value {
    let data: Vec<serde_json::Value> = names
        .iter()
        .map(|id| serde_json::json!({ (keys::ID): id, (keys::OBJECT): keys::MODEL, (CREATED): 0, "owned_by": "busbar" }))
        .collect();
    serde_json::json!({ (keys::OBJECT): LIST, (keys::DATA): data })
}

/// OPENAI'S ROUTER DETECTION — its rungs of the old core `protocol_id` ladder: `/v1/chat/completions`
/// (rung 7), then the OpenAI-family JSON/audio/image ops (`/v1/embeddings`, `/v1/moderations`,
/// `/v1/images/…`, `/v1/audio/…`, rung 14, the loosest path claims). Lower strength binds tighter.
fn claims(
    _h: &busbar_contract::http::HeaderMap,
    path: &str,
) -> Option<busbar_contract::protocol::ClaimStrength> {
    use busbar_contract::protocol::ClaimStrength;
    if path.ends_with("/v1/chat/completions") {
        return Some(ClaimStrength(7));
    }
    if path.ends_with("/v1/embeddings")
        || path.ends_with("/v1/moderations")
        || path.contains("/v1/images/")
        || path.contains("/v1/audio/")
    {
        return Some(ClaimStrength(14));
    }
    None
}

/// OPENAI'S RESIDUAL DETECTION — its arms of the headerless `residual_dialect_for_path` ladder. It
/// owns the OpenAI-compatible default: a `/v1/models/{id}` that no sibling claimed more tightly
/// (rung 25, LOOSER than Gemini's `/v1/models/{id}:{action}` at rung 20, so a genuine Gemini action
/// wins and only a colon-less or non-action id falls here) and an exact `/v1/chat/completions` (rung
/// 55). The broad `/v1/models/` catch is what makes a colon-bearing OpenAI fine-tune id stay OpenAI.
fn residual_claims(path: &str) -> Option<busbar_contract::protocol::ClaimStrength> {
    use busbar_contract::protocol::ClaimStrength;
    if path.starts_with("/v1/models/") {
        return Some(ClaimStrength(25));
    }
    if path == "/v1/chat/completions" {
        return Some(ClaimStrength(55));
    }
    None
}

/// OPENAI'S DECLARATION. See `proto::registry` for what each field replaces.
pub const DECL: ProtocolDecl = ProtocolDecl {
    name: VENDOR_NAME,
    codec: dialect_codec!(VENDOR_NAME),
    handler: Some(&handler::OpenAiRequestHandler),
    verbs: &[
        busbar_contract::operation::OpVerb::CHAT,
        busbar_contract::operation::OpVerb::EMBEDDINGS,
        busbar_contract::operation::OpVerb::MODERATION,
        busbar_contract::operation::OpVerb::IMAGE,
        busbar_contract::operation::OpVerb::TRANSCRIPTION,
        busbar_contract::operation::OpVerb::SPEECH,
    ],
    head_keys: super::proto_codec::LLM_CHAT_HEAD_KEYS,
    streaming_content_type: Some(busbar_contract::protocol::TEXT_EVENT_STREAM),
    array_stream_shim_key: None,
    // `call_…` is the documented native tool-call id shape for both OpenAI surfaces.
    native_tool_id_prefix: Some("call_"),
    ingress_auth: IngressAuth::Bearer,
    // OpenAI's native credential scheme is a plain `Authorization: Bearer <key>` — DECLARED here as
    // data (#83a S2-a, #40(b)): the kernel's egress-auth unit presents the lane credential under it,
    // so the key never passes through this plane.
    egress_auth_headers: None,
    egress_auth_lane_constant: false,
    egress_scheme: Some(EgressScheme::bearer()),
    stream_usage_requires_opt_in: true,
    // ── Promoted writer facts (G6 step A1): the same constants the `OpenAiWriter` methods returned.
    requires_max_tokens: false,
    stop_sequence_cap: Some((4, "OpenAI")),
    cache_markers_model_gated: false,
    fills_thought_signature: false,
    frame_after_message_start: None,
    reshapes_body_at_path_base: false,
    max_cache_control_breakpoints: None,
    quota_exceeded_status: busbar_contract::http::StatusCode::TOO_MANY_REQUESTS,
    ingress_is_eventstream: false,
    emits_sse_done_terminator: true,
    max_citations_per_delta: None,
    // OpenAI Python SDK UA (the Responses surface shares it). RELEASE OBLIGATION: re-verify/bump per
    // release; the `test_egress_ua_versions_are_pinned_and_present` guard forces a conscious change.
    egress_user_agent: "OpenAI/Python 1.54.0",
    has_model_in_url: false,
    auth_failure_status_and_kind: (
        busbar_contract::http::StatusCode::UNAUTHORIZED,
        busbar_contract::protocol::ERR_TYPE_AUTHENTICATION,
    ),
    ingress_relays_amzn_headers: false,
    ingress_relayed_response_header_names: &[],
    auth_failure_message: AUTH_FAILURE_MSG,
    uses_array_stream_shim: false,
    has_native_path_not_found: false,
    egress_stream_accept: busbar_contract::protocol::TEXT_EVENT_STREAM,
    models_list_envelope: Some(models_list_envelope),
    claims: Some(claims),
    residual_claims: Some(residual_claims),
    // THE OPENAI-COMPATIBLE RESIDUAL: the one dialect core falls back to when no fingerprint claims a
    // request yet a dialect must be named (a bare `GET /v1/models`, an un-resolved degraded response).
    residual_default: true,
    vendor_response_metadata: None,
    // OpenAI is the residual default for the shared list-models surface — no fingerprint header.
    list_models_fingerprint_headers: &[],
    static_headers: &[],
};

/// This dialect's registration (its one line is in `crate::codec::DIALECTS`).
pub(crate) const ENTRY: super::proto_codec::DialectEntry = super::proto_codec::DialectEntry {
    decl: &DECL,
    protocol,
    with_writer: |f| {
        let w = OpenAiWriter;
        f(&w)
    },
    with_reader: |f| f(&OpenAiReader),
    leaf: &handler::LEAF,
};

/// Largest upstream `tool_calls[].index` we accept in a streaming chunk. OpenAI documents at most
/// 128 parallel tool calls, so any larger index is malformed; we clamp to this value before it
/// reaches the IR index arithmetic (`oai_idx + 1 + offset`) so a crafted `u64::MAX` index can never
/// overflow the `usize` cast or the addition. Chosen as the highest valid 0-based index (127).
const MAX_TOOL_INDEX: u64 = 127;

/// Hard cap on the number of DISTINCT tool-call indices we track per stream (`open_tools`). Bounds
/// per-request memory and the number of synthesized BlockStart events against a pathological backend
/// emitting unbounded unique indices. Matches OpenAI's documented parallel-tool-call limit (128).
const MAX_OPEN_TOOLS: usize = crate::codec::dialect::MAX_OPEN_TOOL_CALLS;

/// OPENAI CHAT'S USAGE COUNTS, AS DATA (#42). `prompt_tokens` is a TOTAL that already INCLUDES the
/// cached prefix (`prompt_tokens_details.cached_tokens`) and the cache-write slice
/// (`prompt_tokens_details.cache_write_tokens`), so both are subtracted (saturating) to leave the
/// uncached input and carried as the IR's ADDITIVE cache read / cache creation — the cache write is
/// its own tier, never inside the plain input total. The `*_details` sub-buckets
/// (reasoning, audio, predicted outputs) are SLICES of the totals, carried as attribution: a lenient
/// read, never a refusal. The buffered response, the stream's `include_usage` chunk and a
/// truncated-body recovery read this one table.
const USAGE: &[UsageCount] = &[
    (CountSlot::Input, CountRead::Zero(&[PROMPT_TOKENS])),
    (
        CountSlot::Input,
        CountRead::Less(&[PROMPT_TOKENS_DETAILS, keys::CACHED_TOKENS]),
    ),
    (
        CountSlot::Input,
        CountRead::Less(&[PROMPT_TOKENS_DETAILS, keys::CACHE_WRITE_TOKENS]),
    ),
    (CountSlot::Output, CountRead::Zero(&[COMPLETION_TOKENS])),
    (
        CountSlot::CacheWrite,
        CountRead::Opt(&[PROMPT_TOKENS_DETAILS, keys::CACHE_WRITE_TOKENS]),
    ),
    (
        CountSlot::CacheRead,
        CountRead::Opt(&[PROMPT_TOKENS_DETAILS, keys::CACHED_TOKENS]),
    ),
    (
        CountSlot::Reasoning,
        CountRead::Lenient(&[COMPLETION_TOKENS_DETAILS, keys::REASONING_TOKENS]),
    ),
    (
        CountSlot::InputAudio,
        CountRead::Lenient(&[PROMPT_TOKENS_DETAILS, AUDIO_TOKENS]),
    ),
    (
        CountSlot::OutputAudio,
        CountRead::Lenient(&[COMPLETION_TOKENS_DETAILS, AUDIO_TOKENS]),
    ),
    (
        CountSlot::AcceptedPrediction,
        CountRead::Lenient(&[COMPLETION_TOKENS_DETAILS, ACCEPTED_PREDICTION_TOKENS]),
    ),
    (
        CountSlot::RejectedPrediction,
        CountRead::Lenient(&[COMPLETION_TOKENS_DETAILS, REJECTED_PREDICTION_TOKENS]),
    ),
];

/// Stable identifier of the identity [`read_openai_usage`] checks `usage.total_tokens` against,
/// carried on [`crate::codec::ir::UsageIdentityNote::identity`].
const OPENAI_USAGE_IDENTITY: &str = "openai.usage";

/// An OpenAI Chat `usage` object (`None` when absent) → the IR usage, through [`USAGE`]; the
/// serving tier (`service_tier`, a top-level member beside `usage`, OAI-03) is a word, not a count,
/// and is set from `tier`.
///
/// EVERY COUNT THE PINNED WIRE LOCK (`testing/llm-conformance/wire/openai.wire.json`) DECLARES
/// UNDER `usage` IS EITHER LEDGERED OR A SLICE OF A LEDGERED TOTAL. Ledgered: `prompt_tokens`
/// (input, less its cached and cache-write slices), `cached_tokens` (cache read),
/// `cache_write_tokens` (cache write), `completion_tokens` (output). Slices, read for attribution
/// where the IR has a slot and never ledgered twice: `prompt_tokens_details.{audio,image,text}_tokens`
/// partition `prompt_tokens`, `completion_tokens_details.{reasoning,audio,text,accepted_prediction,
/// rejected_prediction}_tokens` sit inside `completion_tokens` (OpenAI bills rejected predictions as
/// completion tokens, and counts them there). `total_tokens` is OpenAI's sum, never a unit: it is
/// cross-checked against the ledgered classes and a gap is WARN-logged and carried as the usage
/// identity note, never ledgered.
fn read_openai_usage(
    usage: Option<&serde_json::Value>,
    tier: Option<&serde_json::Value>,
) -> Result<crate::codec::ir::IrUsage, IrError> {
    let mut ir = crate::codec::usage_count::read_usage(VENDOR_NAME, usage, USAGE)?;
    ir.detail.usage_identity_note = crate::codec::usage_count::stated_total_note(
        VENDOR_NAME,
        OPENAI_USAGE_IDENTITY,
        usage.and_then(|u| u.get(keys::TOTAL_TOKENS)),
        &ir,
    );
    ir.detail.service_tier = crate::codec::carry::read_word(map::WORDS_SERVED_TIER, tier);
    ir.detail.by_modality = usage.and_then(read_by_modality);
    Ok(ir)
}

/// `{prompt,completion}_tokens_details.{text,image,audio}_tokens` -> the IR's by-modality split
/// (DF-MAP item 4; presentation only, never billed). `None` when neither side reports a text or
/// image slice (the audio slices alone keep riding `input_audio_tokens` / `output_audio_tokens`).
fn read_by_modality(usage: &serde_json::Value) -> Option<crate::codec::ir::IrUsageByModality> {
    let side = |details: &str| {
        let d = usage.get(details);
        let n = |k: &str| d.and_then(|d| d.get(k)).and_then(|v| v.as_u64());
        crate::codec::ir::IrModalityCounts {
            text: n(TEXT_TOKENS),
            image: n(IMAGE_TOKENS),
            audio: n(AUDIO_TOKENS),
            video: None,
        }
    };
    let input = side(PROMPT_TOKENS_DETAILS);
    let output = side(COMPLETION_TOKENS_DETAILS);
    (input.text.is_some() || input.image.is_some() || output.text.is_some()).then(|| {
        crate::codec::ir::IrUsageByModality {
            input,
            output,
            ..Default::default()
        }
    })
}

/// The text slice of a `*_tokens_details` object.
const TEXT_TOKENS: &str = "text_tokens";
/// The image slice of `prompt_tokens_details`.
const IMAGE_TOKENS: &str = "image_tokens";

/// Fallback `model` string stamped onto a cross-protocol OpenAI response when the egress backend
/// supplied none. The native OpenAI `chat.completion` / `chat.completion.chunk` schemas define
/// `model` as a REQUIRED non-nullable string, and the official `openai-python` (>=1.0) Pydantic
/// models raise `ValidationError` when it is absent. A backend whose `read_response` yields
/// `model: None` (e.g. Bedrock egress -> OpenAI ingress, where `read_response` sets `model: None`)
/// would otherwise produce a model-less first chunk / completion — both an SDK deserialisation
/// failure and a proxy tell (a real OpenAI endpoint never omits `model`). A current, widely-served
/// model id keeps the synthesized value plausible.
const DEFAULT_MODEL: &str = crate::codec::dialect::FALLBACK_MODEL;

/// Busbar-internal sentinel key for `max_completion_tokens` source tracking. The reader folds BOTH `max_tokens` and the
/// modern `max_completion_tokens` into the single IR `max_tokens` field so a caller's output-token
/// cap survives the cross-protocol seam. But OpenAI's o1/o3 reasoning models REJECT `max_tokens` and
/// require `max_completion_tokens`; an OpenAI->OpenAI passthrough to such a model that arrived as
/// `max_completion_tokens` must re-emit `max_completion_tokens`, not `max_tokens`. The reader records
/// the source spelling under this sentinel in `extra` so the writer can re-emit the SAME key on a
/// same-protocol passthrough. `extra` is cleared on the cross-protocol seam, so the sentinel
/// naturally vanishes there and a cross-protocol egress writes the key the LANE declares
/// (`LaneCaps::max_output_key`, default `max_tokens` — OAI-01). The `__busbar` prefix never
/// collides with a real OpenAI field, and the writer consumes (does not leak) it.
const MAX_COMPLETION_TOKENS_SENTINEL: &str = "__busbar_max_completion_tokens";

/// Busbar-internal sentinel key parking OpenAI's per-message PROVIDER-SPECIFIC fields — an assistant
/// history turn's `audio` reference, the legacy `function_call`, and any future message-level key this
/// reader does not model into typed IR. The value is an object keyed by IR-message index, each entry
/// the raw unmodeled fields of that message. The reader stashes them (see the message loop) so a
/// same-protocol pool-alias re-serialize (which rebuilds the body from the IR rather than forwarding
/// the caller's bytes) re-emits them verbatim; `extra` is cleared on the cross-protocol seam, so they
/// naturally drop there — the correct scope, since no other dialect models them. The `__busbar` prefix
/// never collides with a real OpenAI field, and the writer consumes (does not leak) it.
const MESSAGE_EXTRAS_SENTINEL: &str = "__busbar_openai_message_extras";

/// Busbar-internal key INSIDE one message's `MESSAGE_EXTRAS_SENTINEL` entry marking a legacy
/// `role:"function"` result turn (value: its function `name`). The reader reads such a turn as a
/// tool result (OAI-07); the writer uses the marker to write an OpenAI-origin re-serialize back in
/// the legacy shape. Never reaches the wire.
const LEGACY_FUNCTION_ROLE_KEY: &str = "__busbar_legacy_function_role";

// `MESSAGE_NAMES_SENTINEL` — the `extra` key parking OpenAI's per-message `messages[].name` — lives
// in this plane's shared wire helpers (`crate::codec::dialect`), beside the cross-protocol dropped-keys warn
// that names it.
use crate::codec::dialect::MESSAGE_NAMES_SENTINEL;

// ── OpenAI wire-format named constants ──────────────────────────────────────
//
// Every magic string the ChatCompletions / streaming protocol needs, in one
// place.  Replace bare literals everywhere EXCEPT (a) these const-def lines
// and (b) golden output-contract assertions that pin busbar's own emitted wire
// byte (those keep the literal and are annotated with the comment below).

/// `object` field value on a non-streaming completion response.
const OBJ_COMPLETION: &str = "chat.completion";
/// `object` field value on every streaming chunk.
const OBJ_CHUNK: &str = "chat.completion.chunk";

/// OpenAI `finish_reason` wire token for a normal end-of-turn.
const FINISH_STOP: &str = "stop";
/// OpenAI `finish_reason` wire token for a max-tokens truncation.
const FINISH_LENGTH: &str = "length";
/// OpenAI `finish_reason` wire token emitted when the model called a tool.
const FINISH_TOOL_CALLS: &str = keys::TOOL_CALLS;
/// OpenAI `finish_reason` wire token emitted when content was filtered.
const FINISH_CONTENT_FILTER: &str = "content_filter";
/// Legacy OpenAI `finish_reason` wire token for function-calling (pre-tool_calls era).
const FINISH_FUNCTION_CALL: &str = keys::FUNCTION_CALL;

/// `response_format.type` value for plain-text output.
const RESP_FORMAT_TEXT: &str = keys::TEXT;
/// `response_format.type` value for a schema-constrained JSON output.
const RESP_FORMAT_JSON_SCHEMA: &str = keys::JSON_SCHEMA;
/// `response_format.type` value for unstructured JSON output.
const RESP_FORMAT_JSON_OBJECT: &str = "json_object";

/// Tool `type` field value for all Chat Completions function tools.
const TOOL_TYPE_FUNCTION: &str = keys::FUNCTION;
/// Tool `type` field value for a Chat Completions custom (free-text / grammar input) tool.
const TOOL_TYPE_CUSTOM: &str = keys::CUSTOM;

/// Fallback `json_schema.name` synthesized when the IR carries none.
/// OpenAI REQUIRES this field and the SDK rejects it when absent.
const JSON_SCHEMA_DEFAULT_NAME: &str = "response";

/// Prefix of every native OpenAI chat-completion id (`chatcmpl-<24 base62 chars>`).
const COMPLETION_ID_PREFIX: &str = "chatcmpl-";

/// Upstream URL path for OpenAI Chat Completions.
const PATH_UPSTREAM: &str = "/v1/chat/completions";

/// The human-readable message busbar returns on a bad-key 401, matching the
/// exact phrasing the official OpenAI API uses so SDK `is_auth_error` helpers
/// that key on the message string still fire.
const AUTH_FAILURE_MSG: &str = "Incorrect API key provided.";

/// The dialect's own name `openai`, also the `vendor` tag on an [`crate::codec::ir::IrImageSource::Vendor`] this protocol produces — an OpenAI
/// `file.file_id`, an uploads-API handle with no neutral (base64/url) form. Only an OpenAI-family
/// writer recognizes the tag and re-emits the reference; every other writer drops it with a warn
/// rather than emitting a handle its own backend cannot resolve.
const VENDOR_NAME: &str = "openai";

// Wire words only this dialect speaks, each spelled once here (the words two or more dialects
// share are `crate::codec::keys`). Request/response member names, usage buckets, audio/image/
// moderation members, and the two media words the chat codec names.
/// The OpenAI wire word `language`.
const LANGUAGE: &str = "language";
/// The OpenAI wire word `duration`.
const W_DURATION: &str = "duration";
/// The OpenAI wire word `segments`.
const SEGMENTS: &str = "segments";
/// The OpenAI wire word `avg_logprob`.
const AVG_LOGPROB: &str = "avg_logprob";
/// The OpenAI wire word `no_speech_prob`.
const NO_SPEECH_PROB: &str = "no_speech_prob";
/// The OpenAI wire word `compression_ratio`.
const COMPRESSION_RATIO: &str = "compression_ratio";
/// The OpenAI wire word `words`.
const W_WORDS: &str = "words";
/// The OpenAI wire word `word`.
const WORD: &str = "word";
/// The OpenAI wire word `seconds`.
const SECONDS: &str = "seconds";
/// The OpenAI wire word `speed`.
const SPEED: &str = "speed";
/// The OpenAI wire word `encoding_format`.
const ENCODING_FORMAT: &str = "encoding_format";
/// The OpenAI wire word `list`.
const LIST: &str = "list";
/// The OpenAI wire word `prompt_tokens`.
const PROMPT_TOKENS: &str = "prompt_tokens";
/// The OpenAI wire word `n`.
const W_N: &str = "n";
/// The OpenAI wire word `size`.
const SIZE: &str = "size";
/// The OpenAI wire word `style`.
const STYLE: &str = "style";
/// The OpenAI wire word `background`.
const BACKGROUND: &str = "background";
/// The OpenAI wire word `output_compression`.
const OUTPUT_COMPRESSION: &str = "output_compression";
/// The OpenAI wire word `b64_json`.
const B64_JSON: &str = "b64_json";
/// The OpenAI wire word `revised_prompt`.
const REVISED_PROMPT: &str = "revised_prompt";
/// The OpenAI wire word `created`.
const CREATED: &str = "created";
/// The OpenAI wire word `flagged`.
const FLAGGED: &str = "flagged";
/// The OpenAI wire word `categories`.
const CATEGORIES: &str = "categories";
/// The OpenAI wire word `category_scores`.
const CATEGORY_SCORES: &str = "category_scores";
/// The OpenAI wire word `category_applied_input_types`.
const CATEGORY_APPLIED_INPUT_TYPES: &str = "category_applied_input_types";
/// The OpenAI wire word `file`.
const FILE: &str = "file";
/// The OpenAI media type `audio/wav`.
const AUDIO_WAV: &str = "audio/wav";
/// The OpenAI wire word `prompt_tokens_details`.
const PROMPT_TOKENS_DETAILS: &str = "prompt_tokens_details";
/// The OpenAI wire word `completion_tokens`.
const COMPLETION_TOKENS: &str = "completion_tokens";
/// The OpenAI wire word `completion_tokens_details`.
const COMPLETION_TOKENS_DETAILS: &str = "completion_tokens_details";
/// The OpenAI wire word `audio_tokens`.
const AUDIO_TOKENS: &str = "audio_tokens";
/// The OpenAI wire word `accepted_prediction_tokens`.
const ACCEPTED_PREDICTION_TOKENS: &str = "accepted_prediction_tokens";
/// The OpenAI wire word `rejected_prediction_tokens`.
const REJECTED_PREDICTION_TOKENS: &str = "rejected_prediction_tokens";
/// The OpenAI wire word `audio`.
const AUDIO: &str = "audio";
/// The OpenAI wire word `mp3`.
const FORMAT_MP3: &str = "mp3";
/// The OpenAI wire word `choices`.
const CHOICES: &str = "choices";
/// The OpenAI wire word `max_completion_tokens`.
const MAX_COMPLETION_TOKENS: &str = "max_completion_tokens";
/// The OpenAI wire word `functions`.
const FUNCTIONS: &str = "functions";
/// The OpenAI wire word `reasoning_effort`.
const REASONING_EFFORT: &str = "reasoning_effort";
/// The OpenAI wire word `reasoning_content`.
const REASONING_CONTENT: &str = "reasoning_content";
/// The OpenAI wire word `system_fingerprint`.
const SYSTEM_FINGERPRINT: &str = "system_fingerprint";

// ────────────────────────────────────────────────────────────────────────────

/// Resolve the `model` to emit on an OpenAI response: the upstream-supplied value when present,
/// otherwise the [`DEFAULT_MODEL`] fallback so the required non-nullable `model` field is never
/// omitted on a cross-protocol response. Never panics on the request path.
fn model_or_default(model: Option<&str>) -> &str {
    model.unwrap_or(DEFAULT_MODEL)
}

/// OpenAI native `finish_reason` token → canonical [`crate::codec::ir::IrStopReason`]. The ONLY place that
/// knows OpenAI's finish vocabulary on the read side.
fn read_openai_stop_reason(token: &str) -> crate::codec::ir::IrStopReason {
    use crate::codec::ir::IrStopReason as S;
    match token {
        FINISH_STOP => S::EndTurn,
        FINISH_LENGTH => S::MaxTokens,
        FINISH_TOOL_CALLS | FINISH_FUNCTION_CALL => S::ToolUse,
        FINISH_CONTENT_FILTER => S::Safety,
        _ => S::Other,
    }
}

/// [`crate::codec::ir::IrStopReason`] → OpenAI native `finish_reason`. EXHAUSTIVE: OpenAI's enum is
/// {stop,length,tool_calls,content_filter}; any reason with no OpenAI analog (`refusal`, `error`,
/// `pause_turn`, `other`) degrades to the SDK-safe `stop` rather than leak an off-enum value a strict
/// SDK rejects.
fn write_openai_stop_reason(reason: crate::codec::ir::IrStopReason) -> &'static str {
    use crate::codec::ir::IrStopReason as S;
    match reason {
        S::EndTurn | S::StopSequence => FINISH_STOP,
        S::MaxTokens => FINISH_LENGTH,
        S::ToolUse => FINISH_TOOL_CALLS,
        S::Safety => FINISH_CONTENT_FILTER,
        S::Refusal | S::Error | S::PauseTurn | S::Other => FINISH_STOP,
    }
}

/// Read an OpenAI Chat Completions `response_format` object into the protocol-agnostic
/// [`crate::codec::ir::IrResponseFormat`]. This is the ONLY code that knows OpenAI's structured-output wire
/// shape (`{type:"json_schema", json_schema:{name,schema,strict,description}}` / `{type:"json_object"}`
/// / `{type:"text"}`). Returns `None` for a non-object or absent directive.
fn read_openai_response_format(
    v: &serde_json::Value,
) -> Option<crate::codec::ir::IrResponseFormat> {
    let o = v.as_object()?;
    match o.get(keys::TYPE).and_then(|t| t.as_str()) {
        Some(RESP_FORMAT_TEXT) => Some(crate::codec::ir::IrResponseFormat {
            json: false,
            schema: None,
            name: None,
            strict: None,
            description: None,
        }),
        Some(RESP_FORMAT_JSON_SCHEMA) => {
            let js = o.get(keys::JSON_SCHEMA);
            Some(crate::codec::ir::IrResponseFormat {
                json: true,
                schema: js.and_then(|j| j.get(keys::SCHEMA)).cloned(),
                name: js
                    .and_then(|j| j.get(keys::NAME))
                    .and_then(|n| n.as_str())
                    .map(String::from),
                strict: js
                    .and_then(|j| j.get(keys::STRICT))
                    .and_then(|s| s.as_bool()),
                description: js
                    .and_then(|j| j.get(keys::DESCRIPTION))
                    .and_then(|d| d.as_str())
                    .map(String::from),
            })
        }
        // `json_object` carries no schema; an unrecognized `type` is treated as free-form JSON (the
        // safe non-rejecting default) rather than dropped.
        Some(_) => Some(crate::codec::ir::IrResponseFormat {
            json: true,
            schema: None,
            name: None,
            strict: None,
            description: None,
        }),
        None => None,
    }
}

/// Project the agnostic [`crate::codec::ir::IrResponseFormat`] into OpenAI's native `response_format`. The
/// ONLY code that builds OpenAI's structured-output wire shape.
fn write_openai_response_format(rf: &crate::codec::ir::IrResponseFormat) -> serde_json::Value {
    if !rf.json {
        return serde_json::json!({(keys::TYPE): RESP_FORMAT_TEXT});
    }
    match &rf.schema {
        Some(schema) => {
            let mut js = serde_json::Map::new();
            // OpenAI REQUIRES `json_schema.name`; synthesize a valid one when the source had none.
            js.insert(
                keys::NAME.to_string(),
                serde_json::json!(rf.name.as_deref().unwrap_or(JSON_SCHEMA_DEFAULT_NAME)),
            );
            js.insert(keys::SCHEMA.to_string(), schema.clone());
            if let Some(s) = rf.strict {
                js.insert(keys::STRICT.to_string(), serde_json::json!(s));
            }
            if let Some(d) = &rf.description {
                js.insert(keys::DESCRIPTION.to_string(), serde_json::json!(d));
            }
            serde_json::json!({(keys::TYPE): RESP_FORMAT_JSON_SCHEMA, (keys::JSON_SCHEMA): js})
        }
        None => serde_json::json!({(keys::TYPE): RESP_FORMAT_JSON_OBJECT}),
    }
}

/// Width of a native OpenAI chat-completion id's random suffix: the `chatcmpl-` prefix is followed
/// by exactly 24 base62 characters (total 33 chars), the shape every native `chat.completion` /
/// `chat.completion.chunk` id carries. Matching this length AND alphabet is what keeps the
/// synthesized id structurally indistinguishable from a native one to any client that length-checks
/// or regex-validates `id` (SDK validators, logging/dedup tooling).
const COMPLETION_ID_TOKEN_LEN: usize = 24;

/// Base62 alphabet native OpenAI completion ids draw their suffix from — the shared
/// single-source-of-truth atom (see `crate::codec::dialect::BASE62_ALPHABET`), aliased locally. Used by
/// [`synth_completion_id`].
const BASE62: &[u8; 62] = crate::codec::dialect::BASE62_ALPHABET;

/// Synthesize a protocol-correct OpenAI completion id (`"chatcmpl-<24 base62 chars>"`) for
/// cross-protocol responses where the backend supplied none. Native OpenAI chat-completion ids are
/// `chatcmpl-` plus a fixed-width 24-char base62 token (33 chars total); the official SDKs treat
/// `id` as opaque, but tooling that length-checks or regex-validates the id immediately fingerprints
/// a too-short or wrong-alphabet value as non-native. The previous base-36 form produced a
/// variable-width ~7-char little-endian suffix (~16 chars total) — both too short and non-canonical.
///
/// The 24-char suffix is filled ENTIRELY from the OS CSPRNG (mirroring `synth_anthropic_request_id`
/// in `proto::anthropic` / `synth_amzn_request_id` in `proto::bedrock`), giving native-looking
/// entropy at EVERY position. A
/// 24-char base62 token is ~142 bits of entropy; the birthday bound on a collision is ~2^71 draws,
/// so pure CSPRNG output is collision-free in practice and needs no monotonic-counter backstop. We
/// deliberately do NOT overlay a process counter: a counter overlaid into any fixed region of the
/// token makes those characters predictable/low-entropy (the counter stays small, so its high
/// base62 digits are constant '0'), which is itself a structural fingerprint a native vendor id —
/// which is fully random across all positions — never carries. Native vendor ids ARE fully random,
/// so we are too. Never panics on the request path: on the near-impossible entropy failure the
/// buffer stays the base62 zero char rather than `?`-ing out.
///
/// Mapping CSPRNG bytes into base62 uses REJECTION SAMPLING, not `byte % 62`. A raw modulo is biased
/// because 256 is not a multiple of 62 (256 = 4*62 + 8): the eight residues 0..=7 each receive one
/// extra source byte (5/256 probability vs 4/256 for residues 8..=61), so the first eight alphabet
/// characters ('0'..='7') would appear ~25% more often than the rest. A native vendor id is uniform
/// over the alphabet, so a skewed character histogram is itself a statistical fingerprint. We accept
/// only bytes below 248 (= 4*62, the largest multiple of 62 that fits in a byte) and discard the rest,
/// which yields an exactly-uniform draw over 0..62. Discards are rare (8/256 ≈ 3.1%), so we refill the
/// entropy buffer on demand rather than over-allocating up front; on an entropy failure the loop
/// stops and the remaining slots keep their '0' fill, preserving the panic-free contract.
fn synth_completion_id() -> String {
    // Largest multiple of 62 that fits in a u8; bytes >= this are rejected to keep the draw uniform.
    const BASE62_REJECT_FLOOR: u8 = crate::codec::dialect::BASE62_REJECT_THRESHOLD; // 4 * 62
    let mut token = [b'0'; COMPLETION_ID_TOKEN_LEN];
    let mut filled = 0usize;
    // Pull entropy in batches and consume only the in-range bytes. If a batch yields too few usable
    // bytes we draw another; on an entropy failure we stop and leave '0' fill.
    'outer: while filled < COMPLETION_ID_TOKEN_LEN {
        let mut batch = [0u8; COMPLETION_ID_TOKEN_LEN];
        if !super::synth_rng::fill_entropy(&mut batch) {
            // Near-impossible entropy failure: keep the remaining '0' fill rather than panic.
            break 'outer;
        }
        for &byte in batch.iter() {
            if byte >= BASE62_REJECT_FLOOR {
                continue; // biased residue — discard to keep the distribution uniform
            }
            token[filled] = BASE62[(byte % 62) as usize];
            filled += 1;
            if filled == COMPLETION_ID_TOKEN_LEN {
                break 'outer;
            }
        }
    }

    // `token` is ASCII base62 by construction, hence always valid UTF-8; the fallback only guards
    // against an impossible non-ASCII byte and keeps the path panic-free.
    let token = std::str::from_utf8(&token).unwrap_or("000000000000000000000000");
    format!("{COMPLETION_ID_PREFIX}{token}")
}

/// The `error.code` token OpenAI-compatible upstreams use for a rate limit. The specific token
/// rides on `code`; `type` carries the coarser `rate_limit_error` bucket.
const STREAM_ERR_CODE_RATE_LIMIT: &str = "rate_limit_exceeded";

/// Derive the breaker class for an INLINE mid-stream `{"error":{...}}` chunk from the upstream
/// `error.code` / `error.type`.
///
/// There is no HTTP status to classify on — the response was already 200 when the failure landed —
/// so the envelope's own vocabulary is the only signal. `code` is consulted FIRST because
/// OpenAI-compatible upstreams put the specific token there (`context_length_exceeded`,
/// `rate_limit_exceeded`) and leave `type` on a coarse bucket; `type` is the fallback.
///
/// An unrecognized or absent signal defaults to the transient `ServerError` bucket, mirroring the
/// openai_responses sibling: the lane recovers via cooldown rather than being permanently
/// penalized, and — critically — the stream is never mistaken for a success. The default is a
/// NAMED arm, not a `_ =>` swallow, so a future token surfaces as an explicit unmapped case here.
fn stream_inline_error_class(error_type: Option<&str>, code: Option<&str>) -> StatusClass {
    let signal = code.filter(|c| !c.is_empty()).or(error_type);
    match signal {
        Some(busbar_contract::protocol::PROVIDER_CODE_CONTEXT_LENGTH) => StatusClass::ContextLength,
        Some(STREAM_ERR_CODE_RATE_LIMIT)
        | Some(ERR_TYPE_RATE_LIMIT)
        | Some(ERR_TYPE_INSUFFICIENT_QUOTA) => StatusClass::RateLimit,
        Some(ERR_TYPE_AUTHENTICATION) | Some(ERR_TYPE_PERMISSION) => StatusClass::Auth,
        Some(ERR_TYPE_OVERLOADED) => StatusClass::Overloaded,
        Some(ERR_TYPE_INVALID_REQUEST) | Some(ERR_TYPE_NOT_FOUND) => StatusClass::ClientError,
        Some(ERR_TYPE_SERVER_ERROR) => StatusClass::ServerError,
        Some(_unrecognized) => StatusClass::ServerError,
        None => StatusClass::ServerError,
    }
}

/// OpenAI reader implementation.
#[derive(Clone)]
pub struct OpenAiReader;

/// Project an [`crate::codec::ir::IrBlock::Media`] into the OpenAI Chat Completions content part that can
/// express it, or `None` when this dialect has no slot for it (the caller emits nothing).
///
/// OpenAI Chat has exactly TWO attachment parts — `input_audio` (inline base64 + a bare format
/// token) and `file` (a data-URI `file_data` + `filename`, or an uploads-API `file_id`) — and NO
/// video part. So:
///
/// * Audio with inline bytes → `input_audio`, the format token recovered from the mime subtype.
/// * Document → `file`, as a data URI (round-tripping what the reader parsed) or the native
///   `file_id` when the source is this protocol's own vendor reference.
/// * Video, and audio that is only a URL/foreign reference → NOTHING is emitted, with a `warn!`
///   naming the construct. That is the deliberate, logged drop; the empty text block it replaces was
///   the silent one — indistinguishable, to the model and to the operator, from the caller having
///   attached nothing at all.
fn media_part_from_ir(
    kind: crate::codec::ir::IrMediaKind,
    source: &crate::codec::ir::IrImageSource,
    name: Option<&str>,
) -> Option<serde_json::Value> {
    use crate::codec::ir::{IrImageSource as S, IrMediaKind as K};
    match (kind, source) {
        (K::Audio, S::Base64 { media_type, data }) => {
            // OpenAI's `input_audio.format` is a CLOSED enum — `{wav, mp3}` (openai-openapi
            // `ChatCompletionRequestMessageContentPartAudio.input_audio.format`). The old
            // `media_type.rsplit('/')` emitted the raw mime SUBTYPE, so `audio/mpeg` produced
            // `format:"mpeg"` (and `audio/x-wav` → `"x-wav"`), both of which the API 400-rejects as
            // not-in-enum. Map the mime to a valid enum token instead; an audio mime with NO
            // `{wav, mp3}` representation (e.g. `audio/ogg`, `audio/flac`) has no slot on this
            // dialect at all, so it falls through to the drop-with-warn arm below rather than
            // emitting an invalid `format`.
            match openai_audio_input_format(media_type) {
                Some(format) => Some(serde_json::json!({
                    (keys::TYPE): keys::INPUT_AUDIO,
                    (keys::INPUT_AUDIO): { (keys::DATA): data, (keys::FORMAT): format }
                })),
                None => {
                    crate::codec::drops::writer_drop!(
                        crate::codec::drops::AUDIO,
                        &crate::codec::diagnostics::IR_DROP_UNMODELED_KEYS,
                        [media_kind = AUDIO, mime = media_type.as_str(),],
                        "dropping audio attachment on OpenAI Chat egress: input_audio.format is a \
                         closed {{wav, mp3}} enum and this mime maps to neither; the block is NOT \
                         emitted (deliberately absent, not an invalid format the API would 400 on)"
                    );
                    None
                }
            }
        }
        (K::Document, S::Base64 { media_type, data }) => {
            let mut file = serde_json::Map::new();
            file.insert(
                keys::FILE_DATA.to_string(),
                serde_json::json!(format!("data:{media_type};base64,{data}")),
            );
            if let Some(n) = name {
                file.insert(keys::FILENAME.to_string(), serde_json::json!(n));
            }
            Some(serde_json::json!({ (keys::TYPE): FILE, (FILE): serde_json::Value::Object(file) }))
        }
        // An OpenAI Files handle — this dialect's own or a Responses `input_file.file_id`, the same
        // namespace (SHR-03): re-emit the native `file_id` form.
        (K::Document, source) if super::url_citation_wire::files_api_id(source).is_some() => {
            let id = super::url_citation_wire::files_api_id(source)?;
            let mut file = serde_json::Map::new();
            file.insert(keys::FILE_ID.to_string(), serde_json::json!(id));
            if let Some(n) = name {
                file.insert(keys::FILENAME.to_string(), serde_json::json!(n));
            }
            Some(serde_json::json!({ (keys::TYPE): FILE, (FILE): serde_json::Value::Object(file) }))
        }
        _ => {
            crate::codec::drops::writer_drop!(
                crate::codec::drops::block(kind.as_str()),
                &crate::codec::diagnostics::IR_DROP_UNMODELED_KEYS,
                [media_kind = kind.as_str(), ],
                "dropping attachment on OpenAI Chat egress: this dialect has content parts for \
                 inline audio (`input_audio`) and files (`file`) only — a video block, or an \
                 attachment carried as a bare URL or a foreign vendor handle, has no part to go in. \
                 The block is NOT emitted (it is deliberately absent, not replaced by empty text)");
            None
        }
    }
}

/// Map an audio mime type onto OpenAI Chat's `input_audio.format` enum token, or `None` when the
/// mime has no representation in the closed `{wav, mp3}` enum.
///
/// The enum is `{wav, mp3}` per openai-openapi
/// (`ChatCompletionRequestMessageContentPartAudio.input_audio.format`). Every other dialect speaks
/// real mime types in the neutral IR, so this is the inverse of the reader's `audio/{format}`
/// normalization: `audio/mpeg` (the canonical mp3 mime) and the `audio/mp3` alias → `mp3`;
/// `audio/wav` and its `x-wav`/`wave`/`vnd.wave` aliases → `wav`. Anything else (`audio/ogg`,
/// `audio/flac`, …) returns `None` — the caller drops it with a warn rather than emit an off-enum
/// token the API rejects.
fn openai_audio_input_format(media_type: &str) -> Option<&'static str> {
    match media_type.to_ascii_lowercase().as_str() {
        keys::AUDIO_MPEG | "audio/mp3" | "audio/mpeg3" | "audio/x-mpeg-3" => Some(FORMAT_MP3),
        AUDIO_WAV | "audio/x-wav" | "audio/wave" | "audio/vnd.wave" | "audio/x-pn-wav" => {
            Some(keys::WAV)
        }
        _ => None,
    }
}

/// The Chat content-part kinds this reader models.
const PART_KINDS: &[&str] = &[
    keys::TEXT,
    keys::IMAGE_URL,
    keys::INPUT_AUDIO,
    FILE,
    keys::REFUSAL,
];

/// The Chat request content-part grammar (`codec::drops`). A part of any other kind does not cross
/// a translate attempt, which names it.
const REQUEST_BLOCKS: &[crate::codec::drops::Blocks] = &[crate::codec::drops::Blocks {
    at: &["messages[]", "content[]"],
    tag: Some(keys::TYPE),
    modelled: PART_KINDS,
    companions: &[],
}];

/// The Chat answer content-part grammar.
/// How this dialect spells each IR content-block kind (a dropped block's warn names it so).
const IR_BLOCK_KINDS: &[(&str, &str)] = &[
    (crate::codec::drops::kind::TEXT, "type=text"),
    (crate::codec::drops::kind::IMAGE, "type=image_url"),
    (crate::codec::drops::kind::DOCUMENT, "type=file"),
    (crate::codec::drops::kind::AUDIO, "type=input_audio"),
    (crate::codec::drops::kind::TOOL_USE, "tool_calls[]"),
    (crate::codec::drops::kind::TOOL_RESULT, "role=tool"),
];

/// The IR request members the reader carries by code from a path no map-file row names (how a drop
/// of one is named by the caller's wire path).
const REQUEST_CODE_NAMES: &[(&str, &str)] =
    &[(crate::codec::drops::name::TOP_LOGPROBS, keys::TOP_LOGPROBS)];

/// The IR request members the reader never sets.
// No cache marks (`prompt_cache_key` is a routing hint) and no `top_k`.
const UNREAD: &[&str] = &[
    crate::codec::drops::name::CACHE_CONTROL,
    crate::codec::drops::name::TOP_K,
];

const RESPONSE_BLOCKS: &[crate::codec::drops::Blocks] = &[crate::codec::drops::Blocks {
    at: &["choices[]", "message", "content[]"],
    tag: Some(keys::TYPE),
    modelled: PART_KINDS,
    companions: &[],
}];

/// What the Chat reader parks in `extra` beside the members its map file does not model.
const PARKED: &[crate::codec::drops::Parked] = &[
    // A spelling hint: the cap itself crosses as `max_tokens`.
    crate::codec::drops::Parked {
        key: MAX_COMPLETION_TOKENS_SENTINEL,
        holds: crate::codec::drops::Holds::Nothing,
    },
    crate::codec::drops::Parked {
        key: crate::codec::dialect::MESSAGE_NAMES_SENTINEL,
        holds: crate::codec::drops::Holds::Path(crate::codec::dialect::MESSAGE_NAMES_PATH),
    },
    crate::codec::drops::Parked {
        key: MESSAGE_EXTRAS_SENTINEL,
        holds: crate::codec::drops::Holds::Items("messages[]", &[LEGACY_FUNCTION_ROLE_KEY]),
    },
    // The legacy function-calling members: read into `tools` / `tool_choice`, which cross.
    crate::codec::drops::Parked {
        key: FUNCTIONS,
        holds: crate::codec::drops::Holds::Nothing,
    },
    crate::codec::drops::Parked {
        key: keys::FUNCTION_CALL,
        holds: crate::codec::drops::Holds::Nothing,
    },
    // Governed: the usage opt-in is busbar's metering edit for the far end (design F2).
    crate::codec::drops::Parked {
        key: keys::STREAM_OPTIONS,
        holds: crate::codec::drops::Holds::Nothing,
    },
];

/// Read one OpenAI-format content part: `None` for a part kind this reader does not model, which
/// is dropped — nothing is put in its place.
fn read_openai_part(
    block_val: &serde_json::Value,
) -> Result<Option<crate::codec::ir::IrBlock>, IrError> {
    if !REQUEST_BLOCKS.iter().all(|g| g.models(block_val)) {
        return Ok(None);
    }
    read_openai_block(block_val).map(Some)
}

/// Read an OpenAI-format block of a kind [`REQUEST_BLOCKS`] models.
fn read_openai_block(block_val: &serde_json::Value) -> Result<crate::codec::ir::IrBlock, IrError> {
    let obj = block_val.as_object().ok_or_else(ir_parse_error)?;

    let block_type = obj.get(keys::TYPE).and_then(|v| v.as_str()).unwrap_or("");

    match block_type {
        keys::TEXT => {
            let text_val = obj.get(keys::TEXT);
            let text = text_val.and_then(|t| t.as_str()).unwrap_or("").to_string();
            Ok(crate::codec::ir::IrBlock::Text {
                text,
                cache_control: None,
                citations: Vec::new(),
                refusal: false,
            })
        }
        keys::IMAGE_URL => {
            let image_obj = obj.get(keys::IMAGE_URL).ok_or_else(ir_parse_error)?;
            let url = image_obj
                .get(keys::URL)
                .and_then(|v| v.as_str())
                .unwrap_or("");
            // The IR `Image` contract (set by the Anthropic reader) is: `media_type` = a real MIME
            // type (e.g. "image/png") and `data` = the raw base64 payload. The Anthropic writer
            // renders that as a `{"type":"base64", "media_type":..., "data":...}` source. The prior
            // code stored `media_type: "image"` (a literal, not a MIME type) and `data: <the full
            // url>`, which the Anthropic writer then emitted as a base64 source whose data was a
            // URL — an invalid Anthropic request. For a `data:<mime>;base64,<payload>` URI we now
            // split out the real MIME type and payload so the cross-protocol image is valid.
            // `image_url.detail` (`low`/`high`/`auto`) is the image-fidelity ask the IR carries
            // (IR-08; Responses and Cohere use the same words). An unknown word is dropped with a
            // warn rather than coerced onto a fidelity the caller did not ask for.
            let detail = image_obj.get(keys::DETAIL).and_then(|v| v.as_str());
            let parsed = detail.and_then(crate::codec::ir::IrImageDetail::parse);
            if let (Some(word), None) = (detail, parsed) {
                crate::codec::drops::writer_drop!(
                    crate::codec::drops::wire("messages[].content[].image_url.detail"),
                    &crate::codec::diagnostics::IR_DROP_UNMODELED_KEYS,
                    [detail = word,],
                    "dropping an unknown image_url.detail word: the IR carries auto/low/high only"
                );
            }
            Ok(crate::codec::ir::IrBlock::Image {
                source: super::ir_encode::parse_image_url(url),
                cache_control: None,
                detail: parsed,
            })
        }
        // An audio ATTACHMENT the caller sent for the model to listen to:
        // `{"type":"input_audio","input_audio":{"data":"<b64>","format":"wav"|"mp3"}}`. Before
        // `IrBlock::Media` existed this fell through to the unknown-part arm below and became
        // `{"type":"text","text":""}` with no warn — the audio never reached the model, the model
        // answered "transcribe what?", and nothing in the logs said why, even though a Gemini lane
        // would have accepted it natively as `inlineData`. OpenAI carries the format as a bare token
        // (`wav`), so normalize it to the real mime type the neutral IR (and every other dialect)
        // speaks; the writer reverses this exactly.
        keys::INPUT_AUDIO => {
            let audio_obj = obj.get(keys::INPUT_AUDIO).ok_or_else(ir_parse_error)?;
            let data = audio_obj
                .get(keys::DATA)
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let format = audio_obj
                .get(keys::FORMAT)
                .and_then(|v| v.as_str())
                .unwrap_or(keys::WAV);
            Ok(crate::codec::ir::IrBlock::Media {
                kind: crate::codec::ir::IrMediaKind::Audio,
                source: crate::codec::ir::IrImageSource::Base64 {
                    media_type: format!("audio/{format}"),
                    data,
                },
                name: None,
                cache_control: None,
                citations: None,
                context: None,
            })
        }
        // A file ATTACHMENT: `{"type":"file","file":{"file_data":"data:application/pdf;base64,…",
        // "filename":"x.pdf"}}` or `{"type":"file","file":{"file_id":"file-1"}}`. Same story as
        // `input_audio` — it used to become an empty text block. `file_data` is a data URI, so the
        // shared `parse_image_url` seam (protocol-neutral despite the name: it splits
        // `data:<mime>;base64,<payload>` and otherwise keeps a URL verbatim) yields the same typed
        // source an image gets. A `file_id` is an OpenAI-hosted reference with NO neutral form, so it
        // rides the opaque `Vendor` escape and only an OpenAI-family writer re-emits it.
        FILE => {
            let file_obj = obj.get(FILE).ok_or_else(ir_parse_error)?;
            let name = file_obj
                .get(keys::FILENAME)
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(String::from);
            let source = match file_obj
                .get(keys::FILE_DATA)
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
            {
                Some(data_uri)
                    if data_uri.starts_with("data:")
                        || data_uri.starts_with("https://")
                        || data_uri.starts_with("http://") =>
                {
                    super::ir_encode::parse_image_url(data_uri)
                }
                // `file_data` is documented as the base64-encoded file content, and clients send it
                // BARE (no `data:` prefix) as well as wrapped. Parsed as a URL, a bare payload became
                // an attachment every writer drops (OAI-06); it is the base64 payload itself, typed by
                // the filename's extension (the only type signal a bare payload carries).
                Some(bare_base64) => crate::codec::ir::IrImageSource::Base64 {
                    media_type: file_media_type_from_name(name.as_deref()).to_string(),
                    data: bare_base64.to_string(),
                },
                None => {
                    let file_id = file_obj
                        .get(keys::FILE_ID)
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    crate::codec::ir::IrImageSource::Vendor {
                        vendor: VENDOR_NAME,
                        value: serde_json::json!({ (keys::FILE_ID): file_id }),
                    }
                }
            };
            // The mime type, when the data URI carried one, is the ONLY signal of what kind of
            // attachment this is — an OpenAI `file` part is used for PDFs today but the mime decides.
            let kind = match &source {
                crate::codec::ir::IrImageSource::Base64 { media_type, .. } => {
                    crate::codec::ir::IrMediaKind::from_media_type(media_type)
                }
                _ => crate::codec::ir::IrMediaKind::Document,
            };
            Ok(crate::codec::ir::IrBlock::Media {
                kind,
                source,
                name,
                cache_control: None,
                citations: None,
                context: None,
            })
        }
        // OpenAI gpt-4o-and-later responses carry `refusal` content parts; a client replaying its
        // OpenAI conversation history through busbar will include them. Map a refusal to a Text block
        // carrying the refusal string, flagged as a refusal (IR-02), so the turn survives translation
        // rather than being rejected with a 400, and a dialect with a refusal part keeps it one.
        keys::REFUSAL => {
            let text = obj
                .get(keys::REFUSAL)
                .and_then(|t| t.as_str())
                .unwrap_or("")
                .to_string();
            Ok(crate::codec::ir::IrBlock::Text {
                text,
                cache_control: None,
                citations: Vec::new(),
                refusal: true,
            })
        }
        // An unknown/future part kind never reaches here: `read_openai_part` drops it (nothing is
        // put in its place), so this arm only answers a direct call with a kind outside the grammar.
        _ => Err(ir_parse_error()),
    }
}

/// The media type of a bare-base64 `file.file_data` payload, from its `filename` extension.
/// `application/octet-stream` when there is no filename or the extension is not one listed here —
/// the payload's type is then genuinely unknown, and no specific type is invented for it.
fn file_media_type_from_name(name: Option<&str>) -> &'static str {
    let ext = name
        .and_then(|n| n.rsplit_once('.'))
        .map(|(_, e)| e.to_ascii_lowercase())
        .unwrap_or_default();
    const CHAT_MEDIA_TYPES: &[(&str, &str)] = &[
        ("htm", "text/html"),
        ("json", "application/json"),
        ("xml", "application/xml"),
        ("jpg", keys::IMAGE_JPEG),
        ("jpeg", keys::IMAGE_JPEG),
        (keys::WAV, AUDIO_WAV),
        (FORMAT_MP3, keys::AUDIO_MPEG),
    ];
    crate::codec::dialect::media_type(
        &[
            crate::codec::dialect::DOCUMENT_MEDIA_TYPES,
            crate::codec::dialect::IMAGE_MEDIA_TYPES,
            CHAT_MEDIA_TYPES,
        ],
        &ext,
    )
    .unwrap_or(keys::APPLICATION_OCTET_STREAM)
}

/// Read an OpenAI-format tool from JSON.
fn read_openai_tool(tool_val: &serde_json::Value) -> Result<crate::codec::ir::IrTool, IrError> {
    let obj = tool_val.as_object().ok_or_else(ir_parse_error)?;

    // A tool whose `type` is not `function` — today Chat's `custom` tool
    // (`{"type":"custom","custom":{"name","description","format"}}`, free-text or grammar input, no
    // JSON-schema parameters) — has no function-tool projection in any other dialect. Reading it as
    // a function yielded an EMPTY-NAME, null-schema function tool that every foreign backend rejects
    // (OAI-09). It is carried as a `hosted` tool instead: the raw definition rides verbatim, the
    // cross-protocol seam drops it with its hosted-tool diagnostic, and this dialect's own writer
    // re-emits it unchanged.
    if let Some(kind) = obj.get(keys::TYPE).and_then(|t| t.as_str()) {
        if kind != TOOL_TYPE_FUNCTION {
            return Ok(crate::codec::ir::IrTool {
                name: String::new(),
                description: None,
                input_schema: serde_json::Value::Null,
                cache_control: None,
                hosted: Some(tool_val.clone()),
                strict: None,
            });
        }
    }

    // OpenAI nests the tool definition under `function` ({"type":"function","function":{...}}).
    // Read from there, falling back to the top level so a flattened/native-shaped tool still works.
    let src = obj
        .get(keys::FUNCTION)
        .and_then(|f| f.as_object())
        .unwrap_or(obj);

    let name = src
        .get(keys::NAME)
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let description = src
        .get(keys::DESCRIPTION)
        .and_then(|v| v.as_str().map(String::from));
    let input_schema = src
        .get(keys::PARAMETERS)
        .or_else(|| src.get("input_schema"))
        .cloned()
        .unwrap_or(serde_json::Value::Null);

    Ok(crate::codec::ir::IrTool {
        name,
        description,
        input_schema,
        cache_control: None,
        hosted: None,
        // STRICT function calling. Nested under `function` like `name`/`parameters`, so it is read
        // off `src` (which already resolved the nested-vs-flat shape). Absent ⇒ `None`, which is NOT
        // `Some(false)`: "the caller said nothing" must not be re-emitted as an explicit opt-out.
        strict: src.get(keys::STRICT).and_then(|v| v.as_bool()),
    })
}

/// Read an OpenAI-format `tool_choice` into the IR union. Shapes: the strings `"auto"` /
/// `"none"` / `"required"`, or `{"type":"function","function":{"name":"X"}}` for a forced specific
/// tool. Absent or any unrecognized shape yields `None` (the safe default — no directive emitted).
fn read_openai_tool_choice(
    val: Option<&serde_json::Value>,
) -> Option<crate::codec::ir::IrToolChoice> {
    match val? {
        serde_json::Value::String(s) => match s.as_str() {
            keys::AUTO => Some(crate::codec::ir::IrToolChoice::Auto),
            keys::NONE_WORD => Some(crate::codec::ir::IrToolChoice::None),
            keys::REQUIRED => Some(crate::codec::ir::IrToolChoice::Required),
            _ => None,
        },
        serde_json::Value::Object(o) => {
            if o.get(keys::TYPE).and_then(|t| t.as_str()) == Some(TOOL_TYPE_FUNCTION) {
                o.get(keys::FUNCTION)
                    .and_then(|f| f.get(keys::NAME))
                    .and_then(|n| n.as_str())
                    .map(|name| crate::codec::ir::IrToolChoice::Tool {
                        name: name.to_string(),
                    })
            } else {
                None
            }
        }
        _ => None,
    }
}

/// The OpenAI stream-start identity replayed onto every `chat.completion.chunk` (see
/// `OpenAiStreamFraming`). Captured from the opening chunk the OpenAI writer emits for the IR
/// `MessageStart` (which already synthesizes a stable `id`/`created` when the cross-protocol backend
/// supplied none), so the whole stream shares ONE identity.
#[derive(Clone)]
struct OpenAiChunkIdentity {
    id: serde_json::Value,
    created: serde_json::Value,
    model: Option<serde_json::Value>,
}

/// OpenAI-INGRESS per-stream framing. Holds the latched stream identity and applies the two
/// OpenAI-only client-facing wire quirks the shared `StreamTranslate` translator must NOT name itself:
/// (1) the real OpenAI API repeats the top-level `id`/`created`/`model` on EVERY
/// `chat.completion.chunk`, but the writer emits them only on the opening (role) chunk — so this latches
/// them off the first chunk and replays them onto every later one; and (2) the native `include_usage`
/// convention emits token usage on a SEPARATE trailing chunk AFTER the finish_reason chunk, never folded
/// onto it — but the 1:1 writer FOLDS `usage` onto the finish chunk, so this un-folds it. Built per
/// stream via [`OpenAiWriter::new_stream_framing`]; its reframing runs only on the cross-protocol path
/// (the same-protocol path re-emits frames verbatim and never invokes it).
#[derive(Default)]
struct OpenAiStreamFraming {
    /// The stream-start identity, latched from the first `chat.completion.chunk` that carries an `id`
    /// (the opening role chunk) and replayed onto every later chunk. `None` until that first chunk.
    chunk_identity: Option<OpenAiChunkIdentity>,
    /// Raw IR-block-index → 0-based tool-call ordinal map. The writer stamps the CANONICAL
    /// IR block index onto `tool_calls[].index`, but a source stream can open a tool_use at a non-zero
    /// block index (e.g. an Anthropic stream with text at block 0 and the first tool_use at block 1).
    /// OpenAI's streaming contract requires `tool_calls[].index` to ENUMERATE the tool calls starting
    /// at 0 and incrementing per tool call — SDK argument accumulators (openai-python/openai-node) key
    /// their per-call buffers on that index, so a first tool call arriving at index 1 lands in a
    /// never-flushed slot and the call is dropped. This map assigns each distinct raw index the next
    /// 0-based ordinal on first sight and replays it for that call's argument-fragment chunks. Keeps
    /// PARALLEL tool calls distinct (each raw index → its own ordinal) while guaranteeing the first
    /// call is index 0. Populated lazily; empty on a tool-less stream.
    tool_call_index: std::collections::BTreeMap<u64, u64>,
    /// Did the ORIGINAL client request carry `stream_options.include_usage == true`?
    /// Busbar always injects `include_usage` UPSTREAM so it can bill streaming calls, which makes the
    /// upstream emit token usage; but a native OpenAI stream only surfaces a trailing usage-only chunk
    /// to the CLIENT when the client opted in. When this is `false`, `on_egress_chunk` STRIPS the
    /// folded usage instead of un-folding it, so a client that did not opt in never receives an
    /// unsolicited `{choices:[], usage}` chunk (which would `choices[0]` IndexError). Default `false`
    /// (opt-in, matching native OpenAI); the engine sets it from the client body via
    /// `set_client_include_usage`.
    client_include_usage: bool,
}

impl StreamFraming for OpenAiStreamFraming {
    fn on_egress_chunk(&mut self, chunk: &mut serde_json::Value) -> Option<serde_json::Value> {
        // (a) Identity replay, then (b) the 0-based tool-call index remap, then (c) the include_usage
        // handling — in this order, because the trailing chunk's identity is read off `chunk` AFTER the
        // identity has been populated onto it, so both frames share ONE stream identity. The `[DONE]`
        // sentinel is a separate `finish()` literal and never routed here.
        self.apply_chunk_identity(chunk);
        self.remap_tool_call_index(chunk);
        if self.client_include_usage {
            // Client opted in: un-fold the folded usage into a native separate trailing usage-only
            // chunk, exactly as real OpenAI does under `stream_options.include_usage:true`.
            split_openai_trailing_usage(chunk)
        } else {
            // Client did NOT opt in: STRIP the folded usage entirely so the finish chunk stays
            // usage-free and NO trailing usage-only chunk is emitted — matching a native OpenAI stream
            // without include_usage. Billing is unaffected (it reads the IR-side `last_usage` A-tap,
            // captured before this seam). An opted-out client therefore never receives the
            // unsolicited `{choices:[], usage}` chunk that trips `choices[0]`.
            strip_folded_usage(chunk);
            None
        }
    }

    // OpenAI ingress UN-folds (or strips) usage in `on_egress_chunk`, so the translator must NOT
    // defer/fold the terminal usage itself.
    fn folds_terminal_usage(&self) -> bool {
        false
    }

    fn set_client_include_usage(&mut self, include: bool) {
        self.client_include_usage = include;
    }

    /// SAME-PROTOCOL verbatim strip. On OpenAI->OpenAI the translator re-emits upstream
    /// frames byte-for-byte and never calls `on_egress_chunk`, so the opted-out `include_usage` strip
    /// above cannot fire. Busbar forces `include_usage` UPSTREAM (to bill), so the OpenAI upstream
    /// emits a NATIVE trailing usage-only chunk - a real top-level `usage` OBJECT and an EMPTY
    /// `choices` array. When the CLIENT did not opt in, suppress exactly that frame from the verbatim
    /// client bytes so a strict SDK never `choices[0]`-IndexErrors; the A-tap already captured its
    /// usage for billing. A normal content/finish chunk (non-empty `choices`) is never suppressed, and
    /// the opted-in case re-emits it verbatim.
    ///
    /// Like its `strip_same_proto_usage` sibling, the predicate deliberately does NOT require
    /// `object == "chat.completion.chunk"`. An OpenAI-COMPATIBLE upstream may omit the `object` field
    /// (or use a variant) while still emitting the forced-`include_usage` trailer; requiring the exact
    /// `object` value would let that unsolicited frame leak to an opted-out client. A usage OBJECT
    /// alongside an EMPTY `choices` array is that trailer regardless of `object`.
    fn suppress_same_proto_frame(&self, data: &serde_json::Value) -> bool {
        if self.client_include_usage {
            return false;
        }
        let Some(obj) = data.as_object() else {
            return false;
        };
        let has_usage_obj = obj.get(keys::USAGE).is_some_and(|u| u.is_object());
        let choices_empty = obj
            .get(CHOICES)
            .and_then(|c| c.as_array())
            .is_some_and(|arr| arr.is_empty());
        has_usage_obj && choices_empty
    }

    /// SAME-PROTOCOL intermediate `usage:null` strip (indistinguishability fix). On OpenAI->OpenAI the
    /// translator re-emits frames byte-for-byte, so the opted-out `strip_folded_usage` in
    /// `on_egress_chunk` never runs. Busbar forces `include_usage` UPSTREAM (to bill), so the OpenAI
    /// upstream stamps `"usage":null` on EVERY intermediate content chunk (and the finish chunk) - a key
    /// a native opted-out OpenAI stream never carries, hence a wire-shape tell. When the CLIENT did not
    /// opt in, request a byte-level strip of the top-level `usage` member from any content/finish chunk
    /// that carries a `usage` FIELD alongside a NON-EMPTY `choices` array.
    ///
    /// The predicate deliberately does NOT require `object == "chat.completion.chunk"`. An
    /// OpenAI-COMPATIBLE upstream may omit the `object` field (or use a variant) on its content chunks
    /// while still stamping the forced-`include_usage` `"usage":null` tell; requiring the exact `object`
    /// value would let that tell leak to an opted-out client. A frame with a NON-EMPTY `choices` array
    /// and a top-level `usage` key is a content/finish chunk regardless of `object`, so that pairing is
    /// sufficient. The trailing usage-ONLY chunk (EMPTY `choices`, a usage OBJECT) is dropped whole by
    /// `suppress_same_proto_frame` instead, so it is deliberately NOT matched here (the non-empty
    /// `choices` gate excludes it). The opted-in case returns `false` (the client asked for usage;
    /// re-emit verbatim), so a usage the client legitimately requested is never stripped. The A-tap
    /// already captured usage for billing before this seam.
    fn strip_same_proto_usage(&self, data: &serde_json::Value) -> bool {
        if self.client_include_usage {
            return false;
        }
        let Some(obj) = data.as_object() else {
            return false;
        };
        // A content/finish chunk carries a NON-EMPTY `choices` array. This gate (not `object`) is what
        // distinguishes a content/finish chunk from the empty-choices usage-only trailer, and it works
        // for compatible upstreams that omit or vary `object`.
        let choices_non_empty = obj
            .get(CHOICES)
            .and_then(|c| c.as_array())
            .is_some_and(|arr| !arr.is_empty());
        // Only act when a top-level `usage` key is actually present (the forced-include_usage tell).
        obj.contains_key(keys::USAGE) && choices_non_empty
    }
}

impl OpenAiStreamFraming {
    /// Remap every `choices[].delta.tool_calls[].index` on a `chat.completion.chunk` from the writer's
    /// CANONICAL raw IR-block index to a 0-based per-tool-call ordinal. The FIRST distinct
    /// raw index seen becomes ordinal 0, the next distinct raw index becomes 1, and so on; a raw index
    /// seen again (the tool call's argument-fragment chunks) replays its assigned ordinal. This makes
    /// the first tool call arrive at `index: 0` even when the source stream opened it at a non-zero
    /// block index (e.g. text at block 0, first tool_use at block 1), which is what the OpenAI SDKs
    /// require to route streamed `function.arguments` fragments into the right accumulator. A chunk
    /// with no tool_calls is a no-op.
    fn remap_tool_call_index(&mut self, chunk: &mut serde_json::Value) {
        let Some(obj) = chunk.as_object_mut() else {
            return;
        };
        if obj.get(keys::OBJECT).and_then(|v| v.as_str()) != Some(OBJ_CHUNK) {
            return;
        }
        let Some(choices) = obj.get_mut(CHOICES).and_then(|c| c.as_array_mut()) else {
            return;
        };
        for choice in choices {
            let Some(tool_calls) = choice
                .get_mut(keys::DELTA)
                .and_then(|d| d.get_mut(keys::TOOL_CALLS))
                .and_then(|tc| tc.as_array_mut())
            else {
                continue;
            };
            for tc in tool_calls {
                let Some(raw) = tc.get(keys::INDEX).and_then(|i| i.as_u64()) else {
                    continue;
                };
                // Assign the next ordinal on first sight of this raw index; replay it thereafter.
                // CAPPED at the same bound the reader clamps its own `open_tools` map to
                // (`MAX_OPEN_TOOLS`): the raw index comes off an UNTRUSTED upstream chunk, and an
                // uncapped first-sight insert would let a backend emitting unbounded distinct
                // indices grow this map without limit for one stream's lifetime. Past the cap a
                // NEW raw index passes through unmapped (its own value) — the stream is already
                // malformed beyond OpenAI's documented 128-parallel-call limit, and known indices
                // keep replaying their assigned ordinals.
                if self.tool_call_index.len() >= MAX_OPEN_TOOLS
                    && !self.tool_call_index.contains_key(&raw)
                {
                    continue;
                }
                let next = self.tool_call_index.len() as u64;
                let ordinal = *self.tool_call_index.entry(raw).or_insert(next);
                if let Some(tc_obj) = tc.as_object_mut() {
                    tc_obj.insert(keys::INDEX.to_string(), serde_json::json!(ordinal));
                }
            }
        }
    }

    /// Capture-or-replay the OpenAI stream identity on a `chat.completion.chunk` body. On the first
    /// chunk that carries an `id` (the opening role chunk), latch `id`/`created`/`model`; on every
    /// subsequent chunk (which the writer emits WITHOUT them), inject the latched values.
    fn apply_chunk_identity(&mut self, chunk: &mut serde_json::Value) {
        let Some(obj) = chunk.as_object_mut() else {
            return;
        };
        // Only `chat.completion.chunk` bodies carry stream identity. An in-band error envelope
        // (`{"error":{...}}`) the writer may emit has no `object` field — leave it untouched.
        if obj.get(keys::OBJECT).and_then(|v| v.as_str()) != Some(OBJ_CHUNK) {
            return;
        }
        match &self.chunk_identity {
            None => {
                // First chunk: latch its identity (the writer put id/created on the role chunk, and
                // model when the lane supplied one).
                if obj.contains_key(keys::ID) {
                    self.chunk_identity = Some(OpenAiChunkIdentity {
                        id: obj
                            .get(keys::ID)
                            .cloned()
                            .unwrap_or(serde_json::Value::Null),
                        created: obj.get(CREATED).cloned().unwrap_or(serde_json::Value::Null),
                        model: obj.get(keys::MODEL).cloned(),
                    });
                }
            }
            Some(identity) => {
                // Subsequent chunk: replay the latched identity (the writer omitted it).
                obj.entry(keys::ID.to_string())
                    .or_insert_with(|| identity.id.clone());
                obj.entry(CREATED.to_string())
                    .or_insert_with(|| identity.created.clone());
                if let Some(model) = &identity.model {
                    obj.entry(keys::MODEL.to_string())
                        .or_insert_with(|| model.clone());
                }
            }
        }
    }
}

/// Split a folded-usage OpenAI finish chunk into (finish-chunk-without-usage, trailing
/// usage-only chunk). Returns `Some(trailing_chunk)` when `chunk` is a `chat.completion.chunk` that
/// carries BOTH a folded top-level `usage` object AND a terminal `finish_reason` (the shape the
/// OpenAI writer produces when it cannot emit two events); in that case the folded `usage` is
/// REMOVED from `chunk` in place and re-homed onto a fresh trailing chunk shaped exactly like a
/// native include_usage trailer: same `id`/`created`/`model`/`object`, an EMPTY `choices` array,
/// and the `usage` object. Returns `None` (leaving `chunk` untouched) for any chunk that is not a
/// usage-bearing finish chunk — non-finish chunks, finish chunks without usage, or non-chunk
/// bodies (e.g. an in-band error envelope) — so the common path is a no-op. The trailing chunk's
/// identity is read off `chunk` itself (which `OpenAiStreamFraming::apply_chunk_identity` has already
/// populated with the latched id/created/model), so both frames share ONE stream identity.
fn split_openai_trailing_usage(chunk: &mut serde_json::Value) -> Option<serde_json::Value> {
    let obj = chunk.as_object_mut()?;
    if obj.get(keys::OBJECT).and_then(|v| v.as_str()) != Some(OBJ_CHUNK) {
        return None;
    }
    // A native include_usage trailer carries usage ONLY on a chunk with no active choice, so the
    // presence of a folded top-level `usage` object IS the tell: it is there because the writer put
    // it there, having no way to emit two events for one IR MessageDelta.
    //
    // The test used to be "usage AND a terminal finish_reason", on the assumption that the writer
    // folds only onto the finish chunk. It does not: it folds whenever the terminal MessageDelta
    // carries nonzero counts, and a backend that ends a stream without a stop reason — an
    // `incomplete` Responses stream whose `incomplete_details.reason` the spec does not name —
    // produces a terminal MessageDelta with `stop_reason: None`, hence `finish_reason: null`. That
    // chunk carried the whole stream's usage and neither this seam nor its opt-out twin looked at
    // it, so the usage was lost on the way to a Chat-Completions client. Keying on the fold itself
    // covers both shapes and matches what the spec actually discriminates on: usage rides its own
    // chunk, not a chunk with a choice on it.
    if !obj.contains_key(keys::USAGE) {
        return None;
    }
    let usage = obj.remove(keys::USAGE)?;
    // Build the trailing usage-only chunk mirroring the finish chunk's stream identity. `choices`
    // is an EMPTY array — the native include_usage trailer carries no choice. Fields absent on the
    // source chunk are simply omitted (kept faithful to what the stream already carries).
    let mut trailing = serde_json::Map::new();
    if let Some(id) = obj.get(keys::ID) {
        trailing.insert(keys::ID.to_string(), id.clone());
    }
    trailing.insert(
        keys::OBJECT.to_string(),
        serde_json::Value::String(OBJ_CHUNK.to_string()),
    );
    if let Some(created) = obj.get(CREATED) {
        trailing.insert(CREATED.to_string(), created.clone());
    }
    if let Some(model) = obj.get(keys::MODEL) {
        trailing.insert(keys::MODEL.to_string(), model.clone());
    }
    trailing.insert(CHOICES.to_string(), serde_json::Value::Array(Vec::new()));
    trailing.insert(keys::USAGE.to_string(), usage);
    Some(serde_json::Value::Object(trailing))
}

/// Remove a folded top-level `usage` object from a `chat.completion.chunk` in place, WITHOUT emitting
/// any replacement trailing chunk. This is the opt-OUT twin of `split_openai_trailing_usage`:
/// a client that did not send `stream_options.include_usage` must see a stream that carries NO usage at
/// all, exactly like a native OpenAI stream without include_usage. It strips on the same tell its twin
/// splits on — a folded top-level `usage` object on a `chat.completion.chunk` — because that object is
/// only ever there because the writer folded it. Requiring a terminal `finish_reason` beside it let the
/// one shape the writer folds without a stop reason through, so a client that opted OUT was sent usage
/// it had not asked for. The removed usage was only ever a client-facing echo — billing sources the
/// IR-side `last_usage` A-tap, which is captured upstream of this seam and is unaffected.
fn strip_folded_usage(chunk: &mut serde_json::Value) {
    let Some(obj) = chunk.as_object_mut() else {
        return;
    };
    if obj.get(keys::OBJECT).and_then(|v| v.as_str()) != Some(OBJ_CHUNK) {
        return;
    }
    obj.remove(keys::USAGE);
}

/// OpenAI writer implementation.
pub struct OpenAiWriter {
    /// THIS STREAM'S chunk `id`, minted ONCE and replayed on every later opening chunk.
    ///
    /// A stream is not guaranteed to carry exactly one `MessageStart`: five of the six readers gate
    /// it on their own started flag, but the Anthropic reader emits it 1:1 with the upstream frame,
    /// so an openai-egress stream fed from an Anthropic ingress can see two. Without this cell the
    /// second synthesized a FRESH `chatcmpl-` id, so one completion announced itself twice under
    /// two different ids — and the official SDKs latch `id` from the first chunk that supplies it,
    /// leaving the client correlating against an id the rest of the stream never mentions. A native
    /// OpenAI stream repeats ONE id on every chunk, so the first one wins.
    ///
    /// `Mutex` (not `Cell`) so the writer stays `Sync` as the `ProtocolWriter` trait requires; a
    /// stream is single-threaded at any instant so contention is nil, and a poisoned lock degrades
    /// to minting fresh rather than panicking on the request path.
    chunk_id: std::sync::Mutex<Option<String>>,
    /// The IR indices of THIS STREAM'S text blocks that opened as a refusal
    /// (`BlockStart{refusal: true}`, IR-02). Their text deltas are written as `delta.refusal`, not
    /// `delta.content` — the wire has no block frame to carry the flag, so the writer remembers it.
    refusal_blocks: std::sync::Mutex<std::collections::BTreeSet<usize>>,
}

/// Value-namespace constructor for [`OpenAiWriter`], mirroring the identically-shaped consts on the
/// sibling writers (`AnthropicWriter`, `CohereWriter`, `GeminiWriter`, `ResponsesWriter`): a `const`
/// and a struct may share a name, so every existing site that writes the bare `OpenAiWriter` literal
/// keeps compiling while the type now carries per-stream state. Each USE inlines a FRESH writer with
/// an empty id cell, so every `Protocol::openai()` call mints independent per-stream state — exactly
/// the per-stream scoping a stream-long identity needs. `Mutex::new`/`None` are const, so this is
/// valid in const context.
///
/// `clippy::declare_interior_mutable_const` is suppressed for the same reason it is on the siblings:
/// the per-use fresh instance is precisely the semantics required, and a `static` would share ONE id
/// cell across every stream in the process — one stream's id bleeding into another's chunks.
#[allow(non_upper_case_globals)]
#[allow(clippy::declare_interior_mutable_const)]
pub const OpenAiWriter: OpenAiWriter = OpenAiWriter {
    chunk_id: std::sync::Mutex::new(None),
    refusal_blocks: std::sync::Mutex::new(std::collections::BTreeSet::new()),
};

/// A FRESH writer as a VALUE, for the one-shot `write_request` / `write_response` calls the test
/// suites make. Every dialect with an interior-mutable writer const has one, for the same reason. Borrowing the const directly (`OpenAiWriter.write_request(…)`) is
/// `clippy::borrow_interior_mutable_const`: each borrow inlines its own copy of the interior-mutable
/// cell, which is harmless for a stateless one-shot call but wrong for a STREAM (whose identity must
/// be decided by one writer). This returns the value so the temporary is explicit, and a test that
/// drives a sequence of stream events binds one writer to a local instead of calling this per event.
#[cfg(test)]
pub(crate) fn openai_writer() -> OpenAiWriter {
    OpenAiWriter
}

impl Clone for OpenAiWriter {
    fn clone(&self) -> Self {
        // A mid-stream `Protocol::clone` is still the SAME completion, so the id it already
        // announced comes with it; a poisoned lock degrades to an empty cell rather than panicking.
        OpenAiWriter {
            chunk_id: std::sync::Mutex::new(
                self.chunk_id.lock().map(|id| id.clone()).unwrap_or(None),
            ),
            refusal_blocks: std::sync::Mutex::new(
                self.refusal_blocks
                    .lock()
                    .map(|s| s.clone())
                    .unwrap_or_default(),
            ),
        }
    }
}

impl OpenAiWriter {
    /// THE STREAM'S chunk `id`: the first one wins. Returns the id already captured for this stream
    /// if there is one, otherwise captures and returns `mint()`, so a duplicate opening chunk
    /// re-states the identity the client already latched. Lock poisoning degrades to the freshly
    /// minted id rather than panicking on the request path.
    fn carried_chunk_id(&self, mint: impl FnOnce() -> String) -> String {
        match self.chunk_id.lock() {
            Ok(mut slot) => slot.get_or_insert_with(mint).clone(),
            Err(_) => mint(),
        }
    }

    /// Remember that the text block at `index` is a refusal (IR-02).
    fn mark_refusal_block(&self, index: usize) {
        if let Ok(mut set) = self.refusal_blocks.lock() {
            set.insert(index);
        }
    }

    /// Is the text block at `index` a refusal? A poisoned lock reads as "no" (ordinary content).
    fn is_refusal_block(&self, index: usize) -> bool {
        self.refusal_blocks
            .lock()
            .map(|set| set.contains(&index))
            .unwrap_or(false)
    }
}

#[cfg(test)]
#[path = "tests/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/input_hardening_tests.rs"]
mod input_hardening_tests;

#[cfg(test)]
#[path = "tests/audio_format_regression_tests.rs"]
mod audio_format_regression_tests;

#[cfg(test)]
#[path = "tests/field_carry_tests.rs"]
mod field_carry_tests;

#[cfg(test)]
#[path = "tests/float_usage_tests.rs"]
mod float_usage_tests;

#[cfg(test)]
#[path = "tests/ir_mapping_tests.rs"]
mod ir_mapping_tests;

#[cfg(test)]
#[path = "tests/ir_slot_wiring_tests.rs"]
mod ir_slot_wiring_tests;

#[cfg(test)]
#[path = "tests/ir_round3_tests.rs"]
mod ir_round3_tests;

#[cfg(test)]
#[path = "tests/usage_census_tests.rs"]
mod usage_census_tests;

#[cfg(test)]
#[path = "tests/df_map_audit_tests.rs"]
mod df_map_audit_tests;

/// A Chat completion's `moderation.{input,output}` results -> the IR's safety verdicts (DF-MAP item
/// 1): one verdict per category a result flags (`categories.<name> = true`), `blocked` = false (a
/// moderation result reports, it does not block). Scores do not cross. An `error` arm yields none.
fn read_moderation(
    moderation: Option<&serde_json::Value>,
) -> Vec<crate::codec::ir::IrSafetyVerdict> {
    let mut out = Vec::new();
    for side in [MODERATION_INPUT, MODERATION_OUTPUT] {
        let results = moderation
            .and_then(|m| m.get(side))
            .and_then(|s| s.get(MODERATION_RESULTS))
            .and_then(|r| r.as_array());
        for r in results.into_iter().flatten() {
            let categories = r.get(CATEGORIES).and_then(|c| c.as_object());
            for (category, on) in categories.into_iter().flatten() {
                if on.as_bool() == Some(true) {
                    out.push(crate::codec::ir::IrSafetyVerdict {
                        category: category.clone(),
                        flagged: true,
                        blocked: false,
                    });
                }
            }
        }
    }
    out
}

const MODERATION_INPUT: &str = "input";
const MODERATION_OUTPUT: &str = "output";
const MODERATION_RESULTS: &str = "results";

/// A Chat `message.audio` -> the IR's audio output (DF-MAP item 3): its base64 `data` and its
/// `transcript`. The audio `id` and `expires_at` are OpenAI's own handle and do not cross.
fn read_message_audio(
    audio: Option<&serde_json::Value>,
) -> Option<crate::codec::ir::IrAudioOutput> {
    let audio = audio?.as_object()?;
    let text = |k: &str| audio.get(k).and_then(|v| v.as_str()).map(String::from);
    let out = crate::codec::ir::IrAudioOutput {
        data: text(keys::DATA),
        format: None,
        transcript: text(TRANSCRIPT),
    };
    (out.data.is_some() || out.transcript.is_some()).then_some(out)
}

/// The spoken text of a Chat `message.audio`.
const TRANSCRIPT: &str = "transcript";
