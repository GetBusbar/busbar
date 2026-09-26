// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The Anthropic (Messages API) dialect — one module of the `busbar-llm` protocol crate.
//!
//! THE FIRST EXTRACTED PROTOCOL, and the control experiment for the plugin seam
//! (`design/1.6.0-llm-extraction-plan.md`): the five files here are exactly the per-dialect
//! template `one-core-mcp-a2a-as-protocols.md` bars — this file (the declaration), `reader.rs`
//! (wire → IR), `writer.rs` (IR → wire), `handler.rs` (which operations it serves), and `tests/`
//! (its own tests, nobody else's). Everything it consumes from the engine comes through
//! `busbar-core`'s public surface; nothing in `busbar-core` names this crate
//! (`git grep busbar_proto crates/busbar-core/src` is pinned at zero) — the `busbar` BINARY, the
//! composition root, links it and hands [`DECL`] to
//! core's `proto::registry::install_protocols` at boot. Delete the dependency edge and
//! busbar still builds, boots, refuses `protocol: anthropic` config with the unknown-protocol
//! refusal, and serves the remaining dialects — that build is a gate, not a thought experiment.
//!
//! DUAL COMPILATION, stated so the `#[path]` in core is not read as a leak: `busbar-core`'s
//! test/`test-support` builds compile these same sources back in as `proto::anthropic` (via
//! `extern crate self as busbar_kernel`), so the pre-extraction test fixture surface — hundreds of
//! `Protocol::anthropic()` fixtures and `protocol: anthropic` configs across the core suite —
//! keeps proving what it always proved without core's PRODUCTION build knowing this dialect
//! exists. That is why every core reference in these files is spelled with core's crate name and every
//! self reference is relative.

pub mod handler;
mod reader;
mod writer;

mod auth;
mod blocks;
mod citations;
mod ids;
mod slots;
mod usage;
pub use auth::anthropic_auth_headers;
#[cfg(test)]
use auth::AnthropicCredScheme;
use blocks::*;
use citations::*;
use ids::*;
pub use ids::{request_id_from_entropy, synth_anthropic_request_id};
use slots::*;
use usage::*;

use crate::ir::{IrBlockMeta, IrDelta, IrStreamEvent, IrUsage};
use busbar_contract::http::{header::HeaderValue, HeaderName, StatusCode};
use busbar_contract::protocol::*;
#[cfg(test)]
use busbar_contract::upstream::CanonicalSignal;
use busbar_contract::upstream::StatusClass;
// G6 A4b: the wire-codec surface (ProtocolReader/Writer/Protocol/StreamFraming/ToolIdRemap/
// protocol_for) relocated to this plugin's `proto_codec`; reach it RELATIVELY so it resolves both
// standalone (crate::proto_codec) and netted into core (core::proto::proto_codec).
#[allow(unused_imports)]
// used standalone; redundant with the `busbar_contract::protocol::*` glob when netted into core
use super::proto_codec::*;
// The wire-codec surface, named EXPLICITLY so it resolves to THIS crate's own `proto_codec` and not to
// the `busbar_contract::protocol::*` glob above — which, in a `test-support` build of busbar-core (this
// crate's dev-dependency), re-exports a SECOND copy of these same source items through core's `#[path]`
// dual-compile, and a bare use of either name would then be ambiguous. An explicit import outranks both
// globs; when this file is netted INTO core the two paths are one item, so the explicit is harmless.
#[allow(unused_imports)]
use super::proto_codec::{Protocol, ProtocolReader, ProtocolWriter, StreamFraming};

/// Build this dialect's wire codec — the [`ProtocolDecl::codec`] constructor. A fresh instance per
/// resolution, exactly as the registry's field doc requires.
pub fn protocol() -> Protocol {
    Protocol::new("anthropic", AnthropicReader, AnthropicWriter)
}

/// The [`ProtocolDecl::egress_auth_headers`] builder: Anthropic's native credential shaping,
/// including the `Own | Passthrough` disambiguation of an ambiguous key. Thin declared-data
/// wrapper over [`anthropic_auth_headers`], which the hardening tests drive directly.
fn egress_auth_headers(key: &str, ctx: &SigningContext) -> Vec<(HeaderName, HeaderValue)> {
    anthropic_auth_headers(key, Some(ctx.upstream_creds))
}

/// A native Anthropic stream emits `event: ping` immediately after `message_start` (and
/// periodically thereafter); a translated cross-protocol stream never did, which is both a
/// fingerprintable proxy tell and closes some of the idle-timeout gap a native stream survives.
/// Injected once, right after the translated `message_start` frame, on any INGRESS-Anthropic
/// cross-protocol stream (same-protocol Anthropic passthrough is byte-verbatim and already carries
/// the upstream's own pings, so it never needs this). Lives HERE — this dialect's writer is its
/// only reader — where it used to sit in `proto/mod.rs` as a leaked per-dialect constant.
const ANTHROPIC_PING_SSE_FRAME: &[u8] = b"event: ping\ndata: {\"type\":\"ping\"}\n\n";

/// The [`ProtocolDecl::models_list_envelope`] builder: Anthropic's `GET /v1/models` shape. Each
/// name becomes an Anthropic `model` object, wrapped in the paginated `{ "data": [...], "has_more":
/// false, "first_id": ..., "last_id": ... }` envelope their SDK expects (a single, complete page).
fn models_list_envelope(names: &[&str]) -> serde_json::Value {
    let data: Vec<serde_json::Value> = names
        .iter()
        .map(|id| {
            serde_json::json!({
                "type": "model",
                "id": id,
                "display_name": id,
                "created_at": "1970-01-01T00:00:00Z"
            })
        })
        .collect();
    serde_json::json!({
        "data": data,
        "has_more": false,
        "first_id": names.first(),
        "last_id": names.last(),
    })
}

/// ANTHROPIC'S DECLARATION — everything core knows about this protocol, stated here rather than
/// discovered by a `match` in core. Handed to `install_protocols` by the composition root (the
/// `busbar` binary); in `busbar-core`'s test/`test-support` builds it is instead the cfg-gated
/// built-in row, so the fixture registry the tests see matches the registry a shipped binary has.
/// ANTHROPIC'S ROUTER DETECTION — its rungs of the old core `protocol_id` ladder: the mandatory
/// `anthropic-version`/`anthropic-beta` headers (rung 2), the `x-api-key` credential header that is
/// Anthropic's alone among the six (rung 4, catching curl users who omit the version header), then
/// the `/v1/messages` path (rung 11). Lower strength binds tighter — the shared ladder positions.
fn claims(
    h: &busbar_contract::http::HeaderMap,
    path: &str,
) -> Option<busbar_contract::protocol::ClaimStrength> {
    use busbar_contract::protocol::ClaimStrength;
    if h.contains_key("anthropic-version") || h.contains_key("anthropic-beta") {
        return Some(ClaimStrength(2));
    }
    if h.contains_key("x-api-key") {
        return Some(ClaimStrength(4));
    }
    if path.contains("/v1/messages") {
        return Some(ClaimStrength(11));
    }
    None
}

/// ANTHROPIC'S RESIDUAL DETECTION — its arm of the headerless `residual_dialect_for_path` ladder: a
/// `/v1/messages` path (exact or model-prefixed) names Anthropic (rung 40).
fn residual_claims(path: &str) -> Option<busbar_contract::protocol::ClaimStrength> {
    if path == "/v1/messages" || path.ends_with("/v1/messages") {
        return Some(busbar_contract::protocol::ClaimStrength(40));
    }
    None
}

pub const DECL: ProtocolDecl = ProtocolDecl {
    name: "anthropic",
    codec: {
        // The dialect's neutral codec facade as a STATIC, so the decl hands out a `&'static dyn`
        // borrow (pure memory, zero alloc per `dialect()` call) — the seam's perf contract.
        static CODEC: super::proto_codec::DialectRef = super::proto_codec::dialect_ref("anthropic");
        Some(&CODEC)
    },
    handler: Some(&handler::AnthropicRequestHandler),
    verbs: &[busbar_contract::operation::OpVerb::CHAT],
    head_keys: super::proto_codec::LLM_CHAT_HEAD_KEYS,
    streaming_content_type: Some(busbar_contract::protocol::TEXT_EVENT_STREAM),
    array_stream_shim_key: None,
    // `toolu_…` is Anthropic's documented native tool-call id shape.
    native_tool_id_prefix: Some("toolu_"),
    ingress_auth: IngressAuth::Bearer,
    // Anthropic's api-key (`sk-ant-api…` → `x-api-key`) vs Bearer (`sk-ant-oat…` → Authorization)
    // disambiguation is THIS dialect's scheme, so the builder is declared here — the field that
    // retired the `"anthropic"` arm in core's `egress_auth::resolve`.
    egress_auth_headers: Some(egress_auth_headers),
    egress_auth_lane_constant: true,
    egress_scheme: None,
    stream_usage_requires_opt_in: false,
    // ── Promoted writer facts (G6 step A1): the same constants the `AnthropicWriter` methods returned.
    requires_max_tokens: true,
    stop_sequence_cap: None,
    cache_markers_model_gated: false,
    fills_thought_signature: false,
    frame_after_message_start: Some(ANTHROPIC_PING_SSE_FRAME),
    reshapes_body_at_path_base: true,
    max_cache_control_breakpoints: Some(4),
    quota_exceeded_status: busbar_contract::http::StatusCode::TOO_MANY_REQUESTS,
    ingress_is_eventstream: false,
    emits_sse_done_terminator: false,
    max_citations_per_delta: Some(1),
    // The plausible native-SDK UA for THIS dialect's egress (a backend-facing fingerprint guard). The
    // Anthropic Python SDK is Stainless-generated and emits `<Title>/Python <ver>`. RELEASE
    // OBLIGATION: re-verify each version against the latest published SDK before a release and bump
    // (the `test_egress_ua_versions_are_pinned_and_present` guard forces the change to be conscious).
    egress_user_agent: "Anthropic/Python 0.39.0",
    has_model_in_url: false,
    auth_failure_status_and_kind: (
        busbar_contract::http::StatusCode::UNAUTHORIZED,
        busbar_contract::protocol::ERR_TYPE_AUTHENTICATION,
    ),
    ingress_relays_amzn_headers: false,
    ingress_relayed_response_header_names: &[HDR_REQUEST_ID],
    auth_failure_message: "invalid x-api-key",
    uses_array_stream_shim: false,
    has_native_path_not_found: false,
    egress_stream_accept: busbar_contract::protocol::TEXT_EVENT_STREAM,
    models_list_envelope: Some(models_list_envelope),
    claims: Some(claims),
    residual_claims: Some(residual_claims),
    residual_default: false,
    vendor_response_metadata: None,
    // The Anthropic SDK always sends `anthropic-version`; its presence disambiguates the shared
    // list-models surface as Anthropic. NARROWER than `claims` on purpose (no `x-api-key`/path).
    list_models_fingerprint_headers: &["anthropic-version"],
};

/// Value of the required `anthropic-version` request header (the Messages API version busbar
/// targets). Bump when adopting a newer Anthropic API version.
const ANTHROPIC_API_VERSION: &str = "2023-06-01";

/// Mixed-case base62 alphabet (`[0-9A-Za-z]`), UPPERCASE-FIRST, matching the character set/ordering of
/// a native Anthropic id token. A native `msg_`/`req_` id is `01` followed by a fixed-length mixed-case
/// alphanumeric token — NOT lowercase hex — so encoding the synthesized suffix in this alphabet (rather
/// than bare `{:x}`) removes the alphabet/length/version-prefix distinguishability tell. DISTINCT from
/// the shared `crate::dialect::BASE62_ALPHABET` (lowercase-first): named `ANTHROPIC_NATIVE_ALPHABET` so
/// the two can never be confused — `synth_id_with_prefix` (body ids) needs THIS uppercase-first
/// ordering, while `synth_anthropic_request_id` (response-header id) deliberately uses the shared one.
const ANTHROPIC_NATIVE_ALPHABET: &[u8; 62] =
    b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// The response-header name a native Anthropic endpoint always carries (the SDK reads it into
/// `APIError.request_id` / `Message._request_id`). Defined here (the Anthropic dialect's home) and
/// used within this module; surfaced externally only via the writer vtable
/// (`AnthropicWriter::ingress_response_request_id` / `ingress_relayed_response_header_names`), so
/// the sites that attach it (proxy engine success path) and capture it from upstream cannot drift on
/// spelling.
const HDR_REQUEST_ID: &str = "request-id";

/// Width of a synthesized Anthropic id's token (the part after the `01` version marker): a native
/// `msg_`/`req_` id is `<prefix>01` followed by a fixed-width 24-char mixed-case base62 token, so
/// `msg_`/`req_` + `01` + 24 = 30 chars total. Matching this exact length AND alphabet is what keeps
/// the synthesized id structurally indistinguishable from a native one.
const SYNTH_ID_TOKEN_LEN: usize = 24;

/// SSE event-type strings emitted in the `event:` header of each native Anthropic stream frame.
const EVT_MESSAGE_START: &str = "message_start";
const EVT_CONTENT_BLOCK_START: &str = "content_block_start";
const EVT_CONTENT_BLOCK_DELTA: &str = "content_block_delta";
const EVT_CONTENT_BLOCK_STOP: &str = "content_block_stop";
const EVT_MESSAGE_DELTA: &str = "message_delta";
const EVT_MESSAGE_STOP: &str = "message_stop";

/// `content_block_delta` sub-type values (`delta.type` field).
const DELTA_TYPE_TEXT: &str = "text_delta";
const DELTA_TYPE_THINKING: &str = "thinking_delta";
const DELTA_TYPE_INPUT_JSON: &str = "input_json_delta";
const DELTA_TYPE_SIGNATURE: &str = "signature_delta";
const DELTA_TYPE_CITATIONS: &str = "citations_delta";

/// Native Anthropic `stop_reason` token values.
const STOP_END_TURN: &str = "end_turn";
const STOP_MAX_TOKENS: &str = "max_tokens";
const STOP_STOP_SEQUENCE: &str = "stop_sequence";
const STOP_TOOL_USE: &str = "tool_use";
const STOP_PAUSE_TURN: &str = "pause_turn";
const STOP_REFUSAL: &str = "refusal";

/// `stop_reason` an Anthropic model reports when generation stopped because the CONTEXT WINDOW (not
/// the caller's `max_tokens`) ran out (Claude 4.5+). The reader maps it to the coarse
/// [`crate::ir::IrStopReason::MaxTokens`] — the same "output was cut off by a length limit" signal
/// every other dialect names (`length`, `MAX_TOKENS`, `incomplete/max_output_tokens`) — instead of
/// `Other`, which every writer renders as a NATURAL stop and so told a foreign client a truncated
/// answer was complete; and it sets the IR-16 refinement
/// [`crate::ir::IrStopDetail::ContextWindowExceeded`] beside it, which this writer (and Bedrock's)
/// renders back as this exact token (ANT-11).
const STOP_MODEL_CONTEXT_WINDOW_EXCEEDED: &str = "model_context_window_exceeded";

/// Native structured outputs: `output_config.format.type`. Anthropic's Messages API constrains the
/// ANSWER to a JSON schema with `output_config: {format: {type: "json_schema", schema: {...}}}` (the
/// deprecated beta spelling is the top-level `output_format` of the same shape). This is the native
/// slot a cross-protocol `response_format` projects into (ANT-06 read / ANT-07 write).
const OUTPUT_FORMAT_JSON_SCHEMA: &str = "json_schema";

/// Anthropic `thinking.type` for ADAPTIVE thinking (the model decides how much to think), the only
/// on-mode Opus 4.7+/5.x, Sonnet 5 and Fable accept — `{type:"enabled",budget_tokens}` 400s there.
const THINKING_TYPE_ADAPTIVE: &str = "adaptive";

/// Anthropic `thinking.type` that switches reasoning OFF — the IR's [`crate::ir::IrReasoningAsk::Off`]
/// (IR-09, ANT-09).
const THINKING_TYPE_DISABLED: &str = "disabled";

/// Anthropic tool `type` for an ordinary client (function) tool. Absent `type` means the same thing.
/// Any OTHER `type` is an Anthropic-defined SERVER / client-executed tool (`web_search_*`, `bash_*`,
/// `text_editor_*`, `code_execution_*`, `computer_*`, `memory_*`, `mcp_toolset`, …) whose schema is
/// Anthropic's, not the caller's.
const TOOL_TYPE_CUSTOM: &str = "custom";

/// Used only on a lane WITHOUT native structured outputs (`LaneCaps::native_structured_output`
/// false — the pre-capability default); a native lane writes `output_config.format` instead.
/// Synthetic tool NAME used to translate a cross-protocol `response_format` (structured-output /
/// JSON-schema) directive into Anthropic tool-forcing. Anthropic's Messages API has NO native
/// `response_format` field; the idiomatic way to obtain schema-constrained JSON from a Claude model
/// is to synthesize a single tool whose `input_schema` IS the requested JSON schema and pin
/// `tool_choice` to it (see the Anthropic WRITER). The Anthropic RESPONSE reader recognizes this
/// name and maps the forced `tool_use` back to a plain assistant text block carrying the JSON, so a
/// caller that asked for `response_format` (not a tool) receives structured content and never sees
/// the synthetic tool. Busbar-namespaced to avoid colliding with a caller's own tool, and valid
/// under Anthropic's `^[a-zA-Z0-9_-]{1,64}$` tool-name constraint.
const RESPONSE_FORMAT_TOOL_NAME: &str = "busbar_response_format";

/// Anthropic content block `type` values not covered by the delta sub-type constants above.
const BLOCK_TYPE_REDACTED_THINKING: &str = "redacted_thinking";

/// `extra` key parking the RAW native content blocks the IR cannot model (e.g. `document`), by
/// their position in `req.messages` (system-role messages excluded — they never reach this array
/// on either side, see `read_request`/`write_request`). Each entry is `{"m": <message index>,
/// "i": <block index>, "block": <raw block JSON>}`. `read_block`'s degrade-to-empty-Text arm holds
/// the block's SHAPE in the turn (so message/tool-call ordering survives even cross-protocol,
/// where this sentinel is cleared along with the rest of `extra`); this sentinel additionally lets
/// an Anthropic-to-Anthropic hop that goes through the IR (not a byte-verbatim same-protocol
/// passthrough) splice the ORIGINAL block back in place of the placeholder, so the block survives
/// its own protocol's round-trip instead of being destroyed.
const ANTHROPIC_UNMODELED_BLOCKS_SENTINEL: &str = "__busbar_anthropic_unmodeled_blocks";

/// The native Anthropic content-block `type` values [`read_block`] models. Anything else degrades
/// to an empty Text placeholder there; used here to find which raw blocks need parking under
/// [`ANTHROPIC_UNMODELED_BLOCKS_SENTINEL`] without duplicating `read_block`'s parse logic.
fn is_modeled_anthropic_block_type(t: &str) -> bool {
    matches!(
        t,
        "text"
            | "thinking"
            | STOP_TOOL_USE
            | "tool_result"
            | "image"
            | BLOCK_TYPE_DOCUMENT
            | BLOCK_TYPE_REDACTED_THINKING
    )
}

/// The content-block `type` values the STREAM reader translates (a `content_block_start` of any
/// other type is suppressed together with its deltas and stop — see `read_response_events`).
fn is_streamed_anthropic_block_type(t: &str) -> bool {
    matches!(
        t,
        "text" | "thinking" | STOP_TOOL_USE | "image" | BLOCK_TYPE_REDACTED_THINKING
    )
}

/// The `vendor` tag on an [`crate::ir::IrImageSource::Vendor`] this protocol produces — an Anthropic
/// Files-API `{"type":"file","file_id":…}` document source, or a `{"type":"content"}` document whose
/// body is a block array. Neither has a neutral (base64/url) form, so only this protocol's writer
/// re-emits it; any other writer drops it with a warn.
const VENDOR_NAME: &str = "anthropic";

/// Native Anthropic `document` content block type — a PDF/text attachment the model reads.
const BLOCK_TYPE_DOCUMENT: &str = "document";

/// The one mime an Anthropic `text` document source carries.
const DOCUMENT_MIME_TEXT_PLAIN: &str = "text/plain";

/// The one mime an Anthropic `base64` document source accepts.
const DOCUMENT_MIME_PDF: &str = "application/pdf";

/// Anthropic's `document.source` for inline bytes, by mime: a PDF rides the `base64` source; any
/// `text/*` document rides the `text` source as DECODED text (`media_type: "text/plain"`), since the
/// IR carries it base64 (see the reader's `text` arm). `None` for a mime Anthropic has no inline
/// document source for (a CSV-as-octet-stream, an image posing as a file, …) or for `text/*` bytes
/// that are not UTF-8 — the caller drops that block with a warn rather than ship a certain 400 or a
/// corrupt document (ANT-02).
fn inline_document_source(media_type: &str, data: &str) -> Option<serde_json::Value> {
    if media_type.eq_ignore_ascii_case(DOCUMENT_MIME_PDF) {
        return Some(serde_json::json!({
            "type": "base64",
            "media_type": DOCUMENT_MIME_PDF,
            "data": data,
        }));
    }
    let is_text = media_type
        .split('/')
        .next()
        .is_some_and(|top| top.eq_ignore_ascii_case("text"));
    if is_text {
        let bytes = busbar_contract::media::base64_decode(data)?;
        let text = String::from_utf8(bytes.to_vec()).ok()?;
        return Some(serde_json::json!({
            "type": "text",
            "media_type": DOCUMENT_MIME_TEXT_PLAIN,
            "data": text,
        }));
    }
    None
}

/// Native Anthropic `search_result` content block type — a retrieved RAG passage (source, title and
/// a text `content[]`) the caller supplies for the model to answer from and cite. Read into a
/// `Text` block carrying an [`crate::ir::IrCitation`]; see the arm in [`read_block`] for why it is
/// deliberately NOT in [`is_modeled_anthropic_block_type`].
const BLOCK_TYPE_SEARCH_RESULT: &str = "search_result";

/// Scan a message's RAW `content` array (as read from the wire, BEFORE `read_block` parses it) for
/// unmodeled blocks, pushing `{"m","i","block"}` sentinel entries for each. `read_block` parses
/// every raw block 1:1 with no filtering, so a raw-array index always matches the parsed
/// `IrMessage.content` index at the same position — no separate index bookkeeping needed.
fn stash_unmodeled_blocks(
    msg_val: &serde_json::Value,
    m: usize,
    sink: &mut Vec<serde_json::Value>,
) {
    let Some(content_arr) = msg_val.get("content").and_then(|c| c.as_array()) else {
        return;
    };
    for (i, block_val) in content_arr.iter().enumerate() {
        let block_type = block_val.get("type").and_then(|v| v.as_str()).unwrap_or("");
        // A `document` is MODELLED (`IrBlock::Media`) so it survives a cross-protocol hop, but Media
        // carries only source/name/cache_control — NOT Anthropic's `document.context` string or its
        // `document.citations` toggle. Those two have no neutral/cross-protocol slot, so to keep them
        // 100% lossless SAME-protocol we ALSO park the original document verbatim here WHEN it carries
        // one of them; `write_message` then splices the raw block back on an Anthropic→Anthropic hop
        // (extra survives), preserving context/citations byte-exact, while a cross-protocol egress
        // (extra cleared at the seam) falls back to the Media projection and drops them. A document
        // WITHOUT context/citations is NOT parked (Media round-trips it losslessly), so the common
        // case keeps the modelled-not-stashed contract its round-trip test pins.
        let document_needs_stash = block_type == BLOCK_TYPE_DOCUMENT
            && (block_val.get("context").is_some() || block_val.get("citations").is_some());
        if !is_modeled_anthropic_block_type(block_type) || document_needs_stash {
            sink.push(serde_json::json!({ "m": m, "i": i, "block": block_val }));
        }
    }
}

/// Look up a stashed raw block for position `(m, i)` in the sentinel array (as read back out of
/// `req.extra`), for [`write_message`] to splice in place of the empty-Text placeholder.
fn find_stashed_block(
    sentinel: &[serde_json::Value],
    m: usize,
    i: usize,
) -> Option<serde_json::Value> {
    sentinel.iter().find_map(|entry| {
        let em = entry.get("m")?.as_u64()? as usize;
        let ei = entry.get("i")?.as_u64()? as usize;
        (em == m && ei == i)
            .then(|| entry.get("block").cloned())
            .flatten()
    })
}

/// Anthropic error `type` strings used in error envelopes and in-stream error events. Values
/// shared with the forward/OpenAI-family vocabulary alias their canonical home in
/// `openai_family.rs`; only `timeout_error` is an Anthropic-specific spelling (the forward layer's
/// agnostic kind is the bare `timeout`).
const ERR_TYPE_OVERLOADED: &str = busbar_contract::protocol::ERR_TYPE_OVERLOADED;
const ERR_TYPE_INVALID_REQUEST: &str = busbar_contract::protocol::ERR_TYPE_INVALID_REQUEST;
const ERR_TYPE_AUTHENTICATION: &str = busbar_contract::protocol::ERR_TYPE_AUTHENTICATION;
const ERR_TYPE_RATE_LIMIT: &str = busbar_contract::protocol::ERR_TYPE_RATE_LIMIT;
const ERR_TYPE_API_ERROR: &str = busbar_contract::protocol::ERR_TYPE_API_ERROR;
const ERR_TYPE_TIMEOUT: &str = "timeout_error";
/// The billing member of the published Anthropic `ErrorResponse.error` discriminator — the type a
/// native client sees when the account cannot pay for the request. It has no cross-dialect alias in
/// the substrate vocabulary (OpenAI names the same condition `insufficient_quota`), so it is spelled
/// here, beside the other Anthropic-only type token.
const ERR_TYPE_BILLING: &str = "billing_error";
const ERR_TYPE_NOT_FOUND: &str = busbar_contract::protocol::ERR_TYPE_NOT_FOUND;
const ERR_TYPE_PERMISSION: &str = busbar_contract::protocol::ERR_TYPE_PERMISSION;
const ERR_TYPE_REQUEST_TOO_LARGE: &str = busbar_contract::protocol::ERR_TYPE_REQUEST_TOO_LARGE;

/// Anthropic citation `type` tag values (the `type` field on each citation object).
const CITATION_TYPE_CHAR: &str = "char_location";
const CITATION_TYPE_PAGE: &str = "page_location";
const CITATION_TYPE_CONTENT_BLOCK: &str = "content_block_location";
const CITATION_TYPE_WEB_SEARCH: &str = "web_search_result_location";
const CITATION_TYPE_SEARCH_RESULT: &str = "search_result_location";

/// The sole valid `cache_control.type` Anthropic exposes today.
const CACHE_KIND_EPHEMERAL: &str = "ephemeral";

/// Header names used when attaching Anthropic credentials to upstream requests.
const HDR_X_API_KEY: &str = "x-api-key";
const HDR_ANTHROPIC_VERSION: &str = "anthropic-version";

/// Credential prefix strings used to classify a raw key into its native Anthropic scheme.
const CRED_PREFIX_API_KEY: &str = "sk-ant-api";
const CRED_PREFIX_OAUTH: &str = "sk-ant-oat";

/// The upstream path this writer targets on the Anthropic Messages API.
const PATH_UPSTREAM: &str = "/v1/messages";

/// HTTP status codes that Anthropic (and cross-protocol upstreams) use to signal overload.
const STATUS_OVERLOADED: u16 = 503;
const STATUS_ANTHROPIC_OVERLOADED: u16 = 529;

/// Upper bound on an upstream-supplied streaming content-block index. Anthropic's Messages API
/// numbers blocks densely from 0; a real response has a small handful, never a sparse pathological
/// index. An upstream-controlled `index` flows into the IR (`BlockStart`/`BlockDelta`/`BlockStop`)
/// and then into a downstream WRITER that allocates/serializes against it (e.g. `GeminiWriter`'s
/// `open_tools` set, the Bedrock `contentBlockIndex` field), so a hostile/buggy backend sending a
/// huge `index` (up to `u64::MAX`) could drive a pathological allocation/serialization. CLAMP every
/// read site to this bound before the value enters the IR, mirroring the Bedrock reader's
/// `MAX_CONTENT_BLOCK_INDEX` (same 1023 cap), the OpenAI reader's `MAX_TOOL_INDEX`, and the Cohere
/// reader's `MAX_TOOL_FRAME_INDEX`. 1023 is far above any legitimate block count yet bounds the
/// downstream allocation. Cross-protocol sibling of those clamps.
const MAX_ANTHROPIC_BLOCK_INDEX: u64 = 1023;

/// Read a streaming event's `index`, requiring it to be present and numeric (returns `None` to drop
/// the event otherwise, matching the prior `.as_u64()?` semantics), and CLAMP it to
/// `MAX_ANTHROPIC_BLOCK_INDEX` before narrowing to `usize`. Shared by the three `content_block_*`
/// read sites so the bound can never drift between them. Mirrors `bedrock::clamp_content_block_index`
/// (that reader defaults a missing index to 0; the Anthropic stream instead drops an event with no
/// index, preserving this protocol's stricter `?`-on-missing behavior — the clamp is the additive
/// hardening, the presence requirement is unchanged).
fn read_clamped_block_index(data: &serde_json::Value) -> Option<usize> {
    data.get("index")
        .and_then(|i| i.as_u64())
        .map(|v| v.min(MAX_ANTHROPIC_BLOCK_INDEX) as usize)
}

/// Clamp a temperature to Anthropic's native `[0.0, 1.0]` range, returning `(clamped, was_clamped)`
/// where `was_clamped` is `true` iff the clamp ACTUALLY changed the value. OpenAI / Responses
/// accept temperature up to 2.0, so a cross-protocol request
/// can carry a value Anthropic's API rejects with a 422; the writer forwards the closest valid value
/// instead of bouncing a 422, and uses `was_clamped` to emit a `warn!` so the mutation is NOT silent.
/// Factored out so the non-silent-on-change contract is unit-testable without a tracing subscriber.
fn clamp_temperature_for_anthropic(temperature: f64) -> (f64, bool) {
    // Guard against non-finite input (NaN/±Inf): `f64::clamp` panics on a NaN bound but not a NaN
    // value, yet a NaN/Inf temperature is not a "real value clamped from range" — return it unchanged
    // with was_clamped=false so the helper is total. This is confirmed unreachable via valid JSON
    // (sonic_rs rejects NaN/Inf at parse), so it is a defensive no-op, not a behavior change.
    if !temperature.is_finite() {
        return (temperature, false);
    }
    let clamped = temperature.clamp(0.0, 1.0);
    (clamped, clamped != temperature)
}

#[derive(Clone)]
pub struct AnthropicReader;

/// Map an Anthropic streaming `error.type` token to its breaker `StatusClass`, mirroring the HTTP
/// classifier intent (`AnthropicReader::classify`) and the `write_error` error vocabulary so a
/// mid-stream error drives the SAME breaker transition an equivalent non-stream HTTP error would.
///
/// Native Anthropic error types and their canonical class (see the Anthropic Messages API error
/// shape — `overloaded_error` is the 529 overload signal, `rate_limit_error` the 429):
///   - `overloaded_error`      → Overloaded   (transient — upstream is shedding load)
///   - `rate_limit_error`      → RateLimit    (transient — back off / retry-after)
///   - `api_error`             → ServerError  (transient — upstream 5xx-family fault)
///   - `timeout_error`         → Timeout      (transient — upstream timed out)
///   - `authentication_error`  → Auth         (hard down — credential invalid)
///   - `permission_error`      → Auth         (hard down — 403-family, key lacks access)
///   - `billing_error`         → Billing      (hard down — account/balance issue)
///   - `invalid_request_error` → ClientError  (caller fault — do NOT penalize the lane)
///   - `not_found_error`       → ClientError
///   - `request_too_large`     → ClientError
///
/// An ABSENT type (`None`) or an unrecognized token falls back to `ClientError`: it is the
/// conservative non-penalizing disposition (ClientFault records nothing), so an unknown mid-stream
/// error can never wrongly trip or hard-down a healthy lane. The fallback is a NAMED arm, not a
/// `_ =>` swallow, so a future Anthropic error type surfaces as an explicit unmapped case here.
fn stream_error_class(error_type: Option<&str>) -> StatusClass {
    match error_type {
        Some(ERR_TYPE_OVERLOADED) => StatusClass::Overloaded,
        Some(ERR_TYPE_RATE_LIMIT) => StatusClass::RateLimit,
        Some(ERR_TYPE_API_ERROR) => StatusClass::ServerError,
        Some(ERR_TYPE_TIMEOUT) => StatusClass::Timeout,
        Some(ERR_TYPE_AUTHENTICATION) | Some(ERR_TYPE_PERMISSION) => StatusClass::Auth,
        Some("billing_error") => StatusClass::Billing,
        Some(ERR_TYPE_INVALID_REQUEST)
        | Some(ERR_TYPE_NOT_FOUND)
        | Some(ERR_TYPE_REQUEST_TOO_LARGE)
        | None => StatusClass::ClientError,
        Some(_unrecognized) => StatusClass::ClientError,
    }
}

/// The nine tokens `ErrorResponse.error` is discriminated on. A value outside this set is not a
/// valid error object, so it can never be written to `error.type` — however plausible it looks.
const ANTHROPIC_ERROR_TYPES: [&str; 9] = [
    ERR_TYPE_INVALID_REQUEST,
    ERR_TYPE_AUTHENTICATION,
    "billing_error",
    ERR_TYPE_PERMISSION,
    ERR_TYPE_NOT_FOUND,
    ERR_TYPE_RATE_LIMIT,
    ERR_TYPE_TIMEOUT,
    ERR_TYPE_OVERLOADED,
    ERR_TYPE_API_ERROR,
];

/// Choose the `error.type` token for an outgoing error — the inverse of [`stream_error_class`].
///
/// A signal that is ALREADY one of the nine is kept verbatim, so a token read off a native upstream
/// stream round-trips exactly (`permission_error` does not come back as `authentication_error`,
/// though both read as `Auth`). Anything else is free text — an upstream sentence, a foreign
/// dialect's code — and cannot go in a discriminator field, so the class supplies the token and the
/// text is carried as `message` instead, which is where prose belongs.
///
/// `Auth` and `ClientError` are many-to-one in the forward map, so the inverse picks the general
/// member of each (`authentication_error`, `invalid_request_error`). `Network` has no Anthropic
/// token at all and takes the `api_error` catch-all, as does an absent signal: `null` is not a
/// member of the set, and an SDK dispatching on the type gets no arm for it.
fn stream_error_type(err: &IrError) -> &'static str {
    if let Some(signal) = err.provider_signal.as_deref() {
        if let Some(known) = ANTHROPIC_ERROR_TYPES.iter().find(|t| **t == signal) {
            return known;
        }
    }
    match err.class {
        StatusClass::Overloaded => ERR_TYPE_OVERLOADED,
        StatusClass::RateLimit => ERR_TYPE_RATE_LIMIT,
        StatusClass::Timeout => ERR_TYPE_TIMEOUT,
        StatusClass::Auth => ERR_TYPE_AUTHENTICATION,
        StatusClass::Billing => "billing_error",
        StatusClass::ClientError | StatusClass::ContextLength => ERR_TYPE_INVALID_REQUEST,
        StatusClass::ServerError | StatusClass::Network => ERR_TYPE_API_ERROR,
    }
}

/// Write one RESPONSE content block: [`write_block`] plus the members the published response block
/// schemas require that a request block does not carry. `write_block` is shared with the request
/// writer, and a request block must not grow response-only keys, so the response-only members are
/// added here:
///
/// * `text` — `citations`, `null` when the block carries none (the spec's nullable default);
/// * `tool_use` — `caller`, `{"type":"direct"}` (the spec's default; the IR carries no caller);
/// * `thinking` — `signature`, `""` when the source carried none (the spec types it as a plain
///   string, matching the `""` seed the `content_block_start` writer already emits).
///
/// A value the source reported is left untouched.
fn write_response_block(block: &crate::ir::IrBlock) -> serde_json::Value {
    let mut val = write_block(block);
    if let Some(obj) = val.as_object_mut() {
        match obj.get("type").and_then(|t| t.as_str()) {
            Some("text") => {
                obj.entry("citations").or_insert(serde_json::Value::Null);
            }
            Some(STOP_TOOL_USE) => {
                obj.entry("caller")
                    .or_insert_with(|| serde_json::json!({ "type": "direct" }));
            }
            Some("thinking") => {
                obj.entry("signature")
                    .or_insert_with(|| serde_json::json!(""));
            }
            _ => {}
        }
    }
    val
}

/// Parse Anthropic's `cache_control` object (`{"type":"ephemeral"}`) into the IR's `CacheControl`.
///
/// Shared by every site that can carry an Anthropic cache breakpoint — text/system blocks, tool
/// definitions, and tool_use/tool_result blocks — so a breakpoint placed ON a tool def or tool
/// result survives the cross-protocol seam instead of being silently dropped. Absent/`null`
/// yields `None`; the only valid `type` is `ephemeral` (Anthropic's sole cache kind today), and an
/// unrecognized `type` is a client error (matching the strictness the text-block parser already had).
fn read_cache_control(
    val: Option<&serde_json::Value>,
) -> Result<Option<crate::ir::CacheControl>, IrError> {
    let Some(cc_val) = val else { return Ok(None) };
    let Some(cc_obj) = cc_val.as_object() else {
        return Ok(None);
    };
    match cc_obj.get("type").and_then(|t| t.as_str()) {
        Some(CACHE_KIND_EPHEMERAL) => Ok(Some(crate::ir::CacheControl {
            kind: crate::ir::CacheKind::Ephemeral,
        })),
        None => Ok(None),
        Some(_) => Err(IrError {
            class: StatusClass::ClientError,
            provider_signal: Some(busbar_contract::protocol::SIGNAL_IR_PARSE.to_string()),
            retry_after: None,
        }),
    }
}

/// Serialize the IR's `CacheControl` back to Anthropic's native `{"type":"ephemeral"}` object.
fn write_cache_control(cc: &crate::ir::CacheControl) -> serde_json::Value {
    match cc.kind {
        crate::ir::CacheKind::Ephemeral => serde_json::json!({"type": CACHE_KIND_EPHEMERAL}),
    }
}

/// Normalize Anthropic's native `tool_choice` object into the IR union.
///
/// Anthropic shape: `{"type":"auto"|"any"|"tool"|"none","name"?:"..."}`. `auto` → `Auto`, `none` →
/// `None`, `any` → `Required` (must call some tool), `tool` + `name` → the targeted `Tool{name}`. An
/// absent field or an unrecognized/`tool`-without-`name` shape maps to `None` (omitted) so a request
/// that never carried a directive does not gain a spurious one — except `tool` with a name, which is
/// the load-bearing targeted case this fix exists to preserve.
fn read_anthropic_tool_choice(val: Option<&serde_json::Value>) -> Option<crate::ir::IrToolChoice> {
    let obj = val?.as_object()?;
    match obj.get("type").and_then(|t| t.as_str())? {
        "auto" => Some(crate::ir::IrToolChoice::Auto),
        "none" => Some(crate::ir::IrToolChoice::None),
        "any" => Some(crate::ir::IrToolChoice::Required),
        "tool" => {
            obj.get("name")
                .and_then(|n| n.as_str())
                .map(|name| crate::ir::IrToolChoice::Tool {
                    name: name.to_string(),
                })
        }
        _ => None,
    }
}

/// Emit the IR tool-choice union in Anthropic's native `tool_choice` object shape.
fn write_anthropic_tool_choice(tc: &crate::ir::IrToolChoice) -> serde_json::Value {
    match tc {
        crate::ir::IrToolChoice::Auto => serde_json::json!({"type": "auto"}),
        crate::ir::IrToolChoice::None => serde_json::json!({"type": "none"}),
        crate::ir::IrToolChoice::Required => serde_json::json!({"type": "any"}),
        crate::ir::IrToolChoice::Tool { name } => {
            serde_json::json!({"type": "tool", "name": name})
        }
    }
}

/// Anthropic native `stop_reason` token → canonical [`crate::ir::IrStopReason`]. The ONLY place that
/// knows Anthropic's finish vocabulary on the read side; an unmodeled token maps to `Other`.
fn read_anthropic_stop_reason(token: &str) -> crate::ir::IrStopReason {
    use crate::ir::IrStopReason as S;
    match token {
        STOP_END_TURN => S::EndTurn,
        STOP_MAX_TOKENS => S::MaxTokens,
        STOP_STOP_SEQUENCE => S::StopSequence,
        STOP_TOOL_USE => S::ToolUse,
        STOP_PAUSE_TURN => S::PauseTurn,
        STOP_REFUSAL => S::Refusal,
        STOP_MODEL_CONTEXT_WINDOW_EXCEEDED => S::MaxTokens,
        _ => S::Other,
    }
}

/// [`crate::ir::IrStopReason`] → Anthropic native `stop_reason`. EXHAUSTIVE: Anthropic's enum is
/// `end_turn | max_tokens | stop_sequence | tool_use | pause_turn | refusal |
/// model_context_window_exceeded` — there is NO `safety` member. A foreign content-filter stop
/// (`content_filter`, `SAFETY`, `content_filtered`) is the provider declining to produce the answer,
/// which is exactly what Anthropic's `refusal` tells a client; rendering it as `end_turn` told the
/// client a filtered answer was a complete one (ANT-12). `error`/`other`, which Anthropic cannot name,
/// degrade to `end_turn` rather than leak an off-spec value a strict Anthropic SDK rejects.
fn write_anthropic_stop_reason(reason: crate::ir::IrStopReason) -> &'static str {
    use crate::ir::IrStopReason as S;
    match reason {
        S::EndTurn => STOP_END_TURN,
        S::MaxTokens => STOP_MAX_TOKENS,
        S::StopSequence => STOP_STOP_SEQUENCE,
        S::ToolUse => STOP_TOOL_USE,
        S::PauseTurn => STOP_PAUSE_TURN,
        S::Refusal | S::Safety => STOP_REFUSAL,
        S::Error | S::Other => STOP_END_TURN,
    }
}

/// The IR-16 / IR-02 refinement of an Anthropic stop (`ir-slots-landed.md`): the raw
/// `model_context_window_exceeded` token becomes [`crate::ir::IrStopDetail::ContextWindowExceeded`]
/// beside the coarse `MaxTokens` (ANT-11), and a `refusal` stop's
/// `stop_details:{type:"refusal", category, explanation}` becomes
/// [`crate::ir::IrStopDetail::Refusal`] beside the coarse `Refusal`. Shared by the buffered and the
/// stream reader so the two paths cannot disagree.
fn read_anthropic_stop_detail(
    stop_reason: Option<&str>,
    stop_details: Option<&serde_json::Value>,
) -> Option<crate::ir::IrStopDetail> {
    match stop_reason? {
        STOP_MODEL_CONTEXT_WINDOW_EXCEEDED => Some(crate::ir::IrStopDetail::ContextWindowExceeded),
        STOP_REFUSAL => {
            let d = stop_details?.as_object()?;
            if d.get("type").and_then(|t| t.as_str()) != Some(STOP_REFUSAL) {
                return None;
            }
            let text = |k: &str| d.get(k).and_then(|v| v.as_str()).map(String::from);
            Some(crate::ir::IrStopDetail::Refusal {
                category: text("category"),
                explanation: text("explanation"),
            })
        }
        _ => None,
    }
}

/// The Anthropic `stop_reason` token for a coarse reason plus its IR-16 refinement: a length stop
/// refined as ContextWindowExceeded is Anthropic's own `model_context_window_exceeded` (ANT-11);
/// everything else is [`write_anthropic_stop_reason`].
fn write_anthropic_stop_reason_detailed(
    reason: crate::ir::IrStopReason,
    detail: Option<&crate::ir::IrStopDetail>,
) -> &'static str {
    match (reason, detail) {
        (
            crate::ir::IrStopReason::MaxTokens,
            Some(crate::ir::IrStopDetail::ContextWindowExceeded),
        ) => STOP_MODEL_CONTEXT_WINDOW_EXCEEDED,
        _ => write_anthropic_stop_reason(reason),
    }
}

/// The Anthropic `stop_details` member (required, nullable) for a stop: the refusal object when the
/// stop is written as `refusal` and the IR carries a Refusal detail (IR-02 category), else `null`
/// — Anthropic populates it only on a refusal stop.
fn write_anthropic_stop_details(
    reason: Option<crate::ir::IrStopReason>,
    detail: Option<&crate::ir::IrStopDetail>,
) -> serde_json::Value {
    match (reason.map(write_anthropic_stop_reason), detail) {
        (
            Some(STOP_REFUSAL),
            Some(crate::ir::IrStopDetail::Refusal {
                category,
                explanation,
            }),
        ) => serde_json::json!({
            "type": STOP_REFUSAL,
            "category": category,
            "explanation": explanation,
        }),
        _ => serde_json::Value::Null,
    }
}

fn write_block(block: &crate::ir::IrBlock) -> serde_json::Value {
    match block {
        crate::ir::IrBlock::Text {
            text,
            cache_control,
            citations,
            refusal: _,
        } => {
            let mut obj = serde_json::Map::new();
            obj.insert("type".to_string(), serde_json::json!("text"));
            obj.insert("text".to_string(), serde_json::json!(text));
            if let Some(cc) = cache_control {
                let cc_val = match cc.kind {
                    crate::ir::CacheKind::Ephemeral => {
                        serde_json::json!({"type": CACHE_KIND_EPHEMERAL})
                    }
                };
                obj.insert("cache_control".to_string(), cc_val);
            }
            if !citations.is_empty() {
                let arr: Vec<serde_json::Value> = citations.iter().map(write_citation).collect();
                obj.insert("citations".to_string(), serde_json::Value::Array(arr));
            }
            serde_json::Value::Object(obj)
        }
        // A REDACTED reasoning block (opaque encrypted bytes in `text`) re-emits as Anthropic's native
        // `redacted_thinking` block so an Anthropic→Anthropic round-trip preserves the native shape and
        // the bytes are NOT leaked as visible `thinking` text.
        crate::ir::IrBlock::Thinking {
            text,
            redacted: true,
            cache_control,
            ..
        } => {
            let mut obj = serde_json::Map::new();
            obj.insert(
                "type".to_string(),
                serde_json::json!(BLOCK_TYPE_REDACTED_THINKING),
            );
            obj.insert("data".to_string(), serde_json::json!(text));
            if let Some(cc) = cache_control {
                obj.insert("cache_control".to_string(), write_cache_control(cc));
            }
            serde_json::Value::Object(obj)
        }
        crate::ir::IrBlock::Thinking {
            text,
            signature,
            redacted: false,
            cache_control,
            kind: _,
            signature_origin: _,
        } => {
            let mut obj = serde_json::Map::new();
            obj.insert("type".to_string(), serde_json::json!("thinking"));
            obj.insert("thinking".to_string(), serde_json::json!(text));
            if let Some(sig) = signature {
                obj.insert("signature".to_string(), serde_json::json!(sig));
            }
            if let Some(cc) = cache_control {
                obj.insert("cache_control".to_string(), write_cache_control(cc));
            }
            serde_json::Value::Object(obj)
        }
        crate::ir::IrBlock::ToolUse {
            id,
            name,
            input,
            cache_control,
            // Explicit field list here is intentional documentation of every IrBlock::ToolUse
            // field this writer considered — Anthropic has no wire concept of a Gemini
            // thoughtSignature, so this one is deliberately unused.
            thought_signature: _,
        } => {
            let mut obj = serde_json::Map::new();
            obj.insert("type".to_string(), serde_json::json!(STOP_TOOL_USE));
            obj.insert("id".to_string(), serde_json::json!(id));
            obj.insert("name".to_string(), serde_json::json!(name));
            obj.insert("input".to_string(), input.clone());
            if let Some(cc) = cache_control {
                obj.insert("cache_control".to_string(), write_cache_control(cc));
            }
            serde_json::Value::Object(obj)
        }
        crate::ir::IrBlock::ToolResult {
            tool_use_id,
            content,
            is_error,
            cache_control,
        } => {
            let mut obj = serde_json::Map::new();
            obj.insert("type".to_string(), serde_json::json!("tool_result"));
            obj.insert("tool_use_id".to_string(), serde_json::json!(tool_use_id));
            if content.is_empty() {
                obj.insert("content".to_string(), serde_json::json!(""));
            } else {
                // A tool_result's content is filtered exactly as a message's is (ANT-17): an
                // attachment with no Anthropic projection is OMITTED, never sent as the empty-text
                // placeholder Anthropic rejects. A structured JSON result (Bedrock `{"json":…}`) has
                // no JSON block on Anthropic, but its CONTENT is text-representable: it rides as a
                // `text` block holding the serialized JSON, which is what a tool result is to the
                // model (ANT-16 — it used to be dropped, leaving `content: []`).
                // An EMPTY text block (a degraded placeholder from a foreign reader, or a foreign
                // tool result whose content was `""`) is omitted for the same reason; a result left
                // with nothing is the empty-string content Anthropic accepts.
                let kept: Vec<serde_json::Value> = content
                    .iter()
                    .filter(|b| attachment_is_sendable(b))
                    .filter(
                        |b| !matches!(b, crate::ir::IrBlock::Text { text, .. } if text.is_empty()),
                    )
                    .map(|b| match b {
                        crate::ir::IrBlock::Json(v) => serde_json::json!({
                            "type": "text",
                            "text": serde_json::to_string(v).unwrap_or_default(),
                        }),
                        other => write_block(other),
                    })
                    .collect();
                if kept.is_empty() {
                    obj.insert("content".to_string(), serde_json::json!(""));
                } else {
                    obj.insert("content".to_string(), serde_json::Value::Array(kept));
                }
            }
            if *is_error {
                obj.insert("is_error".to_string(), serde_json::Value::Bool(true));
            }
            if let Some(cc) = cache_control {
                obj.insert("cache_control".to_string(), write_cache_control(cc));
            }
            serde_json::Value::Object(obj)
        }
        crate::ir::IrBlock::Image {
            source,
            cache_control,
            detail: _,
        } => {
            // Anthropic's Messages API has both a native URL image source and a base64 source.
            // S3/FileId references have no Anthropic projection and are FILTERED before write_block
            // (see the unresolvable-image drop in write_message); the arm here is a defensive empty
            // placeholder for the unreachable case.
            let mut img = match source {
                crate::ir::IrImageSource::Url(url) => {
                    serde_json::json!({ "type": "image", "source": { "type": "url", "url": url } })
                }
                crate::ir::IrImageSource::Base64 { media_type, data } => {
                    // VALIDATE the media type before putting it on the wire. Anthropic accepts only
                    // `image/{jpeg,png,gif,webp}` and 400s anything else — and a non-image mime CAN
                    // reach here: the Gemini reader used to map EVERY `inlineData` (including
                    // `audio/mp3`, `application/pdf`) onto an `IrBlock::Image`, so
                    // `{"type":"image","source":{"media_type":"audio/mp3"}}` went upstream and was
                    // rejected. That breaks the half of the losslessness promise that says the
                    // backend never rejects the request, which is the one thing translation must
                    // never do. Bedrock's writer already validated against its own `ImageFormat`
                    // union; this is that same pattern, not a new one. Emit the empty placeholder
                    // (unreachable in practice — `write_message` filters first) rather than a block
                    // Anthropic rejects.
                    match crate::ir::image_subtype_if_supported(media_type) {
                        Some(subtype) => serde_json::json!({
                            "type": "image",
                            "source": { "type": "base64", "media_type": format!("image/{subtype}"), "data": data }
                        }),
                        None => {
                            tracing::warn!(
                                media_type = %media_type,
                                "dropping image block on Anthropic egress: media_type is not one of \
                                 image/{{jpeg,png,gif,webp}}, the only set Anthropic accepts — \
                                 emitting it verbatim would 400 the backend"
                            );
                            serde_json::json!({ "type": "text", "text": "" })
                        }
                    }
                }
                // This protocol's OWN opaque handle (a Files-API `{"type":"file","file_id":…}`
                // source): re-emit it verbatim. A FOREIGN vendor handle is filtered before
                // `write_block` (see `attachment_is_sendable`); the placeholder is defensive only.
                crate::ir::IrImageSource::Vendor { vendor, value } if *vendor == VENDOR_NAME => {
                    serde_json::json!({ "type": "image", "source": value })
                }
                crate::ir::IrImageSource::Vendor { .. } => {
                    serde_json::json!({ "type": "text", "text": "" })
                }
            };
            if let Some(cc) = cache_control {
                if let Some(obj) = img.as_object_mut() {
                    obj.insert("cache_control".to_string(), write_cache_control(cc));
                }
            }
            img
        }
        crate::ir::IrBlock::Media {
            kind,
            source,
            name,
            cache_control,
            citations,
            context,
        } => {
            // Anthropic has exactly ONE attachment block — `document` — and no audio or video block
            // at all. So a Document projects natively (this is the slot an OpenAI `file` part or a
            // Bedrock `document` lands in on an Anthropic egress), and Audio/Video are dropped
            // DELIBERATELY with a warn naming the construct. `write_message` filters those before
            // they get here so nothing is emitted for them; the placeholder below is defensive for a
            // direct `write_block` call.
            if *kind != crate::ir::IrMediaKind::Document {
                tracing::warn!(
                    media_kind = kind.as_str(),
                    "dropping attachment on Anthropic egress: the Messages API has a `document` \
                     content block and NO audio or video block, so this attachment has no native \
                     slot; it is NOT emitted"
                );
                return serde_json::json!({ "type": "text", "text": "" });
            }
            let src = match source {
                crate::ir::IrImageSource::Url(url) => {
                    serde_json::json!({ "type": "url", "url": url })
                }
                crate::ir::IrImageSource::Base64 { media_type, data } => {
                    // Anthropic splits inline document bytes across two source types by mime: a PDF
                    // is the `base64` source, text is the `text` source carrying DECODED text (the
                    // IR holds it base64). Emitting the base64 string as the text source's `data`
                    // handed the model base64 gibberish as its document (ANT-02). A mime with no
                    // Anthropic source is filtered before `write_block`; the placeholder is defensive.
                    match inline_document_source(media_type, data) {
                        Some(src) => src,
                        None => return serde_json::json!({ "type": "text", "text": "" }),
                    }
                }
                // This protocol's OWN opaque source (a Files-API `file_id` or a `content` document):
                // re-emit verbatim. A FOREIGN vendor reference is filtered in `write_message`.
                crate::ir::IrImageSource::Vendor { value, .. } => value.clone(),
            };
            let mut doc = serde_json::json!({ "type": BLOCK_TYPE_DOCUMENT, "source": src });
            if let Some(obj) = doc.as_object_mut() {
                if let Some(n) = name {
                    obj.insert("title".to_string(), serde_json::json!(n));
                }
                // IR-12: the document's citation toggle and context hint (Anthropic / Bedrock).
                if let Some(c) = context {
                    obj.insert("context".to_string(), serde_json::json!(c));
                }
                if let Some(enabled) = citations {
                    obj.insert(
                        "citations".to_string(),
                        serde_json::json!({ "enabled": enabled }),
                    );
                }
                if let Some(cc) = cache_control {
                    obj.insert("cache_control".to_string(), write_cache_control(cc));
                }
            }
            doc
        }
        crate::ir::IrBlock::Json(_) => {
            // A structured-json tool-result block has no top-level Anthropic content shape; it is
            // dropped before reaching write_block (see the json-tool-result filter in the ToolResult
            // arm). Defensive empty placeholder for the unreachable case.
            serde_json::json!({ "type": "text", "text": "" })
        }
    }
}

/// IR effort word → Anthropic `output_config.effort`. Anthropic has no `minimal`; its lowest level is
/// `low`, the nearest the ask can be honoured.
fn anthropic_effort_word(effort: crate::ir::IrReasoningEffort) -> &'static str {
    use crate::ir::IrReasoningEffort as E;
    match effort {
        E::Minimal | E::Low => "low",
        E::Medium => "medium",
        E::High => "high",
        E::XHigh => "xhigh",
        E::Max => "max",
    }
}

/// Anthropic `output_config.effort` word → IR effort. `xhigh`/`max` are the IR-09 words above
/// `High` (ANT-09) — each foreign writer projects them onto its own top (OpenAI `"high"`, the
/// budget table's top entry); `anthropic_effort_word` writes them back verbatim. Anthropic has no
/// `minimal`, so that word is not read.
fn read_anthropic_effort_word(word: &str) -> Option<crate::ir::IrReasoningEffort> {
    use crate::ir::IrReasoningEffort as E;
    match word {
        "low" => Some(E::Low),
        "medium" => Some(E::Medium),
        "high" => Some(E::High),
        "xhigh" => Some(E::XHigh),
        "max" => Some(E::Max),
        _ => None,
    }
}

/// Anthropic `output_config.format` (or the deprecated `output_format`) → the typed IR directive.
/// Only the `json_schema` form with an object schema is a structured-output directive; anything else
/// is not one this reader can name, and yields `None` (the key still rides `extra` same-protocol).
/// Anthropic structured outputs carry no schema name/description sibling and are always enforced, so
/// `name`/`description` are absent and `strict` is left unset rather than asserting a flag the
/// caller never wrote.
fn read_anthropic_output_format(v: &serde_json::Value) -> Option<crate::ir::IrResponseFormat> {
    if v.get("type").and_then(|t| t.as_str()) != Some(OUTPUT_FORMAT_JSON_SCHEMA) {
        return None;
    }
    let schema = v.get("schema").filter(|s| s.is_object())?.clone();
    Some(crate::ir::IrResponseFormat {
        json: true,
        schema: Some(schema),
        name: None,
        strict: None,
        description: None,
    })
}

/// Close every object schema in a structured-output schema (`additionalProperties: false`), in
/// place. Anthropic's structured outputs REQUIRE `additionalProperties: false` on every object (a
/// schema without it is rejected), while OpenAI accepts an open object in non-strict mode — so a
/// cross-protocol schema is closed the same way Anthropic's own SDKs close a schema before sending
/// it. Walks only schema-bearing keywords (`properties`, `items`, `prefixItems`, `anyOf`, `allOf`,
/// `oneOf`, `not`, `$defs`, `definitions`), never a data position like `enum`/`const`/`default`.
fn close_object_schemas(schema: &mut serde_json::Value) {
    let Some(obj) = schema.as_object_mut() else {
        return;
    };
    let is_object = obj.contains_key("properties")
        || match obj.get("type") {
            Some(serde_json::Value::String(t)) => t == "object",
            Some(serde_json::Value::Array(ts)) => ts.iter().any(|t| t == "object"),
            _ => false,
        };
    if is_object && obj.get("additionalProperties") != Some(&serde_json::Value::Bool(false)) {
        obj.insert(
            "additionalProperties".to_string(),
            serde_json::Value::Bool(false),
        );
    }
    for key in ["properties", "$defs", "definitions"] {
        if let Some(map) = obj.get_mut(key).and_then(|v| v.as_object_mut()) {
            map.values_mut().for_each(close_object_schemas);
        }
    }
    for key in ["anyOf", "allOf", "oneOf", "prefixItems"] {
        if let Some(arr) = obj.get_mut(key).and_then(|v| v.as_array_mut()) {
            arr.iter_mut().for_each(close_object_schemas);
        }
    }
    for key in ["items", "not"] {
        if let Some(sub) = obj.get_mut(key) {
            close_object_schemas(sub);
        }
    }
}

/// REQUEST-side attachment filter shared by a message's content AND a `tool_result`'s content — the
/// two places an attachment can sit on the Anthropic request wire. Returns `false` (after a warn
/// naming the construct) for a block that has no valid Anthropic projection, so the caller omits it
/// instead of emitting `write_block`'s empty-text placeholder, which Anthropic rejects ("text content
/// blocks must be non-empty") — the tool_result path used to skip this filter and ship that
/// placeholder (ANT-17).
///
/// Dropped: an image that is a FOREIGN vendor handle (a Responses `file_id`, a Bedrock
/// `s3Location`) or whose mime is not `image/{jpeg,png,gif,webp}`; an audio/video attachment (no
/// Anthropic block); a document that is a foreign vendor handle, or inline bytes of a mime Anthropic
/// has no document source for (see [`inline_document_source`]). This protocol's OWN vendor handles
/// (a Files-API `file_id`) are kept — the writer re-emits them verbatim.
fn attachment_is_sendable(block: &crate::ir::IrBlock) -> bool {
    match block {
        crate::ir::IrBlock::Image { source, .. } => match source {
            crate::ir::IrImageSource::Vendor { vendor, .. } => {
                if *vendor == VENDOR_NAME {
                    return true;
                }
                tracing::warn!(
                    vendor = %vendor,
                    "dropping unresolvable vendor-scoped image reference on Anthropic egress: a \
                     Responses input_image.file_id or a Bedrock s3Location has no cross-vendor analog; \
                     the block is NOT emitted"
                );
                false
            }
            crate::ir::IrImageSource::Base64 { media_type, .. } => {
                if crate::ir::image_subtype_if_supported(media_type).is_some() {
                    return true;
                }
                tracing::warn!(
                    media_type = %media_type,
                    "dropping image block from anthropic request egress: media_type is not one of \
                     image/{{jpeg,png,gif,webp}} and anthropic 400s anything else"
                );
                false
            }
            crate::ir::IrImageSource::Url(_) => true,
        },
        crate::ir::IrBlock::Media { kind, source, .. } => {
            if *kind != crate::ir::IrMediaKind::Document {
                tracing::warn!(
                    media_kind = kind.as_str(),
                    "dropping attachment from anthropic request egress: the Messages API has no \
                     audio or video content block"
                );
                return false;
            }
            match source {
                crate::ir::IrImageSource::Vendor { vendor, .. } if *vendor != VENDOR_NAME => {
                    tracing::warn!(
                        vendor = %vendor,
                        "dropping document attachment from anthropic request egress: the source is \
                         a foreign vendor file handle anthropic's backend cannot resolve"
                    );
                    false
                }
                crate::ir::IrImageSource::Base64 { media_type, data } => {
                    if inline_document_source(media_type, data).is_some() {
                        return true;
                    }
                    tracing::warn!(
                        media_type = %media_type,
                        "dropping document attachment from anthropic request egress: anthropic has \
                         an inline document source only for application/pdf (base64) and UTF-8 \
                         text (text source); this mime has no native slot"
                    );
                    false
                }
                _ => true,
            }
        }
        _ => true,
    }
}

fn write_message(
    msg: &crate::ir::IrMessage,
    m: usize,
    unmodeled_sentinel: &[serde_json::Value],
) -> serde_json::Value {
    let role_str = match msg.role {
        crate::ir::IrRole::User => "user",
        crate::ir::IrRole::Assistant => "assistant",
        // Anthropic's Messages API has NO `system` role inside `messages` — system content lives in
        // the top-level `system` field. `write_request` folds every `IrRole::System` message into
        // that top-level array and FILTERS it out of the per-message loop, so this arm is unreachable
        // on the request path. Map it to `"user"` defensively (NOT the invalid `"system"`) so that
        // even a direct `write_message` call can never emit a `role:"system"` Anthropic rejects.
        crate::ir::IrRole::System => "user",
        // Anthropic has no "tool" message role — tool results are carried as `user` messages whose
        // content holds `tool_result` block(s). (Reachable when translating an OpenAI `tool` message.)
        crate::ir::IrRole::Tool => "user",
    };
    // REQUEST-side filter (write_message feeds write_request only; write_response/_event call
    // write_block directly, so response reasoning still surfaces). Anthropic's Messages API rejects
    // an assistant PLAINTEXT `thinking` block that lacks a `signature` with a 400 — a signature is
    // mandatory on the request path for a `thinking` block. A cross-protocol IR may carry such a
    // block whose signature is None (e.g. reasoning translated from a provider that emits no
    // signature), so drop those rather than forward an egress that the upstream will 400.
    //
    // A REDACTED thinking block (`redacted: true`) is a DIFFERENT wire shape: it re-emits as a
    // native `redacted_thinking` block carrying opaque `data` bytes and NO `signature` — Anthropic
    // accepts it without one (the signature requirement is specific to plaintext `thinking`). So the
    // `redacted: false` guard below is load-bearing: WITHOUT it, every redacted block (which always
    // has `signature: None`) is silently dropped here before `write_block` can re-emit it, losing
    // the encrypted reasoning that lets a multi-turn extended-thinking conversation replay. Only
    // drop UNSIGNED PLAINTEXT thinking. Other block types pass through.
    let mut dropped_unsigned_thinking = 0usize;
    // Original-index `enumerate()` BEFORE the drop filter — `find_stashed_block` keys on the
    // position `read_request` recorded, which is the RAW pre-filter content index; collapsing
    // dropped blocks out of the index space here would misalign every stash lookup after the
    // first drop.
    let blocks: Vec<serde_json::Value> = msg
        .content
        .iter()
        .enumerate()
        .filter_map(|(i, block)| {
            if let crate::ir::IrBlock::Thinking {
                signature,
                redacted: false,
                signature_origin,
                ..
            } = block
            {
                // IR-18: a signature minted by another vendor (Gemini, OpenAI, a non-Claude Bedrock
                // model) is not a valid Anthropic signature — Anthropic 400s on it exactly as on a
                // missing one. Only an Anthropic-origin (or unknown-origin, the pre-slot behaviour)
                // signature is sent.
                let foreign =
                    signature_origin.is_some_and(|o| o != crate::ir::IrSignatureOrigin::Anthropic);
                if signature.is_none() || foreign {
                    dropped_unsigned_thinking += 1;
                    return None;
                }
            }
            if !attachment_is_sendable(block) {
                return None;
            }
            if block.is_citation_carrier() {
                tracing::warn!(
                    "dropping citations with no text on Anthropic egress: an empty text block is \
                     rejected (COH-17)"
                );
                return None;
            }
            // A parked unmodeled block (e.g. `document`) at this exact position: splice the
            // ORIGINAL raw block back rather than emitting `write_block`'s empty-Text placeholder.
            if let Some(raw) = find_stashed_block(unmodeled_sentinel, m, i) {
                return Some(raw);
            }
            Some(write_block(block))
        })
        .collect();
    if dropped_unsigned_thinking > 0 {
        tracing::warn!(
            dropped = dropped_unsigned_thinking,
            "dropped assistant thinking block(s) with no Anthropic signature (none, or another \
             vendor's, IR-18) from anthropic request egress (anthropic rejects them with a 400)"
        );
    }
    // When no blocks survive (e.g. an all-thinking assistant message whose unsigned thinking blocks
    // were all dropped above), emit an EMPTY ARRAY `[]`, not an empty STRING `""`. Anthropic's
    // Messages API rejects a message whose top-level `content` is the empty string with a 400
    // ("text content blocks must be non-empty" / "content: field required"), whereas an empty array
    // is a well-formed message with zero content blocks that the API accepts. This matches the
    // empty-array skeleton `write_response_event` already emits for `message_start.message.content`
    // (a message with no blocks yet). The non-empty branch is unchanged: a populated array of blocks.
    let content_val: serde_json::Value = serde_json::Value::Array(blocks);
    serde_json::json!({ "role": role_str, "content": content_val })
}

/// Project one IR tool onto Anthropic's `tools[]`. `None` for a HOSTED tool that is not an
/// Anthropic-defined one (a Responses `{"type":"web_search"}` — no `name`, no Anthropic analog):
/// emitting it as a function tool would ship a malformed empty-name tool the backend 400s on.
fn write_tool(tool: &crate::ir::IrTool) -> Option<serde_json::Value> {
    if let Some(hosted) = &tool.hosted {
        // An Anthropic-defined tool (read by `read_tool` from a non-`custom` `type`) always carries
        // its `name`; re-emit its raw definition verbatim. Anything else is a foreign hosted tool.
        let anthropic_shaped = hosted
            .get("type")
            .and_then(|t| t.as_str())
            .is_some_and(|t| t != TOOL_TYPE_CUSTOM)
            && hosted.get("name").and_then(|n| n.as_str()).is_some();
        if anthropic_shaped {
            return Some(hosted.clone());
        }
        tracing::warn!(
            "dropping a hosted tool on Anthropic egress: it is not an Anthropic-defined tool and has \
             no Anthropic projection"
        );
        return None;
    }
    let mut obj = serde_json::Map::new();
    obj.insert("name".to_string(), serde_json::json!(tool.name));
    if let Some(desc) = &tool.description {
        obj.insert("description".to_string(), serde_json::json!(desc));
    }
    obj.insert("input_schema".to_string(), tool.input_schema.clone());
    if let Some(cc) = &tool.cache_control {
        obj.insert("cache_control".to_string(), write_cache_control(cc));
    }
    // Anthropic's GA per-tool `strict` — the same schema-guaranteed-arguments contract as OpenAI's
    // `function.strict`, so a caller's guarantee survives the hop instead of being dropped (ANT-05).
    if let Some(strict) = tool.strict {
        obj.insert("strict".to_string(), serde_json::json!(strict));
    }
    Some(serde_json::Value::Object(obj))
}

/// Anthropic writer implementation.
///
/// `open_block_indices` is the per-stream set of IR block indices whose `content_block_start` this
/// writer actually WROTE, and which therefore owe a closing `content_block_stop`. Tracked means
/// emitted: an index is added by the code path that writes the frame, never by the intent to write
/// one later. That matters for `redacted_thinking`, whose start is DEFERRED to the delta carrying
/// the opaque bytes — marking it at its `BlockStart` would let a stream that ends before that delta
/// close a block the client never saw opened. What is NOT tracked at all is
/// `IrBlockMeta::Image` — the published `ContentBlockStartEvent.content_block` discriminator has no
/// `image` member (an assistant content block on the Anthropic response wire is never an image), so
/// that block projects to NO frame at all, exactly as every sibling writer already does. The
/// `BlockStop` arm carries only the integer index and no block kind, so without this set it cannot
/// tell a suppressed index from an opened one and would close a block the client never saw opened.
/// Mirrors `BedrockWriter`'s identically-shaped guard, down to the `Mutex` (which keeps the writer
/// `Sync` as `ProtocolWriter` requires; a stream is single-threaded at any instant, so contention
/// never happens in practice) and the poisoning degradation to a no-op / `false` rather than a panic
/// on the request path.
pub struct AnthropicWriter {
    open_block_indices: std::sync::Mutex<std::collections::BTreeSet<usize>>,
    /// THIS STREAM'S `message.id`, minted ONCE and replayed on every later `message_start`.
    ///
    /// A stream is not guaranteed to carry exactly one `MessageStart`: five of the six readers gate
    /// it on their own started flag, but the Anthropic reader emits it 1:1 with the upstream frame,
    /// so a duplicate reaches this writer. Without this cell the second one synthesized a FRESH
    /// `msg_` id, so one message announced itself twice under two different identities and an SDK
    /// that latched the first was left holding an id nothing else in the stream ever mentions. A
    /// native stream's id is fixed for the life of the message, so the first one wins.
    message_id: std::sync::Mutex<Option<String>>,
}

/// Value-namespace constructor for [`AnthropicWriter`], mirroring `BedrockWriter`'s and
/// `CohereWriter`'s identically-shaped consts: `protocol_for` builds a FRESH `Protocol`, and
/// therefore a fresh writer, per stream, so each use of this const inlines an independent empty set
/// and per-writer state cannot leak across concurrent streams. `clippy::declare_interior_mutable_const`
/// is suppressed deliberately: a shared `static` here WOULD leak one stream's open indices into
/// another, which is exactly the bug this guard exists to prevent.
#[allow(non_upper_case_globals)]
#[allow(clippy::declare_interior_mutable_const)]
pub const AnthropicWriter: AnthropicWriter = AnthropicWriter {
    open_block_indices: std::sync::Mutex::new(std::collections::BTreeSet::new()),
    message_id: std::sync::Mutex::new(None),
};

/// A FRESH writer as a VALUE, for the one-shot `write_request` / `write_response` calls the test
/// suites make. Borrowing the const directly (`AnthropicWriter.write_request(…)`) is
/// `clippy::borrow_interior_mutable_const`: each borrow inlines its own copy of the interior-mutable
/// set, which is harmless for a stateless one-shot call but wrong for a STREAM (whose open/close
/// correlation must see one writer). This returns the value so the temporary is explicit, and a test
/// that drives a sequence of stream events binds one writer to a local instead of calling this per
/// event.
#[cfg(test)]
pub(crate) fn anthropic_writer() -> AnthropicWriter {
    AnthropicWriter
}

impl Clone for AnthropicWriter {
    fn clone(&self) -> Self {
        // Carry the open-index set across a clone so a mid-stream `Protocol::clone` keeps the
        // open/close correlation; a poisoned lock degrades to an empty set rather than panicking.
        AnthropicWriter {
            open_block_indices: std::sync::Mutex::new(
                self.open_block_indices
                    .lock()
                    .map(|set| set.clone())
                    .unwrap_or_default(),
            ),
            // A mid-stream clone is still the SAME message, so the id it already announced comes
            // with it — otherwise the clone would mint a new one on the next `message_start`.
            message_id: std::sync::Mutex::new(
                self.message_id.lock().map(|id| id.clone()).unwrap_or(None),
            ),
        }
    }
}

impl AnthropicWriter {
    /// THE STREAM'S `message.id`: the first one wins.
    ///
    /// Returns the id already captured for this stream if there is one, otherwise captures and
    /// returns `mint()`. A duplicate `message_start` therefore re-states the identity the client
    /// already has instead of announcing a second one. Lock poisoning degrades to the freshly
    /// minted id rather than panicking on the request path.
    fn carried_message_id(&self, mint: impl FnOnce() -> String) -> String {
        match self.message_id.lock() {
            Ok(mut slot) => slot.get_or_insert_with(mint).clone(),
            Err(_) => mint(),
        }
    }

    /// Record that a `content_block_start` was WRITTEN for IR block `index`, so it owes a closing
    /// `content_block_stop`. Returns true when the index was newly opened, false when it was
    /// already open — a redacted-thinking block's start is deferred to its delta, and the boolean
    /// is what keeps a second delta from writing a duplicate start for a block already open on the
    /// wire. Lock poisoning degrades to `false` rather than panicking.
    fn mark_block_open(&self, index: usize) -> bool {
        self.open_block_indices
            .lock()
            .map(|mut set| set.insert(index))
            .unwrap_or(false)
    }

    /// Consume the open record for `index`, returning whether this writer opened it (and so owes
    /// the closing frame). An untracked index is a block whose start had no Anthropic projection.
    /// Lock poisoning degrades to `false` — closing nothing — rather than panicking.
    fn take_block_open(&self, index: usize) -> bool {
        self.open_block_indices
            .lock()
            .map(|mut set| set.remove(&index))
            .unwrap_or(false)
    }
}

#[cfg(test)]
#[path = "tests/anthropic_hardening_tests.rs"]
mod anthropic_hardening_tests;

#[cfg(test)]
#[path = "tests/input_hardening_tests.rs"]
mod input_hardening_tests;

#[cfg(test)]
#[path = "tests/user_and_parallelism_carry_tests.rs"]
mod user_and_parallelism_carry_tests;

#[cfg(test)]
#[path = "tests/reasoning_carry_tests.rs"]
mod reasoning_carry_tests;

#[cfg(test)]
#[path = "tests/field_carry_tests.rs"]
mod field_carry_tests;

#[cfg(test)]
#[path = "tests/usage_float_tests.rs"]
mod usage_float_tests;

#[cfg(test)]
#[path = "tests/ir_mapping_q57_tests.rs"]
mod ir_mapping_q57_tests;

#[cfg(test)]
#[path = "tests/ir_slot_wiring_tests.rs"]
mod ir_slot_wiring_tests;

#[cfg(test)]
#[path = "tests/ir_round3_tests.rs"]
mod ir_round3_tests;
