// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Bedrock Converse protocol reader/writer implementation.

use crate::ir::IrStreamEvent;
use busbar_contract::http::{HeaderName, HeaderValue, StatusCode};
use busbar_contract::protocol::*;
use busbar_contract::protocol::{
    ERR_TYPE_AUTHENTICATION, ERR_TYPE_INSUFFICIENT_QUOTA, ERR_TYPE_INVALID_REQUEST,
    ERR_TYPE_NOT_FOUND, ERR_TYPE_PERMISSION, ERR_TYPE_RATE_LIMIT,
};
#[cfg(test)]
use busbar_contract::upstream::CanonicalSignal;
use busbar_contract::upstream::StatusClass;
// G6 A4b: the wire-codec surface (ProtocolReader/Writer/Protocol/StreamFraming/ToolIdRemap/
// protocol_for) relocated to this plugin's `proto_codec`; reach it RELATIVELY so it resolves both
// standalone (crate::proto_codec) and netted into core (core::proto::proto_codec).
#[allow(unused_imports)]
// used standalone; redundant with the `busbar_contract::protocol::*` glob when netted into core
use super::proto_codec::*;
// See the anthropic dialect for the rationale: an explicit import of the codec surface so it binds to
// THIS crate's own `proto_codec` rather than the `busbar_contract::protocol::*` glob.
#[allow(unused_imports)]
use super::proto_codec::{Protocol, ProtocolReader, ProtocolWriter, StreamFraming};

mod citations;
pub mod handler;
mod reader;
mod writer;

use self::citations::{
    read_bedrock_citation, read_bedrock_citations_content, write_bedrock_citation,
};

/// Build this dialect's wire codec — the [`ProtocolDecl::codec`] constructor. A fresh instance per
/// resolution, exactly as the registry's field doc requires. Mirrors `super::anthropic::protocol`.
pub fn protocol() -> Protocol {
    Protocol::new("bedrock", BedrockReader, BedrockWriter)
}

/// BEDROCK'S ROUTER DETECTION — its rungs of the old core `protocol_id` ladder: the AWS SigV4
/// `Authorization: AWS4-HMAC-SHA256…` signature is the TIGHTEST claim of any dialect (rung 1,
/// unambiguous regardless of path), then the `/converse` path (rung 12) and the `/model/{id}/invoke`
/// path (rung 13). Lower strength binds tighter — the shared ladder positions.
fn claims(
    h: &busbar_contract::http::HeaderMap,
    path: &str,
) -> Option<busbar_contract::protocol::ClaimStrength> {
    use busbar_contract::protocol::ClaimStrength;
    if h.get("authorization")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|a| a.starts_with("AWS4-HMAC-SHA256"))
    {
        return Some(ClaimStrength(1));
    }
    if path.contains("/converse") {
        return Some(ClaimStrength(12));
    }
    if path.starts_with("/model/") && path.ends_with("/invoke") {
        return Some(ClaimStrength(13));
    }
    None
}

/// BEDROCK'S RESIDUAL DETECTION — its arm of the headerless `residual_dialect_for_path` ladder: a
/// `/model/{id}/converse[-stream]` path names Bedrock (rung 30). The `/converse`-suffix requirement
/// is load-bearing: a non-Converse `/model/…` path must NOT wear a Bedrock envelope.
fn residual_claims(path: &str) -> Option<busbar_contract::protocol::ClaimStrength> {
    if path.starts_with("/model/")
        && (path.ends_with("/converse") || path.ends_with("/converse-stream"))
    {
        return Some(busbar_contract::protocol::ClaimStrength(30));
    }
    None
}

/// BEDROCK'S RESPONSE-side untranslatable metadata: the guardrail assessment arrives under a
/// top-level `trace` (`trace.guardrail`), present only when the request asked for it. Reported so the
/// cross-protocol seam LOGS the drop — a guardrail assessment is an AWS account artifact no other
/// protocol can carry. The top-level lookup is Bedrock's own shape and stays here, off core.
fn vendor_response_metadata(body: &serde_json::Value) -> Vec<&'static str> {
    ["trace"]
        .into_iter()
        .filter(|k| body.get(k).is_some())
        .collect()
}

/// BEDROCK'S DECLARATION. The only protocol declaring SigV4 ingress auth and a non-SSE streaming
/// content type — the two facts core used to learn by allocating a reader and a writer to ask.
pub const DECL: ProtocolDecl = ProtocolDecl {
    name: "bedrock",
    codec: {
        // The dialect's neutral codec facade as a STATIC, so the decl hands out a `&'static dyn`
        // borrow (pure memory, zero alloc per `dialect()` call) — the seam's perf contract.
        static CODEC: super::proto_codec::DialectRef = super::proto_codec::dialect_ref("bedrock");
        Some(&CODEC)
    },
    handler: Some(&handler::BedrockRequestHandler),
    verbs: &[
        busbar_contract::operation::OpVerb::CHAT,
        busbar_contract::operation::OpVerb::EMBEDDINGS,
        busbar_contract::operation::OpVerb::IMAGE,
        busbar_contract::operation::OpVerb::RERANK,
    ],
    head_keys: super::proto_codec::LLM_CHAT_HEAD_KEYS,
    // Bedrock ingress expects a BINARY eventstream body, not SSE: mislabeling it breaks the SDK.
    streaming_content_type: Some(APPLICATION_VND_AMAZON_EVENTSTREAM),
    array_stream_shim_key: None,
    // `tooluse_…` is Bedrock's documented native tool-call id shape.
    native_tool_id_prefix: Some("tooluse_"),
    ingress_auth: IngressAuth::SigV4,
    // SIGV4 IS THIS DIALECT'S OWN EGRESS SCHEME AND IT TRAVELS WITH THE DIALECT — as DECLARED DATA
    // (#83a S2-a, O7, #40(b)): the service it signs for, the region as a pure function of the
    // endpoint host (with the `us-east-1` fallback), and the content type the signature covers. The
    // kernel's egress-auth unit holds the lane credential (`ACCESS:SECRET[:SESSION]`) and signs
    // under a teller-minted grant, so the secret never passes through this plane. Never
    // lane-constant: every signature covers the body, the time and the path.
    egress_auth_headers: None,
    egress_auth_lane_constant: false,
    egress_scheme: Some(EgressScheme::SigV4 {
        service: "bedrock",
        region_of_host: declared_sigv4_region,
        default_region: "us-east-1",
        content_type: busbar_contract::protocol::APPLICATION_JSON,
    }),
    // THE MODEL IS IN THE URL (`/model/{model_id}/converse`, `/converse-stream`, `/invoke`): this
    // dialect registers its arrival (`busbar_kernel::ingress::bedrock_arrival`) through
    // `busbar_llm::PATH_INGRESS`, folded into the core side-table by the composition root.
    // `has_model_in_url: true` below is what the boot parity assert pairs with that registration.
    stream_usage_requires_opt_in: false,
    // ── Promoted writer facts (G6 step A1): the same constants the `BedrockWriter` methods returned.
    requires_max_tokens: false,
    stop_sequence_cap: None,
    cache_markers_model_gated: true,
    fills_thought_signature: false,
    frame_after_message_start: None,
    reshapes_body_at_path_base: false,
    max_cache_control_breakpoints: None,
    quota_exceeded_status: busbar_contract::http::StatusCode::BAD_REQUEST,
    ingress_is_eventstream: true,
    emits_sse_done_terminator: false,
    max_citations_per_delta: Some(1),
    // AWS Bedrock is reached via boto3/botocore. RELEASE OBLIGATION: re-verify/bump per release;
    // `test_egress_ua_versions_are_pinned_and_present` guards drift.
    egress_user_agent: "Boto3/1.35.0 md/Botocore#1.35.0",
    has_model_in_url: true,
    auth_failure_status_and_kind: (busbar_contract::http::StatusCode::FORBIDDEN, "auth"),
    ingress_relays_amzn_headers: true,
    ingress_relayed_response_header_names: &[HDR_AMZN_REQUEST_ID, HDR_AMZN_ERROR_TYPE],
    auth_failure_message: "",
    uses_array_stream_shim: false,
    has_native_path_not_found: false,
    // Botocore/boto3 sends the binary eventstream `Accept` on a `ConverseStream` call (the same
    // value as the streaming Content-Type); non-stream is `application/json` like every dialect.
    egress_stream_accept: APPLICATION_VND_AMAZON_EVENTSTREAM,
    // No list-models surface: Bedrock's model discovery is not a `/v1/models` GET.
    models_list_envelope: None,
    claims: Some(claims),
    residual_claims: Some(residual_claims),
    residual_default: false,
    vendor_response_metadata: Some(vendor_response_metadata),
    // No wire-fingerprint header disambiguates Bedrock on the shared list-models surface (its
    // `AWS4-HMAC-SHA256` credential must NOT steer a models-list GET; the OpenAI residual wins).
    list_models_fingerprint_headers: &[],
    static_headers: &[],
};

/// The two response headers a native AWS Bedrock endpoint ALWAYS emits (lowercase on the wire):
/// the per-request id the AWS SDK surfaces via `*Output::request_id()`, and the error-type header
/// the SDK reads BEFORE the body `__type` for typed-exception dispatch. Defined here (the Bedrock
/// dialect's home) and used within this module; surfaced externally only via the writer vtable
/// (`BedrockWriter::ingress_response_request_id` / `ingress_relayed_response_header_names`), so
/// the production sites that capture, forward, or synthesize these headers cannot drift on spelling.
const HDR_AMZN_REQUEST_ID: &str = "x-amzn-requestid";
const HDR_AMZN_ERROR_TYPE: &str = "x-amzn-errortype";

/// The four AWS Bedrock Converse exception names that appear in BOTH the request-level error path
/// (`error_kind_to_bedrock_type`) and the stream-exception path (`bedrock_stream_exception_for`).
/// Named so both functions reference the same const rather than repeating bare literals that could
/// silently diverge on a typo; the single-use exception names in those functions are left bare.
const EXC_THROTTLING: &str = "ThrottlingException";
const EXC_VALIDATION: &str = "ValidationException";
const EXC_SERVICE_UNAVAILABLE: &str = "ServiceUnavailableException";
const EXC_INTERNAL_SERVER: &str = "InternalServerException";

/// The binary framing content-type that AWS Bedrock Converse streaming uses. Both the response
/// `Content-Type` and the egress `Accept` header for a `ConverseStream` call must carry exactly
/// this value; named so neither site can silently diverge.
const APPLICATION_VND_AMAZON_EVENTSTREAM: &str = "application/vnd.amazon.eventstream";

/// The Bedrock-side spelling of the "overloaded" error type that AWS's own error responses carry
/// in their `__type` field (`ServiceUnavailableException` maps back to this on a round-trip).
/// Distinguished from `busbar_contract::protocol::KIND_OVERLOADED` ("overloaded"), which is busbar's own
/// internal kind vocabulary. Both map to `ServiceUnavailableException` via
/// `error_kind_to_bedrock_type`; named here so the match arm is a const pattern rather than a
/// bare literal.
const ERR_TYPE_OVERLOADED: &str = busbar_contract::protocol::ERR_TYPE_OVERLOADED;

/// Map busbar's generic error `kind` vocabulary to the AWS Bedrock Converse exception name carried
/// in `__type`. AWS's Converse error model is a fixed, closed set of exception shapes
/// (`ValidationException`, `ThrottlingException`, `AccessDeniedException`, `ResourceNotFoundException`,
/// `ModelTimeoutException`, `ServiceUnavailableException`, `InternalServerException`,
/// `ServiceQuotaExceededException`, `ModelErrorException`); a native SDK matches on exactly these.
/// Any kind without a Bedrock-native counterpart falls back to `ValidationException` (the generic
/// client-error shape) — chosen deliberately over a catch-all so the wire `__type` is always a real
/// AWS exception name. This is the inverse of the `__type` token `extract_error` reads back, so a
/// same-protocol error round-trips its structured type.
pub fn error_kind_to_bedrock_type(kind: &str) -> &'static str {
    match kind {
        ERR_TYPE_INVALID_REQUEST | "invalid_request" | "validation" | "bad_request" => {
            EXC_VALIDATION
        }
        ERR_TYPE_RATE_LIMIT | "rate_limit" | "too_many_requests" | "throttling" => EXC_THROTTLING,
        ERR_TYPE_AUTHENTICATION | ERR_TYPE_PERMISSION | "auth" | "forbidden" | "unauthorized" => {
            "AccessDeniedException"
        }
        "not_found" | ERR_TYPE_NOT_FOUND | "model_not_found" => "ResourceNotFoundException",
        busbar_contract::protocol::KIND_TIMEOUT | "model_timeout" => "ModelTimeoutException",
        busbar_contract::protocol::KIND_OVERLOADED
        | ERR_TYPE_OVERLOADED
        | "service_unavailable"
        | "unavailable" => EXC_SERVICE_UNAVAILABLE,
        "quota_exceeded" | "service_quota_exceeded" | ERR_TYPE_INSUFFICIENT_QUOTA => {
            "ServiceQuotaExceededException"
        }
        busbar_contract::protocol::KIND_API_ERROR
        | "internal_error"
        | busbar_contract::protocol::KIND_SERVER_ERROR => EXC_INTERNAL_SERVER,
        // No native Bedrock counterpart: fall back to the generic client-error exception so the
        // wire `__type` is still a real AWS exception name a native SDK can decode.
        _ => EXC_VALIDATION,
    }
}

/// Mint a UUID-v4-shaped request id (`8-4-4-4-12` lowercase hex) for the `x-amzn-RequestId` header a
/// native AWS Bedrock response always carries — on EVERY response, success and error, stream and
/// non-stream (the AWS SDK exposes it via `*Output::request_id()`; an absent header makes that return
/// `None`, which is impossible with a real endpoint and a deterministic proxy tell). Uses the OS
/// CSPRNG; returns `None` (so the caller simply OMITS the header) if entropy is unavailable — this is
/// on the request path and must never panic. Single source of truth: every path — success
/// (`proto/mod.rs` via `wrap_buffered_as_stream` / `proxy engine` via `maybe_attach_response_request_id`)
/// and error (`proxy::ingress_error` and the `main.rs` fallback, both via
/// `attach_bedrock_error_headers`) — reaches this through the writer vtable, so there are no private
/// copies.
pub fn synth_amzn_request_id() -> Option<String> {
    let mut buf = [0u8; 16];
    if !super::synth_rng::fill_entropy(&mut buf) {
        return None;
    }
    // RFC 4122 v4 layout (version + variant bits) so the value is a well-formed UUID.
    buf[6] = (buf[6] & 0x0f) | 0x40;
    buf[8] = (buf[8] & 0x3f) | 0x80;
    // One allocation for the 32-char lowercase hex string (was 17+ via per-byte `format!`).
    let s = crate::hex::encode(buf);
    Some(format!(
        "{}-{}-{}-{}-{}",
        &s[0..8],
        &s[8..12],
        &s[12..16],
        &s[16..20],
        &s[20..32]
    ))
}

/// Attach the `x-amzn-RequestId` and `x-amzn-errortype` headers a native AWS Bedrock error response
/// ALWAYS carries to an already-built response. `x-amzn-errortype` mirrors the body `__type` (via
/// `error_kind_to_bedrock_type`, the single source of truth) so header and body agree; the request
/// id is the only request-id surface the AWS SDK exposes via `*Output::request_id()`. This module-
/// private helper is the single source of those headers, dispatched through the
/// `BedrockWriter::attach_error_response_headers` vtable method — the only caller; `proxy engine::
/// ingress_error`, `ingress`, and `auth.rs` reach it through that vtable (not by name), so they
/// cannot drift on which headers a Bedrock error must carry. Best-effort: if entropy or header
/// encoding fails we skip that header rather than panic — this runs on the request path.
fn attach_bedrock_error_headers(headers: &mut busbar_contract::http::HeaderMap, kind: &str) {
    if let Some(id) = synth_amzn_request_id() {
        if let Ok(hv) = HeaderValue::from_str(&id) {
            headers.insert(HeaderName::from_static(HDR_AMZN_REQUEST_ID), hv);
        }
    }
    let errortype = error_kind_to_bedrock_type(kind);
    if let Ok(hv) = HeaderValue::from_str(errortype) {
        headers.insert(HeaderName::from_static(HDR_AMZN_ERROR_TYPE), hv);
    }
}

/// Map a mid-stream `IrError` to the native AWS Converse *ConverseStream output-union* member name
/// the SDK's stream decoder recognizes, plus the human-readable message.
///
/// This is DISTINCT from `error_kind_to_bedrock_type` (which maps the full closed set of
/// REQUEST-level / HTTP Converse exceptions). The ConverseStream response is a Smithy event stream
/// whose modeled mid-stream error events are a SMALLER, fixed union of exactly five shapes:
/// `InternalServerException`, `ModelStreamErrorException`, `ValidationException`,
/// `ThrottlingException`, and `ServiceUnavailableException`. Request-level shapes such as
/// `ModelTimeoutException`, `AccessDeniedException`, and `ServiceQuotaExceededException` are NOT
/// members of that union: a native AWS SDK ConverseStream decoder sees such an `:exception-type`,
/// fails to match it against the stream union, and treats it as an unknown/unmodeled event — so it
/// can never raise the typed mid-stream exception (an indistinguishability tell). We therefore fold
/// every error class onto one of the five legal stream members:
///
/// - `RateLimit` → `ThrottlingException`
/// - `Overloaded` → `ServiceUnavailableException`
/// - `ClientError` / `ContextLength` → `ValidationException`
/// - `Timeout` → `ModelStreamErrorException` (the stream-internal failure shape)
/// - `Auth` / `Billing` / `ServerError` / `Network` → `InternalServerException`
///
/// `Auth` and `Billing` have no stream-union counterpart, so they fold into the generic
/// `InternalServerException` rather than leaking a request-level name onto the stream. Each class is
/// matched explicitly — no catch-all — so a new `StatusClass` variant fails to compile here.
///
/// Shared by `write_response_exception` (the StreamTranslate exception-frame path) and the fallback
/// `write_response_event` Error arm (also a stream-output context) so both stay consistent. The
/// message prefers the upstream's `provider_signal`, falling back to the exception name.
fn bedrock_stream_exception_for(
    err: &busbar_contract::protocol::IrError,
) -> (&'static str, String) {
    let exception_name = match err.class {
        StatusClass::RateLimit => EXC_THROTTLING,
        StatusClass::Overloaded => EXC_SERVICE_UNAVAILABLE,
        StatusClass::ClientError | StatusClass::ContextLength => EXC_VALIDATION,
        StatusClass::Timeout => "ModelStreamErrorException",
        StatusClass::Auth
        | StatusClass::Billing
        | StatusClass::ServerError
        | StatusClass::Network => EXC_INTERNAL_SERVER,
    };
    let message = err
        .provider_signal
        .clone()
        .unwrap_or_else(|| exception_name.to_string());
    (exception_name, message)
}

/// `extra` key under which the Bedrock reader stashes the positions of native Converse `cachePoint`
/// content blocks (the prompt-cache markers, `{"cachePoint": {"type": "default"}}`) that appear
/// INSIDE the `system` array and inside each message's `content` array.
///
/// A `cachePoint` block has NO IR `IrBlock` counterpart (the IR models only
/// Text/Thinking/ToolUse/ToolResult/Image), so without this capture the reader silently DROPPED
/// every `cachePoint` on a same-protocol Bedrock passthrough — disabling prompt caching the caller
/// explicitly requested and turning a cache HIT into a full re-bill of the cached prefix on every
/// turn (a real cost regression). It is a Bedrock-NATIVE marker with no cross-protocol meaning, so
/// stashing it in `extra` is exactly right: it survives a same-protocol round-trip and is correctly
/// dropped on the cross-protocol seam (where `extra` is cleared) rather than leaking a Bedrock-only
/// token onto a foreign wire.
///
/// The stash records each block's ORIGINAL absolute index in its native array so `write_request`
/// can splice it back at the same position. Shape:
/// ```json
/// {
///   "system":   [ { "i": <usize>, "block": <cachePoint value> }, ... ],
///   "messages": [ { "m": <usize>, "i": <usize>, "block": <cachePoint value> }, ... ]
/// }
/// ```
/// The leading `__busbar` prefix keeps it from colliding with any real Bedrock top-level key, and
/// `write_request` consumes it (never re-emitting it via the trailing extra-merge), so the sentinel
/// never appears on the wire.
const CACHE_POINTS_SENTINEL: &str = "__busbar_bedrock_cache_points";

/// `extra` key under which the Bedrock reader stashes the positions of native Converse `guardContent`
/// content blocks (the inline Guardrails markers, `{"guardContent": {"text": {"text": ...,
/// "qualifiers": [...]}}}` or `{"guardContent": {"image": {...}}}`) that appear INSIDE the `system`
/// array and inside each message's `content` array.
///
/// A `guardContent` block has NO IR `IrBlock` counterpart (the IR models only
/// Text/Thinking/ToolUse/ToolResult/Image): the qualifiers (`grounding_source` / `query` /
/// `guard_content`) that tell Bedrock Guardrails which spans to evaluate are not expressible as a
/// plain Text block. Without this capture the reader silently DROPPED every `guardContent` on a
/// same-protocol Bedrock passthrough — disabling the inline content-classification the caller
/// explicitly requested (a guardrail the operator relies on for safety/compliance no longer sees the
/// marked span), making the proxy behaviourally divergent from a direct AWS call. It is a
/// Bedrock-NATIVE marker with no cross-protocol meaning, so stashing it in `extra` is exactly right:
/// it survives a same-protocol round-trip and is correctly dropped on the cross-protocol seam (where
/// `extra` is cleared) rather than leaking a Bedrock-only token onto a foreign wire.
///
/// The stash records each block's ORIGINAL absolute index in its native array (the same
/// `{ "i": <usize>, "block": <value> }` / `{ "m": <usize>, "i": <usize>, "block": <value> }` shape as
/// the `cachePoint` stash) so `write_request` can splice it back at the same position via the shared
/// `splice_cache_points` helper. The leading `__busbar` prefix keeps it from colliding with any real
/// Bedrock top-level key, and `write_request` consumes it (never re-emitting it via the trailing
/// extra-merge), so the sentinel never appears on the wire.
const GUARD_CONTENT_SENTINEL: &str = "__busbar_bedrock_guard_content";

/// `extra` key under which the Bedrock reader stashes the positions of native Converse `document`
/// and `video` content blocks that appear INSIDE each message's `content` array (a `{"document":
/// {...}}` or `{"video": {...}}` member of the Converse `ContentBlock` union).
///
/// A top-level `document`/`video` block has NO IR `IrBlock` counterpart (the IR models only
/// Text/Thinking/ToolUse/ToolResult/Image/Json): a Converse document (a PDF/CSV/etc. the model
/// reasons over) and a video reference carry format + source (`bytes`/`s3Location`) that no neutral
/// IR block expresses. Without this capture the reader silently DROPPED every top-level document and
/// video block on a same-protocol Bedrock passthrough, making the proxy diverge from a direct AWS
/// call (a caller uploading a PDF for analysis had it vanish). It is a Bedrock-NATIVE block with no
/// cross-protocol meaning, so stashing it in `extra` is exactly right: it survives a same-protocol
/// round-trip and is correctly dropped on the cross-protocol seam (where `extra` is cleared) rather
/// than leaking a Bedrock-only block onto a foreign wire.
///
/// The stash records each block's ORIGINAL absolute index in its message `content` array (the same
/// `{ "m": <usize>, "i": <usize>, "block": <value> }` shape as the `guardContent` stash) so
/// `write_request` splices it back at the same position via the shared `splice_cache_points` helper.
/// The leading `__busbar` prefix keeps it from colliding with any real Bedrock key, and
/// `write_request` consumes it (never re-emitting it via the trailing extra-merge), so the sentinel
/// never appears on the wire.
const DOC_VIDEO_SENTINEL: &str = "__busbar_bedrock_doc_video";

/// AWS Bedrock ConverseStream wire event-type names — the discriminator on every stream frame (the
/// SDK's `:event-type` header, surfaced as the `"type"` tag on busbar's decoded JSON). Named once here
/// so no bare wire literal is scattered across the reader / writer / framing, and so a typo is a
/// COMPILE error rather than a silent frame-type mismatch. The set is closed: a native ConverseStream
/// emits exactly these (exception frames carry their own type names, handled separately).
const ET_MESSAGE_START: &str = "messageStart";
const ET_CONTENT_BLOCK_START: &str = "contentBlockStart";
const ET_CONTENT_BLOCK_DELTA: &str = "contentBlockDelta";
const ET_CONTENT_BLOCK_STOP: &str = "contentBlockStop";
const ET_MESSAGE_STOP: &str = "messageStop";
const ET_METADATA: &str = "metadata";

/// The Bedrock `metadata`-frame `metrics` object and its `latencyMs` field: a native ConverseStream
/// reports the stream's real end-to-end latency here. Named so the framing seam that injects it
/// (`BedrockStreamFraming::inject_streaming_metrics`) carries no bare wire literal.
const FIELD_METRICS: &str = "metrics";
const FIELD_LATENCY_MS: &str = "latencyMs";

/// Source-spelling hint for `top_k` (PF — losslessness). Bedrock carries `top_k` in
/// `additionalModelRequestFields` under two spellings: `top_k` (snake_case) and `topK` (camelCase,
/// the form some model families require). The reader lifts EITHER into the first-class IR `top_k`,
/// but a naive writer always re-emits `top_k` — silently RENAMING a native Bedrock->Bedrock
/// passthrough that arrived as `topK`. Mirroring `MAX_COMPLETION_TOKENS_SENTINEL` in `proto::openai_chat`,
/// the reader stamps this sentinel in `extra` when the source spelling was `topK`; the writer then
/// re-emits `topK` (else canonical `top_k`) and CONSUMES the sentinel so it never reaches the wire.
/// `extra` is cleared on the cross-protocol seam, so cross-protocol egress (no sentinel) always emits
/// the canonical `top_k`. The leading `__busbar` prefix never collides with a real Bedrock field.
const TOP_K_CAMEL_SENTINEL: &str = "__busbar_top_k_camel";

/// Clamp a temperature to Bedrock's native `[0.0, 1.0]` range, returning `(clamped, was_clamped)`
/// where `was_clamped` is `true` iff the clamp ACTUALLY changed the value. Mirrors
/// `anthropic::clamp_temperature_for_anthropic` (PF non-silent clamp): OpenAI / Responses accept
/// temperature up to 2.0, so a cross-protocol request can carry a value Bedrock's API rejects with a
/// hard 400 ValidationException; the writer forwards the closest valid value instead of bouncing the
/// request, and uses `was_clamped` to emit a `warn!` so the mutation is NOT silent. Factored out so
/// the non-silent-on-change contract is unit-testable without a tracing subscriber.
fn clamp_temperature_for_bedrock(temperature: f64) -> (f64, bool) {
    // Totality guard, mirroring `anthropic::clamp_temperature_for_anthropic`: a non-finite value
    // (NaN/±Inf) is unreachable via valid JSON (sonic_rs rejects it at parse), but `f64::clamp`
    // would return NaN and `NaN != NaN` would spuriously report `was_clamped`. Pass it through
    // unchanged with `was_clamped == false` so the helper is total and the two siblings agree.
    if !temperature.is_finite() {
        return (temperature, false);
    }
    let clamped = temperature.clamp(0.0, 1.0);
    (clamped, clamped != temperature)
}

/// Read a native Bedrock Converse `reasoningContent` content block into an IR `Thinking` block, or
/// `None` when the block carries neither known member (forward-compatibility: a future
/// `reasoningContent` union member is left undecoded rather than mis-mapped).
///
/// The Converse `reasoningContent` union has two members:
///   - `reasoningText` (`{ "text", "signature" }`) → `Thinking { text, signature }` (the common case;
///     `signature` is the model's opaque reasoning token, preserved verbatim for a faithful
///     round-trip — Bedrock requires it echoed back on a follow-up turn).
///   - `redactedContent` (opaque base64 bytes) → `Thinking { text: <bytes>, redacted: true }` so the
///     writer can re-emit `redactedContent` rather than leaking the bytes as a plaintext
///     `reasoningText`; non-Bedrock writers (no native analog) DROP the typed redacted block.
///
/// Mirrors anthropic.rs `read_block`'s `"thinking"` arm (text + optional signature → `Thinking`).
fn read_bedrock_reasoning_block(reasoning: &serde_json::Value) -> Option<crate::ir::IrBlock> {
    if let Some(reasoning_text) = reasoning.get("reasoningText") {
        let text = reasoning_text
            .get("text")
            .and_then(|t| t.as_str())
            .unwrap_or("")
            .to_string();
        // IR-18: a busbar provenance envelope (another family's signature handed to this client
        // earlier) restores the original bytes and origin; a genuine Converse signature's origin
        // is left for the caller to derive from the model id.
        let (signature, signature_origin) = crate::ir::sig_envelope::read_carried_opt(
            reasoning_text
                .get("signature")
                .and_then(|s| s.as_str().map(String::from)),
            None,
        );
        return Some(crate::ir::IrBlock::Thinking {
            text,
            signature,
            redacted: false,
            cache_control: None,
            kind: None,
            signature_origin,
        });
    }
    if let Some(redacted) = reasoning.get("redactedContent").and_then(|r| r.as_str()) {
        return Some(crate::ir::IrBlock::Thinking {
            text: redacted.to_string(),
            signature: None,
            redacted: true,
            cache_control: None,
            kind: None,
            signature_origin: None,
        });
    }
    None
}

/// Build a native Bedrock Converse `reasoningContent` content block (`{"reasoningContent": ...}`) from
/// an IR `Thinking { text, signature }` — the inverse of `read_bedrock_reasoning_block`.
///
/// A REDACTED `Thinking` (`redacted == true`) re-emits the opaque `redactedContent` member (the bytes
/// are in `text`); any other `Thinking` re-emits a `reasoningText` member, attaching `signature` only
/// when present (Bedrock omits the field for an unsigned reasoning block rather than emitting
/// `"signature": null`). Used by both `write_request` (assistant-turn passthrough) and `write_response`
/// (model reasoning output).
fn bedrock_reasoning_block(
    text: &str,
    signature: &Option<String>,
    redacted: bool,
) -> serde_json::Value {
    if redacted {
        return serde_json::json!({ "reasoningContent": { "redactedContent": text } });
    }
    let mut reasoning_text = serde_json::Map::new();
    reasoning_text.insert("text".to_string(), serde_json::json!(text));
    if let Some(sig) = signature {
        reasoning_text.insert("signature".to_string(), serde_json::json!(sig));
    }
    serde_json::json!({ "reasoningContent": { "reasoningText": serde_json::Value::Object(reasoning_text) } })
}

/// Build a native Bedrock Converse `image` block body (`{ "format", "source": { … } }`) from a typed
/// IR `IrImageSource`, or `None` when the image cannot be represented natively.
///
/// The Bedrock Converse `image` block has only two source shapes: `source.bytes` (base64) and
/// `source.s3Location` (an S3 URI). It has NO arbitrary-URL source. The typed `IrImageSource` maps
/// cleanly onto this:
///   - `Base64 { media_type, data }` → `source.bytes`, normalizing the MIME subtype onto Converse's
///     `ImageFormat` union {png, jpeg, gif, webp} (jpg→jpeg; unknown→png with a warn).
///   - `Vendor { vendor: "bedrock", value }` → `source.s3Location` re-emitted faithfully (the reader
///     captured a native `s3Location` source here, preserving `uri`/`bucketOwner` for a lossless
///     same-protocol round-trip).
///   - `Url(_)` (no Converse arbitrary-URL source) and a FOREIGN `Vendor` (e.g. a Responses `file_id`)
///     have no native projection — DROP with a warn rather than emit a corrupt `bytes` block.
fn bedrock_image_block(source: &crate::ir::IrImageSource) -> Option<serde_json::Value> {
    match source {
        // A Bedrock-produced vendor reference is an `s3Location` (stored as `{format, s3Location}`);
        // re-emit it faithfully. A vendor reference from ANOTHER protocol has no Bedrock projection.
        crate::ir::IrImageSource::Vendor { vendor, value } if *vendor == "bedrock" => {
            let format_str = value
                .get("format")
                .and_then(|f| f.as_str())
                .filter(|s| !s.is_empty())
                .unwrap_or("png");
            let s3_location = value
                .get("s3Location")
                .cloned()
                .unwrap_or_else(|| serde_json::Value::Object(serde_json::Map::new()));
            Some(serde_json::json!({
                "format": format_str,
                "source": { "s3Location": s3_location }
            }))
        }
        // Bedrock Converse has no arbitrary-URL image source, and a foreign vendor reference (a
        // Responses file_id) has no Converse projection — emitting either as base64 `bytes` would
        // corrupt the block. Drop with a warn.
        crate::ir::IrImageSource::Url(_) | crate::ir::IrImageSource::Vendor { .. } => {
            tracing::warn!(
                "dropping image with no Bedrock Converse projection (URL or foreign vendor ref)"
            );
            None
        }
        crate::ir::IrImageSource::Base64 { media_type, data } => {
            // Map the MIME subtype onto a member of Bedrock Converse's `ImageFormat` union
            // {png, jpeg, gif, webp}. `image/jpg` (and casing variants) is NOT a member — Bedrock
            // spells it `jpeg` — so emitting it verbatim 400s a valid client image. Normalize
            // jpg→jpeg; an empty/unsupported subtype coerces to `png` (with a warn) to keep the block
            // valid rather than emit a `format: ""` the SDK rejects.
            let format_str = match media_type.strip_prefix("image/").filter(|s| !s.is_empty()) {
                Some(subtype) => match subtype.to_ascii_lowercase().as_str() {
                    "jpeg" | "jpg" => "jpeg",
                    "png" => "png",
                    "gif" => "gif",
                    "webp" => "webp",
                    _ => {
                        tracing::warn!(
                            media_type = %media_type,
                            "coercing unsupported image subtype to format=png: not a member of \
                             Bedrock Converse's ImageFormat union {{png, jpeg, gif, webp}}"
                        );
                        "png"
                    }
                },
                None => {
                    tracing::warn!(
                        media_type = %media_type,
                        "coercing malformed image media_type to format=png: not a well-formed \
                         'image/<subtype>'"
                    );
                    "png"
                }
            };
            Some(serde_json::json!({
                "format": format_str,
                "source": { "bytes": data }
            }))
        }
    }
}

/// The `vendor` tag on an [`crate::ir::IrImageSource::Vendor`] this protocol produces — a Bedrock
/// `s3Location` document/video/image source, which names an S3 object in the CALLER's AWS account
/// and is meaningless to any other backend.
const VENDOR_NAME: &str = "bedrock";

/// Read a native Converse `document` / `video` block body into an [`crate::ir::IrBlock::Media`].
///
/// Converse spells both the same way — `{"format": "pdf", "name": "…", "source": {…}}` — with a
/// `source` union of inline `bytes` or an `s3Location`. `format` is a bare container token, so it is
/// normalized to a real mime type here (the neutral IR speaks mime; every other dialect does too)
/// and the writer reverses it exactly.
fn bedrock_media_block(
    kind: crate::ir::IrMediaKind,
    value: &serde_json::Value,
) -> crate::ir::IrBlock {
    let format = value.get("format").and_then(|v| v.as_str()).unwrap_or("");
    let name = value
        .get("name")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(String::from);
    let source = value.get("source");
    let ir_source = match source.and_then(|s| s.get("bytes")).and_then(|b| b.as_str()) {
        Some(bytes) => crate::ir::IrImageSource::Base64 {
            media_type: bedrock_media_type_for_format(kind, format),
            data: bytes.to_string(),
        },
        // BED-03: a TEXT document (`source.text`, or the chunked `source.content[].text`) is
        // plain text every dialect can carry as an inline text document. It becomes a real
        // base64-encoded text document (the IR's `Base64.data` contract), NOT a bedrock Vendor
        // reference no foreign writer can re-emit.
        None if bedrock_document_text(source).is_some() => crate::ir::IrImageSource::Base64 {
            media_type: bedrock_text_media_type(format),
            data: busbar_contract::media::base64_encode(
                bedrock_document_text(source).unwrap_or_default().as_bytes(),
            ),
        },
        // An `s3Location` names an object in the caller's own AWS account: no other backend can
        // fetch it, so it rides the opaque `Vendor` escape and only this writer re-emits it.
        None => crate::ir::IrImageSource::Vendor {
            vendor: VENDOR_NAME,
            value: source.cloned().unwrap_or_else(|| serde_json::json!({})),
        },
    };
    // IR-12: a Converse `DocumentBlock` carries the same two attachment controls Anthropic's
    // document block does — `citations: {enabled}` and a free-text `context`. `VideoBlock` has
    // neither, so they are read off a document only.
    let (citations, context) = if kind == crate::ir::IrMediaKind::Document {
        (
            value
                .get("citations")
                .and_then(|c| c.get("enabled"))
                .and_then(|e| e.as_bool()),
            value
                .get("context")
                .and_then(|c| c.as_str())
                .map(String::from),
        )
    } else {
        (None, None)
    };
    crate::ir::IrBlock::Media {
        kind,
        source: ir_source,
        name,
        cache_control: None,
        citations,
        context,
    }
}

/// The inline text of a Converse `DocumentSource` that carries text rather than bytes: `text` (a
/// plain string) or `content` (an array of `{text}` chunks, joined by newlines). `None` for a
/// bytes/s3 source.
fn bedrock_document_text(source: Option<&serde_json::Value>) -> Option<String> {
    let source = source?;
    if let Some(t) = source.get("text").and_then(|t| t.as_str()) {
        return Some(t.to_string());
    }
    let parts: Vec<&str> = source
        .get("content")?
        .as_array()?
        .iter()
        .filter_map(|p| p.get("text").and_then(|t| t.as_str()))
        .collect();
    (!parts.is_empty()).then(|| parts.join("\n"))
}

/// The mime type of a TEXT document source: the format's own text type when it names one (`md`,
/// `csv`, `html`, `txt`), else `text/plain` — a text source is text whatever container it names.
fn bedrock_text_media_type(format: &str) -> String {
    let m = bedrock_media_type_for_format(crate::ir::IrMediaKind::Document, format);
    if m.starts_with("text/") {
        m
    } else {
        "text/plain".to_string()
    }
}

/// Converse's bare container token (`pdf`, `csv`, `mp4`) → a real mime type for the neutral IR.
/// Unknown tokens fall back to the kind's generic type rather than fabricating `application/<token>`,
/// which would be a mime type that does not exist.
fn bedrock_media_type_for_format(kind: crate::ir::IrMediaKind, format: &str) -> String {
    match format.to_ascii_lowercase().as_str() {
        "pdf" => "application/pdf".to_string(),
        "csv" => "text/csv".to_string(),
        "txt" => "text/plain".to_string(),
        "md" => "text/markdown".to_string(),
        "html" => "text/html".to_string(),
        "doc" => "application/msword".to_string(),
        "docx" => {
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document".to_string()
        }
        "xls" => "application/vnd.ms-excel".to_string(),
        "xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet".to_string(),
        "mp4" | "mov" | "webm" | "flv" | "mpeg" | "mpg" | "wmv" | "mkv" => {
            format!("video/{format}")
        }
        "three_gp" => "video/3gpp".to_string(),
        _ => match kind {
            crate::ir::IrMediaKind::Document => "application/octet-stream".to_string(),
            crate::ir::IrMediaKind::Audio => "audio/mpeg".to_string(),
            crate::ir::IrMediaKind::Video => "video/mp4".to_string(),
        },
    }
}

/// Project an [`crate::ir::IrBlock::Media`] into the native Converse content block that carries it,
/// or `None` when Converse has no slot (the caller emits nothing, having warned).
///
/// Converse has a `document` block and a `video` block and NO audio block, and each has a CLOSED
/// format union AWS validates — so an unmappable format is coerced/dropped here rather than sent
/// upstream to be rejected, which is the pattern this writer already applied to images.
fn bedrock_media_content_block(
    kind: crate::ir::IrMediaKind,
    source: &crate::ir::IrImageSource,
    name: Option<&str>,
    citations: Option<bool>,
    context: Option<&str>,
) -> Option<serde_json::Value> {
    let (wire_key, format) = match kind {
        crate::ir::IrMediaKind::Document => ("document", bedrock_document_format(source)?),
        crate::ir::IrMediaKind::Video => ("video", bedrock_video_format(source)?),
        crate::ir::IrMediaKind::Audio => {
            tracing::warn!(
                "dropping audio attachment on Bedrock egress: Converse has `document` and `video` \
                 content blocks and NO audio block, so there is no native slot; the block is NOT \
                 emitted"
            );
            return None;
        }
    };
    let wire_source = match source {
        crate::ir::IrImageSource::Base64 { data, .. } => serde_json::json!({ "bytes": data }),
        crate::ir::IrImageSource::Vendor { vendor, value } if *vendor == VENDOR_NAME => {
            value.clone()
        }
        crate::ir::IrImageSource::Url(_) | crate::ir::IrImageSource::Vendor { .. } => {
            tracing::warn!(
                media_kind = kind.as_str(),
                "dropping attachment on Bedrock egress: Converse has no arbitrary-URL source and \
                 cannot resolve a foreign vendor file handle; the block is NOT emitted"
            );
            return None;
        }
    };
    let mut block = serde_json::Map::new();
    block.insert("format".to_string(), serde_json::json!(format));
    // Converse REQUIRES `name` on a document block. A cross-protocol attachment often has none
    // (Gemini `inlineData` carries no filename), so synthesize one rather than emit a block AWS
    // rejects for a missing required field.
    if kind == crate::ir::IrMediaKind::Document {
        block.insert(
            "name".to_string(),
            serde_json::json!(name.unwrap_or("attachment")),
        );
    } else if let Some(n) = name {
        block.insert("name".to_string(), serde_json::json!(n));
    }
    block.insert("source".to_string(), wire_source);
    // IR-12: the document's citation switch and context ride Converse's `DocumentBlock` natively.
    // A `VideoBlock` has no such members, so on a video they are dropped (with a warn when set).
    if kind == crate::ir::IrMediaKind::Document {
        if let Some(c) = context {
            block.insert("context".to_string(), serde_json::json!(c));
        }
        if let Some(enabled) = citations {
            block.insert(
                "citations".to_string(),
                serde_json::json!({ "enabled": enabled }),
            );
        }
    } else if citations.is_some() || context.is_some() {
        tracing::warn!(
            media_kind = kind.as_str(),
            "dropping attachment citations/context on Bedrock egress: Converse carries them on a \
             document block only"
        );
    }
    Some(serde_json::json!({ wire_key: serde_json::Value::Object(block) }))
}

/// Mime type → a member of Converse's closed `DocumentFormat` union, or `None` (drop with a warn)
/// when the attachment is not something Converse will accept as a document.
fn bedrock_document_format(source: &crate::ir::IrImageSource) -> Option<&'static str> {
    // A vendor (s3Location) source carries no mime; Converse still requires a format, and `pdf` is
    // the overwhelmingly common document a caller puts in S3 for a model to read.
    let crate::ir::IrImageSource::Base64 { media_type, .. } = source else {
        return Some("pdf");
    };
    let f = match media_type.to_ascii_lowercase().as_str() {
        "application/pdf" => "pdf",
        "text/csv" => "csv",
        "text/plain" => "txt",
        "text/markdown" | "text/x-markdown" => "md",
        "text/html" => "html",
        "application/msword" => "doc",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document" => "docx",
        "application/vnd.ms-excel" => "xls",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" => "xlsx",
        other => {
            tracing::warn!(
                media_type = %other,
                "dropping document attachment on Bedrock egress: the mime type is not a member of \
                 Converse's DocumentFormat union {{pdf,csv,doc,docx,xls,xlsx,html,txt,md}} and AWS \
                 rejects anything else; the block is NOT emitted"
            );
            return None;
        }
    };
    Some(f)
}

/// Mime type → a member of Converse's closed `VideoFormat` union, or `None` (drop with a warn).
fn bedrock_video_format(source: &crate::ir::IrImageSource) -> Option<&'static str> {
    let crate::ir::IrImageSource::Base64 { media_type, .. } = source else {
        return Some("mp4");
    };
    let subtype = media_type
        .to_ascii_lowercase()
        .strip_prefix("video/")
        .map(String::from);
    let f = match subtype.as_deref() {
        Some("mp4") => "mp4",
        Some("quicktime") | Some("mov") => "mov",
        Some("webm") => "webm",
        Some("x-flv") | Some("flv") => "flv",
        Some("mpeg") | Some("mpg") => "mpeg",
        Some("x-ms-wmv") | Some("wmv") => "wmv",
        Some("x-matroska") | Some("mkv") => "mkv",
        Some("3gpp") => "three_gp",
        _ => {
            tracing::warn!(
                media_type = %media_type,
                "dropping video attachment on Bedrock egress: the mime type is not a member of \
                 Converse's VideoFormat union; the block is NOT emitted"
            );
            return None;
        }
    };
    Some(f)
}

/// Build a native Bedrock Converse prompt-cache marker block (`{"cachePoint": {"type": "default"}}`).
///
/// This is the Converse content-block / tool-list element AWS uses to mark a prompt-cache boundary:
/// everything BEFORE the marker (in the same `system` / message `content` / `toolConfig.tools` array)
/// is cached as a prefix. The IR carries the equivalent boundary as a first-class `cache_control`
/// field ON a block / tool (set by e.g. the Anthropic reader); the Bedrock writer projects that field
/// to this marker emitted IMMEDIATELY AFTER the block / tool it applies to, which is the position
/// Bedrock expects (the breakpoint sits after the content it closes). Factored out so the one marker
/// shape has a single definition and the cross-protocol write path is unit-testable.
fn bedrock_cache_point() -> serde_json::Value {
    serde_json::json!({ "cachePoint": { "type": "default" } })
}

/// Read a native reasoning ASK off a Converse `additionalModelRequestFields` object (BED-06). Two
/// model-family spellings ride there:
///   * Anthropic-on-Bedrock `thinking`, read exactly as the Anthropic reader reads its own:
///     `{type: "enabled", budget_tokens: N}` → `Budget(N)`; `{type: "adaptive"}` → `Effort(<the
///     output_config.effort word>)` when one is given, else `Dynamic`; no `thinking` but an
///     `output_config.effort` word → `Effort(word)`; `{type: "disabled"}` → `Off` (IR-09).
///   * Amazon Nova `reasoningConfig: {type: "enabled", maxReasoningEffort: "low"|"medium"|"high"}`
///     → `Effort`, and `{type: "disabled"}` → `Off`.
///
/// Anything else (malformed, an unknown type) is no ask.
fn read_bedrock_reasoning_ask(
    amrf: Option<&serde_json::Map<String, serde_json::Value>>,
) -> Option<crate::ir::IrReasoningAsk> {
    use crate::ir::IrReasoningAsk as Ask;
    let amrf = amrf?;
    let type_of = |v: &serde_json::Value| v.get("type").and_then(|t| t.as_str()).map(String::from);
    let effort = amrf
        .get("output_config")
        .and_then(|c| c.get("effort"))
        .and_then(|e| e.as_str())
        .and_then(read_bedrock_claude_effort_word);
    if let Some(thinking) = amrf.get("thinking") {
        return match type_of(thinking).as_deref() {
            Some("enabled") => thinking
                .get("budget_tokens")
                .and_then(|v| v.as_u64())
                .and_then(|v| u32::try_from(v).ok())
                .map(Ask::Budget),
            Some(THINKING_TYPE_ADAPTIVE) => Some(effort.map(Ask::Effort).unwrap_or(Ask::Dynamic)),
            Some(THINKING_TYPE_DISABLED) => Some(Ask::Off),
            _ => None,
        };
    }
    if let Some(rc) = amrf.get("reasoningConfig") {
        return match type_of(rc).as_deref() {
            Some("enabled") => rc
                .get("maxReasoningEffort")
                .and_then(|e| e.as_str())
                .and_then(crate::ir::IrReasoningEffort::parse)
                .map(Ask::Effort),
            Some(THINKING_TYPE_DISABLED) => Some(Ask::Off),
            _ => None,
        };
    }
    effort.map(Ask::Effort)
}

/// Claude's adaptive-thinking `thinking.type` (Anthropic-on-Bedrock spells it as Anthropic does).
const THINKING_TYPE_ADAPTIVE: &str = "adaptive";
/// Reasoning explicitly switched off (Claude `thinking.type`, Nova `reasoningConfig.type`).
const THINKING_TYPE_DISABLED: &str = "disabled";

/// Claude `output_config.effort` word (Anthropic-on-Bedrock) → IR effort. The Claude scale is
/// `low` / `medium` / `high` / `xhigh` / `max` (IR-09 carries all five).
fn read_bedrock_claude_effort_word(word: &str) -> Option<crate::ir::IrReasoningEffort> {
    match word {
        "minimal" => None,
        other => crate::ir::IrReasoningEffort::parse_extended(other),
    }
}

/// IR effort → Claude `output_config.effort` word. Claude has no `minimal`; the nearest is `low`.
fn bedrock_claude_effort_word(effort: crate::ir::IrReasoningEffort) -> &'static str {
    match effort {
        crate::ir::IrReasoningEffort::Minimal => "low",
        other => other.as_str(),
    }
}

/// Read Converse's native structured-output directive, `outputConfig.textFormat` (`{type:
/// "json_schema", structure: {jsonSchema: {schema: "<JSON as a string>", name, description}}}`),
/// into the typed [`crate::ir::IrResponseFormat`] (BED-08). The schema travels as a STRING on this
/// wire; an unparseable one yields no directive rather than a guessed one.
fn read_bedrock_response_format(
    body: &serde_json::Map<String, serde_json::Value>,
) -> Option<crate::ir::IrResponseFormat> {
    let tf = body.get("outputConfig")?.get("textFormat")?;
    if tf.get("type").and_then(|t| t.as_str()) != Some("json_schema") {
        return None;
    }
    let js = tf.get("structure")?.get("jsonSchema")?;
    let schema: serde_json::Value = serde_json::from_str(js.get("schema")?.as_str()?).ok()?;
    Some(crate::ir::IrResponseFormat {
        json: true,
        schema: Some(schema),
        name: js.get("name").and_then(|n| n.as_str()).map(String::from),
        strict: None,
        description: js
            .get("description")
            .and_then(|d| d.as_str())
            .map(String::from),
    })
}

/// Project the typed [`crate::ir::IrResponseFormat`] into Converse's `outputConfig.textFormat`
/// (BED-08), or `None` when Converse has no shape for it: its `OutputFormat.type` enum is
/// `json_schema` only, so a schema-less JSON mode and plain-text mode have no native form.
fn write_bedrock_text_format(rf: &crate::ir::IrResponseFormat) -> Option<serde_json::Value> {
    if !rf.json {
        return None;
    }
    let schema = rf.schema.as_ref()?;
    let mut js = serde_json::Map::new();
    js.insert("schema".to_string(), serde_json::json!(schema.to_string()));
    if let Some(n) = rf.name.as_deref().filter(|s| !s.is_empty()) {
        js.insert("name".to_string(), serde_json::json!(n));
    }
    if let Some(d) = rf.description.as_deref().filter(|s| !s.is_empty()) {
        js.insert("description".to_string(), serde_json::json!(d));
    }
    Some(serde_json::json!({
        "type": "json_schema",
        "structure": { "jsonSchema": serde_json::Value::Object(js) }
    }))
}

/// Read the `cache_control` off the LAST block pushed onto an IR content vector, used by the Bedrock
/// reader to map a native `cachePoint` adjacency back onto the preceding block's first-class IR
/// `cache_control` field (so a Bedrock->Bedrock and Bedrock->Anthropic round-trip preserves the
/// prompt-cache boundary cross-protocol, not only via the positional `CACHE_POINTS_SENTINEL` stash
/// which is dropped on the cross-protocol seam). Only the block kinds that carry a `cache_control`
/// field (every kind but `Json`) can hold the boundary; a `cachePoint` following a `Json` block is
/// left to the positional stash alone. Setting the field is
/// idempotent and additive: it does NOT disable the same-protocol stash, so byte-identical
/// same-protocol round-trips are unaffected (the writer suppresses the inline emission whenever the
/// stash is present — see `write_request`).
fn set_preceding_block_cache_control(blocks: &mut [crate::ir::IrBlock]) {
    if let Some(last) = blocks.last_mut() {
        let cc = Some(crate::ir::CacheControl {
            kind: crate::ir::CacheKind::Ephemeral,
        });
        match last {
            // BED-07: Thinking / Image / Media carry a first-class `cache_control` too, so a
            // cachePoint after a reasoning block or an attachment is a boundary a foreign dialect
            // can express — it lands on that block exactly as it does on Text.
            crate::ir::IrBlock::Text { cache_control, .. }
            | crate::ir::IrBlock::ToolUse { cache_control, .. }
            | crate::ir::IrBlock::ToolResult { cache_control, .. }
            | crate::ir::IrBlock::Thinking { cache_control, .. }
            | crate::ir::IrBlock::Image { cache_control, .. }
            | crate::ir::IrBlock::Media { cache_control, .. } => {
                *cache_control = cc;
            }
            // Json is a tool-result member only; the positional stash carries the marker.
            crate::ir::IrBlock::Json(_) => {}
        }
    }
}

/// Splice captured `cachePoint` blocks back into a freshly-written content array at the ORIGINAL
/// absolute positions the reader recorded, reconstructing the native ordering on a same-protocol
/// passthrough. `entries` are the per-array stash records (`{ "i": <usize>, "block": <value> }`)
/// pulled from the `CACHE_POINTS_SENTINEL` object; a record missing `i`/`block`, or whose index
/// exceeds the current array length, is skipped rather than mis-placed (defensive — the reader
/// always writes both fields with an in-range index, but `extra` survives an arbitrary
/// cross-protocol hop and an out-of-range index must never panic on the request path).
///
/// Records are applied in ASCENDING index order: each insertion shifts later elements right by one,
/// and because the reader recorded indices against the ORIGINAL array (which contained the
/// cachePoints), inserting at the recorded index in ascending order reproduces the original layout
/// exactly. Insertion uses a bounds-clamped `min(len)` so a stale/foreign index lands at the end
/// instead of panicking.
fn splice_cache_points(arr: &mut Vec<serde_json::Value>, entries: &[serde_json::Value]) {
    // Collect (index, block) pairs, then sort by index so ascending insertion preserves layout.
    let mut pending: Vec<(usize, serde_json::Value)> = Vec::new();
    for entry in entries {
        let Some(idx) = entry.get("i").and_then(|v| v.as_u64()) else {
            continue;
        };
        let Some(block) = entry.get("block") else {
            continue;
        };
        pending.push((idx as usize, block.clone()));
    }
    pending.sort_by_key(|(idx, _)| *idx);
    for (idx, block) in pending {
        let pos = idx.min(arr.len());
        arr.insert(pos, block);
    }
}

/// Concatenate two optional `{ "i", "block" }` marker-entry slices (e.g. the captured `cachePoint`
/// and `guardContent` stashes for one array) into a single owned `Vec` for a SINGLE `splice_cache_points`
/// pass. Both classes recorded their indices against the SAME original array, so they MUST be spliced
/// together (the helper sorts the combined batch by index): two separate passes would let the first
/// pass's insertions shift the second pass's recorded indices, mis-placing the second class. Either
/// or both inputs may be `None`/empty; the result preserves every entry verbatim.
fn merge_marker_entries(
    a: Option<&Vec<serde_json::Value>>,
    b: Option<&Vec<serde_json::Value>>,
) -> Vec<serde_json::Value> {
    let mut out: Vec<serde_json::Value> = Vec::new();
    if let Some(entries) = a {
        out.extend_from_slice(entries);
    }
    if let Some(entries) = b {
        out.extend_from_slice(entries);
    }
    out
}

/// The DECLARED SigV4 region of an upstream `host` ([`EgressScheme::SigV4`]'s `region_of_host`):
/// [`derive_sigv4_region`], with the operator warning the signer has always given when a host names
/// no region and the scope falls back to the declared `us-east-1`. Read once per signature.
fn declared_sigv4_region(host: &str) -> Option<&str> {
    let region = derive_sigv4_region(host);
    if region.is_none() {
        tracing::warn!(host = %host, "could not derive AWS region from Bedrock endpoint host; defaulting SigV4 scope to us-east-1 (set a bedrock-runtime[-fips].<region>.amazonaws.com host)");
    }
    region
}

/// Derive the AWS region for SigV4 scope from a Bedrock endpoint host.
///
/// AWS resolves the signing region from the endpoint, not from a single hard-coded prefix. A naive
/// `strip_prefix("bedrock-runtime.")` mis-handles every non-vanilla endpoint shape and silently
/// signs for the wrong region, which AWS rejects with `SignatureDoesNotMatch` — surfaced as a
/// confusing 403 the operator cannot distinguish from a credential error. We therefore match the
/// known Bedrock service labels (with or without the `-fips` qualifier) and any VPC-interface
/// (`vpce`) front, taking the dotted label that immediately follows the service label as the region:
///
///   - `bedrock-runtime.<region>.amazonaws.com`
///   - `bedrock-runtime-fips.<region>.amazonaws.com`
///   - `bedrock-runtime.<region>.vpce.amazonaws.com`
///   - `vpce-0abc...-1xyz.bedrock-runtime.<region>.vpce.amazonaws.com` (interface-endpoint front)
///   - `bedrock.<region>.amazonaws.com` (the control-plane label, defensively)
///
/// Returns `Some(region)` only when a Bedrock service label is found AND the following label looks
/// like an AWS region token (one or more alphabetic dash-parts then a numeric part, e.g.
/// `us-east-1`, `ap-southeast-2`, `eu-central-1`, `us-gov-west-1`, `us-iso-east-1`); otherwise
/// `None`. The caller logs a `tracing::warn!` and falls back to
/// `us-east-1` for `None`, so a mis-derived region is no longer silent. Pure string parsing on a
/// `&str` — no panic, no allocation of the host.
pub(crate) fn derive_sigv4_region(host: &str) -> Option<&str> {
    // An AWS region token: one or more alphabetic dash-parts followed by a final numeric part.
    //   3-part canonical:  us-east-1, ap-southeast-2, eu-central-1, ca-central-1
    //   4-part partitions: us-gov-west-1, us-gov-east-1 (GovCloud), us-iso-east-1, us-isob-east-1
    //                      (ISO), and any future >=3-part naming scheme.
    // We accept any dash token of >= 3 parts whose leading parts are all ASCII-alphabetic and whose
    // FINAL part is all ASCII-digits, so the parser tracks real AWS region shapes regardless of how
    // many middle direction/partition segments AWS adds. We still reject obvious non-regions (a bare
    // label, a 2-part token, an IP octet, a CNAME segment) because they fail the >=3 / alpha+digit
    // structure. The old code hard-required EXACTLY 3 parts, which silently rejected every GovCloud
    // and ISO region and fell the caller back to a wrong `us-east-1` SigV4 scope (403
    // SignatureDoesNotMatch).
    fn looks_like_region(label: &str) -> bool {
        let parts: Vec<&str> = label.split('-').collect();
        // Need at least <area>-<direction>-<number>; no empty parts (rejects leading/trailing/
        // doubled dashes).
        if parts.len() < 3 || parts.iter().any(|p| p.is_empty()) {
            return false;
        }
        let Some((last, leading)) = parts.split_last() else {
            return false;
        };
        last.bytes().all(|x| x.is_ascii_digit())
            && leading
                .iter()
                .all(|p| p.bytes().all(|x| x.is_ascii_alphabetic()))
    }

    // Walk the dotted labels; when we hit a Bedrock service label, the NEXT label is the region.
    let labels: Vec<&str> = host.split('.').collect();
    for (i, label) in labels.iter().enumerate() {
        if matches!(
            *label,
            "bedrock-runtime" | "bedrock-runtime-fips" | "bedrock" | "bedrock-fips"
        ) {
            if let Some(next) = labels.get(i + 1) {
                if looks_like_region(next) {
                    return Some(next);
                }
            }
        }
    }
    None
}

/// Read a native Bedrock Converse `image` content block into an `IrBlock::Image`, or `None` when
/// the block carries no usable source.
///
/// The Converse `ImageSource` union has TWO members: `source.bytes` (base64) and
/// `source.s3Location` (`{"uri":...,"bucketOwner":...}`). The old reader only decoded `bytes`, so an
/// S3-referenced image read with `data = ""` — silently dropping the image, diverging from a direct
/// AWS call and breaking a same-protocol passthrough. We now ALSO probe `source.s3Location` and,
/// when present, carry the whole s3Location object (plus the captured `format`) in the typed
/// `IrImageSource::Vendor { vendor: "bedrock", value }` escape so `bedrock_image_block` can re-emit
/// `source.s3Location` on same-protocol egress (a foreign writer drops the vendor ref). A base64
/// image reads as `IrImageSource::Base64`. A block with neither source yields `None` so a
/// content-less image is not injected as an empty-bytes block.
fn read_bedrock_image_block(image: &serde_json::Value) -> Option<crate::ir::IrBlock> {
    let format_str = image
        .get("format")
        .and_then(|f| f.as_str())
        .unwrap_or("")
        .to_string();
    let source = image.get("source");

    // Prefer inline base64 `bytes`.
    if let Some(bytes) = source.and_then(|s| s.get("bytes")).and_then(|b| b.as_str()) {
        return Some(crate::ir::IrBlock::Image {
            source: crate::ir::IrImageSource::Base64 {
                media_type: format!("image/{}", format_str),
                data: bytes.to_string(),
            },
            cache_control: None,
            detail: None,
        });
    }

    // Otherwise, an `s3Location` source — a Bedrock-scoped reference the typed `S3` variant carries
    // as `{format, s3Location}` so the writer re-emits a faithful `source.s3Location` block on
    // same-protocol egress instead of dropping the image.
    if let Some(s3_location) = source.and_then(|s| s.get("s3Location")) {
        if s3_location.is_object() {
            return Some(crate::ir::IrBlock::Image {
                source: crate::ir::IrImageSource::Vendor {
                    vendor: "bedrock",
                    value: serde_json::json!({
                        "format": format_str,
                        "s3Location": s3_location.clone(),
                    }),
                },
                cache_control: None,
                detail: None,
            });
        }
    }

    None
}

/// Model a Converse `guardContent` block's CONTENT (BED-02): `{text: {text, qualifiers}}` is prompt
/// text and `{image: {format, source}}` is a prompt image — the qualifiers (which spans a guardrail
/// evaluates) have no neutral form and ride only the positional stash. `None` for a block with
/// neither member.
fn guard_content_block(guard: &serde_json::Value) -> Option<crate::ir::IrBlock> {
    if let Some(t) = guard
        .get("text")
        .and_then(|t| t.get("text"))
        .and_then(|t| t.as_str())
    {
        return Some(crate::ir::IrBlock::Text {
            text: t.to_string(),
            cache_control: None,
            citations: Vec::new(),
            refusal: false,
        });
    }
    guard.get("image").and_then(read_bedrock_image_block)
}

/// The IR indices of the blocks the reader MODELLED out of a stashed wire block (the `b` member of a
/// `guardContent` / `document` / `video` stash record), for one message (`Some(m)`) or for the
/// `system` array (`None`). The writer suppresses its own emission of these blocks because the
/// verbatim stash splice re-emits them — that is what keeps a same-protocol round-trip
/// byte-identical while a cross-protocol IR (stash cleared) carries the modelled block.
fn stashed_ir_indices<'a>(
    stashes: impl IntoIterator<Item = Option<&'a Vec<serde_json::Value>>>,
    msg: Option<usize>,
) -> std::collections::BTreeSet<usize> {
    stashes
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| msg.is_none_or(|m| e.get("m").and_then(|v| v.as_u64()) == Some(m as u64)))
        .filter_map(|e| e.get("b").and_then(|v| v.as_u64()))
        .map(|b| b as usize)
        .collect()
}

/// Normalize Bedrock Converse's native `toolConfig.toolChoice` into the IR union.
///
/// Bedrock shape: `{"auto":{}}` → `Auto`, `{"any":{}}` → `Required` (must call some tool),
/// `{"tool":{"name":"X"}}` → the targeted `Tool{name:"X"}`. Bedrock has NO native "none". An
/// absent or unrecognized shape yields `None` (omitted) so a request that never carried a directive
/// does not gain a spurious one. Takes the whole `toolConfig` object so the caller can pass
/// `obj.get("toolConfig")` directly.
fn read_bedrock_tool_choice(
    tool_config: Option<&serde_json::Value>,
) -> Option<crate::ir::IrToolChoice> {
    let tc = tool_config?.get("toolChoice")?.as_object()?;
    if tc.contains_key("auto") {
        Some(crate::ir::IrToolChoice::Auto)
    } else if tc.contains_key("any") {
        Some(crate::ir::IrToolChoice::Required)
    } else if let Some(tool) = tc.get("tool") {
        tool.get("name")
            .and_then(|n| n.as_str())
            .map(|name| crate::ir::IrToolChoice::Tool {
                name: name.to_string(),
            })
    } else {
        None
    }
}

/// Emit the IR tool-choice union in Bedrock's native `toolChoice` shape.
///
/// Returns `None` for `IrToolChoice::None`: Bedrock Converse has no native "don't call a tool"
/// directive, so the closest faithful behavior is to omit `toolChoice` entirely (the backend then
/// applies its own default) rather than emit an invalid shape.
fn write_bedrock_tool_choice(tc: &crate::ir::IrToolChoice) -> Option<serde_json::Value> {
    match tc {
        crate::ir::IrToolChoice::Auto => Some(serde_json::json!({"auto": {}})),
        crate::ir::IrToolChoice::Required => Some(serde_json::json!({"any": {}})),
        crate::ir::IrToolChoice::Tool { name } => {
            // AWS documents `toolChoice.tool` (force this SPECIFIC tool) as Anthropic-Claude-only
            // on Converse — Titan/Llama/other model families reject it. The writer cannot gate on
            // the model: `write_request(&self, req: &IrRequest)` receives only the IR, which has no
            // `model` field (Bedrock carries the model in the URL, not the body). A real fix needs
            // new `EgressPrep` capability plumbing — out of scope here; emit it (the common case,
            // Claude-on-Bedrock, is unaffected) and warn so a non-Claude target's guaranteed
            // ValidationException is at least diagnosable from the logs.
            tracing::warn!(
                "emitting toolChoice.tool (force a SPECIFIC tool) on Bedrock egress: this directive \
                 is documented Anthropic-Claude-only on Converse and Bedrock model families that are \
                 not Claude will reject it; the writer has no way to know which model this request \
                 targets"
            );
            Some(serde_json::json!({"tool": {"name": name}}))
        }
        crate::ir::IrToolChoice::None => None,
    }
}

/// Bedrock stopReason → canonical IR stop_reason.
fn stop_reason_map(ward: &str) -> crate::ir::IrStopReason {
    use crate::ir::IrStopReason as S;
    match ward {
        "end_turn" => S::EndTurn,
        "tool_use" => S::ToolUse,
        "max_tokens" => S::MaxTokens,
        "stop_sequence" => S::StopSequence,
        // Both moderation outcomes fold to the canonical `Safety`.
        "content_filtered" | "guardrail_intervened" => S::Safety,
        // BED-10: generation ended because the model's CONTEXT WINDOW filled — output was cut off by
        // a token limit, which is what `MaxTokens` means to every client dialect (a dedicated
        // context-window reason needs the IR-16 slot).
        STOP_MODEL_CONTEXT_WINDOW_EXCEEDED => S::MaxTokens,
        // BED-10: the model produced output Bedrock could not parse (text or a tool call) — an
        // error termination, not a natural end.
        "malformed_model_output" | "malformed_tool_use" => S::Error,
        _ => S::Other,
    }
}

/// Whether a Bedrock model id names a Claude model: `anthropic.` / `claude`, which covers the bare
/// model id, the regional and global inference profiles and their ARNs. The Converse body carries no
/// model family, so the id is the only place it is visible (see `write_request_for_lane`).
fn bedrock_model_is_claude(model: &str) -> bool {
    let m = model.to_ascii_lowercase();
    m.contains("anthropic.") || m.contains("claude")
}

/// Which family minted the reasoning signatures of a Bedrock conversation addressed to `model`
/// (IR-18). Claude → `Anthropic` (Claude on Bedrock mints Anthropic signatures). A model id that
/// visibly names another provider (`<provider>.<model>`, optionally behind a geographic inference
/// profile prefix or an ARN) → `BedrockOther`. Anything the id does not reveal — no model, a
/// busbar alias, an opaque application-inference-profile ARN — is `None` (unknown: every writer
/// keeps its pre-slot behaviour), never a guess.
fn bedrock_signature_origin(model: Option<&str>) -> Option<crate::ir::IrSignatureOrigin> {
    let model = model?;
    if bedrock_model_is_claude(model) {
        return Some(crate::ir::IrSignatureOrigin::Anthropic);
    }
    let id = model
        .rsplit('/')
        .next()
        .unwrap_or(model)
        .to_ascii_lowercase();
    let mut parts = id.split('.');
    let first = parts.next().unwrap_or("");
    let provider = match first {
        "us" | "eu" | "apac" | "global" | "us-gov" | "jp" | "au" | "ca" => parts.next(),
        _ => Some(first),
    }?;
    let names_provider = parts.next().is_some_and(|rest| !rest.is_empty())
        && !provider.is_empty()
        && provider
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
    names_provider.then_some(crate::ir::IrSignatureOrigin::BedrockOther)
}

/// Converse request member for the processing tier (IR-04).
const FIELD_SERVICE_TIER: &str = "serviceTier";

/// Converse `serviceTier: {type}` → the IR tier: `priority` → Priority, `default` → Default,
/// `flex` → Flex. `reserved` (provisioned capacity) has no IR tier: `None`.
fn read_bedrock_service_tier(
    obj: &serde_json::Map<String, serde_json::Value>,
) -> Option<crate::ir::IrServiceTier> {
    match obj.get(FIELD_SERVICE_TIER)?.get("type")?.as_str()? {
        "priority" => Some(crate::ir::IrServiceTier::Priority),
        "default" => Some(crate::ir::IrServiceTier::Default),
        "flex" => Some(crate::ir::IrServiceTier::Flex),
        _ => None,
    }
}

/// The IR tier → the Converse `serviceTier.type` word, or `None` for a tier Converse has no word
/// for (Auto, Scale): dropped with a warn and reported by `dropped_egress_controls`.
fn write_bedrock_service_tier(tier: crate::ir::IrServiceTier) -> Option<&'static str> {
    match tier {
        crate::ir::IrServiceTier::Priority => Some("priority"),
        crate::ir::IrServiceTier::Default => Some("default"),
        crate::ir::IrServiceTier::Flex => Some("flex"),
        crate::ir::IrServiceTier::Auto | crate::ir::IrServiceTier::Scale => None,
    }
}

/// Converse `requestMetadata` (string → string, filters the caller's invocation logs) → the typed
/// [`crate::ir::IrRequest::metadata`] (IR-03). A non-string value is not a member Converse defines
/// and is skipped. The raw object still rides `extra`, so a same-protocol hop re-emits it verbatim.
fn read_bedrock_request_metadata(
    body: &serde_json::Map<String, serde_json::Value>,
) -> Option<Vec<(String, String)>> {
    let m = body.get(FIELD_REQUEST_METADATA)?.as_object()?;
    Some(
        m.iter()
            .filter_map(|(k, v)| v.as_str().map(|v| (k.clone(), v.to_string())))
            .collect(),
    )
}

/// Converse's request-metadata member.
const FIELD_REQUEST_METADATA: &str = "requestMetadata";
/// Converse caps `requestMetadata` at 16 entries.
const REQUEST_METADATA_MAX_ENTRIES: usize = 16;

/// Whether `s` fits a Converse `requestMetadata` key/value: `min..=256` characters, each in
/// `[a-zA-Z0-9\s:_@$#=/+,-.]` (the service model's pattern). OpenAI metadata allows 512-character
/// values and any character, so a cross-protocol entry can fall outside it.
fn bedrock_request_metadata_fits(s: &str, min: usize) -> bool {
    let n = s.chars().count();
    (min..=256).contains(&n)
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c.is_whitespace() || ":_@$#=/+,-.".contains(c))
}

/// The typed [`crate::ir::IrRequest::metadata`] → Converse `requestMetadata` (IR-03), same keys.
/// An entry Converse would reject (the pattern / length above, or past the 16-entry cap) is dropped
/// with a warn and the rest are kept — one bad entry must not cost the request a 400. `None` when
/// nothing is left to write.
fn write_bedrock_request_metadata(pairs: &[(String, String)]) -> Option<serde_json::Value> {
    let mut out = serde_json::Map::new();
    for (k, v) in pairs {
        if !bedrock_request_metadata_fits(k, 1) || !bedrock_request_metadata_fits(v, 0) {
            tracing::warn!(
                key = %k,
                "dropping a metadata entry on Bedrock egress: Converse requestMetadata keys and \
                 values are at most 256 characters of [a-zA-Z0-9 whitespace :_@$#=/+,-.]"
            );
            continue;
        }
        if out.len() == REQUEST_METADATA_MAX_ENTRIES && !out.contains_key(k) {
            tracing::warn!(
                key = %k,
                "dropping a metadata entry on Bedrock egress: Converse requestMetadata holds at \
                 most 16 entries"
            );
            continue;
        }
        out.insert(k.clone(), serde_json::json!(v));
    }
    (!out.is_empty()).then_some(serde_json::Value::Object(out))
}

/// The refinement a Bedrock stopReason states beyond its coarse IR reason (IR-16, BED-10):
/// `model_context_window_exceeded` is `MaxTokens` (the coarse reason `stop_reason_map` gives) PLUS
/// [`crate::ir::IrStopDetail::ContextWindowExceeded`], so a dialect that names the refinement
/// (Anthropic) receives it exactly. Every other stopReason states no detail.
fn stop_detail_map(ward: &str) -> Option<crate::ir::IrStopDetail> {
    (ward == STOP_MODEL_CONTEXT_WINDOW_EXCEEDED)
        .then_some(crate::ir::IrStopDetail::ContextWindowExceeded)
}

/// Converse's `model_context_window_exceeded` stopReason (IR-16, BED-10).
const STOP_MODEL_CONTEXT_WINDOW_EXCEEDED: &str = "model_context_window_exceeded";

/// Canonical IR stop_reason (plus its [`crate::ir::IrStopDetail`]) → Bedrock stopReason. A
/// context-window detail is written as Converse's own `model_context_window_exceeded` (IR-16,
/// BED-10); every other detail has no Converse spelling, so the coarse reason is written.
fn stop_reason_reverse_detailed(
    canonical: crate::ir::IrStopReason,
    detail: Option<&crate::ir::IrStopDetail>,
) -> &'static str {
    match detail {
        Some(crate::ir::IrStopDetail::ContextWindowExceeded) => STOP_MODEL_CONTEXT_WINDOW_EXCEEDED,
        _ => stop_reason_reverse(canonical),
    }
}

/// Canonical IR stop_reason → Bedrock stopReason (inverse of `stop_reason_map`).
fn stop_reason_reverse(canonical: crate::ir::IrStopReason) -> &'static str {
    use crate::ir::IrStopReason as S;
    match canonical {
        S::EndTurn => "end_turn",
        S::ToolUse => "tool_use",
        S::MaxTokens => "max_tokens",
        S::StopSequence => "stop_sequence",
        S::Safety => "content_filtered",
        // BED-09: a model REFUSAL is a content-policy stop; Converse's closed enum spells that
        // `content_filtered` (the refusal text itself still rides the content).
        S::Refusal => "content_filtered",
        // error / pause_turn / other → end_turn rather than an off-spec value a strict Converse
        // client rejects.
        S::Error | S::PauseTurn | S::Other => "end_turn",
    }
}

/// Read the prompt-cache token fields off a Bedrock Converse `usage` object into the IR's
/// `(cache_creation_input_tokens, cache_read_input_tokens)` pair. AWS names the write side
/// `cacheWriteInputTokens` (tokens written to the cache this turn = a cache *creation* in
/// Anthropic terminology) and the read side `cacheReadInputTokens` (per the Bedrock
/// `TokenUsage` shape). Both are OPTIONAL on the wire — a model/region without prompt caching,
/// or a request that neither created nor read a cache entry, simply omits them — so each maps
/// to `None` when absent (distinct from `Some(0)`, which a backend may legitimately send when
/// caching was active but contributed zero tokens). The old code hardcoded both to `None`,
/// silently dropping real cache accounting on every read; this plumbs the actual values so a
/// Bedrock→Bedrock (and Bedrock→Anthropic) round-trip preserves cache usage.
///
/// A present-but-UNREADABLE count is an [`crate::usage_count::UnreadableCount`] the caller turns
/// into a refusal (#42, item 133). The old read returned `None` for it — indistinguishable from "no
/// caching this turn" — so a reported cache read or write was ledgered as none.
fn read_cache_usage(
    usage_obj: Option<&serde_json::Value>,
) -> Result<(Option<u64>, Option<u64>), crate::usage_count::UnreadableCount> {
    let cache_creation_input_tokens =
        crate::usage_count::billed_count_opt(usage_obj, "cacheWriteInputTokens")?;
    let cache_read_input_tokens =
        crate::usage_count::billed_count_opt(usage_obj, "cacheReadInputTokens")?;
    Ok((cache_creation_input_tokens, cache_read_input_tokens))
}

/// The `CacheTTL` enum's two values, as the Bedrock service model spells them.
const CACHE_TTL_5M: &str = "5m";
const CACHE_TTL_1H: &str = "1h";

/// Read Bedrock's per-TTL cache-WRITE breakdown off a Converse `usage` object into the neutral
/// [`crate::ir::IrUsageDetail`] 5m/1h pair.
///
/// The service model gives `TokenUsage` a `cacheDetails` member — "Detailed breakdown of cache
/// writes by TTL. Empty if no cache creation occurred. Sorted by TTL duration (1h before 5m)" — a
/// list of `CacheDetail { ttl: CacheTTL ("5m" | "1h"), inputTokens }`. That is the SAME split
/// Anthropic reports as `cache_creation.ephemeral_5m_input_tokens` / `ephemeral_1h_input_tokens`,
/// and the IR carries it in exactly those two fields, for exactly the reason stated there: the two
/// TTLs are PRICED DIFFERENTLY, so collapsing them into the one `cacheWriteInputTokens` total leaves
/// a bill that reconciles in aggregate and cannot be reconciled per line. Reading only the total
/// dropped the split on every Bedrock response.
///
/// A TTL the upstream did not report stays `None` (never `Some(0)`), matching the sibling buckets;
/// an unrecognized `ttl` string is ignored rather than folded into one of the two known tiers (the
/// total in `cacheWriteInputTokens` still carries it, so nothing is unbilled).
///
/// Counts are read through [`crate::usage_count::billed_count_opt`], the crate's billed-count seam —
/// a float-spelled `20.0` is twenty tokens here, not a silent zero; an entry with no (or a `null`)
/// `inputTokens` contributes nothing, as before; and a present-but-UNREADABLE `inputTokens` on a
/// 5m/1h entry is an [`crate::usage_count::UnreadableCount`] the caller turns into a refusal (#42,
/// item 133). The old read skipped that entry, so its tier reported fewer tokens than were written.
/// An unrecognized TTL's count is not read at all: it reaches no tier.
fn read_cache_details(
    usage_obj: Option<&serde_json::Value>,
) -> Result<(Option<u64>, Option<u64>), crate::usage_count::UnreadableCount> {
    let Some(list) = usage_obj
        .and_then(|u| u.get("cacheDetails"))
        .and_then(|d| d.as_array())
    else {
        return Ok((None, None));
    };
    let mut five_m: Option<u64> = None;
    let mut one_h: Option<u64> = None;
    for entry in list {
        let tier = match entry.get("ttl").and_then(|t| t.as_str()) {
            Some(CACHE_TTL_5M) => &mut five_m,
            Some(CACHE_TTL_1H) => &mut one_h,
            _ => continue,
        };
        let Some(tokens) = crate::usage_count::billed_count_opt(Some(entry), "inputTokens")? else {
            continue;
        };
        *tier = Some(tier.unwrap_or(0).saturating_add(tokens));
    }
    Ok((five_m, one_h))
}

/// Write the IR's per-TTL cache-write split back onto a Bedrock Converse `usage` object, the inverse
/// of [`read_cache_details`]. Emits the entries in the order the service model documents (1h before
/// 5m) and ONLY for the tiers the IR actually carries — the spec says `cacheDetails` is "Empty if no
/// cache creation occurred", so a response with no per-TTL split gains no member at all.
fn write_cache_details(
    usage_obj: &mut serde_json::Map<String, serde_json::Value>,
    usage: &crate::ir::IrUsage,
) {
    let mut details = Vec::new();
    if let Some(v) = usage.detail.cache_creation_1h_input_tokens {
        details.push(serde_json::json!({ "ttl": CACHE_TTL_1H, "inputTokens": v }));
    }
    if let Some(v) = usage.detail.cache_creation_5m_input_tokens {
        details.push(serde_json::json!({ "ttl": CACHE_TTL_5M, "inputTokens": v }));
    }
    if !details.is_empty() {
        usage_obj.insert(
            "cacheDetails".to_string(),
            serde_json::Value::Array(details),
        );
    }
}

/// Write the IR's prompt-cache token fields back onto a Bedrock Converse `usage` object, the
/// inverse of `read_cache_usage`. Emits `cacheWriteInputTokens` from `cache_creation_input_tokens`
/// and `cacheReadInputTokens` from `cache_read_input_tokens`, and ONLY when the IR carries a value
/// (`Some`) — a `None` field is omitted rather than serialized as `0`, so a Bedrock→Bedrock
/// round-trip of a no-cache response stays byte-identical to native AWS (which omits the fields
/// when caching was inactive) and never fabricates a cache-accounting tell. The old writer dropped
/// these fields entirely.
fn write_cache_usage(
    usage_obj: &mut serde_json::Map<String, serde_json::Value>,
    usage: &crate::ir::IrUsage,
) {
    if let Some(ccit) = usage.cache_creation_input_tokens {
        usage_obj.insert("cacheWriteInputTokens".to_string(), ccit.into());
    }
    if let Some(crit) = usage.cache_read_input_tokens {
        usage_obj.insert("cacheReadInputTokens".to_string(), crit.into());
    }
    // The per-TTL breakdown of the write total above: priced separately, so carried separately.
    write_cache_details(usage_obj, usage);
}

/// Upper bound applied to the upstream-controlled Bedrock ConverseStream `contentBlockIndex` at
/// every stream read site (`contentBlockStart` / `contentBlockDelta` / `contentBlockStop`). The
/// wire value is attacker-controllable: a hostile/buggy backend can send an arbitrarily huge index
/// (up to `u64::MAX`), which the old code cast straight to `usize` and forwarded into IR
/// `BlockStart`/`BlockDelta`/`BlockStop` indices. A downstream ingress writer keying per-index
/// state off that value would then allocate/track against a pathological index. A real Converse
/// stream emits small sequential block indices (0, 1, 2, …); any larger value is malformed, so we
/// clamp to this bounded cap before it enters the IR. Mirrors the OpenAI reader's `MAX_TOOL_INDEX`
/// and the Cohere reader's `MAX_TOOL_FRAME_INDEX` clamps.
const MAX_CONTENT_BLOCK_INDEX: u64 = 1023;

/// Read the upstream-controlled `contentBlockIndex` off a Bedrock ConverseStream frame, defaulting
/// to 0 when absent/non-numeric, and clamp it to `MAX_CONTENT_BLOCK_INDEX` so a crafted huge index
/// can never be forwarded into an IR block index. Shared by all three stream read sites so the
/// clamp stays uniform.
fn clamp_content_block_index(data: &serde_json::Value) -> usize {
    data.get("contentBlockIndex")
        .and_then(|i| i.as_u64())
        .unwrap_or(0)
        .min(MAX_CONTENT_BLOCK_INDEX) as usize
}

#[derive(Clone)]
pub struct BedrockReader;

/// Bedrock-ingress per-stream framing state machine. A native AWS SDK ConverseStream emits the terminal
/// information as a `messageStop` frame FOLLOWED by EXACTLY ONE `metadata` (usage) frame — but the IR
/// carries a single combined `MessageDelta{stop_reason, usage}` (the egress reader collapses any
/// protocol's stop/usage into one), and a foreign backend can split stop vs usage across two events. So
/// this state machine fans the combined delta into a stop-only delta (→ `messageStop`) plus, when usage
/// rode with the stop, a usage-only delta (→ `metadata`); otherwise it DEFERS the metadata to a trailing
/// usage-only delta (OpenAI `include_usage`) or — if none arrives (default OpenAI streaming) — to the
/// finish-time flush. The `emitted`/`pending` flags enforce the one-metadata invariant however the
/// backend split the terminal info. Built per stream via [`BedrockWriter::new_stream_framing`]; reached
/// only on Bedrock ingress.
#[derive(Default)]
struct BedrockStreamFraming {
    /// Whether a `metadata` (usage) frame has ALREADY been emitted for this stream. Guards the
    /// exactly-one-metadata invariant: suppress a duplicate usage-only delta, and skip the finish flush.
    emitted: bool,
    /// Set when a combined stop-delta arrived with all-zero usage so the `metadata` frame was DEFERRED
    /// (awaiting a trailing usage-only delta). If that delta never arrives (default OpenAI streaming),
    /// `on_finish` flushes a single best-effort zero-usage `metadata` so the stream is never missing its
    /// terminal frame.
    pending: bool,
}

impl super::proto_codec::StreamFraming for BedrockStreamFraming {
    // Bedrock ingress carries usage in a SEPARATE `metadata` frame (handled by on_combined_stop_delta
    // / on_usage_only_delta / on_finish), not folded into a terminal message_delta, so it must NOT use
    // the generic terminal-usage deferral.
    fn folds_terminal_usage(&self) -> bool {
        false
    }

    fn abort_exception_type(&self) -> Option<&'static str> {
        // A native ConverseStream that aborts emits a modeled exception frame; busbar uses
        // `InternalServerException` (the generic server-fault type) so the close is well-formed for the
        // AWS SDK decoder. Keeps the Bedrock wire exception-type name in this module, not the agnostic
        // translator (which calls this seam and names no wire type).
        Some(EXC_INTERNAL_SERVER)
    }

    fn inject_streaming_metrics(
        &self,
        event_type: &str,
        data: &mut serde_json::Value,
        started_at: Option<std::time::Instant>,
    ) {
        // A native ConverseStream `metadata` frame carries a `metrics` object with the stream's real
        // `latencyMs`, and the service model marks it required. Inject the elapsed wall-clock since
        // the first byte was fed; a frame that already carries one (a same-protocol upstream's own
        // measurement) is left alone, and if timing is somehow unavailable the member is still
        // emitted (as `0`) rather than dropped. The writer leaves `metrics` off so this is the
        // single source of it. Only the `metadata` frame is special.
        if event_type != ET_METADATA {
            return;
        }
        // u128 -> u64 for JSON; saturate (elapsed never realistically exceeds u64 ms).
        let elapsed_ms =
            started_at.map(|start| u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX));
        ensure_metrics(data, elapsed_ms);
    }

    fn on_combined_stop_delta(
        &mut self,
        stop_reason: crate::ir::IrStopReason,
        stop_sequence: Option<String>,
        usage: &crate::ir::IrUsage,
    ) -> Option<Vec<crate::ir::IrStreamEvent>> {
        // Frame 1: stop-only delta → `messageStop` (usage, if any, rides frame 2).
        let mut events = vec![crate::ir::IrStreamEvent::MessageDelta {
            stop_reason: Some(stop_reason),
            stop_sequence: stop_sequence.clone(),
            usage: crate::ir::IrUsage {
                input_tokens: 0,
                output_tokens: 0,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
                detail: crate::ir::IrUsageDetail::default(),
            },
            stop_detail: None,
        }];
        // Frame 2: `metadata` carrying the token usage — but a native ConverseStream emits EXACTLY ONE
        // `metadata`. Emit it ONLY if real usage rode WITH the stop (the native Bedrock→Bedrock case
        // AND any egress that bundles usage into the stop delta). If usage is all-zero, this is an
        // OpenAI `include_usage` stop chunk whose tokens arrive in a SEPARATE trailing usage-only delta
        // — DEFER the metadata to that delta so we emit it once with the REAL tokens, never a zero-usage
        // frame.
        // Guard the metadata frame on `!self.emitted` so a (malformed/adversarial) egress that emits a
        // SECOND combined stop-delta with usage cannot produce a second `metadata` frame — the
        // exactly-one-metadata invariant holds even against a hostile backend. A well-behaved egress
        // (all 6 readers) emits at most one terminal stop-delta, so this is byte-identical for real
        // streams; once emitted, a repeat call yields only the (idempotent) stop frame.
        // Cache-only usage counts too: a FULL cache hit can carry `input_tokens == 0 &&
        // output_tokens == 0` yet non-zero `cache_read_input_tokens` / `cache_creation_input_tokens`.
        // Omitting the cache fields deferred the metadata frame and later flushed a ZERO-usage
        // `metadata` frame, so the Bedrock client SDK's stream-metadata callback under-reported the
        // cache tokens on the wire. Include them so the real usage is emitted inline.
        let has_usage = usage.input_tokens != 0
            || usage.output_tokens != 0
            || usage.cache_read_input_tokens.unwrap_or(0) != 0
            || usage.cache_creation_input_tokens.unwrap_or(0) != 0;
        if !self.emitted {
            if has_usage {
                events.push(crate::ir::IrStreamEvent::MessageDelta {
                    stop_reason: None,
                    stop_sequence,
                    usage: usage.clone(),
                    stop_detail: None,
                });
                self.emitted = true;
                self.pending = false;
            } else {
                // Deferred: the stop carried no usage. The trailing usage-only delta (OpenAI
                // `include_usage`) will emit the metadata if it arrives — but in DEFAULT OpenAI
                // streaming (no `include_usage`) it never does, so mark the metadata pending and let
                // `on_finish` flush a single zero-usage `metadata` frame at end-of-stream. A native
                // ConverseStream ALWAYS ends with a metadata frame; its total absence is a proxy tell
                // and loses token accounting.
                self.pending = true;
            }
        }
        Some(events)
    }

    fn on_usage_only_delta(&mut self) -> Option<bool> {
        // A usage-only delta (`stop_reason: None`) → a `metadata` frame. This is the trailing OpenAI
        // `include_usage` chunk (or a native usage frame). Emit at most once: suppress it if a
        // `metadata` already rode with the stop above, so the stream carries exactly one metadata frame
        // regardless of how the egress backend split stop vs usage.
        if self.emitted {
            return Some(false);
        }
        self.emitted = true;
        self.pending = false; // the deferral is now resolved
        Some(true)
    }

    fn on_finish(&mut self) -> Option<crate::ir::IrStreamEvent> {
        // If a combined stop-delta deferred the `metadata` frame (zero usage, expecting a trailing
        // usage-only delta) and that delta never arrived — the DEFAULT OpenAI streaming case — flush a
        // single best-effort zero-usage `metadata` frame now.
        if !self.pending || self.emitted {
            return None;
        }
        self.emitted = true;
        self.pending = false;
        Some(crate::ir::IrStreamEvent::MessageDelta {
            stop_reason: None,
            stop_sequence: None,
            usage: crate::ir::IrUsage {
                input_tokens: 0,
                output_tokens: 0,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
                detail: crate::ir::IrUsageDetail::default(),
            },
            stop_detail: None,
        })
    }
}

/// Per-stream set of IR block indices this writer OPENED and therefore owes a closing
/// `contentBlockStop` (Text / ToolUse / Thinking — NOT `Image`, whose `BlockStart` maps to `None`
/// and which is never streamed as `contentBlock*` frames). NOTE: being tracked here does NOT mean a
/// `contentBlockStart` was emitted — only `ToolUse` projects a start frame; Text and Thinking open
/// IMPLICITLY on their first `contentBlockDelta` (per the ConverseStream wire, whose
/// `ContentBlockStart$start` union models only `toolUse`). The `BlockStop` arm carries only the
/// integer index, no block kind, so without this it cannot tell an untracked index (Image, whose
/// start was suppressed) from a tracked one, and previously closed EVERY index unconditionally —
/// emitting an orphan `contentBlockStop` for a block a real ConverseStream client never saw opened.
/// `Mutex` keeps the writer `Sync` as `ProtocolWriter` requires; a stream is single-threaded at any
/// instant, so lock contention never happens in practice. Lock poisoning degrades to a no-op /
/// `false` rather than panicking on the request path — mirrors `CohereWriter`'s identical guard
/// (`cohere/mod.rs`).
pub struct BedrockWriter {
    open_block_indices: std::sync::Mutex<std::collections::BTreeSet<usize>>,
}

/// Value-namespace constructor for [`BedrockWriter`], mirroring `CohereWriter`'s identically-shaped
/// const: `protocol_for` (`proto/mod.rs`) builds a FRESH `Protocol`, and therefore a fresh writer,
/// per stream — each use of this const inlines an independent empty set, so per-writer state cannot
/// leak across concurrent streams. `clippy::declare_interior_mutable_const` is suppressed
/// deliberately: a shared `static` here WOULD leak one stream's open indices into another, which is
/// exactly the bug this guard exists to prevent.
#[allow(non_upper_case_globals)]
#[allow(clippy::declare_interior_mutable_const)]
pub const BedrockWriter: BedrockWriter = BedrockWriter {
    open_block_indices: std::sync::Mutex::new(std::collections::BTreeSet::new()),
};

impl Clone for BedrockWriter {
    fn clone(&self) -> Self {
        // Carry the open-index set across a clone so a mid-stream `Protocol::clone` keeps the
        // in-flight open/close correlation; a poisoned lock degrades to an empty set rather than
        // panicking on the request path.
        BedrockWriter {
            open_block_indices: std::sync::Mutex::new(
                self.open_block_indices
                    .lock()
                    .map(|set| set.clone())
                    .unwrap_or_default(),
            ),
        }
    }
}

impl BedrockWriter {
    /// Record that IR block `index` was OPENED and so owes a closing `contentBlockStop` (whether or
    /// not a `contentBlockStart` was actually emitted — Text/Thinking open implicitly, ToolUse emits
    /// a start). Lock poisoning degrades to a no-op rather than panicking on the request path.
    fn mark_block_open(&self, index: usize) {
        if let Ok(mut set) = self.open_block_indices.lock() {
            set.insert(index);
        }
    }

    /// Return true and forget `index` if the block was opened (so its `BlockStop` must emit a
    /// `contentBlockStop`); false if it was never opened (e.g. an `Image` block, whose `BlockStart`
    /// mapped to `None` and was NOT marked open), in which case the matching `BlockStop` must also
    /// emit nothing. Lock poisoning degrades to `false` (suppress) rather than panicking on the
    /// request path.
    fn take_block_open(&self, index: usize) -> bool {
        self.open_block_indices
            .lock()
            .map(|mut set| set.remove(&index))
            .unwrap_or(false)
    }
}

/// Wrap a SINGLE non-stream `IrResponse` into a Bedrock ConverseStream binary `eventstream` byte
/// sequence (`application/vnd.amazon.eventstream`), for the case where a bedrock-ingress client
/// requested `ConverseStream` (`wants_stream`) but the cross-protocol upstream answered with a
/// BUFFERED (non-SSE) 2xx. Returning that single response as `application/json` + a non-stream
/// Converse body is undecodable by the AWS SDK's eventstream decoder (it expects framed
/// `messageStart`/`contentBlockDelta`/…/`messageStop`/`metadata` events) — a hard functional failure
/// and a deterministic proxy tell on the headline bedrock-ingress surface. This synthesizes the
/// native frame sequence a real ConverseStream emits for the same completion: one `messageStart`,
/// then per content block a `contentBlockStart` + its `contentBlockDelta`(s) + `contentBlockStop`,
/// then `messageStop` (carrying the stop reason) and a trailing `metadata` frame (carrying token
/// usage) — matching the two-frame stop/usage split the Bedrock writer's `MessageDelta` arm expects.
/// Each event is rendered through the SAME `bedrock` writer used on the live streaming path and
/// encoded via `eventstream::encode_frame`, so the bytes are byte-for-byte what a native stream sends.
/// Never panics on the request path: a frame whose payload fails to serialize is skipped.
pub fn bedrock_response_to_eventstream(
    ir: &crate::ir::IrResponse,
    elapsed_ms: Option<u64>,
) -> Vec<u8> {
    use crate::ir::{IrBlock, IrBlockMeta, IrDelta, IrStreamEvent, IrUsage};
    let writer = protocol();
    let writer = writer.writer();
    let mut out: Vec<u8> = Vec::new();
    // Render one IR stream event through the bedrock writer and append the encoded frame (if the
    // writer maps it to a native frame; some IR events have no Bedrock analog and yield None).
    // `write_response_events` (not the single-frame method): a multi-citation delta frames as one
    // `citation` delta per citation, exactly as a native ConverseStream interleaves them.
    let push = |ev: &IrStreamEvent, out: &mut Vec<u8>| {
        for (event_type, mut payload) in writer.write_response_events(ev) {
            // A native ConverseStream `metadata` frame ALWAYS carries a `metrics.latencyMs` (the SDK
            // surfaces it via `ConverseStreamMetadataEvent::metrics()`); the bedrock writer's
            // `MessageDelta` arm deliberately omits `metrics`, and the LIVE StreamTranslate path injects
            // it there (`proto::mod.rs`). On this BUFFERED synthesis path StreamTranslate is bypassed,
            // so inject it HERE too — otherwise `metrics == None`, which a real endpoint never returns
            // (a deterministic proxy tell, and a missing required member). Use the request's elapsed
            // wall-clock, consistent with the live path; the member is emitted even when timing is
            // unavailable (see `ensure_metrics`).
            if event_type == ET_METADATA {
                ensure_metrics(&mut payload, elapsed_ms);
            }
            if let Ok(bytes) = crate::json::to_vec(&payload) {
                out.extend_from_slice(&crate::eventstream::encode_frame(&event_type, &bytes));
            }
        }
    };

    // messageStart
    push(
        &IrStreamEvent::MessageStart {
            role: ir.role,
            usage: None,
            id: None,
            created: None,
            model: ir.model.clone(),
        },
        &mut out,
    );

    // Per content block: contentBlockStart → contentBlockDelta(s) → contentBlockStop. Mirror the
    // live streaming fan-out (`read_response_events`) so the SDK sees the same per-block framing.
    // `index` is incremented only when a block actually emits frames (NOT `enumerate()` over
    // `ir.content`): ToolResult/Image/Json blocks below emit nothing, and enumerate()'s position
    // would burn an index on them, leaving a gap a native ConverseStream never has.
    let mut index = 0usize;
    for block in ir.content.iter() {
        match block {
            IrBlock::Text {
                text, citations, ..
            } => {
                push(
                    &IrStreamEvent::BlockStart {
                        index,
                        block: IrBlockMeta::Text,
                        refusal: false,
                    },
                    &mut out,
                );
                push(
                    &IrStreamEvent::BlockDelta {
                        index,
                        delta: IrDelta::TextDelta(text.clone()),
                    },
                    &mut out,
                );
                // BED-12: the block's citations ride the same `contentBlockIndex` as its text, as
                // `citation` deltas — the frames the live stream path emits, so a buffered answer
                // synthesized as a ConverseStream carries the sources the buffered body carries.
                if !citations.is_empty() {
                    push(
                        &IrStreamEvent::BlockDelta {
                            index,
                            delta: IrDelta::CitationsDelta(citations.clone()),
                        },
                        &mut out,
                    );
                }
                push(&IrStreamEvent::BlockStop { index }, &mut out);
                index += 1;
            }
            IrBlock::ToolUse {
                id, name, input, ..
            } => {
                push(
                    &IrStreamEvent::BlockStart {
                        index,
                        block: IrBlockMeta::ToolUse {
                            id: id.clone(),
                            name: name.clone(),
                        },
                        refusal: false,
                    },
                    &mut out,
                );
                push(
                    &IrStreamEvent::BlockDelta {
                        index,
                        delta: IrDelta::InputJsonDelta(input.to_string()),
                    },
                    &mut out,
                );
                push(&IrStreamEvent::BlockStop { index }, &mut out);
                index += 1;
            }
            // A Thinking (reasoningContent) block streams natively as `contentBlockDelta`
            // (`reasoningContent`) frames closed by a `contentBlockStop` — with NO `contentBlockStart`
            // (`ContentBlockStart$start` models only `toolUse`; there is no `reasoningContent`
            // member). The writer maps the `IrBlockMeta::Thinking` start to None (marking the block
            // open so its stop still fires) and re-emits each ThinkingDelta / SignatureDelta /
            // RedactedReasoningDelta as a `contentBlockDelta.reasoningContent` frame. Drive the same
            // start/delta(s)/stop event sequence the live streaming path produces.
            IrBlock::Thinking {
                text,
                signature,
                redacted,
                kind,
                ..
            } => {
                push(
                    &IrStreamEvent::BlockStart {
                        index,
                        block: IrBlockMeta::Thinking { kind: *kind },
                        refusal: false,
                    },
                    &mut out,
                );
                if *redacted {
                    // Opaque encrypted reasoning — `text` holds the bytes, ONE delta carries them.
                    push(
                        &IrStreamEvent::BlockDelta {
                            index,
                            delta: IrDelta::RedactedReasoningDelta(text.clone()),
                        },
                        &mut out,
                    );
                } else {
                    push(
                        &IrStreamEvent::BlockDelta {
                            index,
                            delta: IrDelta::ThinkingDelta(text.clone()),
                        },
                        &mut out,
                    );
                    if let Some(sig) = signature {
                        push(
                            &IrStreamEvent::BlockDelta {
                                index,
                                delta: IrDelta::SignatureDelta(sig.clone()),
                            },
                            &mut out,
                        );
                    }
                }
                push(&IrStreamEvent::BlockStop { index }, &mut out);
                index += 1;
            }
            // ToolResult/Image/Json blocks have no native ConverseStream content-delta frame on this
            // synthesized path; skip them WITHOUT advancing `index` — no frame emitted, no index
            // spent. Enumerated EXPLICITLY (no `_` catch-all) so a future `IrBlock` variant is a
            // COMPILE error here rather than silent data loss.
            IrBlock::ToolResult { .. }
            | IrBlock::Image { .. }
            | IrBlock::Media { .. }
            | IrBlock::Json(_) => {}
        }
    }

    // messageStop (stop reason) then metadata (usage) — the writer's `MessageDelta` arm maps a
    // stop_reason-bearing delta to `messageStop` and a usage-only delta to `metadata`, exactly the
    // two native frames a real ConverseStream ends with.
    // Default the synthesized stop reason from the IR CONTENT, not unconditionally `end_turn`. A
    // native Bedrock Converse reports `tool_use` for a turn that emitted a tool call; if the buffered
    // IR carried a ToolUse block but no explicit stop_reason (a cross-protocol 2xx whose upstream
    // omitted it), default to the canonical `tool_use` so `stop_reason_reverse` yields `tool_use` and
    // an AWS SDK consumer keying agentic control flow off stopReason re-invokes the tool. Only fall
    // back to `end_turn` when the completion carried no tool call.
    let default_stop_reason = if ir
        .content
        .iter()
        .any(|b| matches!(b, IrBlock::ToolUse { .. }))
    {
        crate::ir::IrStopReason::ToolUse
    } else {
        crate::ir::IrStopReason::EndTurn
    };
    push(
        &IrStreamEvent::MessageDelta {
            stop_reason: ir.stop_reason.or(Some(default_stop_reason)),
            usage: IrUsage {
                input_tokens: 0,
                output_tokens: 0,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
                detail: crate::ir::IrUsageDetail::default(),
            },
            stop_sequence: None,
            // IR-16: the refinement rides the stop-bearing frame, so a buffered context-window stop
            // synthesizes the same `messageStop` a streamed one does (buffered == stream).
            stop_detail: ir.stop_detail.clone(),
        },
        &mut out,
    );
    push(
        &IrStreamEvent::MessageDelta {
            stop_reason: None,
            usage: ir.usage.clone(),
            stop_sequence: None,
            stop_detail: None,
        },
        &mut out,
    );
    out
}

/// Build a `metrics` object carrying `latencyMs`, the one member the Converse `metrics` shape has.
fn metrics_object(latency_ms: u64) -> serde_json::Value {
    let mut metrics = serde_json::Map::new();
    metrics.insert(
        FIELD_LATENCY_MS.to_string(),
        serde_json::Value::from(latency_ms),
    );
    serde_json::Value::Object(metrics)
}

/// True when `value` already carries a well-formed `metrics.latencyMs` (an integer), i.e. the
/// upstream's own measurement, which is always passed through in preference to busbar's.
fn has_valid_metrics(value: &serde_json::Value) -> bool {
    value
        .get(FIELD_METRICS)
        .and_then(|m| m.get(FIELD_LATENCY_MS))
        .is_some_and(|ms| ms.is_u64() || ms.is_i64())
}

/// Ensure a Converse-shaped JSON object carries `metrics.latencyMs`. A `metrics` the upstream
/// supplied is kept as-is; otherwise busbar's measured latency is written. `metrics` is a REQUIRED
/// member of the Converse response (and of the ConverseStream `metadata` event), so when no
/// measurement is available at all the member is still emitted, as `0`, rather than dropped: an
/// absent required member is the larger deviation from the service model. Non-object values are
/// left alone.
pub fn ensure_metrics(value: &mut serde_json::Value, elapsed_ms: Option<u64>) {
    if has_valid_metrics(value) {
        return;
    }
    if let Some(obj) = value.as_object_mut() {
        obj.insert(
            FIELD_METRICS.to_string(),
            metrics_object(elapsed_ms.unwrap_or(0)),
        );
    }
}

/// Complete a SERIALIZED Converse response body so it carries `metrics.latencyMs`, preserving every
/// other byte. Returns `None` when the body already carries a well-formed `metrics` (pass the
/// upstream's through untouched) or when it is not a JSON object. When the top-level object simply
/// lacks the member, the member is spliced in before the closing brace so key order, whitespace and
/// number formatting of the upstream body survive; only a malformed `metrics` (present but without
/// an integer `latencyMs`) forces a full re-serialization.
pub fn complete_converse_body(
    body: &[u8],
    parsed: &serde_json::Value,
    elapsed_ms: Option<u64>,
) -> Option<Vec<u8>> {
    let obj = parsed.as_object()?;
    if has_valid_metrics(parsed) {
        return None;
    }
    let latency_ms = elapsed_ms.unwrap_or(0);
    if obj.contains_key(FIELD_METRICS) {
        // Present but unusable: replace it. Splicing would leave two `metrics` keys.
        let mut fixed = parsed.clone();
        ensure_metrics(&mut fixed, Some(latency_ms));
        return crate::json::to_vec(&fixed).ok();
    }
    // The last significant byte must be the object's closing brace (the parse above guarantees a
    // top-level object, so this only guards against trailing garbage a lenient parser accepted).
    let close = body.iter().rposition(|b| !b.is_ascii_whitespace())?;
    if body[close] != b'}' {
        return None;
    }
    let prev = body[..close]
        .iter()
        .rposition(|b| !b.is_ascii_whitespace())?;
    let separator = if body[prev] == b'{' { "" } else { "," };
    let member = format!("{separator}\"{FIELD_METRICS}\":{{\"{FIELD_LATENCY_MS}\":{latency_ms}}}");
    let mut out = Vec::with_capacity(body.len() + member.len());
    out.extend_from_slice(&body[..close]);
    out.extend_from_slice(member.as_bytes());
    out.extend_from_slice(&body[close..]);
    Some(out)
}

/// The same-protocol (Bedrock -> Bedrock) NON-stream response translator. The forward path relays a
/// same-protocol non-stream 2xx verbatim, chunk by chunk, so nothing ever added the `metrics` member
/// a Converse response is required to carry when the upstream left it out. This translator stands
/// in for that relay on Bedrock ingress: it buffers the body, and at end-of-stream emits it with
/// `metrics.latencyMs` present (the upstream's own value when it sent one, else busbar's measured
/// latency from the moment the upstream's headers arrived to the end of its body). A body that is
/// not a Converse response (an InvokeModel embeddings / image / rerank body) is emitted unchanged.
///
/// Because the forward path takes billing usage from the installed translator, this also reports
/// the body's usage, via the same per-operation tap the relay used (`handler::same_protocol_usage`),
/// and a rerank body's counted search units (`handler::same_protocol_open_billing`).
///
/// Bounded: past the translation cap the body is relayed verbatim from that point on (no member can
/// be added to a body busbar will not hold whole), keeping only the tail so usage can still be
/// recovered from the trailing `usage` object.
pub struct BedrockConverseBodyTranslator {
    started: std::time::Instant,
    buf: Vec<u8>,
    cap: usize,
    /// Set once the body outgrew `cap`: everything is relayed as it arrives and `buf` holds only
    /// the most recent `cap` bytes.
    passthrough: bool,
    usage: Option<busbar_contract::billing::TokenUsage>,
    /// The non-token billing the body reported (a rerank's search units, item 134).
    open_billing: Option<busbar_contract::billing::Billing>,
}

impl Default for BedrockConverseBodyTranslator {
    fn default() -> Self {
        Self::new()
    }
}

impl BedrockConverseBodyTranslator {
    pub fn new() -> Self {
        Self::with_cap(crate::wire_shim::max_translated_body_bytes())
    }

    pub fn with_cap(cap: usize) -> Self {
        Self {
            started: std::time::Instant::now(),
            buf: Vec::new(),
            cap,
            passthrough: false,
            usage: None,
            open_billing: None,
        }
    }

    fn elapsed_ms(&self) -> Option<u64> {
        u64::try_from(self.started.elapsed().as_millis()).ok()
    }

    /// Drop the oldest bytes so `buf` keeps only the last `cap` (the usage object sits at the end).
    fn keep_tail(&mut self) {
        if self.buf.len() > self.cap {
            let excess = self.buf.len() - self.cap;
            self.buf.drain(..excess);
        }
    }
}

impl busbar_contract::protocol::StreamTranslator for BedrockConverseBodyTranslator {
    fn feed(&mut self, chunk: &[u8]) -> Vec<u8> {
        self.buf.extend_from_slice(chunk);
        if self.passthrough {
            self.keep_tail();
            return chunk.to_vec();
        }
        if self.buf.len() > self.cap {
            // Too large to complete: release everything withheld so far and relay from here on.
            self.passthrough = true;
            let withheld = self.buf.clone();
            self.keep_tail();
            return withheld;
        }
        Vec::new()
    }

    fn finish(&mut self) -> Vec<u8> {
        let body = std::mem::take(&mut self.buf);
        if self.passthrough {
            // Only a tail fragment is held: isolate the trailing `usage` object for billing, and
            // fall back to the same conservative floor the verbatim relay used for an over-cap body.
            // The floor mirrors the relay's: an over-cap body demonstrably consumed tokens, so it
            // is never metered at zero; the retained tail prices as output at the shared
            // bytes-per-token rate (a genuine under-estimate, never an over-charge).
            let tail_len = body.len() as u64;
            self.usage = protocol()
                .reader()
                .recover_truncated_usage(&body)
                .or_else(|| {
                    Some(busbar_contract::billing::TokenUsage {
                        output: (tail_len / crate::wire_shim::TRUNCATED_TAIL_BYTES_PER_TOKEN)
                            .max(1),
                        ..Default::default()
                    })
                });
            return Vec::new();
        }
        let parsed = crate::json::parse::<serde_json::Value>(&body).ok();
        self.usage = handler::same_protocol_usage(&body, parsed.as_ref());
        self.open_billing = handler::same_protocol_open_billing(&body, parsed.as_ref());
        match parsed {
            Some(v) if handler::is_converse_response(&v) => {
                complete_converse_body(&body, &v, self.elapsed_ms()).unwrap_or(body)
            }
            _ => body,
        }
    }

    fn usage(&self) -> Option<busbar_contract::billing::TokenUsage> {
        self.usage.clone()
    }

    fn open_billing(&self) -> Option<busbar_contract::billing::Billing> {
        self.open_billing.clone()
    }

    fn terminal_error(&self) -> Option<&str> {
        None
    }

    fn aborted(&self) -> bool {
        false
    }

    fn set_client_include_usage(&mut self, _include: bool) {}
}

#[cfg(test)]
#[path = "tests/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/input_hardening_tests.rs"]
mod input_hardening_tests;

#[cfg(test)]
#[path = "tests/field_carry_tests.rs"]
mod field_carry_tests;

#[cfg(test)]
#[path = "tests/usage_float_tests.rs"]
mod usage_float_tests;

#[cfg(test)]
#[path = "tests/ir_mapping_tests.rs"]
mod ir_mapping_tests;

#[cfg(test)]
#[path = "tests/ir_mapping_structured_tests.rs"]
mod ir_mapping_structured_tests;

/// IR mapping — the typed IR slots and the lane capabilities (BED-10, IR-03/10/11/12/18,
/// IR-09, LaneCaps).
#[cfg(test)]
#[path = "tests/ir_slot_wiring_tests.rs"]
mod ir_slot_wiring_tests;

#[cfg(test)]
#[path = "tests/ir_round3_tests.rs"]
mod ir_round3_tests;
