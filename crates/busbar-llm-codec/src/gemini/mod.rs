// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Gemini protocol reader/writer implementation.

use crate::ir::IrStreamEvent;
use crate::usage_count::read_count_u64;
#[cfg(test)]
use busbar_substrate_values::breaker::CanonicalSignal;
use busbar_substrate_values::breaker::StatusClass;
use busbar_substrate_values::proto::*;
use busbar_substrate_values::proto::{
    ERR_TYPE_AUTHENTICATION, ERR_TYPE_INVALID_REQUEST, ERR_TYPE_NOT_FOUND, ERR_TYPE_PERMISSION,
    ERR_TYPE_RATE_LIMIT,
};
use http::StatusCode;
// G6 A4b: the wire-codec surface (ProtocolReader/Writer/Protocol/StreamFraming/ToolIdRemap/
// protocol_for) relocated to this plugin's `proto_codec`; reach it RELATIVELY so it resolves both
// standalone (crate::proto_codec) and netted into core (core::proto::proto_codec).
#[allow(unused_imports)]
// used standalone; redundant with busbar_substrate_values::proto::* when netted into core
use super::proto_codec::*;
// See the anthropic dialect for the rationale: an explicit import of the codec surface so it binds to
// THIS crate's own `proto_codec` rather than the ambiguous `busbar_substrate_values::proto::*` re-export.
#[allow(unused_imports)]
use super::proto_codec::{Protocol, ProtocolReader, ProtocolWriter, StreamFraming};

mod citations;
mod framer;
pub mod handler;
mod reader;
mod schema;
mod slots;
mod usage;
mod writer;

use citations::*;
pub use framer::GeminiJsonArrayFramer;
use schema::*;
use slots::*;
use usage::*;

/// Build this dialect's wire codec — the [`ProtocolDecl::codec`] constructor. A fresh instance per
/// resolution, exactly as the registry's field doc requires. Mirrors
/// `super::anthropic::protocol`.
pub fn protocol() -> Protocol {
    Protocol::new("gemini", GeminiReader, GeminiWriter)
}

/// The [`ProtocolDecl::models_list_envelope`] builder: Gemini's `GET /v1(beta)/models` shape. Each
/// name becomes a Gemini `Model` resource (`models/{id}` resource name, and the two generation
/// methods busbar serves for it), wrapped in the `{ "models": [...] }` envelope their SDK expects.
fn models_list_envelope(names: &[&str]) -> serde_json::Value {
    let models: Vec<serde_json::Value> = names
        .iter()
        .map(|id| {
            serde_json::json!({
                "name": format!("models/{id}"),
                "displayName": id,
                "supportedGenerationMethods": ["generateContent", "streamGenerateContent"]
            })
        })
        .collect();
    serde_json::json!({ "models": models })
}

/// GEMINI'S ROUTER DETECTION — its rungs of the old `busbar-core` `protocol_id` ladder, stated here
/// so core folds them without naming Gemini: the mandatory-unique `x-goog-api-key` header (rung 3,
/// tighter than the shared path suffixes), then the `:{action}` path verbs (rung 5), then the
/// `/v1{,beta}/models/` wildcard surface (rung 6). Strength values are the ladder POSITION (lower
/// binds tighter); they are the single ladder shared with the sibling dialects' predicates.
fn claims(
    h: &http::HeaderMap,
    path: &str,
) -> Option<busbar_substrate_values::proto::ClaimStrength> {
    use busbar_substrate_values::proto::ClaimStrength;
    if h.contains_key("x-goog-api-key") {
        return Some(ClaimStrength(3));
    }
    if path.contains(":generateContent")
        || path.contains(":streamGenerateContent")
        || path.contains(":embedContent")
        || path.contains(":batchEmbedContents")
        || path.contains(":predict")
    {
        return Some(ClaimStrength(5));
    }
    if path.starts_with("/v1/models/") || path.starts_with("/v1beta/models/") {
        return Some(ClaimStrength(6));
    }
    None
}

/// The Gemini ACTION suffixes the RESIDUAL classifier recognises on the shared `/v1/models/{id}`
/// surface — DISTINCT from the router's `:{verb}` set above (this is the drop-through error-envelope
/// question, not the routing one): a `/v1/models/{id}` whose last segment ends in one of these is
/// Gemini; any other colon-bearing id (an OpenAI fine-tune) is not, and falls to the OpenAI residual.
const GEMINI_RESIDUAL_ACTIONS: [&str; 7] = [
    ":generateContent",
    ":streamGenerateContent",
    ":countTokens",
    ":embedContent",
    ":batchGenerateContent",
    ":generateAnswer",
    ":batchEmbedContents",
];

/// GEMINI'S RESIDUAL DETECTION — its arm of the headerless `residual_dialect_for_path` ladder: the
/// whole `/v1beta/models…` surface is Gemini-only (rung 10), and a `/v1/models/{id}` whose last
/// segment carries a genuine Gemini action suffix is Gemini (rung 20, tighter than the OpenAI
/// `/v1/models/` catch at rung 25).
fn residual_claims(path: &str) -> Option<busbar_substrate_values::proto::ClaimStrength> {
    use busbar_substrate_values::proto::ClaimStrength;
    if path.starts_with("/v1beta/models") {
        return Some(ClaimStrength(10));
    }
    if path.starts_with("/v1/models/") {
        let last_segment = path.rsplit('/').next().unwrap_or("");
        if GEMINI_RESIDUAL_ACTIONS
            .iter()
            .any(|a| last_segment.ends_with(a))
        {
            return Some(ClaimStrength(20));
        }
    }
    None
}

/// GEMINI'S DECLARATION. The only protocol declaring an array-stream shim key, and the reason that
/// key is a DECLARATION rather than a literal in the agnostic strip: `proxy` removes every declared
/// shim key without naming one.
pub const DECL: ProtocolDecl = ProtocolDecl {
    name: "gemini",
    codec: {
        // The dialect's neutral codec facade as a STATIC, so the decl hands out a `&'static dyn`
        // borrow (pure memory, zero alloc per `dialect()` call) — the seam's perf contract.
        static CODEC: super::proto_codec::DialectRef = super::proto_codec::dialect_ref("gemini");
        Some(&CODEC)
    },
    handler: Some(&handler::GeminiRequestHandler),
    verbs: &[
        busbar_contract::operation::OpVerb::CHAT,
        busbar_contract::operation::OpVerb::EMBEDDINGS,
        busbar_contract::operation::OpVerb::IMAGE,
        busbar_contract::operation::OpVerb::TRANSCRIPTION,
        busbar_contract::operation::OpVerb::SPEECH,
    ],
    head_keys: super::proto_codec::LLM_CHAT_HEAD_KEYS,
    streaming_content_type: Some(busbar_substrate_values::proxy::TEXT_EVENT_STREAM),
    array_stream_shim_key: Some(GEMINI_JSON_ARRAY_SHIM_KEY),
    // Gemini carries NO tool id on the wire (it correlates `functionCall`s by name), so there is
    // nothing to reshape and no risk of a foreign id leaking to a Gemini client.
    native_tool_id_prefix: None,
    ingress_auth: IngressAuth::Bearer,
    // Gemini's native credential is the raw key in a custom `x-goog-api-key` header (no Bearer) —
    // DECLARED here as data (#83a S2-a, #40(b)): the kernel's egress-auth unit presents the lane
    // credential under it (lane-constant, so the boot path prebuilds it), and the key never passes
    // through this plane.
    egress_auth_headers: None,
    egress_auth_lane_constant: false,
    egress_scheme: Some(EgressScheme::header("x-goog-api-key")),
    // THE MODEL IS IN THE URL (`/v1beta/models/{model}:generateContent`): this dialect registers its
    // arrival (`busbar_kernel::ingress::gemini_arrival`) through `busbar_llm::PATH_INGRESS`, which the
    // composition root hands to the core side-table. `has_model_in_url: true` below is what the boot
    // parity assert pairs with that registration; the arrival is no longer a field on this decl (it
    // named the core-only `Arrival`, which `ProtocolDecl`'s substrate home cannot).
    stream_usage_requires_opt_in: false,
    // ── Promoted writer facts (G6 step A1): the same constants the `GeminiWriter` methods returned.
    requires_max_tokens: false,
    stop_sequence_cap: Some((5, "Gemini")),
    cache_markers_model_gated: false,
    fills_thought_signature: true,
    frame_after_message_start: None,
    reshapes_body_at_path_base: false,
    max_cache_control_breakpoints: None,
    quota_exceeded_status: http::StatusCode::TOO_MANY_REQUESTS,
    ingress_is_eventstream: false,
    emits_sse_done_terminator: false,
    max_citations_per_delta: None,
    // Google GenAI SDK UA. RELEASE OBLIGATION: re-verify/bump per release;
    // `test_egress_ua_versions_are_pinned_and_present` guards drift.
    egress_user_agent: "google-genai-sdk/0.8.0 gl-python/3.11",
    has_model_in_url: true,
    auth_failure_status_and_kind: (http::StatusCode::BAD_REQUEST, ERR_TYPE_INVALID_REQUEST),
    ingress_relays_amzn_headers: false,
    ingress_relayed_response_header_names: &[],
    auth_failure_message: GEMINI_BAD_KEY_MESSAGE,
    uses_array_stream_shim: true,
    has_native_path_not_found: true,
    egress_stream_accept: busbar_substrate_values::proxy::TEXT_EVENT_STREAM,
    models_list_envelope: Some(models_list_envelope),
    claims: Some(claims),
    residual_claims: Some(residual_claims),
    residual_default: false,
    vendor_response_metadata: Some(vendor_response_metadata),
    // The Gemini SDK sends `x-goog-api-key`; its presence disambiguates the shared list-models
    // surface as Gemini (the `/v1beta` path is handled by the detection fold, not this header set).
    list_models_fingerprint_headers: &["x-goog-api-key"],
};

/// GEMINI'S RESPONSE-side untranslatable metadata: `safetyRatings` (Google's own harm-category
/// vocabulary) live under `candidates[].safetyRatings`, present only when the request asked for them.
/// Reported so the cross-protocol seam can LOG that they were dropped — no other protocol can carry
/// them. The nested `candidates[]` lookup is Gemini's own shape and stays here, off core.
fn vendor_response_metadata(body: &serde_json::Value) -> Vec<&'static str> {
    ["safetyRatings"]
        .into_iter()
        .filter(|k| {
            body.get("candidates")
                .and_then(|c| c.as_array())
                .is_some_and(|cands| cands.iter().any(|c| c.get(k).is_some()))
        })
        .collect()
}

/// Router-internal shim key the gemini ingress route injects into the request body when the client
/// sent a streaming `:streamGenerateContent` request WITHOUT `?alt=sse` (so the response must be the
/// JSON-array streaming format, not SSE). It rides alongside the `model`/`stream` shims. Single
/// source of truth shared by the route injection (`ingress`), the forward-layer strip
/// (`proxy::strip_router_shim_keys`), and the Gemini reader's `modeled_keys` exclusion so it never
/// reaches a backend on any path. A leading `__busbar` makes a collision with a real provider field
/// impossible. Defined here and referenced at this owning path, so the route/forward sites reach it
/// via `super::gemini::GEMINI_JSON_ARRAY_SHIM_KEY`.
pub const GEMINI_JSON_ARRAY_SHIM_KEY: &str = "__busbar_gemini_json_array";

/// The canonical Gemini bad-API-key message text (`google.rpc.Status.message` a real Generative
/// Language API 400/INVALID_ARGUMENT carries on an invalid key). Single-sourced here: the auth-failure
/// path returns it via `GeminiWriter::auth_failure_message`, and `write_error` matches on it to gate
/// the `details[].reason == "API_KEY_INVALID"` ErrorInfo array onto exactly that bad-key 400.
pub const GEMINI_BAD_KEY_MESSAGE: &str = "API key not valid. Please pass a valid API key.";

/// Hard cap on the number of distinct tool-call block indices recorded in `state.open_tools` for a
/// single Gemini SSE stream. The set is drained on either of the stream's TWO terminal paths — a
/// `finishReason` chunk (the normal candidate-terminated close) or a mid-stream prompt-block envelope
/// (`candidates_absent` + `promptFeedback.blockReason`, which also closes every open block before its
/// terminal `MessageDelta`/`MessageStop`) — so a hostile or buggy upstream that streams an unbounded
/// run of `functionCall` parts WITHOUT ever reaching either terminal path would grow it without
/// bound — one inserted index per part — until the process is OOM-killed. No legitimate Gemini
/// response approaches this many parallel tool calls in a single turn; past the cap we stop both
/// recording new tool frames and emitting their BlockStart/BlockDelta events, so per-request heap
/// stays bounded. The cap leaves every realistic stream untouched. Mirrors the Cohere reader's
/// `MAX_TRACKED_TOOL_FRAMES`.
const MAX_GEMINI_TOOL_FRAMES: usize = 4096;

// ── finishReason value tokens ─────────────────────────────────────────────────
/// Gemini `FinishReason.STOP` — normal/tool-call end.
const GEMINI_FINISH_STOP: &str = "STOP";
/// Gemini `FinishReason.MAX_TOKENS` — output truncated by token cap.
const GEMINI_FINISH_MAX_TOKENS: &str = "MAX_TOKENS";
/// Gemini `FinishReason.SAFETY` — content-safety stop.
const GEMINI_FINISH_SAFETY: &str = "SAFETY";
/// Gemini `FinishReason.OTHER` — unenumerated stop reason.
const GEMINI_FINISH_OTHER: &str = "OTHER";
/// Gemini `FinishReason.MALFORMED_FUNCTION_CALL` — model produced an unparseable tool call.
const GEMINI_FINISH_MALFORMED_FUNCTION_CALL: &str = "MALFORMED_FUNCTION_CALL";
/// Gemini `FinishReason.RECITATION` — verbatim recitation stop (maps to `safety` in the IR).
const GEMINI_FINISH_RECITATION: &str = "RECITATION";
/// Gemini `FinishReason.PROHIBITED_CONTENT` — content-policy block (maps to `safety`).
const GEMINI_FINISH_PROHIBITED_CONTENT: &str = "PROHIBITED_CONTENT";

/// Upstream URL path prefix shared by all Gemini Generative Language API endpoints. The
/// per-request path appends `/{model}:{method}` (and optionally `?alt=sse`) via
/// `upstream_path_for` / `upstream_path_for_stream`. Single source of truth for the four
/// sites that previously hard-coded the string literal.
const GEMINI_PATH_BASE: &str = "/v1beta/models";

// ── usageMetadata field names ─────────────────────────────────────────────────
/// JSON key for Gemini's top-level usage wrapper (`usageMetadata`).
const FIELD_USAGE_METADATA: &str = "usageMetadata";
/// JSON key for the prompt (input) token count inside `usageMetadata`.
const FIELD_PROMPT_TOKEN_COUNT: &str = "promptTokenCount";
/// JSON key for the candidates (output) token count inside `usageMetadata`.
const FIELD_CANDIDATES_TOKEN_COUNT: &str = "candidatesTokenCount";
/// JSON key for the total token count inside `usageMetadata`.
const FIELD_TOTAL_TOKEN_COUNT: &str = "totalTokenCount";
/// JSON key for the THINKING (reasoning) token count inside `usageMetadata`. Reported by the
/// 2.5-series models and, unlike OpenAI's `reasoning_tokens`, it is NOT a subset of the visible
/// output count — Google reports it as a separate ADDITIVE term. See
/// [`GEMINI_USAGE_ADDITIVE_TERMS`] for the full identity, which was MEASURED rather than read.
const FIELD_THOUGHTS_TOKEN_COUNT: &str = "thoughtsTokenCount";
/// JSON key for the context-cache token count inside `usageMetadata`.
const FIELD_CACHED_CONTENT_TOKEN_COUNT: &str = "cachedContentTokenCount";
/// JSON key for the server-side tool-use prompt tokens inside `usageMetadata`. Despite the name,
/// this is NOT a slice of `promptTokenCount` but a FOURTH ADDITIVE TERM beside it, charged at the
/// input rate and billed as such since 1.6.0 — see [`GEMINI_USAGE_ADDITIVE_TERMS`].
const FIELD_TOOL_USE_PROMPT_TOKEN_COUNT: &str = "toolUsePromptTokenCount";
/// JSON key for the billing-lane marker inside `usageMetadata` (`ON_DEMAND` / `PROVISIONED`).
/// INFORMATIONAL, not billed — see [`crate::ir::types::IrUsageDetail::traffic_type`]. Undeclared by
/// the pinned generativelanguage discovery document (it describes the Gemini API surface; this is
/// the Vertex one) — carried in the IR per OWNER RULING Q1, docs/design/1.6.0-QUESTIONS.md Q36,
/// rather than left as a silent drop.
const FIELD_TRAFFIC_TYPE: &str = "trafficType";

/// THE MEASURED GEMINI USAGE IDENTITY — the four counters inside `usageMetadata` that are ADDITIVE
/// terms of `totalTokenCount`:
///
/// ```text
/// totalTokenCount == promptTokenCount
///                  + candidatesTokenCount
///                  + thoughtsTokenCount
///                  + toolUsePromptTokenCount
/// ```
///
/// THIS TABLE IS DATA, NOT DOCTRINE. It was derived from seven real Vertex AI `gemini-2.5-flash`
/// turns recorded on 2026-09-07 and committed under
/// `src/tests/proto/golden/vendor/` (see that directory's README for the per-recording numbers).
/// `gemini_usage_identity_tests.rs` replays every one of them through the real decoder, so changing
/// this list without a recording that supports the change turns the corpus red.
///
/// WHY IT HAD TO BE MEASURED. Two of the four terms were genuinely ambiguous from the published
/// spec, and the sum identity differs depending on the answer:
///
/// * `thoughtsTokenCount` — additive, CONFIRMED. Not a slice of `candidatesTokenCount`.
/// * `toolUsePromptTokenCount` — additive, and this OVERTURNS what busbar believed. The grounding
///   recording settles it with no interpretation required: `toolUsePromptTokenCount` is **32**
///   while the whole `promptTokenCount` is **18**. A sub-bucket cannot exceed its bucket. The
///   IR field's own doc-comment, `docs/design/billing-usage-units.md` and
///   `docs/design/billing-unified.md` all called it `⊂ prompt`; the wire says otherwise.
///
/// THE MONEY CONSEQUENCE, APPLIED IN 1.6.0. busbar used to fold only prompt + candidates + thoughts
/// into `IrUsage`, so a Gemini turn that used a server-side tool was under-counted by exactly
/// `toolUsePromptTokenCount` (32 of 222 tokens — 14% — on the recording above). All four terms are
/// now billed: `gemini_usage` adds the tool-use term to `input_tokens` (Google charges it at the
/// input rate) and `GeminiReader::recover_truncated_usage` does the same for a response too large to
/// reassemble. This is a REGISTERED money change — see the CHANGELOG line and
/// `testing/shadow-oracle/accepted-differences.json`.
///
/// THIS TABLE IS ALSO THE GUARD. Because the billed figure is now exactly the sum of the terms
/// listed here, [`gemini_usage_identity_note`] reduces to a DISCREPANCY METRIC over
/// `totalTokenCount`: it fires when Google's stated total cannot be reached from this table, i.e.
/// when Google is reporting a counter this dialect does not model yet. It never corrects, clamps or
/// zeroes a bucket to make the sum close.
const GEMINI_USAGE_ADDITIVE_TERMS: &[&str] = &[
    FIELD_PROMPT_TOKEN_COUNT,
    FIELD_CANDIDATES_TOKEN_COUNT,
    FIELD_THOUGHTS_TOKEN_COUNT,
    FIELD_TOOL_USE_PROMPT_TOKEN_COUNT,
];

/// Stable identifier for the identity [`gemini_usage_identity_note`] checks, carried on
/// [`crate::ir::UsageIdentityNote::identity`] so callers branch on a constant, not on prose.
const GEMINI_USAGE_IDENTITY: &str = "gemini.usageMetadata";

/// Cross-check what busbar will BILL for this turn against the total Google itself stated, and
/// report a disagreement instead of hiding one.
///
/// `billed` is `IrUsage::billable_tokens` for the usage just decoded. Since 1.6.0 busbar bills every
/// term in [`GEMINI_USAGE_ADDITIVE_TERMS`], so that figure IS the sum of the modelled terms and this
/// check is a DATA-DRIVEN DISCREPANCY METRIC over `totalTokenCount`: it can only fire when Google's
/// stated total cannot be reached from the table — a counter this dialect does not model at all, or
/// a term whose meaning has changed. Either way the answer is a new recording and a table entry, not
/// an adjustment here. `wire_sum`/`unmodelled_term` on the log line say which of the two it is: the
/// table failing to close against the total is the "new counter on the wire" signal, while a gap
/// that appears only against `billed` means the normalization (cache subtraction) moved the money.
///
/// Returns `None` in the ordinary case — no `totalTokenCount` on the block (Gemini omits the
/// counters entirely on the early SSE frames, which carry a `usageMetadata` object with nothing in
/// it), or the billed figure already matches Google's total.
///
/// NOTHING IS ZEROED, CLAMPED OR BACK-FILLED. `totalTokenCount` was write-only in this dialect until
/// now, which is precisely why a whole additive term could go unbilled without anything noticing.
/// The buckets stay exactly as Google sent them; the shortfall travels beside them.
fn gemini_usage_identity_note(
    u: Option<&serde_json::Value>,
    billed: u64,
) -> Option<crate::ir::UsageIdentityNote> {
    let u = u?;
    // ABSENT is not ZERO. A `usageMetadata` that states no total states nothing to check against;
    // treating a missing total as 0 would report every ordinary streaming frame as a discrepancy.
    let reported_total = u.get(FIELD_TOTAL_TOKEN_COUNT).and_then(read_count_u64)?;
    let summed_total = billed;
    if summed_total == reported_total {
        return None;
    }
    let unaccounted = i64::try_from(reported_total).unwrap_or(i64::MAX)
        - i64::try_from(summed_total).unwrap_or(i64::MAX);
    // WHICH KIND OF SHORTFALL IS THIS? Sum the terms busbar KNOWS are additive, straight from the
    // const table. If that sum does NOT close against Google's total, Google is reporting a counter
    // this dialect does not model at all and the table needs a new entry backed by a new recording —
    // that is the case this metric exists for. If it DOES close while `billed` still disagrees, the
    // gap is in the normalization rather than on the wire (e.g. an upstream that reports more cached
    // tokens than prompt tokens). The two demand completely different responses, so an operator
    // reading this line should not have to guess which one they are looking at.
    //
    // Read through `billed_count`, the same seam the billed terms were read through: the caller has
    // already refused an unreadable term (#42), so every term here is a count or absent (zero).
    let wire_sum: u64 = GEMINI_USAGE_ADDITIVE_TERMS
        .iter()
        .try_fold(0u64, |sum, k| {
            crate::usage_count::billed_count(u, k).map(|n| sum.saturating_add(n))
        })
        .ok()?;
    let unmodelled_term = wire_sum != reported_total;
    tracing::warn!(
        identity = GEMINI_USAGE_IDENTITY,
        reported_total,
        summed_total,
        unaccounted,
        wire_sum,
        unmodelled_term,
        "gemini usageMetadata does not reconcile: the stated totalTokenCount disagrees with what \
         busbar bills. unmodelled_term=true means Google reports a counter this dialect does not \
         model and GEMINI_USAGE_ADDITIVE_TERMS needs a new entry backed by a recording; false means \
         the wire's own terms close and the gap is in normalization. Buckets are reported as \
         received; nothing was zeroed, clamped or back-filled."
    );
    Some(crate::ir::UsageIdentityNote {
        reported_total,
        summed_total,
        unaccounted,
        identity: GEMINI_USAGE_IDENTITY,
    })
}

// ── response identity field names ─────────────────────────────────────────────
/// JSON key for the opaque response identifier emitted at the top level.
const FIELD_RESPONSE_ID: &str = "responseId";
/// JSON key for the serving model name emitted at the top level.
const FIELD_MODEL_VERSION: &str = "modelVersion";
/// JSON key for the RFC3339 response-creation timestamp Vertex stamps at the top level of every
/// `GenerateContentResponse`. Undeclared by the pinned generativelanguage discovery document for
/// the same reason [`FIELD_TRAFFIC_TYPE`] is (Vertex-only surface) — carried in the IR per OWNER
/// RULING Q1, docs/design/1.6.0-QUESTIONS.md Q36. See [`crate::ir::types::IrResponse::create_time`].
const FIELD_CREATE_TIME: &str = "createTime";

/// Read Gemini/Vertex's top-level `createTime` off a response body, verbatim (no reformatting — a
/// foreign timestamp parser could reject a Vertex-specific precision/zone quirk this codec has no
/// need to understand). `None` when the body carries no such field (every non-Vertex Gemini
/// response, and every non-Gemini protocol).
fn read_gemini_create_time(body: &serde_json::Value) -> Option<String> {
    body.get(FIELD_CREATE_TIME)
        .and_then(|v| v.as_str())
        .map(str::to_string)
}

// ── gRPC / google.rpc.Code status name tokens ────────────────────────────────
/// google.rpc.Code name for a malformed/bad-argument request.
const GRPC_INVALID_ARGUMENT: &str = "INVALID_ARGUMENT";
/// google.rpc.Code name for a quota/rate-limit failure.
const GRPC_RESOURCE_EXHAUSTED: &str = "RESOURCE_EXHAUSTED";
/// google.rpc.Code name for a service-overload / temporarily unavailable failure.
const GRPC_UNAVAILABLE: &str = "UNAVAILABLE";
/// google.rpc.Code name for a missing or invalid credential.
const GRPC_UNAUTHENTICATED: &str = "UNAUTHENTICATED";
/// google.rpc.Code name for a permission / billing failure.
const GRPC_PERMISSION_DENIED: &str = "PERMISSION_DENIED";
/// google.rpc.Code name for an internal server error.
const GRPC_INTERNAL: &str = "INTERNAL";
/// google.rpc.Code name for a deadline / timeout failure.
const GRPC_DEADLINE_EXCEEDED: &str = "DEADLINE_EXCEEDED";
/// google.rpc.Code name for a resource not found.
const GRPC_NOT_FOUND: &str = "NOT_FOUND";
/// google.rpc.Code name for an unimplemented / not-supported operation.
const GRPC_UNIMPLEMENTED: &str = "UNIMPLEMENTED";
/// Busbar/Anthropic internal error kind for an overloaded upstream (maps to GRPC_UNAVAILABLE).
const ERR_TYPE_OVERLOADED: &str = busbar_substrate_values::proto::ERR_TYPE_OVERLOADED;

// ── ErrorInfo tokens ──────────────────────────────────────────────────────────
/// The machine-readable `reason` value carried in `google.rpc.ErrorInfo` for an invalid API key.
const GEMINI_ERROR_REASON_API_KEY_INVALID: &str = "API_KEY_INVALID";
/// The protobuf type URL for `google.rpc.ErrorInfo` (carried in `details[].@type`).
const GEMINI_ERROR_INFO_TYPE_URL: &str = "type.googleapis.com/google.rpc.ErrorInfo";

// ── structured-output + generation field keys ─────────────────────────────────
/// JSON key for the MIME type of the response format inside `generationConfig`.
const FIELD_RESPONSE_MIME_TYPE: &str = "responseMimeType";
/// MIME type value for JSON structured output.
const MIME_APPLICATION_JSON: &str = "application/json";
/// JSON key for a `functionCall` content part.
const FIELD_FUNCTION_CALL: &str = "functionCall";
/// JSON key for the finish reason on a candidate.
const FIELD_FINISH_REASON: &str = "finishReason";

/// The set of top-level Gemini request keys the reader models into typed `IrRequest` fields (any
/// OTHER key is swept verbatim into `extra` for round-trip fidelity). This set is a compile-time
/// constant, so it is built ONCE into a process-global `OnceLock` and shared by every
/// `read_request` call instead of being re-allocated and re-hashed per request on the ingress hot
/// path. Every member is a `&'static str`, so the cached set borrows nothing request-scoped.
fn modeled_request_keys() -> &'static std::collections::HashSet<&'static str> {
    static MODELED_KEYS: std::sync::OnceLock<std::collections::HashSet<&'static str>> =
        std::sync::OnceLock::new();
    MODELED_KEYS.get_or_init(|| {
        // NB: `generationConfig` is deliberately ABSENT. The reader promotes 5 of its sub-fields
        // (`maxOutputTokens`/`temperature`/`topP`/`topK`/`stopSequences`) into typed IR fields, but
        // a native Gemini client may also send unmodeled sub-fields (`responseMimeType` for JSON
        // mode, `thinkingConfig` for extended thinking, `candidateCount`, `seed`,
        // `presence/frequencyPenalty`, `responseModalities`, `speechConfig`, …). Were
        // `generationConfig` modeled-out of `extra`, the writer — which rebuilds it from only the 5
        // typed fields — would SILENTLY DROP every unmodeled sub-field on cross-protocol ingress.
        // Keeping the raw `generationConfig` object in `extra` lets the writer OVERLAY the 5 typed
        // fields onto the original object (the same pattern `BedrockWriter` uses for
        // `inferenceConfig`), preserving unknown sub-fields. Same-protocol Gemini→Gemini is
        // unaffected (byte-identical), and the cross-protocol seam (`proxy engine ir.extra.clear()`)
        // still prevents foreign Gemini sub-fields from leaking onto a non-Gemini backend.
        [
            "contents",
            "tools",
            "systemInstruction",
            "model",
            GEMINI_JSON_ARRAY_SHIM_KEY,
        ]
        .into_iter()
        .collect()
    })
}

#[derive(Clone)]
pub struct GeminiReader;

/// Lowercase+uppercase+digit base62 alphabet — the mixed-case alphanumeric character class a native
/// Gemini `responseId` draws from (e.g. `PXmFaPzVMI…`). Carries no `-`/`_`, so no separator or
/// hyphen leaks the synthetic boundary the old `{:x}-{:x}` form exposed.
/// Base62 alphabet for the synthesized `responseId` — the shared single-source-of-truth atom (see
/// `busbar_substrate_values::proto::BASE62_ALPHABET`), aliased locally so the generator below reads naturally.
const RESPONSE_ID_ALPHABET: &[u8; 62] = busbar_substrate_values::proto::BASE62_ALPHABET;

/// Width of a synthesized Gemini `responseId`. Native Gemini bodies/streams carry a short opaque
/// base64url-style token (~11–16 chars) with NO positional structure; 16 base62 chars stays in that
/// length/entropy profile so a client that length-checks or regex-validates `responseId` cannot
/// fingerprint it as non-native.
const RESPONSE_ID_TOKEN_LEN: usize = 16;

/// Rejection-sampling threshold for the base62 reduction in `synth_response_id`: the largest multiple
/// of 62 that fits in a `u8` is `4 * 62 = 248`. Any random byte `>= 248` is in the partial final
/// block (`248..=255` → residues `0..=7`) that would otherwise be over-represented by a bare
/// `byte % 62`, so we reject and resample those to keep the symbol distribution uniform.
const RESPONSE_ID_REJECT_THRESHOLD: u8 = busbar_substrate_values::proto::BASE62_REJECT_THRESHOLD;

/// Mint a Gemini-shaped `responseId` for the cross-protocol path where the backend supplied none.
///
/// A native Gemini `responseId` is an opaque, mixed-case alphanumeric base64url-style token with NO
/// embedded structure (no hyphen, no lowercase-hex-only restriction, no embedded timestamp). The
/// previous `format!("{:x}-{:x}", unix_now_secs(), seq)` form was structurally distinguishable on two
/// counts: (a) the `-` separator plus `[0-9a-f]`-only character class is a shape no native id has,
/// and (b) the leading hex segment leaked the proxy host's wall-clock second to anyone holding a
/// response id. This mints an opaque CSPRNG-backed base62 token of native length instead: the WHOLE
/// token is filled from `getrandom` with NO counter overlay. A counter overlaid into any fixed
/// region of the token leaves those characters predictable/low-entropy (the counter stays small, so
/// its high base62 digits are constant '0') — a structural tell at whatever position it occupies. A
/// 16-char base62 token is ~95 bits of entropy, collision-free in practice for a per-process id
/// stream, so no counter backstop is needed and every position stays fully random like a native id.
/// No embedded clock, no separator, no new dependency. Never panics on the request path: on entropy
/// failure the buffer stays the base62 zero char.
///
/// The byte→base62 reduction uses REJECTION SAMPLING, not a bare `byte % 62`. `256 % 62 != 0`, so a
/// plain modulo over a uniform `u8` is biased: residues `0..=7` (reachable by the 8 extra byte values
/// `248..=255`) occur slightly more often than `8..=61`. We instead reject any byte `>=
/// RESPONSE_ID_REJECT_THRESHOLD` (the largest multiple of 62 that fits in a `u8`, i.e. `4*62 = 248`)
/// and resample, so every surviving byte maps uniformly across the 62 symbols. Rejected bytes are
/// simply skipped and more random bytes are drawn as needed.
fn synth_response_id() -> String {
    let mut token = [b'0'; RESPONSE_ID_TOKEN_LEN];
    let mut filled = 0usize;
    // Bound the number of refill rounds so a stuck/zero entropy source can never spin forever on the
    // request path; ~4/256 of bytes are rejected, so a handful of rounds covers the token with margin
    // and the `'0'`-prefilled buffer is the panic-free fallback if entropy never arrives.
    let mut rounds = 0u32;
    const MAX_ROUNDS: u32 = 8;
    while filled < RESPONSE_ID_TOKEN_LEN && rounds < MAX_ROUNDS {
        rounds += 1;
        // Draw a generous batch so a single getrandom call typically fills the whole token even after
        // rejections (RESPONSE_ID_TOKEN_LEN*2 bytes leave ample headroom for the ~1.6% reject rate).
        let mut batch = [0u8; RESPONSE_ID_TOKEN_LEN * 2];
        if !super::synth_rng::fill_entropy(&mut batch) {
            break;
        }
        for &byte in batch.iter() {
            if filled >= RESPONSE_ID_TOKEN_LEN {
                break;
            }
            if byte >= RESPONSE_ID_REJECT_THRESHOLD {
                // Biased residue region — reject and resample rather than fold it in.
                continue;
            }
            token[filled] = RESPONSE_ID_ALPHABET[(byte % 62) as usize];
            filled += 1;
        }
    }

    // `token` is ASCII base62 by construction, hence always valid UTF-8; the fallback only guards an
    // impossible non-ASCII byte and keeps the path panic-free (no unwrap/expect on the request path).
    String::from_utf8(token.to_vec()).unwrap_or_else(|_| "0".repeat(RESPONSE_ID_TOKEN_LEN))
}

/// Synthesize a stable, non-empty tool-call id for a Gemini `functionCall`.
///
/// The Gemini wire format carries no tool-call id on `functionCall` parts, so reading them with
/// `id: String::new()` (the old behavior) produced an empty `tool_use_id`/`id` on cross-protocol
/// egress (Anthropic / OpenAI), both of which REQUIRE a non-empty id to correlate the later
/// `tool_result`/`tool` message. With an empty id, two tool calls sharing a function name could not
/// be told apart and `tool_result` routing broke.
///
/// We derive a deterministic id from `(call_index, function_name, turn_salt)` via the stdlib
/// `std::collections::hash_map::DefaultHasher` (SipHash-1-3; no new dependency). Determinism within a
/// run is all we need here — `DefaultHasher::new()` seeds from fixed constants (it is NOT the
/// per-process randomized `RandomState` used by `HashMap`), so the same `(index, name, salt)` always
/// hashes to the same id. The id only needs to be stable WITHIN a single request/response so the
/// synthesized `tool_result` (which the reader keys by function name — Gemini's only correlation
/// handle) and the `tool_use` agree; including the call index disambiguates repeated function
/// names within one turn. The `call_` prefix keeps it visibly synthetic and matches no native id
/// shape we must preserve. An empty `name` still yields a non-empty id (the index disambiguates).
///
/// `turn_salt` disambiguates ACROSS turns: `call_index` alone restarts at 0 on every independent
/// `read_response`/`read_response_events` call (each Gemini response is exactly one turn, decoded in
/// isolation with no visibility into any other turn), so two DIFFERENT turns in the SAME growing
/// conversation whose first tool call shares a name (e.g. `get_weather` called again for a different
/// city on a later turn) used to synthesize the IDENTICAL id — a real cross-protocol correlation bug
/// (Anthropic/OpenAI require a tool_use id to be unique per message/conversation) and exactly the
/// ambiguity this function exists to prevent. Response call sites pass the response's own
/// `responseId` (present on essentially every real Gemini response — see `write_response`'s own
/// synth-when-absent handling) as the salt, so different turns produce different ids. The
/// REQUEST reader (`read_request`) passes `""`: its `call_index` is already global across the WHOLE
/// `contents` array (every turn in the visible history, not reset per turn — see its call site), so
/// it has no cross-turn collision to begin with and needs no additional salt.
fn synth_tool_call_id(call_index: usize, function_name: &str, turn_salt: &str) -> String {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    call_index.hash(&mut hasher);
    function_name.hash(&mut hasher);
    turn_salt.hash(&mut hasher);
    format!("call_{:016x}", hasher.finish())
}

/// The native call id Gemini carries on a `functionCall` / `functionResponse` object (IR audit
/// GEM-08). Gemini's `FunctionCall.id` and `FunctionResponse.id` are optional: when a model (or a
/// client echoing one) populates them, the response is paired with its call by that id. `None` when
/// absent or empty, so the caller falls back to its synthesized id.
fn gemini_call_id(obj: &serde_json::Value) -> Option<&str> {
    obj.get("id")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
}

/// Pairs each Gemini `functionResponse` in a request history with the `functionCall` it answers
/// (IR audit GEM-01).
///
/// Every other dialect correlates a tool result to its call by ID, and Anthropic / OpenAI reject a
/// history whose result names no earlier call. Gemini keys the pair by the call's native `id` when
/// both sides carry one, and otherwise only by POSITION: the responses in a user turn answer the
/// calls of the model turn before it, in order. The reader used to give each call a synthesized
/// `call_<hash>` id and each result the bare function NAME, so no pair ever matched on any foreign
/// target.
///
/// Resolution for one response: (1) its own `id`, when present; (2) otherwise the EARLIEST still
/// unanswered call of the same name in the MOST RECENT model turn that has one (positional pairing
/// for parallel same-name calls, and a stale unanswered call in an older turn never steals a newer
/// turn's answer); (3) otherwise the name, exactly as before — a result with no call to pair with
/// stays an orphan and is warned about.
#[derive(Default)]
struct GeminiCallLedger {
    /// `(id, name, turn, answered)` for every call seen so far, in history order.
    calls: Vec<(String, String, usize, bool)>,
}

impl GeminiCallLedger {
    fn record_call(&mut self, id: &str, name: &str, turn: usize) {
        self.calls
            .push((id.to_string(), name.to_string(), turn, false));
    }

    fn pair_response(&mut self, explicit_id: Option<&str>, name: &str) -> String {
        if let Some(id) = explicit_id {
            if let Some(c) = self.calls.iter_mut().find(|c| !c.3 && c.0 == id) {
                c.3 = true;
            }
            return id.to_string();
        }
        let latest_turn = self
            .calls
            .iter()
            .filter(|c| !c.3 && c.1 == name)
            .map(|c| c.2)
            .max();
        if let Some(turn) = latest_turn {
            if let Some(c) = self
                .calls
                .iter_mut()
                .find(|c| !c.3 && c.1 == name && c.2 == turn)
            {
                c.3 = true;
                return c.0.clone();
            }
        }
        tracing::warn!(
            tool_name = %name,
            "gemini functionResponse answers no unanswered functionCall of that name in the \
             history; it is carried with the function name as its tool_use_id and a foreign \
             backend sees an orphan tool result"
        );
        name.to_string()
    }
}

/// Read one Gemini attachment part — `inlineData{mimeType,data}` or `fileData{fileUri,mimeType}` —
/// into its IR block. Shared by the request reader (a user turn's attachments), the
/// `functionResponse.parts` reader (GEM-07) and the response reader (a model's image/audio output,
/// GEM-17), so the three agree on routing. `None` when the part is neither.
///
/// Gemini's `inlineData` carries ANY mime type — `audio/mp3`, `application/pdf`, `video/mp4` as
/// readily as `image/png`. Images route to `Image`, everything else to the typed `Media` block whose
/// writers know which target has a native slot for it (an `audio/*` payload described to Anthropic
/// as an `image` is a 400). `fileData` carries an OPTIONAL `mimeType` beside the uri, and it is the
/// only thing that says whether the reference is an image, a PDF or a video; an absent mimeType keeps
/// the historical behaviour: an unqualified URL reads as an image, the shape every dialect's
/// `image_url` can carry.
fn read_gemini_media_part(part: &serde_json::Value) -> Option<crate::ir::IrBlock> {
    if let Some(inline_data) = part.get("inlineData") {
        let mime_type = inline_data
            .get("mimeType")
            .and_then(|m| m.as_str())
            .unwrap_or("")
            .to_string();
        let data = inline_data
            .get("data")
            .and_then(|d| d.as_str())
            .unwrap_or("")
            .to_string();
        return Some(if mime_type.to_ascii_lowercase().starts_with("image/") {
            crate::ir::IrBlock::Image {
                source: crate::ir::IrImageSource::Base64 {
                    media_type: mime_type,
                    data,
                },
                cache_control: None,
                detail: None,
            }
        } else {
            crate::ir::IrBlock::Media {
                kind: crate::ir::IrMediaKind::from_media_type(&mime_type),
                source: crate::ir::IrImageSource::Base64 {
                    media_type: mime_type,
                    data,
                },
                name: None,
                cache_control: None,
                citations: None,
                context: None,
            }
        });
    }
    if let Some(file_data) = part.get("fileData") {
        let uri = file_data
            .get("fileUri")
            .and_then(|u| u.as_str())
            .unwrap_or("")
            .to_string();
        let mime = file_data
            .get("mimeType")
            .and_then(|m| m.as_str())
            .unwrap_or("");
        return Some(
            if mime.is_empty() || mime.to_ascii_lowercase().starts_with("image/") {
                crate::ir::IrBlock::Image {
                    source: crate::ir::IrImageSource::Url(uri),
                    cache_control: None,
                    detail: None,
                }
            } else {
                crate::ir::IrBlock::Media {
                    kind: crate::ir::IrMediaKind::from_media_type(mime),
                    source: crate::ir::IrImageSource::Url(uri),
                    name: None,
                    cache_control: None,
                    citations: None,
                    context: None,
                }
            },
        );
    }
    None
}

/// Write one IR attachment block as its Gemini part (`inlineData` / `fileData`). The inverse of
/// [`read_gemini_media_part`], used for a tool result's attachments (`functionResponse.parts`,
/// GEM-06). `None` for a non-attachment block or a vendor-scoped handle Gemini cannot resolve.
fn write_gemini_media_part(block: &crate::ir::IrBlock) -> Option<serde_json::Value> {
    let (source, url_mime): (&crate::ir::IrImageSource, &str) = match block {
        crate::ir::IrBlock::Image { source, .. } => (
            source,
            match source {
                crate::ir::IrImageSource::Url(u) => gemini_image_mime_for_url(u),
                _ => "",
            },
        ),
        crate::ir::IrBlock::Media { kind, source, .. } => (source, gemini_mime_for_kind(*kind)),
        _ => return None,
    };
    match source {
        crate::ir::IrImageSource::Url(uri) => Some(serde_json::json!({
            "fileData": { "fileUri": uri, "mimeType": url_mime }
        })),
        crate::ir::IrImageSource::Base64 { media_type, data } => Some(serde_json::json!({
            "inlineData": { "mimeType": media_type, "data": data }
        })),
        crate::ir::IrImageSource::Vendor { .. } => None,
    }
}

/// A representative `mimeType` for a media kind whose source is a bare URL and therefore carries no
/// mime of its own (an Anthropic `document.source.url`, an OpenAI `image_url`-style file URL).
///
/// Gemini's `fileData` requires a `mimeType` to decode the referenced file, so omitting it is worse
/// than a well-formed generic: `application/pdf` is the document form Gemini's own docs use in the
/// `fileData` example, and the audio/video generics are the standard container-agnostic types. This
/// is a WRITE-side default, never a claim about the referenced bytes — a source that knows its real
/// mime (every `Base64` one) never routes through here.
fn gemini_mime_for_kind(kind: crate::ir::IrMediaKind) -> &'static str {
    match kind {
        crate::ir::IrMediaKind::Document => "application/pdf",
        crate::ir::IrMediaKind::Audio => "audio/mpeg",
        crate::ir::IrMediaKind::Video => "video/mp4",
    }
}

/// A representative `image/*` `mimeType` for an image whose source is a bare URL (an OpenAI
/// `image_url`, an Anthropic `image.source.url`) and therefore carries no mime of its own. Gemini's
/// `fileData` REQUIRES a `mimeType` to decode the referenced file (this file's invariant, above), so
/// omitting it is worse than a well-formed guess. Derived from the URL's file extension, defaulting
/// to `image/jpeg` (the most common web image type) when the extension is absent or unrecognized.
/// This is a WRITE-side default, never a claim about the referenced bytes — a `Base64` image always
/// knows its real mime and never routes through here.
fn gemini_image_mime_for_url(uri: &str) -> &'static str {
    // Compare only the path's extension, lowercased, ignoring any `?query`/`#fragment` suffix.
    let path = uri.split(['?', '#']).next().unwrap_or(uri);
    let ext = path.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    match ext.as_str() {
        "png" => "image/png",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "heic" => "image/heic",
        "heif" => "image/heif",
        _ => "image/jpeg",
    }
}

/// Gemini's `thinkingConfig.thinkingLevel` (Gemini 3) → the IR effort ask (IR audit GEM-09). The
/// level is Gemini's word-form reasoning knob, the same concept as OpenAI's `reasoning_effort`, so
/// it maps onto [`crate::ir::IrReasoningEffort`] one-for-one. Case-insensitive (the REST enum is
/// upper-case, the documentation examples lower-case). `None` for an unrecognized level.
fn read_gemini_thinking_level(level: &str) -> Option<crate::ir::IrReasoningAsk> {
    let effort = match level.to_ascii_lowercase().as_str() {
        "minimal" => crate::ir::IrReasoningEffort::Minimal,
        "low" => crate::ir::IrReasoningEffort::Low,
        "medium" => crate::ir::IrReasoningEffort::Medium,
        "high" => crate::ir::IrReasoningEffort::High,
        _ => return None,
    };
    Some(crate::ir::IrReasoningAsk::Effort(effort))
}

/// Normalize a Gemini OpenAPI-subset `Schema` (`parameters`, `responseSchema`) into JSON Schema for
/// the IR (IR audit GEM-11). Gemini's native enum spells types in upper case (`OBJECT`, `STRING`, …)
/// and marks optional-null with `nullable: true`; every foreign target validates JSON Schema, where
/// `"OBJECT"` is not a type and `nullable` is not a keyword, so the schema reached them malformed.
/// Walks only schema positions (`properties` values, `items`, `prefixItems`, `anyOf`/`oneOf`/`allOf`,
/// a schema-valued `additionalProperties`, `$defs`/`definitions` values) so an `enum`/`example`/
/// `default` VALUE that happens to hold a `type` key is never rewritten. `parametersJsonSchema` /
/// `responseJsonSchema` are already JSON Schema and never pass through here.
fn gemini_openapi_schema_to_json_schema(schema: &serde_json::Value) -> serde_json::Value {
    fn walk(v: &serde_json::Value, depth: usize) -> serde_json::Value {
        let Some(obj) = v.as_object() else {
            return v.clone();
        };
        if depth > GEMINI_SCHEMA_INLINE_MAX_DEPTH {
            return v.clone();
        }
        let mut out = serde_json::Map::new();
        for (k, val) in obj {
            let mapped = match k.as_str() {
                "type" => match val.as_str() {
                    Some(t) => match t {
                        "STRING" | "NUMBER" | "INTEGER" | "BOOLEAN" | "ARRAY" | "OBJECT"
                        | "NULL" => serde_json::json!(t.to_ascii_lowercase()),
                        _ => val.clone(),
                    },
                    None => val.clone(),
                },
                "properties" | "$defs" | "definitions" => match val.as_object() {
                    Some(m) => serde_json::Value::Object(
                        m.iter()
                            .map(|(pk, pv)| (pk.clone(), walk(pv, depth + 1)))
                            .collect(),
                    ),
                    None => val.clone(),
                },
                "items" | "additionalProperties" => walk(val, depth + 1),
                "anyOf" | "oneOf" | "allOf" | "prefixItems" => match val.as_array() {
                    Some(a) => {
                        serde_json::Value::Array(a.iter().map(|s| walk(s, depth + 1)).collect())
                    }
                    None => val.clone(),
                },
                _ => val.clone(),
            };
            out.insert(k.clone(), mapped);
        }
        // `nullable: true` → a `"null"` member in `type`; `nullable: false` is the default and
        // simply goes. A `nullable` with no string `type` beside it is left alone (nothing to widen).
        if let Some(nullable) = out.get("nullable").and_then(|n| n.as_bool()) {
            match out.get("type").and_then(|t| t.as_str()).map(str::to_string) {
                Some(t) => {
                    out.remove("nullable");
                    if nullable && t != "null" {
                        out.insert("type".to_string(), serde_json::json!([t, "null"]));
                    }
                }
                None if !nullable => {
                    out.remove("nullable");
                }
                None => {}
            }
        }
        serde_json::Value::Object(out)
    }
    walk(schema, 0)
}

/// Convert Vertex's RFC 3339 `createTime` (`2025-06-01T12:34:56.123456Z`, or with a `±HH:MM`
/// offset) into Unix epoch SECONDS — the IR's `created` (IR audit GEM-18). `None` for anything that
/// is not a well-formed RFC 3339 date-time, so a malformed value leaves `created` for the seam to
/// stamp exactly as before. Fractional seconds are truncated (the IR's `created` is whole seconds).
fn gemini_rfc3339_to_epoch(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    let num = |r: std::ops::Range<usize>| -> Option<i64> {
        let part = b.get(r)?;
        if part.is_empty() || !part.iter().all(u8::is_ascii_digit) {
            return None;
        }
        std::str::from_utf8(part).ok()?.parse().ok()
    };
    if b.len() < 20
        || b[4] != b'-'
        || b[7] != b'-'
        || !matches!(b[10], b'T' | b't')
        || b[13] != b':'
        || b[16] != b':'
    {
        return None;
    }
    let (year, month, day) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (hour, minute, second) = (num(11..13)?, num(14..16)?, num(17..19)?);
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }
    let mut i = 19;
    if b.get(i) == Some(&b'.') {
        i += 1;
        let start = i;
        while b.get(i).is_some_and(u8::is_ascii_digit) {
            i += 1;
        }
        if i == start {
            return None;
        }
    }
    let offset_secs: i64 = match b.get(i) {
        Some(b'Z' | b'z') if i + 1 == b.len() => 0,
        Some(sign @ (b'+' | b'-')) if i + 6 == b.len() && b[i + 3] == b':' => {
            let (oh, om) = (num(i + 1..i + 3)?, num(i + 4..i + 6)?);
            if oh > 23 || om > 59 {
                return None;
            }
            let o = oh * 3600 + om * 60;
            if *sign == b'+' {
                o
            } else {
                -o
            }
        }
        _ => return None,
    };
    // days_from_civil (Howard Hinnant's public-domain algorithm).
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let epoch = days * 86_400 + hour * 3600 + minute * 60 + second - offset_secs;
    u64::try_from(epoch).ok()
}

/// The `AUDIO` entry of a Gemini `promptTokensDetails` / `candidatesTokensDetails` modality list
/// (`[{"modality":"AUDIO","tokenCount":N}, …]`) — the audio slice the IR carries as
/// `input_audio_tokens` / `output_audio_tokens` (IR audit GEM-12). Attribution only: both IR fields
/// are slices of totals `billable_tokens` never reads. `None` when the list has no AUDIO entry.
fn gemini_modality_count(
    usage: Option<&serde_json::Value>,
    list: &str,
    modality: &str,
) -> Option<u64> {
    usage?
        .get(list)?
        .as_array()?
        .iter()
        .find(|e| e.get("modality").and_then(|m| m.as_str()) == Some(modality))
        .and_then(|e| e.get("tokenCount"))
        .and_then(read_count_u64)
}

/// Gemini's `logprobsResult` — two PARALLEL arrays, `chosenCandidates[i]` (the generated token at
/// position i) and `topCandidates[i].candidates[]` (the alternatives at that position) — zipped
/// into the neutral IR entries. Gemini carries no byte arrays (`bytes: None`; an OpenAI writer
/// synthesizes them from UTF-8).
fn read_gemini_logprobs(v: Option<&serde_json::Value>) -> Vec<crate::ir::IrTokenLogprob> {
    let chosen = match v
        .and_then(|lr| lr.get("chosenCandidates"))
        .and_then(|c| c.as_array())
    {
        Some(c) => c,
        None => return Vec::new(),
    };
    let tops = v
        .and_then(|lr| lr.get("topCandidates"))
        .and_then(|c| c.as_array());
    chosen
        .iter()
        .enumerate()
        .filter_map(|(i, c)| {
            Some(crate::ir::IrTokenLogprob {
                token: c.get("token")?.as_str()?.to_string(),
                logprob: c.get("logProbability")?.as_f64()?,
                bytes: None,
                top: tops
                    .and_then(|t| t.get(i))
                    .and_then(|t| t.get("candidates"))
                    .and_then(|c| c.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|t| {
                                Some(crate::ir::IrTopLogprob {
                                    token: t.get("token")?.as_str()?.to_string(),
                                    logprob: t.get("logProbability")?.as_f64()?,
                                    bytes: None,
                                })
                            })
                            .collect()
                    })
                    .unwrap_or_default(),
            })
        })
        .collect()
}

/// Neutral IR logprobs → Gemini's `logprobsResult` (chosen + top parallel arrays). `topCandidates`
/// is emitted only when at least one position carries alternatives, matching Gemini's own omission
/// of the array when `logprobs` (the top-count) was not requested.
fn write_gemini_logprobs_result(lps: &[crate::ir::IrTokenLogprob]) -> serde_json::Value {
    let chosen: Vec<serde_json::Value> = lps
        .iter()
        .map(|lp| serde_json::json!({"token": lp.token, "logProbability": lp.logprob}))
        .collect();
    let mut obj = serde_json::json!({ "chosenCandidates": chosen });
    if lps.iter().any(|lp| !lp.top.is_empty()) {
        let tops: Vec<serde_json::Value> = lps
            .iter()
            .map(|lp| {
                serde_json::json!({
                    "candidates": lp
                        .top
                        .iter()
                        .map(|t| serde_json::json!({"token": t.token, "logProbability": t.logprob}))
                        .collect::<Vec<serde_json::Value>>()
                })
            })
            .collect();
        obj["topCandidates"] = serde_json::json!(tops);
    }
    obj
}

/// Normalize Gemini's native `toolConfig.functionCallingConfig` into the IR `tool_choice` union.
///
/// Mapping: `AUTO` → `Auto`; `NONE` → `None`; `ANY` with no `allowedFunctionNames` → `Required`
/// (must call some tool); `ANY` + `allowedFunctionNames:[X, …]` → the targeted `Tool{name:X}` (the
/// IR models a single targeted tool, so the FIRST allowed name is used). An absent `toolConfig`,
/// absent `functionCallingConfig`/`mode`, or an unrecognized mode yields `None` (the `Option`) so a
/// request that never carried a directive does not gain a spurious one on translation. Takes the
/// whole `toolConfig` object so the caller can pass `obj.get("toolConfig")` directly.
fn read_gemini_tool_choice(
    tool_config: Option<&serde_json::Value>,
) -> Option<crate::ir::IrToolChoice> {
    let fcc = tool_config?.get("functionCallingConfig")?;
    let mode = fcc.get("mode").and_then(|m| m.as_str())?;
    match mode.to_uppercase().as_str() {
        "AUTO" => Some(crate::ir::IrToolChoice::Auto),
        "NONE" => Some(crate::ir::IrToolChoice::None),
        "ANY" => {
            // `allowedFunctionNames` is a LIST in Gemini, but the IR's `Tool` variant models a
            // SINGLE targeted tool. A single name maps cleanly to `Tool{name}`. With N>1 names,
            // fabricating `Tool{name: first}` would INVENT a stricter constraint (force exactly one
            // specific tool) the request never made; the directive is `Required` (call SOME tool)
            // and the subset itself rides the IR's `allowed_tools` slot (IR-10,
            // `read_gemini_allowed_tools`).
            let names = fcc.get("allowedFunctionNames").and_then(|a| a.as_array());
            match names {
                Some(arr) if arr.len() > 1 => Some(crate::ir::IrToolChoice::Required),
                _ => match names.and_then(|a| a.first()).and_then(|n| n.as_str()) {
                    Some(name) => Some(crate::ir::IrToolChoice::Tool {
                        name: name.to_string(),
                    }),
                    None => Some(crate::ir::IrToolChoice::Required),
                },
            }
        }
        _ => None,
    }
}

/// Emit the IR `tool_choice` union as a Gemini `functionCallingConfig` object.
fn write_gemini_tool_choice(tc: &crate::ir::IrToolChoice) -> serde_json::Value {
    match tc {
        crate::ir::IrToolChoice::Auto => serde_json::json!({"mode": "AUTO"}),
        crate::ir::IrToolChoice::None => serde_json::json!({"mode": "NONE"}),
        crate::ir::IrToolChoice::Required => serde_json::json!({"mode": "ANY"}),
        crate::ir::IrToolChoice::Tool { name } => {
            serde_json::json!({"mode": "ANY", "allowedFunctionNames": [name]})
        }
    }
}

/// Default a possibly-absent Gemini `functionCall.args` to an empty JSON OBJECT (`{}`), not `null`.
///
/// A zero-argument Gemini `functionCall` either OMITS the `args` field or sends an empty object.
/// The args field models a tool-call argument MAP, so the correct empty value is `{}` — serializing
/// `null` instead leaked `"input": null` / `"arguments": "null"` onto cross-protocol Anthropic /
/// OpenAI egress, an invalid tool-input shape strict SDKs reject (they require an object). An
/// EXPLICITLY-present value (including an explicit `null`, which a native client could send) is kept
/// verbatim — we only synthesize the empty object for the truly-absent case.
fn empty_object_if_absent(args: Option<&serde_json::Value>) -> serde_json::Value {
    match args {
        Some(v) => v.clone(),
        None => serde_json::Value::Object(serde_json::Map::new()),
    }
}

/// Coerce an `IrBlock::ToolUse.input` into a valid Gemini `functionCall.args` value.
///
/// Gemini's `functionCall.args` is a protobuf Struct: it MUST be a JSON OBJECT. A cross-protocol
/// reader (Anthropic/OpenAI/Bedrock/Cohere) can hand us a `ToolUse.input` that is NOT an object — a
/// JSON array (`[1,2]`), a bare scalar (`42`/`true`/`"text"`), a `null`, or an unparseable raw string
/// — and emitting any of those verbatim under `args` produces a request the backend rejects (400).
/// This mirrors the `ToolResult.response` coercion below: an object passes through byte-identical (so
/// the same-protocol Gemini→Gemini round-trip stays lossless), a `null` becomes an empty-but-valid
/// `{}`, and any other non-object (array/scalar) is wrapped under `{"args": <value>}` so its content
/// survives. A raw JSON string is parsed first, then the SAME coercion is applied to the parse result;
/// an unparseable string is treated as a scalar and wrapped.
fn coerce_tool_args(input: &serde_json::Value) -> serde_json::Value {
    // Resolve the candidate value: a string is a serialized payload — parse it, falling back to the
    // string itself (a scalar) when it does not parse as JSON. Any non-string value is used as-is.
    let candidate: serde_json::Value = match input.as_str() {
        Some(s) => busbar_substrate_values::json::parse_str(s).unwrap_or_else(|_| input.clone()),
        None => input.clone(),
    };
    if candidate.is_object() {
        candidate
    } else if candidate.is_null() {
        serde_json::json!({})
    } else {
        serde_json::json!({ "args": candidate })
    }
}

/// True when a Gemini response/stream chunk carries NO usable `candidates` (absent, non-array, OR an
/// EMPTY array). Used to distinguish a prompt-block / error-only envelope from a normal
/// candidate-bearing chunk.
///
/// An EMPTY `candidates: []` is treated the SAME as a missing array: a native Gemini envelope that
/// rejects the PROMPT (e.g. `{"candidates":[],"promptFeedback":{"blockReason":"SAFETY"}}`) carries an
/// empty candidates array alongside the top-level `promptFeedback.blockReason`. Keying only on
/// array-PRESENCE (the old behavior) let that empty-array shape slip past the prompt-block arm in both
/// the streaming reader and `read_response`, so the streaming path emitted a bare un-terminated stream
/// and the non-streaming path hard-failed `candidates.is_empty()` into a spurious `ir_parse` error —
/// dropping a legitimate content-policy block. Broadening to treat `[]` as absent routes both into the
/// existing prompt-block / terminal arms. A genuinely empty array with NO block reason still falls
/// through to the existing handling below those arms (unchanged).
fn candidates_absent(data: &serde_json::Value) -> bool {
    match data.get("candidates").and_then(|c| c.as_array()) {
        Some(arr) => arr.is_empty(),
        None => true,
    }
}

/// Extract a top-level `promptFeedback.blockReason` (the PROMPT-level content block signal) if the
/// envelope carries one, e.g. `{"promptFeedback":{"blockReason":"SAFETY"}}`. Returns the raw reason
/// string (SAFETY / BLOCKLIST / PROHIBITED_CONTENT / OTHER / …) so the caller can map it to a
/// canonical stop reason. `None` when absent or not a non-empty string.
fn prompt_block_reason(data: &serde_json::Value) -> Option<&str> {
    data.get("promptFeedback")
        .and_then(|pf| pf.get("blockReason"))
        .and_then(|r| r.as_str())
        .filter(|s| !s.is_empty())
}

/// Map a Gemini candidate `finishReason` to a canonical IR stop reason.
///
/// `STOP`/`MAX_TOKENS`/`SAFETY` map to their direct canonical siblings (`end_turn`/`max_tokens`/
/// `safety`). The remaining Gemini-only reasons — `RECITATION`, `IMAGE_SAFETY`, `SPII`,
/// `BLOCKLIST`, `PROHIBITED_CONTENT` (content-policy stops) → `safety`; `MALFORMED_FUNCTION_CALL`
/// (the model emitted an UNPARSEABLE tool call — generation FAILED, there is NO valid call to run)
/// → `error`, NOT `tool_use`: `tool_use` would tell the client to execute and continue a tool call
/// that does not exist, so it would search for a tool_use block, find none/garbage and break; `OTHER`,
/// `LANGUAGE`, and any unknown future reason → the canonical `Other` variant (`_ => S::Other`) — were
/// previously passed through `to_lowercase()` VERBATIM, producing values (`recitation`,
/// `malformed_function_call`, `spii`, …) that NO downstream SDK enum recognizes. Mapping them to the
/// canonical IR set the Anthropic/OpenAI writers already translate (`safety`→Anthropic `safety`/OpenAI
/// `content_filter`; `error`→`end_turn`/`stop`; `Other`→each writer's natural-stop default) keeps the
/// translation lossless instead of leaking an unrecognized Gemini token to a non-Gemini client. A
/// Gemini→Gemini round-trip is unaffected: the writer emits `Other` back as the native `OTHER`
/// finishReason (`write_gemini_stop_reason`: `Other => GEMINI_FINISH_OTHER`) and `safety` back as
/// `SAFETY`, so a Gemini `OTHER` stop round-trips OTHER→Other→OTHER unchanged; these stops are terminal
/// — the body is not replayed. (Do NOT "simplify" the `_ => S::Other` arm to `S::EndTurn`: that would
/// silently convert a Gemini→Gemini `OTHER` stop into `STOP`.)
fn map_gemini_finish_reason(finish_reason: &str) -> crate::ir::IrStopReason {
    use crate::ir::IrStopReason as S;
    match finish_reason {
        GEMINI_FINISH_STOP => S::EndTurn,
        GEMINI_FINISH_MAX_TOKENS => S::MaxTokens,
        GEMINI_FINISH_SAFETY
        | GEMINI_FINISH_RECITATION
        | "IMAGE_SAFETY"
        | "SPII"
        | "BLOCKLIST"
        | GEMINI_FINISH_PROHIBITED_CONTENT
        // The image-generation content-policy stops (IR audit GEM-15): the same policy refusal
        // as their text siblings above, applied to an image the model was generating.
        | "IMAGE_PROHIBITED_CONTENT"
        | "IMAGE_RECITATION" => S::Safety,
        // The model produced an invalid function call: an abnormal stop with no runnable tool call.
        // `UNEXPECTED_TOOL_CALL` (the model called a tool while none was enabled) is the same
        // failed generation — there is no call the client could run (GEM-15).
        GEMINI_FINISH_MALFORMED_FUNCTION_CALL | "UNEXPECTED_TOOL_CALL" => S::Error,
        // OTHER / LANGUAGE / any novel future reason.
        _ => S::Other,
    }
}

/// Map a Gemini `promptFeedback.blockReason` to a canonical IR stop reason. A prompt block is a
/// content-policy refusal of the input, so it surfaces as `safety` (matching the candidate-level
/// `finishReason: SAFETY` → `safety` mapping) for the well-known content-policy reasons; any other
/// reason is lowercased so a novel block reason is still surfaced rather than dropped.
fn prompt_block_stop_reason(block_reason: &str) -> crate::ir::IrStopReason {
    use crate::ir::IrStopReason as S;
    match block_reason {
        // RECITATION maps to Safety at the candidate level (and per GEMINI_FINISH_RECITATION's own
        // doc); classify a prompt-level RECITATION block the same way, not Other.
        GEMINI_FINISH_SAFETY
        | "BLOCKLIST"
        | GEMINI_FINISH_PROHIBITED_CONTENT
        | GEMINI_FINISH_RECITATION
        // A prompt blocked for its IMAGE content is the same policy block (IR audit GEM-15).
        | "IMAGE_SAFETY" => S::Safety,
        _ => S::Other,
    }
}

/// [`crate::ir::IrStopReason`] → Gemini native `finishReason`. EXHAUSTIVE: Gemini's enum has NO
/// TOOL_USE member (a tool-call turn ends with STOP), so EndTurn/StopSequence/ToolUse → STOP;
/// MaxTokens → MAX_TOKENS; Safety → SAFETY; any other reason → the native `OTHER` member (a valid enum
/// value that honestly signals an unenumerated stop, never an off-spec upper-cased token).
fn write_gemini_stop_reason(reason: crate::ir::IrStopReason) -> &'static str {
    use crate::ir::IrStopReason as S;
    match reason {
        S::EndTurn | S::StopSequence | S::ToolUse => GEMINI_FINISH_STOP,
        S::MaxTokens => GEMINI_FINISH_MAX_TOKENS,
        // A refusal is the model declining on policy grounds — Gemini's SAFETY stop, not an
        // unenumerated OTHER (IR audit GEM-14).
        S::Safety | S::Refusal => GEMINI_FINISH_SAFETY,
        S::Error | S::PauseTurn | S::Other => GEMINI_FINISH_OTHER,
    }
}

/// Map a canonical `StatusClass` onto the `(HTTP code, google.rpc.Code name)` pair Gemini uses in
/// its `google.rpc.Status` error envelope. Exhaustive over `StatusClass` (no `_ =>` catch-all) so
/// a new class forces a conscious choice here rather than silently degrading to INTERNAL.
fn gemini_stream_error_code_status(class: StatusClass) -> (u16, &'static str) {
    match class {
        StatusClass::RateLimit => (429, GRPC_RESOURCE_EXHAUSTED),
        StatusClass::Overloaded => (503, GRPC_UNAVAILABLE),
        StatusClass::ServerError => (500, GRPC_INTERNAL),
        StatusClass::Timeout => (504, GRPC_DEADLINE_EXCEEDED),
        StatusClass::Network => (503, GRPC_UNAVAILABLE),
        StatusClass::Auth => (401, GRPC_UNAUTHENTICATED),
        StatusClass::Billing => (403, GRPC_PERMISSION_DENIED),
        StatusClass::ClientError => (400, GRPC_INVALID_ARGUMENT),
        StatusClass::ContextLength => (400, GRPC_INVALID_ARGUMENT),
    }
}

/// Map an inline google.rpc.Status `(status name, code)` — as delivered in a 200-status SSE error
/// chunk's `error` object — onto a canonical `StatusClass`. This is the read-side inverse of
/// `gemini_stream_error_code_status` (which maps `StatusClass` back onto `(code, name)` for the
/// writer): an inline upstream error is mapped to a class so the downstream ingress writer can
/// terminate the stream with a protocol-shaped error frame.
///
/// Preference order: the UPPER_SNAKE google.rpc.Code `status` string when present (the authoritative
/// field a native Gemini SDK branches on), falling back to the numeric HTTP `code` when `status` is
/// absent or unrecognized. The `status` arm is exhaustive over the google.rpc.Code names the real
/// Generative Language API emits; an unrecognized string falls through to the numeric-code mapping,
/// and a name we do not model is bound to a NAMED arm (not a `_` wildcard that silently degrades —
/// per the no-catch-all rule; `&str`/`Option<&str>` matches are never type-exhaustive so a named
/// fallback is the explicit-choice equivalent here). An absent/unknown code defaults to
/// `ServerError` — the safe class for an unclassified upstream failure (it is retryable and trips
/// the breaker, never masking a real failure as success).
fn gemini_error_status_class(status: Option<&str>, code: Option<u64>) -> StatusClass {
    if let Some(name) = status {
        match name {
            GRPC_RESOURCE_EXHAUSTED => return StatusClass::RateLimit,
            GRPC_UNAVAILABLE => return StatusClass::Overloaded,
            GRPC_DEADLINE_EXCEEDED => return StatusClass::Timeout,
            GRPC_UNAUTHENTICATED => return StatusClass::Auth,
            GRPC_PERMISSION_DENIED => return StatusClass::Billing,
            GRPC_INVALID_ARGUMENT
            | "FAILED_PRECONDITION"
            | "OUT_OF_RANGE"
            | GRPC_NOT_FOUND
            | "ALREADY_EXISTS"
            | "ABORTED"
            | "CANCELLED" => return StatusClass::ClientError,
            GRPC_INTERNAL | "UNKNOWN" | "DATA_LOSS" | GRPC_UNIMPLEMENTED => {
                return StatusClass::ServerError
            }
            // An UPPER_SNAKE status string outside the modeled google.rpc.Code set: fall through to
            // the numeric `code` mapping below rather than guessing. Named (not `_`) per the
            // no-catch-all rule; `other` is intentionally unused beyond falling through.
            other => {
                let _ = other;
            }
        }
    }
    match code {
        Some(429) => StatusClass::RateLimit,
        Some(503) => StatusClass::Overloaded,
        Some(504) => StatusClass::Timeout,
        Some(401) => StatusClass::Auth,
        Some(403) => StatusClass::Billing,
        Some(c) if (400..500).contains(&c) => StatusClass::ClientError,
        // Any 5xx, or an absent/unknown code: ServerError is the safe, breaker-tripping default for
        // an unclassified upstream failure rather than masking it as a client error.
        Some(_) | None => StatusClass::ServerError,
    }
}

/// Gemini writer implementation.
///
/// Carries one piece of per-stream state: the open streaming tool calls. A native Gemini SSE stream
/// emits a tool call as a SINGLE `functionCall` part `{name, args}`. The IR, however, carries the
/// tool NAME only on the `BlockStart` (`IrBlockMeta::ToolUse{name}`) and the arguments only on the
/// following `InputJsonDelta(String)` fragment(s) — and a cross-protocol backend (OpenAI / Anthropic)
/// commonly streams the `arguments` JSON across MULTIPLE partial-JSON fragments (`{"lo`, `c":"SF"}`),
/// each surfaced as its OWN `InputJsonDelta`. A stateless writer that emits one IR event at a time
/// therefore produced N parts on the wire — a `{name, args:{}}` BlockStart frame plus one nameless
/// `{args}` delta frame PER fragment, each parsing a partial fragment that fails (so `args:{}`) — a
/// split-and-data-loss shape a native google-genai client never sees (and where a strict client
/// reading `part.function_call.name` sees an empty name and lost arguments).
///
/// To emit the native single `{name, args}` shape REGARDLESS of fragmentation we BUFFER per open tool
/// block: the name from its `BlockStart` and every `InputJsonDelta` fragment CONCATENATED into one
/// arg string. We emit nothing on the BlockStart or the deltas; on `BlockStop` we parse the fully
/// reassembled arg string ONCE and emit a single `{name, args}` part. A zero-argument tool call (no
/// delta at all) flushes `{name, args:{}}` the same way, so the call is never lost.
///
/// The buffer is a `Vec` keyed by IR block index, NOT a single slot: a cross-protocol backend may
/// open several parallel tool blocks (OpenAI streams `tool_calls` index 0 and 1; the OpenAI reader
/// emits BlockStart(1), BlockStart(2), then their deltas, then BlockStop(1), BlockStop(2) at finish —
/// the BlockStarts are NOT strictly interleaved with their own BlockStop). A single-slot buffer would
/// be clobbered by the second BlockStart, dropping the first tool's name and args. The per-index Vec
/// lets every open tool accumulate independently.
///
/// `StreamTranslate::new` builds a FRESH `Protocol::gemini()` (hence a fresh `GeminiWriter` with an
/// empty buffer) for each stream, so this state is stream-scoped by construction — exactly the
/// precedent `ResponsesWriter`'s per-stream `sequence`/`response_id` fields established.
/// One open streaming tool call in [`GeminiWriter::open_tools`]: the IR block `index` its
/// `BlockStart` opened, the call's `id` (re-emitted as `functionCall.id`, GEM-08), its function `name`
/// and every `InputJsonDelta` fragment concatenated into `args`.
#[derive(Clone, Debug)]
struct GeminiOpenTool {
    index: usize,
    id: String,
    name: String,
    args: String,
}

pub struct GeminiWriter {
    /// The currently open streaming tool calls, one [`GeminiOpenTool`] per OPEN tool block:
    /// - `index` is the IR block index from the opening `BlockStart`, used to match subsequent
    ///   `BlockDelta`/`BlockStop` events to THE RIGHT tool block (parallel tool calls share no slot).
    /// - `id` and `name` are the call id and function name buffered off the `BlockStart`.
    /// - `args` is every `InputJsonDelta` fragment for this block CONCATENATED, so a multi-chunk
    ///   streamed `arguments` JSON reassembles into one string parsed once on `BlockStop`. An empty
    ///   string (no delta arrived) flushes `args:{}` for a zero-argument tool call.
    ///
    /// A `Vec` (not a map) keeps the dependency surface nil and the common case (0–2 open tools)
    /// trivially cheap; lookups are a linear scan over the open set, which is bounded by the upstream
    /// reader's own tool-frame cap.
    ///
    /// `Mutex` (not `Cell`) so the writer stays `Sync` as the `ProtocolWriter` trait requires; a
    /// stream is single-threaded at any instant so contention is nil, and a poisoned lock degrades
    /// to the stateless behavior rather than panicking on the request path.
    open_tools: std::sync::Mutex<Vec<GeminiOpenTool>>,
    /// THIS STREAM'S `responseId`, minted ONCE and replayed on every later identity frame.
    ///
    /// A stream is not guaranteed to carry exactly one `MessageStart`: the Anthropic reader emits
    /// it 1:1 with the upstream frame rather than gating it, so a gemini-egress stream fed from an
    /// Anthropic ingress can see two. Without this cell the second synthesized a FRESH
    /// `responseId`, so one response announced itself twice under two different ids and the
    /// `google-genai` SDK's `chunk.response_id` changed mid-stream. A native Gemini stream's
    /// `responseId` is fixed for the response, so the first one wins. Same `Mutex` /
    /// poison-degrades discipline as `open_tools`.
    response_id: std::sync::Mutex<Option<String>>,
    /// THIS STREAM'S answer text so far, and the byte offset each text block started at — what a
    /// streamed citation's CHARACTER offsets (the IR contract, relative to their own text block) are
    /// converted against to become the candidate-wide BYTE offsets Gemini's `citationSources` carry
    /// (IR audit GEM-16), exactly as the buffered writer converts them. Same `Mutex` /
    /// poison-degrades discipline as `open_tools`; a poisoned lock passes offsets through unconverted.
    stream_text: std::sync::Mutex<GeminiStreamText>,
}

/// The streamed answer text [`GeminiWriter::stream_text`] accumulates: the concatenated `text` and
/// one `(ir_block_index, byte_start)` per text block, in the order the blocks first carried text.
#[derive(Clone, Debug, Default)]
struct GeminiStreamText {
    text: String,
    block_starts: Vec<(usize, usize)>,
}

/// Value-namespace constructor for [`GeminiWriter`]. A `const` and a struct may share a name (they
/// live in the value and type namespaces respectively), so every existing site that writes the bare
/// `GeminiWriter` literal — `Protocol::gemini()` and the tests — keeps compiling unchanged while the
/// type now carries per-stream state. Each USE of the const inlines a FRESH `GeminiWriter` with an
/// empty `open_tool` buffer, so every `Protocol::gemini()` call mints an independent buffer — the
/// per-stream scoping the single-frame functionCall fix needs. `Mutex::new`/`None` are const, so
/// this is valid in const context.
///
/// `clippy::declare_interior_mutable_const` warns that a `const` with interior mutability is inlined
/// per use rather than shared. That per-use fresh instance is PRECISELY the semantics we need: a
/// `static` would share ONE buffer across every stream in the process, bleeding one stream's open
/// tool name into another. So the lint's suggestion is wrong for this site and is suppressed
/// deliberately — mirroring `ResponsesWriter`.
#[allow(non_upper_case_globals)]
#[allow(clippy::declare_interior_mutable_const)]
pub const GeminiWriter: GeminiWriter = GeminiWriter {
    open_tools: std::sync::Mutex::new(Vec::new()),
    response_id: std::sync::Mutex::new(None),
    stream_text: std::sync::Mutex::new(GeminiStreamText {
        text: String::new(),
        block_starts: Vec::new(),
    }),
};

impl Clone for GeminiWriter {
    fn clone(&self) -> Self {
        // Preserve the in-flight open tool calls across a mid-stream `Protocol::clone` so the
        // functionCall name/args correlation survives; a poisoned lock degrades to an empty buffer
        // (stateless behavior) rather than panicking on the request path.
        GeminiWriter {
            open_tools: std::sync::Mutex::new(
                self.open_tools
                    .lock()
                    .map(|t| t.clone())
                    .unwrap_or_default(),
            ),
            // A mid-stream clone is still the SAME response, so it keeps the id already announced.
            response_id: std::sync::Mutex::new(
                self.response_id.lock().map(|id| id.clone()).unwrap_or(None),
            ),
            stream_text: std::sync::Mutex::new(
                self.stream_text
                    .lock()
                    .map(|t| t.clone())
                    .unwrap_or_default(),
            ),
        }
    }
}

impl GeminiWriter {
    /// THE STREAM'S `responseId`: the first one wins. Returns the id already captured for this
    /// stream if there is one, otherwise captures and returns `mint()`, so a duplicate identity
    /// frame re-states the id the client already has. Lock poisoning degrades to the freshly minted
    /// id rather than panicking on the request path.
    fn carried_response_id(&self, mint: impl FnOnce() -> String) -> String {
        match self.response_id.lock() {
            Ok(mut slot) => slot.get_or_insert_with(mint).clone(),
            Err(_) => mint(),
        }
    }
}

#[cfg(test)]
#[path = "tests/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/input_hardening_tests.rs"]
mod input_hardening_tests;

#[cfg(test)]
#[path = "tests/logprobs_carry_tests.rs"]
mod logprobs_carry_tests;

#[cfg(test)]
#[path = "tests/image_url_mime_regression_tests.rs"]
mod image_url_mime_regression_tests;

#[cfg(test)]
#[path = "tests/field_carry_tests.rs"]
mod field_carry_tests;

#[cfg(test)]
#[path = "tests/usage_identity_tests.rs"]
mod usage_identity_tests;

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
