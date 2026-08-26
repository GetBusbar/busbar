// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Shared helpers and constants for the OpenAI-family protocols (Chat Completions and Responses).
//! Both wire formats belong to the same provider family; items that are identical across them
//! live here so they are single-sourced rather than copy-pasted (and risking drift).

#[cfg(any(test, feature = "test-support"))]
use axum::http::StatusCode;

/// Machine-readable `code` field emitted in a bad-key 401 OpenAI-family error envelope.
/// Used in `bearer_error_code` to mirror the native `authentication_error` → `invalid_api_key`
/// pairing that official SDKs surface as `error.code`. Also matched by the Responses stream
/// classifier (`class_for_response_failed`) when the provider signal echoes this code back.
pub const CODE_INVALID_API_KEY: &str = "invalid_api_key";

/// Busbar-internal `provider_signal` label for a context-length result (the LANE label, not the
/// OpenAI wire code). Distinct from `PROVIDER_CODE_CONTEXT_LENGTH` ("context_length_exceeded"),
/// which is the provider-facing code extracted from the request body. Gated the same as
/// `openai_classify`, its only referent, a test-only single-source mirror of the production
/// classifier — visible to a dependent crate's test builds too via the `test-support` feature.
#[cfg(any(test, feature = "test-support"))]
pub const PROVIDER_SIGNAL_CONTEXT_LENGTH: &str = "context_length";

/// Fallback model name when a cross-protocol request carries none. The Chat-Completions and
/// Responses writers are two wire formats of the SAME provider family, so this value is
/// deliberately identical and MUST stay in lockstep — single-sourced here and referenced by both
/// modules. If the two protocols ever genuinely diverge, split it back out at that point.
pub const OPENAI_FAMILY_DEFAULT_MODEL: &str = "gpt-4o";

/// DoS cap on concurrently-tracked open tool-call accumulators per stream. Matches OpenAI's
/// documented parallel-tool-call limit (128). Single-sourced here so Chat Completions and
/// Responses cannot drift.
pub const OPENAI_FAMILY_MAX_OPEN_TOOLS: usize = 128;

// CANONICAL error-kind vocabulary home. The forward-layer KIND_* bank (`proxy::KIND_*`), the
// admin API's ERR_TYPE_NOT_FOUND/ERR_TYPE_INVALID_REQUEST, and the anthropic writer's private
// ERR_TYPE_* bank all alias these consts, so the shared string values are single-sourced here and
// cannot drift. (`proxy::KIND_OVERLOADED` = "overloaded" and anthropic's "timeout_error" are
// DELIBERATELY different values and stay defined at their own sites.)
/// OpenAI error `type` for a malformed / bad-argument request.
pub const ERR_TYPE_INVALID_REQUEST: &str = "invalid_request_error";
/// OpenAI error `type` for a missing or invalid API key. Relocated to the neutral
/// `busbar_substrate::proto` leaf (Batch A) so `busbar-mcp` names it without depending on
/// `busbar-core`; re-exported here so every existing caller is unchanged.
pub use busbar_substrate::proto::ERR_TYPE_AUTHENTICATION;
/// OpenAI error `type` for a permission / access-control denial.
pub const ERR_TYPE_PERMISSION: &str = "permission_error";
/// OpenAI error `type` for a resource that does not exist.
pub const ERR_TYPE_NOT_FOUND: &str = "not_found_error";
/// OpenAI error `type` for a rate-limit / throttle response.
pub const ERR_TYPE_RATE_LIMIT: &str = "rate_limit_error";
/// OpenAI error `type` for a transient upstream failure.
pub const ERR_TYPE_SERVER_ERROR: &str = "server_error";
/// OpenAI error `type` for a billing-quota exhaustion (HTTP 429).
pub const ERR_TYPE_INSUFFICIENT_QUOTA: &str = "insufficient_quota";
/// Anthropic/busbar internal kind for an overloaded upstream; mapped to `server_error` on the
/// OpenAI wire (OpenAI has no `overloaded_error` type).
pub const ERR_TYPE_OVERLOADED: &str = "overloaded_error";
/// Anthropic-vocabulary error `type` for a generic upstream/API failure; also the agnostic
/// forward-layer kind (`proxy::KIND_API_ERROR` aliases this).
pub const ERR_TYPE_API_ERROR: &str = "api_error";
/// Error `type` for an oversized request (HTTP 413); shared by the forward KIND bank and the
/// anthropic writer.
pub const ERR_TYPE_REQUEST_TOO_LARGE: &str = "request_too_large";

/// Precise context-length prose scan shared by `OpenAiReader::extract_error` and
/// `ResponsesReader::extract_error` — the message scan was duplicated. The scan must be PRECISE:
/// a naive OR of weak tokens (`token`/`maximum`) misclassifies unrelated errors (e.g. a quota body
/// like "maximum number of tokens allowed per day" — a rate-limit, not oversized). Require a
/// CO-LOCATED context-length phrase: a self-contained canonical phrase, or `exceeds` paired
/// specifically with `context`/`token limit`. The caller supplies its own lowercased source
/// (openai scans `error.message`; responses scans the whole body) and applies the
/// `oversized_status` (400/413) GATE itself — that gate is NOT part of this helper.
pub fn openai_context_length_prose_scan(text: &str) -> bool {
    text.contains("maximum context length")
        || text.contains("context length exceeded")
        || text.contains("reduce the length")
        || (text.contains("exceeds") && (text.contains("context") || text.contains("token limit")))
}

/// Map an OpenAI-family error `type` string onto its canonical machine-readable `code`, shared by
/// the OpenAI Chat Completions and `/v1/responses` writers (both emit the identical OpenAI error
/// envelope). A real bad-key 401 returns `{"type":"authentication_error", ..., "code":"invalid_api_key"}`
/// and the official SDKs surface `error.code` to callers, so emitting `code: null` on an auth (or
/// over-quota) failure is a deterministic proxy tell that contradicts the total-indistinguishability
/// promise — we mirror the native pairing for those two types. Every other modeled type, plus any
/// caller-supplied passthrough type, keeps `null`: the shape OpenAI uses when no machine-readable
/// code applies. There is no `_ =>` catch-all hiding an unhandled case; the final arm binds `other`
/// explicitly and emits `null`, the correct native value for those types.
pub fn bearer_error_code(error_type: &str) -> serde_json::Value {
    match error_type {
        crate::proxy::KIND_AUTHENTICATION => {
            serde_json::Value::String(CODE_INVALID_API_KEY.to_string())
        }
        // Real OpenAI quota-exhaustion errors carry BOTH `type` and `code` set to
        // `insufficient_quota` (HTTP 429). The over-budget governance path
        // (ingress `ingress_error(..., KIND_INSUFFICIENT_QUOTA, ...)`) reaches these writers with that
        // type; emitting `code: null` for it is an SDK-visible mismatch (the official client surfaces
        // `error.code == "insufficient_quota"`) and a proxy tell, so we mirror the native pairing.
        crate::proxy::KIND_INSUFFICIENT_QUOTA => {
            serde_json::Value::String(crate::proxy::KIND_INSUFFICIENT_QUOTA.to_string())
        }
        crate::proxy::KIND_INVALID_REQUEST
        | crate::proxy::KIND_PERMISSION
        | crate::proxy::KIND_NOT_FOUND
        | crate::proxy::KIND_RATE_LIMIT
        | crate::proxy::KIND_SERVER_ERROR
        | crate::proxy::KIND_API_ERROR => serde_json::Value::Null,
        other => {
            // A caller-supplied passthrough type we model no code for: OpenAI carries no
            // machine-readable code for these, so `null` matches the native shape. Named binding
            // (not `_`) keeps the arm explicit per the no-catch-all rule.
            let _ = other;
            serde_json::Value::Null
        }
    }
}

/// Canonical OpenAI-family error classification, shared verbatim by `OpenAiReader::classify` and
/// `ResponsesReader::classify` (the two were word-for-word identical). Both surfaces emit the same
/// OpenAI error envelope, so the mapping — context-length-exceeded (fail over without penalty) first,
/// then 429→RateLimit, 401/403→Auth, 5xx→ServerError, other 4xx→ClientError — is single-sourced here.
#[cfg(any(test, feature = "test-support"))]
pub fn openai_classify(status: StatusCode, body: &[u8]) -> crate::breaker::CanonicalSignal {
    use crate::breaker::StatusClass;
    // context-length-exceeded — the lane is healthy; this must fail over (to a larger-context
    // model), not penalize the breaker. Detect by OpenAI code/message first.
    let code_is_context = serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|j| {
            j.get("error")
                .and_then(|e| e.get("code"))
                .and_then(|c| c.as_str())
                .map(|s| s.to_string())
        })
        .as_deref()
        == Some(crate::proxy::PROVIDER_CODE_CONTEXT_LENGTH);
    // Mirror production `extract_error`: the prose message scan is GATED to the HTTP statuses an
    // oversized request actually uses (400 invalid_request_error; 413 payload-too-large). Without the
    // gate a 401/429/5xx whose prose happens to contain "maximum context length" would reclassify as
    // ContextLength — letting a genuine auth/rate-limit/server failure escape fault attribution. The
    // structured `code: "context_length_exceeded"` path is NOT gated (it is unambiguous).
    let oversized = status == StatusCode::BAD_REQUEST || status == StatusCode::PAYLOAD_TOO_LARGE;
    let body_lower = String::from_utf8_lossy(body).to_lowercase();
    if code_is_context || (oversized && body_lower.contains("maximum context length")) {
        return crate::breaker::CanonicalSignal {
            class: StatusClass::ContextLength,
            provider_signal: Some(PROVIDER_SIGNAL_CONTEXT_LENGTH.to_string()),
            retry_after: None,
        };
    }

    if status == StatusCode::TOO_MANY_REQUESTS {
        return crate::breaker::CanonicalSignal {
            class: StatusClass::RateLimit,
            provider_signal: Some("429".to_string()),
            retry_after: None,
        };
    }

    if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
        return crate::breaker::CanonicalSignal {
            class: StatusClass::Auth,
            provider_signal: Some("auth".to_string()),
            retry_after: None,
        };
    }

    if status.is_server_error() {
        return crate::breaker::CanonicalSignal {
            class: StatusClass::ServerError,
            provider_signal: Some("5xx".to_string()),
            retry_after: None,
        };
    }

    if status.is_client_error() {
        return crate::breaker::CanonicalSignal {
            class: StatusClass::ClientError,
            provider_signal: Some(format!("{}", status.as_u16())),
            retry_after: None,
        };
    }

    crate::breaker::CanonicalSignal {
        class: StatusClass::ClientError,
        provider_signal: None,
        retry_after: None,
    }
}

/// Busbar-internal `extra` key parking OpenAI Chat's per-message `messages[].name` (the optional
/// participant name that disambiguates several speakers in one role).
///
/// WHY A SENTINEL AND NOT AN `IrMessage` FIELD: `name` has NO representation in ANY other protocol in
/// the matrix — Anthropic, Gemini, Bedrock, Cohere and even Responses all model a turn as
/// (role, content) with no participant name — so a first-class IR field would be a field only one
/// dialect could ever read or write. It rides `extra` instead, which gives exactly the right scope:
///
/// * SAME-PROTOCOL (including a pool-alias route that re-serializes rather than forwarding bytes):
///   the writer reads it back and re-emits `name` on each message, so a participant name no longer
///   disappears the moment a route rewrites the model. That was a real same-protocol loss.
/// * CROSS-PROTOCOL: `extra` is cleared at the seam and `ir/variant.rs` names this key in its
///   dropped-keys warn, so the loss is signalled instead of silent.
///
/// Value shape: an object keyed by the message's index in `IrRequest.messages` (as a decimal string)
/// → the name. Keyed by index rather than positional array so a request where only message 7 has a
/// name costs one entry, and so the writer's lookup cannot be thrown off by a `null` hole.
///
/// LIVES HERE (not in the `busbar-llm` plugin) because core's `ir/variant.rs` names this key by
/// its own const, not a duplicated string literal — a genuine core<->dialect crossing, unlike
/// `MAX_COMPLETION_TOKENS_SENTINEL` (openai_chat-only, stays in that crate).
pub const MESSAGE_NAMES_SENTINEL: &str = "__busbar_openai_message_names";

// SHARED ACROSS THE OPENAI-FAMILY DIALECTS AND COHERE (tool-call argument stringification): cohere's
// and the openai writers/readers call this too, so it stays at this shared crossing rather than
// becoming a cross-protocol-crate dependency. It names no concrete IR, so it is a neutral string
// helper that legitimately lives in core. (The url-citation projection that used to sit here HAS
// moved to `busbar-llm/src/openai_annotations.rs` — it names `IrCitation`, so it belongs beside the
// openai codecs that own it, reached through the reader/writer vtable.)
/// Render an IR ToolUse `input` value as the OpenAI `function.arguments` string.
///
/// OpenAI carries tool-call arguments as a *string* of JSON. The reader stores well-formed
/// arguments as a parsed `Value`, but falls back to `Value::String(raw)` when the upstream sent
/// arguments that are not valid JSON (a streaming-partial or malformed tool call). Re-serializing
/// such a `Value::String` via `crate::json::to_string` would JSON-encode the string a second time —
/// emitting an escaped, quoted blob on the wire (double-encoding). Emit a `Value::String` verbatim
/// so the original argument text round-trips unchanged; any other `Value` is serialized normally.
pub fn tool_arguments_to_string(input: &serde_json::Value) -> String {
    match input {
        serde_json::Value::String(s) => s.clone(),
        other => crate::json::to_string(other).unwrap_or_else(|_| "{}".to_string()),
    }
}

#[cfg(test)]
#[path = "tests/openai_family_tests.rs"]
mod tests;
