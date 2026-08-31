// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! NEUTRAL WIRE/EGRESS VALUE TYPES — the serialized-body carrier an `OperationHandler` yields and
//! the resolved-primitives egress context routing hands a `RequestHandler`. Both are pure value
//! types a plane crate names without reaching into `busbar-core`; core re-exports them from
//! `busbar_core::handlers::{WireBody, EgressCtx}` so its own call sites are unchanged.

use busbar_api::operation::Operation;
use bytes::Bytes;
use serde_json::Value;

/// A serialized wire body plus the content-type the OperationHandler chose for it. The engine relays both without
/// interpreting either — `application/json` for JSON ops, `audio/mpeg` etc. for a binary op like speech.
pub struct WireBody {
    pub bytes: Bytes,
    pub content_type: axum::http::HeaderValue,
}

impl WireBody {
    /// JSON body — the common case.
    pub fn json(bytes: Bytes) -> Self {
        Self {
            bytes,
            content_type: axum::http::HeaderValue::from_static("application/json"),
        }
    }
    /// A body with an explicit content-type (e.g. audio speech). Falls back to octet-stream if the
    /// content-type string is not a valid header value.
    pub fn typed(bytes: Bytes, content_type: &str) -> Self {
        let content_type = axum::http::HeaderValue::from_str(content_type)
            .unwrap_or_else(|_| axum::http::HeaderValue::from_static("application/octet-stream"));
        Self {
            bytes,
            content_type,
        }
    }
}

/// What routing hands a `RequestHandler` so it can render the upstream URL path. RESOLVED PRIMITIVES
/// ONLY — never the `Lane` or a config handle: a codec/handler touching routing state is exactly the
/// coupling this fixes. Grows a field (region, api-version, …) when a protocol needs more; the trait
/// signature does not. Routing populates it from the lane and applies any `lane.path` override itself.
pub struct EgressCtx<'a> {
    /// Which operation's endpoint to render — the template selector.
    pub operation: Operation,
    /// The resolved wire model id (routing calls `Lane::wire_model()`), for URL-model protocols
    /// (Gemini `models/{model}:…`, Bedrock `model/{model}/invoke`).
    pub model: &'a str,
    /// Whether the caller asked to stream (chat/audio path variants); `false` for the JSON ops.
    pub stream: bool,
    /// Optional per-provider path-BASE override (the lane's `path_base`). For URL-model protocols
    /// (Gemini) it replaces the protocol's hardcoded base segment (e.g. `/v1beta/models`) so a
    /// provider can be pointed at a different layout — e.g. Vertex AI's
    /// `/v1/projects/{p}/locations/{l}/publishers/google/models`. `None` uses the protocol default.
    /// Distinct from the full-path `path` override, which is static and ignores the per-request model.
    pub path_base: Option<&'a str>,
}

/// The egress request wire a hop produced: a JSON `Value` still to be shim/model-shaped by the
/// router before serialization, or a FINAL body (a non-JSON egress wire — multipart transcription /
/// audio). Mirrors the pre-cutover `write_request_value` `Some(Value)` / `None`→`write_request` split.
///
/// Relocated from `busbar_core::handlers` at Batch C-3 (it is a return type on the sealed neutral
/// `IrHandle`, so it must be nameable by a plane crate); core re-exports it from
/// `busbar_core::handlers::EgressWire` so its own call sites are unchanged.
pub enum EgressWire {
    /// A JSON egress body the router still post-shapes (shim-key strip, model rewrite, path-base).
    Json(Value),
    /// A final egress body a non-JSON wire already serialized.
    Bytes(Bytes),
}

/// The neutral outcome of a non-stream cross-protocol response translation. Mirrors every exit of the
/// pre-cutover buffered-response arm: a delivered body (JSON / typed / synthesized native frames), or
/// one of the two read-succeeded-but-undelivered terminals the caller still renders (404 / 500).
///
/// Relocated from `busbar_core::handlers` at Batch C-3 (a return type on the sealed neutral
/// `IrHandle`); core re-exports it from `busbar_core::handlers::TranslatedResponse` so its own call
/// sites are unchanged.
pub enum TranslatedResponse {
    /// A JSON ingress body (`application/json`) the caller still post-processes (native response-metrics
    /// injection, gemini JSON-array wrap) before delivery.
    Json(Value),
    /// A final ingress body + its own content-type (a non-JSON ingress wire — speech audio — or the
    /// opaque egress→ingress bridge).
    Typed(WireBody),
    /// Synthesized native stream frames (a wants-stream ingress answered by a BUFFERED upstream — e.g.
    /// a Bedrock ConverseStream client served a non-SSE Converse body). Delivered under the ingress
    /// stream content-type.
    StreamFrames(Vec<u8>),
    /// JSON path only: the ingress protocol does not serve this operation → the caller renders the 404
    /// (`DETAIL_ENDPOINT_UNSUPPORTED_OPERATION`). The egress read succeeded, but NO completion reaches
    /// the client, so the caller does NOT bill this and leaves its spend guard armed to refund — a
    /// response the client never receives is not charged (mirrors the streaming refund-on-non-delivery).
    IngressUnsupported,
    /// Opaque path only: the egress read succeeded but the ingress handler is absent, so no client body
    /// could be written → the caller falls through to its ingress-native untranslatable 500. NO
    /// completion reaches the client, so the caller does NOT bill this and leaves its spend guard armed
    /// to refund — same non-delivery posture as `IngressUnsupported`.
    Untranslatable,
}
