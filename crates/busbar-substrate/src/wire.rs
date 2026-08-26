// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! NEUTRAL WIRE/EGRESS VALUE TYPES — the serialized-body carrier an `OperationHandler` yields and
//! the resolved-primitives egress context routing hands a `RequestHandler`. Both are pure value
//! types a plane crate names without reaching into `busbar-core`; core re-exports them from
//! `busbar_core::handlers::{WireBody, EgressCtx}` so its own call sites are unchanged.

use busbar_api::operation::Operation;
use bytes::Bytes;

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
