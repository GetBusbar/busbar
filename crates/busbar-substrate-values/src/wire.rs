// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! NEUTRAL WIRE/EGRESS VALUE TYPES — the serialized-body carrier an `OperationHandler` yields and
//! the resolved-primitives egress context routing hands a `RequestHandler`. Both are pure value
//! types a plane crate names without reaching into `busbar-core`; core re-exports them from
//! `busbar_kernel::handlers::{WireBody, EgressCtx}` so its own call sites are unchanged.

use bytes::Bytes;
use serde_json::Value;

/// A serialized wire body plus the content-type the OperationHandler chose for it. The engine relays both without
/// interpreting either — `application/json` for JSON ops, `audio/mpeg` etc. for a binary op like speech.
pub struct WireBody {
    pub bytes: Bytes,
    pub content_type: http::HeaderValue,
}

impl WireBody {
    /// JSON body — the common case.
    pub fn json(bytes: Bytes) -> Self {
        Self {
            bytes,
            content_type: http::HeaderValue::from_static("application/json"),
        }
    }
    /// A body with an explicit content-type (e.g. audio speech). Falls back to octet-stream if the
    /// content-type string is not a valid header value.
    pub fn typed(bytes: Bytes, content_type: &str) -> Self {
        let content_type = http::HeaderValue::from_str(content_type)
            .unwrap_or_else(|_| http::HeaderValue::from_static("application/octet-stream"));
        Self {
            bytes,
            content_type,
        }
    }
}

/// What routing hands a `RequestHandler` so it can render the upstream URL path. A SHAPE: defined
/// in `busbar_contract::codec` (DECISIONS #83, SD-1 of the #83a split) and re-exported here under its
/// historical path.
pub use busbar_contract::codec::EgressCtx;

/// The egress request wire a hop produced: a JSON `Value` still to be shim/model-shaped by the
/// router before serialization, or a FINAL body (a non-JSON egress wire — multipart transcription /
/// audio). Mirrors the pre-cutover `write_request_value` `Some(Value)` / `None`→`write_request` split.
///
/// Relocated from `busbar_kernel::handlers` at Batch C-3 (it is a return type on the sealed neutral
/// `IrHandle`, so it must be nameable by a plane crate); core re-exports it from
/// `busbar_kernel::handlers::EgressWire` so its own call sites are unchanged.
pub enum EgressWire {
    /// A JSON egress body the router still post-shapes (shim-key strip, model rewrite, path-base).
    Json(Value),
    /// A final egress body a non-JSON wire already serialized.
    Bytes(Bytes),
    /// NO egress body could be written, and `reason` says why. The loud arm: a handle that cannot
    /// write itself onto the target dialect says so, and the seam turns that into a refusal the
    /// caller sees. The alternative — answering with an empty body — sends a request upstream that
    /// is not the caller's request, and the first sign of it is the backend's own error.
    Unrepresentable { reason: String },
}

/// The neutral outcome of a non-stream cross-protocol response translation. Mirrors every exit of the
/// pre-cutover buffered-response arm: a delivered body (JSON / typed / synthesized native frames), or
/// one of the two read-succeeded-but-undelivered terminals the caller still renders (404 / 500).
///
/// Relocated from `busbar_kernel::handlers` at Batch C-3 (a return type on the sealed neutral
/// `IrHandle`); core re-exports it from `busbar_kernel::handlers::TranslatedResponse` so its own call
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

#[cfg(test)]
#[path = "tests/egress_wire_tests.rs"]
mod egress_wire_tests;
