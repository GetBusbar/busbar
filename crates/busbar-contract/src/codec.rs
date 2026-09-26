// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CODEC-CELL SHAPES (DECISIONS #83: contract = shapes) — the values a protocol's codec cells
//! and the kernel's dispatch hand each other: the resolved-primitives egress context a request
//! handler renders the upstream path from, the two refusals a cell reports, and the wire carriers a
//! cell's handle writes itself out as ([`WireBody`], [`EgressWire`], [`TranslatedResponse`]).
//!
//! Relocated from `busbar-substrate-values` (`wire` and `handlers`), which re-exports each under its
//! historical path. The wire carriers are RE-EXPRESSED over this crate's own [`SlabBytes`]: the
//! reference-counted foreign buffer they used to carry is banned from this surface
//! (`tests/bounded_limits.rs`), so a body is a shared slab here and the host adopts it as its own
//! buffer, without copying, at its transport boundary.

use crate::bounded::SlabBytes;
use crate::operation::Operation;
use serde_json::Value;

/// A serialized wire body plus the content-type the OperationHandler chose for it. The engine relays both without
/// interpreting either — `application/json` for JSON ops, `audio/mpeg` etc. for a binary op like speech.
pub struct WireBody {
    pub bytes: SlabBytes,
    pub content_type: http::HeaderValue,
}

impl WireBody {
    /// JSON body — the common case.
    pub fn json(bytes: SlabBytes) -> Self {
        Self {
            bytes,
            content_type: http::HeaderValue::from_static(crate::protocol::APPLICATION_JSON),
        }
    }
    /// A body with an explicit content-type (e.g. audio speech). Falls back to octet-stream if the
    /// content-type string is not a valid header value.
    pub fn typed(bytes: SlabBytes, content_type: &str) -> Self {
        let content_type = http::HeaderValue::from_str(content_type)
            .unwrap_or_else(|_| http::HeaderValue::from_static("application/octet-stream"));
        Self {
            bytes,
            content_type,
        }
    }
}

/// The egress request wire a hop produced: a JSON `Value` still to be shim/model-shaped by the
/// router before serialization, or a FINAL body (a non-JSON egress wire — multipart transcription /
/// audio). Mirrors the pre-cutover `write_request_value` `Some(Value)` / `None`→`write_request` split.
pub enum EgressWire {
    /// A JSON egress body the router still post-shapes (shim-key strip, model rewrite, path-base).
    Json(Value),
    /// A final egress body a non-JSON wire already serialized.
    Bytes(SlabBytes),
    /// NO egress body could be written, and `reason` says why. The loud arm: a handle that cannot
    /// write itself onto the target dialect says so, and the seam turns that into a refusal the
    /// caller sees. The alternative — answering with an empty body — sends a request upstream that
    /// is not the caller's request, and the first sign of it is the backend's own error.
    Unrepresentable { reason: String },
}

/// The neutral outcome of a non-stream cross-protocol response translation. Mirrors every exit of the
/// pre-cutover buffered-response arm: a delivered body (JSON / typed / synthesized native frames), or
/// one of the two read-succeeded-but-undelivered terminals the caller still renders (404 / 500).
pub enum TranslatedResponse {
    /// A JSON ingress body (`application/json`) the caller still post-processes (native response-metrics
    /// injection, a dialect's JSON-array wrap) before delivery.
    Json(Value),
    /// A final ingress body + its own content-type (a non-JSON ingress wire — speech audio — or the
    /// opaque egress→ingress bridge).
    Typed(WireBody),
    /// Synthesized native stream frames (a wants-stream ingress answered by a BUFFERED upstream — e.g.
    /// an event-stream client served a non-SSE buffered body). Delivered under the ingress stream
    /// content-type.
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

/// What routing hands a request handler so it can render the upstream URL path. RESOLVED PRIMITIVES
/// ONLY — never the `Lane` or a config handle: a codec/handler touching routing state is exactly the
/// coupling this fixes. Grows a field (region, api-version, …) when a protocol needs more; the trait
/// signature does not. Routing populates it from the lane and applies any `lane.path` override itself.
pub struct EgressCtx<'a> {
    /// Which operation's endpoint to render — the template selector.
    pub operation: Operation,
    /// The resolved wire model id (routing calls `Lane::wire_model()`), for protocols that carry the
    /// model in the URL path rather than the body.
    pub model: &'a str,
    /// Whether the caller asked to stream (chat/audio path variants); `false` for the JSON ops.
    pub stream: bool,
    /// Optional per-provider path-BASE override (the lane's `path_base`). For URL-model protocols it
    /// replaces the protocol's hardcoded base segment (e.g. `/v1beta/models`) so a provider can be
    /// pointed at a different layout — a host that serves the same dialect under a
    /// project/location-scoped path. `None` uses the protocol default.
    /// Distinct from the full-path `path` override, which is static and ignores the per-request model.
    pub path_base: Option<&'a str>,
}

/// A request that could not be parsed into this operation's IR — rendered as a caller-dialect 4xx
/// (via the existing `proxy::ingress_error`). `UnsupportedSubOp` is the second 404 site
/// (`ImageIr.op` unsupported for the model) — distinct from handler-absence, same terminal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IngressReject {
    BadRequest(String),
    UnsupportedSubOp { op: Operation, model: String },
}

/// An upstream response body this OperationHandler could not decode into its operation's IR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodecError {
    Malformed(String),
}
