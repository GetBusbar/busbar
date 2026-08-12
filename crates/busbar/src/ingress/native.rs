// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ERROR-SHAPING BOUNDARY: one resolved ingress, one native envelope.
//!
//! Everything that must answer a request from its PATH ALONE — the oversized-body `413` reshape,
//! the `404` fallback, the `405` wrong-method reply, the auth-time `401` — comes through here, so
//! there is exactly one place that turns [`crate::plane::PlaneDispatch::ingress_of`]'s answer into
//! bytes. The alternative is what shipped: several sites each deciding for themselves, from a
//! classifier that could not see the mount table, and quietly disagreeing about what `/mcp` is.
//!
//! It is the SHAPE that is decided here, never the outcome. Status and message arrive from the
//! caller, because the caller is the only one that knows why it is refusing.

use axum::http::StatusCode;
use axum::response::Response;

use crate::plane::Ingress;

/// The dialect an answer to `ingress` is SHAPED IN, as a name the protocol registry understands.
///
/// This is the ONE place an unrecognised residual path is answered in OpenAI's envelope, and it is
/// a decision about the REPLY rather than a claim about the path: the caller's dialect is unknown,
/// and OpenAI's is the most widely understood of the six — what a generic HTTP client probing `/` is
/// most likely to parse. Stated here so the status/message lookups and the envelope builder cannot
/// answer it two different ways, which is precisely how `/mcp` acquired an OpenAI 413.
pub(crate) fn envelope_dialect(ingress: Ingress) -> &'static str {
    ingress.wire_format().unwrap_or(crate::proto::PROTO_OPENAI)
}

/// Render `status`/`kind`/`message` in the dialect the resolved `ingress` is spoken in.
///
/// The `kind` is the protocol-agnostic error category the LLM writers map to their own vocabulary
/// (`request_too_large`, `not_found`, …); a JSON-RPC plane has no such vocabulary — its category IS
/// its numeric code — so the mounted arm does not consult it.
pub(crate) fn native_error(
    ingress: Ingress,
    status: StatusCode,
    kind: &str,
    message: &str,
) -> Response {
    match ingress {
        // EVERY MOUNTED PLANE SPEAKS JSON-RPC 2.0. That is not an assumption made here — it is what
        // `Plane::wire_format_names` states and what `every_mounted_planes_dialect_is_jsonrpc`
        // pins, so the day a mounted plane speaks something else the build says so rather than this
        // arm quietly mis-shaping it. Answering a JSON-RPC client in a vendor envelope is not a
        // cosmetic mismatch: the client's decoder fails, and the failure is attributed to the wrong
        // layer.
        Ingress::Mounted(_) => crate::ingress::jsonrpc::transport_refusal(status, message),
        // THE RESIDUAL, including the case where the path names no dialect at all — see
        // [`envelope_dialect`] for what is chosen then, and why that is a decision about the reply
        // rather than the fallthrough the old classifier smuggled into every site that read it.
        Ingress::Residual(_) => {
            crate::proxy::ingress_error(envelope_dialect(ingress), status, kind, message)
        }
    }
}
