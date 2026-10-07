// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ERROR-SHAPING BOUNDARY: one resolved ingress, one native envelope.
//!
//! Everything that must answer a request from its PATH ALONE — the oversized-body `413` reshape,
//! the `404` fallback, the `405` wrong-method reply, the auth-time `401` — comes through here, so
//! there is exactly one place that turns [`crate::plane::PlaneDispatch::ingress_of`]'s answer into
//! bytes. The alternative is what shipped: several sites each deciding for themselves, from a
//! classifier that could not see the mount table, and quietly disagreeing about what a given mounted
//! plane's path is.
//!
//! It is the SHAPE that is decided here, never the outcome. Status and message arrive from the
//! caller, because the caller is the only one that knows why it is refusing.

use axum::http::StatusCode;
use axum::response::Response;
use busbar_contract::caps::ReasonCode;

use crate::guest::{ListenerLines, Refused};
use crate::plane::Ingress;

/// The declared dialect NAME an answer to `(method, path)` is labelled with (the auth step's
/// denial tap): a mounted plane's first wire format ([`Ingress::shaping_wire_format`]); on the
/// fallback, the declared name of the matched line's `refusal_dialect` (spec Part 3 §12 l.2646:
/// "each declared route carries an opaque `refusal_dialect`", the router sets it before `arrive`).
/// Empty when no claimant's line answers the path: the kernel names no dialect of its own.
pub fn denial_label(
    lines: Option<&dyn ListenerLines>,
    ingress: Ingress,
    method: &str,
    path: &str,
) -> &'static str {
    match ingress {
        Ingress::Mounted(_) => ingress.shaping_wire_format().unwrap_or(""),
        Ingress::Fallback => lines
            .and_then(|l| l.facts(method, path))
            .map_or("", |f| f.dialect),
    }
}

/// Render a refusal the kernel answers with NO UNIT — its `401` before any handler, its no-route
/// `404`, its wrong-method `405`, the body cap's `413`, the request-panic boundary's `500` — in the
/// shape the resolved `ingress` is spoken in.
///
/// The kernel owns the refusal; the bytes are the line's claimant's (spec THE DESIGN §5
/// l.958-960: "the bytes come from the line's claimant through `refusal` under the line's
/// `refusal_dialect` … or, with no line, from the listener's 1.5.5 default"). `reason` is what the
/// claimant renders; `status`, `kind` and `message` are the kernel's own words, the `message` the
/// claimant's text and the three together the listener's default when no claimant's line answers.
#[allow(clippy::too_many_arguments)]
pub(crate) fn native_error(
    lines: Option<&dyn ListenerLines>,
    ingress: Ingress,
    method: &str,
    path: &str,
    status: StatusCode,
    reason: ReasonCode,
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
        // THE FALLBACK: the matched line's claimant renders it from the target by its own path
        // rule; with no claimant's line, the listener's default envelope.
        Ingress::Fallback => {
            match lines.and_then(|l| l.refuse(method, path, reason, status.as_u16(), message)) {
                Some(refused) => refused_response(refused),
                None => listener_default(status, kind, message),
            }
        }
    }
}

/// THE LISTENER'S OWN DEFAULT, with no claimant's line to render it: the dialect-free envelope
/// (`{"error": {"message", "type"}}`), as JSON, at the kernel's status.
pub(crate) fn listener_default(status: StatusCode, kind: &str, message: &str) -> Response {
    use axum::response::IntoResponse;
    let envelope = crate::proxy::agnostic_error_envelope(kind, message);
    let body = crate::json::to_string(&envelope).unwrap_or_else(|_| envelope.to_string());
    axum::response::Response::builder()
        .status(status)
        .header(
            axum::http::header::CONTENT_TYPE,
            busbar_contract::protocol::APPLICATION_JSON,
        )
        .body(axum::body::Body::from(body))
        .unwrap_or_else(|_| status.into_response())
}

/// A claimant's rendered refusal as the response the listener writes: its status, its head fields
/// in its order (a field whose name or value is not a legal header is dropped), its body.
pub(crate) fn refused_response(refused: Refused) -> Response {
    let status = StatusCode::from_u16(refused.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut resp = Response::new(axum::body::Body::from(refused.body));
    *resp.status_mut() = status;
    for (name, value) in refused.fields {
        let (Ok(name), Ok(value)) = (
            axum::http::HeaderName::from_bytes(&name),
            axum::http::HeaderValue::from_bytes(&value),
        ) else {
            continue;
        };
        resp.headers_mut().append(name, value);
    }
    resp
}
