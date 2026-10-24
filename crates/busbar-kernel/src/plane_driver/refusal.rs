// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DOOR'S DIALECT REFUSAL (`BUSBAR-1.6.0.md` Part 3, "THE PLANE-EXTRACTION SEAM"): a refusal
//! the kernel classified as a kind-neutral `(status, kind)` is shaped into the CALLER'S dialect at
//! the plane door that answers it. The dialect writer comes from the plane's own declared protocol
//! (`crate::proto::decl_for(..).dialect()`), so this module names no dialect literally; an ingress
//! name that resolves to no protocol gets the neutral [`agnostic_error_envelope`], the shape that
//! survives every LLM dialect being dropped from the build. The bytes are 1.5.5's, unchanged.

use busbar_contract::protocol::APPLICATION_JSON;

/// THE NEUTRAL ERROR ENVELOPE — the body for an ingress name that resolves to no protocol. The
/// plainest `{"error": {"message", "type"}}` object, stated ONCE here so the spellings cannot drift,
/// and neutral so it survives every LLM dialect being dropped from the build.
pub fn agnostic_error_envelope(kind: &str, msg: &str) -> serde_json::Value {
    serde_json::json!({ "error": { "message": msg, "type": kind } })
}

/// The agnostic ingress-error shaper: project a `(status, kind, msg)` into the caller-dialect error
/// response, attaching the protocol-appropriate headers via the resolved writer vtable. When `ingress`
/// resolves to no protocol the body is the neutral `agnostic_error_envelope` and no protocol headers
/// are attached — the shape that survives every LLM dialect being dropped from the build.
pub fn ingress_error(
    ingress: &str,
    status: axum::http::StatusCode,
    kind: &str,
    msg: &str,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let dialect = crate::proto::decl_for(ingress).and_then(|d| d.dialect());
    let envelope = match &dialect {
        Some(di) => di.write_error(crate::proto::CODEC_HOST, status.as_u16(), kind, msg),
        None => agnostic_error_envelope(kind, msg),
    };
    let body = crate::json::to_string(&envelope)
        .unwrap_or_else(|_| agnostic_error_envelope(kind, msg).to_string());
    let mut resp = axum::response::Response::builder()
        .status(status)
        .header(axum::http::header::CONTENT_TYPE, APPLICATION_JSON)
        .body(axum::body::Body::from(body))
        .unwrap_or_else(|_| status.into_response());
    if let Some(di) = &dialect {
        for (name, value) in di.error_response_fields(crate::proto::CODEC_HOST, kind, &envelope) {
            if let (Ok(n), Ok(v)) = (
                axum::http::HeaderName::from_bytes(name.as_bytes()),
                axum::http::HeaderValue::from_bytes(&value),
            ) {
                resp.headers_mut().insert(n, v);
            }
        }
    }
    resp
}

#[cfg(test)]
#[path = "tests/refusal_tests.rs"]
mod tests;
