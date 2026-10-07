// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE INGRESS ERROR VOCABULARY: the shape an answer the kernel refuses at ingress is written in (the
//! caller's dialect when its declarations name one, the neutral envelope when not), the error-kind
//! tokens, the media types, the pre-routing pool label, the body caps the ingress reads, and the
//! operator's opt-in route-policy response headers. The kernel owns ingress (spec Part 3, the inbound
//! steps), so its error vocabulary lives here.

// The contract's shape vocabulary (DECISIONS #83: contract = shapes): the media types and the
// agnostic error-KIND tokens a dialect and the kernel both key on.
pub use busbar_contract::protocol::{
    APPLICATION_JSON, KIND_API_ERROR, KIND_AUTHENTICATION, KIND_INSUFFICIENT_QUOTA,
    KIND_INVALID_REQUEST, KIND_NOT_FOUND, KIND_OVERLOADED, KIND_PERMISSION, KIND_RATE_LIMIT,
    KIND_REQUEST_TOO_LARGE, KIND_SERVER_ERROR, KIND_TIMEOUT, TEXT_EVENT_STREAM,
};
// The translate-body cap the ingress reads a request body against (the egress unit owns the value).
pub use busbar_kernel_egress::upstream::{
    max_translate_body_bytes, set_max_translate_body_bytes, TRANSLATE_BODY_MAX_BYTES_DEFAULT,
};

/// Bounded `pool` metric-label sentinel used for every pre-routing failure (malformed body,
/// unresolved model, governance rejection) so the label space stays finite (metrics.rs).
pub const POOL_LABEL_UNRESOLVED: &str = "unresolved";

/// The `x-busbar-route-policy` TRANSPARENCY response header: the policy name that chose the lane.
pub const HDR_ROUTE_POLICY: &str = "x-busbar-route-policy";
/// The `x-busbar-route-target` TRANSPARENCY response header: the chosen lane's model.
pub const HDR_ROUTE_TARGET: &str = "x-busbar-route-target";

/// Whether the operator opted in to the `x-busbar-route-policy` / `-target` TRANSPARENCY headers
/// (`advanced.response_headers.route_policy`; default `false`). Set SYNCHRONOUSLY once at boot by
/// [`configure_route_policy_headers`]: a settled decision read at every emission site, never rebuilt
/// by a config apply (restart-to-apply). Unset ⇒ `false`.
static ROUTE_POLICY_HEADERS_ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

/// Apply the operator's `advanced.response_headers.route_policy` decision. Called exactly once, at
/// boot, before the router is built; `OnceLock::set` silently no-ops on any later call.
pub fn configure_route_policy_headers(enabled: bool) {
    let _ = ROUTE_POLICY_HEADERS_ENABLED.set(enabled);
}

/// Did the operator opt in to the `x-busbar-route-*` headers? Gates the route-policy header emit —
/// the header is a fingerprintable observable, so it defaults OFF.
pub fn route_policy_headers_enabled() -> bool {
    ROUTE_POLICY_HEADERS_ENABLED.get().copied().unwrap_or(false)
}

/// THE NEUTRAL ERROR ENVELOPE — the body for an ingress name that resolves to no protocol. The
/// plainest `{"error": {"message", "type"}}` object, stated ONCE here so the spellings cannot drift,
/// and neutral so it survives every LLM dialect being dropped from the build.
pub fn agnostic_error_envelope(kind: &str, msg: &str) -> serde_json::Value {
    serde_json::json!({ "error": { "message": msg, "type": kind } })
}

/// The canonical auth-failure `(HTTP status, error kind)` for an ingress protocol name — the agnostic
/// dispatch through the registry's `ProtocolDecl::auth_failure_status_and_kind` (which replaced the
/// `ProtocolWriter` vtable method). `BedrockWriter` resolves to (403, "auth"); `GeminiWriter` to (400,
/// "invalid_request_error"); every other dialect and an unknown/dropped protocol fall back to the
/// default (401, [`KIND_AUTHENTICATION`]) so the request path stays panic-free. Neutral: reads only the
/// protocol registry, so it survives every LLM dialect being dropped from the build.
pub fn auth_failure_status_and_kind(proto: &str) -> (http::StatusCode, &'static str) {
    crate::proto::decl_for(proto)
        .map(|d| d.auth_failure_status_and_kind)
        .unwrap_or((http::StatusCode::UNAUTHORIZED, KIND_AUTHENTICATION))
}

/// The agnostic ingress-error shaper: project a `(status, kind, msg)` into the caller-dialect error
/// response, attaching the protocol-appropriate headers via the resolved writer vtable. When `ingress`
/// resolves to no protocol the body is the neutral `agnostic_error_envelope` and no protocol headers
/// are attached — the shape that survives every LLM dialect being dropped with the `busbar-llm` plane.
pub fn ingress_error(
    ingress: &str,
    status: axum::http::StatusCode,
    kind: &str,
    msg: &str,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let dialect = crate::proto::decl_for(ingress).and_then(|d| d.dialect());
    let envelope = match &dialect {
        Some(di) => di.write_error(status.as_u16(), kind, msg),
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
        di.attach_error_response_headers(resp.headers_mut(), kind, &envelope);
    }
    resp
}
