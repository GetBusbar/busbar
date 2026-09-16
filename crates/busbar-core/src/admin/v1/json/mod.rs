// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The v1 JSON error/OK ENVELOPE PRIMITIVES — the frozen `{"error":{"code","message"}}` projection
//! and its `ok_json` twin.
//!
//! The JSON-REST *service* (the `/api/v1/admin/*` route table, the handlers, the openapi document,
//! the recording layer) was extracted to the `busbar-admin` sibling crate (1.6.0). What STAYS here is
//! the small set of envelope helpers that busbar-core itself still needs: `router::fallback_error_response`
//! renders `err_json` for the native-API root, and `admin::planeverbs::CorePlaneAdminEnvelope` (the
//! core backing for the self-enveloping plane-verb seam, which `busbar-a2a`/`busbar-mcp` name at
//! `busbar_core::admin::planeverbs::CorePlaneAdminEnvelope`) reaches `err_json`/`err_json_cond`/`ok_json`.
//! busbar-admin's handlers call these through `busbar_core::admin::v1::json::{err_json,ok_json,err_json_cond}`.

use axum::http::{header::CONTENT_TYPE, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use serde_json::json;

use super::contract::taxonomy::Cond;
use super::contract::AdminError;

/// Serialize a successful view to the JSON body with the given status. `view` is any `contract` view
/// (`#[derive(Serialize)]`); the JSON projection is the derive, so a field added to a view appears
/// automatically (additive-only holds by construction).
pub fn ok_json<T: Serialize>(status: StatusCode, view: &T) -> Response {
    (
        status,
        [(CONTENT_TYPE, crate::proxy::APPLICATION_JSON)],
        serde_json::to_string(view).unwrap_or_else(|_| "{}".to_string()),
    )
        .into_response()
}

/// Project an `AdminError` onto the stable v1 JSON error envelope
/// `{"error":{"code":<stable>,"message":<human>}}` with the error's HTTP status. Tooling branches on
/// `code`; `message` is human-only.
pub fn err_json(e: &AdminError) -> Response {
    err_json_tagged(e, None)
}

/// `err_json`, but NAMING the taxonomy [`Cond`] that produced the error. Used at the shared seams
/// whose condition is fixed (malformed `If-Match`, malformed cursor, the keys surface), so the
/// class-level drift test can witness the declaration at CONDITION granularity, not just at
/// `ErrKind` granularity. The wire bytes are identical to `err_json` — the tag is `#[cfg(test)]`.
pub fn err_json_cond(e: &AdminError, cond: Cond) -> Response {
    err_json_tagged(e, Some(cond))
}

/// The one construction site of the v1 error envelope. In a TEST build it stamps the response with
/// the taxonomy [`observed::Tag`] so the router's recording layer — which knows the matched route,
/// which this function does not — can attribute the emission to an operation and check it against
/// `declared_errors`. In a release build the tag does not exist and this is the plain projection.
#[cfg_attr(not(any(test, feature = "test-support")), allow(unused_variables))]
fn err_json_tagged(e: &AdminError, cond: Option<Cond>) -> Response {
    let status = StatusCode::from_u16(e.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    #[cfg_attr(not(any(test, feature = "test-support")), allow(unused_mut))]
    let mut resp = (
        status,
        [(CONTENT_TYPE, crate::proxy::APPLICATION_JSON)],
        json!({"error": {"code": e.code(), "message": e.message()}}).to_string(),
    )
        .into_response();
    #[cfg(any(test, feature = "test-support"))]
    if let Some(kind) = crate::admin::v1::contract::taxonomy::err_kind_of(e) {
        resp.extensions_mut()
            .insert(crate::admin::v1::contract::taxonomy::observed::Tag { kind, cond });
    }
    resp
}
