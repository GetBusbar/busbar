// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The v1 JSON error/OK ENVELOPE PRIMITIVES — the frozen `{"error":{"code","message"}}` projection
//! and its `ok_json` twin. Moved in from the kernel (1.6.0-TODO.md PATH TO DEV-GREEN, D4): the
//! admin crate writes its own responses. The envelope BYTES and their framing are the kernel's one
//! construction (`busbar_kernel::admin::envelope`, `busbar_kernel::router::refusal_response`), which
//! the kernel's own gate and router fallback answer with too; what is added here is the admin
//! taxonomy's `AdminError` → (status, code, message) projection and the test-build condition tag.

use axum::http::{header::CONTENT_TYPE, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Serialize;

use crate::v1::contract::taxonomy::Cond;
use crate::v1::contract::AdminError;

/// Serialize a successful view to the JSON body with the given status. `view` is any `contract` view
/// (`#[derive(Serialize)]`); the JSON projection is the derive, so a field added to a view appears
/// automatically (additive-only holds by construction).
pub fn ok_json<T: Serialize>(status: StatusCode, view: &T) -> Response {
    (
        status,
        [(CONTENT_TYPE, busbar_contract::protocol::APPLICATION_JSON)],
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
/// the taxonomy [`observed::Tag`](crate::v1::contract::taxonomy::observed::Tag) so the router's
/// recording layer — which knows the matched route, which this function does not — can attribute the
/// emission to an operation and check it against `declared_errors`. In a release build the tag does
/// not exist and this is the plain projection.
#[cfg_attr(not(any(test, feature = "test-support")), allow(unused_variables))]
fn err_json_tagged(e: &AdminError, cond: Option<Cond>) -> Response {
    #[cfg_attr(not(any(test, feature = "test-support")), allow(unused_mut))]
    let mut resp = busbar_kernel::router::refusal_response(e.http_status(), e.code(), &e.message());
    #[cfg(any(test, feature = "test-support"))]
    if let Some(kind) = crate::v1::contract::taxonomy::err_kind_of(e) {
        resp.extensions_mut()
            .insert(crate::v1::contract::taxonomy::observed::Tag { kind, cond });
    }
    resp
}
