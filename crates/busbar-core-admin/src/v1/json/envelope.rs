// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The v1 JSON error/OK ENVELOPE PRIMITIVES — the frozen `{"error":{"code","message"}}` projection
//! of an [`AdminError`] and its `ok_json` twin. Moved here from the kernel's `admin::v1::json` (P2 D4,
//! ARCHITECT Q-D4-ADMIN (b) 2026-10-04): the kernel keeps only the neutral envelope for the answers it
//! gives itself (`busbar_kernel::admin::gate`), and every error here is framed by that same
//! construction (`gate::error_envelope`), so the bytes cannot differ.

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
        [(CONTENT_TYPE, busbar_kernel::proxy::APPLICATION_JSON)],
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
/// the taxonomy [`crate::v1::contract::taxonomy::observed::Tag`] so the router's recording layer — which knows the matched route,
/// which this function does not — can attribute the emission to an operation and check it against
/// `declared_errors`. In a release build the tag does not exist and this is the plain projection.
#[cfg_attr(not(any(test, feature = "test-support")), allow(unused_variables))]
fn err_json_tagged(e: &AdminError, cond: Option<Cond>) -> Response {
    #[cfg_attr(not(any(test, feature = "test-support")), allow(unused_mut))]
    let mut resp =
        busbar_kernel::admin::gate::error_envelope(e.http_status(), e.code(), &e.message());
    #[cfg(any(test, feature = "test-support"))]
    if let Some(kind) = crate::v1::contract::taxonomy::err_kind_of(e) {
        resp.extensions_mut()
            .insert(crate::v1::contract::taxonomy::observed::Tag { kind, cond });
    }
    resp
}
