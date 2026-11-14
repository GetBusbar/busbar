// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use axum::http::{header::CONTENT_TYPE, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Serialize;

use crate::v1::contract::taxonomy::Cond;
use crate::v1::contract::AdminError;

pub fn ok_json<T: Serialize>(status: StatusCode, view: &T) -> Response {
    match serde_json::to_string(view) {
        Ok(body) => (
            status,
            [(CONTENT_TYPE, busbar_contract::protocol::APPLICATION_JSON)],
            body,
        )
            .into_response(),
        Err(_) => busbar_kernel::admin::gate::error_envelope(
            StatusCode::INTERNAL_SERVER_ERROR.into(),
            "internal",
            "response serialization failed",
        ),
    }
}

pub fn err_json(e: &AdminError) -> Response {
    err_json_tagged(e, None)
}

pub fn err_json_cond(e: &AdminError, cond: Cond) -> Response {
    err_json_tagged(e, Some(cond))
}

fn err_json_tagged(e: &AdminError, cond: Option<Cond>) -> Response {
    tagged(
        busbar_kernel::admin::gate::error_envelope(e.http_status(), e.code(), &e.message()),
        e,
        cond,
    )
}

/// Test builds tag the envelope with the declared kind and condition the contract tests read back.
#[cfg(test)]
fn tagged(mut resp: Response, e: &AdminError, cond: Option<Cond>) -> Response {
    if let Some(kind) = crate::v1::contract::taxonomy::err_kind_of(e) {
        resp.extensions_mut()
            .insert(crate::v1::contract::taxonomy::observed::Tag { kind, cond });
    }
    resp
}

/// Production envelopes carry no test tag.
#[cfg(not(test))]
fn tagged(resp: Response, _: &AdminError, _: Option<Cond>) -> Response {
    resp
}
