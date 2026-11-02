// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use axum::http::{header::CONTENT_TYPE, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Serialize;

use crate::v1::contract::taxonomy::Cond;
use crate::v1::contract::AdminError;

pub fn ok_json<T: Serialize>(status: StatusCode, view: &T) -> Response {
    (
        status,
        [(CONTENT_TYPE, busbar_contract::protocol::APPLICATION_JSON)],
        serde_json::to_string(view).unwrap_or_else(|_| "{}".to_string()),
    )
        .into_response()
}

pub fn err_json(e: &AdminError) -> Response {
    err_json_tagged(e, None)
}

pub fn err_json_cond(e: &AdminError, cond: Cond) -> Response {
    err_json_tagged(e, Some(cond))
}

#[cfg_attr(not(test), allow(unused_variables))]
fn err_json_tagged(e: &AdminError, cond: Option<Cond>) -> Response {
    #[cfg_attr(not(test), allow(unused_mut))]
    let mut resp =
        busbar_kernel::admin::gate::error_envelope(e.http_status(), e.code(), &e.message());
    #[cfg(test)]
    if let Some(kind) = crate::v1::contract::taxonomy::err_kind_of(e) {
        resp.extensions_mut()
            .insert(crate::v1::contract::taxonomy::observed::Tag { kind, cond });
    }
    resp
}
