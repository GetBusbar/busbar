// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `json::Body`: a JSON answer over axum, written by the facade (axum's own `Json` responder is
//! serde_json's, and its `json` feature stays off).

use axum_core::response::{IntoResponse, Response};
use http::header::CONTENT_TYPE;
use http::{HeaderValue, StatusCode};
use serde::Serialize;

/// An axum answer whose body is `T` as JSON, with `content-type: application/json`, as axum's
/// `Json` answers. A value the writer refuses answers 500 with the refusal as plain text (it
/// holds no input).
#[derive(Debug, Clone, Copy, Default)]
pub struct Body<T>(pub T);

impl<T: Serialize> IntoResponse for Body<T> {
    fn into_response(self) -> Response {
        match super::to_vec(&self.0) {
            Ok(bytes) => (
                [(CONTENT_TYPE, HeaderValue::from_static("application/json"))],
                bytes,
            )
                .into_response(),
            Err(error) => (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response(),
        }
    }
}
