// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ONE HTML PAGE ANSWER of the authorization server and hosted login: every consent, device and
//! login page refuses to render inside another origin's frame (#359 SEC-L8, anti-clickjacking).

use axum::http::{header, HeaderValue};
use axum::response::{Html, IntoResponse, Response};

/// An HTML page that no other origin may frame.
pub(crate) struct Page<T>(pub(crate) T);

impl<T> IntoResponse for Page<T>
where
    Html<T>: IntoResponse,
{
    fn into_response(self) -> Response {
        let mut response = Html(self.0).into_response();
        let headers = response.headers_mut();
        headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
        headers.insert(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static("frame-ancestors 'none'"),
        );
        response
    }
}
