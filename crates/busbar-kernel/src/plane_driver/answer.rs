// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

pub enum PlaneAnswer {
    Unary(
        axum::http::StatusCode,
        axum::http::HeaderMap,
        axum::body::Bytes,
    ),

    Live(axum::response::Response),
}

impl PlaneAnswer {
    pub fn into_response(self) -> axum::response::Response {
        match self {
            PlaneAnswer::Unary(status, headers, body) => {
                let mut resp = axum::response::Response::new(axum::body::Body::from(body));
                *resp.status_mut() = status;
                *resp.headers_mut() = headers;
                resp
            }
            PlaneAnswer::Live(resp) => resp,
        }
    }
}

#[cfg(test)]
#[path = "tests/answer_tests.rs"]
mod tests;
