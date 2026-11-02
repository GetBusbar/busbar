// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use axum::response::{IntoResponse, Response};
use serde_json::Value;

pub struct Metadata<'a> {
    pub resource: std::borrow::Cow<'a, str>,

    pub authorization_servers: &'a [String],

    pub scopes_supported: &'a [String],
}

pub fn metadata(m: &Metadata<'_>) -> Response {
    let mut doc = serde_json::Map::new();
    doc.insert("resource".into(), Value::from(m.resource.as_ref()));
    if !m.authorization_servers.is_empty() {
        doc.insert(
            "authorization_servers".into(),
            Value::from(m.authorization_servers),
        );
    }
    if !m.scopes_supported.is_empty() {
        doc.insert("scopes_supported".into(), Value::from(m.scopes_supported));
    }
    doc.insert(
        "bearer_methods_supported".into(),
        Value::from(vec!["header"]),
    );
    (
        [
            (axum::http::header::CACHE_CONTROL, "public, max-age=3600"),
            (
                axum::http::header::CONTENT_TYPE,
                "application/json; charset=utf-8",
            ),
        ],
        axum::Json(Value::Object(doc)),
    )
        .into_response()
}

#[cfg(test)]
#[path = "tests/protocol_tests.rs"]
mod protocol_tests;
