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
    let rendered = metadata_rendered(m);
    let mut response = rendered.body.into_response();
    for (name, value) in rendered.fields {
        if let (Ok(name), Ok(value)) = (
            axum::http::HeaderName::from_bytes(&name),
            axum::http::HeaderValue::from_bytes(&value),
        ) {
            response.headers_mut().insert(name, value);
        }
    }
    response
}

/// The fixed OAuth metadata document as neutral head/body output.
pub fn metadata_rendered(m: &Metadata<'_>) -> crate::plane_driver::Rendered {
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
    crate::plane_driver::Rendered {
        status: 200,
        fields: vec![
            (b"cache-control".to_vec(), b"public, max-age=3600".to_vec()),
            (
                b"content-type".to_vec(),
                b"application/json; charset=utf-8".to_vec(),
            ),
        ],
        body: serde_json::to_vec(&Value::Object(doc)).expect("metadata is a JSON value"),
    }
}

#[cfg(test)]
#[path = "tests/protocol_tests.rs"]
mod protocol_tests;
