// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use axum::response::{IntoResponse, Response};

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

/// The metadata document, borrowed from the configured values and serialized in member order.
#[derive(serde::Serialize)]
struct Document<'a> {
    #[serde(skip_serializing_if = "omitted")]
    authorization_servers: &'a [String],
    bearer_methods_supported: [&'static str; 1],
    resource: &'a str,
    #[serde(skip_serializing_if = "omitted")]
    scopes_supported: &'a [String],
}

fn omitted(list: &&[String]) -> bool {
    list.is_empty()
}

/// The fixed OAuth metadata document as neutral head/body output.
pub(crate) fn metadata_rendered(m: &Metadata<'_>) -> crate::plane_driver::Rendered {
    let doc = Document {
        authorization_servers: m.authorization_servers,
        bearer_methods_supported: ["header"],
        resource: m.resource.as_ref(),
        scopes_supported: m.scopes_supported,
    };
    let mut rendered = crate::plane_driver::Rendered {
        status: 200,
        fields: crate::cold::host::ingress_metadata_fields(),
        body: Vec::with_capacity(128),
    };
    busbar_contract::json::to_writer(&mut rendered.body, &doc).expect("metadata is a JSON value");
    rendered
}

#[cfg(test)]
#[path = "tests/protocol_tests.rs"]
mod protocol_tests;
