// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The kernel's RFC 9728 render, and the bar a declared route carries beside its mount.

use axum::response::Response;
use serde_json::{json, Value};

use super::super::protocol::{metadata, Metadata};

/// The status and the parsed body of one response.
async fn read(r: Response) -> (u16, Value) {
    let status = r.status().as_u16();
    let bytes = axum::body::to_bytes(r.into_body(), 1 << 20).await.unwrap();
    let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, value)
}

/// One document from three facts: the audience, and each OPTIONAL member omitted when empty, never
/// emitted empty (RFC 9728 §2). Scopes with no authorization servers is a combination neither
/// shipped plane states, so a render that assumed one plane's facts would show here.
#[tokio::test]
async fn the_resource_document_renders_its_facts_and_omits_an_empty_member() {
    let scopes = vec!["zeta.read".to_string()];
    let doc = metadata(&Metadata {
        resource: std::borrow::Cow::Borrowed("https://zeta.example/rpc"),
        authorization_servers: &[],
        scopes_supported: &scopes,
    });
    let (status, body) = read(doc).await;
    assert_eq!(status, 200);
    assert_eq!(body["resource"], "https://zeta.example/rpc");
    assert_eq!(body["scopes_supported"], json!(["zeta.read"]));
    assert_eq!(body["bearer_methods_supported"], json!(["header"]));
    assert!(
        body.get("authorization_servers").is_none(),
        "an EMPTY optional member is omitted, never emitted empty: {body}"
    );
}

/// A DECLARED ROUTE CARRIES THE BAR ITS MOUNT DECLARED: `CoreRouter::route` records the path, the
/// method and the bar in one act, so the audience check stays beside the mount and no handler has
/// to remember to ask.
#[test]
fn a_declared_route_inherits_the_bar_beside_its_mount() {
    use busbar_contract::abi::mechanism::route::{RouteAuth, RouteMethod};
    let (_router, table) = crate::core_routes::CoreRouter::new()
        .route(
            "/zeta".to_string(),
            RouteMethod::Post,
            RouteAuth::Key,
            || async { axum::http::StatusCode::NO_CONTENT },
        )
        .route(
            "/.well-known/oauth-protected-resource/zeta".to_string(),
            RouteMethod::Get,
            RouteAuth::None,
            || async {
                metadata(&Metadata {
                    resource: std::borrow::Cow::Borrowed("https://zeta.example/rpc"),
                    authorization_servers: &[],
                    scopes_supported: &[],
                })
            },
        )
        .into_parts();
    assert_eq!(
        table.declared_auth("/zeta", &axum::http::Method::POST),
        Some(RouteAuth::Key),
        "the mount declares the bar; the handler never asks"
    );
    assert_eq!(
        table.declared_auth(
            "/.well-known/oauth-protected-resource/zeta",
            &axum::http::Method::GET
        ),
        Some(RouteAuth::None),
        "RFC 9728 §3: the document is readable without a credential"
    );
}
