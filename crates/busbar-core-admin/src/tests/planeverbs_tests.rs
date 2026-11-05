// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

#[test]
fn a_resolved_lookup_is_returned_untouched() {
    let found =
        registered(|| Some(("entry", "cfg"))).expect("a lookup that resolved must not be refused");
    assert_eq!(found, ("entry", "cfg"));
}

#[tokio::test]
async fn plane_unavailable_and_internal_fault_remain_distinct_on_the_listener() {
    let router = axum::Router::new()
        .route(
            "/unavailable",
            axum::routing::get(|| async {
                refusal_response("unused", "unused", PlaneVerbError::Unavailable)
            }),
        )
        .route(
            "/internal",
            axum::routing::get(|| async {
                refusal_response(
                    "unused",
                    "unused",
                    PlaneVerbError::Internal("PRIVATE_BACKEND_SENTINEL".into()),
                )
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    for (path, status, code) in [
        ("unavailable", 503, "unavailable"),
        ("internal", 500, "internal"),
    ] {
        let response = client
            .get(format!("http://{address}/{path}"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), status);
        assert_eq!(response.headers()["content-type"], "application/json");
        let text = response.text().await.unwrap();
        assert!(!text.contains("PRIVATE_BACKEND_SENTINEL"));
        let body: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(body["error"]["code"], code);
    }
    server.abort();
    let _ = server.await;
}
