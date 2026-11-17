// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The axum responder of the JSON facade. Moved unchanged from busbar-contract `json_facade`.
use busbar_json as json;
use serde::Serialize;

/// `json::Body` answers the writer's bytes as `application/json` (status from the tuple, as axum's
/// `Json`); no serde_json, no axum `json` feature.
#[cfg(feature = "axum")]
#[test]
fn body_bytes_and_content_type_pinned() {
    use axum_core::response::IntoResponse;
    use futures::StreamExt;
    use http::header::CONTENT_TYPE;
    use http::StatusCode;

    #[derive(Serialize)]
    struct Answer {
        b: u64,
        a: &'static str,
    }

    let content_type = |response: &axum_core::response::Response| {
        let types: Vec<Vec<u8>> = response
            .headers()
            .get_all(CONTENT_TYPE)
            .iter()
            .map(|value| value.as_bytes().to_vec())
            .collect();
        types
    };
    let read = |response: axum_core::response::Response| {
        let chunks = futures::executor::block_on(
            response.into_body().into_data_stream().collect::<Vec<_>>(),
        );
        chunks
            .into_iter()
            .flat_map(|chunk| chunk.expect("body chunk").to_vec())
            .collect::<Vec<u8>>()
    };

    let response = json::Body(Answer { b: 2, a: "x\"y" }).into_response();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(content_type(&response), [b"application/json".to_vec()]);
    assert_eq!(read(response), br#"{"b":2,"a":"x\"y"}"#);

    let exact = json::parse_value(br#"{"n":18446744073709551617}"#).expect("parsed");
    let response = (StatusCode::UNAUTHORIZED, json::Body(exact)).into_response();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(content_type(&response), [b"application/json".to_vec()]);
    assert_eq!(read(response), br#"{"n":18446744073709551617}"#);
}
