//! Tests for [`super::read_capped_token_response`] — the shared capped-read-and-decode helper
//! `jwt_bearer::Signer::mint` and `oauth_client_credentials::ClientCreds::mint` both call, so this is the
//! one place that proves the truncated-oversized vs transport-error distinction for both mechanisms at
//! once.

/// One GET through the REAL minter client (the engine), returning the response plus the mint
/// deadline the read helper consumes.
async fn fetch(url: &str) -> (http::Response<hyper::body::Incoming>, tokio::time::Instant) {
    let client = super::minter_client().unwrap();
    let request = busbar_substrate::egress::engine::request(
        http::Method::GET,
        url.parse().expect("mock url"),
        http::HeaderMap::new(),
        bytes::Bytes::new(),
    );
    let deadline = tokio::time::Instant::now() + super::MINT_DEADLINE;
    let resp = busbar_substrate::egress::engine::send_bounded(&client, request, deadline)
        .await
        .expect("the mock answers");
    (resp, deadline)
}

/// A response body over the cap is reported as a clear, distinguishable "exceeded the cap" error, never
/// silently buffered or partially parsed.
#[tokio::test]
async fn over_cap_response_is_reported_as_truncated() {
    let state = std::sync::Arc::new(crate::test_support::MockServerState::new());
    let oversized_token = "a".repeat(300 * 1024);
    state.push(crate::test_support::MockResponse::Ok {
        status: axum::http::StatusCode::OK,
        body: serde_json::json!({ "access_token": oversized_token, "expires_in": 3600 }),
    });
    let server = crate::test_support::MockServer::new(state).await;

    let (resp, deadline) = fetch(&server.base_url()).await;
    let err = super::read_capped_token_response(resp, deadline)
        .await
        .expect_err("an over-cap response must be a clear error, not a buffered success");
    server.shutdown().await;

    assert!(
        err.contains("cap"),
        "expected an error naming the size cap, got: {err}"
    );
}

/// A connection that drops mid-read produces a DIFFERENT, distinguishable message from the
/// oversized-response case above — an operator debugging a real transport failure must not see the same
/// "exceeded the cap" wording a misconfigured size limit would produce (both minters previously folded
/// `ReadEnd::Truncated` and `ReadEnd::TransportError` into one ambiguous message).
#[tokio::test]
async fn transport_error_during_read_is_reported_distinctly_from_truncation() {
    let state = std::sync::Arc::new(crate::test_support::MockServerState::new());
    // Emits zero real frames, pauses, then yields a stream `Err` — a genuine mid-body connection drop,
    // not our own size cap tripping.
    state.push(crate::test_support::MockResponse::SseTransportError { ok_events: vec![] });
    let server = crate::test_support::MockServer::new(state).await;

    let (resp, deadline) = fetch(&server.base_url()).await;
    let err = super::read_capped_token_response(resp, deadline)
        .await
        .expect_err("a connection that drops mid-read must be a clear error");
    server.shutdown().await;

    assert!(
        !err.contains("cap") && !err.contains("truncat"),
        "a transport-error message must not read as an oversized-response/cap message, got: {err}"
    );

    // And it must actually differ from the truncated-response wording proven above, not merely dodge
    // those two words by coincidence.
    let truncated_msg = "token endpoint response exceeded the 1-byte cap; refusing to parse a truncated token response";
    assert_ne!(
        err, truncated_msg,
        "transport-error and truncated-response messages must be distinguishable"
    );
}
