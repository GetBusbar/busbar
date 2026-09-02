//! Tests for [`super::read_capped_token_response`] — the shared capped-read-and-decode helper
//! `jwt_bearer::Signer::mint` and `oauth_client_credentials::ClientCreds::mint` both call, so this is the
//! one place that proves the truncated-oversized vs transport-error distinction for both mechanisms at
//! once.

/// One GET through the REAL minter client (the engine), returning the response plus the mint
/// deadline the read helper consumes.
async fn fetch(url: &str) -> (http::Response<hyper::body::Incoming>, tokio::time::Instant) {
    let client = super::minter_client().unwrap();
    let request = crate::egress::engine::request(
        http::Method::GET,
        url.parse().expect("mock url"),
        http::HeaderMap::new(),
        bytes::Bytes::new(),
    );
    let deadline = tokio::time::Instant::now() + super::MINT_DEADLINE;
    let resp = crate::egress::engine::send_bounded(&client, request, deadline)
        .await
        .expect("the mock answers");
    (resp, deadline)
}

/// A response body over the cap is reported as a clear, distinguishable "exceeded the cap" error, never
/// silently buffered or partially parsed.
#[tokio::test]
async fn over_cap_response_is_reported_as_truncated() {
    // A 300 KiB body overruns the 256 KiB default cap, served on a real loopback socket through
    // substrate's own egress fixture (busbar-core's `MockServer` is unreachable from here).
    let oversized_token = "a".repeat(300 * 1024);
    let body =
        serde_json::json!({ "access_token": oversized_token, "expires_in": 3600 }).to_string();
    let server = crate::egress::fixtures::spawn_http(crate::egress::fixtures::CannedResponse::ok(&body), 1);

    let (resp, deadline) = fetch(&format!("http://{}", server.addr)).await;
    let err = super::read_capped_token_response(resp, deadline)
        .await
        .expect_err("an over-cap response must be a clear error, not a buffered success");

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
    // The premature-close fixture answers the response HEAD (advertising a content-length) then
    // CLOSES the socket without the body — a genuine mid-body connection drop, not our own size cap
    // tripping. hyper surfaces the premature EOF as a transport error (`ReadEnd::TransportError`).
    // Real-socket substrate twin of busbar-core's old `MockResponse::SseTransportError`.
    let server = crate::egress::fixtures::spawn_http_premature_close(1024);

    let (resp, deadline) = fetch(&format!("http://{}", server.addr)).await;
    let err = super::read_capped_token_response(resp, deadline)
        .await
        .expect_err("a connection that drops mid-read must be a clear error");

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
