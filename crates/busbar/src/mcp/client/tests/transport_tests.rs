// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The streamable-HTTP transport, against a REAL loopback server.
//!
//! A real server rather than a mock, because the two properties that matter — a redirect is not
//! followed, and an SSE answer is read — are properties of the HTTP client's behaviour and a mock
//! would be asserting my own understanding of it back at me.

use crate::mcp::client::jsonrpc::{parse_response, tools_list, RpcOutcome};
use crate::mcp::client::pool::McpConnectionPool;
use crate::mcp::client::ssrf::{SsrfPolicy, SsrfRefusal};
use crate::mcp::client::transport::{HttpTransport, TransportError};
use std::time::Duration;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

fn private_ok() -> SsrfPolicy {
    SsrfPolicy {
        allow_private: true,
    }
}

/// Serve one HTTP response with a correctly framed body, and return the URL to POST to.
///
/// `Content-Length` is COMPUTED rather than written by hand. A hand-written length that is too long
/// makes the client report a truncated read, which looks exactly like the transport bug this file
/// exists to rule out — a fixture that can fake the failure it is testing for is worse than no
/// fixture.
async fn serve(status: &str, content_type: &str, body: &'static str) -> String {
    let raw = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    raw_one_shot(raw).await
}

/// Serve exactly one HTTP request with a canned raw response, and return the URL to POST to.
async fn raw_one_shot(raw_response: String) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        if let Ok((mut sock, _)) = listener.accept().await {
            let mut buf = [0u8; 4096];
            // One read is enough for the small request this client sends; the point is to consume it
            // before answering, not to parse it.
            let _ = sock.read(&mut buf).await;
            let _ = sock.write_all(raw_response.as_bytes()).await;
            let _ = sock.flush().await;
        }
    });
    format!("http://127.0.0.1:{}/mcp", addr.port())
}

#[tokio::test]
async fn a_json_response_round_trips() {
    let url = serve(
        "200 OK",
        "application/json",
        r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}"#,
    )
    .await;
    let pool = McpConnectionPool::new();
    let req = tools_list(&url, 1, None);
    let resp = HttpTransport::send(&pool, &req, private_ok(), Duration::from_secs(5))
        .await
        .expect("a 200 with JSON round trips");
    assert_eq!(resp.status, 200);
    assert_eq!(
        parse_response(&resp.body, 1),
        RpcOutcome::Result(serde_json::json!({"tools": []}))
    );
}

/// A REDIRECT IS NEVER FOLLOWED, and it is reported AS a redirect rather than as a parse failure —
/// the two mechanisms of `super::ssrf`, both exercised.
#[tokio::test]
async fn a_redirect_is_refused_and_names_where_it_pointed() {
    let url = raw_one_shot(
        "HTTP/1.1 302 Found\r\nLocation: http://169.254.169.254/latest/meta-data/\r\n\
         Content-Length: 0\r\n\r\n"
            .to_string(),
    )
    .await;
    let pool = McpConnectionPool::new();
    let req = tools_list(&url, 1, Some("secret-upstream-token"));
    let err = HttpTransport::send(&pool, &req, private_ok(), Duration::from_secs(5))
        .await
        .expect_err("a 302 must be refused");
    assert_eq!(
        err,
        TransportError::Refused(SsrfRefusal::Redirect {
            status: 302,
            location: "http://169.254.169.254/latest/meta-data/".into()
        })
    );
    assert!(
        err.to_string().contains("credential is already sent"),
        "the refusal must say why redirects are dangerous here: {err}"
    );
}

/// SSE is a permitted CONTENT TYPE for the answer to a POST in this revision, and nothing more.
/// The LAST `data:` payload is the response; earlier ones are progress notifications.
#[tokio::test]
async fn an_sse_answer_yields_the_last_data_payload() {
    let url = serve(
        "200 OK",
        "text/event-stream",
        "event: progress\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"x\"}\n\n\
         data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"ok\":true}}\n\n",
    )
    .await;
    let pool = McpConnectionPool::new();
    let req = tools_list(&url, 1, None);
    let resp = HttpTransport::send(&pool, &req, private_ok(), Duration::from_secs(5))
        .await
        .expect("an SSE answer is read");
    assert_eq!(
        parse_response(&resp.body, 1),
        RpcOutcome::Result(serde_json::json!({"ok": true})),
        "the LAST data payload is the response, not the first"
    );
}

/// The SSRF guard runs on the transport too, not only in the pool's own tests: a destination that
/// fails the check never reaches the socket.
#[tokio::test]
async fn the_transport_refuses_a_destination_the_guard_rejects() {
    let pool = McpConnectionPool::new();
    let req = tools_list("https://169.254.169.254/mcp", 1, Some("token"));
    let err = HttpTransport::send(&pool, &req, SsrfPolicy::default(), Duration::from_secs(5))
        .await
        .expect_err("cloud metadata is refused");
    assert!(
        matches!(
            err,
            TransportError::Refused(SsrfRefusal::CloudMetadata { .. })
        ),
        "got {err:?}"
    );
}

/// An upstream JSON-RPC error is a TRANSPORT SUCCESS. Folding the two would make a breaker count
/// protocol disagreements as outages.
#[tokio::test]
async fn an_upstream_jsonrpc_error_is_not_a_transport_error() {
    let url = serve(
        "200 OK",
        "application/json",
        r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"no such"}}"#,
    )
    .await;
    let pool = McpConnectionPool::new();
    let resp = HttpTransport::send(
        &pool,
        &tools_list(&url, 1, None),
        private_ok(),
        Duration::from_secs(5),
    )
    .await
    .expect("reachable and healthy, protocol disagreement aside");
    assert!(matches!(
        parse_response(&resp.body, 1),
        RpcOutcome::Error { code: -32601, .. }
    ));
}

// ══ RESPONSE CORRELATION, READ OFF BOTH DIRECTIONS OF A REAL WIRE ════════════════════════════════
//
// WHY THESE READ THE REQUEST BYTES TOO. The sibling investigation on the request side found the
// in-house battery's `SRV.NOTIF.NO-RESPONSE` check passing against a provably broken binary, because
// the battery's own `isResponse()` predicate was `'id' in msg` and the illegal reply was classified
// as neither a response nor a notification. An instrument can be blind to exactly the defect it is
// pointed at. The defence here is to assert on BYTES rather than on any predicate: what `id` busbar
// actually put on the socket, and what busbar did with an answer naming a different one.

/// Serve one canned response AND hand back every byte of the request that was made, so a test can
/// assert on both directions rather than on the parser's opinion of one of them.
async fn one_shot_capturing(
    status: &str,
    content_type: &str,
    body: &'static str,
) -> (String, std::sync::Arc<std::sync::Mutex<Vec<u8>>>) {
    let raw = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let addr = listener.local_addr().unwrap();
    let captured = std::sync::Arc::clone(&seen);
    tokio::spawn(async move {
        if let Ok((mut sock, _)) = listener.accept().await {
            let mut buf = [0u8; 8192];
            if let Ok(n) = sock.read(&mut buf).await {
                captured
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .extend_from_slice(&buf[..n]);
            }
            let _ = sock.write_all(raw.as_bytes()).await;
            let _ = sock.flush().await;
        }
    });
    (format!("http://127.0.0.1:{}/mcp", addr.port()), seen)
}

/// THE DEFECT. Busbar sends `"id": 4242` and the upstream answers `"id": 9999` carrying a tool list
/// busbar never asked for. Before the correlation, that list was returned as this dispatch's result
/// — and every fixture in this tree paired one request with one response, so nothing could see it.
#[tokio::test]
async fn an_answer_naming_a_different_request_is_refused_and_its_payload_never_surfaces() {
    let (url, seen) = one_shot_capturing(
        "200 OK",
        "application/json",
        r#"{"jsonrpc":"2.0","id":9999,"result":{"tools":[{"name":"ANOTHER_CALLERS_TOOL"}]}}"#,
    )
    .await;
    let pool = McpConnectionPool::new();
    let resp = HttpTransport::send(
        &pool,
        &tools_list(&url, 4242, None),
        private_ok(),
        Duration::from_secs(5),
    )
    .await
    .expect("the upstream answered");

    // DIRECTION 1: the id busbar really put on the socket. Asserted off the captured bytes, not off
    // the struct busbar built, so a builder that wrote one id and a transport that sent another
    // could not both pass.
    let request =
        String::from_utf8_lossy(&seen.lock().unwrap_or_else(|e| e.into_inner())).to_string();
    assert!(
        request.contains(r#""id":4242"#),
        "busbar did not put this dispatch's id on the wire: {request}"
    );

    // DIRECTION 2: what busbar does with an answer naming another one.
    let out = parse_response(&resp.body, 4242);
    assert!(
        matches!(out, RpcOutcome::Uncorrelated(_)),
        "an answer to request 9999 was accepted as the answer to request 4242: {out:?}"
    );
    assert!(
        !format!("{out:?}").contains("ANOTHER_CALLERS_TOOL"),
        "the other request's payload came back out of the refusal: {out:?}"
    );
}

/// THE CONTROL. The identical exchange with the identical id is served, and its payload survives.
/// Without it, every assertion above is satisfied by a client that refuses everything.
#[tokio::test]
async fn the_same_exchange_with_the_id_that_was_sent_is_served() {
    let (url, seen) = one_shot_capturing(
        "200 OK",
        "application/json",
        r#"{"jsonrpc":"2.0","id":4242,"result":{"tools":[{"name":"OUR_TOOL"}]}}"#,
    )
    .await;
    let pool = McpConnectionPool::new();
    let resp = HttpTransport::send(
        &pool,
        &tools_list(&url, 4242, None),
        private_ok(),
        Duration::from_secs(5),
    )
    .await
    .expect("the upstream answered");
    let request =
        String::from_utf8_lossy(&seen.lock().unwrap_or_else(|e| e.into_inner())).to_string();
    assert!(request.contains(r#""id":4242"#), "{request}");
    assert_eq!(
        parse_response(&resp.body, 4242),
        RpcOutcome::Result(serde_json::json!({ "tools": [{ "name": "OUR_TOOL" }] }))
    );
}

/// The two shapes that are not "a different id" but are equally uncorrelatable: `"id": null`, which
/// section 5 reserves for "the sender could not tell which request this was", and no `id` member at
/// all, which is both REQUIRED-and-missing and the shape a notification has.
#[tokio::test]
async fn a_null_id_and_a_missing_id_are_uncorrelated_rather_than_results() {
    for body in [
        r#"{"jsonrpc":"2.0","id":null,"result":{"tools":[]}}"#,
        r#"{"jsonrpc":"2.0","result":{"tools":[]}}"#,
    ] {
        let (url, _seen) = one_shot_capturing("200 OK", "application/json", body).await;
        let pool = McpConnectionPool::new();
        let resp = HttpTransport::send(
            &pool,
            &tools_list(&url, 4242, None),
            private_ok(),
            Duration::from_secs(5),
        )
        .await
        .expect("the upstream answered");
        let out = parse_response(&resp.body, 4242);
        assert!(
            matches!(out, RpcOutcome::Uncorrelated(_)),
            "`{body}` was accepted as this dispatch's answer: {out:?}"
        );
    }
}
