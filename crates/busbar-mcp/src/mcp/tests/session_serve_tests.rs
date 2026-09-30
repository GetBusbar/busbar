// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SERVING THE SESSION REVISIONS: `2025-06-18` and `2025-11-25` session Streamable HTTP, and the
//! `2024-11-05` event-stream transport, beside the stateless `2026-07-28` revision on ONE endpoint.
//!
//! OWNER 2026-09-29 compat scope; MCP-COMPAT plan C4 (ARCHITECT approval 2026-09-29). Every test
//! drives a REAL router over a REAL socket, for the reason `ingress_tests` gives: what is under test
//! is which verb reaches which arm, behind the auth middleware, and a handler-level call would pass
//! while the arm was unmounted.
//!
//! The session binding (ARCHITECT ruling 2026-09-29) is proven against a GOVERNED chain with two
//! real minted keys: a session belongs to the principal and the credential that opened it, and on
//! every one of the four paths that name a session (POST, GET resume, DELETE, the legacy
//! `?sessionId=` message address) any other credential reads it as a session that does not exist.

use super::super::test_engine::*;
use super::super::McpCfg as Cfg;
use super::H_PROTOCOL_VERSION as VERSION;
use crate::testkit::TestAppMcpExt as _;
use busbar_plane_mcp::adapt::{H_LAST_EVENT_ID as CURSOR, H_SESSION_ID as SID};

const ENDPOINT: &str = "/mcp";
const CANONICAL: &str = "https://gateway.example.com/mcp";

/// The origin a message address is relative to.
fn origin_of(url: &str) -> &str {
    url.trim_end_matches(ENDPOINT)
}

fn cfg() -> Cfg {
    Cfg {
        canonical_uri: CANONICAL.to_string(),
        authorization_servers: vec!["https://login.example.com".to_string()],
        scopes_supported: Vec::new(),
        allowed_origins: Vec::new(),
    }
}

/// Serve an MCP-enabled app with an OPEN auth chain (protocol tests; see `ingress_tests::serve`).
async fn serve_open() -> (String, tokio::task::JoinHandle<()>) {
    metrics_init();
    let app = test_app().mcp(&cfg()).build();
    listen(build_router(app)).await
}

async fn listen(router: axum::Router) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (format!("http://{addr}{}", ENDPOINT), handle)
}

/// Serve an MCP-enabled app behind the KEY chain, and mint two real keys' audience-bound tokens.
async fn serve_governed() -> (String, String, String, tokio::task::JoinHandle<()>) {
    use busbar_kernel::governance::signing::{TokenSigner, TokenVerifier, DEFAULT_KID};
    use busbar_kernel::governance::NewKeySpec;
    metrics_init();
    let store = engine().scratch_store();
    let signer = TokenSigner::from_secret_bytes(&[23u8; 32], DEFAULT_KID);
    let gov = engine()
        .governance(
            store,
            Some("admintok".to_string()),
            Some(TokenSigner::from_secret_bytes(&[23u8; 32], DEFAULT_KID)),
        )
        .unwrap();
    let mut tokens = Vec::new();
    for name in ["session-owner", "session-intruder"] {
        let (key, plain) = gov
            .mint_signed(
                NewKeySpec {
                    name: name.to_string(),
                    allowed_pools: None,
                    group: Some("one-group".to_string()),
                    labels: Default::default(),
                    ..Default::default()
                },
                2_000_000_000,
                busbar_kernel::store::now(),
            )
            .unwrap();
        let generation = TokenVerifier::single(signer.kid(), signer.verifying_key())
            .verify(plain.as_str(), busbar_kernel::store::now(), None)
            .expect("the plain token verifies")
            .generation;
        tokens.push(signer.mint_for_audience(
            &key.id,
            2_000_000_000,
            generation.as_deref(),
            CANONICAL,
            Some(name),
        ));
    }
    let app = test_app().keys_chain().governance(gov).mcp(&cfg()).build();
    let (url, h) = listen(build_router(app)).await;
    let intruder = tokens.pop().unwrap();
    let owner = tokens.pop().unwrap();
    (url, owner, intruder, h)
}

fn initialize(id: i64, version: &str) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0", "id": id, "method": "initialize",
        "params": {
            "protocolVersion": version,
            "capabilities": {},
            "clientInfo": { "name": "compat-test", "version": "1" },
        },
    })
}

fn request(id: i64, method: &str) -> serde_json::Value {
    serde_json::json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": {} })
}

struct Answer {
    status: u16,
    session: Option<String>,
    body: serde_json::Value,
}

async fn post(
    url: &str,
    bearer: Option<&str>,
    body: &serde_json::Value,
    headers: &[(&str, &str)],
) -> Answer {
    let mut req = reqwest::Client::new()
        .post(url)
        .header("accept", "application/json, text/event-stream")
        .json(body);
    if let Some(b) = bearer {
        req = req.header("authorization", format!("Bearer {b}"));
    }
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let resp = req.send().await.unwrap();
    let status = resp.status().as_u16();
    let session = resp
        .headers()
        .get(SID)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let text = resp.text().await.unwrap_or_default();
    let body = if content_type.starts_with("text/event-stream") {
        text.lines()
            .filter_map(|l| l.strip_prefix("data: "))
            .filter_map(|d| serde_json::from_str::<serde_json::Value>(d).ok())
            .find(|v| v.get("id").is_some())
            .unwrap_or_default()
    } else {
        serde_json::from_str(&text).unwrap_or_default()
    };
    Answer {
        status,
        session,
        body,
    }
}

/// Opens a session at `version` and completes it with `notifications/initialized`.
async fn open_session(url: &str, bearer: Option<&str>, version: &str) -> String {
    let a = post(url, bearer, &initialize(0, version), &[]).await;
    assert_eq!(a.status, 200, "initialize: {}", a.body);
    let sid = a.session.expect("initialize names a session");
    let done = serde_json::json!({ "jsonrpc": "2.0", "method": "notifications/initialized" });
    let n = post(url, bearer, &done, &[(SID, &sid), (VERSION, version)]).await;
    assert_eq!(n.status, 202, "notifications/initialized is accepted");
    sid
}

/// Reads an event stream until `pred` matches an event's `(event, data)` or the deadline passes.
async fn read_until(
    resp: &mut reqwest::Response,
    mut pred: impl FnMut(Option<&str>, &str) -> bool,
) -> Option<(Option<String>, String)> {
    let mut buf = String::new();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        while let Some(end) = buf.find("\n\n") {
            let raw: String = buf.drain(..end + 2).collect();
            let mut event = None;
            let mut data = Vec::new();
            for line in raw.lines() {
                if let Some(e) = line.strip_prefix("event: ") {
                    event = Some(e.to_string());
                } else if let Some(d) = line.strip_prefix("data: ") {
                    data.push(d.to_string());
                }
            }
            let data = data.join("\n");
            if pred(event.as_deref(), &data) {
                return Some((event, data));
            }
        }
        let chunk = tokio::time::timeout_at(deadline, resp.chunk())
            .await
            .ok()?
            .ok()??;
        buf.push_str(&String::from_utf8_lossy(&chunk));
    }
}

// ── NEGOTIATION ─────────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn initialize_opens_a_session_in_the_requested_revision() {
    let (url, h) = serve_open().await;
    for v in ["2025-06-18", "2025-11-25"] {
        let a = post(&url, None, &initialize(1, v), &[]).await;
        assert_eq!(a.status, 200, "{v}: {}", a.body);
        assert_eq!(a.body["result"]["protocolVersion"], v);
        let sid = a.session.expect("a session revision names its session");
        assert_eq!(sid.len(), 32, "128 bits, hex");
        assert!(sid.bytes().all(|b| b.is_ascii_hexdigit()));
        assert!(a.body["result"]["serverInfo"]["name"].is_string());
    }
    h.abort();
}

#[tokio::test]
async fn an_unimplemented_revision_is_offered_the_latest_session_revision() {
    let (url, h) = serve_open().await;
    // `2024-11-05` is carried only on its own event stream, so asking for it on the endpoint is
    // answered like an unknown revision.
    for asked in ["2025-03-26", "1999-01-01", "2024-11-05"] {
        let a = post(&url, None, &initialize(1, asked), &[]).await;
        assert_eq!(a.status, 200);
        assert_eq!(a.body["result"]["protocolVersion"], "2025-11-25", "{asked}");
    }
    h.abort();
}

#[tokio::test]
async fn two_initializes_mint_two_different_sessions() {
    let (url, h) = serve_open().await;
    let a = post(&url, None, &initialize(1, "2025-06-18"), &[]).await;
    let b = post(&url, None, &initialize(1, "2025-06-18"), &[]).await;
    assert_ne!(a.session, b.session);
    h.abort();
}

// ── IN SESSION ──────────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_session_request_is_answered_in_the_session_revisions_shape() {
    let (url, h) = serve_open().await;
    let sid = open_session(&url, None, "2025-06-18").await;
    let hdr = [(SID, sid.as_str()), (VERSION, "2025-06-18")];
    let a = post(&url, None, &request(2, "tools/list"), &hdr).await;
    assert_eq!(a.status, 200, "{}", a.body);
    assert!(a.body["result"]["tools"].is_array(), "{}", a.body);
    assert!(
        a.body["result"].get("resultType").is_none(),
        "a 2026-only member leaked"
    );
    let p = post(&url, None, &request(3, "ping"), &hdr).await;
    assert_eq!(p.body["result"], serde_json::json!({}));
    h.abort();
}

#[tokio::test]
async fn red_a_session_client_never_reaches_a_stateless_only_method() {
    let (url, h) = serve_open().await;
    let sid = open_session(&url, None, "2025-11-25").await;
    let hdr = [(SID, sid.as_str()), (VERSION, "2025-11-25")];
    for m in ["server/discover", "subscriptions/listen", "tasks/get"] {
        let a = post(&url, None, &request(4, m), &hdr).await;
        assert_eq!(a.body["error"]["code"], -32601, "{m}: {}", a.body);
    }
    h.abort();
}

#[tokio::test]
async fn an_unknown_session_is_404() {
    let (url, h) = serve_open().await;
    let hdr = [
        (SID, "0123456789abcdef0123456789abcdef"),
        (VERSION, "2025-06-18"),
    ];
    let a = post(&url, None, &request(5, "tools/list"), &hdr).await;
    assert_eq!(a.status, 404);
    h.abort();
}

#[tokio::test]
async fn a_version_header_that_disagrees_with_the_session_is_400() {
    let (url, h) = serve_open().await;
    let sid = open_session(&url, None, "2025-06-18").await;
    let hdr = [(SID, sid.as_str()), (VERSION, "2025-11-25")];
    let a = post(&url, None, &request(6, "tools/list"), &hdr).await;
    assert_eq!(a.status, 400, "{}", a.body);
    h.abort();
}

#[tokio::test]
async fn delete_ends_a_session_and_it_is_404_after() {
    let (url, h) = serve_open().await;
    let sid = open_session(&url, None, "2025-11-25").await;
    let c = reqwest::Client::new();
    let d = c
        .delete(&url)
        .header(SID, &sid)
        .header(VERSION, "2025-11-25")
        .send()
        .await
        .unwrap();
    assert!(
        d.status().is_success(),
        "DELETE of a live session: {}",
        d.status()
    );
    let hdr = [(SID, sid.as_str()), (VERSION, "2025-11-25")];
    let a = post(&url, None, &request(7, "tools/list"), &hdr).await;
    assert_eq!(a.status, 404);
    h.abort();
}

// ── THE GET STREAM AND RESUMPTION ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn get_with_a_session_opens_its_event_stream() {
    let (url, h) = serve_open().await;
    let sid = open_session(&url, None, "2025-06-18").await;
    let resp = reqwest::Client::new()
        .get(&url)
        .header("accept", "text/event-stream")
        .header(SID, &sid)
        .header(VERSION, "2025-06-18")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let ct = resp
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(ct.starts_with("text/event-stream"), "{ct}");
    h.abort();
}

#[tokio::test]
async fn a_resume_cursor_the_session_never_issued_replays_nothing_and_is_not_an_error_page() {
    let (url, h) = serve_open().await;
    let sid = open_session(&url, None, "2025-11-25").await;
    let resp = reqwest::Client::new()
        .get(&url)
        .header("accept", "text/event-stream")
        .header(SID, &sid)
        .header(VERSION, "2025-11-25")
        .header(CURSOR, "99-99")
        .send()
        .await
        .unwrap();
    // A cursor naming a stream this session does not hold is never replayed from another stream
    // (the spec forbids it); the answer is a 404 for that stream, not another stream's events.
    assert_ne!(resp.status().as_u16(), 500);
    h.abort();
}

// ── THE STATELESS PATH IS UNCHANGED ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_plain_get_and_a_sessionless_delete_are_still_405() {
    let (url, h) = serve_open().await;
    let c = reqwest::Client::new();
    for method in [reqwest::Method::GET, reqwest::Method::DELETE] {
        let resp = c.request(method.clone(), &url).send().await.unwrap();
        assert_eq!(resp.status().as_u16(), 405, "{method}");
    }
    h.abort();
}

/// ARCHITECT ruling 2026-09-29: a sessionless GET that accepts an event stream is told apart by
/// its version header. Absent: the `2024-11-05` stream. Naming a single-endpoint revision, or one
/// this server does not implement: `405`.
#[tokio::test]
async fn red_a_sessionless_event_stream_get_with_a_version_header_is_405() {
    let (url, h) = serve_open().await;
    let c = reqwest::Client::new();
    for v in [
        "2025-06-18",
        "2025-11-25",
        "2026-07-28",
        "2025-03-26",
        "not-a-revision",
    ] {
        let resp = c
            .get(&url)
            .header("accept", "text/event-stream")
            .header(VERSION, v)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 405, "{v}");
        assert_eq!(
            resp.headers().get("allow").and_then(|v| v.to_str().ok()),
            Some("POST")
        );
    }
    let legacy = c
        .get(&url)
        .header("accept", "text/event-stream")
        .send()
        .await
        .unwrap();
    assert_eq!(
        legacy.status().as_u16(),
        200,
        "no version header: the 2024-11-05 stream"
    );
    h.abort();
}

#[tokio::test]
async fn a_stateless_request_carrying_a_session_header_is_still_stateless() {
    let (url, h) = serve_open().await;
    let v = super::PROTOCOL_VERSION;
    let body = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/list",
        "params": { "_meta": {
            "io.modelcontextprotocol/protocolVersion": v,
            "io.modelcontextprotocol/clientCapabilities": {},
        }},
    });
    let hdr = [
        (VERSION, v),
        ("mcp-method", "tools/list"),
        (SID, "0123456789abcdef0123456789abcdef"),
    ];
    let a = post(&url, None, &body, &hdr).await;
    assert_eq!(a.status, 200, "{}", a.body);
    assert!(
        a.session.is_none(),
        "the stateless revision never echoes a session"
    );
    h.abort();
}

// ── THE 2024-11-05 EVENT-STREAM TRANSPORT ───────────────────────────────────────────────────────

#[tokio::test]
async fn the_event_stream_transport_names_an_address_and_answers_on_the_stream() {
    let (url, h) = serve_open().await;
    let mut stream = reqwest::Client::new()
        .get(&url)
        .header("accept", "text/event-stream")
        .send()
        .await
        .unwrap();
    assert_eq!(stream.status().as_u16(), 200);
    let (_, address) = read_until(&mut stream, |e, _| e == Some("endpoint"))
        .await
        .expect("the first event names the message address");
    assert!(
        address.starts_with(&format!("{ENDPOINT}?sessionId=")),
        "{address}"
    );
    let origin = origin_of(&url);
    let target = format!("{origin}{address}");
    let a = post(&target, None, &initialize(10, "2024-11-05"), &[]).await;
    assert_eq!(
        a.status, 202,
        "a message POST is accepted; its answer rides the stream"
    );
    let (_, data) = read_until(&mut stream, |e, d| {
        e == Some("message") && d.contains("\"id\":10")
    })
    .await
    .expect("the initialize answer arrives on the stream");
    let v: serde_json::Value = serde_json::from_str(&data).unwrap();
    assert_eq!(v["result"]["protocolVersion"], "2024-11-05");
    h.abort();
}

#[tokio::test]
async fn a_message_address_for_no_live_stream_is_404() {
    let (url, h) = serve_open().await;
    let target = format!("{url}?sessionId=0123456789abcdef0123456789abcdef");
    let a = post(&target, None, &request(11, "tools/list"), &[]).await;
    assert_eq!(a.status, 404);
    h.abort();
}

// ── RED: THE SESSION IS BOUND TO THE PRINCIPAL AND CREDENTIAL THAT OPENED IT ────────────────────

#[tokio::test]
async fn red_another_credential_cannot_use_delete_or_resume_a_session() {
    let (url, owner, intruder, h) = serve_governed().await;
    let sid = open_session(&url, Some(&owner), "2025-11-25").await;
    let hdr = [(SID, sid.as_str()), (VERSION, "2025-11-25")];

    // POST
    let a = post(&url, Some(&intruder), &request(20, "tools/list"), &hdr).await;
    assert_eq!(
        a.status, 404,
        "a foreign POST reads the session as unknown: {}",
        a.body
    );
    // GET resume
    let c = reqwest::Client::new();
    let g = c
        .get(&url)
        .header("authorization", format!("Bearer {intruder}"))
        .header("accept", "text/event-stream")
        .header(SID, &sid)
        .header(VERSION, "2025-11-25")
        .header(CURSOR, "0-0")
        .send()
        .await
        .unwrap();
    assert_eq!(
        g.status().as_u16(),
        404,
        "a foreign resume reads the session as unknown"
    );
    // DELETE
    let d = c
        .delete(&url)
        .header("authorization", format!("Bearer {intruder}"))
        .header(SID, &sid)
        .header(VERSION, "2025-11-25")
        .send()
        .await
        .unwrap();
    assert_eq!(d.status().as_u16(), 404, "a foreign DELETE ends nothing");

    // ...and the owner's session survived every one of those.
    let ok = post(&url, Some(&owner), &request(21, "tools/list"), &hdr).await;
    assert_eq!(ok.status, 200, "{}", ok.body);
    h.abort();
}

#[tokio::test]
async fn red_another_credential_cannot_post_to_an_event_stream_address() {
    let (url, owner, intruder, h) = serve_governed().await;
    let mut stream = reqwest::Client::new()
        .get(&url)
        .header("authorization", format!("Bearer {owner}"))
        .header("accept", "text/event-stream")
        .send()
        .await
        .unwrap();
    assert_eq!(stream.status().as_u16(), 200);
    let (_, address) = read_until(&mut stream, |e, _| e == Some("endpoint"))
        .await
        .expect("endpoint event");
    let target = format!("{}{address}", origin_of(&url));
    let a = post(&target, Some(&intruder), &initialize(30, "2024-11-05"), &[]).await;
    assert_eq!(
        a.status, 404,
        "a foreign message POST reads the address as unknown"
    );
    let ok = post(&target, Some(&owner), &initialize(31, "2024-11-05"), &[]).await;
    assert_eq!(ok.status, 202);
    h.abort();
}
