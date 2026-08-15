// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The MCP HTTP ingress: the transport-level MUSTs of revision `2026-07-28`.
//!
//! These tests drive a REAL router over a REAL socket rather than calling the handler, because half
//! of what is under test is the interaction between the route table, the auth middleware and the
//! handler — which method reaches which arm, and whether a refusal happens before or after
//! admission. A handler-level test would answer none of those questions and would pass while the
//! endpoint was unmounted.

use crate::mcp::envelope::{PROTOCOL_VERSION, SUPPORTED_PROTOCOL_VERSIONS};
use crate::mcp::McpCfg;
use crate::test_support::TestApp;

const CANONICAL: &str = "https://gateway.example.com/mcp";

fn mcp_cfg(allowed_origins: Vec<String>) -> McpCfg {
    McpCfg {
        canonical_uri: CANONICAL.to_string(),
        authorization_servers: vec!["https://login.example.com".to_string()],
        scopes_supported: Vec::new(),
        allowed_origins,
    }
}

/// Serve an MCP-enabled app with an OPEN auth chain.
///
/// Open on purpose: these tests are about the PROTOCOL envelope, and every one of them must reach
/// the handler to say anything. The auth half of this plane is asserted separately — by
/// `resource_tests` for the challenge and the metadata document, and by
/// `auth::tests::test_mcp_token_is_confined_to_the_mcp_plane` for the audience boundary — so
/// leaving the door open here narrows what each test can be wrong about rather than skipping a
/// check.
async fn serve(origins: Vec<String>) -> (String, tokio::task::JoinHandle<()>) {
    crate::metrics::init();
    let app = TestApp::new().mcp(&mcp_cfg(origins)).build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (format!("http://{addr}/mcp"), handle)
}

/// A well-formed request envelope for `method`. Every mirrored header agrees with the body, so a
/// test that wants a mismatch introduces exactly one and nothing else can be responsible.
/// A method the server genuinely does NOT implement.
///
/// Before the method table landed, EVERY method took the `-32601` arm, so any name served as the
/// "the request reached dispatch" control. Now that `tools/*`, `prompts/*`, `resources/*`,
/// `completion/complete` and `server/discover` answer, a control has to be a method that is really
/// absent — otherwise the tests below would be asserting `404` against a surface that returns
/// `200`, and the day one of them turned green for the wrong reason nobody would know which.
///
/// `logging/setLevel` is the choice, and it is a real absence rather than a name invented to be
/// missing: this revision carries no session to hold a log level across requests, so a client asks
/// for logging per request in `_meta` and there is nothing for a `setLevel` RPC to set. A test
/// asserting `404` against a method that could never exist would be asserting nothing.
///
/// RE-EXAMINED WHEN `notifications/message` LANDED, because that is exactly the change that could
/// have turned this control into a lie. It did not, and the reason is worth stating rather than
/// assuming. `logging/setLevel` exists to SET A LEVEL THAT PERSISTS, and its own schema description
/// says so: *"the server should send all logs at this level and higher to the client as
/// notifications/message"* — a standing instruction, for later messages. Under `2026-07-28` there is
/// no later: no handshake, no session, no standing stream, so an RPC that set a level would have
/// nowhere to keep it and nothing to apply it to. busbar therefore reads the level from the
/// request's own `_meta` and emits the records on that request's own response stream
/// (`crate::mcp::sse`), which is the only shape a stateless protocol leaves. The absence is
/// unchanged and it is still principled.
const UNIMPLEMENTED: &str = "logging/setLevel";

fn well_formed(method: &str) -> (serde_json::Value, Vec<(&'static str, String)>) {
    // `_meta` sits under `params`, which is where the schema puts it and where every real client
    // sends it. An earlier version of this helper put it at the top level; the tests all passed and
    // the official conformance suite failed every scenario at setup, because the tests and the
    // implementation shared one wrong belief. The fixture is now the shape the wire carries.
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": {
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {},
            },
        },
    });
    let headers = vec![
        ("mcp-protocol-version", PROTOCOL_VERSION.to_string()),
        ("mcp-method", method.to_string()),
    ];
    (body, headers)
}

async fn post(
    url: &str,
    body: &serde_json::Value,
    headers: &[(&'static str, String)],
) -> (u16, serde_json::Value) {
    let client = reqwest::Client::new();
    let mut req = client.post(url).json(body);
    for (k, v) in headers {
        req = req.header(*k, v.clone());
    }
    let resp = req.send().await.unwrap();
    let status = resp.status().as_u16();
    let json = resp.json::<serde_json::Value>().await.unwrap_or_default();
    (status, json)
}

/// The error code and status a refusal carried, so every assertion below reads as one line.
fn err(v: &serde_json::Value) -> i64 {
    v.pointer("/error/code")
        .and_then(serde_json::Value::as_i64)
        .unwrap_or_else(|| panic!("response carried no JSON-RPC error: {v}"))
}

/// An unimplemented method is `404` with `-32601`, NOT a `200` carrying an error object.
///
/// This is the single easiest MUST in the revision to get wrong, because returning `200` with an
/// error body is what JSON-RPC over HTTP has meant everywhere else for a decade. It is also the arm
/// every well-formed request takes today, which makes it the control for every other test in this
/// file: when a test below asserts `400`, the thing it is proving is that the request did NOT get
/// this far.
#[tokio::test]
async fn an_unimplemented_method_is_404_with_method_not_found() {
    let (url, h) = serve(Vec::new()).await;
    let (body, headers) = well_formed(UNIMPLEMENTED);
    let (status, json) = post(&url, &body, &headers).await;
    assert_eq!(status, 404, "an unimplemented method must not be a 200");
    assert_eq!(err(&json), -32601);
    assert_eq!(json["jsonrpc"], "2.0");
    assert_eq!(json["id"], 1, "the request id must be echoed on the error");
    h.abort();
}

/// GET and DELETE answer `405`, and say so with an `Allow` header. This revision has no GET stream
/// and no sessions; a client built against an older one has found the right endpoint and used a verb
/// that no longer exists, and `405` is the diagnosis that says so where `404` would send it hunting
/// for a path that is not missing.
#[tokio::test]
async fn get_and_delete_are_405_because_the_stream_and_sessions_are_gone() {
    let (url, h) = serve(Vec::new()).await;
    let client = reqwest::Client::new();
    for method in [reqwest::Method::GET, reqwest::Method::DELETE] {
        let resp = client.request(method.clone(), &url).send().await.unwrap();
        assert_eq!(resp.status().as_u16(), 405, "{method} on the MCP endpoint");
        assert_eq!(
            resp.headers().get("allow").and_then(|v| v.to_str().ok()),
            Some("POST"),
            "a 405 owes the caller the verb that does work"
        );
    }
    h.abort();
}

/// An `Mcp-Session-Id` header is IGNORED: not honoured, not echoed, not minted. Under this revision
/// there are no protocol sessions, and a server that echoed one would tell a client it had
/// established state that does not exist — which is exactly the sticky-authority problem this
/// revision removes rather than defends.
#[tokio::test]
async fn a_session_id_header_is_ignored_and_never_echoed() {
    let (url, h) = serve(Vec::new()).await;
    let (body, mut headers) = well_formed(UNIMPLEMENTED);
    headers.push(("mcp-session-id", "stale-session".to_string()));
    let client = reqwest::Client::new();
    let mut req = client.post(&url).json(&body);
    for (k, v) in &headers {
        req = req.header(*k, v.clone());
    }
    let resp = req.send().await.unwrap();
    assert_eq!(
        resp.status().as_u16(),
        404,
        "the session header must change nothing about how the request is handled"
    );
    assert!(
        resp.headers().get("mcp-session-id").is_none(),
        "a session id must never be minted or echoed"
    );
    h.abort();
}

/// THE MIRRORED HEADERS. Each case below makes an intermediary and the executor disagree about what
/// the request is, which is request smuggling spelled in JSON, and each must be `400` with `-32020`
/// rather than resolved in favour of either reading.
#[tokio::test]
async fn every_header_body_disagreement_is_a_400_header_mismatch() {
    let (url, h) = serve(Vec::new()).await;

    // (a) the protocol-version header is absent entirely — a MUST on every POST.
    let (body, headers) = well_formed("tools/list");
    let without_version: Vec<_> = headers
        .iter()
        .filter(|(k, _)| *k != "mcp-protocol-version")
        .cloned()
        .collect();
    let (status, json) = post(&url, &body, &without_version).await;
    assert_eq!((status, err(&json)), (400, -32020), "no version header");

    // (b) the header disagrees with the body's `_meta`.
    let mut disagreeing = headers.clone();
    disagreeing[0].1 = "2025-11-25".to_string();
    let (status, json) = post(&url, &body, &disagreeing).await;
    assert_eq!((status, err(&json)), (400, -32020), "version disagreement");

    // (c) USED TO LIVE HERE and does not any more: a body whose `_meta` carries no protocol
    // version. That is a defect in the request's own PARAMS, not two readings of one request
    // disagreeing, so it answers `-32602` and is pinned by `request_meta_tests`. Naming the move
    // rather than deleting the case silently, because "the header rules cover it" was the belief
    // that put a body defect in the header vocabulary in the first place.

    // (d) `Mcp-Method` absent — REQUIRED on every request.
    let without_method: Vec<_> = headers
        .iter()
        .filter(|(k, _)| *k != "mcp-method")
        .cloned()
        .collect();
    let (status, json) = post(&url, &body, &without_method).await;
    assert_eq!((status, err(&json)), (400, -32020), "no Mcp-Method");

    // (e) `Mcp-Method` naming a different method than the body. THE smuggling case: a rate limiter
    // policing `tools/list` while the server executes `tools/call`.
    let mut wrong_method = headers.clone();
    wrong_method[1].1 = "tools/call".to_string();
    let (status, json) = post(&url, &body, &wrong_method).await;
    assert_eq!((status, err(&json)), (400, -32020), "Mcp-Method mismatch");

    // (f) header VALUES are case-sensitive even though header NAMES are not. `TOOLS/LIST` is not
    // `tools/list`, and folding case here would let a mismatch present itself as a match.
    let mut cased = headers.clone();
    cased[1].1 = "TOOLS/LIST".to_string();
    let (status, json) = post(&url, &body, &cased).await;
    assert_eq!(
        (status, err(&json)),
        (400, -32020),
        "case-folded Mcp-Method"
    );

    h.abort();
}

/// `Mcp-Name` is REQUIRED on exactly `tools/call`, `resources/read` and `prompts/get`, mirrors
/// `params.name` or `params.uri` depending on which, and must be decoded from its `=?base64?…?=`
/// sentinel BEFORE it is compared.
#[tokio::test]
async fn the_name_header_is_required_where_it_is_required_and_decoded_before_comparison() {
    use base64::Engine as _;
    let (url, h) = serve(Vec::new()).await;
    let b64 = |s: &str| base64::engine::general_purpose::STANDARD.encode(s);

    // Absent on a method that requires it.
    let mut body = serde_json::json!({
        "jsonrpc": "2.0", "id": 7, "method": "tools/call",
        "params": {
            "name": "search",
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {},
            },
        },
    });
    let base = vec![
        ("mcp-protocol-version", PROTOCOL_VERSION.to_string()),
        ("mcp-method", "tools/call".to_string()),
    ];
    let (status, json) = post(&url, &body, &base).await;
    assert_eq!((status, err(&json)), (400, -32020), "Mcp-Name absent");

    // Present and disagreeing with `params.name`.
    let mut wrong = base.clone();
    wrong.push(("mcp-name", "delete_everything".to_string()));
    let (status, json) = post(&url, &body, &wrong).await;
    assert_eq!((status, err(&json)), (400, -32020), "Mcp-Name mismatch");

    // Present and agreeing: the request proceeds to dispatch, which has no such method.
    let mut ok = base.clone();
    ok.push(("mcp-name", "search".to_string()));
    let (status, json) = post(&url, &body, &ok).await;
    assert_ne!(
        (status, err(&json)),
        (400, -32020),
        "an agreeing Mcp-Name must reach dispatch, not the header-mismatch arm"
    );

    // The base64 sentinel decodes before comparison. A server comparing the ENCODED form would
    // reject every client that legitimately encoded a name it could not put in a header verbatim.
    let mut sentinel = base.clone();
    sentinel.push(("mcp-name", format!("=?base64?{}?=", b64("search"))));
    let (status, json) = post(&url, &body, &sentinel).await;
    assert_ne!(
        (status, err(&json)),
        (400, -32020),
        "a sentinel-encoded Mcp-Name that decodes to the body's name must be accepted"
    );

    // The markers are CASE-SENSITIVE and lowercase. `=?BASE64?…?=` is a literal value that merely
    // looks encoded, so decoding it would accept a name the client never sent.
    let mut upper = base.clone();
    upper.push(("mcp-name", format!("=?BASE64?{}?=", b64("search"))));
    let (status, json) = post(&url, &body, &upper).await;
    assert_eq!(
        (status, err(&json)),
        (400, -32020),
        "an upper-case sentinel marker is not a sentinel"
    );

    // `resources/read` mirrors `params.uri`, not `params.name`. A rule shorter than the enumeration
    // gets one of the three wrong.
    body = serde_json::json!({
        "jsonrpc": "2.0", "id": 8, "method": "resources/read",
        "params": {
            "uri": "file:///a", "name": "decoy",
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {},
            },
        },
    });
    let read = vec![
        ("mcp-protocol-version", PROTOCOL_VERSION.to_string()),
        ("mcp-method", "resources/read".to_string()),
        ("mcp-name", "file:///a".to_string()),
    ];
    let (status, json) = post(&url, &body, &read).await;
    assert_ne!(
        (status, err(&json)),
        (400, -32020),
        "resources/read mirrors params.uri, so an agreeing header is not a mismatch"
    );

    // And it is NOT required on a method that does not take a target. Requiring it everywhere would
    // refuse conforming clients.
    let (list_body, list_headers) = well_formed("tools/list");
    let (status, _json) = post(&url, &list_body, &list_headers).await;
    assert_eq!(
        status, 200,
        "tools/list must not require Mcp-Name, and it is now an implemented method"
    );

    h.abort();
}

/// An unsupported protocol version is `400` with `-32022` and a `data` block naming what WAS
/// requested and what IS supported — the list is an invitation to retry, and a refusal that does not
/// carry it leaves a client guessing.
#[tokio::test]
async fn an_unsupported_protocol_version_names_what_is_supported() {
    let (url, h) = serve(Vec::new()).await;
    let body = serde_json::json!({
        "jsonrpc": "2.0", "id": 3, "method": "tools/list",
        "params": { "_meta": {
            "io.modelcontextprotocol/protocolVersion": "2025-06-18",
            "io.modelcontextprotocol/clientCapabilities": {},
        } },
    });
    let headers = vec![
        ("mcp-protocol-version", "2025-06-18".to_string()),
        ("mcp-method", "tools/list".to_string()),
    ];
    let (status, json) = post(&url, &body, &headers).await;
    assert_eq!(status, 400);
    assert_eq!(err(&json), -32022);
    assert_eq!(json["error"]["data"]["requested"], "2025-06-18");
    assert_eq!(
        json["error"]["data"]["supported"],
        serde_json::json!(SUPPORTED_PROTOCOL_VERSIONS),
        "the supported list must be the one constant the server actually enforces"
    );
    h.abort();
}

/// A malformed request is never told which versions we speak. `data.supported` is an invitation to
/// retry, and inviting a request that failed for an unrelated reason to retry teaches the client the
/// wrong lesson about why it failed.
#[tokio::test]
async fn a_malformed_request_is_refused_before_the_version_is_judged() {
    let (url, h) = serve(Vec::new()).await;
    // Unsupported version AND a mirrored-header disagreement. The header rules win.
    let body = serde_json::json!({
        "jsonrpc": "2.0", "id": 4, "method": "tools/list",
        "params": { "_meta": {
            "io.modelcontextprotocol/protocolVersion": "1999-01-01",
            "io.modelcontextprotocol/clientCapabilities": {},
        } },
    });
    let headers = vec![
        ("mcp-protocol-version", "1999-01-01".to_string()),
        ("mcp-method", "tools/call".to_string()),
    ];
    let (status, json) = post(&url, &body, &headers).await;
    assert_eq!((status, err(&json)), (400, -32020));
    assert!(
        json["error"]["data"].is_null(),
        "a header mismatch must not leak the supported-version list"
    );
    h.abort();
}

/// Envelope shape: a body that is not JSON, and a JSON-RPC batch. Neither is part of this
/// revision's transport, and both are refused explicitly rather than read as an object with no
/// `method` — which would answer the wrong question with the wrong code.
#[tokio::test]
async fn a_non_json_body_and_a_batch_are_each_refused_with_their_own_code() {
    let (url, h) = serve(Vec::new()).await;
    let client = reqwest::Client::new();
    let resp = client
        .post(&url)
        .header("content-type", "application/json")
        .header("mcp-protocol-version", PROTOCOL_VERSION)
        .header("mcp-method", "tools/list")
        .body("{not json")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 400);
    assert_eq!(err(&resp.json().await.unwrap()), -32700);

    let (single, headers) = well_formed("tools/list");
    let batch = serde_json::json!([single]);
    let (status, json) = post(&url, &batch, &headers).await;
    assert_eq!(
        (status, err(&json)),
        (400, -32600),
        "a batch is not a message"
    );

    let (status, json) = post(
        &url,
        &serde_json::json!({ "jsonrpc": "1.0", "id": 1, "method": "tools/list" }),
        &headers,
    )
    .await;
    assert_eq!((status, err(&json)), (400, -32600), "jsonrpc must be 2.0");
    h.abort();
}

/// ORIGIN VALIDATION, the DNS-rebinding defence. A request carrying NO `Origin` is not a browser
/// request and must be unaffected — refusing those refuses every agent, which is every real client.
/// A request carrying one is refused unless the operator listed it, and the match is exact.
#[tokio::test]
async fn an_origin_is_refused_unless_the_operator_listed_it() {
    let (url, h) = serve(vec!["https://app.example.com".to_string()]).await;
    let (body, headers) = well_formed("tools/list");

    let (status, _) = post(&url, &body, &headers).await;
    assert_eq!(status, 200, "no Origin at all must be unaffected");

    let mut allowed = headers.clone();
    allowed.push(("origin", "https://app.example.com".to_string()));
    let (status, _) = post(&url, &body, &allowed).await;
    assert_eq!(status, 200, "a listed Origin must be admitted");

    // LOOPBACK is always allowed, allowlist or not. A browser sends a loopback `Origin` only for a
    // document served FROM loopback, which is already inside the trust boundary; the rebinding
    // attacker's page carries its own origin (`http://evil.test`), never this one. Refusing these
    // would refuse the local inspector and the local agent for no security gain.
    for local in [
        "http://localhost:3999",
        "http://127.0.0.1:8080",
        "http://[::1]:8080",
        "https://localhost",
    ] {
        let mut loopback = headers.clone();
        loopback.push(("origin", local.to_string()));
        let (status, _) = post(&url, &body, &loopback).await;
        assert_eq!(status, 200, "loopback Origin `{local}` must be admitted");
    }

    for bad in [
        "https://evil.test",
        "https://app.example.com.evil.test",
        "http://app.example.com",
        "null",
        // Near misses on loopback that are NOT loopback: an attacker who registers
        // `localhost.evil.test` must not inherit the local trust boundary.
        "http://localhost.evil.test",
        "http://127.0.0.1.evil.test",
        "http://notlocalhost",
    ] {
        let mut refused = headers.clone();
        refused.push(("origin", bad.to_string()));
        let (status, _) = post(&url, &body, &refused).await;
        assert_eq!(status, 403, "Origin `{bad}` must be refused with 403");
    }
    h.abort();
}

/// The default posture: with no `allowed_origins` configured, EVERY origin is refused and only
/// origin-less (non-browser) callers get through. A deployment that forgot to configure origins is
/// closed to browsers rather than open to all of them.
#[tokio::test]
async fn the_default_origin_allowlist_is_empty_and_therefore_closed() {
    let (url, h) = serve(Vec::new()).await;
    let (body, headers) = well_formed("tools/list");
    let mut with_origin = headers.clone();
    with_origin.push(("origin", "https://app.example.com".to_string()));
    let (status, _) = post(&url, &body, &with_origin).await;
    assert_eq!(status, 403);
    // ... and the loopback exemption is not a hole in that default: it is the one origin class a
    // rebinding attacker cannot forge.
    let mut loopback = headers.clone();
    loopback.push(("origin", "http://localhost:3999".to_string()));
    let (status, _) = post(&url, &body, &loopback).await;
    assert_eq!(
        status, 200,
        "loopback is admitted even with an empty allowlist"
    );
    let (status, _) = post(&url, &body, &headers).await;
    assert_eq!(status, 200, "an agent sending no Origin is still served");
    h.abort();
}

/// A deployment with no `mcp:` block mounts NOTHING. Not a 405, not a 401 from an MCP-shaped
/// handler — the path is simply not this plane's, and falls through to whatever the residual LLM
/// plane makes of it. A gateway that is not an MCP server must not answer as one.
#[tokio::test]
async fn without_the_config_block_the_plane_does_not_exist() {
    crate::metrics::init();
    let app = TestApp::new().build();
    let core = crate::base_data_router(
        &app.plugin_routes,
        app.mcp.as_deref(),
        app.a2a.as_ref(),
        app.oauth_as.as_ref(),
    )
    .1;
    for r in core.routes() {
        assert!(
            !r.path.starts_with("/.well-known/oauth-protected-resource"),
            "an unconfigured deployment mounted {}",
            r.path
        );
    }
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let h = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let resp = reqwest::Client::new()
        .get(format!(
            "http://{addr}/.well-known/oauth-protected-resource/mcp"
        ))
        .send()
        .await
        .unwrap();
    assert_ne!(
        resp.status().as_u16(),
        200,
        "a deployment that is not an MCP server must not serve protected-resource metadata"
    );
    h.abort();
}
