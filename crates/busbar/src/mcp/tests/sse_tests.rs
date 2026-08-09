// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE POST's SSE RESPONSE STREAM, and the `notifications/message` records that ride it.
//!
//! Driven over a REAL socket rather than by calling [`super::as_event_stream`], and the reason is
//! specific to what is under test: what is claimed is that a CLIENT gets a stream, and a client
//! reads an HTTP response, not a `Response` value. The `Accept` negotiation in particular is only
//! meaningful against a real header map — a unit test could assert the preference function agrees
//! with itself while the handler never called it.

use crate::mcp::ingress::PROTOCOL_VERSION;
use crate::mcp::McpCfg;
use crate::test_support::TestApp;

const CANONICAL: &str = "https://gateway.example.com/mcp";

/// Spelled as a LITERAL rather than imported from [`crate::mcp::sse::META_LOGGING_LEVEL`], because
/// this is the string a CLIENT types. A test that imported the constant would assert that the server
/// agrees with itself about a key's name and would keep passing through a rename that broke every
/// client — the wire spelling is exactly the thing that must not be refactorable.
const META_LOGGING_LEVEL: &str = "io.busbar/loggingLevel";

/// An MCP-enabled app with an OPEN auth chain, and one registered server whose prompts and
/// resources are the operator's own. Open on purpose, for the reason `ingress_tests::serve` states:
/// these tests are about the RESPONSE FRAMING, and every one of them must reach the handler to say
/// anything at all.
async fn serve() -> (String, tokio::task::JoinHandle<()>) {
    crate::metrics::init();
    let app = TestApp::new()
        .mcp(&McpCfg {
            canonical_uri: CANONICAL.to_string(),
            authorization_servers: vec!["https://login.example.com".to_string()],
            scopes_supported: Vec::new(),
            allowed_origins: Vec::new(),
        })
        .build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (format!("http://{addr}/mcp"), handle)
}

/// One well-formed request, with an optional extra `_meta` member so a test that wants to name a
/// logging level introduces exactly that and nothing else.
fn body(method: &str, extra_meta: Option<(&str, serde_json::Value)>) -> serde_json::Value {
    let mut meta = serde_json::Map::new();
    meta.insert(
        "io.modelcontextprotocol/protocolVersion".into(),
        PROTOCOL_VERSION.into(),
    );
    meta.insert(
        "io.modelcontextprotocol/clientCapabilities".into(),
        serde_json::json!({}),
    );
    if let Some((k, v)) = extra_meta {
        meta.insert(k.to_string(), v);
    }
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": { "_meta": serde_json::Value::Object(meta) },
    })
}

/// POST, returning `(status, content-type, body-text)`. The body is returned as TEXT, never parsed:
/// half of what is under test is whether the bytes are SSE frames or a JSON document, and a helper
/// that parsed JSON would erase the distinction it exists to observe.
async fn post(url: &str, accept: &str, body: &serde_json::Value) -> (u16, String, String) {
    let method = body["method"].as_str().unwrap().to_string();
    let resp = reqwest::Client::new()
        .post(url)
        .header("accept", accept)
        .header("mcp-protocol-version", PROTOCOL_VERSION)
        .header("mcp-method", method)
        .json(body)
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    (status, ct, resp.text().await.unwrap())
}

/// Every `data:` payload on an SSE response, parsed. The framing is asserted separately; this is for
/// the tests that care about WHAT was streamed rather than HOW.
fn events(text: &str) -> Vec<serde_json::Value> {
    text.lines()
        .filter_map(|l| l.strip_prefix("data: "))
        .map(|d| serde_json::from_str::<serde_json::Value>(d).expect("every SSE data line is JSON"))
        .collect()
}

// ── B5: the SSE response stream on the POST ────────────────────────────────────────────────────

/// A client that lists `text/event-stream` FIRST gets a stream.
///
/// This is the whole of B5 in one assertion: revision `2026-07-28` removed the GET stream, and SSE
/// survived as a POST response content type. Before this landed, busbar answered `application/json`
/// to every `Accept` there is, so a client that asked for a stream was told, in effect, that this
/// server did not have one.
#[tokio::test]
async fn a_client_that_prefers_event_stream_gets_an_sse_response() {
    let (url, _h) = serve().await;
    let (status, ct, text) = post(
        &url,
        "text/event-stream, application/json",
        &body("tools/list", None),
    )
    .await;
    assert_eq!(status, 200);
    assert!(
        ct.starts_with("text/event-stream"),
        "a client that preferred a stream got `{ct}`"
    );
    assert!(
        text.contains("event: message\ndata: "),
        "the response is not SSE-framed: {text:?}"
    );
    let evs = events(&text);
    let results: Vec<&serde_json::Value> =
        evs.iter().filter(|e| e.get("result").is_some()).collect();
    assert_eq!(
        results.len(),
        1,
        "exactly one JSON-RPC result rides the stream: {evs:?}"
    );
    assert!(results[0].pointer("/result/tools").is_some());
}

/// The DEFAULT is unchanged, and that is the half of B5 that protects every existing client.
///
/// Every MCP client sends BOTH media types, because both are legal answers. A server that read
/// `text/event-stream` as a membership test rather than a preference would have switched every
/// client on earth to a stream. This asserts the ordinary `Accept` still gets the ordinary answer.
#[tokio::test]
async fn the_ordinary_accept_still_gets_one_json_document() {
    let (url, _h) = serve().await;
    let (status, ct, text) = post(
        &url,
        "application/json, text/event-stream",
        &body("tools/list", None),
    )
    .await;
    assert_eq!(status, 200);
    assert!(
        ct.starts_with("application/json"),
        "a client that preferred JSON got `{ct}`"
    );
    assert!(!text.contains("event: message"), "{text:?}");
    assert!(serde_json::from_str::<serde_json::Value>(&text)
        .unwrap()
        .pointer("/result/tools")
        .is_some());
}

/// An explicit `q` beats the written order, because that is what `q` is for.
#[tokio::test]
async fn a_q_value_decides_the_preference_before_the_written_order() {
    let (url, _h) = serve().await;
    let (_, ct, _) = post(
        &url,
        "application/json;q=0.1, text/event-stream;q=0.9",
        &body("tools/list", None),
    )
    .await;
    assert!(ct.starts_with("text/event-stream"), "{ct}");

    let (_, ct, _) = post(
        &url,
        "text/event-stream;q=0.1, application/json;q=0.9",
        &body("tools/list", None),
    )
    .await;
    assert!(ct.starts_with("application/json"), "{ct}");
}

/// A REFUSAL stays one JSON document, whatever the client asked for.
///
/// An error response is terminal: nothing follows it, so a stream framing would be a stream that is
/// over before it starts. The status/code pair is the whole content of the answer and it must reach
/// a client that reads statuses, not one that reads frames.
#[tokio::test]
async fn an_error_is_never_framed_as_a_stream() {
    let (url, _h) = serve().await;
    let (status, ct, text) = post(
        &url,
        "text/event-stream, application/json",
        &body("logging/setLevel", None),
    )
    .await;
    assert_eq!(status, 404, "an unimplemented method is still 404");
    assert!(!ct.starts_with("text/event-stream"), "{ct}");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&text).unwrap()["error"]["code"],
        -32601
    );
}

/// NO `id:` AND NO `retry:` ON ANY EVENT.
///
/// Both are resumption machinery, and this revision deleted resumption: there is no GET stream to
/// resume on and busbar answers `405` to the verb that would carry one. An `id:` here would be an
/// offer to resume that this server cannot honour, which is worse than silence because a client
/// would build on it. Asserted rather than commented, because "we chose not to" and "we forgot" look
/// identical in a diff.
#[tokio::test]
async fn the_stream_offers_no_resumption_it_cannot_honour() {
    let (url, _h) = serve().await;
    let (_, _, text) = post(&url, "text/event-stream", &body("resources/list", None)).await;
    for line in text.lines() {
        assert!(
            !line.starts_with("id:") && !line.starts_with("retry:"),
            "the stream advertised resumability this revision removed: {line:?}"
        );
    }
}

// ── B7: `notifications/message` ────────────────────────────────────────────────────────────────

/// A stream carries busbar's own log records, and they arrive BEFORE the result.
///
/// The ordering is the point, not decoration: a record describing the work has to reach the client
/// before the answer that work produced, or the client has finished the request by the time it is
/// told what happened during it.
#[tokio::test]
async fn the_stream_carries_notifications_message_ahead_of_the_result() {
    let (url, _h) = serve().await;
    let (_, _, text) = post(
        &url,
        "text/event-stream, application/json",
        &body("tools/list", None),
    )
    .await;
    let evs = events(&text);
    let logs: Vec<&serde_json::Value> = evs
        .iter()
        .filter(|e| e.get("method") == Some(&serde_json::json!("notifications/message")))
        .collect();
    assert!(
        !logs.is_empty(),
        "no notifications/message rode the stream: {evs:?}"
    );
    let last = evs.last().expect("the stream is not empty");
    assert!(
        last.get("result").is_some(),
        "the result must be the LAST event, not {last:?}"
    );
    // A NOTIFICATION HAS NO ID. `BASE.NOTIF.NO-ID` is a MUST NOT, and a notification carrying one is
    // a request the client would be obliged to answer.
    for log in &logs {
        assert!(
            log.get("id").is_none(),
            "a notification carried an id: {log}"
        );
        assert_eq!(log["params"]["logger"], "busbar.mcp.dispatch");
    }
}

/// THE LEVEL FILTER BITES, and it is observable from the outside.
///
/// `info` is the default and hides the `debug` record; asking for `debug` reveals it. Two requests
/// differing in one `_meta` member, so nothing else can be responsible for the difference.
#[tokio::test]
async fn the_requested_logging_level_filters_the_records() {
    let (url, _h) = serve().await;

    let (_, _, default_text) = post(&url, "text/event-stream", &body("tools/list", None)).await;
    let (_, _, debug_text) = post(
        &url,
        "text/event-stream",
        &body(
            "tools/list",
            Some((META_LOGGING_LEVEL, serde_json::json!("debug"))),
        ),
    )
    .await;

    let levels = |t: &str| -> Vec<String> {
        events(t)
            .iter()
            .filter_map(|e| e.pointer("/params/level").and_then(|v| v.as_str()))
            .map(str::to_string)
            .collect()
    };
    let at_default = levels(&default_text);
    let at_debug = levels(&debug_text);
    assert!(
        !at_default.iter().any(|l| l == "debug"),
        "the default level leaked a debug record: {at_default:?}"
    );
    assert!(
        at_debug.iter().any(|l| l == "debug"),
        "asking for debug produced no debug record: {at_debug:?}"
    );
    assert!(
        at_debug.len() > at_default.len(),
        "the filter changed nothing: default={at_default:?} debug={at_debug:?}"
    );
}

/// A client that did not ask for a stream gets no log records at all, and that is not a limitation.
///
/// `notifications/message` is a NOTIFICATION: it has no place in a single JSON-RPC response
/// document, which carries exactly one result. There is nowhere to put it, so it is not sent —
/// rather than being smuggled into the result object, which would put a second message inside the
/// first.
#[tokio::test]
async fn a_json_response_carries_no_notifications_because_it_cannot() {
    let (url, _h) = serve().await;
    let (_, _, text) = post(
        &url,
        "application/json, text/event-stream",
        &body("tools/list", None),
    )
    .await;
    assert!(!text.contains("notifications/message"), "{text}");
}
