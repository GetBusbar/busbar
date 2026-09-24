//! Tests for `assemble.rs`: the streaming-usage injection an OpenAI Chat egress needs so the ledger
//! records the tokens a streamed answer actually used (item 362). Driven end to end through the
//! pooled entry against a recording upstream, so what is asserted is the body the upstream
//! received (or that it received nothing).

use crate::engine::{forward_with_pool, WeightedLane};
use crate::test_support::{LaneSpec, MockResponse, MockServer, MockServerState, TestApp};
use serde_json::{json, Value};
use std::sync::Arc;

/// An OpenAI chat stream that answers and then carries the trailing usage chunk an opted-in
/// request is owed.
fn stream_with_usage_chunk() -> MockResponse {
    MockResponse::Sse {
        events: vec![
            r#"{"id":"chatcmpl-x","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","content":"Hi"},"finish_reason":null}]}"#
                .to_string(),
            r#"{"id":"chatcmpl-x","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}"#
                .to_string(),
            r#"{"id":"chatcmpl-x","object":"chat.completion.chunk","choices":[],"usage":{"prompt_tokens":7,"completion_tokens":17,"total_tokens":24}}"#
                .to_string(),
            "[DONE]".to_string(),
        ],
        abort_at_index: None,
    }
}

/// One same-protocol OpenAI streaming request carrying `stream_options` spelled as given, against
/// one recording OpenAI lane. Returns the client response and the upstream's recorded state.
async fn stream_with_stream_options(
    stream_options: Value,
) -> (axum::response::Response, Arc<MockServerState>, MockServer) {
    crate::testkit::install_test_seams();
    busbar_kernel::metrics::init();
    let state = Arc::new(MockServerState::new());
    state.push(stream_with_usage_chunk());
    let server = MockServer::new(state.clone()).await;
    let app = TestApp::new()
        .lane(
            LaneSpec::new(
                "gpt-4o",
                crate::proto_codec::PROTO_OPENAI,
                &server.base_url(),
            )
            .provider("openai"),
        )
        .pool("po", &[(0, 1)])
        .build();
    let body = serde_json::to_vec(&json!({
        "model": "po",
        "messages": [{"role": "user", "content": "hi"}],
        "stream": true,
        "stream_options": stream_options,
    }))
    .unwrap();
    let resp = forward_with_pool(
        &app,
        vec![WeightedLane {
            reasoning: None,
            idx: 0,
            weight: 1,
            attempt_timeout_ms: None,
        }],
        body.into(),
        None,
        "po",
        None,
        "openai",
        crate::test_support::CHAT,
        None,
    )
    .await;
    (resp, state, server)
}

/// `"stream_options": null` is the OpenAI spelling of "no options". Forwarded verbatim it leaves the
/// upstream silent on usage and the ledger records zero tokens for a real answer; it must be
/// upgraded exactly like an absent key — and the client, who did not opt in, still sees no usage.
#[tokio::test]
async fn a_null_stream_options_is_upgraded_so_the_upstream_reports_usage() {
    let (resp, state, server) = stream_with_stream_options(Value::Null).await;
    assert_eq!(resp.status().as_u16(), 200, "the stream is served");
    let client_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("client body");
    let egress = state
        .get_last_request_body()
        .expect("the upstream received the request");
    let ev: Value = serde_json::from_slice(&egress).expect("egress body is JSON");
    assert_eq!(
        ev.pointer("/stream_options/include_usage"),
        Some(&Value::Bool(true)),
        "a null stream_options must carry include_usage:true upstream, or the ledger reads 0: {ev}"
    );
    let client_text = String::from_utf8_lossy(&client_bytes);
    assert!(
        client_text.contains("Hi"),
        "the answer reaches the client: {client_text}"
    );
    assert!(
        !client_text.contains("completion_tokens"),
        "a client that did not opt in is not sent the usage chunk: {client_text}"
    );
    server.shutdown().await;
}

/// A `stream_options` that is present but can hold no `include_usage` flag (a string, number, bool
/// or array) cannot be metered without reshaping the caller's value. It is refused with a 400
/// before any send — never forwarded to an upstream that might serve it unmetered.
#[tokio::test]
async fn a_wrong_typed_stream_options_is_refused_before_any_send() {
    for wrong in [json!("x"), json!(1), json!(true), json!([])] {
        let (resp, state, server) = stream_with_stream_options(wrong.clone()).await;
        assert_eq!(
            resp.status().as_u16(),
            400,
            "stream_options = {wrong} must be refused, not forwarded"
        );
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("refusal body");
        let text = String::from_utf8_lossy(&body);
        assert!(
            text.contains(super::DETAIL_STREAM_OPTIONS_NOT_OBJECT),
            "the refusal names the field: {text}"
        );
        assert!(
            state.get_last_request_body().is_none(),
            "stream_options = {wrong}: nothing may reach the upstream"
        );
        server.shutdown().await;
    }
}

/// The injector unit contract on the refused shape: `Err` carrying the caller's bytes verbatim, from
/// both entry points (the pristine injector defers to the DOM injector on a `stream_options` key).
#[test]
fn the_injectors_answer_err_on_a_wrong_typed_stream_options() {
    let body: &[u8] = br#"{"stream":true,"stream_options":"x"}"#;
    let dom = super::try_inject_openai_stream_include_usage(bytes::Bytes::from_static(body));
    assert_eq!(dom, Err(bytes::Bytes::from_static(body)));
    let pristine =
        super::try_inject_openai_stream_include_usage_pristine(bytes::Bytes::from_static(body));
    assert_eq!(pristine, Err(bytes::Bytes::from_static(body)));
}
