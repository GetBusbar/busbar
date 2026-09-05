//! A `POST /v1/responses` request with `"stream": true` is answered as a Responses SSE stream
//! (`content-type: text/event-stream`, opening `response.created`, terminal `response.completed`)
//! for EVERY egress dialect — whether the upstream streamed its answer or handed back one buffered
//! JSON body — and the stream is metered exactly like every other stream (11 input / 7 output
//! tokens land on the key's ledger once).
//!
//! Each egress dialect gets two cases: the upstream streams natively (the live translate path), and
//! the upstream ignores `stream` and answers a single JSON body (the buffered-response synthesis
//! path; this is what the oracle's mock upstream does for `/v1/responses`).
use super::{forward_with_pool, UsageSink};
use crate::test_support::{LaneSpec, TestApp};
use busbar_substrate::testkit::engine_kit::{EngineTestKit as _, TestAppKit};
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const MARKER: &str = "hi";
const IN_TOK: u64 = 11;
const OUT_TOK: u64 = 7;

/// A one-shot canned upstream: every connection gets the same `status`/`content_type`/`body`,
/// bytes verbatim. The shared mock server frames SSE as bare `data:` lines, which cannot carry the
/// `event:`-typed frames the Anthropic and Responses readers key on, so the fixtures here are
/// served raw. Reads the whole request (headers + declared body) before answering, so the egress
/// client never sees its write cut short.
async fn canned_upstream(content_type: &'static str, body: Vec<u8>) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind canned upstream");
    let addr = listener.local_addr().expect("canned upstream addr");
    let body = Arc::new(body);
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let body = body.clone();
            tokio::spawn(async move {
                let mut req: Vec<u8> = Vec::new();
                let mut buf = [0u8; 4096];
                let mut header_end: Option<usize> = None;
                let mut content_length = 0usize;
                loop {
                    let Ok(n) = sock.read(&mut buf).await else {
                        return;
                    };
                    if n == 0 {
                        break;
                    }
                    req.extend_from_slice(&buf[..n]);
                    if header_end.is_none() {
                        if let Some(pos) = req.windows(4).position(|w| w == b"\r\n\r\n") {
                            header_end = Some(pos + 4);
                            let head = String::from_utf8_lossy(&req[..pos]).to_ascii_lowercase();
                            content_length = head
                                .lines()
                                .find_map(|l| l.strip_prefix("content-length:"))
                                .and_then(|v| v.trim().parse().ok())
                                .unwrap_or(0);
                        }
                    }
                    if let Some(end) = header_end {
                        if req.len() >= end + content_length {
                            break;
                        }
                    }
                }
                let head = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    body.len()
                );
                let _ = sock.write_all(head.as_bytes()).await;
                let _ = sock.write_all(&body).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    format!("http://{addr}")
}

fn sse(frames: &[(&str, Value)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (event, data) in frames {
        busbar_substrate::proto::write_sse_frame(&mut out, event, data);
    }
    out
}

/// What the upstream answers a `stream: true` request with.
enum Upstream {
    /// A native stream in the egress dialect (SSE, or Bedrock's binary eventstream).
    Stream,
    /// One buffered JSON body — the upstream ignored `stream`.
    Buffered,
}

/// The egress dialect's answer for a one-text-block completion of `MARKER` with `IN_TOK`/`OUT_TOK`.
fn upstream_answer(egress: &str, shape: &Upstream) -> (&'static str, Vec<u8>) {
    let usage_oa = json!({"prompt_tokens": IN_TOK, "completion_tokens": OUT_TOK, "total_tokens": IN_TOK + OUT_TOK});
    match (egress, shape) {
        ("anthropic", Upstream::Stream) => (
            "text/event-stream",
            sse(&[
                ("message_start", json!({"type": "message_start", "message": {"id": "msg_up", "type": "message",
                    "role": "assistant", "model": "m0", "content": [], "stop_reason": null,
                    "usage": {"input_tokens": IN_TOK, "output_tokens": 0}}})),
                ("content_block_start", json!({"type": "content_block_start", "index": 0,
                    "content_block": {"type": "text", "text": ""}})),
                ("content_block_delta", json!({"type": "content_block_delta", "index": 0,
                    "delta": {"type": "text_delta", "text": MARKER}})),
                ("content_block_stop", json!({"type": "content_block_stop", "index": 0})),
                ("message_delta", json!({"type": "message_delta",
                    "delta": {"stop_reason": "end_turn", "stop_sequence": null},
                    "usage": {"output_tokens": OUT_TOK}})),
                ("message_stop", json!({"type": "message_stop"})),
            ]),
        ),
        ("anthropic", Upstream::Buffered) => (
            "application/json",
            json!({"id": "msg_up", "type": "message", "role": "assistant", "model": "m0",
                "content": [{"type": "text", "text": MARKER}], "stop_reason": "end_turn", "stop_sequence": null,
                "usage": {"input_tokens": IN_TOK, "output_tokens": OUT_TOK}})
            .to_string()
            .into_bytes(),
        ),
        ("openai", Upstream::Stream) => {
            let base = json!({"id": "chatcmpl-up", "object": "chat.completion.chunk", "created": 0, "model": "m0"});
            let mut first = base.clone();
            first["choices"] = json!([{"index": 0, "delta": {"role": "assistant", "content": MARKER}, "finish_reason": null}]);
            let mut last = base;
            last["choices"] = json!([{"index": 0, "delta": {}, "finish_reason": "stop"}]);
            last["usage"] = usage_oa;
            let mut body = sse(&[("", first), ("", last)]);
            body.extend_from_slice(busbar_substrate::proto::SSE_DONE_FRAME);
            ("text/event-stream", body)
        }
        ("openai", Upstream::Buffered) => (
            "application/json",
            json!({"id": "chatcmpl-up", "object": "chat.completion", "created": 0, "model": "m0",
                "choices": [{"index": 0, "message": {"role": "assistant", "content": MARKER}, "finish_reason": "stop"}],
                "usage": usage_oa})
            .to_string()
            .into_bytes(),
        ),
        ("cohere", Upstream::Stream) => {
            let mut body = sse(&[
                ("", json!({"type": "message-start", "id": "cohere-up",
                    "delta": {"message": {"role": "assistant", "content": []}}})),
                ("", json!({"type": "content-delta", "index": 0,
                    "delta": {"message": {"content": {"type": "text", "text": MARKER}}}})),
                ("", json!({"type": "message-end", "delta": {"finish_reason": "COMPLETE",
                    "usage": {"tokens": {"input_tokens": IN_TOK, "output_tokens": OUT_TOK}}}})),
            ]);
            body.extend_from_slice(busbar_substrate::proto::SSE_DONE_FRAME);
            ("text/event-stream", body)
        }
        ("cohere", Upstream::Buffered) => (
            "application/json",
            json!({"id": "cohere-up", "finish_reason": "COMPLETE",
                "message": {"role": "assistant", "content": [{"type": "text", "text": MARKER}]},
                "usage": {"billed_units": {"input_tokens": IN_TOK, "output_tokens": OUT_TOK},
                          "tokens": {"input_tokens": IN_TOK, "output_tokens": OUT_TOK}}})
            .to_string()
            .into_bytes(),
        ),
        ("gemini", shape) => {
            let body = json!({"candidates": [{"content": {"role": "model", "parts": [{"text": MARKER}]},
                "finishReason": "STOP", "index": 0}],
                "usageMetadata": {"promptTokenCount": IN_TOK, "candidatesTokenCount": OUT_TOK,
                                  "totalTokenCount": IN_TOK + OUT_TOK},
                "modelVersion": "m0"});
            match shape {
                Upstream::Stream => ("text/event-stream", sse(&[("", body)])),
                Upstream::Buffered => ("application/json", body.to_string().into_bytes()),
            }
        }
        ("bedrock", Upstream::Stream) => {
            let frames: [(&str, Value); 5] = [
                ("messageStart", json!({"role": "assistant"})),
                ("contentBlockDelta", json!({"delta": {"text": MARKER}, "contentBlockIndex": 0})),
                ("contentBlockStop", json!({"contentBlockIndex": 0})),
                ("messageStop", json!({"stopReason": "end_turn"})),
                ("metadata", json!({"usage": {"inputTokens": IN_TOK, "outputTokens": OUT_TOK,
                    "totalTokens": IN_TOK + OUT_TOK}, "metrics": {"latencyMs": 12}})),
            ];
            let mut body = Vec::new();
            for (event, payload) in frames {
                body.extend(busbar_substrate::eventstream::encode_frame(
                    event,
                    &busbar_substrate::json::to_vec(&payload).expect("frame json"),
                ));
            }
            ("application/vnd.amazon.eventstream", body)
        }
        ("bedrock", Upstream::Buffered) => (
            "application/json",
            json!({"output": {"message": {"role": "assistant", "content": [{"text": MARKER}]}},
                "stopReason": "end_turn",
                "usage": {"inputTokens": IN_TOK, "outputTokens": OUT_TOK, "totalTokens": IN_TOK + OUT_TOK},
                "metrics": {"latencyMs": 12}})
            .to_string()
            .into_bytes(),
        ),
        ("responses", Upstream::Stream) => {
            let item_done = json!({"type": "message", "id": "msg_up", "role": "assistant", "status": "completed",
                "content": [{"type": "output_text", "text": MARKER, "annotations": []}]});
            let usage = json!({"input_tokens": IN_TOK, "input_tokens_details": {"cached_tokens": 0},
                "output_tokens": OUT_TOK, "output_tokens_details": {"reasoning_tokens": 0},
                "total_tokens": IN_TOK + OUT_TOK});
            (
                "text/event-stream",
                sse(&[
                    ("response.created", json!({"type": "response.created", "sequence_number": 0,
                        "response": {"id": "resp_up", "object": "response", "created_at": 0, "model": "m0",
                            "status": "in_progress", "error": null, "output": [], "usage": null}})),
                    ("response.output_item.added", json!({"type": "response.output_item.added", "sequence_number": 1,
                        "output_index": 0, "item": {"type": "message", "id": "msg_up", "role": "assistant",
                            "status": "in_progress", "content": []}})),
                    ("response.output_text.delta", json!({"type": "response.output_text.delta", "sequence_number": 2,
                        "output_index": 0, "content_index": 0, "item_id": "msg_up", "delta": MARKER})),
                    ("response.output_item.done", json!({"type": "response.output_item.done", "sequence_number": 3,
                        "output_index": 0, "item": item_done})),
                    ("response.completed", json!({"type": "response.completed", "sequence_number": 4,
                        "response": {"id": "resp_up", "object": "response", "created_at": 0, "model": "m0",
                            "status": "completed", "error": null, "output": [item_done], "usage": usage}})),
                ]),
            )
        }
        ("responses", Upstream::Buffered) => (
            "application/json",
            json!({"id": "resp_up", "object": "response", "status": "completed", "model": "m0",
                "output": [{"type": "message", "id": "msg_up", "role": "assistant", "status": "completed",
                    "content": [{"type": "output_text", "text": MARKER, "annotations": []}]}],
                "usage": {"input_tokens": IN_TOK, "output_tokens": OUT_TOK, "total_tokens": IN_TOK + OUT_TOK}})
            .to_string()
            .into_bytes(),
        ),
        (other, _) => panic!("no upstream fixture for egress dialect {other}"),
    }
}

fn proto_const(egress: &str) -> &'static str {
    match egress {
        "anthropic" => crate::proto_codec::PROTO_ANTHROPIC,
        "openai" => crate::proto_codec::PROTO_OPENAI,
        "cohere" => crate::proto_codec::PROTO_COHERE,
        "gemini" => crate::proto_codec::PROTO_GEMINI,
        "bedrock" => crate::proto_codec::PROTO_BEDROCK,
        "responses" => crate::proto_codec::PROTO_RESPONSES,
        other => panic!("unknown egress dialect {other}"),
    }
}

/// Parse an SSE body into `(event, data)` frames.
fn parse_frames(body: &str) -> Vec<(String, String)> {
    body.split("\n\n")
        .filter(|f| !f.trim().is_empty())
        .map(|frame| {
            let mut event = String::new();
            let mut data: Vec<&str> = Vec::new();
            for line in frame.lines() {
                if let Some(e) = line.strip_prefix("event:") {
                    event = e.trim().to_string();
                } else if let Some(d) = line.strip_prefix("data:") {
                    data.push(d.strip_prefix(' ').unwrap_or(d));
                }
            }
            (event, data.join("\n"))
        })
        .collect()
}

/// Drive one `stream: true` Responses request at a lane speaking `egress`, whose upstream answers
/// with `shape`; assert the SSE contract and the metering.
async fn run_case(egress: &str, shape: Upstream) {
    crate::testkit::install_test_seams();
    busbar_core::metrics::init();
    let label = format!(
        "responses ingress -> {egress} egress ({})",
        match shape {
            Upstream::Stream => "upstream streamed",
            Upstream::Buffered => "upstream answered one JSON body",
        }
    );
    let (content_type, body) = upstream_answer(egress, &shape);
    let base_url = canned_upstream(content_type, body).await;

    // A governed key on a fresh in-memory registry, so the ledger starts empty for this case.
    let store: Arc<dyn busbar_api::Store> = Arc::new(busbar_store_memory::MemoryStore::new());
    let gov_kit = crate::test_support::engine_kit::CORE_ENGINE_KIT
        .governance(store, None, None)
        .expect("governance");
    let (key, _secret) = gov_kit
        .create_key(
            busbar_substrate::governance::NewKeySpec {
                name: "k".to_string(),
                allowed_pools: None,
                group: None,
                labels: Default::default(),
                ..Default::default()
            },
            1_700_000_000,
        )
        .expect("create key");
    let mut lane = LaneSpec::new("m0", proto_const(egress), &base_url);
    if egress == "bedrock" {
        lane = lane.provider("aws");
    }
    let mut builder = TestApp::new().lane(lane).pool("p", &[(0, 1)]);
    TestAppKit::set_governance(&mut builder, gov_kit.clone());
    let app = builder.build();
    let (host, _rt) = crate::engine::test_host_rt(&app);

    let charged_at = busbar_substrate::store::now();
    let sink = UsageSink {
        gov: host.governance().expect("governance is configured"),
        cost: host.cost(),
        key: Arc::new(key.clone()),
        pool: Arc::from("p"),
        charged_at,
        admit: None,
    };
    let request = json!({"model": "p", "stream": true, "input": MARKER});
    let resp = forward_with_pool(
        &app,
        vec![crate::engine::WeightedLane {
            reasoning: None,
            idx: 0,
            weight: 1,
            attempt_timeout_ms: None,
        }],
        serde_json::to_vec(&request).unwrap().into(),
        None,
        "p",
        None,
        crate::proto_codec::PROTO_RESPONSES,
        crate::test_support::CHAT,
        Some(sink),
    )
    .await;

    assert_eq!(
        resp.status().as_u16(),
        200,
        "[{label}] the stream is served"
    );
    let ct = resp
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(
        ct.starts_with("text/event-stream"),
        "[{label}] a stream: true Responses request is answered as SSE, got content-type {ct:?}"
    );
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("drain the stream");
    let text = String::from_utf8(bytes.to_vec()).expect("SSE is UTF-8");
    let frames = parse_frames(&text);
    assert!(!frames.is_empty(), "[{label}] the stream carries events");
    assert_eq!(
        frames[0].0, "response.created",
        "[{label}] the stream opens with response.created: {text}"
    );
    assert!(
        !text.contains("[DONE]"),
        "[{label}] a Responses stream has no [DONE] sentinel: {text}"
    );
    let (last_event, last_data) = frames.last().expect("terminal frame");
    assert_eq!(
        last_event, "response.completed",
        "[{label}] the stream ends with response.completed: {text}"
    );
    let completed: Value = serde_json::from_str(last_data)
        .unwrap_or_else(|e| panic!("[{label}] response.completed data is JSON ({e}): {last_data}"));
    assert_eq!(
        completed["type"], "response.completed",
        "[{label}] {last_data}"
    );
    assert!(
        completed["sequence_number"].is_u64(),
        "[{label}] response.completed carries a sequence_number: {last_data}"
    );
    let response = &completed["response"];
    assert_eq!(response["object"], "response", "[{label}] {last_data}");
    assert_eq!(response["status"], "completed", "[{label}] {last_data}");
    assert!(
        response["id"]
            .as_str()
            .is_some_and(|id| id.starts_with("resp_")),
        "[{label}] response.completed names a resp_ id: {last_data}"
    );
    assert_eq!(
        response["output"][0]["content"][0]["text"], MARKER,
        "[{label}] the completed output carries the upstream text: {last_data}"
    );
    assert_eq!(
        response["usage"]["input_tokens"], IN_TOK,
        "[{label}] {last_data}"
    );
    assert_eq!(
        response["usage"]["output_tokens"], OUT_TOK,
        "[{label}] {last_data}"
    );
    assert_eq!(
        response["usage"]["total_tokens"],
        IN_TOK + OUT_TOK,
        "[{label}] {last_data}"
    );
    // Every frame's payload is JSON with a `type` matching its event line.
    for (event, data) in &frames {
        let v: Value = serde_json::from_str(data)
            .unwrap_or_else(|e| panic!("[{label}] frame {event} data is JSON ({e}): {data}"));
        assert_eq!(
            v["type"],
            event.as_str(),
            "[{label}] event line matches payload type"
        );
    }

    // Metering: the stream's usage lands on the key's ledger exactly once, 11 in / 7 out.
    let gov = app.governance.clone().expect("governance is configured");
    let usage = gov
        .usage_for(&app.cost, &key.id, charged_at)
        .expect("usage read")
        .expect("the key exists");
    assert_eq!(
        usage.tokens,
        IN_TOK + OUT_TOK,
        "[{label}] the stream's tokens are ledgered once"
    );
    gov_kit.flush_metering();
    let rows = gov_kit
        .metering_for(busbar_substrate::governance::metering_bucket(charged_at))
        .expect("metering read");
    let mine: Vec<_> = rows.iter().filter(|r| r.key_id == key.id).collect();
    assert_eq!(
        mine.len(),
        1,
        "[{label}] one metering row for the key: {rows:?}"
    );
    assert_eq!(mine[0].requests, 1, "[{label}] the request is counted once");
    assert_eq!(
        (mine[0].tokens_input, mine[0].tokens_output),
        (IN_TOK, OUT_TOK),
        "[{label}] input/output tokens metered"
    );
}

#[tokio::test]
async fn responses_stream_over_anthropic_stream() {
    run_case("anthropic", Upstream::Stream).await;
}

#[tokio::test]
async fn responses_stream_over_anthropic_buffered() {
    run_case("anthropic", Upstream::Buffered).await;
}

#[tokio::test]
async fn responses_stream_over_openai_stream() {
    run_case("openai", Upstream::Stream).await;
}

#[tokio::test]
async fn responses_stream_over_openai_buffered() {
    run_case("openai", Upstream::Buffered).await;
}

#[tokio::test]
async fn responses_stream_over_cohere_stream() {
    run_case("cohere", Upstream::Stream).await;
}

#[tokio::test]
async fn responses_stream_over_cohere_buffered() {
    run_case("cohere", Upstream::Buffered).await;
}

#[tokio::test]
async fn responses_stream_over_gemini_stream() {
    run_case("gemini", Upstream::Stream).await;
}

#[tokio::test]
async fn responses_stream_over_gemini_buffered() {
    run_case("gemini", Upstream::Buffered).await;
}

#[tokio::test]
async fn responses_stream_over_bedrock_stream() {
    run_case("bedrock", Upstream::Stream).await;
}

#[tokio::test]
async fn responses_stream_over_bedrock_buffered() {
    run_case("bedrock", Upstream::Buffered).await;
}

#[tokio::test]
async fn responses_stream_over_responses_stream() {
    run_case("responses", Upstream::Stream).await;
}

/// Same-protocol: a Responses upstream that ignores `stream` and answers one JSON body. A
/// wants-stream same-protocol buffered 2xx now routes through the same buffered translate path
/// (`engine/attempt/respond.rs`) that cross-protocol buffered responses use, so the client still
/// gets its dialect's SSE stream instead of a relayed `application/json` body.
#[tokio::test]
async fn responses_stream_over_responses_buffered() {
    run_case("responses", Upstream::Buffered).await;
}
