//! A GENERATION THE UPSTREAM REPORTS AS FAILED SURFACES AS AN ERROR AND CHARGES WHAT IT USED.
//!
//! OWNER RULING Q31 (docs/design/1.6.0-QUESTIONS.md, Q32): a 2xx whose own stop reason says the
//! generation FAILED — a Cohere `finish_reason: "ERROR"`, a Gemini `MALFORMED_FUNCTION_CALL` — is
//! not a success. The client gets an error (never a success terminator in its own dialect), the
//! serving lane's breaker records a fault, and the usage the upstream reported is still charged:
//! the #62 rule (a failed stream bills what it streamed) applied to both delivery arms.
//!
//! Driven end to end through [`crate::engine::forward_with_pool`] against a scripted upstream, so
//! each assertion reads the real seam: the response the client receives, the pool cell's breaker,
//! the tap the Route step reads, and the governance token ledger.
use crate::engine::{forward_with_pool, TapCell, TapFinish, UsageSink, WeightedLane};
use crate::test_support::engine_kit::{EngineTestKit as _, TestAppKit};
use crate::test_support::{LaneSpec, MockResponse, MockServer, MockServerState, TestApp};
use std::sync::Arc;

/// What one request left behind.
struct Outcome {
    status: u16,
    body: String,
    finish: Option<TapFinish>,
    reported: Option<(u64, u64)>,
    ledger_tokens: u64,
    breaker_faulted: bool,
}

/// Drive one openai-ingress chat request through a single-member pool whose lane speaks `egress`,
/// the upstream answering `reply`, on a governed key; drain the body and read every seam back.
async fn drive(egress: &'static str, reply: MockResponse, stream: bool) -> Outcome {
    drive_from(crate::proto_codec::PROTO_OPENAI, egress, reply, stream).await
}

/// [`drive`] from an `ingress` dialect of the caller's choosing — `ingress == egress` is the
/// same-protocol relay.
async fn drive_from(
    ingress: &'static str,
    egress: &'static str,
    reply: MockResponse,
    stream: bool,
) -> Outcome {
    crate::testkit::install_test_seams();
    let state = Arc::new(MockServerState::new());
    state.push(reply);
    let server = MockServer::new(state).await;
    let store: Arc<dyn busbar_api::Store> = Arc::new(busbar_store_memory::MemoryStore::new());
    let gov_kit = crate::test_support::engine_kit::CORE_ENGINE_KIT
        .governance(store, None, None)
        .expect("governance");
    let (key, _secret) = gov_kit
        // A default spec: an unnamed key with no group, which is all the ledger read needs.
        .create_key(Default::default(), 1_700_000_000)
        .expect("create key");
    let mut builder = TestApp::new()
        .lane(LaneSpec::new("m0", egress, &server.base_url()))
        .pool("p", &[(0, 1)]);
    TestAppKit::set_governance(&mut builder, gov_kit.clone());
    let app = builder.build();
    let (host, _rt) = crate::engine::test_host_rt(&app);
    let charged_at = crate::engine::now();
    let sink = UsageSink {
        pin: host.meter_pin().expect("governance is configured"),
        key: Arc::new(key.clone()),
        pool: Arc::from("p"),
        charged_at,
        admit: None,
    };
    let body = serde_json::json!({"model": "p", "stream": stream,
        "messages": [{"role": "user", "content": "hi"}]});
    let resp = forward_with_pool(
        &app,
        vec![WeightedLane {
            reasoning: None,
            idx: 0,
            weight: 1,
            attempt_timeout_ms: None,
        }],
        serde_json::to_vec(&body).unwrap().into(),
        None,
        "p",
        None,
        ingress,
        crate::test_support::CHAT,
        Some(sink),
    )
    .await;
    let status = resp.status().as_u16();
    let tap = resp.extensions().get::<TapCell>().cloned();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("drain");
    let report = tap.as_ref().and_then(|t| t.get());
    let gov = app.governance.clone().expect("governance is configured");
    let ledger_tokens = gov
        .usage_for(&app.cost, &key.id, charged_at)
        .expect("usage read")
        .map(|u| u.tokens)
        .unwrap_or(0);
    // A fault on the pool cell either opens it or benches it for a soft cooldown; either way the
    // lane now needs a recovery probe, which a success never asks for.
    let breaker_faulted = app.store.lane_needs_probe(0, crate::engine::now());
    server.shutdown().await;
    Outcome {
        status,
        body: String::from_utf8_lossy(&bytes).into_owned(),
        finish: report.map(|r| r.finish),
        reported: report
            .and_then(|r| r.usage.as_ref())
            .map(|u| (u.input, u.output)),
        ledger_tokens,
        breaker_faulted,
    }
}

/// A Cohere v2 non-stream chat body with the given `finish_reason`, reporting 10 in / 5 out.
fn cohere_body(finish_reason: &str) -> MockResponse {
    MockResponse::Ok {
        status: axum::http::StatusCode::OK,
        body: serde_json::json!({
            "id": "c-1",
            "finish_reason": finish_reason,
            "message": {"role": "assistant", "content": [{"type": "text", "text": "x"}]},
            "usage": {"tokens": {"input_tokens": 10, "output_tokens": 5}}
        }),
    }
}

/// BUFFERED (item 302). A Cohere `finish_reason: "ERROR"` served to an OpenAI client is an error,
/// a breaker fault, and a 10/5 charge. At the pin it was an HTTP 200 `finish_reason: "stop"`,
/// recorded `Complete`, and the breaker counted a success.
#[tokio::test]
async fn buffered_cohere_error_is_an_error_a_breaker_fault_and_charges_10_5() {
    let out = drive(
        crate::proto_codec::PROTO_COHERE,
        cohere_body("ERROR"),
        false,
    )
    .await;
    assert!(
        out.status >= 500,
        "a failed generation must reach the client as an error, not a success; got {} {}",
        out.status,
        out.body
    );
    assert!(
        !out.body.contains("\"finish_reason\""),
        "no completion (and no success terminator) is relayed for a failed generation: {}",
        out.body
    );
    assert!(
        out.breaker_faulted,
        "the serving lane's breaker must record a fault for a failed generation"
    );
    assert_eq!(out.finish, Some(TapFinish::Error), "the end is an Error");
    assert_eq!(
        out.reported,
        Some((10, 5)),
        "the charge is what the upstream reported it used"
    );
    assert_eq!(
        out.ledger_tokens, 15,
        "the ledger holds the upstream-reported 10 in + 5 out"
    );
}

/// CONTROL for the buffered case: the same body with `COMPLETE` is a 200 success, no fault, 10/5.
#[tokio::test]
async fn buffered_cohere_complete_is_a_success_and_charges_10_5() {
    let out = drive(
        crate::proto_codec::PROTO_COHERE,
        cohere_body("COMPLETE"),
        false,
    )
    .await;
    assert_eq!(out.status, 200, "{}", out.body);
    assert!(!out.breaker_faulted, "a completed generation is no fault");
    assert_eq!(out.finish, Some(TapFinish::Complete));
    assert_eq!(out.reported, Some((10, 5)));
    assert_eq!(out.ledger_tokens, 15);
}

/// SAME-PROTOCOL NON-STREAM (owner ruling Q31 follow-up). A Cohere `finish_reason: "ERROR"` relayed
/// to a Cohere client is passed through BYTE FOR BYTE — the client reads its own dialect's failure
/// token — but the lane's breaker records the fault, the end is `Error`, and the 10/5 the upstream
/// reported is charged. At the pin the breaker counted a success and the end was `Complete`.
#[tokio::test]
async fn same_protocol_cohere_error_relays_verbatim_faults_the_breaker_and_charges_10_5() {
    let reply = cohere_body("ERROR");
    let MockResponse::Ok { body: upstream, .. } = &reply else {
        unreachable!()
    };
    let upstream = upstream.to_string();
    let out = drive_from(
        crate::proto_codec::PROTO_COHERE,
        crate::proto_codec::PROTO_COHERE,
        reply,
        false,
    )
    .await;
    assert_eq!(out.status, 200, "the relay is served on its headers");
    assert_eq!(
        out.body, upstream,
        "the upstream body reaches the client byte-for-byte unchanged"
    );
    assert!(
        out.breaker_faulted,
        "the serving lane's breaker must record a fault for a failed generation"
    );
    assert_eq!(out.finish, Some(TapFinish::Error), "the end is an Error");
    assert_eq!(
        out.reported,
        Some((10, 5)),
        "the charge is what the upstream reported"
    );
    assert_eq!(out.ledger_tokens, 15, "the ledger holds 10 in + 5 out");
}

/// CONTROL for the same-protocol relay: `COMPLETE` is a clean success, no fault, 10/5.
#[tokio::test]
async fn same_protocol_cohere_complete_is_a_success_and_charges_10_5() {
    let out = drive_from(
        crate::proto_codec::PROTO_COHERE,
        crate::proto_codec::PROTO_COHERE,
        cohere_body("COMPLETE"),
        false,
    )
    .await;
    assert_eq!(out.status, 200);
    assert!(!out.breaker_faulted, "a completed generation is no fault");
    assert_eq!(out.finish, Some(TapFinish::Complete));
    assert_eq!(out.reported, Some((10, 5)));
    assert_eq!(out.ledger_tokens, 15);
}

/// One Gemini SSE stream: a text chunk, then a terminal chunk with `finish_reason`, reporting
/// 10 prompt / 5 candidate tokens.
fn gemini_stream(finish_reason: &str) -> MockResponse {
    let first = serde_json::json!({"candidates": [{"index": 0,
        "content": {"role": "model", "parts": [{"text": "x"}]}}]});
    let last = serde_json::json!({"candidates": [{"index": 0,
        "content": {"role": "model", "parts": [{"text": ""}]},
        "finishReason": finish_reason}],
        "usageMetadata": {"promptTokenCount": 10, "candidatesTokenCount": 5,
            "totalTokenCount": 15}});
    MockResponse::Sse {
        events: vec![first.to_string(), last.to_string()],
        abort_at_index: None,
    }
}

/// STREAMED (item 303). A Gemini `MALFORMED_FUNCTION_CALL` stream served to an OpenAI client ends
/// in an error frame, records a breaker fault, and still charges the 10/5 it streamed (#62). At the
/// pin it ended as a normal `finish_reason: "stop"` with no error frame and no fault.
#[tokio::test]
async fn streamed_gemini_malformed_function_call_is_an_error_frame_a_breaker_fault_and_charges() {
    let out = drive(
        crate::proto_codec::PROTO_GEMINI,
        gemini_stream("MALFORMED_FUNCTION_CALL"),
        true,
    )
    .await;
    assert_eq!(out.status, 200, "a stream is served on its headers");
    assert!(
        out.body.contains("\"error\""),
        "the stream must end in an error frame; got {}",
        out.body
    );
    assert!(
        out.breaker_faulted,
        "the serving lane's breaker must record a fault for a failed generation"
    );
    assert_eq!(out.finish, Some(TapFinish::Error), "the end is an Error");
    assert_eq!(out.reported, Some((10, 5)), "what streamed is the charge");
    assert_eq!(
        out.ledger_tokens, 15,
        "the ledger holds the streamed 10 + 5"
    );
}

/// CONTROL for the streamed case: the same stream ending `STOP` is a clean success, no fault.
#[tokio::test]
async fn streamed_gemini_stop_is_a_success_and_charges() {
    let out = drive(
        crate::proto_codec::PROTO_GEMINI,
        gemini_stream("STOP"),
        true,
    )
    .await;
    assert_eq!(out.status, 200);
    assert!(
        !out.body.contains("\"error\""),
        "a clean stream carries no error frame: {}",
        out.body
    );
    assert!(!out.breaker_faulted, "a completed generation is no fault");
    assert_eq!(out.finish, Some(TapFinish::Complete));
    assert_eq!(out.reported, Some((10, 5)));
    assert_eq!(out.ledger_tokens, 15);
}

/// Relay `chunks` of one Cohere non-stream body through the SAME-PROTOCOL relay (`FirstByteBody`
/// with no translator) with NO usage sink — the ungoverned relay, which keeps no copy of the body —
/// and return (the bytes the client received, the tap's end, whether the pool cell faulted).
async fn relay_ungoverned(chunks: Vec<&'static [u8]>) -> (Vec<u8>, Option<TapFinish>, bool) {
    use http_body_util::BodyExt as _;
    crate::testkit::install_test_seams();
    let app = TestApp::new()
        .lane(LaneSpec::new(
            "m0",
            crate::proto_codec::PROTO_COHERE,
            "http://127.0.0.1:1",
        ))
        .pool("p", &[(0, 1)])
        .build();
    let (host, rt) = crate::engine::test_host_rt(&app);
    let inner = futures::stream::iter(
        chunks
            .into_iter()
            .map(|c| Ok::<bytes::Bytes, hyper::Error>(bytes::Bytes::from_static(c)))
            .collect::<Vec<_>>(),
    );
    let tap = TapCell::new();
    let body = crate::engine::FirstByteBody::new(
        inner,
        false, // same-protocol NON-STREAM application/json
        crate::proto_codec::PROTO_COHERE,
        crate::test_support::CHAT,
        (),
        tokio::time::Instant::now() + std::time::Duration::from_secs(300),
        host,
        rt,
        0,
        Arc::new(Default::default()),
        "p",
        None,
        None,
        None, // UNGOVERNED: no usage sink, so no copy of the body is kept
        false,
        tap.clone(),
    );
    let served = body
        .into_body()
        .collect()
        .await
        .expect("drain")
        .to_bytes()
        .to_vec();
    let finish = tap.get().map(|r| r.finish);
    let faulted = app.store.lane_needs_probe(0, crate::engine::now());
    (served, finish, faulted)
}

/// UNGOVERNED SAME-PROTOCOL NON-STREAM (architect ruling on the Q31 follow-up). The stop-reason key
/// arrives SPLIT across two chunks (`"finish_re` | `ason":"ERROR"…`); the incremental scan still
/// finds it, the breaker records the fault and the end is `Error` — and the client's bytes are the
/// upstream's, unchanged. At the pin the ungoverned relay read nothing and the breaker saw success.
#[tokio::test]
async fn ungoverned_same_protocol_cohere_error_split_key_faults_the_breaker() {
    let first: &'static [u8] = br#"{"id":"c-1","finish_re"#;
    let second: &'static [u8] = br#"ason":"ERROR","message":{"role":"assistant","content":[{"type":"text","text":"x"}]},"usage":{"tokens":{"input_tokens":10,"output_tokens":5}}}"#;
    let (served, finish, faulted) = relay_ungoverned(vec![first, second]).await;
    assert_eq!(
        served,
        [first, second].concat(),
        "the upstream body reaches the client byte-for-byte unchanged"
    );
    assert!(
        faulted,
        "the serving lane's breaker must record a fault for a failed generation"
    );
    assert_eq!(finish, Some(TapFinish::Error), "the end is an Error");
}

/// CONTROL: the same split relay ending `COMPLETE` is no fault and ends `Complete`.
#[tokio::test]
async fn ungoverned_same_protocol_cohere_complete_split_key_is_no_fault() {
    let first: &'static [u8] = br#"{"id":"c-1","finish_re"#;
    let second: &'static [u8] = br#"ason":"COMPLETE","message":{"role":"assistant","content":[{"type":"text","text":"x"}]},"usage":{"tokens":{"input_tokens":10,"output_tokens":5}}}"#;
    let (served, finish, faulted) = relay_ungoverned(vec![first, second]).await;
    assert_eq!(served, [first, second].concat());
    assert!(!faulted, "a completed generation is no fault");
    assert_eq!(finish, Some(TapFinish::Complete));
}
