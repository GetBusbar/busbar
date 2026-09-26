//! A USAGE THE READER REFUSES, AFTER THE BODY WAS DELIVERED, BILLS THE FLOOR — NEVER 0.
//!
//! Item 133 made every dialect reader REFUSE a present-but-unreadable billed count
//! (`{"input_tokens":"1500"}`) instead of reading it as zero. On the relay paths that refusal lands
//! AFTER the client has the body, so there is nothing left to refuse: the request used to bill 0
//! tokens for the whole response, with a warning. That is a LEDGER fault — the book records that no
//! work happened. The ruling: an unreadable usage after delivery is NO USAGE RECOVERED, and bills
//! exactly what the truncated-tail path bills when it recovers nothing — the conservative floor over
//! the delivered bytes (`estimate_usage_from_truncated_tail`), attributed to the output tier.
use super::*;
use crate::test_support::engine_kit::EngineTestKit as _;
use busbar_kernel::governance::NewKeySpec;
use bytes::Bytes;
use http_body_util::BodyExt as _;

/// The floor the truncated-tail path bills for `delivered` bytes — the figure a refused usage must
/// now bill, read off the SAME function rather than re-derived here.
fn floor_for(delivered: usize) -> u64 {
    estimate_usage_from_truncated_tail(delivered).output
}

/// Drive ONE same-protocol, non-stream anthropic body through `FirstByteBody` to its end and return
/// the tokens the key's ledger holds afterwards.
async fn billed_tokens_for(body: &str) -> u64 {
    crate::testkit::install_test_seams();
    busbar_kernel::metrics::init();
    let store = crate::test_support::engine_kit::CORE_ENGINE_KIT.scratch_store();
    let gov = crate::test_support::engine_kit::CORE_ENGINE_KIT
        .governance(store, None, None)
        .expect("gov");
    let cost = crate::test_support::engine_kit::CORE_ENGINE_KIT.cost_flat(0);
    let (key, _secret) = gov
        .create_key(
            NewKeySpec {
                name: "k".to_string(),
                ..Default::default()
            },
            1_700_000_000,
        )
        .expect("create key");
    let charged_at: u64 = 1_700_000_000;
    let sink = Some(UsageSink {
        pin: busbar_kernel::plane_host::MeterPin::new(
            busbar_kernel::plane_host::GovHandle(gov.clone()),
            busbar_kernel::plane_host::CostHandle(cost.clone()),
        ),
        key: Arc::new(key.clone()),
        pool: Arc::from(""),
        charged_at,
        admit: None,
    });
    let app = crate::test_support::TestApp::new()
        .lane(crate::test_support::LaneSpec::new(
            "claude-x",
            crate::proto_codec::PROTO_ANTHROPIC,
            "http://127.0.0.1:1",
        ))
        .pool("pa", &[(0, 1)])
        .build();
    let (host, rt) = crate::engine::test_host_rt(&app);
    let inner = futures::stream::iter(vec![Ok::<Bytes, hyper::Error>(Bytes::from(
        body.to_string(),
    ))]);
    let fbb = FirstByteBody::new(
        inner,
        false, // same-protocol NON-STREAM application/json
        "anthropic",
        crate::test_support::CHAT,
        (),
        tokio::time::Instant::now() + std::time::Duration::from_secs(300),
        host,
        rt,
        0,
        Arc::new(busbar_kernel::store::BreakerCfg::default()),
        "pa",
        None,
        None,
        sink,
        false,
        TapCell::new(),
    );
    let served = fbb.into_body().collect().await.expect("drain").to_bytes();
    assert_eq!(served.as_ref(), body.as_bytes(), "the body relays verbatim");
    let mut tokens = 0;
    for _ in 0..200 {
        tokio::task::yield_now().await;
        tokens = gov
            .usage_for(cost.as_ref(), &key.id, charged_at)
            .expect("usage read")
            .map(|u| u.tokens)
            .unwrap_or(0);
        if tokens != 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
    }
    tokens
}

fn message_with_usage(usage: &str) -> String {
    format!(
        r#"{{"id":"msg_1","type":"message","role":"assistant","model":"claude-x","content":[{{"type":"text","text":"hi"}}],"stop_reason":"end_turn","stop_sequence":null,"usage":{usage}}}"#
    )
}

#[tokio::test]
async fn buffered_relay_refused_usage_bills_the_floor_not_zero() {
    // CONTROL: the same body with a READABLE usage bills exactly what it says.
    let readable = message_with_usage(r#"{"input_tokens":1500,"output_tokens":9}"#);
    assert_eq!(billed_tokens_for(&readable).await, 1509);

    // THE DEFECT: a stringified count the reader refuses. At the pin this billed 0.
    let refused = message_with_usage(r#"{"input_tokens":"1500","output_tokens":9}"#);
    let billed = billed_tokens_for(&refused).await;
    assert_ne!(
        billed, 0,
        "a refused usage on a delivered body must never bill 0"
    );
    assert_eq!(
        billed,
        floor_for(refused.len()),
        "a refused usage bills the no-usage-recovered floor over the delivered bytes"
    );
}

/// The STREAMING twin: an OpenAI same-protocol stream whose usage chunk carries a count the reader
/// refuses ends in an `ir_parse` error after the frames were relayed. It bills the floor over the
/// bytes the upstream sent (the same measure the truncated-tail floor is taken over), never 0.
#[tokio::test]
async fn stream_refused_usage_bills_the_floor_not_zero() {
    use crate::test_support::{LaneSpec, MockResponse, MockServer, MockServerState, TestApp};
    use busbar_kernel::test_support::engine_kit::TestAppKit;
    crate::testkit::install_test_seams();
    let base = serde_json::json!({"id": "chatcmpl-refused", "object": "chat.completion.chunk",
        "created": 0, "model": "m0"});
    let mut first = base.clone();
    first["choices"] = serde_json::json!([{"index": 0,
        "delta": {"role": "assistant", "content": "hello"}, "finish_reason": null}]);
    let mut last = base.clone();
    last["choices"] = serde_json::json!([{"index": 0, "delta": {}, "finish_reason": "stop"}]);
    let mut usage = base;
    usage["choices"] = serde_json::json!([]);
    usage["usage"] = serde_json::json!({"prompt_tokens": "1500", "completion_tokens": 9});
    let events = vec![first.to_string(), last.to_string(), usage.to_string()];
    // The bytes the upstream sent: each event framed `data: …\n\n`, then the `[DONE]` frame.
    let upstream: usize = events.iter().map(|e| e.len() + 8).sum::<usize>()
        + busbar_kernel::proto::SSE_DONE_FRAME.len();
    let state = Arc::new(MockServerState::new());
    state.push(MockResponse::Sse {
        events,
        abort_at_index: None,
    });
    let server = MockServer::new(state).await;

    let store: Arc<dyn busbar_contract::records::RecordStore> =
        crate::test_support::engine_kit::CORE_ENGINE_KIT.scratch_store();
    let gov_kit = crate::test_support::engine_kit::CORE_ENGINE_KIT
        .governance(store, None, None)
        .expect("governance");
    let (key, _secret) = gov_kit
        .create_key(
            NewKeySpec {
                name: "k".to_string(),
                ..Default::default()
            },
            1_700_000_000,
        )
        .expect("create key");
    let mut builder = TestApp::new()
        .lane(LaneSpec::new(
            "m0",
            crate::proto_codec::PROTO_OPENAI,
            &server.base_url(),
        ))
        .pool("p", &[(0, 1)]);
    TestAppKit::set_governance(&mut builder, gov_kit.clone());
    let app = builder.build();
    let (host, _rt) = crate::engine::test_host_rt(&app);
    let charged_at = busbar_kernel::store::now();
    let sink = UsageSink {
        pin: host.meter_pin().expect("governance is configured"),
        key: Arc::new(key.clone()),
        pool: Arc::from("p"),
        charged_at,
        admit: None,
    };
    let body = serde_json::json!({"model": "p", "stream": true,
        "messages": [{"role": "user", "content": "hi"}]});
    let resp = crate::engine::forward_with_pool(
        &app,
        vec![crate::engine::WeightedLane {
            reasoning: None,
            idx: 0,
            weight: 1,
            attempt_timeout_ms: None,
        }],
        serde_json::to_vec(&body).unwrap().into(),
        None,
        "p",
        None,
        crate::proto_codec::PROTO_OPENAI,
        crate::test_support::CHAT,
        Some(sink),
    )
    .await;
    assert_eq!(resp.status().as_u16(), 200, "the stream is served");
    let _ = axum::body::to_bytes(resp.into_body(), usize::MAX).await;

    let gov = app.governance.clone().expect("governance is configured");
    let tokens = gov
        .usage_for(&app.cost, &key.id, charged_at)
        .expect("usage read")
        .expect("the key exists")
        .tokens;
    assert_ne!(
        tokens, 0,
        "a refused usage on a delivered stream must never bill 0"
    );
    assert_eq!(
        tokens,
        floor_for(upstream),
        "a refused stream usage bills the floor over the bytes the upstream sent"
    );
    server.shutdown().await;
}
