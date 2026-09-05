//! A streamed response that never carries a usage frame bills ZERO tokens on every ingress
//! dialect: the token ledger stays empty (nothing is charged to the key's budget) and the
//! metering series records exactly one request for the serving model with no token counts —
//! the stream-end tap runs once, with no usage to hand it.
use super::{forward_with_pool, UsageSink};
use crate::test_support::{LaneSpec, MockResponse, MockServer, MockServerState, TestApp};
use busbar_substrate::testkit::engine_kit::{EngineTestKit as _, TestAppKit};
use std::sync::Arc;

/// An OpenAI chat SSE stream with one content delta and a stop, and NO usage chunk.
fn stream_without_usage() -> MockResponse {
    let base = serde_json::json!({"id": "chatcmpl-nousage", "object": "chat.completion.chunk",
        "created": 0, "model": "m0"});
    let mut first = base.clone();
    first["choices"] = serde_json::json!([{"index": 0,
        "delta": {"role": "assistant", "content": "hello"}, "finish_reason": null}]);
    let mut last = base;
    last["choices"] = serde_json::json!([{"index": 0, "delta": {}, "finish_reason": "stop"}]);
    MockResponse::Sse {
        events: vec![first.to_string(), last.to_string()],
        abort_at_index: None,
    }
}

/// The streamed chat request as each ingress dialect spells it (the engine reads the `stream`
/// flag the arrival layer injects for the path-model dialects, so it rides in the body here).
fn body_for(ingress: &str) -> serde_json::Value {
    match ingress {
        "anthropic" => serde_json::json!({"model": "p", "max_tokens": 16, "stream": true,
            "messages": [{"role": "user", "content": "hi"}]}),
        "openai" | "cohere" => serde_json::json!({"model": "p", "stream": true,
            "messages": [{"role": "user", "content": "hi"}]}),
        "responses" => serde_json::json!({"model": "p", "stream": true, "input": "hi"}),
        "gemini" => serde_json::json!({"model": "p", "stream": true,
            "contents": [{"role": "user", "parts": [{"text": "hi"}]}]}),
        "bedrock" => serde_json::json!({"model": "p", "stream": true,
            "messages": [{"role": "user", "content": [{"text": "hi"}]}]}),
        other => panic!("no body for ingress dialect {other}"),
    }
}

#[tokio::test]
async fn stream_without_usage_frame_bills_zero_on_every_dialect() {
    crate::testkit::install_test_seams();
    for ingress in [
        crate::proto_codec::PROTO_ANTHROPIC,
        crate::proto_codec::PROTO_OPENAI,
        crate::proto_codec::PROTO_RESPONSES,
        crate::proto_codec::PROTO_GEMINI,
        crate::proto_codec::PROTO_BEDROCK,
        crate::proto_codec::PROTO_COHERE,
    ] {
        let state = Arc::new(MockServerState::new());
        state.push(stream_without_usage());
        let server = MockServer::new(state).await;

        // A governed key on a fresh in-memory registry, so the ledger and the metering series
        // start empty for this dialect.
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
        let mut builder = TestApp::new()
            .lane(
                LaneSpec::new("m0", crate::proto_codec::PROTO_OPENAI, &server.base_url())
                    .provider("zai"),
            )
            .pool("p", &[(0, 1)]);
        // The governance registry rides in through the neutral engine test kit seam.
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
        let resp = forward_with_pool(
            &app,
            vec![crate::engine::WeightedLane {
                reasoning: None,
                idx: 0,
                weight: 1,
                attempt_timeout_ms: None,
            }],
            serde_json::to_vec(&body_for(ingress)).unwrap().into(),
            None,
            "p",
            None,
            ingress,
            crate::test_support::CHAT,
            Some(sink),
        )
        .await;
        assert_eq!(
            resp.status().as_u16(),
            200,
            "[{ingress}] the stream is served"
        );
        // Drain the stream to its end: the stream-end tap fires on the last poll.
        let _ = axum::body::to_bytes(resp.into_body(), usize::MAX).await;

        // The token ledger: nothing charged to the key (tokens 0, spend 0).
        let gov = app.governance.clone().expect("governance is configured");
        let usage = gov
            .usage_for(&app.cost, &key.id, charged_at)
            .expect("usage read")
            .expect("the key exists");
        assert_eq!(
            usage.tokens, 0,
            "[{ingress}] no usage frame means zero tokens ledgered"
        );
        assert_eq!(
            usage.spend_cents, 0,
            "[{ingress}] nothing was admitted through the door here, so no fee and no token spend"
        );
        // The metering series: exactly one request for the serving model, with no token counts —
        // the stream-end tap ran once and had no usage to hand it.
        gov_kit.flush_metering();
        let rows = gov_kit
            .metering_for(busbar_substrate::governance::metering_bucket(charged_at))
            .expect("metering read");
        let mine: Vec<_> = rows.iter().filter(|r| r.key_id == key.id).collect();
        assert_eq!(
            mine.len(),
            1,
            "[{ingress}] one metering row for the key: {rows:?}"
        );
        let row = mine[0];
        assert_eq!(
            row.model, "m0",
            "[{ingress}] metered against the serving model"
        );
        assert_eq!(row.requests, 1, "[{ingress}] the request is counted once");
        assert_eq!(
            (
                row.tokens_input,
                row.tokens_output,
                row.tokens_cache_read,
                row.tokens_cache_write
            ),
            (0, 0, 0, 0),
            "[{ingress}] every token tier is zero"
        );
        server.shutdown().await;
    }
}
