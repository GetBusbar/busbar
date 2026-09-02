// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Regression tests for `translate_response_cross_protocol` in
//! `crates/busbar-core/src/proxy/engine/mod.rs`: a buffered cross-protocol response whose delivery
//! resolves to a NON-DELIVERY terminal must NOT charge the caller — neither the token ledger nor the
//! lane request budget. The two non-delivery terminals are `IngressUnsupported` (renders a 404) and
//! `Untranslatable` (falls through to the ingress-native 500); both build a body the client never
//! receives, so billing them (as the pre-fix code did — it recorded usage and disarmed the refund
//! guard *before* the delivery `match`) drained the key's TPM/spend and the lane's request budget for
//! a completion that was never delivered. A DELIVERED response still bills exactly once.
//!
//! Each case asserts against the ACTUAL charge seams: the governance token ledger
//! (`GovState::usage_for`) and the lane request budget (`LaneRuntime::lane_budget_remaining`, refunded
//! on `BudgetSpendGuard::drop` when the guard is left armed).

use super::{translate_response_cross_protocol, BudgetSpendGuard};
use crate::engine::AppEngineExt as _;
use busbar_core::governance::{GovState, MemoryStore, NewKeySpec};
use std::sync::Arc;

/// A governed fixture: an `App` whose sole lane is the OpenAI EGRESS with a limited request budget of
/// 5, plus the governance ledger + a virtual key bound to a loose day-budget group (so
/// `usage_for(key)` materialises the key's token bucket exactly as the usage-tap tests rely on).
fn fixture() -> (
    Arc<busbar_core::state::App>,
    Arc<GovState>,
    Arc<busbar_core::cost::CostModel>,
    busbar_api::VirtualKey,
) {
    crate::testkit::install_test_seams();
    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, None).expect("gov"));
    let groups = std::collections::BTreeMap::from([(
        "g".to_string(),
        busbar_core::config::GroupCfg {
            parent: None,
            enabled: true,
            limits: vec![busbar_core::config::groups::LimitCfg {
                metric: busbar_core::config::groups::LimitMetric::Budget,
                amount: 1_000_000_000,
                per: Some(busbar_core::config::groups::LimitWindow::Day),
                scope: None,
                on_exhaust: None,
                downgrade_to: None,
            }],
            ..Default::default()
        },
    )]);
    let cost = Arc::new(busbar_core::cost::CostModel::resolve_parts(
        None, 0, &groups,
    ));
    let (key, _secret) = gov
        .create_key(
            NewKeySpec {
                name: "k".to_string(),
                allowed_pools: None,
                group: Some("g".to_string()),
                labels: Default::default(),
                ..Default::default()
            },
            1_700_000_000,
        )
        .expect("create key");
    let app = crate::test_support::TestApp::new()
        .lane(
            crate::test_support::LaneSpec::new(
                "gpt-4o",
                crate::proto_codec::PROTO_OPENAI,
                "http://127.0.0.1:1",
            )
            .provider("openai")
            .budget(5),
        )
        .pool("p", &[(0, 1)])
        .build();
    (app, gov, cost, key)
}

/// The outcome of driving one buffered cross-protocol response: the delivered HTTP status, the token
/// count the ledger attributed to the key, and the lane's remaining request budget after the spend
/// guard has dropped.
struct Outcome {
    status: axum::http::StatusCode,
    ledger_tokens: u64,
    budget_remaining: i64,
}

/// Drive `translate_response_cross_protocol` for one (op, ingress, egress-2xx-body) triple on a fresh
/// governed fixture. Before the call we consume ONE unit of the lane budget — the headers-time spend
/// the guard is responsible for refunding — then arm a `BudgetSpendGuard` exactly as the live caller
/// does. The guard is dropped (its refund seam) before we read the budget back.
async fn drive(op: busbar_substrate::handlers::Op, ingress: &'static str, body: Vec<u8>) -> Outcome {
    let (app, gov, cost, key) = fixture();
    let sink = Some(crate::engine::UsageSink {
        gov: gov.clone(),
        cost: cost.clone(),
        key: Arc::new(key.clone()),
        pool: Arc::from("p"),
        charged_at: 1_700_000_000,
        admit: None,
    });
    let breaker = busbar_core::store::BreakerCfg::default();

    // The headers-time budget unit the buffered path spends before it buffers the body (the unit the
    // guard refunds on a non-delivery return). 5 -> 4.
    assert!(
        app.store.spend_budget(0),
        "the limited lane must have budget to spend"
    );

    let status = {
        let mut guard = BudgetSpendGuard {
            store: &*app.store,
            lane: 0,
            armed: true,
        };
        // A GENUINE `hyper::body::Incoming` (unconstructible by hand): serve the fixture body from
        // a one-shot local socket and fetch it through the REAL owned egress client — the same
        // stack the live caller hands this function.
        let upstream = {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind fixture upstream");
            let addr = listener.local_addr().expect("fixture addr");
            let body = body.clone();
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let (mut sock, _) = listener.accept().await.expect("accept");
                let mut buf = [0u8; 4096];
                let _ = sock.read(&mut buf).await;
                let head = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\
                     content-length: {}\r\nconnection: close\r\n\r\n",
                    body.len()
                );
                sock.write_all(head.as_bytes()).await.expect("write head");
                sock.write_all(&body).await.expect("write body");
            });
            let uri: axum::http::Uri = format!("http://{addr}/").parse().expect("fixture uri");
            let req = crate::engine::egress_request(
                uri,
                axum::http::HeaderMap::new(),
                bytes::Bytes::new(),
            );
            app.engine_tables()
                .client()
                .get()
                .request(req)
                .await
                .expect("fixture upstream send")
        };
        let resp = translate_response_cross_protocol(
            &app,
            0,
            ingress,
            op,
            "p",
            &breaker,
            upstream,
            tokio::time::Instant::now() + std::time::Duration::from_secs(5),
            busbar_core::store::Permit::Unbounded,
            &mut guard,
            sink,
            axum::http::StatusCode::OK,
            false,
            false,
            std::time::Instant::now(),
            None,
            false,
        )
        .await;
        resp.status()
        // `guard` drops HERE: refunds the spent unit iff the function left it armed (non-delivery).
    };

    let ledger_tokens = gov
        .usage_for(&cost, &key.id, busbar_core::store::now())
        .expect("usage read")
        .map(|u| u.tokens)
        .unwrap_or(0);
    let budget_remaining = app
        .store
        .lane_budget_remaining(0)
        .expect("the lane is budget-limited");
    Outcome {
        status,
        ledger_tokens,
        budget_remaining,
    }
}

/// DELIVERED (control): an OpenAI egress chat completion translated to an Anthropic ingress client is
/// a real delivered body — it MUST bill exactly once (22 tokens) and MUST keep the spent budget unit
/// (the guard disarms, so no refund).
#[tokio::test]
async fn delivered_cross_protocol_response_bills_once() {
    crate::testkit::install_test_seams();
    let body = br#"{"id":"x","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}],"usage":{"prompt_tokens":13,"completion_tokens":9}}"#.to_vec();
    let out = drive(
        busbar_substrate::handlers::chat("openai", busbar_substrate::transport::Transport::Http),
        "anthropic",
        body,
    )
    .await;
    assert_eq!(
        out.status,
        axum::http::StatusCode::OK,
        "the body is delivered"
    );
    assert_eq!(
        out.ledger_tokens, 22,
        "a delivered cross-protocol response bills its 13+9 tokens exactly once"
    );
    assert_eq!(
        out.budget_remaining, 4,
        "a delivered response keeps the headers-time budget unit (guard disarmed, no refund)"
    );
}

/// NON-DELIVERY 404: an OpenAI egress EMBEDDINGS 2xx routed to an Anthropic ingress (which does not
/// serve embeddings) resolves to `IngressUnsupported` — a 404 carrying NO completion. The egress read
/// succeeded and carried real usage (42 input tokens), but nothing is delivered, so NEITHER the token
/// ledger NOR the request budget may be charged: the budget unit is refunded (5) and the ledger is 0.
#[tokio::test]
async fn ingress_unsupported_404_does_not_charge() {
    crate::testkit::install_test_seams();
    let body = br#"{"object":"list","data":[{"object":"embedding","index":0,"embedding":[0.1,0.2,0.3]}],"model":"text-embedding-3-small","usage":{"prompt_tokens":42}}"#.to_vec();
    crate::testkit::install_test_seams();
    let out = drive(
        busbar_substrate::handlers::op_for(
            "openai",
            busbar_core::operation::Operation::EMBEDDINGS,
            busbar_substrate::transport::Transport::Http,
        )
        .expect("openai serves embeddings"),
        "anthropic",
        body,
    )
    .await;
    assert_eq!(
        out.status,
        axum::http::StatusCode::NOT_FOUND,
        "an ingress that does not serve the op renders a 404"
    );
    assert_eq!(
        out.ledger_tokens, 0,
        "a 404 that delivers no completion must NOT bill the 42 upstream tokens"
    );
    assert_eq!(
        out.budget_remaining, 5,
        "a non-delivery 404 must refund the headers-time budget unit (guard left armed)"
    );
}

/// NON-DELIVERY 500: an OpenAI egress SPEECH 2xx (opaque binary audio the codec reads happily) routed
/// to an Anthropic ingress (which does not serve speech) resolves to `Untranslatable` — a fall-through
/// to the ingress-native 500 carrying NO completion. The opaque read succeeded (usage `Flat`), but
/// nothing is delivered, so the request budget must be refunded (5) and the token ledger stays 0.
#[tokio::test]
async fn untranslatable_500_does_not_charge() {
    crate::testkit::install_test_seams();
    // Non-JSON bytes: forces the engine's OPAQUE arm; the OpenAI speech reader accepts any binary
    // audio body and returns a `Flat` usage marker.
    let body = vec![
        0x00u8, 0x01, 0x02, 0xFF, b'n', b'o', b't', b'-', b'j', b's', b'o', b'n',
    ];
    crate::testkit::install_test_seams();
    let out = drive(
        busbar_substrate::handlers::op_for(
            "openai",
            busbar_core::operation::Operation::SPEECH,
            busbar_substrate::transport::Transport::Http,
        )
        .expect("openai serves speech"),
        "anthropic",
        body,
    )
    .await;
    assert_eq!(
        out.status,
        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        "an untranslatable opaque body renders the ingress-native 500"
    );
    assert_eq!(
        out.ledger_tokens, 0,
        "a 500 that delivers no completion must NOT meter/bill the request"
    );
    assert_eq!(
        out.budget_remaining, 5,
        "a non-delivery 500 must refund the headers-time budget unit (guard left armed)"
    );
}
