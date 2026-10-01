// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A PROVIDER DIAL THE DIAL TABLE REFUSES fails over exactly as a refused connection does.
//!
//! The lane's name resolves, the address it answered with is refused before any socket opens, and
//! the attempt is a transient upstream failure classified `connect` (not `timeout`): the lane cools
//! down, the walk moves to the next lane, and when every lane is refused the client gets the bytes a
//! pool whose every upstream refused the connection gets.
//!
//! The runtime's client is built inside [`with_scoped_dial`], so it resolves through this test's
//! names and judges by this test's table; no other test's dial is touched. The refused address is
//! an OPERATOR-BLOCKED loopback address rather than a metadata one, so that a dial the table failed
//! to refuse would reach a live mock and be seen there.

use crate::engine::attempt::EgressSendError;
use crate::engine::{forward_with_pool, WeightedLane};
use crate::test_support::{LaneSpec, MockResponse, MockServer, MockServerState, TestApp};
use busbar_kernel::egress::engine::{with_scoped_dial, DialTable};
use busbar_kernel::egress::fixtures::RebindingResolver;
use busbar_kernel::net_guard::DialDenylist;
use busbar_kernel::store::now;
use reqwest::StatusCode;
use serde_json::json;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

/// The table every test here dials under: loopback `127.0.0.1` is operator-blocked.
fn blocking_loopback() -> DialTable {
    DialTable::new(DialDenylist::new(
        &["127.0.0.1".to_string()],
        &[],
        false,
        std::iter::empty(),
    ))
}

/// Names that answer `addr`, counting how often they were asked.
fn names_answering(addr: SocketAddr) -> Arc<RebindingResolver> {
    Arc::new(RebindingResolver::counting(addr))
}

fn lanes(n: usize) -> Vec<WeightedLane> {
    (0..n)
        .map(|idx| WeightedLane {
            reasoning: None,
            idx,
            weight: 1,
            attempt_timeout_ms: None,
        })
        .collect()
}

fn request_body() -> bytes::Bytes {
    serde_json::to_vec(&json!({
        "model": "test-model",
        "messages": [{"role": "user", "content": "hi"}],
        "max_tokens": 100
    }))
    .expect("json")
    .into()
}

async fn forward<A: busbar_kernel::test_support::BuiltAppSeam>(
    app: &Arc<A>,
    n: usize,
) -> axum::response::Response {
    forward_with_pool(
        app,
        lanes(n),
        request_body(),
        None,
        "",
        None,
        "anthropic",
        crate::test_support::CHAT,
        None,
    )
    .await
}

/// THE CLASS: the error a refused dial yields through the client the runtime builds reads as NOT a
/// timeout, so the attempt records `connect`, the class a refused connection records.
#[tokio::test]
async fn a_refused_dial_is_a_connect_failure_not_a_timeout() {
    let names = names_answering(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9));
    let client = with_scoped_dial(blocking_loopback(), names.clone(), || {
        crate::engine::build_egress_client(&crate::engine::EgressClientSpec::pooled_webpki(
            4, 300, false, false,
        ))
    });
    let err = client
        .request(crate::engine::egress_request(
            "http://primary.localhost:9/v1/messages"
                .parse()
                .expect("uri"),
            http::HeaderMap::new(),
            bytes::Bytes::new(),
        ))
        .await
        .expect_err("the blocked answer is refused");
    assert_eq!(names.calls(), 1, "the scoped names answered the dial");
    assert!(err.is_connect());
    assert!(
        !EgressSendError::Client(err).is_timeout(),
        "a refused dial must classify as connect, not timeout"
    );
}

/// THE FAIL-OVER: the primary lane's name answers a blocked address, so its dial is refused; the
/// walk moves to the next lane, which answers. The primary's mock never saw a request, and the
/// primary lane is cooling down as a transient failure.
#[tokio::test]
async fn a_refused_primary_fails_over_to_the_next_lane() {
    crate::testkit::install_test_seams();
    let primary_state = Arc::new(MockServerState::new());
    primary_state.push(MockResponse::Sse {
        events: vec!["never".to_string()],
        abort_at_index: None,
    });
    let primary = MockServer::new(primary_state.clone()).await;
    let next_state = Arc::new(MockServerState::new());
    next_state.push(MockResponse::Sse {
        events: vec!["event-0".to_string(), "event-1".to_string()],
        abort_at_index: None,
    });
    let next = MockServer::new(next_state.clone()).await;

    let primary_addr: SocketAddr = primary
        .base_url()
        .trim_start_matches("http://")
        .parse()
        .expect("the mock's address");
    let names = names_answering(primary_addr);
    let primary_url = format!("http://primary.localhost:{}", primary_addr.port());
    let app = with_scoped_dial(blocking_loopback(), names.clone(), || {
        let app = TestApp::new()
            .lane(LaneSpec::new(
                "lane0",
                crate::proto_codec::PROTO_ANTHROPIC,
                &primary_url,
            ))
            .lane(LaneSpec::new(
                "lane1",
                crate::proto_codec::PROTO_ANTHROPIC,
                &next.base_url(),
            ))
            .pool("default", &[(0, 1), (1, 1)])
            .build();
        let _ = crate::engine::test_host_rt(&app);
        app
    });

    let response = forward(&app, 2).await;
    assert_eq!(response.status().as_u16(), 200, "the next lane answered");
    assert!(names.calls() >= 1, "the primary's name was resolved");
    assert!(
        primary_state.get_last_request_path().is_none(),
        "the refused dial never reached the primary"
    );
    assert!(next_state.get_last_request_path().is_some());
    assert!(
        !app.store.usable(0, now()),
        "the refused lane cools down as a transient failure"
    );

    primary.shutdown().await;
    next.shutdown().await;
}

/// THE ALL-DOWN BYTES: a pool whose every lane's dial is refused answers the client exactly as a
/// pool whose every upstream refused the connection does: same status, same body.
#[tokio::test]
async fn an_all_refused_pool_answers_as_an_all_down_pool() {
    crate::testkit::install_test_seams();
    // Port 1 on loopback: nothing listens, so the baseline's connections are refused.
    let refused_url = "http://127.0.0.1:1";
    let baseline = TestApp::new()
        .lane(LaneSpec::new("lane0", crate::proto_codec::PROTO_ANTHROPIC, refused_url))
        .lane(LaneSpec::new("lane1", crate::proto_codec::PROTO_ANTHROPIC, refused_url))
        .pool("default", &[(0, 1), (1, 1)])
        .build();
    let _ = crate::engine::test_host_rt(&baseline);
    let base = forward(&baseline, 2).await;
    let base_status = base.status();
    let base_body = axum::body::to_bytes(base.into_body(), usize::MAX)
        .await
        .expect("baseline body");

    let names = names_answering(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1));
    let judged = with_scoped_dial(blocking_loopback(), names.clone(), || {
        let app = TestApp::new()
            .lane(LaneSpec::new(
                "lane0",
                crate::proto_codec::PROTO_ANTHROPIC,
                "http://primary.localhost:1",
            ))
            .lane(LaneSpec::new(
                "lane1",
                crate::proto_codec::PROTO_ANTHROPIC,
                "http://secondary.localhost:1",
            ))
            .pool("default", &[(0, 1), (1, 1)])
            .build();
        let _ = crate::engine::test_host_rt(&app);
        app
    });
    let refused = forward(&judged, 2).await;
    assert!(names.calls() >= 2, "both lanes' names were resolved and refused");
    assert_eq!(refused.status(), base_status);
    assert_eq!(base_status, StatusCode::SERVICE_UNAVAILABLE);
    let refused_body = axum::body::to_bytes(refused.into_body(), usize::MAX)
        .await
        .expect("refused body");
    // Byte for byte but the per-request id, which every answer mints afresh.
    assert_eq!(
        without_request_id(&refused_body),
        without_request_id(&base_body),
        "the all-down body"
    );
}

/// An error body with its freshly minted `request_id` blanked, every other byte kept.
fn without_request_id(body: &[u8]) -> serde_json::Value {
    let mut v: serde_json::Value = serde_json::from_slice(body).expect("a JSON error body");
    if let Some(id) = v.get_mut("request_id") {
        *id = serde_json::Value::Null;
    }
    v
}
