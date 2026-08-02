use crate::config;

#[test]
fn test_config_parsing_status_503() {
    let cfg: config::OnExhaustedCfg = serde_yaml::from_str("reject").unwrap();
    assert!(matches!(cfg.to_runtime(), config::OnExhausted::Status503));
}

#[test]
fn test_config_parsing_least_bad() {
    let cfg: config::OnExhaustedCfg = serde_yaml::from_str("least_bad").unwrap();
    assert!(matches!(cfg.to_runtime(), config::OnExhausted::LeastBad));
}

#[test]
fn test_config_parsing_fallback_pool() {
    let cfg: config::OnExhaustedCfg = serde_yaml::from_str("{ fallback_pool: drain }").unwrap();
    if let config::OnExhausted::FallbackPool(name) = cfg.to_runtime() {
        assert_eq!(name, "drain");
    } else {
        panic!("Expected FallbackPool variant");
    }
}

#[test]
fn test_config_parsing_unknown_fails() {
    let result: Result<config::OnExhaustedCfg, _> = serde_yaml::from_str("invalid");
    assert!(result.is_err(), "Unknown action should fail parsing");
}

#[test]
fn test_config_parsing_bare_fallback_pool_fails() {
    // The old colon form `fallback_pool:drain` is no longer a bare keyword; only the
    // structured `{ fallback_pool: name }` map is accepted.
    let result: Result<config::OnExhaustedCfg, _> = serde_yaml::from_str("'fallback_pool:drain'");
    assert!(result.is_err(), "Colon-form keyword should fail parsing");
}

// ── least_bad routing ────────────────────────────────────────────────────────────────────────────
// `least_bad` is licensed to override ONE thing: the circuit breaker, an inference busbar drew from
// observed failures. It is not licensed to override operator declarations — a `failover.exclusions`
// blocklist, a `dead` mark, or an exhausted `max_requests` budget. These assert that boundary.

use crate::proxy::forward_with_pool;
use crate::state::{now, WeightedLane};
use crate::test_support::{LaneSpec, MockResponse, MockServer, MockServerState, TestApp};
use serde_json::json;
use std::sync::Arc;

async fn ok_server_for(model: &'static str) -> MockServer {
    let state = Arc::new(MockServerState::new());
    for _ in 0..4 {
        state.push(MockResponse::Ok {
            status: axum::http::StatusCode::OK,
            body: json!({
                "role": "assistant",
                "content": [{"type": "text", "text": "hi"}],
                "model": model,
                "stop_reason": "end_turn",
                "usage": {"input_tokens": 1, "output_tokens": 1}
            }),
        });
    }
    MockServer::new(state).await
}

fn lane(idx: usize) -> WeightedLane {
    WeightedLane {
        reasoning: None,
        idx,
        weight: 1,
        attempt_timeout_ms: None,
    }
}

fn chat_body(pool: &str) -> Vec<u8> {
    serde_json::to_vec(
        &json!({"model": pool, "messages": [{"role": "user", "content": "hi"}], "max_tokens": 10}),
    )
    .unwrap()
}

fn pool_runtime_with_exclusions(excl: Option<Vec<String>>) -> crate::state::PoolRuntime {
    crate::state::PoolRuntime {
        members: Default::default(),
        failover: Some(crate::config::FailoverCfg {
            timeout_secs: 120,
            exclusions: excl,
            max_hops: 3,
        }),
        affinity: None,
        breaker: None,
        policy: None,
        gates: Vec::new(),
        rewrite_hooks: Vec::new(),
    }
}

/// `least_bad` must not reach for a member the operator blocklisted. `docs/failover.md` promises an
/// excluded member "can never" be landed on and that automatic selection "never spends on it" — the
/// whole point being that it is the expensive last resort a human invokes deliberately. Reaching
/// for it precisely when everything else is on fire inverts that.
#[tokio::test]
async fn least_bad_never_reaches_an_excluded_member() {
    crate::metrics::init();
    let server_a = ok_server_for("alpha").await;
    let server_b = ok_server_for("beta").await;

    let app = TestApp::new()
        .lane(
            LaneSpec::new(
                "alpha",
                crate::proto::Protocol::anthropic(),
                &server_a.base_url(),
            )
            .provider("p"),
        )
        .lane(
            LaneSpec::new(
                "beta",
                crate::proto::Protocol::anthropic(),
                &server_b.base_url(),
            )
            .provider("p"),
        )
        .pool("pe", &[(0, 1), (1, 1)])
        .pool_runtime(
            "pe",
            pool_runtime_with_exclusions(Some(vec!["beta".into()])),
        )
        .on_exhausted("pe", crate::config::OnExhausted::LeastBad)
        .build();

    // alpha is the only eligible member and its breaker is Open → the pool is exhausted.
    app.store.force_open_in("pe", 0, now() + 300);

    let resp = forward_with_pool(
        app.clone(),
        vec![lane(0), lane(1)],
        chat_body("pe").into(),
        None,
        "pe",
        None,
        "anthropic",
        crate::handlers::CHAT,
        None,
    )
    .await;

    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(
        app.store.snapshot(1, now()).ok,
        0,
        "the excluded member must not serve the degraded dispatch"
    );
    assert_eq!(
        app.store.snapshot(0, now()).ok,
        1,
        "least_bad must degrade onto the eligible Open member, not the blocklisted healthy one"
    );
    server_a.shutdown().await;
    server_b.shutdown().await;
}

/// Deadness lives outside the breaker cell, so a dead lane reports a cooldown of 0 and would sort
/// FIRST — beating a lane that genuinely recovers in seconds. `least_bad` must rank only among
/// lanes that could actually serve.
#[tokio::test]
async fn least_bad_ranks_only_admissible_lanes() {
    crate::metrics::init();
    let server_dead = ok_server_for("gone").await;
    let server_soon = ok_server_for("soon").await;

    let app = TestApp::new()
        .lane(
            LaneSpec::new(
                "gone",
                crate::proto::Protocol::anthropic(),
                &server_dead.base_url(),
            )
            .provider("p")
            .dead("administratively down"),
        )
        .lane(
            LaneSpec::new(
                "soon",
                crate::proto::Protocol::anthropic(),
                &server_soon.base_url(),
            )
            .provider("p"),
        )
        .pool("pl", &[(0, 1), (1, 1)])
        .pool_runtime("pl", pool_runtime_with_exclusions(None))
        .on_exhausted("pl", crate::config::OnExhausted::LeastBad)
        .build();

    app.store.force_open_in("pl", 1, now() + 5);

    let resp = forward_with_pool(
        app.clone(),
        vec![lane(0), lane(1)],
        chat_body("pl").into(),
        None,
        "pl",
        None,
        "anthropic",
        crate::handlers::CHAT,
        None,
    )
    .await;

    assert_eq!(
        resp.status().as_u16(),
        200,
        "the recovering lane must serve"
    );
    assert_eq!(
        app.store.snapshot(0, now()).ok,
        0,
        "the dead lane must not be ranked, let alone dispatched to"
    );
    server_dead.shutdown().await;
    server_soon.shutdown().await;
}

/// Regression fence for the naive fix. Filtering `least_bad` on `request_ctx.excluded` looks
/// equivalent but is not: that set also accumulates every lane the request already TRIED, so in the
/// dominant exhaustion case it holds every member and `least_bad` silently degenerates to `reject`.
#[tokio::test]
async fn least_bad_still_serves_the_only_member_after_it_was_tried() {
    crate::metrics::init();
    let server = ok_server_for("solo").await;

    let app = TestApp::new()
        .lane(
            LaneSpec::new(
                "solo",
                crate::proto::Protocol::anthropic(),
                &server.base_url(),
            )
            .provider("p"),
        )
        .pool("ps", &[(0, 1)])
        .pool_runtime("ps", pool_runtime_with_exclusions(None))
        .on_exhausted("ps", crate::config::OnExhausted::LeastBad)
        .build();

    app.store.force_open_in("ps", 0, now() + 30);

    let resp = forward_with_pool(
        app.clone(),
        vec![lane(0)],
        chat_body("ps").into(),
        None,
        "ps",
        None,
        "anthropic",
        crate::handlers::CHAT,
        None,
    )
    .await;

    assert_eq!(
        resp.status().as_u16(),
        200,
        "least_bad must still override the Open breaker for a non-excluded member"
    );
    server.shutdown().await;
}

/// `failover.exclusions` is a PER-POOL member blocklist, and a fallback pool is an independent
/// membership. Its own blocklist was never consulted, so a member the operator blocklisted there
/// could still be reached by spilling into the pool — the one path exclusions exist to prevent.
#[tokio::test]
async fn a_fallback_pool_applies_its_own_exclusions() {
    crate::metrics::init();
    let server_primary = ok_server_for("primary").await;
    let server_ok = ok_server_for("spare").await;
    let server_blocked = ok_server_for("blocked").await;

    let app = TestApp::new()
        .lane(
            LaneSpec::new(
                "primary",
                crate::proto::Protocol::anthropic(),
                &server_primary.base_url(),
            )
            .provider("p"),
        )
        .lane(
            LaneSpec::new(
                "spare",
                crate::proto::Protocol::anthropic(),
                &server_ok.base_url(),
            )
            .provider("p"),
        )
        .lane(
            LaneSpec::new(
                "blocked",
                crate::proto::Protocol::anthropic(),
                &server_blocked.base_url(),
            )
            .provider("p"),
        )
        .pool("pf", &[(0, 1)])
        .pool_runtime("pf", pool_runtime_with_exclusions(None))
        .on_exhausted(
            "pf",
            crate::config::OnExhausted::FallbackPool("spill".into()),
        )
        .fallback_pool("spill", &[(1, 1), (2, 1)])
        .pool_runtime(
            "spill",
            pool_runtime_with_exclusions(Some(vec!["blocked".into()])),
        )
        .build();

    // Exhaust the primary so the request spills.
    app.store.force_open_in("pf", 0, now() + 300);

    for _ in 0..4 {
        let resp = forward_with_pool(
            app.clone(),
            vec![lane(0)],
            chat_body("pf").into(),
            None,
            "pf",
            None,
            "anthropic",
            crate::handlers::CHAT,
            None,
        )
        .await;
        assert_eq!(resp.status().as_u16(), 200);
    }

    assert_eq!(
        app.store.snapshot(2, now()).ok,
        0,
        "a member blocklisted by the FALLBACK pool must never serve a spilled request"
    );
    assert_eq!(
        app.store.snapshot(1, now()).ok,
        4,
        "the eligible fallback member serves every spilled request"
    );
    server_primary.shutdown().await;
    server_ok.shutdown().await;
    server_blocked.shutdown().await;
}
