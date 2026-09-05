//! The four distinct 503 bodies a hook can produce before any upstream is contacted, pinned to
//! WHICH hook produced them: a decision gate that could not complete, a decision gate whose
//! restriction left no lane, the pool's base routing policy that could not select, and the base
//! policy whose restriction left no lane. Each literal is a client-visible contract; the test
//! fails if two of them ever collapse into one, or if a gate's body is served for a policy's fault.
use super::forward_with_pool;
use crate::test_support::{LaneSpec, TestApp};
use busbar_api::{
    Candidate, PolicyResult, RoutingContext, RoutingDecision, RoutingPolicy, RoutingRequest,
};
use busbar_substrate::hooks::ResolvedPolicy;
use std::sync::Arc;

const GATE_COULD_NOT_COMPLETE: &str = "A required gate could not complete. Please retry shortly.";
const GATE_RESTRICT_EMPTY: &str =
    "No upstream satisfies a required gate's restriction. Please retry shortly.";
const POLICY_COULD_NOT_SELECT: &str =
    "The routing policy could not select an upstream. Please retry shortly.";
const POLICY_RESTRICT_EMPTY: &str =
    "No upstream satisfies the routing policy's restriction. Please retry shortly.";

/// A hook that either fails outright or restricts to a tag no lane carries.
enum Fault {
    Error,
    RestrictToNothing,
}

struct FaultyHook(Fault);

#[async_trait::async_trait]
impl RoutingPolicy for FaultyHook {
    async fn decide(
        &self,
        _req: &RoutingRequest<'_>,
        _candidates: &[Candidate<'_>],
        _ctx: &RoutingContext<'_>,
        _budget: std::time::Duration,
    ) -> PolicyResult {
        match self.0 {
            Fault::Error => Err("deliberately broken".into()),
            Fault::RestrictToNothing => Ok(RoutingDecision::Restrict {
                tags_any: vec!["a-tag-no-lane-carries".to_string()],
            }),
        }
    }
    fn name(&self) -> &'static str {
        "faulty"
    }
}

/// Fail-closed on both axes: an error terminates in `reject`, an empty restriction rejects.
fn resolved(fault: Fault) -> ResolvedPolicy {
    ResolvedPolicy::Policy {
        policy: Arc::new(FaultyHook(fault)),
        on_error: busbar_substrate::config::PolicyOnError::Reject,
        on_error_chain: Vec::new(),
        timeout: std::time::Duration::from_millis(50),
        send_prompt: false,
        send_user: false,
        on_empty: busbar_substrate::config::PolicyOnError::Reject,
    }
}

/// The OpenAI-native spelling of busbar's own overloaded 503 kind, read off the ingress error
/// writer itself so the test pins "the same kind as every other busbar 503" and no vendor string.
async fn overloaded_kind_on_openai() -> String {
    let resp = super::ingress_error(
        "openai",
        http::StatusCode::SERVICE_UNAVAILABLE,
        super::KIND_OVERLOADED,
        "x",
    );
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    v["error"]["type"].as_str().unwrap_or_default().to_string()
}

/// Where the faulty hook is seated.
enum Seat {
    DecisionGate,
    BasePolicy,
}

/// Fire one request at a two-lane pool with the faulty hook in the given seat; return
/// (status, error kind, error message) from the OpenAI-shaped envelope.
async fn fire(seat: Seat, fault: Fault) -> (u16, String, String) {
    crate::testkit::install_test_seams();
    let mut builder = TestApp::new()
        .lane(LaneSpec::new(
            "m0",
            crate::proto_codec::PROTO_OPENAI,
            "http://127.0.0.1:1/",
        ))
        .lane(LaneSpec::new(
            "m1",
            crate::proto_codec::PROTO_OPENAI,
            "http://127.0.0.1:1/",
        ))
        .pool("p", &[(0, 1), (1, 1)])
        .pool_member_meta("p", 0, None, None, &["eu"])
        .pool_member_meta("p", 1, None, None, &["us"]);
    let mut global_gate = None;
    match seat {
        Seat::DecisionGate => global_gate = Some(resolved(fault)),
        Seat::BasePolicy => builder = builder.pool_policy_resolved("p", resolved(fault)),
    }
    let mut app = builder.build();
    if let Some(g) = global_gate {
        Arc::get_mut(&mut app).expect("sole owner").global_gates = vec![(0u16, g)];
    }
    let (_host, _rt) = crate::engine::test_host_rt(&app);
    let body = serde_json::to_vec(
        &serde_json::json!({"model": "p", "messages": [{"role": "user", "content": "hi"}]}),
    )
    .unwrap();
    let resp = forward_with_pool(
        &app,
        (0..2)
            .map(|idx| crate::engine::WeightedLane {
                reasoning: None,
                idx,
                weight: 1,
                attempt_timeout_ms: None,
            })
            .collect(),
        body.into(),
        None,
        "p",
        None,
        "openai",
        crate::test_support::CHAT,
        None,
    )
    .await;
    let status = resp.status().as_u16();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes)
        .unwrap_or_else(|e| panic!("json error body: {e}: {}", String::from_utf8_lossy(&bytes)));
    (
        status,
        v["error"]["type"].as_str().unwrap_or_default().to_string(),
        v["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
    )
}

#[tokio::test]
async fn decision_gate_that_cannot_complete_has_its_own_503_body() {
    let (status, kind, message) = fire(Seat::DecisionGate, Fault::Error).await;
    assert_eq!((status, kind), (503, overloaded_kind_on_openai().await));
    assert_eq!(message, GATE_COULD_NOT_COMPLETE);
}

#[tokio::test]
async fn decision_gate_restriction_leaving_no_lane_has_its_own_503_body() {
    let (status, kind, message) = fire(Seat::DecisionGate, Fault::RestrictToNothing).await;
    assert_eq!((status, kind), (503, overloaded_kind_on_openai().await));
    assert_eq!(message, GATE_RESTRICT_EMPTY);
}

#[tokio::test]
async fn base_policy_that_cannot_select_has_its_own_503_body() {
    let (status, kind, message) = fire(Seat::BasePolicy, Fault::Error).await;
    assert_eq!((status, kind), (503, overloaded_kind_on_openai().await));
    assert_eq!(message, POLICY_COULD_NOT_SELECT);
}

#[tokio::test]
async fn base_policy_restriction_leaving_no_lane_has_its_own_503_body() {
    let (status, kind, message) = fire(Seat::BasePolicy, Fault::RestrictToNothing).await;
    assert_eq!((status, kind), (503, overloaded_kind_on_openai().await));
    assert_eq!(message, POLICY_RESTRICT_EMPTY);
}

/// The four literals are pairwise distinct, so a client can tell which hook refused it.
#[test]
fn the_four_503_literals_are_distinct() {
    let all = [
        GATE_COULD_NOT_COMPLETE,
        GATE_RESTRICT_EMPTY,
        POLICY_COULD_NOT_SELECT,
        POLICY_RESTRICT_EMPTY,
    ];
    for (i, a) in all.iter().enumerate() {
        for b in &all[i + 1..] {
            assert_ne!(a, b);
        }
    }
}
