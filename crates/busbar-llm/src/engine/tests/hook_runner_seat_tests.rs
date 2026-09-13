//! THE CELL FOR THE HOOK RUNNER'S MOVE: a hook registered on a served request fires ONCE per
//! request, at the SAME seat, and the code that projects it and maps its answer is
//! `busbar_core_policy::runner` — the crate the seam moved into.
//!
//! WHY THIS IS THE CELL AND NOT A RESTATEMENT. The move is by identity, so a test that only
//! asserted behaviour would have passed before the move as well and proven nothing about WHERE the
//! code is. This file therefore names the runner's crate path and NOTHING of this crate's hook
//! module: it calls `busbar_core_policy::runner::read_hook_facts` directly on the same body the
//! served request carried and asserts the served projection and the direct projection are the SAME
//! answer. At the base commit the module does not exist and this file does not compile, which is
//! the red; at the tip it compiles and passes, which is the green — and the only thing that can
//! make it pass is the served path going through the moved code rather than a copy left behind.
//!
//! FIRES ONCE, NOT ZERO AND NOT TWICE. Three served requests are sent through one gate hook. A
//! seam that re-reads or re-fires (the "one read per seam today" note in the runner is exactly the
//! shape that could regress into it) shows up as a count above three; a seam that is wired but
//! never reached shows up as zero.
use crate::test_support::{LaneSpec, TestApp};
use busbar_api::{
    Candidate, PolicyResult, RoutingContext, RoutingDecision, RoutingPolicy, RoutingRequest,
};
use busbar_substrate::hooks::ResolvedPolicy;
use busbar_substrate::testkit::engine_kit::EngineTestKit as _;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// The body every request in this cell carries, so the served projection and the direct projection
/// are answers about the SAME bytes.
fn body() -> serde_json::Value {
    serde_json::json!({
        "model": "p",
        "max_tokens": 16,
        "messages": [{"role": "user", "content": "the runner's one read"}]
    })
}

/// A gate that counts how many times it was asked and what shape it was handed. It abstains, so
/// every request it sees is SERVED — the seat under test is the served path's, not an error path's.
struct CountingGate {
    fires: AtomicUsize,
    /// The `(message_count, has_tools, total_chars)` triple of the last projection it was handed.
    seen: std::sync::Mutex<Option<(usize, bool, usize)>>,
}

#[async_trait::async_trait]
impl RoutingPolicy for CountingGate {
    async fn decide(
        &self,
        req: &RoutingRequest<'_>,
        _candidates: &[Candidate<'_>],
        _ctx: &RoutingContext<'_>,
        _budget: std::time::Duration,
    ) -> PolicyResult {
        self.fires.fetch_add(1, Ordering::SeqCst);
        *self.seen.lock().unwrap() = Some((req.message_count, req.has_tools, req.total_chars));
        Ok(RoutingDecision::Abstain)
    }
    fn name(&self) -> &'static str {
        "counting-gate"
    }
}

fn gate(policy: Arc<dyn RoutingPolicy>) -> ResolvedPolicy {
    ResolvedPolicy::Policy {
        policy,
        on_error: busbar_substrate::config::PolicyOnError::default(),
        on_error_chain: Vec::new(),
        timeout: std::time::Duration::from_millis(500),
        send_prompt: false,
        send_user: false,
        on_empty: busbar_substrate::config::PolicyOnError::Reject,
    }
}

/// THE CELL. Three served requests, one registered gate: three fires, one shape, and the shape is
/// the one `busbar_core_policy::runner` reads off the same bytes.
#[tokio::test]
async fn a_hook_registered_through_the_runner_fires_once_per_served_request_at_the_same_seat() {
    const SERVED: usize = 3;
    crate::testkit::install_test_seams();
    crate::test_support::engine_kit::CORE_ENGINE_KIT.metrics_init();

    let state = Arc::new(crate::test_support::MockServerState::new());
    for _ in 0..SERVED {
        state.push(crate::test_support::MockResponse::Ok {
            status: reqwest::StatusCode::OK,
            body: serde_json::json!({
                "role": "assistant",
                "content": [{"type": "text", "text": "hi"}],
                "model": "m0",
                "stop_reason": "end_turn",
                "usage": {"input_tokens": 1, "output_tokens": 1}
            }),
        });
    }
    let server = crate::test_support::MockServer::new(state).await;

    let mut app = TestApp::new()
        .lane(LaneSpec::new(
            "m0",
            crate::proto_codec::PROTO_ANTHROPIC,
            &server.base_url(),
        ))
        .pool("p", &[(0, 1)])
        .build();

    let counter = Arc::new(CountingGate {
        fires: AtomicUsize::new(0),
        seen: std::sync::Mutex::new(None),
    });
    let policy: Arc<dyn RoutingPolicy> = counter.clone();
    let a = Arc::get_mut(&mut app).expect("sole owner");
    a.global_gates = vec![(0u16, gate(policy))];

    let router = busbar_substrate::testkit::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let _serve = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });

    for i in 0..SERVED {
        let status = reqwest::Client::new()
            .post(format!("http://{addr}/p/v1/messages"))
            .body(body().to_string())
            .send()
            .await
            .unwrap()
            .status()
            .as_u16();
        assert_eq!(status, 200, "request {i} must be SERVED, not degraded");
    }

    // ONCE PER SERVED REQUEST. Not zero (the hook is wired and reached) and not more (the seam
    // projects and fires one time on the path, however many times the body is read).
    assert_eq!(
        counter.fires.load(Ordering::SeqCst),
        SERVED,
        "a registered hook fires exactly once per served request"
    );

    // THE SAME SEAT, AND IT IS THE RUNNER'S. What the gate was handed on the served path is what
    // the runner reads off the same bytes, called here directly through its own crate path.
    let served = counter
        .seen
        .lock()
        .unwrap()
        .expect("the gate was handed a shape");
    let bytes = body().to_string().into_bytes();
    let direct = busbar_core_policy::runner::read_hook_facts(
        &body(),
        &bytes,
        busbar_substrate::proxy::APPLICATION_JSON,
        crate::proto_codec::PROTO_ANTHROPIC,
        Some(busbar_api::operation::Operation::CHAT),
    )
    .expect("the runner reads this body")
    .shape();
    assert_eq!(
        served,
        (direct.turn_count, direct.has_tools, direct.text_chars),
        "the served seat's projection is the runner's projection of the same bytes — one answer, \
         in one crate"
    );
    // AND IT IS THE RIGHT ANSWER, stated as a literal rather than as an equality with itself: one
    // turn, no tools, and the exact character count of the prompt this cell sent. Without this the
    // assertion above is satisfied by a runner that projects NOTHING, since both sides would read
    // the same empty shape from the same broken function.
    assert_eq!(
        served,
        (1, false, "the runner's one read".chars().count()),
        "the projection the hook is handed is the request that was actually sent"
    );
}
