//! The seat order of a migrated request-stage hook chain, observed end to end on a real ingress
//! path (real key auth, real admission, real engine): the admission door charges the request
//! first, then the global rewrite runs, then the request-stage taps observe the REWRITTEN request,
//! then the decision gates decide, and only after the gates does the candidate tap fire. A gate
//! reject refunds the billable request (the fee base) but keeps the admission count.
//!
//! Every seat is proven structurally rather than by wall-clock order where the seat is a detached
//! task (taps are fire-and-forget): the rewrite hook reads the ledger AT the moment it runs, the
//! request tap's payload carries the rewritten prompt, and a rejecting gate stops everything
//! seated after it — so a request tap that still arrives was seated before the gate and a
//! candidate tap that never arrives was seated after it.
use crate::test_support::{LaneSpec, TestApp};
use busbar_api::{
    Candidate, PolicyResult, RewriteReply, RoutingContext, RoutingDecision, RoutingPolicy,
    RoutingRequest, TransformOutcome,
};
use busbar_substrate::hooks::ResolvedPolicy;
use busbar_substrate::testkit::engine_kit::{EngineTestKit as _, TestAppKit};
use std::sync::{Arc, Mutex};

/// The marker the rewrite hook plants in the prompt; a tap payload carrying it saw the rewrite.
const REWRITTEN: &str = "rewritten-by-the-global-rewrite-seat";

/// One probe policy playing one seat: it appends its seat name to the shared log when it runs and
/// (for the rewrite seat) samples the key's admission count at that instant.
struct SeatProbe {
    seat: &'static str,
    log: Arc<Mutex<Vec<String>>>,
    /// Rewrite seat only: reads the key's `requests` count when the rewrite runs.
    requests_now: Option<Box<dyn Fn() -> u64 + Send + Sync>>,
    /// Gate seat only: the reject the gate answers with.
    reject: Option<(u16, &'static str)>,
    /// Tap seats: the last delivered projection.
    last_payload: Mutex<Option<Vec<u8>>>,
}

impl SeatProbe {
    fn new(seat: &'static str, log: &Arc<Mutex<Vec<String>>>) -> Self {
        Self {
            seat,
            log: log.clone(),
            requests_now: None,
            reject: None,
            last_payload: Mutex::new(None),
        }
    }
}

#[async_trait::async_trait]
impl RoutingPolicy for SeatProbe {
    async fn decide(
        &self,
        _req: &RoutingRequest<'_>,
        _candidates: &[Candidate<'_>],
        _ctx: &RoutingContext<'_>,
        _budget: std::time::Duration,
    ) -> PolicyResult {
        self.log.lock().unwrap().push(self.seat.to_string());
        Ok(match self.reject {
            Some((status, message)) => RoutingDecision::Reject {
                status,
                message: message.to_string(),
            },
            None => RoutingDecision::Abstain,
        })
    }
    fn name(&self) -> &'static str {
        self.seat
    }
    async fn transform(
        &self,
        _req: &RoutingRequest<'_>,
        _budget: std::time::Duration,
    ) -> TransformOutcome {
        let requests = self.requests_now.as_ref().map(|f| f());
        self.log
            .lock()
            .unwrap()
            .push(format!("{}:requests={:?}", self.seat, requests));
        TransformOutcome::Rewrite(RewriteReply {
            messages: vec![serde_json::json!({"role": "user", "content": REWRITTEN})],
            tools: vec![],
        })
    }
    async fn notify(&self, projection: &[u8], _budget: std::time::Duration) {
        self.log.lock().unwrap().push(self.seat.to_string());
        *self.last_payload.lock().unwrap() = Some(projection.to_vec());
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

/// Poll a tap probe until its detached delivery lands (bounded), or return `None`.
async fn delivered(tap: &SeatProbe, budget_ms: u64) -> Option<Vec<u8>> {
    for _ in 0..(budget_ms / 10) {
        if let Some(p) = tap.last_payload.lock().unwrap().clone() {
            return Some(p);
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    None
}

/// The key's ledger as the test reads it: (admission count, derived spend in cents, the durable
/// row's admission count, the durable row's billable count).
type Ledger = (u64, i64, u64, u64);

/// Governed fixture: a keys-chain data plane over an in-memory governance registry with one
/// signed key, one live anthropic lane in pool `p`, and the four probed seats installed.
struct Rig {
    addr: std::net::SocketAddr,
    secret: String,
    log: Arc<Mutex<Vec<String>>>,
    request_tap: Arc<SeatProbe>,
    candidate_tap: Arc<SeatProbe>,
    _serve: tokio::task::JoinHandle<()>,
    _server: crate::test_support::MockServer,
}

async fn rig(reject_at_gate: bool) -> (Rig, Arc<dyn Fn() -> Ledger + Send + Sync>) {
    crate::testkit::install_test_seams();
    crate::test_support::engine_kit::CORE_ENGINE_KIT.metrics_init();

    // A live lane that answers 200, so a served request (no gate reject) bills one fee.
    let state = Arc::new(crate::test_support::MockServerState::new());
    for _ in 0..2 {
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

    let store: Arc<dyn busbar_api::Store> = Arc::new(busbar_store_memory::MemoryStore::new());
    let signer = busbar_substrate::governance::signing::TokenSigner::from_secret_bytes(
        &[7u8; 32],
        busbar_substrate::governance::signing::DEFAULT_KID,
    );
    let gov_kit = crate::test_support::engine_kit::CORE_ENGINE_KIT
        .governance(store, None, Some(signer))
        .expect("governance");
    let (key, secret) = gov_kit
        .mint_signed(
            busbar_substrate::governance::NewKeySpec {
                name: "seats".to_string(),
                allowed_pools: None,
                group: None,
                labels: Default::default(),
                ..Default::default()
            },
            2_000_000_000,
            1_000_000_000,
        )
        .expect("mint");

    let mut builder = TestApp::new()
        .keys_chain()
        .lane(LaneSpec::new(
            "m0",
            crate::proto_codec::PROTO_ANTHROPIC,
            &server.base_url(),
        ))
        .pool("p", &[(0, 1)]);
    // The governance registry rides in through the neutral engine test kit seam.
    TestAppKit::set_governance(&mut builder, gov_kit);
    let mut app = builder.build();

    let log = Arc::new(Mutex::new(Vec::new()));
    // The ledger reader: the key's admission count and derived spend off the live cell, plus the
    // durable row (flushed on demand) where the admission and billable counts are stored apart.
    let gov = app.governance.clone().expect("governance is configured");
    let cost = app.cost.clone();
    let key_id = key.id.clone();
    let read: Arc<dyn Fn() -> Ledger + Send + Sync> = Arc::new(move || {
        let u = gov
            .usage_for(&cost, &key_id, busbar_substrate::store::now())
            .expect("usage read")
            .expect("the key exists");
        gov.flush_budgets();
        // Window 0 is the key's all-time bucket.
        let row = gov.store().get_usage(&key_id, 0).expect("ledger row");
        (
            u.requests,
            u.spend_cents,
            row.requests,
            row.billable_requests,
        )
    });
    let mut rewrite = SeatProbe::new("rewrite", &log);
    let read_for_rewrite = read.clone();
    rewrite.requests_now = Some(Box::new(move || read_for_rewrite().0));
    let request_tap = Arc::new(SeatProbe::new("request-tap", &log));
    let candidate_tap = Arc::new(SeatProbe::new("candidate-tap", &log));
    let mut gate_probe = SeatProbe::new("gate", &log);
    if reject_at_gate {
        gate_probe.reject = Some((451, "the gate says no"));
    }

    let a = Arc::get_mut(&mut app).expect("sole owner");
    a.rewrite_hooks = vec![(std::time::Duration::from_millis(500), Arc::new(rewrite))];
    // The request tap holds the prompt grant so its payload carries the (rewritten) messages.
    let rt: Arc<dyn RoutingPolicy> = request_tap.clone();
    a.tap_hooks = vec![(std::time::Duration::from_millis(500), true, rt, Vec::new())];
    let ct: Arc<dyn RoutingPolicy> = candidate_tap.clone();
    a.tap_hooks_candidate = vec![(std::time::Duration::from_millis(500), false, ct, Vec::new())];
    a.global_gates = vec![(0u16, gate(Arc::new(gate_probe)))];

    let router = busbar_substrate::testkit::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let serve = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (
        Rig {
            addr,
            secret,
            log,
            request_tap,
            candidate_tap,
            _serve: serve,
            _server: server,
        },
        read,
    )
}

async fn send(rig: &Rig) -> u16 {
    reqwest::Client::new()
        .post(format!("http://{}/p/v1/messages", rig.addr))
        .bearer_auth(&rig.secret)
        .body(
            serde_json::json!({"model": "p", "max_tokens": 16,
                "messages": [{"role": "user", "content": "the original prompt"}]})
            .to_string(),
        )
        .send()
        .await
        .unwrap()
        .status()
        .as_u16()
}

/// A rejecting decision gate: the admission charge, the rewrite and the request tap all happened
/// before it; the candidate tap never fires; the billable request is refunded and the admission
/// count is kept.
#[tokio::test]
async fn migrated_request_hook_seats_after_admit_before_candidate() {
    let (rig, read) = rig(true).await;
    let status = send(&rig).await;
    assert_eq!(status, 451, "the gate's reject is what the caller receives");

    // Admission door before rewrite: the rewrite seat saw the request already counted.
    let log = rig.log.lock().unwrap().clone();
    assert!(
        log.iter().any(|e| e == "rewrite:requests=Some(1)"),
        "the rewrite seat must run AFTER the admission door charged the request; log: {log:?}"
    );
    // Rewrite before the request tap: the tap's payload carries the rewritten prompt, and the tap
    // was delivered at all even though the gate rejected (so it was seated before the gate).
    let payload = delivered(&rig.request_tap, 2_000)
        .await
        .expect("the request-stage tap fires before the gate and is delivered despite the reject");
    let text = String::from_utf8_lossy(&payload);
    assert!(
        text.contains(REWRITTEN),
        "the request tap must observe the REWRITTEN request: {text}"
    );
    assert!(
        !text.contains("the original prompt"),
        "the request tap must not see the pre-rewrite prompt: {text}"
    );
    // The gate ran (it produced the 451) and the candidate tap, seated after the gates, never
    // fires on a rejected request.
    assert!(
        log.iter().any(|e| e == "gate"),
        "the gate seat ran; log: {log:?}"
    );
    assert!(
        delivered(&rig.candidate_tap, 300).await.is_none(),
        "the candidate tap is seated after the gates, so a gate reject must never reach it"
    );
    // The reject consumed the requests slot but refunded the fee base (the default cost model is a
    // flat 1-cent fee per billable request, so derived spend reads the billable count directly).
    let (requests, spend, row_requests, row_billable) = read();
    assert_eq!(requests, 1, "the admission count is never refunded");
    assert_eq!(
        spend, 0,
        "the billable request (the fee base) is refunded on a gate reject"
    );
    assert_eq!(
        (row_requests, row_billable),
        (1, 0),
        "the durable ledger row keeps the admission and drops the billable request"
    );
}

/// The positive twin: an abstaining gate lets the request through, the candidate tap fires AFTER
/// the gate decided, and a served request keeps its billable request (one fee).
#[tokio::test]
async fn candidate_tap_fires_after_an_abstaining_gate_and_a_served_request_bills_once() {
    let (rig, read) = rig(false).await;
    let status = send(&rig).await;
    assert_eq!(status, 200, "the live lane serves the request");
    assert!(
        delivered(&rig.candidate_tap, 2_000).await.is_some(),
        "the candidate tap fires on a request the gates let through"
    );
    let log = rig.log.lock().unwrap().clone();
    let gate_at = log.iter().position(|e| e == "gate").expect("the gate ran");
    let cand_at = log
        .iter()
        .position(|e| e == "candidate-tap")
        .expect("the candidate tap was delivered");
    let rewrite_at = log
        .iter()
        .position(|e| e.starts_with("rewrite:"))
        .expect("the rewrite ran");
    assert!(
        rewrite_at < gate_at && gate_at < cand_at,
        "seat order must be rewrite, gate, candidate tap; log: {log:?}"
    );
    let (requests, spend, row_requests, row_billable) = read();
    assert_eq!((requests, row_requests), (1, 1));
    assert_eq!(
        (spend, row_billable),
        (1, 1),
        "a served request keeps its one billable request (1-cent flat fee)"
    );
}
