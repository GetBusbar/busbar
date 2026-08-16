// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! KILL-THE-UPSTREAM, A2A relay — the audit's degenerate fast-fail cell, on ALL THREE bindings.
//!
//! The relay mounts the breaker beneath the transport axis (one admission in `prepare`, one
//! recording on every hop exit), so JsonRpc, HttpJson and Grpc are covered by ONE mechanism — and
//! this file proves that claim rather than asserting it, by running the same battery under each
//! binding's card through the REAL router (`relay_harness`, `crate::build_router`).
//!
//! The claims are the owner-decided breaker-across-planes renderings and the audit's test rows:
//!
//! 1. TRIP: a backend hard-down (401) opens the ONE core cell for the agent.
//! 2. FAST-FAIL: the SECOND submission is refused in milliseconds and the dead backend's recorder
//!    shows ZERO new traffic.
//! 3. THE RENDERING: the task yields `rejected` — the spec's own "we did not accept this work",
//!    never `failed` — and the caller still gets a task id to poll, plus `503` + `Retry-After`.
//!
//! RED before the wiring: the relay re-asked trust and never availability, every failure was a
//! busbar-attributed `502`, the second call reached the dead backend again, and no task was ever
//! `rejected`.

use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::relay_harness::{envelope, harness_on, Harness, BACKEND, BACKEND_ADDR};
use crate::a2a::fetch::{FetchPolicy, HttpResponse, Resolver};
use crate::a2a::relay::{
    ChunkFlow, RelayCall, RelayRefusal, RelaySeam, RelayTransport, StreamHead, BINDING_GRPC,
    BINDING_HTTP_JSON, BINDING_JSONRPC,
};
use crate::store::PlaneBreakers;

// ══ THE UNIT HALF: the relay records into the ONE core cell, and it opens ════════════════════════

struct PublicResolver;
impl Resolver for PublicResolver {
    fn resolve(&self, _host: &str) -> Result<Vec<IpAddr>, String> {
        Ok(vec![BACKEND_ADDR])
    }
}

struct AlwaysDelegable;
impl crate::a2a::relay::DelegationGate for AlwaysDelegable {
    fn still_delegable(
        &self,
        _agent_id: &str,
        _admitted: u64,
    ) -> Result<(), crate::a2a::relay::NotDelegable> {
        Ok(())
    }
}

/// A backend that answers every hop with one status — and COUNTS the hops, because "the dead
/// backend was never touched again" is an assertion on the upstream's own counter, per the audit.
struct CountingDenier {
    status: u16,
    hits: AtomicUsize,
}
impl RelayTransport for CountingDenier {
    fn send(
        &self,
        _m: &str,
        _u: &reqwest::Url,
        _a: IpAddr,
        _h: &[(String, String)],
        _b: &[u8],
    ) -> Result<HttpResponse, String> {
        self.hits.fetch_add(1, Ordering::SeqCst);
        Ok(HttpResponse {
            status: self.status,
            location: None,
            body: b"denied".to_vec(),
            peer_spki: None,
            client_identity_offered: false,
        })
    }
    fn post_stream(
        &self,
        _u: &reqwest::Url,
        _a: IpAddr,
        _h: &[(String, String)],
        _b: &[u8],
        _c: &mut (dyn FnMut(&[u8]) -> ChunkFlow + Send),
    ) -> Result<StreamHead, String> {
        self.hits.fetch_add(1, Ordering::SeqCst);
        Ok(StreamHead {
            status: self.status,
            content_type: "text/plain".to_string(),
            body: b"denied".to_vec(),
        })
    }
}

struct Seam<'a> {
    policy: FetchPolicy,
    transport: &'a CountingDenier,
}
impl RelaySeam for Seam<'_> {
    fn resolver(&self) -> &dyn Resolver {
        &PublicResolver
    }
    fn transport(&self) -> &dyn RelayTransport {
        self.transport
    }
    fn policy(&self) -> &FetchPolicy {
        &self.policy
    }
}

fn a_call<'a>(
    breakers: &'a Arc<PlaneBreakers>,
    rpc_id: &'a serde_json::Value,
    policy: &'a FetchPolicy,
) -> RelayCall<'a> {
    RelayCall {
        agent_id: "planner",
        backend_url: BACKEND,
        lease: None,
        gate: &AlwaysDelegable,
        admitted_generation: 0,
        body: br#"{"jsonrpc":"2.0","id":1,"method":"message/send","params":{}}"#,
        rpc_id,
        policy,
        a2a_version: "0.3",
        framing: crate::a2a::relay::default_framing(),
        breakers: Some(Arc::clone(breakers)),
    }
}

/// A 401 from the backend is recorded through the plane's Stage-1 normalizer into the ONE core
/// cell (Auth → HardDown → the cell opens on the FIRST failure), and the SECOND hop is refused
/// `BreakerOpen` in milliseconds with the dead backend's counter unmoved.
#[test]
fn a_backend_hard_down_opens_the_core_cell_and_the_second_hop_never_reaches_the_wire() {
    let breakers = Arc::new(PlaneBreakers::new());
    let transport = CountingDenier {
        status: 401,
        hits: AtomicUsize::new(0),
    };
    let seam = Seam {
        policy: FetchPolicy::default(),
        transport: &transport,
    };
    let rpc_id = serde_json::json!(1);
    let policy = FetchPolicy::default();

    let first = crate::a2a::relay::relay(&a_call(&breakers, &rpc_id, &policy), &seam, 1_000);
    assert!(
        matches!(first, Err(RelayRefusal::Status { status: 401, .. })),
        "{first:?}"
    );
    assert_eq!(transport.hits.load(Ordering::SeqCst), 1);
    assert!(
        matches!(
            breakers.state(&PlaneBreakers::agent_key("planner")),
            crate::store::BreakerState::Open { .. }
        ),
        "the agent's cell must be Open after a definitive backend failure"
    );

    let t0 = Instant::now();
    let second = crate::a2a::relay::relay(&a_call(&breakers, &rpc_id, &policy), &seam, 1_000);
    let elapsed = t0.elapsed();
    match second {
        Err(RelayRefusal::BreakerOpen {
            agent_id,
            retry_after_secs,
        }) => {
            assert_eq!(agent_id, "planner");
            assert!(retry_after_secs >= 1);
        }
        other => panic!("a tripped agent must refuse BreakerOpen, got {other:?}"),
    }
    assert!(
        elapsed < Duration::from_secs(1),
        "the refusal must be milliseconds, took {elapsed:?}"
    );
    assert_eq!(
        transport.hits.load(Ordering::SeqCst),
        1,
        "the dead backend must never be touched again"
    );
}

// ══ THE INGRESS HALF: `rejected` + a task id + 503/Retry-After, per BINDING ══════════════════════

/// The busbar task id a refusal names, read from the `google.rpc.ResourceInfo` entry in
/// `error.data` — the same place a conformant client reads it.
fn task_id_of(body: &serde_json::Value) -> String {
    body["error"]["data"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|e| e["resourceType"] == "a2a.busbar/task")
        .and_then(|e| e["resourceName"].as_str())
        .unwrap_or_else(|| panic!("the refusal must name the task: {body}"))
        .to_string()
}

/// `call` with the RESPONSE HEADERS kept, because `Retry-After` is a header.
async fn call_with_headers(
    h: &Harness,
    body: &serde_json::Value,
) -> (u16, reqwest::header::HeaderMap, serde_json::Value) {
    let resp = reqwest::Client::new()
        .post(format!("http://{}/a2a/agents/planner", h.addr))
        .header("authorization", format!("Bearer {}", h.bearer))
        .header("content-type", "application/json")
        .json(body)
        .send()
        .await
        .expect("the call completes");
    let status = resp.status().as_u16();
    let headers = resp.headers().clone();
    (
        status,
        headers,
        resp.json().await.unwrap_or(serde_json::Value::Null),
    )
}

/// One binding's whole battery: trip on the first submission, then assert the second is `503` +
/// `Retry-After`, carries a task id, leaves that task `rejected` in busbar's own store, and never
/// reaches the recording transport again. `submission` is the binding-appropriate spelling: the
/// gRPC leg transcodes the v1.0 verb set, exactly as the client-leg battery submits it.
async fn battery(binding: &str, submission: serde_json::Value) {
    let h = harness_on(
        super::relay_harness::Outcome::Answers(401, "denied".to_string()),
        binding,
    )
    .await;

    // Submission 1 reaches the dying backend: a busbar-attributed failure, and the trip.
    let (s1, b1) = super::relay_harness::call_agent(&h, "planner", &submission).await;
    assert_eq!(s1, 502, "the first failure is the hop's: {b1}");
    let hits_after_first = h.sent().len();
    assert!(
        hits_after_first >= 1,
        "the first submission must reach the transport"
    );

    // Submission 2: the audit's timing claim plus the §5 rendering, all on outputs.
    let t0 = Instant::now();
    let (s2, headers, b2) = call_with_headers(&h, &submission).await;
    let elapsed = t0.elapsed();
    assert!(
        elapsed < Duration::from_secs(1),
        "[{binding}] a tripped agent must refuse in <1s, took {elapsed:?}"
    );
    assert_eq!(s2, 503, "[{binding}] {b2}");
    let retry_after: u64 = headers
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| panic!("[{binding}] the refusal carries Retry-After: {b2}"));
    assert!(retry_after >= 1);
    assert_eq!(
        h.sent().len(),
        hits_after_first,
        "[{binding}] the dead backend's recorder must show zero new traffic"
    );

    // `rejected`, with an id to poll: the row predates the hop, the refusal names it, and busbar's
    // own store holds the terminal state the spec reserves for work that was never accepted.
    let task_id = task_id_of(&b2);
    let task = crate::a2a::taskstore::TASKS
        .get_unscoped(&task_id)
        .unwrap_or_else(|| panic!("[{binding}] the named task must resolve in busbar's store"));
    assert_eq!(
        task.state,
        crate::a2a::task::TaskState::Rejected,
        "[{binding}] a breaker refusal is `rejected` — we did not accept this work — never `failed`"
    );
}

#[tokio::test]
async fn a_tripped_agent_rejects_fresh_submissions_on_the_jsonrpc_binding() {
    battery(BINDING_JSONRPC, envelope()).await;
}

#[tokio::test]
async fn a_tripped_agent_rejects_fresh_submissions_on_the_httpjson_binding() {
    battery(BINDING_HTTP_JSON, envelope()).await;
}

#[tokio::test]
async fn a_tripped_agent_rejects_fresh_submissions_on_the_grpc_binding() {
    // The v1.0 spelling, which is what the gRPC leg transcodes — the same submission the
    // client-leg battery drives this binding with.
    battery(
        BINDING_GRPC,
        serde_json::json!({
            "jsonrpc": "2.0", "id": 7, "method": "SendMessage",
            "params": {
                "message": {
                    "messageId": "m-1",
                    "role": "ROLE_USER",
                    "parts": [{ "text": "PLAN THE MIGRATION" }]
                }
            }
        }),
    )
    .await;
}
