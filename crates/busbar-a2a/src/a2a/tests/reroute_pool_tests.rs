// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! KILL-THE-UPSTREAM-MID-POOL, A2A relay — the failover seam mounted at ADMISSION TIME
//! (`agent_pools:` → `failover::walk` in `receive`, ONE selection above the binding axis), proven
//! through the REAL router against a recording seam fronting two backends.
//!
//! The claims, each an observable behaviour of this plane:
//!
//! 1. REROUTE ON TRIP: member A hard-down → the next FRESH submission is served by member B, with
//!    A's trip recorded and A untouched on the second call (the recorder's per-host log is the
//!    witness). Run under BOTH JSON-RPC and gRPC cards — the selection sits above the framing, so
//!    two bindings through one battery is the same one-mechanism claim the fast-fail battery made.
//! 2. PINNING IS SEMANTICS, NOT A DODGE: an accepted task's verbs go to the member that accepted
//!    it — a task rerouted to B at submission is READ at B even when the caller addresses the
//!    pool's primary — and when the pinned member is tripped, the verb gets the breaker refusal
//!    (503 + `Retry-After`, task row NOT ended) and is NEVER dispatched to a twin.
//! 3. THE PIN RULE: a member approved under a different card fingerprint is refused
//!    (`rejected`, with an id), and nothing is dispatched to it.
//! 4. DISPOSITION: a true client-fault answer (400) never penalizes the member.
//!
//! Each was watched RED with the pool declaration neutralized (selection degenerate): no twin
//! answer, no pinned re-target, no pool cell — the un-pooled breaker unit's behaviour exactly.

use std::time::{Duration, Instant};

use super::relay_harness::{
    a_card_on, approve_card, backend_ok_for, envelope, harness_full, Harness, Outcome, BACKEND,
};
use crate::a2a::relay::BINDING_GRPC;

/// The twin backend's endpoint — a SECOND `.test` host, so the recorder's per-host log can tell
/// the two members' traffic apart.
const BACKEND_B: &str = "https://backend-b.agent.test/a2a";

/// One gRPC frame, as a backend answers it — the same three lines the client-leg battery carries,
/// for the same reason: a healthy gRPC backend answers frames, not JSON.
fn grpc_frame<M: prost::Message>(message: &M) -> Vec<u8> {
    let len = prost::Message::encoded_len(message);
    let mut out = vec![0u8];
    out.extend_from_slice(
        &(u32::try_from(len).expect("a test fixture fits in a frame")).to_be_bytes(),
    );
    prost::Message::encode(message, &mut out).expect("the message encodes");
    out
}

/// A healthy gRPC backend's `SendMessageResponse`, latin-1-smuggled into the `String` fixture the
/// recording transport carries (byte-for-byte; see the client-leg battery's identical note).
fn grpc_send_answer() -> String {
    let frame = grpc_frame(&a2a_pb::proto::SendMessageResponse {
        payload: Some(a2a_pb::proto::send_message_response::Payload::Task(
            a2a_pb::proto::Task {
                id: "BACKEND-OWN-TASK-ID".to_string(),
                context_id: "BACKEND-OWN-CONTEXT".to_string(),
                status: Some(a2a_pb::proto::TaskStatus {
                    state: a2a_pb::proto::TaskState::Completed as i32,
                    ..Default::default()
                }),
                ..Default::default()
            },
        )),
    });
    frame.iter().map(|b| *b as char).collect()
}

/// Twin deployment: `planner-a`/`planner-b` in pool `planner`, member A answering `a_status`, B
/// healthy. Both registrations are approved against the SAME card, so their fingerprints agree —
/// which is what makes them interchangeable.
async fn pool_harness(a_status: u16) -> Harness {
    pool_harness_answering(a_status, backend_ok_for(serde_json::json!(7))).await
}

/// The same deployment with the healthy twin's answer chosen by the test — the gRPC battery hands
/// it a protobuf frame instead of the JSON-RPC document.
async fn pool_harness_answering(a_status: u16, b_answer: String) -> Harness {
    harness_full(
        Outcome::AnswersByHost(vec![
            (
                "backend.agent.test".to_string(),
                a_status,
                "denied".to_string(),
            ),
            ("backend-b.agent.test".to_string(), 200, b_answer),
        ]),
        false,
        &["planner-a", "planner-b"],
        None,
        &[("planner-a", BACKEND), ("planner-b", BACKEND_B)],
        &[("planner", &["planner-a", "planner-b"])],
    )
    .await
}

fn hits(h: &Harness, host: &str) -> usize {
    h.sent().iter().filter(|r| r.url.contains(host)).count()
}

async fn submit(
    h: &Harness,
    agent: &str,
    body: &serde_json::Value,
) -> (u16, reqwest::header::HeaderMap, serde_json::Value) {
    let resp = reqwest::Client::new()
        .post(format!("http://{}/a2a/agents/{agent}", h.addr))
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

/// One binding's whole reroute battery — the trip-then-reroute instrument (claim 1 above).
async fn reroute_battery(h: Harness, submission: serde_json::Value) {
    // SUBMISSION 1 walks to the primary (lane 0), which answers a definitive 401: the hop fails
    // as it always did (busbar-attributed 502), and A's trip lands on the POOL cell at A's lane.
    let (s1, _, b1) = submit(&h, "planner-a", &submission).await;
    assert_eq!(s1, 502, "the first failure is the hop's: {b1}");
    assert_eq!(hits(&h, "backend.agent.test"), 1);
    assert_eq!(hits(&h, "backend-b.agent.test"), 0);
    assert!(
        matches!(
            h.app.plane_breakers.state_at("agent:planner", 0),
            busbar_substrate::store::BreakerState::Open { .. }
        ),
        "A's trip is recorded on the pool cell at A's lane"
    );

    // SUBMISSION 2: the walk refuses A's Open cell at ADMISSION — before any socket — and admits
    // B. The caller gets a completed task from the TWIN, in milliseconds of selection overhead,
    // and the dead member's recorder shows zero new traffic.
    let t0 = Instant::now();
    let (s2, _, b2) = submit(&h, "planner-a", &submission).await;
    assert!(t0.elapsed() < Duration::from_secs(5));
    assert_eq!(s2, 200, "the twin serves the rerouted submission: {b2}");
    assert!(
        b2.get("result").is_some(),
        "a served submission has a result: {b2}"
    );
    assert_eq!(
        hits(&h, "backend.agent.test"),
        1,
        "A untouched on the second call"
    );
    assert!(hits(&h, "backend-b.agent.test") >= 1);
}

/// THE EQUALITY-CELL INSTRUMENT (`failover-reroute × a2a-client`), JSON-RPC binding.
#[tokio::test]
async fn a_tripped_pool_primary_reroutes_a_fresh_submission_to_the_twin_and_stays_untouched() {
    reroute_battery(pool_harness(401).await, envelope()).await;
}

/// The same battery under the gRPC card — the selection sits ABOVE the binding axis, so the same
/// mechanism serves the v1.0 verb set with nothing re-decided.
#[tokio::test]
async fn a_tripped_pool_primary_reroutes_a_fresh_submission_on_the_grpc_binding() {
    let h = pool_harness_answering(401, grpc_send_answer()).await;
    let card = a_card_on(BINDING_GRPC);
    h.plane.with_registrations_mut(|regs| {
        for reg in regs.iter_mut() {
            approve_card(reg, card.clone());
        }
    });
    reroute_battery(
        h,
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

/// THE PINNING SEMANTICS — both halves of the audit's task-affinity row:
///
/// (a) a task the walk routed to B at submission is READ at B, even though the caller addresses
///     the pool primary's name;
/// (b) with the pinned member tripped, the task-scoped verb gets the breaker refusal (503 +
///     `Retry-After`), the task row is NOT ended, and NO twin sees a byte of task-scoped traffic —
///     failover is an admission-time choice, never a migration.
#[tokio::test]
async fn an_accepted_task_stays_pinned_to_its_member_and_a_tripped_pin_refuses_the_verb() {
    let h = pool_harness(401).await;

    // Trip A, then submit: accepted at B (the reroute), with busbar's task id in the answer.
    let (_, _, _) = submit(&h, "planner-a", &envelope()).await;
    let (s2, _, b2) = submit(&h, "planner-a", &envelope()).await;
    assert_eq!(s2, 200, "{b2}");
    let task_id = b2
        .pointer("/result/id")
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| panic!("the accepted task has busbar's id: {b2}"))
        .to_string();

    // (a) tasks/get, addressed to the PRIMARY's name: the row's recorded member is B, so the read
    // relays to B — never to A, whose recorder stays at its single (tripping) hit.
    let b_before = hits(&h, "backend-b.agent.test");
    let get = serde_json::json!({
        "jsonrpc": "2.0", "id": 9, "method": "tasks/get", "params": { "id": task_id }
    });
    let (sg, _, bg) = submit(&h, "planner-a", &get).await;
    assert_eq!(sg, 200, "{bg}");
    assert_eq!(
        hits(&h, "backend.agent.test"),
        1,
        "task-scoped traffic never reaches the tripped/unpinned member"
    );
    assert!(
        hits(&h, "backend-b.agent.test") > b_before,
        "the read went to the member that holds the task"
    );

    // (b) Trip B (the pinned member) and ask again: the verb is REFUSED with the breaker's own
    // rendering — and NOT rerouted to A, whose recorder must not move.
    h.app.plane_breakers.force_open(
        "agent:planner",
        1,
        busbar_substrate::store::now().saturating_add(600),
    );
    let a_hits = hits(&h, "backend.agent.test");
    let b_hits = hits(&h, "backend-b.agent.test");
    let (sr, headers, br) = submit(&h, "planner-a", &get).await;
    assert_eq!(sr, 503, "a tripped pinned member refuses the verb: {br}");
    assert!(
        headers.get(reqwest::header::RETRY_AFTER).is_some(),
        "the refusal carries Retry-After from the cell's own deadline"
    );
    assert_eq!(hits(&h, "backend.agent.test"), a_hits, "no migration to A");
    assert_eq!(
        hits(&h, "backend-b.agent.test"),
        b_hits,
        "nothing dispatched"
    );
    // The task row survives the refusal: a failed READ must not end live work.
    let task = busbar_core::plane::taskstore::TASKS
        .get_unscoped(&task_id)
        .expect("the task row survives a refused verb");
    // The engine is `TaskRow`-neutral; `state` is the canonical token string.
    assert_ne!(task.state, "rejected");
    assert_ne!(task.state, "failed");
}

/// THE PIN RULE: `planner-b` approved under a DIFFERENT card fingerprint is not interchangeable —
/// the submission is `rejected` with an id, the refusal says why, and B is never dispatched to.
#[tokio::test]
async fn a_member_approved_under_a_different_card_fingerprint_is_refused_never_dispatched() {
    let h = pool_harness(401).await;
    // Re-approve B under a drifted fingerprint: the operator's same-deployment claim is now false.
    h.plane.with_registrations_mut(|regs| {
        for reg in regs.iter_mut() {
            if reg.agent_id == "planner-b" {
                let digests =
                    crate::a2a::card::skill_digests(&super::relay_harness::a_card()).expect("d");
                let sighting =
                    busbar_substrate::trust::Sighting::Seen(busbar_substrate::trust::Observation {
                        pin: Some(crate::a2a::pin::CardPin::JwsIssuerKey {
                            issuer_key: "KEY".to_string(),
                            card_fingerprint: "sha256/A-DIFFERENT-CARD".to_string(),
                        }),
                        capabilities: digests,
                    });
                reg.approval = busbar_substrate::trust::Approval::registered();
                crate::a2a::pin::approve_registration(&mut reg.approval, &sighting, None)
                    .expect("approve");
                reg.sighting = sighting;
            }
        }
    });

    let (_, _, _) = submit(&h, "planner-a", &envelope()).await; // trips A
    let (s2, _, b2) = submit(&h, "planner-a", &envelope()).await;
    assert_eq!(s2, 503, "{b2}");
    let message = b2
        .pointer("/error/message")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    assert!(
        message.contains("not interchangeable"),
        "the refusal says why: {b2}"
    );
    assert_eq!(
        hits(&h, "backend-b.agent.test"),
        0,
        "nothing is dispatched to a member busbar cannot show is the same deployment"
    );
}

/// DISPOSITION (`disposition × a2a-client`): a true 4xx from the backend is the REQUEST's fault —
/// `ClientFault` through the one classifier — so the member is never penalized: no trip, and the
/// next submission still dispatches to it.
#[tokio::test]
async fn a_client_fault_answer_never_penalizes_the_agent() {
    let h = pool_harness(400).await;

    let (_, _, _) = submit(&h, "planner-a", &envelope()).await;
    assert!(
        matches!(
            h.app.plane_breakers.state_at("agent:planner", 0),
            busbar_substrate::store::BreakerState::Closed
        ),
        "a 400 is the request's fault, never the member's"
    );
    let (_, _, _) = submit(&h, "planner-a", &envelope()).await;
    assert_eq!(
        hits(&h, "backend.agent.test"),
        2,
        "an unpenalized member keeps receiving its own traffic"
    );
    assert_eq!(hits(&h, "backend-b.agent.test"), 0);
}
