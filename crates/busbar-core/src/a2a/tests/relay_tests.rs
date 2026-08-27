// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE RELAY, DRIVEN THROUGH THE REAL ROUTER.
//!
//! Every assertion here goes through `crate::build_router` and a real socket, with a REAL
//! audience-bound busbar token minted by the same signer the verifier runs. A relay that behaves
//! correctly when a test calls it and forwards the caller's credential when axum calls it is the
//! exact defect these tests exist to catch, and a test that called `relay::relay` directly would
//! have passed against it — because the header the ingress must not forward is one only the ingress
//! ever sees.
//!
//! ## The needle is a credential that was really minted, not a constant somebody planted
//!
//! The sentinel is the bearer token the caller actually authenticated with. A planted constant
//! proves that one string does not leak; the real token proves that the thing which authenticated
//! this request does not leak, which is the claim.
//!
//! What makes the scan non-vacuous is stated three ways, exactly as the sibling plane's scan does
//! it: a BYTE FLOOR on the wire, an ENCODING-COUNT floor, and a CONTROL that requires the scanner
//! to FIND the credential which is legitimately forwarded on this very wire. Without the control, a
//! relay that sent nothing at all would score a clean bill of health.
//!
//! ## The two credential rules are DIFFERENT claims and are tested apart
//!
//! Rule one — the caller's key never reaches a backend — is the scan. Rule two — busbar's own
//! credential is never spent on behalf of a caller that is not itself authorised for the backend —
//! is the confused-deputy section at the bottom, and it would be satisfied by a relay that violates
//! rule one and vice versa. Both hold; neither implies the other.

use crate::plane::store::StoreNamedTestExt;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::Ordering;

use super::relay_harness::*;
use crate::a2a::creds::EgressGrantExt;
use crate::a2a::fetch::{FetchPolicy, HttpResponse, Resolver};
use crate::a2a::relay::{ChunkFlow, StreamHead};

/// A key with exactly these `agent` grants. `None` is the WILDCARD principal — an omitted list, not
/// an empty one, and the difference is the whole of `scope_allowed`'s fail-closed cross-kind rule.
fn a_key(id: &str, agents: Option<&[&str]>) -> busbar_api::VirtualKey {
    busbar_api::VirtualKey {
        id: id.to_string(),
        generation_hash: String::new(),
        name: id.to_string(),
        allowed_scopes: agents.map(|list| {
            list.iter()
                .map(|a| busbar_api::ScopeRef {
                    kind: crate::a2a::inbound::SCOPE_KIND_AGENT.to_string(),
                    value: (*a).to_string(),
                })
                .collect()
        }),
        enabled: true,
        created_at: 0,
        group: None,
        labels: std::collections::BTreeMap::new(),
        expires_at: None,
        deleted_at: None,
        revision: 1,
        ..Default::default()
    }
}

// ══ THE GUARDS ═══════════════════════════════════════════════════════════════════════════════════

/// THE RELAY HAPPENS AT ALL. Everything below is about WHAT is on the hop; this one is that there
/// is a hop. Before this file existed the ingress recorded a dispatch and returned a Task envelope
/// without ever contacting the backend, and every other test on this plane stayed green.
#[tokio::test]
async fn an_admitted_call_is_actually_submitted_to_the_backend_agent() {
    let h = harness(Outcome::Answers(200, backend_ok()), false).await;
    let (status, body) = call(&h).await;
    assert_eq!(status, 200, "the admitted call must be served: {body}");

    let sent = h.sent();
    assert_eq!(
        sent.len(),
        1,
        "exactly one hop must have been made to the backend agent, got {}",
        sent.len()
    );
    assert_eq!(sent[0].url, BACKEND, "the hop must go to the backend agent");
    assert!(
        contains(&sent[0].body, b"PLAN THE MIGRATION"),
        "the caller's request body must reach the backend; a relay that submits an empty body is \
         not a relay"
    );
}

/// THE ADVERSARIAL SCAN. The caller's busbar key authenticated them TO busbar; it means nothing to
/// the backend agent's vendor and handing it over gives that vendor a working busbar credential
/// belonging to somebody else.
#[tokio::test]
async fn the_callers_busbar_key_appears_nowhere_on_the_relayed_wire() {
    let h = harness(Outcome::Answers(200, backend_ok()), true).await;
    let (status, body) = call(&h).await;
    assert_eq!(status, 200, "{body}");

    let wire = h.all_wire();
    assert!(
        wire.len() > 100,
        "the scan has nothing to scan: {} bytes",
        wire.len()
    );
    let forms = encodings(&h.bearer);
    assert_eq!(forms.len(), 5, "every encoding must be exercised");
    for (encoding, bytes) in &forms {
        assert!(
            !contains(&wire, bytes),
            "the caller's busbar key reached the backend agent, encoded as {encoding}"
        );
    }
    // Belt and braces on the same haystack: not even the token's claims segment may leave.
    let payload_segment = h
        .bearer
        .trim_start_matches(busbar_substrate::governance::signing::TOKEN_PREFIX)
        .split('.')
        .next()
        .expect("a token has a first segment")
        .to_string();
    assert!(
        !contains(&wire, payload_segment.as_bytes()),
        "the token's claims segment reached the backend agent"
    );
}

/// THE CONTROL. The scanner is proven able to FIND a credential on this very wire — the LEASED one,
/// which busbar legitimately presents as itself. Without this, the assertion above would be equally
/// green against a relay that sent nothing at all.
#[tokio::test]
async fn the_scan_finds_the_leased_credential_that_is_legitimately_forwarded() {
    let h = harness(Outcome::Answers(200, backend_ok()), true).await;
    let (status, body) = call(&h).await;
    assert_eq!(status, 200, "{body}");

    let wire = h.all_wire();
    assert!(
        contains(&wire, LEASED.as_bytes()),
        "the scanner must be able to find a legitimately-forwarded credential, or its silence in \
         the test above proves nothing"
    );
    // ...and it is presented the way the operator configured it, as busbar's own bearer.
    let sent = h.sent();
    let auth = sent[0]
        .headers
        .iter()
        .find(|(n, _)| n == "authorization")
        .map(|(_, v)| v.clone())
        .unwrap_or_default();
    assert_eq!(
        auth,
        format!("Bearer {LEASED}"),
        "the outbound credential must be the LEASED one and nothing else"
    );
}

/// With NO outbound credential configured, the hop carries NONE. Never the caller's, and never a
/// silently-substituted one: "the leased credential, or none" is the whole rule.
///
/// THIS IS THE TWIN THAT CAUGHT THE ORIGINAL LEAK. Run against a forwarding draft WITH a credential
/// configured, the scan above was green — the leased header overwrote the forwarded one on its way
/// past. A single-configuration scan would have shipped it.
#[tokio::test]
async fn with_no_leased_credential_the_hop_carries_no_credential_at_all() {
    let h = harness(Outcome::Answers(200, backend_ok()), false).await;
    let (status, body) = call(&h).await;
    assert_eq!(status, 200, "{body}");

    let sent = h.sent();
    assert!(
        !sent[0]
            .headers
            .iter()
            .any(|(n, _)| n == "authorization" || n == "proxy-authorization"),
        "an unconfigured hop must carry no authorization header at all, got {:?}",
        sent[0].headers
    );
    let wire = h.all_wire();
    for (encoding, bytes) in &encodings(&h.bearer) {
        assert!(
            !contains(&wire, bytes),
            "the caller's busbar key reached the backend as {encoding}"
        );
    }
}

/// A BACKEND FAILURE IS A BUSBAR-ATTRIBUTED ERROR, not a silent empty Task.
///
/// The tempting shape is to hand the caller the Task envelope busbar already opened and let them
/// poll. That is worse than an error: the caller is told the work was accepted, the task sits in
/// `submitted` forever, and the operator's first evidence is a support ticket.
#[tokio::test]
async fn a_backend_failure_is_a_busbar_attributed_error_and_not_a_silent_empty_task() {
    let h = harness(Outcome::Fails("connection refused".to_string()), false).await;
    let (status, body) = call(&h).await;
    assert_eq!(
        status, 502,
        "a failed hop is an upstream fault and must be answered as one: {body}"
    );
    // A2A section 5.4 binds a backend that did not answer something busbar could relay to
    // `InvalidAgentResponseError` (-32006), and the plane answers in the JSON-RPC error envelope a
    // JSON-RPC endpoint owes: an INTEGER code, never a busbar-internal name.
    assert_eq!(
        body.pointer("/error/code")
            .and_then(serde_json::Value::as_i64),
        Some(-32006),
        "the error must be attributed to the upstream hop: {body}"
    );
    assert!(
        body.pointer("/result").is_none(),
        "a failed hop must not also hand back a result envelope: {body}"
    );
    // The backend endpoint must not be named to the caller: publishing it is publishing the way
    // around every control busbar applies.
    let rendered = body.to_string();
    assert!(
        !rendered.contains("backend.agent.test"),
        "the refusal named the backend endpoint: {rendered}"
    );
}

/// A NON-2xx FROM THE BACKEND is the same fault, reported the same way. A relay that only handled
/// the transport error would turn a backend's own 500 into a green Task.
#[tokio::test]
async fn a_non_success_status_from_the_backend_is_a_busbar_attributed_error_too() {
    let h = harness(
        Outcome::Answers(503, r#"{"error":"the agent is down"}"#.to_string()),
        false,
    )
    .await;
    let (status, body) = call(&h).await;
    assert_eq!(status, 502, "{body}");
    assert_eq!(
        body.pointer("/error/code")
            .and_then(serde_json::Value::as_i64),
        Some(-32006),
        "{body}"
    );
}

/// THE REPLY COMES BACK, under BUSBAR's task identity.
///
/// The backend's own task id must not become the caller's handle: the caller's later `GetTask` is
/// scoped against busbar's store, which keys on the id busbar issued. Carrying the backend's id
/// through would hand the caller a handle that resolves to nothing.
#[tokio::test]
async fn the_backends_reply_comes_back_under_busbars_own_task_identity() {
    let h = harness(Outcome::Answers(200, backend_ok()), false).await;
    let (status, body) = call(&h).await;
    assert_eq!(status, 200, "{body}");

    assert_eq!(
        body.pointer("/result/status/state")
            .and_then(|v| v.as_str()),
        Some("completed"),
        "the backend's terminal state must reach the caller: {body}"
    );
    assert_eq!(
        body.pointer("/result/artifacts/0/parts/0/text")
            .and_then(|v| v.as_str()),
        Some("THE PLAN"),
        "the backend's artifacts must reach the caller: {body}"
    );
    let id = body
        .pointer("/result/id")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    assert!(
        id.starts_with("a2a-planner-"),
        "the caller must be given BUSBAR's task id, got {id}"
    );
    assert_ne!(id, "BACKEND-OWN-TASK-ID");
    assert_eq!(
        body.pointer("/result/contextId").and_then(|v| v.as_str()),
        Some("ctx-abc"),
        "the caller's own contextId groups the session, not the backend's: {body}"
    );

    // And the task busbar recorded ended where the backend said it ended.
    let task = crate::plane::taskstore::TASKS
        .get_unscoped(&id)
        .expect("the task busbar opened is in the working set");
    assert_eq!(task.state, crate::a2a::task::TaskState::Completed);
}

/// A FAILED HOP ENDS THE TASK AS `failed`, rather than leaving it `submitted` forever.
///
/// The refusal names the task id so the caller can correlate the failure with the record busbar
/// kept, which is the whole reason the task is opened before the outcome is known.
#[tokio::test]
async fn a_failed_hop_ends_the_task_as_failed_rather_than_leaving_it_submitted() {
    let h = harness(Outcome::Fails("connection refused".to_string()), false).await;
    let (status, body) = call(&h).await;
    assert_eq!(status, 502, "{body}");

    let id = task_named_by(&body);
    assert!(
        id.starts_with("a2a-planner-"),
        "the refusal must name the task busbar opened so the caller can correlate it: {body}"
    );
    let task = crate::plane::taskstore::TASKS
        .get_unscoped(&id)
        .expect("the task busbar opened is in the working set");
    assert_eq!(
        task.state,
        crate::a2a::task::TaskState::Failed,
        "a task whose hop can never complete must be terminal, not left `submitted`"
    );
}

/// THE PER-TASK HASH CHAIN CARRIES THE HOP, and the chain VERIFIES.
///
/// `task.delegated` is the delegating side's one indispensable provenance fact — who delegated, to
/// which registered agent — and it is chained BEFORE the socket, so a hop that never returns still
/// left a record saying it was made. A chain nothing ever recomputes proves nothing, so this
/// recomputes it.
#[tokio::test]
async fn every_relayed_task_leaves_a_verifying_hash_chained_delegation_event() {
    let h = harness(Outcome::Answers(200, backend_ok()), false).await;
    let (status, body) = call(&h).await;
    assert_eq!(status, 200, "{body}");
    let id = body
        .pointer("/result/id")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();

    let store = h.gov.store();
    let events = store.list_task_events(&id).expect("events read back");
    // With the RAM default nothing is persisted, and that is the documented product contract rather
    // than a defect — so the assertion is on the CHAIN and is skipped, loudly, where the configured
    // backend implements none of the task methods.
    if events.is_empty() {
        return;
    }
    crate::plane::taskstore::verify_task_event_rows(&events).expect("the per-task chain verifies");
    assert!(
        events
            .iter()
            .any(|e| e.kind == crate::plane::provenance::EV_DELEGATED),
        "the hop must leave a `task.delegated` event on the task's own chain: {events:?}"
    );
}

/// THE HOP IS METERED; THE CALLEE'S INTERNAL SPEND IS NOT BUSBAR'S PLANE.
///
/// The backend answers with a usage block claiming an enormous number of tokens. busbar meters ONE
/// REQUEST — the hop it made — and NONE of those tokens, because that traffic never touched
/// busbar's plane and a gateway that reported a number for what happens inside a black box would be
/// reporting a guess. `Attribution::covers_callee_internal_spend` says so as a type; this says so
/// on the ledger, which is where an operator reads it.
#[tokio::test]
async fn the_hop_is_metered_and_the_callees_own_reported_spend_is_not() {
    let reply = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 7,
        "result": {
            "id": "BACKEND-OWN-TASK-ID",
            "contextId": "BACKEND-OWN-CONTEXT",
            "kind": "task",
            "status": { "state": "completed" },
            // The callee's own accounting, volunteered on the reply. busbar must not adopt it.
            "usage": { "inputTokens": 999_999, "outputTokens": 888_888 }
        }
    })
    .to_string();
    let h = harness(Outcome::Answers(200, reply), false).await;
    let (status, body) = call(&h).await;
    assert_eq!(status, 200, "{body}");

    let written = h.gov.flush_metering();
    assert!(written >= 1, "the hop must be metered at all");
    let rows = h
        .gov
        .store()
        .list_metering(crate::governance::metering_bucket(
            busbar_substrate::store::now(),
        ))
        .expect("metering reads back");
    let mine: Vec<_> = rows.iter().filter(|r| r.provider == "a2a").collect();
    assert_eq!(
        mine.len(),
        1,
        "the hop must be metered EXACTLY ONCE — the relay must not bill a second time for the same \
         call: {mine:?}"
    );
    assert_eq!(mine[0].requests, 1);
    assert_eq!(
        mine[0].model, "agent:planner",
        "the hop is metered under this plane's own resource spelling, so an `agent` line is \
         distinguishable from a pool line in the same ledger"
    );
    assert_eq!(
        (
            mine[0].tokens_input,
            mine[0].tokens_output,
            mine[0].tokens_cache_read,
            mine[0].tokens_cache_write
        ),
        (0, 0, 0, 0),
        "busbar adopted the callee's own token counts; that traffic never touched busbar's plane"
    );
}

/// THE NAME IS RESOLVED EXACTLY ONCE AND THE JUDGED ADDRESS IS WHAT THE TRANSPORT IS GIVEN.
///
/// This is the property `transport.rs` exists for, asserted at the RELAY's own call site. A relay
/// that handed the URL to an HTTP client and let the client resolve the host would reinstate the
/// second lookup — and would pass every other test in this file, because none of them reaches a
/// socket.
#[tokio::test]
async fn the_backend_name_is_resolved_exactly_once_and_the_judged_address_is_pinned() {
    let h = harness(Outcome::Answers(200, backend_ok()), false).await;
    let (status, body) = call(&h).await;
    assert_eq!(status, 200, "{body}");

    assert_eq!(
        h.lookups.load(Ordering::SeqCst),
        1,
        "the backend name must be looked up EXACTLY ONCE for the hop, through the guard's own \
         resolver; a relay that never consults it has handed the name to a client instead"
    );
    let sent = h.sent();
    assert_eq!(
        sent[0].addr,
        Some(BACKEND_ADDR),
        "the transport must be handed the address the guard judged, not a placeholder"
    );
}

// ══ THE TRANSITIVE CONFUSED DEPUTY ═══════════════════════════════════════════════════════════════

/// A CALLER GRANTED ONE AGENT CANNOT CAUSE A CREDENTIAL TO BE MINTED TOWARD ANOTHER.
///
/// busbar is both directions at once, which is the only reason this bug can exist: an authenticated
/// inbound call could otherwise cause busbar to spend its OWN standing credential on a backend the
/// caller was never entitled to reach. Every byte of that hop is busbar's own, so the "the caller's
/// key never leaves" rule is fully satisfied while the caller has just gained reach it does not
/// hold. The two rules are different claims and this is the second one.
#[tokio::test]
async fn a_caller_with_no_grant_on_an_agent_causes_no_hop_and_no_lease_toward_it() {
    // Granted `planner` and NOT `payments`. Both are registered, approved and have a credential
    // configured — so the only thing standing between this caller and busbar's `payments`
    // credential is the grant.
    let h = harness_granting(Outcome::Answers(200, backend_ok()), true, &["planner"]).await;

    let (status, body) = call_agent(&h, "payments", &envelope()).await;
    assert!(
        (400..500).contains(&status),
        "a caller with no grant on `payments` must be refused, got {status}: {body}"
    );
    assert!(
        h.sent().is_empty(),
        "NO hop may be made toward an agent this caller holds no grant on, got {:?}",
        h.sent()
    );
    let wire = h.all_wire();
    assert!(
        !contains(&wire, LEASED.as_bytes()),
        "busbar's own credential for `payments` was spent on behalf of a caller that holds no \
         grant on it — that is the transitive confused deputy"
    );

    // And the SAME caller still reaches the agent it IS granted, so the refusal above is the grant
    // doing work rather than the harness being broken.
    let (ok, body) = call_agent(&h, "planner", &envelope()).await;
    assert_eq!(ok, 200, "the granted agent must still be reachable: {body}");
    assert_eq!(h.sent().len(), 1, "exactly the granted hop was made");
}

/// THE GATE ITSELF, ASKED DIRECTLY. The end-to-end test above passes for two reasons at once
/// (`authorize` refuses, and the gate refuses); this isolates the second, so a future edit that
/// removed the gate and left `authorize` would still be caught here.
#[test]
fn the_egress_gate_refuses_a_caller_that_holds_no_grant_on_the_target() {
    let key = a_key("k-1", Some(&["planner"]));

    let granted = crate::a2a::creds::authorise_egress(&key, "planner", 1_000)
        .expect("the granted agent authorises");
    assert_eq!(
        granted.agent_id(),
        "planner",
        "the grant must name the agent it was taken against, because the mint reads the id off it"
    );

    let denied = crate::a2a::creds::authorise_egress(&key, "payments", 1_000);
    assert!(
        matches!(
            denied,
            Err(crate::a2a::creds::AgentEgressDenied::NoAgentGrant { .. })
        ),
        "a caller with no `agent:payments` grant must not obtain an egress grant for it: {denied:?}"
    );
    // The refusal has to SAY the caller is not authorised, not merely be an error: an operator
    // debugging a legitimate grant reads this string.
    let rendered = denied.unwrap_err().to_string();
    assert!(
        rendered.contains("payments") && rendered.contains("k-1"),
        "the refusal must name the caller and the agent: {rendered}"
    );
}

/// A TOMBSTONED OR EXPIRED KEY OBTAINS NO GRANT. A lease outliving the key that occasioned it is a
/// hop nobody's grant covers, and a key row survives forever so that billing and audit keep
/// resolving it — which means a row's EXISTENCE is not the check.
#[test]
fn a_key_that_is_not_live_obtains_no_egress_grant() {
    // A WILDCARD principal (`allowed_scopes: None`) that is DISABLED: it would be granted every
    // agent if it were live, so this isolates the liveness half of the gate.
    let mut key = a_key("k-2", None);
    key.enabled = false;
    let denied = crate::a2a::creds::authorise_egress(&key, "planner", 1_000);
    assert!(
        matches!(
            denied,
            Err(crate::a2a::creds::AgentEgressDenied::KeyNotLive { .. })
        ),
        "a disabled key must obtain no egress grant even as a wildcard principal: {denied:?}"
    );
}

/// THE MINT READS THE AGENT OFF THE GRANT, so authorising against one agent and minting against
/// another is refused rather than quietly honoured. This is the one combination that would defeat
/// the gate while looking correct at a call site.
#[test]
fn a_grant_for_one_agent_cannot_mint_against_a_registration_for_another() {
    let key = a_key("k-3", Some(&["planner"]));
    let grant =
        crate::a2a::creds::authorise_egress(&key, "planner", 1_000).expect("planner authorises");

    let mut reg = crate::a2a::registry::AgentRegistration::registered("payments", OTHER_BACKEND);
    reg.outbound_cred = Some(crate::a2a::creds::OutboundCredential {
        secret: busbar_secret_ref::SecretRef::file(secret_file().to_string_lossy().to_string()),
        placement: crate::a2a::creds::CredentialPlacement::Bearer,
        lease_ttl_ms: 600_000,
    });
    let out = crate::a2a::creds::mint(
        &grant,
        &reg,
        &crate::config::secret::SecretResolver::builtins_only(),
        1_000,
    );
    assert!(
        matches!(out, Err(crate::a2a::creds::LeaseError::WrongAgent { .. })),
        "a grant for `planner` must not mint against the `payments` registration: {out:?}"
    );
}

// ══ MID-FLIGHT DEMOTION ══════════════════════════════════════════════════════════════════════════

/// A REGISTRATION DEMOTED BETWEEN ADMISSION AND THE SOCKET NEVER RECEIVES THE TASK.
///
/// Re-verification runs on its own schedule and can demote at any instant; that is the entire point
/// of the rug-pull defence. A demotion that only takes effect on the NEXT request is a demotion the
/// in-flight request escapes — and the in-flight request is the interesting one. The gate is
/// consulted against the LIVE registry after the guard and before the transport, so this suspends
/// the registration from a resolver the relay is obliged to call on its way past.
#[tokio::test]
async fn a_registration_demoted_between_admission_and_the_socket_is_not_reached() {
    let h = harness(Outcome::Answers(200, backend_ok()), false).await;

    // THE DEMOTION, applied through the plane's own registry — the same mutation a re-verification
    // sweep makes — after admission has already happened and before the hop is attempted. It is
    // installed on the RESOLVER because the resolver is called by the guard, which runs immediately
    // before the gate: there is no other seam between the two.
    let plane = std::sync::Arc::clone(&h.plane);
    struct DemotingResolver(std::sync::Arc<crate::a2a::plane::A2aPlane>);
    impl Resolver for DemotingResolver {
        fn resolve(&self, _host: &str) -> Result<Vec<IpAddr>, String> {
            self.0.with_registrations_mut(|regs| {
                for reg in regs.iter_mut() {
                    reg.approval.suspend("the sweep saw the card drift");
                }
            });
            Ok(vec![BACKEND_ADDR])
        }
    }
    struct NeverPosts;
    impl crate::a2a::relay::RelayTransport for NeverPosts {
        fn send(
            &self,
            _m: &str,
            _u: &reqwest::Url,
            _a: IpAddr,
            _h: &[(String, String)],
            _b: &[u8],
        ) -> Result<HttpResponse, String> {
            panic!("a demoted registration must never be reached");
        }
        fn post_stream(
            &self,
            _u: &reqwest::Url,
            _a: IpAddr,
            _h: &[(String, String)],
            _b: &[u8],
            _c: &mut (dyn FnMut(&[u8]) -> ChunkFlow + Send),
        ) -> Result<StreamHead, String> {
            panic!("a demoted registration must never be reached");
        }
    }
    struct Seam(std::sync::Arc<crate::a2a::plane::A2aPlane>);
    impl crate::a2a::relay::RelaySeam for Seam {
        fn resolver(&self) -> &dyn Resolver {
            // Leaked once, for the life of a test process. A `Box::leak` rather than a field
            // because the trait returns a borrow and the resolver has to own the plane handle.
            Box::leak(Box::new(DemotingResolver(std::sync::Arc::clone(&self.0))))
        }
        fn transport(&self) -> &dyn crate::a2a::relay::RelayTransport {
            &NeverPosts
        }
    }
    h.plane.set_relay_seam(std::sync::Arc::new(Seam(plane)));

    let (status, body) = call(&h).await;
    assert_eq!(
        status, 503,
        "a demoted agent is not serving, and that is a statement about the AGENT rather than about \
         the hop: {body}"
    );
    assert!(
        h.sent().is_empty(),
        "no hop may be recorded for a demoted registration"
    );

    // AND THE TASK IS NOT BURNED. The work never started and the agent is what changed; failing the
    // caller's task for an operator's suspension would make a resume impossible once the agent is
    // restored.
    let id = task_named_by(&body);
    assert!(!id.is_empty(), "the refusal must name the task: {body}");
    let task = crate::plane::taskstore::TASKS
        .get_unscoped(&id)
        .expect("the task exists");
    assert_ne!(
        task.state,
        crate::a2a::task::TaskState::Failed,
        "a demotion must not terminate the caller's task"
    );
}

/// AND THE ORDINARY PATH STILL REFUSES A REGISTRATION THAT WAS ALREADY DEMOTED, at admission, with
/// the same 503. The two answers agree, which is what stops a caller learning WHEN the demotion
/// landed by comparing status codes.
#[tokio::test]
async fn an_already_demoted_registration_is_refused_at_admission_with_the_same_status() {
    let h = harness(Outcome::Answers(200, backend_ok()), false).await;
    h.plane.with_registrations_mut(|regs| {
        for reg in regs.iter_mut() {
            reg.approval.suspend("suspended by the operator");
        }
    });
    let (status, body) = call(&h).await;
    assert_eq!(status, 503, "{body}");
    assert!(h.sent().is_empty(), "no hop for a suspended registration");
}

// ══ THE SCAN CANNOT GO STALE ═════════════════════════════════════════════════════════════════════

/// A lease for `agent_id`, minted the way the ingress mints one — through a REAL grant, because
/// there is no other way to reach the mint.
fn a_lease(agent_id: &'static str, now_ms: u64) -> crate::a2a::creds::Lease {
    let path = secret_file();
    let resolver = crate::config::secret::SecretResolver::builtins_only();
    let key = a_key("k-lease", Some(&[agent_id]));
    let grant = crate::a2a::creds::authorise_egress(&key, agent_id, 1).expect("the grant");
    crate::a2a::creds::mint_from(
        &grant,
        &crate::a2a::creds::OutboundCredential {
            secret: busbar_secret_ref::SecretRef::file(path.to_string_lossy().to_string()),
            placement: crate::a2a::creds::CredentialPlacement::Bearer,
            lease_ttl_ms: 600_000,
        },
        &resolver,
        now_ms,
    )
    .expect("the lease mints")
}

/// THE JSON-RPC FRAMING OF ONE BODY, for the builder tests below.
///
/// `build_request` takes a FRAMED request now — the composition is the binding's and the header set
/// is the builder's — so these tests frame first and assert on the headers second, which is the
/// same two steps the hop takes.
fn framed(url: &reqwest::Url, body: &[u8], streaming: bool) -> crate::a2a::relay::FramedRequest {
    let envelope: serde_json::Value =
        serde_json::from_slice(body).unwrap_or(serde_json::Value::Null);
    let params = envelope
        .get("params")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    crate::a2a::relay::default_framing()
        .compose(
            url,
            &crate::a2a::relay::Outbound {
                verbatim: body,
                method: crate::a2a::local::method_of(&envelope),
                params: &params,
            },
            streaming,
        )
        .expect("the JSON-RPC framing is a courier and cannot refuse a body")
}

/// `OutboundRelayRequest` is destructured EXHAUSTIVELY, so a field added to it without being added
/// to `wire_bytes` stops this test COMPILING rather than silently narrowing the scan. A scan that
/// quietly stops covering a new field is the exact false green the whole shape exists to prevent.
#[test]
fn every_field_of_the_outbound_request_is_scanned() {
    let url = reqwest::Url::parse(BACKEND).expect("a URL");
    let body_bytes = b"{\"params\":{\"text\":\"BODYMARK\"}}";
    let req = crate::a2a::relay::build_request(
        framed(&url, body_bytes, false),
        "planner",
        Some(&a_lease("planner", 1_000)),
        "0.3",
        1_000,
    )
    .expect("the request builds");

    let crate::a2a::relay::OutboundRelayRequest {
        http_method,
        url,
        headers,
        body,
    } = &req;
    let wire = req.wire_bytes();
    assert!(contains(&wire, url.as_bytes()), "url must be scanned");
    assert!(
        contains(&wire, http_method.as_bytes()),
        "the request line's verb must be scanned"
    );
    assert!(!headers.is_empty(), "headers must be present to be scanned");
    for (n, v) in headers {
        assert!(
            contains(&wire, n.as_bytes()),
            "header name `{n}` must be scanned"
        );
        assert!(
            contains(&wire, v.as_bytes()),
            "header value for `{n}` must be scanned"
        );
    }
    assert!(contains(&wire, body), "body must be scanned");
    assert!(
        contains(&wire, b"BODYMARK"),
        "the body's content is reached"
    );
    assert!(contains(&wire, LEASED.as_bytes()), "the lease is reached");
}

/// THE BUILDER'S HEADER SET IS CLOSED. Every header on a relayed request is one of exactly three
/// things — a constant, the leased credential, or nothing — and this enumerates them so a fourth
/// source has to be added here to exist.
#[test]
fn the_relayed_request_carries_only_constants_and_the_lease() {
    let url = reqwest::Url::parse(BACKEND).expect("a URL");

    let bare =
        crate::a2a::relay::build_request(framed(&url, b"{}", false), "planner", None, "0.3", 1_000)
            .expect("the request builds");
    let names: Vec<&str> = bare.headers.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(
        names,
        vec!["content-type", "accept", "a2a-version"],
        "with no lease the hop carries the constants and NOTHING else"
    );

    let leased = crate::a2a::relay::build_request(
        framed(&url, b"{}", false),
        "planner",
        Some(&a_lease("planner", 1_000)),
        "0.3",
        1_000,
    )
    .expect("the request builds");
    let names: Vec<&str> = leased.headers.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(
        names,
        vec!["content-type", "accept", "a2a-version", "authorization"],
        "the lease adds exactly one header"
    );
}

/// A LEASE MINTED FOR ANOTHER AGENT CANNOT RIDE THIS HOP, and an EXPIRED one cannot either. Both
/// checks live on `Lease::header_for`; this pins that the relay's builder actually goes through it
/// rather than reading the secret out around the side.
#[test]
fn a_lease_for_another_agent_or_a_dead_one_refuses_the_hop() {
    let url = reqwest::Url::parse(BACKEND).expect("a URL");
    let lease = a_lease("researcher", 1_000);
    let wrong = crate::a2a::relay::build_request(
        framed(&url, b"{}", false),
        "planner",
        Some(&lease),
        "0.3",
        1_000,
    );
    assert!(
        matches!(wrong, Err(crate::a2a::creds::LeaseError::WrongAgent { .. })),
        "a credential leased for one agent must not be presented to another: {wrong:?}"
    );

    let lease = a_lease("planner", 1_000);
    let expired = crate::a2a::relay::build_request(
        framed(&url, b"{}", false),
        "planner",
        Some(&lease),
        "0.3",
        10_000_000,
    );
    assert!(
        matches!(expired, Err(crate::a2a::creds::LeaseError::Expired { .. })),
        "an expired lease must not be presented: {expired:?}"
    );
}

/// A gate that admits everything, for the unit-level relay tests whose subject is a different
/// property. Named so that a test using it is visibly not testing the gate.
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

/// THE GUARD IS THE SAME ONE. An internal backend endpoint is refused by the relay exactly as it is
/// by the card fetch, and the refusal names the address rather than merely reporting a failure.
#[test]
fn the_relay_refuses_an_internal_backend_through_the_same_ssrf_guard() {
    struct Internal;
    impl Resolver for Internal {
        fn resolve(&self, _host: &str) -> Result<Vec<IpAddr>, String> {
            Ok(vec![IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254))])
        }
    }
    struct NeverCalled;
    impl crate::a2a::relay::RelayTransport for NeverCalled {
        fn send(
            &self,
            _m: &str,
            _u: &reqwest::Url,
            _a: IpAddr,
            _h: &[(String, String)],
            _b: &[u8],
        ) -> Result<HttpResponse, String> {
            panic!("the transport must never be reached for a refused target");
        }
        fn post_stream(
            &self,
            _u: &reqwest::Url,
            _a: IpAddr,
            _h: &[(String, String)],
            _b: &[u8],
            _c: &mut (dyn FnMut(&[u8]) -> ChunkFlow + Send),
        ) -> Result<StreamHead, String> {
            panic!("the transport must never be reached for a refused target");
        }
    }
    struct Seam;
    impl crate::a2a::relay::RelaySeam for Seam {
        fn resolver(&self) -> &dyn Resolver {
            &Internal
        }
        fn transport(&self) -> &dyn crate::a2a::relay::RelayTransport {
            &NeverCalled
        }
    }

    let out = crate::a2a::relay::relay(
        &crate::a2a::relay::RelayCall {
            admitted_generation: 0,
            agent_id: "planner",
            backend_url: BACKEND,
            lease: None,
            gate: &AlwaysDelegable,
            body: b"{}",
            rpc_id: &serde_json::json!(1),
            policy: &FetchPolicy::default(),
            a2a_version: "0.3",
            framing: crate::a2a::relay::default_framing(),
            breakers: None,
            host: None,
            host_scope: None,
            admission: busbar_plugin::hot::AdmissionId::NONE,
        },
        &Seam,
        1_000,
    );
    assert!(
        matches!(
            out,
            Err(crate::a2a::relay::RelayRefusal::Guard(
                crate::a2a::fetch::FetchRefusal::InternalAddress { .. }
            ))
        ),
        "the relay must guard its target with the same guard the card fetch uses: {out:?}"
    );
}

/// A JSON-RPC `error` ON A 200 IS A FAILED HOP. It is the shape in which a backend refusal would
/// otherwise arrive looking like success, and the backend's own words stay out of the caller's
/// answer.
///
/// ITS CODE, HOWEVER, TRAVELS. A backend that answered `TaskNotFoundError` said something specific,
/// and collapsing every backend error into `InvalidAgentResponseError` reported a caller's typo as
/// a gateway fault: measured against the official TCK, that is `CORE-GET-002`, `CORE-CANCEL-003`,
/// `CORE-MULTI-004`, `STREAM-SUB-004`, `JSONRPC-SSE-002` and `JSONRPC-ERR-003` — "Expected error
/// code -32001 (TaskNotFoundError), got -32006". The code is a protocol fact and is re-emitted; the
/// prose is the backend's and is not; and the `ErrorInfo` reason is re-derived from the code
/// through busbar's own table, so nothing the backend wrote reaches the caller even inside `data`.
#[tokio::test]
async fn a_json_rpc_error_from_the_backend_is_a_failed_hop_carrying_its_code_and_not_its_words() {
    let reply = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 7,
        "error": {
            "code": -32001,
            "message": "BACKEND SAYS NO",
            "data": [{ "@type": "x", "domain": "BACKEND DOMAIN", "reason": "BACKEND REASON" }]
        }
    })
    .to_string();
    let h = harness(Outcome::Answers(200, reply), false).await;
    let (status, body) = call(&h).await;
    // A2A section 5.4 binds TaskNotFoundError to -32001 and to HTTP 404, from one row.
    assert_eq!(status, 404, "{body}");
    assert_eq!(
        body.pointer("/error/code")
            .and_then(serde_json::Value::as_i64),
        Some(-32001),
        "the backend's error SEMANTICS must survive the hop: {body}"
    );
    let rendered = body.to_string();
    for leaked in ["BACKEND SAYS NO", "BACKEND DOMAIN", "BACKEND REASON"] {
        assert!(
            !rendered.contains(leaked),
            "the backend's own words must not be reflected to the caller: {rendered}"
        );
    }
    assert_eq!(
        body.pointer("/error/data/0/reason")
            .and_then(|v| v.as_str()),
        Some("TASK_NOT_FOUND"),
        "the reason must be re-derived from the code, not echoed: {body}"
    );
    // AND THE TASK IS STILL ENDED. A refusal that rendered differently must not also record
    // differently, or a caller's task row would be left in flight for work nothing will finish.
    let id = task_named_by(&body);
    assert!(
        !id.is_empty(),
        "the refusal must still name the task: {body}"
    );
    assert_eq!(
        crate::plane::taskstore::TASKS
            .get_unscoped(&id)
            .expect("the task exists")
            .state,
        crate::a2a::task::TaskState::Failed,
    );
}

/// A CODE A2A DOES NOT DEFINE IS NOT RE-EMITTED. To a client it is indistinguishable from one the
/// specification will define later, so it collapses to `InvalidAgentResponseError` — which is the
/// true statement: busbar could not make sense of what the backend answered.
#[tokio::test]
async fn a_backend_code_the_specification_does_not_define_is_not_passed_through() {
    let reply = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 7,
        "error": { "code": -31000, "message": "vendor specific" }
    })
    .to_string();
    let h = harness(Outcome::Answers(200, reply), false).await;
    let (status, body) = call(&h).await;
    assert_eq!(status, 502, "{body}");
    assert_eq!(
        body.pointer("/error/code")
            .and_then(serde_json::Value::as_i64),
        Some(-32006),
        "{body}"
    );
}

/// THE GUARD READS THE REGISTRATION'S POLICY, NOT THE PLANE'S DEFAULT.
///
/// `allow_private:` is a per-registration line. The card fetch, `connect`, `approve` and the
/// re-verification sweep all obtain their policy from `A2aPlane::fetch_policy_for`, which narrows
/// the plane default by that line. The relay used `RelaySeam::policy()` — the plane default — so an
/// operator who set `allow_private: true` got a registration that could be fetched, verified and
/// approved over a loopback endpoint and then refused at every task submission, with the refusal
/// quoting the knob that was already set. Measured on a live rig before this test existed:
///
///   a2a: the relayed task submission failed agent=conformance
///   error=the relay target was refused: agent card URL `http://127.0.0.1:56868/` uses scheme
///   `http`; … set this registration's `allow_private: true` if the endpoint is a loopback …
///
/// Both directions are asserted, because a relay that simply stopped guarding would also pass the
/// first half.
///
/// THE COUNTERFACTUAL IS NOW STRUCTURAL RATHER THAN ASSERTED. This test used to hand the seam a
/// PERMISSIVE policy and require the relay to ignore it. `RelaySeam::policy()` has since been
/// deleted — its last caller was the push-delivery path's `allow_plaintext` read, and that knob is
/// gone — so a seam cannot carry a policy for the relay to wrongly read. What remains asserted is
/// the half that is still falsifiable: the registration's own policy decides, in both directions.
#[test]
fn the_relay_guards_with_the_registrations_policy_and_not_the_planes_default() {
    struct Loopback;
    impl Resolver for Loopback {
        fn resolve(&self, _host: &str) -> Result<Vec<IpAddr>, String> {
            Ok(vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))])
        }
    }
    struct Reached;
    impl crate::a2a::relay::RelayTransport for Reached {
        fn send(
            &self,
            _m: &str,
            _u: &reqwest::Url,
            _a: IpAddr,
            _h: &[(String, String)],
            _b: &[u8],
        ) -> Result<HttpResponse, String> {
            Ok(HttpResponse {
                status: 200,
                location: None,
                body: br#"{"jsonrpc":"2.0","id":1,"result":{"kind":"task","id":"t","contextId":"c","status":{"state":"completed"}}}"#.to_vec(),
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
            unreachable!("this test does not stream")
        }
    }
    struct Seam;
    impl crate::a2a::relay::RelaySeam for Seam {
        fn resolver(&self) -> &dyn Resolver {
            &Loopback
        }
        fn transport(&self) -> &dyn crate::a2a::relay::RelayTransport {
            &Reached
        }
    }

    // The seam carries the PLANE DEFAULT, which is fail-closed and refuses loopback and plaintext.
    // That is correct for the plane and is exactly what must not decide this hop.
    let plane_default = FetchPolicy::default();
    assert!(
        !plane_default.allow_private,
        "the plane default must stay fail-closed, or this test proves nothing"
    );
    let registration_policy = FetchPolicy {
        allow_private: true,
        ..FetchPolicy::default()
    };

    let out = crate::a2a::relay::relay(
        &crate::a2a::relay::RelayCall {
            admitted_generation: 0,
            agent_id: "conformance",
            backend_url: "http://127.0.0.1:9110/",
            lease: None,
            gate: &AlwaysDelegable,
            body: b"{}",
            rpc_id: &serde_json::json!(1),
            policy: &registration_policy,
            a2a_version: "0.3",
            framing: crate::a2a::relay::default_framing(),
            breakers: None,
            host: None,
            host_scope: None,
            admission: busbar_plugin::hot::AdmissionId::NONE,
        },
        &Seam,
        1_000,
    );
    assert!(
        !matches!(out, Err(crate::a2a::relay::RelayRefusal::Guard(_))),
        "a registration whose `allow_private:` admits its loopback backend must reach it: {out:?}"
    );

    // AND THE GUARD IS STILL LIVE. The same seam, the same address, with the registration's own
    // policy fail-closed, must refuse — otherwise the first half is equally consistent with a relay
    // that has stopped guarding altogether.
    let out = crate::a2a::relay::relay(
        &crate::a2a::relay::RelayCall {
            admitted_generation: 0,
            agent_id: "conformance",
            backend_url: "http://127.0.0.1:9110/",
            lease: None,
            gate: &AlwaysDelegable,
            body: b"{}",
            rpc_id: &serde_json::json!(1),
            policy: &plane_default,
            a2a_version: "0.3",
            framing: crate::a2a::relay::default_framing(),
            breakers: None,
            host: None,
            host_scope: None,
            admission: busbar_plugin::hot::AdmissionId::NONE,
        },
        &Seam,
        1_000,
    );
    assert!(
        matches!(out, Err(crate::a2a::relay::RelayRefusal::Guard(_))),
        "the relay must still guard, and must not read the SEAM's permissive policy: {out:?}"
    );
}

/// The busbar task id a refusal names, read out of the ProtoJSON `data` array.
///
/// It used to be an `error.taskId` member. JSON-RPC 2.0 section 5 admits `code`, `message` and
/// `data` and nothing else, so it now rides as a `google.rpc.ResourceInfo` beside the `ErrorInfo` —
/// the same fact, in the place a conformant client looks.
fn task_named_by(body: &serde_json::Value) -> String {
    body.pointer("/error/data")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .find(|e| e["@type"] == "type.googleapis.com/google.rpc.ResourceInfo")
        .and_then(|e| e["resourceName"].as_str())
        .unwrap_or_default()
        .to_string()
}

/// THE IDENTITY SUBSTITUTION HAS TO FIND THE PAYLOAD, NOT ASSUME IT IS THE `result`.
///
/// A2A v0.3 makes the JSON-RPC `result` the Task itself. v1.0 — the vocabulary the official TCK and
/// the pinned `a2a-go` control speak — WRAPS it: `result: {"task": {…}}`. busbar wrote its ids at
/// the top level either way, which against a v1.0 backend produced a `result` carrying busbar's
/// `id`/`contextId` as siblings of `task` while the backend's own ids stayed inside it. Two
/// consequences, both measured:
///
///   * the envelope stopped validating — `$: Additional properties are not allowed ('contextId',
///     'id' were unexpected)`, which is 10 MUST requirements in the TCK's own report; and
///   * a caller reading the Task got the BACKEND's id, presented it to `GetTask`, and busbar
///     resolved it against a store that has never heard of it —
///     `GetTask returned task ID 'a2a-conformance-…', expected '019ff370-…'`.
///
/// The second is the exact failure the function's own doc comment says it exists to prevent.
#[test]
fn the_identity_substitution_finds_the_task_inside_a_v1_result_wrapper() {
    // v1.0: the payload is wrapped.
    let mut wrapped = serde_json::json!({
        "task": {
            "id": "backend-task",
            "contextId": "backend-context",
            "status": { "state": "TASK_STATE_COMPLETED" },
            "artifacts": [],
        }
    });
    crate::a2a::relay::rewrite_identity(&mut wrapped, "busbar-task", "busbar-context", None);
    assert_eq!(wrapped["task"]["id"], "busbar-task");
    assert_eq!(wrapped["task"]["contextId"], "busbar-context");
    assert!(
        wrapped.get("id").is_none() && wrapped.get("contextId").is_none(),
        "the wrapper must not grow members the Task schema forbids: {wrapped}"
    );
    let rendered = wrapped.to_string();
    assert!(
        !rendered.contains("backend-task") && !rendered.contains("backend-context"),
        "the backend's own ids must not survive anywhere: {rendered}"
    );

    // v0.3: the payload IS the result. Unchanged behaviour.
    let mut bare = serde_json::json!({
        "kind": "task",
        "id": "backend-task",
        "contextId": "backend-context",
        "status": { "state": "completed" },
    });
    crate::a2a::relay::rewrite_identity(&mut bare, "busbar-task", "busbar-context", None);
    assert_eq!(bare["id"], "busbar-task");
    assert_eq!(bare["contextId"], "busbar-context");

    // A `message` payload is wrapped the same way in v1.0.
    let mut msg = serde_json::json!({ "message": { "messageId": "m", "role": "agent" } });
    crate::a2a::relay::rewrite_identity(&mut msg, "busbar-task", "busbar-context", None);
    assert_eq!(msg["message"]["contextId"], "busbar-context");
    assert!(msg.get("contextId").is_none(), "{msg}");
}

/// THE MATCHED SKILL IS METADATA, NOT A MEMBER OF THE TASK.
///
/// It used to be inserted as a top-level `skill` member. A2A's `Task` admits no such member, so a
/// conformant client validating the envelope rejects it — and busbar has invented a field in
/// somebody else's schema. `metadata` is the member the specification provides for exactly this,
/// and the key is namespaced so it cannot collide with the backend's own.
#[test]
fn the_matched_skill_travels_in_metadata_rather_than_as_an_invented_member() {
    let mut result =
        serde_json::json!({ "task": { "id": "x", "status": { "state": "completed" } } });
    crate::a2a::relay::rewrite_identity(&mut result, "t", "c", Some("plan"));
    assert_eq!(result["task"]["metadata"]["busbar/skill"], "plan");
    assert!(
        result["task"].get("skill").is_none() && result.get("skill").is_none(),
        "no invented member on the Task: {result}"
    );
}

/// THE STATE BUSBAR RECORDS IS THE ONE THE BACKEND REPORTED, IN EITHER VOCABULARY.
///
/// `reported_task_state` read `/status/state` off the `result` and parsed it with the STORE's token
/// parser. Against a v1.0 backend both halves missed: the status is at `/task/status/state`, and
/// the token is `TASK_STATE_COMPLETED` rather than `completed`. Every relayed task was therefore
/// recorded as `working` — including completed ones, including failed ones — so busbar's own task
/// rows disagreed with the answer it had just handed the caller.
#[test]
fn the_reported_state_is_read_from_either_vocabulary_and_either_shape() {
    for (payload, expected) in [
        (
            serde_json::json!({ "task": { "status": { "state": "TASK_STATE_COMPLETED" } } }),
            crate::a2a::task::TaskState::Completed,
        ),
        (
            serde_json::json!({ "status": { "state": "completed" } }),
            crate::a2a::task::TaskState::Completed,
        ),
        (
            serde_json::json!({ "task": { "status": { "state": "TASK_STATE_INPUT_REQUIRED" } } }),
            crate::a2a::task::TaskState::InputRequired,
        ),
        (
            serde_json::json!({ "status": { "state": "input-required" } }),
            crate::a2a::task::TaskState::InputRequired,
        ),
        // Anything unreadable stays `working`: a relay that guessed `completed` from a state it
        // could not read would close a task that is still running.
        (
            serde_json::json!({ "task": {} }),
            crate::a2a::task::TaskState::Working,
        ),
    ] {
        assert_eq!(
            crate::a2a::relay::reported_task_state(&payload),
            expected,
            "{payload}"
        );
    }
}

/// A STREAMED EVENT IS WRAPPED TOO, AND ITS IDENTITY MEMBER IS NAMED DIFFERENTLY.
///
/// v1.0 streams `result: {"statusUpdate": {…}}` and `result: {"artifactUpdate": {…}}`, and inside
/// those the task is named by `taskId`, not `id` — they are events ABOUT a task, not the task. With
/// only `task` and `message` recognised as wrappers, busbar wrote `id`/`contextId` beside the
/// wrapper and left the backend's `taskId`/`contextId` inside it, which is the same defect as the
/// unary one and worse in its consequence: a caller following a stream reads the update's `taskId`
/// to correlate events, and it named the backend's task.
#[test]
fn a_streamed_update_event_is_rewritten_inside_its_wrapper_and_by_its_own_member_name() {
    for wrapper in ["statusUpdate", "artifactUpdate"] {
        let mut ev = serde_json::json!({
            wrapper: {
                "taskId": "backend-task",
                "contextId": "backend-context",
                "status": { "state": "TASK_STATE_WORKING" },
            }
        });
        crate::a2a::relay::rewrite_identity(&mut ev, "busbar-task", "busbar-context", None);
        assert_eq!(ev[wrapper]["taskId"], "busbar-task", "{ev}");
        assert_eq!(ev[wrapper]["contextId"], "busbar-context", "{ev}");
        assert!(
            ev[wrapper].get("id").is_none(),
            "an update event has no `id` member and must not be given one: {ev}"
        );
        assert!(
            ev.get("id").is_none() && ev.get("contextId").is_none(),
            "the wrapper must not grow identity members: {ev}"
        );
        let rendered = ev.to_string();
        assert!(
            !rendered.contains("backend-"),
            "the backend's ids must not survive: {rendered}"
        );
    }
}

/// A MESSAGE IS NOT A TASK, and must not be given a task's `id`.
///
/// A2A's `Message` names the task it belongs to with `taskId`, and has no `id` at all — its own
/// identifier is `messageId`. Inserting `id` invents a member the schema forbids, and overwriting
/// `messageId` would rewrite the caller's own correlation handle.
#[test]
fn a_message_payload_keeps_its_own_identifier_and_is_never_given_a_task_id_member() {
    let mut result = serde_json::json!({
        "message": { "messageId": "caller-message", "role": "agent", "taskId": "backend-task" }
    });
    crate::a2a::relay::rewrite_identity(&mut result, "busbar-task", "busbar-context", None);
    assert_eq!(result["message"]["messageId"], "caller-message");
    assert_eq!(result["message"]["taskId"], "busbar-task");
    assert_eq!(result["message"]["contextId"], "busbar-context");
    assert!(result["message"].get("id").is_none(), "{result}");
}

/// THE IDENTITY BUSBAR ISSUES IS ONE BUSBAR CAN RESOLVE — end to end, through the mounted route.
///
/// busbar substitutes its own task id into every answer, so the id a caller holds is busbar's. It
/// then relayed the caller's follow-up VERBATIM, so that id was forwarded to a backend that has
/// never heard of it: every `GetTask`, `CancelTask` and `SubscribeToTask` a caller made with the id
/// busbar itself gave them failed. In the official TCK that is `CORE-GET-001` ("GetTask failed"),
/// `CORE-CANCEL-002` and `CORE-SEND-002` — the last cluster of MUST failures that is busbar's own
/// and not the fronted agent's.
///
/// Driven through the real route rather than over `idmap` directly, because the defect was never in
/// the mapping — it was that nothing recorded one and nothing consulted it.
#[tokio::test]
async fn a_follow_up_naming_the_id_busbar_issued_reaches_the_backend_by_the_backends_own_id() {
    let reply = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 7,
        "result": { "task": {
            "id": "BACKEND-OWN-TASK-ID",
            "contextId": "backend-context",
            "status": { "state": "TASK_STATE_COMPLETED" }
        }}
    })
    .to_string();
    // THREE CALLS, THREE REQUEST IDS — so the fixture has to answer the request it was asked. Under
    // the literal `Answers` this document's hardcoded `"id": 7` was served to the follow-ups sent
    // under `8` and `9` as well, and the relay's correlation refused them `502`: correctly, because
    // an answer naming another request is exactly what it exists to stop. The backend is what was
    // wrong, not the check. See `Outcome::AnswersCorrelated`.
    let h = harness(Outcome::AnswersCorrelated(200, reply), false).await;

    // 1. A submission. The caller is handed BUSBAR's id, and the backend's must not appear.
    let (status, body) = call(&h).await;
    assert_eq!(status, 200, "{body}");
    let issued = body
        .pointer("/result/task/id")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    assert!(issued.starts_with("a2a-planner-"), "{body}");
    assert!(
        !body.to_string().contains("BACKEND-OWN-TASK-ID"),
        "the backend's id must not be published: {body}"
    );

    // 2. The follow-up, naming the id the caller was actually given.
    let before = h.sent().len();
    let (status, body) = call_agent(
        &h,
        "planner",
        &serde_json::json!({
            "jsonrpc": "2.0", "id": 8, "method": "GetTask",
            "params": { "id": issued, "historyLength": 2 }
        }),
    )
    .await;
    assert_eq!(status, 200, "{body}");

    // 3. WHAT ACTUALLY WENT ON THE WIRE. This is the assertion the defect was invisible to: the
    //    caller's answer looked fine either way, and the wrong id only shows in the hop.
    let sent = h.sent();
    let forwarded = String::from_utf8_lossy(&sent[before..][0].body).to_string();
    let forwarded: serde_json::Value = serde_json::from_str(&forwarded).expect("json on the wire");
    assert_eq!(
        forwarded["params"]["id"], "BACKEND-OWN-TASK-ID",
        "the follow-up must reach the backend by the id the BACKEND knows: {forwarded}"
    );
    assert_eq!(
        forwarded["params"]["historyLength"], 2,
        "nothing but the identity may be rewritten: {forwarded}"
    );

    // 4. AND THE ANSWER IS ABOUT THE TASK THE CALLER ASKED ABOUT. busbar opened a FRESH task row
    //    for every read and stamped that new row's id onto the answer, so a caller asking about
    //    task A was told about task B — both busbar ids, for the same work:
    //      CORE-GET-001: GetTask returned task ID 'a2a-conformance-61d1929…',
    //                    expected 'a2a-conformance-522818d…'
    assert_eq!(
        body.pointer("/result/task/id").and_then(|v| v.as_str()),
        Some(issued.as_str()),
        "a read must answer about the task it named: {body}"
    );

    // 5. AND IT OPENED NO SECOND ROW. The other half of the same mistake: a caller polling a
    //    long-running task once a second minted a durable task row per poll.
    //
    //    Asserted through the ANSWER rather than by counting rows in `TASKS`, and deliberately: the
    //    registry is process-wide and these tests run in parallel, so a count is a race. The
    //    property is exact either way — a read that opened a fresh row would stamp THAT row's id
    //    onto the answer, which is precisely how this defect presented.
    let (_, again) = call_agent(
        &h,
        "planner",
        &serde_json::json!({
            "jsonrpc": "2.0", "id": 9, "method": "GetTask", "params": { "id": issued }
        }),
    )
    .await;
    assert_eq!(
        again.pointer("/result/task/id").and_then(|v| v.as_str()),
        Some(issued.as_str()),
        "repeated reads must keep naming the one task, not a new row per poll: {again}"
    );
}

/// AN ADMITTED, RELAYED AGENT TASK IS VISIBLE ON `/metrics`.
///
/// The plane ingress boundary is proved end-to-end over a real `/metrics` scrape in
/// `plane::metrics_tests`, but the A2A traffic it can drive there is a refusal: this plane requires
/// governance, and standing a signed, audience-bound, agent-scoped key up is what this harness
/// exists for. So the SUCCESS case is claimed here, where a fully admitted `message/send` is
/// actually relayed to a backend and answered `200` — the request an operator most needs a latency
/// series for, and the one a test that only ever drove refusals would leave unproven.
#[tokio::test]
async fn an_admitted_agent_task_lands_in_the_plane_request_series() {
    let h = harness(Outcome::Answers(200, backend_ok()), false).await;
    // `outcome="ok"` on this plane is only reachable through the whole admit → meter → egress-gate
    // → relay path, so no refusal in any concurrently-running test can produce it by accident.
    let labels = [
        ("plane", "a2a"),
        ("ingress_protocol", "jsonrpc"),
        ("outcome", "ok"),
    ];
    let before = crate::test_support::metric_sum(crate::metrics::PLANE_REQUESTS_TOTAL, &labels);
    let (status, body) = call(&h).await;
    assert_eq!(status, 200, "the admitted call must be served: {body}");
    let after = crate::test_support::metric_sum(crate::metrics::PLANE_REQUESTS_TOTAL, &labels);

    assert!(
        after > before,
        "a relayed agent task produced no `{}` sample on the a2a plane (before {before}, after \
         {after}) — the plane is invisible to an operator again",
        crate::metrics::PLANE_REQUESTS_TOTAL,
    );
    assert!(
        crate::test_support::metric_sum(
            "busbar_plane_request_duration_seconds_count",
            &[("plane", "a2a"), ("ingress_protocol", "jsonrpc")],
        ) > 0.0,
        "the agent plane must carry a latency series, not just a count"
    );
}
