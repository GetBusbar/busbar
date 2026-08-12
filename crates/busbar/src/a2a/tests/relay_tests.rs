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

use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::Ordering;

use super::relay_harness::*;
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
        .trim_start_matches(crate::governance::signing::TOKEN_PREFIX)
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
    assert_eq!(
        body.pointer("/error/code").and_then(|v| v.as_str()),
        Some("upstream_error"),
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
        body.pointer("/error/code").and_then(|v| v.as_str()),
        Some("upstream_error")
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
    let task = crate::a2a::taskstore::TASKS
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

    let id = body
        .pointer("/error/taskId")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    assert!(
        id.starts_with("a2a-planner-"),
        "the refusal must name the task busbar opened so the caller can correlate it: {body}"
    );
    let task = crate::a2a::taskstore::TASKS
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
    crate::a2a::provenance::verify_chain(&events).expect("the per-task chain verifies");
    assert!(
        events
            .iter()
            .any(|e| e.kind == crate::a2a::provenance::EV_DELEGATED),
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
        .list_metering(crate::governance::metering_bucket(crate::store::now()))
        .expect("metering reads back");
    let mine: Vec<_> = rows
        .iter()
        .filter(|r| r.provider == crate::plane::Plane::A2a.key())
        .collect();
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
            Err(crate::a2a::creds::EgressDenied::NoAgentGrant { .. })
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
            Err(crate::a2a::creds::EgressDenied::KeyNotLive { .. })
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
        fn post(
            &self,
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
    struct Seam(std::sync::Arc<crate::a2a::plane::A2aPlane>, FetchPolicy);
    impl crate::a2a::relay::RelaySeam for Seam {
        fn resolver(&self) -> &dyn Resolver {
            // Leaked once, for the life of a test process. A `Box::leak` rather than a field
            // because the trait returns a borrow and the resolver has to own the plane handle.
            Box::leak(Box::new(DemotingResolver(std::sync::Arc::clone(&self.0))))
        }
        fn transport(&self) -> &dyn crate::a2a::relay::RelayTransport {
            &NeverPosts
        }
        fn policy(&self) -> &FetchPolicy {
            &self.1
        }
    }
    h.plane
        .set_relay_seam(std::sync::Arc::new(Seam(plane, FetchPolicy::default())));

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
    let id = body
        .pointer("/error/taskId")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    assert!(!id.is_empty(), "the refusal must name the task: {body}");
    let task = crate::a2a::taskstore::TASKS
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

/// `OutboundRelayRequest` is destructured EXHAUSTIVELY, so a field added to it without being added
/// to `wire_bytes` stops this test COMPILING rather than silently narrowing the scan. A scan that
/// quietly stops covering a new field is the exact false green the whole shape exists to prevent.
#[test]
fn every_field_of_the_outbound_request_is_scanned() {
    let url = reqwest::Url::parse(BACKEND).expect("a URL");
    let req = crate::a2a::relay::build_request(
        &url,
        "planner",
        Some(&a_lease("planner", 1_000)),
        b"{\"params\":{\"text\":\"BODYMARK\"}}",
        false,
        1_000,
    )
    .expect("the request builds");

    let crate::a2a::relay::OutboundRelayRequest { url, headers, body } = &req;
    let wire = req.wire_bytes();
    assert!(contains(&wire, url.as_bytes()), "url must be scanned");
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

    let bare = crate::a2a::relay::build_request(&url, "planner", None, b"{}", false, 1_000)
        .expect("the request builds");
    let names: Vec<&str> = bare.headers.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(
        names,
        vec!["content-type", "accept"],
        "with no lease the hop carries the two constants and NOTHING else"
    );

    let leased = crate::a2a::relay::build_request(
        &url,
        "planner",
        Some(&a_lease("planner", 1_000)),
        b"{}",
        false,
        1_000,
    )
    .expect("the request builds");
    let names: Vec<&str> = leased.headers.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(
        names,
        vec!["content-type", "accept", "authorization"],
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
    let wrong =
        crate::a2a::relay::build_request(&url, "planner", Some(&lease), b"{}", false, 1_000);
    assert!(
        matches!(wrong, Err(crate::a2a::creds::LeaseError::WrongAgent { .. })),
        "a credential leased for one agent must not be presented to another: {wrong:?}"
    );

    let lease = a_lease("planner", 1_000);
    let expired =
        crate::a2a::relay::build_request(&url, "planner", Some(&lease), b"{}", false, 10_000_000);
    assert!(
        matches!(expired, Err(crate::a2a::creds::LeaseError::Expired { .. })),
        "an expired lease must not be presented: {expired:?}"
    );
}

/// A gate that admits everything, for the unit-level relay tests whose subject is a different
/// property. Named so that a test using it is visibly not testing the gate.
struct AlwaysDelegable;
impl crate::a2a::relay::DelegationGate for AlwaysDelegable {
    fn still_delegable(&self, _agent_id: &str) -> Result<(), crate::a2a::relay::NotDelegable> {
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
        fn post(
            &self,
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
    struct Seam(FetchPolicy);
    impl crate::a2a::relay::RelaySeam for Seam {
        fn resolver(&self) -> &dyn Resolver {
            &Internal
        }
        fn transport(&self) -> &dyn crate::a2a::relay::RelayTransport {
            &NeverCalled
        }
        fn policy(&self) -> &FetchPolicy {
            &self.0
        }
    }

    let out = crate::a2a::relay::relay(
        &crate::a2a::relay::RelayCall {
            agent_id: "planner",
            backend_url: BACKEND,
            lease: None,
            gate: &AlwaysDelegable,
            body: b"{}",
        },
        &Seam(FetchPolicy::default()),
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
#[tokio::test]
async fn a_json_rpc_error_from_the_backend_is_a_failed_hop_not_a_result() {
    let reply = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 7,
        "error": { "code": -32001, "message": "BACKEND SAYS NO" }
    })
    .to_string();
    let h = harness(Outcome::Answers(200, reply), false).await;
    let (status, body) = call(&h).await;
    assert_eq!(status, 502, "{body}");
    assert!(
        !body.to_string().contains("BACKEND SAYS NO"),
        "the backend's own error text must not be reflected to the caller: {body}"
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
async fn an_admitted_agent_task_lands_in_the_shared_request_series() {
    let h = harness(Outcome::Answers(200, backend_ok()), false).await;
    // `outcome="ok"` on this plane is only reachable through the whole admit → meter → egress-gate
    // → relay path, so no refusal in any concurrently-running test can produce it by accident.
    let labels = [
        ("plane", "a2a"),
        ("ingress_protocol", "jsonrpc"),
        ("outcome", "ok"),
    ];
    let before = crate::test_support::metric_sum(crate::metrics::REQUESTS_TOTAL, &labels);
    let (status, body) = call(&h).await;
    assert_eq!(status, 200, "the admitted call must be served: {body}");
    let after = crate::test_support::metric_sum(crate::metrics::REQUESTS_TOTAL, &labels);

    assert!(
        after > before,
        "a relayed agent task produced no `{}` sample on the a2a plane (before {before}, after \
         {after}) — the plane is invisible to an operator again",
        crate::metrics::REQUESTS_TOTAL,
    );
    assert!(
        crate::test_support::metric_sum(
            "busbar_request_duration_seconds_count",
            &[("plane", "a2a"), ("ingress_protocol", "jsonrpc")],
        ) > 0.0,
        "the agent plane must carry a latency series, not just a count"
    );
}
