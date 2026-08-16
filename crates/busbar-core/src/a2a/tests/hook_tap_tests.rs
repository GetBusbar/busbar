// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE A2A HALF OF "A TAP OBSERVES A NON-LLM PROTOCOL", on both of this plane's roles.
//!
//! Two cells of `qa/capability-equality.json`, and they are different claims about different
//! traffic:
//!
//! * `hooks-tap x a2a-server` — a submission a caller sent busbar reaches a global tap, carrying the
//!   caller's own prose. Its note said *"there is no transform/rewrite path for inbound A2A
//!   payloads"*, which was true of the REWRITE verb and had been read as true of observation too.
//! * `hooks-tap x a2a-client` — a hop BUSBAR ORIGINATED reaches the same tap. This is the harder and
//!   more important half: nothing a caller sent composed that document, so it is exactly the traffic
//!   an operator cannot see any other way, and it is why `.notify(` having had two production call
//!   sites (both under `proxy/`) was a real hole rather than a bookkeeping one.
//!
//! ## Why the originated half is asserted against the RECORDING SEAM as well as the tap
//!
//! Every push-config verb here is ALSO answered locally, so `200` is what a caller gets whether or
//! not a hop was made. The harness's seam records the request the relay asked to send, and this file
//! reads it: a tap delivery is only evidence about the originated hop if the hop actually happened.

use super::relay_harness::{
    a_card_on, approve_card, backend_ok, call, call_agent, envelope, harness_gated, in_turn, Gates,
    Harness, Outcome, Recorded,
};
use crate::config::{HookCfg, HookKind, PromptAccess, UserAccess};
use crate::test_support::RecordingTap;
use std::sync::Arc;

/// A token that appears nowhere in the deployment except in the caller's own message text.
const NEEDLE: &str = "PLAN THE MIGRATION";

/// The caller's webhook, so a push-config submission has something to register.
const CALLER_HOOK: &str = "https://receiver.caller.test/notify";

/// A `Gates` carrying ONLY taps — no `agents.hooks:` attach at all, which is the deployment the
/// `hooks-tap` cells are about: an operator who attached a global observer and no gate.
fn taps_only(taps: Vec<crate::hooks::TapEntry>) -> Gates {
    Gates {
        // No hook is loaded, so the plugin env is the empty one every un-gated harness gets.
        env: crate::hooks::HookEnv::new(
            Arc::new(busbar_plugin_loader::PluginRegistry::empty()),
            Arc::new(crate::config::secret::SecretResolver::builtins_only()),
        ),
        hooks: Vec::new(),
        attach: Vec::new(),
        taps,
    }
}

/// A `kind: gate` on the hermetic test cdylib holding `prompt: ro`, with the same 10 s deadline and
/// the same reasoning as `hook_gate_tests::gate`: the VERDICT is under test, not the deadline, and a
/// 1 ms budget fires on scheduling delay alone under a saturated suite.
fn gate(settings: serde_json::Value) -> HookCfg {
    HookCfg {
        kind: HookKind::Gate,
        plugin: "test-hook".to_string(),
        timeout_ms: 10_000,
        on_error: "weighted".to_string(),
        prompt: PromptAccess::Ro,
        user: UserAccess::Ro,
        priority: 0,
        at: None,
        settings: settings.as_object().cloned().unwrap_or_default(),
        on_empty: None,
        global: false,
        default: false,
        signals: Vec::new(),
        groups: Vec::new(),
        phase: Vec::new(),
    }
}

/// The gate attach, with the cdylib loaded through the real scan/trust/load pipeline. ITS ABSENCE IS
/// A HARD FAILURE, never a skip, for the reason the sibling battery states: with no gate to load
/// every assertion below is vacuous and reports green.
fn gates_and_taps(
    name: &str,
    settings: serde_json::Value,
    taps: Vec<crate::hooks::TapEntry>,
) -> Gates {
    let env = crate::test_support::test_hook_env(
        &["test-hook"],
        busbar_plugin_sign::HookNeeds {
            prompt: busbar_plugin_sign::NeedLevel::Rw,
            user: busbar_plugin_sign::NeedLevel::Ro,
        },
    )
    .expect(
        "the busbar-hook-test-plugin cdylib is not built. This battery is the a2a-client half of \
         the hook-parity acceptance tests and it CANNOT be skipped: with no gate to load, every \
         assertion below is vacuous and reports a green. Build it: `cargo build -p \
         busbar-hook-test-plugin`.",
    );
    Gates {
        env,
        hooks: vec![(name.to_string(), gate(settings))],
        attach: vec![name.to_string()],
        taps,
    }
}

// ══ a2a-server: THE SUBMISSION A CALLER SENT ═════════════════════════════════════════════════════

/// A `message/send` reaches a global tap, carrying the caller's own message text.
///
/// The CONTROL is the untapped harness in every other file in this directory: the same submission is
/// served and relayed there, so a delivery here is a statement about the tap and not about the
/// fixture. It is restated inline anyway — `sent().len() == 1` — because a submission the gate
/// refused would deliver a projection too, and that would be a different finding.
#[tokio::test]
async fn an_inbound_submission_reaches_a_global_tap_carrying_the_callers_content() {
    let (tap, entry) = RecordingTap::entry(true);
    let h = harness_gated(
        Outcome::AnswersCorrelated(200, backend_ok()),
        false,
        &["planner"],
        Some(taps_only(vec![entry])),
    )
    .await;

    let (status, body) = call(&h).await;
    assert_eq!(
        status, 200,
        "a tap is fire-and-forget and can never fail the submission it observes: {body}"
    );
    assert_eq!(
        h.sent().len(),
        1,
        "the submission really was relayed, so the projection below is about a served request"
    );

    let seen = tap.wait_for(1).await;
    let projection = &seen[0];
    assert_eq!(projection["op"], "notify", "{projection}");
    assert_eq!(
        projection["request"]["ingress_protocol"], "a2a",
        "the projection must name the plane the request arrived on: {projection}"
    );
    assert_eq!(
        projection["request"]["pool"], "planner",
        "`pool` is the CONTAINER — here the registered agent the submission resolved to: \
         {projection}"
    );
    assert!(
        tap.seen_text().contains(NEEDLE),
        "the caller's own message parts must reach the tap. Without them the tap fired with an \
         empty projection, which records a submission per row and a fact about none of them. Got: \
         {}",
        tap.seen_text()
    );
}

// ══ a2a-client: THE HOP BUSBAR ORIGINATED ════════════════════════════════════════════════════════

/// The backend's own name for the task these fixtures open — the id busbar's substituted
/// registration is addressed by. Spelled exactly as `pushback_tests` spells it, because both files
/// are asserting about the same substitution.
const BACKEND_TASK: &str = "BACKEND-OWN-TASK-ID";

/// A backend that is still WORKING. Load-bearing, not incidental: busbar does not arm a backend for
/// a task it already holds as terminal (`pushback::worth_registering`), so a fixture whose task
/// completed would make every originated-hop assertion below vacuous.
fn jsonrpc_working() -> String {
    serde_json::json!({
        "jsonrpc": "2.0", "id": 7,
        "result": { "id": BACKEND_TASK, "contextId": "BACKEND-OWN-CONTEXT", "kind": "task",
                    "status": { "state": "working" } }
    })
    .to_string()
}

/// The backend's answer to a push-config verb, carrying BUSBAR'S OWN config id so the
/// reconciliation finds its registration and does not re-arm.
fn jsonrpc_config() -> String {
    serde_json::json!({
        "jsonrpc": "2.0", "id": 0,
        "result": { "taskId": BACKEND_TASK, "id": crate::a2a::pushback::config_id(BACKEND_TASK),
                    "url": "https://busbar.example/a2a/push" }
    })
    .to_string()
}

/// The caller's own `CreateTaskPushNotificationConfig`, naming ITS url, ITS credential and ITS id —
/// the submission that makes busbar mirror a registration of its own onto the backend.
fn create_call(task: &str) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0", "id": 9, "method": "CreateTaskPushNotificationConfig",
        "params": {
            "taskId": task,
            "id": "caller-cfg-9a2b",
            "url": CALLER_HOOK,
            "authentication": { "scheme": "Bearer", "credentials": "caller-webhook-secret" },
        }
    })
}

/// The gated/tapped harness on the JSON-RPC binding, with every registration approved against a card
/// that declares it — `harness_on`'s own body, which cannot be reused directly because it takes no
/// `Gates`.
async fn harness_jsonrpc(gates: Gates) -> Harness {
    let h = harness_gated(
        in_turn(200, vec![jsonrpc_working(), jsonrpc_config()]),
        false,
        &["planner"],
        Some(gates),
    )
    .await;
    let card = a_card_on(crate::a2a::relay::BINDING_JSONRPC);
    h.plane.with_registrations_mut(|regs| {
        for reg in regs.iter_mut() {
            approve_card(reg, card.clone());
        }
    });
    h
}

/// Open a task and register the caller's callback on it — which is what makes busbar mirror its OWN
/// registration onto the backend, the busbar-originated hop this half is about. Hands back every
/// request the relay asked to send.
async fn open_and_register(h: &Harness) -> Vec<Recorded> {
    let (status, body) = call_agent(h, "planner", &envelope()).await;
    assert_eq!(status, 200, "the task must open: {body}");
    let task = body
        .pointer("/result/id")
        .or_else(|| body.pointer("/result/task/id"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or_else(|| panic!("the submission answered no task id: {body}"))
        .to_string();
    let (status, body) = call_agent(h, "planner", &create_call(&task)).await;
    assert_eq!(
        status, 200,
        "the caller's registration must succeed: {body}"
    );
    // The mirror hop is fired off the request path and is not awaited by the caller's answer, so it
    // is POLLED for rather than assumed present. Absence is the finding the callers assert on.
    for _ in 0..200 {
        if h.sent()
            .iter()
            .any(|r| String::from_utf8_lossy(&r.wire()).contains("PushNotificationConfig"))
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    h.sent()
}

/// Did busbar compose its OWN registration for the backend?
fn originated_a_registration(sent: &[Recorded]) -> bool {
    sent.iter().any(|r| {
        let wire = String::from_utf8_lossy(&r.wire()).to_string();
        wire.contains("CreateTaskPushNotificationConfig")
            && wire.contains(&crate::a2a::pushback::config_id(BACKEND_TASK))
    })
}

/// THE ORIGINATED HOP REACHES THE TAP. busbar's own registration at the backend is composed by
/// busbar, sent by busbar, and — until this unit — observed by nobody.
///
/// The assertion is on the config id BUSBAR mints for ITSELF, which appears in no document the
/// caller sent: it is proof the projection carries the originated hop's params rather than an echo
/// of the submission that triggered them.
#[tokio::test]
async fn a_busbar_originated_hop_reaches_a_global_tap_carrying_the_document_busbar_composed() {
    let (tap, entry) = RecordingTap::entry(true);
    let h = harness_jsonrpc(taps_only(vec![entry])).await;

    let sent = open_and_register(&h).await;
    assert!(
        originated_a_registration(&sent),
        "the fixture must actually make busbar's own registration hop, or a delivery below would \
         be about the submission rather than the originated hop"
    );

    // POLLED ON THE ORIGINATED DOCUMENT ITSELF, not on a projection COUNT: the caller's own two
    // requests are delivered by the front-door firing site, so a count of three would be satisfied
    // by them plus any third delivery and would go red for the wrong reason if the front door ever
    // changed how many projections one submission produces.
    let needle = crate::a2a::pushback::config_id(BACKEND_TASK);
    for _ in 0..500 {
        if tap.seen_text().contains(&needle) {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    let text = tap.seen_text();
    assert!(
        text.contains(&needle),
        "the document BUSBAR composed for itself must reach the tap. Only the caller's own two \
         requests arriving would mean the originated leg is still unobserved. Got: {text}"
    );
    assert!(
        text.contains("https://busbar.example/a2a/push"),
        "the callback address busbar hands the backend is the fact an operator attaches an egress \
         observer to see; it must be in the projection. Got: {text}"
    );
}

/// THE GATE ON THE ORIGINATED HOP — `hooks-gate x a2a-client`, the ledger's last missing gate cell.
///
/// The gate screens on a token that appears ONLY in the document busbar composes for itself, so the
/// caller's own submission and its own config set both pass it and only busbar's hop is refused.
/// That separation is the point: a gate that refused everything would prove nothing about the
/// originated leg, because the task would never open.
///
/// THE ASSERTION IS ON THE WIRE, not on a status. Every push-config verb is also answered locally,
/// so the caller sees `200` whether or not busbar made a hop — "it returned 200" is exactly the
/// false green this plane's own test files were written about.
#[tokio::test]
async fn a_hook_gate_refuses_a_busbar_originated_hop_and_the_caller_is_unaffected() {
    // ── THE CONTROL: the same gate screening on a token no document here carries. It must make the
    //    originated hop, or "no hop" below is not evidence of a refusal. ───────────────────────────
    let control = harness_jsonrpc(gates_and_taps(
        "screen",
        serde_json::json!({ "reject_if_contains": "a-token-no-document-here-carries" }),
        Vec::new(),
    ))
    .await;
    let sent = open_and_register(&control).await;
    assert!(
        originated_a_registration(&sent),
        "the control must make busbar's own registration hop with a gate attached that objects to \
         nothing; without it, the refusal below could be any other failure"
    );

    // ── THE TEST: the same gate, screening on the config id BUSBAR mints for ITSELF. ─────────────
    let h = harness_jsonrpc(gates_and_taps(
        "screen",
        serde_json::json!({ "reject_if_contains": crate::a2a::pushback::config_id(BACKEND_TASK) }),
        Vec::new(),
    ))
    .await;
    let sent = open_and_register(&h).await;
    assert!(
        !originated_a_registration(&sent),
        "the gate must REFUSE the hop busbar originated: no request carrying busbar's own \
         registration may have been composed for the backend. Wire: {:?}",
        sent.iter()
            .map(|r| String::from_utf8_lossy(&r.wire()).to_string())
            .collect::<Vec<_>>()
    );
    // AND THE CALLER IS UNTOUCHED. A refused housekeeping hop leaves the customer exactly where it
    // was: `open_and_register`'s own assertions already required both of the caller's requests to
    // be answered `200`, and the submission itself still reached the backend.
    assert!(
        !sent.is_empty(),
        "the caller's own submission must still have been relayed — gating busbar's housekeeping \
         must not gate the caller's traffic"
    );
}
