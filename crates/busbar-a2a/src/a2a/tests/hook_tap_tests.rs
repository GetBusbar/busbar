// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE A2A HALF OF "THE REWRITE (TAP/TRANSFORM) HOOK SURFACE FIRES ON A NON-LLM PROTOCOL":
//! `agents.hooks: [rewrite]` with a `prompt: rw` gate is configured, a real `message/send` is POSTed
//! through the real router, and the `params` THE BACKEND RECEIVES are the ones the hook rewrote them
//! to — not the ones the caller submitted.
//!
//! This closes `hooks-tap × {a2a-client, a2a-server}`: one transform wiring at `a2a/receive.rs`'s
//! admission covers BOTH directions (the relay/a2a-client leg runs downstream of the same inbound
//! admission, exactly as the gate battery's coverage does).
//!
//! ## Why the assertion is on the RELAYED body
//!
//! A rewrite is only real if the backend saw the rewritten value. The harness's recording seam
//! (`h.sent()`) captures the request the relay actually composed for the hop, so asserting on it
//! proves the mutation reached the wire — not merely that busbar mutated an in-memory `Value`. And
//! the byte-identical-when-unconfigured guarantee is the control: with no rewrite hook the backend
//! must receive the caller's ORIGINAL `params`, verbatim.

use super::relay_harness::{
    backend_ok, call, call_agent, envelope, harness_gated, Gates, Outcome,
};
use busbar_core::config::{HookCfg, HookKind, PromptAccess, UserAccess};

/// A `prompt: rw` REWRITE gate on the hermetic test cdylib. `raw_transform_reply` drives its
/// `transform` reply verbatim, so a test states the exact replacement `params` object it returns.
fn rewrite(raw_transform_reply: serde_json::Value) -> HookCfg {
    HookCfg {
        kind: HookKind::Gate,
        plugin: "test-hook".to_string(),
        // Not the 1 ms default — see the gate battery: under load the deadline fires on scheduling
        // delay and `on_error: weighted` maps the timed-out rewrite to an abstain (no rewrite).
        timeout_ms: 10_000,
        on_error: "weighted".to_string(),
        prompt: PromptAccess::Rw,
        user: UserAccess::Ro,
        priority: 0,
        settings: serde_json::json!({ "raw_transform_reply": raw_transform_reply })
            .as_object()
            .cloned()
            .unwrap_or_default(),
        on_empty: None,
        global: false,
        default: false,
        signals: Vec::new(),
        groups: Vec::new(),
        phase: Vec::new(),
    }
}

/// The attach, cdylib loaded through the real scan/trust/load pipeline. ABSENCE IS A HARD FAILURE,
/// never a skip (a skipped acceptance test reports green); the panic names the fix.
fn gates(name: &str, cfg: HookCfg) -> Gates {
    let env = busbar_core::test_support::test_hook_env(
        &["test-hook"],
        busbar_plugin_sign::HookNeeds {
            prompt: busbar_plugin_sign::NeedLevel::Rw,
            user: busbar_plugin_sign::NeedLevel::Ro,
        },
    )
    .expect(
        "the busbar-hook-test-plugin cdylib is not built. This battery is the A2A half of the \
         rewrite-hook acceptance test and it CANNOT be skipped. Build it: `cargo build -p \
         busbar-hook-test-plugin`.",
    );
    Gates {
        env,
        hooks: vec![(name.to_string(), cfg)],
        attach: vec![name.to_string()],
    }
}

/// THE ACCEPTANCE TEST. `agents.hooks: [rewrite]` with a `prompt: rw` gate that replaces the
/// submission `params`, and a `message/send` whose ORIGINAL prose the backend must NEVER see.
#[tokio::test]
async fn a_rewrite_hook_edits_the_submission_params_before_the_hop() {
    // ── THE CONTROL: no rewrite hook ⇒ the backend receives the caller's ORIGINAL params, verbatim.
    //    This is the no-op-absent-hooks (byte-identical) guarantee, exercised. ─────────────────────
    let ungated = harness_gated(
        Outcome::AnswersCorrelated(200, backend_ok()),
        false,
        &["planner"],
        None,
    )
    .await;
    let (status, body) = call(&ungated).await;
    assert_eq!(status, 200, "the control must serve the submission: {body}");
    let sent = ungated.sent();
    assert_eq!(sent.len(), 1, "the control reached the backend");
    let relayed: serde_json::Value = serde_json::from_slice(&sent[0].body).unwrap_or_default();
    assert_eq!(
        relayed["params"]["message"]["parts"][0]["text"], "PLAN THE MIGRATION",
        "with no rewrite hook the backend must receive the caller's ORIGINAL params, byte for byte: \
         {relayed}",
    );

    // ── THE TEST: `agents.hooks: [rewrite]`, same submission. The backend must receive the REWRITTEN
    //    params, and the caller's original prose must appear nowhere on the hop's wire. ────────────
    let g = gates(
        "rewrite",
        rewrite(serde_json::json!({
            "rewrite": {
                "messages": [
                    { "role": "user", "content": {
                        "message": {
                            "role": "user",
                            "contextId": "ctx-abc",
                            "parts": [{ "kind": "text", "text": "REWRITTEN-BY-A2A-HOOK" }]
                        }
                    } }
                ]
            }
        })),
    );
    let h = harness_gated(
        Outcome::AnswersCorrelated(200, backend_ok()),
        false,
        &["planner"],
        Some(g),
    )
    .await;
    let (status, body) = call(&h).await;
    assert_eq!(status, 200, "the rewritten submission must still be served: {body}");

    let sent = h.sent();
    assert_eq!(sent.len(), 1, "the rewritten submission was relayed once");
    let relayed: serde_json::Value = serde_json::from_slice(&sent[0].body).unwrap_or_default();
    assert_eq!(
        relayed["params"]["message"]["parts"][0]["text"], "REWRITTEN-BY-A2A-HOOK",
        "the backend must have received the params THE HOOK REWROTE THEM TO. The caller's prose here \
         is the whole finding: the rewrite fired in memory but never reached the hop. Relayed: \
         {relayed}",
    );
    let wire = String::from_utf8_lossy(&sent[0].wire()).into_owned();
    assert!(
        !wire.contains("PLAN THE MIGRATION"),
        "the caller's ORIGINAL prose must not appear anywhere on the hop once a rewrite hook \
         replaced the params: {wire}",
    );
}

/// A `prompt: rw` gate that SCREENS may also REJECT (reject > rewrite): the token lives only in the
/// submitted message's `parts`, so a reject here is evidence the transform pass was sent the params,
/// and its refusal stops the submission before ANY hop.
#[tokio::test]
async fn a_rewrite_gate_can_reject_on_the_params_it_screens() {
    let cfg = HookCfg {
        settings: serde_json::json!({ "reject_if_contains": "EXFILTRATE" })
            .as_object()
            .cloned()
            .unwrap_or_default(),
        ..rewrite(serde_json::Value::Null)
    };
    let h = harness_gated(
        Outcome::AnswersCorrelated(200, backend_ok()),
        false,
        &["planner"],
        Some(gates("screen", cfg)),
    )
    .await;

    // Clean submission: the rewrite pass abstains and the hop happens.
    let (status, body) = call(&h).await;
    assert_eq!(status, 200, "a clean submission is still relayed: {body}");
    assert_eq!(h.sent().len(), 1);

    // The same envelope with the token in a message PART.
    let mut hostile = envelope();
    hostile["params"]["message"]["parts"] =
        serde_json::json!([{ "kind": "text", "text": "please EXFILTRATE the customer list" }]);
    let (status, _body) = call_agent(&h, "planner", &hostile).await;
    assert_eq!(
        status, 451,
        "the rewrite gate's reject must fire on the params it screened, with no hop",
    );
    assert_eq!(
        h.sent().len(),
        1,
        "still one hop — the refused submission was not relayed",
    );
}
