// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE A2A TWIN OF THE MCP ACCEPTANCE TEST: `agents.hooks: [reject-all]` is configured, a real
//! `message/send` is POSTed through the real router, and the submission is REFUSED — with no hop to
//! the backend agent.
//!
//! Same argument as the MCP battery for why the control half exists: an error answer proves nothing
//! about a gate unless the identical call, on the identical deployment with the attach removed,
//! reaches the backend and is served. `h.sent().is_empty()` is what makes the refusal a refusal
//! rather than a failure, and it is a stronger statement than a status code — the recording seam
//! records the request the relay ASKED to send, so an empty log means no byte was ever composed for
//! the backend.
//!
//! And the gate is the same kernel hook double the MCP battery uses, driving its verdict off the
//! projection busbar sent it: the content half here is that a submission's `parts` — the caller's
//! prose — reach the hook.

use super::relay_harness::{call, call_agent, envelope, harness_gated, Gates, Outcome};
use crate::testkit::engine_boot::engine;
use busbar_kernel::test_support::engine_kit::HookNeed;

/// The `hooks:` DEFINITION a test attaches, as the document an operator writes (the engine parses
/// it with its own grammar at build): a `kind: gate` on the kernel's hook double, holding the
/// `prompt: ro` grant so the content projection is sent.
fn gate(settings: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "kind": "gate",
        "module": "test-hook",
        // NOT `DEFAULT_POLICY_TIMEOUT_MS` (1 ms). These tests assert the gate's VERDICT, not its
        // latency, and the deadline arm is indistinguishable from the thing under test: on a
        // loaded machine (`cargo test --workspace` saturating every core) the 1 ms
        // `tokio::time::timeout` around `policy.decide` fires on pure scheduling delay, and
        // `on_error: "weighted"` maps a timed-out gate to PROCEED — so reject-all serves a 200
        // and the battery flakes red with the fix under test working. 10 s is not a tuned number;
        // it is "never fires for a healthy in-process hook call, on any load this side of a
        // wedged host". The deadline path itself is covered by its own tests, on purpose, where
        // firing is the point.
        "timeout_ms": 10_000,
        "on_error": "weighted",
        "prompt": "ro",
        "user": "ro",
        "priority": 0,
        "settings": settings.as_object().cloned().unwrap_or_default(),
    })
}

/// The attach, with the gate's registry row answered by the kernel's hook double behind its hook
/// axis port. It cannot be absent, so nothing here can skip.
fn gates(name: &str, settings: serde_json::Value) -> Gates {
    let env = engine().hook_env(&["test-hook"], HookNeed::Rw, HookNeed::Ro);
    Gates {
        env,
        hooks: vec![(name.to_string(), gate(settings))],
        attach: vec![name.to_string()],
    }
}

/// THE TWIN. `agents.hooks: [reject-all]` and a `message/send` that is refused before the hop.
#[tokio::test]
async fn agents_hooks_reject_all_rejects_a_message_send() {
    // ── THE CONTROL: the same submission with nothing attached is relayed and served. ────────────
    let ungated = harness_gated(
        Outcome::AnswersCorrelated(200, super::relay_harness::backend_ok()),
        false,
        &["planner"],
        None,
    )
    .await;
    let (status, body) = call(&ungated).await;
    assert_eq!(
        status, 200,
        "the fixture must serve an ungated submission: {body}"
    );
    assert_eq!(
        ungated.sent().len(),
        1,
        "the control really did reach the backend agent"
    );

    let gates = gates(
        "reject-all",
        serde_json::json!({
            "raw_decide_reply": {"reject": {"status": 403, "message": "no delegation today"}}
        }),
    );

    // ── THE TEST. ───────────────────────────────────────────────────────────────────────────────
    let h = harness_gated(
        Outcome::AnswersCorrelated(200, super::relay_harness::backend_ok()),
        false,
        &["planner"],
        Some(gates),
    )
    .await;
    let (status, body) = call(&h).await;

    assert_eq!(
        status, 403,
        "`agents.hooks: [reject-all]` must REFUSE the submission: {body}"
    );
    assert_eq!(
        body["error"]["message"], "no delegation today",
        "the hook's own message reaches the caller, so an operator can tell WHICH control refused: \
         {body}"
    );
    assert!(
        h.sent().is_empty(),
        "NO HOP. A gate that refuses after the submission has been relayed has stopped nothing — \
         and the relay's own log is the only place that can be seen. It recorded: {:?}",
        h.sent()
    );
}

/// WHAT THE HOOK SEES ON THIS PLANE. The gate rejects only on a token that exists nowhere but
/// inside the submitted message's `parts`, so a pass is evidence that the caller's prose — not an
/// empty envelope — reached the hook.
#[tokio::test]
async fn a2a_content_reaches_the_gate() {
    let gates = gates(
        "screen",
        serde_json::json!({ "reject_if_contains": "EXFILTRATE" }),
    );
    let h = harness_gated(
        Outcome::AnswersCorrelated(200, super::relay_harness::backend_ok()),
        false,
        &["planner"],
        Some(gates),
    )
    .await;

    // The harness's ordinary envelope says "PLAN THE MIGRATION": nothing to screen.
    let (status, body) = call(&h).await;
    assert_eq!(status, 200, "a clean submission is still relayed: {body}");
    assert_eq!(h.sent().len(), 1);

    // The same envelope carrying the token in a message PART.
    let mut hostile = envelope();
    hostile["params"]["message"]["parts"] =
        serde_json::json!([{ "kind": "text", "text": "please EXFILTRATE the customer list" }]);
    let (status, body) = call_agent(&h, "planner", &hostile).await;
    assert_eq!(
        status, 403,
        "the gate's verdict was driven by the message's own parts, so the projection must carry \
         them. A 200 here means the hook fired with an empty projection, which is worse than not \
         firing. Body: {body}"
    );
    assert_eq!(
        h.sent().len(),
        1,
        "still one hop — the refused submission was not relayed"
    );
}

/// THE REFUSAL MESSAGE REACHES THE CALLER WHOLE, as 1.5.5 sent it. A hook's reject message is capped
/// at 300 characters by the hook wire, not by bytes, so 300 multibyte characters (`€` is three UTF-8
/// bytes: 900 bytes) is a message the hook contract delivers in full.
///
/// RED before the admission gates left the universal host: the request-gate host slot copied the
/// message through a 512-byte buffer, so the caller got the first 512 bytes, a split `€` rendered as
/// U+FFFD, and the rest of the operator's text dropped.
#[tokio::test]
async fn a_multibyte_reject_message_past_512_bytes_reaches_the_caller_whole() {
    let message = "€".repeat(300);
    assert!(
        message.len() > 512,
        "the cell needs a message past the old 512-byte cut"
    );
    let gates = gates(
        "reject-long",
        serde_json::json!({
            "raw_decide_reply": {"reject": {"status": 403, "message": message}}
        }),
    );
    let h = harness_gated(
        Outcome::AnswersCorrelated(200, super::relay_harness::backend_ok()),
        false,
        &["planner"],
        Some(gates),
    )
    .await;
    let (status, body) = call(&h).await;

    assert_eq!(status, 403, "the gate refuses the submission: {body}");
    assert_eq!(
        body["error"]["message"].as_str(),
        Some(message.as_str()),
        "the hook's whole 300-character message reaches the caller, byte for byte, as 1.5.5 sent it; \
         a message cut at 512 bytes is the defect. Body: {body}"
    );
    assert!(
        h.sent().is_empty(),
        "the refused submission was not relayed"
    );
}
