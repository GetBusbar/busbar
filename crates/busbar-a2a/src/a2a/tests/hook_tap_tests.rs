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

use super::relay_harness::{backend_ok, call, call_agent, envelope, harness_gated, Gates, Outcome};
use crate::testkit::engine_boot::engine;
use busbar_kernel::test_support::engine_kit::HookNeed;

/// A `prompt: rw` REWRITE gate on the hermetic test cdylib, as the `hooks:` document an operator
/// writes (the engine parses it with its own grammar at build). `raw_transform_reply` drives its
/// `transform` reply verbatim, so a test states the exact replacement `params` object it returns.
fn rewrite(raw_transform_reply: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "kind": "gate",
        "module": "test-hook",
        // Not the 1 ms default — see the gate battery: under load the deadline fires on scheduling
        // delay and `on_error: weighted` maps the timed-out rewrite to an abstain (no rewrite).
        "timeout_ms": 10_000,
        "on_error": "weighted",
        "prompt": "rw",
        "user": "ro",
        "priority": 0,
        "settings": { "raw_transform_reply": raw_transform_reply },
    })
}

/// The attach, cdylib loaded through the real scan/trust/load pipeline. ABSENCE IS A HARD FAILURE,
/// never a skip (a skipped acceptance test reports green); the panic names the fix.
fn gates(name: &str, cfg: serde_json::Value) -> Gates {
    let env = engine()
        .hook_env(&["test-hook"], HookNeed::Rw, HookNeed::Ro)
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
    assert_eq!(
        status, 200,
        "the rewritten submission must still be served: {body}"
    );

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
    let mut cfg = rewrite(serde_json::Value::Null);
    cfg["settings"] = serde_json::json!({ "reject_if_contains": "EXFILTRATE" });
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

/// A COMMITTED REWRITE BUSBAR CANNOT READ BACK REFUSES THE SUBMISSION — it does not fall back to the
/// `params` the hook said it had replaced.
///
/// The apply site read the verdict's bytes with `if let Ok(v) = …`, so a hook that reported
/// `applied` and produced bytes busbar could not read left `rewritten_params` at `None` and the
/// relay forwarded the caller's ORIGINAL `params`. For the hook class this seam exists for that is
/// fail-OPEN in the precise sense: a redaction hook says "I have removed the secret from this
/// submission", its output is unreadable, and busbar sends the message WITH the secret still in it
/// to the backend agent.
///
/// The bytes below ARE the rewrite a failing hook commits — the `args_json` half of a
/// `TransformVerdict::Proceed { applied: true, .. }`. Driven at the DECISION rather than through a
/// hook chain because the plane cannot make the host seam emit unreadable bytes and the rule under
/// test is what the PLANE does when it does: core's own `transform_over_over` only ever commits a
/// JSON OBJECT (`apply_rewrite_to_invoke_args` refuses anything else) and re-serialises it, so the
/// `Err` arm is a guard on the plugin-ABI seam, not an exploitable hole through today's host. The
/// relay-side consequence — a refusal, never a hop — is the `Err` arm's only caller, and the scan
/// below pins that there is no second, lenient reader of the same bytes.
#[test]
fn a_committed_rewrite_busbar_cannot_read_back_is_refused_rather_than_silently_undone() {
    use crate::a2a::receive::committed_params;

    let ok = committed_params(br#"{"message":{"parts":[{"kind":"text","text":"rewritten"}]}}"#)
        .expect("an ordinary rewrite is read back and used");
    assert_eq!(
        ok["message"]["parts"][0]["text"], "rewritten",
        "the control: a readable rewrite still lands, so the rule refuses unusable output rather \
         than refusing rewrites"
    );

    for unusable in [
        &b"not json at all"[..],
        &b""[..],
        &b"{\"message\": "[..],
        // Well-formed JSON that is not a `params` object. A JSON-RPC `params` member is a
        // STRUCTURED value (section 4.2) and an object for every A2A method, and the write-back
        // inserts this value under `"params"` — so admitting `7` would put a malformed envelope on
        // the hop, having already told the hook its rewrite landed.
        &b"7"[..],
        &b"[1,2,3]"[..],
        &b"null"[..],
        &b"\"message/send\""[..],
    ] {
        assert!(
            committed_params(unusable).is_err(),
            "a committed rewrite busbar cannot use must REFUSE the submission; falling back to the \
             caller's original `params` silently undoes a redaction the hook reported as applied: \
             {:?}",
            String::from_utf8_lossy(unusable)
        );
    }
}

/// THE REFUSAL AN A2A CLIENT ACTUALLY READS. A hook fault answered with an opaque 500 and no
/// JSON-RPC error object would be the same silence one layer out, so the body the `Err` arm returns
/// is pinned to the row of A2A section 5.4 its HTTP status comes from: `InternalError`, -32603, 500.
#[test]
fn the_unreadable_rewrite_refusal_is_a_conformant_a2a_internal_error() {
    let id = serde_json::json!("req-7");
    let body = crate::a2a::rpcerror::body(
        &id,
        crate::a2a::rpcerror::A2aError::Internal,
        "a rewrite hook attached to this agent committed a rewrite that busbar could not read back.",
    );
    assert_eq!(body["jsonrpc"], "2.0", "the refusal is a JSON-RPC envelope");
    assert_eq!(body["id"], id, "and it echoes the caller's id: {body}");
    assert_eq!(
        body["error"]["code"], -32603,
        "the status and the body come from the SAME row of section 5.4; 500 is `InternalError`: {body}"
    );
    assert_eq!(
        crate::a2a::rpcerror::A2aError::Internal.http_status(),
        500,
        "and the HTTP status the apply site returns is that row's own"
    );
}

/// THE APPLY SITE HAS NO LENIENT READER OF THE SAME BYTES, AND ITS `Err` ARM RETURNS — a source
/// scan, because the behavioural half above covers only the shapes somebody thought of and this
/// covers the shape a future convenience would re-add.
///
/// The defect was one `if let Ok(v) = serde_json::from_slice…` inside the `applied` branch: a
/// conditional that keeps the ORIGINAL `params` when the parse fails and says nothing. The rule is
/// that the committed bytes are read in exactly one place, through `committed_params`, and that the
/// `Err` that reader returns REFUSES — a reader that can fail whose failure is then swallowed at the
/// call site is the same fail-open wearing a better type.
///
/// The COMPANION half is what makes the scan falsifiable: the predicate is run against a string that
/// WOULD be a violation, so the scan cannot be passing because it never matches anything.
#[test]
fn the_rewrite_apply_site_never_falls_back_to_the_caller_s_original_params() {
    /// Does this source text read the committed bytes with a conditional that can silently keep the
    /// originals? One predicate, used on the real file and on the companion.
    fn has_lenient_reader(src: &str) -> bool {
        src.lines().any(|l| {
            let l = l.trim();
            !l.starts_with("//")
                && (l.contains("if let Ok(") || l.contains("while let Ok("))
                && l.contains("from_slice")
        })
    }

    let src = include_str!("../receive.rs");
    assert!(
        !has_lenient_reader(src),
        "`a2a/receive.rs` reads deserialized bytes through a conditional that drops the error. On \
         the rewrite apply site that is the fail-open this case exists for: the hook committed a \
         rewrite, busbar could not read it, and the ORIGINAL `params` went to the backend agent."
    );
    assert!(
        src.contains("committed_params(&args_json)"),
        "the committed rewrite must be read through `committed_params`, whose `Err` arm refuses \
         the submission"
    );
    // AND THE `Err` IS A REFUSAL, not a log line. Reading the bytes strictly and then carrying on
    // with the originals would move the fail-open one line down, so the arm's disposition is pinned
    // as well as its reader: everything between `match committed_params` and the end of that match
    // must contain a `return`.
    let arm = src
        .split_once("match committed_params(&args_json)")
        .map(|(_, rest)| rest)
        .expect("the apply site reads the committed bytes through `committed_params`");
    let arm = &arm[..arm.find("// 5. METER").unwrap_or(arm.len())];
    assert!(
        arm.contains("Err(e) => {") && arm.contains(".into_response();"),
        "the `Err` arm of the rewrite apply site must RETURN a refusal. A strict reader whose \
         failure is logged and stepped over relays the caller's original `params` exactly as the \
         lenient one did: {arm}"
    );
    assert!(
        has_lenient_reader("if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&x) {"),
        "the scan's predicate must match a line that WOULD be a violation, or a green scan is \
         evidence of nothing"
    );
}

/// **WHAT A PANICKING `prompt: rw` HOOK ACTUALLY PRODUCES — and it is not a join failure.**
///
/// This is the reachability leg for [`crate::a2a::receive::tap_join_verdict`], and it is driven
/// through the REAL cdylib rather than asserted from the source, because the whole disposition
/// question at that join turns on what can arrive there. A missing check is not a vulnerability
/// until the line is shown to execute.
///
/// A `kind: hook` plugin's panic is caught THREE times before it could reach a plane: the SDK's
/// mandatory export-boundary `catch_unwind` (→ `STATUS_PANIC`), the engine's `ffi_guard` inside
/// `transport_call`, and `DlopenPolicy::call`'s own belt-and-braces guard. It therefore arrives at
/// `transform_over_over` as `TransformOutcome::Failed` — **the seam RAN and produced a verdict** —
/// and the operator's `on_error` decides what happens next. Both halves are here because the pair
/// is the point:
///
/// * `on_error: weighted` — the submission is SERVED and the backend receives the caller's ORIGINAL
///   `params`. That answer is only possible if the panic never reached the plane's `spawn_blocking`
///   join, which now REFUSES. This half is the falsifier.
/// * `on_error: reject` — the same panic refuses the submission. The operator's declared
///   disposition is consulted, which is exactly the lever a join failure takes away, since on a
///   join failure the chain never ran for `on_error` to be applied to.
#[tokio::test]
async fn a_hook_that_panics_is_the_seams_own_failed_verdict_never_a_join_failure() {
    // ── `on_error: weighted`: a panicking rewrite hook is a hook that could not answer, and the
    //    operator did not declare it load-bearing, so the submission proceeds UNCHANGED. ──────────
    let mut cfg = rewrite(serde_json::Value::Null);
    cfg["settings"] = serde_json::json!({ "panic_transform": true });
    let h = harness_gated(
        Outcome::AnswersCorrelated(200, backend_ok()),
        false,
        &["planner"],
        Some(gates("panicky", cfg)),
    )
    .await;
    let (status, body) = call(&h).await;
    assert_eq!(
        status, 200,
        "a PANICKING rewrite hook is caught at the ABI boundary and reaches the seam as a FAILED \
         call, which `on_error: weighted` proceeds through. A 503 here would mean the panic had \
         reached the plane's join instead — the arm this test exists to prove is NOT the \
         hook-panic path: {body}"
    );
    let sent = h.sent();
    assert_eq!(sent.len(), 1, "the submission was relayed exactly once");
    let relayed: serde_json::Value = serde_json::from_slice(&sent[0].body).unwrap_or_default();
    assert_eq!(
        relayed["params"]["message"]["parts"][0]["text"], "PLAN THE MIGRATION",
        "and it carried the caller's ORIGINAL params: the seam's own fail-safe arm, chosen by the \
         operator, not the plane's join: {relayed}"
    );

    // ── `on_error: reject`: the SAME panic, declared load-bearing. The operator's disposition is
    //    applied — which is the lever a join failure removes, because the chain never ran. ────────
    let mut cfg = rewrite(serde_json::Value::Null);
    cfg["on_error"] = serde_json::json!("reject");
    cfg["settings"] = serde_json::json!({ "panic_transform": true });
    let h = harness_gated(
        Outcome::AnswersCorrelated(200, backend_ok()),
        false,
        &["planner"],
        Some(gates("panicky-required", cfg)),
    )
    .await;
    let (status, _body) = call(&h).await;
    assert_eq!(
        status,
        busbar_kernel::hooks::REQUIRED_HOOK_UNAVAILABLE_STATUS,
        "a load-bearing rewrite hook that panicked refuses the submission on the seam's own \
         'a required gate could not complete' verdict"
    );
    assert!(
        h.sent().is_empty(),
        "and nothing was relayed: the refusal precedes the hop"
    );
}

/// **A REWRITE LEG THAT DID NOT JOIN REFUSES THE SUBMISSION, AND IS NEVER SILENT.**
///
/// The `spawn_blocking` join for the `prompt: rw` tap was `.unwrap_or(Proceed { applied: false, .. })`
/// — the one disposition on this seam that left NO TRACE AT ALL (`transform_over_over` logs its own
/// `Failed` and timeout arms), and the one that answers an UNKNOWN verdict with "relay the caller's
/// `params`". Those `params` are the caller's UNTRUSTED submission — the `message.parts` a screening
/// hook is attached to read — so proceeding forwards to a backend agent, over busbar's leased
/// credential, exactly the payload a hook was installed to inspect and possibly reject. Unknown is
/// not allow.
///
/// **This is why it is NOT the voice twin's answer.** There the originals are the plane's OWN LOCKED
/// params, so proceeding hands the session what the operator configured and is genuinely fail-safe.
/// Copying that disposition here would be reasoning from the wrong premise about whose bytes they
/// are.
///
/// Driven at the DECISION rather than through a hook chain for the reason
/// [`crate::a2a::receive::committed_params`] is: the plane cannot make the host seam misbehave,
/// and the rule under test is what the PLANE does when it does. The
/// `a_hook_that_panics_is_the_seams_own_failed_verdict_never_a_join_failure` cell above is the other
/// leg — what CAN arrive here — and the `JoinError` below is real, produced by an actual panicked
/// blocking task, never a constructed stand-in.
#[tokio::test]
async fn a_rewrite_leg_that_did_not_join_refuses_the_submission_and_is_never_silent() {
    use busbar_kernel::plane_host::TransformVerdict;
    use busbar_substrate_values::testkit::warn_capture::WarnCapture;
    use tracing_subscriber::layer::SubscriberExt as _;

    // A REAL `JoinError`: exactly the value the tap leg receives when its blocking task panics.
    let joined: Result<TransformVerdict, tokio::task::JoinError> =
        tokio::task::spawn_blocking(|| -> TransformVerdict { panic!("the rewrite leg blew up") })
            .await;
    assert!(
        joined.is_err(),
        "the fixture must actually be a panicked join"
    );

    // THE CONTROL, first: a leg that DID join is passed through untouched, so the rule refuses a
    // missing verdict rather than refusing rewrites.
    let passed = crate::a2a::receive::tap_join_verdict(
        Ok(TransformVerdict::Proceed {
            applied: false,
            args_json: Vec::new(),
        }),
        "planner",
        "message/send",
    );
    assert!(
        matches!(passed, TransformVerdict::Proceed { applied: false, .. }),
        "a verdict that arrived is the verdict"
    );

    let cap = WarnCapture::default();
    let verdict =
        tracing::subscriber::with_default(tracing_subscriber::registry().with(cap.clone()), || {
            crate::a2a::receive::tap_join_verdict(joined, "planner", "message/send")
        });

    match verdict {
        TransformVerdict::Reject {
            status,
            message,
            hook,
        } => {
            assert_eq!(
                status,
                busbar_kernel::hooks::REQUIRED_HOOK_UNAVAILABLE_STATUS,
                "a leg that never answered is the seam's own 'a required gate could not complete' \
                 condition, minted at the one status every other firing site renders for it"
            );
            assert_eq!(
                message,
                busbar_kernel::hooks::REQUIRED_HOOK_UNAVAILABLE_MESSAGE,
                "and the one content-free message, so a client learns nothing about the operator's \
                 hook topology from a leg that fell over"
            );
            assert!(
                !hook.is_empty(),
                "the refusal names the subject the plane's own reject arm logs; a blank here is \
                 the silence this fix removes, one field further in"
            );
        }
        TransformVerdict::Proceed { applied, .. } => panic!(
            "a rewrite leg that did not join must REFUSE the submission — proceeding relays the \
             caller's UNTRUSTED `params` to the backend agent with the hook chain's verdict \
             unknown, which is the whole reason this seam exists. Got: \
             Proceed {{ applied: {applied} }}"
        ),
    }

    // AND THE SILENCE IS GONE. Every one of these is load-bearing for an operator reading the log:
    // what failed, whose control it was, which verb, the error, and what busbar did about it.
    let lines = cap.messages().join("\n");
    assert!(
        cap.contains("did not join"),
        "the join failure must be logged at all — it was the only hook-failure mode on this seam \
         with no line: {lines}"
    );
    assert!(
        cap.contains("prompt: rw"),
        "and it must name the CONTROL that went unanswered: {lines}"
    );
    assert!(
        cap.contains("agent=planner") && cap.contains("method=message/send"),
        "and the subject: which agent's chain, on which verb: {lines}"
    );
    assert!(
        cap.contains("the rewrite leg blew up"),
        "and the underlying error, so the line is a diagnosis and not a notification: {lines}"
    );
    assert!(
        cap.contains("REFUSED"),
        "and what busbar did about it — silence and success must never be the same output at the \
         hook seam: {lines}"
    );
}
