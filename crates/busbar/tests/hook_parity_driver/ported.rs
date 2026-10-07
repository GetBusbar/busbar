// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The request-stage hook tests the legacy engine crate carried, held on the driver before that
//! crate is deleted: the rewrite chain, the tap's group scope, content the reader cannot model, the
//! four 503 bodies a hook can produce, the hook content ceiling and the response tap's
//! `response_tokens_out`. Each test names the legacy test it ports (crate-relative path) and keeps
//! its inputs and the values it asserted.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use busbar_contract::hooks::{
    Candidate, PolicyResult, RewriteReply, RoutingContext, RoutingDecision, RoutingPolicy,
    RoutingRequest, TransformOutcome,
};
use busbar_contract::signal::Signal;
use busbar_kernel::config::PolicyOnError;
use busbar_kernel::hooks::{RequestedSignals, ResolvedPolicy, TapEntry};
use serde_json::{json, Value};

use crate::policies::{capturing, wait_for_tap_body, CaptureTap};
use crate::rig::{member, Answered, Callers, Hooks, Member, Pool, Rig};

/// The principal the kernel's passing steps verify.
const PRINCIPAL: &str = "acct:battery";

const ANTHROPIC: &[(&str, &str)] = &[
    ("content-type", "application/json"),
    ("anthropic-version", "2023-06-01"),
];

const JSON: &[(&str, &str)] = &[("content-type", "application/json")];

fn pool(members: Vec<Member>) -> Pool {
    Pool { name: "p", members }
}

fn chat_body() -> Value {
    json!({
        "model": "p",
        "messages": [{"role": "user", "content": "hi"}],
        "max_tokens": 10
    })
}

// ── the rewrite chain ────────────────────────────────────────────────────────────────────────────

/// One link of a rewrite chain: records the turns it was shown, then replaces them with one user
/// turn carrying its marker.
struct ChainLink {
    marker: &'static str,
    saw: Mutex<Option<Vec<(String, String)>>>,
}

#[async_trait::async_trait]
impl RoutingPolicy for ChainLink {
    async fn decide(
        &self,
        _: &RoutingRequest<'_>,
        _: &[Candidate<'_>],
        _: &RoutingContext<'_>,
        _: Duration,
    ) -> PolicyResult {
        Ok(RoutingDecision::Abstain)
    }
    fn name(&self) -> &'static str {
        "mock-rewrite"
    }
    async fn transform(&self, req: &RoutingRequest<'_>, _: Duration) -> TransformOutcome {
        *self.saw.lock().unwrap() = req.prompt.as_ref().map(|p| {
            p.messages
                .iter()
                .map(|(r, t)| (r.to_string(), t.to_string()))
                .collect()
        });
        TransformOutcome::Rewrite(RewriteReply {
            messages: vec![json!({"role": "user", "content": self.marker})],
            tools: vec![],
        })
    }
}

/// Two global rewrite hooks run in configuration order, the second seeing the first's output, and
/// the far end is sent the last one's rewrite.
///
/// Ports legacy `engine/tests/usage_tap_tests.rs::apply_global_rewrites_chains_in_order`.
#[tokio::test]
async fn global_rewrites_chain_in_order_and_the_last_wins() {
    let link = |marker| {
        Arc::new(ChainLink {
            marker,
            saw: Mutex::new(None),
        })
    };
    let (a, b) = (link("A"), link("B"));
    let rig = Rig::new(
        pool(vec![member("m0", "m0")]),
        None,
        Hooks {
            rewrites: vec![
                (Duration::from_millis(50), a.clone()),
                (Duration::from_millis(50), b.clone()),
            ],
            ..Hooks::default()
        },
    );
    let answer = rig
        .fire(&json!({
            "model": "p",
            "max_tokens": 10,
            "messages": [{"role": "user", "content": "orig"}]
        }))
        .await;
    assert_eq!(answer.status, 200, "{}", answer.text());
    assert_eq!(
        a.saw.lock().unwrap().clone(),
        Some(vec![("user".to_string(), "orig".to_string())]),
        "the first rewrite sees the caller's turns"
    );
    assert_eq!(
        b.saw.lock().unwrap().clone(),
        Some(vec![("user".to_string(), "A".to_string())]),
        "the second rewrite runs on the first one's output"
    );
    let sent: Value =
        serde_json::from_slice(&answer.sent.last().expect("dispatched").body).expect("JSON");
    // Last hook in the chain wins; B ran on A's rewritten body.
    assert_eq!(sent["messages"][0]["content"], "B");
}

// ── the tap's group scope ────────────────────────────────────────────────────────────────────────

/// A response-stage tap scoped to `engineering`, its capture.
fn scoped_tap() -> (Arc<CaptureTap>, TapEntry) {
    let cap = Arc::new(CaptureTap {
        last: Mutex::new(None),
    });
    let policy: Arc<dyn RoutingPolicy> = cap.clone();
    (
        cap,
        (
            Duration::from_millis(500),
            false,
            policy,
            vec!["engineering".to_string()],
        ),
    )
}

/// One served unit whose verified caller is in `groups` (self and ancestors), with the scoped tap
/// on the response stage.
async fn scoped_run(groups: &[&str]) -> Arc<CaptureTap> {
    let (cap, tap) = scoped_tap();
    let mut callers = Callers::default();
    callers.groups.insert(
        PRINCIPAL.to_string(),
        groups.iter().map(|g| (*g).to_string()).collect(),
    );
    let mut hooks = Hooks {
        callers,
        ..Hooks::default()
    };
    hooks.taps.response = vec![tap];
    let rig = Rig::new(pool(vec![member("m0", "served")]), None, hooks);
    let answer = rig.fire(&chat_body()).await;
    assert_eq!(answer.status, 200, "{}", answer.text());
    cap
}

/// A group-scoped stage tap fires for a caller in the group and never for one outside it, the
/// scope resolved through the hook stage's caller seam.
///
/// Ports legacy `engine/tests/hook_seam_tests.rs::substrate_fire_stage_taps_honors_group_scope_via_host_seam`.
#[tokio::test]
async fn a_group_scoped_stage_tap_fires_only_for_an_in_group_caller() {
    // IN-group caller (`user:bob` ∈ engineering) → the tap FIRES.
    let cap_in = scoped_run(&["user:bob", "engineering"]).await;
    let payload = wait_for_tap_body(&cap_in).await;
    assert_eq!(
        payload["stage"]["at"], "response",
        "the in-group caller's group-scoped stage tap must fire with the notify wire: {payload}"
    );

    // OUT-of-group caller (`user:sue` ∈ sales) → the tap does NOT fire.
    let cap_out = scoped_run(&["user:sue", "sales"]).await;
    for _ in 0..30 {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        cap_out.last.lock().unwrap().is_none(),
        "an out-of-group caller must NOT fire a group-scoped stage tap"
    );
}

// ── content the reader cannot model ──────────────────────────────────────────────────────────────

/// A valid request carrying a role and a block type the reader has never heard of reaches a
/// content gate, which sees the turns busbar can read, and is forwarded upstream byte for byte;
/// unreadable content contributes nothing and never refuses the request.
///
/// Ports legacy `engine/tests/hook_seam_tests.rs::unreadable_content_reaches_the_gate_and_is_forwarded`.
#[tokio::test]
async fn unreadable_content_reaches_the_gate_and_is_forwarded_byte_for_byte() {
    let (seen, gate) = capturing(true, false, None);
    let rig = Rig::new(
        pool(vec![member("m0", "m0")]),
        None,
        Hooks {
            gates: vec![(0, gate)],
            ..Hooks::default()
        },
    );
    let body = r#"{"model":"m0","max_tokens":10,"messages":[{"role":"wizard","content":"cast"},{"role":"user","content":[{"type":"text","text":"READABLE"},{"type":"never_heard_of","x":1}]}]}"#;
    let answer = rig
        .fire_with(
            &crate::common::TestUnits::passing(),
            "/v1/messages",
            ANTHROPIC,
            body.as_bytes(),
        )
        .await;
    assert_eq!(
        answer.status,
        200,
        "never refused for content it cannot read: {}",
        answer.text()
    );
    let upstream = answer
        .sent
        .last()
        .expect("the upstream received the request");
    assert_eq!(
        String::from_utf8_lossy(&upstream.body),
        body,
        "forwarded byte for byte"
    );
    let captured = seen.lock().unwrap().clone().expect("the gate ran");
    let (_, turns) = captured.prompt.expect("the gate was handed the prompt");
    assert!(
        turns
            .iter()
            .any(|(r, t)| r == "user" && t.contains("READABLE")),
        "the gate sees what busbar can read: {turns:?}"
    );
    assert!(
        turns.iter().all(|(r, _)| r != "wizard" && !r.is_empty()),
        "an unreadable turn contributes nothing: {turns:?}"
    );
}

// ── the four 503 bodies a hook can produce ───────────────────────────────────────────────────────

const GATE_COULD_NOT_COMPLETE: &str = "A required gate could not complete. Please retry shortly.";
const GATE_RESTRICT_EMPTY: &str =
    "No upstream satisfies a required gate's restriction. Please retry shortly.";
const POLICY_COULD_NOT_SELECT: &str =
    "The routing policy could not select an upstream. Please retry shortly.";
const POLICY_RESTRICT_EMPTY: &str =
    "No upstream satisfies the routing policy's restriction. Please retry shortly.";

/// The OpenAI-native spelling of busbar's overloaded 503 kind (`overloaded` is not an OpenAI
/// error type; its writer maps it onto `server_error`).
const OVERLOADED_ON_OPENAI: &str = "server_error";

/// A hook that either fails outright or restricts to a tag no lane carries.
#[derive(Clone, Copy)]
enum Fault {
    Error,
    RestrictToNothing,
}

struct FaultyHook(Fault);

#[async_trait::async_trait]
impl RoutingPolicy for FaultyHook {
    async fn decide(
        &self,
        _: &RoutingRequest<'_>,
        _: &[Candidate<'_>],
        _: &RoutingContext<'_>,
        _: Duration,
    ) -> PolicyResult {
        match self.0 {
            Fault::Error => Err("deliberately broken".into()),
            Fault::RestrictToNothing => Ok(RoutingDecision::Restrict {
                tags_any: vec!["a-tag-no-lane-carries".to_string()],
            }),
        }
    }
    fn name(&self) -> &'static str {
        "faulty"
    }
}

/// Fail-closed on the restriction axis; `on_error` is the operator's.
fn resolved(fault: Fault, on_error: PolicyOnError) -> ResolvedPolicy {
    ResolvedPolicy::Policy {
        policy: Arc::new(FaultyHook(fault)),
        on_error,
        on_error_chain: Vec::new(),
        timeout: Duration::from_millis(50),
        send_prompt: false,
        send_user: false,
        on_empty: PolicyOnError::Reject,
    }
}

/// Where the faulty hook is seated.
#[derive(Clone, Copy)]
enum Seat {
    DecisionGate,
    BasePolicy,
}

/// One OpenAI chat request at a two-member pool (tagged `eu` and `us`, both unreachable) with the
/// faulty hook in `seat`: (status, error kind, error message) from the OpenAI envelope.
async fn fire(seat: Seat, fault: Fault, on_error: PolicyOnError) -> (u32, String, String) {
    let members = vec![
        member("m0", "m0").provider("oai").tags(&["eu"]).dead(),
        member("m1", "m1").provider("oai").tags(&["us"]).dead(),
    ];
    let hooks = match seat {
        Seat::DecisionGate => Hooks {
            gates: vec![(0, resolved(fault, on_error))],
            ..Hooks::default()
        },
        Seat::BasePolicy => Hooks {
            policy: Some(resolved(fault, on_error)),
            ..Hooks::default()
        },
    };
    let rig = Rig::new(pool(members), None, hooks);
    let answer: Answered = rig
        .fire_with(
            &crate::common::TestUnits::passing(),
            "/v1/chat/completions",
            JSON,
            &serde_json::to_vec(
                &json!({"model": "p", "messages": [{"role": "user", "content": "hi"}]}),
            )
            .expect("body serializes"),
        )
        .await;
    let v = answer.json();
    assert!(!v.is_null(), "a JSON error body: {}", answer.text());
    (
        answer.status,
        v["error"]["type"].as_str().unwrap_or_default().to_string(),
        v["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
    )
}

/// An errored decision gate declared load-bearing (`on_error: reject`) is refused with busbar's
/// overloaded 503 kind and its own body.
///
/// Ports legacy `engine/tests/gate_policy_503_literals_tests.rs::decision_gate_that_cannot_complete_has_its_own_503_body`.
#[tokio::test]
async fn a_decision_gate_that_cannot_complete_has_its_own_503_body() {
    let (status, kind, message) =
        fire(Seat::DecisionGate, Fault::Error, PolicyOnError::Reject).await;
    assert_eq!((status, kind.as_str()), (503, OVERLOADED_ON_OPENAI));
    assert_eq!(message, GATE_COULD_NOT_COMPLETE);
}

/// A decision gate whose restriction leaves no member is refused with its own 503 body.
///
/// Ports legacy `engine/tests/gate_policy_503_literals_tests.rs::decision_gate_restriction_leaving_no_lane_has_its_own_503_body`.
#[tokio::test]
async fn a_decision_gate_restriction_leaving_no_member_has_its_own_503_body() {
    let (status, kind, message) = fire(
        Seat::DecisionGate,
        Fault::RestrictToNothing,
        PolicyOnError::Reject,
    )
    .await;
    assert_eq!((status, kind.as_str()), (503, OVERLOADED_ON_OPENAI));
    assert_eq!(message, GATE_RESTRICT_EMPTY);
}

/// The pool's base routing policy that errors under `on_error: reject` is refused with its own
/// 503 body.
///
/// Ports legacy `engine/tests/gate_policy_503_literals_tests.rs::base_policy_that_cannot_select_has_its_own_503_body`.
#[tokio::test]
async fn a_base_policy_that_cannot_select_has_its_own_503_body() {
    let (status, kind, message) = fire(Seat::BasePolicy, Fault::Error, PolicyOnError::Reject).await;
    assert_eq!((status, kind.as_str()), (503, OVERLOADED_ON_OPENAI));
    assert_eq!(message, POLICY_COULD_NOT_SELECT);
}

/// The pool's base routing policy whose restriction leaves no member is refused with its own 503
/// body.
///
/// Ports legacy `engine/tests/gate_policy_503_literals_tests.rs::base_policy_restriction_leaving_no_lane_has_its_own_503_body`.
#[tokio::test]
async fn a_base_policy_restriction_leaving_no_member_has_its_own_503_body() {
    let (status, kind, message) = fire(
        Seat::BasePolicy,
        Fault::RestrictToNothing,
        PolicyOnError::Reject,
    )
    .await;
    assert_eq!((status, kind.as_str()), (503, OVERLOADED_ON_OPENAI));
    assert_eq!(message, POLICY_RESTRICT_EMPTY);
}

/// The same failed gate call under a hook the operator did NOT declare load-bearing
/// (`on_error: weighted`) refuses nothing: it degrades to a route, and the refusal body belongs to
/// `on_error: reject` alone.
///
/// Ports legacy `engine/tests/gate_policy_503_literals_tests.rs::decision_gate_that_cannot_complete_only_refuses_when_declared_load_bearing`.
#[tokio::test]
async fn a_decision_gate_that_cannot_complete_refuses_only_when_declared_load_bearing() {
    let (_status, _kind, message) =
        fire(Seat::DecisionGate, Fault::Error, PolicyOnError::Weighted).await;
    assert_ne!(
        message, GATE_COULD_NOT_COMPLETE,
        "`on_error: weighted` proceeds past a gate that could not answer; the refusal body belongs \
         to `on_error: reject` alone"
    );
}

/// The four hook-produced 503 bodies, as the caller is answered them, are pairwise distinct, so a
/// client can tell which hook refused it.
///
/// Ports legacy `engine/tests/gate_policy_503_literals_tests.rs::the_four_503_literals_are_distinct`.
#[tokio::test]
async fn the_four_hook_503_bodies_are_pairwise_distinct() {
    let mut all = Vec::new();
    for (seat, fault) in [
        (Seat::DecisionGate, Fault::Error),
        (Seat::DecisionGate, Fault::RestrictToNothing),
        (Seat::BasePolicy, Fault::Error),
        (Seat::BasePolicy, Fault::RestrictToNothing),
    ] {
        let (status, _, message) = fire(seat, fault, PolicyOnError::Reject).await;
        assert_eq!(status, 503);
        all.push(message);
    }
    for (i, a) in all.iter().enumerate() {
        for b in &all[i + 1..] {
            assert_ne!(a, b);
        }
    }
}

// ── the hook content ceiling ─────────────────────────────────────────────────────────────────────

/// The hook content ceiling defaults to 0 (the prompt projection is shown in full); a non-zero
/// ceiling omits over-ceiling content whole (never truncated) yet keeps the grant visible (a
/// present-but-empty projection) and the real `total_chars`.
///
/// Ports legacy `engine/tests/hook_opt_in_projection_tests.rs::hook_content_uncapped_by_default_and_omits_whole_when_opted_in`.
#[tokio::test]
async fn hook_content_is_uncapped_by_default_and_omitted_whole_when_opted_in() {
    let big = "x".repeat(200_000);
    let v = json!({"model": "m0", "messages": [{"role": "user", "content": big}]});
    let shown = || async {
        let (seen, policy) = capturing(true, false, None);
        let rig = Rig::new(
            pool(vec![member("m0", "m0").provider("oai")]),
            None,
            Hooks {
                policy: Some(policy),
                ..Hooks::default()
            },
        );
        let answer = rig
            .fire_with(
                &crate::common::TestUnits::passing(),
                "/v1/chat/completions",
                JSON,
                &serde_json::to_vec(&v).expect("body serializes"),
            )
            .await;
        assert_eq!(answer.status, 200, "{}", answer.text());
        let captured = seen.lock().unwrap().clone();
        captured.expect("the policy was asked")
    };

    // 1. DEFAULT (unlimited): the over-64KiB body is projected in FULL.
    busbar_kernel::proxy::set_hook_content_max_bytes(
        busbar_kernel::proxy::DEFAULT_HOOK_CONTENT_MAX_BYTES,
    );
    assert_eq!(
        busbar_kernel::proxy::DEFAULT_HOOK_CONTENT_MAX_BYTES,
        0,
        "the prompt projection default is UNLIMITED (0); anything else is fail-open regression"
    );
    let c = shown().await;
    let (_, messages) = c.prompt.expect("a prompt: ro hook is shown the prompt");
    assert_eq!(
        messages.len(),
        1,
        "with the cap OFF by default the body is projected in FULL"
    );
    assert_eq!(messages[0].1.len(), 200_000, "content sent uncapped");

    // 2. OPT-IN ceiling: over-cap content is omitted WHOLE, grant stays visible (present-but-empty).
    busbar_kernel::proxy::set_hook_content_max_bytes(64 * 1024);
    let c = shown().await;
    // Restore the unlimited default for other tests sharing the process-global ceiling.
    busbar_kernel::proxy::set_hook_content_max_bytes(
        busbar_kernel::proxy::DEFAULT_HOOK_CONTENT_MAX_BYTES,
    );
    let (system, messages) = c.prompt.expect(
        "the grant is honoured: an over-cap projection is EMPTY, never absent — absence is what an \
         UNGRANTED hook sees, and the two must stay distinguishable",
    );
    assert!(messages.is_empty(), "content omitted whole");
    assert_eq!(system, None);
    assert_eq!(
        c.total_chars, 200_000,
        "the size bucket still reports the real total, so the omission is visible"
    );
}

// ── the response tap's `response_tokens_out` ─────────────────────────────────────────────────────

/// The response tap's payload for one served anthropic-ingress unit over an openai member
/// reporting two output tokens, `response_tokens_out` declared or not.
async fn response_tap_payload(declared: bool) -> Value {
    let (cap, tap) = crate::policies::webhook_tap();
    let mut requested = RequestedSignals::default();
    if declared {
        requested.insert(Signal::ResponseTokensOut);
    }
    let mut hooks = Hooks {
        requested,
        ..Hooks::default()
    };
    hooks.taps.response = vec![tap];
    let rig = Rig::new(
        pool(vec![member("m", "m").provider("oai").output_tokens(2)]),
        None,
        hooks,
    );
    let answer = rig.fire(&chat_body()).await;
    assert_eq!(answer.status, 200, "the answer was delivered");
    wait_for_tap_body(&cap).await
}

/// A tap declaring `response_tokens_out` reads the unit's reported output count on the `response`
/// stage tap; a deployment that declares nothing gets a payload with no such key.
///
/// Ports legacy `unit/tests/route.rs::completion_tap_carries_response_tokens_out_when_declared`.
#[tokio::test]
async fn the_response_tap_carries_response_tokens_out_when_declared() {
    let declared = response_tap_payload(true).await;
    assert_eq!(declared["stage"]["at"], "response");
    assert_eq!(
        declared["request"]["response_tokens_out"], 2,
        "a declared response_tokens_out carries the unit's output count"
    );
    let undeclared = response_tap_payload(false).await;
    assert!(
        undeclared["request"].get("response_tokens_out").is_none(),
        "an undeclared signal adds no key to the payload"
    );
}
