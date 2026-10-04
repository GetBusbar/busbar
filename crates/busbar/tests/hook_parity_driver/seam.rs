// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `v1.5.5` `crates/busbar/src/proxy/tests/hook_seam_tests.rs`, on the driver: the opt-in grants
//! (what a hook is shown), the decision gates and the base policy (reject, restrict, order and
//! their reconcile), the on-error chain, the rewrite chain, the stage taps, the reject envelopes
//! and the correlation id. Each test keeps its 1.5.5 name and the values 1.5.5 asserted.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use busbar_kernel::config::PolicyOnError;
use busbar_kernel::hooks::{FallbackHook, ResolvedPolicy};
use busbar_kernel::plane_driver::{CallerKey, Constraint, Restrict};
use serde_json::{json, Value};

use crate::policies::{
    canned_gate, capturing, rewriting, wait_for_tap_body, webhook_tap, Canned, CannedGate,
    ErroringPolicy,
};
use crate::rig::{member, Callers, Hooks, Pool, Rig};

/// The principal the kernel's passing steps verify.
const PRINCIPAL: &str = "acct:battery";

fn pool(members: Vec<crate::rig::Member>) -> Pool {
    Pool { name: "p", members }
}

/// One live member.
fn one() -> Pool {
    pool(vec![member("m0", "m0")])
}

/// One dead member.
fn one_dead() -> Pool {
    pool(vec![member("m0", "m0").dead()])
}

fn body() -> Value {
    // The end-user id spelled the way this dialect spells it (`metadata.user_id` on Anthropic),
    // and the `user` key beside it, as a client may send both.
    json!({
        "model": "m0",
        "max_tokens": 16,
        "system": "sys prompt",
        "user": "alice",
        "metadata": {"user_id": "alice"},
        "messages": [{"role": "user", "content": "hello"}]
    })
}

fn chat_body() -> Value {
    json!({
        "model": "p",
        "messages": [{"role": "user", "content": "hi"}],
        "max_tokens": 10
    })
}

/// The previous release's `run`: a one-member pool whose base route policy is a capturing
/// policy with these grants and this decision, one unit of `v`; what it saw and the answer.
async fn run(
    send_prompt: bool,
    send_user: bool,
    reject: Option<(u16, String)>,
    v: Value,
) -> (crate::rig::Answered, Option<crate::policies::CapturedReq>) {
    let (seen, policy) = capturing(send_prompt, send_user, reject);
    let rig = Rig::new(
        one(),
        None,
        Hooks {
            policy: Some(policy),
            ..Hooks::default()
        },
    );
    let answer = rig.fire(&v).await;
    let captured = seen.lock().unwrap().clone();
    (answer, captured)
}

fn gates(gates: Vec<(u16, ResolvedPolicy)>) -> Hooks {
    Hooks {
        gates,
        ..Hooks::default()
    }
}

#[tokio::test]
async fn default_flags_project_nothing() {
    let (answer, captured) = run(false, false, None, body()).await;
    let captured = captured.expect("policy must have been called");
    assert!(captured.prompt.is_none(), "send_prompt off ⇒ no prompt");
    assert!(captured.identity.is_none(), "send_user off ⇒ no identity");
    assert_eq!(answer.status, 200, "abstain ⇒ the walk's own pick serves");
}

#[tokio::test]
async fn global_gate_reject_short_circuits_the_request() {
    let (_, gate) = capturing(false, false, Some((451, "blocked by global policy".into())));
    let rig = Rig::new(one_dead(), None, gates(vec![(0, gate)]));
    let answer = rig.fire(&chat_body()).await;
    assert_eq!(
        answer.status, 451,
        "a global reject gate must short-circuit with its clamped status, before any dispatch"
    );
    assert!(answer.sent.is_empty(), "no far end was reached");
}

#[tokio::test]
async fn global_gate_abstain_does_not_reject() {
    let (_, gate) = capturing(false, false, None);
    let rig = Rig::new(one_dead(), None, gates(vec![(0, gate)]));
    let answer = rig.fire(&chat_body()).await;
    assert_ne!(
        answer.status, 451,
        "an abstaining global gate must not reject the request"
    );
    assert_eq!(answer.sent.len(), 1, "the request proceeded to the walk");
}

#[test]
fn enforce_restricts_reapplies_compliance_tags_across_pools() {
    // Fallback pool "fb": member 0 carries `baa`, member 1 carries nothing.
    let tags: Vec<Vec<String>> = vec![vec!["baa".to_string()], vec![]];
    let members = || tags.iter().enumerate().map(|(i, t)| (i, t.as_slice()));
    let restrict = |tag: &str, on_empty: PolicyOnError, name: &'static str| Constraint {
        restricts: vec![Restrict {
            tags_any: vec![tag.to_string()],
            on_empty,
            name,
        }],
        ..Constraint::default()
    };

    // A required `baa` restrict narrows the fallback pool to ONLY the tagged member.
    assert_eq!(
        restrict("baa", PolicyOnError::Reject, "baa-gate")
            .enforce(members())
            .unwrap(),
        vec![0],
        "only the baa-tagged fallback lane may survive a required restrict"
    );
    // A required restrict with NO matching fallback member fails CLOSED, never spills.
    assert!(
        restrict("hipaa", PolicyOnError::Reject, "hipaa-gate")
            .enforce(members())
            .is_err(),
        "a required restrict with no eligible fallback lane must fail closed, not spill"
    );
    // A `weighted` restrict with no match is an advisory escape — candidates pass unchanged.
    assert_eq!(
        restrict("hipaa", PolicyOnError::Weighted, "hipaa-advisory")
            .enforce(members())
            .unwrap()
            .len(),
        2,
        "a weighted restrict with no eligible lane escapes (candidates unchanged)"
    );
    // No active restrict → identity.
    assert_eq!(Constraint::default().enforce(members()).unwrap().len(), 2);
}

#[tokio::test]
async fn base_policy_restrict_persists_across_fallback_pool_hop() {
    let primary = pool(vec![member("primary", "primary").tags(&["baa"]).dead()]);
    let fallback = Pool {
        name: "fb",
        members: vec![member("fbmember", "fbmember")],
    };
    let rig = Rig::new(
        primary,
        Some(fallback),
        Hooks {
            policy: Some(canned_gate(
                Canned::Restrict(vec!["baa".to_string()]),
                "compliance",
            )),
            ..Hooks::default()
        },
    );
    let answer = rig.fire(&chat_body()).await;
    assert_eq!(
        answer.status, 503,
        "a base-policy compliance restrict must fail closed at the fallback boundary"
    );
    assert!(
        answer.text().contains("restriction"),
        "the 503 must be the compliance fail-closed, not a generic transport 503: {}",
        answer.text()
    );
    assert!(
        answer.sent.iter().all(|r| r.member != "fbmember"),
        "the ineligible fallback member is never served"
    );
}

#[tokio::test]
async fn completion_tap_fires_synthetic_rejected_by_auth() {
    let (cap, tap) = webhook_tap();
    let mut hooks = Hooks::default();
    hooks.taps.response = vec![tap];
    let rig = Rig::new(one_dead(), None, hooks);
    let answer = rig
        .fire_unauthenticated("/v1/messages", &serde_json::to_vec(&chat_body()).unwrap())
        .await;
    assert_eq!(answer.status, 401);
    let payload = wait_for_tap_body(&cap).await;
    assert_eq!(payload["stage"]["at"], "response");
    assert_eq!(payload["stage"]["outcome"], "rejected_by_auth");
    assert_eq!(payload["stage"]["status"], 401);
}

#[tokio::test]
async fn completion_tap_status_is_protocol_native_gemini_400() {
    let (cap, tap) = webhook_tap();
    let mut hooks = Hooks::default();
    hooks.taps.response = vec![tap];
    let rig = Rig::new(one_dead(), None, hooks);
    // Gemini ingress path + bad key → the served response is HTTP 400 (not 401).
    let answer = rig
        .fire_unauthenticated(
            "/v1beta/models/gemini-x:generateContent",
            br#"{"contents":[{"role":"user","parts":[{"text":"hi"}]}]}"#,
        )
        .await;
    assert_eq!(answer.status, 400, "gemini bad-key is native 400");
    let payload = wait_for_tap_body(&cap).await;
    assert_eq!(payload["stage"]["outcome"], "rejected_by_auth");
    assert_eq!(
        payload["stage"]["status"], 400,
        "the tap status must match the client-visible native status, not a hardcoded 401"
    );
}

#[tokio::test]
async fn completion_tap_fires_synthetic_rejected_by_gate() {
    let (cap, tap) = webhook_tap();
    let mut hooks = gates(vec![(
        0,
        canned_gate(Canned::Reject(451, "denied"), "denier"),
    )]);
    hooks.taps.response = vec![tap];
    let rig = Rig::new(one_dead(), None, hooks);
    let answer = rig.fire(&chat_body()).await;
    assert_eq!(answer.status, 451);
    let payload = wait_for_tap_body(&cap).await;
    assert_eq!(payload["stage"]["at"], "response");
    assert_eq!(payload["stage"]["outcome"], "rejected_by_gate");
    assert_eq!(payload["stage"]["status"], 451);
}

#[tokio::test]
async fn completion_tap_reports_ok_outcome() {
    let (cap, tap) = webhook_tap();
    let mut hooks = Hooks::default();
    hooks.taps.response = vec![tap];
    let rig = Rig::new(pool(vec![member("m0", "served")]), None, hooks);
    let answer = rig.fire(&chat_body()).await;
    assert_eq!(answer.status, 200);
    let payload = wait_for_tap_body(&cap).await;
    assert_eq!(payload["stage"]["at"], "response");
    assert_eq!(payload["stage"]["outcome"], "ok");
    assert_eq!(payload["stage"]["status"], 200);
}

#[tokio::test]
async fn attempt_tap_carries_attempt_story() {
    let (cap, tap) = webhook_tap();
    let mut hooks = Hooks::default();
    hooks.taps.routing = vec![tap];
    let rig = Rig::new(pool(vec![member("m0", "served")]), None, hooks);
    let answer = rig.fire(&chat_body()).await;
    assert_eq!(answer.status, 200);
    let payload = wait_for_tap_body(&cap).await;
    assert_eq!(payload["stage"]["at"], "routing");
    assert_eq!(payload["stage"]["attempt_number"], 1);
    assert_eq!(payload["stage"]["model"], "m0");
    assert!(
        payload["stage"].get("previous_failure").is_none(),
        "no failure precedes the first attempt"
    );
}

#[tokio::test]
async fn route_tap_reports_surviving_candidates() {
    let (cap, tap) = webhook_tap();
    let mut hooks = Hooks::default();
    hooks.taps.candidate = vec![tap];
    let rig = Rig::new(pool(vec![member("m0", "served")]), None, hooks);
    let answer = rig.fire(&chat_body()).await;
    assert_eq!(answer.status, 200);
    let payload = wait_for_tap_body(&cap).await;
    assert_eq!(payload["stage"]["at"], "candidate");
    assert_eq!(payload["stage"]["remaining_candidates"], 1);
}

/// The body the far end was sent.
fn sent_body(answer: &crate::rig::Answered) -> Value {
    let last = answer
        .sent
        .last()
        .expect("upstream must have been dispatched");
    serde_json::from_slice(&last.body).expect("the far end's body is JSON")
}

#[tokio::test]
async fn same_protocol_passthrough_carries_global_rewrite() {
    let rig = Rig::new(
        one(),
        None,
        Hooks {
            rewrites: vec![rewriting("COMPRESSED")],
            ..Hooks::default()
        },
    );
    let answer = rig.fire(&chat_body()).await;
    assert_eq!(answer.status, 200);
    assert_eq!(
        sent_body(&answer)["messages"][0]["content"],
        "COMPRESSED",
        "the upstream must see the REWRITTEN body on the same-protocol fast path"
    );
}

#[tokio::test]
async fn pool_scoped_rw_gate_rewrites_the_body() {
    let rig = Rig::new(
        one(),
        None,
        Hooks {
            pool_rewrites: vec![rewriting("POOL-COMPRESSED")],
            ..Hooks::default()
        },
    );
    let answer = rig.fire(&chat_body()).await;
    assert_eq!(answer.status, 200);
    assert_eq!(
        sent_body(&answer)["messages"][0]["content"],
        "POOL-COMPRESSED",
        "a pool-scoped rw gate must rewrite the dispatched body"
    );
}

#[tokio::test]
async fn on_error_fallback_hook_fires_and_decides() {
    let gate = ResolvedPolicy::Policy {
        policy: Arc::new(ErroringPolicy),
        on_error: PolicyOnError::Weighted,
        on_error_chain: vec![FallbackHook {
            policy: Arc::new(CannedGate {
                canned: Canned::Reject(451, "fallback says no"),
                name: "backup",
            }),
            timeout: Duration::from_millis(500),
            send_prompt: false,
            send_user: false,
            on_empty: PolicyOnError::Reject,
        }],
        timeout: Duration::from_millis(50),
        send_prompt: false,
        send_user: false,
        on_empty: PolicyOnError::Reject,
    };
    let rig = Rig::new(one_dead(), None, gates(vec![(0, gate)]));
    let answer = rig.fire(&chat_body()).await;
    assert_eq!(
        answer.status, 451,
        "the failed gate's fallback hook must fire and its reject must be honored"
    );
}

#[tokio::test]
async fn on_error_chain_exhausted_applies_terminal() {
    let gate = ResolvedPolicy::Policy {
        policy: Arc::new(ErroringPolicy),
        on_error: PolicyOnError::Reject,
        on_error_chain: vec![FallbackHook {
            policy: Arc::new(ErroringPolicy),
            timeout: Duration::from_millis(50),
            send_prompt: false,
            send_user: false,
            on_empty: PolicyOnError::Reject,
        }],
        timeout: Duration::from_millis(50),
        send_prompt: false,
        send_user: false,
        on_empty: PolicyOnError::Reject,
    };
    let rig = Rig::new(one_dead(), None, gates(vec![(0, gate)]));
    let answer = rig.fire(&chat_body()).await;
    assert_eq!(
        answer.status, 503,
        "an exhausted chain must land on the fail-closed reject terminal"
    );
    assert!(answer.sent.is_empty(), "refused before any dispatch");
}

#[tokio::test]
async fn on_error_reject_terminal_short_circuits_before_a_live_lane_ever_dispatches() {
    let gate = ResolvedPolicy::Policy {
        policy: Arc::new(ErroringPolicy),
        on_error: PolicyOnError::Reject,
        on_error_chain: vec![],
        timeout: Duration::from_millis(50),
        send_prompt: false,
        send_user: false,
        on_empty: PolicyOnError::Reject,
    };
    let rig = Rig::new(
        pool(vec![member("m0", "live-lane")]),
        None,
        gates(vec![(0, gate)]),
    );
    let answer = rig.fire(&chat_body()).await;
    assert_eq!(
        answer.status, 503,
        "an errored gate terminating in `on_error: reject` must fail closed BEFORE dispatch — a \
         live, healthy lane must never actually serve this request"
    );
    assert!(answer.sent.is_empty());
}

#[tokio::test]
async fn global_request_stage_tap_fires_on_a_real_dispatched_request() {
    let (cap, tap) = webhook_tap();
    let mut hooks = Hooks::default();
    hooks.taps.request = vec![tap];
    let rig = Rig::new(pool(vec![member("m0", "live-lane")]), None, hooks);
    let answer = rig.fire(&chat_body()).await;
    assert_eq!(
        answer.status, 200,
        "the request must still dispatch normally"
    );
    let payload = wait_for_tap_body(&cap).await;
    assert_eq!(
        payload["op"], "notify",
        "the global request-stage tap must receive the real notify wire envelope: {payload}"
    );
}

#[tokio::test]
async fn pool_gate_reject_fires_from_pool_runtime_gates() {
    let rig = Rig::new(
        one_dead(),
        None,
        Hooks {
            pool_gates: vec![(
                0,
                canned_gate(Canned::Reject(451, "pool gate says no"), "pg"),
            )],
            ..Hooks::default()
        },
    );
    let answer = rig.fire(&chat_body()).await;
    assert_eq!(
        answer.status, 451,
        "a pool gate must fire in the phase-2 reconcile"
    );
}

#[tokio::test]
async fn reject_priority_tie_break_surfaces_lowest_priority() {
    // Deliberately stated out of order: the stable sort must put 1 before 5.
    let rig = Rig::new(
        one_dead(),
        None,
        gates(vec![
            (
                5,
                canned_gate(Canned::Reject(451, "high priority number"), "late"),
            ),
            (
                1,
                canned_gate(Canned::Reject(452, "low priority number"), "early"),
            ),
        ]),
    );
    let answer = rig.fire(&chat_body()).await;
    assert_eq!(
        answer.status, 452,
        "the lowest-priority rejecting gate must supply the surfacing status"
    );
}

#[tokio::test]
async fn multi_restrict_disjoint_intersection_fails_closed() {
    let rig = Rig::new(
        pool(vec![
            member("eu-lane", "eu-lane").tags(&["eu"]).dead(),
            member("baa-lane", "baa-lane").tags(&["baa"]).dead(),
        ]),
        None,
        gates(vec![
            (0, canned_gate(Canned::Restrict(vec!["eu".into()]), "geo")),
            (
                1,
                canned_gate(Canned::Restrict(vec!["baa".into()]), "hipaa"),
            ),
        ]),
    );
    let answer = rig.fire(&chat_body()).await;
    assert_eq!(
        answer.status, 503,
        "disjoint concurrent restricts must intersect to empty and fail closed"
    );
}

#[tokio::test]
async fn multi_restrict_intersection_dispatches_only_the_survivor() {
    let rig = Rig::new(
        pool(vec![
            member("eu-only", "eu-only").tags(&["eu"]).dead(),
            member("eu-baa", "both").tags(&["eu", "baa"]),
        ]),
        None,
        gates(vec![
            (0, canned_gate(Canned::Restrict(vec!["eu".into()]), "geo")),
            (
                1,
                canned_gate(Canned::Restrict(vec!["baa".into()]), "hipaa"),
            ),
        ]),
    );
    let answer = rig.fire(&chat_body()).await;
    assert_eq!(answer.status, 200);
    assert_eq!(
        answer.model(),
        "both",
        "dispatch must stay inside the restrict intersection"
    );
}

#[tokio::test]
async fn stale_order_filtered_against_post_restrict_set() {
    let rig = Rig::new(
        pool(vec![
            member("excluded", "excluded").tags(&["a"]).dead(),
            member("kept-lane", "kept").tags(&["b"]),
        ]),
        None,
        gates(vec![
            (0, canned_gate(Canned::Order(vec![0]), "orderer")),
            (
                1,
                canned_gate(Canned::Restrict(vec!["b".into()]), "restrictor"),
            ),
        ]),
    );
    let answer = rig.fire(&chat_body()).await;
    assert_eq!(answer.status, 200);
    assert_eq!(
        answer.model(),
        "kept",
        "a t0 order naming only restricted-out members must abstain to the surviving set"
    );
}

#[tokio::test]
async fn order_last_in_chain_wins() {
    let rig = Rig::new(
        pool(vec![member("lane-a", "alpha"), member("lane-b", "beta")]),
        None,
        gates(vec![
            (0, canned_gate(Canned::Order(vec![0, 1]), "first")),
            (1, canned_gate(Canned::Order(vec![1, 0]), "second")),
        ]),
    );
    let answer = rig.fire(&chat_body()).await;
    assert_eq!(answer.status, 200);
    assert_eq!(
        answer.model(),
        "beta",
        "the LAST ordering gate in the chain must win the reconcile"
    );
}

#[tokio::test]
async fn last_order_gate_filtered_to_empty_abstains_to_base_not_to_a_lower_gate() {
    let rig = Rig::new(
        pool(vec![
            member("base-lane", "base").tags(&["keep"]),
            member("low-lane", "low").tags(&["keep"]),
            member("excluded-lane", "excluded").dead(),
        ]),
        None,
        gates(vec![
            (
                0,
                canned_gate(Canned::Restrict(vec!["keep".into()]), "restrictor"),
            ),
            (10, canned_gate(Canned::Order(vec![1]), "low-orderer")),
            (20, canned_gate(Canned::Order(vec![2]), "high-orderer")),
        ]),
    );
    let answer = rig.fire(&chat_body()).await;
    assert_eq!(answer.status, 200);
    assert_eq!(
        answer.model(),
        "base",
        "a filtered-to-empty highest-priority order must abstain to the pool's base ordering, \
         not fall through to a lower-priority gate's stale order"
    );
}

#[tokio::test]
async fn global_gate_order_arm_is_honored() {
    let rig = Rig::new(
        pool(vec![member("lane-a", "alpha"), member("lane-b", "beta")]),
        None,
        gates(vec![(0, canned_gate(Canned::Order(vec![1]), "prefer-b"))]),
    );
    let answer = rig.fire(&chat_body()).await;
    assert_eq!(answer.status, 200);
    assert_eq!(
        answer.model(),
        "beta",
        "a global ordering gate must steer dispatch (the ORDER arm is live)"
    );
}

#[tokio::test]
async fn send_prompt_projects_content_only() {
    let (_, captured) = run(true, false, None, body()).await;
    let captured = captured.expect("policy must have been called");
    let (system, messages) = captured.prompt.expect("send_prompt on ⇒ prompt present");
    assert_eq!(system.as_deref(), Some("sys prompt"));
    assert_eq!(messages, vec![("user".to_string(), "hello".to_string())]);
    assert!(captured.identity.is_none(), "send_user off ⇒ no identity");
}

#[tokio::test]
async fn send_user_projects_identity_only() {
    let (_, captured) = run(false, true, None, body()).await;
    let captured = captured.expect("policy must have been called");
    assert!(captured.prompt.is_none(), "send_prompt off ⇒ no prompt");
    let (key_id, key_name, user) = captured.identity.expect("send_user on ⇒ identity present");
    assert_eq!(key_id, None, "no governance ⇒ no key id");
    assert_eq!(key_name, None, "no governance ⇒ no key name");
    assert_eq!(user.as_deref(), Some("alice"));
}

#[tokio::test]
async fn reject_decision_maps_to_reject_request_outcome() {
    let (answer, captured) = run(true, false, Some((451, "PII detected".into())), body()).await;
    assert!(captured.is_some(), "the policy decided");
    assert_eq!(answer.status, 451);
    assert_eq!(answer.json()["error"]["message"], "PII detected");
    assert!(
        answer.sent.is_empty(),
        "a rejection is a decision: nothing dispatched"
    );
}

#[tokio::test]
async fn max_tokens_saturates_not_wraps() {
    let v = json!({
        "model": "m0",
        "max_tokens": 5_000_000_000u64,
        "messages": [{"role": "user", "content": "hi"}]
    });
    let (_, captured) = run(false, false, None, v).await;
    let captured = captured.expect("policy must have been called");
    // 1.5.5: an absurd caller cap still signals "the largest cap there is".
    assert_eq!(captured.max_tokens, Some(u32::MAX));
    assert_ne!(
        captured.max_tokens,
        Some(5_000_000_000u64 as u32),
        "the one thing that must never happen is a wrap to a small number"
    );
}

/// A rig whose verified caller has `key`, and whose base policy is a `send_user` capture.
async fn identity_seen(key: Option<CallerKey>) -> crate::policies::CapturedReq {
    let (seen, policy) = capturing(false, true, None);
    let mut callers = Callers::default();
    if let Some(key) = key {
        callers.keys.insert(PRINCIPAL.to_string(), key);
    }
    let rig = Rig::new(
        one(),
        None,
        Hooks {
            policy: Some(policy),
            callers,
            ..Hooks::default()
        },
    );
    rig.fire(&body()).await;
    let captured = seen.lock().unwrap().clone();
    captured.expect("policy called")
}

#[tokio::test]
async fn send_user_projects_governance_key_identity() {
    let secret = "bb_sk_secret-material-never-projected";
    let captured = identity_seen(Some(CallerKey {
        id: "vk_123".to_string(),
        name: "sales-team".to_string(),
    }))
    .await;
    let (key_id, key_name, user) = captured.identity.expect("identity present");
    assert_eq!(key_id.as_deref(), Some("vk_123"));
    assert_eq!(key_name.as_deref(), Some("sales-team"));
    assert_eq!(user.as_deref(), Some("alice"));
    // The secret NEVER rides the projection, under any configuration.
    assert_ne!(key_id.as_deref(), Some(secret));
    assert_ne!(key_name.as_deref(), Some(secret));
}

#[tokio::test]
async fn send_user_falls_back_to_synthesized_group_key_identity() {
    // The key the identity step resolved for a group/SSO principal: its id/name carry the
    // principal.
    let captured = identity_seen(Some(CallerKey {
        id: "eng-oncall".to_string(),
        name: "eng-oncall".to_string(),
    }))
    .await;
    let (key_id, key_name, _user) = captured.identity.expect("identity present");
    assert_eq!(
        key_id.as_deref(),
        Some("eng-oncall"),
        "a group principal's synthesized key id must project, not fall through to None"
    );
    assert_eq!(key_name.as_deref(), Some("eng-oncall"));
}

#[tokio::test]
async fn send_user_prefers_resolved_key_over_disabled_legacy_lookup() {
    // The identity a hook sees is the key of the principal the kernel VERIFIED (the authoritative
    // admission), never a second lookup of the raw token.
    let captured = identity_seen(Some(CallerKey {
        id: "synthesized-principal".to_string(),
        name: "synthesized-principal".to_string(),
    }))
    .await;
    let (key_id, key_name, _user) = captured.identity.expect("identity present");
    assert_eq!(
        key_id.as_deref(),
        Some("synthesized-principal"),
        "must resolve to the key auth actually authorized (the synthesized key), \
         not the disabled legacy key a raw `lookup` would hit"
    );
    assert_eq!(key_name.as_deref(), Some("synthesized-principal"));
}

#[tokio::test]
async fn forward_with_pool_keyed_threads_group_key_to_pool_policy() {
    let captured = identity_seen(Some(CallerKey {
        id: "eng-oncall".to_string(),
        name: "eng-oncall".to_string(),
    }))
    .await;
    let (key_id, _, _) = captured.identity.expect("identity present");
    assert_eq!(
        key_id.as_deref(),
        Some("eng-oncall"),
        "the resolved key must reach a pool's send_user policy"
    );
}

#[tokio::test]
async fn reject_status_and_message_resanitized_at_the_seam() {
    let (answer, _) = run(
        false,
        false,
        Some((500, "evil\r\ninjected\u{202E}spoof".into())),
        body(),
    )
    .await;
    assert_eq!(answer.status, 403);
    assert_eq!(
        answer.json()["error"]["message"],
        "evilinjectedspoof",
        "seam must re-sanitize"
    );
}

/// One unit refused by a gate rejecting with `status` and `message`, at `target` in `dialect`.
async fn gate_refusal(
    status: u16,
    message: &'static str,
    target: &str,
    fields: &[(&str, &str)],
    body: &[u8],
) -> crate::rig::Answered {
    let rig = Rig::new(
        one_dead(),
        None,
        gates(vec![(
            0,
            canned_gate(Canned::Reject(status, message), "guard"),
        )]),
    );
    rig.fire_with(&crate::common::TestUnits::passing(), target, fields, body)
        .await
}

const ANTHROPIC: &[(&str, &str)] = &[
    ("content-type", "application/json"),
    ("anthropic-version", "2023-06-01"),
];

#[tokio::test]
async fn reject_408_maps_to_anthropic_timeout_envelope() {
    let answer = gate_refusal(
        408,
        "guardrail: request deadline",
        "/v1/messages",
        ANTHROPIC,
        &serde_json::to_vec(&chat_body()).unwrap(),
    )
    .await;
    assert_eq!(answer.status, 408);
    let v = answer.json();
    assert_eq!(v["error"]["type"], "timeout_error");
    assert_eq!(v["error"]["message"], "guardrail: request deadline");
}

#[tokio::test]
async fn reject_rides_the_full_forward_path() {
    let (seen, policy) = capturing(false, false, Some((451, "PII detected".into())));
    let rig = Rig::new(
        Pool {
            name: "pa",
            members: vec![member("m0", "m0")],
        },
        None,
        Hooks {
            policy: Some(policy),
            ..Hooks::default()
        },
    );
    let answer = rig
        .fire(&json!({
            "model": "pa",
            "messages": [{"role": "user", "content": "hi"}],
            "max_tokens": 5
        }))
        .await;
    assert_eq!(
        answer.status, 451,
        "the hook's status must reach the caller"
    );
    let v = answer.json();
    assert_eq!(v["type"], "error");
    assert_eq!(v["error"]["type"], "invalid_request_error");
    assert_eq!(v["error"]["message"], "PII detected");
    assert!(
        seen.lock().unwrap().is_some(),
        "the policy must actually have decided"
    );
}

#[test]
fn reject_kind_mapping_matches_status_semantics() {
    use crate::plane::exchange::refuse::gate_kind;
    use busbar_contract::protocol::{
        KIND_AUTHENTICATION, KIND_INVALID_REQUEST, KIND_NOT_FOUND, KIND_PERMISSION,
        KIND_RATE_LIMIT, KIND_TIMEOUT,
    };
    assert_eq!(gate_kind(401), KIND_AUTHENTICATION);
    assert_eq!(gate_kind(403), KIND_PERMISSION);
    assert_eq!(gate_kind(404), KIND_NOT_FOUND);
    assert_eq!(gate_kind(408), KIND_TIMEOUT);
    assert_eq!(gate_kind(429), KIND_RATE_LIMIT);
    for other in [400, 422, 451, 499] {
        assert_eq!(gate_kind(other), KIND_INVALID_REQUEST);
    }
}

#[tokio::test]
async fn reject_message_reaches_anthropic_error_body() {
    let answer = gate_refusal(
        451,
        "PII detected in message 3",
        "/v1/messages",
        ANTHROPIC,
        &serde_json::to_vec(&chat_body()).unwrap(),
    )
    .await;
    assert_eq!(answer.status, 451);
    let v = answer.json();
    assert_eq!(v["type"], "error");
    assert_eq!(
        v["error"]["message"], "PII detected in message 3",
        "the hook's sanitized reject message must reach the client verbatim"
    );
}

#[tokio::test]
async fn reject_produces_bedrock_native_envelope() {
    let answer = gate_refusal(
        429,
        "quota guardrail: try later",
        "/model/m0/converse",
        &[("content-type", "application/json")],
        br#"{"messages":[{"role":"user","content":[{"text":"hi"}]}]}"#,
    )
    .await;
    assert_eq!(answer.status, 429);
    assert!(
        answer
            .fields
            .iter()
            .any(|(n, _)| n.eq_ignore_ascii_case(b"x-amzn-errortype")),
        "Bedrock error envelope must carry x-amzn-errortype"
    );
    assert_eq!(
        answer.json()["message"],
        "quota guardrail: try later",
        "Bedrock error body carries the message field"
    );
}

#[test]
fn request_id_counter_is_unique_and_monotonic_across_sequential_requests() {
    // The counter the driver's binder stamps each unit from is the process's one counter
    // (`App::next_request_id`).
    let app = busbar_kernel::test_support::TestApp::new().build();
    let a = app.next_request_id();
    let b = app.next_request_id();
    let c = app.next_request_id();
    assert!(b > a, "the counter must strictly increase: {a} then {b}");
    assert!(c > b, "the counter must strictly increase: {b} then {c}");
    assert_eq!(b, a + 1, "a plain fetch_add(1): no gaps between requests");
    assert_eq!(c, a + 2);
    let app2 = busbar_kernel::test_support::TestApp::new().build();
    let d = app2.next_request_id();
    assert_ne!(
        d, a,
        "two independently-seeded counters must not coincide (boot entropy seed)"
    );
}

#[tokio::test]
async fn same_request_id_joins_gate_decision_and_completion_tap() {
    let (cap, tap) = webhook_tap();
    let (seen, gate) = capturing(false, false, None);
    let mut hooks = gates(vec![(0, gate)]);
    hooks.taps.response = vec![tap];
    let rig = Rig::new(pool(vec![member("m0", "served")]), None, hooks);
    let answer = rig.fire(&chat_body()).await;
    assert_eq!(answer.status, 200);
    let gate_request_id = seen
        .lock()
        .unwrap()
        .as_ref()
        .expect("the gate ran and captured the RoutingRequest")
        .request_id;
    let payload = wait_for_tap_body(&cap).await;
    let tap_request_id = payload["request"]["request_id"]
        .as_u64()
        .expect("response tap payload carries request_id as a plain integer");
    assert_eq!(
        gate_request_id, tap_request_id,
        "the pre-forward routing decision and the post-response response tap for the SAME \
         request must carry the IDENTICAL request_id — that identity is the join-key contract"
    );
}

/// A layer capturing the value recorded onto a native `u64` field named `request_id`.
#[derive(Clone, Default)]
struct RequestIdSpanCapture(Arc<Mutex<Option<u64>>>);

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for RequestIdSpanCapture {
    fn on_record(
        &self,
        _id: &tracing::span::Id,
        values: &tracing::span::Record<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        struct Vis<'a>(&'a Mutex<Option<u64>>);
        impl tracing::field::Visit for Vis<'_> {
            fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
                if field.name() == "request_id" {
                    *self.0.lock().unwrap() = Some(value);
                }
            }
            fn record_debug(&mut self, _: &tracing::field::Field, _: &dyn std::fmt::Debug) {}
        }
        values.record(&mut Vis(&self.0));
    }
}

#[tokio::test]
async fn request_id_is_recorded_as_native_u64_tracing_field() {
    let (cap, tap) = webhook_tap();
    let mut hooks = Hooks::default();
    hooks.taps.response = vec![tap];
    let rig = Rig::new(pool(vec![member("m0", "served")]), None, hooks);
    let seen = Arc::new(Mutex::new(None));
    use tracing_subscriber::layer::SubscriberExt as _;
    let subscriber = tracing_subscriber::registry().with(RequestIdSpanCapture(seen.clone()));
    let _guard = tracing::subscriber::set_default(subscriber);
    tracing::callsite::rebuild_interest_cache();
    let answer = rig.fire(&chat_body()).await;
    assert_eq!(answer.status, 200);
    let payload = wait_for_tap_body(&cap).await;
    let tap_id = payload["request"]["request_id"]
        .as_u64()
        .expect("the tap carries the id");
    assert_eq!(
        *seen.lock().unwrap(),
        Some(tap_id),
        "the unit's span records the SAME id the response tap carries, as a native u64"
    );
}
