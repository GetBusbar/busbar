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

use super::policies::{
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
) -> (crate::rig::Answered, Option<super::policies::CapturedReq>) {
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
async fn identity_seen(key: Option<CallerKey>) -> super::policies::CapturedReq {
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

/// The gate's status picks the refusal's kind, rendered in the caller's dialect (here Anthropic's
/// `error.type`): 401, 403, 404, 408 and 429 their own kinds, every other 4xx an invalid request.
#[tokio::test]
async fn reject_kind_mapping_matches_status_semantics() {
    for (status, kind) in [
        (401, "authentication_error"),
        (403, "permission_error"),
        (404, "not_found_error"),
        (408, "timeout_error"),
        (429, "rate_limit_error"),
        (400, "invalid_request_error"),
        (422, "invalid_request_error"),
        (451, "invalid_request_error"),
        (499, "invalid_request_error"),
    ] {
        let answer = gate_refusal(
            status,
            "guardrail",
            "/v1/messages",
            ANTHROPIC,
            &serde_json::to_vec(&chat_body()).unwrap(),
        )
        .await;
        assert_eq!(answer.status, u32::from(status), "{status}");
        assert_eq!(answer.json()["error"]["type"], kind, "{status}");
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

// ── F25 REHOME: the hook seam rows the coverage map (v2) homes on the driver ─────────────────────

/// The 503 body a decision gate that could not complete answers (1.5.5's literal).
const GATE_COULD_NOT_COMPLETE: &str = "A required gate could not complete. Please retry shortly.";
/// The 503 body a decision gate's restriction leaving no lane answers.
const GATE_RESTRICT_EMPTY: &str =
    "No upstream satisfies a required gate's restriction. Please retry shortly.";
/// The 503 body a base routing policy that could not select answers.
const POLICY_COULD_NOT_SELECT: &str =
    "The routing policy could not select an upstream. Please retry shortly.";
/// The 503 body a base policy's restriction leaving no lane answers.
const POLICY_RESTRICT_EMPTY: &str =
    "No upstream satisfies the routing policy's restriction. Please retry shortly.";

/// A hook that either fails outright or restricts to a tag no lane carries.
#[derive(Clone, Copy)]
enum Fault {
    Error,
    RestrictToNothing,
}

struct FaultyHook(Fault);

#[async_trait::async_trait]
impl busbar_contract::hooks::RoutingPolicy for FaultyHook {
    async fn decide(
        &self,
        _req: &busbar_contract::hooks::RoutingRequest<'_>,
        _candidates: &[busbar_contract::hooks::Candidate<'_>],
        _ctx: &busbar_contract::hooks::RoutingContext<'_>,
        _budget: Duration,
    ) -> busbar_contract::hooks::PolicyResult {
        match self.0 {
            Fault::Error => Err("deliberately broken".into()),
            Fault::RestrictToNothing => Ok(busbar_contract::hooks::RoutingDecision::Restrict {
                tags_any: vec!["a-tag-no-lane-carries".to_string()],
            }),
        }
    }
    fn name(&self) -> &'static str {
        "faulty"
    }
}

/// The faulty hook, resolved fail-closed on the restriction axis with the operator's `on_error`.
fn faulty(fault: Fault, on_error: PolicyOnError) -> ResolvedPolicy {
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

/// The chat-completions caller's own spelling of busbar's overloaded 503 kind, read off the plane's
/// own refusal renderer, so the test pins "the same kind as every other busbar 503" and no literal.
fn overloaded_kind_on_chat_completions() -> String {
    // The chat-completions envelope mints nothing, so the host it is rendered with gives nothing.
    struct NoHost;
    impl busbar_contract::codec::CodecHost for NoHost {
        fn fill_entropy(&self, _out: &mut [u8]) -> bool {
            false
        }
        fn wall_clock_now(&self) -> Option<u64> {
            None
        }
    }
    let rendered = busbar_plane_llm::exchange::refuse::render(
        &NoHost,
        "openai",
        503,
        busbar_contract::protocol::KIND_OVERLOADED,
        "x",
        0,
    );
    let v: Value = serde_json::from_slice(&rendered.body).expect("a refusal is JSON");
    v["error"]["type"].as_str().unwrap_or_default().to_string()
}

/// One chat-completions request at a two-lane pool with the faulty hook in `seat`: (status, error
/// kind, error message) off the caller's envelope, and whether a far end was reached.
async fn fire_faulty(
    seat: Seat,
    fault: Fault,
    on_error: PolicyOnError,
) -> (u32, String, String, bool) {
    let hook = faulty(fault, on_error);
    let hooks = match seat {
        Seat::DecisionGate => gates(vec![(0, hook)]),
        Seat::BasePolicy => Hooks {
            policy: Some(hook),
            ..Hooks::default()
        },
    };
    let rig = Rig::new(
        pool(vec![
            member("m0", "m0").provider("oai").tags(&["eu"]),
            member("m1", "m1").provider("oai").tags(&["us"]),
        ]),
        None,
        hooks,
    );
    let answer = rig
        .fire_with(
            &crate::common::TestUnits::passing(),
            "/v1/chat/completions",
            &[("content-type", "application/json")],
            &serde_json::to_vec(&chat_body()).unwrap(),
        )
        .await;
    let v = answer.json();
    (
        answer.status,
        v["error"]["type"].as_str().unwrap_or_default().to_string(),
        v["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
        !answer.sent.is_empty(),
    )
}

/// LEGACY `crates/busbar-llm/src/engine/tests/gate_policy_503_literals_tests.rs::decision_gate_that_cannot_complete_has_its_own_503_body`
/// (coverage map v2 row 213). 1.5.5: a load-bearing decision gate that could not complete answers
/// 503, busbar's overloaded kind, and its own words: "A required gate could not complete. Please
/// retry shortly."
///
/// RED: the failed gate's refusal collapses into another 503 body, another status or kind.
#[tokio::test]
async fn decision_gate_that_cannot_complete_has_its_own_503_body() {
    let (status, kind, message, _) =
        fire_faulty(Seat::DecisionGate, Fault::Error, PolicyOnError::Reject).await;
    assert_eq!((status, kind), (503, overloaded_kind_on_chat_completions()));
    assert_eq!(message, GATE_COULD_NOT_COMPLETE);
}

/// LEGACY `crates/busbar-llm/src/engine/tests/gate_policy_503_literals_tests.rs::decision_gate_restriction_leaving_no_lane_has_its_own_503_body`
/// (coverage map v2 row 214). 1.5.5: a decision gate whose restriction leaves no lane answers 503,
/// the overloaded kind, and "No upstream satisfies a required gate's restriction. Please retry
/// shortly."
///
/// RED: the restriction's refusal wears another body (a policy's, or a generic exhaustion).
#[tokio::test]
async fn decision_gate_restriction_leaving_no_lane_has_its_own_503_body() {
    let (status, kind, message, _) = fire_faulty(
        Seat::DecisionGate,
        Fault::RestrictToNothing,
        PolicyOnError::Reject,
    )
    .await;
    assert_eq!((status, kind), (503, overloaded_kind_on_chat_completions()));
    assert_eq!(message, GATE_RESTRICT_EMPTY);
}

/// LEGACY `crates/busbar-llm/src/engine/tests/gate_policy_503_literals_tests.rs::base_policy_that_cannot_select_has_its_own_503_body`
/// (coverage map v2 row 215). 1.5.5: the pool's base routing policy that could not select answers
/// 503, the overloaded kind, and "The routing policy could not select an upstream. Please retry
/// shortly."
///
/// RED: a policy's fault is served under a gate's body, or under another status or kind.
#[tokio::test]
async fn base_policy_that_cannot_select_has_its_own_503_body() {
    let (status, kind, message, _) =
        fire_faulty(Seat::BasePolicy, Fault::Error, PolicyOnError::Reject).await;
    assert_eq!((status, kind), (503, overloaded_kind_on_chat_completions()));
    assert_eq!(message, POLICY_COULD_NOT_SELECT);
}

/// LEGACY `crates/busbar-llm/src/engine/tests/gate_policy_503_literals_tests.rs::base_policy_restriction_leaving_no_lane_has_its_own_503_body`
/// (coverage map v2 row 216). 1.5.5: a base policy whose restriction leaves no lane answers 503,
/// the overloaded kind, and "No upstream satisfies the routing policy's restriction. Please retry
/// shortly."
///
/// RED: the policy's restriction refusal collapses into the gate's words or another body.
#[tokio::test]
async fn base_policy_restriction_leaving_no_lane_has_its_own_503_body() {
    let (status, kind, message, _) = fire_faulty(
        Seat::BasePolicy,
        Fault::RestrictToNothing,
        PolicyOnError::Reject,
    )
    .await;
    assert_eq!((status, kind), (503, overloaded_kind_on_chat_completions()));
    assert_eq!(message, POLICY_RESTRICT_EMPTY);
}

/// LEGACY `crates/busbar-llm/src/engine/tests/gate_policy_503_literals_tests.rs::decision_gate_that_cannot_complete_only_refuses_when_declared_load_bearing`
/// (coverage map v2 row 217). 1.5.5: the SAME failed gate under `on_error: weighted` refuses
/// nothing: the unit proceeds to a route, and the "could not complete" body belongs to
/// `on_error: reject` alone.
///
/// RED: a gate the operator did not declare load-bearing still refuses with its 503 body, or the
/// unit never reaches a far end.
#[tokio::test]
async fn decision_gate_that_cannot_complete_only_refuses_when_declared_load_bearing() {
    let (_status, _kind, message, dispatched) =
        fire_faulty(Seat::DecisionGate, Fault::Error, PolicyOnError::Weighted).await;
    assert_ne!(
        message, GATE_COULD_NOT_COMPLETE,
        "`on_error: weighted` proceeds past a gate that could not answer; the refusal body belongs \
         to `on_error: reject` alone"
    );
    assert!(dispatched, "the unit proceeded to the walk");
}

/// LEGACY `crates/busbar-llm/src/engine/tests/hook_seam_tests.rs::reject_kind_mapping_matches_status_semantics`
/// (coverage map v2 row 311). 1.5.5: the refusal a load-bearing hook's FAILED call produces
/// (`REQUIRED_HOOK_UNAVAILABLE_STATUS`, 503) reads as RETRYABLE, the overloaded kind: on the
/// Anthropic envelope `error.type` is `overloaded_error`, never a client error.
///
/// RED: the required-hook-unavailable 503 renders as an invalid request (or any non-retryable
/// kind), so an SDK caller never retries a transient hook outage.
#[tokio::test]
async fn reject_kind_mapping_matches_status_semantics_required_hook_unavailable() {
    assert_eq!(busbar_kernel::hooks::REQUIRED_HOOK_UNAVAILABLE_STATUS, 503);
    let rig = Rig::new(
        one(),
        None,
        gates(vec![(0, faulty(Fault::Error, PolicyOnError::Reject))]),
    );
    let answer = rig.fire(&chat_body()).await;
    assert_eq!(answer.status, 503);
    assert_eq!(answer.json()["type"], "error");
    assert_eq!(answer.json()["error"]["type"], "overloaded_error");
    assert!(answer.sent.is_empty(), "refused before any dispatch");
}

/// A response-stage tap that counts its deliveries and keeps the last payload.
#[derive(Default)]
struct CountingTap {
    fired: std::sync::atomic::AtomicUsize,
    last: Mutex<Option<Value>>,
}

#[async_trait::async_trait]
impl busbar_contract::hooks::RoutingPolicy for CountingTap {
    async fn decide(
        &self,
        _req: &busbar_contract::hooks::RoutingRequest<'_>,
        _cands: &[busbar_contract::hooks::Candidate<'_>],
        _ctx: &busbar_contract::hooks::RoutingContext<'_>,
        _budget: Duration,
    ) -> busbar_contract::hooks::PolicyResult {
        Ok(busbar_contract::hooks::RoutingDecision::Abstain)
    }
    fn name(&self) -> &'static str {
        "counting-tap"
    }
    async fn notify(
        &self,
        tap: Arc<busbar_contract::abi::host::hook::NotifyFrame>,
        _budget: Duration,
    ) {
        *self.last.lock().unwrap() = Some(tap.projection_json());
        self.fired.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

/// A counting tap and its entry, scoped to `groups` (empty: every caller).
fn counting_tap(groups: Vec<String>) -> (Arc<CountingTap>, busbar_kernel::hooks::TapEntry) {
    let tap = Arc::new(CountingTap::default());
    let policy: Arc<dyn busbar_contract::hooks::RoutingPolicy> = tap.clone();
    (tap, (Duration::from_millis(500), false, policy, groups))
}

/// Give detached taps room to deliver, then read how many did.
async fn settled_count(tap: &CountingTap) -> usize {
    for _ in 0..50 {
        if tap.fired.load(std::sync::atomic::Ordering::SeqCst) > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    // And a little longer, so a SECOND (wrong) delivery has the chance to land too.
    tokio::time::sleep(Duration::from_millis(100)).await;
    tap.fired.load(std::sync::atomic::Ordering::SeqCst)
}

/// LEGACY `crates/busbar-llm/src/engine/tests/hook_seam_tests.rs::substrate_fire_stage_taps_honors_group_scope_via_host_seam`
/// (coverage map v2 row 279). 1.5.5: a stage tap scoped to a group fires for a caller inside the
/// group and does NOT fire for a caller outside it.
///
/// RED: the served driver fires a group-scoped tap for an out-of-group caller (a governance or
/// audit tap mis-firing), or drops it for an in-group one.
#[tokio::test]
async fn substrate_fire_stage_taps_honors_group_scope_via_host_seam() {
    async fn fired_for(groups_of_caller: &[&str]) -> usize {
        let (tap, entry) = counting_tap(vec!["engineering".to_string()]);
        let mut callers = Callers::default();
        callers.groups.insert(
            PRINCIPAL.to_string(),
            groups_of_caller.iter().map(|g| (*g).to_string()).collect(),
        );
        let mut hooks = Hooks {
            callers,
            ..Hooks::default()
        };
        hooks.taps.response = vec![entry];
        let rig = Rig::new(pool(vec![member("m0", "served")]), None, hooks);
        let answer = rig.fire(&chat_body()).await;
        assert_eq!(answer.status, 200);
        settled_count(&tap).await
    }
    assert_eq!(
        fired_for(&["user:bob", "engineering"]).await,
        1,
        "the in-group caller's group-scoped stage tap must fire"
    );
    assert_eq!(
        fired_for(&["user:sue", "sales"]).await,
        0,
        "an out-of-group caller must NOT fire a group-scoped stage tap"
    );
}

/// LEGACY `crates/busbar-llm/src/engine/tests/hook_seam_tests.rs::unreadable_content_reaches_the_gate_and_is_forwarded`
/// (coverage map v2 row 317). 1.5.5: a valid-JSON request carrying a block type the reader does not
/// model reaches a content gate, which is shown the turns busbar CAN read, and is forwarded to the
/// far end byte for byte; unreadable content contributes nothing and never refuses the request.
/// (Rewritten with an unknown block type only: an unknown role is a 400 since
/// `hook_ir_differential`.)
///
/// RED: the request is refused for content the reader cannot model, it reaches the far end
/// altered, or the gate is shown an empty or invented turn.
#[tokio::test]
async fn unreadable_content_reaches_the_gate_and_is_forwarded() {
    let (seen, gate) = capturing(true, false, None);
    let rig = Rig::new(one(), None, gates(vec![(0, gate)]));
    let body = r#"{"model":"m0","max_tokens":10,"messages":[{"role":"user","content":[{"type":"text","text":"READABLE"},{"type":"never_heard_of","x":1}]}]}"#;
    let answer = rig
        .fire_with(
            &crate::common::TestUnits::passing(),
            crate::proofs::wire::FIRE_TARGET,
            crate::proofs::wire::FIRE_FIELDS,
            body.as_bytes(),
        )
        .await;
    assert_eq!(
        answer.status, 200,
        "never refused for content it cannot read"
    );
    let sent = answer
        .sent
        .last()
        .expect("the far end received the request");
    assert_eq!(
        String::from_utf8_lossy(&sent.body),
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
        turns.iter().all(|(r, _)| !r.is_empty()),
        "an unreadable block contributes no turn of its own: {turns:?}"
    );
}

/// A rewrite seat answering a fixed rewrite, and recording what it was shown and how often.
struct FixedRewrite {
    name: &'static str,
    reply: busbar_contract::hooks::TransformOutcome,
    calls: std::sync::atomic::AtomicUsize,
    shown: Mutex<Vec<(String, String)>>,
}

impl FixedRewrite {
    fn new(name: &'static str, reply: busbar_contract::hooks::TransformOutcome) -> Arc<Self> {
        Arc::new(FixedRewrite {
            name,
            reply,
            calls: std::sync::atomic::AtomicUsize::new(0),
            shown: Mutex::new(Vec::new()),
        })
    }
    fn rewriting(name: &'static str, messages: Vec<Value>, tools: Vec<Value>) -> Arc<Self> {
        Self::new(
            name,
            busbar_contract::hooks::TransformOutcome::Rewrite(
                busbar_contract::hooks::RewriteReply { messages, tools },
            ),
        )
    }
    fn calls(&self) -> usize {
        self.calls.load(std::sync::atomic::Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl busbar_contract::hooks::RoutingPolicy for FixedRewrite {
    async fn decide(
        &self,
        _req: &busbar_contract::hooks::RoutingRequest<'_>,
        _cands: &[busbar_contract::hooks::Candidate<'_>],
        _ctx: &busbar_contract::hooks::RoutingContext<'_>,
        _budget: Duration,
    ) -> busbar_contract::hooks::PolicyResult {
        Ok(busbar_contract::hooks::RoutingDecision::Abstain)
    }
    fn name(&self) -> &'static str {
        self.name
    }
    async fn transform(
        &self,
        req: &busbar_contract::hooks::RoutingRequest<'_>,
        _budget: Duration,
    ) -> busbar_contract::hooks::TransformOutcome {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if let Some(prompt) = req.prompt.as_ref() {
            *self.shown.lock().unwrap() = prompt
                .messages
                .iter()
                .map(|(r, t)| (r.to_string(), t.to_string()))
                .collect();
        }
        self.reply.clone()
    }
}

/// A rewrite seat as the rig seats one.
fn seated(hook: &Arc<FixedRewrite>) -> (Duration, Arc<dyn busbar_contract::hooks::RoutingPolicy>) {
    let policy: Arc<dyn busbar_contract::hooks::RoutingPolicy> = hook.clone();
    (Duration::from_millis(500), policy)
}

/// One chat-completions unit at a one-member chat-completions pool.
async fn fire_chat_completions(rig: &Rig, body: &Value) -> crate::rig::Answered {
    rig.fire_with(
        &crate::common::TestUnits::passing(),
        "/v1/chat/completions",
        &[("content-type", "application/json")],
        &serde_json::to_vec(body).unwrap(),
    )
    .await
}

/// LEGACY `crates/busbar-llm/src/engine/tests/usage_tap_tests.rs::apply_rewrite_to_body_swaps_messages_and_is_fail_safe`
/// (coverage map v2 row 622). 1.5.5: a rewrite on an openai chat body replaces `messages` with the
/// hook's (`[{"role":"user","content":"compressed"}]`), injects the hook's tool BESIDE the caller's
/// (2 tools), and leaves every unrelated field (the model) untouched; a body with no `messages`
/// array is left untouched (fail-safe, not applied), and an empty rewrite changes nothing.
///
/// RED: the rewrite drops the caller's tool or the model, writes a non-chat body it cannot frame,
/// or an empty rewrite alters the request.
#[tokio::test]
async fn apply_rewrite_to_body_swaps_messages_and_is_fail_safe() {
    let hook = FixedRewrite::rewriting(
        "rewrite-tool-injector",
        vec![json!({"role": "user", "content": "compressed"})],
        vec![json!({"type": "function", "function": {"name": "rewriter_retrieve"}})],
    );
    let rig = Rig::new(
        pool(vec![member("m0", "m0").provider("oai")]),
        None,
        Hooks {
            rewrites: vec![seated(&hook)],
            ..Hooks::default()
        },
    );
    let answer = fire_chat_completions(
        &rig,
        &json!({
            "model": "m0",
            "messages": [{"role": "user", "content": "a very long original prompt"}],
            "tools": [{"type": "function", "function": {"name": "existing"}}]
        }),
    )
    .await;
    assert_eq!(answer.status, 200);
    let sent = sent_body(&answer);
    assert_eq!(
        sent["messages"],
        json!([{"role": "user", "content": "compressed"}])
    );
    let tools = sent["tools"].as_array().expect("tools");
    assert_eq!(tools.len(), 2, "tool injected, existing kept: {sent}");
    assert_eq!(sent["model"], "m0", "unrelated fields untouched");

    // The fail-safe arms, through the plane's own apply step: a body with no `messages` array and
    // an empty rewrite both leave the arrival untouched.
    use busbar_plane_llm::exchange::arrive::arrive;
    use busbar_plane_llm::exchange::project::apply_rewrite;
    let head: &[(&[u8], &[u8])] = &[(b"content-type", b"application/json")];
    let rewrite = br#"{"messages":[{"role":"user","content":"compressed"}],"tools":[]}"#;
    let non_chat = br#"{"model":"m0","contents":[{"parts":[]}]}"#;
    if let Ok(mut arrived) = arrive("POST", "/v1/chat/completions", head, non_chat, &()) {
        let before = arrived.body.clone();
        assert_eq!(
            apply_rewrite(&mut arrived, rewrite),
            None,
            "non-chat body left untouched (fail-safe)"
        );
        assert_eq!(arrived.body, before);
    }
    let chat = br#"{"model":"m0","messages":[{"role":"user","content":"x"}]}"#;
    let mut arrived = arrive("POST", "/v1/chat/completions", head, chat, &()).expect("arrives");
    let before = arrived.body.clone();
    assert_eq!(
        apply_rewrite(&mut arrived, br#"{"messages":[],"tools":[]}"#),
        None,
        "an empty rewrite changes nothing"
    );
    assert_eq!(arrived.body, before);
}

/// LEGACY `crates/busbar-llm/src/engine/tests/usage_tap_tests.rs::apply_global_rewrites_chains_in_order`
/// (coverage map v2 row 625). 1.5.5: global rewrites fire in order and each sees the prior's
/// output: hook A rewrites to "A", hook B (shown A's output) rewrites to "B", and "B" is what the
/// far end is sent; the order reversed ends at "A".
///
/// RED: the chain runs out of order, a later hook is shown the caller's original body, or only one
/// rewrite of the chain is applied.
#[tokio::test]
async fn apply_global_rewrites_chains_in_order() {
    async fn chained(first: &'static str, second: &'static str) -> (Value, Vec<(String, String)>) {
        let hook = |text: &'static str| {
            FixedRewrite::rewriting(
                "mock-rewrite",
                vec![json!({"role": "user", "content": text})],
                vec![],
            )
        };
        let (head, tail) = (hook(first), hook(second));
        let rig = Rig::new(
            one(),
            None,
            Hooks {
                rewrites: vec![seated(&head), seated(&tail)],
                ..Hooks::default()
            },
        );
        let answer = rig.fire(&chat_body()).await;
        assert_eq!(answer.status, 200);
        let shown = tail.shown.lock().unwrap().clone();
        (sent_body(&answer), shown)
    }
    let (sent, shown_to_b) = chained("A", "B").await;
    assert_eq!(
        sent["messages"][0]["content"], "B",
        "the last hook in the chain wins"
    );
    assert_eq!(
        shown_to_b,
        vec![("user".to_string(), "A".to_string())],
        "B ran on A's rewritten body"
    );
    let (sent, _) = chained("B", "A").await;
    assert_eq!(sent["messages"][0]["content"], "A");
}

/// LEGACY `crates/busbar-llm/src/unit/tests/approve.rs::with_no_seat_installed_the_step_is_a_no_op_exactly_as_the_live_path_is`
/// (coverage map v2 row 659). 1.5.5: with no hook seated, a unit passes the hook stage unchanged:
/// nothing refused, nothing added, and the far end is sent exactly the caller's bytes.
///
/// RED: an empty hook stage alters the request (a re-serialization, an added field) or refuses.
#[tokio::test]
async fn with_no_seat_installed_the_step_is_a_no_op_exactly_as_the_live_path_is() {
    let rig = Rig::new(one(), None, Hooks::default());
    let body =
        br#"{"model":"m0","max_tokens":10,"messages":[{"role":"user","content":"untouched"}]}"#;
    let answer = rig
        .fire_with(
            &crate::common::TestUnits::passing(),
            crate::proofs::wire::FIRE_TARGET,
            crate::proofs::wire::FIRE_FIELDS,
            body,
        )
        .await;
    assert_eq!(
        answer.status, 200,
        "nothing is seated, so nothing can refuse"
    );
    assert!(answer.outcome.is_completed(), "{:?}", answer.outcome);
    let sent = answer.sent.last().expect("the far end was reached");
    assert_eq!(
        sent.body.as_slice(),
        body.as_slice(),
        "the far body is the caller's bytes"
    );
}

/// LEGACY `crates/busbar-llm/src/unit/tests/approve.rs::the_first_veto_wins_and_nothing_after_it_is_consulted`
/// (coverage map v2 row 662). 1.5.5: of two ordered request seats, the first one's veto wins, the
/// unit is refused as a hook veto, and the seat after it is never consulted (its call counter stays
/// 0). Seated as the request stage's ordered rewrite seats (the decision gates are consulted
/// together, as 1.5.5 fanned them out). The request stage runs at the head of the route leg, and
/// the loop ends a refused route leg as `Failed(Route, reason)` (`teller.rs` `under_hold`), the
/// outcome the kernel's own `a_veto_is_rendered_by_the_plane_with_the_hooks_status_and_words_before_any_attempt`
/// pins for a request-stage veto.
///
/// RED: a seat after the veto is still asked, or the refusal is not the hook veto.
#[tokio::test]
async fn the_first_veto_wins_and_nothing_after_it_is_consulted() {
    let vetoing = FixedRewrite::new(
        "vetoing-seat",
        busbar_contract::hooks::TransformOutcome::Reject {
            status: 451,
            message: "vetoed".to_string(),
        },
    );
    let after = FixedRewrite::rewriting(
        "seat-after",
        vec![json!({"role": "user", "content": "never"})],
        vec![],
    );
    let rig = Rig::new(
        one_dead(),
        None,
        Hooks {
            rewrites: vec![seated(&vetoing), seated(&after)],
            ..Hooks::default()
        },
    );
    let answer = rig.fire(&chat_body()).await;
    assert_eq!(answer.status, 451, "the first seat vetoed");
    assert!(
        matches!(
            answer.outcome,
            busbar_contract::caps::Outcome::Failed(
                busbar_contract::caps::StepName::Route,
                busbar_contract::caps::ReasonCode::HookVeto
            )
        ),
        "{:?}",
        answer.outcome
    );
    assert_eq!(vetoing.calls(), 1);
    assert_eq!(after.calls(), 0, "the seat after the veto was never asked");
    assert!(answer.sent.is_empty());
}

/// LEGACY `crates/busbar-llm/src/unit/tests/route.rs::completion_tap_fires_once_on_the_walk_and_never_on_a_pre_forward_refusal`
/// (coverage map v2 row 727). 1.5.5: a served unit fires the completion (response-stage) tap
/// exactly ONCE, with the response payload (`at: response`, `outcome: ok`, `status: 200`); a unit
/// refused before the walk (an unknown model, 404) fires it zero times.
///
/// RED: the completion tap fires twice for one unit, or a pre-forward 404 fires one.
#[tokio::test]
async fn completion_tap_fires_once_on_the_walk_and_never_on_a_pre_forward_refusal() {
    let (tap, entry) = counting_tap(Vec::new());
    let mut hooks = Hooks::default();
    hooks.taps.response = vec![entry];
    let rig = Rig::new(pool(vec![member("m0", "served")]), None, hooks);
    let answer = rig.fire(&chat_body()).await;
    assert_eq!(answer.status, 200);
    assert_eq!(
        settled_count(&tap).await,
        1,
        "the completion tap fires exactly once"
    );
    let payload = tap.last.lock().unwrap().clone().expect("the tap fired");
    assert_eq!(payload["stage"]["at"], "response");
    assert_eq!(payload["stage"]["outcome"], "ok");
    assert_eq!(payload["stage"]["status"], 200);

    // The pre-forward refusal: no destination, so no walk and no completion tap.
    let (missed, entry) = counting_tap(Vec::new());
    let mut hooks = Hooks::default();
    hooks.taps.response = vec![entry];
    let rig = Rig::new(pool(vec![member("m0", "served")]), None, hooks);
    let mut body = chat_body();
    body["model"] = json!("missing");
    let answer = rig
        .fire_with(
            &crate::common::TestUnits::refusing(
                busbar_contract::caps::StepName::Verify,
                busbar_contract::caps::ReasonCode::NoDestination,
            ),
            crate::proofs::wire::FIRE_TARGET,
            crate::proofs::wire::FIRE_FIELDS,
            &serde_json::to_vec(&body).unwrap(),
        )
        .await;
    assert_eq!(answer.status, 404);
    assert_eq!(
        settled_count(&missed).await,
        0,
        "a pre-forward refusal fires no completion tap"
    );
}

/// LEGACY `crates/busbar-llm/src/unit/tests/route.rs::completion_tap_carries_response_tokens_out_when_declared`
/// (coverage map v2 row 728), held to 1.5.5: 1.5.5 never computed `response_tokens_out`. Its
/// stage taps (candidate, routing, response) projected no catalog signal
/// (`v1.5.5 crates/busbar/src/proxy/hooks.rs:1348-1352`, `signals: Default::default()`, "the wire is
/// byte-identical"), and the signal was reserved in the catalog with no compute fn
/// (`v1.5.5 crates/api/src/signal.rs:90-95`). The legacy crate's figure (the far end's 1 output token
/// on the tap) was post-1.5.5 drift. So the `response` stage tap's payload carries no
/// `response_tokens_out` key, declared or not (PR #919's finding).
///
/// RED: a `response_tokens_out` key on the completion tap, which 1.5.5's wire never carried.
#[tokio::test]
async fn completion_tap_carries_no_response_tokens_out_as_in_1_5_5() {
    async fn tapped(declared: bool) -> Value {
        let (tap, entry) = counting_tap(Vec::new());
        let mut hooks = Hooks::default();
        hooks.taps.response = vec![entry];
        if declared {
            hooks
                .requested
                .insert(busbar_contract::Signal::ResponseTokensOut);
        }
        let rig = Rig::new(pool(vec![member("m0", "served")]), None, hooks);
        let answer = rig.fire(&chat_body()).await;
        assert_eq!(answer.status, 200, "the answer was delivered");
        settled_count(&tap).await;
        let payload = tap.last.lock().unwrap().clone();
        payload.expect("the completion tap fired")
    }
    let declared = tapped(true).await;
    assert_eq!(declared["stage"]["at"], "response");
    assert!(
        declared["request"].get("response_tokens_out").is_none(),
        "1.5.5's response tap projected no signal, a declared one included: {declared}"
    );
    let undeclared = tapped(false).await;
    assert!(
        undeclared["request"].get("response_tokens_out").is_none(),
        "an undeclared signal adds no key to the payload"
    );
}

/// Q128 arch u58 (HIGH): AN AD-HOC ROUTE THAT MISNAMES ITS MODEL'S PROVIDER is refused behind the
/// caller's identity and grant, as 1.5.5's `adhoc()` ran its governance guard before it answered the
/// mismatch. The plane's `arrive` names the entry its refusal concerns (abi/plane "A refused
/// arrival", rule 6), so a caller the grant refuses hears the grant's refusal, and a granted one
/// hears the mismatch's own 400 at admission, with nothing sent upstream.
#[tokio::test]
async fn an_adhoc_provider_mismatch_is_judged_behind_the_callers_grant() {
    use busbar_contract::caps::{Outcome, ReasonCode, StepName};
    let rig = Rig::new(one(), None, Hooks::default());
    let body = serde_json::to_vec(&body()).unwrap();
    // `m0` is served by `ant`; the path names `oai`.
    let target = "/oai/m0/v1/messages";
    let fields = super::wire::FIRE_FIELDS;

    let ungranted = rig
        .fire_with(
            &crate::common::TestUnits::refusing(StepName::Approve, ReasonCode::ScopeDenied),
            target,
            fields,
            &body,
        )
        .await;
    assert_eq!(
        ungranted.outcome,
        Outcome::Refused(StepName::Approve, ReasonCode::ScopeDenied),
        "the caller's grant is judged before the mismatch is answered"
    );
    assert!(ungranted.sent.is_empty(), "nothing goes upstream");

    let granted = rig
        .fire_with(&crate::common::TestUnits::passing(), target, fields, &body)
        .await;
    assert_eq!(granted.status, 400, "the mismatch keeps 1.5.5's status");
    assert_eq!(
        granted.json()["error"]["message"],
        "The model 'm0' does not exist or you do not have access to it."
    );
    assert!(
        matches!(granted.outcome, Outcome::Refused(StepName::Admit, _)),
        "a granted caller's mismatch is rendered at admission, before anything is charged: {:?}",
        granted.outcome
    );
    assert!(granted.sent.is_empty(), "nothing goes upstream");
}

/// THE FOUR 503 WORDS ARE FOUR: a gate that could not complete, a gate's restriction that left no
/// member, a base policy that could not select, and a base policy's restriction that left no member
/// each answer their own sentence, so a caller can tell which refused it. Rehomes
/// `crates/busbar-llm/src/engine/tests/gate_policy_503_literals_tests.rs::the_four_503_literals_are_distinct`.
#[test]
fn the_four_503_literals_are_distinct() {
    let four = [
        GATE_COULD_NOT_COMPLETE,
        GATE_RESTRICT_EMPTY,
        POLICY_COULD_NOT_SELECT,
        POLICY_RESTRICT_EMPTY,
    ];
    for (i, a) in four.iter().enumerate() {
        for b in &four[i + 1..] {
            assert_ne!(a, b);
        }
    }
}
