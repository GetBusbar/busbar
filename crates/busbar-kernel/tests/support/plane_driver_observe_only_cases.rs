// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE OBSERVE-ONLY STATEMENT (hook screening, canonical forwarding, G2): `project` carries
//! `PROJECT_IN_OBSERVE_ONLY` exactly when no hook bound to the unit stops, changes or routes the
//! request on what the plane publishes. A unit that binds a gate, a rewrite or a routing policy
//! that reads the request carries 0, which states nothing, so the plane screens it.

use super::*;
use busbar_contract::abi::plane::PROJECT_IN_OBSERVE_ONLY;

/// A tap: it observes, and never stops, changes or routes anything.
struct Tap;

#[async_trait::async_trait]
impl RoutingPolicy for Tap {
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
        "tap"
    }
}

fn tap() -> busbar_kernel::hooks::TapEntry {
    (Duration::from_millis(500), true, Arc::new(Tap), Vec::new())
}

/// Every stage a tap binds at, one tap each.
fn tap_stages() -> Vec<(&'static str, StageTaps)> {
    vec![
        (
            "request",
            StageTaps {
                request: vec![tap()],
                ..StageTaps::default()
            },
        ),
        (
            "candidate",
            StageTaps {
                candidate: vec![tap()],
                ..StageTaps::default()
            },
        ),
        (
            "routing",
            StageTaps {
                routing: vec![tap()],
                ..StageTaps::default()
            },
        ),
        (
            "response",
            StageTaps {
                response: vec![tap()],
                ..StageTaps::default()
            },
        ),
    ]
}

/// The `ProjectIn::flags` every `project` of one unit over `hooks` carried.
async fn flags_over(hooks: BoundHooks) -> Vec<u32> {
    let r = rig_with_hooks(
        Way::Double,
        BufferCaps::default(),
        Book::default(),
        Some(hooks),
    );
    let (steps, far, caller) = (
        TestUnits::passing(),
        Far::new(&["ok"], &[b"done"]).naming_its_pool(),
        Caller::default(),
    );
    let units = r
        .driver
        .unit(&steps, &far, &caller, arrival("/call", b"user:hello"), 0);
    let outcome = drive(&units).await;
    assert!(matches!(outcome, Outcome::Completed), "{outcome:?}");
    let flags = r.project_flags();
    assert!(!flags.is_empty(), "a bound unit crosses `project`");
    flags
}

#[tokio::test]
async fn a_tap_only_unit_is_stated_observe_only() {
    for (stage, taps) in tap_stages() {
        let mut hooks = bound(Vec::new(), Vec::new());
        hooks.taps = taps;
        assert_eq!(
            flags_over(hooks).await,
            vec![PROJECT_IN_OBSERVE_ONLY],
            "a unit whose only hook is a {stage} tap states observe-only"
        );
    }
}

#[tokio::test]
async fn a_unit_with_every_tap_stage_and_nothing_else_is_stated_observe_only() {
    let mut hooks = bound(Vec::new(), Vec::new());
    hooks.taps = StageTaps {
        request: vec![tap()],
        candidate: vec![tap()],
        routing: vec![tap()],
        response: vec![tap()],
    };
    assert_eq!(flags_over(hooks).await, vec![PROJECT_IN_OBSERVE_ONLY]);
}

#[tokio::test]
async fn a_gated_unit_states_nothing_with_or_without_taps() {
    for send_prompt in [false, true] {
        for (stage, taps) in tap_stages()
            .into_iter()
            .chain([("no", StageTaps::default())])
        {
            let (_, g) = gate_granted(None, send_prompt);
            let mut hooks = bound(Vec::new(), vec![(0, g)]);
            hooks.taps = taps;
            assert_eq!(
                flags_over(hooks).await,
                vec![0],
                "a gate (prompt {send_prompt}) with {stage} tap: the plane screens"
            );
        }
    }
}

#[tokio::test]
async fn a_rewritten_unit_states_nothing_on_every_project() {
    let mut hooks = bound(
        vec![(
            Duration::from_millis(500),
            Arc::new(Rewriter {
                name: "rewriter",
                refuses_failed_rewrite: false,
            }),
        )],
        Vec::new(),
    );
    hooks.taps.request = vec![tap()];
    assert_eq!(
        flags_over(hooks).await,
        vec![0, 0],
        "the first view and the re-projection after the rewrite both screen"
    );
}

#[tokio::test]
async fn a_unit_whose_policy_is_a_gate_transport_states_nothing() {
    for send_prompt in [false, true] {
        let (_, policy) = gate_granted(None, send_prompt);
        let mut hooks = bound(Vec::new(), Vec::new());
        hooks.pool_policies.insert("pool-a".to_string(), policy);
        assert_eq!(
            flags_over(hooks).await,
            vec![0],
            "a configured hook ordering the pool (prompt {send_prompt}) reads the request"
        );
    }
}

/// A pool ordering as `ranked_policy` resolves a built-in strategy, varied by what makes a
/// policy read the request.
fn ranking(send_prompt: bool, chained: bool) -> ResolvedPolicy {
    let chain = chained.then(|| busbar_kernel::hooks::FallbackHook {
        policy: Arc::new(Tap),
        timeout: Duration::from_millis(500),
        send_prompt: false,
        send_user: false,
        on_empty: PolicyOnError::Reject,
    });
    ResolvedPolicy::Policy {
        policy: Arc::new(Tap),
        on_error: PolicyOnError::default(),
        on_error_chain: chain.into_iter().collect(),
        timeout: Duration::from_millis(500),
        send_prompt,
        send_user: false,
        on_empty: PolicyOnError::Reject,
        content_blind: true,
    }
}

#[tokio::test]
async fn a_ranking_only_unit_is_stated_observe_only_with_or_without_taps() {
    for (stage, taps) in tap_stages()
        .into_iter()
        .chain([("no", StageTaps::default())])
    {
        let mut hooks = bound(Vec::new(), Vec::new());
        hooks
            .pool_policies
            .insert("pool-a".to_string(), ranking(false, false));
        hooks.taps = taps;
        assert_eq!(
            flags_over(hooks).await,
            vec![PROJECT_IN_OBSERVE_ONLY],
            "a built-in ranking strategy with {stage} tap only observes"
        );
    }
}

#[tokio::test]
async fn a_content_blind_policy_that_is_sent_the_prompt_or_chains_a_fallback_states_nothing() {
    for (send_prompt, chained) in [(true, false), (false, true), (true, true)] {
        let mut hooks = bound(Vec::new(), Vec::new());
        hooks
            .pool_policies
            .insert("pool-a".to_string(), ranking(send_prompt, chained));
        assert_eq!(
            flags_over(hooks).await,
            vec![0],
            "prompt {send_prompt}, fallback chain {chained}: the plane screens"
        );
    }
}
