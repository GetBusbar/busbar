// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE OBSERVE-ONLY PREDICATE AGAINST THE EMPTY-PROJECTION ARM (hook screening, canonical
//! forwarding, G2): a unit the plane screens (`!observe_only`) is never `idle`, so a FAULT the
//! plane answers only when it screens always takes the `Err(stopped)` arm, never
//! `Projection::empty`, and the caller's bytes never go up unjudged.

use super::*;

struct Hook;

#[async_trait::async_trait]
impl RoutingPolicy for Hook {
    async fn decide(
        &self,
        _: &busbar_contract::hooks::RoutingRequest<'_>,
        _: &[busbar_contract::hooks::Candidate<'_>],
        _: &busbar_contract::hooks::RoutingContext<'_>,
        _: Duration,
    ) -> busbar_contract::hooks::PolicyResult {
        Ok(busbar_contract::hooks::RoutingDecision::Abstain)
    }
    fn name(&self) -> &'static str {
        "hook"
    }
}

struct Nobody;

impl CallerFacts for Nobody {
    fn key(&self, _: &str) -> Option<CallerKey> {
        None
    }
    fn in_groups(&self, _: Option<&str>, groups: &[String]) -> bool {
        groups.is_empty()
    }
    fn rate_headroom(&self, _: &str, _: &str) -> Option<f64> {
        None
    }
    fn budget(&self, _: &str) -> Vec<BudgetBucketState> {
        Vec::new()
    }
    fn hook_read<'a>(
        &'a self,
        _: &'a str,
        _: Option<&'a str>,
        _: &'a str,
        _: bool,
    ) -> crate::audit::amend::ReadConfirmation<'a> {
        Box::pin(async { Ok(()) })
    }
}

const POOL: &str = "pool";

fn policy(content_blind: bool, send_prompt: bool, chained: bool) -> ResolvedPolicy {
    let chain = chained.then(|| FallbackHook {
        policy: Arc::new(Hook),
        timeout: Duration::from_secs(1),
        send_prompt: false,
        send_user: false,
        on_empty: PolicyOnError::Reject,
    });
    ResolvedPolicy::Policy {
        policy: Arc::new(Hook),
        on_error: PolicyOnError::default(),
        on_error_chain: chain.into_iter().collect(),
        timeout: Duration::from_secs(1),
        send_prompt,
        send_user: false,
        on_empty: PolicyOnError::Reject,
        content_blind,
    }
}

fn tap() -> TapEntry {
    (Duration::from_secs(1), true, Arc::new(Hook), Vec::new())
}

/// One unit shape: what is bound, and whether the plane is told it is observe-only.
struct Shape {
    name: &'static str,
    rewrite: bool,
    gate: bool,
    policy: Option<ResolvedPolicy>,
    taps: StageTaps,
    observe_only: bool,
}

fn taps_at(stage: usize) -> StageTaps {
    let mut t = StageTaps::default();
    [
        &mut t.request,
        &mut t.candidate,
        &mut t.routing,
        &mut t.response,
    ][stage]
        .push(tap());
    t
}

fn shapes() -> Vec<Shape> {
    let mut out = Vec::new();
    for stage in 0..4 {
        out.push(Shape {
            name: "tap only",
            rewrite: false,
            gate: false,
            policy: None,
            taps: taps_at(stage),
            observe_only: true,
        });
        out.push(Shape {
            name: "ranking strategy with a tap",
            rewrite: false,
            gate: false,
            policy: Some(policy(true, false, false)),
            taps: taps_at(stage),
            observe_only: true,
        });
        out.push(Shape {
            name: "gate with a tap",
            rewrite: false,
            gate: true,
            policy: None,
            taps: taps_at(stage),
            observe_only: false,
        });
    }
    out.push(Shape {
        name: "ranking strategy alone",
        rewrite: false,
        gate: false,
        policy: Some(policy(true, false, false)),
        taps: StageTaps::default(),
        observe_only: true,
    });
    for (name, rewrite, gate, policy) in [
        ("gate", false, true, None),
        ("rewrite", true, false, None),
        ("rewrite and gate", true, true, None),
        (
            "gate-transport policy, prompt no",
            false,
            false,
            Some(policy(false, false, false)),
        ),
        (
            "gate-transport policy, prompt ro",
            false,
            false,
            Some(policy(false, true, false)),
        ),
        (
            "ranking strategy sent the prompt",
            false,
            false,
            Some(policy(true, true, false)),
        ),
        (
            "ranking strategy with a fallback chain",
            false,
            false,
            Some(policy(true, false, true)),
        ),
        (
            "ranking strategy with a gate",
            false,
            true,
            Some(policy(true, false, false)),
        ),
    ] {
        out.push(Shape {
            name,
            rewrite,
            gate,
            policy,
            taps: StageTaps::default(),
            observe_only: false,
        });
    }
    out
}

fn bind(shape: &Shape) -> UnitHooks {
    let mut pool_policies = std::collections::HashMap::new();
    if let Some(p) = &shape.policy {
        pool_policies.insert(POOL.to_string(), p.clone());
    }
    let hooks = BoundHooks {
        rewrites: if shape.rewrite {
            vec![(
                Duration::from_secs(1),
                Arc::new(Hook) as Arc<dyn RoutingPolicy>,
            )]
        } else {
            Vec::new()
        },
        gates: if shape.gate {
            vec![(0, policy(false, true, false))]
        } else {
            Vec::new()
        },
        pool_rewrites: Default::default(),
        pool_gates: Default::default(),
        pool_policies,
        taps: shape.taps.clone(),
        requested: RequestedSignals::default(),
        next_request_id: Arc::new(|| 1),
        caller: Arc::new(Nobody),
        dialects: vec!["d".to_string()],
    };
    hooks
        .bind(&Bind {
            pool: POOL,
            principal: None,
            dialect: 0,
            request_id: None,
        })
        .unwrap_or_else(|| panic!("{}: a unit with a hook binds", shape.name))
}

#[test]
fn observe_only_is_stated_for_exactly_the_hooks_that_only_observe() {
    for shape in shapes() {
        assert_eq!(
            bind(&shape).observe_only(),
            shape.observe_only,
            "{}",
            shape.name
        );
    }
}

#[test]
fn canonicalise_fault_never_takes_empty_arm() {
    for shape in shapes() {
        let unit = bind(&shape);
        assert!(
            unit.observe_only() || !unit.idle(),
            "{}: a screened unit is never idle",
            shape.name
        );
    }
    let ranked = bind(&Shape {
        name: "ranking strategy alone",
        rewrite: false,
        gate: false,
        policy: Some(policy(true, false, false)),
        taps: StageTaps::default(),
        observe_only: true,
    });
    assert!(
        ranked.observe_only() && !ranked.idle(),
        "the relation is one-way: a ranking-only unit is observe-only but not idle"
    );
}
