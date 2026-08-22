// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for A2A catalogue construction, both directions — this plane's half of
//! [`crate::catalogue`]'s seam: which grants an `AgentRegistration` requires, which question its
//! catalogue asks of the ordered gate, its structural fitness and its refusal words.
//!
//! The four filters are checked one at a time AND together, because a conjunction is exactly the
//! shape where one clause quietly stops mattering: three tests that each pass with a different
//! single filter disabled would all still be green.

use super::*;
use crate::trust::Observation;
use busbar_api::{ScopeRef, VirtualKey};
use serde_json::json;
use std::collections::BTreeMap;

fn a_key(scopes: Option<Vec<&str>>) -> VirtualKey {
    VirtualKey {
        id: "k1".to_string(),
        generation_hash: String::new(),
        name: "k1".to_string(),
        allowed_scopes: scopes.map(|s| {
            s.into_iter()
                .map(|v| ScopeRef {
                    kind: SCOPE_KIND_AGENT.to_string(),
                    value: v.to_string(),
                })
                .collect()
        }),
        enabled: true,
        created_at: 0,
        group: None,
        labels: BTreeMap::new(),
        expires_at: None,
        deleted_at: None,
        revision: 1,
        ..Default::default()
    }
}

/// THE ASK, wrapped. The catalogue judges a caller rather than a bare key now: the ordered
/// validator's first and fourth steps need a clock and a generation, and carrying all three together
/// is what stops a call site pairing this caller's key with another request's snapshot.
fn as_caller(key: &VirtualKey) -> Caller<'_> {
    Caller {
        key: Some(key),
        now: 0,
        generation: crate::trust::validate::Generations::at_admission(1),
    }
}

/// THE RECEIVING ASK for a task shape: no delegating agent, so no egress grant is required.
fn inbound(shape: &TaskShape) -> Wanted {
    Wanted {
        shape: shape.clone(),
        delegating_from: None,
    }
}

/// THE DELEGATING ASK: the same shape plus the fronted agent doing the delegating, which is the ONE
/// structural difference between the two directions and is now one extra `Grant` in the list rather
/// than a second function.
fn from_agent(from: &str, shape: &TaskShape) -> Wanted {
    Wanted {
        shape: shape.clone(),
        delegating_from: Some(from.to_string()),
    }
}

fn a_card(skills: serde_json::Value, capabilities: serde_json::Value) -> serde_json::Value {
    json!({
        "protocolVersion": "0.3.0",
        "name": "agent",
        "defaultInputModes": ["application/json"],
        "defaultOutputModes": ["application/json"],
        "capabilities": capabilities,
        "skills": skills
    })
}

fn approved_with(agent_id: &str, card: serde_json::Value) -> AgentRegistration {
    let mut r = AgentRegistration::registered(agent_id, format!("https://backend/{agent_id}"));
    let digests = crate::a2a::card::skill_digests(&card).expect("digests");
    let sighting = Sighting::Seen(Observation {
        pin: Some(crate::a2a::pin::CardPin::JwsIssuerKey {
            issuer_key: "KEY".to_string(),
            card_fingerprint: "sha256/CARD".to_string(),
        }),
        capabilities: digests,
    });
    crate::a2a::pin::approve_registration(&mut r.approval, &sighting, None).expect("approve");
    r.sighting = sighting;
    r.cached_card = Some(card);
    r
}

fn planner() -> AgentRegistration {
    approved_with(
        "planner",
        a_card(
            json!([{ "id": "plan", "name": "Plan" }, { "id": "summarize", "name": "Summarize" }]),
            json!({ "streaming": true, "pushNotifications": false }),
        ),
    )
}

fn researcher() -> AgentRegistration {
    approved_with(
        "researcher",
        a_card(
            json!([{ "id": "research", "name": "Research" }]),
            json!({ "streaming": false, "pushNotifications": true }),
        ),
    )
}

fn ids(candidates: &[Candidate<'_>]) -> Vec<String> {
    candidates.iter().map(|c| c.item.agent_id.clone()).collect()
}

#[test]
fn an_unconstrained_caller_sees_every_approved_agent_in_registry_order() {
    // Insertion order, not hash order: an operator-facing listing that reshuffles between reads is
    // one nobody can diff.
    let regs = vec![planner(), researcher()];
    let cat = inbound_catalogue(
        &as_caller(&a_key(None)),
        &regs,
        &inbound(&TaskShape::default()),
    );
    assert_eq!(ids(&cat), vec!["planner", "researcher"]);
    assert!(
        cat.iter().all(|c| c.fit.is_none()),
        "no skill was asked for"
    );
}

#[test]
fn scope_decides_visibility_and_a_pool_only_key_sees_nothing() {
    let regs = vec![planner(), researcher()];
    assert_eq!(
        ids(&inbound_catalogue(
            &as_caller(&a_key(Some(vec!["planner"]))),
            &regs,
            &inbound(&TaskShape::default())
        )),
        vec!["planner"]
    );
    let mut pool_only = a_key(Some(vec![]));
    pool_only.allowed_scopes = Some(vec![ScopeRef::pool("fast")]);
    assert!(
        inbound_catalogue(
            &as_caller(&pool_only),
            &regs,
            &inbound(&TaskShape::default())
        )
        .is_empty(),
        "cross-kind admission is fail-closed"
    );
}

#[test]
fn only_an_approved_registration_is_ever_a_candidate() {
    // Every non-approved state, by name, so a regression says WHICH one started leaking.
    let key = a_key(None);
    let shape = TaskShape::default();

    let pending = AgentRegistration::registered("pending", "https://backend/pending");
    let mut quarantined = planner();
    quarantined.agent_id = "quarantined".to_string();
    quarantined.sighting = Sighting::Seen(Observation {
        pin: Some(crate::a2a::pin::CardPin::JwsIssuerKey {
            issuer_key: "KEY".to_string(),
            card_fingerprint: "sha256/CARD".to_string(),
        }),
        capabilities: [("plan".to_string(), "MOVED".to_string())]
            .into_iter()
            .collect(),
    });
    let mut suspended = planner();
    suspended.agent_id = "suspended".to_string();
    suspended
        .approval
        .suspend("anomaly breaker: error_rate 0.9");
    let mut errored = planner();
    errored.agent_id = "errored".to_string();
    errored.sighting = Sighting::Failed("connection refused".to_string());

    for (what, reg, expected) in [
        ("pending", pending, TrustState::Pending),
        ("quarantined", quarantined, TrustState::Quarantined),
        ("suspended", suspended, TrustState::Suspended),
        ("errored", errored, TrustState::Error),
    ] {
        assert!(
            inbound_catalogue(
                &as_caller(&key),
                std::slice::from_ref(&reg),
                &inbound(&shape)
            )
            .is_empty(),
            "a {what} registration must not be a candidate"
        );
        assert_eq!(
            explain(&reg, &as_caller(&key), &inbound(&shape)).expect_err(what),
            Excluded::NotTrusted(expected),
            "{what}"
        );
    }
}

#[test]
fn capability_matching_is_structural_and_names_the_skill_it_matched() {
    let regs = vec![planner(), researcher()];
    let key = a_key(None);

    let want_plan = TaskShape {
        skill: Some("plan".to_string()),
        ..Default::default()
    };
    let cat = inbound_catalogue(&as_caller(&key), &regs, &inbound(&want_plan));
    assert_eq!(ids(&cat), vec!["planner"]);
    assert_eq!(cat[0].fit.as_deref(), Some("plan"));

    // A skill nobody declares yields an empty catalogue, and the exclusion NAMES it: A2A agents are
    // not fungible, so "some agent will cope" is not an available answer.
    let want_nothing = TaskShape {
        skill: Some("translate".to_string()),
        ..Default::default()
    };
    assert!(inbound_catalogue(&as_caller(&key), &regs, &inbound(&want_nothing)).is_empty());
    assert_eq!(
        explain(&regs[0], &as_caller(&key), &inbound(&want_nothing)).expect_err("no such skill"),
        Excluded::SkillNotDeclared("translate".to_string())
    );
}

#[test]
fn a_required_protocol_capability_the_card_does_not_declare_excludes_the_agent() {
    let regs = vec![planner(), researcher()];
    let key = a_key(None);

    let streaming = TaskShape {
        requires_streaming: true,
        ..Default::default()
    };
    assert_eq!(
        ids(&inbound_catalogue(
            &as_caller(&key),
            &regs,
            &inbound(&streaming)
        )),
        vec!["planner"]
    );
    assert_eq!(
        explain(&regs[1], &as_caller(&key), &inbound(&streaming)).expect_err("no streaming"),
        Excluded::CapabilityNotDeclared("streaming")
    );

    let push = TaskShape {
        requires_push_notifications: true,
        ..Default::default()
    };
    assert_eq!(
        ids(&inbound_catalogue(&as_caller(&key), &regs, &inbound(&push))),
        vec!["researcher"]
    );
    assert_eq!(
        explain(&regs[0], &as_caller(&key), &inbound(&push)).expect_err("no push"),
        Excluded::CapabilityNotDeclared("pushNotifications")
    );
}

#[test]
fn modes_must_be_compatible_in_both_directions() {
    // An agent that accepts the request and answers in a format the caller cannot read has not
    // served the task, so output is checked as well as input.
    let key = a_key(None);
    let regs = vec![planner()];

    let sends_audio = TaskShape {
        input_modes: vec!["audio/wav".to_string()],
        ..Default::default()
    };
    assert_eq!(
        explain(&regs[0], &as_caller(&key), &inbound(&sends_audio))
            .expect_err("incompatible input"),
        Excluded::ModesIncompatible
    );

    let wants_pdf = TaskShape {
        output_modes: vec!["application/pdf".to_string()],
        ..Default::default()
    };
    assert_eq!(
        explain(&regs[0], &as_caller(&key), &inbound(&wants_pdf)).expect_err("incompatible output"),
        Excluded::ModesIncompatible
    );

    let json = TaskShape {
        input_modes: vec!["application/json".to_string()],
        output_modes: vec!["application/json".to_string()],
        ..Default::default()
    };
    assert_eq!(
        ids(&inbound_catalogue(&as_caller(&key), &regs, &inbound(&json))),
        vec!["planner"]
    );
}

#[test]
fn a_caller_that_names_no_modes_is_not_constraining_the_match() {
    // Silence says nothing. Reading it as "accepts nothing" would empty every catalogue by default,
    // which is a fail-closed that closes on the ordinary case.
    let key = a_key(None);
    let regs = vec![planner()];
    assert_eq!(
        ids(&inbound_catalogue(
            &as_caller(&key),
            &regs,
            &inbound(&TaskShape::default())
        )),
        vec!["planner"]
    );
}

#[test]
fn a_skills_own_modes_override_the_card_defaults_and_fall_back_to_them() {
    let key = a_key(None);
    let card = json!({
        "protocolVersion": "0.3.0",
        "name": "agent",
        "defaultInputModes": ["application/json"],
        "defaultOutputModes": ["application/json"],
        "capabilities": {},
        "skills": [
            { "id": "transcribe", "inputModes": ["audio/wav"], "outputModes": ["text/plain"] },
            { "id": "plan" }
        ]
    });
    let regs = vec![approved_with("multi", card)];

    // The skill's OWN modes win where it declares them.
    let audio = TaskShape {
        skill: Some("transcribe".to_string()),
        input_modes: vec!["audio/wav".to_string()],
        output_modes: vec!["text/plain".to_string()],
        ..Default::default()
    };
    assert_eq!(
        ids(&inbound_catalogue(
            &as_caller(&key),
            &regs,
            &inbound(&audio)
        )),
        vec!["multi"]
    );

    let json_to_transcribe = TaskShape {
        skill: Some("transcribe".to_string()),
        input_modes: vec!["application/json".to_string()],
        ..Default::default()
    };
    assert_eq!(
        explain(&regs[0], &as_caller(&key), &inbound(&json_to_transcribe))
            .expect_err("the skill overrides"),
        Excluded::ModesIncompatible
    );

    // And a skill that declares none falls back to the card defaults rather than reading as
    // "accepts nothing".
    let plan_json = TaskShape {
        skill: Some("plan".to_string()),
        input_modes: vec!["application/json".to_string()],
        ..Default::default()
    };
    assert_eq!(
        ids(&inbound_catalogue(
            &as_caller(&key),
            &regs,
            &inbound(&plan_json)
        )),
        vec!["multi"]
    );
}

#[test]
fn an_agent_with_no_cached_card_is_not_a_candidate_whatever_its_approval_says() {
    // There is nothing to match against, and "no card" must never read as "matches everything".
    let key = a_key(None);
    let mut reg = planner();
    reg.cached_card = None;
    assert!(inbound_catalogue(
        &as_caller(&key),
        std::slice::from_ref(&reg),
        &inbound(&TaskShape::default())
    )
    .is_empty());
    assert_eq!(
        explain(&reg, &as_caller(&key), &inbound(&TaskShape::default())).expect_err("no card"),
        Excluded::NoCachedCard
    );
}

// ══ THE DELEGATION CATALOGUE ═════════════════════════════════════════════════════════════════════

#[test]
fn a_delegation_target_needs_an_explicit_egress_grant_and_empty_means_nobody() {
    // The fail-closed floor. Reading an empty `egress_scopes` as "everyone" would be a registration
    // granting egress nobody wrote down.
    let key = a_key(None);
    let shape = TaskShape::default();
    let mut regs = vec![planner(), researcher()];

    assert!(
        delegation_catalogue(&as_caller(&key), &regs, &from_agent("orchestrator", &shape))
            .is_empty(),
        "no egress grant, no delegation target"
    );
    assert_eq!(
        explain(
            &regs[0],
            &as_caller(&key),
            &from_agent("orchestrator", &shape)
        )
        .expect_err("no grant"),
        Excluded::NoEgressGrant
    );

    regs[0].egress_scopes = vec!["orchestrator".to_string()];
    assert_eq!(
        ids(&delegation_catalogue(
            &as_caller(&key),
            &regs,
            &from_agent("orchestrator", &shape)
        )),
        vec!["planner"]
    );
    // And the grant is per fronted agent: a DIFFERENT one is still refused.
    assert!(
        delegation_catalogue(&as_caller(&key), &regs, &from_agent("intern", &shape)).is_empty()
    );
}

#[test]
fn the_egress_grant_is_the_only_structural_difference_between_the_two_catalogues() {
    // Receiving is a strict subset of delegating minus the trust root, and this is where that
    // relation is visible: grant egress to everyone and the two catalogues agree exactly.
    let key = a_key(None);
    let shape = TaskShape {
        skill: Some("plan".to_string()),
        ..Default::default()
    };
    let mut regs = vec![planner(), researcher()];
    for r in regs.iter_mut() {
        r.egress_scopes = vec!["orchestrator".to_string()];
    }
    assert_eq!(
        ids(&inbound_catalogue(
            &as_caller(&key),
            &regs,
            &inbound(&shape)
        )),
        ids(&delegation_catalogue(
            &as_caller(&key),
            &regs,
            &from_agent("orchestrator", &shape)
        ))
    );
}

#[test]
fn every_filter_is_load_bearing_in_the_conjunction() {
    // A conjunction is where a clause quietly stops mattering. Each row below fails exactly one
    // filter while satisfying the others, so a filter that stopped being applied lets its own row
    // through and is named by the failure.
    let shape = TaskShape {
        skill: Some("plan".to_string()),
        requires_streaming: true,
        requires_push_notifications: false,
        input_modes: vec!["application/json".to_string()],
        output_modes: vec!["application/json".to_string()],
    };
    let scoped = a_key(Some(vec!["planner"]));

    // The control: everything satisfied.
    let mut ok = planner();
    ok.egress_scopes = vec!["orchestrator".to_string()];
    assert_eq!(
        ids(&delegation_catalogue(
            &as_caller(&scoped),
            &[ok.clone()],
            &from_agent("orchestrator", &shape)
        )),
        vec!["planner"],
        "the control must pass, or the rows below prove nothing"
    );

    // One filter broken per row.
    let mut untrusted = ok.clone();
    untrusted.approval.suspend("operator: out of band report");
    let mut unscoped = ok.clone();
    unscoped.agent_id = "elsewhere".to_string();
    let mut no_egress = ok.clone();
    no_egress.egress_scopes.clear();
    let mut wrong_skill = approved_with(
        "planner",
        a_card(json!([{ "id": "other" }]), json!({ "streaming": true })),
    );
    wrong_skill.egress_scopes = vec!["orchestrator".to_string()];
    let mut no_streaming = approved_with(
        "planner",
        a_card(json!([{ "id": "plan" }]), json!({ "streaming": false })),
    );
    no_streaming.egress_scopes = vec!["orchestrator".to_string()];

    for (what, reg) in [
        ("trust", untrusted),
        ("scope", unscoped),
        ("egress", no_egress),
        ("skill", wrong_skill),
        ("capability", no_streaming),
    ] {
        assert!(
            delegation_catalogue(
                &as_caller(&scoped),
                &[reg],
                &from_agent("orchestrator", &shape)
            )
            .is_empty(),
            "the `{what}` filter stopped being applied"
        );
    }
}

#[test]
fn the_task_shape_carries_no_channel_for_prose() {
    // CONTENT-BLINDNESS, enforced by construction rather than by discipline: the decision function
    // is not given any content to read. Exhaustive destructure, no `..`, so a `text` field cannot
    // arrive without this failing to compile.
    let TaskShape {
        skill,
        requires_streaming,
        requires_push_notifications,
        input_modes,
        output_modes,
    } = TaskShape::default();
    assert!(skill.is_none());
    assert!(!requires_streaming && !requires_push_notifications);
    assert!(input_modes.is_empty() && output_modes.is_empty());
}

/// CROSS-TENANT ISOLATION, stated as such rather than inferred.
///
/// `scope_decides_visibility_and_a_pool_only_key_sees_nothing` above shows a narrowed key seeing
/// less; this shows TWO principals seeing DISJOINT inventories through the unified walk, which is
/// the property an operator actually relies on. Asserted as disjointness AND non-emptiness together:
/// "each saw one agent" is exactly what a swapped filter would also report, and "each saw nothing"
/// is what a filter that refuses everything would.
#[test]
fn no_principal_sees_another_principals_agents() {
    let regs = vec![planner(), researcher()];
    let alice = a_key(Some(vec!["planner"]));
    let bob = a_key(Some(vec!["researcher"]));
    let anything = inbound(&TaskShape::default());

    let alice_sees = ids(&inbound_catalogue(&as_caller(&alice), &regs, &anything));
    let bob_sees = ids(&inbound_catalogue(&as_caller(&bob), &regs, &anything));

    assert_eq!(alice_sees, vec!["planner"]);
    assert_eq!(bob_sees, vec!["researcher"]);
    assert!(
        alice_sees.iter().all(|a| !bob_sees.contains(a)),
        "one principal's catalogue appeared in the other's: {alice_sees:?} / {bob_sees:?}"
    );
    assert!(!alice_sees.is_empty() && !bob_sees.is_empty());

    // The DELEGATION direction is isolated by the same grant, not merely by the egress list: grant
    // both registrations egress to one orchestrator and each key still reaches only its own.
    let mut both = regs.clone();
    for r in both.iter_mut() {
        r.egress_scopes = vec!["orchestrator".to_string()];
    }
    let delegating = from_agent("orchestrator", &TaskShape::default());
    assert_eq!(
        ids(&delegation_catalogue(
            &as_caller(&alice),
            &both,
            &delegating
        )),
        vec!["planner"],
        "the egress grant does not widen what a key's own scope reaches"
    );

    // And the addressed read agrees with the listing: naming another principal's agent is refused
    // with the SCOPE reason.
    assert_eq!(
        explain(&regs[1], &as_caller(&alice), &anything).expect_err("not alice's"),
        Excluded::NotInScope
    );
}

/// A KEY THAT IS NO LONGER LIVE SEES NOTHING, and is told so in its own arm.
///
/// The ordered gate's identity step, reached through the unified walk. `CallerNotLive` is kept apart
/// from `NotInScope` because "grant this key a scope" and "this key is gone" are two different
/// things for an operator to do.
#[test]
fn a_key_that_is_no_longer_live_sees_no_agent_at_all() {
    let regs = vec![planner(), researcher()];
    let live = a_key(None);
    let anything = inbound(&TaskShape::default());
    assert_eq!(
        ids(&inbound_catalogue(&as_caller(&live), &regs, &anything)).len(),
        2,
        "the control must pass, or the rows below prove nothing"
    );

    for (what, mutate) in [
        (
            "deleted",
            (|k: &mut VirtualKey| k.deleted_at = Some(1)) as fn(&mut VirtualKey),
        ),
        ("disabled", |k: &mut VirtualKey| k.enabled = false),
        ("expired", |k: &mut VirtualKey| k.expires_at = Some(1)),
    ] {
        let mut gone = live.clone();
        mutate(&mut gone);
        let asked = Caller {
            key: Some(&gone),
            now: 100,
            generation: crate::trust::validate::Generations::at_admission(1),
        };
        assert!(
            inbound_catalogue(&asked, &regs, &anything).is_empty(),
            "a {what} key must see no agent"
        );
        assert_eq!(
            explain(&regs[0], &asked, &anything).expect_err(what),
            Excluded::CallerNotLive,
            "{what}"
        );
    }
}
