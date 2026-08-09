// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for inbound authentication, authorization and dispatch.
//!
//! The one that carries the most weight is
//! `a_key_scoped_only_to_pools_acquires_no_agents_on_upgrade`: the cross-kind admission semantics
//! are frozen and fail-closed, and the whole `a2a_inbound` design rests on that being true rather
//! than assumed. It is cheap to check here and expensive to discover later.

use super::*;
use crate::a2a::registry::AgentRegistration;
use crate::trust::{Observation, Sighting};
use busbar_api::ScopeRef;
use std::collections::BTreeMap;

fn a_key(id: &str, scopes: Option<Vec<ScopeRef>>) -> VirtualKey {
    VirtualKey {
        id: id.to_string(),
        generation_hash: String::new(),
        name: id.to_string(),
        allowed_scopes: scopes,
        enabled: true,
        created_at: 0,
        group: None,
        labels: BTreeMap::new(),
        expires_at: None,
        deleted_at: None,
        revision: 1,
    }
}

fn agent_scope(value: &str) -> ScopeRef {
    ScopeRef {
        kind: SCOPE_KIND_AGENT.to_string(),
        value: value.to_string(),
    }
}

fn approved(agent_id: &str) -> AgentRegistration {
    let mut r = AgentRegistration::registered(
        agent_id,
        format!("https://internal-{agent_id}.corp.example/a2a"),
    );
    let sighting = Sighting::Seen(Observation {
        pin: Some(crate::a2a::pin::CardPin::JwsIssuerKey {
            issuer_key: "KEY".to_string(),
            card_fingerprint: "sha256/CARD".to_string(),
        }),
        capabilities: [("plan".to_string(), "d1".to_string())]
            .into_iter()
            .collect(),
    });
    crate::a2a::pin::approve_registration(&mut r.approval, &sighting, None).expect("approve");
    r.sighting = sighting;
    r
}

fn registrations() -> Vec<AgentRegistration> {
    vec![approved("planner"), approved("summarizer")]
}

#[test]
fn a_scoped_live_key_of_the_right_kind_reaches_the_backend() {
    let key = a_key("k1", Some(vec![agent_scope("planner")]));
    let d = authorize(
        &key,
        CREDENTIAL_KIND_A2A_INBOUND,
        "planner",
        &registrations(),
        1_000,
    )
    .expect("authorized");
    assert_eq!(
        d,
        Dispatch {
            agent_id: "planner".to_string(),
            backend_url: "https://internal-planner.corp.example/a2a".to_string(),
            billed_key_id: "k1".to_string(),
        }
    );
}

#[test]
fn a_credential_of_another_kind_is_refused_with_401_and_never_names_a_backend() {
    let key = a_key("k1", None);
    for kind in ["sigv4", "bearer", "", "a2a-inbound", "A2A_INBOUND"] {
        let err = authorize(&key, kind, "planner", &registrations(), 1_000)
            .expect_err("only `a2a_inbound` admits here");
        assert_eq!(
            err,
            InboundRefusal::WrongCredentialKind {
                presented: kind.to_string()
            },
            "kind `{kind}`"
        );
        assert_eq!(err.status(), 401);
    }
}

#[test]
fn an_out_of_scope_key_is_refused_403_before_any_backend_is_named() {
    // The Lambda-authorizer posture: 403 BEFORE the work, because on this plane the work may be a
    // long-running task that reached down into L2 tools, and a 403 after it has already cost the
    // operator the thing the check was for.
    let key = a_key("k1", Some(vec![agent_scope("summarizer")]));
    let err = authorize(
        &key,
        CREDENTIAL_KIND_A2A_INBOUND,
        "planner",
        &registrations(),
        1_000,
    )
    .expect_err("out of scope");
    assert_eq!(
        err,
        InboundRefusal::NotInScope {
            key_id: "k1".to_string(),
            agent_id: "planner".to_string(),
        }
    );
    assert_eq!(err.status(), 403);
}

#[test]
fn a_key_scoped_only_to_pools_acquires_no_agents_on_upgrade() {
    // THE FROZEN CROSS-KIND SEMANTIC, checked rather than assumed. An explicit `allowed_scopes` is
    // exhaustive ACROSS ALL KINDS, so a key that named only pools grants access to NO agents. The
    // fail-OPEN reading would turn every existing pool-scoped key into a wildcard over a brand-new
    // kind, silently, on upgrade — and this whole credential design sits on top of it.
    let key = a_key("legacy", Some(vec![ScopeRef::pool("fast")]));
    for agent in ["planner", "summarizer"] {
        let err = authorize(
            &key,
            CREDENTIAL_KIND_A2A_INBOUND,
            agent,
            &registrations(),
            1_000,
        )
        .expect_err("a pool-only key grants NO agents");
        assert_eq!(err.status(), 403, "agent `{agent}`");
    }
    // An OMITTED list is the only wildcard.
    let wildcard = a_key("root", None);
    assert!(authorize(
        &wildcard,
        CREDENTIAL_KIND_A2A_INBOUND,
        "planner",
        &registrations(),
        1_000
    )
    .is_ok());
    // And an EMPTY explicit list is no scopes at all, never "all".
    let empty = a_key("empty", Some(Vec::new()));
    assert_eq!(
        authorize(
            &empty,
            CREDENTIAL_KIND_A2A_INBOUND,
            "planner",
            &registrations(),
            1_000
        )
        .expect_err("an empty list is NO scopes")
        .status(),
        403
    );
}

#[test]
fn a_key_that_is_not_live_is_refused_401_however_it_is_not_live() {
    // Three separate ways a key stops admitting, and the tombstone one matters most: the row
    // survives forever so billing and audit keep resolving it, so a row's EXISTENCE is not the
    // check.
    let cases: Vec<(&str, VirtualKey)> = vec![
        ("disabled", {
            let mut k = a_key("k1", None);
            k.enabled = false;
            k
        }),
        ("tombstoned", {
            let mut k = a_key("k1", None);
            k.deleted_at = Some(500);
            k
        }),
        ("expired", {
            let mut k = a_key("k1", None);
            k.expires_at = Some(1_000);
            k
        }),
    ];
    for (what, key) in cases {
        let err = authorize(
            &key,
            CREDENTIAL_KIND_A2A_INBOUND,
            "planner",
            &registrations(),
            1_000,
        )
        .expect_err(what);
        assert_eq!(
            err,
            InboundRefusal::KeyNotLive {
                key_id: "k1".to_string()
            },
            "{what}"
        );
        assert_eq!(err.status(), 401, "{what}");
    }
    // Reaching the expiry IS expired; one millisecond before it is not.
    let mut k = a_key("k1", None);
    k.expires_at = Some(1_001);
    assert!(authorize(
        &k,
        CREDENTIAL_KIND_A2A_INBOUND,
        "planner",
        &registrations(),
        1_000
    )
    .is_ok());
}

#[test]
fn a_suspended_fronted_agent_refuses_inbound_as_well_as_outbound() {
    // The breaker trips on how the agent BEHAVES. An agent behaving badly behaves badly for whoever
    // reached it, so a suspension that only closed the outbound direction would leave the inbound
    // one serving poisoned artifacts carrying busbar's own provenance stamp.
    let key = a_key("k1", None);
    let mut regs = registrations();
    regs[0]
        .approval
        .suspend("anomaly breaker: terminal_failure_rate observed 0.900");

    let err = authorize(&key, CREDENTIAL_KIND_A2A_INBOUND, "planner", &regs, 1_000)
        .expect_err("a suspended agent is not serving");
    assert!(
        matches!(
            err,
            InboundRefusal::NotServing {
                state: crate::trust::TrustState::Suspended,
                ref reason,
                ..
            } if reason.as_deref().is_some_and(|r| r.contains("terminal_failure_rate"))
        ),
        "got {err:?}"
    );
    assert_eq!(
        err.status(),
        503,
        "a statement about the AGENT, not the caller"
    );
    // Its sibling is untouched.
    assert!(authorize(
        &key,
        CREDENTIAL_KIND_A2A_INBOUND,
        "summarizer",
        &regs,
        1_000
    )
    .is_ok());
}

#[test]
fn a_quarantined_or_pending_agent_is_not_serving_either() {
    let key = a_key("k1", None);
    for (what, reg) in [
        (
            "pending",
            AgentRegistration::registered("planner", "https://x/"),
        ),
        ("quarantined", {
            let mut r = approved("planner");
            r.sighting = Sighting::Seen(Observation {
                pin: Some(crate::a2a::pin::CardPin::JwsIssuerKey {
                    issuer_key: "KEY".to_string(),
                    card_fingerprint: "sha256/CARD".to_string(),
                }),
                capabilities: [("plan".to_string(), "MOVED".to_string())]
                    .into_iter()
                    .collect(),
            });
            r
        }),
        ("error", {
            let mut r = approved("planner");
            r.sighting = Sighting::Failed("connection refused".to_string());
            r
        }),
    ] {
        let err =
            authorize(&key, CREDENTIAL_KIND_A2A_INBOUND, "planner", &[reg], 1_000).expect_err(what);
        assert_eq!(err.status(), 503, "{what}");
    }
}

#[test]
fn an_unknown_agent_is_a_404_and_an_out_of_scope_one_says_so() {
    // The confusable case is the one that matters, and it is not confusable: an agent that exists
    // and is out of scope says exactly that, so an operator debugging a scope grant is not shown
    // "no such agent" for one they are looking at.
    let key = a_key("k1", Some(vec![agent_scope("summarizer")]));
    let err = authorize(
        &key,
        CREDENTIAL_KIND_A2A_INBOUND,
        "nonexistent",
        &registrations(),
        1_000,
    )
    .expect_err("no such agent");
    assert_eq!(
        err,
        InboundRefusal::NoSuchAgent {
            agent_id: "nonexistent".to_string()
        }
    );
    assert_eq!(err.status(), 404);
    assert!(err.to_string().contains("nonexistent"));
}

#[test]
fn the_credential_kind_and_the_scope_kind_are_the_spellings_the_rest_of_the_tree_uses() {
    // Two constants, and both are wire-visible: the credential kind appears on a stored
    // `CredentialMeta` row and the scope kind on every `ScopeRef` an operator writes. Changing
    // either silently orphans every existing row, so they are pinned by value.
    assert_eq!(CREDENTIAL_KIND_A2A_INBOUND, "a2a_inbound");
    assert_eq!(SCOPE_KIND_AGENT, "agent");
}
