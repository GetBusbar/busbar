// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for the `AgentRegistration` record.
//!
//! What is being checked is mostly NEGATIVE: that the record adds nothing to the lifecycle, that
//! its derived answers are the machine's answers, and that a registration cannot come into
//! existence already delegable.

use super::*;
use crate::a2a::card;
use busbar_substrate::trust::Observation;
use serde_json::json;
use std::collections::BTreeMap;

fn a_pin() -> CardPin {
    CardPin::JwsIssuerKey {
        issuer_key: "MCowBQYDK2VwAyEAKEY".to_string(),
        card_fingerprint: "sha256/CARD".to_string(),
    }
}

fn seen(pin: CardPin, skills: &[(&str, &str)]) -> Sighting<CardPin> {
    Sighting::Seen(Observation {
        pin: Some(pin),
        capabilities: skills
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect::<BTreeMap<_, _>>(),
    })
}

#[test]
fn a_fresh_registration_is_pending_and_delegable_to_nobody() {
    let reg = AgentRegistration::registered("planner", "https://a2a.vendor/planner");
    assert_eq!(reg.trust_state(), TrustState::Pending);
    assert!(!reg.is_delegable(), "the fail-closed floor");
    assert!(!reg.may_dispatch("plan", "whatever"));
    assert!(reg.suspension_reason().is_none());
    assert_eq!(reg.protocol_binding.label(), "JSONRPC");
    // The other binding is an enum ARM rather than a free string, so adding gRPC support is a
    // decision somebody makes rather than a value that turns up in a config file.
    assert_eq!(crate::a2a::registry::ProtocolBinding::Grpc.label(), "GRPC");
    assert!(
        reg.egress_scopes.is_empty(),
        "no fronted agent may delegate here until an operator says one may"
    );
}

#[test]
fn the_records_trust_answers_are_the_machines_answers_and_not_a_second_opinion() {
    // The point of holding an `Approval` rather than a `trust_state` field: there is no stored
    // answer that could disagree with the observation it summarizes.
    let mut reg = AgentRegistration::registered("planner", "https://a2a.vendor/planner");
    reg.sighting = seen(a_pin(), &[("plan", "d1")]);
    assert_eq!(
        reg.trust_state(),
        TrustState::Pending,
        "capture never promotes"
    );

    crate::a2a::pin::approve_registration(&mut reg.approval, &reg.sighting.clone(), None)
        .expect("approve");
    assert_eq!(reg.trust_state(), TrustState::Approved);
    assert!(reg.is_delegable());
    assert!(reg.may_dispatch("plan", "d1"));
    assert!(
        !reg.may_dispatch("plan", "d2"),
        "only AT the approved digest"
    );

    // Drift derives quarantine and closes the dispatch gate, with no field anywhere set to say so.
    reg.sighting = seen(a_pin(), &[("plan", "MOVED")]);
    assert_eq!(reg.trust_state(), TrustState::Quarantined);
    assert!(!reg.is_delegable());
    assert!(!reg.may_dispatch("plan", "MOVED"));
    assert_eq!(reg.changes().changed, vec!["plan".to_string()]);
}

#[test]
fn the_anomaly_breaker_suspends_a_registration_whose_card_is_beyond_reproach() {
    // The rug-pull case: pin locked, every digest matching, and the agent simply misbehaving. This
    // is the only remaining correction for it, so it has to actually suspend rather than report.
    let mut reg = AgentRegistration::registered("planner", "https://a2a.vendor/planner");
    reg.sighting = seen(a_pin(), &[("plan", "d1")]);
    crate::a2a::pin::approve_registration(&mut reg.approval, &reg.sighting.clone(), None)
        .expect("approve");
    assert!(reg.may_dispatch("plan", "d1"));

    reg.thresholds = crate::a2a::anomaly::Thresholds {
        min_observations: 20,
        error_rate: Some(0.5),
        ..Default::default()
    };
    reg.window = crate::a2a::anomaly::Window {
        observations: 40,
        errors: 30,
        first_observation_ms: 1_000,
        last_observation_ms: 9_000,
        ..Default::default()
    };

    let trip = reg.apply_anomaly_breaker().expect("the breaker must trip");
    assert_eq!(trip.signal.label(), "error_rate");
    assert_eq!(reg.trust_state(), TrustState::Suspended);
    assert!(!reg.is_delegable());
    assert!(
        !reg.may_dispatch("plan", "d1"),
        "a suspended registration serves NOTHING, card notwithstanding"
    );

    let reason = reg.suspension_reason().expect("a visible reason");
    for fragment in [
        "error_rate",
        "0.750",
        "0.500",
        "40 observation(s)",
        "1000ms",
        "9000ms",
    ] {
        assert!(
            reason.contains(fragment),
            "the operator-visible reason must carry `{fragment}`: {reason}"
        );
    }
}

#[test]
fn the_breaker_below_its_sample_floor_does_not_suspend_anything() {
    let mut reg = AgentRegistration::registered("planner", "https://a2a.vendor/planner");
    reg.sighting = seen(a_pin(), &[("plan", "d1")]);
    crate::a2a::pin::approve_registration(&mut reg.approval, &reg.sighting.clone(), None)
        .expect("approve");
    reg.thresholds = crate::a2a::anomaly::Thresholds {
        min_observations: 20,
        error_rate: Some(0.5),
        ..Default::default()
    };
    // One dispatch, and it failed: a 100 percent error rate on a sample of one.
    reg.window = crate::a2a::anomaly::Window {
        observations: 1,
        errors: 1,
        ..Default::default()
    };
    assert!(reg.apply_anomaly_breaker().is_none());
    assert_eq!(reg.trust_state(), TrustState::Approved);
}

#[test]
fn the_breaker_does_not_re_suspend_or_overwrite_an_operators_own_reason() {
    let mut reg = AgentRegistration::registered("planner", "https://a2a.vendor/planner");
    reg.sighting = seen(a_pin(), &[("plan", "d1")]);
    crate::a2a::pin::approve_registration(&mut reg.approval, &reg.sighting.clone(), None)
        .expect("approve");
    reg.approval
        .suspend("operator: vendor breach disclosed 2026-08-09");

    reg.thresholds = crate::a2a::anomaly::Thresholds {
        min_observations: 1,
        error_rate: Some(0.1),
        ..Default::default()
    };
    reg.window = crate::a2a::anomaly::Window {
        observations: 10,
        errors: 10,
        ..Default::default()
    };
    assert!(
        reg.apply_anomaly_breaker().is_none(),
        "an already-suspended registration is not re-suspended"
    );
    assert_eq!(
        reg.suspension_reason(),
        Some("operator: vendor breach disclosed 2026-08-09"),
        "the operator's out-of-band reason must not be overwritten by a breaker line"
    );
}

#[test]
fn intent_and_accumulation_are_separable_field_by_field() {
    // The overlay/store ruling, checked rather than asserted: taking the record apart along that
    // line must account for EVERY field. This destructure is exhaustive with no `..`, so a new
    // field fails to compile until somebody has decided which side it is on.
    let reg = AgentRegistration::registered("planner", "https://a2a.vendor/planner");
    let AgentRegistration {
        // ── INTENT: what an operator wrote, and may edit. Overlay. ──
        agent_id,
        backend_url,
        protocol_version,
        protocol_binding,
        approval,
        reverify,
        thresholds,
        egress_scopes,
        outbound_cred,
        allow_private,
        // ── ACCUMULATION: what happened, and may not be edited. Store. ──
        sighting,
        cached_card,
        ledger,
        window,
    } = &reg;

    // Intent is complete without any observation, which is what makes a declaratively-pinned
    // registration a legal thing to have.
    assert_eq!(agent_id, "planner");
    assert_eq!(backend_url, "https://a2a.vendor/planner");
    assert_eq!(protocol_version, "0.3.0");
    assert_eq!(
        *protocol_binding,
        crate::a2a::registry::ProtocolBinding::JsonRpc
    );
    assert!(approval.pin().is_none());
    assert!(reverify.ttl_ms > 0);
    assert_eq!(thresholds.min_observations, 0);
    assert!(egress_scopes.is_empty());
    assert!(outbound_cred.is_none());
    assert!(
        !*allow_private,
        "the private-address opt-in is INTENT and its floor is off: a registration that came into \
         existence permitted to reach loopback would be an SSRF the operator never wrote down"
    );

    // Accumulation is empty on a fresh registration, and nothing about the trust answer depends on
    // it having been filled in.
    assert_eq!(*sighting, Sighting::Never);
    assert!(cached_card.is_none());
    assert_eq!(*ledger, crate::a2a::reverify::Ledger::default());
    assert_eq!(*window, crate::a2a::anomaly::Window::default());
}

#[test]
fn the_cached_card_is_the_document_as_received() {
    // Both hashes are over the received document, so a registration that stored a re-serialization
    // would be caching something whose fingerprint is not the one that was approved.
    let mut reg = AgentRegistration::registered("planner", "https://a2a.vendor/planner");
    let document = json!({
        "protocolVersion": "0.3.0",
        "name": "planner",
        "somethingBusbarDoesNotModel": { "z": 1, "a": 2 },
        "skills": [{ "id": "plan" }]
    });
    let fingerprint = card::fingerprint(&document).expect("fingerprint");
    reg.cached_card = Some(document.clone());

    assert_eq!(
        card::fingerprint(reg.cached_card.as_ref().expect("cached")).expect("fingerprint"),
        fingerprint,
        "caching must not change what the card hashes to"
    );
}
