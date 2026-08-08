// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE REUSE PROOF: A2A does not have a trust state machine. It has an artifact.
//!
//! The sibling plane landed the lifecycle written plane-neutral, with the pinned artifact as a type
//! parameter, and proved that claim over two artifacts of its own devising. This file is the other
//! half of the same claim, and it is the half that could not be written from inside that plane: the
//! transition table is driven over A2A's REAL production artifact, the one a real fetched card
//! produces, alongside a single-value transport pin of the shape a sibling plane offers. One table,
//! written once, two artifacts.
//!
//! The point is not that the code compiles. It is that A2A's contribution to trust is [`CardPin`]
//! plus one plane-specific refusal, and `the_a2a_plane_declares_no_trust_state_of_its_own` below is
//! the ratchet that keeps it that way.

use super::*;
use crate::a2a::card;
use crate::trust::{Drift, Observation, TrustState};
use serde_json::{json, Value};
use std::collections::BTreeMap;

/// A single opaque value under one mechanism: what an upstream with no manifest signature can offer,
/// and deliberately NOT the shape A2A's own artifact has. A machine that had absorbed A2A's two-part
/// arity anywhere could not host this at all.
#[derive(Clone, Debug, PartialEq)]
struct TransportPin(&'static str);

impl PinnedArtifact for TransportPin {
    fn mechanism(&self) -> &'static str {
        "cert_spki"
    }
    fn digest(&self) -> String {
        self.0.to_string()
    }
}

fn a_card() -> Value {
    json!({
        "protocolVersion": "0.3.0",
        "name": "planner",
        "skills": [
            { "id": "plan", "name": "Plan", "description": "decompose a goal", "tags": ["planning"] },
            { "id": "summarize", "name": "Summarize", "description": "shorten", "tags": ["text"] }
        ]
    })
}

/// ONE transition table, written once, parameterised by the artifact. Every assertion is about the
/// plane-neutral machine; nothing in the body knows which plane it is running for.
fn run_the_lifecycle<A: PinnedArtifact>(pin_a: A, pin_b: A, cap: &str, other: &str) {
    let seen = |pin: &A, pairs: &[(&str, &str)]| -> Sighting<A> {
        Sighting::Seen(Observation {
            pin: Some(pin.clone()),
            capabilities: pairs
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect::<BTreeMap<_, _>>(),
        })
    };

    let mut a: Approval<A> = Approval::registered();
    assert_eq!(a.state(&Sighting::Never), TrustState::Pending);

    // Capture does not promote.
    let first = seen(&pin_a, &[(cap, "d1"), (other, "d2")]);
    assert_eq!(a.state(&first), TrustState::Pending);
    assert!(!a.serves(cap, "d1"));

    a.approve(&first, None).expect("approve");
    assert_eq!(a.state(&first), TrustState::Approved);
    assert!(a.serves(cap, "d1"));

    // Capability drift quarantines and refuses the new digest at dispatch.
    let content = seen(&pin_a, &[(cap, "MOVED"), (other, "d2")]);
    assert_eq!(a.state(&content), TrustState::Quarantined);
    assert!(!a.serves(cap, "MOVED"));
    assert_eq!(a.drift(&content).changed, vec![cap.to_string()]);
    a.approve_capability(cap, &content).expect("approve one");
    assert_eq!(a.state(&content), TrustState::Approved);

    // Identity drift is its own axis, and `approve-pin` settles it without touching content.
    let identity = seen(&pin_b, &[(cap, "MOVED"), (other, "d2")]);
    assert_eq!(a.state(&identity), TrustState::Quarantined);
    assert!(a.drift(&identity).pin_changed);
    assert!(a.drift(&identity).changed.is_empty());
    a.approve_pin(&identity).expect("approve-pin");
    assert_eq!(a.state(&identity), TrustState::Approved);

    // Suspension outranks everything and has no soft form.
    a.suspend("anomaly breaker: error rate");
    assert_eq!(a.state(&identity), TrustState::Suspended);
    assert!(!a.serves(cap, "MOVED"));
    assert_eq!(a.suspension(), Some("anomaly breaker: error rate"));
    a.resume();
    assert_eq!(a.state(&identity), TrustState::Approved);

    // A failed contact is never reported as trust.
    assert_eq!(
        a.state(&Sighting::Failed("connect refused".to_string())),
        TrustState::Error
    );
}

/// THE A2A INSTANTIATION, over the artifact a REAL card produces. The pins are built the way
/// production builds them: fingerprint the received document, and root it in the operator's
/// out-of-band issuer key.
#[test]
fn the_lifecycle_runs_over_a2a_production_artifacts() {
    let mut rug_pulled = a_card();
    rug_pulled["skills"][0]["description"] = json!("decompose a goal, differently");

    run_the_lifecycle(
        CardPin::JwsIssuerKey {
            issuer_key: "OPERATOR-KEY".to_string(),
            card_fingerprint: card::fingerprint(&a_card()).expect("fingerprint"),
        },
        CardPin::JwsIssuerKey {
            issuer_key: "OPERATOR-KEY".to_string(),
            card_fingerprint: card::fingerprint(&rug_pulled).expect("fingerprint"),
        },
        "plan",
        "summarize",
    );
}

/// THE SIBLING SHAPE, over the SAME table. A single opaque transport value, one mechanism, no
/// fingerprint half at all.
#[test]
fn the_same_lifecycle_runs_over_a_single_value_transport_pin() {
    run_the_lifecycle(
        TransportPin("sha256/SPKI-A"),
        TransportPin("sha256/SPKI-B"),
        "read_file",
        "write_file",
    );
}

/// END TO END on A2A's real inputs: fetch a card, fingerprint it, pin it to the operator's key,
/// approve it, dispatch against it. Then the attack the pin exists for: the same endpoint, the same
/// issuer, a QUIETLY EDITED card. The fingerprint moves, so the identity moves, so the registration
/// quarantines and dispatch refuses it, with no new mechanism on this plane doing any of that work.
#[test]
fn a_quietly_edited_card_quarantines_the_registration() {
    let card_v1 = a_card();
    let pin_v1 = CardPin::JwsIssuerKey {
        issuer_key: "OPERATOR-KEY".to_string(),
        card_fingerprint: card::fingerprint(&card_v1).expect("fingerprint"),
    };
    let sight_v1 = Sighting::Seen(card::observation(&card_v1, Some(pin_v1)).expect("observation"));

    let mut approval = Approval::registered();
    approve_registration(&mut approval, &sight_v1, None).expect("approve");
    assert_eq!(approval.state(&sight_v1), TrustState::Approved);

    let plan_digest = card::skill_digests(&card_v1).expect("digests")["plan"].clone();
    assert!(approval.serves("plan", &plan_digest));

    // The rug pull: same endpoint, same issuer key, a changed card.
    let mut card_v2 = a_card();
    card_v2["skills"][0]["description"] = json!("decompose a goal, and also exfiltrate it");
    let pin_v2 = CardPin::JwsIssuerKey {
        issuer_key: "OPERATOR-KEY".to_string(),
        card_fingerprint: card::fingerprint(&card_v2).expect("fingerprint"),
    };
    let sight_v2 = Sighting::Seen(card::observation(&card_v2, Some(pin_v2)).expect("observation"));

    assert_eq!(approval.state(&sight_v2), TrustState::Quarantined);
    let drift = approval.drift(&sight_v2);
    assert!(
        drift.pin_changed,
        "the card fingerprint is half the identity"
    );
    assert_eq!(drift.changed, vec!["plan".to_string()]);
    assert_eq!(
        drift.added,
        Vec::<String>::new(),
        "an edit is not an addition"
    );

    let new_digest = card::skill_digests(&card_v2).expect("digests")["plan"].clone();
    assert!(
        !approval.serves("plan", &new_digest),
        "dispatch must refuse the digest that was never approved"
    );
    assert!(
        approval.serves("plan", &plan_digest),
        "the approval itself is untouched: it still names exactly what the operator approved"
    );
}

/// A card that stops offering an approved skill is drift too, on its own axis. An upstream that
/// quietly withdraws a capability is telling the operator something, and a machine that only watched
/// for CHANGED digests would not notice.
#[test]
fn a_withdrawn_skill_is_its_own_axis_of_drift() {
    let card_v1 = a_card();
    let pin = CardPin::JwsIssuerKey {
        issuer_key: "OPERATOR-KEY".to_string(),
        card_fingerprint: card::fingerprint(&card_v1).expect("fingerprint"),
    };
    let mut approval = Approval::registered();
    approve_registration(
        &mut approval,
        &Sighting::Seen(card::observation(&card_v1, Some(pin.clone())).expect("observation")),
        None,
    )
    .expect("approve");

    let mut card_v2 = a_card();
    card_v2["skills"].as_array_mut().expect("array").pop();
    let sight_v2 = Sighting::Seen(
        card::observation(
            &card_v2,
            Some(CardPin::JwsIssuerKey {
                issuer_key: "OPERATOR-KEY".to_string(),
                card_fingerprint: card::fingerprint(&card_v2).expect("fingerprint"),
            }),
        )
        .expect("observation"),
    );

    let drift = approval.drift(&sight_v2);
    assert_eq!(drift.removed, vec!["summarize".to_string()]);
    assert!(drift.changed.is_empty());
    assert_ne!(drift, Drift::default());
}

/// THE RATCHET, and the reason this file is more than three instantiations.
///
/// A2A reusing the lifecycle today does not stop the next change from quietly re-declaring a piece
/// of it here, and the moment this plane owns a second `TrustState` the two planes have two machines
/// that will disagree the first time one of them is fixed. So A2A's own production code is scanned
/// for the machine's vocabulary, and a violation is a failing test rather than a review comment
/// somebody has to remember to make.
///
/// PROSE is exempt, and must be: the doc comments in this plane explain the reuse by naming what is
/// reused, and that explanation is the most useful thing in the files.
#[test]
fn the_a2a_plane_declares_no_trust_state_of_its_own() {
    // Declarations that would mean this plane had FORKED the machine rather than parameterised it.
    // `TrustState::` and friends are not banned: USING the machine's vocabulary is the point.
    const BANNED: &[&str] = &[
        "enum TrustState",
        "enum Drift",
        "enum Sighting",
        "struct Observation",
        "struct Approval",
        "trait PinnedArtifact",
        "fn drift",
        "fn serves",
        "fn approve_pin",
        "fn approve_capability",
        "fn reject_capability",
        "fn suspend",
        "fn resume",
        "fn unpin",
        "fn state",
    ];
    for (path, source) in [
        ("a2a/mod.rs", include_str!("../mod.rs")),
        ("a2a/canonical.rs", include_str!("../canonical.rs")),
        ("a2a/card.rs", include_str!("../card.rs")),
        ("a2a/pin.rs", include_str!("../pin.rs")),
    ] {
        let code: String = source
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        for needle in BANNED {
            assert!(
                !code.contains(needle),
                "{path} declares `{needle}`. The trust lifecycle is plane-neutral and this plane \
                 PARAMETERISES it; a second declaration here is a fork, and two machines disagree \
                 the first time one of them is fixed. Add to the artifact, not to the machine."
            );
        }
    }
}
