// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The A2A identity pin, and the one A2A rule that is NOT in the plane-neutral machine.

use super::*;
use crate::trust::{Observation, TrustState};
use std::collections::BTreeMap;

fn caps() -> BTreeMap<String, String> {
    BTreeMap::from([("plan".to_string(), "sha256/PLAN".to_string())])
}

fn seen(pin: CardPin) -> Sighting<CardPin> {
    Sighting::Seen(Observation {
        pin: Some(pin),
        capabilities: caps(),
    })
}

fn signed(key: &str, fp: &str) -> CardPin {
    CardPin::JwsIssuerKey {
        issuer_key: key.to_string(),
        card_fingerprint: fp.to_string(),
    }
}

/// The MECHANISM is part of the value, not a field beside it. A registration therefore cannot claim
/// one root while carrying another, and a transport pin can never compare equal to a signature pin
/// that happens to quote the same fingerprint.
#[test]
fn the_mechanism_is_part_of_the_identity_not_a_label_beside_it() {
    let jws = signed("KEY", "sha256/FP");
    let spki = CardPin::CertSpki {
        spki: "KEY".to_string(),
        card_fingerprint: "sha256/FP".to_string(),
    };
    assert_ne!(jws, spki);
    assert_ne!(jws.mechanism(), spki.mechanism());
    assert_ne!(jws.digest(), spki.digest());
    assert_eq!(jws.card_fingerprint(), spki.card_fingerprint());
}

/// A signed pin is TWO values and drift in either half is drift. The two halves are two different
/// attacks: a card re-signed under a different key is the look-alike, and a new card under the right
/// key is the rug-pull. A single-value pin could not tell an operator which one happened.
#[test]
fn either_half_of_a_signed_pin_is_identity_drift() {
    let mut approval = Approval::registered();
    approve_registration(&mut approval, &seen(signed("KEY-1", "sha256/FP-1")), None)
        .expect("approve");

    assert!(
        approval
            .drift(&seen(signed("KEY-2", "sha256/FP-1")))
            .pin_changed,
        "a different issuer key is drift"
    );
    assert!(
        approval
            .drift(&seen(signed("KEY-1", "sha256/FP-2")))
            .pin_changed,
        "a different card under the same key is drift"
    );
    assert!(
        !approval
            .drift(&seen(signed("KEY-1", "sha256/FP-1")))
            .pin_changed
    );
}

/// The rendering names every part the equality compares. An audit row that said only "the pin
/// changed" would not tell an operator whether they are looking at a scheduled key rotation or an
/// impostor, and those two get opposite responses.
#[test]
fn the_rendering_names_every_part_the_equality_compares() {
    let base = signed("KEY-1", "sha256/FP-1");
    let rotated_key = signed("KEY-2", "sha256/FP-1");
    let rotated_card = signed("KEY-1", "sha256/FP-2");
    assert_ne!(base.digest(), rotated_key.digest());
    assert_ne!(base.digest(), rotated_card.digest());
    assert_ne!(rotated_key.digest(), rotated_card.digest());
    assert!(base.digest().contains("jws_issuer_key"));
    assert_eq!(CardPin::Unpinned.digest(), "unpinned");
}

/// THE A2A CAP, and it is the reason this plane has an `approve` of its own at all. An unpinned
/// registration has no authenticity root, so locking it would produce a record that "matches" every
/// later observation. It stays capturable and inspectable, and it is never delegable.
#[test]
fn an_unpinned_registration_is_capturable_and_never_approvable() {
    let sighting = seen(CardPin::Unpinned);
    let mut approval = Approval::registered();

    // Captured: the state machine sees it and reports it as pending, which is what an operator
    // inspecting a candidate needs.
    assert_eq!(approval.state(&sighting), TrustState::Pending);

    assert_eq!(
        approve_registration(&mut approval, &sighting, None),
        Err(ApproveError::Unpinned)
    );
    assert_eq!(
        approval.state(&sighting),
        TrustState::Pending,
        "a refused approval must leave nothing behind"
    );
    assert!(!approval.serves("plan", "sha256/PLAN"));
    assert!(!CardPin::Unpinned.is_a_root());
    assert_eq!(CardPin::Unpinned.card_fingerprint(), None);
}

/// The cap is checked on the pin that would actually be LOCKED, not on the one that was observed.
/// Checking the observation alone would let an unpinned override sail past a check aimed at the
/// endpoint, and an operator-supplied value is exactly where an `unpinned` default would come from.
#[test]
fn an_unpinned_override_cannot_launder_a_pinned_observation() {
    let mut approval = Approval::registered();
    assert_eq!(
        approve_registration(
            &mut approval,
            &seen(signed("KEY-1", "sha256/FP-1")),
            Some(CardPin::Unpinned)
        ),
        Err(ApproveError::Unpinned)
    );
    assert_eq!(approval.pin(), None);
}

/// The operator's out-of-band value WINS over whatever the endpoint presented. That is the whole
/// difference between an authenticity root and trust-on-first-use with a human in it.
#[test]
fn the_operator_override_wins_over_the_presented_identity() {
    let mut approval = Approval::registered();
    let operator_key = signed("OPERATOR-KEY", "sha256/FP-1");
    approve_registration(
        &mut approval,
        &seen(signed("KEY-THE-ENDPOINT-CLAIMED", "sha256/FP-1")),
        Some(operator_key.clone()),
    )
    .expect("approve");
    assert_eq!(approval.pin(), Some(&operator_key));
    // And the endpoint's own claim is now drift, which is precisely the look-alike being caught.
    assert!(
        approval
            .drift(&seen(signed("KEY-THE-ENDPOINT-CLAIMED", "sha256/FP-1")))
            .pin_changed
    );
}

/// A registration with nothing to lock is refused by the plane-neutral machine, and that refusal
/// passes through this plane unchanged rather than being re-spelled.
#[test]
fn nothing_to_lock_is_still_the_plane_neutral_refusal() {
    let mut approval = Approval::registered();
    assert_eq!(
        approve_registration(&mut approval, &Sighting::Never, None),
        Err(ApproveError::Trust(TrustError::NoPinToLock))
    );
    assert!(format!("{}", ApproveError::Unpinned).contains("unpinned"));
}

/// A transport-pinned registration approves normally: an unsigned card is a DEGRADED root, not an
/// absent one, and the design's distinction between the two is only real if the code keeps it.
#[test]
fn a_transport_pinned_registration_approves_like_any_other() {
    for pin in [
        CardPin::CertSpki {
            spki: "sha256/SPKI".to_string(),
            card_fingerprint: "sha256/FP".to_string(),
        },
        CardPin::Mtls {
            spki: "sha256/SPKI".to_string(),
            card_fingerprint: "sha256/FP".to_string(),
        },
    ] {
        let mut approval = Approval::registered();
        approve_registration(&mut approval, &seen(pin.clone()), None).expect("approve");
        assert_eq!(approval.state(&seen(pin)), TrustState::Approved);
        assert!(approval.serves("plan", "sha256/PLAN"));
    }
}
