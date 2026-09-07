// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The two readings a caller takes off a leg's answer.
//!
//! `is_delivered` and `shed` are complements: exactly one of them is the affirmative on any given
//! outcome, and a caller that gated a settle on the first while relaying the second would be
//! settling a refusal as an answer. They are asserted here on both arms, which is the only way the
//! complement is provable at all.

use crate::wire::{Delivered, RouteOutcome, Shed};
use busbar_contract::DestinationId;

fn delivered() -> RouteOutcome {
    RouteOutcome::Delivered(Delivered {
        destination: DestinationId::new(0),
        pool: "primary".to_string(),
        status: None,
        frames: 2,
        finish: None,
        degraded: false,
        relayed_error: None,
    })
}

/// An answer that arrived is delivered and carries no refusal.
#[test]
fn a_delivered_leg_is_delivered_and_sheds_nothing() {
    let outcome = delivered();
    assert!(outcome.is_delivered());
    assert!(
        outcome.shed().is_none(),
        "an answer the client already has is not a refusal"
    );
}

/// A refusal is not delivered, whichever refusal it is. Asserted over every shed this unit can
/// produce, so no one of them can quietly read as an answer.
#[test]
fn no_refusal_this_unit_can_produce_reads_as_delivered() {
    let refusals = [
        Shed::overloaded(7),
        Shed::request_timeout(),
        Shed::empty_pool(),
        Shed::restrict_no_lane(),
        Shed::invalid_body(),
        Shed::internal(),
    ];
    for shed in refusals {
        let outcome = RouteOutcome::Refused(shed.clone());
        assert!(
            !outcome.is_delivered(),
            "{shed:?} is a refusal and must never read as an answer"
        );
        assert_eq!(
            outcome.shed(),
            Some(&shed),
            "a refusal must hand back the shed it carries"
        );
    }
}

/// The two readings are complements on every outcome: exactly one is affirmative.
#[test]
fn delivered_and_shed_are_complements() {
    for outcome in [delivered(), RouteOutcome::Refused(Shed::overloaded(2))] {
        assert_ne!(
            outcome.is_delivered(),
            outcome.shed().is_some(),
            "{outcome:?} must be an answer or a refusal, never both and never neither"
        );
    }
}
