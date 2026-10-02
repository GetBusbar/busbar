// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The counterparty-admit gate: the ordered identity → grant → artifact → generation walk.

use crate::trust::counterparty::{admit, CounterpartyFacts, CounterpartyRefusal};
use busbar_contract::caps::ReasonCode;

/// A counterparty that passes every check is admitted.
#[test]
fn an_admissible_counterparty_is_admitted() {
    assert_eq!(admit(&CounterpartyFacts::admissible()), Ok(()));
}

/// The gate refuses at the FIRST failing check, in its fixed order: a caller that is also ungranted,
/// facing an unapproved counterparty at a stale generation, is still refused `Unidentified` — the
/// coarsest check closes first and no later one is reached.
#[test]
fn the_first_failing_check_wins() {
    let all_bad = CounterpartyFacts {
        identified: false,
        granted: false,
        approved: false,
        current_generation: false,
    };
    assert_eq!(admit(&all_bad), Err(CounterpartyRefusal::Unidentified));
}

/// Each later check is only reached once every earlier one passes.
#[test]
fn each_check_is_reached_in_order() {
    let ungranted = CounterpartyFacts {
        granted: false,
        ..CounterpartyFacts::admissible()
    };
    assert_eq!(admit(&ungranted), Err(CounterpartyRefusal::Ungranted));

    let unapproved = CounterpartyFacts {
        approved: false,
        ..CounterpartyFacts::admissible()
    };
    assert_eq!(admit(&unapproved), Err(CounterpartyRefusal::NotApproved));

    let stale = CounterpartyFacts {
        current_generation: false,
        ..CounterpartyFacts::admissible()
    };
    assert_eq!(admit(&stale), Err(CounterpartyRefusal::StaleGeneration));
}

/// Each refusal records under its own closed-vocabulary reason, so a counterparty refusal is the
/// same word as the equivalent stop elsewhere in the loop.
#[test]
fn each_refusal_maps_to_its_reason_code() {
    assert_eq!(
        CounterpartyRefusal::Unidentified.reason(),
        ReasonCode::Unauthenticated
    );
    assert_eq!(
        CounterpartyRefusal::Ungranted.reason(),
        ReasonCode::ScopeDenied
    );
    assert_eq!(
        CounterpartyRefusal::NotApproved.reason(),
        ReasonCode::NoDestination
    );
    assert_eq!(
        CounterpartyRefusal::StaleGeneration.reason(),
        ReasonCode::Superseded
    );
}
