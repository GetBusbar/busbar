// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The arity posture: exactly-one-or-refuse (carrying the ambiguous set) and choose-one-of-many.

use crate::trust::arity::{select, Arity, ArityRefusal, Selection};
use busbar_contract::caps::ReasonCode;

/// `ExactlyOne` over a single candidate resolves to it.
#[test]
fn exactly_one_resolves_the_lone_candidate() {
    assert_eq!(
        select(Arity::ExactlyOne, vec!["planner"]),
        Ok(Selection::One("planner"))
    );
}

/// `ExactlyOne` over several candidates refuses AMBIGUOUS, carrying the whole surviving set — the
/// "exactly-one-agent-or-refuse-503" decision. The candidates arrive in the order offered.
#[test]
fn exactly_one_over_several_is_ambiguous_and_carries_the_candidates() {
    assert_eq!(
        select(Arity::ExactlyOne, vec!["planner", "researcher", "writer"]),
        Err(ArityRefusal::Ambiguous {
            candidates: vec!["planner", "researcher", "writer"]
        })
    );
}

/// The empty set refuses `NoCandidate` under BOTH postures — a distinct fault from ambiguity.
#[test]
fn empty_is_no_candidate_under_either_posture() {
    let empty: Vec<&str> = Vec::new();
    assert_eq!(
        select(Arity::ExactlyOne, empty.clone()),
        Err(ArityRefusal::NoCandidate)
    );
    assert_eq!(
        select(Arity::ChooseOne, empty),
        Err(ArityRefusal::NoCandidate)
    );
}

/// `ChooseOne` hands on the whole non-empty set for the pick — even a single candidate, so the pick
/// path is one shape regardless of count.
#[test]
fn choose_one_hands_on_the_set() {
    assert_eq!(
        select(Arity::ChooseOne, vec!["a", "b"]),
        Ok(Selection::Choose(vec!["a", "b"]))
    );
    assert_eq!(
        select(Arity::ChooseOne, vec!["only"]),
        Ok(Selection::Choose(vec!["only"]))
    );
}

/// Both refusals record under the one closed-vocabulary reason for "no single destination"; the
/// none-versus-several distinction lives in the variant and the carried set, not a second word.
#[test]
fn both_refusals_reason_as_no_destination() {
    let none: ArityRefusal<&str> = ArityRefusal::NoCandidate;
    let ambiguous = ArityRefusal::Ambiguous {
        candidates: vec!["x", "y"],
    };
    assert_eq!(none.reason(), ReasonCode::NoDestination);
    assert_eq!(ambiguous.reason(), ReasonCode::NoDestination);
}

/// The seat is generic over the candidate type: a plane carries its own item through the resolve and
/// through the ambiguous refusal unchanged.
#[test]
fn candidate_type_is_the_planes_own() {
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct AgentRef(u32);
    assert_eq!(
        select(Arity::ExactlyOne, vec![AgentRef(7)]),
        Ok(Selection::One(AgentRef(7)))
    );
    assert_eq!(
        select(Arity::ExactlyOne, vec![AgentRef(1), AgentRef(2)]),
        Err(ArityRefusal::Ambiguous {
            candidates: vec![AgentRef(1), AgentRef(2)]
        })
    );
}
