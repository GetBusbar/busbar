// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The pick: affinity, the ranked walk, the reconcile, and above all WHERE each exclusion happens.

use super::{cands, Lanes};
use crate::lane::{LaneCandidate, Unavailable};
use crate::order::{
    pick, reconcile_order, sticky_position, OrderVerdict, OrderingHook, Pick, PickOutcome,
};
use crate::swrr::SwrrState;
use std::collections::HashSet;

/// A hook with a canned answer, so a test states the chain it means and nothing else.
struct Canned {
    name: &'static str,
    priority: u16,
    verdict: OrderVerdict,
}

impl OrderingHook for Canned {
    fn name(&self) -> &'static str {
        self.name
    }
    fn priority(&self) -> u16 {
        self.priority
    }
    fn order(&self, _candidates: &[LaneCandidate]) -> OrderVerdict {
        self.verdict.clone()
    }
}

fn no_exclusions() -> HashSet<usize> {
    HashSet::new()
}

#[allow(clippy::too_many_arguments)]
fn pick_with(
    lanes: &Lanes,
    candidates: &[LaneCandidate],
    order: Option<&[usize]>,
    affinity: Option<u64>,
    excluded: &HashSet<usize>,
) -> (PickOutcome, Vec<(usize, Unavailable)>) {
    let mut swrr = SwrrState::new();
    let mut passed_over = Vec::new();
    let outcome = pick(
        "p",
        candidates,
        lanes,
        lanes,
        &mut swrr,
        order,
        affinity,
        excluded,
        &mut passed_over,
        1000,
        false,
    );
    (outcome, passed_over)
}

// ── session affinity ────────────────────────────────────────────────────────────────────────────

#[test]
fn sticky_affinity_never_selects_zero_weight_drained_member() {
    let lanes = Lanes::default();
    // One candidate, fully drained. The affinity hash lands on it — the only position there is — so
    // the affinity path is exercised ON the drained lane. It is skipped, and the floor (which also
    // excludes a zero weight) finds nothing.
    let drained_only = cands(&[(0, 0)]);
    let (outcome, _) = pick_with(&lanes, &drained_only, None, Some(12345), &no_exclusions());
    assert_eq!(
        outcome,
        PickOutcome::NoneAdmissible,
        "a drained member must never be stickily selected"
    );
    assert!(
        lanes.admissions.borrow().is_empty(),
        "and it must not even be offered to the admission"
    );

    // Realistic drain: lane 0 drained, lane 1 healthy. For EVERY affinity key the answer is lane 1.
    let drained_and_healthy = cands(&[(0, 0), (1, 1)]);
    for key in [1u64, 2, 3, 41, 42, 99, 100, 12345] {
        let lanes = Lanes::default();
        let (outcome, _) = pick_with(
            &lanes,
            &drained_and_healthy,
            None,
            Some(key),
            &no_exclusions(),
        );
        assert_eq!(
            outcome,
            PickOutcome::Admitted(Pick {
                lane: 1,
                position: 1
            }),
            "key {key} must route to the healthy lane, never the drained one"
        );
    }
}

#[test]
fn the_affinity_position_is_the_hash_over_the_candidate_count() {
    let c = cands(&[(10, 1), (11, 1), (12, 1)]);
    assert_eq!(sticky_position(&c, Some(7), &no_exclusions()), Some(1));
    assert_eq!(sticky_position(&c, Some(9), &no_exclusions()), Some(0));
    assert_eq!(sticky_position(&c, None, &no_exclusions()), None);
    // A lane this request already tried is not pinned to.
    let mut tried = HashSet::new();
    tried.insert(11usize);
    assert_eq!(sticky_position(&c, Some(7), &tried), None);
}

#[test]
fn the_affinity_offer_comes_first_and_exactly_once() {
    let lanes = Lanes::with(|l| {
        l.at_capacity.insert(1);
    });
    // The hash pins position 1, which is at capacity. It is offered FIRST, refused, and the pick
    // falls through to the floor.
    let c = cands(&[(0, 1), (1, 1)]);
    let (outcome, passed) = pick_with(&lanes, &c, None, Some(3), &no_exclusions());
    assert_eq!(lanes.admissions.borrow()[0], 1, "the pinned lane is asked first");
    assert_eq!(
        outcome,
        PickOutcome::Admitted(Pick {
            lane: 0,
            position: 0
        })
    );
    assert!(passed.iter().any(|(_, why)| *why == Unavailable::AtCapacity));
}

#[test]
fn a_refused_affinity_offer_is_not_locally_excluded() {
    // The pinned lane is the ONLY one, and it is at capacity. Because a refused affinity offer is
    // deliberately not excluded, the floor may pick it again — so the admission sees it twice, and
    // the recorded reason is doubled. Anything reading those reasons expects that.
    let lanes = Lanes::with(|l| {
        l.at_capacity.insert(0);
    });
    let c = cands(&[(0, 1)]);
    let (outcome, passed) = pick_with(&lanes, &c, None, Some(0), &no_exclusions());
    assert_eq!(outcome, PickOutcome::NoneAdmissible);
    assert_eq!(
        *lanes.admissions.borrow(),
        vec![0, 0],
        "the pinned lane is attempted a second time through the floor"
    );
    assert_eq!(passed.len(), 2, "and the at-capacity reason is doubled");
}

// ── where the exclusions happen ─────────────────────────────────────────────────────────────────

#[test]
fn a_dead_or_exhausted_or_tripped_lane_never_reaches_the_admission() {
    for (label, lanes) in [
        (
            "dead",
            Lanes::with(|l| {
                l.dead.insert(0);
            }),
        ),
        (
            "budget exhausted",
            Lanes::with(|l| {
                l.exhausted.insert(0);
            }),
        ),
        (
            "breaker open",
            Lanes::with(|l| {
                l.open_breaker.insert(0);
            }),
        ),
    ] {
        let c = cands(&[(0, 1), (1, 1)]);
        let (outcome, _) = pick_with(&lanes, &c, None, None, &no_exclusions());
        assert_eq!(
            outcome,
            PickOutcome::Admitted(Pick {
                lane: 1,
                position: 1
            }),
            "{label}: the healthy lane serves"
        );
        assert!(
            !lanes.admissions.borrow().contains(&0),
            "{label}: the excluded lane must be filtered BEFORE the walk, never ordered last and \
             attempted"
        );
    }
}

#[test]
fn only_an_at_capacity_lane_consumes_a_turn() {
    // Lane 0 is at capacity: it passes the pre-walk filter, is selected, and only then refuses — so
    // it does consume an admission. Lane 1 serves.
    let lanes = Lanes::with(|l| {
        l.at_capacity.insert(0);
    });
    let c = cands(&[(0, 5), (1, 1)]);
    let (outcome, passed) = pick_with(&lanes, &c, None, None, &no_exclusions());
    assert_eq!(
        lanes.admissions.borrow()[0],
        0,
        "the at-capacity lane reaches the admission after selection"
    );
    assert_eq!(passed, vec![(0, Unavailable::AtCapacity)]);
    assert_eq!(
        outcome,
        PickOutcome::Admitted(Pick {
            lane: 1,
            position: 1
        })
    );
}

#[test]
fn an_all_excluded_pool_admits_nothing_and_records_why() {
    let lanes = Lanes::with(|l| {
        l.open_breaker.insert(0);
        l.exhausted.insert(1);
    });
    let c = cands(&[(0, 1), (1, 1)]);
    let (outcome, _) = pick_with(&lanes, &c, None, None, &no_exclusions());
    assert_eq!(outcome, PickOutcome::NoneAdmissible);
    assert!(
        lanes.admissions.borrow().is_empty(),
        "every lane was excluded before the walk"
    );
}

#[test]
fn a_cross_hop_exclusion_is_honoured() {
    let lanes = Lanes::default();
    let mut excluded = HashSet::new();
    excluded.insert(0usize);
    let c = cands(&[(0, 1), (1, 1)]);
    let (outcome, _) = pick_with(&lanes, &c, None, None, &excluded);
    assert_eq!(
        outcome,
        PickOutcome::Admitted(Pick {
            lane: 1,
            position: 1
        })
    );
    assert!(!lanes.admissions.borrow().contains(&0));
}

#[test]
fn a_passed_deadline_selects_nothing() {
    let lanes = Lanes::default();
    let c = cands(&[(0, 1), (1, 1)]);
    let mut swrr = SwrrState::new();
    let mut passed_over = Vec::new();
    let outcome = pick(
        "p",
        &c,
        &lanes,
        &lanes,
        &mut swrr,
        None,
        None,
        &no_exclusions(),
        &mut passed_over,
        1000,
        true,
    );
    assert_eq!(outcome, PickOutcome::NoneAdmissible);
    assert!(lanes.admissions.borrow().is_empty());
}

// ── the ranked walk ─────────────────────────────────────────────────────────────────────────────

#[test]
fn ordered_walk_picks_first_preferred_when_healthy() {
    let lanes = Lanes::default();
    let c = cands(&[(0, 1), (1, 1), (2, 1)]);
    let (outcome, _) = pick_with(&lanes, &c, Some(&[2, 0, 1]), None, &no_exclusions());
    assert_eq!(
        outcome,
        PickOutcome::Admitted(Pick {
            lane: 2,
            position: 2
        }),
        "the top-ranked healthy lane is chosen"
    );
}

#[test]
fn ordered_walk_skips_an_unhealthy_preferred_lane() {
    let lanes = Lanes::with(|l| {
        l.open_breaker.insert(2);
    });
    let c = cands(&[(0, 1), (1, 1), (2, 1)]);
    let (outcome, _) = pick_with(&lanes, &c, Some(&[2, 0, 1]), None, &no_exclusions());
    assert_eq!(
        outcome,
        PickOutcome::Admitted(Pick {
            lane: 0,
            position: 0
        })
    );
    assert!(!lanes.admissions.borrow().contains(&2));
}

#[test]
fn ordered_walk_never_yields_a_drained_lane() {
    // The readiness peek does not look at weight, so without the drain check here a ranked ordering
    // could put a drained lane first and yield it.
    let lanes = Lanes::default();
    let c = cands(&[(0, 0), (1, 1)]);
    let (outcome, _) = pick_with(&lanes, &c, Some(&[0, 1]), None, &no_exclusions());
    assert_eq!(
        outcome,
        PickOutcome::Admitted(Pick {
            lane: 1,
            position: 1
        })
    );
}

#[test]
fn an_unranked_but_healthy_lane_is_reachable_rather_than_stranded() {
    // The ordering ranks only lane 0, which is tripped. The pick falls through to the floor over the
    // same set, which reaches the unranked lane 1.
    let lanes = Lanes::with(|l| {
        l.open_breaker.insert(0);
    });
    let c = cands(&[(0, 1), (1, 1)]);
    let (outcome, _) = pick_with(&lanes, &c, Some(&[0]), None, &no_exclusions());
    assert_eq!(
        outcome,
        PickOutcome::Admitted(Pick {
            lane: 1,
            position: 1
        })
    );
}

// ── the reconcile ───────────────────────────────────────────────────────────────────────────────

#[test]
fn order_last_in_chain_wins() {
    let first = Canned {
        name: "first",
        priority: 0,
        verdict: OrderVerdict::Order(vec![0, 1]),
    };
    let second = Canned {
        name: "second",
        priority: 1,
        verdict: OrderVerdict::Order(vec![1, 0]),
    };
    let c = cands(&[(0, 1), (1, 1)]);
    let hooks: Vec<&dyn OrderingHook> = vec![&first, &second];
    let (order, name) = reconcile_order(&hooks, &c).expect("a hook ordered");
    assert_eq!(order, vec![1, 0], "the LAST ordering in the chain wins");
    assert_eq!(name, "second");

    // And the winner is the one that actually serves.
    let lanes = Lanes::default();
    let (outcome, _) = pick_with(&lanes, &c, Some(&order), None, &no_exclusions());
    assert_eq!(
        outcome,
        PickOutcome::Admitted(Pick {
            lane: 1,
            position: 1
        })
    );
}

#[test]
fn stale_order_filtered_against_post_restrict_set() {
    // An ordering captured before a concurrent restriction names ONLY a member that restriction
    // removed. Filtered against the surviving set it is empty, so it abstains and the request
    // proceeds on the survivors — never a strand, never a resurrected excluded member.
    let orderer = Canned {
        name: "orderer",
        priority: 0,
        verdict: OrderVerdict::Order(vec![0]),
    };
    // The surviving set after the restriction: lane 1 only.
    let surviving = cands(&[(1, 1)]);
    let hooks: Vec<&dyn OrderingHook> = vec![&orderer];
    assert!(
        reconcile_order(&hooks, &surviving).is_none(),
        "an ordering naming only restricted-out members abstains"
    );

    let lanes = Lanes::default();
    let (outcome, _) = pick_with(&lanes, &surviving, None, None, &no_exclusions());
    assert_eq!(
        outcome,
        PickOutcome::Admitted(Pick {
            lane: 1,
            position: 0
        }),
        "the survivor serves"
    );
}

#[test]
fn last_order_gate_filtered_to_empty_abstains_to_base_not_to_a_lower_gate() {
    // The low-priority hook orders a surviving lane; the high-priority one orders a lane the
    // restriction removed. The high one outranks it and abstains — and abstaining falls through to
    // the pool's BASE ordering, not back to the low one's answer.
    let low = Canned {
        name: "low",
        priority: 0,
        verdict: OrderVerdict::Order(vec![1]),
    };
    let high = Canned {
        name: "high",
        priority: 1,
        verdict: OrderVerdict::Order(vec![2]),
    };
    let surviving = cands(&[(0, 1), (1, 1)]);
    let hooks: Vec<&dyn OrderingHook> = vec![&low, &high];
    assert!(
        reconcile_order(&hooks, &surviving).is_none(),
        "the winner abstained, so no lower-priority order is left standing"
    );

    // The base ordering then serves the first healthy candidate.
    let lanes = Lanes::default();
    let (outcome, _) = pick_with(&lanes, &surviving, None, None, &no_exclusions());
    assert_eq!(
        outcome,
        PickOutcome::Admitted(Pick {
            lane: 0,
            position: 0
        })
    );
}

#[test]
fn ties_keep_their_source_order() {
    // Two hooks at the same priority: the later one in the source list is the later one in the
    // chain, so it wins.
    let a = Canned {
        name: "a",
        priority: 7,
        verdict: OrderVerdict::Order(vec![0]),
    };
    let b = Canned {
        name: "b",
        priority: 7,
        verdict: OrderVerdict::Order(vec![1]),
    };
    let c = cands(&[(0, 1), (1, 1)]);
    let hooks: Vec<&dyn OrderingHook> = vec![&a, &b];
    let (order, name) = reconcile_order(&hooks, &c).expect("ordered");
    assert_eq!(order, vec![1]);
    assert_eq!(name, "b");
}

#[test]
fn an_abstaining_chain_leaves_the_base_ordering_alone() {
    let a = Canned {
        name: "a",
        priority: 0,
        verdict: OrderVerdict::Abstain,
    };
    let c = cands(&[(0, 1), (1, 1)]);
    let hooks: Vec<&dyn OrderingHook> = vec![&a];
    assert!(reconcile_order(&hooks, &c).is_none());
}

#[test]
fn every_ordering_native_declares_that_it_may_change_the_destination() {
    let a = Canned {
        name: "a",
        priority: 0,
        verdict: OrderVerdict::Abstain,
    };
    assert!(
        a.may_change_destination(),
        "an ordering hook changes which destination is selected, and says so"
    );
}
