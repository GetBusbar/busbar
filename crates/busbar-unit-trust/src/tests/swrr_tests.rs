// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The weighted floor.

use super::{cands, Lanes};
use crate::swrr::{select_weighted, SwrrState};

#[test]
fn test_zero_weight_member_is_never_selected() {
    let lanes = Lanes::default();
    let mut swrr = SwrrState::new();
    let c = cands(&[(0, 0), (1, 1)]);
    for _ in 0..20 {
        assert_eq!(
            select_weighted(&mut swrr, "p", &c, &lanes, &lanes, 1000),
            Some(1),
            "a drained lane must never be selected"
        );
    }
    // Every member drained: nothing is selectable.
    let all_drained = cands(&[(0, 0), (1, 0)]);
    assert_eq!(
        select_weighted(&mut swrr, "p", &all_drained, &lanes, &lanes, 1000),
        None,
        "an all-drained set selects nothing"
    );
}

#[test]
fn selection_is_proportional_to_the_weights() {
    let lanes = Lanes::default();
    let mut swrr = SwrrState::new();
    let c = cands(&[(0, 5), (1, 3), (2, 1), (3, 1)]);
    let mut counts = [0usize; 4];
    for _ in 0..1000 {
        let picked =
            select_weighted(&mut swrr, "p", &c, &lanes, &lanes, 1000).expect("all healthy");
        counts[picked] += 1;
    }
    assert_eq!(counts, [500, 300, 100, 100], "exactly proportional, no drift");
}

#[test]
fn the_credits_return_to_zero_after_a_full_cycle() {
    let lanes = Lanes::default();
    let mut swrr = SwrrState::new();
    let c = cands(&[(0, 2), (1, 1)]);
    for _ in 0..3 {
        let _ = select_weighted(&mut swrr, "p", &c, &lanes, &lanes, 1000);
    }
    assert_eq!(swrr.credit("p", 0) + swrr.credit("p", 1), 0);
}

#[test]
fn equal_weights_walk_in_configuration_order() {
    let lanes = Lanes::default();
    let mut swrr = SwrrState::new();
    let c = cands(&[(0, 1), (1, 1), (2, 1)]);
    let picks: Vec<usize> = (0..3)
        .map(|_| select_weighted(&mut swrr, "p", &c, &lanes, &lanes, 1000).expect("healthy"))
        .collect();
    assert_eq!(picks, vec![0, 1, 2]);
}

#[test]
fn an_excluded_lane_never_consumes_a_turn() {
    // Lane 0 is tripped, so it is filtered before the walk. The remaining lane takes every turn and
    // the tripped one accrues no credit at all.
    let lanes = Lanes::with(|l| {
        l.open_breaker.insert(0);
    });
    let mut swrr = SwrrState::new();
    let c = cands(&[(0, 9), (1, 1)]);
    for _ in 0..5 {
        assert_eq!(
            select_weighted(&mut swrr, "p", &c, &lanes, &lanes, 1000),
            Some(1)
        );
    }
    assert_eq!(
        swrr.credit("p", 0),
        0,
        "a filtered lane's credit never moves, so it does not surge on recovery"
    );
}

#[test]
fn two_pools_sharing_a_lane_keep_independent_credit() {
    let lanes = Lanes::default();
    let mut swrr = SwrrState::new();
    let c = cands(&[(0, 1), (1, 1)]);
    let _ = select_weighted(&mut swrr, "pool-a", &c, &lanes, &lanes, 1000);
    assert_eq!(swrr.credit("pool-b", 0), 0);
}

#[test]
fn a_reset_puts_a_rejoining_lane_back_level() {
    let lanes = Lanes::default();
    let mut swrr = SwrrState::new();
    let c = cands(&[(0, 1), (1, 1)]);
    let _ = select_weighted(&mut swrr, "p", &c, &lanes, &lanes, 1000);
    swrr.reset("p", 0);
    assert_eq!(swrr.credit("p", 0), 0);
}
