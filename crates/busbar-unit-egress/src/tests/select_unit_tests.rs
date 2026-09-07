// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The pick's own parts, each asserted where it decides something.
//!
//! What is here is the request context's two readings of what is left of the deadline, the probe
//! guard's arm state, the rotation memory the unit hands out, and the one place the affinity fast
//! path is allowed to offer a member the rest of the pick will offer again. Each of the four is a
//! value some other path reads and none of them is otherwise stated: a deadline reading that
//! answered a constant, or a guard that always reported itself disarmed, would leave every walk
//! test still passing.

use super::harness::{Health, TestBreaker};
use super::{member, Node};
use crate::ports::DestinationId;
use crate::select::{ProbeGuard, RequestCtx, WeightedFloor};
use crate::EgressUnit;

// ── what is left of the walk's deadline ─────────────────────────────────────────────────────────

/// The seconds reading is the distance to the deadline, and it is that at more than one instant —
/// a reading that answered a constant would agree with any one of these and none of the rest.
#[test]
fn the_seconds_left_are_the_distance_to_the_deadline() {
    let ctx = RequestCtx::new(30, 1_000, 1_000_000);
    assert_eq!(ctx.remaining_secs(1_000), 30);
    assert_eq!(ctx.remaining_secs(1_010), 20);
    assert_eq!(ctx.remaining_secs(1_029), 1);
}

/// At and past the deadline the seconds left are zero and the walk is expired — the pair the order
/// re-selects on, so they are asserted at the exact edge rather than either side of it.
#[test]
fn the_deadline_edge_is_exact() {
    let ctx = RequestCtx::new(30, 1_000, 1_000_000);
    assert!(!ctx.expired(1_029), "one second short of the deadline");
    assert_eq!(ctx.remaining_secs(1_029), 1);
    assert!(ctx.expired(1_030), "the deadline instant is already past");
    assert_eq!(ctx.remaining_secs(1_030), 0);
    assert!(ctx.expired(1_031));
    assert_eq!(ctx.remaining_secs(1_031), 0, "and it never goes negative");
}

/// The millisecond reading is the same distance at sub-second precision — the one the bounded wait
/// is written against, where a budget near a second boundary must not collapse to zero.
#[test]
fn the_milliseconds_left_are_the_same_distance_at_finer_grain() {
    let ctx = RequestCtx::new(30, 1_000, 1_000_000);
    assert_eq!(ctx.remaining_ms(1_000_000), 30_000);
    assert_eq!(ctx.remaining_ms(1_029_750), 250);
    assert_eq!(ctx.remaining_ms(1_029_999), 1);
    assert_eq!(ctx.remaining_ms(1_030_000), 0);
    assert_eq!(ctx.remaining_ms(1_030_500), 0, "and it never goes negative");
}

/// A deadline further out than a `u64` of milliseconds can express saturates rather than wrapping:
/// the answer is the largest wait, never a short one.
#[test]
fn a_deadline_beyond_the_millisecond_range_saturates_upward() {
    let ctx = RequestCtx::new(u64::MAX, 0, 0);
    assert_eq!(ctx.remaining_ms(0), u64::MAX);
}

// ── the probe guard's arm state ─────────────────────────────────────────────────────────────────

/// A fresh guard is armed; both ways of handing the probe on disarm it. The state is what decides
/// whether `drop` gives a probe back, so each transition is asserted directly AND against what the
/// breaker was actually told on drop.
#[test]
fn a_guard_is_armed_until_the_probe_is_handed_on() {
    let breaker = TestBreaker::new();
    let destination = DestinationId::new(0);

    // Armed on arrival, and a dropped armed guard gives the probe back.
    {
        let guard = ProbeGuard::new(&breaker, "primary", destination, 7, 1_000);
        assert!(guard.is_armed(), "a fresh guard still owes a release");
    }
    assert_eq!(
        breaker.probe_releases(),
        vec![("primary".to_string(), destination, 7)],
        "an armed guard that is dropped releases the probe it owns"
    );

    // Disarmed by hand: nothing further is released.
    {
        let mut guard = ProbeGuard::new(&breaker, "primary", destination, 8, 1_000);
        guard.disarm();
        assert!(!guard.is_armed(), "a disarmed guard owes nothing");
    }
    assert_eq!(
        breaker.probe_releases().len(),
        1,
        "a disarmed guard releases nothing on drop"
    );

    // Handing the epoch on disarms too, and yields the epoch it was won at.
    {
        let mut guard = ProbeGuard::new(&breaker, "primary", destination, 9, 1_000);
        assert!(guard.is_armed());
        assert_eq!(guard.take_epoch(), 9);
        assert!(
            !guard.is_armed(),
            "exactly one guard is live per win, so taking the epoch disarms this one"
        );
    }
    assert_eq!(
        breaker.probe_releases().len(),
        1,
        "a guard whose epoch was taken releases nothing on drop"
    );
}

// ── the rotation memory the unit hands out ──────────────────────────────────────────────────────

/// The floor a caller is handed is the unit's OWN memory, not a fresh one per call. A rotation is
/// smooth only if the credits survive between hops, so a `floor()` that answered with a new floor
/// each time would silently restart the rotation on every request.
#[test]
fn the_unit_hands_out_its_own_rotation_memory_and_not_a_fresh_one() {
    let unit = EgressUnit::new();
    assert_eq!(unit.floor().tracked(), (0, 0), "a new unit has no history");

    let offered = [(DestinationId::new(0), 1_u32), (DestinationId::new(1), 1)];
    let first = unit
        .floor()
        .take_turn("primary", &offered)
        .expect("a turn was taken");

    assert_eq!(
        unit.floor().tracked(),
        (1, 2),
        "the turn just taken must be visible through the very next call to floor()"
    );

    // And the rotation actually rotates, which it can only do if it is reading the same credits.
    let second = unit
        .floor()
        .take_turn("primary", &offered)
        .expect("a second turn was taken");
    assert_ne!(
        first, second,
        "two equally-weighted members alternate; a restarted rotation would repeat the first"
    );
}

/// The same assertion made against a floor the caller owns, so the property is the floor's and not
/// the unit's wrapper.
#[test]
fn a_floor_alternates_between_two_equal_members() {
    let floor = WeightedFloor::new();
    let offered = [(DestinationId::new(0), 1_u32), (DestinationId::new(1), 1)];
    let taken: Vec<DestinationId> = (0..4)
        .map(|_| {
            floor
                .take_turn("primary", &offered)
                .expect("a turn was taken")
        })
        .collect();
    assert_eq!(
        taken,
        vec![
            DestinationId::new(0),
            DestinationId::new(1),
            DestinationId::new(0),
            DestinationId::new(1),
        ]
    );
}

// ── the one member the pick may offer twice ─────────────────────────────────────────────────────

/// The affinity fast path is a preference, not a turn. A member offered by affinity and refused is
/// deliberately NOT struck off this pick: it falls through to the weighted floor, which may
/// legitimately offer it again. Locally excluding it there would cost the pool its only member on
/// the very hop the wait terminal is written to handle.
#[test]
fn an_affinity_member_that_is_refused_is_still_reachable_by_the_floor() {
    let mut node = Node::with_lanes(&["a"]);
    node.affinity = Some(0);
    let members = vec![member(DestinationId::new(0), "a")];
    // The one member is healthy but has no free slot: at capacity is the one reason the walk
    // records and the wait terminal can cure.
    node.capacity.set_ceiling(DestinationId::new(0), 1);
    let held = node.capacity.saturate(DestinationId::new(0));

    let mut ctx = node.request_ctx();
    let picked = node.pick("primary", &members, &mut ctx);
    assert!(picked.is_none(), "there was no free slot to pick");

    let reasons = ctx.excluded_reasons();
    assert_eq!(
        reasons.len(),
        2,
        "the affinity offer and the floor's offer are two attempts on the same member: {reasons:?}"
    );
    assert!(
        reasons.iter().all(|(d, _)| *d == DestinationId::new(0)),
        "both attempts are the same member: {reasons:?}"
    );
    drop(held);
}

/// The complement: with no affinity in play, a refused member IS struck off and offered once only.
/// This is what makes the grace above a property of the affinity path rather than of every refusal.
#[test]
fn a_member_refused_without_affinity_is_offered_once() {
    let mut node = Node::with_lanes(&["a"]);
    node.affinity = None;
    let members = vec![member(DestinationId::new(0), "a")];
    node.capacity.set_ceiling(DestinationId::new(0), 1);
    let held = node.capacity.saturate(DestinationId::new(0));

    let mut ctx = node.request_ctx();
    assert!(node.pick("primary", &members, &mut ctx).is_none());
    assert_eq!(
        ctx.excluded_reasons().len(),
        1,
        "without affinity the member gets exactly one turn: {:?}",
        ctx.excluded_reasons()
    );
    drop(held);
}

/// Affinity is a preference and never a constraint: a member the request has already tried is
/// skipped by the fast path rather than offered again, and that skip is not an exclusion reason.
#[test]
fn affinity_skips_a_member_this_request_has_already_tried() {
    let mut node = Node::with_lanes(&["a", "b"]);
    node.affinity = Some(0);
    node.breaker.set(DestinationId::new(1), Health::default());
    let members = vec![
        member(DestinationId::new(0), "a"),
        member(DestinationId::new(1), "b"),
    ];

    let mut ctx = node.request_ctx();
    ctx.exclude(DestinationId::new(0));
    let picked = node
        .pick("primary", &members, &mut ctx)
        .expect("the sibling took it");
    assert_eq!(picked.destination, DestinationId::new(1));
    assert!(
        ctx.excluded_reasons().is_empty(),
        "an already-tried member is selection policy, not an availability reason: {:?}",
        ctx.excluded_reasons()
    );
}

/// A drained member is skipped by the fast path for the same reason, and by the health filter after
/// it — no path may select a member the operator is bleeding off.
#[test]
fn affinity_never_selects_a_drained_member() {
    let mut node = Node::with_lanes(&["a", "b"]);
    node.affinity = Some(0);
    let mut members = vec![
        member(DestinationId::new(0), "a"),
        member(DestinationId::new(1), "b"),
    ];
    members[0].weight = 0;

    let mut ctx = node.request_ctx();
    let picked = node
        .pick("primary", &members, &mut ctx)
        .expect("the sibling took it");
    assert_eq!(picked.destination, DestinationId::new(1));
}
