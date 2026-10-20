// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The four terminals, and the words each of them says.
//!
//! Carried over from the previous release's on-exhausted tests. Every literal asserted here — the
//! status, the kind, the detail, the wait — is the one that shipped, and each is compared against
//! the constant rather than a retyped copy of it, so a reworded constant fails the test that reads
//! it rather than passing a test that repeats the same mistake. Each is the walk's own answer
//! ([`super::Walker`]); the cases that dispatch also run through the far end where what they
//! claim is about the member that served.

use super::harness::{ok_frames, Health, Script};
use super::{member, Node, Routed};
use busbar_contract::DestinationId;
use busbar_kernel_egress::exhaustion::AT_CAPACITY_RETRY_AFTER_SECS;
use busbar_kernel_egress::pool::OnExhausted;
use busbar_kernel_egress::ports::Clock;
use busbar_kernel_egress::wire::{DETAIL_OVERLOADED, KIND_OVERLOADED, STATUS_SERVICE_UNAVAILABLE};

/// A pool of `n` members whose every member is suppressed, so the walk finds nowhere to send.
fn exhausted_pool(n: usize, cooldowns: &[u64]) -> Node {
    let lanes: Vec<&'static str> = ["a", "b", "c", "d"][..n].to_vec();
    let mut node = Node::with_lanes(&lanes);
    node.pool(
        "primary",
        (0..n)
            .map(|d| member(DestinationId::new(d as u64), ["a", "b", "c", "d"][d]))
            .collect(),
    );
    for (d, cooldown) in cooldowns.iter().enumerate() {
        node.breaker.set(
            DestinationId::new(d as u64),
            Health {
                cooldown: *cooldown,
                ..Health::default()
            },
        );
    }
    node
}

#[test]
fn the_default_terminal_is_the_shed_and_it_says_the_words_that_shipped() {
    let node = exhausted_pool(2, &[30, 45]);
    let shed = node.walker("primary").shed();
    assert_eq!(shed.status, STATUS_SERVICE_UNAVAILABLE);
    assert_eq!(shed.kind, KIND_OVERLOADED);
    assert_eq!(shed.detail, DETAIL_OVERLOADED);
    assert!(!shed.gate_rejected);
}

#[test]
fn the_shed_advertises_the_soonest_genuine_cooldown() {
    let node = exhausted_pool(3, &[90, 30, 60]);
    assert_eq!(
        node.walker("primary").shed().retry_after_secs,
        Some(30),
        "the client should come back when the first benched member is due to be probed"
    );
}

#[test]
fn a_member_that_is_merely_busy_does_not_mask_a_sibling_in_a_long_cooldown() {
    let mut node = exhausted_pool(2, &[600, 0]);
    // The second member reports no cooldown because it is at capacity, not benched. Its zero must
    // not become the minimum.
    node.capacity.set_ceiling(DestinationId::new(1), 1);
    let held = node.capacity.saturate(DestinationId::new(1));
    node.tune("primary", |pool| pool.on_exhausted = OnExhausted::Status503);

    assert_eq!(node.walker("primary").shed().retry_after_secs, Some(600));
    drop(held);
}

#[test]
fn a_purely_saturated_pool_gets_the_floor_and_never_the_bare_one_second() {
    let mut node = Node::with_lanes(&["a", "b"]);
    node.pool(
        "primary",
        vec![
            member(DestinationId::new(0), "a"),
            member(DestinationId::new(1), "b"),
        ],
    );
    node.capacity.set_ceiling(DestinationId::new(0), 1);
    node.capacity.set_ceiling(DestinationId::new(1), 1);
    let held: Vec<_> = (0..2)
        .map(|d| node.capacity.saturate(DestinationId::new(d as u64)))
        .collect();

    assert_eq!(
        node.walker("primary").shed().retry_after_secs,
        Some(AT_CAPACITY_RETRY_AFTER_SECS),
        "a bare one second reads as retry immediately, which just re-collides with the saturation"
    );
    assert_eq!(AT_CAPACITY_RETRY_AFTER_SECS, 2);
    assert_eq!(
        node.route("primary").shed().map(|r| r.retry_after),
        Some(Some(2)),
        "and the far end hands the same wait on"
    );
    drop(held);
}

#[test]
fn an_empty_candidate_set_gets_the_floor_too() {
    let node = Node::with_lanes(&[]);
    let token = super::route_token();
    let wait = busbar_kernel_egress::exhaustion::retry_after_secs(
        node.breaker.as_ref(),
        &[],
        "unknown-pool",
        node.clock.now_secs(),
        &token,
    );
    assert_eq!(
        wait, AT_CAPACITY_RETRY_AFTER_SECS,
        "an empty set is where least is known about when a slot frees, so it gets the honest floor"
    );
}

#[test]
fn a_pool_with_no_members_at_all_refuses() {
    let mut node = Node::with_lanes(&[]);
    node.pool("primary", Vec::new());
    let shed = node.walker("primary").shed();
    assert_eq!(shed.detail, DETAIL_OVERLOADED);
    assert_eq!(shed.retry_after_secs, None);
}

// ── the spill ───────────────────────────────────────────────────────────────────────────────────

fn spill_node() -> Node {
    let mut node = Node::with_lanes(&["a", "b"]);
    node.pool("primary", vec![member(DestinationId::new(0), "a")]);
    node.pool("overflow", vec![member(DestinationId::new(1), "b")]);
    node.tune("primary", |p| {
        p.on_exhausted = OnExhausted::FallbackPool("overflow".to_string());
    });
    node.breaker.set(
        DestinationId::new(0),
        Health {
            cooldown: 60,
            ..Health::default()
        },
    );
    node.conns.script("b", Script::Frames(ok_frames()));
    node
}

#[test]
fn a_spill_reaches_the_other_pools_healthy_member() {
    let node = spill_node();
    let taken = node.walker("primary").take();
    assert_eq!(taken.member.destination, DestinationId::new(1));
    assert_eq!(taken.pool, "overflow");
    assert!(taken.degraded, "a spill's dispatch is a degraded one");
    drop(taken);

    let outcome = node.route("primary");
    match outcome {
        Routed::Delivered(delivered) => {
            assert_eq!(delivered.destination, DestinationId::new(1));
            assert_eq!(
                delivered.pool, "overflow",
                "the outcome is recorded against the pool that actually served it"
            );
        }
        other => panic!("expected the spill to serve, got {other:?}"),
    }
    assert_eq!(
        node.breaker.outcomes("overflow", DestinationId::new(1)),
        vec![busbar_kernel_egress::ports::Outcome::Success]
    );
}

#[test]
fn a_spill_that_comes_back_round_terminates() {
    let mut node = spill_node();
    // Point the overflow pool back at the primary and make its member unusable too, so the chain
    // is primary to overflow to primary.
    node.tune("overflow", |p| {
        p.on_exhausted = OnExhausted::FallbackPool("primary".to_string());
    });
    node.breaker.set(
        DestinationId::new(1),
        Health {
            cooldown: 90,
            ..Health::default()
        },
    );

    let shed = node.walker("primary").shed();
    assert_eq!(shed.detail, DETAIL_OVERLOADED);
}

#[test]
fn a_spill_at_an_unconfigured_pool_refuses_with_the_floor() {
    let mut node = spill_node();
    node.tune("primary", |p| {
        p.on_exhausted = OnExhausted::FallbackPool("nowhere".to_string());
    });

    assert_eq!(
        node.walker("primary").shed().retry_after_secs,
        Some(AT_CAPACITY_RETRY_AFTER_SECS)
    );
}

#[test]
fn a_spill_applies_the_target_pools_own_blocklist() {
    let mut node = Node::with_lanes(&["a", "b", "c"]);
    node.pool("primary", vec![member(DestinationId::new(0), "a")]);
    node.pool(
        "overflow",
        vec![
            member(DestinationId::new(1), "b"),
            member(DestinationId::new(2), "c"),
        ],
    );
    node.tune("primary", |p| {
        p.on_exhausted = OnExhausted::FallbackPool("overflow".to_string());
    });
    // The operator blocklisted `b` in the OVERFLOW pool. The primary pool's own list says nothing
    // about it, so without the target's list being re-applied the spill could reach it.
    node.tune("overflow", |p| {
        p.failover.exclusions = vec!["b".to_string()];
    });
    node.breaker.set(
        DestinationId::new(0),
        Health {
            cooldown: 60,
            ..Health::default()
        },
    );
    node.conns.script("b", Script::Frames(ok_frames()));
    node.conns.script("c", Script::Frames(ok_frames()));

    let outcome = node.route("primary");
    assert!(
        matches!(&outcome, Routed::Delivered(d) if d.destination == DestinationId::new(2)),
        "the blocklisted member must be unreachable through the spill: {outcome:?}"
    );
}

#[test]
fn a_spill_carries_the_deadline_across_the_hop() {
    let node = spill_node();
    let mut walker = node.walker("primary");
    node.clock.advance_secs(node.timeout_secs + 1);
    assert_eq!(
        walker.shed().detail,
        busbar_kernel_egress::wire::DETAIL_REQUEST_TIMEOUT,
        "a spill is not a fresh request"
    );
}

// ── the last resort ─────────────────────────────────────────────────────────────────────────────

fn least_bad_node() -> Node {
    let mut node = Node::with_lanes(&["a", "b", "c"]);
    node.pool(
        "primary",
        vec![
            member(DestinationId::new(0), "a"),
            member(DestinationId::new(1), "b"),
            member(DestinationId::new(2), "c"),
        ],
    );
    node.tune("primary", |p| p.on_exhausted = OnExhausted::LeastBad);
    for lane in ["a", "b", "c"] {
        node.conns.script(lane, Script::Frames(ok_frames()));
    }
    node
}

#[test]
fn the_last_resort_takes_the_soonest_cooldown() {
    let node = least_bad_node();
    node.breaker.set(
        DestinationId::new(0),
        Health {
            cooldown: 300,
            ..Health::default()
        },
    );
    node.breaker.set(
        DestinationId::new(1),
        Health {
            cooldown: 10,
            ..Health::default()
        },
    );
    node.breaker.set(
        DestinationId::new(2),
        Health {
            cooldown: 120,
            ..Health::default()
        },
    );

    let taken = node.walker("primary").take();
    assert_eq!(taken.member.destination, DestinationId::new(1), "{taken:?}");
    assert!(
        taken.degraded,
        "the last resort's dispatch is a degraded one"
    );
}

#[test]
fn the_last_resort_ranks_only_usable_members() {
    let node = least_bad_node();
    // A dead member reports no cooldown at all; without the usability filter its zero would sort
    // it to the front of the last-resort order.
    node.breaker.set(
        DestinationId::new(0),
        Health {
            dead: true,
            ..Health::default()
        },
    );
    node.breaker.set(
        DestinationId::new(1),
        Health {
            cooldown: 10,
            ..Health::default()
        },
    );
    node.breaker.set(
        DestinationId::new(2),
        Health {
            cooldown: 120,
            ..Health::default()
        },
    );

    let taken = node.walker("primary").take();
    assert_eq!(taken.member.destination, DestinationId::new(1), "{taken:?}");
    assert!(
        taken.degraded,
        "the last resort's dispatch is a degraded one"
    );
}

#[test]
fn the_last_resort_skips_a_saturated_best_member_for_a_free_sibling() {
    let node = least_bad_node();
    node.breaker.set(
        DestinationId::new(0),
        Health {
            cooldown: 10,
            ..Health::default()
        },
    );
    node.breaker.set(
        DestinationId::new(1),
        Health {
            cooldown: 20,
            ..Health::default()
        },
    );
    node.breaker.set(
        DestinationId::new(2),
        Health {
            cooldown: 30,
            ..Health::default()
        },
    );
    node.capacity.set_ceiling(DestinationId::new(0), 1);
    let held = node.capacity.saturate(DestinationId::new(0));

    let taken = node.walker("primary").take();
    assert_eq!(
        taken.member.destination,
        DestinationId::new(1),
        "refusing because the single best member is momentarily busy defeats the whole point"
    );
    drop(taken);
    drop(held);
}

#[test]
fn the_last_resort_never_reaches_a_blocklisted_member() {
    let mut node = least_bad_node();
    node.tune("primary", |p| p.failover.exclusions = vec!["b".to_string()]);
    node.breaker.set(
        DestinationId::new(0),
        Health {
            cooldown: 300,
            ..Health::default()
        },
    );
    node.breaker.set(
        DestinationId::new(1),
        Health {
            cooldown: 10,
            ..Health::default()
        },
    );
    node.breaker.set(
        DestinationId::new(2),
        Health {
            cooldown: 120,
            ..Health::default()
        },
    );

    let taken = node.walker("primary").take();
    assert_eq!(
        taken.member.destination,
        DestinationId::new(2),
        "the blocklist is applied before anything reads the membership: {taken:?}"
    );
}

#[test]
fn the_last_resort_owns_no_probe() {
    let node = least_bad_node();
    // Every member's cell offers a probe. The last resort bypasses the breaker entirely, so it
    // must neither win nor release one — releasing a probe a peer won would revert the peer's.
    for d in 0..3 {
        node.breaker.set(
            DestinationId::new(d as u64),
            Health {
                cooldown: 10,
                offers_probe: Some(7),
                ..Health::default()
            },
        );
    }
    let _ = node.route("primary");
    assert!(
        node.breaker.probe_releases().is_empty(),
        "the one documented breaker bypass owns no probe and so can never release one"
    );
}

#[test]
fn the_last_resort_sheds_when_every_member_is_saturated() {
    let node = least_bad_node();
    for d in 0..3 {
        node.breaker.set(
            DestinationId::new(d as u64),
            Health {
                cooldown: 10,
                ..Health::default()
            },
        );
        node.capacity.set_ceiling(DestinationId::new(d as u64), 1);
    }
    let held: Vec<_> = (0..3)
        .map(|d| node.capacity.saturate(DestinationId::new(d as u64)))
        .collect();

    let shed = node.walker("primary").shed();
    assert_eq!(shed.detail, DETAIL_OVERLOADED);
    assert_eq!(shed.retry_after_secs, Some(10));
    drop(held);
}

// ── the terminals over the served breaker, and the burst (F25 row 155 rehomes) ─────────────────

use busbar_kernel_breaker::cfg::BreakerCfg;
use busbar_kernel_egress::ports::{Breaker, Capacity, Outcome, Permit};
use busbar_kernel_egress::walk::Step;

use super::harness::route_token;
use super::walk_tests::{answer, ok_200, real_egress, route_async, route_over, RealBreaker};
use super::STREAM_CEILING_SECS;

/// Hold `lane`'s one slot: it is at capacity for as long as the returned permit lives.
fn saturated(node: &Node, lane: DestinationId) -> Permit {
    node.capacity.set_ceiling(lane, 1);
    node.capacity.saturate(lane)
}

/// F25 row 522: rehomed from the retired engine crate's src/engine/tests/on_exhausted_tests.rs::least_bad_still_serves_the_only_member_after_it_was_tried.
/// A single-member pool under least_bad whose member's breaker is Open: the ordered walk passes it
/// over (so the request's exclusion record holds every member), and the last resort still
/// overrides the breaker for that member, which serves 200.
#[test]
fn least_bad_still_serves_the_only_member_after_it_was_tried() {
    let solo = DestinationId::new(0);
    let mut node = Node::with_lanes(&["a"]);
    node.pool("ps", vec![member(solo, "solo")]);
    node.tune("ps", |p| p.on_exhausted = OnExhausted::LeastBad);
    node.conns.script("a", Script::Frames(answer(200)));
    let real = RealBreaker::new();
    let _ = real.cell("ps", solo).hard_down(node.clock.now_secs(), 30);

    let outcome = route_over(&node, &real_egress(&node, &real), "ps");

    assert!(
        matches!(&outcome, Routed::Delivered(d) if d.destination == solo && d.status == ok_200()),
        "least_bad must still override the Open breaker for a non-excluded member: {outcome:?}"
    );
}

/// F25 row 181: rehomed from the retired engine crate's src/engine/tests/forward_pool_integration_tests.rs::test_forward_once_records_success_and_spends_budget.
/// A lane with two units of lifetime budget, five failures and a 600 s cooldown behind it, served
/// through least_bad: the 2xx is recorded as one success against the lane (its window gains one
/// success, its error count stays 5) and spends exactly one unit (2 to 1).
#[test]
fn test_forward_once_records_success_and_spends_budget() {
    let lane = DestinationId::new(0);
    let mut node = Node::with_lanes(&["a"]);
    node.pool("leastbad", vec![member(lane, "lane0")]);
    node.tune("leastbad", |p| p.on_exhausted = OnExhausted::LeastBad);
    node.conns.script("a", Script::Frames(answer(200)));
    let real = RealBreaker::new();
    real.unit.set_budget(lane, 2);
    let now = node.clock.now_secs();
    let cell = real.cell("leastbad", lane);
    for _ in 0..5 {
        let _ = cell.record_failure(now, &BreakerCfg::default(), None, 3_600);
    }
    let _ = cell.hard_down(now, 600);
    assert_eq!(cell.err_count(), 5, "precondition: five failures");
    assert_eq!(
        cell.outcomes_in_window(now, 60),
        (5, 5),
        "precondition: no success yet"
    );
    assert_eq!(
        real.unit.budget_remaining(lane),
        Some(2),
        "precondition: budget 2"
    );

    let outcome = route_over(&node, &real_egress(&node, &real), "leastbad");

    assert!(
        matches!(&outcome, Routed::Delivered(d) if d.status == ok_200()),
        "least_bad serves the 2xx: {outcome:?}"
    );
    assert_eq!(real.outcomes("leastbad", lane), vec![Outcome::Success]);
    assert_eq!(
        cell.outcomes_in_window(now, 60),
        (6, 5),
        "the degraded 2xx records a success against the lane"
    );
    assert_eq!(cell.err_count(), 5);
    assert_eq!(
        real.unit.budget_remaining(lane),
        Some(1),
        "the degraded 2xx spends one unit of the lane's budget"
    );
}

/// F25 row 34: rehomed from the retired engine crate's src/engine/engine_tests/send_envelope_tests.rs::a_black_holed_stream_send_on_the_degraded_walk_times_out_at_the_ceiling.
/// The black hole on the DEGRADED walk: the only member's breaker is Open and least_bad licensed,
/// so the dispatch is the last resort's. Its streamed send, whose head never comes, resolves at the
/// stream ceiling (300 s, never the walk's 120 s budget, as 1.5.5 ran a streamed request), never
/// hangs, is refused 503, and records exactly one transient against the member.
#[test]
fn a_black_holed_stream_send_on_the_degraded_walk_times_out_at_the_ceiling() {
    let lane = DestinationId::new(0);
    let mut node = Node::with_lanes(&["a"]);
    node.pool("p", vec![member(lane, "gpt-4o")]);
    node.tune("p", |p| p.on_exhausted = OnExhausted::LeastBad);
    node.wants_stream = true;
    node.conns.script("a", Script::Hang);
    let real = RealBreaker::new();
    let _ = real.cell("p", lane).hard_down(node.clock.now_secs(), 300);
    let started = node.clock.now_millis();

    let outcome = route_over(&node, &real_egress(&node, &real), "p");

    assert_eq!(
        node.clock.now_millis() - started,
        u128::from(STREAM_CEILING_SECS * 1000),
        "the degraded stream send resolves at the ceiling"
    );
    assert_eq!(
        outcome.shed().map(|r| r.status),
        Some(u32::from(STATUS_SERVICE_UNAVAILABLE)),
        "black-holed headers on the degraded walk are an upstream failure: {outcome:?}"
    );
    assert_eq!(
        real.outcomes("p", lane),
        vec![Outcome::Transient { retry_after: None }]
    );
    assert_eq!(
        real.cell("p", lane).err_count(),
        1,
        "the degraded-path ceiling expiry records the breaker transient"
    );
}

/// A pool `primary` of `primary` lanes and a pool `overflow` of the rest, `primary` spilling into
/// `overflow`, every lane answering 200, under a 300 s failover budget a park would run to.
fn spill_world(lanes: &[&'static str], primary: usize) -> Node {
    let mut node = Node::with_lanes(lanes);
    node.timeout_secs = 300;
    let members = |range: std::ops::Range<usize>| {
        range
            .map(|i| member(DestinationId::new(i as u64), lanes[i]))
            .collect::<Vec<_>>()
    };
    node.pool("primary", members(0..primary));
    node.pool("overflow", members(primary..lanes.len()));
    node.tune("primary", |p| {
        p.on_exhausted = OnExhausted::FallbackPool("overflow".to_string());
    });
    for lane in lanes {
        node.conns.script(lane, Script::Frames(answer(200)));
    }
    node
}

/// F25 row 526: rehomed from the retired engine crate's src/engine/tests/on_exhausted_tests.rs::at_capacity_fallback_spills_to_fast_member.
/// A breaker-healthy primary at capacity under fallback_pool SPILLS at once to the overflow pool's
/// free member, which serves 200; the saturated primary is never dispatched to (it serves zero).
#[test]
fn at_capacity_fallback_spills_to_fast_member() {
    let (slow, fast) = (DestinationId::new(0), DestinationId::new(1));
    let node = spill_world(&["a", "b"], 1);
    let _held = saturated(&node, slow);
    let started = node.clock.now_millis();

    let outcome = node.route("primary");

    assert!(
        matches!(&outcome, Routed::Delivered(d)
            if d.pool == "overflow" && d.destination == fast && d.status == ok_200()),
        "a saturated primary must spill to the fast overflow pool and be served: {outcome:?}"
    );
    assert_eq!(
        node.clock.now_millis() - started,
        0,
        "spilled at once, never parked"
    );
    assert_eq!(
        node.breaker.outcomes("overflow", fast),
        vec![Outcome::Success],
        "the fast overflow member serves the spilled request"
    );
    assert!(
        node.breaker.outcomes("primary", slow).is_empty(),
        "the saturated primary never serializes the request"
    );
    assert_eq!(node.conns.dialled(), vec!["b".to_string()]);
}

/// F25 row 528: rehomed from the retired engine crate's src/engine/tests/on_exhausted_tests.rs::at_capacity_bounded_burst_all_spill_not_serialized.
/// A burst of 4 concurrent requests on a pool whose single slot is held: every one spills to the
/// roomy overflow member and is served 200 there, side by side (each answer takes 200 ms and the
/// whole burst takes 200 ms), and the saturated slot serves none of them.
#[test]
fn at_capacity_bounded_burst_all_spill_not_serialized() {
    const N: usize = 4;
    let (slow, fast) = (DestinationId::new(0), DestinationId::new(1));
    let node = spill_world(&["a", "b"], 1);
    node.capacity.set_ceiling(fast, 20);
    node.conns.script(
        "b",
        Script::Drip {
            replies: answer(200),
            step_ms: 100,
            complete: true,
        },
    );
    let _held = saturated(&node, slow);
    let egress = node.egress();
    let started = node.clock.now_millis();

    let burst = node.rt.block_on(futures::future::join_all(
        (0..N).map(|_| route_async(&node, &egress, "primary")),
    ));

    for outcome in &burst {
        assert!(
            matches!(outcome, Routed::Delivered(d)
                if d.pool == "overflow" && d.destination == fast && d.status == ok_200()),
            "every request in the burst is served by the overflow pool, not queued: {outcome:?}"
        );
    }
    assert_eq!(
        node.clock.now_millis() - started,
        200,
        "the {N} spilled requests ran in parallel, not one after another"
    );
    assert_eq!(
        node.breaker.outcomes("overflow", fast),
        vec![Outcome::Success; N]
    );
    assert!(
        node.breaker.outcomes("primary", slow).is_empty(),
        "the single saturated slot served none of them"
    );
    assert_eq!(node.conns.dialled(), vec!["b".to_string(); N]);
}

/// F25 row 529: rehomed from the retired engine crate's src/engine/tests/on_exhausted_tests.rs::at_capacity_all_members_busy_two_member_pool_spills.
/// A two-member primary with BOTH members at capacity is exhausted and spills: the overflow member
/// serves 200, neither primary member is dispatched to.
#[test]
fn at_capacity_all_members_busy_two_member_pool_spills() {
    let (a, b, fast) = (
        DestinationId::new(0),
        DestinationId::new(1),
        DestinationId::new(2),
    );
    let node = spill_world(&["a", "b", "c"], 2);
    let _held = [saturated(&node, a), saturated(&node, b)];
    let started = node.clock.now_millis();

    let outcome = node.route("primary");

    assert!(
        matches!(&outcome, Routed::Delivered(d)
            if d.pool == "overflow" && d.destination == fast && d.status == ok_200()),
        "with every member at capacity the pool is exhausted and must spill: {outcome:?}"
    );
    assert_eq!(node.clock.now_millis() - started, 0, "spilled at once");
    assert_eq!(
        node.breaker.outcomes("overflow", fast),
        vec![Outcome::Success]
    );
    assert!(node.breaker.outcomes("primary", a).is_empty());
    assert!(node.breaker.outcomes("primary", b).is_empty());
    assert_eq!(node.conns.dialled(), vec!["c".to_string()]);
}

/// F25 row 531: rehomed from the retired engine crate's src/engine/tests/on_exhausted_tests.rs::at_capacity_fallback_chain_spills_through_to_third_pool.
/// A fallback chain A to B to C, A and B each at capacity: the at-capacity exhaustion cascades
/// through the whole chain and C's member serves 200; A's and B's members serve nothing.
#[test]
fn at_capacity_fallback_chain_spills_through_to_third_pool() {
    let (a, b, c) = (
        DestinationId::new(0),
        DestinationId::new(1),
        DestinationId::new(2),
    );
    let mut node = Node::with_lanes(&["a", "b", "c"]);
    node.timeout_secs = 300;
    node.pool("pa", vec![member(a, "a")]);
    node.pool("pb", vec![member(b, "b")]);
    node.pool("pc", vec![member(c, "c")]);
    node.tune("pa", |p| {
        p.on_exhausted = OnExhausted::FallbackPool("pb".to_string());
    });
    node.tune("pb", |p| {
        p.on_exhausted = OnExhausted::FallbackPool("pc".to_string());
    });
    for lane in ["a", "b", "c"] {
        node.conns.script(lane, Script::Frames(answer(200)));
    }
    let _held = [saturated(&node, a), saturated(&node, b)];

    let outcome = node.route("pa");

    assert!(
        matches!(&outcome, Routed::Delivered(d)
            if d.pool == "pc" && d.destination == c && d.status == ok_200()),
        "A to B to C: the at-capacity signal cascades to the fast pool: {outcome:?}"
    );
    assert_eq!(node.breaker.outcomes("pc", c), vec![Outcome::Success]);
    assert!(node.breaker.outcomes("pa", a).is_empty());
    assert!(node.breaker.outcomes("pb", b).is_empty());
    assert_eq!(node.conns.dialled(), vec!["c".to_string()]);
}

/// F25 row 532: rehomed from the retired engine crate's src/engine/tests/on_exhausted_tests.rs::at_capacity_self_referential_fallback_stays_503.
/// A SATURATED pool whose on_exhausted names ITSELF as its fallback stops at the visited-pool loop
/// guard: a 503 shed with the at-capacity floor, at once, without parking and without dispatching.
#[test]
fn at_capacity_self_referential_fallback_stays_503() {
    let busy = DestinationId::new(0);
    let mut node = Node::with_lanes(&["a"]);
    node.timeout_secs = 300;
    node.pool("loop", vec![member(busy, "busy")]);
    node.tune("loop", |p| {
        p.on_exhausted = OnExhausted::FallbackPool("loop".to_string());
    });
    let _held = saturated(&node, busy);

    let shed = node.walker("loop").shed();
    assert_eq!(shed.status, STATUS_SERVICE_UNAVAILABLE);
    assert_eq!(shed.detail, DETAIL_OVERLOADED);

    let started = node.clock.now_millis();
    let outcome = node.route("loop");
    assert_eq!(
        outcome.shed(),
        Some(&super::Refusal {
            status: u32::from(STATUS_SERVICE_UNAVAILABLE),
            retry_after: Some(2),
        }),
        "a self-referential fallback stops at the loop guard with 503: {outcome:?}"
    );
    assert_eq!(node.clock.now_millis() - started, 0, "never parked");
    assert_eq!(*node.telemetry.queue_parks.lock().unwrap(), 0);
    assert!(node.conns.dialled().is_empty(), "never dispatched");
}

/// F25 row 533: rehomed from the retired engine crate's src/engine/tests/on_exhausted_tests.rs::at_capacity_fallback_to_also_exhausted_pool_cascades_to_503.
/// A saturated primary spilling into a pool that is itself at capacity (no further on_exhausted)
/// cascades to the 503 shed with its Retry-After, at once, dispatching nothing.
#[test]
fn at_capacity_fallback_to_also_exhausted_pool_cascades_to_503() {
    let (primary, overflow) = (DestinationId::new(0), DestinationId::new(1));
    let node = spill_world(&["a", "b"], 1);
    let _held = [saturated(&node, primary), saturated(&node, overflow)];
    let started = node.clock.now_millis();

    let outcome = node.route("primary");

    assert_eq!(
        outcome.shed(),
        Some(&super::Refusal {
            status: u32::from(STATUS_SERVICE_UNAVAILABLE),
            retry_after: Some(2),
        }),
        "spilling into an also-at-capacity pool cascades to a 503 shed: {outcome:?}"
    );
    assert_eq!(node.clock.now_millis() - started, 0, "shed, not queued");
    assert!(node.conns.dialled().is_empty());
}

/// F25 row 483: rehomed from the retired engine crate's src/engine/tests/lane_availability_proptest_tests.rs::bug1_witness_fallback_spills_served_by_fallback_not_primary.
/// The park-then-serve witness: a breaker-HEALTHY primary at capacity under fallback_pool MUST
/// spill, served 200 by the fallback with the primary serving zero. The primary's slot here frees
/// the moment anything waits for it, so a walk that parked instead of spilling would be served by
/// the primary and fail.
#[test]
fn bug1_witness_fallback_spills_served_by_fallback_not_primary() {
    let (primary, spare) = (DestinationId::new(0), DestinationId::new(1));
    let mut node = spill_world(&["a", "b"], 1);
    node.timeout_secs = 2;
    node.capacity.set_ceiling(primary, 1);
    node.capacity.saturate_until_waited(primary);

    let outcome = node.route("primary");

    assert!(
        matches!(&outcome, Routed::Delivered(d)
            if d.pool == "overflow" && d.destination == spare && d.status == ok_200()),
        "fallback_pool with an eligible fallback must SPILL, not shed: {outcome:?}"
    );
    assert!(
        node.breaker.outcomes("primary", primary).is_empty(),
        "the at-capacity primary must serve ZERO: never park-then-serve the primary"
    );
    assert_eq!(
        node.breaker.outcomes("overflow", spare),
        vec![Outcome::Success],
        "the eligible fallback serves exactly the one spilled request"
    );
    assert_eq!(*node.telemetry.queue_parks.lock().unwrap(), 0);
}

/// F25 row 484: rehomed from the retired engine crate's src/engine/tests/lane_availability_proptest_tests.rs::budget_contract_holds_under_full_saturation_for_every_policy.
/// Under FULL saturation (the primary's and the fallback's single slots both held) every
/// on_exhausted policy sheds 503 with the at-capacity floor inside the 2 s failover budget: at once
/// for reject, least_bad and fallback_pool, at the queue's own 50 ms bound for queue.
#[test]
fn budget_contract_holds_under_full_saturation_for_every_policy() {
    for (policy, waited_ms) in [
        (OnExhausted::Status503, 0_u64),
        (OnExhausted::LeastBad, 0),
        (OnExhausted::Queue { max_ms: 50 }, 50),
        (OnExhausted::FallbackPool("overflow".to_string()), 0),
    ] {
        let (busy, overflow) = (DestinationId::new(0), DestinationId::new(1));
        let mut node = spill_world(&["a", "b"], 1);
        node.timeout_secs = 2;
        node.tune("primary", |p| p.on_exhausted = policy.clone());
        let _held = [saturated(&node, busy), saturated(&node, overflow)];
        let started = node.clock.now_millis();

        let outcome = node.route("primary");

        let elapsed = node.clock.now_millis() - started;
        assert_eq!(
            outcome.shed(),
            Some(&super::Refusal {
                status: u32::from(STATUS_SERVICE_UNAVAILABLE),
                retry_after: Some(2),
            }),
            "a fully-saturated pool sheds 503 under {policy:?}: {outcome:?}"
        );
        assert!(
            elapsed <= u128::from(node.timeout_secs * 1000),
            "ingress to disposition {elapsed} ms exceeded the failover budget for {policy:?}"
        );
        assert_eq!(elapsed, u128::from(waited_ms), "{policy:?}");
        assert!(node.conns.dialled().is_empty(), "{policy:?}");
        assert_eq!(*node.telemetry.queue_depth.lock().unwrap(), 0, "{policy:?}");
    }
}

// ── the generated worlds of row 480 ────────────────────────────────────────────────────────────

/// Every generated world's failover budget, seconds: a park to it would blow the bound.
const FAILOVER_SECS: u64 = 2;

/// The lanes a generated world can hold: up to five primary members and four fallback members.
const LANES: [&str; 9] = ["l0", "l1", "l2", "l3", "l4", "l5", "l6", "l7", "l8"];

/// A member's breaker cell at the decision.
#[derive(Clone, Copy, Debug)]
enum CellAt {
    Closed,
    /// Open, its cooldown a day away.
    OpenActive,
    /// Open, its cooldown passed: probe-winnable.
    OpenExpired,
    /// A peer holds the recovery probe.
    HalfOpen,
}

/// A member's concurrency.
#[derive(Clone, Copy, Debug)]
enum CapAt {
    Unbounded,
    /// Bounded, with a free slot.
    BoundedFree(usize),
    /// One slot, held for the whole case.
    Saturated,
}

#[derive(Clone, Copy, Debug)]
struct LaneAt {
    dead: bool,
    budget_out: bool,
    cell: CellAt,
    cap: CapAt,
}

#[derive(Clone, Copy, Debug)]
enum PolicyAt {
    Reject,
    LeastBad,
    Fallback,
    Queue(u64),
}

#[derive(Clone, Debug)]
struct World {
    primary: Vec<LaneAt>,
    fallback: Vec<LaneAt>,
    policy: PolicyAt,
}

/// A seeded generator (xorshift64*), so every run draws the same worlds.
struct Draw(u64);

impl Draw {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    fn lane(&mut self) -> LaneAt {
        LaneAt {
            dead: self.below(2) == 1,
            budget_out: self.below(2) == 1,
            cell: match self.below(4) {
                0 => CellAt::Closed,
                1 => CellAt::OpenActive,
                2 => CellAt::OpenExpired,
                _ => CellAt::HalfOpen,
            },
            cap: match self.below(3) {
                0 => CapAt::Unbounded,
                1 => CapAt::BoundedFree(1 + self.below(8) as usize),
                _ => CapAt::Saturated,
            },
        }
    }

    fn world(&mut self) -> World {
        let primary = (0..1 + self.below(5)).map(|_| self.lane()).collect();
        let fallback = (0..1 + self.below(4)).map(|_| self.lane()).collect();
        let policy = match self.below(4) {
            0 => PolicyAt::Reject,
            1 => PolicyAt::LeastBad,
            2 => PolicyAt::Fallback,
            _ => PolicyAt::Queue(5 + self.below(46)),
        };
        World {
            primary,
            fallback,
            policy,
        }
    }
}

/// Drive one request through the walk and the far end over `world`, every member answering 200,
/// and assert the strengthened invariant against an oracle read off the same breaker and permit
/// store at decision time. Answers the disposition branch taken.
fn run_world(world: &World) -> &'static str {
    let p = world.primary.len();
    let total = p + world.fallback.len();
    let spills = matches!(world.policy, PolicyAt::Fallback);
    let id = |i: usize| DestinationId::new(i as u64);

    let mut node = Node::with_lanes(&LANES[..total]);
    node.timeout_secs = FAILOVER_SECS;
    node.pool("primary", (0..p).map(|i| member(id(i), LANES[i])).collect());
    if spills {
        node.pool(
            "fallback",
            (p..total).map(|i| member(id(i), LANES[i])).collect(),
        );
    }
    node.tune("primary", |pool| {
        pool.on_exhausted = match world.policy {
            PolicyAt::Reject => OnExhausted::Status503,
            PolicyAt::LeastBad => OnExhausted::LeastBad,
            PolicyAt::Fallback => OnExhausted::FallbackPool("fallback".to_string()),
            PolicyAt::Queue(max_ms) => OnExhausted::Queue { max_ms },
        };
    });
    for lane in &LANES[..total] {
        node.conns.script(lane, Script::Frames(answer(200)));
    }

    let real = RealBreaker::new();
    let now = node.clock.now_secs();
    let mut held = Vec::new();
    for (i, lane) in world.primary.iter().chain(&world.fallback).enumerate() {
        let d = id(i);
        if lane.dead {
            real.kill(d);
        }
        if lane.budget_out {
            real.unit.set_budget(d, 0);
        }
        match lane.cap {
            CapAt::Unbounded => {}
            CapAt::BoundedFree(slots) => node.capacity.set_ceiling(d, slots),
            CapAt::Saturated => held.push(saturated(&node, d)),
        }
        let cell = real.cell(if i < p { "primary" } else { "fallback" }, d);
        match lane.cell {
            CellAt::Closed => {}
            CellAt::OpenActive => {
                let _ = cell.hard_down(now, 86_400);
            }
            CellAt::OpenExpired => {
                let _ = cell.hard_down(now.saturating_sub(1), 0);
            }
            CellAt::HalfOpen => {
                let _ = cell.hard_down(now.saturating_sub(1), 0);
                let _ = cell.acquire(now);
            }
        }
    }

    // The oracle, at decision time, off the same breaker and permit store the walk reads.
    let token = route_token();
    let free = |d: DestinationId| node.capacity.try_acquire(d).is_some();
    let ready =
        |pool: &str, d: DestinationId| real.admissible(d) && real.ready(pool, d, now, &token);
    let elig_primary: Vec<DestinationId> = (0..p)
        .map(id)
        .filter(|d| ready("primary", *d) && free(*d))
        .collect();
    let soonest = (0..p)
        .map(id)
        .filter(|d| real.admissible(*d))
        .map(|d| real.cooldown_remaining("primary", d, now, &token))
        .filter(|r| *r > 0)
        .min();
    let any_waitable = (0..p).map(id).any(|d| ready("primary", d) && !free(d));
    let ls_serve = (0..p).map(id).any(|d| real.admissible(d) && free(d));
    let fb_elig = spills && (p..total).map(id).any(|d| ready("fallback", d) && free(d));

    let started = node.clock.now_millis();
    let outcome = route_over(&node, &real_egress(&node, &real), "primary");
    let elapsed = node.clock.now_millis() - started;
    let primary_ok = real.successes("primary");
    let fallback_ok = real.successes("fallback");
    let refused = outcome.shed().map(|r| (r.status, r.retry_after));
    let shed_503 = Some(u32::from(STATUS_SERVICE_UNAVAILABLE));

    // The budget contract, always.
    assert!(
        elapsed <= u128::from(FAILOVER_SECS * 1000),
        "ingress to disposition {elapsed} ms exceeded the failover budget: {world:?}"
    );
    let branch = if !elig_primary.is_empty() {
        // (a) An eligible primary member existed: it serves, never a shed, never a spill.
        assert!(
            matches!(&outcome, Routed::Delivered(d) if d.pool == "primary"
                && elig_primary.contains(&d.destination) && d.status == ok_200()),
            "an eligible primary member {elig_primary:?} existed but did not serve: \
             {outcome:?} {world:?}"
        );
        assert_eq!(primary_ok, 1, "{world:?}");
        assert_eq!(fallback_ok, 0, "{world:?}");
        "primary"
    } else {
        // (b) The primary is exhausted: the disposition is the policy's.
        match world.policy {
            PolicyAt::Reject => {
                let wait = soonest.unwrap_or(AT_CAPACITY_RETRY_AFTER_SECS);
                assert_eq!(
                    refused,
                    Some((
                        u32::from(STATUS_SERVICE_UNAVAILABLE),
                        Some(u32::try_from(wait).expect("a representable wait"))
                    )),
                    "reject sheds 503 with the soonest genuine cooldown, else the at-capacity \
                     floor: {world:?}"
                );
                assert_eq!(elapsed, 0, "{world:?}");
                "reject"
            }
            PolicyAt::LeastBad if ls_serve => {
                assert!(
                    matches!(&outcome, Routed::Delivered(d)
                        if d.pool == "primary" && d.status == ok_200()),
                    "least_bad degrades onto a free admissible member: {outcome:?} {world:?}"
                );
                assert_eq!(primary_ok, 1, "{world:?}");
                assert_eq!(fallback_ok, 0, "{world:?}");
                "least_bad served"
            }
            PolicyAt::LeastBad => {
                assert_eq!(refused.map(|r| r.0), shed_503, "{world:?}");
                assert!(refused.and_then(|r| r.1).is_some(), "{world:?}");
                "least_bad shed"
            }
            PolicyAt::Fallback if fb_elig => {
                assert!(
                    matches!(&outcome, Routed::Delivered(d)
                        if d.pool == "fallback" && d.status == ok_200()),
                    "fallback_pool with an eligible fallback must SPILL: {outcome:?} {world:?}"
                );
                assert_eq!(primary_ok, 0, "the primary serves ZERO: {world:?}");
                assert_eq!(fallback_ok, 1, "{world:?}");
                "fallback spill"
            }
            PolicyAt::Fallback => {
                assert_eq!(refused.map(|r| r.0), shed_503, "{world:?}");
                assert!(refused.and_then(|r| r.1).is_some(), "{world:?}");
                assert_eq!(primary_ok, 0, "{world:?}");
                "fallback cascade"
            }
            PolicyAt::Queue(max_ms) => {
                assert_eq!(refused.map(|r| r.0), shed_503, "{world:?}");
                assert!(refused.and_then(|r| r.1).is_some(), "{world:?}");
                assert_eq!(
                    elapsed,
                    u128::from(if any_waitable { max_ms } else { 0 }),
                    "the queue waits its own bound when a member is at capacity, not at all \
                     otherwise; never toward the failover budget: {world:?}"
                );
                assert_eq!(primary_ok + fallback_ok, 0, "{world:?}");
                "queue shed"
            }
        }
    };
    drop(held);
    branch
}

/// F25 row 480: rehomed from the retired engine crate's src/engine/tests/lane_availability_proptest_tests.rs::strengthened_lane_availability_invariant.
/// The strengthened lane-availability invariant over 512 seeded worlds: a primary pool of 1 to 5
/// and a fallback pool of 1 to 4 members, each dead or not, out of budget or not, its cell Closed,
/// Open (active), Open (expired) or HalfOpen, unbounded, bounded with a free slot or saturated, under
/// each of the four on_exhausted policies (queue at 5 to 50 ms). One request each, through the walk
/// and the far end over the served breaker: an eligible primary member always serves, else the
/// disposition is the policy's (reject: 503 with the soonest cooldown or the floor; least_bad: a
/// free admissible member serves, else 503; fallback_pool: the fallback serves and the primary
/// serves zero, else 503; queue: 503 after its own bound at most), always inside the failover
/// budget. Every branch is reached.
#[test]
fn strengthened_lane_availability_invariant() {
    let mut draw = Draw(0x9E37_79B9_7F4A_7C15);
    let mut reached = std::collections::BTreeSet::new();
    for _ in 0..512 {
        reached.insert(run_world(&draw.world()));
    }
    assert_eq!(
        reached.into_iter().collect::<Vec<_>>(),
        vec![
            "fallback cascade",
            "fallback spill",
            "least_bad served",
            "least_bad shed",
            "primary",
            "queue shed",
            "reject",
        ],
        "the generated worlds reach every disposition"
    );
}

// ── the wait ────────────────────────────────────────────────────────────────────────────────────

fn queue_node(max_ms: u64) -> Node {
    let mut node = Node::with_lanes(&["a", "b"]);
    node.pool(
        "primary",
        vec![
            member(DestinationId::new(0), "a"),
            member(DestinationId::new(1), "b"),
        ],
    );
    node.tune("primary", |p| {
        p.on_exhausted = OnExhausted::Queue { max_ms };
    });
    for lane in ["a", "b"] {
        node.conns.script(lane, Script::Frames(ok_frames()));
    }
    node
}

#[test]
fn the_wait_sheds_at_once_when_nothing_it_could_wait_for_is_busy() {
    let node = queue_node(250);
    // Every member is suppressed, not busy. No slot will free, so waiting is pointless.
    node.breaker.set(
        DestinationId::new(0),
        Health {
            cooldown: 60,
            ..Health::default()
        },
    );
    node.breaker.set(
        DestinationId::new(1),
        Health {
            cooldown: 60,
            ..Health::default()
        },
    );

    assert_eq!(node.walker("primary").shed().retry_after_secs, Some(60));
    // v1.5.5 `crates/busbar/src/proxy/engine/walk.rs:191-202`: the pre-check sheds before the
    // depth gauge is touched.
    assert_eq!(
        *node.telemetry.queue_parks.lock().unwrap(),
        0,
        "the request never parked"
    );
}

#[test]
fn the_wait_dispatches_on_the_member_that_freed_a_slot() {
    let node = queue_node(250);
    node.capacity.set_ceiling(DestinationId::new(0), 1);
    node.capacity.set_ceiling(DestinationId::new(1), 1);
    // Both members are at capacity when the pick runs. `a` stays held for the whole route; `b`'s
    // slot is given back at the moment the wait terminal reaches the permit store — after the pick
    // recorded its at-capacity exclusions and after the depth gauge counted the waiter in. Freeing
    // a slot before the route instead leaves it free at the PICK, so the walk dispatches on the
    // ordered path and the wait terminal is never entered at all.
    let held_a = node.capacity.saturate(DestinationId::new(0));
    node.capacity.saturate_until_waited(DestinationId::new(1));

    let taken = node.walker("primary").take();

    assert_eq!(
        *node.telemetry.queue_parks.lock().unwrap(),
        1,
        "the request reached its member by parking, not by the ordered walk"
    );
    assert_eq!(
        taken.member.destination,
        DestinationId::new(1),
        "the answer comes off the member that freed a slot"
    );
    assert!(
        taken.degraded,
        "an answer served out of the wait terminal is a degraded one"
    );
    drop(taken);
    assert_eq!(
        *node.telemetry.queue_depth.lock().unwrap(),
        0,
        "the waiter is counted back out on the dispatching exit too"
    );
    drop(held_a);
}

#[test]
fn the_wait_sheds_when_no_slot_frees_and_the_gauge_balances() {
    let node = queue_node(250);
    node.capacity.set_ceiling(DestinationId::new(0), 1);
    node.capacity.set_ceiling(DestinationId::new(1), 1);
    let held: Vec<_> = (0..2)
        .map(|d| node.capacity.saturate(DestinationId::new(d as u64)))
        .collect();

    let shed = node.walker("primary").shed();
    assert_eq!(shed.detail, DETAIL_OVERLOADED);
    assert_eq!(shed.retry_after_secs, Some(AT_CAPACITY_RETRY_AFTER_SECS));
    assert_eq!(*node.telemetry.queue_parks.lock().unwrap(), 1);
    assert_eq!(
        *node.telemetry.queue_depth.lock().unwrap(),
        0,
        "the depth gauge is decremented on every exit, so it can never leak a phantom waiter"
    );
    drop(held);
}

/// F25 row 546: rehomed from the retired engine crate's src/engine/tests/on_exhausted_tests.rs::queue_won_permit_but_breaker_now_open_never_dispatches.
/// A request parked in the queue wins the member's freed slot, but the member's breaker tripped
/// Open while it waited: the breaker re-check on the won member refuses it, the request is never
/// dispatched, and it ends in the 503 shed at once (the wait does not run on to its bound).
#[test]
fn queue_won_permit_but_breaker_now_open_never_dispatches() {
    let svc = DestinationId::new(0);
    let mut node = Node::with_lanes(&["a"]);
    node.timeout_secs = 300;
    node.pool("p", vec![member(svc, "svc")]);
    node.tune("p", |p| {
        p.on_exhausted = OnExhausted::Queue { max_ms: 2_000 }
    });
    node.conns.script("a", Script::Frames(ok_frames()));
    // At capacity at the pick; the slot frees the moment the parked request asks for it.
    node.capacity.set_ceiling(svc, 1);
    node.capacity.saturate_until_waited(svc);

    let mut walker = node.walker("p");
    let super::Walker {
        node: n,
        pools,
        token,
        walk,
        shape: _,
    } = &mut walker;
    let ports = super::ports(n, pools);
    let Step::Wait(wait) = walk.next(&ports, n.affinity, token) else {
        panic!("expected the queue terminal's wait");
    };
    let parked = walk
        .park(&ports, &wait, token)
        .unwrap_or_else(|shed| panic!("expected a wait, got the shed {shed:?}"));
    // The breaker trips Open WHILE the request is parked.
    node.breaker.set(
        svc,
        Health {
            cooldown: 300,
            ..Health::default()
        },
    );
    let started = node.clock.now_millis();
    let waited = node.rt.block_on(parked.wait(&ports));
    let shed = walk
        .waited(&ports, waited, token)
        .expect_err("a member whose breaker opened while queued must never be dispatched to");

    assert_eq!(shed.status, STATUS_SERVICE_UNAVAILABLE);
    assert_eq!(shed.detail, DETAIL_OVERLOADED);
    assert_eq!(shed.retry_after_secs, Some(300));
    assert_eq!(
        node.clock.now_millis() - started,
        0,
        "the won slot is refused at once; the wait does not run on to its bound"
    );
    assert_eq!(
        node.breaker.pick_order(),
        vec![svc],
        "admitted once, at the pick; the re-check on the won slot refused it"
    );
    assert_eq!(*node.telemetry.queue_parks.lock().unwrap(), 1);
    assert_eq!(*node.telemetry.queue_depth.lock().unwrap(), 0);
    assert!(
        node.breaker.outcomes("p", svc).is_empty(),
        "the now-Open member served nothing"
    );
}

/// v1.5.5 `crates/busbar/src/proxy/engine/walk.rs:212-214`: the depth gauge is RAII, decremented
/// on every exit including a dropped future.
#[test]
fn the_wait_gives_the_depth_gauge_back_when_the_parked_request_is_dropped() {
    let node = queue_node(250);
    node.capacity.set_ceiling(DestinationId::new(0), 1);
    node.capacity.set_ceiling(DestinationId::new(1), 1);
    let held: Vec<_> = (0..2)
        .map(|d| node.capacity.saturate(DestinationId::new(d as u64)))
        .collect();

    // Park the request, then walk away from it without ever polling it again — a client that hung
    // up mid-wait. The increment happened; nothing but a drop will run the decrement.
    node.walker("primary").abandon_wait();

    assert_eq!(
        *node.telemetry.queue_parks.lock().unwrap(),
        1,
        "the request did park, so the gauge was incremented"
    );
    assert_eq!(
        *node.telemetry.queue_depth.lock().unwrap(),
        0,
        "an abandoned waiter must not leave a phantom behind in the depth gauge"
    );
    drop(held);
}

#[test]
fn the_wait_is_bounded_by_what_is_left_of_the_walk_and_not_only_by_its_own_setting() {
    let node = queue_node(u64::MAX);
    node.capacity.set_ceiling(DestinationId::new(0), 1);
    node.capacity.set_ceiling(DestinationId::new(1), 1);
    let held: Vec<_> = (0..2)
        .map(|d| node.capacity.saturate(DestinationId::new(d as u64)))
        .collect();

    // The wait would run forever on its own setting; the walk's remaining budget is the real
    // bound, and the shed proves the wait ended.
    let started = node.clock.now_millis();
    let shed = node.walker("primary").shed();
    assert_eq!(shed.detail, DETAIL_OVERLOADED);
    assert_eq!(
        node.clock.now_millis() - started,
        u128::from(node.timeout_secs * 1000),
        "the wait ended at the walk's own deadline"
    );
    drop(held);
}

/// THE STATED MEMBER'S OWN WAIT (`OnPieceOut::wait_member`, read through `FarEnd::member_wait`): a
/// member of the unit's pool reads its own cell's cooldown, not the soonest across the pool; a
/// name that is no member of the pool reads none (the pump then refuses the plane's statement).
#[test]
fn a_stated_member_reads_its_own_wait_and_a_stranger_reads_none() {
    use crate::plane_driver::FarEnd as _;
    let mut node = Node::with_lanes(&["a", "b"]);
    node.pool(
        "p",
        vec![
            member(DestinationId::new(0), "a"),
            member(DestinationId::new(1), "b"),
        ],
    );
    node.breaker.set(
        DestinationId::new(0),
        Health {
            cooldown: 30,
            ..Health::default()
        },
    );
    node.breaker.set(
        DestinationId::new(1),
        Health {
            cooldown: 110,
            ..Health::default()
        },
    );
    let egress = node.egress();
    let far = egress.unit(node.unit_route("p"));
    let token = super::route_token();
    assert_eq!(far.member_wait(&token, "b"), Some(110));
    assert_eq!(far.member_wait(&token, "a"), Some(30));
    assert_eq!(far.member_wait(&token, "stranger"), None);
}

// ── the hooks' restriction holds through the terminals (arch-audit u42 BLOCK) ───────────────────

/// A required restriction the unit's hooks put on every pick: only these destinations are kept,
/// and a pick that keeps none is the restriction no member satisfies.
struct Restrict(Vec<DestinationId>);

impl busbar_kernel_egress::walk::Shape for Restrict {
    fn shape(
        &self,
        members: Vec<busbar_kernel_egress::pool::Member>,
        _primary: bool,
    ) -> Option<(Vec<busbar_kernel_egress::pool::Member>, Vec<DestinationId>)> {
        let kept: Vec<_> = members
            .into_iter()
            .filter(|m| self.0.contains(&m.destination))
            .collect();
        (!kept.is_empty()).then_some((kept, Vec::new()))
    }
}

/// Every member of `node`'s pool benched with its cooldown, by destination.
fn bench(node: &Node, cooldowns: &[u64]) {
    for (d, cooldown) in cooldowns.iter().enumerate() {
        node.breaker.set(
            DestinationId::new(d as u64),
            Health {
                cooldown: *cooldown,
                ..Health::default()
            },
        );
    }
}

/// v1.5.5 shrank the walk's candidates to the restriction's survivors so the restriction
/// "PERSISTS across every failover hop" (`crates/busbar/src/proxy/engine/mod.rs:1085`,
/// `:1298-1300`), and its last resort ranked only those candidates
/// (`crates/busbar/src/proxy/engine/walk.rs:1126-1130`).
/// The soonest-cooldown member is one the restriction excludes: the last resort must pass it over.
#[test]
fn the_last_resort_never_reaches_a_member_the_restriction_excludes() {
    let node = least_bad_node();
    bench(&node, &[10, 300, 120]);

    let taken = node
        .walker("primary")
        .shaped(Restrict(vec![DestinationId::new(1), DestinationId::new(2)]))
        .take();
    assert_eq!(
        taken.member.destination,
        DestinationId::new(2),
        "the last resort ranks the members the hooks kept, never the whole pool: {taken:?}"
    );
    assert!(taken.degraded);
}

/// The kept members are all busy, an excluded one is free: the last resort sheds (v1.5.5
/// `crates/busbar/src/proxy/engine/walk.rs:1142-1146`, over the restricted `cands`) rather than
/// dispatch to the excluded one, and the shed's wait is the kept member's own.
#[test]
fn the_last_resort_sheds_rather_than_reach_an_excluded_member() {
    let node = least_bad_node();
    bench(&node, &[10, 300, 120]);
    let held = saturated(&node, DestinationId::new(1));

    let shed = node
        .walker("primary")
        .shaped(Restrict(vec![DestinationId::new(1)]))
        .shed();
    assert_eq!(shed.detail, DETAIL_OVERLOADED);
    assert!(!shed.gate_rejected);
    assert_eq!(
        shed.retry_after_secs,
        Some(300),
        "the wait is read off the members the restriction kept (v1.5.5 handle_status_503 over the \
         restricted cands)"
    );
    drop(held);
}

/// The shed's Retry-After reads only the kept members (v1.5.5
/// `crates/busbar/src/proxy/engine/walk.rs:100` and `:49-61`, over the restricted `cands`): an
/// excluded member's sooner cooldown is not the client's to wait for.
#[test]
fn the_shed_advertises_only_the_kept_members_cooldown() {
    let node = exhausted_pool(3, &[10, 300, 120]);
    let shed = node
        .walker("primary")
        .shaped(Restrict(vec![DestinationId::new(1), DestinationId::new(2)]))
        .shed();
    assert_eq!(shed.detail, DETAIL_OVERLOADED);
    assert_eq!(shed.retry_after_secs, Some(120));
}

/// The queue terminal's shed reads the same kept members (v1.5.5
/// `crates/busbar/src/proxy/engine/walk.rs:202`, over the restricted `cands`).
#[test]
fn the_wait_terminals_shed_advertises_only_the_kept_members_cooldown() {
    let node = queue_node(250);
    bench(&node, &[10, 300]);
    let shed = node
        .walker("primary")
        .shaped(Restrict(vec![DestinationId::new(1)]))
        .shed();
    assert_eq!(shed.retry_after_secs, Some(300));
}
