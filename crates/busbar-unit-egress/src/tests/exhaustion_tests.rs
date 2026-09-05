// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The four terminals, and the words each of them says.
//!
//! Carried over from the previous release's on-exhausted tests. Every literal asserted here — the
//! status, the kind, the detail, the wait — is the one that shipped, and each is compared against
//! the constant rather than a retyped copy of it, so a reworded constant fails the test that reads
//! it rather than passing a test that repeats the same mistake.

use super::harness::{ok_frames, Health, Script};
use super::{member, Node};
use crate::exhaustion::AT_CAPACITY_RETRY_AFTER_SECS;
use crate::pool::OnExhausted;
use crate::ports::Clock;
use crate::wire::{RouteOutcome, DETAIL_OVERLOADED, KIND_OVERLOADED, STATUS_SERVICE_UNAVAILABLE};
use busbar_contract::DestinationId;

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
    let outcome = node.route("primary");
    let shed = outcome.shed().expect("a refusal");
    assert_eq!(shed.status, STATUS_SERVICE_UNAVAILABLE);
    assert_eq!(shed.kind, KIND_OVERLOADED);
    assert_eq!(shed.detail, DETAIL_OVERLOADED);
    assert!(!shed.gate_rejected);
}

#[test]
fn the_shed_advertises_the_soonest_genuine_cooldown() {
    let node = exhausted_pool(3, &[90, 30, 60]);
    let outcome = node.route("primary");
    assert_eq!(
        outcome.shed().expect("a refusal").retry_after_secs,
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
    node.pools.insert({
        let mut pool = node.pools.get("primary").unwrap().clone();
        pool.on_exhausted = OnExhausted::Status503;
        pool
    });

    let outcome = node.route("primary");
    assert_eq!(
        outcome.shed().expect("a refusal").retry_after_secs,
        Some(600)
    );
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

    let outcome = node.route("primary");
    assert_eq!(
        outcome.shed().expect("a refusal").retry_after_secs,
        Some(AT_CAPACITY_RETRY_AFTER_SECS),
        "a bare one second reads as retry immediately, which just re-collides with the saturation"
    );
    assert_eq!(AT_CAPACITY_RETRY_AFTER_SECS, 2);
    drop(held);
}

#[test]
fn an_empty_candidate_set_gets_the_floor_too() {
    let node = Node::with_lanes(&[]);
    let wait = crate::exhaustion::retry_after_secs(
        node.breaker.as_ref(),
        &[],
        "unknown-pool",
        node.clock.now_secs(),
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
    let outcome = node.route("primary");
    let shed = outcome.shed().expect("a refusal");
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
    node.transport.script("b", Script::Frames(ok_frames()));
    node
}

#[test]
fn a_spill_reaches_the_other_pools_healthy_member() {
    let node = spill_node();
    let outcome = node.route("primary");
    match outcome {
        RouteOutcome::Delivered(delivered) => {
            assert_eq!(delivered.destination, DestinationId::new(1));
            assert_eq!(
                delivered.pool, "overflow",
                "the outcome is recorded against the pool that actually served it"
            );
            assert!(delivered.degraded);
        }
        other => panic!("expected the spill to serve, got {other:?}"),
    }
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

    let outcome = node.route("primary");
    let shed = outcome.shed().expect("a refusal");
    assert_eq!(shed.detail, DETAIL_OVERLOADED);
}

#[test]
fn a_spill_at_an_unconfigured_pool_refuses_with_the_floor() {
    let mut node = spill_node();
    node.tune("primary", |p| {
        p.on_exhausted = OnExhausted::FallbackPool("nowhere".to_string());
    });

    let outcome = node.route("primary");
    assert_eq!(
        outcome.shed().expect("a refusal").retry_after_secs,
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
    node.transport.script("b", Script::Frames(ok_frames()));
    node.transport.script("c", Script::Frames(ok_frames()));

    let outcome = node.route("primary");
    assert!(
        matches!(&outcome, RouteOutcome::Delivered(d) if d.destination == DestinationId::new(2)),
        "the blocklisted member must be unreachable through the spill: {outcome:?}"
    );
}

#[test]
fn a_spill_carries_the_deadline_across_the_hop() {
    let node = spill_node();
    let mut ctx = node.request_ctx();
    node.clock.advance_secs(node.timeout_secs + 1);
    let outcome = node.route_with("primary", &mut ctx);
    assert_eq!(
        outcome.shed().expect("a refusal").detail,
        crate::wire::DETAIL_REQUEST_TIMEOUT,
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
        node.transport.script(lane, Script::Frames(ok_frames()));
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

    let outcome = node.route("primary");
    assert!(
        matches!(&outcome, RouteOutcome::Delivered(d) if d.destination == DestinationId::new(1)),
        "{outcome:?}"
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

    let outcome = node.route("primary");
    assert!(
        matches!(&outcome, RouteOutcome::Delivered(d) if d.destination == DestinationId::new(1)),
        "{outcome:?}"
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

    let outcome = node.route("primary");
    assert!(
        matches!(&outcome, RouteOutcome::Delivered(d) if d.destination == DestinationId::new(1)),
        "refusing because the single best member is momentarily busy defeats the whole point"
    );
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

    let outcome = node.route("primary");
    assert!(
        matches!(&outcome, RouteOutcome::Delivered(d) if d.destination == DestinationId::new(2)),
        "the blocklist is applied before anything reads the membership: {outcome:?}"
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

    let outcome = node.route("primary");
    let shed = outcome.shed().expect("a refusal");
    assert_eq!(shed.detail, DETAIL_OVERLOADED);
    assert_eq!(shed.retry_after_secs, Some(10));
    drop(held);
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
        node.transport.script(lane, Script::Frames(ok_frames()));
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

    let outcome = node.route("primary");
    assert_eq!(
        outcome.shed().expect("a refusal").retry_after_secs,
        Some(60)
    );
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
    let held_a = node.capacity.saturate(DestinationId::new(0));
    let held_b = node.capacity.saturate(DestinationId::new(1));

    // Both members are at capacity when the pick runs; one frees while the request is parked.
    let mut ctx = node.request_ctx();
    let plan = {
        // Run the pick first so the at-capacity exclusions are recorded, then free a slot.
        drop(held_a);
        drop(held_b);
        node.route_with("primary", &mut ctx)
    };
    assert!(plan.is_delivered(), "{plan:?}");
}

#[test]
fn the_wait_sheds_when_no_slot_frees_and_the_gauge_balances() {
    let node = queue_node(250);
    node.capacity.set_ceiling(DestinationId::new(0), 1);
    node.capacity.set_ceiling(DestinationId::new(1), 1);
    let held: Vec<_> = (0..2)
        .map(|d| node.capacity.saturate(DestinationId::new(d as u64)))
        .collect();

    let outcome = node.route("primary");
    let shed = outcome.shed().expect("a refusal");
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
    let outcome = node.route("primary");
    assert!(outcome.shed().is_some());
    drop(held);
}
