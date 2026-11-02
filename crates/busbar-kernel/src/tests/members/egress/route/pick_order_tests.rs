// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::harness::Health;
use super::{member, Node};
use busbar_contract::caps::Pass;
use busbar_contract::DestinationId;
use busbar_kernel_egress::ports::Unavailable;

fn three_lanes() -> (Node, Vec<busbar_kernel_egress::pool::Member>) {
    let node = Node::with_lanes(&["a", "b", "c"]);
    let members = vec![
        member(DestinationId::new(0), "a"),
        member(DestinationId::new(1), "b"),
        member(DestinationId::new(2), "c"),
    ];
    (node, members)
}

#[test]
fn a_ranking_takes_its_first_healthy_choice() {
    let (mut node, members) = three_lanes();
    node.preference = Some(vec![
        DestinationId::new(2),
        DestinationId::new(0),
        DestinationId::new(1),
    ]);
    let mut ctx = node.request_ctx();
    let picked = node.pick("p", &members, &mut ctx).expect("a member");
    assert_eq!(picked.destination, DestinationId::new(2));
}

#[test]
fn a_ranking_walks_past_a_suppressed_preferred_member() {
    let (mut node, members) = three_lanes();
    node.preference = Some(vec![
        DestinationId::new(2),
        DestinationId::new(0),
        DestinationId::new(1),
    ]);
    node.breaker.set(
        DestinationId::new(2),
        Health {
            cooldown: 30,
            ..Health::default()
        },
    );
    let mut ctx = node.request_ctx();
    let picked = node.pick("p", &members, &mut ctx).expect("a member");
    assert_eq!(picked.destination, DestinationId::new(0));
}

#[test]
fn a_ranking_walks_past_a_member_this_request_already_tried() {
    let (mut node, members) = three_lanes();
    node.preference = Some(vec![
        DestinationId::new(2),
        DestinationId::new(0),
        DestinationId::new(1),
    ]);
    let mut ctx = node.request_ctx();
    ctx.exclude(DestinationId::new(2));
    let picked = node.pick("p", &members, &mut ctx).expect("a member");
    assert_eq!(picked.destination, DestinationId::new(0));
}

#[test]
fn a_ranking_that_covers_only_unhealthy_members_falls_through_to_the_floor() {
    let (mut node, members) = three_lanes();

    node.preference = Some(vec![DestinationId::new(2)]);
    node.breaker.set(
        DestinationId::new(2),
        Health {
            cooldown: 30,
            ..Health::default()
        },
    );
    let mut ctx = node.request_ctx();
    let picked = node.pick("p", &members, &mut ctx).expect("a member");
    assert!(
        picked.destination == DestinationId::new(0) || picked.destination == DestinationId::new(1),
        "an unranked member is lowest priority but never stranded"
    );
}

#[test]
fn an_empty_ranking_is_the_plain_floor() {
    let (mut node, members) = three_lanes();
    node.preference = Some(Vec::new());
    let mut ctx = node.request_ctx();
    assert!(node.pick("p", &members, &mut ctx).is_some());
}

#[test]
fn ordered_walk_empty_order_is_swrr() {
    use super::walk_tests::RealBreaker;
    use busbar_kernel_egress::ports::Clock;
    use busbar_kernel_egress::select::{pick_among, PickInput};

    let (node, members) = three_lanes();
    let real = RealBreaker::new();
    let order: Vec<DestinationId> = Vec::new();
    let token = Pass::<busbar_contract::caps::Route>::mint(&crate::seal::acquire());
    let pick = || {
        let mut ctx = node.request_ctx();
        pick_among(
            &PickInput {
                breaker: real.as_ref(),
                capacity: node.capacity.as_ref(),
                floor: &node.floor,
                pool: "p",
                members: &members,
                affinity: None,
                preference: Some(order.as_slice()),
                now: node.clock.now_secs(),
                token: &token,
            },
            &mut ctx,
        )
        .map(|picked| picked.destination)
    };

    let seen: std::collections::HashSet<DestinationId> = (0..9)
        .map(|_| pick().expect("an empty ranking behaves as the floor"))
        .collect();
    assert!(
        seen.len() >= 2,
        "an empty ranking must distribute across healthy members, not pin one; saw {seen:?}"
    );

    let _ = real
        .cell("p", DestinationId::new(0))
        .hard_down(node.clock.now_secs(), 1_000_000);
    for _ in 0..9 {
        let picked = pick().expect("the floor finds a healthy member");
        assert!(
            picked == DestinationId::new(1) || picked == DestinationId::new(2),
            "the floor skips the tripped member 0, got {picked:?}"
        );
    }
}

#[test]
fn request_ctx_new_huge_deadline_does_not_panic() {
    use busbar_kernel_egress::ports::Clock;
    use busbar_kernel_egress::select::RequestCtx;

    let node = Node::with_lanes(&[]);
    let (now_secs, now_millis) = (node.clock.now_secs(), node.clock.now_millis());
    for secs in [u64::MAX, u64::MAX / 2, 1_000_000_000_000_000_000] {
        let ctx = RequestCtx::new(secs, now_secs, now_millis);
        let ms = ctx.remaining_ms(now_millis);
        assert!(
            ms > 0,
            "a huge deadline yields a positive remaining budget (secs={secs}), got {ms}"
        );
        assert!(!ctx.expired(now_secs), "secs={secs}");
        assert!(ctx.remaining_secs(now_secs) > 0, "secs={secs}");
    }
}

#[test]
fn a_ranking_never_selects_a_drained_member() {
    let (mut node, mut members) = three_lanes();
    members[2].weight = 0;
    node.preference = Some(vec![
        DestinationId::new(2),
        DestinationId::new(0),
        DestinationId::new(1),
    ]);
    let mut ctx = node.request_ctx();
    let picked = node.pick("p", &members, &mut ctx).expect("a member");
    assert_ne!(
        picked.destination,
        DestinationId::new(2),
        "weight zero is the operator's drain signal and no path may defeat it"
    );
}

#[test]
fn a_fully_drained_pool_selects_nothing() {
    let (node, mut members) = three_lanes();
    for m in &mut members {
        m.weight = 0;
    }
    let mut ctx = node.request_ctx();
    assert!(node.pick("p", &members, &mut ctx).is_none());
}

#[test]
fn session_affinity_never_pins_to_a_drained_member() {
    let (mut node, mut members) = three_lanes();
    members[0].weight = 0;

    node.affinity = Some(3);
    let mut ctx = node.request_ctx();
    let picked = node.pick("p", &members, &mut ctx).expect("a member");
    assert_ne!(
        picked.destination,
        DestinationId::new(0),
        "a session whose hash lands on a drained member must not keep pinning to it"
    );
}

#[test]
fn session_affinity_is_offered_first() {
    let (mut node, members) = three_lanes();
    node.affinity = Some(1);
    let mut ctx = node.request_ctx();
    let picked = node.pick("p", &members, &mut ctx).expect("a member");
    assert_eq!(picked.destination, DestinationId::new(1));
}

#[test]
fn a_member_at_capacity_is_recorded_as_such() {
    let (node, members) = three_lanes();
    for destination in 0..3 {
        node.capacity
            .set_ceiling(DestinationId::new(destination), 1);
    }
    let held: Vec<_> = (0..3)
        .map(|d| node.capacity.saturate(DestinationId::new(d as u64)))
        .collect();

    let mut ctx = node.request_ctx();
    assert!(node.pick("p", &members, &mut ctx).is_none());
    let reasons = ctx.excluded_reasons();
    assert_eq!(reasons.len(), 3, "every member was passed over");
    assert!(reasons
        .iter()
        .all(|(_, why)| matches!(why, Unavailable::AtCapacity { .. })));
    drop(held);
}

#[test]
fn a_suppressed_member_is_recorded_with_its_own_reason() {
    let (node, members) = three_lanes();
    for destination in 0..3 {
        node.breaker.set(
            DestinationId::new(destination),
            Health {
                cooldown: 42,
                ..Health::default()
            },
        );
    }
    let mut ctx = node.request_ctx();
    assert!(node.pick("p", &members, &mut ctx).is_none());
    let reasons = ctx.excluded_reasons();
    assert_eq!(reasons.len(), 3, "every suppressed member is recorded");
    for destination in 0..3 {
        assert!(reasons.contains(&(
            DestinationId::new(destination),
            Unavailable::BreakerOpen { until: 42 }
        )));
    }
}

#[test]
fn health_only_exhaustion_records_exact_reasons_without_admission_or_a_rotation_turn() {
    let (node, members) = three_lanes();
    for (destination, health) in [
        Health {
            dead: true,
            ..Health::default()
        },
        Health {
            budget_exhausted: true,
            ..Health::default()
        },
        Health {
            probe_in_flight: true,
            ..Health::default()
        },
    ]
    .into_iter()
    .enumerate()
    {
        node.breaker
            .set(DestinationId::new(destination as u64), health);
    }
    let mut ctx = node.request_ctx();
    assert!(node.pick("p", &members, &mut ctx).is_none());
    assert_eq!(
        ctx.excluded_reasons(),
        &[
            (DestinationId::new(0), Unavailable::Dead),
            (DestinationId::new(1), Unavailable::BudgetExhausted),
            (DestinationId::new(2), Unavailable::ProbeInFlight),
        ]
    );
    assert!(node.breaker.admission_attempts.lock().unwrap().is_empty());
    assert!(node
        .capacity
        .acquisition_attempts
        .lock()
        .unwrap()
        .is_empty());
    assert!(node.breaker.log.lock().unwrap().is_empty());

    let (fresh, _) = three_lanes();
    for destination in 0..3 {
        node.breaker
            .set(DestinationId::new(destination), Health::default());
    }
    for _ in 0..6 {
        let picked = node.pick("p", &members, &mut node.request_ctx()).unwrap();
        let expected = fresh.pick("p", &members, &mut fresh.request_ctx()).unwrap();
        assert_eq!(picked.destination, expected.destination);
    }
}

#[test]
fn health_only_reasons_omit_drained_and_already_tried_members_and_expired_picks() {
    let (node, mut members) = three_lanes();
    for destination in 0..3 {
        node.breaker.set(
            DestinationId::new(destination),
            Health {
                probe_in_flight: true,
                ..Health::default()
            },
        );
    }
    members[0].weight = 0;
    let mut ctx = node.request_ctx();
    ctx.exclude(DestinationId::new(1));
    assert!(node.pick("p", &members, &mut ctx).is_none());
    assert_eq!(
        ctx.excluded_reasons(),
        &[(DestinationId::new(2), Unavailable::ProbeInFlight)]
    );
    let mut expired = busbar_kernel_egress::RequestCtx::new(0, 0, 0);
    assert!(node.pick("p", &members, &mut expired).is_none());
    assert!(expired.excluded_reasons().is_empty());
}

#[test]
fn only_a_member_at_capacity_spends_a_turn_of_the_rotation() {
    let node = Node::with_lanes(&["a", "b"]);
    let members = vec![
        member(DestinationId::new(0), "a"),
        member(DestinationId::new(1), "b"),
    ];
    node.breaker.set(
        DestinationId::new(0),
        Health {
            cooldown: 30,
            ..Health::default()
        },
    );
    node.capacity.set_ceiling(DestinationId::new(1), 1);
    let held = node.capacity.saturate(DestinationId::new(1));

    let mut ctx = node.request_ctx();
    assert!(node.pick("p", &members, &mut ctx).is_none());
    assert_eq!(
        node.breaker.pick_order(),
        vec![DestinationId::new(1)],
        "the suppressed member was excluded before the rotation, never selected and refused"
    );
    assert_eq!(
        ctx.excluded_reasons(),
        &[(
            DestinationId::new(1),
            Unavailable::AtCapacity {
                drain_hint_ms: None
            }
        )]
    );
    drop(held);
}

fn tiered() -> (Node, Vec<busbar_kernel_egress::pool::Member>) {
    let (node, mut members) = three_lanes();
    for (tier, m) in (0u32..).zip(members.iter_mut()) {
        m.tier = tier;
    }
    (node, members)
}

#[test]
fn the_lowest_tier_takes_every_request_while_it_is_healthy() {
    let (node, members) = tiered();
    for _ in 0..4 {
        let mut ctx = node.request_ctx();
        let picked = node.pick("p", &members, &mut ctx).expect("a member");
        assert_eq!(picked.destination, DestinationId::new(0));
    }
}

#[test]
fn a_suppressed_lower_tier_hands_the_request_to_the_next_tier() {
    let (node, members) = tiered();
    node.breaker.set(
        DestinationId::new(0),
        Health {
            cooldown: 30,
            ..Health::default()
        },
    );
    for _ in 0..3 {
        let mut ctx = node.request_ctx();
        let picked = node.pick("p", &members, &mut ctx).expect("a member");
        assert_eq!(picked.destination, DestinationId::new(1));
    }
}

#[test]
fn members_at_one_tier_keep_the_weighted_rotation() {
    let (node, members) = three_lanes();
    let mut seen = Vec::new();
    for _ in 0..3 {
        let mut ctx = node.request_ctx();
        seen.push(
            node.pick("p", &members, &mut ctx)
                .expect("a member")
                .destination,
        );
    }
    assert_eq!(
        seen,
        vec![
            DestinationId::new(0),
            DestinationId::new(1),
            DestinationId::new(2)
        ]
    );
}
