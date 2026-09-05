// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Slices, the epoch fence, the all-or-nothing chain draw, and the leases that come back on every
//! end.

use busbar_caps::{OriginKind, ReasonCode};
use busbar_kernel::slice::{
    overdraft, takes_lease, BucketId, BucketScope, CapDimension, ConcurrencyGauge, Draw, Epoch,
    LeaseSet, Overdraft, Posture, SliceBook, SliceGrant, SliceId,
};

fn grant(granted: u64, valid_until: u64, epoch: u64) -> SliceGrant {
    SliceGrant {
        id: SliceId(1),
        granted,
        valid_until,
        epoch: Epoch(epoch),
    }
}

#[test]
fn a_draw_that_fits_is_local_and_one_that_does_not_asks_the_store() {
    let mut book = SliceBook::new();
    let bucket = BucketId::all("team");
    book.install(
        bucket.clone(),
        CapDimension::NanoUnits,
        grant(1_000, 60_000, 1),
    );

    assert_eq!(
        book.draw(
            &bucket,
            &CapDimension::NanoUnits,
            600,
            0,
            Epoch(1),
            Posture::Normal
        ),
        Draw::Granted
    );
    assert_eq!(
        book.draw(
            &bucket,
            &CapDimension::NanoUnits,
            600,
            0,
            Epoch(1),
            Posture::Normal
        ),
        Draw::NeedReserve { shortfall: 200 }
    );
}

#[test]
fn a_slice_behind_the_fleets_epoch_cannot_be_spent() {
    let mut book = SliceBook::new();
    let bucket = BucketId::all("team");
    book.install(
        bucket.clone(),
        CapDimension::NanoUnits,
        grant(1_000, 60_000, 1),
    );
    assert_eq!(
        book.draw(
            &bucket,
            &CapDimension::NanoUnits,
            10,
            0,
            Epoch(2),
            Posture::Normal
        ),
        Draw::Stale,
        "the other side of the partition has moved on"
    );
}

#[test]
fn an_expired_slice_stays_spendable_through_a_store_outage_but_not_otherwise() {
    let mut book = SliceBook::new();
    let bucket = BucketId::all("team");
    book.install(
        bucket.clone(),
        CapDimension::NanoUnits,
        grant(1_000, 100, 1),
    );

    // Normally an expired slice is stale.
    assert_eq!(
        book.draw(
            &bucket,
            &CapDimension::NanoUnits,
            10,
            200,
            Epoch(1),
            Posture::Normal
        ),
        Draw::Stale
    );
    // Through an outage it is still spendable: the store accounts it as drawn, so no other node can
    // have it, and refusing here would refuse units the fleet has already paid for.
    assert_eq!(
        book.draw(
            &bucket,
            &CapDimension::NanoUnits,
            10,
            200,
            Epoch(1),
            Posture::Outage
        ),
        Draw::Granted
    );
}

#[test]
fn a_chain_draw_is_all_or_nothing_and_the_refusal_releases_what_was_taken() {
    let mut book = SliceBook::new();
    let child = BucketId::all("child");
    let parent = BucketId::all("parent");
    book.install(
        child.clone(),
        CapDimension::NanoUnits,
        grant(1_000, 60_000, 1),
    );
    book.install(
        parent.clone(),
        CapDimension::NanoUnits,
        grant(10, 60_000, 1),
    );

    let refused = book
        .draw_chain(
            &[
                (child.clone(), CapDimension::NanoUnits, 500),
                (parent.clone(), CapDimension::NanoUnits, 500),
            ],
            0,
            Epoch(1),
            Posture::Normal,
        )
        .expect_err("the parent bucket has no headroom");
    assert_eq!(refused.at, 1);
    assert_eq!(refused.bucket, parent);

    // The child's slice was given straight back: a half-drawn chain is money in one place and not
    // another.
    assert_eq!(
        book.get(&child, &CapDimension::NanoUnits).map(|s| s.spent),
        Some(0)
    );
}

#[test]
fn a_chain_that_fits_draws_every_line() {
    let mut book = SliceBook::new();
    let child = BucketId::all("child");
    let parent = BucketId::all("parent");
    book.install(
        child.clone(),
        CapDimension::NanoUnits,
        grant(1_000, 60_000, 1),
    );
    book.install(
        parent.clone(),
        CapDimension::NanoUnits,
        grant(1_000, 60_000, 1),
    );
    assert!(book
        .draw_chain(
            &[
                (child.clone(), CapDimension::NanoUnits, 500),
                (parent.clone(), CapDimension::NanoUnits, 500),
            ],
            0,
            Epoch(1),
            Posture::Normal,
        )
        .is_ok());
    assert_eq!(
        book.get(&parent, &CapDimension::NanoUnits).map(|s| s.spent),
        Some(500)
    );
}

#[test]
fn a_scoped_bucket_draws_only_for_the_pool_it_names() {
    let scoped = BucketId::pool("team", "fast");
    assert!(scoped.draws_for(Some("fast")));
    assert!(
        !scoped.draws_for(Some("slow")),
        "a fallback hop draws nothing"
    );
    assert!(!scoped.draws_for(None));
    assert!(BucketId::all("team").draws_for(Some("anything")));
    assert_eq!(scoped.scope, BucketScope::Pool("fast".into()));
}

#[test]
fn a_draw_on_a_scope_the_unit_did_not_route_through_is_given_back() {
    let mut book = SliceBook::new();
    let bucket = BucketId::pool("team", "fast");
    book.install(bucket.clone(), CapDimension::Requests, grant(10, 60_000, 1));
    assert_eq!(
        book.draw(
            &bucket,
            &CapDimension::Requests,
            1,
            0,
            Epoch(1),
            Posture::Normal
        ),
        Draw::Granted
    );
    book.give_back(&bucket, &CapDimension::Requests, 1);
    assert_eq!(
        book.get(&bucket, &CapDimension::Requests).map(|s| s.spent),
        Some(0)
    );
}

#[test]
fn only_the_dimensions_that_accrue_mid_unit_can_overdraw() {
    assert!(CapDimension::NanoUnits.accrues_mid_unit());
    assert!(CapDimension::Class(busbar_caps::MeterClassId::new("tokens")).accrues_mid_unit());
    // These two are known at the door, so there is nothing left to discover about them.
    assert!(!CapDimension::Requests.accrues_mid_unit());
    assert!(!CapDimension::Concurrent.accrues_mid_unit());
}

#[test]
fn running_out_mid_unit_carries_rather_than_refusing() {
    assert_eq!(overdraft(false, false), Overdraft::ContinueAndCarry);
    // A window that never rolls has no next window to carry into.
    assert_eq!(overdraft(true, false), Overdraft::ContinueNoCarry);
    // The ceiling is the hard bound, and it is the only one that stops anything.
    assert_eq!(overdraft(false, true), Overdraft::Ceiling);
}

#[test]
fn the_gauge_counts_units_and_gives_the_lease_back() {
    let gauge = ConcurrencyGauge::new();
    let bucket = BucketId::all("team");
    let mut leases = LeaseSet::new();

    gauge.acquire(&bucket, 2).expect("room");
    leases.take(bucket.clone());
    gauge.acquire(&bucket, 2).expect("room");
    assert_eq!(gauge.count(&bucket), 2);
    assert_eq!(gauge.acquire(&bucket, 2), Err(ReasonCode::OverBudget));

    assert_eq!(leases.release_all(&gauge), 1);
    assert_eq!(gauge.count(&bucket), 1);
    assert!(leases.is_empty());
}

#[test]
fn the_administrative_surface_answers_at_a_saturated_concurrency_cap() {
    // A kernel-verb unit takes no lease, which is what makes the audit and usage surfaces answer at
    // exactly the moment an operator most needs them to.
    assert!(!takes_lease(OriginKind::Client, true));
    // Ticks and handshakes take none either: no money moves in them.
    assert!(!takes_lease(OriginKind::Tick, false));
    assert!(!takes_lease(OriginKind::Handshake, false));
    // Everything else does, including the nested, delivery and provider units.
    assert!(takes_lease(OriginKind::Client, false));
    assert!(takes_lease(OriginKind::Provider, false));
    assert!(takes_lease(
        OriginKind::Nested {
            parent: busbar_caps::UnitKey::new(1)
        },
        false
    ));
}
