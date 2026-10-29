// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The leases that come back on every end.

use busbar_contract::caps::{OriginKind, ReasonCode};
use busbar_kernel::slice::{bucket_all, takes_lease, ConcurrencyGauge, LeaseSet};

#[test]
fn the_gauge_counts_units_and_gives_the_lease_back() {
    let gauge = ConcurrencyGauge::new();
    let bucket = bucket_all("team");
    let mut leases = LeaseSet::new();

    gauge.acquire(&bucket, 2).expect("room");
    leases.take(bucket);
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
            parent: busbar_contract::caps::UnitKey::new(1)
        },
        false
    ));
}
