// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The host-clock to `Instant` bridge: the origin plus the reading, and the host's monotonic
//! distances kept exactly.

use std::time::Duration;

use busbar_contract::mono_instant::instant_at;

#[test]
fn instants_keep_the_host_clock_distances_exactly() {
    let base = instant_at(5_000_000_000);
    let later = instant_at(5_000_000_000 + 1_234_567);
    let earlier = instant_at(5_000_000_000 - 7_000);
    assert_eq!(later.duration_since(base), Duration::from_nanos(1_234_567));
    assert_eq!(base.duration_since(earlier), Duration::from_nanos(7_000));
}

#[test]
fn the_same_reading_always_maps_to_the_same_instant() {
    assert_eq!(instant_at(9_000_000_000), instant_at(9_000_000_000));
}
