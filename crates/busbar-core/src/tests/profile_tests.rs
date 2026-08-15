// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar/src/profile.rs`.

use super::*;

#[test]
fn bucket_is_bounded_and_tracks_true_count() {
    // Offer far more samples than the cap; the retained set must never exceed BUCKET_CAP, but the
    // `seen` count must reflect EVERY observation (so the report's `n=` stays truthful).
    let mut b = Bucket::default();
    let offered = BUCKET_CAP * 4 + 123;
    for i in 0..offered {
        b.record(i as u32);
    }
    assert_eq!(
        b.samples.len(),
        BUCKET_CAP,
        "retained samples must be capped at BUCKET_CAP, not grow unbounded"
    );
    assert_eq!(
        b.seen, offered as u64,
        "seen must count all offered samples, not just the retained ones"
    );
}

#[test]
fn bucket_under_cap_keeps_everything() {
    // Below the cap it behaves exactly like the old unbounded Vec: every sample retained, in order.
    let mut b = Bucket::default();
    for i in 0..10u32 {
        b.record(i);
    }
    assert_eq!(b.samples.len(), 10);
    assert_eq!(b.seen, 10);
    assert_eq!(b.samples, (0..10).collect::<Vec<_>>());
}

#[test]
fn reservoir_stays_representative_of_the_range() {
    // Reservoir sampling keeps a uniform subset, so the retained min/max should still span most of
    // the offered range (a first-N cap would freeze the max near BUCKET_CAP). Feed a large ramp and
    // check the retained max lands in the upper reaches - a smoke test that late samples are admitted.
    let mut b = Bucket::default();
    let offered = BUCKET_CAP * 10;
    for i in 0..offered {
        b.record(i as u32);
    }
    let max = *b.samples.iter().max().unwrap();
    assert!(
        max as usize > offered / 2,
        "reservoir must admit late/high samples (max {max} should exceed half of {offered}); a \
             first-N cap would freeze the retained max near BUCKET_CAP"
    );
}
