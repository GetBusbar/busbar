// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-substrate/src/profile.rs`.

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

/// ITEM 571: the bucket store keeps no count of the `Stage` enum, so a stage it has never seen takes
/// a bucket instead of indexing past the end of one.
///
/// The store was an array sized by a hand-kept literal and indexed by a variant's position with no
/// bound; a stage added without editing the literal panicked the first sample of a profiling run, on
/// the request path. Here the LAST declared variant records into a store holding nothing, which is
/// exactly the index the old array had no room for once the enum outgrew its count.
#[test]
fn a_stage_the_store_has_never_seen_takes_a_bucket_instead_of_indexing_past_the_end() {
    let mut store = Vec::new();
    bucket_for(&mut store, Stage::PostSend).record(7);
    bucket_for(&mut store, Stage::MwAuth).record(9);
    bucket_for(&mut store, Stage::PostSend).record(11);
    assert_eq!(
        store.len(),
        2,
        "one bucket per stage that recorded, and no more"
    );
    let (_, post) = store
        .iter()
        .find(|(stage, _)| *stage == Stage::PostSend)
        .expect("the stage that recorded has a bucket");
    assert_eq!(
        post.samples,
        vec![7, 11],
        "both samples land in the same bucket"
    );
    assert_eq!(post.seen, 2);
}
