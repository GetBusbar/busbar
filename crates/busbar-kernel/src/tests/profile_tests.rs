// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

#[test]
fn bucket_is_bounded_and_tracks_true_count() {
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

#[test]
fn a_stage_the_store_has_never_seen_takes_a_bucket_instead_of_indexing_past_the_end() {
    let mut store = Vec::new();
    bucket_for(&mut store, Stage::Finish).record(7);
    bucket_for(&mut store, Stage::MwAuth).record(9);
    bucket_for(&mut store, Stage::Finish).record(11);
    assert_eq!(
        store.len(),
        2,
        "one bucket per stage that recorded, and no more"
    );
    let (_, post) = store
        .iter()
        .find(|(stage, _)| *stage == Stage::Finish)
        .expect("the stage that recorded has a bucket");
    assert_eq!(
        post.samples,
        vec![7, 11],
        "both samples land in the same bucket"
    );
    assert_eq!(post.seen, 2);
}
