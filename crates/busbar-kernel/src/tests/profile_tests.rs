// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

#[test]
fn bucket_counts_and_sums_every_sample() {
    let mut b = Bucket::default();
    let offered = 4096 * 4 + 123;
    for i in 0..offered {
        b.record(i);
    }
    assert_eq!(
        b.seen,
        u64::from(offered),
        "seen counts every sample offered"
    );
    assert_eq!(b.sum_ns, (0..u64::from(offered)).sum::<u64>());
    assert_eq!(b.sketch.count(), offered as usize, "no sample is dropped");
}

#[test]
fn the_reported_percentiles_track_late_and_high_samples() {
    let mut b = Bucket::default();
    for us in 1..=10_000u32 {
        b.record(us * 1_000);
    }
    let line = b
        .line(Stage::Finish)
        .expect("a stage that recorded reports");
    assert!(
        line.starts_with("BUSBAR_PROFILE stage=finish n=10000 mean=5000.500 "),
        "{line}"
    );
    let field = |name: &str| -> f64 {
        line.split(' ')
            .find_map(|kv| kv.strip_prefix(name))
            .expect("field present")
            .parse()
            .expect("a number")
    };
    for (name, truth) in [("p50=", 5_000.0), ("p99=", 9_900.0)] {
        let got = field(name);
        assert!(
            (got - truth).abs() <= truth / 100.0,
            "{name}{got}, true {truth}"
        );
    }
}

#[test]
fn a_stage_that_recorded_nothing_prints_no_line() {
    assert_eq!(Bucket::default().line(Stage::MwAuth), None);
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
    assert_eq!(post.sum_ns, 7 + 11, "both samples land in the same bucket");
    assert_eq!(post.seen, 2);
}
