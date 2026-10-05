// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Settlement, and the dual write onto the previous release's rows.

use crate::legacy::{opening_balances, LegacyHead};

#[test]
fn an_empty_legacy_head_opens_at_zero_rather_than_refusing() {
    // A store that keeps nothing across a restart, and an older store that cannot answer, both give
    // an empty head. Neither may stop the node.
    let head = LegacyHead::empty();
    assert!(head.is_empty());
    assert!(opening_balances(&head, 7).is_empty());
}

#[test]
fn a_legacy_head_with_balances_opens_one_entry_per_bucket_at_the_named_card() {
    let head = LegacyHead {
        seq: Some(9_182),
        hash: Some("abc".into()),
        balances: vec![("free".into(), 0), ("paid".into(), 12_345)],
        cells_read: 2,
    };
    let opened = opening_balances(&head, 3);
    assert_eq!(opened.len(), 2);
    assert_eq!(opened[1].bucket, "paid");
    assert_eq!(opened[1].amount, 12_345);
    assert!(opened.iter().all(|o| o.rate_card_version == 3));
}

fn posting(principal: &str, bucket: &str, window_start: u64, n: u64) -> crate::LegacyPosting {
    crate::LegacyPosting {
        principal: principal.into(),
        bucket: bucket.into(),
        window_start,
        reserved: 10 + n,
        settled: 7 + n,
        overdraft: n % 3,
        fee_count: n % 2,
    }
}

/// **THE PRODUCTION DUAL WRITE HOLDS ONE ROW PER CELL, NOT ONE PER POSTING.**
///
/// The recorder the node used to bind kept every posting for the life of the process. The summing
/// binding keeps a row per (principal, bucket, window), and what its one reader folds — a sum per
/// bucket and window — comes out the same as summing every posting the recorder kept.
#[test]
fn the_summed_rows_hold_one_row_per_cell_and_fold_to_the_recorders_sums() {
    use crate::legacy::{LegacyRows, RecordingRows, SummedRows};
    use std::collections::BTreeMap;

    let recorded = RecordingRows::new();
    let summed = SummedRows::new();
    let (mut r, mut s) = (recorded.clone(), summed.clone());
    let cells = [
        ("p1", "b1", 10u64),
        ("p1", "b1", 20),
        ("p2", "b1", 10),
        ("p1", "b2", 10),
    ];
    for n in 0..1_000u64 {
        let (principal, bucket, window) = cells[(n % 4) as usize];
        let p = posting(principal, bucket, window, n);
        r.write(&p).unwrap();
        s.write(&p).unwrap();
    }

    assert_eq!(recorded.written().len(), 1_000);
    assert_eq!(
        summed.len(),
        cells.len(),
        "one row per cell, whatever the traffic"
    );

    type Sums = BTreeMap<(String, u64), (u64, u64, u64, u64)>;
    let sum = |sums: &mut Sums, p: &crate::LegacyPosting| {
        let e = sums.entry((p.bucket.clone(), p.window_start)).or_default();
        e.0 += p.reserved;
        e.1 += p.settled;
        e.2 += p.overdraft;
        e.3 += p.fee_count;
    };
    let (mut from_recorder, mut from_sums) = (Sums::new(), Sums::new());
    recorded.fold_written(&mut |p| sum(&mut from_recorder, p));
    summed.fold_rows(&mut |p| sum(&mut from_sums, p));
    assert_eq!(from_sums, from_recorder);
    assert_eq!(summed.rows().len(), cells.len());
}

/// A cell's figures saturate at their bound rather than wrapping to a small number that looks true.
#[test]
fn a_summed_row_saturates_rather_than_wrapping() {
    use crate::legacy::{LegacyRows, SummedRows};
    let summed = SummedRows::new();
    let mut s = summed.clone();
    let mut big = posting("p", "b", 1, 0);
    big.settled = u64::MAX;
    s.write(&big).unwrap();
    s.write(&big).unwrap();
    assert_eq!(summed.rows()[0].settled, u64::MAX);
}
