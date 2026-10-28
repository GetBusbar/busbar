// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Settlement, and the dual write onto the previous release's rows.

use crate::migration::{opening_balances, MigrationHead};

#[test]
fn an_empty_legacy_head_opens_at_zero_rather_than_refusing() {
    // A store that keeps nothing across a restart, and an older store that cannot answer, both give
    // an empty head. Neither may stop the node.
    let head = MigrationHead::empty();
    assert!(head.is_empty());
    assert!(opening_balances(&head, 7).is_empty());
}

#[test]
fn a_legacy_head_with_balances_opens_one_entry_per_bucket_at_the_named_card() {
    let head = MigrationHead {
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

/// **THE BOOK AND THE DUAL-WRITE ROWS ARE BOUNDED TOGETHER, AT 1.5.5'S HORIZON.**
///
/// Before this, every window a node settled into stayed in the book and in the summed rows for the
/// life of the process. A window past the thirty-one-day horizon that a checkpoint sealed at the
/// book's own figures now leaves both in one step, and every balance and row inside the horizon —
/// and the all-time window, which never ages — reads exactly what it read before.
#[test]
fn a_sealed_window_past_the_horizon_leaves_the_book_and_the_rows_and_nothing_inside_it_moves() {
    use crate::checkpoint::Checkpoint;
    use crate::legacy::SummedRows;
    use crate::settle::{Figures, Ledger};
    use crate::totals::{Totals, ALL_TIME_WINDOW, WINDOW_RETENTION_SECS};

    use super::fixtures::key;

    const DAY: u64 = 86_400;
    let old = DAY;
    let recent = 30 * DAY;
    let now = old + WINDOW_RETENTION_SECS;

    let rows = SummedRows::new();
    let mut ledger = Ledger::dual_writing(Box::new(rows.clone()));
    for window in [ALL_TIME_WINDOW, old, recent] {
        for principal in ["p1", "p2"] {
            ledger.record_hold_opened(&key("b"), window, 100);
            ledger.replay_post(
                &key("b"),
                window,
                principal,
                Figures {
                    reserved: 100,
                    settled: 60,
                    fee_count: 1,
                },
            );
        }
    }
    assert_eq!(ledger.book().len(), 3);
    assert_eq!(rows.len(), 6, "a row per principal, bucket and window");
    let book_inside: Vec<_> = ledger
        .book()
        .iter()
        .filter(|((_, window), _)| *window != old)
        .map(|(at, figures)| (at.clone(), *figures))
        .collect();
    let rows_inside: Vec<_> = rows
        .rows()
        .into_iter()
        .filter(|row| row.window_start != old)
        .collect();

    let sealed = Checkpoint::seal(1, 1, now, Vec::new(), ledger.book().snapshot(), 0, 0, None)
        .expect("an unsigned checkpoint seals");

    assert!(
        ledger.retirable(&sealed, now - 1).is_empty(),
        "a second inside the horizon, nothing goes"
    );
    assert_eq!(ledger.book().len(), 3);
    assert_eq!(rows.len(), 6);

    let retired = ledger.retirable(&sealed, now);
    assert_eq!(retired.iter().copied().collect::<Vec<_>>(), vec![old]);
    assert_eq!(ledger.book().len(), 3, "naming the windows moves nothing");
    assert_eq!(ledger.retire_windows(&retired), 1);
    assert_eq!(ledger.book().get(&key("b"), old), Totals::zero());
    assert_eq!(
        rows.len(),
        4,
        "the old window's two rows went with its balance"
    );

    let book_after: Vec<_> = ledger
        .book()
        .iter()
        .map(|(at, figures)| (at.clone(), *figures))
        .collect();
    assert_eq!(
        book_after, book_inside,
        "every balance inside the horizon is unchanged"
    );
    assert_eq!(
        rows.rows(),
        rows_inside,
        "every row inside the horizon is unchanged"
    );

    // Long after, the rolling window goes too; the all-time window never does.
    let after_a_year = ledger.retirable(&sealed, u64::MAX);
    assert_eq!(
        after_a_year.iter().copied().collect::<Vec<_>>(),
        vec![recent]
    );
    ledger.retire_windows(&after_a_year);
    assert_eq!(ledger.book().len(), 1);
    assert_eq!(rows.len(), 2);
    assert!(ledger
        .book()
        .iter()
        .all(|((_, w), _)| *w == ALL_TIME_WINDOW));
}
