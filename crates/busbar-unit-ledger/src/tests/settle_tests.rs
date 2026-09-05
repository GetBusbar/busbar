// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Settlement, and the dual write onto the previous release's rows.

use crate::legacy::{opening_balances, LegacyHead, LegacyPosting, RecordingRows};
use crate::settle::Ledger;

use super::fixtures::{hold, key, ledger_token, pool_key, usage};

#[test]
fn settling_moves_the_reservation_out_and_the_amount_in() {
    let mut ledger = Ledger::new();
    let token = ledger_token();
    let k = key("b");
    ledger.record_draw(&k, 1, 1_000);
    ledger.record_hold_opened(&k, 1, 600);
    ledger.record_slice_spent(&k, 1, 600);
    assert_eq!(ledger.book().get(&k, 1).open_holds, 600);

    let posted = ledger.settle(&k, 1, hold("alice", 600), &usage("tokens", 450), &token);
    assert_eq!(posted.settled(), 450);
    assert_eq!(posted.reserved(), 600);
    let figures = ledger.book().get(&k, 1);
    assert_eq!(figures.open_holds, 0);
    assert_eq!(figures.settled, 450);
    assert_eq!(
        figures.open_slice_remainders, 550,
        "the 150 that was reserved and not used goes back to the slice"
    );
}

#[test]
fn two_dimensions_on_one_bucket_are_two_independent_balances() {
    use busbar_caps::MeterClassId;
    let mut ledger = Ledger::new();
    let token = ledger_token();
    let money = key("shared");
    let tokens = crate::totals::TotalsKey::new(
        crate::totals::BucketId::new("shared"),
        crate::totals::CapDimension::class(&MeterClassId::new("tokens")),
        crate::totals::BucketScope::All,
    );

    ledger.record_draw(&money, 1, 500);
    ledger.record_hold_opened(&money, 1, 500);
    ledger.record_slice_spent(&money, 1, 500);
    ledger.settle(&money, 1, hold("a", 500), &usage("tokens", 500), &token);

    assert_eq!(ledger.book().get(&money, 1).settled, 500);
    assert_eq!(
        ledger.book().get(&tokens, 1).settled,
        0,
        "a money settlement must not appear in a token balance"
    );
}

#[test]
fn a_pool_scope_is_a_different_balance_from_the_whole_bucket() {
    let mut ledger = Ledger::new();
    let token = ledger_token();
    let all = key("b");
    let pool = pool_key("b", "west");
    ledger.record_draw(&pool, 1, 300);
    ledger.record_hold_opened(&pool, 1, 300);
    ledger.record_slice_spent(&pool, 1, 300);
    ledger.settle(&pool, 1, hold("a", 300), &usage("tokens", 300), &token);

    assert_eq!(ledger.book().get(&pool, 1).settled, 300);
    assert_eq!(ledger.book().get(&all, 1).settled, 0);
}

#[test]
fn every_settlement_reaches_the_previous_releases_rows() {
    let rows = RecordingRows::new();
    let mut ledger = Ledger::dual_writing(Box::new(rows.clone()));
    let token = ledger_token();
    let k = key("legacy");
    ledger.record_draw(&k, 42, 1_000);
    ledger.record_hold_opened(&k, 42, 700);
    ledger.record_slice_spent(&k, 42, 700);
    ledger.settle(&k, 42, hold("bob", 700), &usage("tokens", 690), &token);

    assert_eq!(
        rows.written(),
        vec![LegacyPosting {
            principal: "bob".into(),
            bucket: "legacy".into(),
            window_start: 42,
            reserved: 700,
            settled: 690,
            overdraft: 0,
        }]
    );
}

#[test]
fn a_legacy_row_that_will_not_write_does_not_fail_the_settlement() {
    // The previous release settled. A parity obligation may not stop this one from doing the same.
    struct Refuses;
    impl crate::legacy::LegacyRows for Refuses {
        fn write(
            &mut self,
            _posting: &LegacyPosting,
        ) -> Result<(), crate::legacy::LegacyWriteError> {
            Err(crate::legacy::LegacyWriteError::Unavailable(
                "under test".into(),
            ))
        }
    }
    let mut ledger = Ledger::dual_writing(Box::new(Refuses));
    let token = ledger_token();
    let k = key("b");
    ledger.record_hold_opened(&k, 1, 10);
    let posted = ledger.settle(&k, 1, hold("a", 10), &usage("tokens", 10), &token);
    assert_eq!(posted.settled(), 10);
    assert_eq!(ledger.book().get(&k, 1).settled, 10);
}

#[test]
fn a_ledger_with_no_dual_write_settles_the_same_way() {
    let mut plain = Ledger::new();
    let mut dual = Ledger::dual_writing(Box::new(RecordingRows::new()));
    let token = ledger_token();
    let k = key("b");
    for ledger in [&mut plain, &mut dual] {
        ledger.record_draw(&k, 1, 100);
        ledger.record_hold_opened(&k, 1, 100);
        ledger.record_slice_spent(&k, 1, 100);
        ledger.settle(&k, 1, hold("a", 100), &usage("tokens", 80), &token);
    }
    assert_eq!(plain.book().get(&k, 1), dual.book().get(&k, 1));
}

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
