// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The identity, under random postings and under a hand-corrupted amount.

use busbar_contract::caps::{QuantitySource, Usage};

use busbar_kernel_ledger::identity::residual;
use busbar_kernel_ledger::settle::Ledger;
use busbar_kernel_ledger::totals::Totals;

use super::fixtures::{hold, key, ledger_token, usage, usage_token, Rng};

#[test]
fn the_identity_holds_over_a_long_run_of_random_postings() {
    for seed in [1u64, 7, 99, 1234, 987654321] {
        let mut rng = Rng::seeded(seed);
        let mut ledger = Ledger::new();
        let token = ledger_token();
        let k = key("random");
        let window = 1_000;
        let opening = Totals::zero();

        for step in 0..400u64 {
            match rng.below(6) {
                // Draw from the store.
                0 => ledger.record_draw(&k, window, i128::from(rng.below(10_000) + 1)),
                // Give some back.
                1 => {
                    let held = ledger.book().get(&k, window).open_slice_remainders;
                    if held > 0 {
                        let give = i128::from(rng.below(u64::try_from(held).unwrap_or(1)));
                        ledger.record_release(&k, window, give);
                    }
                }
                // Correct something.
                2 => {
                    let amount = i128::from(rng.below(500)) - 250;
                    ledger.record_adjustment(&k, window, amount);
                }
                // Mark something unreconciled, or agree with it again.
                3 => {
                    let amount = i128::from(rng.below(400)) - 200;
                    ledger.record_unreconciled(&k, window, amount);
                }
                // Move value to the next window and back.
                4 => {
                    let amount = i128::from(rng.below(300));
                    ledger.record_cross_window_transfer(&k, window, window + 1, amount);
                }
                // Open a hold, spend some of it, settle.
                _ => {
                    let reserved = rng.below(2_000) + 1;
                    let spent = rng.below(reserved * 2 + 1);
                    ledger.record_hold_opened(&k, window, reserved);
                    ledger.record_slice_spent(&k, window, i128::from(reserved));
                    let mut h = hold("p", reserved);
                    // Spending past the reservation is an overdraft, which the hold records for
                    // itself; the identity has to close either way.
                    if spent > reserved {
                        h.record_overdraft(spent - reserved);
                    }
                    let u = usage("tokens", spent);
                    ledger.settle(&k, window, h, u128::from(spent), &u, &token);
                }
            }
            let r = residual(&opening, &ledger.book().get(&k, window));
            assert!(
                r.holds(),
                "seed {seed}, step {step}: the books stopped balancing — {r}"
            );
        }
    }
}

#[test]
fn a_hand_corrupted_priced_amount_breaks_the_identity() {
    // The point of the identity is that somebody cannot quietly change what was settled. So change
    // it, by hand, in the books, and check that the identity notices.
    let mut ledger = Ledger::new();
    let token = ledger_token();
    let k = key("corrupt");
    let window = 1;
    let opening = Totals::zero();

    ledger.record_draw(&k, window, 1_000);
    ledger.record_hold_opened(&k, window, 800);
    ledger.record_slice_spent(&k, window, 800);
    ledger.settle(
        &k,
        window,
        hold("p", 800),
        500,
        &usage("tokens", 500),
        &token,
    );
    assert!(residual(&opening, &ledger.book().get(&k, window)).holds());

    // One figure, edited in place, the way a tamper would.
    ledger.book_mut().entry(k.clone(), window).settled += 1;
    let r = residual(&opening, &ledger.book().get(&k, window));
    assert!(!r.holds(), "an edited settled amount went undetected");
    assert_eq!(
        r.amount(),
        1,
        "the residual names how far out the books are"
    );

    // And the other direction.
    ledger.book_mut().entry(k.clone(), window).settled -= 2;
    assert_eq!(
        residual(&opening, &ledger.book().get(&k, window)).amount(),
        -1
    );
}

#[test]
fn overdraft_is_subtracted_rather_than_added() {
    // Spending past the reservation means value that was never drawn. If the identity added it,
    // an overdraft would look like a hole in the books.
    let mut ledger = Ledger::new();
    let token = ledger_token();
    let k = key("overdrawn");
    let window = 1;

    ledger.record_draw(&k, window, 100);
    ledger.record_hold_opened(&k, window, 100);
    ledger.record_slice_spent(&k, window, 100);
    let mut h = hold("p", 100);
    h.record_overdraft(40);
    ledger.settle(&k, window, h, 140, &usage("tokens", 140), &token);

    let figures = ledger.book().get(&k, window);
    assert_eq!(figures.settled, 140);
    assert_eq!(figures.overdraft_carried_out, 40);
    assert!(residual(&Totals::zero(), &figures).holds());
}

#[test]
fn an_estimated_usage_report_still_settles_and_still_balances() {
    let mut ledger = Ledger::new();
    let token = ledger_token();
    let k = key("estimated");
    ledger.record_draw(&k, 1, 500);
    ledger.record_hold_opened(&k, 1, 500);
    ledger.record_slice_spent(&k, 1, 500);
    let estimate = Usage::estimate(
        &usage_token(),
        vec![busbar_contract::caps::UsageLine {
            class: busbar_contract::caps::MeterClassId::new("bytes"),
            quantity: 250,
            source: QuantitySource::Count,
            estimated: false,
        }],
    )
    .unwrap();
    let posted = ledger.settle(&k, 1, hold("p", 500), 250, &estimate, &token);
    assert!(posted
        .flags()
        .contains(busbar_contract::caps::PostingFlags::ESTIMATED));
    assert!(residual(&Totals::zero(), &ledger.book().get(&k, 1)).holds());
}

/// ITEMS 127/128: a posting REPLAYED off the journal moves the book exactly as the live posting did.
///
/// A restart rebuilds the book by replaying what the journal holds, and a replay that moved the
/// figures by a second copy of the arithmetic would be a second answer to the identity. Both doors
/// go through one function; this says so with the figures, including an overdraft and the dual
/// write the reconciliation reads.
#[test]
fn a_replayed_posting_moves_the_book_exactly_as_the_live_one_did() {
    let token = ledger_token();
    let k = key("replayed");
    for (reserved, used) in [(1_000u64, 900u64), (500, 800), (0, 0), (0, 250)] {
        let live_rows = busbar_kernel_ledger::legacy::RecordingRows::new();
        let replay_rows = busbar_kernel_ledger::legacy::RecordingRows::new();
        let mut live = Ledger::dual_writing(Box::new(live_rows.clone()));
        let mut replayed = Ledger::dual_writing(Box::new(replay_rows.clone()));
        let mut h = hold("p", reserved);
        if used > reserved {
            h.record_overdraft(used - reserved);
        }
        let posted = live.settle(&k, 1, h, u128::from(used), &usage("tokens", used), &token);
        replayed.replay_post(
            &k,
            1,
            "p",
            busbar_kernel_ledger::settle::Figures {
                reserved: posted.reserved(),
                settled: posted.settled(),
                overdraft: posted.overdraft(),
                fee_count: 0,
            },
        );
        assert_eq!(
            live.book().snapshot(),
            replayed.book().snapshot(),
            "{reserved}/{used}"
        );
        assert_eq!(
            live_rows.written(),
            replay_rows.written(),
            "the dual write is fed on replay as it was live"
        );
    }
}

/// ITEM 26 (a deletion, so the replacing behaviour is asserted): `record_adjustment_releasing` had
/// no caller anywhere — not in production and not in a test — and is gone. A correction is
/// `record_adjustment`: it moves value between `settled` and `adjustments` and hands NOTHING back to
/// the store, so `drawn` and the slice do not move and the identity stays closed.
#[test]
fn a_correction_moves_settled_into_adjustments_and_releases_nothing() {
    let token = ledger_token();
    let mut ledger = Ledger::new();
    let k = key("corrected");
    ledger.record_draw(&k, 1, 1_000);
    ledger.record_hold_opened(&k, 1, 1_000);
    ledger.record_slice_spent(&k, 1, 1_000);
    ledger.settle(&k, 1, hold("p", 1_000), 800, &usage("tokens", 800), &token);
    let before = ledger.book().get(&k, 1);

    ledger.record_adjustment(&k, 1, 300);
    let after = ledger.book().get(&k, 1);
    assert_eq!(after.settled, before.settled - 300);
    assert_eq!(after.adjustments, before.adjustments + 300);
    assert_eq!(
        after.drawn, before.drawn,
        "a correction releases nothing to the store"
    );
    assert_eq!(after.released, before.released);
    assert_eq!(after.open_slice_remainders, before.open_slice_remainders);
    assert!(residual(&Totals::zero(), &after).holds());
}
