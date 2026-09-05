// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The identity, under random postings and under a hand-corrupted amount.

use busbar_caps::Usage;

use crate::identity::{closed_window_is_settled, residual};
use crate::settle::Ledger;
use crate::totals::Totals;

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
                    ledger.settle(&k, window, h, &u, &token);
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
    ledger.settle(&k, window, hold("p", 800), &usage("tokens", 500), &token);
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
fn every_column_the_identity_names_is_actually_load_bearing() {
    // A column that could be edited without the identity noticing is a column the identity is not
    // really checking. Each one is nudged in turn.
    let base = Totals {
        drawn: 1_000,
        settled: 400,
        open_holds: 200,
        open_slice_remainders: 400,
        ..Totals::zero()
    };
    assert!(residual(&Totals::zero(), &base).holds());

    let nudge: [fn(&mut Totals); 7] = [
        |t| t.settled += 1,
        |t| t.open_holds += 1,
        |t| t.open_slice_remainders += 1,
        |t| t.unreconciled += 1,
        |t| t.adjustments += 1,
        |t| t.overdraft_carried_out += 1,
        |t| t.cross_window_transfers += 1,
    ];
    for (i, change) in nudge.iter().enumerate() {
        let mut edited = base;
        change(&mut edited);
        assert!(
            !residual(&Totals::zero(), &edited).holds(),
            "column {i} can be edited without the identity noticing"
        );
    }
    // And the right-hand side.
    let mut edited = base;
    edited.drawn += 1;
    assert!(!residual(&Totals::zero(), &edited).holds());
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
    ledger.settle(&k, window, h, &usage("tokens", 140), &token);

    let figures = ledger.book().get(&k, window);
    assert_eq!(figures.settled, 140);
    assert_eq!(figures.overdraft_carried_out, 40);
    assert!(residual(&Totals::zero(), &figures).holds());
}

#[test]
fn the_identity_is_measured_as_a_delta_from_the_last_checkpoint() {
    // The whole point of a checkpoint is that verification does not have to walk history. The case
    // that makes it visible is a checkpoint whose own figures do NOT balance from zero — a migration
    // that sealed an opening balance carried over from a previous release, which was settled without
    // this deployment ever having drawn it. Everything after that point still has to close.
    let since = Totals {
        settled: 3_000,
        ..Totals::zero()
    };
    assert!(
        !residual(&Totals::zero(), &since).holds(),
        "the fixture is only interesting if the opening figures do not balance from zero"
    );

    let mut now = since;
    now.drawn += 1_000;
    now.open_holds += 400;
    now.open_slice_remainders += 600;
    assert!(
        residual(&since, &now).holds(),
        "activity since the checkpoint balances, whatever the checkpoint opened at"
    );
    assert!(
        !residual(&Totals::zero(), &now).holds(),
        "and walking history from zero would report the migration as a hole"
    );
}

#[test]
fn a_closed_window_that_is_still_moving_is_a_different_finding_from_one_that_does_not_balance() {
    let since = Totals {
        drawn: 1_000,
        settled: 1_000,
        ..Totals::zero()
    };
    // Nothing moved: settled.
    assert!(closed_window_is_settled(&since, &since).is_ok());

    // A transfer out, matched by the value leaving the remainder column: still settled, because the
    // window's own figures balance.
    let mut transferred = since;
    transferred.open_slice_remainders -= 100;
    transferred.cross_window_transfers += 100;
    assert!(closed_window_is_settled(&since, &transferred).is_ok());

    // A settlement into a closed window: not settled, by 50.
    let mut posted_late = since;
    posted_late.settled += 50;
    assert_eq!(closed_window_is_settled(&since, &posted_late), Err(50));
}

#[test]
fn cross_window_transfers_close_on_both_sides() {
    let mut ledger = Ledger::new();
    let k = key("windows");
    ledger.record_draw(&k, 100, 900);
    ledger.record_cross_window_transfer(&k, 100, 200, 300);

    assert!(residual(&Totals::zero(), &ledger.book().get(&k, 100)).holds());
    assert!(residual(&Totals::zero(), &ledger.book().get(&k, 200)).holds());
    assert_eq!(ledger.book().get(&k, 100).open_slice_remainders, 600);
    assert_eq!(ledger.book().get(&k, 200).open_slice_remainders, 300);
    // The two transfer columns are equal and opposite, so a transfer recorded on one side only
    // could not pass both checks.
    assert_eq!(
        ledger.book().get(&k, 100).cross_window_transfers,
        -ledger.book().get(&k, 200).cross_window_transfers
    );
}

#[test]
fn an_attribution_bucket_balances_when_everything_accrued_was_posted() {
    assert!(crate::identity::attribution_holds(1_234, 1_234));
    assert!(!crate::identity::attribution_holds(1_234, 1_233));
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
        vec![busbar_caps::UsageLine {
            class: busbar_caps::MeterClassId::new("bytes"),
            quantity: 250,
        }],
    )
    .unwrap();
    let posted = ledger.settle(&k, 1, hold("p", 500), &estimate, &token);
    assert!(posted
        .flags()
        .contains(busbar_caps::PostingFlags::ESTIMATED));
    assert!(residual(&Totals::zero(), &ledger.book().get(&k, 1)).holds());
}
