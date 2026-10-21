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

        // The ledger's own verbs, every one the node calls. (A release, an adjustment and a
        // cross-window transfer had verbs too; nothing in production called them, so they are
        // deleted and this walk no longer draws them.)
        for step in 0..400u64 {
            match rng.below(3) {
                // Draw from the store.
                0 => ledger.record_draw(&k, window, i128::from(rng.below(10_000) + 1)),
                // Mark something unreconciled, or agree with it again.
                1 => {
                    let amount = i128::from(rng.below(400)) - 200;
                    ledger.record_unreconciled(&k, window, amount);
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
                    ledger.settle_recording(&k, window, h, u128::from(spent), &u, &token);
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
    ledger.settle_recording(
        &k,
        window,
        hold("p", 800),
        500,
        &usage("tokens", 500),
        &token,
    );
    assert!(residual(&opening, &ledger.book().get(&k, window)).holds());

    // One figure, edited in place, the way a tamper would.
    let mut tampered = ledger.book().get(&k, window);
    tampered.settled += 1;
    let r = residual(&opening, &tampered);
    assert!(!r.holds(), "an edited settled amount went undetected");
    assert_eq!(
        r.amount(),
        1,
        "the residual names how far out the books are"
    );

    // And the other direction.
    tampered.settled -= 2;
    assert_eq!(residual(&opening, &tampered).amount(), -1);
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
    ledger.settle_recording(&k, window, h, 140, &usage("tokens", 140), &token);

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
    let posted = ledger
        .settle_recording(&k, 1, hold("p", 500), 250, &estimate, &token)
        .posted;
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
        let posted = live
            .settle_recording(&k, 1, h, u128::from(used), &usage("tokens", used), &token)
            .posted;
        replayed.replay_post(
            &k,
            1,
            "p",
            busbar_kernel_ledger::settle::Figures {
                reserved: posted.reserved(),
                settled: posted.settled(),
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

/// **A POSTING CLOSES THE IDENTITY BY CONSTRUCTION, WHATEVER OVERDRAFT ITS HOLD COUNTED.**
///
/// A hold that counted an overdraft while it ran and then settled at or inside its reservation
/// comes out of `Posted::settle` carrying the counter, not the comparison. The ledger used to book
/// that figure as handed in, so the posting released the unused reservation AND carried an overdraft
/// out, and the identity was out by the counter. The ledger now reckons the overdraft from the
/// posting's own two figures — `settled - reserved`, floored at zero — and takes no other, so the
/// books balance and no overdraft is carried for a posting its reservation covered.
#[test]
fn a_hold_that_counted_an_overdraft_and_settled_inside_its_reservation_still_balances() {
    let mut ledger = Ledger::new();
    let token = ledger_token();
    let k = key("counted-then-covered");
    let window = 1;
    let opening = Totals::zero();

    ledger.record_draw(&k, window, 800);
    ledger.record_hold_opened(&k, window, 800);
    ledger.record_slice_spent(&k, window, 800);
    let mut h = hold("p", 800);
    h.record_overdraft(300);
    let settlement = ledger.settle_recording(&k, window, h, 500, &usage("tokens", 500), &token);

    let after = ledger.book().get(&k, window);
    assert!(
        residual(&opening, &after).holds(),
        "the books are out by the hold's counter: {}",
        residual(&opening, &after)
    );
    assert_eq!(after.overdraft_carried_out, 0, "the reservation covered it");
    assert_eq!(settlement.released, 300);
    assert!(settlement.overdraft.is_none());
}
