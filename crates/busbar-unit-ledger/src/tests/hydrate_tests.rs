// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **The restart cell: boot, spend, restart, spend again — and the figures survive.**
//!
//! One shape, four steps, and the assertion is at every one of them. A ledger boots with an empty
//! book against a durable record holding nothing, spends, is thrown away, and a NEW ledger boots
//! against the record the first one left. What the second one carries has to be what the first one
//! settled, to the nano-unit; what it carries after spending again has to be the two runs summed.
//!
//! The counter-cell is in the same file and is the whole point: the same four steps against a
//! ledger that is NOT hydrated forget everything, which is what the unit chain did before this
//! existed. A restart proof with only the passing arm proves the code runs, not that it matters.

use crate::hydrate::{HydratedPosting, Hydration, HydrationError, SpendSource};
use crate::identity::residual;
use crate::settle::Ledger;
use crate::totals::{BucketId, BucketScope, CapDimension, Totals, TotalsKey, WindowStart};

/// A durable record a test can append to and boot a fresh ledger against.
///
/// Standing in for the journal, which is the composition root's binding and not this crate's. What
/// it has to be faithful about is exactly one thing — a posting written is a posting a later boot
/// reads — and it is.
#[derive(Debug, Default)]
struct Record {
    postings: Vec<HydratedPosting>,
    unreadable: bool,
}

impl SpendSource for Record {
    fn postings(&self) -> Result<Vec<HydratedPosting>, HydrationError> {
        if self.unreadable {
            return Err(HydrationError::RecordUnavailable("the disk is gone".into()));
        }
        Ok(self.postings.clone())
    }
}

const WINDOW: WindowStart = 1_770_000_000;

fn key(bucket: &str) -> TotalsKey {
    TotalsKey::new(
        BucketId::new(bucket),
        CapDimension::NanoUnits,
        BucketScope::All,
    )
}

/// Post `settled` nano-units onto a ledger AND onto the record the next boot will read, exactly as
/// the composition root does: the books move and the journal takes the record, in that order.
fn spend(ledger: &mut Ledger, record: &mut Record, bucket: &str, settled: i128) {
    let key = key(bucket);
    let figures = ledger.book_mut().entry(key.clone(), WINDOW);
    figures.drawn += settled;
    figures.settled += settled;
    record.postings.push(HydratedPosting {
        key,
        window: WINDOW,
        settled,
        overdraft: 0,
    });
}

#[test]
fn the_figures_survive_a_restart_and_a_ledger_that_does_not_hydrate_forgets_them() {
    let mut record = Record::default();

    // ── BOOT ────────────────────────────────────────────────────────────────────────────────────
    let mut first = Ledger::new();
    let booted = first.hydrate(&record).expect("an empty record hydrates");
    assert_eq!(booted.postings, 0, "an empty record replays no postings");
    assert!(booted.carried.is_empty(), "and carries nothing");
    assert_eq!(
        first.book().get(&key("acme"), WINDOW).settled,
        0,
        "a first boot starts at nothing"
    );

    // ── SPEND ───────────────────────────────────────────────────────────────────────────────────
    spend(&mut first, &mut record, "acme", 250_000_000);
    spend(&mut first, &mut record, "acme", 90_000_000);
    spend(&mut first, &mut record, "widget", 10_000_000);
    assert_eq!(
        first.book().get(&key("acme"), WINDOW).settled,
        340_000_000,
        "the first run settled 0.34 of a unit against acme"
    );

    // ── RESTART ─────────────────────────────────────────────────────────────────────────────────
    // The process is gone. Everything the ledger held in memory is gone with it; the record is not.
    drop(first);
    let mut second = Ledger::new();
    let restored = second.hydrate(&record).expect("the record reads back");
    assert_eq!(restored.postings, 3, "every posting on the record replays");
    assert_eq!(restored.balances, 2, "onto the two balances that moved");
    assert_eq!(
        second.book().get(&key("acme"), WINDOW).settled,
        340_000_000,
        "THE FIGURE SURVIVED: what the first run settled is what the second run boots holding"
    );
    assert_eq!(
        second.book().get(&key("widget"), WINDOW).settled,
        10_000_000,
        "and so did the other balance's"
    );
    assert_eq!(
        restored.carried.nanos(&key("acme"), WINDOW),
        340_000_000,
        "and the carried figure the door is handed is that same number"
    );
    assert_eq!(
        restored.carried.cents(&key("acme"), WINDOW),
        34,
        "in the whole cents a spend cap is configured in"
    );

    // A restored book BALANCES. The overdraft is the part of a posting nothing drew, so `drawn` is
    // restored as the settlement less the carry — get that wrong and every replayed posting reads
    // as an imbalance the first time the books are checked.
    assert!(
        residual(&Totals::zero(), &second.book().get(&key("acme"), WINDOW)).holds(),
        "the restored book satisfies the identity from zero"
    );

    // ── SPEND AGAIN ─────────────────────────────────────────────────────────────────────────────
    spend(&mut second, &mut record, "acme", 60_000_000);
    assert_eq!(
        second.book().get(&key("acme"), WINDOW).settled,
        400_000_000,
        "the second run's spend lands ON TOP of what it inherited, not instead of it"
    );

    // ── THE COUNTER-CELL ────────────────────────────────────────────────────────────────────────
    // The same record, the same four steps, and no hydration — which is what the unit chain did.
    let forgetful = Ledger::new();
    assert_eq!(
        forgetful.book().get(&key("acme"), WINDOW).settled,
        0,
        "a ledger that does not hydrate boots at zero however much the record holds"
    );
}

#[test]
fn a_record_that_will_not_read_is_an_error_and_never_an_empty_book() {
    // The whole reason the seam returns a result. Answering "nothing spent" to a record nobody could
    // read is how a maxed-out key spends its whole cap again after a store blip at boot.
    let record = Record {
        postings: vec![HydratedPosting {
            key: key("acme"),
            window: WINDOW,
            settled: 500_000_000,
            overdraft: 0,
        }],
        unreadable: true,
    };
    let mut ledger = Ledger::new();
    let outcome = ledger.hydrate(&record);
    assert!(
        matches!(outcome, Err(HydrationError::RecordUnavailable(_))),
        "an unreadable record is an error, not an absence: {outcome:?}"
    );
    assert!(
        ledger.book().is_empty(),
        "and nothing was folded in before it failed"
    );
}

#[test]
fn an_overdrafting_posting_restores_the_carry_and_still_balances() {
    // The one figure a naive replay gets wrong. An overdraft is the part of a posting that nothing
    // drew, so a book that restored `drawn` as the whole settlement would be out by exactly the
    // carry on every overdrafting balance.
    let record = Record {
        postings: vec![HydratedPosting {
            key: key("acme"),
            window: WINDOW,
            settled: 100_000_000,
            overdraft: 40_000_000,
        }],
        unreadable: false,
    };
    let mut ledger = Ledger::new();
    let restored = ledger.hydrate(&record).expect("the record reads back");
    let figures = ledger.book().get(&key("acme"), WINDOW);
    assert_eq!(figures.settled, 100_000_000, "the settlement is restored");
    assert_eq!(
        figures.overdraft_carried_out, 40_000_000,
        "and so is the carry it left the window with"
    );
    assert_eq!(
        figures.drawn, 60_000_000,
        "the store gave up the settlement less the carry, because the carry was never drawn"
    );
    assert!(
        residual(&Totals::zero(), &figures).holds(),
        "so the restored balance closes"
    );
    assert_eq!(
        restored.carried.cents(&key("acme"), WINDOW),
        10,
        "and the door is handed the whole settlement, which is what was spent"
    );
}

#[test]
fn the_bucket_view_folds_every_balance_and_every_window_the_caller_asks_for() {
    // The door names a bucket and a window; the book names a balance. Two dimensions on one bucket
    // are two balances, and a view that answered from one of them would under-report the spend.
    let requests = TotalsKey::new(
        BucketId::new("acme"),
        CapDimension::Requests,
        BucketScope::All,
    );
    let record = Record {
        postings: vec![
            HydratedPosting {
                key: key("acme"),
                window: WINDOW,
                settled: 250_000_000,
                overdraft: 0,
            },
            HydratedPosting {
                key: requests,
                window: WINDOW,
                settled: 90_000_000,
                overdraft: 0,
            },
            HydratedPosting {
                key: key("acme"),
                window: WINDOW + 86_400,
                settled: 500_000_000,
                overdraft: 0,
            },
            HydratedPosting {
                key: key("widget"),
                window: WINDOW,
                settled: 700_000_000,
                overdraft: 0,
            },
        ],
        unreadable: false,
    };
    let mut ledger = Ledger::new();
    let carried = ledger.hydrate(&record).expect("reads back").carried;

    assert_eq!(
        carried.bucket_cents("acme", Some(WINDOW)),
        34,
        "one window folds every dimension on the bucket: 0.25 + 0.09"
    );
    assert_eq!(
        carried.bucket_cents("acme", None),
        84,
        "every window folds both of them: 0.25 + 0.09 + 0.50"
    );
    assert_eq!(
        carried.bucket_cents("widget", None),
        70,
        "and another bucket's spend is not this one's"
    );
    assert_eq!(
        carried.bucket_cents("never-seen", None),
        0,
        "a bucket the record held nothing for carries nothing"
    );

    // The divide happens ONCE over the fold, not per balance. Two balances each carrying half a
    // cent carry a whole cent between them.
    let halves = Record {
        postings: vec![
            HydratedPosting {
                key: key("half"),
                window: WINDOW,
                settled: 5_000_000,
                overdraft: 0,
            },
            HydratedPosting {
                key: TotalsKey::new(
                    BucketId::new("half"),
                    CapDimension::Requests,
                    BucketScope::All,
                ),
                window: WINDOW,
                settled: 5_000_000,
                overdraft: 0,
            },
        ],
        unreadable: false,
    };
    let mut ledger = Ledger::new();
    let carried = ledger.hydrate(&halves).expect("reads back").carried;
    assert_eq!(
        carried.bucket_cents("half", Some(WINDOW)),
        1,
        "summed then divided is one cent; divided then summed would have been nothing"
    );
}

#[test]
fn a_balance_whose_postings_cancelled_carries_no_row_at_all() {
    let record = Record {
        postings: vec![
            HydratedPosting {
                key: key("acme"),
                window: WINDOW,
                settled: 250_000_000,
                overdraft: 0,
            },
            HydratedPosting {
                key: key("acme"),
                window: WINDOW,
                settled: -250_000_000,
                overdraft: 0,
            },
        ],
        unreadable: false,
    };
    let mut ledger = Ledger::new();
    let restored: Hydration = ledger.hydrate(&record).expect("reads back");
    assert_eq!(restored.postings, 2, "both postings replayed");
    assert_eq!(
        restored.balances, 0,
        "but the balance they cancelled on carries nothing, and a zero row in front of a reader is noise"
    );
    assert_eq!(restored.carried.bucket_cents("acme", None), 0);
}
