// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ITEM 99: A CLIENT THAT GOES AWAY MID-DISPATCH IS CHARGED.
//!
//! Two cells, identical but for whether the client stayed, both ending on the same four-figure
//! reading of a real ledger: how many postings reached the books, what was settled, what is still
//! held open, and what went back to the slice. The unit reserved 1,000 at the door and the
//! destination reported 900 before the caller left.
//!
//! The cell names no `Drop`, no terminal and no binding. What it reads is the books, after posting
//! whatever end the loop handed to somebody — the caller that waited reads its end off the loop's
//! return value; the caller that went away cannot, so the end reaches the leg's own plane through
//! [`busbar_kernel::teller::RouteAwait::abandoned`]. Before that seam the loop sealed the end, emptied
//! the cell and DROPPED the posting (`let _ended = terminal(..)`): no row, nothing settled, and the
//! reservation still drawn — `(0, 0, 1000, 0)` against the waited-for `(1, 900, 0, 100)`.

mod common;

use std::future::Future;
use std::sync::atomic::AtomicBool;
use std::task::{Context, Waker};

use busbar_contract::caps::{Canary, OriginKind, UnitKey};
use busbar_kernel::inflight::{arrival_hold, Enter, InFlight};
use busbar_kernel::slice::ConcurrencyGauge;
use busbar_kernel::teller::{run_unit, run_unit_async, AccrualMeter, Ended, Evidence, Kernel, Run};
use busbar_kernel_ledger::settle::Ledger;
use busbar_kernel_ledger::totals::{BucketId, BucketScope, CapDimension, TotalsKey};

use common::{ctx, principal, NeverRoutes, TestDoor, TestUnits};

/// Postings that reached the books, settled, still held open, handed back to the slice.
type Figures = (usize, i128, i128, i128);

fn balance() -> TotalsKey {
    TotalsKey::new(
        BucketId::new("abandoned"),
        CapDimension::NanoUnits,
        BucketScope::All,
    )
}

/// Post an end onto the books exactly as a composition root does: read the posting off the sealed
/// end and move the ledger with it. An end nobody hands over is an end this never sees.
fn post(ledger: &mut Ledger, ended: Ended) -> usize {
    match ended {
        Ended::Settled { end, .. } => match end.into_posted() {
            Ok(posted) => {
                ledger.post(&balance(), 1, posted);
                1
            }
            Err(_) => 0,
        },
        Ended::AlreadySettled => 0,
    }
}

fn one_unit(went_away: bool) -> Figures {
    let kernel = Kernel::new();
    // The door reserves 1,000; the destination reported 900 before the unit ended.
    let units = TestUnits {
        evidence: Evidence {
            located: Some(900),
            ..Evidence::default()
        },
        ..TestUnits::default()
    };
    let table = InFlight::new(4);
    let key = UnitKey::new(1);
    let slot = table
        .insert(Enter {
            key,
            origin: OriginKind::Client,
            session: None,
            admin_listener: false,
            zero_hold_tick: false,
            arrival: arrival_hold(&kernel, &TestDoor, principal()),
            now: 0,
        })
        .expect("the empty table takes the unit");
    let gauge = ConcurrencyGauge::new();
    let canary = Canary::new();
    let meter = AccrualMeter::new();
    let run = Run {
        cell: slot.cell(),
        parent: None,
        leases: slot.leases(),
        gauge: &gauge,
        canary: &canary,
        meter: &meter,
    };

    // The reservation, as the books hold it while the unit runs: drawn from the store, spent out of
    // the slice into the hold.
    let mut ledger = Ledger::new();
    let k = balance();
    ledger.record_draw(&k, 1, 1_000);
    ledger.record_hold_opened(&k, 1, 1_000);
    ledger.record_slice_spent(&k, 1, 1_000);

    let mut rows = 0;
    if went_away {
        let dropped = AtomicBool::new(false);
        let route = NeverRoutes {
            units: &units,
            dropped: &dropped,
        };
        let unit = ctx(1);
        {
            let mut running = std::pin::pin!(run_unit_async(&kernel, &units, &unit, run, &route));
            let mut cx = Context::from_waker(Waker::noop());
            assert!(running.as_mut().poll(&mut cx).is_pending());
        }
        // The caller has gone. Whatever the loop handed on is what reaches the books.
        let handed: Vec<Ended> = std::mem::take(&mut *units.abandoned.lock().unwrap());
        for ended in handed {
            rows += post(&mut ledger, ended);
        }
    } else {
        rows += post(&mut ledger, run_unit(&kernel, &units, &ctx(1), run));
    }
    table.remove(key);

    let figures = ledger.book().get(&k, 1);
    (
        rows,
        figures.settled,
        figures.open_holds,
        figures.open_slice_remainders,
    )
}

#[test]
fn a_client_that_waited_is_charged_what_was_served() {
    assert_eq!(one_unit(false), (1, 900, 0, 100));
}

#[test]
fn a_client_that_went_away_mid_dispatch_is_charged_what_was_served() {
    assert_eq!(
        one_unit(true),
        (1, 900, 0, 100),
        "the abandoned unit's posting never reached the books: (rows, settled, open holds, \
         released)"
    );
}
