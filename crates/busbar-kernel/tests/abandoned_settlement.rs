// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

mod common;

use std::future::Future;
use std::sync::atomic::AtomicBool;
use std::task::{Context, Waker};

use busbar_contract::caps::{OriginKind, UnitKey};
use busbar_kernel::canary::Canary;
use busbar_kernel::inflight::{arrival_hold, Enter, InFlight};
use busbar_kernel::slice::ConcurrencyGauge;
use busbar_kernel::teller::{run_unit, run_unit_async, AccrualMeter, Ended, Evidence, Kernel, Run};

use common::{ctx, principal, NeverRoutes, TestDoor, TestUnits};

type Figures = (usize, u64);

fn post(books: &mut Figures, ended: Ended) {
    match ended {
        Ended::Settled { end, .. } => {
            if let Ok(posted) = end.into_posted() {
                books.0 += 1;
                books.1 += posted.quantity();
            }
        }
        Ended::AlreadySettled => {}
    }
}

fn one_unit(went_away: bool) -> Figures {
    let kernel = Kernel::new();

    let units = TestUnits {
        evidence: Evidence {
            reported: Some(900),
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
            arrival: arrival_hold(&kernel, &TestDoor, principal(), kernel.next_call()),
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
        taps: None,
    };

    let mut books: Figures = (0, 0);
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

        let handed: Vec<Ended> = std::mem::take(&mut *units.abandoned.lock().unwrap());
        for ended in handed {
            post(&mut books, ended);
        }
    } else {
        post(&mut books, run_unit(&kernel, &units, &ctx(1), run));
    }
    table.remove(key);
    books
}

#[test]
fn a_client_that_waited_is_charged_what_was_served() {
    assert_eq!(one_unit(false), (1, 900));
}

#[test]
fn a_client_that_went_away_mid_dispatch_is_charged_what_was_served() {
    assert_eq!(
        one_unit(true),
        (1, 900),
        "the abandoned unit's posting never reached the books: (rows, count)"
    );
}
