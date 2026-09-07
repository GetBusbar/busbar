// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What a leg's offer of headroom buys the unit that made it, and where the catch-up tick clips.
//!
//! Two figures the loop reads once each and never asks about again. The first is the headroom a
//! Route leg offers while it runs: the loop cannot work out how far a reservation may grow — only
//! the leg holds the chain that answers — so the leg says so, and the exit applies it when the
//! spend lands. An offer nobody reads is a unit carried as an overdraft that its principal's window
//! could have backed all along. The second is the bound a catch-up tick is clipped at: a gap
//! exactly as long as the idle bound is one the session may still price in full, and the clip
//! belongs one millisecond past it.

mod common;

use busbar_caps::{Canary, Outcome, PostingFlags};
use busbar_kernel::slice::{ConcurrencyGauge, LeaseCell};
use busbar_kernel::teller::{run_unit, AccrualMeter, Ended, Evidence, Kernel, Run};
use busbar_kernel::tick::{session_tick, SessionTick, SESSION_IDLE_MAX_MS};

use common::{cell, ctx, Door, TestUnits};

/// Run one unit that opens a hold of `reserved`, spends `spend`, with `headroom` on offer.
fn overdraft_of(reserved: u64, spend: u64, headroom: u64) -> u64 {
    let kernel = Kernel::new();
    let units = TestUnits {
        door: Door::Own(reserved),
        spend,
        evidence: Evidence {
            located: Some(spend),
            ..Evidence::default()
        },
        ..TestUnits::default()
    };
    let cell = cell(&kernel);
    let canary = Canary::new();
    let gauge = ConcurrencyGauge::new();
    let leases = LeaseCell::new();
    // The offer a leg makes while it runs. It is a reading of the principal's window rather than a
    // quantity that accumulates, so it is made before the spend and the last word wins.
    let meter = AccrualMeter::new();
    meter.offer_headroom(headroom);
    let ended = run_unit(
        &kernel,
        &units,
        &ctx(1),
        Run {
            cell: &cell,
            parent: None,
            leases: &leases,
            gauge: &gauge,
            canary: &canary,
            meter: &meter,
        },
    );
    match ended {
        Ended::Settled { end, .. } => {
            assert_eq!(end.outcome(), Outcome::Completed);
            let posted = end.posted().expect("value was delivered, so it posts");
            assert_eq!(posted.settled(), spend, "the unit posts what it spent");
            posted.overdraft()
        }
        other => panic!("expected a settled end, got {other:?}"),
    }
}

/// The offer is READ, and it is what the reservation grows out of.
///
/// Three units spend the same 400 against the same reservation of 100, and differ only in what
/// their leg offered. The offer is the whole difference between a unit carried as an overdraft and
/// one whose window backed it: an offer that is never recorded, or read back as nothing, prices
/// all three the same and silently overdraws a principal with headroom to spare.
#[test]
fn what_the_leg_offered_is_what_the_reservation_grows_out_of() {
    assert_eq!(
        overdraft_of(100, 400, 0),
        300,
        "a leg that offers nothing carries the whole excess"
    );
    assert_eq!(
        overdraft_of(100, 400, 200),
        100,
        "the offer backs what it can, and only the rest is carried"
    );
    assert_eq!(
        overdraft_of(100, 400, 300),
        0,
        "an offer that covers the excess exactly leaves nothing to carry"
    );
    assert_eq!(
        overdraft_of(100, 400, 5_000),
        0,
        "and an offer larger than the excess draws only what the spend needed"
    );
}

/// A unit whose offer covered the excess is not flagged as an overdraft; one whose did not, is.
#[test]
fn the_overdraft_flag_follows_the_offer() {
    let kernel = Kernel::new();
    for (headroom, overdrawn) in [(0u64, true), (300, false)] {
        let units = TestUnits {
            door: Door::Own(100),
            spend: 400,
            evidence: Evidence {
                located: Some(400),
                ..Evidence::default()
            },
            ..TestUnits::default()
        };
        let cell = cell(&kernel);
        let canary = Canary::new();
        let gauge = ConcurrencyGauge::new();
        let leases = LeaseCell::new();
        let meter = AccrualMeter::new();
        meter.offer_headroom(headroom);
        let ended = run_unit(
            &kernel,
            &units,
            &ctx(2),
            Run {
                cell: &cell,
                parent: None,
                leases: &leases,
                gauge: &gauge,
                canary: &canary,
                meter: &meter,
            },
        );
        match ended {
            Ended::Settled { end, .. } => {
                let posted = end.posted().expect("value was delivered");
                assert_eq!(
                    posted.flags().contains(PostingFlags::OVERDRAFT),
                    overdrawn,
                    "an offer of {headroom} was read as something else"
                );
            }
            other => panic!("expected a settled end, got {other:?}"),
        }
    }
}

/// A gap exactly as long as the idle bound is priced in full, and the clip is the millisecond after.
///
/// The catch-up is capped at the idle bound, and a session that has been silent for exactly that
/// long has not yet passed it — the same edge the close above it is decided on. Clipping there
/// would mark a posting estimated and CLOSE a session that was still inside its own bound.
#[test]
fn a_catch_up_exactly_at_the_idle_bound_is_priced_whole_and_the_next_millisecond_is_clipped() {
    assert_eq!(
        session_tick(1_000, SESSION_IDLE_MAX_MS, 0, None, true, false, false),
        SessionTick::Accrue {
            elapsed: SESSION_IDLE_MAX_MS,
            late: true,
            clipped: false,
            checkpoint: None,
        },
        "a gap exactly at the bound is inside it"
    );
    assert_eq!(
        session_tick(1_000, SESSION_IDLE_MAX_MS + 1, 0, None, true, false, false),
        SessionTick::Accrue {
            elapsed: SESSION_IDLE_MAX_MS,
            late: true,
            clipped: true,
            checkpoint: None,
        },
        "and the millisecond past it is clipped at the bound"
    );
}
