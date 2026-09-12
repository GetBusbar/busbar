// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE STAGE REPORT KEEPS ITS PROMISE ACROSS THE LOOP'S ONE AWAIT.
//!
//! Its sibling `stage_profile.rs` drives the synchronous entry point, and that entry point is the
//! asynchronous loop polled exactly once: the leg it is handed is ready on its first poll, so the
//! unit never suspends and the report's wait row is timed over a wait that never waited. Every
//! production caller that has been switched onto this loop is the ASYNCHRONOUS one, whose Route
//! step awaits an upstream — and on that shape the loop's future is polled again, after the leg
//! parked it.
//!
//! That second poll is the measurement this file is for. A per-poll timer would arm the wait row
//! once per poll and the operator's table would say one request waited twice; a step re-entered
//! after a suspension would double-count that step. Neither is visible to a cell that never lets
//! the loop park.
//!
//! Its own test binary, for the same reason its sibling is: the profiler is process-global and
//! these assertions are about counts, so a cell sharing a binary would be counting somebody else's
//! requests as well as its own.

mod common;

use std::future::Future;

use busbar_kernel::profile::{self, Stage};
use busbar_kernel::slice::{ConcurrencyGauge, LeaseCell};
use busbar_kernel::teller::{
    run_unit_async, AccrualMeter, Ended, Kernel, RouteAwait, RouteLeg, Run,
};

use common::{cell, ctx, Canary, Decision, Route, RoutePlan, TestUnits, UnitToken};

/// One unit whose Route leg parks the loop once and then answers, driven to its end across that
/// suspension, with every declared stage recorded EXACTLY ONCE.
///
/// The switched-over caller this stands for is the composition root's own node for the protocol it
/// has moved onto this loop: its Route step awaits an upstream, and the root drives it through
/// `run_unit_async`. This cell cannot reach that node — the kernel is below the root — so it drives
/// the same loop, through the same entry point, with a leg of the same shape.
#[test]
fn every_declared_stage_fires_exactly_once_across_a_suspended_route() {
    profile::set_enabled(true);
    profile::reset();

    let kernel = Kernel::new();
    let units = TestUnits::passing();
    let cell = cell(&kernel);
    let canary = Canary::new();
    let gauge = ConcurrencyGauge::new();
    let leases = LeaseCell::new();
    let meter = AccrualMeter::new();
    let route = ParksOnce::default();
    let ctx = ctx(1);

    let mut running = std::pin::pin!(run_unit_async(
        &kernel,
        &units,
        &ctx,
        Run {
            cell: &cell,
            parent: None,
            leases: &leases,
            gauge: &gauge,
            canary: &canary,
            meter: &meter,
        },
        &route,
    ));
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    assert!(
        running.as_mut().poll(&mut cx).is_pending(),
        "the fixture's leg parks the loop on its first poll, or this cell is measuring the \
         synchronous shape the cell above already measures"
    );
    let ended = match running.as_mut().poll(&mut cx) {
        std::task::Poll::Ready(ended) => ended,
        std::task::Poll::Pending => panic!(
            "the leg answers on its second poll; a loop still parked after it has answered is a \
             unit that never reaches its end"
        ),
    };
    assert!(
        matches!(ended, Ended::Settled { .. }),
        "the request has to reach its end, or the stages it did not reach are unmeasured rather \
         than missing"
    );

    let wrong: Vec<(&'static str, u64)> = Stage::ALL
        .iter()
        .map(|s| (s.name(), profile::seen(*s)))
        .filter(|(_, n)| *n != 1)
        .collect();
    assert!(
        wrong.is_empty(),
        "every stage the report enumerates is timed ONCE by the loop, including across the one \
         await; these were not: {wrong:?} (counts: {:?})",
        Stage::ALL
            .iter()
            .map(|s| (s.name(), profile::seen(*s)))
            .collect::<Vec<_>>()
    );
}

/// THE UPSTREAM THAT THINKS ONCE AND THEN ANSWERS.
///
/// The battery's own `NeverRoutes` parks the loop for ever, which is the cancellation shape. What
/// this cell needs is the ORDINARY shape: a leg that parks the loop exactly once — long enough for
/// the loop's future to be polled a second time — and then completes, so the unit runs on through
/// Meter, Audit and Encode to its end with a real suspension behind it.
#[derive(Default)]
struct ParksOnce {
    parked: std::sync::atomic::AtomicBool,
}

impl RouteAwait for ParksOnce {
    fn route_leg<'a>(
        &'a self,
        token: &'a UnitToken<Route>,
        _ctx: &'a busbar_kernel::teller::UnitCtx,
        _meter: &'a AccrualMeter,
    ) -> RouteLeg<'a> {
        Box::pin(Parking {
            parked: &self.parked,
            token,
        })
    }
}

/// The leg itself: `Pending` the first time it is polled, the route step's ordinary answer the next.
struct Parking<'a> {
    parked: &'a std::sync::atomic::AtomicBool,
    token: &'a UnitToken<Route>,
}

impl std::future::Future for Parking<'_> {
    type Output = Decision<Route>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        if self.parked.swap(true, std::sync::atomic::Ordering::Relaxed) {
            return std::task::Poll::Ready(Decision::proceed(self.token, RoutePlan::default()));
        }
        // Woken immediately: the cell polls the loop itself, so this only keeps a real runtime from
        // parking the task for ever if this fixture is ever driven by one.
        cx.waker().wake_by_ref();
        std::task::Poll::Pending
    }
}
