// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use busbar_contract::caps::{Pass, Route, SeatVerdict, StepName};
use busbar_kernel::teller::UnitCtx;

use super::units::TestUnits;

pub struct NeverRoutes<'u> {
    pub units: &'u TestUnits,

    pub dropped: &'u AtomicBool,

    pub abandoned: Mutex<Vec<busbar_kernel::teller::Ended>>,
}

pub struct Never<'u> {
    dropped: &'u AtomicBool,
}

impl std::future::Future for Never<'_> {
    type Output = SeatVerdict<Route>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        std::task::Poll::Pending
    }
}

impl Drop for Never<'_> {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::Release);
    }
}

impl busbar_kernel::teller::RouteAwait for NeverRoutes<'_> {
    fn route_leg<'a>(
        &'a self,
        _token: &'a Pass<Route>,
        _ctx: &'a UnitCtx,
        _destinations: &'a [busbar_contract::caps::VerifiedDestination],
    ) -> busbar_kernel::teller::RouteLeg<'a> {
        self.units.note(StepName::Route);
        Box::pin(Never {
            dropped: self.dropped,
        })
    }

    fn abandoned(&self, _ctx: &UnitCtx, ended: busbar_kernel::teller::Ended) {
        self.abandoned.lock().unwrap().push(ended);
    }
}
