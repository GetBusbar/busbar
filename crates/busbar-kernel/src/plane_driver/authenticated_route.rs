// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::{Arc, Mutex};
use std::time::Duration;

use busbar_contract::abi::mechanism::call::{AbiStr, Outcome};
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::plane::{
    check::check_authenticated_route, AuthenticatedRouteIn, MAX_ROUTE_ENTRY_BYTES,
    ROUTE_AUTHENTICATED,
};
use busbar_contract::abi::sdk::door::{blank_in, blank_out};
use busbar_contract::caps::{PrincipalId, ReasonCode, Refusal};
use busbar_contract::plane_calls::Lent;

use super::{CallerEnd, DriverSteps, FarEnd, PlaneDriver, PlaneUnits, UnitState};
use crate::teller::UnitCtx;

// A lookup cannot inherit an unbounded stream lifetime. An earlier request deadline wins.
const LOOKUP_CEILING: Duration = Duration::from_secs(30);

struct Buffers {
    caller_ref: Vec<u8>,
    entry: Vec<u8>,
}

/// Retain borrowed host bytes until dispatcher retirement, including cancellation/drop races.
struct Lookup<'a> {
    driver: &'a PlaneDriver,
    state: &'a Mutex<UnitState>,
    ticket: Ticket,
    buffers: Option<Box<Buffers>>,
    kept: Arc<Mutex<Option<Box<Buffers>>>>,
    pending: bool,
}

impl Drop for Lookup<'_> {
    fn drop(&mut self) {
        *self.kept.lock().unwrap_or_else(|e| e.into_inner()) = self.buffers.take();
        if self.pending {
            // No admission exists: cancellation cannot publish writes or charges. The worker
            // owns the one cancellation and retains the loan until it has finished.
            self.state
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .close
                .closed();
            self.driver.calls.drop_client(self.ticket);
        }
        self.driver.calls.recycle(self.ticket);
    }
}

impl<S: DriverSteps + Sync, F: FarEnd, C: CallerEnd> PlaneUnits<'_, S, F, C> {
    pub(super) async fn resolve_authenticated_route(
        &self,
        ctx: &UnitCtx,
        principal: &PrincipalId,
    ) -> Result<(), Refusal> {
        if !self
            .lock()
            .decoded
            .as_ref()
            .is_some_and(|d| d.route == ROUTE_AUTHENTICATED)
        {
            return Ok(());
        }
        let refuse = |why| Refusal::new(why);
        if !self.driver.authenticated_route {
            return Err(refuse(ReasonCode::DecodeFailed));
        }
        let caller_ref = self.lock().caller_ref.clone();
        if *principal == PrincipalId::anonymous() || caller_ref.is_empty() {
            return Err(refuse(ReasonCode::Unauthenticated));
        }
        let mut reload = self.driver.reload.subscribe();
        if *reload.borrow() {
            return Err(refuse(ReasonCode::Drain));
        }
        let now = self.driver.calls.now_ns();
        let ceiling = now.saturating_add(LOOKUP_CEILING.as_nanos() as u64);
        let deadline = if self.deadline_ns == 0 {
            ceiling
        } else {
            ceiling.min(self.deadline_ns)
        };
        if deadline <= now {
            return Err(refuse(ReasonCode::DeadlineExceeded));
        }
        let ticket = self
            .driver
            .calls
            .mint()
            .ok_or_else(|| refuse(ReasonCode::InFlightCap))?;
        let mut lookup = Lookup {
            driver: self.driver,
            state: &self.state,
            ticket,
            buffers: Some(Box::new(Buffers {
                caller_ref,
                entry: vec![0; MAX_ROUTE_ENTRY_BYTES],
            })),
            kept: Arc::default(),
            pending: false,
        };
        let buffers = lookup.buffers.as_mut().expect("owned buffers");
        let mut input = AuthenticatedRouteIn {
            unit: ctx.key.get(),
            caller_ref: AbiStr::over(&buffers.caller_ref),
            entry_buf: buffers.entry.as_mut_ptr(),
            entry_cap: buffers.entry.len(),
            ..blank_in()
        };
        input.head.deadline_ns = deadline;
        self.driver.calls.bind_unit(ticket, ctx.key.get());
        let lent: Lent = lookup.kept.clone();
        let mut flight = self
            .driver
            .calls
            .authenticated_route(ticket, input, blank_out(), lent)
            .ok_or_else(|| refuse(ReasonCode::DecodeFailed))?;
        lookup.pending = true;
        let answered = tokio::select! {
            biased;
            cause = self.caller.stopped() => return Err(refuse(cause)),
            _ = reload.changed() => return Err(refuse(ReasonCode::Drain)),
            _ = tokio::time::sleep(Duration::from_nanos(deadline.saturating_sub(now))) => {
                return Err(refuse(ReasonCode::DeadlineExceeded));
            }
            answered = &mut flight => answered,
        };
        lookup.pending = false;
        if answered.disposition.is_some() {
            self.lock().close.closed();
        }
        let output = flight.out().ok_or_else(|| refuse(ReasonCode::PlanePanic))?;
        let buffers = lookup.buffers.as_ref().expect("owned buffers");
        check_authenticated_route(
            answered.outcome,
            &output,
            &buffers.entry,
            buffers.entry.len(),
        )
        .map_err(|_| refuse(ReasonCode::PlanePanic))?;
        match answered.outcome {
            Outcome::Ready => {
                let entry = buffers.entry[..output.entry_written as usize].to_vec();
                let op = {
                    let mut state = self.lock();
                    let decoded = state
                        .decoded
                        .as_mut()
                        .ok_or_else(|| refuse(ReasonCode::DecodeFailed))?;
                    decoded.route = output.route;
                    decoded.pool = Some(entry.clone());
                    *self
                        .driver
                        .config
                        .op_classes
                        .get(decoded.op_class as usize)
                        .ok_or_else(|| refuse(ReasonCode::DecodeFailed))?
                };
                // Only destination facts change. Operation, request, estimates and caller stay
                // fixed, and the caller immediately runs ordinary Verify/Approve/Admit.
                self.steps.decoded(ctx, op, output.route, Some(&entry));
                Ok(())
            }
            Outcome::Refused => {
                self.lock().declined = Some((output.refusal, output.refusal_status));
                Err(refuse(ReasonCode::DecodeFailed))
            }
            _ => Err(refuse(if self.driver.calls.now_ns() >= deadline {
                ReasonCode::DeadlineExceeded
            } else {
                ReasonCode::PlanePanic
            })),
        }
    }
}
