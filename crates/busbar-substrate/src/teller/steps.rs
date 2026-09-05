// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The plane's side of the Teller: one method per step, plus the small neutral facts the steps
//! hand each other and the [`Refusal`] a step answers with when it stops the unit.

use super::tokens::{Decision, Hold, Posted, UnitToken};
use super::unit::{StepName, Unit, UnitEnd};
use super::{Admit, Approve, Arrival, Audit, Authenticate, Decode, Meter, Route, Verify};
use axum::response::Response;
use std::sync::Arc;

/// What Authenticate establishes: the caller, as the auth layer resolved it.
#[derive(Clone, Default)]
pub struct Principal {
    /// The virtual key the caller presented, when the request is governed.
    pub key: Option<Arc<busbar_api::VirtualKey>>,
}

impl std::fmt::Debug for Principal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Principal")
            .field("governed", &self.key.is_some())
            .finish()
    }
}

/// What Meter establishes: the routed response, and what the meter read off it for Audit.
#[derive(Debug)]
pub struct Metered {
    /// The routed response, carried on to Audit (the body may still be streaming).
    pub resp: Response,
    /// The response status the meter saw.
    pub status: u16,
}

/// What Audit closes: the one response the unit produced and how the unit got there.
#[derive(Debug)]
pub struct Closing {
    /// The response the loop will return once Audit has posted the unit.
    pub resp: Response,
    /// Completed, or refused at Route or Meter (under the hold).
    pub end: UnitEnd,
}

/// A step's "stop here": the plane's OWN already-finished, protocol-native response (its
/// refusal shaping stays byte-identical to what the plane produced in place), stamped by the loop
/// with the step it was raised at. A refusal at or before Admit reaches `audit_refused` (nothing was
/// charged); a refusal after Admit reaches `audit` with the hold (the admission stands).
pub struct Refusal {
    resp: Response,
    at: StepName,
}

impl Refusal {
    /// Wrap a finished response as a refusal. The step is stamped when the refusal is turned into
    /// a [`Decision`] with the step's token, so a plane cannot mislabel where it stopped.
    pub fn new(resp: Response) -> Self {
        Refusal {
            resp,
            at: StepName::Arrival,
        }
    }

    /// Stamp the step (loop-side).
    pub(super) fn at(mut self, at: StepName) -> Self {
        self.at = at;
        self
    }

    /// The step the unit stopped at.
    pub fn step(&self) -> StepName {
        self.at
    }

    /// Whether the refusal was raised under an open hold (strictly after Admit).
    pub fn after_admit(&self) -> bool {
        self.at.after_admit()
    }

    /// The refusal response, by reference.
    pub fn response(&self) -> &Response {
        &self.resp
    }

    /// Take the refusal response out.
    pub fn into_response(self) -> Response {
        self.resp
    }

    /// The refusal as what Audit closes (loop-side).
    pub(super) fn into_closing(self) -> Closing {
        Closing {
            resp: self.resp,
            end: UnitEnd::Refused(self.at),
        }
    }
}

impl std::fmt::Debug for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Refusal")
            .field("at", &self.at)
            .field("status", &self.resp.status().as_u16())
            .finish()
    }
}

/// A protocol plane's contribution to the Teller: one method per step. Each method receives the
/// [`UnitToken`] for its own step and the previous step's facts, and answers with a [`Decision`]
/// for its own step — the only kind it can build with that token. The loop ([`super::run_unit`])
/// owns the order; the plane owns what each step means for its protocol.
///
/// `route` and `meter` are async (they touch the network); every other step is sync. Methods take
/// `&mut self` because a plane moves its owned per-unit payload (body, parsed form, grant) into its
/// engine at Route.
#[async_trait::async_trait]
pub trait TellerPlane: Send {
    /// Step 1 — read the plane's share of the arrival facts.
    fn arrival(&mut self, token: &UnitToken<Arrival>, unit: &Unit<'_>) -> Decision<Arrival>;

    /// Step 2 — recognise the request's shape.
    fn decode(&mut self, token: &UnitToken<Decode>, unit: &Unit<'_>) -> Decision<Decode>;

    /// Step 3 — resolve the caller.
    fn authenticate(
        &mut self,
        token: &UnitToken<Authenticate>,
        unit: &Unit<'_>,
    ) -> Decision<Authenticate>;

    /// Step 4 — verify the destination against the caller's scope, before anything is charged.
    fn verify(
        &mut self,
        token: &UnitToken<Verify>,
        unit: &Unit<'_>,
        principal: &Principal,
    ) -> Decision<Verify>;

    /// Step 5 — the approval seat.
    fn approve(
        &mut self,
        token: &UnitToken<Approve>,
        unit: &Unit<'_>,
        principal: &Principal,
    ) -> Decision<Approve>;

    /// Step 6 — the door. A pass opens the hold via [`UnitToken::<Admit>::hold`].
    fn admit(
        &mut self,
        token: &UnitToken<Admit>,
        unit: &Unit<'_>,
        principal: &Principal,
    ) -> Decision<Admit>;

    /// Step 7 — route the unit under the hold and produce the response.
    async fn route(
        &mut self,
        token: &UnitToken<Route>,
        unit: &Unit<'_>,
        hold: &Hold,
    ) -> Decision<Route>;

    /// Step 8 — read what the routed response cost.
    async fn meter(
        &mut self,
        token: &UnitToken<Meter>,
        unit: &Unit<'_>,
        hold: &Hold,
        resp: Response,
    ) -> Decision<Meter>;

    /// Step 9 (admitted) — finish a unit that was admitted: close the hold and hand back the one
    /// response the loop returns. Reached for every unit that passed Admit, whether Route/Meter
    /// completed or refused (`closing.end` says which).
    fn audit(
        &mut self,
        token: &UnitToken<Audit>,
        unit: &Unit<'_>,
        hold: Hold,
        closing: Closing,
    ) -> Decision<Audit>;

    /// Step 9 (refused before the door) — finish a unit that never passed Admit: nothing was
    /// charged, there is no hold, and the response is the plane's own refusal.
    fn audit_refused(
        &mut self,
        token: &UnitToken<Audit>,
        unit: &Unit<'_>,
        refusal: Refusal,
    ) -> Decision<Audit>;

    /// The receipt: the loop hands the plane the [`Posted`] proof it minted after Audit, exactly
    /// once per unit. Not a step — a plane that has nothing to record ignores it.
    fn posted(&mut self, unit: &Unit<'_>, posted: Posted);
}
