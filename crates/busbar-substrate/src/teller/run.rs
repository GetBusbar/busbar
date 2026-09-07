// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ONE LOOP. The nine steps are called here, in this order, and nowhere else:
//!
//! `arrival → decode → authenticate → verify → approve → admit (opens the Hold) → route (under the
//! Hold) → meter (under the Hold) → audit (closes the Hold) → Posted`.
//!
//! The order is fixed twice over: by the source order below, and by the types — each step's
//! decision is built only with that step's token, Route and Meter take `&Hold` (which only Admit
//! can open), Audit takes the `Hold` by value (so it cannot outlive Audit), and `Posted` is minted
//! only from the Audit token after the plane's Audit step returned.
//!
//! A refusal at or before Admit reaches the plane's `audit_refused` (nothing was charged; there is
//! no hold). A refusal at Route or Meter reaches the plane's `audit` WITH the hold (the admission
//! stands; the caller was charged). No `Response` leaves this module except through one of those
//! two Audit doors, and every unit that runs through [`run_unit`] is posted exactly once — including
//! the unit whose caller went away mid-Route or mid-Meter, which [`Abandoned`] carries through the
//! same `audit` door with the hold, ending as `UnitEnd::Abandoned`.

use super::steps::{Closing, Refusal, TellerPlane};
use super::tokens::{Hold, Posted, UnitToken};
use super::unit::{Unit, UnitEnd};
use super::{Admit, Approve, Arrival, Audit, Authenticate, Decode, Meter, Route, StepName, Verify};
use axum::response::Response;

/// The steps up to and including the door, in order. Returns the open hold, or the refusal of the
/// step that stopped the unit (no response is shaped here — that is Audit's job). Written as one
/// chain so the order reads top to bottom and a refusal simply stops the chain: no `?`, no early
/// return.
///
/// (`result_large_err`: a `Refusal` carries the plane's finished `Response` by value, so the
/// refusal bytes reach Audit exactly as the plane shaped them.)
#[allow(clippy::result_large_err)]
fn open<P: TellerPlane>(plane: &mut P, unit: &Unit<'_>) -> Result<Hold, Refusal> {
    plane
        .arrival(&UnitToken::<Arrival>::mint(), unit)
        .into_result()
        .and_then(|()| {
            plane
                .decode(&UnitToken::<Decode>::mint(), unit)
                .into_result()
        })
        .and_then(|()| {
            plane
                .authenticate(&UnitToken::<Authenticate>::mint(), unit)
                .into_result()
        })
        .and_then(|principal| {
            plane
                .verify(&UnitToken::<Verify>::mint(), unit, &principal)
                .into_result()
                .map(|()| principal)
        })
        .and_then(|principal| {
            plane
                .approve(&UnitToken::<Approve>::mint(), unit, &principal)
                .into_result()
                .map(|()| principal)
        })
        .and_then(|principal| {
            plane
                .admit(&UnitToken::<Admit>::mint(), unit, &principal)
                .into_result()
        })
}

/// Audit for a unit that never passed the door: the plane's `audit_refused`, then the posting.
fn close_refused<P: TellerPlane>(plane: &mut P, unit: &Unit<'_>, refusal: Refusal) -> Response {
    let at = refusal.step();
    let token = UnitToken::<Audit>::mint();
    let (resp, end) = match plane.audit_refused(&token, unit, refusal).into_result() {
        Ok(resp) => (resp, UnitEnd::Refused(at)),
        Err(refusal) => (refusal.into_response(), UnitEnd::Refused(StepName::Audit)),
    };
    plane.posted(unit, Posted::mint(&token, end));
    resp
}

/// Audit for a unit that passed the door: the plane's `audit` closes the hold, then the posting.
fn close_admitted<P: TellerPlane>(
    plane: &mut P,
    unit: &Unit<'_>,
    hold: Hold,
    closing: Closing,
) -> Response {
    let end = closing.end;
    let token = UnitToken::<Audit>::mint();
    let (resp, end) = match plane.audit(&token, unit, hold, closing).into_result() {
        Ok(resp) => (resp, end),
        Err(refusal) => (refusal.into_response(), UnitEnd::Refused(StepName::Audit)),
    };
    plane.posted(unit, Posted::mint(&token, end));
    resp
}

/// Run one unit through every step and return the one response Audit produced.
pub async fn run_unit<P: TellerPlane>(mut plane: P, unit: Unit<'_>) -> Response {
    let hold = match open(&mut plane, &unit) {
        Ok(hold) => hold,
        Err(refusal) => return close_refused(&mut plane, &unit, refusal),
    };
    // THE TWO AWAITS are inside this scope, and they are the only place a caller that goes away can
    // drop the loop. The guard owns the audit door for the length of them, so an admitted unit ends
    // at Audit whichever way it leaves.
    let mut abandoned = Abandoned::arm(plane, unit, hold);
    let closing = under_hold(&mut abandoned).await;
    reached(abandoned, closing)
}

/// Route then Meter, under the hold the door opened, and what Audit will close over. THE TWO AWAITS
/// are here; the guard holding the plane, the unit and the hold is what survives a caller that goes
/// away in the middle of either.
async fn under_hold<P: TellerPlane>(guard: &mut Abandoned<'_, P>) -> Closing {
    let Some(hold) = guard.hold.as_ref() else {
        // Unreachable: this is called exactly once, before either taker has run. Answered rather
        // than unwrapped, because a guard that cannot be read still has to say something if it is.
        return Closing {
            resp: abandoned_response(),
            end: UnitEnd::Abandoned,
        };
    };
    match guard
        .plane
        .route(&UnitToken::<Route>::mint(), &guard.unit, hold)
        .await
        .into_result()
    {
        Ok(resp) => match guard
            .plane
            .meter(&UnitToken::<Meter>::mint(), &guard.unit, hold, resp)
            .await
            .into_result()
        {
            Ok(metered) => Closing {
                resp: metered.resp,
                end: UnitEnd::Completed,
            },
            Err(refusal) => refusal.into_closing(),
        },
        Err(refusal) => refusal.into_closing(),
    }
}

/// The unit reached its own end: take the hold back out of the guard and close it here, so the
/// guard's own drop has nothing left to do.
fn reached<P: TellerPlane>(mut guard: Abandoned<'_, P>, closing: Closing) -> Response {
    match guard.hold.take() {
        Some(hold) => close_admitted(&mut guard.plane, &guard.unit, hold, closing),
        // Unreachable: this is called exactly once, on the one path out of the awaits, and the only
        // other taker is the guard's drop — which cannot have run while the guard is still owned here.
        None => closing.resp,
    }
}

/// The status an abandoned unit's stand-in response carries: the client closed the request. It never
/// reaches a socket — the caller that would have read it is the one that went away — but a plane that
/// records what it audited records the truth about how the unit ended.
const CLIENT_CLOSED_REQUEST: u16 = 499;

/// The stand-in response Audit closes over for a unit nobody is left to answer.
fn abandoned_response() -> Response {
    let mut resp = Response::new(axum::body::Body::empty());
    *resp.status_mut() = axum::http::StatusCode::from_u16(CLIENT_CLOSED_REQUEST)
        .unwrap_or(axum::http::StatusCode::INTERNAL_SERVER_ERROR);
    resp
}

/// THE UNIT THE CALLER WENT AWAY FROM.
///
/// The loop awaits in exactly two places — Route and Meter — so a client that disconnects
/// mid-request drops the loop's future in exactly those two places, with the hold open and the
/// plane's admission standing. This is what stands there.
///
/// It owns everything Audit needs from the moment the door answered — the plane, the unit and the
/// hold — so an abandoned unit leaves through the SAME audit door and the SAME posting a finished
/// unit leaves through, with the end named for what happened. Without it, a dropped future takes the
/// hold with it and neither `audit` nor `posted` ever runs, which is the one thing this module says
/// cannot happen: every unit is posted exactly once.
///
/// [`reached`] is how a unit that finished on its own takes the hold back out. A guard whose hold has
/// been taken does nothing when it is dropped, which is the whole of the arming.
struct Abandoned<'a, P: TellerPlane> {
    plane: P,
    unit: Unit<'a>,
    /// The open hold, until somebody closes it. `None` once one of the two callers has.
    hold: Option<Hold>,
}

impl<'a, P: TellerPlane> Abandoned<'a, P> {
    /// Take the audit door, for the length of the awaits.
    fn arm(plane: P, unit: Unit<'a>, hold: Hold) -> Self {
        Abandoned {
            plane,
            unit,
            hold: Some(hold),
        }
    }
}

impl<P: TellerPlane> Drop for Abandoned<'_, P> {
    fn drop(&mut self) {
        if let Some(hold) = self.hold.take() {
            // The response is discarded because there is nobody left to hand it to. What matters is
            // that Audit was REACHED — the hold is closed and the unit is posted, exactly once.
            let _resp = close_admitted(
                &mut self.plane,
                &self.unit,
                hold,
                Closing {
                    resp: abandoned_response(),
                    end: UnitEnd::Abandoned,
                },
            );
        }
    }
}

/// The session opener: the same steps as [`run_unit`] up to and including Admit, for a plane whose
/// unit has no one-shot Route leg (a live session that binds its carrier AFTER the door). On a pass
/// the caller receives the open hold and is responsible for closing it later; on a refusal the unit
/// is audited (`audit_refused`) and posted here, exactly as [`run_unit`] would, and the plane's
/// refusal response comes back. Nothing is charged before the door in either case.
///
/// (`result_large_err`: the `Err` is the plane's own finished refusal `Response`, carried by value
/// so it reaches the caller byte-identical, exactly as the one-shot path returns it.)
#[allow(clippy::result_large_err)]
pub fn open_unit<P: TellerPlane>(plane: &mut P, unit: &Unit<'_>) -> Result<Hold, Response> {
    match open(plane, unit) {
        Ok(hold) => Ok(hold),
        Err(refusal) => Err(close_refused(plane, unit, refusal)),
    }
}
