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
//! two Audit doors, and every unit that runs through [`run_unit`] is posted exactly once.

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
    let closing = match plane
        .route(&UnitToken::<Route>::mint(), &unit, &hold)
        .await
        .into_result()
    {
        Ok(resp) => match plane
            .meter(&UnitToken::<Meter>::mint(), &unit, &hold, resp)
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
    };
    close_admitted(&mut plane, &unit, hold, closing)
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
