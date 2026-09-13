// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The hook-veto seat at APPROVE, and the refusal the step produces.
//!
//! The scope check ([`crate::approve`]) is the "does the principal hold enough scope" half of
//! APPROVE. This module is the other half the design names: a kind-neutral gate seat consulted
//! AFTER scope admission and BEFORE the hold, where the first veto wins. It lives beside the scope
//! check rather than inside it so a second plane seats the same face unchanged.

use busbar_contract::{ClaimKey, OpClassId, VetoCode};

use crate::{approve, Grants, Scope};

/// Why the APPROVE step refused a unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    /// The principal's held [`Grants`] do not satisfy the required [`Scope`].
    InsufficientScope {
        /// The scope that would have sufficed.
        needed: Scope,
    },
    /// A seated gate vetoed the unit AFTER the scope check admitted it and BEFORE the hold. Carries
    /// the hook's own closed reason and which seat, by position in the ordered list, stopped it —
    /// "a hook vetoed" without a position is unactionable on a deployment with more than one seat.
    Vetoed {
        /// The closed reason the seat returned, from the contract's own [`VetoCode`] vocabulary.
        code: VetoCode,
        /// Which seat stopped it, by position in the ordered list.
        seat: usize,
    },
}

/// A 1.6.0-native gate seated at APPROVE, kind-neutral so a second plane seats it unchanged.
///
/// A gate at this seat may VETO a unit and may do nothing else: it cannot narrow the destination
/// set (that set was sealed at the verify step, and a gate that could re-open it could widen it) and
/// it cannot rewrite the request (a step that rewrites is a step that has to be metered). It runs
/// AFTER the scope check has admitted the unit and BEFORE the hold is opened, so a veto stops the
/// unit before it is charged.
///
/// The reason is not free text: a gate returns one of the contract's CLOSED [`VetoCode`]s or
/// nothing, because the reason a unit ended is a closed vocabulary and a hook is not entitled to add
/// to it. `// contract:` the integrator registers the seats; this crate owns none, exactly as it
/// owns no policy store.
pub trait VetoSeat {
    /// Whether this gate stops the unit, and with which closed reason. `None` proceeds.
    ///
    /// It is handed only what the APPROVE step knows about the operation — the claim and its
    /// operation class — never the body, the credential or the hold: a gate that could read the
    /// body would be a step, and a gate that could read the hold would be the door.
    fn veto(&self, claim: ClaimKey, op: OpClassId) -> Option<VetoCode>;
}

/// The full APPROVE decision: the scope check, then the veto seats.
///
/// The scope check runs FIRST — a unit the principal may not perform is refused for insufficient
/// scope before any gate is asked, because consulting a gate about a unit that has already been
/// refused hands a refused unit's facts to something with no decision left to make. Only once the
/// scope admits the unit are the ordered `seats` consulted, and THE FIRST VETO WINS: a seat that
/// vetoes stops the walk, so a later seat is never asked about a unit already refused. An empty seat
/// list is not a special case — the walk finds nothing and the unit proceeds, unit-for-unit as
/// before the seat existed.
///
/// This composes with the plane's own APPROVE contribution exactly as the design says: the scope
/// half here runs first, and a veto after it wins regardless of what it returned.
pub fn approve_gated(
    held: Grants,
    needed: Scope,
    claim: ClaimKey,
    op: OpClassId,
    seats: &[&dyn VetoSeat],
) -> Result<(), Refused> {
    approve(held, needed)?;
    for (seat, gate) in seats.iter().enumerate() {
        if let Some(code) = gate.veto(claim, op) {
            return Err(Refused::Vetoed { code, seat });
        }
    }
    Ok(())
}
