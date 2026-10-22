// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! EVERY UNIT THAT ARRIVED IS CLOSED EXACTLY ONCE.
//!
//! A plane keeps what it needs of a unit keyed by the unit from `arrive` on (`abi::plane`, "ONE
//! UNIT, ONE KEY"), and lets it go at the unit's closing call: the `on_piece` answer that says its
//! reply is complete (`EMIT_DONE`), the `refusal` that ends it (`RefusalIn::unit`), or the `cancel`
//! that names it (`PlaneCancelIn::unit`, SEAM-L(r): "a unit's last terminal crossing"). A plane that
//! bounds the units it keeps refuses new ones once its bound is full, so a unit that never gets its
//! closing call is a place lost for as long as the instance lives.
//!
//! The unit's [`Close`] is owned from `arrive` on, in the unit's own state: each closing crossing
//! marks it, and a [`super::PlaneUnits`] dropped with it still open (its caller went away at the
//! screen or the route's hook stage, a panic unwound it, or it ended failed after its answer had
//! begun, so no `refusal` was rendered) OWES it. Nothing crosses the dispatcher inside a `Drop`
//! (`BUSBAR-1.6.0.md` Part 3 section 12, "Cancel": "Nothing crosses the dispatcher inside a
//! `Drop`"), so the drop records the debt and the driver's sweep pays it, outside any `Drop`, with
//! the host's own ticketless `cancel` naming the unit (`PlaneCancelIn::unit`, audit P-M7: "so a
//! plane that keys its units from `arrive` finds one whose ticket no piece ever carried"). The
//! unit's money already ended on its own path, so the close bills nothing; the record writes its
//! `cancel` carries are written, as every `cancel`'s are.
//!
//! A unit already closed owes nothing, so the debt is paid at most once and never beside a closing
//! call the unit already had.

use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::caps::PrincipalId;

use super::{PlaneDriver, PlaneUnits};

/// Where a unit stands with its plane's closing call.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum Close {
    /// `arrive` has not crossed for it: the plane holds nothing of it.
    #[default]
    NotArrived,
    /// `arrive` crossed and no closing call has: the plane holds the unit.
    Open,
    /// Its closing call crossed, or is owed to the driver's sweep, which makes it.
    Closed,
}

impl Close {
    /// A closing call crossed for the unit (or was handed to the sweep, which makes it).
    pub(crate) fn closed(&mut self) {
        if *self == Close::Open {
            *self = Close::Closed;
        }
    }
}

/// A unit dropped open: the `cancel` the sweep owes it.
pub(crate) struct Owed {
    /// The unit, as the kernel minted it.
    unit: u64,
    /// The principal the kernel verified for it: its `cancel`'s row is written under it.
    principal: Option<PrincipalId>,
}

impl PlaneDriver {
    /// Pay every close owed: the host's own `cancel` of each unit, named, on a ticket no piece of
    /// it carried (the instance's ticketless crossing, so none is held past it), its record writes
    /// written. Called by [`PlaneDriver::sweep`]; never inside a `Drop`, never under a lock.
    pub(crate) fn close_owed(&self) {
        // One at a time, the lock let go before each crossing: a crossing that unwinds leaves the
        // rest owed, and the one it was paying owed again, for the next sweep, never dropped.
        loop {
            let next = self.lock_owed().pop();
            let Some(owed) = next else {
                return;
            };
            let (unit, principal) = (owed.unit, owed.principal.clone());
            let mut paying = Paying {
                driver: self,
                owed: Some(owed),
            };
            let ticket = self.calls.mint();
            let cancelled = self.cancel_now(ticket.unwrap_or(Ticket::NONE), unit);
            // The `cancel` answered: the debt is paid, whatever it answered.
            paying.owed = None;
            if let Some(t) = ticket {
                self.calls.recycle(t);
            }
            if let Some(c) = cancelled {
                self.fold_writes(&c.writes, principal.as_ref());
            }
        }
    }

    /// How many units are owed their close (a witness for the tests).
    pub fn owed_closes(&self) -> usize {
        self.lock_owed().len()
    }

    fn lock_owed(&self) -> std::sync::MutexGuard<'_, Vec<Owed>> {
        self.owed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// A debt being paid: an unwind out of its `cancel` owes it again (the next sweep pays it), so no
/// debt is lost to a panic. Crosses nothing in its `Drop`.
struct Paying<'d> {
    driver: &'d PlaneDriver,
    owed: Option<Owed>,
}

impl Drop for Paying<'_> {
    fn drop(&mut self) {
        if let Some(owed) = self.owed.take() {
            self.driver.lock_owed().push(owed);
        }
    }
}

/// THE UNIT'S CLOSE, OWNED FROM `arrive`: a unit dropped while its plane still holds it is owed its
/// `cancel` (module doc). Runs on every path a unit leaves by, an unwind included; it crosses
/// nothing and cannot panic.
impl<S, F, C> Drop for PlaneUnits<'_, S, F, C> {
    fn drop(&mut self) {
        let st = self
            .state
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if st.close != Close::Open {
            return;
        }
        st.close = Close::Closed;
        let owed = Owed {
            unit: st.unit,
            principal: st.principal.clone(),
        };
        self.driver.lock_owed().push(owed);
    }
}
