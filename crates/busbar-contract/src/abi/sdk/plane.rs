// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLANE KIND'S SHARED PIECES (`abi::plane`): what the planes wrote alike, stated once.
//!
//! * [`dealt_section`] — the section a plane declares, read out of the blob `validate` is dealt
//!   (`{<verb>: <section>}` for each stated verb the document writes; architect ruling R-6).
//! * [`UnitCancel`] — the unit a `cancel` names, ended in the plane's unit table, and
//!   [`cancel_disposition`], the answer it gives.

use crate::abi::mechanism::ticket::Ticket;
use crate::abi::plane::{PlaneCancelIn, CANCEL_ABORTED, CANCEL_OK_PARTIAL};
use crate::abi::sdk::lent::Lent;
use crate::abi::sdk::publish::Keyed;

/// The refusal of a dealt blob that is JSON but not an object.
pub const NOT_A_MAP: &str = "the dealt settings are not a map of the plane's sections";

/// The section `verb` names in the dealt blob `settings`: `None` when the blob is empty, writes no
/// `verb`, or writes it `null` (the empty section); the section's value otherwise.
///
/// # Errors
/// The blob is not JSON (serde's words), or not an object ([`NOT_A_MAP`]).
pub fn dealt_section(settings: &[u8], verb: &str) -> Result<Option<serde_json::Value>, String> {
    if settings.is_empty() {
        return Ok(None);
    }
    let value: serde_json::Value = serde_json::from_slice(settings).map_err(|e| e.to_string())?;
    let serde_json::Value::Object(mut verbs) = value else {
        return Err(NOT_A_MAP.to_string());
    };
    Ok(verbs.remove(verb).filter(|section| !section.is_null()))
}

/// What a plane `cancel` names: the ticket whose op is cancelled, and the unit the host names
/// ([`PlaneCancelIn::unit`], the key its `arrive` carried; `0` names none).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnitCancel {
    /// The ticket whose op is cancelled.
    pub ticket: Ticket,
    /// The unit the host names; `0` for none.
    pub unit: u64,
}

/// What [`UnitCancel::end`] does with each unit the cancel names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ending {
    /// The unit leaves the table.
    Remove,
    /// The unit stays (the plane marks it over in `answered`, e.g. so a refusal can still render it).
    Keep,
}

impl UnitCancel {
    /// The cancel `input` names.
    #[must_use]
    pub fn of(input: &Lent<'_, PlaneCancelIn>) -> Self {
        Self {
            ticket: input.cancel().ticket(),
            unit: input.unit(),
        }
    }

    /// THE ONE CANCEL RULE over a plane's table of units by the kernel's key: the unit the host
    /// names, when the table holds it; else every unit whose pieces came on the cancelled ticket
    /// (`ticket_of`; [`Ticket::NONE`] names none). `answered` runs once on each, under the table's
    /// lock, and says whether its far end had begun its answer; the answer is whether any had.
    /// Then each leaves the table or stays, as `ending` says.
    ///
    /// A ticket is unique per instance and a unit records the ticket of its own pieces, so a ticket
    /// names at most one unit, and the op a cancel names is the named unit's own: the unit by key
    /// and the unit by ticket are the same unit whenever both are found.
    pub fn end<V>(
        self,
        units: &Keyed<u64, V>,
        ending: Ending,
        ticket_of: impl Fn(&V) -> Option<Ticket>,
        mut answered: impl FnMut(&mut V) -> bool,
    ) -> bool {
        if self.unit != 0 {
            // One entry's lock: on a sharded table the named unit is one shard's.
            let named = match ending {
                Ending::Remove => units.remove(&self.unit).map(|mut u| answered(&mut u)),
                Ending::Keep => units.with(&self.unit, |u| u.map(&mut answered)),
            };
            if let Some(named) = named {
                return named;
            }
        }
        if self.ticket == Ticket::NONE {
            return false;
        }
        units.with_all(|map| {
            let on = |u: &V| ticket_of(u) == Some(self.ticket);
            let mut any = false;
            for u in map.values_mut().filter(|u| on(u)) {
                any |= answered(u);
            }
            if ending == Ending::Remove {
                map.retain(|_, u| !on(u));
            }
            any
        })
    }
}

/// A cancelled unit's disposition: [`CANCEL_OK_PARTIAL`] when its far end had begun its answer
/// (the units it reported bill if its answer was streamed), else [`CANCEL_ABORTED`] (nothing bills).
#[must_use]
pub const fn cancel_disposition(answered: bool) -> u32 {
    if answered {
        CANCEL_OK_PARTIAL
    } else {
        CANCEL_ABORTED
    }
}

#[cfg(test)]
#[path = "tests/plane_tests.rs"]
mod tests;
