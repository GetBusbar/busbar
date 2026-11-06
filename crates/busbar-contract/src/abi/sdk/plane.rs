// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLANE KIND'S SHARED PIECES (`abi::plane`): what the planes wrote alike, stated once.

use crate::abi::mechanism::ticket::Ticket;
use crate::abi::plane::{OnPieceOut, OutField, RecordWrite, UnitCount};
use crate::abi::plane::{PlaneCancelIn, CANCEL_ABORTED, CANCEL_OK_PARTIAL};
use crate::abi::sdk::lent::Lent;
use crate::abi::sdk::publish::Keyed;
use crate::abi::sdk::{lent::HostBuf, out::Out};

pub mod conditional;

/// Settle every piece buffer together. If any buffer is short, all written counts are zero
/// and all required counts are reported so the host can retry the complete answer atomically.
pub fn settle_piece(
    out: &mut Out<'_, OnPieceOut>,
    fields: &HostBuf<'_, OutField>,
    units: &HostBuf<'_, UnitCount>,
    arena: &HostBuf<'_, u8>,
    records: Option<&HostBuf<'_, RecordWrite>>,
) -> bool {
    let short =
        !(fields.fits() && units.fits() && arena.fits() && records.is_none_or(HostBuf::fits));
    if let Some(records) = records {
        let (written, needed) = records.settle(short);
        out.set(|o| &o.records_written, written as u32);
        out.set(|o| &o.records_needed, needed as u32);
    }
    let (fw, fn_) = fields.settle(short);
    let (uw, un) = units.settle(short);
    let (aw, an) = arena.settle(short);
    out.set(|o| &o.fields_written, fw as u32);
    out.set(|o| &o.fields_needed, fn_ as u32);
    out.set(|o| &o.units_written, uw as u32);
    out.set(|o| &o.units_needed, un as u32);
    out.set(|o| &o.arena_written, aw as u64);
    out.set(|o| &o.arena_needed, an as u64);
    short
}

/// The refusal of a dealt blob that is JSON but not an object.
pub const NOT_A_MAP: &str = "the dealt settings are not a map of the plane's sections";

/// The section `verb` names in the dealt blob `settings`: `None` when the blob is empty, writes no
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
    pub fn end<V>(
        self,
        units: &Keyed<u64, V>,
        ending: Ending,
        ticket_of: impl Fn(&V) -> Option<Ticket>,
        mut answered: impl FnMut(&mut V) -> bool,
    ) -> bool {
        if self.unit != 0 {
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
