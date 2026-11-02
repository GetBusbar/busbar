// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::caps::{MeterClassId, OriginKind, Outcome, PostingFlags};

pub use busbar_contract::{FinishClass, StatusAt, WireStatusClass};

/// Everything the settlement writer reads: what the plane REPORTED.
///
/// Deliberately plain data: the writer is a pure function of this.
#[derive(Debug, Clone, Default)]
pub struct Evidence {
    /// The figure the plane reported for the unit, from far-end-reported units only; `None` when
    /// it reported none. An estimate is never a report and never reaches here.
    pub reported: Option<u64>,
    /// The fee units the plane reported: whether the unit incurred the flat fee, as the plane
    /// decided it (#44). The kernel decides no fee of its own.
    pub fee_units: u32,
    /// Which class the settled amount is reported against.
    pub class: Option<MeterClassId>,
    /// Whether the verified set contained an upstream candidate, which is what makes a client unit
    /// draw a request slot.
    pub upstream_candidate: bool,
}

/// What the writer writes for one unit: the amount, its marks, and the fee units.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Written {
    /// The amount the posting settles.
    pub amount: u64,
    /// The marks it carries.
    pub flags: PostingFlags,
    /// The fee units it carries, as the plane reported them.
    pub fee: u32,
}

pub const KERNEL_ACCRUAL_CLASS: MeterClassId = MeterClassId::new("nano_units");

pub fn settle_written(end: &Outcome, evidence: &Evidence) -> Written {
    let (amount, flags) = match evidence.reported {
        Some(reported) => (reported, PostingFlags::NONE),
        None if end.is_completed() => (0, PostingFlags::NONE),
        None => (0, PostingFlags::ESTIMATED),
    };
    Written {
        amount,
        flags,
        fee: evidence.fee_units,
    }
}

pub fn requests_drawn(origin: OriginKind, upstream_candidate: bool) -> u32 {
    u32::from(origin == OriginKind::Client && upstream_candidate)
}

pub fn requests_settled(reached_admitted: bool, drawn: u32) -> u32 {
    if reached_admitted {
        drawn
    } else {
        0
    }
}
