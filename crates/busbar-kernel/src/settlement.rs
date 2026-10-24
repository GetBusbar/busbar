// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The settlement WRITER: what a unit's end posts, as a pure function of what the plane reported.
//!
//! Moved verbatim out of [`crate::teller`], which re-exports every item here under its old path.
//! The loop's [`exit`](crate::teller::exit), the node's sweep and the recovery path all settle by
//! these functions; none of them reads a clock, a seal or a cell.
//!
//! THE PLANE REPORTS; THE KERNEL WRITES (`BUSBAR-1.6.0.md` §7, #77(2)). The kernel
//! decides no figure and no fee: it writes the units the plane reported and the fee units the plane
//! reported, adds no floor, and resolves no disagreement in anybody's favour. A plane that
//! under-reports is that plugin's bug. The one thing the kernel still answers itself is a unit it
//! brought back from a journal after a crash, which no live plane can report for.

use busbar_contract::caps::{MeterClassId, OriginKind, Outcome, PostingFlags};

/// Where a transport reports a status, what it reported, and what the plane made of the ending.
///
/// The contract's own, re-exported under the paths the loop has always named them by.
pub use busbar_contract::{FinishClass, StatusAt, WireStatusClass};

/// Everything the settlement writer reads: what the plane REPORTED, and what the kernel's own
/// journal knows about a unit it recovered.
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
    /// Whether this hold came back from a journal record after a crash.
    pub recovered: bool,
    /// Whether the record showed the unit had dispatched before the crash.
    pub dispatched: bool,
    /// What the last checkpoint recorded as accrued.
    pub checkpointed: u64,
    /// Whether the settle record itself was lost after value was delivered.
    pub settle_record_lost: bool,
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

/// The class the kernel's own accrual is reported against when nothing else named one.
///
/// Spelled ONCE. The exit path, the sweep and the recovery path all post against the same class,
/// and three string literals for one class is three places a typo can put a settled unit on a meter
/// nobody prices.
pub const KERNEL_ACCRUAL_CLASS: MeterClassId = MeterClassId::new("nano_units");

/// THE SETTLEMENT WRITER. It writes what it is told, whatever the unit's end was: a cut bills what
/// streamed (#62), a failed unit bills what the plane reported of it, and nothing is ever floored,
/// zeroed or lowered by the kernel.
///
/// 1. **Recovered from a journal record.** No live plane can report for it. If the record shows the
///    unit had dispatched, write the last checkpoint (zero if there never was one), marked
///    recovered; if it had not dispatched, nothing happened: write zero, marked void. Never a guess
///    upward.
/// 2. **Anything else.** Write the plane's reported figure. A unit whose plane reported nothing
///    writes zero; when it also did not complete, the zero is marked estimated, so the posting
///    says in its own marks that no far end stood behind the end it reached.
///
/// A lost settle record adds its own mark on top: the posting is retained and re-appended.
pub fn settle_written(end: &Outcome, evidence: &Evidence) -> Written {
    let (amount, flags) = if evidence.recovered {
        if evidence.dispatched {
            (evidence.checkpointed, PostingFlags::RECOVERED)
        } else {
            (0, PostingFlags::VOIDED)
        }
    } else {
        match evidence.reported {
            Some(reported) => (reported, PostingFlags::NONE),
            None if end.is_completed() => (0, PostingFlags::NONE),
            None => (0, PostingFlags::ESTIMATED),
        }
    };
    let flags = if evidence.settle_record_lost {
        flags.with(PostingFlags::UNPOSTED)
    } else {
        flags
    };
    Written {
        amount,
        flags,
        fee: evidence.fee_units,
    }
}

/// How many request slots a unit draws at the door.
///
/// A client unit whose verified set contains an upstream draws one; everything else draws none, so
/// a provider push consumes no client's slot.
pub fn requests_drawn(origin: OriginKind, upstream_candidate: bool) -> u32 {
    u32::from(origin == OriginKind::Client && upstream_candidate)
}

/// How many request slots a unit settles at.
///
/// The drawn quantity, for every unit whose hold cell reached admitted — and it is NEVER released,
/// whatever the unit's end. That is the rule that makes it impossible to escape a cap by failing:
/// a thousand failed requests consume a thousand slots and post no fee at all.
pub fn requests_settled(reached_admitted: bool, drawn: u32) -> u32 {
    if reached_admitted {
        drawn
    } else {
        0
    }
}
