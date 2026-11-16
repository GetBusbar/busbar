// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! MIN-3 plane usage (IF §12.4): the cumulative USAGE kept per session, the cancel table that decides
//! what a session's end bills, and the one generic mapping from a USAGE onto a ledger `UsageLine`.
//!
//! The plane reports quantities only (§8.6 `UsageRec`, class text in the tail). Core keeps, per session,
//! the last value per (class, source) any `request`, `piece` or `end` answer stated; it never adds two
//! USAGE of one (class, source). When the session ends, [`bill`] decides from core's own facts
//! (`far_end_answered`, `streamed`) what of that set is posted, and [`DeclaredClasses::map`] turns it
//! into `UsageLine`s for the existing `Posting::from_usage` + `cost::price` path.

use busbar_contract::caps::{QuantitySource, ReasonCode, UsageLine};
use busbar_contract::{Count, MeterClassId};
use busbar_plugin_abi::plane::{UsageRec, SRC_ESTIMATED, SRC_FLOOR, SRC_REPORTED};

/// The four pinned 1.5.5 cancel rules, as core's own text (IF §12.4). Byte-equal to the headings of
/// busbar-contract abi/plane/mod.rs until D1 deletes that module; C-CANCEL-BILL pins it.
pub const CANCEL_RULES: [&str; 4] = [
    "A TRANSLATE-ABORT IS NEVER BILLED",
    "ONLY FAR-END-REPORTED USAGE IS BILLED",
    "A NON-STREAMED PARTIAL BILLS ZERO",
    "THE BUDGET REFUND IS A SEPARATE ACT",
];

/// The most scale a USAGE may state (§8.6: scale 0..=9).
pub const MAX_SCALE: u32 = 9;

/// The longest class text (§8.6: `[a-z0-9_.:]{1,64}`).
pub const MAX_CLASS: usize = 64;

/// Round 11: a core cancel bills the reported units only when a byte of the reply reached the client
/// (rule 3). The plane no longer answers a disposition, so this is `streamed`.
#[must_use]
pub const fn cancel_bills_reported_units(streamed: bool) -> bool {
    streamed
}

/// Whether a USAGE source bills on a cancel (rule 2): SRC_REPORTED and SRC_FLOOR do, SRC_ESTIMATED never.
#[must_use]
pub const fn source_bills(source: u32) -> bool {
    matches!(source, SRC_REPORTED | SRC_FLOOR)
}

/// A USAGE the session may not keep.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsageInvalid {
    /// The class text is empty, longer than 64 bytes or outside `[a-z0-9_.:]`.
    Class,
    /// `scale` > 9.
    Scale,
    /// `source` is not SRC_REPORTED, SRC_ESTIMATED or SRC_FLOOR.
    Source,
}

/// One kept value: the session's running total for (class, source).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reported {
    pub class: Box<str>,
    pub source: u32,
    pub amount: u64,
    pub scale: u32,
}

/// The last value per (class, source) a session answered (IF §12.4, §8.6 `UsageRec` round 11).
#[derive(Debug, Clone, Default)]
pub struct SessionUsage {
    last: Vec<Reported>,
}

impl SessionUsage {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Keep one USAGE from any `request`, `piece` or `end` answer: it replaces the (class, source)'s
    /// previous value, never adds to it.
    pub fn answer(&mut self, class: &str, rec: UsageRec) -> Result<(), UsageInvalid> {
        if class.is_empty()
            || class.len() > MAX_CLASS
            || !class
                .bytes()
                .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b':'))
        {
            return Err(UsageInvalid::Class);
        }
        if rec.scale > MAX_SCALE {
            return Err(UsageInvalid::Scale);
        }
        if !matches!(rec.source, SRC_REPORTED | SRC_ESTIMATED | SRC_FLOOR) {
            return Err(UsageInvalid::Source);
        }
        if let Some(kept) = self
            .last
            .iter_mut()
            .find(|r| r.source == rec.source && &*r.class == class)
        {
            kept.amount = rec.amount;
            kept.scale = rec.scale;
        } else {
            self.last.push(Reported {
                class: class.into(),
                source: rec.source,
                amount: rec.amount,
                scale: rec.scale,
            });
        }
        Ok(())
    }

    /// The kept set, in first-answered order.
    #[must_use]
    pub fn last(&self) -> &[Reported] {
        &self.last
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.last.is_empty()
    }
}

/// How a session ended, from core's own facts (never the plane's word alone).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ending {
    /// The plane's `end` was called (also a cancel that came after `end` was called).
    End,
    /// Core cancelled it: client gone, deadline, budget cut or drain.
    Cancel {
        cause: ReasonCode,
        /// An upstream exchange of this session returned its head.
        far_end_answered: bool,
        /// A byte of the reply reached the client.
        streamed: bool,
    },
    /// A plane FAULT, a quarantine or a failed `end` (today's CANCEL_FAILED).
    Failed,
}

/// What a session's end posts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bill<'a> {
    /// These kept values, once.
    Usage(Vec<&'a Reported>),
    /// `Usage::estimate`: the session ended by `end` and answered no USAGE.
    Estimate,
    /// Nothing at all (no estimate either).
    Nothing,
}

/// The §12.4 cancel table. Rule 4 (the budget hold is released on its own path, whatever the bill) is
/// the caller's: this never folds in or returns the refund.
#[must_use]
pub fn bill(ending: Ending, usage: &SessionUsage) -> Bill<'_> {
    match ending {
        Ending::Failed => Bill::Nothing,
        Ending::End if usage.is_empty() => Bill::Estimate,
        Ending::End => Bill::Usage(usage.last.iter().collect()),
        Ending::Cancel {
            far_end_answered,
            streamed,
            ..
        } => {
            if !far_end_answered || !cancel_bills_reported_units(streamed) {
                return Bill::Nothing;
            }
            let kept: Vec<&Reported> = usage
                .last
                .iter()
                .filter(|r| source_bills(r.source))
                .collect();
            if kept.is_empty() {
                Bill::Nothing
            } else {
                Bill::Usage(kept)
            }
        }
    }
}

/// The quantity a USAGE states, at the ledger's micro-unit scale. Scale > 6 rounds half-even; the second
/// value says it rounded (the caller audits it).
#[must_use]
pub fn scaled(amount: u64, scale: u32) -> Option<(Count, bool)> {
    if scale > MAX_SCALE {
        return None;
    }
    let amount = i128::from(amount);
    if scale <= 6 {
        return Some((Count::from_micros(amount * 10_i128.pow(6 - scale)), false));
    }
    let divisor = 10_i128.pow(scale - 6);
    let (quotient, remainder) = (amount / divisor, amount % divisor);
    let twice = remainder * 2;
    let up = twice > divisor || (twice == divisor && quotient % 2 == 1);
    Some((
        Count::from_micros(quotient + i128::from(up)),
        remainder != 0,
    ))
}

/// One D_USAGE_CLASS the plane described.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DeclaredClass {
    pub class: MeterClassId,
    pub unit: u32,
    /// NaN = no default (left out of candidate cost recipes).
    pub expected_units: f64,
}

/// The classes an instance declared at describe, interned by the caller (`vocabulary::Registration`).
#[derive(Debug, Clone, Default)]
pub struct DeclaredClasses {
    classes: Vec<DeclaredClass>,
}

/// The mapped lines of one bill, with what the caller audits.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Mapped {
    pub lines: Vec<UsageLine>,
    /// Classes the plane never declared: dropped and audited (C-USAGE).
    pub dropped: Vec<Box<str>>,
    /// Classes whose scale > 6 was rounded half-even: audited.
    pub rounded: Vec<Box<str>>,
}

impl DeclaredClasses {
    #[must_use]
    pub fn new(classes: Vec<DeclaredClass>) -> Self {
        Self { classes }
    }

    #[must_use]
    pub fn get(&self, class: &str) -> Option<&DeclaredClass> {
        self.classes.iter().find(|d| d.class.as_str() == class)
    }

    #[must_use]
    pub fn classes(&self) -> &[DeclaredClass] {
        &self.classes
    }

    /// Map each billed value to one `UsageLine`: class = the declared class, quantity =
    /// [`scaled`], source = the figure the plane reported (`QuantitySource::Count`, as the teller writes
    /// a plane's figure), `estimated` for SRC_ESTIMATED and SRC_FLOOR (the node's floor, not a figure the
    /// far end reported).
    #[must_use]
    pub fn map(&self, billed: &[&Reported]) -> Mapped {
        let mut mapped = Mapped::default();
        for r in billed {
            let Some(declared) = self.get(&r.class) else {
                if !mapped.dropped.contains(&r.class) {
                    mapped.dropped.push(r.class.clone());
                }
                continue;
            };
            let Some((quantity, rounded)) = scaled(r.amount, r.scale) else {
                continue;
            };
            if rounded && !mapped.rounded.contains(&r.class) {
                mapped.rounded.push(r.class.clone());
            }
            mapped.lines.push(UsageLine {
                class: declared.class,
                quantity,
                source: QuantitySource::Count,
                estimated: r.source != SRC_REPORTED,
            });
        }
        mapped
    }
}

#[cfg(test)]
#[path = "tests/usage_tests.rs"]
mod usage_tests;
