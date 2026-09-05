// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What a unit used, as the usage unit reports it.

use crate::step::MeterClassId;
use crate::token::UsageToken;

/// The most lines one unit's usage report may carry. A bound, not a guess: the record the journal
/// writes is fixed-size, so the report that feeds it has to be bounded too.
pub const MAX_USAGE_LINES: usize = 16;

/// One reported quantity, against one declared meter class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageLine {
    /// Which declared class this quantity belongs to.
    pub class: MeterClassId,
    /// How much of it, in the class's own quantity.
    pub quantity: u64,
}

/// Why a usage report was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsageError {
    /// More lines than the fixed-size record can hold.
    TooManyLines,
}

impl std::fmt::Display for UsageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("more usage lines than the record can hold")
    }
}

impl std::error::Error for UsageError {}

/// What the unit used: the folded report the ledger settles against.
///
/// Built only by the usage unit, with its own token — a plane can say what it saw, but only the
/// usage unit can turn that into the figure that moves money. A report the destination never
/// confirmed is marked estimated, and that mark travels all the way onto the posting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Usage {
    lines: Vec<UsageLine>,
    estimated: bool,
}

impl Usage {
    /// Report what the unit used.
    pub fn report(_token: &UsageToken, lines: Vec<UsageLine>) -> Result<Self, UsageError> {
        if lines.len() > MAX_USAGE_LINES {
            return Err(UsageError::TooManyLines);
        }
        Ok(Usage {
            lines,
            estimated: false,
        })
    }

    /// Report the kernel's own floor, because the destination reported nothing.
    pub fn estimate(token: &UsageToken, lines: Vec<UsageLine>) -> Result<Self, UsageError> {
        let mut usage = Usage::report(token, lines)?;
        usage.estimated = true;
        Ok(usage)
    }

    /// The reported lines.
    pub fn lines(&self) -> &[UsageLine] {
        &self.lines
    }

    /// The sum across every line.
    pub fn total(&self) -> u64 {
        self.lines
            .iter()
            .fold(0u64, |acc, l| acc.saturating_add(l.quantity))
    }

    /// Whether this is the kernel's floor rather than a reported figure.
    pub fn is_estimated(&self) -> bool {
        self.estimated
    }
}
