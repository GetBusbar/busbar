// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What a unit used, as the usage unit reports it.

use crate::step::MeterClassId;
use crate::token::UsageToken;
use busbar_contract::ClassDirection;

/// The most lines one unit's usage report may carry. A bound, not a guess: the record the journal
/// writes is fixed-size, so the report that feeds it has to be bounded too.
pub const MAX_USAGE_LINES: usize = 16;

/// Where in a decoded payload a locator found its value.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LocatorPtr(String);

impl LocatorPtr {
    /// Name a location inside a payload.
    pub fn new(ptr: impl Into<String>) -> Self {
        LocatorPtr(ptr.into())
    }

    /// The pointer as the audit row records it.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Where one reported quantity came from.
///
/// The set is closed on purpose. A quantity that could come from anywhere is a quantity nobody can
/// check, and a plane that could invent a source could invent an invoice. Adding an eighth source
/// is a change to this enum, which is a change somebody has to review.
///
/// It lives here rather than in the unit that folds it because three crates read it: the usage unit
/// writes it, the ledger settles against it, and the audit record carries it. Three spellings of
/// one provenance means the independent recompute and the record it is checked against can disagree
/// about what the same number was.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuantitySource {
    /// A value the destination itself reported, found at a declared location in its payload and
    /// evaluated as the frames arrived.
    Locator {
        /// Which side of the unit the value belongs to.
        direction: ClassDirection,
        /// Where in the payload it was found.
        ptr: LocatorPtr,
    },
    /// Bytes the kernel counted, divided by a declared divisor. The division floors, so the result
    /// is a floor and is marked as an estimate.
    KernelBytes {
        /// How many bytes make one unit of the class's quantity.
        divisor: u64,
    },
    /// Frames the kernel counted, times a declared factor. Exact — a frame is a whole thing.
    KernelFrames {
        /// How many units of quantity one frame is worth.
        factor: u64,
    },
    /// A transport that decodes its own timestamped payload, reporting units from the timestamp
    /// deltas over its clock rate. Available only where the transport declares that it decodes.
    TransportUnits,
    /// Time the kernel measured on a clock that cannot go backwards.
    KernelElapsedMono,
    /// A count the kernel derived — recipients resolved, frames relayed, requests admitted.
    Count,
    /// A cardinality a plane surfaced as a declared content fact: calls, objects, rows, queries,
    /// messages. Priced only against a class the config declares, and paired with a kernel-derived
    /// companion in the same unit wherever one exists, so the variance rule has something to
    /// compare against.
    PlaneCount {
        /// The declared content fact the cardinality was read from.
        content_fact_key: String,
    },
}

impl QuantitySource {
    /// Whether the kernel derived this figure itself, rather than reading it from something
    /// somebody else said.
    pub fn is_kernel_derived(&self) -> bool {
        matches!(
            self,
            QuantitySource::KernelBytes { .. }
                | QuantitySource::KernelFrames { .. }
                | QuantitySource::KernelElapsedMono
                | QuantitySource::Count
        )
    }

    /// Whether this figure was reported by somebody other than the kernel, and therefore wants a
    /// companion to be checked against.
    pub fn is_reported(&self) -> bool {
        !self.is_kernel_derived()
    }

    /// Whether a figure from this source is a floor rather than an exact count. Only the byte
    /// division is: it floors, and a floor is an estimate.
    pub fn is_floor(&self) -> bool {
        matches!(self, QuantitySource::KernelBytes { .. })
    }
}

/// One reported quantity, against one declared meter class.
///
/// The source and the estimate mark travel with the quantity, because a figure the destination
/// confirmed and a figure the node floored are not the same evidence, and a billing dispute turns
/// on exactly that difference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageLine {
    /// Which declared class this quantity belongs to.
    pub class: MeterClassId,
    /// How much of it, in the class's own quantity.
    pub quantity: u64,
    /// Where the number came from.
    pub source: QuantitySource,
    /// Whether this line is the node's floor rather than a figure somebody reported.
    pub estimated: bool,
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
