// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The closed set of places a quantity may come from.
//!
//! The set is closed on purpose. A quantity that could come from anywhere is a quantity nobody can
//! check, and a plane that could invent a source could invent an invoice. Adding an eighth source
//! is a change to this enum, which is a change somebody has to review.

/// Which side of a unit a located quantity belongs to. The three input-side directions partition
/// the same bytes, so a hold sizes them as one; the kernel direction sits outside that partition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Direction {
    /// Bytes the caller sent that the destination had to read fresh.
    Input,
    /// Bytes the destination produced.
    Output,
    /// Input the destination served from its own cache.
    CacheRead,
    /// Input the destination wrote into its cache.
    CacheWrite,
    /// A quantity the kernel derived for itself rather than one either side reported.
    Kernel,
}

/// Where in a decoded payload a locator found its value.
// contract: the locator expression the plane declares
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuantitySource {
    /// A value the destination itself reported, found at a declared location in its payload and
    /// evaluated as the frames arrived.
    Locator {
        /// Which side of the unit the value belongs to.
        direction: Direction,
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

    /// Turn a raw measurement into the class's own quantity.
    ///
    /// A divisor of nothing yields nothing rather than dividing by zero — a class declared with no
    /// divisor cannot convert bytes, and refusing to guess is the safe reading. The frame factor
    /// saturates rather than wrapping.
    pub fn quantity_from_raw(&self, raw: u64) -> u64 {
        match self {
            QuantitySource::KernelBytes { divisor } => {
                if *divisor == 0 {
                    0
                } else {
                    raw / divisor
                }
            }
            QuantitySource::KernelFrames { factor } => raw.saturating_mul(*factor),
            _ => raw,
        }
    }
}
