// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The closed set of places a quantity may come from, and the one conversion this unit adds to it.
//!
//! The set itself lives in `busbar-caps`, beside the usage report that carries it, because three
//! crates read a source: this unit writes it, the ledger settles against it, and the audit record
//! carries it into the journal. It was spelled three different ways before — seven arms here, four
//! in the audit crate, none in the capability crate — which meant the independent recompute and the
//! record it is checked against could disagree about what the same number was.
//!
//! What stays here is the raw-to-quantity conversion, because it is metering policy: the divisor
//! and the factor are this unit's reading of a class declaration, not part of what a provenance IS.

pub use busbar_caps::{LocatorPtr, QuantitySource};
pub use busbar_contract::ClassDirection as Direction;

/// Turn a raw measurement into the class's own quantity.
///
/// A divisor of nothing yields nothing rather than dividing by zero — a class declared with no
/// divisor cannot convert bytes, and refusing to guess is the safe reading. The frame factor
/// saturates rather than wrapping.
pub fn quantity_from_raw(source: &QuantitySource, raw: u64) -> u64 {
    match source {
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
