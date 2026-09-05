// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Hold sizing.
//!
//! The hold is ACCOUNTING. It sizes the ledger's reservation for a unit that has already been
//! admitted; it is not a second door and it never refuses a unit the decision admitted. If it
//! turns out to be too small the unit tops it up, and if there is nothing to top up from the unit
//! still runs to its end and posts the excess. Nothing here can make a request fail that would
//! otherwise have succeeded — which is exactly why the hold's conservatism is invisible to a
//! caller and does not need a parity exception.
//!
//! The size is the per-class estimated quantity times the most expensive unit price for that class
//! over the destinations the unit may reach, summed, plus the flat fee as its own line, all
//! multiplied by the chain's tier and rounded UP once.

// contract: Estimate { per_class } is a type the contract crate owns. It is declared here so the
// door has something to size against while the crates land side by side.

/// One meter class's contribution to the estimate: how much of it the unit is expected to consume,
/// and the highest price any destination it may reach charges for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassEstimate {
    /// The meter class this line is for.
    pub class: String,
    /// The estimated quantity, in the class's own units, already converted from bytes through the
    /// class's divisor by the caller.
    pub quantity: u64,
    /// The highest per-unit price, in nano-units, over the verified destination set. The maximum,
    /// not the mean: a hold that is too small has to top up, and a hold that is too large costs
    /// nothing but headroom the unit gives straight back at settlement.
    pub max_unit_price_nanos: u64,
}

/// What the unit is expected to consume, per meter class, plus the flat fee line.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Estimate {
    /// One line per meter class.
    pub per_class: Vec<ClassEstimate>,
    /// The flat per-request fee line, in nano-units, already zero for every unit that does not
    /// pay one — a provider push, a heartbeat, a kernel verb.
    pub fee_nanos: u64,
}

impl Estimate {
    /// An estimate with nothing in it: the shape of a unit priced at zero.
    pub fn zero() -> Self {
        Self::default()
    }

    /// The summed pre-tier size, in nano-units, before the chain's multiplier is applied.
    pub fn pre_tier_nanos(&self) -> u128 {
        let mut total: u128 = self.fee_nanos as u128;
        for line in &self.per_class {
            total =
                total.saturating_add((line.quantity as u128) * (line.max_unit_price_nanos as u128));
        }
        total
    }

    /// The hold size in nano-units: the pre-tier sum times the chain's tier in basis points,
    /// rounded UP once over the whole sum — one divide, never a sum of per-line ceilings, so the
    /// figure does not drift with how the estimate happened to be split into lines.
    pub fn hold_nanos(&self, tier_bp: u32) -> u64 {
        let pre = self.pre_tier_nanos();
        let scaled = pre.saturating_mul(tier_bp as u128);
        let ceil = scaled.div_ceil(10_000);
        u64::try_from(ceil).unwrap_or(u64::MAX)
    }
}
