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
//!
//! ## ONE GUARD POLICY FOR THIS FILE: EVERY OPERATOR SATURATES
//!
//! Every arithmetic operator here is `saturating_*`, and the multiply-and-sum is not this file's at
//! all — it delegates to [`busbar_kernel_ledger::cost::nanos_sum`], the pricing law's fold, so the
//! hold is sized by the arithmetic the bill is computed with rather than by a second copy of it.
//! It used to carry its own: a `saturating_add` around a BARE `*`, which is the shape the crate's
//! own `nanos_sum` doc calls out — *"a comment that says only that is TRUE AND BESIDE THE POINT,
//! which is exactly how the unguarded copy read and exactly why it survived review."*
//!
//! ## WHY THE HOLD ROUNDS UP AND THE BILL DOES NOT
//!
//! [`Estimate::hold_nanos`] rounds the tier term UP. [`busbar_kernel_ledger::cost::apply_tier`]
//! rounds it HALF-TO-EVEN (#44 `BUSBAR-1.6.0.md:372`). That is a deliberate difference and not a
//! drift, because the two are not the same operation: a BILL is what the customer pays and #44
//! governs its rounding, while a HOLD is a RESERVATION that is released at settlement and is never
//! paid by anybody. Rounding a reservation up costs a caller nothing (the module header above says
//! why: a hold that is too large gives the headroom straight back) and rounding it down risks a
//! hold too small for the unit it was opened for. A reservation and a price are different nouns and
//! this is the one place the tree is entitled to round them differently.

// contract: Estimate { per_class } is a type the contract crate owns. It is declared here so the
// door has something to size against while the crates land side by side.

/// How many basis points make one whole unit — the divisor that turns a tier expressed in basis
/// points back into a multiplier. A tier of 10 000 basis points is a multiplier of one, so a hold
/// sized at the full tier is the pre-tier sum unchanged.
///
/// Named rather than written at the divide, because a bare ten thousand at the bottom of a
/// money calculation is indistinguishable from a rounding scale or a percentage-times-hundred, and
/// the three are not interchangeable.
const BASIS_POINTS_PER_UNIT: u128 = 10_000;

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
    ///
    /// THE FOLD IS [`busbar_kernel_ledger::cost::nanos_sum`]'S, not this file's. What is left here
    /// is which quantity pairs with which price; the multiply, the sum and the saturation at both
    /// steps belong to the one implementation.
    ///
    /// This sizes a RESERVATION, not a spend figure: an over-estimate a unit gives back at
    /// settlement, rounded UP (see [`Self::hold_nanos`]). Every spend figure — what the door
    /// compares to a cap and what a read serves — is the one function's
    /// ([`busbar_kernel_ledger::cost::Tally`], through [`crate::price::Pricer::derive_spend_cents`]).
    ///
    /// The fee enters as a LINE rather than as a scalar seed — `(fee_nanos, 1)`, a quantity of
    /// `fee_nanos` at a price of one — so it is summed by the same guarded fold as everything else
    /// instead of being the one term that got in before the guard. The previous spelling seeded the
    /// accumulator with the fee and then folded a BARE `*` over the classes: `u64 × u64` fits a
    /// `u128` so that product could not overflow, but "the product is safe" is the true-and-beside-
    /// the-point reading the crate's own fold documents, and it is the SUM that reaches ~2^130.
    pub fn pre_tier_nanos(&self) -> u128 {
        busbar_kernel_ledger::cost::nanos_sum(
            std::iter::once((self.fee_nanos, 1)).chain(
                self.per_class
                    .iter()
                    .map(|line| (line.quantity, line.max_unit_price_nanos)),
            ),
        )
    }

    /// The hold size in nano-units: the pre-tier sum times the chain's tier in basis points,
    /// rounded UP once over the whole sum — one divide, never a sum of per-line ceilings, so the
    /// figure does not drift with how the estimate happened to be split into lines.
    ///
    /// UP, not half-to-even, and the module header says why: this sizes a reservation, not a bill.
    ///
    /// The multiply saturates BEFORE the divide, which is the shape that under-bills by four orders
    /// of magnitude wherever it sizes MONEY — and it is checked here rather than assumed. It cannot
    /// under-size this hold: for the saturation to bite at all the product must reach `2^128`, and
    /// `u128::MAX / 10_000` is still about `3.4e34`, which the `u64` narrowing on the last line
    /// clamps to `u64::MAX` (about `1.8e19`) exactly as the true figure would be clamped. Every
    /// input that saturates the multiply therefore returns `u64::MAX` either way, so the ordering
    /// is unobservable HERE while being a live defect where the same shape sized a bill. Stated
    /// rather than tidied, because the reason it is safe is the narrowing and not the arithmetic,
    /// and a future change to the return type would take the safety with it.
    pub fn hold_nanos(&self, tier_bp: u32) -> u64 {
        let pre = self.pre_tier_nanos();
        let scaled = pre.saturating_mul(tier_bp as u128);
        let ceil = scaled.div_ceil(BASIS_POINTS_PER_UNIT);
        u64::try_from(ceil).unwrap_or(u64::MAX)
    }
}
