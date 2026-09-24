// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! The money arithmetic: a dated rate-card history, the quantities a posting stores, and the lookup
//! that turns the two into a price.
//!
//! Everything here is a pure function over integers. No clock, no store, no config parser and no
//! plane appears in this crate, so an auditor can re-derive an invoice from the source by hand.
//!
//! # The three layers
//!
//! ```text
//!   layer 0   QUANTITIES   what happened, and when            immutable, the truth
//!   layer 1   HISTORY      what things cost, and since when   append-only, sequenced
//!   layer 2   LOOKUP       price(layer 0, layer 1)            pure, derived, never truth
//! ```
//!
//! Layer zero is [`Posting`]: quantities per meter class, the lane, the fee count, the tier and the
//! instant. Layer one is [`History`]: entries of `(effective_from, card)`, appended and never
//! rewritten. Layer two is [`price`]. Nothing priced is authoritative — a [`CachedPrice`] on a
//! posting is a convenience, and where it disagrees with a lookup the lookup wins.
//!
//! # The five clauses, and where each one lives
//!
//! 1. **Rates.** Config carries micro-units per quantity as a decimal. The one
//!    conversion to the integer nano-unit rate happens once, when the card is built: multiply by a
//!    thousand and round to nearest, half away from zero; anything not finite or not positive clamps
//!    to zero. See [`nano_rate`]. After that point no decimal number touches money again.
//! 2. **Storage.** A posting stores QUANTITIES and the instant they happened, and nothing priced.
//!    See [`Posting`].
//! 3. **Projections.** Minor units and micro-units are read-only views of the summed nano-units,
//!    each truncating exactly once at the very end. Minor units floor at zero; micro-units do not.
//!    See [`minor_of`] and [`micros_of`]. The divisor is [`NANOS_PER_CENT`] — THE ONE SCALE, and the
//!    only one there is.
//! 4. **Append-only.** A card is never replaced. A price change APPENDS a [`CardEntry`], and a
//!    posting prices at whatever [`HistoryView::card_at`] resolves for its own instant, so an edit
//!    prices what happens after it rather than what happened before it. See [`History::append`].
//! 5. **Tier.** One multiplier per chain, in basis points, applied once over the summed pre-tier
//!    amount — a single divide, never a sum of per-line floors, rounded HALF-TO-EVEN because it is
//!    a per-N-units division term (#44 `BUSBAR-1.6.0.md:372`, restated at #81 `:428`). There is ONE
//!    implementation of it, [`apply_tier`]; [`checked_apply_tier`] is the same arithmetic refusing
//!    instead of pinning, and [`apply_tier_signed`] is the same arithmetic on a signed column.
//!
//! # Money is UNITLESS
//!
//! #66 (`BUSBAR-1.6.0.md:528`, owner-locked): *"Money is UNITLESS abstract cost — no currency type,
//! no symbol … rate card + ledger + views are unitless numbers."* There is no currency type in this
//! crate, no currency argument to any function here, and exactly one scale — [`NANOS_PER_CENT`] —
//! which is therefore not a choice anything can make. What a figure is DISPLAYED as, and in what
//! denomination, belongs to the operator's dashboard and is invisible from here
//! (`docs/configuration.md:634`).
//!
//! That absence is a money property, not a tidiness one. A scale that could be NAMED could be named
//! differently by two readers of the same figures, or moved by a request body — and moving it moves
//! every figure on the card by a power of ten with no conversion and nothing said.
//!
//! # The two readers
//!
//! [`price`] is the lookup. [`derive_spend_cents`] and [`derive_spend_micros`] are the legacy
//! read-time derivation over a whole bucket's lanes at one card, kept because the legacy usage
//! projection still reads that way. A property test asserts the two agree: the lookup over a
//! single-entry history equals the legacy derivation at that card, exactly.

mod history;
mod posting;
mod project;
mod rate;
mod view;

/// The exact count type the one function prices — re-exported so a caller driving a
/// [`Tally`] names it through the crate that prices it.
pub use busbar_contract::count::Count;
pub use history::{Author, CardEntry, CardEntryDraft, History, HistorySeq, HistoryView};
pub use posting::{
    apply_tier, apply_tier_signed, checked_apply_tier, price, price_at_card, price_fail_closed,
    CachedPrice, Posting, Priced, PricedLine, Quantity, Unpriceable, FEE_CLASS, STANDARD_TIER_BP,
};
pub use project::{
    cents_of, derive_spend_cents, derive_spend_micros, derive_spend_minor, micros_of, minor_of,
};
pub use rate::{
    nano_rate, nanos_sum, representable_nano_rate, CellPrices, LaneClass, LaneRates, RateCard,
    TierRates, CLASS_CACHE_READ, CLASS_CACHE_WRITE, CLASS_INPUT, CLASS_OUTPUT,
};
pub use view::{
    nanos_of_exact, price as price_ledger, price_exact, price_in_view, whole, LedgerEntry, Money,
    MoneyError, Tally, EXACT_SCALE, MONEY_SCALE,
};

/// **THE ONE SCALE.** Nano-units in one minor unit: ten million.
///
/// This is the ONLY divisor on the money path (#66 `BUSBAR-1.6.0.md:528`). There is no currency
/// type to ask for a second one, no table of minor-unit exponents to look one up in, and no request
/// body, config key or label that can move it — a scale nothing can name is a scale nothing can
/// change. It is the number every 1.5.5 cent projection divided by, so every figure that release
/// produced comes out of this tree bit-identical.
///
/// The name is historical ("cent") and the quantity is not: money here is unitless abstract cost,
/// and a minor unit is a hundredth of one abstract unit because that is the granularity 1.5.5
/// billed at. Denomination and symbol are the dashboard's (`docs/configuration.md:634`).
pub const NANOS_PER_CENT: u128 = 10_000_000;

/// Nano-units in one micro-unit, for the finer of the two read projections.
pub const NANOS_PER_MICRO: u128 = 1_000;

/// Micro-units in one minor unit — [`NANOS_PER_CENT`] over [`NANOS_PER_MICRO`] — the factor the
/// flat fee is lifted by in the micro projection. A test says the three agree.
pub const MICROS_PER_CENT: i64 = 10_000;

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;
