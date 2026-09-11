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
//!   layer 2   LOOKUP       price(layer 0, layer 1, currency)  pure, derived, never truth
//! ```
//!
//! Layer zero is [`Posting`]: quantities per meter class, the lane, the fee count, the tier and the
//! instant. Layer one is [`History`]: entries of `(effective_from, card)`, appended and never
//! rewritten. Layer two is [`price`]. Nothing priced is authoritative — a [`CachedPrice`] on a
//! posting is a convenience, and where it disagrees with a lookup the lookup wins.
//!
//! # The five clauses, and where each one lives
//!
//! 1. **Rates.** Config carries micro-units per quantity as a decimal, per currency. The one
//!    conversion to the integer nano-unit rate happens once, when the card is built: multiply by a
//!    thousand and round to nearest, half away from zero; anything not finite or not positive clamps
//!    to zero. See [`nano_rate`]. After that point no decimal number touches money again.
//! 2. **Storage.** A posting stores QUANTITIES and the instant they happened, and nothing priced.
//!    See [`Posting`].
//! 3. **Projections.** Minor units and micro-units are read-only views of the summed nano-units,
//!    each truncating exactly once at the very end. Minor units floor at zero; micro-units do not.
//!    See [`minor_of`] and [`micros_of`]. The divisor is the currency's, decided in the one place a
//!    currency's scale is decided: [`CurrencyCode::nanos_per_minor`].
//! 4. **Append-only.** A card is never replaced. A price change APPENDS a [`CardEntry`], and a
//!    posting prices at whatever [`HistoryView::card_at`] resolves for its own instant, so an edit
//!    prices what happens after it rather than what happened before it. See [`History::append`].
//! 5. **Tier.** One multiplier per chain, in basis points, applied once over the summed pre-tier
//!    amount — a single divide, never a sum of per-line floors. See [`apply_tier`].
//!
//! # No pivot currency
//!
//! A card prices each (lane, class) cell in every currency it names, natively. There is no exchange
//! table in this crate, no conversion and no rounding of a conversion: a currency the card in force
//! does not name is [`Unpriceable::CurrencyNotPriced`], which is a refusal, and never a figure
//! derived from another currency. Two currencies never sum.
//!
//! # The two readers
//!
//! [`price`] is the lookup. [`derive_spend_cents`] and [`derive_spend_micros`] are the legacy
//! read-time derivation over a whole bucket's lanes at one card, kept because the legacy usage
//! projection still reads that way. A property test asserts the two agree: the lookup over a
//! single-entry history equals the legacy derivation at that card, exactly.
//!
//! Each of those has a MAP-SHAPED twin — [`derive_spend_minor_units`] and
//! [`derive_spend_micros_units`], over [`LaneRates::reserved_units_nanos`] — because the 1.5.5
//! ledger row stores usage as `class -> quantity` rather than as lines, and a reader of those rows
//! that cannot call in here grows a second pricing policy instead. The two shapes share the lane
//! lookup, the single divide, the fee and the floor; the only line that differs is which fold reads
//! the report.

mod currency;
mod history;
mod model;
mod posting;
mod project;
mod rate;
mod schedule;

pub use currency::CurrencyCode;
pub use history::{Author, CardEntry, CardEntryDraft, History, HistorySeq, HistoryView};
pub use model::{
    CostModel, GroupBucket, GroupRuntime, GroupSpec, GroupTable, LimitMetric, LimitSpec, ScopeSpec,
    GROUP_BUCKET_PREFIX,
};
pub use posting::{
    apply_tier, price, price_at_card, price_fail_closed, CachedPrice, Posting, Priced, PricedLine,
    Quantity, Unpriceable, FEE_CLASS, STANDARD_TIER_BP,
};
pub use project::{
    cents_of, derive_spend_cents, derive_spend_micros, derive_spend_micros_in,
    derive_spend_micros_units, derive_spend_minor, derive_spend_minor_units, micros_of, minor_of,
};
pub use rate::{nano_rate, CellPrices, LaneClass, LaneRates, RateCard, TierRates};
// The fee TERMS are contract data: declared there, carried by the rate-apply seam, applied here.
// Re-exported rather than redeclared, exactly as the group vocabulary above is, so a caller that
// holds a card names one crate for the card AND for what it charges.
pub use busbar_contract::tariff::{
    FeeTerms, PerUnitTerm, Rounding, ScopeKind, ScopedFeeTerms, TariffScope,
};
pub use schedule::{charge_minor, ScheduleCharge, BOUND_CLASS, ENTRY_CLASS};

/// Nano-units in one cent. A cent is a hundredth of one United States dollar, and a nano-unit is a
/// billionth of one, so ten million nano-units make a cent.
///
/// It is `CurrencyCode::USD.nanos_per_minor()` written as a constant, and a test says so. The two
/// existing separately is how the 1.5.5 figures stay legible: every cent projection in that release
/// divided by this number, and the generalised projection divides by the same number for the same
/// currency.
pub const NANOS_PER_CENT: u128 = 10_000_000;

/// Nano-units in one micro-unit, for the finer of the two read projections.
pub const NANOS_PER_MICRO: u128 = 1_000;

/// Micro-units in one cent, the scale the flat fee is lifted by in the USD micro projection.
pub const MICROS_PER_CENT: i64 = 10_000;

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;
