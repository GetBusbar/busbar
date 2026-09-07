// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! The money arithmetic: quantities, a dated rate-card history, and the lookup that prices one
//! against the other.
//!
//! Everything here is a pure function over integers. No clock, no store, no config parser and no
//! plane appears in this crate, so an auditor can re-derive an invoice from the source by hand.
//!
//! # Money is a lookup, not a stored number
//!
//! ```text
//!   layer 0   QUANTITIES   what happened, and when            immutable, the truth
//!   layer 1   HISTORY      what things cost, and since when   append-only, sequenced
//!   layer 2   LOOKUP       price(layer 0, layer 1, currency)  pure, derived, never truth
//! ```
//!
//! A [`Posting`] stores quantities per meter class and the instant they happened. A [`History`] is
//! an append-only sequence of dated [`CardEntry`] values. A price is [`price`]: quantity times the
//! rate of the card in force at that instant, in the currency asked for, NATIVELY. Nothing priced is
//! authoritative. Nothing is ever rewritten, which is what makes an invoice reproducible — name the
//! two inputs and you get the same answer forever.
//!
//! # The five clauses, and where each one lives
//!
//! 1. **Rates.** Config carries micro-units per quantity as a decimal. The one conversion to the
//!    integer nano-unit rate happens once, when the card is built: multiply by a thousand and round
//!    to nearest, half away from zero; anything not finite or not positive clamps to zero. See
//!    [`nano_rate`]. After that point no decimal number touches money again.
//! 2. **Storage.** A posting stores QUANTITIES — no rate, no amount, no card. See [`Posting`].
//! 3. **Projections.** A currency's minor units and micro-units are read-only views of the summed
//!    nano-units, each truncating exactly once at the very end. Minor units floor at zero;
//!    micro-units do not. The minor-unit divisor is the currency's and nothing else's. See
//!    [`minor_of`] and [`micros_of`].
//! 4. **Append-only.** A card edit APPENDS a dated entry; it never rewrites one. A posting prices
//!    at the entry in force at its own instant, so an edit prices what happens after it and a
//!    back-dated correction out-ranks what it corrects without deleting it. See [`History::append`]
//!    and [`HistoryView::card_at`].
//! 5. **Tier.** One multiplier per chain, in basis points, applied once over the summed pre-tier
//!    amount — a single divide, never a sum of per-line floors. See [`apply_tier`].
//!
//! # Currency, natively
//!
//! A card's cell holds one configured integer rate PER CURRENCY. `price(·, JPY)` reads the yen rate.
//! There is no pivot currency, no FX table, no conversion and no rounding of a conversion — token to
//! yen, not token to dollar to yen. A currency a card does not name is
//! [`Unpriceable::CurrencyNotPriced`], never a converted figure and never a zero.
//!
//! # The two readers
//!
//! [`price`] is the lookup. [`derive_spend_cents`] and [`derive_spend_micros`] are the older
//! release's read-time derivation over a whole ledger view, kept because the legacy usage endpoint
//! still reads that way. For a one-entry history they are the same arithmetic — same rates, same
//! order, same saturation, same single truncation — and a property test asserts it, which is what
//! makes the migration exact rather than approximately right.

mod currency;
mod history;
mod posting;
mod project;
mod rate;

pub use currency::CurrencyCode;
pub use history::{Author, CardEntry, CardEntryDraft, History, HistorySeq, HistoryView};
pub use posting::{
    apply_tier, price, price_against, CachedPrice, Posting, Priced, PricedLine, Quantity,
    Unpriceable, FEE_CLASS, STANDARD_TIER_BP,
};
pub use project::{
    cents_of, derive_spend_cents, derive_spend_micros, derive_spend_minor, micros_of, minor_of,
};
pub use rate::{
    nano_rate, CellPrices, LaneClass, LaneRates, RateCard, TierRates, CLASS_CACHE_READ,
    CLASS_CACHE_WRITE, CLASS_INPUT, CLASS_OUTPUT,
};

/// Nano-units in one cent — the US dollar's minor unit, and the scale a migrated 1.5.5 deployment
/// reads at.
///
/// It is exactly `CurrencyCode::USD.nanos_per_minor()`, and that equality is asserted rather than
/// asserted-by-comment: it is the reason the currency migration moves no byte.
pub const NANOS_PER_CENT: u128 = 10_000_000;

/// Nano-units in one micro-unit, for the finer of the two read projections. A DISPLAY scale, the
/// same for every currency.
pub const NANOS_PER_MICRO: u128 = 1_000;

/// Micro-units in one cent, the scale a dollar fee is lifted by in the micro projection. The
/// general form is a currency's `nanos_per_minor() / NANOS_PER_MICRO`.
pub const MICROS_PER_CENT: i64 = 10_000;

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;
