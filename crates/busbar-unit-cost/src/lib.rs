// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! The money arithmetic: a rate card, a priced posting, and the projections that display it.
//!
//! Everything here is a pure function over integers. No clock, no store, no config parser and no
//! plane appears in this crate, so an auditor can re-derive an invoice from the source by hand.
//!
//! # The five clauses, and where each one lives
//!
//! 1. **Rates.** Config carries micro-units per quantity as a decimal. The one conversion to the
//!    integer nano-unit rate happens once, when the card is built: multiply by a thousand and round
//!    to nearest, half away from zero; anything not finite or not positive clamps to zero. See
//!    [`nano_rate`]. After that point no decimal number touches money again.
//! 2. **Storage.** A posting stores one priced line per reported quantity plus the flat fee as a
//!    line of its own, and the pre-tier amount is the sum of those lines. See [`Posting`].
//! 3. **Projections.** Cents and micro-units are read-only views of the summed nano-units, each
//!    truncating exactly once at the very end. Cents floor at zero; micro-units do not. See
//!    [`cents_of`] and [`micros_of`].
//! 4. **Immutability.** A posting is priced against the card pinned when its hold opened, and it
//!    records that card's version, so a later card edit moves no posting already made. See
//!    [`RateCard::pin`].
//! 5. **Tier.** One multiplier per chain, in basis points, applied once over the summed pre-tier
//!    amount — a single divide, never a sum of per-line floors. See [`apply_tier`].
//!
//! Clauses 1 to 4 are the older release's pricing law with a changed storage layout: every
//! truncation and every ordering is the same, so the same usage against the same card produces the
//! same figure. Clause 5 is new, and has no older-release counterpart to compare against.
//!
//! # The two readers
//!
//! [`price`] builds the stored posting (the new layout). [`derive_spend_cents`] and
//! [`derive_spend_micros`] are the older release's read-time derivation, kept verbatim because the
//! legacy usage projection still reprices at read time from the current card. A property test
//! asserts the two agree: the older derivation at a pinned card equals the sum of the stored
//! nano-units.

mod posting;
mod project;
mod rate;

pub use posting::{apply_tier, price, Posting, PricedLine, FEE_CLASS, STANDARD_TIER_BP};
pub use project::{cents_of, derive_spend_cents, derive_spend_micros, micros_of};
pub use rate::{nano_rate, LaneClass, LaneRates, PinnedCard, RateCard, RateCardVersion};

/// Nano-units in one cent. A cent is a hundredth of one abstract cost unit, and a nano-unit is a
/// billionth of one, so ten million nano-units make a cent.
pub const NANOS_PER_CENT: u128 = 10_000_000;

/// Nano-units in one micro-unit, for the finer of the two read projections.
pub const NANOS_PER_MICRO: u128 = 1_000;

/// Micro-units in one cent, the scale the flat fee is lifted by in the micro projection.
pub const MICROS_PER_CENT: i64 = 10_000;

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;
