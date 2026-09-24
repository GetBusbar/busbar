// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The read projections, and the read-time derivation the legacy usage endpoint still performs.
//!
//! Two things live here and they are deliberately separate. The projections turn a nano-unit total
//! into the display scales. The derivation reprices a token ledger against a card at read time —
//! which is still what the legacy endpoint does, except that the card it reprices against is now the
//! one the history says was in force, rather than whatever is configured at the moment of the read.

use busbar_contract::caps::UsageLine;

use crate::cost::rate::RateCard;
use crate::cost::{whole, MoneyError, Tally, NANOS_PER_CENT, NANOS_PER_MICRO, STANDARD_TIER_BP};

/// **A nano-unit total in whole MINOR units**: one truncating divide, then floored at zero.
///
/// The divisor is [`crate::cost::NANOS_PER_CENT`] and only that — **THE ONE SCALE** (#66
/// `BUSBAR-1.6.0.md:528`: money is unitless abstract cost). There is no second divisor a reader
/// could pick, so a figure cannot be truncated at two scales by two readers, and no request body,
/// config key or label can move it.
///
/// The divide truncates toward zero and never rounds up — a fractional minor unit the quantities did
/// not reach is dropped, deterministically. The conversion to the signed display type SATURATES
/// rather than casting: a ledger large enough to pass the top of the range would, on a wrapping
/// cast, land negative, and the floor below would then turn it into zero — an over-the-top spend
/// billing as free and escaping every cap. Pinning at the top blocks instead.
pub fn minor_of(nanos: u128) -> i64 {
    let minor = i64::try_from(nanos / NANOS_PER_CENT).unwrap_or(i64::MAX);
    minor.max(0)
}

/// A nano-unit total in whole cents — the 1.5.5 spelling of [`minor_of`], which is the same
/// function at the same divisor and is kept because that is the name every 1.5.5 caller used.
pub fn cents_of(nanos: u128) -> i64 {
    minor_of(nanos)
}

/// A nano-unit total in micro-units: the same single truncating divide, at the finer scale, with
/// NO floor at zero. The two projections differ here on purpose and the difference is load-bearing
/// for the ledger endpoint, so it is asserted rather than assumed.
pub fn micros_of(nanos: u128) -> i64 {
    i64::try_from(nanos / NANOS_PER_MICRO).unwrap_or(i64::MAX)
}

/// Derive what a ledger view costs, in minor units, against one card: every lane the bucket used,
/// plus — when asked for — the flat fee times the billable request count.
///
/// **THE ONE FUNCTION'S, NOT A COPY OF IT** (items 104, 25). This used to be its own
/// multiply-and-sum with its own posture on every question the one function answers: a lane the
/// card did not name was SKIPPED (priced free), a class the card was silent about priced at zero,
/// and a sum past the range pinned at `i64::MAX`. Each of those is now the one function's answer,
/// because this is [`crate::cost::Tally`] at the card:
///
/// - card ABSENT: tokens price at nothing, the fee posts (#42's only silent zero);
/// - card PRESENT and the lane or a hit class unpriced: `Err` — a refusal, never a free line (#42);
/// - overflow: `Err(Overflow)` — a refusal, never a pinned bill (item 28).
///
/// One truncation, at the very end: two lanes each worth half a minor unit make a whole one.
pub fn derive_spend_minor<'a>(
    card: &RateCard,
    lanes: impl Iterator<Item = (&'a str, &'a [UsageLine])>,
    fee_requests: u64,
    include_request_fee: bool,
) -> Result<i64, MoneyError> {
    tally(card, lanes, fee_requests, include_request_fee)?
        .money()?
        .minor_i64()
}

/// The 1.5.5 spelling of [`derive_spend_minor`] — the same function, kept under the name every
/// 1.5.5 caller used.
pub fn derive_spend_cents<'a>(
    card: &RateCard,
    lanes: impl Iterator<Item = (&'a str, &'a [UsageLine])>,
    fee_requests: u64,
    include_request_fee: bool,
) -> Result<i64, MoneyError> {
    derive_spend_minor(card, lanes, fee_requests, include_request_fee)
}

/// As [`derive_spend_minor`] but in micro-units, for the finer projections.
///
/// The fee is a minor unit lifted by the one scale ([`crate::cost::MICROS_PER_CENT`] micro-units
/// each), inside the one function, so a deployment's figures are unchanged to the byte.
pub fn derive_spend_micros<'a>(
    card: &RateCard,
    lanes: impl Iterator<Item = (&'a str, &'a [UsageLine])>,
    fee_requests: u64,
    include_request_fee: bool,
) -> Result<i64, MoneyError> {
    tally(card, lanes, fee_requests, include_request_fee)?
        .money()?
        .micros_i64()
}

/// Drive the one function over a bucket's lanes at one card: one row per lane at the standard tier
/// (a bucket view carries no tier), then the bucket's fee row.
fn tally<'a, 'c>(
    card: &'c RateCard,
    lanes: impl Iterator<Item = (&'a str, &'a [UsageLine])>,
    fee_requests: u64,
    include_request_fee: bool,
) -> Result<Tally<'c>, MoneyError> {
    let mut t = Tally::at_card(card);
    for (lane, lines) in lanes {
        t.row(
            lane,
            0,
            STANDARD_TIER_BP,
            lines.iter().map(|l| (l.class.as_str(), whole(l.quantity))),
            whole(0),
        )?;
    }
    if include_request_fee {
        t.fee(0, STANDARD_TIER_BP, whole(fee_requests))?;
    }
    Ok(t)
}
