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
use crate::cost::{MICROS_PER_CENT, NANOS_PER_CENT, NANOS_PER_MICRO};

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

/// Derive what a ledger view costs, in minor units, against one card: a few multiply-adds over the
/// lanes the bucket actually used, plus — when asked for — the flat fee times the billable request
/// count.
///
/// Quantities are the truth and the amount is always derived, never stored as truth on this path.
/// A lane a present card does not name derives at nothing. THAT IS NOT SILENT, and it is not decided
/// here: this is a PROJECTION with no channel to refuse in, so the refusal lives where the lane's
/// has always lived — [`RateCard::lane_unpriced`] asks the question, and
/// [`crate::cost::price_fail_closed`] / [`crate::cost::price_exact`] are the postures that answer
/// it by refusing rather than serving for free (#42 `BUSBAR-1.6.0.md:367`).
///
/// The nano-units accumulate across every lane FIRST and divide to minor units ONCE. Two lanes each
/// contributing half a cent make a whole cent; a per-lane floor would drop both to nothing and
/// undercharge every bucket that used more than one lane.
pub fn derive_spend_minor<'a>(
    card: &RateCard,
    lanes: impl Iterator<Item = (&'a str, &'a [UsageLine])>,
    fee_requests: u64,
    include_request_fee: bool,
) -> i64 {
    let nanos = sum_nanos(card, lanes);
    let mut minor = i64::try_from(nanos / NANOS_PER_CENT).unwrap_or(i64::MAX);
    if include_request_fee {
        let fee = card
            .fee()
            .saturating_mul(i64::try_from(fee_requests).unwrap_or(i64::MAX));
        minor = minor.saturating_add(fee);
    }
    minor.max(0)
}

/// The 1.5.5 spelling of [`derive_spend_minor`] — the same function, kept under the name every
/// 1.5.5 caller used.
pub fn derive_spend_cents<'a>(
    card: &RateCard,
    lanes: impl Iterator<Item = (&'a str, &'a [UsageLine])>,
    fee_requests: u64,
    include_request_fee: bool,
) -> i64 {
    derive_spend_minor(card, lanes, fee_requests, include_request_fee)
}

/// As [`derive_spend_minor`] but in micro-units, for the finer projections. No floor at zero here.
///
/// The fee is lifted from minor units to micro-units by the one scale: a minor unit is
/// [`crate::cost::NANOS_PER_CENT`] nano-units and a micro-unit is a thousand, so the lift is the
/// ratio of the two — ten thousand, [`crate::cost::MICROS_PER_CENT`], which is the number the 1.5.5
/// projection used, so a deployment's figures are unchanged to the byte.
pub fn derive_spend_micros<'a>(
    card: &RateCard,
    lanes: impl Iterator<Item = (&'a str, &'a [UsageLine])>,
    fee_requests: u64,
    include_request_fee: bool,
) -> i64 {
    let nanos = sum_nanos(card, lanes);
    let micros = i64::try_from(nanos / NANOS_PER_MICRO).unwrap_or(i64::MAX);
    if include_request_fee {
        let fee_micros = card
            .fee()
            .saturating_mul(MICROS_PER_CENT)
            .saturating_mul(i64::try_from(fee_requests).unwrap_or(i64::MAX));
        micros.saturating_add(fee_micros)
    } else {
        micros
    }
}

/// The shared accumulation both derivations run: sum nano-units over every (lane, lines) pair,
/// skipping any lane the present card does not name.
fn sum_nanos<'a>(
    card: &RateCard,
    lanes: impl Iterator<Item = (&'a str, &'a [UsageLine])>,
) -> u128 {
    let mut nanos: u128 = 0;
    for (lane, lines) in lanes {
        if let Some(rates) = card.lane_rates(lane) {
            nanos = nanos.saturating_add(rates.nanos(lines));
        }
    }
    nanos
}
