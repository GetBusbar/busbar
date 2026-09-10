// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The read projections, and the read-time derivation the legacy usage endpoint still performs.
//!
//! Two things live here and they are deliberately separate. The projections turn a nano-unit total
//! into the display scales. The derivation reprices a token ledger against a card at read time —
//! which is still what the legacy endpoint does, except that the card it reprices against is now the
//! one the history says was in force, rather than whatever is configured at the moment of the read.

use busbar_caps::UsageLine;

use crate::currency::CurrencyCode;
use crate::rate::RateCard;
use crate::{MICROS_PER_CENT, NANOS_PER_MICRO};

/// **A nano-unit total in whole MINOR units of its currency**: one truncating divide, then floored
/// at zero.
///
/// The divisor is the currency's and only the currency's — ten million for a dollar, a billion for a
/// yen, a million for a dinar. This is the one place that divide happens, so a figure cannot be
/// truncated at two scales by two readers.
///
/// The divide truncates toward zero and never rounds up — a fractional minor unit the quantities did
/// not reach is dropped, deterministically. The conversion to the signed display type SATURATES
/// rather than casting: a ledger large enough to pass the top of the range would, on a wrapping
/// cast, land negative, and the floor below would then turn it into zero — an over-the-top spend
/// billing as free and escaping every cap. Pinning at the top blocks instead.
pub fn minor_of(nanos: u128, currency: CurrencyCode) -> i64 {
    let minor = i64::try_from(nanos / currency.nanos_per_minor()).unwrap_or(i64::MAX);
    minor.max(0)
}

/// A nano-unit total in whole cents — [`minor_of`] at the currency a 1.5.5 deployment's figures are
/// in, which is the spelling every 1.5.5 caller used.
pub fn cents_of(nanos: u128) -> i64 {
    minor_of(nanos, CurrencyCode::USD)
}

/// A nano-unit total in micro-units: the same single truncating divide, at the finer scale, with
/// NO floor at zero. The two projections differ here on purpose and the difference is load-bearing
/// for the ledger endpoint, so it is asserted rather than assumed.
///
/// A micro-unit is a millionth of the MAJOR unit whatever the currency, so no currency enters here:
/// the finer projection is a scale of the accumulator, not of the minor unit.
pub fn micros_of(nanos: u128) -> i64 {
    i64::try_from(nanos / NANOS_PER_MICRO).unwrap_or(i64::MAX)
}

/// Derive what a ledger view costs, in the currency's minor units, against one card: a few
/// multiply-adds over the lanes the bucket actually used, plus — when asked for — the flat fee times
/// the billable request count.
///
/// Quantities are the truth and the amount is always derived, never stored as truth on this path.
/// A lane a present card does not name derives at nothing, and so does the flat fee in a currency
/// the card names no fee in. Neither is SILENT: this is a projection with no channel to refuse in,
/// so the refusal lives where the lane's has always lived — [`RateCard::lane_unpriced`] and
/// [`RateCard::fee_unpriced`] ask the question, and [`crate::price_fail_closed`] is the posture that
/// answers it by refusing rather than serving for free.
///
/// The nano-units accumulate across every lane FIRST and divide to minor units ONCE. Two lanes each
/// contributing half a cent make a whole cent; a per-lane floor would drop both to nothing and
/// undercharge every bucket that used more than one lane.
pub fn derive_spend_minor<'a>(
    card: &RateCard,
    currency: CurrencyCode,
    lanes: impl Iterator<Item = (&'a str, &'a [UsageLine])>,
    fee_requests: u64,
    include_request_fee: bool,
) -> i64 {
    let nanos = sum_nanos(card, currency, lanes);
    let mut minor = i64::try_from(nanos / currency.nanos_per_minor()).unwrap_or(i64::MAX);
    if include_request_fee {
        // `unwrap_or(0)` is the projection's documented arm and not a silent one: a card silent
        // about the fee in this currency contributes no fee here, and says so through
        // `fee_unpriced` to the caller that must decide.
        let fee = card
            .fee_for(currency)
            .unwrap_or(0)
            .saturating_mul(i64::try_from(fee_requests).unwrap_or(i64::MAX));
        minor = minor.saturating_add(fee);
    }
    minor.max(0)
}

/// [`derive_spend_minor`] at the currency a 1.5.5 deployment's figures are in.
pub fn derive_spend_cents<'a>(
    card: &RateCard,
    lanes: impl Iterator<Item = (&'a str, &'a [UsageLine])>,
    fee_requests: u64,
    include_request_fee: bool,
) -> i64 {
    derive_spend_minor(
        card,
        CurrencyCode::USD,
        lanes,
        fee_requests,
        include_request_fee,
    )
}

/// As [`derive_spend_minor`] but in micro-units, for the finer projections. No floor at zero here.
///
/// The fee is lifted from minor units to micro-units by the currency's own scale: a minor unit is
/// `nanos_per_minor` nano-units and a micro-unit is a thousand, so the lift is the ratio of the two.
/// For a dollar that ratio is ten thousand — [`crate::MICROS_PER_CENT`] — which is the number the
/// 1.5.5 projection used, so a USD deployment's figures are unchanged to the byte.
pub fn derive_spend_micros_in<'a>(
    card: &RateCard,
    currency: CurrencyCode,
    lanes: impl Iterator<Item = (&'a str, &'a [UsageLine])>,
    fee_requests: u64,
    include_request_fee: bool,
) -> i64 {
    let nanos = sum_nanos(card, currency, lanes);
    let micros = i64::try_from(nanos / NANOS_PER_MICRO).unwrap_or(i64::MAX);
    if include_request_fee {
        let micros_per_minor =
            i64::try_from(currency.nanos_per_minor() / NANOS_PER_MICRO).unwrap_or(MICROS_PER_CENT);
        // As in [`derive_spend_minor`]: the projection's documented arm, `fee_unpriced` the
        // question, `price_fail_closed` the refusal.
        let fee_micros = card
            .fee_for(currency)
            .unwrap_or(0)
            .saturating_mul(micros_per_minor)
            .saturating_mul(i64::try_from(fee_requests).unwrap_or(i64::MAX));
        micros.saturating_add(fee_micros)
    } else {
        micros
    }
}

/// [`derive_spend_micros_in`] at the currency a 1.5.5 deployment's figures are in.
pub fn derive_spend_micros<'a>(
    card: &RateCard,
    lanes: impl Iterator<Item = (&'a str, &'a [UsageLine])>,
    fee_requests: u64,
    include_request_fee: bool,
) -> i64 {
    derive_spend_micros_in(
        card,
        CurrencyCode::USD,
        lanes,
        fee_requests,
        include_request_fee,
    )
}

/// The shared accumulation both derivations run: sum nano-units over every (lane, lines) pair,
/// skipping any lane the present card does not name.
fn sum_nanos<'a>(
    card: &RateCard,
    currency: CurrencyCode,
    lanes: impl Iterator<Item = (&'a str, &'a [UsageLine])>,
) -> u128 {
    let mut nanos: u128 = 0;
    for (lane, lines) in lanes {
        if let Some(rates) = card.lane_rates(lane, currency) {
            nanos = nanos.saturating_add(rates.nanos(lines));
        }
    }
    nanos
}
