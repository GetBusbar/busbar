// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The read projections, and the read-time derivation the legacy usage endpoint still performs.
//!
//! Two things live here and they are deliberately separate. The projections turn a nano-unit total
//! into the display scales. The derivation reprices a token ledger against a card at read time —
//! the older release's behaviour, which the legacy endpoint reproduces exactly, so that correcting
//! a rate is a config edit and past figures become right on the next read.

use busbar_caps::UsageLine;

use crate::currency::CurrencyCode;
use crate::rate::RateCard;
use crate::NANOS_PER_MICRO;

/// A nano-unit total in whole MINOR UNITS of a currency: one truncating divide, then floored at
/// zero.
///
/// THE ONE PROJECTION TO A CURRENCY'S OWN SCALE. The divisor is
/// [`CurrencyCode::nanos_per_minor`] and never a literal, so a currency with no minor unit at all
/// (yen) truncates at the whole yen, a three-place currency (the dinars) truncates at the fils, and
/// dollars truncate at the cent — through the same divide, in the same place, with the same
/// rounding.
///
/// The divide truncates toward zero and never rounds up — a fraction of a minor unit the quantities
/// did not reach is dropped, deterministically. The conversion to the signed display type SATURATES
/// rather than casting: a ledger large enough to pass the top of the range would, on a wrapping
/// cast, land negative, and the floor below would then turn it into zero — an over-the-top spend
/// billing as free and escaping every cap. Pinning at the top blocks instead.
pub fn minor_of(nanos: u128, currency: CurrencyCode) -> i64 {
    let minor = i64::try_from(nanos / currency.nanos_per_minor()).unwrap_or(i64::MAX);
    minor.max(0)
}

/// A nano-unit total in whole cents — [`minor_of`] at [`CurrencyCode::USD`], which is the one
/// currency a migrated 1.5.5 deployment has.
///
/// Kept as a name because the older release's arithmetic is stated in cents and the equality against
/// it is stated in cents; it is a wrapper and not a second divide, so there is nothing here that can
/// drift from the general projection.
pub fn cents_of(nanos: u128) -> i64 {
    minor_of(nanos, CurrencyCode::USD)
}

/// A nano-unit total in micro-units: the same single truncating divide, at the finer scale, with
/// NO floor at zero. The two projections differ here on purpose and the difference is load-bearing
/// for the ledger endpoint, so it is asserted rather than assumed.
pub fn micros_of(nanos: u128) -> i64 {
    i64::try_from(nanos / NANOS_PER_MICRO).unwrap_or(i64::MAX)
}

/// Derive what a ledger view costs, in cents, against the CURRENT card: a few multiply-adds over
/// the lanes the bucket actually used, plus — when asked for — the flat fee times the billable
/// request count.
///
/// Quantities are the truth and the amount is always derived, never stored as truth on this path.
/// A lane a present card does not name derives at nothing: the operator's card edit taking effect
/// retroactively is the designed behaviour, not a failure.
///
/// The nano-units accumulate across every lane FIRST and divide to cents ONCE. Two lanes each
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
        let fee = card
            .fee_minor(currency)
            .saturating_mul(i64::try_from(fee_requests).unwrap_or(i64::MAX));
        minor = minor.saturating_add(fee);
    }
    minor.max(0)
}

/// The same derivation in cents — [`derive_spend_minor`] at [`CurrencyCode::USD`], which is what a
/// migrated 1.5.5 deployment prices in.
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

/// As [`derive_spend_cents`] but in micro-units, for the finer projections. No floor at zero here.
///
/// Micro-units are a DISPLAY scale, not a currency's minor unit, so this divide is by a fixed
/// thousand for every currency. The fee is lifted from the currency's minor unit to micro-units by
/// that currency's own scale, which is the only place the currency enters.
pub fn derive_spend_micros<'a>(
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
            i64::try_from(currency.nanos_per_minor() / NANOS_PER_MICRO).unwrap_or(i64::MAX);
        let fee_micros = card
            .fee_minor(currency)
            .saturating_mul(micros_per_minor)
            .saturating_mul(i64::try_from(fee_requests).unwrap_or(i64::MAX));
        micros.saturating_add(fee_micros)
    } else {
        micros
    }
}

/// The shared accumulation both derivations run: sum nano-units over every (lane, lines) pair, in
/// one currency, skipping any lane the present card does not name.
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
