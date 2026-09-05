// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The read projections, and the read-time derivation the legacy usage endpoint still performs.
//!
//! Two things live here and they are deliberately separate. The projections turn a nano-unit total
//! into the display scales. The derivation reprices a token ledger against a card at read time —
//! the older release's behaviour, which the legacy endpoint reproduces exactly, so that correcting
//! a rate is a config edit and past figures become right on the next read.

use busbar_caps::UsageLine;

use crate::rate::RateCard;
use crate::{MICROS_PER_CENT, NANOS_PER_CENT, NANOS_PER_MICRO};

/// A nano-unit total in whole cents: one truncating divide, then floored at zero.
///
/// The divide truncates toward zero and never rounds up — a fractional cent the quantities did not
/// reach is dropped, deterministically. The conversion to the signed display type SATURATES rather
/// than casting: a ledger large enough to pass the top of the range would, on a wrapping cast, land
/// negative, and the floor below would then turn it into zero — an over-the-top spend billing as
/// free and escaping every cap. Pinning at the top blocks instead.
pub fn cents_of(nanos: u128) -> i64 {
    let cents = i64::try_from(nanos / NANOS_PER_CENT).unwrap_or(i64::MAX);
    cents.max(0)
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
pub fn derive_spend_cents<'a>(
    card: &RateCard,
    lanes: impl Iterator<Item = (&'a str, &'a [UsageLine])>,
    fee_requests: u64,
    include_request_fee: bool,
) -> i64 {
    let nanos = sum_nanos(card, lanes);
    let mut cents = i64::try_from(nanos / NANOS_PER_CENT).unwrap_or(i64::MAX);
    if include_request_fee {
        let fee = card
            .per_request_fee_cents()
            .saturating_mul(i64::try_from(fee_requests).unwrap_or(i64::MAX));
        cents = cents.saturating_add(fee);
    }
    cents.max(0)
}

/// As [`derive_spend_cents`] but in micro-units, for the finer projections. No floor at zero here.
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
            .per_request_fee_cents()
            .saturating_mul(MICROS_PER_CENT)
            .saturating_mul(i64::try_from(fee_requests).unwrap_or(i64::MAX));
        micros.saturating_add(fee_micros)
    } else {
        micros
    }
}

/// The shared accumulation both derivations run: sum nano-units over every (lane, lines) pair,
/// skipping any lane the present card does not name.
fn sum_nanos<'a>(card: &RateCard, lanes: impl Iterator<Item = (&'a str, &'a [UsageLine])>) -> u128 {
    let mut nanos: u128 = 0;
    for (lane, lines) in lanes {
        if let Some(rates) = card.lane_rates(lane) {
            nanos = nanos.saturating_add(rates.nanos(lines));
        }
    }
    nanos
}
