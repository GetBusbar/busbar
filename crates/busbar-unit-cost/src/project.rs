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
/// A lane a present card does not name derives at nothing.
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
        let fee = card
            .per_request_fee(currency)
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
        let fee_micros = card
            .per_request_fee(currency)
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

// ── the budget comparison's arithmetic ──────────────────────────────────────────────────────────

/// **What a spend cap has left, in whole minor units, floored at zero.**
///
/// The door used to spell this itself, twice: once as `cap.saturating_sub(derived).max(0)` in the
/// headroom read and once, in a different shape, as the two-armed comparison in the admission check.
/// Two spellings of one subtraction is the shape that lets a request be JUDGED against one figure
/// and REPORTED against another — the headroom answer an operator reads and the answer the door
/// acted on can drift apart with nothing in the build to notice.
///
/// So the subtraction lives once, here, beside the projections it is a consumer of. Saturating,
/// because a spend already past the top of the range must not wrap into headroom; floored at zero,
/// because a bucket that is over its cap has nothing left rather than a negative amount left, and a
/// negative headroom handed to a top-up would size a hold backwards.
#[must_use]
pub fn budget_remaining_cents(cap_cents: i64, spent_cents: i64) -> i64 {
    cap_cents.saturating_sub(spent_cents).max(0)
}

/// **The spend a budget comparison reads: what the balance already carried, plus what this process
/// has accrued since.**
///
/// The carried figure is the ledger's, restored at boot from the durable record; the accrued figure
/// is the node-local cell's, derived from the tokens counted since. They are two facts about one
/// balance and the comparison needs their sum, which makes the sum money arithmetic — so it is here
/// rather than at the door, for the same reason the divide and the rate conversion are.
///
/// Saturating and floored at zero, for the reason the derivations are: an adversarial ledger that
/// pushed the total past the top of the range would, wrapped, land negative and read as FREE.
#[must_use]
pub fn spend_total_cents(carried_cents: i64, accrued_cents: i64) -> i64 {
    carried_cents.saturating_add(accrued_cents).max(0)
}

/// **Whether one more request may be admitted against a spend cap.**
///
/// Two ways to be over, and they are not the same question. The bucket is over when nothing is left
/// at all; and it is over when what is left will not cover the flat fee this request would add. The
/// second arm is the fee LOOKAHEAD, and dropping it would admit a request the fee alone puts past
/// the cap — the bucket would then be over budget by exactly one fee for the rest of the window.
///
/// **Written as the tag wrote it, deliberately, and NOT rearranged around the subtraction.**
///
/// The obvious form is `budget_remaining_cents(cap, spent)` compared against the fee, and it is
/// wrong — not by argument but by measurement. The two disagree at the saturation edge: at
/// `cap = i64::MAX, spent = 1, fee = i64::MAX` the tag's `spent.saturating_add(fee)` pins at
/// `i64::MAX`, which is NOT greater than the cap, so the tag admits; the subtraction form has
/// `i64::MAX` of fee against `i64::MAX - 1` of headroom and refuses. That is a request the shipped
/// binary admits and a rearrangement would refuse, and this release does not move a money decision
/// by a single case.
///
/// So the arithmetic MOVED here and did not change: the two arms below are the two arms of
/// `busbar-unit-admission`'s check pass at the tag, character for character. What the move buys is
/// that the comparison and the headroom read now live beside each other, under one crate's tests,
/// with the divergence between the two forms written down rather than waiting to be discovered.
#[must_use]
pub fn over_budget(cap_cents: i64, spent_cents: i64, fee_cents: i64) -> bool {
    spent_cents >= cap_cents || spent_cents.saturating_add(fee_cents) > cap_cents
}
