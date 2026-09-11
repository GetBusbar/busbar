// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The money fold, at the top of its range.
//!
//! The derivation above this one already saturates: the cross-model sum uses `saturating_add`, and
//! the cent projection saturates rather than casting. This file pins the arithmetic INSIDE one
//! model's fold, which is the last place a plain operator could still wrap or panic before the
//! saturating layers ever see the number.

use std::collections::BTreeMap;

use busbar_contract::ids::{
    DIM_CACHE_READ, DIM_CACHE_WRITE, DIM_TOKENS_IN, DIM_TOKENS_OUT, TOKEN_DIMENSIONS,
};

use crate::price::RateNanos;

/// A unit map holding the largest count each of the four reserved keys can carry.
fn maximal_units() -> BTreeMap<String, u64> {
    TOKEN_DIMENSIONS
        .iter()
        .map(|u| ((*u).to_string(), u64::MAX))
        .collect()
}

/// The four reserved keys at the largest count and the largest rate the types allow.
///
/// Each of the four products is very nearly the whole width of the accumulator, so their sum is
/// past the top of it. A plain add panics on overflow in a debug build and wraps in a release one,
/// and a wrapped total lands back near zero — an over-the-top ledger deriving as nearly FREE and
/// escaping every budget cap. Saturating instead pins at the maximum, which is an astronomical
/// spend that blocks, and which the cent projection above then pins at the signed maximum.
#[test]
fn a_maximal_ledger_saturates_the_money_fold_rather_than_wrapping() {
    let rate = RateNanos {
        input: u64::MAX,
        output: u64::MAX,
        cache_read: u64::MAX,
        cache_write: u64::MAX,
    };
    assert_eq!(rate.reserved_nanos(&maximal_units()), u128::MAX);
}

/// One key at the maximum is representable exactly: a u64 count times a u64 rate fits the wide
/// accumulator with room to spare, so the saturation above is the SUM saturating, not a single
/// product being clipped. Without this, a fold that returned the maximum for everything large
/// would pass the case above while quietly destroying ordinary arithmetic.
#[test]
fn one_key_at_the_maximum_is_exact_and_does_not_saturate() {
    let rate = RateNanos {
        input: u64::MAX,
        ..RateNanos::default()
    };
    let mut units = BTreeMap::new();
    units.insert(DIM_TOKENS_IN.to_string(), u64::MAX);
    let expected = u128::from(u64::MAX) * u128::from(u64::MAX);
    assert_eq!(rate.reserved_nanos(&units), expected);
    assert!(expected < u128::MAX);
}

/// A NEGATIVE CONFIGURED FEE IS NOT A DISCOUNT, and it is clamped where the rate table is
/// resolved rather than left to the comparison to survive.
///
/// The derivation adds the fee times the billable count to the token spend and then floors the
/// whole thing at zero. An unclamped negative fee therefore does not merely contribute nothing: it
/// SUBTRACTS from the token spend, so a bucket whose tokens have already carried it over its cap
/// derives back under the cap and the door admits. The tag's own cost model clamps at resolve, in
/// both its constructors, and the pricing card in the ledger's crate clamps too; the door has to
/// agree with both or a request is judged at one fee and billed at another.
#[test]
fn a_negative_configured_fee_is_clamped_at_resolve_and_can_never_credit_a_bucket() {
    use crate::price::Pricer;

    assert_eq!(Pricer::flat(-5).price_per_request_cents(), 0);

    // One micro-unit per input token: a million input tokens is a hundred cents of spend. A
    // hundred billable requests at minus five cents would be five hundred cents of credit.
    let rates = BTreeMap::from([(
        "m".to_string(),
        RateNanos::from_micros_per_token(1.0, 0.0, 0.0, 0.0),
    )]);
    let pricer = Pricer::with_card(-5, rates);
    assert_eq!(pricer.price_per_request_cents(), 0);

    let mut units = BTreeMap::new();
    units.insert(DIM_TOKENS_IN.to_string(), 1_000_000u64);
    assert_eq!(
        pricer.derive_spend_cents([("m", &units)].into_iter(), 100, true),
        100,
        "the tokens are the spend; the clamped fee adds nothing and takes nothing away"
    );
}

/// THE PROJECTION PUTS EACH CONFIGURED RATE IN ITS OWN SLOT.
///
/// Every other call site in the tree passes `0.0` for both cache arguments, and the conversion
/// agreement test in the cost crate reads only `.input` — so all four slots could be wired to the
/// same argument, or the two cache slots transposed, and nothing in the workspace would notice.
/// Four distinct rates, so any swap between any two of them moves an answer: cache-tier tokens
/// would otherwise be judged at the door against a rate the ledger does not bill them at, which is
/// the whole reason the two cache tiers are separate fields.
#[test]
fn each_configured_rate_lands_in_its_own_slot() {
    assert_eq!(
        RateNanos::from_micros_per_token(1.0, 2.0, 3.0, 4.0),
        RateNanos {
            input: 1_000,
            output: 2_000,
            cache_read: 3_000,
            cache_write: 4_000,
        },
        "a transposed or duplicated slot bills a cache tier at another tier's rate"
    );
}

/// Ordinary figures are untouched by the change: the fold is still an exact sum of four
/// multiply-adds everywhere below the top of the range.
#[test]
fn ordinary_counts_still_sum_exactly() {
    let rate = RateNanos {
        input: 3,
        output: 5,
        cache_read: 7,
        cache_write: 11,
    };
    let mut units = BTreeMap::new();
    units.insert(DIM_TOKENS_IN.to_string(), 100);
    units.insert(DIM_TOKENS_OUT.to_string(), 200);
    units.insert(DIM_CACHE_READ.to_string(), 300);
    units.insert(DIM_CACHE_WRITE.to_string(), 400);
    assert_eq!(
        rate.reserved_nanos(&units),
        100 * 3 + 200 * 5 + 300 * 7 + 400 * 11
    );
}
