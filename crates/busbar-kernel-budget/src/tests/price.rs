// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The door's money derivation — THE ONE FUNCTION (`busbar_kernel_ledger::cost::Tally`) over the
//! pricer's card — at the top of its range and on the #42 positions.
//!
//! This crate used to carry its own fold (`RateNanos::reserved_nanos`), which SATURATED: a maximal
//! ledger pinned at `u128::MAX` and the cent projection pinned at `i64::MAX`, a spend nobody
//! consumed standing in for a refusal. The fold is gone (items 104, 25) and an overflow is now the
//! one function's refusal (item 28), which the door blocks on.

use std::collections::BTreeMap;

use busbar_kernel_ledger::cost::MoneyError;

use crate::price::{
    Pricer, RateNanos, RESERVED_UNITS, UNIT_CACHE_READ, UNIT_CACHE_WRITE, UNIT_INPUT, UNIT_OUTPUT,
};

/// A unit map holding the largest count each of the four reserved keys can carry.
fn maximal_units() -> BTreeMap<String, u64> {
    RESERVED_UNITS
        .iter()
        .map(|u| ((*u).to_string(), u64::MAX))
        .collect()
}

/// A pricer whose one model `m` carries these rates, with no fee.
fn pricer_for(rate: RateNanos) -> Pricer {
    super::carded(0, BTreeMap::from([("m".to_string(), rate)]))
}

/// The four reserved keys at the largest count and the largest rate the types allow. The true
/// figure is past every integer the money path holds, so it is REFUSED — neither wrapped toward
/// free (the defect saturation was added to stop) nor pinned at a ceiling nobody consumed (the
/// defect saturation introduced).
#[test]
fn a_maximal_ledger_is_refused_rather_than_wrapped_or_pinned() {
    let rate = RateNanos {
        input: u64::MAX,
        output: u64::MAX,
        cache_read: u64::MAX,
        cache_write: u64::MAX,
    };
    assert_eq!(
        pricer_for(rate).derive_spend_cents([("m", &maximal_units())].into_iter(), 0, false),
        Err(MoneyError::Overflow)
    );
}

/// Below the range, the one function is exact: a large-but-representable figure is not clipped,
/// so the refusal above is about the range and not about being large.
#[test]
fn a_large_representable_figure_is_exact() {
    let rate = RateNanos {
        input: 1_000_000_000, // a thousand units a token
        ..RateNanos::default()
    };
    let mut units = BTreeMap::new();
    units.insert(UNIT_INPUT.to_string(), 1_000_000_000_000u64);
    // 1e12 tokens × 1e9 nano-units = 1e21 nano-units = 1e14 minor units, exactly.
    assert_eq!(
        pricer_for(rate).derive_spend_cents([("m", &units)].into_iter(), 0, false),
        Ok(100_000_000_000_000)
    );
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
    let pricer = super::carded(-5, rates);
    assert_eq!(pricer.price_per_request_cents(), 0);

    let mut units = BTreeMap::new();
    units.insert(UNIT_INPUT.to_string(), 1_000_000u64);
    assert_eq!(
        pricer.derive_spend_cents([("m", &units)].into_iter(), 100, true),
        Ok(100),
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

/// Ordinary figures are untouched by the change: the one function is an exact sum of four
/// multiply-adds everywhere below the top of the range, byte-identical to the fold it replaced.
#[test]
fn ordinary_counts_still_sum_exactly() {
    let rate = RateNanos {
        input: 3_000,
        output: 5_000,
        cache_read: 7_000,
        cache_write: 11_000,
    };
    let mut units = BTreeMap::new();
    units.insert(UNIT_INPUT.to_string(), 10_000);
    units.insert(UNIT_OUTPUT.to_string(), 20_000);
    units.insert(UNIT_CACHE_READ.to_string(), 30_000);
    units.insert(UNIT_CACHE_WRITE.to_string(), 40_000);
    // (10_000×3_000 + 20_000×5_000 + 30_000×7_000 + 40_000×11_000) nano = 780_000_000 nano
    // = 78 minor units.
    assert_eq!(
        pricer_for(rate).derive_spend_cents([("m", &units)].into_iter(), 0, false),
        Ok(78)
    );
}

// ── #42 — THE DOOR MUST NOT ADMIT WHAT IT CANNOT PRICE ───────────────────────────────────────────
// `docs/design/BUSBAR-1.6.0.md:370` (#42): *"rate_card PRESENT ⇒ billed: a hit class not priced ⇒
// REFUSE (money-sacred, never a silent 0) … A silent 0 is ONLY ever returned when rate_card is
// absent."*
//
// The three tests below are ONE statement taken in three positions, and the refusal arm alone does
// not make it: a rule that blocks every derivation satisfies the first and breaks the node. The
// second and third are what say the refusal is about being UNPRICED and not about being cheap.

/// A pricer holding a card that names `priced` and nothing else.
fn card_naming_only_priced() -> crate::price::Pricer {
    super::carded(
        2,
        BTreeMap::from([(
            "priced".to_string(),
            RateNanos::from_micros_per_token(3.0, 16.0, 0.0, 0.0),
        )]),
    )
}

/// A million input and a million output tokens, the shape the worked example bills.
fn a_million_each() -> BTreeMap<String, u64> {
    BTreeMap::from([
        (UNIT_INPUT.to_string(), 1_000_000u64),
        (UNIT_OUTPUT.to_string(), 1_000_000u64),
    ])
}

/// THE REFUSAL. A present card with no entry for the model must not derive that model's
/// consumption as nothing.
///
/// This derivation GATES ADMISSION against a group's `budget:` cap, so the old answer — the flat
/// fee and not one nano-unit of the tokens — let an unpriced model run uncapped on spend forever.
/// Its first repair pinned the figure at `i64::MAX`; the refusal now arrives AS a refusal (the one
/// function's `LaneUnpriced`), and the door blocks on it (item 124).
#[test]
fn a_present_card_silent_about_the_model_blocks_rather_than_deriving_free() {
    let pricer = card_naming_only_priced();
    let units = a_million_each();
    assert!(
        pricer.model_unpriced("nobody-priced-me"),
        "the fixture's premise: the card is present and does not name this model"
    );
    assert_eq!(
        pricer.derive_spend_cents([("nobody-priced-me", &units)].into_iter(), 1, true),
        Err(MoneyError::LaneUnpriced {
            card_seq: busbar_kernel_ledger::cost::HistorySeq::OPENING,
            lane: "nobody-priced-me".to_string(),
        }),
        "#42: an unpriced model on a billed node is a refusal, never a silent 0 — and on THIS \
         path the silent 0 was an admission"
    );
}

/// THE EXPLICIT-FREE CONTROL. A model the card DOES name, priced at zero on every tier, is free —
/// legitimately, under #77(5) (*"free is an EXPLICIT zero row"*) — and must derive the flat fee
/// and nothing more. It must NOT block.
///
/// Without this arm the test above is satisfied by a pricer that blocks on everything.
#[test]
fn a_model_the_card_prices_at_explicit_zero_is_free_and_does_not_block() {
    let pricer = super::carded(
        2,
        BTreeMap::from([(
            "free-on-purpose".to_string(),
            RateNanos::from_micros_per_token(0.0, 0.0, 0.0, 0.0),
        )]),
    );
    assert!(
        !pricer.model_unpriced("free-on-purpose"),
        "an entry that exists is priced, whatever it is priced AT"
    );
    assert_eq!(
        pricer.derive_spend_cents(
            [("free-on-purpose", &a_million_each())].into_iter(),
            1,
            true
        ),
        Ok(2),
        "two million tokens at an explicit zero rate cost the flat fee and nothing else"
    );
}

/// THE BILLING-OFF CONTROL. With NO card there is nothing for a model to be missing from, so #42's
/// one legal silent zero still reads zero and nothing blocks.
#[test]
fn with_no_card_at_all_an_unknown_model_still_reads_the_fee_alone() {
    let pricer = crate::price::Pricer::flat(2);
    assert!(
        !pricer.model_unpriced("anything-at-all"),
        "billing off: no card, so no class is unpriced"
    );
    assert_eq!(
        pricer.derive_spend_cents(
            [("anything-at-all", &a_million_each())].into_iter(),
            1,
            true
        ),
        Ok(2),
        "#42: a silent 0 is correct — and only correct — when rate_card is absent"
    );
}
