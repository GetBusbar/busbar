// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The pricing law under test.
//!
//! The three files below split by clause: rates and the pin, the stored posting and the tier, and
//! the read-time derivation. The identity file is the one that ties the two readers together — the
//! older release's derivation at a pinned card against the sum of the stored nano-units.

use busbar_caps::step::MeterClassId;
use busbar_caps::{KernelSeal, QuantitySource, Usage, UsageLine, UsageToken};

use crate::{price, CurrencyCode, History, LaneClass, Posting, Priced, RateCard, Unpriceable};

mod budget_tests;
mod currency_tests;
mod derive_tests;
mod history_tests;
mod identity_tests;
mod posting_tests;
mod rate_tests;

/// The four classes the older release priced, under the names it used for them.
pub(crate) const INPUT: &str = "input";
pub(crate) const OUTPUT: &str = "output";
pub(crate) const CACHE_READ: &str = "cache_read";
pub(crate) const CACHE_WRITE: &str = "cache_write";

/// Build a usage report for a test.
///
/// Minting a token here is what a test needs in order to have a report at all: the report type can
/// only be built by the usage unit holding its own token, which is the property being relied on
/// everywhere else in this crate. The seal is confined to the kernel in real code; these lines are
/// test-only and are the same exception the capability crate's own tests take.
pub(crate) fn usage(lines: &[(&'static str, u64)]) -> Usage {
    let seal = KernelSeal::acquire_for_kernel();
    let token = UsageToken::mint(&seal);
    let lines = lines
        .iter()
        .map(|(class, quantity)| UsageLine {
            class: MeterClassId::new(class),
            quantity: *quantity,
            source: QuantitySource::Count,
            estimated: false,
        })
        .collect();
    Usage::report(&token, lines).expect("a test report stays within the line bound")
}

/// The same, marked as the kernel's own floor rather than a reported figure.
pub(crate) fn estimated_usage(lines: &[(&'static str, u64)]) -> Usage {
    let seal = KernelSeal::acquire_for_kernel();
    let token = UsageToken::mint(&seal);
    let lines = lines
        .iter()
        .map(|(class, quantity)| UsageLine {
            class: MeterClassId::new(class),
            quantity: *quantity,
            source: QuantitySource::Count,
            estimated: false,
        })
        .collect();
    Usage::estimate(&token, lines).expect("a test report stays within the line bound")
}

/// The plain line form the read-time derivation takes.
pub(crate) fn lines(entries: &[(&'static str, u64)]) -> Vec<UsageLine> {
    entries
        .iter()
        .map(|(class, quantity)| UsageLine {
            class: MeterClassId::new(class),
            quantity: *quantity,
            source: QuantitySource::Count,
            estimated: false,
        })
        .collect()
}

/// A card over one lane, priced in micro-units per token for the two reserved classes the older
/// release's tests used.
pub(crate) fn card(
    lane: &'static str,
    input_micro: f64,
    output_micro: f64,
    fee_cents: i64,
) -> RateCard {
    RateCard::from_micro_rates(
        [
            (LaneClass::new(lane, INPUT), input_micro),
            (LaneClass::new(lane, OUTPUT), output_micro),
        ],
        fee_cents,
    )
}

/// A card over one lane pricing all four of the older release's classes.
pub(crate) fn card4(lane: &'static str, rates: [f64; 4], fee_cents: i64) -> RateCard {
    RateCard::from_micro_rates(
        [
            (LaneClass::new(lane, INPUT), rates[0]),
            (LaneClass::new(lane, OUTPUT), rates[1]),
            (LaneClass::new(lane, CACHE_READ), rates[2]),
            (LaneClass::new(lane, CACHE_WRITE), rates[3]),
        ],
        fee_cents,
    )
}

/// Price a usage report against ONE card, through the whole lookup path.
///
/// The card is wrapped in a single-entry history effective from instant zero and the posting is
/// dated at zero, so `card_at` resolves to that entry and the answer is the lookup's, not a
/// shortcut's. Every case in these files that used to price against a pinned card now runs through
/// the history, which is the point: the migration's claim is that a single-entry history IS the old
/// pinned card, and the cheapest way to keep that claim honest is to make the old cases prove it.
pub(crate) fn priced(
    card: &RateCard,
    lane: &str,
    usage: &busbar_caps::Usage,
    fee_count: u64,
    tier_bp: u32,
) -> Priced {
    priced_in(card, lane, usage, fee_count, tier_bp, CurrencyCode::USD)
        .expect("a one-currency card prices in its own currency")
}

/// The same, in a named currency, keeping the refusal rather than unwrapping it.
pub(crate) fn priced_in(
    card: &RateCard,
    lane: &str,
    usage: &busbar_caps::Usage,
    fee_count: u64,
    tier_bp: u32,
    currency: CurrencyCode,
) -> Result<Priced, Unpriceable> {
    let history = History::opening(card.clone(), 0);
    let posting = Posting::from_usage(lane, usage, fee_count, tier_bp, 0, 0);
    price(&history.current(), &posting, currency)
}

/// A posting carrying one class's quantity, dated at a named instant.
pub(crate) fn posting_at(lane: &str, arrived_ms: u64, lines: &[(&'static str, u64)]) -> Posting {
    Posting::from_usage(
        lane,
        &usage(lines),
        0,
        crate::STANDARD_TIER_BP,
        arrived_ms,
        arrived_ms,
    )
}
