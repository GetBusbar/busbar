// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **THE SCOPE A POSTING WAS CHARGED AT, APPLIED AND AUDITABLE.**
//!
//! The counts are the teller's and the amounts are the card's, and until a posting recorded which
//! schedule it was charged under a card could only ever carry ONE — the node's — because a reader
//! re-pricing the row had no way to choose a second. These cells are about the field that closed
//! that: a pool's own figures reach a unit routed to that pool, they reach no other unit, and the
//! row says which schedule produced the figure it carries.

use busbar_contract::tariff::{FeeTerms, ScopeKind, ScopedFeeTerms, TariffScope};

use super::*;
use crate::{HistorySeq, STANDARD_TIER_BP};

/// A card with no lane rates at all, so every figure below is the SCHEDULE's and nothing else's.
fn card(node: i64, pool: (&str, i64)) -> RateCard {
    let mut c = RateCard::absent_scoped(
        CurrencyCode::USD,
        ScopedFeeTerms::node(FeeTerms {
            entry: node,
            ..FeeTerms::default()
        }),
    );
    c.set_scope_terms(
        CurrencyCode::USD,
        TariffScope::pool(pool.0),
        FeeTerms {
            entry: pool.1,
            ..FeeTerms::default()
        },
    );
    c
}

/// One visit, no transaction, no quantities — so the whole priced figure is the door's fee.
fn one_visit(scope: TariffScope) -> Posting {
    Posting {
        lane: "lane".to_string(),
        quantities: Vec::new(),
        entry_count: 1,
        transaction_count: 0,
        tier_bp: STANDARD_TIER_BP,
        arrived_ms: 1_000,
        arrived_mono: 1,
        scope,
        estimated: false,
        cached: None,
    }
}

/// **A POOL-SCOPED ENTRY FEE PRICES A UNIT ROUTED TO THAT POOL, AND NOT ANOTHER.**
///
/// The one cell the whole field exists for. Two postings that differ in NOTHING but the scope they
/// recorded are priced at two different figures by one card — and a third, at a pool the card
/// scopes nothing for, falls to the node's schedule rather than to a zero.
///
/// A pricing site that ignored the posting's scope answers 7 on every row here and all three
/// assertions collapse at once.
#[test]
fn a_pool_scoped_entry_fee_prices_a_unit_routed_to_that_pool_and_not_another() {
    let card = card(7, ("busy", 41));
    let history = History::opening(card, 0);
    let view = history.current();
    let cents = |p: &Posting| {
        price(&view, p, CurrencyCode::USD)
            .expect("the card names USD")
            .minor()
    };

    assert_eq!(
        cents(&one_visit(TariffScope::pool("busy"))),
        41,
        "a unit the row says was charged at pool `busy` is charged pool `busy`'s door fee"
    );
    assert_eq!(
        cents(&one_visit(TariffScope::pool("quiet"))),
        7,
        "a pool this card scopes nothing for falls to the node's schedule — not to nothing"
    );
    assert_eq!(
        cents(&one_visit(TariffScope::node())),
        7,
        "and a unit no narrower schedule applied to is charged the node's"
    );
}

/// **THE SAME POSTING, RE-PRICED LATER, REACHES THE SAME FIGURE FROM THE ROW ALONE.**
///
/// What makes the field an ACCOUNTING record rather than a convenience: the lookup consults the
/// posting's scope and the dated card and nothing else, so an auditor holding the postings and the
/// history re-derives every scoped figure by hand, with no configuration in front of them.
#[test]
fn the_scope_on_the_row_is_all_a_later_reader_needs_to_re_derive_the_figure() {
    let history = History::opening(card(7, ("busy", 41)), 0);
    let posting = one_visit(TariffScope::pool("busy"));
    let first = price(&history.current(), &posting, CurrencyCode::USD).expect("USD");
    let again = price(&history.current(), &posting, CurrencyCode::USD).expect("USD");
    assert_eq!(first.priced_nanos, again.priced_nanos);
    assert_eq!(first.minor(), 41);
    assert_eq!(
        first.card_seq,
        HistorySeq::OPENING,
        "the figure came off the dated entry the instant resolved to, and off nothing else"
    );
}

/// **THE ROW ENCODING IS ADDITIVE, AND AN ABSENT FIELD IS THE NODE'S OWN SCOPE.**
///
/// A row written before the field existed ends where it always ended, and reading no scope off it
/// is the same as reading `default` — which is the only schedule such a row could have been charged
/// under. Everything else round-trips, and a spelling nobody declared is `None` rather than a
/// silent fallback to `default`: a row naming a scope no reader can resolve must be reported, not
/// re-priced under a schedule it does not name.
#[test]
fn the_row_encoding_round_trips_and_an_absent_field_reads_as_the_node() {
    for scope in [
        TariffScope::node(),
        TariffScope::plane("a-kind"),
        TariffScope::pool("busy"),
        TariffScope::tier("gold"),
    ] {
        assert_eq!(
            TariffScope::decode(&scope.encoded()),
            Some(scope.clone()),
            "{} must read back as itself",
            scope.encoded()
        );
    }
    assert_eq!(
        TariffScope::decode(""),
        Some(TariffScope::node()),
        "a row that carries no scope at all is a row from the previous release"
    );
    assert_eq!(TariffScope::node().encoded(), "default");
    assert_eq!(TariffScope::pool("busy").encoded(), "pool:busy");
    assert_eq!(TariffScope::decode("dialect:openai"), None, "not a scope");
    assert_eq!(TariffScope::decode("pool:"), None, "a pool with no name");
    assert_eq!(
        TariffScope::decode("default:x"),
        None,
        "the node's scope is keyed by nothing, because there is only one of it"
    );
    assert_eq!(ScopeKind::parse("tier"), Some(ScopeKind::Tier));
    assert_eq!(ScopeKind::parse("dialect"), None);
}

/// **A SCOPED SCHEDULE DOES NOT DISTURB THE NODE'S.** The two are separate answers on one card, and
/// a deployment that scoped a pool is charged exactly as before everywhere else.
#[test]
fn adding_a_scope_to_a_card_changes_nothing_for_a_posting_that_records_none() {
    let bare = RateCard::absent_in(
        CurrencyCode::USD,
        FeeTerms {
            entry: 7,
            ..FeeTerms::default()
        },
    );
    let scoped = card(7, ("busy", 41));
    let posting = one_visit(TariffScope::node());
    let at = |c: &RateCard| {
        crate::price_at_card(HistorySeq::OPENING, c, &posting, CurrencyCode::USD)
            .expect("USD")
            .priced_nanos
    };
    assert_eq!(at(&bare), at(&scoped));
}
