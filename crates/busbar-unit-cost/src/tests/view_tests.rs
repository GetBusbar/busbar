// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The view renders what it was handed, and renders every amount as a string.

use crate::view::IdentityDeltaView;

fn a_view() -> IdentityDeltaView {
    IdentityDeltaView {
        bucket: "key-1".to_string(),
        dimension: "spend".to_string(),
        scope: "key".to_string(),
        window_start: 1_700_000_000,
        delta_settlements: 1,
        delta_open_holds: 2,
        delta_open_slice_remainders: 3,
        delta_unreconciled: 4,
        delta_adjustments: 5,
        delta_overdraft_carried: 6,
        delta_cross_window_transfers: 7,
        delta_drawn: 8,
        residual_nanos: 9,
        closes: false,
    }
}

/// Every amount is quoted, and `window_start` and `closes` are not.
///
/// The distinction is the whole point of the rendering: an amount is an `i128` a JSON consumer
/// would round, and a window instant and a boolean are not.
#[test]
fn every_amount_renders_as_a_decimal_string_and_nothing_else_does() {
    let json = a_view().to_json();
    for field in [
        "delta_settlements",
        "delta_open_holds",
        "delta_open_slice_remainders",
        "delta_unreconciled",
        "delta_adjustments",
        "delta_overdraft_carried",
        "delta_cross_window_transfers",
        "delta_drawn",
        "residual_nanos",
    ] {
        assert!(
            json.contains(&format!("\"{field}\":\"")),
            "{field} is not quoted in {json}"
        );
    }
    assert!(json.contains("\"window_start\":1700000000"), "{json}");
    assert!(json.contains("\"closes\":false"), "{json}");
}

/// A figure past 2^53 survives the round trip as its own digits.
///
/// This is the reason the strings exist, so it is asserted against the actual boundary rather than
/// against a small number that would pass either way.
#[test]
fn a_figure_a_double_would_round_renders_exactly() {
    let big = 9_007_199_254_740_993_i128; // 2^53 + 1: the first integer an f64 cannot hold.
    let view = IdentityDeltaView {
        delta_drawn: big,
        ..a_view()
    };
    assert!(
        view.to_json()
            .contains("\"delta_drawn\":\"9007199254740993\""),
        "{}",
        view.to_json()
    );
}

/// A bucket name is configuration, so the renderer escapes it rather than trusting it.
#[test]
fn a_bucket_name_carrying_json_syntax_is_escaped() {
    let view = IdentityDeltaView {
        bucket: "ke\"y\\1\n".to_string(),
        ..a_view()
    };
    let json = view.to_json();
    assert!(json.contains(r#""bucket":"ke\"y\\1\n""#), "{json}");
}

/// Each verdict moves the amount its name says it moves, and no other.
///
/// The three differ ONLY by money, so they are asserted against the figure rather than against a
/// label: a verdict that returned the right token and the wrong delta would look correct in a log
/// and be wrong on an invoice.
#[test]
fn each_verdict_decides_its_own_correction() {
    use crate::view::{DisputeVerdictView, Verdict};

    let overturned = DisputeVerdictView::decide("d-1", "key-1", Verdict::Overturn, 1_000, None);
    assert_eq!(overturned.corrected_amount_nanos, 1_000);
    assert_eq!(
        overturned.delta_nanos, 0,
        "an overturned dispute moves nothing"
    );

    let upheld = DisputeVerdictView::decide("d-1", "key-1", Verdict::Uphold, 1_000, None);
    assert_eq!(upheld.corrected_amount_nanos, 0);
    assert_eq!(upheld.delta_nanos, -1_000, "the whole charge comes off");

    let amended = DisputeVerdictView::decide("d-1", "key-1", Verdict::Amend, 1_000, Some(250));
    assert_eq!(amended.corrected_amount_nanos, 250);
    assert_eq!(amended.delta_nanos, -750);
}

/// `amended_to` is read ONLY by `amend`.
///
/// Otherwise an `uphold` carrying an amount would refund a different figure than it charged, which
/// is a way to move arbitrary money through a verb whose name says it removes a known charge.
#[test]
fn an_amount_on_a_verdict_that_does_not_take_one_is_ignored() {
    use crate::view::{DisputeVerdictView, Verdict};

    let upheld = DisputeVerdictView::decide("d-1", "key-1", Verdict::Uphold, 1_000, Some(999_999));
    assert_eq!(upheld.corrected_amount_nanos, 0);
    assert_eq!(upheld.delta_nanos, -1_000);

    let overturned =
        DisputeVerdictView::decide("d-1", "key-1", Verdict::Overturn, 1_000, Some(999_999));
    assert_eq!(overturned.delta_nanos, 0);
}

/// An `amend` with no amount corrects to what was already charged, i.e. moves nothing.
///
/// The safe direction: a malformed amend must not invent a refund.
#[test]
fn an_amend_with_no_amount_moves_nothing() {
    use crate::view::{DisputeVerdictView, Verdict};

    let amended = DisputeVerdictView::decide("d-1", "key-1", Verdict::Amend, 1_000, None);
    assert_eq!(amended.delta_nanos, 0);
}

/// The verdict tokens round-trip, and nothing else parses.
#[test]
fn only_the_three_verdicts_parse() {
    use crate::view::Verdict;

    for verdict in [Verdict::Uphold, Verdict::Overturn, Verdict::Amend] {
        assert_eq!(Verdict::parse(verdict.as_str()), Some(verdict));
    }
    assert_eq!(Verdict::parse("maybe"), None);
    assert_eq!(Verdict::parse("Uphold"), None, "the token is lower case");
    assert_eq!(Verdict::parse(""), None);
}

/// Every amount on the verdict view is a decimal string too.
#[test]
fn the_verdict_view_quotes_every_amount() {
    use crate::view::{DisputeVerdictView, Verdict};

    let json =
        DisputeVerdictView::decide("d-1", "key-1", Verdict::Amend, 1_000, Some(250)).to_json();
    for field in [
        "posted_amount_nanos",
        "corrected_amount_nanos",
        "delta_nanos",
    ] {
        assert!(
            json.contains(&format!("\"{field}\":\"")),
            "{field} in {json}"
        );
    }
    assert!(json.contains(r#""delta_nanos":"-750""#), "{json}");
}
