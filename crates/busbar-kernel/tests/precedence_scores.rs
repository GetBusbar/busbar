// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The precedence score of every selector form, as a table of figures rather than an ordering.
//!
//! The order two claims are tried in is decided by a number, and every cell that reads that number
//! elsewhere reads it as "more than" or "less than" — which every band in the table satisfies for
//! whole ranges of arithmetic that are not the arithmetic the code is written in. So the figures
//! themselves are pinned here, one row per form: the band a form sits in, the length it adds, the
//! literal bonus a pattern earns and the discount an open segment costs. A band that moves, a
//! bonus that stops being a bonus or a discount that stops discounting is a red cell here, before
//! it is a reordering of somebody's claims at boot.
//!
//! Every expectation below is a WRITTEN-OUT figure. Recomputing the expression under test would
//! agree with any arithmetic at all, including the wrong one.

use busbar_kernel::grammar::{specificity, Segment, Selector};
use busbar_kernel::registry::precedence;

/// Each band, and the length each form adds to it.
#[test]
fn every_selector_form_scores_in_the_band_the_order_gives_it() {
    // A whole path: the top band, plus the length of the path.
    assert_eq!(specificity(&Selector::ExactPath("/v1/chat")), 10_008);
    assert_eq!(specificity(&Selector::ExactPath("")), 10_000);

    // One level of prefix.
    assert_eq!(specificity(&Selector::PrefixOneLevel("/v1")), 4_003);

    // A header, by name and value together.
    assert_eq!(specificity(&Selector::HeaderExact("x-a", "bc")), 3_005);
    assert_eq!(specificity(&Selector::HeaderPrefix("x-a", "bc")), 2_005);
    assert_eq!(specificity(&Selector::HeaderPresent("x-key")), 1_505);

    // A fragment of a path, anchored or floating, scores by its literal alone.
    assert_eq!(specificity(&Selector::PathSuffix("/speech")), 1_007);
    assert_eq!(specificity(&Selector::PathContains("/speech")), 1_007);

    // The transport handshake forms.
    assert_eq!(specificity(&Selector::Sni("a.example")), 809);
    assert_eq!(specificity(&Selector::ClientCertSubject("a.example")), 809);
    assert_eq!(specificity(&Selector::StreamName("a.example")), 809);
    assert_eq!(specificity(&Selector::Alpn("h2")), 602);

    // A port names no literal at all, so it scores its band and nothing more.
    assert_eq!(specificity(&Selector::Port(443)), 500);
    assert_eq!(specificity(&Selector::Port(80)), 500);
}

/// A pattern earns a bonus per literal segment and pays a discount per open one.
///
/// Three figures live in one expression — the band, the per-literal bonus and the segment count —
/// and the discount is subtracted from all three together. Each is pinned by a row that differs
/// from its neighbour in exactly one of them.
#[test]
fn a_pattern_earns_a_bonus_for_every_literal_and_pays_for_every_open_segment() {
    // Two literals and a variable: the band, two bonuses, three segments.
    assert_eq!(
        specificity(&Selector::PathPattern(&[
            Segment::Lit("v1"),
            Segment::Var,
            Segment::Lit("x")
        ])),
        5_203
    );
    // The same pattern with one literal fewer loses exactly one bonus.
    assert_eq!(
        specificity(&Selector::PathPattern(&[
            Segment::Lit("v1"),
            Segment::Var,
            Segment::Var
        ])),
        5_103
    );
    // A shorter pattern of the same literal count loses exactly one segment.
    assert_eq!(
        specificity(&Selector::PathPattern(&[Segment::Lit("v1"), Segment::Var])),
        5_102
    );
    // And one open segment costs the discount, on top of the segment it counts as.
    assert_eq!(
        specificity(&Selector::PathPattern(&[Segment::Lit("v1"), Segment::Tail])),
        5_052
    );
    assert_eq!(
        specificity(&Selector::PathPattern(&[
            Segment::Lit("v1"),
            Segment::Tail,
            Segment::Tail
        ])),
        5_003
    );
    // A bare tail: the band, no bonus, one segment, one discount.
    assert_eq!(specificity(&Selector::PathPattern(&[Segment::Tail])), 4_951);
}

/// The discount saturates rather than wrapping, and it saturates exactly at nothing.
///
/// A pattern is a plane's own slice and nothing bounds how many open segments it names. The score
/// bottoms out at zero: the least specific thing there is, and never a number that wrapped past the
/// top of the order.
#[test]
fn a_pattern_of_open_segments_bottoms_out_at_nothing() {
    const MANY_TAILS: &[Segment] = &[Segment::Tail; 128];
    // The band and the count together cannot pay this many discounts.
    assert_eq!(specificity(&Selector::PathPattern(MANY_TAILS)), 0);

    // The band is still whole one tail before the bottom of the scale, so the saturation is a floor
    // and not a rounding of everything nearby.
    const SIXTY_TAILS: &[Segment] = &[Segment::Tail; 60];
    assert_eq!(specificity(&Selector::PathPattern(SIXTY_TAILS)), 2_060);
}

/// The anchor only ever separates a tie, and it never moves a form out of its band.
#[test]
fn the_anchor_breaks_a_tie_and_changes_no_score() {
    assert_eq!(precedence(&Selector::PathSuffix("/speech")), (1_007, 1));
    assert_eq!(precedence(&Selector::PathContains("/speech")), (1_007, 0));
    assert_eq!(precedence(&Selector::ExactPath("/v1/chat")), (10_008, 0));
    assert_eq!(precedence(&Selector::Port(443)), (500, 0));
}
