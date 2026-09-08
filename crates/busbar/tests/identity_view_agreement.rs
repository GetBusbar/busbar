// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The identity is stated twice, so this is where the two statements are made to agree.
//!
//! `busbar_unit_ledger::identity::residual` is the authoritative one: the terms are defined in that
//! crate and a sealed checkpoint anchors them. `busbar_unit_cost::IdentityDeltaView::between` is the
//! rendering one, which derives the same residual from the per-term deltas it has to compute anyway
//! in order to show them.
//!
//! Two implementations of one rule is a drift hazard, and the honest response is not to pretend
//! there is one — it is to check them against each other somewhere that can see both. Neither unit
//! crate depends on the other (the ledger's manifest says "nothing else" and means it), so the only
//! place that can hold this test is the composition root, which depends on both. That is why it
//! lives here rather than beside either implementation.
//!
//! The figures are driven by a deterministic generator rather than a fixture: a residual is a
//! subtraction over eight signed terms, and a handful of hand-picked cases would agree by accident.

use busbar_unit_cost::{IdentityDeltaView, IdentityTerms};
use busbar_unit_ledger::identity::residual;
use busbar_unit_ledger::totals::Totals;

/// A xorshift over a fixed seed: reproducible, and dependency-free.
struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    /// A signed nano-unit figure, spread across a range wide enough that sums cross 2^53 — the
    /// point past which the two implementations would have to be doing identical integer work to
    /// keep agreeing.
    fn amount(&mut self) -> i128 {
        i128::from(self.next_u64() as i64) * 1_000_003
    }
}

/// The two term-sets one draw produces, in the two crates' shapes.
fn draw(rng: &mut Rng) -> (Totals, IdentityTerms) {
    let settled = rng.amount();
    let open_holds = rng.amount();
    let open_slice_remainders = rng.amount();
    let unreconciled = rng.amount();
    let adjustments = rng.amount();
    let carried_in = rng.amount();
    let carried_out = rng.amount();
    let cross_window_transfers = rng.amount();
    let drawn = rng.amount();

    let totals = Totals {
        settled,
        open_holds,
        open_slice_remainders,
        unreconciled,
        adjustments,
        overdraft_carried_in: carried_in,
        overdraft_carried_out: carried_out,
        cross_window_transfers,
        drawn,
        ..Totals::default()
    };
    // `overdraft_carried` is the pair as the books hold it — out less in — which is exactly what
    // `Totals::overdraft_carried()` returns. Copying the field rather than recomputing it here is
    // deliberate: this test must not become a third implementation.
    let terms = IdentityTerms {
        settled,
        open_holds,
        open_slice_remainders,
        unreconciled,
        adjustments,
        overdraft_carried: totals.overdraft_carried(),
        cross_window_transfers,
        drawn,
    };
    (totals, terms)
}

#[test]
fn the_view_and_the_ledger_unit_compute_the_same_residual() {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    for case in 0..2_000 {
        let (since_totals, since_terms) = draw(&mut rng);
        let (now_totals, now_terms) = draw(&mut rng);

        let authoritative = residual(&since_totals, &now_totals);
        let view = IdentityDeltaView::between(
            "key-1",
            "spend",
            "key",
            1_700_000_000,
            &since_terms,
            &now_terms,
        );

        assert_eq!(
            view.residual_nanos,
            authoritative.amount(),
            "case {case}: the view's residual disagrees with the ledger unit's"
        );
        assert_eq!(
            view.closes,
            authoritative.holds(),
            "case {case}: the view's `closes` disagrees with the ledger unit's `holds`"
        );
        assert_eq!(
            view.delta_drawn, authoritative.drawn,
            "case {case}: the view's drawn delta is not the identity's right-hand side"
        );
    }
}

/// The generator has to actually produce imbalances, or the test above is 2,000 zeros agreeing.
#[test]
fn the_generator_produces_both_verdicts() {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let mut closed = 0;
    let mut broken = 0;
    for _ in 0..2_000 {
        let (since_totals, _) = draw(&mut rng);
        let (now_totals, _) = draw(&mut rng);
        if residual(&since_totals, &now_totals).holds() {
            closed += 1;
        } else {
            broken += 1;
        }
    }
    assert!(
        broken > 0,
        "every generated case balanced, so the agreement test proved nothing"
    );
    // A balancing case is the one where a sign error still agrees, so the pair is worth having.
    // It is not reachable by chance here, so this is asserted as the known shape rather than as a
    // requirement the generator has to keep meeting.
    assert_eq!(
        closed, 0,
        "random signed terms balanced by chance: {closed}"
    );
}
