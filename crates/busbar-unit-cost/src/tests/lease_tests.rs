// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Cells for the metering lease ([`crate::lease`]).
//!
//! The `CostHold` half is MOVED BY IDENTITY from the retiring engine's own cost battery, where
//! these assertions were written while the arithmetic lived at the host seam: same amounts, same
//! names, same claims. The only adaptation is the `charge` helper — it built a single-line audit
//! breakdown and took its `total`, and the itemized breakdown type did not come with the lease, so
//! here it is the money scalar the hot-path settle actually takes.
//!
//! The [`LeaseBook`] half is the registry semantics the host-side lease shim used to carry inline:
//! the non-zero minted id, the refuse-all door, the lease that stays open across settles, and the
//! remove-before-finalize double-refund guard.

use crate::lease::{CostAmount, CostHold, LeaseBook};

// ── CostHold: reserve → settle → refund ─────────────────────────────────────────────────────────

/// Helper: the money `total` scalar of a single-line audit charge of `n` nanodollars. The hot-path
/// settle takes ONLY this scalar — the itemization is audit-only and travels a separate tap, which
/// is why no breakdown type appears in this crate at all.
fn charge(n: u128) -> CostAmount {
    CostAmount(n)
}

#[test]
fn reserve_folds_the_flat_fee_in_once() {
    let h = CostHold::reserve(CostAmount(1_000), CostAmount(50), None);
    assert_eq!(h.reserved(), CostAmount(1_050));
}

#[test]
fn finalize_ledgers_the_exact_settled_sum_and_refunds_the_unspent_reserve() {
    let mut h = CostHold::reserve(CostAmount(1_000), CostAmount(0), None);
    h.settle_partial(charge(300));
    assert_eq!(h.settled(), CostAmount(300));
    let s = h.finalize();
    assert_eq!(s.ledgered_total, CostAmount(300)); // the EXACT charge, not the reserve
    assert_eq!(s.refund, CostAmount(700)); // reserved 1000 − settled 300
}

#[test]
fn streamed_partials_accumulate_to_the_true_charge() {
    let mut h = CostHold::reserve(CostAmount(1_000), CostAmount(0), None);
    h.settle_partial(charge(120));
    h.settle_partial(charge(80));
    h.settle_partial(charge(50));
    assert_eq!(h.settled(), CostAmount(250));
    let s = h.finalize();
    assert_eq!(s.ledgered_total, CostAmount(250));
    assert_eq!(s.refund, CostAmount(750));
}

#[test]
fn an_over_settle_ledgers_the_true_amount_and_refunds_zero_never_negative() {
    let mut h = CostHold::reserve(CostAmount(100), CostAmount(0), None);
    h.settle_partial(charge(250)); // the coarse estimate was low
    let s = h.finalize();
    assert_eq!(s.ledgered_total, CostAmount(250));
    assert_eq!(s.refund, CostAmount(0));
}

#[test]
fn a_hold_never_settled_refunds_the_whole_reserve() {
    let h = CostHold::reserve(CostAmount(500), CostAmount(25), None);
    let s = h.finalize();
    assert_eq!(s.ledgered_total, CostAmount(0));
    assert_eq!(s.refund, CostAmount(525));
}

// ── CostHold: exhaustion (the mid-stream hard-stop signal) ──────────────────────────────────────

#[test]
fn an_uncapped_lease_is_never_exhausted_and_has_no_finite_remaining() {
    let mut h = CostHold::reserve(CostAmount(100), CostAmount(0), None);
    assert!(!h.is_exhausted());
    assert_eq!(h.remaining(), None);
    h.settle_partial(CostAmount(10_000)); // far past the coarse reserve
    assert!(!h.is_exhausted()); // no cap ⇒ never dry
    assert_eq!(h.remaining(), None);
}

#[test]
fn under_cap_is_not_exhausted_and_reports_the_headroom() {
    let mut h = CostHold::reserve(CostAmount(1_000), CostAmount(0), Some(CostAmount(1_000)));
    h.settle_partial(CostAmount(600));
    assert!(!h.is_exhausted());
    assert_eq!(h.remaining(), Some(CostAmount(400))); // 1000 cap − 600 settled
}

#[test]
fn at_cap_is_exhausted_with_zero_remaining() {
    let mut h = CostHold::reserve(CostAmount(1_000), CostAmount(0), Some(CostAmount(1_000)));
    h.settle_partial(CostAmount(1_000)); // settled == cap
    assert!(h.is_exhausted());
    assert_eq!(h.remaining(), Some(CostAmount::ZERO));
}

#[test]
fn over_cap_is_exhausted_and_remaining_saturates_at_zero() {
    let mut h = CostHold::reserve(CostAmount(1_000), CostAmount(0), Some(CostAmount(1_000)));
    h.settle_partial(CostAmount(1_500)); // settled > cap
    assert!(h.is_exhausted());
    assert_eq!(h.remaining(), Some(CostAmount::ZERO)); // saturates, never negative
}

#[test]
fn exhaustion_fires_against_the_cap_not_the_coarse_over_estimated_reserve() {
    // The audit-B keystone: reserve a coarse OVER-estimate (10_000) but a tight true budget cap
    // (1_000). A settle past the cap but well below the reserve MUST read as dry — the stop fires
    // against the cap, not `settled ≥ reserved` (which would fire late by the over-estimate margin).
    let mut h = CostHold::reserve(CostAmount(10_000), CostAmount(0), Some(CostAmount(1_000)));
    h.settle_partial(CostAmount(1_200)); // > cap 1000, but « reserved 10_000
    assert!(h.is_exhausted());
    assert_eq!(h.remaining(), Some(CostAmount::ZERO));
}

#[test]
fn a_zero_cap_is_refuse_all_exhausted_from_the_outset_and_distinct_from_no_cap() {
    // Some(0) must NOT collapse into "no cap": it is a refuse-all budget, dry before any settle.
    let refuse_all = CostHold::reserve(CostAmount(0), CostAmount(0), Some(CostAmount::ZERO));
    assert!(refuse_all.is_exhausted());
    assert_eq!(refuse_all.remaining(), Some(CostAmount::ZERO));

    // ... whereas an uncapped lease with the same amounts is never exhausted.
    let uncapped = CostHold::reserve(CostAmount(0), CostAmount(0), None);
    assert!(!uncapped.is_exhausted());
    assert_eq!(uncapped.remaining(), None);
}

#[test]
fn cost_amount_addition_saturates_instead_of_wrapping() {
    // C1 regression: a hostile/huge breakdown or a long run of partial settles must NOT wrap the
    // u128 accumulator to ~0 (silent under-settlement in release, debug panic). Add + Sum saturate.
    let big = CostAmount(u128::MAX);
    assert_eq!(
        big + CostAmount(1),
        CostAmount(u128::MAX),
        "Add must saturate, not wrap to 0"
    );
    assert_eq!(big + big, CostAmount(u128::MAX));
    let summed: CostAmount = [big, CostAmount(1), big].into_iter().sum();
    assert_eq!(summed, CostAmount(u128::MAX), "Sum must saturate, not wrap");
}

// ── LeaseBook: the book of open leases ──────────────────────────────────────────────────────────

#[test]
fn a_minted_lease_id_is_never_zero() {
    // A seam that reserves `0` as its "no lease" sentinel reads a zero id as a refusal. The book
    // mints from one and only climbs, so a live lease can never be mistaken for one.
    let mut book = LeaseBook::new();
    for _ in 0..4 {
        let id = book
            .open(CostAmount(100), CostAmount::ZERO, None)
            .expect("an uncapped lease opens");
        assert_ne!(id, 0);
    }
}

#[test]
fn minted_ids_are_distinct_so_two_carriers_never_share_a_lease() {
    let mut book = LeaseBook::new();
    let a = book.open(CostAmount(100), CostAmount::ZERO, None).unwrap();
    let b = book.open(CostAmount(100), CostAmount::ZERO, None).unwrap();
    assert_ne!(a, b);
}

#[test]
fn a_refuse_all_cap_is_denied_at_the_door_and_opens_nothing() {
    let mut book = LeaseBook::new();
    assert_eq!(
        book.open(CostAmount(0), CostAmount::ZERO, Some(CostAmount::ZERO)),
        None,
        "a lease that can never settle a nonzero increment is not worth opening"
    );
    assert!(
        book.is_empty(),
        "a denied reserve must leave no entry behind"
    );
}

#[test]
fn a_lease_stays_open_across_settles_and_reports_exhaustion_at_the_cap() {
    let mut book = LeaseBook::new();
    let id = book
        .open(
            CostAmount(10_000),
            CostAmount::ZERO,
            Some(CostAmount(1_000)),
        )
        .unwrap();
    assert_eq!(book.settle(id, CostAmount(600)), Some(false));
    assert_eq!(book.settled_of(id), Some(CostAmount(600)));
    // Still open, and the cap — not the coarse 10_000 reserve — is what dries it.
    assert_eq!(book.settle(id, CostAmount(400)), Some(true));
    assert_eq!(book.settled_of(id), Some(CostAmount(1_000)));
    assert_eq!(book.len(), 1, "a settled lease is not a closed lease");
}

#[test]
fn settling_or_reading_an_unknown_lease_answers_none() {
    let mut book = LeaseBook::new();
    assert_eq!(book.settle(9_999, CostAmount(1)), None);
    assert_eq!(book.settled_of(9_999), None);
}

#[test]
fn close_finalizes_once_and_a_second_close_refunds_nothing() {
    // THE DOUBLE-REFUND GUARD. A lingering caller-side handle closing a second time must not apply
    // the refund twice — the entry is removed before it is finalized, so the second close finds
    // nothing at all.
    let mut book = LeaseBook::new();
    let id = book.open(CostAmount(1_000), CostAmount(50), None).unwrap();
    book.settle(id, CostAmount(300));
    let first = book.close(id).expect("the first close finalizes");
    assert_eq!(first.ledgered_total, CostAmount(300));
    assert_eq!(first.refund, CostAmount(750)); // reserved 1050 − settled 300
    assert_eq!(book.close(id), None, "a second close must refund nothing");
    assert!(book.is_empty(), "a closed lease does not leak the book");
}

#[test]
fn a_settle_after_close_answers_none_rather_than_reopening() {
    let mut book = LeaseBook::new();
    let id = book.open(CostAmount(100), CostAmount::ZERO, None).unwrap();
    book.close(id);
    assert_eq!(book.settle(id, CostAmount(10)), None);
}
