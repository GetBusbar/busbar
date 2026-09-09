// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The arithmetic a posting is made of, at the edges where it stops being obvious.
//!
//! Three edges, and money is wrong at every one of them if they are not pinned. The priced total
//! arrives as a `u128` and the reservation is a `u64`, so there is a width the two do not share and
//! a wrap there would post nearly nothing for the most expensive unit the node has ever run. The
//! overdraft flag has two independent causes — a hold whose own counter is non-zero, and a
//! settlement above what was ever held back — so the boundary between "spent exactly the
//! reservation" and "spent one nano-unit more" is the line between a clean posting and a disputed
//! one. And a unit that runs past the end more than once must carry each share once: a second spend
//! that re-recorded the first one's shortfall would bill the same overdraft twice.
//!
//! The flags are a bitset, which means every one of them is a claim that can be silently merged with
//! its neighbour; they are checked here as eight distinct bits and as a set that only ever grows.

use crate::*;

fn seal() -> KernelSeal {
    KernelSeal::acquire_for_kernel()
}

fn nothing_used(k: &KernelSeal) -> Usage {
    Usage::report(&UsageToken::mint(k), Vec::new()).expect("an empty report is within the bound")
}

fn opened(k: &KernelSeal, reserved: u64) -> Hold {
    let admit: AdmitToken<Admit> = AdmitToken::mint(k);
    Hold::open(&admit, PrincipalId::new("acct-1"), reserved)
}

#[test]
fn a_unit_that_spent_exactly_its_reservation_settles_clean() {
    // The boundary itself. `settled == reserved` is the unit that used precisely what was held back
    // for it, and nothing about it is an overdraft: there is no value delivered with nothing behind
    // it, and the disputes report has no row to write.
    let k = seal();
    let posted = Posted::settle(
        opened(&k, 1_000),
        1_000,
        &nothing_used(&k),
        &LedgerToken::mint(&k),
    );
    assert_eq!(posted.settled(), 1_000);
    assert_eq!(posted.reserved(), 1_000);
    assert_eq!(posted.released(), 0, "nothing is left to give back");
    assert_eq!(posted.overdraft(), 0);
    assert!(
        posted.flags().is_clean(),
        "spending the reservation exactly is not an overdraft: {:?}",
        posted.flags()
    );
}

#[test]
fn one_nano_unit_past_the_reservation_is_already_an_overdraft() {
    // The other side of the same line, one unit away. The two tests together are what make the
    // comparison a boundary rather than a direction.
    let k = seal();
    let posted = Posted::settle(
        opened(&k, 1_000),
        1_001,
        &nothing_used(&k),
        &LedgerToken::mint(&k),
    );
    assert_eq!(posted.settled(), 1_001);
    assert_eq!(
        posted.released(),
        0,
        "a hold that ran past its reservation releases nothing"
    );
    assert!(posted.flags().contains(PostingFlags::OVERDRAFT));
}

#[test]
fn a_unit_that_spent_one_less_than_its_reservation_releases_that_one() {
    let k = seal();
    let posted = Posted::settle(
        opened(&k, 1_000),
        999,
        &nothing_used(&k),
        &LedgerToken::mint(&k),
    );
    assert_eq!(posted.released(), 1);
    assert!(posted.flags().is_clean());
}

#[test]
fn a_priced_total_wider_than_the_reservation_settles_at_the_ceiling_and_never_wraps() {
    // The one figure that crosses a width boundary. A wrap here would post nearly nothing for the
    // most expensive unit the node has ever run — the failure is silent, and it is in the node's
    // favour, which is the worst combination a billing defect can have.
    let k = seal();
    let ledger = LedgerToken::mint(&k);
    let posted = Posted::settle(opened(&k, 1_000), u128::MAX, &nothing_used(&k), &ledger);
    assert_eq!(posted.settled(), u64::MAX, "the ceiling, not a wrap");
    assert!(posted.flags().contains(PostingFlags::OVERDRAFT));
    assert_eq!(posted.released(), 0);

    // One past the width is already the ceiling; one below it is itself. The two are what say the
    // saturation happens at the boundary and not somewhere near it.
    let over = Posted::settle(
        opened(&k, u64::MAX),
        u128::from(u64::MAX) + 1,
        &nothing_used(&k),
        &LedgerToken::mint(&k),
    );
    assert_eq!(over.settled(), u64::MAX);
    let exact = Posted::settle(
        opened(&k, u64::MAX),
        u128::from(u64::MAX),
        &nothing_used(&k),
        &LedgerToken::mint(&k),
    );
    assert_eq!(exact.settled(), u64::MAX);
    assert_eq!(exact.reserved(), u64::MAX);
    assert_eq!(exact.released(), 0);
    assert!(
        exact.flags().is_clean(),
        "settling the whole width against a reservation of the whole width is exact, not overdrawn"
    );
}

#[test]
fn a_holds_own_overdraft_flags_the_posting_even_when_the_priced_total_is_small() {
    // The second, independent cause. The hold's counter knows what the unit spent against a slice
    // that would not grow; the priced total may still come in under the reservation, and a posting
    // that read only the comparison would call that unit clean.
    let k = seal();
    let mut hold = opened(&k, 1_000);
    let spend = hold.spend(1_400, 0);
    assert_eq!(spend.overdraft, 400, "nothing could back the excess");
    let posted = Posted::settle(hold, 10, &nothing_used(&k), &LedgerToken::mint(&k));
    assert_eq!(posted.settled(), 10);
    assert_eq!(posted.overdraft(), 400);
    assert!(
        posted.flags().contains(PostingFlags::OVERDRAFT),
        "the hold's own counter is enough on its own"
    );
    assert_eq!(posted.released(), 990, "the residual is still the residual");
}

#[test]
fn a_unit_that_runs_past_the_end_twice_carries_each_share_once() {
    // The shortfall the hold reports is cumulative, so what a spend leaves unbacked is whatever of
    // it is not already carried. A second spend that re-recorded the first one's shortfall would
    // bill the same overdraft twice and the settlement would be wrong by the first share.
    let k = seal();
    let mut hold = opened(&k, 100);
    let first = hold.spend(150, 0);
    assert_eq!(first.overdraft, 50);
    let second = hold.spend(30, 0);
    assert_eq!(second.overdraft, 30, "its own share, not the running total");
    let third = hold.spend(20, 0);
    assert_eq!(third.overdraft, 20);
    assert_eq!(hold.overdraft(), 100, "50 + 30 + 20, counted once each");
    assert_eq!(hold.accrued(), 200);

    let posted = Posted::settle(hold, 200, &nothing_used(&k), &LedgerToken::mint(&k));
    assert_eq!(posted.overdraft(), 100);
    assert!(posted.flags().contains(PostingFlags::OVERDRAFT));
}

#[test]
fn a_holds_own_figures_saturate_rather_than_wrapping() {
    // Every one of these is a `u64` the accounting adds to, and each is reachable from a
    // configuration rather than from a bug: a reservation of the whole width is what "no cap
    // applies" looks like once it has been written down as a number.
    let k = seal();
    let mut hold = opened(&k, u64::MAX);
    assert_eq!(
        hold.top_up(1_000),
        u64::MAX,
        "the reservation cannot grow past the width"
    );
    assert_eq!(hold.reserved(), u64::MAX);

    let accrual = hold.accrue(u64::MAX);
    assert_eq!(accrual, Accrual::Within { remaining: 0 });
    // Both sides are pinned at the width now, so a further spend is inside a reservation that
    // cannot grow and against an accrued total that cannot either. Saturating is the declared
    // policy and this is what it means at the top: the answer is `Within`, with nothing left. Said
    // out loud here rather than left for a reader to discover from a posting.
    assert_eq!(hold.accrue(1), Accrual::Within { remaining: 0 });
    assert_eq!(hold.remaining(), 0);
    assert_eq!(hold.accrued(), u64::MAX);
    assert_eq!(
        hold.overdraft(),
        0,
        "a saturated accrual carries nothing it can name"
    );

    let mut carried = opened(&k, 0);
    carried.record_overdraft(u64::MAX);
    carried.record_overdraft(7);
    assert_eq!(carried.overdraft(), u64::MAX);
}

#[test]
fn a_spend_the_headroom_only_half_covers_reports_both_halves_and_the_hold_agrees() {
    let k = seal();
    let mut hold = opened(&k, 100);
    let spend = hold.spend(500, 250);
    assert_eq!(spend.accrued, 500, "a spend is never trimmed");
    assert_eq!(spend.topped_up, 250);
    assert_eq!(spend.overdraft, 150);
    assert_eq!(hold.reserved(), 350, "the door's 100 plus the draw's 250");
    assert_eq!(hold.overdraft(), 150);
    assert_eq!(hold.remaining(), 0);

    // What the three figures have to add up to, stated as arithmetic rather than as three
    // independent assertions: everything spent is either inside the reservation or accounted for.
    assert_eq!(spend.topped_up + spend.overdraft, spend.accrued - 100);
}

#[test]
fn the_eight_posting_flags_are_eight_distinct_bits() {
    // A bitset is where two claims quietly become one. Each flag puts the posting on a report
    // somebody reads, so two that shared a bit would put a unit on the wrong one.
    let flags = [
        PostingFlags::ESTIMATED,
        PostingFlags::METER_DISPUTED,
        PostingFlags::OVERDRAFT,
        PostingFlags::LATE_ACCRUAL,
        PostingFlags::RECOVERED,
        PostingFlags::VOIDED,
        PostingFlags::UNPOSTED,
        PostingFlags::DOWNGRADED,
    ];
    assert!(PostingFlags::NONE.is_clean());
    assert!(PostingFlags::default().is_clean());
    for (i, flag) in flags.iter().enumerate() {
        assert!(!flag.is_clean(), "a flag that is set is not a clean set");
        assert!(flag.contains(*flag));
        assert!(
            flag.contains(PostingFlags::NONE),
            "every set contains nothing"
        );
        assert!(!PostingFlags::NONE.contains(*flag));
        for other in &flags[..i] {
            assert_ne!(flag, other, "two flags share a bit");
            assert!(!flag.contains(*other), "a flag answers for its neighbour");
        }
    }

    // `with` only ever adds, and `contains` is every-flag-of rather than any-flag-of.
    let both = PostingFlags::OVERDRAFT.with(PostingFlags::ESTIMATED);
    assert!(both.contains(PostingFlags::OVERDRAFT));
    assert!(both.contains(PostingFlags::ESTIMATED));
    assert!(both.contains(PostingFlags::OVERDRAFT.with(PostingFlags::ESTIMATED)));
    assert!(!both.contains(PostingFlags::VOIDED));
    assert!(!both.contains(PostingFlags::OVERDRAFT.with(PostingFlags::VOIDED)));
    assert_eq!(
        both.with(PostingFlags::OVERDRAFT),
        both,
        "adding twice adds once"
    );
}

#[test]
fn a_flag_the_ledger_decides_on_is_added_without_clearing_what_the_hold_decided() {
    // A dispute, a downgrade and a void are the ledger's own readings, and they arrive after the
    // posting exists. A `flagged` that replaced the set instead of adding to it would silently drop
    // the overdraft the hold had already established.
    let k = seal();
    let mut hold = opened(&k, 10);
    hold.spend(50, 0);
    let posted = Posted::settle(hold, 50, &nothing_used(&k), &LedgerToken::mint(&k))
        .flagged(PostingFlags::METER_DISPUTED)
        .flagged(PostingFlags::DOWNGRADED);
    assert!(posted.flags().contains(PostingFlags::OVERDRAFT));
    assert!(posted.flags().contains(PostingFlags::METER_DISPUTED));
    assert!(posted.flags().contains(PostingFlags::DOWNGRADED));
    assert!(!posted.flags().contains(PostingFlags::VOIDED));
}

#[test]
fn a_late_accrual_posts_wholly_overdrawn_because_nothing_was_ever_held_back_for_it() {
    // Its own constructor rather than a settlement, because by the time the figure exists the
    // reservation is gone. The two figures the reconciliation reads have to say so: nothing
    // reserved, and every unit of it unbacked.
    let k = seal();
    let ledger = LedgerToken::mint(&k);
    let accrual = HoldAccrual::after_terminal(PrincipalId::new("acct-3"), 640, &ledger);
    assert_eq!(accrual.amount(), 640);
    assert_eq!(
        accrual.overdraft(),
        640,
        "there was never a reservation for any part of it"
    );
    assert_eq!(accrual.principal().as_str(), "acct-3");

    let posted = Posted::settle_late(accrual, &ledger);
    assert_eq!(posted.reserved(), 0);
    assert_eq!(posted.settled(), 640);
    assert_eq!(posted.overdraft(), 640);
    assert_eq!(
        posted.released(),
        0,
        "nothing was held, so nothing goes back"
    );
    assert!(posted.flags().contains(PostingFlags::LATE_ACCRUAL));
    assert!(posted.flags().contains(PostingFlags::OVERDRAFT));
    assert_eq!(posted.principal().as_str(), "acct-3");
}

#[test]
fn the_live_slot_is_not_displaced_by_a_second_admission() {
    // The cell refuses the second hold and hands it back — and the one that matters is the one it
    // KEEPS. A refusal that swapped the live hold for the loser would leave the exit path settling
    // a reservation the door never granted, with both holds still accounted for and nothing else
    // able to tell. So the cell is emptied afterwards and the hold that comes out is identified.
    let k = seal();
    let admit: AdmitToken<Admit> = AdmitToken::mint(&k);
    let cell = HoldCell::new(Hold::open(&admit, PrincipalId::new("acct-1"), 0));
    let arrival = cell
        .admit(
            Hold::open(&admit, PrincipalId::new("acct-1"), 1_000),
            &admit,
        )
        .expect("the first admission wins");
    assert_eq!(arrival.reserved(), 0);

    let rejected = cell
        .admit(
            Hold::open(&admit, PrincipalId::new("acct-2"), 9_999),
            &admit,
        )
        .expect_err("a cell takes one admission");
    assert_eq!(rejected.error, CellError::AlreadyAdmitted);
    assert_eq!(rejected.hold.principal().as_str(), "acct-2");

    let live = cell
        .take(&ExitToken::mint(&k))
        .expect("the cell still holds the admitted hold");
    assert_eq!(live.reserved(), 1_000, "the live slot was not displaced");
    assert_eq!(live.principal().as_str(), "acct-1");

    let ledger = LedgerToken::mint(&k);
    let _ = Posted::settle(arrival, 0, &nothing_used(&k), &ledger);
    let _ = Posted::settle(rejected.hold, 0, &nothing_used(&k), &ledger);
    let _ = Posted::settle(live, 0, &nothing_used(&k), &ledger);
}

#[test]
fn a_child_that_missed_its_parent_is_handed_back_rather_than_posted_against_an_empty_slot() {
    // The cell's own answer, under one guard. A slot that had already been emptied cannot carry a
    // child's posting, and the refusal has to give the accrual BACK: a child that missed its parent
    // still has to post, late, on its own.
    let k = seal();
    let admit: AdmitToken<Admit> = AdmitToken::mint(&k);
    let ledger = LedgerToken::mint(&k);
    let cell = HoldCell::new(Hold::open(&admit, PrincipalId::new("acct-1"), 0));
    let arrival = cell
        .admit(Hold::open(&admit, PrincipalId::new("acct-1"), 500), &admit)
        .expect("admitted");

    let accrual = cell
        .accrue_child(&PrincipalId::new("acct-1"), 120, &admit)
        .expect("an admitted parent takes a child's spend");
    assert_eq!(cell.accruals(), 1);

    let taken = cell.take(&ExitToken::mint(&k)).expect("the parent exits");
    let handed_back = Posted::into_parent(accrual, &cell, &ledger)
        .expect_err("the parent is gone; the child posts late");
    assert_eq!(handed_back.amount(), 120);

    let late = Posted::settle_late(handed_back, &ledger);
    assert!(late.flags().contains(PostingFlags::LATE_ACCRUAL));
    let _ = Posted::settle(arrival, 0, &nothing_used(&k), &ledger);
    let _ = Posted::settle(taken, 120, &nothing_used(&k), &ledger);
}
