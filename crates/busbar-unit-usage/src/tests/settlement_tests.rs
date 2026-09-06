// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The settlement table, one test per row, plus the requests slot that settles alongside it.
//!
//! The flat per-request fee is NOT here: it is kernel-derived, decided from the kernel's own fee
//! evidence, and its table lives with that rule.

use super::*;
use crate::{requests_settled, settle, Evidence, SettleFlag, UnitEndKind};

fn evidence<'a>() -> Evidence<'a> {
    Evidence::default()
}

/// ROW: completed, the locator arrived. The located usage is the amount, unflagged.
#[test]
fn completed_with_a_locator_settles_at_the_located_usage() {
    let located = usage(&[(INPUT, 11), (OUTPUT, 7)]);
    let s = settle(
        UnitEndKind::Completed,
        &Evidence {
            located: Some(&located),
            ..evidence()
        },
    );
    assert_eq!(pairs(&s.lines), vec![(INPUT, 11), (OUTPUT, 7)]);
    assert!(s.flags.is_empty());
}

/// ROW: completed, a REQUIRED locator absent. NOTHING is billed — when the destination reports no
/// usage there is no usage to bill — and the kernel's floor is kept as internal evidence that
/// reaches the disputes report and no invoice.
#[test]
fn completed_with_a_required_locator_absent_bills_nothing_and_keeps_the_floor_internally() {
    let floor = plain(&[(INPUT, 500)]);
    let s = settle(
        UnitEndKind::Completed,
        &Evidence {
            located: None,
            kernel_floor: &floor,
            locator_required: true,
            ..evidence()
        },
    );
    assert!(s.lines.is_empty(), "nothing bills");
    assert!(s.is_zero());
    assert!(s.flags.contains(&SettleFlag::Estimated));
    assert!(s.flags.contains(&SettleFlag::MeterDisputed));
    assert_eq!(pairs(&s.internal_evidence), vec![(INPUT, 500)]);
}

/// The same row with NO card in force: nothing is required, so nothing is billed AND nothing is
/// flagged. A deployment with pricing switched off does not generate disputes.
#[test]
fn completed_with_no_locator_required_bills_nothing_and_flags_nothing() {
    let floor = plain(&[(INPUT, 500)]);
    let s = settle(
        UnitEndKind::Completed,
        &Evidence {
            located: None,
            kernel_floor: &floor,
            locator_required: false,
            ..evidence()
        },
    );
    assert!(s.lines.is_empty());
    assert!(s.flags.is_empty());
}

/// ROW: a live end that is not a completion, with the locator arrived. The located usage bills.
#[test]
fn a_live_non_completed_end_with_a_locator_settles_at_the_located_usage() {
    let located = usage(&[(OUTPUT, 40)]);
    let s = settle(
        UnitEndKind::LiveNonCompleted {
            terminal_error: false,
        },
        &Evidence {
            located: Some(&located),
            ..evidence()
        },
    );
    assert_eq!(pairs(&s.lines), vec![(OUTPUT, 40)]);
    assert!(s.flags.is_empty());
}

/// ROW, the exception inside it: a stream whose end carries a terminal error signal bills NOTHING,
/// whatever the locator found. The located figure becomes internal evidence.
#[test]
fn a_stream_ending_in_a_terminal_error_bills_nothing() {
    let located = usage(&[(OUTPUT, 40)]);
    let s = settle(
        UnitEndKind::LiveNonCompleted {
            terminal_error: true,
        },
        &Evidence {
            located: Some(&located),
            ..evidence()
        },
    );
    assert!(s.lines.is_empty());
    assert_eq!(pairs(&s.internal_evidence), vec![(OUTPUT, 40)]);
}

/// ROW: a live end that is not a completion, with no locator at all. The kernel's accrued floor is
/// the amount, and it is marked as the estimate it is.
#[test]
fn a_live_non_completed_end_with_no_locator_settles_at_the_kernel_floor() {
    let floor = plain(&[(INPUT, 120)]);
    let s = settle(
        UnitEndKind::LiveNonCompleted {
            terminal_error: false,
        },
        &Evidence {
            located: None,
            kernel_floor: &floor,
            ..evidence()
        },
    );
    assert_eq!(pairs(&s.lines), vec![(INPUT, 120)]);
    assert!(s.flags.contains(&SettleFlag::Estimated));
}

/// ROW: recovered after a crash with a dispatch record present. The last checkpointed accrual is
/// the amount, marked as recovered.
#[test]
fn a_crash_recovered_unit_that_was_dispatched_settles_at_its_last_checkpoint() {
    let checkpoint = plain(&[(OUTPUT, 30)]);
    let s = settle(
        UnitEndKind::CrashRecovered { dispatched: true },
        &Evidence {
            checkpointed_accrual: &checkpoint,
            ..evidence()
        },
    );
    assert_eq!(pairs(&s.lines), vec![(OUTPUT, 30)]);
    assert!(s.flags.contains(&SettleFlag::Recovered));
}

/// The same row with NO checkpoint: nothing was accrued, so nothing is billed — still recovered
/// rather than voided, because something was dispatched.
#[test]
fn a_crash_recovered_unit_with_no_checkpoint_settles_at_nothing() {
    let s = settle(
        UnitEndKind::CrashRecovered { dispatched: true },
        &evidence(),
    );
    assert!(s.lines.is_empty());
    assert!(s.flags.contains(&SettleFlag::Recovered));
}

/// ROW: recovered after a crash with NO dispatch record. Nothing was ever sent, so nothing is
/// owed, and the unit is voided.
#[test]
fn a_crash_recovered_unit_that_was_never_dispatched_is_voided() {
    let floor = plain(&[(INPUT, 999)]);
    let s = settle(
        UnitEndKind::CrashRecovered { dispatched: false },
        &Evidence {
            kernel_floor: &floor,
            ..evidence()
        },
    );
    assert!(s.lines.is_empty());
    assert!(s.flags.contains(&SettleFlag::Voided));
    assert!(!s.flags.contains(&SettleFlag::Recovered));
}

/// ROW: an accrual whose parent had already exited. It posts on its own account, marked as the
/// late arrival it is — a late accrual ALWAYS posts, so the identity between what was accrued and
/// what was settled still balances.
#[test]
fn a_late_accrual_always_posts_on_its_own_account() {
    let child = plain(&[(OUTPUT, 5)]);
    let s = settle(
        UnitEndKind::LateAccrual { slice_empty: false },
        &Evidence {
            child_posting: &child,
            ..evidence()
        },
    );
    assert_eq!(pairs(&s.lines), vec![(OUTPUT, 5)]);
    assert!(s.flags.contains(&SettleFlag::LateAccrual));
    assert!(!s.flags.contains(&SettleFlag::Overdraft));
}

/// The same row against an EMPTY slice: it posts anyway and says so. The bucket stays exhausted;
/// what it does not do is lose the posting.
#[test]
fn a_late_accrual_against_an_empty_slice_posts_and_says_so() {
    let child = plain(&[(OUTPUT, 5)]);
    let s = settle(
        UnitEndKind::LateAccrual { slice_empty: true },
        &Evidence {
            child_posting: &child,
            ..evidence()
        },
    );
    assert_eq!(pairs(&s.lines), vec![(OUTPUT, 5)]);
    assert!(s.flags.contains(&SettleFlag::Overdraft));
}

/// ROW: value was delivered but the settle record did not survive. The posting is retained for
/// re-appending, marked as not yet posted.
#[test]
fn a_lost_settle_record_retains_the_posting_for_re_appending() {
    let located = usage(&[(OUTPUT, 12)]);
    let s = settle(
        UnitEndKind::DurabilityLost,
        &Evidence {
            located: Some(&located),
            ..evidence()
        },
    );
    assert_eq!(pairs(&s.lines), vec![(OUTPUT, 12)]);
    assert!(s.flags.contains(&SettleFlag::Unposted));
}

/// The estimated mark on a report travels onto the settlement, so a figure the destination never
/// confirmed is visibly a floor all the way through.
#[test]
fn the_estimated_mark_travels_from_the_report_onto_the_settlement() {
    let floored = estimated_usage(&[(INPUT, 10)]);
    let s = settle(
        UnitEndKind::Completed,
        &Evidence {
            located: Some(&floored),
            ..evidence()
        },
    );
    assert!(s.flags.contains(&SettleFlag::Estimated));
}

// ── the requests slot ────────────────────────────────────────────────────────────────────────────

/// A slot drawn at the door is NEVER released. A unit that was admitted and then failed still
/// consumed it, which is what stops failures escaping a cap by failing; a unit refused before the
/// door consumed nothing.
#[test]
fn a_drawn_requests_slot_is_never_released() {
    assert_eq!(requests_settled(1, true), 1, "admitted then failed: kept");
    assert_eq!(
        requests_settled(1, false),
        0,
        "refused at the door: nothing"
    );
    assert_eq!(
        requests_settled(0, true),
        0,
        "nothing drawn, nothing settled"
    );
}

/// Every settlement mark has a posting flag behind it, and the late-accrual mark reaches the one
/// the capability crate declared for it. Before this, the two vocabularies were never bridged: a
/// settlement could be marked late and the posting it produced could not say so.
#[test]
fn every_settlement_mark_carries_onto_the_posting() {
    use crate::settlement::{posting_flags, SettleFlag};
    use busbar_caps::PostingFlags as P;

    assert_eq!(SettleFlag::LateAccrual.posting_flag(), P::LATE_ACCRUAL);
    assert_eq!(SettleFlag::Estimated.posting_flag(), P::ESTIMATED);
    assert_eq!(SettleFlag::MeterDisputed.posting_flag(), P::METER_DISPUTED);
    assert_eq!(SettleFlag::Recovered.posting_flag(), P::RECOVERED);
    assert_eq!(SettleFlag::Voided.posting_flag(), P::VOIDED);
    assert_eq!(SettleFlag::Overdraft.posting_flag(), P::OVERDRAFT);
    assert_eq!(SettleFlag::Unposted.posting_flag(), P::UNPOSTED);

    // No two marks collapse onto one flag, so a posting can always be read back to the marks that
    // produced it.
    let all = [
        SettleFlag::Estimated,
        SettleFlag::MeterDisputed,
        SettleFlag::Recovered,
        SettleFlag::Voided,
        SettleFlag::LateAccrual,
        SettleFlag::Overdraft,
        SettleFlag::Unposted,
    ];
    for (i, a) in all.iter().enumerate() {
        for b in &all[i + 1..] {
            assert_ne!(a.posting_flag(), b.posting_flag(), "{a:?} and {b:?}");
        }
    }

    let folded = posting_flags([&SettleFlag::LateAccrual, &SettleFlag::Overdraft]);
    assert!(folded.contains(P::LATE_ACCRUAL));
    assert!(folded.contains(P::OVERDRAFT));
    assert!(!folded.contains(P::ESTIMATED));
}
