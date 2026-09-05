// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The settlement table, one test per row, plus the two dimensions that settle alongside it: the
//! flat fee and the requests slot.

use super::*;
use crate::{
    fee_count, requests_settled, settle, Evidence, FeeInputs, Finish, SettleFlag, StatusClass,
    UnitEndKind,
};

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

// ── the fee, which is kernel-derived and decided at one frame ────────────────────────────────────

fn fee(client: bool, upstream: bool, relayed: bool) -> FeeInputs {
    FeeInputs {
        client_open_or_oneshot: client,
        upstream_leg_selected: upstream,
        first_response_frame_relayed: relayed,
        status_class: None,
        finish: None,
    }
}

/// The fee posts for a client request that selected an upstream leg and had its first response
/// frame relayed with a successful status. An empty successful body still counts: an empty success
/// is a served request.
#[test]
fn the_fee_posts_for_a_relayed_successful_client_request() {
    let inputs = FeeInputs {
        status_class: Some(StatusClass::Success),
        finish: Some(Finish::Complete),
        ..fee(true, true, true)
    };
    assert_eq!(fee_count(&inputs), (1, false));
}

/// Each of the three preconditions on its own is enough to post nothing: a unit that is not a
/// client request, one that never selected an upstream leg, and one whose first response frame
/// never reached the client.
#[test]
fn the_fee_posts_nothing_when_any_precondition_fails() {
    assert_eq!(fee_count(&fee(false, true, true)), (0, false));
    assert_eq!(fee_count(&fee(true, false, true)), (0, false));
    assert_eq!(fee_count(&fee(true, true, false)), (0, false));
}

/// A failing status posts nothing, whatever else happened.
#[test]
fn a_failing_status_posts_no_fee() {
    let inputs = FeeInputs {
        status_class: Some(StatusClass::Failure),
        finish: Some(Finish::Error),
        ..fee(true, true, true)
    };
    assert_eq!(fee_count(&inputs), (0, false));
}

/// The plane's own reading is a SECOND source for the same fact. When it contradicts the
/// transport's status — either way round — the LOWER answer posts and the unit is disputed. This
/// is what catches a plane that lies about how a request finished.
#[test]
fn a_plane_contradicting_the_status_posts_the_lower_fee_and_disputes_it() {
    let plane_says_error = FeeInputs {
        status_class: Some(StatusClass::Success),
        finish: Some(Finish::Error),
        ..fee(true, true, true)
    };
    assert_eq!(fee_count(&plane_says_error), (0, true));

    let plane_says_complete = FeeInputs {
        status_class: Some(StatusClass::Failure),
        finish: Some(Finish::Complete),
        ..fee(true, true, true)
    };
    assert_eq!(fee_count(&plane_says_complete), (0, true));
}

/// With only one source available, that source decides and there is nothing to dispute.
#[test]
fn one_source_alone_decides_the_fee() {
    let status_only = FeeInputs {
        status_class: Some(StatusClass::Success),
        finish: None,
        ..fee(true, true, true)
    };
    assert_eq!(fee_count(&status_only), (1, false));

    let finish_only = FeeInputs {
        status_class: None,
        finish: Some(Finish::Error),
        ..fee(true, true, true)
    };
    assert_eq!(fee_count(&finish_only), (0, false));

    // Neither source: the frame was relayed and nothing contradicts it.
    assert_eq!(fee_count(&fee(true, true, true)), (1, false));
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
