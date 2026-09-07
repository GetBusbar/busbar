//! Tests for `refusal.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

use super::*;

#[test]
fn envelope_shape_matches_the_1_5_5_error_contract() {
    let rendered = envelope(RefusalReason::ScopeMissing);
    let parsed: serde_json::Value = serde_json::from_str(&rendered).expect("valid json");
    assert_eq!(parsed.as_object().unwrap().len(), 1);
    let error = parsed.get("error").expect("error key").as_object().unwrap();
    assert_eq!(error.len(), 2);
    assert_eq!(error["code"], "forbidden");
    assert!(error["message"].is_string());
}

#[test]
fn every_reason_maps_to_one_of_the_ten_frozen_codes() {
    const FROZEN_CODES: &[&str] = &[
        "not_found",
        "unauthorized",
        "method_not_allowed",
        "forbidden",
        "invalid_request",
        "version_conflict",
        "conflict",
        "rate_limited",
        "internal",
        "unavailable",
    ];
    let all = [
        RefusalReason::InFlightCap,
        RefusalReason::CursorBudget,
        RefusalReason::CredentialBudget,
        RefusalReason::SessionBudget,
        RefusalReason::BodyTooLarge,
        RefusalReason::OpenSlotBusy,
        RefusalReason::SchemeNotDeclared,
        RefusalReason::CredentialRejected,
        RefusalReason::SessionUnbound,
        RefusalReason::Revoked,
        RefusalReason::ScopeMissing,
        RefusalReason::Vetoed,
        RefusalReason::NoDestination,
        RefusalReason::OverBudget,
        RefusalReason::GroupFrozen,
        RefusalReason::Unpriced,
        RefusalReason::OverdraftCeiling,
        RefusalReason::StaleSlice,
        RefusalReason::DurabilityUnavailable,
        RefusalReason::TierMismatch,
        RefusalReason::SpillBudget,
        RefusalReason::ArenaBudget,
        RefusalReason::RateLimited,
        RefusalReason::DecodeFailed,
        RefusalReason::ChallengeExhausted,
        RefusalReason::PoolNotPermitted,
        RefusalReason::NoRate,
        RefusalReason::Replayed,
        RefusalReason::InFlight,
        RefusalReason::DestinationBudgetExhausted,
        RefusalReason::BreakerOpen,
        RefusalReason::DestinationUnreachable,
        RefusalReason::MeterDisputed,
        RefusalReason::HandoffMismatch,
        RefusalReason::PlanePanic,
        RefusalReason::TaskLost,
        RefusalReason::SecretPlaceholder,
        RefusalReason::Stalled,
        RefusalReason::Drain,
        RefusalReason::Superseded,
        RefusalReason::ClientGone,
        RefusalReason::DeadlineExceeded,
    ];
    // The whole closed set, not a sample of it: `code_for` matches exhaustively, so a reason
    // added to the contract fails to compile there and this count says the walk saw it too.
    assert_eq!(
        all.len(),
        42,
        "the contract's reason set changed and this walk did not"
    );
    for reason in all {
        assert!(
            FROZEN_CODES.contains(&code_for(reason)),
            "{reason:?} mapped to a code outside the frozen ten"
        );
    }
}

/// Every row of the ratified table is what the documentation says AND what the code does.
///
/// The mapping is lossy on purpose and the table is where that is decided, so a row that exists
/// in code and not in the table is a decision nobody agreed to — and a row in the table that
/// `code_for` does not render is a promise to an operator that the wire breaks. Both directions
/// are checked off the same twenty rows: the documented row is read out of this file's own
/// source, and the rendered code is read out of `code_for` for the very same reason value.
#[test]
fn every_ratified_row_is_documented_and_rendered() {
    let source = include_str!("refusal.rs");
    let table = source
        .split("//! | `RefusalReason` | `code` | Why |")
        .nth(1)
        .expect("the ratified table is still in the module header");
    let rows = [
        (RefusalReason::InFlightCap, "rate_limited"),
        (RefusalReason::CursorBudget, "invalid_request"),
        (RefusalReason::CredentialBudget, "invalid_request"),
        (RefusalReason::SessionBudget, "unavailable"),
        (RefusalReason::BodyTooLarge, "invalid_request"),
        (RefusalReason::OpenSlotBusy, "conflict"),
        (RefusalReason::SchemeNotDeclared, "unauthorized"),
        (RefusalReason::CredentialRejected, "unauthorized"),
        (RefusalReason::SessionUnbound, "unauthorized"),
        (RefusalReason::Revoked, "forbidden"),
        (RefusalReason::ScopeMissing, "forbidden"),
        (RefusalReason::Vetoed, "forbidden"),
        (RefusalReason::NoDestination, "not_found"),
        (RefusalReason::OverBudget, "rate_limited"),
        (RefusalReason::GroupFrozen, "forbidden"),
        (RefusalReason::Unpriced, "invalid_request"),
        (RefusalReason::OverdraftCeiling, "rate_limited"),
        (RefusalReason::StaleSlice, "unavailable"),
        (RefusalReason::DurabilityUnavailable, "unavailable"),
        (RefusalReason::TierMismatch, "internal"),
        (RefusalReason::SpillBudget, "unavailable"),
        (RefusalReason::ArenaBudget, "unavailable"),
        (RefusalReason::RateLimited, "rate_limited"),
        (RefusalReason::DecodeFailed, "invalid_request"),
        (RefusalReason::ChallengeExhausted, "unauthorized"),
        (RefusalReason::PoolNotPermitted, "forbidden"),
        (RefusalReason::NoRate, "invalid_request"),
        (RefusalReason::Replayed, "conflict"),
        (RefusalReason::InFlight, "conflict"),
        (RefusalReason::DestinationBudgetExhausted, "unavailable"),
        (RefusalReason::BreakerOpen, "unavailable"),
        (RefusalReason::DestinationUnreachable, "unavailable"),
        (RefusalReason::MeterDisputed, "internal"),
        (RefusalReason::HandoffMismatch, "internal"),
        (RefusalReason::PlanePanic, "internal"),
        (RefusalReason::TaskLost, "internal"),
        (RefusalReason::SecretPlaceholder, "internal"),
        (RefusalReason::Stalled, "unavailable"),
        (RefusalReason::Drain, "unavailable"),
        (RefusalReason::Superseded, "conflict"),
        (RefusalReason::ClientGone, "conflict"),
        (RefusalReason::DeadlineExceeded, "unavailable"),
    ];
    assert_eq!(
        rows.len(),
        42,
        "the contract's reason set changed and this table did not"
    );
    for (reason, code) in rows {
        let row = format!("| `{reason:?}` | `{code}` |");
        assert!(
            table.contains(&row),
            "the ratified table has no row reading {row}"
        );
        assert_eq!(
            code_for(reason),
            code,
            "{reason:?} renders a code the ratified table does not promise"
        );
    }
}
