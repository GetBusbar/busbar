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

/// The envelope stays one JSON document when the message is one a caller supplied.
///
/// Today's callers bring closed, quote-free prose, so the shape has never been asked this — but the
/// envelope is `pub`, and the moment the administrative error taxonomy renders through it the
/// message carries caller-supplied text: a resource name in a `not_found`, a validation complaint,
/// the human half of a conflict. A `"` in any of those closes the string early and hands the reader
/// a DIFFERENT document from the one this rendered, with a `code` the client's parser never sees.
///
/// The characters below are the closed set JSON requires an escape for: the two structural ones,
/// the five with short forms, and a representative control character. Asserting through a parser
/// rather than against expected bytes is deliberate — the claim is "still one document that says
/// what it was given", not "escaped the way this test's author would have escaped it".
#[test]
fn the_envelope_survives_a_message_a_caller_wrote() {
    const AWKWARD: &[&str] = &[
        r#"key "prod" not found"#,
        r"path C:\config not found",
        "line one\nline two",
        "carriage\rreturn",
        "tab\there",
        "backspace\u{08}here",
        "formfeed\u{0c}here",
        "control\u{01}here",
    ];
    for message in AWKWARD {
        let rendered = envelope_of("invalid_request", message);
        let parsed: serde_json::Value = serde_json::from_str(&rendered)
            .unwrap_or_else(|e| panic!("the envelope around {message:?} is not one document: {e}"));
        let error = parsed
            .get("error")
            .and_then(serde_json::Value::as_object)
            .expect("the envelope's one key");
        assert_eq!(error.len(), 2, "the envelope is code and message and nothing else");
        assert_eq!(error["code"], "invalid_request");
        assert_eq!(
            error["message"].as_str(),
            Some(*message),
            "the message a reader parses back is not the message this was given"
        );
    }
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
    // `../refusal.rs`, not `refusal.rs`: this file is reached through `#[path = "tests/refusal.rs"]`
    // from `src/refusal.rs`, so `include_str!` resolves against `src/tests/` — the directory THIS
    // file lives in — and the bare name reads this test file back into itself. The ratified table is
    // in the IMPLEMENTATION module's header, one directory up. Read against itself the split still
    // found the marker (the marker is spelled out just below, in this file's own source) and handed
    // back this file's tail, so the check ran against a haystack that can never contain a table row.
    let source = include_str!("../refusal.rs");
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
