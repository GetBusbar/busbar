//! `settle_checked` (item 150): a failed durable quarantine settle is surfaced, never swallowed.

use super::*;

/// GREEN write: the look proceeds (no error), which is what lets it go on to stamp the ledger
/// and answer `200` with the view.
#[test]
fn a_successful_settle_reports_no_error() {
    assert!(settle_checked(true, "fs").is_ok());
}

/// ITEM 150's exit proof: a FAILED durable write must not be silently swallowed (the old
/// `let _ = host.quarantine_settle(..)`, which this replaces) and must not read back as success
/// to the operator. It must be an `Internal` refusal — `connect_reply` maps `Err` from `look` to
/// `AdminReply::Rejected`, which the core admin shim answers as a `5xx`, never a `200`.
#[test]
fn a_failed_settle_is_reported_as_an_internal_error_not_silently_swallowed() {
    let err = settle_checked(false, "fs")
        .expect_err("a failed durable write must be surfaced as a refusal, not treated as success");
    match err {
        PlaneVerbError::Internal(msg) => {
            assert!(
                msg.contains("fs"),
                "the diagnostic names the server the clearance was lost for: {msg}"
            );
        }
        other => panic!(
            "a failed quarantine settle must refuse with `Internal` (the admin API's 5xx), \
             not {other:?} — an operator must be told the clearance was not recorded"
        ),
    }
}
