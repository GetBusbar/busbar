// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `governance::ledger` cold code (see `crate::cold::governance`).

use busbar_contract::count::{Count, CountError};
use busbar_contract::records::RecordStoreError;

use crate::governance::AdjustRefused;

/// `ledger_adjust`: a priced bucket whose billable request count is out of range, refused.
#[cold]
pub(crate) fn ledger_adjust_billable_count_refusal(e: CountError) -> RecordStoreError {
    RecordStoreError::from(format!("billable request count: {e}"))
}

/// `ledger_correction`: one retained correction the flush tick's retry could not settle, `key:
/// error`.
#[cold]
pub(crate) fn ledger_correction_retry_failure(
    key_id: &str,
    error: &dyn std::fmt::Display,
) -> String {
    format!("{key_id}: {error}")
}

/// `ledger_correction`: a downward correction with no segment of its lane and entry in the window
/// holding its epoch, refused.
#[cold]
pub(crate) fn ledger_correction_unplaced(bucket: &str, window: u64, class: &str) -> AdjustRefused {
    AdjustRefused::Unplaced {
        bucket: bucket.to_owned(),
        window,
        class: class.to_owned(),
    }
}

/// `ledger_correction`: a correction that would take the day's metered count of a class out of
/// range, refused.
#[cold]
pub(crate) fn ledger_correction_metering_exceeds(
    day: u64,
    class: &str,
    count: Count,
    delta: Count,
) -> AdjustRefused {
    AdjustRefused::Exceeds {
        bucket: format!("metering@{day}"),
        class: class.to_owned(),
        count,
        delta,
    }
}
