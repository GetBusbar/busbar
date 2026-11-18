// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE LEDGER CRATE'S COLD CODE (LINT-RULES LR-167): the refusals its request-path modules build,
//! out of line. A priced posting never reaches any of them.

use crate::cost::{EntryKey, MoneyError};

/// A configured rate's refusal, spelled once into the `String` the configuration check reports.
#[cold]
pub(crate) fn refusal(text: std::fmt::Arguments<'_>) -> String {
    std::fmt::format(text)
}

/// The tally's refusal of a lane the card in force does not name; it owns the lane it names.
#[cold]
pub(crate) fn tally_lane_unpriced(card_seq: Option<EntryKey>, lane: &str) -> MoneyError {
    MoneyError::LaneUnpriced {
        card_seq,
        lane: lane.to_string(),
    }
}

/// The tally's refusal of a class the card in force names no price for; it owns the lane and class
/// it names.
#[cold]
pub(crate) fn tally_class_unpriced(
    card_seq: Option<EntryKey>,
    lane: &str,
    class: &str,
) -> MoneyError {
    MoneyError::ClassUnpriced {
        card_seq,
        lane: lane.to_string(),
        class: class.to_string(),
    }
}
