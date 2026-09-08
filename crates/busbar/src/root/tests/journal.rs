// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The root journal's cells. Two properties, and both are about a CONTRACT WITH SOMETHING OUTSIDE
//! THE PROCESS rather than about a computation: the two words a reader tells the halves apart by,
//! and the promise that emitting a record on the serving path can never be the thing that fails.

use crate::root::journal::{leg, served, Answered, MESSAGE, TARGET};

/// THE TWO WORDS ARE THE MEASUREMENT. A reader outside the process tells the loop from the legacy
/// re-serve by these two strings and by nothing else, so a rename here is a rename of the contract
/// `cargo xtask gate teller-steps` reads — and a rename that compiled would leave that gate
/// measuring five legacy legs and agreeing with a file that says three.
#[test]
fn the_two_halves_are_named_by_two_distinct_stable_words() {
    assert_eq!(Answered::Loop.word(), "loop");
    assert_eq!(Answered::Legacy.word(), "legacy");
    assert_ne!(Answered::Loop.word(), Answered::Legacy.word());
    assert_eq!(TARGET, "busbar::root::journal");
    assert_eq!(MESSAGE, "root served unit");
}

/// A record with no subscriber installed is a filtered call and nothing else — the emission path
/// may never panic on the serving path it sits on.
#[test]
fn emitting_a_record_with_no_subscriber_is_inert() {
    served(leg::ADMIN, Answered::Loop);
    served(leg::ADMIN, Answered::Legacy);
    served(leg::LLM, Answered::Loop);
}
