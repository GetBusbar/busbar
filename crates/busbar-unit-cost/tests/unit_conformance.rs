// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Conformance: this crate is a well-formed `unit`.
//!
//! The kind's shared battery is `busbar_plugin_testkit::unit_conformance`. This file is THE SAME
//! FILE, modulo this crate's own type and step, in every sibling of the kind — so a ruling added to
//! the battery reaches all fourteen crates on their next build instead of being hand-copied
//! fourteen times and drifting, which is exactly what `kind-isolation:testkit` found.
//!
//! **The answer half is OWED here.** This unit SERVES its step, so its battery arm is
//! `assert_total` rather than `assert_answers`, and pricing needs a pinned rate card. It is also
//! the crate whose answers are MONEY, so the two existing integration tests beside this one
//! (`hot_path_allocation`, `rate_conversion_agreement`) stay the load-bearing ones and this file
//! adds the kind's declaration check on top rather than replacing anything.

use busbar_caps::StepName;
use busbar_plugin_testkit::unit_conformance as conf;
use busbar_unit_cost::unit::CostUnit;

#[test]
fn the_kind_has_one_entry_and_it_names_its_own_step() {
    conf::assert_owns_one_step::<CostUnit>(StepName::Admit);
}
