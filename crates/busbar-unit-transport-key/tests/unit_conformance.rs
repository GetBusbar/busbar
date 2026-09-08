// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Conformance: this crate is a well-formed `unit`.
//!
//! The kind's shared battery is `busbar_plugin_testkit::unit_conformance`. This file is THE SAME
//! FILE, modulo this crate's own type and step, in every sibling of the kind — so a ruling added to
//! the battery reaches all fourteen crates on their next build instead of being hand-copied
//! fourteen times and drifting, which is exactly what `kind-isolation:testkit` found.
//!
//! **The answer half is OWED here, and it is the one crate where the battery's "no I/O" reading
//! does not apply.** This unit resolves a secret and writes a journal entry, which is why it runs
//! at listener provisioning and never on the request path; its `decide` needs a secret source, a
//! journal and a TLS config sink. `busbar-unit-scope` and `busbar-unit-auth` are the kind's worked
//! examples of the full battery; this crate runs the declaration half today.

use busbar_caps::StepName;
use busbar_plugin_testkit::unit_conformance as conf;
use busbar_unit_transport_key::unit::TransportKeyUnit;

#[test]
fn the_kind_has_one_entry_and_it_names_its_own_step() {
    conf::assert_owns_one_step::<TransportKeyUnit>(StepName::Verify);
}
