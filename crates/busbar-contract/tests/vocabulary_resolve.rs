// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A per-unit path resolves a reported name against the vocabulary and never interns one.
//!
//! [`Registration::resolve`] is the lookup a unit's one line uses to turn a class it reported into
//! the static name a usage line carries. It must answer only what registration put there, and it
//! must allocate nothing for a name nobody registered, with the vocabulary open or closed. Its own
//! test binary, because the vocabulary is the process's.

use busbar_contract::{MeterClassId, Registration};

#[test]
fn resolving_answers_what_registration_holds_and_interns_nothing() {
    let before = Registration::interned();
    assert_eq!(
        Registration::resolve("class-reported-before-anyone-registered-it"),
        None,
        "a name nobody registered does not resolve"
    );
    assert_eq!(
        Registration::interned(),
        before,
        "resolving an unregistered name allocates nothing, even with the vocabulary open"
    );

    let mut boot = Registration::new();
    let registered = boot
        .key("search_units")
        .expect("the vocabulary is open while the root fills it");
    assert_eq!(Registration::resolve("search_units"), Some(registered));
    assert_eq!(
        Registration::meter_class("search_units"),
        Some(MeterClassId::new("search_units"))
    );
    assert_eq!(Registration::meter_class("undeclared_units"), None);
    assert_eq!(Registration::interned(), before + 1);
}
