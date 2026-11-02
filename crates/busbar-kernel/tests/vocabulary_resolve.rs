// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::MeterClassId;
use busbar_kernel::Registration;

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
