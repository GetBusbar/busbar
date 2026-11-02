// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_kernel::Registration;

#[test]
fn a_registration_interns_a_configured_key_exactly_once() {
    let mut reg = Registration::new();
    assert!(reg.is_empty());

    let lane = String::from("acme-frontier");
    let first = reg
        .key(&lane)
        .expect("the vocabulary is open and far from its ceiling");
    let second = reg
        .key(&lane)
        .expect("a key already registered always resolves");

    assert_eq!(first, "acme-frontier");
    assert_eq!(first, second);

    assert!(std::ptr::eq(first, second));
    assert_eq!(reg.len(), 1);

    let other = reg.key("gadget-frontier").expect("the vocabulary is open");
    assert_ne!(first, other);
    assert_eq!(reg.len(), 2);
}
