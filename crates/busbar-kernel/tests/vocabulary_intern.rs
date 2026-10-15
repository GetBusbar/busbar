// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The kernel's word interner interns each configured key exactly once (moved here with the
//! interner from `busbar-contract`, which holds no static: THE DESIGN A.8, `BUSBAR-1.6.0.md`
//! l.3701). Its own test binary, because the vocabulary is the process's.

use busbar_kernel::Registration;

/// A registration interns each configured key exactly once, and reuses it after that.
///
/// This is the leak-once rule as a value rather than as a sentence. A plane's declarations are
/// associated constants, so a configured lane or host has to become a static name somewhere; here
/// is where, and here only. The idempotence is the whole point: a key interned per unit would be a
/// leak that grows with traffic, which is precisely what one transport was doing per dial.
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
    // The SAME name, not an equal one: interning twice leaks once.
    assert!(std::ptr::eq(first, second));
    assert_eq!(reg.len(), 1);

    // A different key is a second entry, and the fixed term is readable from the count.
    let other = reg.key("gadget-frontier").expect("the vocabulary is open");
    assert_ne!(first, other);
    assert_eq!(reg.len(), 2);
}
