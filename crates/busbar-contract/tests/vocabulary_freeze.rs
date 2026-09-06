// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The process vocabulary is filled at boot, frozen once, and refuses a novel key after.
//!
//! The interner's own documentation says nothing outside registration may intern, because a key
//! minted per unit is exactly the leak interning replaces. Idempotence does not get that: it makes
//! a key interned twice cost one allocation, and says nothing about a name that is DIFFERENT every
//! time — a model name, an agent name, a dialect name read out of a request body. A plane holding
//! its own registration and calling it per request leaks one string per distinct client-supplied
//! name for the life of the process.
//!
//! Ownership of the registration value is not the seam that stops it: the value is constructible by
//! anyone. The leaked strings are the resource, the resource is process-wide, and so the bound has
//! to be process-wide too. That is what this file pins: one vocabulary per image, open while the
//! composition root fills it, closed afterwards, and a novel key after the close is REFUSED rather
//! than leaked — with the refusal returned as a value, never raised as a panic, because the name
//! that reaches it is client-supplied and a panic on client input is a way to stop the node.
//!
//! Its own test binary on purpose: the freeze is a property of the process, so a test that takes it
//! must not share a process with a test that needs the vocabulary open.

use busbar_contract::Registration;

/// A registration built AFTER the freeze — the plugin-side one this is all about — resolves what
/// boot registered and refuses everything else.
#[test]
fn a_registration_built_after_the_freeze_resolves_but_never_interns() {
    let mut boot = Registration::new();
    let configured = boot
        .key("lane-configured-at-boot")
        .expect("the vocabulary is open while the root fills it");
    let configured_lane = boot
        .lane("gpt-4o")
        .expect("the vocabulary is open while the root fills it");
    let after_boot = Registration::interned();
    Registration::freeze();

    // What a plane's decode_ingress would hold: a registration of its own, minted per unit, with a
    // name taken from the request in hand.
    let mut plugin_side = Registration::new();

    // A configured name still resolves, because resolving is a lookup and costs nothing.
    assert_eq!(
        plugin_side.key("lane-configured-at-boot"),
        Some(configured),
        "a key the root registered resolves to the same static name from anywhere"
    );
    assert_eq!(plugin_side.lane("gpt-4o"), Some(configured_lane));

    // A name that arrived with the request is refused, not leaked.
    assert_eq!(
        plugin_side.key("model-name-from-this-request-body"),
        None,
        "a key nobody registered at boot is refused after the freeze"
    );
    assert_eq!(plugin_side.lane("lane-name-from-this-request-body"), None);

    // The refusal is the whole point: the process leaked nothing for either of them.
    assert_eq!(
        Registration::interned(),
        after_boot,
        "a refused key allocates nothing at all"
    );
    assert!(Registration::is_frozen());

    // The freeze is idempotent, so a second root call — or a plugin calling it out of spite —
    // changes nothing about what is already registered. Asserted here rather than in a test of its
    // own because the freeze is a property of the PROCESS: two tests in one binary would race for
    // which of them ran while the vocabulary was still open.
    Registration::freeze();
    assert_eq!(Registration::interned(), after_boot);
    assert!(Registration::is_frozen());
}
