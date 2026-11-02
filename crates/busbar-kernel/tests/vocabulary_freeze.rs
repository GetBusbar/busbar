// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_kernel::Registration;

#[test]
fn a_registration_built_after_the_freeze_resolves_but_never_interns() {
    let mut boot = Registration::new();
    let configured = boot
        .key("lane-configured-at-boot")
        .expect("the vocabulary is open while the root fills it");
    let configured_lane = boot
        .lane("model-1")
        .expect("the vocabulary is open while the root fills it");
    let after_boot = Registration::interned();
    Registration::freeze();

    let mut plugin_side = Registration::new();

    assert_eq!(
        plugin_side.key("lane-configured-at-boot"),
        Some(configured),
        "a key the root registered resolves to the same static name from anywhere"
    );
    assert_eq!(plugin_side.lane("model-1"), Some(configured_lane));

    assert_eq!(
        plugin_side.key("model-name-from-this-request-body"),
        None,
        "a key nobody registered at boot is refused after the freeze"
    );
    assert_eq!(plugin_side.lane("lane-name-from-this-request-body"), None);

    assert_eq!(
        Registration::interned(),
        after_boot,
        "a refused key allocates nothing at all"
    );
    assert!(Registration::is_frozen());

    Registration::freeze();
    assert_eq!(Registration::interned(), after_boot);
    assert!(Registration::is_frozen());
}
