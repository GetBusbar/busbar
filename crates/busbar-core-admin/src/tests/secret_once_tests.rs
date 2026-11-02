// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::caps::UnitKey;
use busbar_kernel::teller::Kernel;

#[test]
fn the_one_shot_secret_capability_never_prints_what_it_carries() {
    let kernel = Kernel::new();
    let once = busbar_contract::SecretOnce::mint(
        &kernel.admin_token(),
        0xdead_beef_dead_beef_dead_beef_dead_beef,
        UnitKey::new(1),
        "/body/secret",
    );
    let printed = format!("{once:?}");
    assert!(printed.contains("/body/secret"));
    assert!(
        !printed.contains("dead"),
        "the nonce is never printed: {printed}"
    );
    assert_eq!(once.nonce(), 0xdead_beef_dead_beef_dead_beef_dead_beef);
    assert!(once.matches(0xdead_beef_dead_beef_dead_beef_dead_beef));
    assert!(!once.matches(1));
}

#[test]
fn a_one_shot_secret_is_bound_to_one_unit_and_one_target() {
    let kernel = Kernel::new();
    let once = busbar_contract::SecretOnce::mint(
        &kernel.admin_token(),
        42,
        UnitKey::new(6),
        "/body/token",
    );
    assert_eq!(once.target(), "/body/token");
    assert_eq!(once.unit(), UnitKey::new(6));
    assert!(once.matches(42));
    assert!(!once.matches(43));

    let elsewhere = busbar_contract::SecretOnce::mint(
        &kernel.admin_token(),
        42,
        UnitKey::new(6),
        "/header/x-key",
    );
    assert_ne!(once.target(), elsewhere.target());
    assert_ne!(once, elsewhere);
}
