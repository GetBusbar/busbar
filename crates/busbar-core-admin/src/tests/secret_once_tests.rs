// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The one-time secret placeholder, read back: bound to one unit and one target, and never printing
//! the nonce that IS the secret.
//!
//! `SecretOnce::mint(` is spelled only in this crate, the verbs unit's home (construction
//! `token-sealed:secret-once-mint`), so these tests moved here from busbar-contract
//! (`src/caps/tests/mod.rs`, `src/caps/tests/what_the_record_reads.rs`,
//! `tests/secret_carriers_print_nothing.rs`). The verbs unit's token comes from the kernel's
//! named seam, `Kernel::admin_token`, exactly as the composition root lends it to the unit; this
//! file spells no token constructor and never the seal.
//!
//! Two types carry the name: the capability (`busbar_contract::caps::SecretOnce`, bound to a unit
//! and a target) and the ABI destination's placeholder (`busbar_contract::SecretOnce`). Each is
//! named by its full path below so a reader never has to guess which one a test holds.

use busbar_contract::caps::UnitKey;
use busbar_kernel::teller::Kernel;

#[test]
fn the_one_shot_secret_capability_never_prints_what_it_carries() {
    let kernel = Kernel::new();
    let once = busbar_contract::caps::SecretOnce::mint(
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
    assert!(once.matches(0xdead_beef_dead_beef_dead_beef_dead_beef));
    assert!(!once.matches(1));
}

#[test]
fn a_one_shot_secret_is_bound_to_one_unit_and_one_target() {
    // The mint is reversed unless the nonce appears exactly once at exactly this target, so both
    // facts have to be readable — and the nonce, which IS the secret, must not be.
    let kernel = Kernel::new();
    let once = busbar_contract::caps::SecretOnce::mint(
        &kernel.admin_token(),
        42,
        UnitKey::new(6),
        "/body/token",
    );
    assert_eq!(once.target(), "/body/token");
    assert_eq!(once.unit(), UnitKey::new(6));
    assert!(once.matches(42));
    assert!(!once.matches(43));

    // A second placeholder at a different target is a different capability, and the accessor is what
    // the substitution site reads to tell them apart.
    let elsewhere = busbar_contract::caps::SecretOnce::mint(
        &kernel.admin_token(),
        42,
        UnitKey::new(6),
        "/header/x-key",
    );
    assert_ne!(once.target(), elsewhere.target());
    assert_ne!(once, elsewhere);
}

/// The one-time placeholder's nonce IS the secret: it is the thing the encoded bytes must contain
/// exactly once, and a reader who has it has what the verb minted.
#[test]
fn a_one_time_placeholder_does_not_print_its_nonce() {
    // A REAL capability token, not a fixture seal: the verbs unit's `Grant<AdminVerb>` is one of
    // the types the contract implements its sealed `KernelSeal` for (#65).
    let kernel = Kernel::new();
    let nonce = 0x0dd1_c0ff_ee15_dead_beef_cafe_f00d_1234_u128;
    let once = busbar_contract::SecretOnce::mint(&kernel.admin_token(), nonce, "body.secret");
    let printed = format!("{once:?}");
    assert!(
        !printed.contains(&nonce.to_string()) && !printed.contains(&format!("{nonce:x}")),
        "a one-time placeholder printed its nonce: {printed}"
    );
    // What it DOES say: where the secret is allowed to appear, which is what a mismatch at the
    // encode step needs to be diagnosable.
    assert!(printed.contains("body.secret"), "{printed}");
    assert_eq!(once.nonce(), nonce);
}
