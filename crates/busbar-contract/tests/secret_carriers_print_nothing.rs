// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What a secret-carrying ABI type says when something formats it.
//!
//! Every one of these is handed across the plugin ABI, so the code that might format it is code
//! this tree cannot see. The guarantee has to be the type's, not the caller's discipline.

use busbar_contract::{ArrivalLocation, Credential, KeyMaterial, SecretValue};

#[test]
fn a_credential_does_not_print_the_credential() {
    let c = Credential {
        location: ArrivalLocation::Header("authorization"),
        bytes: b"sk-live-SECRET".to_vec(),
    };
    let printed = format!("{c:?}");
    assert!(
        !printed.contains("SECRET"),
        "a credential printed its own bytes: {printed}"
    );
    assert!(!printed.contains("sk-live"), "{printed}");
    // What it DOES say: where the credential arrived and how long it was — enough to diagnose a
    // scheme that read the wrong header, and nothing a reader could present as the credential.
    assert!(printed.contains("authorization"), "{printed}");
    assert!(printed.contains("14"), "{printed}");
}

#[test]
fn a_resolved_secret_does_not_print_its_bytes() {
    let s = SecretValue::new(b"sk-live-SECRET".to_vec());
    assert!(!format!("{s:?}").contains("SECRET"));
}

#[test]
fn key_material_prints_how_much_and_how_old_but_not_what() {
    let k = KeyMaterial {
        bytes: b"signing-SECRET".to_vec(),
        fetched_at: 1_700_000_000,
    };
    let printed = format!("{k:?}");
    assert!(!printed.contains("SECRET"), "{printed}");
    assert!(
        !printed.contains("115"),
        "the raw bytes were printed: {printed}"
    );
    assert!(
        printed.contains("14") && printed.contains("1700000000"),
        "{printed}"
    );
}
