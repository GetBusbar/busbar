// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::crypto::{approve_signer, verify, Boundary, DelegatedSigner, Signer};

#[test]
fn per_boot_signers_are_distinct_local_and_verify() {
    let first = DelegatedSigner::generate().unwrap();
    let second = DelegatedSigner::generate().unwrap();
    assert_ne!(first.public_key(), second.public_key());
    assert_eq!(first.boundary(), Boundary::ThisModule);
    approve_signer(&first).unwrap();
    let mut signature = Vec::new();
    first.sign(b"a live page", &mut signature).unwrap();
    verify(first.public_key(), b"a live page", &signature).unwrap();
    assert!(verify(second.public_key(), b"a live page", &signature).is_err());
    assert!(verify(first.public_key(), b"another page", &signature).is_err());
    assert_eq!(
        format!("{first:?}"),
        format!(
            "DelegatedSigner {{ key_id: {:?}, .. }}",
            first.public_key().key_id
        )
    );
}
