// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/auth-admin-tokens/src/lib.rs`.

use super::*;

fn hash(s: &str) -> String {
    sha256_hex(s.as_bytes())
}

#[test]
fn no_configured_token_passes() {
    assert_eq!(
        authenticate_admin_tokens(None, Some("x"), None),
        AuthOutcome::Pass
    );
}

#[test]
fn no_credential_passes() {
    let h = hash("secret");
    assert_eq!(
        authenticate_admin_tokens(Some(&h), None, None),
        AuthOutcome::Pass
    );
}

#[test]
fn either_carrier_identifies() {
    let h = hash("secret");
    for (b, hd) in [
        (Some("secret"), None),
        (None, Some("secret")),
        (Some("secret"), Some("wrong")),
        (Some("wrong"), Some("secret")),
    ] {
        match authenticate_admin_tokens(Some(&h), b, hd) {
            AuthOutcome::Identify(p) => assert_eq!(p.id, ADMIN_TOKENS_PRINCIPAL_ID),
            other => panic!("expected Identify, got {other:?} for ({b:?},{hd:?})"),
        }
    }
}

#[test]
fn wrong_credential_rejects() {
    let h = hash("secret");
    assert_eq!(
        authenticate_admin_tokens(Some(&h), Some("nope"), None),
        AuthOutcome::Reject
    );
    assert_eq!(
        authenticate_admin_tokens(Some(&h), None, Some("nope")),
        AuthOutcome::Reject
    );
}
