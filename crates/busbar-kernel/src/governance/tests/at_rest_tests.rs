// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::governance::{GovState, NewKeySpec};
use crate::test_support::store_double::MemoryStore;
use busbar_contract::records::{RecordStore, SecretForm};
use std::sync::Arc;

fn meta(id: &str, public_id: &str) -> CredentialMeta {
    CredentialMeta {
        id: id.to_string(),
        key_id: "vk_1".to_string(),
        kind: "signed-request".to_string(),
        slot: 0,
        public_id: public_id.to_string(),
        secret_form: SecretForm::Recoverable,
        created_at: 0,
        updated_at: 0,
        expires_at: None,
        revoked_at: None,
        revoke_reason: None,
        revision: 0,
    }
}

fn kek(seed: u8, kid: &str) -> CredentialKek {
    CredentialKek::derive(kid, &[seed; 32])
}

#[test]
fn a_sealed_secret_opens_only_for_its_row_and_its_key() {
    let k = kek(7, "k1");
    let m = meta("cred_a", "AKIA1");
    let sealed = k.seal(&m, b"wJalrXUtnFEMI/K7MDENG").unwrap();
    assert!(sealed.starts_with("v1:aead:k1:"), "{sealed}");
    assert!(!sealed.contains("wJalrXUtnFEMI"));
    assert_eq!(
        open(Some(&k), &m, &sealed).as_deref().map(String::as_str),
        Some("wJalrXUtnFEMI/K7MDENG")
    );
    // Two seals of one secret differ (a fresh nonce each).
    assert_ne!(sealed, k.seal(&m, b"wJalrXUtnFEMI/K7MDENG").unwrap());
    // Moved to another row: does not open.
    assert!(open(Some(&k), &meta("cred_b", "AKIA1"), &sealed).is_none());
    assert!(open(Some(&k), &meta("cred_a", "AKIA2"), &sealed).is_none());
    // Another signing key, the same kid or not: does not open. No key: does not open.
    assert!(open(Some(&kek(8, "k1")), &m, &sealed).is_none());
    assert!(open(Some(&kek(7, "k2")), &m, &sealed).is_none());
    assert!(open(None, &m, &sealed).is_none());
    // Altered: does not open.
    let mut altered = sealed.clone();
    let last = altered.pop().unwrap();
    altered.push(if last == 'A' { 'B' } else { 'A' });
    assert!(open(Some(&k), &m, &altered).is_none());
}

#[test]
fn a_row_written_before_1_6_0_still_opens_and_an_unknown_scheme_does_not() {
    let m = meta("cred_a", "AKIA1");
    assert_eq!(
        open(None, &m, "v1:plain:legacy")
            .as_deref()
            .map(String::as_str),
        Some("legacy")
    );
    assert!(is_plain("v1:plain:legacy"));
    assert!(open(Some(&kek(7, "k1")), &m, "v2:other:x").is_none());
    assert!(open(Some(&kek(7, "k1")), &m, "legacy").is_none());
}

#[test]
fn the_key_never_prints() {
    let text = format!("{:?}", kek(7, "k1"));
    assert_eq!(text, "CredentialKek { kid: \"k1\", .. }");
}

fn signing_gov(store: Arc<MemoryStore>, seed: u8) -> GovState {
    let signer = crate::governance::signing::TokenSigner::from_secret_bytes(
        &[seed; 32],
        crate::governance::signing::DEFAULT_KID,
    );
    GovState::new_with_signer(store, None, Some(signer)).unwrap()
}

fn mint(g: &GovState) -> (String, String) {
    let (_, _, public_id, secret) = g
        .mint_signed_with_credential(
            NewKeySpec {
                name: "at-rest".to_string(),
                ..Default::default()
            },
            2_000_000_000,
            1_700_000_000,
            &crate::test_support::issued::double().0,
            &crate::test_support::issued::double().1,
        )
        .unwrap();
    (public_id, secret.expose(&crate::seal::lend()).clone())
}

/// RED before the seal: the store held `v1:plain:<secret>`. Now no store row carries the secret,
/// and the read still answers it, live.
#[test]
fn a_minted_recoverable_credential_reaches_the_store_sealed_and_still_authenticates() {
    let store = Arc::new(MemoryStore::new());
    let g = signing_gov(store.clone(), 7);
    let (public_id, secret) = mint(&g);
    let rows = store.list_credentials_since(0).unwrap();
    assert_eq!(rows.len(), 1);
    assert!(rows[0].secret.starts_with("v1:aead:"), "not sealed");
    assert!(!rows[0].secret.contains(&secret));
    let kind = crate::test_support::issued::double().0;
    let (read, live) = g.credential_secret(&kind, &public_id, 1_700_000_001);
    assert!(live);
    assert_eq!(read.expose(&crate::seal::lend()), &secret);
}

/// The same store under another signing key: the credential does not authenticate (it answers
/// as an unknown one, the dummy and not live), rather than opening under the wrong key.
#[test]
fn a_credential_sealed_under_another_signing_key_does_not_authenticate() {
    let store = Arc::new(MemoryStore::new());
    let (public_id, secret) = mint(&signing_gov(store.clone(), 7));
    let other = signing_gov(store, 9);
    let kind = crate::test_support::issued::double().0;
    let (read, live) = other.credential_secret(&kind, &public_id, 1_700_000_001);
    assert!(!live);
    assert_ne!(read.expose(&crate::seal::lend()), &secret);
}
