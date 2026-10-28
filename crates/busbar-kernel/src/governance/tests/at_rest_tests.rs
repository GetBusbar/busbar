// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::governance::{GovState, NewKeySpec};
use crate::test_support::store_double::MemoryStore;
use busbar_contract::records::{CredentialSecret, RecordStore, SecretForm};
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

/// The at-rest keys `credentials.at_rest` resolves to: `key` from `seed`, `previous` from `prev`.
fn keys(seed: u8, prev: Option<u8>) -> AtRestKeys {
    let prev = prev.map(|p| [p; 32]);
    AtRestKeys::new(&[seed; 32], prev.as_ref().map(|p| &p[..]))
}

/// `envelope` with its kid replaced by `kid`: a row that names a key it was not sealed under.
fn with_kid(envelope: &str, kid: &str) -> String {
    let rest = envelope.strip_prefix("v1:aead:").expect("sealed");
    let (_, tail) = rest.split_once(':').expect("kid");
    format!("v1:aead:{kid}:{tail}")
}

#[test]
fn a_sealed_secret_opens_only_for_its_row_and_its_key() {
    let k = keys(7, None);
    let m = meta("cred_a", "AKIA1");
    let sealed = k.seal(&m, b"wJalrXUtnFEMI/K7MDENG").unwrap();
    assert!(
        sealed.starts_with(&format!("v1:aead:{}:", k.kid())),
        "{sealed}"
    );
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
    // Another key, naming its own kid or this one's: does not open. No key: does not open.
    let other = keys(8, None);
    assert!(open(Some(&other), &m, &sealed).is_none());
    assert!(open(Some(&other), &m, &with_kid(&sealed, other.kid())).is_none());
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
    assert!(open(Some(&keys(7, None)), &m, "v2:other:x").is_none());
    assert!(open(Some(&keys(7, None)), &m, "legacy").is_none());
}

#[test]
fn the_key_never_prints() {
    let k = keys(7, Some(8));
    let text = format!("{k:?}");
    assert_eq!(
        text,
        format!(
            "AtRestKeys {{ kid: \"{}\", previous: Some(\"{}\"), .. }}",
            k.kid(),
            keys(8, None).kid()
        )
    );
}

/// The kid names the key without being it: 16 hex characters, stable for one key, distinct across
/// keys, and not a prefix of the key's bytes in hex.
#[test]
fn the_kid_is_derived_from_the_key_and_is_not_its_bytes() {
    let a = keys(7, None);
    assert_eq!(a.kid().len(), 16);
    assert!(a.kid().bytes().all(|b| b.is_ascii_hexdigit()));
    assert_eq!(a.kid(), keys(7, None).kid());
    assert_ne!(a.kid(), keys(8, None).kid());
    assert!(!hex::encode([7_u8; 32]).contains(a.kid()));
}

/// The old key still opens what it sealed: a row sealed under A opens under `key: B, previous: A`.
#[test]
fn the_previous_key_still_opens_a_row_it_sealed() {
    let a = keys(1, None);
    let m = meta("cred_a", "AKIA1");
    let sealed = a.seal(&m, b"wJalrXUtnFEMI/K7MDENG").unwrap();
    assert_eq!(
        open(Some(&keys(2, Some(1))), &m, &sealed)
            .as_deref()
            .map(String::as_str),
        Some("wJalrXUtnFEMI/K7MDENG")
    );
    // A third key with neither: does not open.
    assert!(open(Some(&keys(3, Some(4))), &m, &sealed).is_none());
}

/// A recoverable at-rest key reference resolves to 32 raw bytes or 64 hex characters; anything else
/// is refused, naming the path and never the value.
#[test]
fn an_at_rest_key_is_32_bytes_or_64_hex_characters() {
    let hex64 = hex::encode([5_u8; 32]);
    assert_eq!(
        &parse_key("credentials.at_rest.key", hex64.as_bytes()).unwrap()[..],
        &[5_u8; 32]
    );
    assert_eq!(
        &parse_key("credentials.at_rest.key", format!("{hex64}\n").as_bytes()).unwrap()[..],
        &[5_u8; 32]
    );
    assert_eq!(
        &parse_key("credentials.at_rest.key", &[9_u8; 32]).unwrap()[..],
        &[9_u8; 32]
    );
    let e = parse_key("credentials.at_rest.previous", b"short-secret-value").unwrap_err();
    assert!(e.contains("credentials.at_rest.previous"), "{e}");
    assert!(!e.contains("short-secret-value"), "{e}");
}

fn signing_gov(store: Arc<MemoryStore>, seed: u8) -> GovState {
    let signer = crate::governance::signing::TokenSigner::from_secret_bytes(
        &[seed; 32],
        crate::governance::signing::DEFAULT_KID,
    );
    GovState::new_with_signer(store, None, Some(signer)).unwrap()
}

/// A node on `store` whose `credentials.at_rest` is `key: <seed>, previous: <prev>`.
fn node(store: Arc<MemoryStore>, seed: u8, prev: Option<u8>) -> GovState {
    let g = signing_gov(store, 7);
    g.set_at_rest_keys(Some(keys(seed, prev)));
    g
}

fn try_mint(g: &GovState) -> crate::governance::RecordStoreResult<(String, String)> {
    let (_, _, public_id, secret) = g.mint_signed_with_credential(
        NewKeySpec {
            name: "at-rest".to_string(),
            ..Default::default()
        },
        2_000_000_000,
        1_700_000_000,
        &crate::test_support::issued::double().0,
        &crate::test_support::issued::double().1,
    )?;
    Ok((public_id, secret.expose(&crate::seal::lend()).clone()))
}

fn mint(g: &GovState) -> (String, String) {
    try_mint(g).unwrap()
}

const NOW: u64 = 1_700_000_001;

fn read(g: &GovState, public_id: &str) -> (String, bool) {
    let kind = crate::test_support::issued::double().0;
    let (s, live) = g.credential_secret(&kind, public_id, NOW);
    (s.expose(&crate::seal::lend()).clone(), live)
}

/// The one stored credential row.
fn row(store: &MemoryStore) -> CredentialSecret {
    let rows = store.list_credentials_since(0).unwrap();
    assert_eq!(rows.len(), 1);
    rows.into_iter().next().unwrap()
}

fn kid_of(envelope: &str) -> &str {
    sealed_kid(envelope).expect("a sealed envelope")
}

/// RED before the seal: the store held `v1:plain:<secret>`. Now no store row carries the secret,
/// and the read still answers it, live.
#[test]
fn a_minted_recoverable_credential_reaches_the_store_sealed_and_still_authenticates() {
    let store = Arc::new(MemoryStore::new());
    let g = node(store.clone(), 1, None);
    let (public_id, secret) = mint(&g);
    let r = row(&store);
    assert!(r.secret.starts_with("v1:aead:"), "not sealed");
    assert_eq!(kid_of(&r.secret), keys(1, None).kid());
    assert!(!r.secret.contains(&secret));
    assert_eq!(read(&g, &public_id), (secret, true));
}

/// RED before the dedicated key: the KEK was the signing key's, so minting needed only that. Now a
/// node with no `credentials.at_rest` refuses, says what to configure, and writes nothing.
#[test]
fn minting_a_recoverable_credential_without_an_at_rest_key_is_refused_with_the_sentence() {
    let store = Arc::new(MemoryStore::new());
    let g = signing_gov(store.clone(), 7);
    let e = try_mint(&g).unwrap_err().to_string();
    assert!(e.contains(NO_KEY_REFUSAL), "{e}");
    assert!(e.contains("credentials.at_rest.key"), "{e}");
    assert!(store.list_credentials_since(0).unwrap().is_empty());
    assert!(
        store.list_keys().unwrap().is_empty(),
        "a binding was written"
    );
    // A bearer-only mint needs no at-rest key.
    assert!(g
        .mint_signed(
            NewKeySpec {
                name: "bearer".to_string(),
                ..Default::default()
            },
            2_000_000_000,
            1_700_000_000,
        )
        .is_ok());
}

/// ROTATION RE-WRAPS AND NEVER BREAKS. Sealed under A; the node is reconfigured `key: B,
/// previous: A`. The row authenticates before the re-wrap (under `previous`), the re-wrap re-seals
/// it under B (the stored kid changes and the store still holds no secret), and it authenticates
/// after. A second pass finds nothing to do.
#[test]
fn rotation_reseals_a_row_under_the_new_key_and_it_still_authenticates() {
    let store = Arc::new(MemoryStore::new());
    let (public_id, secret) = mint(&node(store.clone(), 1, None));
    let before = row(&store);
    assert_eq!(kid_of(&before.secret), keys(1, None).kid());

    let rotated = node(store.clone(), 2, Some(1));
    assert_eq!(read(&rotated, &public_id), (secret.clone(), true));

    let pass = rotated.rewrap_credentials(NOW).unwrap();
    assert_eq!((pass.resealed, pass.pending), (1, 0), "{pass:?}");
    let after = row(&store);
    assert_eq!(kid_of(&after.secret), keys(2, None).kid());
    assert!(!after.secret.contains(&secret));
    assert_eq!(after.meta.id, before.meta.id);
    assert_eq!(read(&rotated, &public_id), (secret.clone(), true));
    // With A retired (`key: B` alone), it still authenticates.
    assert_eq!(
        read(&node(store.clone(), 2, None), &public_id),
        (secret, true)
    );

    let again = rotated.rewrap_credentials(NOW).unwrap();
    assert_eq!((again.resealed, again.pending), (0, 0), "{again:?}");
}

/// Two nodes rotating together: the claim lets exactly one of them re-seal the row.
#[test]
fn two_nodes_rotating_together_reseal_a_row_once() {
    let store = Arc::new(MemoryStore::new());
    let (public_id, secret) = mint(&node(store.clone(), 1, None));
    let x = node(store.clone(), 2, Some(1));
    let y = node(store.clone(), 2, Some(1));
    // Both read the row under A before either re-wraps it.
    let candidates = store.list_credentials_since(0).unwrap();
    let first = x.rewrap_rows(candidates.clone(), NOW).unwrap();
    let second = y.rewrap_rows(candidates, NOW).unwrap();
    assert_eq!(first.resealed + second.resealed, 1, "{first:?} {second:?}");
    assert_eq!(kid_of(&row(&store).secret), keys(2, None).kid());
    assert_eq!(read(&y, &public_id), (secret, true));
}

/// A row revoked between the re-wrap's read and its write is not written back: a re-wrap never
/// brings a revoked credential back to life.
#[test]
fn a_rewrap_never_revives_a_revoked_row() {
    let store = Arc::new(MemoryStore::new());
    let (public_id, _) = mint(&node(store.clone(), 1, None));
    let rotated = node(store.clone(), 2, Some(1));
    let candidates = store.list_credentials_since(0).unwrap();
    store
        .revoke_credential(&candidates[0].meta.id, "leaked")
        .unwrap();
    let pass = rotated.rewrap_rows(candidates, NOW).unwrap();
    assert_eq!(pass.resealed, 0, "{pass:?}");
    let r = row(&store);
    assert!(r.meta.revoked_at.is_some(), "the revocation was undone");
    assert_eq!(kid_of(&r.secret), keys(1, None).kid());
    rotated.refresh().unwrap();
    assert!(!read(&rotated, &public_id).1);
}

/// A row that opens under neither key does not authenticate: it answers as an unknown credential
/// (the dummy, not live). The re-wrap leaves it as it is.
#[test]
fn a_row_under_neither_key_does_not_authenticate() {
    let store = Arc::new(MemoryStore::new());
    let (public_id, secret) = mint(&node(store.clone(), 1, None));
    let stranger = node(store.clone(), 3, Some(4));
    let (got, live) = read(&stranger, &public_id);
    assert!(!live);
    assert_ne!(got, secret);
    assert_eq!(got, crate::auth::DUMMY_SECRET);
    let pass = stranger.rewrap_credentials(NOW).unwrap();
    assert_eq!((pass.resealed, pass.pending), (0, 0), "{pass:?}");
    assert_eq!(kid_of(&row(&store).secret), keys(1, None).kid());
    // No key at all: the same.
    assert!(!read(&signing_gov(store, 7), &public_id).1);
}

/// A pre-1.6.0 row (`v1:plain:`) is re-sealed under `key` too, and still authenticates.
#[test]
fn a_legacy_plain_row_is_resealed_under_the_key() {
    let store = Arc::new(MemoryStore::new());
    let g = node(store.clone(), 1, None);
    let (public_id, secret) = mint(&g);
    // The row as 1.5.5 wrote it.
    let mut legacy = row(&store);
    legacy.secret = format!("v1:plain:{secret}");
    store.put_credential(&legacy).unwrap();
    g.refresh().unwrap();
    assert_eq!(read(&g, &public_id), (secret.clone(), true));

    let pass = g.rewrap_credentials(NOW).unwrap();
    assert_eq!((pass.resealed, pass.pending), (1, 0), "{pass:?}");
    let r = row(&store);
    assert_eq!(kid_of(&r.secret), keys(1, None).kid());
    assert!(!r.secret.contains(&secret));
    assert_eq!(read(&g, &public_id), (secret, true));
}
