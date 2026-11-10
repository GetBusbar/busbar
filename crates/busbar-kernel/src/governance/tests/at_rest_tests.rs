// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::governance::{GovState, NewKeySpec};
use busbar_contract::records::{CredentialSecret, SecretForm};
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

fn keys(seed: u8, prev: Option<u8>) -> AtRestKeys {
    let prev = prev.map(|p| [p; 32]);
    AtRestKeys::new(&[seed; 32], prev.as_ref().map(|p| &p[..]))
}

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

    assert_ne!(sealed, k.seal(&m, b"wJalrXUtnFEMI/K7MDENG").unwrap());

    assert!(open(Some(&k), &meta("cred_b", "AKIA1"), &sealed).is_none());
    assert!(open(Some(&k), &meta("cred_a", "AKIA2"), &sealed).is_none());

    let other = keys(8, None);
    assert!(open(Some(&other), &m, &sealed).is_none());
    assert!(open(Some(&other), &m, &with_kid(&sealed, other.kid())).is_none());
    assert!(open(None, &m, &sealed).is_none());

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

#[test]
fn the_kid_is_derived_from_the_key_and_is_not_its_bytes() {
    let a = keys(7, None);
    assert_eq!(a.kid().len(), 16);
    assert!(a.kid().bytes().all(|b| b.is_ascii_hexdigit()));
    assert_eq!(a.kid(), keys(7, None).kid());
    assert_ne!(a.kid(), keys(8, None).kid());
    assert!(!hex::encode([7_u8; 32]).contains(a.kid()));
}

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

    assert!(open(Some(&keys(3, Some(4))), &m, &sealed).is_none());
}

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

async fn signing_gov(store: Arc<crate::persistence::facade::CoreStore>, seed: u8) -> GovState {
    let signer = crate::governance::signing::TokenSigner::from_secret_bytes(
        &[seed; 32],
        crate::governance::signing::DEFAULT_KID,
    );
    GovState::new_with_core(store, None, Some(signer))
        .await
        .unwrap()
}

async fn node(
    store: Arc<crate::persistence::facade::CoreStore>,
    seed: u8,
    prev: Option<u8>,
) -> GovState {
    let g = signing_gov(store, 7).await;
    g.set_at_rest_keys(Some(keys(seed, prev)));
    g
}

async fn try_mint(g: &GovState) -> crate::governance::RecordStoreResult<(String, String)> {
    let kind = crate::tests::frozen_text("signed_credential_kind");
    let shape = busbar_contract::auth_calls::IssuedShape {
        id_prefix: "AKIA".to_string(),
        id_len: 20,
        id_alphabet: "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".to_string(),
        secret_len: 40,
        secret_alphabet: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
            .to_string(),
    };
    let (_, _, public_id, secret) = g
        .mint_signed_with_credential_async(
            NewKeySpec {
                name: "at-rest".to_string(),
                ..Default::default()
            },
            2_000_000_000,
            1_700_000_000,
            kind.as_str().expect("the frozen credential kind is text"),
            &shape,
        )
        .await?;
    Ok((public_id, secret.expose(&crate::seal::lend()).clone()))
}

async fn mint(g: &GovState) -> (String, String) {
    try_mint(g).await.unwrap()
}

fn now() -> u64 {
    crate::store::now()
}

fn read(g: &GovState, public_id: &str) -> (String, bool) {
    let kind = crate::tests::frozen_text("signed_credential_kind");
    let (s, live) = g.credential_secret(
        kind.as_str().expect("the frozen credential kind is text"),
        public_id,
        now(),
    );
    (s.expose(&crate::seal::lend()).clone(), live)
}

async fn row(store: &crate::persistence::facade::CoreStore) -> CredentialSecret {
    let rows = store.identity().list_credentials_since(0).await.unwrap();
    assert_eq!(rows.len(), 1);
    rows.into_iter().next().unwrap()
}

fn kid_of(envelope: &str) -> &str {
    sealed_kid(envelope).expect("a sealed envelope")
}

#[tokio::test]
async fn a_minted_recoverable_credential_reaches_the_store_sealed_and_still_authenticates() {
    let store = crate::real_store::core().await;
    let g = node(store.clone(), 1, None).await;
    let (public_id, secret) = mint(&g).await;
    let r = row(&store).await;
    assert!(r.secret.starts_with("v1:aead:"), "not sealed");
    assert_eq!(kid_of(&r.secret), keys(1, None).kid());
    assert!(!r.secret.contains(&secret));
    assert_eq!(read(&g, &public_id), (secret, true));
}

#[tokio::test]
async fn minting_a_recoverable_credential_without_an_at_rest_key_is_refused_with_the_sentence() {
    let store = crate::real_store::core().await;
    let g = signing_gov(store.clone(), 7).await;
    let e = try_mint(&g).await.unwrap_err().to_string();
    assert!(e.contains(NO_KEY_REFUSAL), "{e}");
    assert!(e.contains("credentials.at_rest.key"), "{e}");
    assert!(store
        .identity()
        .list_credentials_since(0)
        .await
        .unwrap()
        .is_empty());
    assert!(
        store.identity().list_keys().await.unwrap().is_empty(),
        "a binding was written"
    );

    assert!(g
        .mint_signed_async(
            NewKeySpec {
                name: "bearer".to_string(),
                ..Default::default()
            },
            2_000_000_000,
            1_700_000_000,
        )
        .await
        .is_ok());
}

#[tokio::test]
async fn rotation_reseals_a_row_under_the_new_key_and_it_still_authenticates() {
    let store = crate::real_store::core().await;
    let (public_id, secret) = mint(&node(store.clone(), 1, None).await).await;
    let before = row(&store).await;
    assert_eq!(kid_of(&before.secret), keys(1, None).kid());

    let rotated = node(store.clone(), 2, Some(1)).await;
    assert_eq!(read(&rotated, &public_id), (secret.clone(), true));

    let pass = rotated.rewrap_credentials_async(now()).await.unwrap();
    assert_eq!((pass.resealed, pass.pending), (1, 0), "{pass:?}");
    let after = row(&store).await;
    assert_eq!(kid_of(&after.secret), keys(2, None).kid());
    assert!(!after.secret.contains(&secret));
    assert_eq!(after.meta.id, before.meta.id);
    assert_eq!(read(&rotated, &public_id), (secret.clone(), true));

    assert_eq!(
        read(&node(store.clone(), 2, None).await, &public_id),
        (secret, true)
    );

    let again = rotated.rewrap_credentials_async(now()).await.unwrap();
    assert_eq!((again.resealed, again.pending), (0, 0), "{again:?}");
}

#[tokio::test]
async fn two_nodes_rotating_together_reseal_a_row_once() {
    let store = crate::real_store::core().await;
    let (public_id, secret) = mint(&node(store.clone(), 1, None).await).await;
    let x = node(store.clone(), 2, Some(1)).await;
    let y = node(store.clone(), 2, Some(1)).await;

    let candidates = store.identity().list_credentials_since(0).await.unwrap();
    let first = x
        .rewrap_rows_async(candidates.clone(), now())
        .await
        .unwrap();
    let second = y.rewrap_rows_async(candidates, now()).await.unwrap();
    assert_eq!(first.resealed + second.resealed, 1, "{first:?} {second:?}");
    assert_eq!(kid_of(&row(&store).await.secret), keys(2, None).kid());
    assert_eq!(read(&y, &public_id), (secret, true));
}

#[tokio::test]
async fn a_rewrap_never_revives_a_revoked_row() {
    let store = crate::real_store::core().await;
    let (public_id, _) = mint(&node(store.clone(), 1, None).await).await;
    let rotated = node(store.clone(), 2, Some(1)).await;
    let candidates = store.identity().list_credentials_since(0).await.unwrap();
    store
        .identity()
        .revoke_credential(&candidates[0].meta.id, "leaked")
        .await
        .unwrap();
    let pass = rotated.rewrap_rows_async(candidates, now()).await.unwrap();
    assert_eq!(pass.resealed, 0, "{pass:?}");
    let r = row(&store).await;
    assert!(r.meta.revoked_at.is_some(), "the revocation was undone");
    assert!(r.secret.is_empty(), "revocation must retire the envelope");
    assert_eq!(r.meta.secret_form, SecretForm::None);
    rotated.refresh_async().await.unwrap();
    assert!(!read(&rotated, &public_id).1);
}

#[tokio::test]
async fn a_row_under_neither_key_does_not_authenticate() {
    let store = crate::real_store::core().await;
    let (public_id, secret) = mint(&node(store.clone(), 1, None).await).await;
    let stranger = node(store.clone(), 3, Some(4)).await;
    let (got, live) = read(&stranger, &public_id);
    assert!(!live);
    assert_ne!(got, secret);
    assert_eq!(got, "");
    let pass = stranger.rewrap_credentials_async(now()).await.unwrap();
    assert_eq!((pass.resealed, pass.pending), (0, 0), "{pass:?}");
    assert_eq!(kid_of(&row(&store).await.secret), keys(1, None).kid());

    assert!(!read(&signing_gov(store, 7).await, &public_id).1);
}

async fn legacy_store() -> (Arc<crate::persistence::facade::CoreStore>, String, String) {
    let source = crate::real_store::core().await;
    let (public_id, secret) = mint(&node(source.clone(), 1, None).await).await;
    let mut legacy = row(&source).await;
    legacy.secret = format!("v1:plain:{secret}").into();
    let key = source
        .identity()
        .get_key(&legacy.meta.key_id)
        .await
        .unwrap()
        .unwrap();
    let store = crate::real_store::core().await;
    store.identity().put_key(&key).await.unwrap();
    store.identity().put_credential(&legacy).await.unwrap();
    (store, public_id, secret)
}

#[tokio::test]
async fn a_legacy_plain_row_is_resealed_under_the_key() {
    let (store, public_id, secret) = legacy_store().await;
    let g = node(store.clone(), 1, None).await;
    g.refresh_async().await.unwrap();
    assert_eq!(read(&g, &public_id), (secret.clone(), true));

    let pass = g.rewrap_credentials_async(now()).await.unwrap();
    assert_eq!((pass.resealed, pass.pending), (1, 0), "{pass:?}");
    let r = row(&store).await;
    assert_eq!(kid_of(&r.secret), keys(1, None).kid());
    assert!(!r.secret.contains(&secret));
    assert_eq!(read(&g, &public_id), (secret, true));
}

mod immutable_store {
    use super::*;
    async fn rewrap(legacy_plaintext: bool) {
        let (backing, public_id, secret) = if legacy_plaintext {
            legacy_store().await
        } else {
            let backing = crate::real_store::core().await;
            let (public_id, secret) = mint(&node(backing.clone(), 1, None).await).await;
            (backing, public_id, secret)
        };
        let before = row(&backing).await;
        let store = backing.clone();
        let mut forbidden = before.clone();
        forbidden.secret = "v1:plain:replacement".to_owned().into();
        assert!(store.identity().put_credential(&forbidden).await.is_err());
        assert_eq!(row(&backing).await.secret, before.secret);

        let rotated = GovState::new_with_core(store.clone(), None, None)
            .await
            .unwrap();
        rotated.set_at_rest_keys(Some(keys(2, Some(1))));
        assert_eq!(read(&rotated, &public_id), (secret.clone(), true));
        let pass = rotated.rewrap_credentials_async(now()).await.unwrap();
        assert_eq!((pass.resealed, pass.pending), (1, 0), "{pass:?}");
        let after = row(&backing).await;
        assert_eq!(kid_of(&after.secret), keys(2, None).kid());
        assert_eq!(after.meta.id, before.meta.id);
        assert_eq!(after.meta.key_id, before.meta.key_id);
        assert_eq!(after.meta.public_id, before.meta.public_id);
        assert_eq!(after.meta.revoked_at, before.meta.revoked_at);
        assert!(!after.secret.contains(&secret));
        assert!(after.meta.revision > before.meta.revision);

        let retired = GovState::new_with_core(store.clone(), None, None)
            .await
            .unwrap();
        retired.set_at_rest_keys(Some(keys(2, None)));
        assert_eq!(read(&retired, &public_id), (secret, true));
        assert!(store.identity().put_credential(&forbidden).await.is_err());
        let again = retired.rewrap_credentials_async(now()).await.unwrap();
        assert_eq!((again.resealed, again.pending), (0, 0), "{again:?}");
        assert_eq!(row(&backing).await.meta.revision, after.meta.revision);
    }

    #[tokio::test]
    async fn key_rotation_works_without_allowing_ordinary_live_secret_replacement() {
        rewrap(false).await;
    }

    #[tokio::test]
    async fn legacy_plaintext_is_sealed_without_allowing_ordinary_live_secret_replacement() {
        rewrap(true).await;
    }

    #[tokio::test]
    async fn racing_rewraps_apply_once_and_stale_replay_cannot_increment_revision() {
        let store = crate::real_store::core().await;
        mint(&node(store.clone(), 1, None).await).await;
        let expected = row(&store).await;
        let replacement = keys(2, Some(1))
            .seal(&expected.meta, b"replacement")
            .unwrap();
        let barrier = Arc::new(tokio::sync::Barrier::new(3));
        let workers: Vec<_> = (0..2)
            .map(|_| {
                let (store, expected, replacement, barrier) = (
                    store.clone(),
                    expected.clone(),
                    replacement.clone(),
                    barrier.clone(),
                );
                tokio::spawn(async move {
                    barrier.wait().await;
                    store
                        .identity()
                        .rewrap_credential(&expected, &replacement)
                        .await
                        .unwrap()
                })
            })
            .collect();
        barrier.wait().await;
        let mut applied = 0;
        for worker in workers {
            applied += usize::from(worker.await.unwrap());
        }
        assert_eq!(applied, 1);
        let after = row(&store).await;
        assert_eq!(after.secret.as_str(), replacement);
        let mut meta = after.meta.clone();
        meta.revision = expected.meta.revision;
        assert_eq!(
            meta, expected.meta,
            "CAS only changes envelope and store revision"
        );
        assert!(!store
            .identity()
            .rewrap_credential(&expected, &replacement)
            .await
            .unwrap());
        assert_eq!(row(&store).await, after, "replay makes no write");
    }

    #[tokio::test]
    async fn rewrap_cannot_resurrect_a_revoked_or_deleted_snapshot() {
        for delete in [false, true] {
            let store = crate::real_store::core().await;
            mint(&node(store.clone(), 1, None).await).await;
            let expected = row(&store).await;
            let replacement = keys(2, Some(1))
                .seal(&expected.meta, b"replacement")
                .unwrap();
            if delete {
                store
                    .identity()
                    .delete_key(&expected.meta.key_id)
                    .await
                    .unwrap();
            } else {
                store
                    .identity()
                    .revoke_credential(&expected.meta.id, "retired")
                    .await
                    .unwrap();
            }
            let before = store.identity().list_credentials_since(0).await.unwrap();
            assert!(!store
                .identity()
                .rewrap_credential(&expected, &replacement)
                .await
                .unwrap());
            assert_eq!(
                store.identity().list_credentials_since(0).await.unwrap(),
                before
            );
        }
    }
}
