// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::signing::{TokenSigner, TokenVerifier, DEFAULT_KID};
use super::{GovState, NewKeySpec, VirtualKey};
use std::sync::Arc;

const START: u64 = 1_000;
const END: u64 = 2_000;

async fn fixture() -> (GovState, String) {
    let core = crate::real_store::core().await;
    let gov = GovState::new_with_core(core, None, Some(signer(9)))
        .await
        .expect("native governance");
    let (_, token) = gov
        .mint_signed_async(
            NewKeySpec {
                name: "retained authority".into(),
                ..Default::default()
            },
            END,
            START,
        )
        .await
        .expect("mint");
    (gov, token.expose(&crate::seal::lend()).to_owned())
}

fn signer(byte: u8) -> TokenSigner {
    TokenSigner::from_secret_bytes(&[byte; 32], DEFAULT_KID)
}

fn replace(gov: &GovState, key: VirtualKey) {
    gov.caches
        .write()
        .unwrap()
        .by_id
        .insert(key.id.clone(), Arc::new(key));
}

#[tokio::test]
async fn signed_lifetime_survives_original_key_retention() {
    let (gov, token) = fixture().await;
    let proof = gov
        .verify_token_authority(&token, START, None)
        .expect("proof");
    assert!(proof.current_key(&gov, END - 1, None).is_ok());
    assert!(proof.current_key(&gov, END, None).is_err());
    assert!(proof.original_key().enabled);
    assert!(proof.original_key().expires_at.is_none());
}

#[tokio::test]
async fn exact_verifying_key_survives_arc_replacement_but_not_same_kid_rotation() {
    let (gov, token) = fixture().await;
    let proof = gov
        .verify_token_authority(&token, START, None)
        .expect("proof");
    gov.set_signing_key(Some(signer(9)));
    assert!(proof.current_key(&gov, START, None).is_ok());
    gov.set_signing_key(Some(signer(8)));
    assert!(proof.current_key(&gov, START, None).is_err());
    gov.set_signing_key(None);
    assert!(proof.current_key(&gov, START, None).is_err());
}

#[tokio::test]
async fn current_key_changes_do_not_rewrite_original_authority() {
    let (gov, token) = fixture().await;
    let proof = gov
        .verify_token_authority(&token, START, None)
        .expect("proof");
    let original = Arc::clone(proof.original_key());
    let mut changed = original.as_ref().clone();
    changed.group = Some("new-current-group".into());
    changed.allowed_scopes = Some(Vec::new());
    replace(&gov, changed);
    let current = proof.current_key(&gov, START, None).expect("current row");
    assert_eq!(current.group.as_deref(), Some("new-current-group"));
    assert_eq!(current.allowed_scopes, Some(Vec::new()));
    assert!(Arc::ptr_eq(proof.original_key(), &original));
    assert!(original.group.is_none());
    assert!(original.allowed_scopes.is_none());
}

#[tokio::test]
async fn current_hydrated_row_refuses_disable_delete_expiry_rotation_and_self_hold() {
    let (gov, token) = fixture().await;
    let proof = gov
        .verify_token_authority(&token, START, None)
        .expect("proof");
    let original = proof.original_key().as_ref().clone();
    let mut changed = original.clone();
    changed.enabled = false;
    replace(&gov, changed);
    assert!(proof.current_key(&gov, START, None).is_err());
    let mut changed = original.clone();
    changed.deleted_at = Some(START);
    replace(&gov, changed);
    assert!(proof.current_key(&gov, START, None).is_err());
    let mut changed = original.clone();
    changed.expires_at = Some(START);
    replace(&gov, changed);
    assert!(proof.current_key(&gov, START, None).is_err());
    let mut changed = original.clone();
    changed.generation_hash = super::binding_marker(&original.id, "rotated");
    replace(&gov, changed);
    assert!(proof.current_key(&gov, START, None).is_err());
    let mut changed = original;
    changed.binding_mode = Some(super::SELF_KEY_BINDING_MODE.into());
    changed.idp_subject = Some("held-subject".into());
    replace(&gov, changed);
    gov.install_transition_self_holds(std::collections::BTreeSet::from(["held-subject".into()]));
    assert!(proof.current_key(&gov, START, None).is_err());
}

#[tokio::test]
async fn current_revocation_and_missing_row_refuse_retained_proof() {
    let (gov, token) = fixture().await;
    let proof = gov
        .verify_token_authority(&token, START, None)
        .expect("proof");
    gov.revoke_async(&proof.original_key().id, "regression")
        .await
        .expect("revoke");
    assert!(proof.current_key(&gov, START, None).is_err());
    gov.caches
        .write()
        .unwrap()
        .by_id
        .remove(&proof.original_key().id);
    assert!(proof.current_key(&gov, START, None).is_err());
}

#[tokio::test]
async fn matching_signer_and_key_in_another_governance_domain_do_not_match_authority() {
    let (gov, token) = fixture().await;
    let proof = gov
        .verify_token_authority(&token, START, None)
        .expect("proof");
    let (other, _) = fixture().await;
    replace(&other, proof.original_key().as_ref().clone());
    assert!(other.verify_token(&token, START, None).is_some());
    assert!(proof.current_key(&other, START, None).is_err());
}

#[tokio::test]
async fn retained_audience_is_exact_and_cannot_be_reinterpreted() {
    let (gov, token) = fixture().await;
    let signer = signer(9);
    let verifier = TokenVerifier::single(signer.kid(), signer.verifying_key());
    let claims = verifier.verify(&token, START, None).expect("claims");
    let audience = "urn:test:original";
    let bound = signer.mint_for_audience(
        &claims.sub,
        END,
        claims.generation.as_deref(),
        audience,
        None,
    );
    let proof = gov
        .verify_token_authority(&bound, START, Some(audience))
        .expect("bound proof");
    assert!(proof.current_key(&gov, START, Some(audience)).is_ok());
    assert!(proof.current_key(&gov, START, None).is_err());
    assert!(proof
        .current_key(&gov, START, Some("urn:test:other"))
        .is_err());
    assert!(gov.verify_token_authority(&bound, START, None).is_none());
}

#[tokio::test]
async fn altered_signature_cannot_mint_retained_authority() {
    let (gov, token) = fixture().await;
    let (payload, signature) = token.rsplit_once('.').expect("token separator");
    let first = if signature.starts_with('A') { 'B' } else { 'A' };
    let changed = format!(
        "{payload}.{first}{}",
        signature.get(1..).expect("signature tail")
    );
    assert!(gov.verify_token_authority(&changed, START, None).is_none());
}

#[tokio::test]
async fn absent_signed_generation_cannot_survive_binding_rotation() {
    let (gov, token) = fixture().await;
    let initial = gov.verify_token(&token, START, None).expect("initial row");
    let mut legacy = initial.as_ref().clone();
    legacy.generation_hash.clear();
    replace(&gov, legacy);
    let token = signer(9).mint(&initial.id, END, None);
    let proof = gov
        .verify_token_authority(&token, START, None)
        .expect("ungenerated binding");
    assert!(proof.current_key(&gov, START, None).is_ok());
    let mut rotated = initial.as_ref().clone();
    rotated.generation_hash = super::binding_marker(&initial.id, "rotation");
    replace(&gov, rotated);
    assert!(proof.current_key(&gov, START, None).is_err());
}

struct CountReads {
    inner: Arc<dyn busbar_contract::persistence::PersistenceBackend>,
    reads: std::sync::atomic::AtomicUsize,
}

impl busbar_contract::persistence::PersistenceBackend for CountReads {
    fn info(&self) -> busbar_contract::persistence::BackendInfo {
        self.inner.info()
    }
    fn read(
        &self,
        request: Arc<busbar_contract::persistence::Read>,
    ) -> busbar_contract::persistence::Call<'_, busbar_contract::persistence::ReadResult> {
        self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner.read(request)
    }
    fn scan(
        &self,
        request: Arc<busbar_contract::persistence::Scan>,
    ) -> busbar_contract::persistence::Call<'_, busbar_contract::persistence::Page> {
        self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner.scan(request)
    }
    fn commit(
        &self,
        candidate: busbar_contract::persistence::PreparedCandidate,
        key: busbar_contract::persistence::CommitKey,
    ) -> busbar_contract::persistence::Call<'_, busbar_contract::persistence::Decision> {
        self.inner.commit(candidate, key)
    }
    fn clock(
        &self,
        dataset: busbar_contract::persistence::DatasetId,
    ) -> busbar_contract::persistence::Call<'_, busbar_contract::persistence::ClockObservation>
    {
        self.inner.clock(dataset)
    }
}

#[tokio::test(flavor = "current_thread")]
async fn current_read_never_schedules_stale_revocation_refresh() {
    use std::sync::atomic::Ordering;
    let backend = Arc::new(CountReads {
        inner: crate::real_store::native_backend().await,
        reads: std::sync::atomic::AtomicUsize::new(0),
    });
    let core = crate::real_store::core_over(backend.clone()).await;
    let gov = GovState::new_with_core(core, None, Some(signer(9)))
        .await
        .expect("gov");
    let now = crate::store::now();
    let later = now + super::REVOCATION_SYNC_TTL_SECS * 2;
    let (_, token) = gov
        .mint_signed_async(NewKeySpec::default(), later + 100, now)
        .await
        .expect("mint");
    let proof = gov
        .verify_token_authority(token.expose(&crate::seal::lend()), now, None)
        .expect("proof");
    let before = backend.reads.load(Ordering::SeqCst);
    assert!(proof.current_key(&gov, later, None).is_ok());
    tokio::task::yield_now().await;
    assert_eq!(
        backend.reads.load(Ordering::SeqCst),
        before,
        "current read must not launch stale refresh under admission"
    );
    gov.prepare_current_credentials(later);
    tokio::task::yield_now().await;
    assert!(
        backend.reads.load(Ordering::SeqCst) > before,
        "the same stale refresh is scheduled by the explicit outside-gate operation"
    );
}

#[tokio::test]
async fn current_credential_refusal_retains_the_actual_checked_cause() {
    use super::current_credential::CurrentCredentialRefusal as Refusal;
    let (gov, token) = fixture().await;
    let proof = gov
        .verify_token_authority(&token, START, None)
        .expect("proof");
    assert_eq!(proof.current_key(&gov, END, None), Err(Refusal::Expired));
    assert_eq!(
        proof.current_key(&gov, START, Some("different")),
        Err(Refusal::AudienceMismatch)
    );
    gov.set_signing_key(Some(signer(8)));
    assert_eq!(
        proof.current_key(&gov, START, None),
        Err(Refusal::UntrustedSigner)
    );
    gov.set_signing_key(None);
    assert_eq!(
        proof.current_key(&gov, START, None),
        Err(Refusal::SigningUnavailable)
    );
    let (foreign, _) = fixture().await;
    assert_eq!(
        proof.current_key(&foreign, START, None),
        Err(Refusal::ForeignAuthority)
    );
}

#[tokio::test]
async fn hydrated_standing_refusals_preserve_each_source_branch() {
    use super::current_credential::CurrentCredentialRefusal as Refusal;
    let (gov, token) = fixture().await;
    let proof = gov
        .verify_token_authority(&token, START, None)
        .expect("proof");
    let original = proof.original_key().as_ref().clone();
    let mut key = original.clone();
    key.enabled = false;
    replace(&gov, key);
    assert_eq!(
        proof.current_key(&gov, START, None),
        Err(Refusal::DisabledKey)
    );
    let mut key = original.clone();
    key.deleted_at = Some(START);
    replace(&gov, key);
    assert_eq!(
        proof.current_key(&gov, START, None),
        Err(Refusal::DeletedKey)
    );
    let mut key = original.clone();
    key.expires_at = Some(START);
    replace(&gov, key);
    assert_eq!(
        proof.current_key(&gov, START, None),
        Err(Refusal::KeyExpired)
    );
    let mut key = original.clone();
    key.generation_hash = super::binding_marker(&key.id, "rotated");
    replace(&gov, key);
    assert_eq!(
        proof.current_key(&gov, START, None),
        Err(Refusal::RotatedKey)
    );
    let mut key = original.clone();
    key.binding_mode = Some(super::SELF_KEY_BINDING_MODE.into());
    key.idp_subject = Some("held-subject".into());
    replace(&gov, key);
    gov.install_transition_self_holds(std::collections::BTreeSet::from(["held-subject".into()]));
    assert_eq!(
        proof.current_key(&gov, START, None),
        Err(Refusal::SubjectHeld)
    );
    gov.caches.write().unwrap().by_id.remove(&original.id);
    assert_eq!(
        proof.current_key(&gov, START, None),
        Err(Refusal::MissingKey)
    );
    replace(&gov, original);
    gov.revoke_async(&proof.original_key().id, "refusal reason")
        .await
        .expect("revoke");
    assert_eq!(proof.current_key(&gov, START, None), Err(Refusal::Revoked));
}

#[test]
fn current_credential_codes_use_the_existing_auth_refusal_map() {
    use super::current_credential::CurrentCredentialRefusal as Refusal;
    use crate::refusal::{CoreRefusals, RefusalMap};
    use busbar_plugin_abi::fail::refused::{R_BAD_CREDENTIAL, R_EXPIRED};
    let map = CoreRefusals::new();
    for reason in [Refusal::Expired, Refusal::KeyExpired] {
        let reply = map.for_auth(1, reason.auth_code().expect("auth code"));
        assert_eq!((reply.status, reply.code), (401, R_EXPIRED));
    }
    for reason in [
        Refusal::SigningUnavailable,
        Refusal::AudienceMismatch,
        Refusal::UntrustedSigner,
        Refusal::Revoked,
        Refusal::SubjectHeld,
        Refusal::MissingKey,
        Refusal::DisabledKey,
        Refusal::RotatedKey,
        Refusal::DeletedKey,
    ] {
        let reply = map.for_auth(1, reason.auth_code().expect("auth code"));
        assert_eq!((reply.status, reply.code), (401, R_BAD_CREDENTIAL));
    }
    assert_eq!(Refusal::ForeignAuthority.auth_code(), None);
}
