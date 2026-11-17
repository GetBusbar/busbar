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
    assert!(proof.current_key(&gov, END - 1, None).is_some());
    assert!(proof.current_key(&gov, END, None).is_none());
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
    assert!(proof.current_key(&gov, START, None).is_some());
    gov.set_signing_key(Some(signer(8)));
    assert!(proof.current_key(&gov, START, None).is_none());
    gov.set_signing_key(None);
    assert!(proof.current_key(&gov, START, None).is_none());
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
    assert!(proof.current_key(&gov, START, None).is_none());
    let mut changed = original.clone();
    changed.deleted_at = Some(START);
    replace(&gov, changed);
    assert!(proof.current_key(&gov, START, None).is_none());
    let mut changed = original.clone();
    changed.expires_at = Some(START);
    replace(&gov, changed);
    assert!(proof.current_key(&gov, START, None).is_none());
    let mut changed = original.clone();
    changed.generation_hash = super::binding_marker(&original.id, "rotated");
    replace(&gov, changed);
    assert!(proof.current_key(&gov, START, None).is_none());
    let mut changed = original;
    changed.binding_mode = Some(super::SELF_KEY_BINDING_MODE.into());
    changed.idp_subject = Some("held-subject".into());
    replace(&gov, changed);
    gov.install_transition_self_holds(std::collections::BTreeSet::from(["held-subject".into()]));
    assert!(proof.current_key(&gov, START, None).is_none());
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
    assert!(proof.current_key(&gov, START, None).is_none());
    gov.caches
        .write()
        .unwrap()
        .by_id
        .remove(&proof.original_key().id);
    assert!(proof.current_key(&gov, START, None).is_none());
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
    assert!(proof.current_key(&other, START, None).is_none());
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
    assert!(proof.current_key(&gov, START, Some(audience)).is_some());
    assert!(proof.current_key(&gov, START, None).is_none());
    assert!(proof
        .current_key(&gov, START, Some("urn:test:other"))
        .is_none());
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
