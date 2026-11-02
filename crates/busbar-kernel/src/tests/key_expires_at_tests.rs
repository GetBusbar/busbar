// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::governance::signing::{TokenSigner, DEFAULT_KID};
use crate::governance::{GovState, NewKeySpec, RecordStore};
use std::sync::Arc;

const NOW: u64 = 1_700_000_000;

const TOKEN_EXP: u64 = NOW + 3_600;

const ROW_EXPIRED_AT: u64 = NOW - 30 * 86_400;

fn gov_and_store() -> (
    Arc<GovState>,
    Arc<busbar_plugin_loader::store_v3::LoadedStore>,
) {
    let store = crate::real_store::store();
    let signer = TokenSigner::from_secret_bytes(&[5u8; 32], DEFAULT_KID);
    let gov = Arc::new(
        GovState::new_with_signer(store.clone(), Some("admintok".into()), Some(signer))
            .expect("gov"),
    );
    (gov, store)
}

fn mint_then_expire_the_row(
    gov: &GovState,
    store: &busbar_plugin_loader::store_v3::LoadedStore,
    pools: Option<Vec<&str>>,
    mint_now: u64,
    token_exp: u64,
    row_expired_at: u64,
) -> String {
    let spec = NewKeySpec {
        name: "long-lived".into(),
        allowed_pools: pools.map(|p| p.into_iter().map(str::to_string).collect()),
        group: None,
        labels: Default::default(),
        ..Default::default()
    };
    let (binding, token) = gov.mint_signed(spec, token_exp, mint_now).expect("mint");
    let mut row = store
        .get_key(&binding.id)
        .expect("store read")
        .expect("the minted row");
    assert_eq!(
        row.expires_at, None,
        "mint never stamps expires_at; it is a stored field nothing in the engine writes"
    );
    row.expires_at = Some(row_expired_at);
    store.put_key(&row).expect("rewrite the row");
    gov.refresh().expect("reload caches");
    token.expose(&crate::seal::lend()).clone()
}

#[test]
fn a_key_row_whose_expires_at_is_in_the_past_still_verifies() {
    let (gov, store) = gov_and_store();
    let token = mint_then_expire_the_row(&gov, &store, None, NOW, TOKEN_EXP, ROW_EXPIRED_AT);

    let resolved = gov
        .verify_token(&token, NOW, None)
        .expect("a past expires_at on the key row must not refuse the token");
    assert_eq!(
        resolved.expires_at,
        Some(ROW_EXPIRED_AT),
        "the past expires_at is carried on the resolved binding, so it was read and ignored, \
         not lost"
    );
    assert!(resolved.enabled, "the row stays enabled; nothing flips it");

    assert!(
        gov.verify_token(&token, TOKEN_EXP + 1, None).is_none(),
        "the token's own exp IS enforced: the same token past its exp must be refused"
    );
}
