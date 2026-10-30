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
fn a_key_row_whose_expires_at_is_in_the_past_is_refused() {
    let (gov, store) = gov_and_store();
    let token = mint_then_expire_the_row(&gov, &store, None, NOW, TOKEN_EXP, ROW_EXPIRED_AT);

    let (verdict, log) = capture(|| gov.verify_token(&token, NOW, None));
    assert!(
        verdict.is_none(),
        "a key row whose expires_at is in the past must refuse the token"
    );
    assert!(
        log.text()
            .contains("signed-token rejected: the key row's expires_at has passed"),
        "the refusal is recorded like every other signed-token refusal; got: {}",
        log.text()
    );

    let row = gov
        .lookup_by_sub(&key_id_of(&gov, &store))
        .expect("the binding stays resolvable for the admin views");
    assert_eq!(
        row.expires_at,
        Some(ROW_EXPIRED_AT),
        "the stored expires_at is kept, so the admin views keep showing it"
    );
    assert!(
        row.enabled,
        "the row stays enabled; expiry is not a disable"
    );

    assert!(
        gov.verify_token(&token, TOKEN_EXP + 1, None).is_none(),
        "the token's own exp stays enforced"
    );
}

#[test]
fn a_key_row_expires_at_its_own_second() {
    let (gov, store) = gov_and_store();
    let token = mint_then_expire_the_row(&gov, &store, None, NOW - 10, TOKEN_EXP, NOW);

    assert!(
        gov.verify_token(&token, NOW - 1, None).is_some(),
        "one second before the row's expires_at the key still admits"
    );
    assert!(
        gov.verify_token(&token, NOW, None).is_none(),
        "at the row's expires_at the key is refused"
    );
}

fn key_id_of(_gov: &GovState, store: &busbar_plugin_loader::store_v3::LoadedStore) -> String {
    let keys = store.list_keys().expect("store read");
    assert_eq!(keys.len(), 1, "exactly the one minted key");
    keys[0].id.clone()
}

fn capture<T>(f: impl FnOnce() -> T) -> (T, Buf) {
    let buf = Buf::default();
    let writer = buf.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_target(false)
        .with_ansi(false)
        .with_max_level(tracing::Level::DEBUG)
        .finish();
    let out = tracing::subscriber::with_default(subscriber, f);
    (out, buf)
}

#[derive(Clone, Default)]
struct Buf(Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for Buf {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Buf {
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

