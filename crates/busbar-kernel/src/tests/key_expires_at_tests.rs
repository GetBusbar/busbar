// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Binding: a virtual key's stored `expires_at` is ENFORCED (owner-signed 2026-10-30, SEC-VKEY).
//! 1.5.5's signed-token admission read only the token's own `exp`; 1.6.0 also refuses a key whose
//! row `expires_at` is at or before `now`, at the governance seam and end to end through the `keys`
//! auth chain on the data plane (the same opaque 401 an expired token gets). The row keeps the
//! value, so the admin views still show it.

use crate::governance::signing::{TokenSigner, DEFAULT_KID};
use crate::governance::{GovState, MemoryStore, NewKeySpec, RecordStore};
use std::sync::Arc;

/// A fixed "now" so the token `exp` and the key row's `expires_at` are unambiguous.
const NOW: u64 = 1_700_000_000;
/// The token lives an hour past `NOW`.
const TOKEN_EXP: u64 = NOW + 3_600;
/// The key row's `expires_at`: thirty days BEFORE `NOW`.
const ROW_EXPIRED_AT: u64 = NOW - 30 * 86_400;

/// A governance engine over a memory store the test also keeps a handle to, so it can rewrite the
/// key row the way an operator (or a migrated 1.5.5 database) would.
fn gov_and_store() -> (Arc<GovState>, Arc<MemoryStore>) {
    let store = Arc::new(MemoryStore::new());
    let signer = TokenSigner::from_secret_bytes(&[5u8; 32], DEFAULT_KID);
    let gov = Arc::new(
        GovState::new_with_signer(store.clone(), Some("admintok".into()), Some(signer))
            .expect("gov"),
    );
    (gov, store)
}

/// Mint a key, then stamp its row with an `expires_at` in the past and reload the caches.
/// Returns the bearer token minted BEFORE the stamp (its own `exp` is still in the future).
///
/// `mint_now`/`token_exp`/`row_expired_at` are threaded in rather than read off the module's fixed
/// `NOW`/`TOKEN_EXP`/`ROW_EXPIRED_AT` constants: the governance-seam test below verifies with an
/// EXPLICIT, caller-supplied clock (`gov.verify_token(&token, NOW, None)`), so a frozen epoch is
/// fine there. The data-plane test runs the token through a REAL HTTP round trip, and the `keys`
/// engine arm on that path (`keys_arm_verdict` in `crate::auth`) checks the token's `exp` against
/// the process's real wall clock (`busbar_kernel::store::now()`), never an injected one — so a token minted
/// against a frozen historical epoch is genuinely expired by the time the request lands, and gets
/// refused for exactly the reason the module doc says IS enforced (the token's own `exp`), not the
/// row's `expires_at` this test is about.
fn mint_then_expire_the_row(
    gov: &GovState,
    store: &MemoryStore,
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

/// Governance seam: a token whose own `exp` is still in the future is REFUSED once its key row's
/// `expires_at` is a month in the past, and the refusal is traced like every other signed-token
/// refusal. The row keeps the value (admin views read it); the token's own `exp` stays enforced too.
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

/// The boundary: `expires_at == now` is already expired (as a token's `exp == now` is), and the
/// second before it still admits.
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

/// The one key `mint_then_expire_the_row` minted.
fn key_id_of(_gov: &GovState, store: &MemoryStore) -> String {
    let keys = store.list_keys().expect("store read");
    assert_eq!(keys.len(), 1, "exactly the one minted key");
    keys[0].id.clone()
}

/// Run `f` with a DEBUG subscriber and return its output beside the result.
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

// `a_key_row_whose_expires_at_is_in_the_past_is_admitted_on_the_data_plane` MOVED to the
// composition root's door suite (`crates/busbar/src/root/tests/serve_tests.rs`): it drives a real
// request through the data router built with the claims of the door that serves the `pools` map.
// This file's own seam-only test above names no plane and stays here.
