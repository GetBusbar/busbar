// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Binding: a virtual key's `expires_at` is a stored, UNENFORCED field. 1.5.5's signed-token
//! admission reads only the token's own `exp` (signature, then `exp`, then the denylist, then the
//! binding's generation); nothing refuses on the key row's `expires_at`, and rotate re-mints on the
//! 90-day token TTL. A key row whose `expires_at` is in the past is therefore STILL admitted, both
//! at the governance seam and end to end through the `keys` auth chain on the data plane.
//!
//! This pins the 1.5.5 rule so a well-meaning "enforce expires_at" cannot land silently: the day
//! that becomes the design, this test is the one that has to change, on purpose.

use crate::governance::signing::{TokenSigner, DEFAULT_KID};
use crate::governance::{GovState, MemoryStore, NewKeySpec, Store};
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
    token
}

/// Governance seam: the token verifies and resolves the binding even though the row's
/// `expires_at` is a month in the past — and the resolved binding carries that past value back
/// (stored, read, ignored). The contrast in the same test: the token's OWN `exp` is enforced.
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

    // The one expiry 1.5.5 enforces is the token's `exp`.
    assert!(
        gov.verify_token(&token, TOKEN_EXP + 1, None).is_none(),
        "the token's own exp IS enforced: the same token past its exp must be refused"
    );
}

// `a_key_row_whose_expires_at_is_in_the_past_is_admitted_on_the_data_plane` MOVED to
// `tests/key_expires_at_cross_plane.rs`: it drives a real HTTP round trip through `build_router`,
// which only routes `/pa/v1/messages` through the REAL `busbar_llm` plane's `build_runtime`/`viewer`
// — an integration-test target, never this `#[cfg(test)]` unit module (see
// `endpoints_cross_plane.rs`'s header for the same reason). This file's own seam-only test above
// names no plane and stays here.
