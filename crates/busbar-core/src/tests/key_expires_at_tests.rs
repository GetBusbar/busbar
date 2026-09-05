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
fn mint_then_expire_the_row(gov: &GovState, store: &MemoryStore, pools: Option<Vec<&str>>) -> String {
    let spec = NewKeySpec {
        name: "long-lived".into(),
        allowed_pools: pools.map(|p| p.into_iter().map(str::to_string).collect()),
        group: None,
        labels: Default::default(),
        ..Default::default()
    };
    let (binding, token) = gov.mint_signed(spec, TOKEN_EXP, NOW).expect("mint");
    let mut row = store
        .get_key(&binding.id)
        .expect("store read")
        .expect("the minted row");
    assert_eq!(
        row.expires_at, None,
        "mint never stamps expires_at; it is a stored field nothing in the engine writes"
    );
    row.expires_at = Some(ROW_EXPIRED_AT);
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
    let token = mint_then_expire_the_row(&gov, &store, None);

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

/// End to end on the data plane through the `keys` chain: the request is admitted (200 from the
/// mock upstream) with the row's `expires_at` in the past, while a wrong token is still refused
/// (401) on the same app — so the admission is a real gate, not an open chain.
#[tokio::test]
async fn a_key_row_whose_expires_at_is_in_the_past_is_admitted_on_the_data_plane() {
    use crate::test_support::{LaneSpec, MockResponse, MockServer, MockServerState, TestApp};

    crate::metrics::init();
    let state = Arc::new(MockServerState::new());
    state.push(MockResponse::Ok {
        status: axum::http::StatusCode::OK,
        body: serde_json::json!({
            "id": "msg_1", "type": "message", "role": "assistant", "model": "m",
            "content": [{"type": "text", "text": "hi"}], "stop_reason": "end_turn",
            "usage": {"input_tokens": 1, "output_tokens": 1}
        }),
    });
    let server = MockServer::new(state).await;

    let (gov, store) = gov_and_store();
    let token = mint_then_expire_the_row(&gov, &store, Some(vec!["pa"]));

    let app = TestApp::new()
        .lane(LaneSpec::new("m", crate::proto::PROTO_ANTHROPIC, &server.base_url()).api_key("up"))
        .pool("pa", &[(0, 1)])
        .keys_chain()
        .governance(gov)
        .build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });

    let body = serde_json::json!({
        "model": "pa",
        "messages": [{"role": "user", "content": "hi"}],
        "max_tokens": 8
    })
    .to_string();
    let client = reqwest::Client::new();

    let admitted = client
        .post(format!("http://{addr}/pa/v1/messages"))
        .bearer_auth(&token)
        .body(body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(
        admitted.status().as_u16(),
        200,
        "a key row with a past expires_at must still be admitted (1.5.5 never enforced it)"
    );

    let refused = client
        .post(format!("http://{addr}/pa/v1/messages"))
        .bearer_auth("bbk_not_a_real_token")
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(
        refused.status().as_u16(),
        401,
        "the keys chain is a real gate on this app: a bad token is refused"
    );

    handle.abort();
    server.shutdown().await;
}
