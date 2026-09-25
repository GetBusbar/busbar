// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! CROSS-PLANE `expires_at` DATA-PLANE ADMISSION TEST, relocated here from
//! `src/tests/key_expires_at_tests.rs` (the "fix the 38" pass after the A6/HostCtx
//! dev-dependency-cycle cleanup): it builds a real `TestApp` with a lane/pool and drives a REAL HTTP
//! round trip through `build_router`, which only routes `/pa/v1/messages` to the pool `pa` through
//! the REAL `busbar_llm` plane's `build_runtime`/`viewer` — same reason as `endpoints_cross_plane.rs`
//! (see its header). What this test asserts (a key row's `expires_at` is unenforced; the token's own
//! `exp` IS) is core's own governance/auth behaviour, not anything about the LLM dialect — the real
//! plane is present only so the request has somewhere to route.
//!
//! `a_key_row_whose_expires_at_is_in_the_past_still_verifies` (the governance-seam half, no
//! `TestApp`/router involved) names no plane and stays in `src/tests/key_expires_at_tests.rs`.

mod linked;

use busbar_kernel::governance::signing::{TokenSigner, DEFAULT_KID};
use busbar_kernel::governance::{GovState, MemoryStore, NewKeySpec, Store};
use busbar_kernel::test_support::{LaneSpec, MockResponse, MockServer, MockServerState, TestApp};
use std::sync::Arc;

fn register_planes() {
    linked::install();
}

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

/// End to end on the data plane through the `keys` chain: the request is admitted (200 from the
/// mock upstream) with the row's `expires_at` in the past, while a wrong token is still refused
/// (401) on the same app — so the admission is a real gate, not an open chain.
#[tokio::test]
async fn a_key_row_whose_expires_at_is_in_the_past_is_admitted_on_the_data_plane() {
    register_planes();
    busbar_kernel::metrics::init();
    // Force the protocol registry's core-test built-in tail to seed BEFORE `TestApp::build()` banks
    // `AppSlots` off `busbar_kernel::proto::known_protocols()`. Any registry accessor seeds it
    // (idempotent, process-wide), and ordinarily some earlier test in the same binary already has by
    // the time this one runs — but filtered down to just this test there is no earlier caller, so
    // `known_protocols()` is empty at bank time and grows later on the request path, and `AppSlots`
    // (sized off the empty snapshot) then indexes out of bounds. Not this test's bug to fix twice;
    // seeding here up front is what every real request path does implicitly by the time it reads the
    // registry at all.
    let _ = busbar_kernel::proto::decl_for(busbar_kernel::proto::PROTO_ANTHROPIC);
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

    // This request goes through a REAL HTTP round trip and the `keys` engine arm checks the
    // token's own `exp` against the process's REAL wall clock (`busbar_kernel::store::now()`), not an
    // injected one — so, unlike the seam test in `src/tests/key_expires_at_tests.rs`, the token here
    // must be minted relative to the actual current time, not a frozen constant (which would already
    // be expired by wall-clock time and get refused for the token's own `exp`, not for anything to
    // do with the row's `expires_at`).
    let real_now = busbar_kernel::store::now();
    let real_token_exp = real_now + 3_600;
    let real_row_expired_at = real_now - 30 * 86_400;

    let (gov, store) = gov_and_store();
    let token = mint_then_expire_the_row(
        &gov,
        &store,
        Some(vec!["pa"]),
        real_now,
        real_token_exp,
        real_row_expired_at,
    );

    let app = TestApp::new()
        .lane(
            LaneSpec::new(
                "m",
                busbar_kernel::proto::PROTO_ANTHROPIC,
                &server.base_url(),
            )
            .api_key("up"),
        )
        .pool("pa", &[(0, 1)])
        .keys_chain()
        .governance(gov)
        .build();
    let router = busbar_kernel::build_router(app);
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
    // Measured on the published 1.5.5 AND on HEAD's release binary (shadow-oracle script cell
    // key-expired-out-of-band.sh, sqlite store edited between two boots): both answer 200. A
    // stored expires_at is never enforced on the data plane; only the token's own exp is.
    assert_eq!(
        admitted.status().as_u16(),
        200,
        "a key row with a past expires_at is still admitted (1.5.5 never enforced it; measured)"
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
