// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! W1-K5: login state custody over CoreStore (IF §12.6), on core's in-tree store.

use std::cell::Cell;
use std::sync::Arc;

use busbar_plugin_abi::host_side::caller::{CallStack, Caller, InstanceLimits};
use busbar_plugin_abi::types::KindCode;

use super::{LoginStates, StoreLoginStates, MAX_STATE, STATE_TTL_S};
use crate::plugin_records::RecordsDenied;

const START: u64 = 1_800_000_000;

thread_local! {
    static NOW: Cell<u64> = const { Cell::new(START) };
}

fn clock() -> u64 {
    NOW.with(Cell::get)
}

fn set_now(now: u64) {
    NOW.with(|cell| cell.set(now));
}

fn auth<'a>(plugin: &'a str, name: &'a str) -> Caller<'a> {
    Caller {
        plugin,
        kind: KindCode::Auth,
        name,
        instance: 3,
        slot: 0,
        chain: 1,
        deadline: std::time::Instant::now(),
        stack: CallStack::default(),
        out_of_process: false,
        limits: InstanceLimits::default(),
    }
}

async fn states() -> StoreLoginStates {
    StoreLoginStates::with_clock(crate::real_store::core().await, clock)
}

#[tokio::test]
async fn a_key_is_32_random_bytes_in_base64url() {
    let s = states().await;
    let a = s.new_key();
    let b = s.new_key();
    assert_eq!(a.len(), 43);
    assert!(a
        .bytes()
        .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_'));
    assert_ne!(a, b);
}

#[tokio::test]
async fn a_state_is_taken_exactly_once() {
    let s = states().await;
    let who = auth("auth-oidc", "corp");
    let key = s.new_key();
    s.put(&who, &key, b"issuer|nonce").await.expect("put");
    let taken = s.take(&who, &key).await.expect("the state");
    assert_eq!(taken.as_slice(), b"issuer|nonce");
    assert!(
        s.take(&who, &key).await.is_none(),
        "a second take finds nothing"
    );
}

#[tokio::test]
async fn a_state_is_bound_to_its_auth_instance() {
    let s = states().await;
    let key = s.new_key();
    s.put(&auth("auth-oidc", "corp"), &key, b"st")
        .await
        .expect("put");
    assert!(s.take(&auth("auth-oidc", "other"), &key).await.is_none());
    assert!(s.take(&auth("auth-github", "corp"), &key).await.is_none());
    assert!(s.take(&auth("auth-oidc", "corp"), &key).await.is_some());
}

#[tokio::test]
async fn an_expired_state_is_never_answered() {
    let s = states().await;
    let who = auth("auth-oauth", "mcp");
    let key = s.new_key();
    s.put(&who, &key, b"st").await.expect("put");
    set_now(START + STATE_TTL_S);
    assert!(s.take(&who, &key).await.is_none());
}

#[tokio::test]
async fn keys_and_states_are_checked() {
    let s = states().await;
    let who = auth("auth-oidc", "corp");
    for bad in [
        "",
        "short",
        &"a".repeat(44),
        &format!("{}=", "a".repeat(42)),
    ] {
        assert_eq!(s.put(&who, bad, b"st").await, Err(RecordsDenied::Invalid));
        assert!(s.take(&who, bad).await.is_none());
    }
    let key = s.new_key();
    assert_eq!(
        s.put(&who, &key, &vec![0; MAX_STATE + 1]).await,
        Err(RecordsDenied::TooLarge)
    );
    assert!(s.take(&who, &s.new_key()).await.is_none(), "an unknown key");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_racing_callbacks_get_one_state() {
    let s = Arc::new(states().await);
    let key: Arc<str> = Arc::from(&*s.new_key());
    s.put(&auth("auth-oidc", "corp"), &key, b"st")
        .await
        .expect("put");
    let racers: Vec<_> = (0..2)
        .map(|_| {
            let (s, key) = (Arc::clone(&s), Arc::clone(&key));
            tokio::spawn(async move { s.take(&auth("auth-oidc", "corp"), &key).await.is_some() })
        })
        .collect();
    let mut won = 0;
    for racer in racers {
        if racer.await.expect("racer") {
            won += 1;
        }
    }
    assert_eq!(won, 1);
}

#[tokio::test]
async fn a_sweep_deletes_only_abandoned_states() {
    let s = states().await;
    let who = auth("auth-oidc", "corp");
    let old = s.new_key();
    s.put(&who, &old, b"abandoned").await.expect("put");
    assert_eq!(s.sweep_expired(&who).await, Ok(0));
    set_now(START + STATE_TTL_S);
    let fresh = s.new_key();
    s.put(&who, &fresh, b"fresh").await.expect("put");
    assert_eq!(s.sweep_expired(&who).await, Ok(1));
    assert_eq!(
        s.take(&who, &fresh).await.map(|v| v.as_slice().to_vec()),
        Some(b"fresh".to_vec())
    );
}

#[tokio::test]
async fn the_arc_impl_is_the_same_custody() {
    let s: Arc<dyn LoginStates> = Arc::new(states().await);
    let who = auth("auth-oidc", "corp");
    let key = s.new_key();
    s.put(&who, &key, b"st").await.expect("put");
    let shared = Arc::clone(&s);
    assert!(LoginStates::take(&shared, &who, &key).await.is_some());
}
