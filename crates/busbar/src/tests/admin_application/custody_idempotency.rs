// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_core_admin::idempotency::durable::{self, Refused, Settled};
use busbar_core_admin::idempotency::{IdempotencyCache, Probe, IDEMPOTENCY_TTL_SECS};

use std::sync::Arc;

async fn durable_store() -> Arc<busbar_kernel::persistence::scoped::ScopedStore> {
    crate::root::real_store::admin_scoped().await
}

fn key(actor: &str, header: &str) -> (String, String) {
    (actor.to_string(), header.to_string())
}

#[tokio::test]
async fn create_and_rotate_claims_are_disjoint_after_cache_loss() {
    let now = busbar_kernel::store::now();

    let rotate = key("alice", "h");
    let create = key("alice", "rotate:1:x:1:h");
    for (first, second) in [(&create, &rotate), (&rotate, &create)] {
        let store = durable_store().await;
        let claim = durable::claim(store.as_ref(), first, now)
            .await
            .expect("first operation claims");
        durable::settle(
            store.as_ref(),
            &claim,
            now + 1,
            &Settled::Applied("key".into()),
        )
        .await
        .expect("first operation settles");
        assert!(
            durable::claim(store.as_ref(), second, now + 2)
                .await
                .is_ok(),
            "other operation must claim independently"
        );
        assert!(
            matches!(
                durable::claim(store.as_ref(), first, now + 2).await,
                Err(Refused::Applied(_))
            ),
            "the original operation remains protected"
        );
    }
}

#[tokio::test]
async fn an_applied_claim_is_refused_after_a_restart_not_run_again() {
    let now = busbar_kernel::store::now();
    let store = durable_store().await;
    let k = key("alice", "restart-1");
    let claim = durable::claim(store.as_ref(), &k, now)
        .await
        .expect("the first claim is granted");
    durable::settle(
        store.as_ref(),
        &claim,
        now + 1,
        &Settled::Applied("key:vk_1".into()),
    )
    .await
    .unwrap();

    let cache: IdempotencyCache<String> = IdempotencyCache::new();
    assert!(matches!(
        cache.probe(k.clone(), now + 2),
        Probe::Reserved(_)
    ));
    assert_eq!(
        durable::claim(store.as_ref(), &k, now + 2).await,
        Err(Refused::Applied("key:vk_1".into())),
    );
}

#[tokio::test]
async fn a_settled_answer_is_handed_to_the_next_claimer() {
    let now = busbar_kernel::store::now();
    let store = durable_store().await;
    let k = key("alice", "answer-1");
    let claim = durable::claim(store.as_ref(), &k, now).await.unwrap();
    durable::settle(
        store.as_ref(),
        &claim,
        now,
        &Settled::Answer(b"first".to_vec()),
    )
    .await
    .unwrap();
    assert_eq!(
        durable::claim(store.as_ref(), &k, now + 10).await,
        Err(Refused::Answer(b"first".to_vec()))
    );
}

#[tokio::test]
async fn a_released_claim_frees_the_key_for_exactly_one_retry() {
    let now = busbar_kernel::store::now();
    let store = durable_store().await;
    let k = key("alice", "released-1");
    let first = durable::claim(store.as_ref(), &k, now).await.unwrap();
    durable::settle(store.as_ref(), &first, now + 1, &Settled::Released)
        .await
        .unwrap();
    let second = durable::claim(store.as_ref(), &k, now + 2)
        .await
        .expect("a released claim frees the key");
    assert_ne!(first, second);
    assert_eq!(
        durable::claim(store.as_ref(), &k, now + 3).await,
        Err(Refused::InFlight)
    );
}

#[tokio::test]
async fn an_unsettled_claim_is_in_flight_until_it_lapses() {
    let now = busbar_kernel::store::now() - IDEMPOTENCY_TTL_SECS + 5;
    let store = durable_store().await;
    let k = key("alice", "unsettled-1");
    durable::claim(store.as_ref(), &k, now).await.unwrap();
    assert_eq!(
        durable::claim(store.as_ref(), &k, now + 1).await,
        Err(Refused::InFlight)
    );

    tokio::time::sleep(std::time::Duration::from_secs(6)).await;
    assert!(
        durable::claim(store.as_ref(), &k, now + 1 + IDEMPOTENCY_TTL_SECS)
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn claims_are_scoped_to_the_principal() {
    let now = busbar_kernel::store::now();
    let store = durable_store().await;
    durable::claim(store.as_ref(), &key("alice", "same"), now)
        .await
        .unwrap();
    assert!(durable::claim(store.as_ref(), &key("bob", "same"), now)
        .await
        .is_ok());
}

#[tokio::test]
async fn a_held_claim_never_expires_while_its_effect_or_settlement_is_unknown() {
    let now = busbar_kernel::store::now();
    let store = durable_store().await;
    let k = key("alice", "held-without-settlement");
    let first = durable::claim_held(store.as_ref(), &k, now).await.unwrap();
    let later = now + IDEMPOTENCY_TTL_SECS * 3;

    assert_eq!(
        durable::claim_held(store.as_ref(), &k, later).await,
        Err(Refused::InFlight)
    );
    let receipt = b"the exact first operation, metadata, body and 503".to_vec();
    durable::settle(
        store.as_ref(),
        &first,
        now,
        &Settled::Retained(receipt.clone()),
    )
    .await
    .unwrap();

    let other = durable::claim_held(store.as_ref(), &key("alice", "unrelated-held"), later)
        .await
        .unwrap();
    durable::settle(
        store.as_ref(),
        &other,
        later,
        &Settled::Answer(b"done".to_vec()),
    )
    .await
    .unwrap();
    assert_eq!(
        durable::claim_held(store.as_ref(), &k, later).await,
        Err(Refused::Retained(receipt))
    );
}

#[tokio::test]
async fn an_old_held_refusal_cannot_skip_a_newer_in_flight_generation() {
    let now = busbar_kernel::store::now();
    let store = durable_store().await;
    let k = key("alice", "held-released");
    let first = durable::claim_held(store.as_ref(), &k, now).await.unwrap();
    durable::settle(store.as_ref(), &first, now, &Settled::Released)
        .await
        .unwrap();
    let second = durable::claim_held(store.as_ref(), &k, now + 1)
        .await
        .unwrap();
    assert_ne!(first, second);
    assert_eq!(
        durable::claim_held(store.as_ref(), &k, now + 2).await,
        Err(Refused::InFlight)
    );
    let later = now + IDEMPOTENCY_TTL_SECS * 3;
    assert_eq!(
        durable::claim_held(store.as_ref(), &k, later).await,
        Err(Refused::InFlight)
    );
    durable::settle(
        store.as_ref(),
        &second,
        now + 1,
        &Settled::Answer(b"completed".to_vec()),
    )
    .await
    .unwrap();
    let third = durable::claim_held(store.as_ref(), &k, later)
        .await
        .unwrap();
    assert_ne!(second, third, "only a definite answer expires normally");
    assert_eq!(
        durable::claim_held(store.as_ref(), &k, later + 1).await,
        Err(Refused::InFlight)
    );
}

#[tokio::test]
async fn a_late_predecessor_settlement_cannot_replace_a_successor_receipt() {
    let now = busbar_kernel::store::now();
    let store = durable_store().await;
    let k = key("alice", "late-settlement");
    let first = durable::claim_held(store.as_ref(), &k, now).await.unwrap();
    durable::settle(store.as_ref(), &first, now, &Settled::Released)
        .await
        .unwrap();
    let second = durable::claim_held(store.as_ref(), &k, now + 1)
        .await
        .unwrap();
    let receipt = Settled::Retained(b"exact successor operation and answer".to_vec());
    durable::settle(store.as_ref(), &second, now + 1, &receipt)
        .await
        .unwrap();

    durable::settle(store.as_ref(), &first, now, &Settled::Released)
        .await
        .unwrap();
    assert_eq!(
        durable::claim_held(store.as_ref(), &k, now + 9_000).await,
        Err(Refused::Retained(
            b"exact successor operation and answer".to_vec()
        ))
    );
}

#[tokio::test]
async fn a_legacy_refusal_cannot_hide_its_pending_successor_during_migration() {
    let now = busbar_kernel::store::now();
    let store = durable_store().await;
    let k = key("alice", "legacy-pending-successor");
    let first = durable::claim(store.as_ref(), &k, now).await.unwrap();
    durable::settle(store.as_ref(), &first, now, &Settled::Released)
        .await
        .unwrap();
    let _pending = durable::claim(store.as_ref(), &k, now + 1).await.unwrap();
    assert_eq!(
        durable::claim_held(store.as_ref(), &k, now + 2).await,
        Err(Refused::InFlight)
    );
}

#[tokio::test]
async fn credential_body_binding_survives_process_cache_loss() {
    let store = durable_store().await;
    // The actual store judges spent-token expiry by its own wall clock. Backdate
    // this claim so the replay window ends shortly without advancing that clock.
    let now = busbar_kernel::store::now() - IDEMPOTENCY_TTL_SECS + 5;
    let key = key("credential-binding-actor", "create:bound-action");
    let a = busbar_contract::abi::sdk::digest::sha256(br#"{"name":"a"}"#);
    let b = busbar_contract::abi::sdk::digest::sha256(br#"{"name":"b"}"#);
    let claim = durable::claim_bound(store.as_ref(), &key, a, now)
        .await
        .unwrap()
        .unwrap();
    durable::settle(
        store.as_ref(),
        &claim,
        now,
        &Settled::Applied("key:public-id".into()),
    )
    .await
    .unwrap();
    assert!(
        matches!(durable::claim_bound(store.as_ref(), &key, a, now + 1).await, Ok(Err(Refused::Applied(resource))) if resource == "key:public-id")
    );
    for changed in [b, busbar_contract::abi::sdk::digest::sha256(b"{")] {
        assert!(durable::claim_bound(store.as_ref(), &key, changed, now + 1)
            .await
            .is_err());
    }
    let other = ("other-actor".into(), key.1.clone());
    assert!(durable::claim_bound(store.as_ref(), &other, b, now + 1)
        .await
        .unwrap()
        .is_ok());
    assert_eq!(
        durable::claim_bound(store.as_ref(), &key, b, now + IDEMPOTENCY_TTL_SECS).await,
        Ok(Err(Refused::InFlight)),
        "a caller timestamp cannot expire the store's still-live claim"
    );
    // Tokens remain live through their deadline second; cross it in real time.
    tokio::time::sleep(std::time::Duration::from_secs(6)).await;
    let after_expiry = busbar_kernel::store::now();
    assert!(after_expiry > now + IDEMPOTENCY_TTL_SECS);
    assert!(durable::claim_bound(store.as_ref(), &key, b, after_expiry)
        .await
        .unwrap()
        .is_ok());
    assert!(durable::claim_bound(store.as_ref(), &key, a, after_expiry)
        .await
        .is_err());
}
