// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_core_admin::idempotency::durable::{self, Refused, Settled};
use busbar_core_admin::idempotency::{IdempotencyCache, Probe, IDEMPOTENCY_TTL_SECS};

use std::path::PathBuf;
use std::sync::Arc;

use busbar_plugin_loader::dispatch::kinds::store::Store;
use busbar_plugin_loader::dispatch::{
    load_dropped, rendering_of_library, Bind, ConnTable, DispatchConfig, Dispatcher, NoSink,
};
use busbar_plugin_loader::store_v3::LoadedStore;

fn durable_store() -> Arc<LoadedStore> {
    let path = PathBuf::from(
        std::env::var_os("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN").expect(
            "BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN must name the freshly built product store",
        ),
    );
    let stated = rendering_of_library(&path)
        .expect("the product store library's statement is readable")
        .expect("the product store library carries its statement");
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let plugin = load_dropped::<Store>(
        &path,
        &stated,
        Bind {
            instance: format!("governance-test-{}", busbar_kernel::door::op_id().counter()).into(),
            max_inflight_cap: 1024,
            sink: Arc::new(NoSink),
            dispatcher: dispatcher.adopter(),
            conns: ConnTable::NoNeeds,
        },
    )
    .expect("the product store loads through its actual ABI");
    let settings =
        std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".to_string());
    let _: serde_json::Value =
        serde_json::from_str(&settings).expect("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS is JSON");
    Arc::new(
        LoadedStore::open(
            plugin,
            dispatcher,
            settings.as_bytes(),
            busbar_kernel::door::op_id,
        )
        .expect("the product store opens with its supplied settings"),
    )
}

fn key(actor: &str, header: &str) -> (String, String) {
    (actor.to_string(), header.to_string())
}

#[test]
fn create_and_rotate_claims_are_disjoint_after_cache_loss() {
    // Framing belongs to core-admin's private factory tests. Here the public durable API
    // receives distinct original header inputs as data, without recreating that framing.
    let rotate = key("alice", "h");
    let create = key("alice", "rotate:1:x:1:h");
    for (first, second) in [(&create, &rotate), (&rotate, &create)] {
        let store = durable_store();
        let claim = durable::claim(store.as_ref(), first, 1_000).expect("first operation claims");
        durable::settle(
            store.as_ref(),
            &claim,
            1_001,
            &Settled::Applied("key".into()),
        )
        .expect("first operation settles");
        assert!(
            durable::claim(store.as_ref(), second, 1_002).is_ok(),
            "other operation must claim independently"
        );
        assert!(
            matches!(
                durable::claim(store.as_ref(), first, 1_002),
                Err(Refused::Applied(_))
            ),
            "the original operation remains protected"
        );
    }
}

#[test]
fn an_applied_claim_is_refused_after_a_restart_not_run_again() {
    let store = durable_store();
    let k = key("alice", "restart-1");
    let claim = durable::claim(store.as_ref(), &k, 1_000).expect("the first claim is granted");
    durable::settle(
        store.as_ref(),
        &claim,
        1_001,
        &Settled::Applied("key:vk_1".into()),
    )
    .unwrap();

    let cache: IdempotencyCache<String> = IdempotencyCache::new();
    assert!(matches!(cache.probe(k.clone(), 1_002), Probe::Reserved(_)));
    assert_eq!(
        durable::claim(store.as_ref(), &k, 1_002),
        Err(Refused::Applied("key:vk_1".into())),
    );
}

#[test]
fn a_settled_answer_is_handed_to_the_next_claimer() {
    let store = durable_store();
    let k = key("alice", "answer-1");
    let claim = durable::claim(store.as_ref(), &k, 1_000).unwrap();
    durable::settle(
        store.as_ref(),
        &claim,
        1_000,
        &Settled::Answer(b"first".to_vec()),
    )
    .unwrap();
    assert_eq!(
        durable::claim(store.as_ref(), &k, 1_010),
        Err(Refused::Answer(b"first".to_vec()))
    );
}

#[test]
fn a_released_claim_frees_the_key_for_exactly_one_retry() {
    let store = durable_store();
    let k = key("alice", "released-1");
    let first = durable::claim(store.as_ref(), &k, 1_000).unwrap();
    durable::settle(store.as_ref(), &first, 1_001, &Settled::Released).unwrap();
    let second = durable::claim(store.as_ref(), &k, 1_002).expect("a released claim frees the key");
    assert_ne!(first, second);
    assert_eq!(
        durable::claim(store.as_ref(), &k, 1_003),
        Err(Refused::InFlight)
    );
}

#[test]
fn an_unsettled_claim_is_in_flight_until_it_lapses() {
    let store = durable_store();
    let k = key("alice", "unsettled-1");
    durable::claim(store.as_ref(), &k, 1_000).unwrap();
    assert_eq!(
        durable::claim(store.as_ref(), &k, 1_001),
        Err(Refused::InFlight)
    );

    assert!(durable::claim(store.as_ref(), &k, 1_001 + IDEMPOTENCY_TTL_SECS).is_ok());
}

#[test]
fn claims_are_scoped_to_the_principal() {
    let store = durable_store();
    durable::claim(store.as_ref(), &key("alice", "same"), 1_000).unwrap();
    assert!(durable::claim(store.as_ref(), &key("bob", "same"), 1_000).is_ok());
}

#[test]
fn a_held_claim_never_expires_while_its_effect_or_settlement_is_unknown() {
    let store = durable_store();
    let k = key("alice", "held-without-settlement");
    let first = durable::claim_held(store.as_ref(), &k, 1_000).unwrap();
    let later = 1_000 + IDEMPOTENCY_TTL_SECS * 3;

    assert_eq!(
        durable::claim_held(store.as_ref(), &k, later),
        Err(Refused::InFlight)
    );
    let receipt = b"the exact first operation, metadata, body and 503".to_vec();
    durable::settle(
        store.as_ref(),
        &first,
        1_000,
        &Settled::Retained(receipt.clone()),
    )
    .unwrap();

    let other =
        durable::claim_held(store.as_ref(), &key("alice", "unrelated-held"), later).unwrap();
    durable::settle(
        store.as_ref(),
        &other,
        later,
        &Settled::Answer(b"done".to_vec()),
    )
    .unwrap();
    assert_eq!(
        durable::claim_held(store.as_ref(), &k, later),
        Err(Refused::Retained(receipt))
    );
}

#[test]
fn an_old_held_refusal_cannot_skip_a_newer_in_flight_generation() {
    let store = durable_store();
    let k = key("alice", "held-released");
    let first = durable::claim_held(store.as_ref(), &k, 1_000).unwrap();
    durable::settle(store.as_ref(), &first, 1_000, &Settled::Released).unwrap();
    let second = durable::claim_held(store.as_ref(), &k, 1_001).unwrap();
    assert_ne!(first, second);
    assert_eq!(
        durable::claim_held(store.as_ref(), &k, 1_002),
        Err(Refused::InFlight)
    );
    let later = 1_000 + IDEMPOTENCY_TTL_SECS * 3;
    assert_eq!(
        durable::claim_held(store.as_ref(), &k, later),
        Err(Refused::InFlight)
    );
    durable::settle(
        store.as_ref(),
        &second,
        1_001,
        &Settled::Answer(b"completed".to_vec()),
    )
    .unwrap();
    let third = durable::claim_held(store.as_ref(), &k, later).unwrap();
    assert_ne!(second, third, "only a definite answer expires normally");
    assert_eq!(
        durable::claim_held(store.as_ref(), &k, later + 1),
        Err(Refused::InFlight)
    );
}

#[test]
fn a_late_predecessor_settlement_cannot_replace_a_successor_receipt() {
    let store = durable_store();
    let k = key("alice", "late-settlement");
    let first = durable::claim_held(store.as_ref(), &k, 1_000).unwrap();
    durable::settle(store.as_ref(), &first, 1_000, &Settled::Released).unwrap();
    let second = durable::claim_held(store.as_ref(), &k, 1_001).unwrap();
    let receipt = Settled::Retained(b"exact successor operation and answer".to_vec());
    durable::settle(store.as_ref(), &second, 1_001, &receipt).unwrap();

    durable::settle(store.as_ref(), &first, 1_000, &Settled::Released).unwrap();
    assert_eq!(
        durable::claim_held(store.as_ref(), &k, 10_000),
        Err(Refused::Retained(
            b"exact successor operation and answer".to_vec()
        ))
    );
}

#[test]
fn a_legacy_refusal_cannot_hide_its_pending_successor_during_migration() {
    let store = durable_store();
    let k = key("alice", "legacy-pending-successor");
    let first = durable::claim(store.as_ref(), &k, 1_000).unwrap();
    durable::settle(store.as_ref(), &first, 1_000, &Settled::Released).unwrap();
    let _pending = durable::claim(store.as_ref(), &k, 1_001).unwrap();
    assert_eq!(
        durable::claim_held(store.as_ref(), &k, 1_002),
        Err(Refused::InFlight)
    );
}
