// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::persistence::host_records::tests::{attach, Backend};
use std::sync::atomic::Ordering;

#[tokio::test]
async fn journal_inventory_row_is_refused() {
    let key = [JOURNAL_INVENTORY_PREFIX, &7u64.to_be_bytes()].concat();
    let backend = Arc::new(Backend::default());
    let owner = BootIdentity::new(Arc::new(attach(backend).await)).unwrap();
    assert!(owner
        .records
        .decide(
            vec![predicate(NODE_SCHEMA, key.clone(), None)],
            vec![put(NODE_SCHEMA, key, b"arbitrary".to_vec())]
        )
        .await
        .unwrap());
    assert!(owner.registered().await.is_err());
}

#[tokio::test]
async fn new_holder_never_reuses_a_live_or_released_historical_node() {
    let backend = Arc::new(Backend::default());
    let core = Arc::new(attach(backend).await);
    let owner = Arc::new(BootIdentity::new(core.clone()).unwrap());
    let first = owner.take_node("host").await.unwrap();
    assert_eq!(owner.take_node("host").await.unwrap().id, first.id);
    let concurrent = Arc::new(BootIdentity::new(core.clone()).unwrap());
    let second = concurrent.take_node("host").await.unwrap();
    assert_ne!(first.id, second.id);
    assert!(second.lease.is_some());
    first.lease.as_ref().unwrap().release().await.unwrap();
    let reopened = Arc::new(BootIdentity::new(core).unwrap());
    let third = reopened.take_node("host").await.unwrap();
    assert_ne!(first.id, third.id);
    assert_ne!(second.id, third.id);
    assert!(third.lease.is_some());
    assert!(!first.lease.unwrap().refresh().await.unwrap());
    let nodes = reopened.registered().await.unwrap();
    for id in [first.id, second.id, third.id] {
        assert!(nodes.iter().any(|(_, found)| *found == id));
    }
}

#[tokio::test]
async fn renewal_changes_exact_lease_bytes_and_rejects_stale_mutation() {
    let backend = Arc::new(Backend::default());
    let owner = Arc::new(BootIdentity::new(Arc::new(attach(backend.clone()).await)).unwrap());
    let taken = owner.take_node("renewal").await.unwrap();
    let lease = taken.lease.unwrap();
    let key = lease_key("renewal");
    let before = owner.records.records.get(NODE_SCHEMA, &key).await.unwrap();
    backend.now.fetch_add(1, Ordering::SeqCst);
    assert!(lease.refresh().await.unwrap());
    let after = owner.records.records.get(NODE_SCHEMA, &key).await.unwrap();
    assert_ne!(before, after);
    assert!(!owner
        .records
        .decide(
            vec![predicate(NODE_SCHEMA, key, before)],
            vec![put(
                NODE_SCHEMA,
                b"stale-renewal-must-not-write".to_vec(),
                vec![1]
            )],
        )
        .await
        .unwrap());
    assert!(owner
        .records
        .records
        .get(NODE_SCHEMA, b"stale-renewal-must-not-write")
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn secondary_heartbeat_keeps_shared_writer_lease_after_primary_release() {
    let backend = Arc::new(Backend::default());
    let core = Arc::new(attach(backend.clone()).await);
    let primary_owner = Arc::new(BootIdentity::new(core.clone()).unwrap());
    let primary = primary_owner
        .take_node("shared")
        .await
        .unwrap()
        .lease
        .unwrap();
    let secondary_owner = Arc::new(BootIdentity::new(core.clone()).unwrap());
    let secondary = secondary_owner
        .take_node("shared")
        .await
        .unwrap()
        .lease
        .unwrap();
    let authority = core.authority().unwrap();
    let key = writer_lease_key(authority.writer_epoch, authority.writer);
    let before = secondary_owner
        .records
        .records
        .get(NODE_SCHEMA, &key)
        .await
        .unwrap()
        .unwrap();
    primary.release().await.unwrap();
    assert!(!primary.refresh().await.unwrap());
    backend.now.fetch_add(1, Ordering::SeqCst);
    assert!(secondary.refresh().await.unwrap());
    let after = secondary_owner
        .records
        .records
        .get(NODE_SCHEMA, &key)
        .await
        .unwrap()
        .unwrap();
    assert_ne!(before, after);
    let row = LeaseRow::parse(after.expose(&crate::seal::lend())).unwrap();
    assert_eq!(row.expires_ms, 20_000);
    secondary.release().await.unwrap();
    assert_eq!(
        secondary_owner
            .records
            .records
            .get(NODE_SCHEMA, &key)
            .await
            .unwrap()
            .unwrap(),
        after
    );
}

#[tokio::test]
async fn stale_lease_cannot_renew_or_release_replacement_missing_or_reassigned_owner() {
    for change in 0..4 {
        let backend = Arc::new(Backend::default());
        let owner = Arc::new(BootIdentity::new(Arc::new(attach(backend).await)).unwrap());
        let taken = owner.take_node("replaced").await.unwrap();
        let lease = taken.lease.unwrap();
        let key = lease_key("replaced");
        match change {
            0 => lease.release().await.unwrap(),
            1 => {
                assert!(owner
                    .records
                    .decide(
                        vec![],
                        vec![put(
                            NODE_SCHEMA,
                            key.clone(),
                            LeaseRow {
                                holder: [owner.holder[0].wrapping_add(1); 16],
                                expires_ms: u64::MAX
                            }
                            .bytes()
                        )]
                    )
                    .await
                    .unwrap());
            }
            2 => {
                assert!(owner
                    .records
                    .decide(
                        vec![],
                        vec![Mutation::Delete {
                            schema: NODE_SCHEMA.into(),
                            key: key.clone(),
                        }]
                    )
                    .await
                    .unwrap());
            }
            _ => {
                let authority = owner.core.authority().unwrap();
                assert!(owner
                    .records
                    .decide(
                        vec![],
                        vec![put(
                            NODE_SCHEMA,
                            host_key("replaced"),
                            Assignment {
                                id: taken.id.wrapping_add(1),
                                epoch: authority.writer_epoch,
                                writer: authority.writer
                            }
                            .bytes()
                        )]
                    )
                    .await
                    .unwrap());
            }
        }
        let before = owner.records.records.get(NODE_SCHEMA, &key).await.unwrap();
        assert!(!lease.refresh().await.unwrap(), "change {change}");
        lease.release().await.unwrap();
        assert_eq!(
            owner.records.records.get(NODE_SCHEMA, &key).await.unwrap(),
            before,
            "stale release must preserve current lease for change {change}"
        );
    }
}

#[tokio::test]
async fn cancelled_keyset_write_keeps_original_body_before_a_new_call_can_plan() {
    let backend = Arc::new(Backend::default());
    let core = Arc::new(attach(backend.clone()).await);
    let owner = BootIdentity::new(core).unwrap();
    backend.hang.store(true, Ordering::SeqCst);
    {
        let write = owner.keep_keyset("original");
        tokio::pin!(write);
        assert!(futures::poll!(&mut write).is_pending());
        assert!(owner.records.pending.lock().unwrap().is_some());
    }
    backend.hang.store(false, Ordering::SeqCst);
    assert_eq!(owner.keep_keyset("replacement").await.unwrap(), "original");
    assert!(owner.records.pending.lock().unwrap().is_none());
}

#[tokio::test]
async fn lost_keyset_acknowledgement_replays_before_publishing() {
    let backend = Arc::new(Backend::default());
    let owner = BootIdentity::new(Arc::new(attach(backend.clone()).await)).unwrap();
    backend.lose_reply.store(true, Ordering::SeqCst);
    assert_eq!(owner.keep_keyset("seed").await.unwrap(), "seed");
    assert!(!backend.lose_reply.load(Ordering::SeqCst));
    assert!(owner.records.pending.lock().unwrap().is_none());
}

fn is_deployment_id(id: &str) -> bool {
    id.strip_prefix("dep_").is_some_and(|hex| {
        hex.len() == 32 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    })
}

#[tokio::test]
async fn deployment_id_stable_across_restart() {
    let backend = Arc::new(Backend::default());
    let core = Arc::new(attach(backend).await);
    let first = BootIdentity::new(core.clone()).unwrap();
    let id = first.keep_deployment_id().await.unwrap();
    assert!(is_deployment_id(&id), "{id}");
    assert_eq!(first.keep_deployment_id().await.unwrap(), id);
    // A restarted process, and a second node, are new owners over the same Store.
    let restarted = BootIdentity::new(core).unwrap();
    assert_eq!(restarted.keep_deployment_id().await.unwrap(), id);
}

#[tokio::test]
async fn deployment_id_is_not_keyset() {
    let backend = Arc::new(Backend::default());
    let owner = BootIdentity::new(Arc::new(attach(backend).await)).unwrap();
    let seed = "ab".repeat(32);
    owner.keep_keyset(&seed).await.unwrap();
    let id = owner.keep_deployment_id().await.unwrap();
    assert!(!id.contains(&seed[..16]));
    assert_eq!(
        owner.stored_keyset().await.unwrap().as_deref(),
        Some(seed.as_str()),
        "keeping the deployment id leaves the secret keyset row alone"
    );
    let keyset_row = owner
        .records
        .records
        .get(KEYSET_SCHEMA, KEYSET_KEY)
        .await
        .unwrap();
    assert!(owner
        .records
        .records
        .get(DEPLOYMENT_SCHEMA, KEYSET_KEY)
        .await
        .unwrap()
        .is_none());
    assert!(keyset_row.is_some());
}

#[tokio::test]
async fn node_id_changes_on_new_writer() {
    let backend = Arc::new(Backend::default());
    let core = Arc::new(attach(backend).await);
    let first = Arc::new(BootIdentity::new(core.clone()).unwrap())
        .take_node("host")
        .await
        .unwrap();
    first.lease.as_ref().unwrap().release().await.unwrap();
    let second = Arc::new(BootIdentity::new(core).unwrap())
        .take_node("host")
        .await
        .unwrap();
    assert_ne!(
        first.id, second.id,
        "a new owner never inherits the node id"
    );
}

#[tokio::test]
async fn nodes_lists_every_lease() {
    let backend = Arc::new(Backend::default());
    let core = Arc::new(attach(backend.clone()).await);
    let owner = Arc::new(BootIdentity::new(core.clone()).unwrap());
    let first = owner.take_node("host").await.unwrap();
    let concurrent = Arc::new(BootIdentity::new(core.clone()).unwrap());
    let second = concurrent.take_node("host").await.unwrap();
    first.lease.as_ref().unwrap().release().await.unwrap();
    let reopened = Arc::new(BootIdentity::new(core).unwrap());
    let third = reopened.take_node("host").await.unwrap();

    let nodes = reopened.nodes().await.unwrap();
    let id = |n: u64| format!("node_{n:016x}");
    assert_eq!(nodes.len(), 3, "{nodes:?}");
    let row = |n: u64| nodes.iter().find(|r| r.node_id == id(n)).unwrap();
    assert_eq!(row(first.id).state, "stopped");
    assert_eq!(row(second.id).state, "live");
    assert_eq!(row(third.id).state, "live");
    assert_eq!(row(third.id).role, "writer");
    assert_eq!(row(first.id).role, "replica");
    assert!(nodes
        .iter()
        .all(|r| r.started_at > 0 && r.last_seen_at >= r.started_at));
    let ids: Vec<_> = nodes.iter().map(|r| r.node_id.clone()).collect();
    let mut sorted = ids.clone();
    sorted.sort();
    assert_eq!(ids.len(), sorted.len());

    // Past the lease TTL with no refresh, the nodes that did not stop are lost, not stopped.
    backend
        .now
        .fetch_add(LEASE_TTL_MS / 1_000 + 1, Ordering::SeqCst);
    let later = reopened.nodes().await.unwrap();
    let row = |n: u64| later.iter().find(|r| r.node_id == id(n)).unwrap();
    assert_eq!(row(first.id).state, "stopped");
    assert_eq!(row(second.id).state, "lost");
    assert_eq!(row(third.id).state, "lost");
}

#[tokio::test]
async fn etag_survives_restart_without_collision() {
    // ADMIN-API-1.6 6.1: a restarted process never repeats a generation the last one served,
    // so `"<deployment_id>.<config_generation>"` cannot collide across a restart.
    let backend = Arc::new(Backend::default());
    let core = Arc::new(attach(backend).await);
    let first = BootIdentity::new(core.clone()).unwrap();
    assert_eq!(first.advance_generation(0).await.unwrap(), 1);
    assert_eq!(first.advance_generation(1).await.unwrap(), 2);
    let restarted = BootIdentity::new(core).unwrap();
    // A fresh process starts its counter at zero; the stored row still wins.
    assert_eq!(restarted.advance_generation(0).await.unwrap(), 3);
}

#[tokio::test]
async fn generation_monotonic_all_sources() {
    // `max(stored, prior) + 1`: a prior ahead of the row (a node that published while the row was
    // behind) moves the row forward, and the row ahead of the prior moves the prior forward.
    let backend = Arc::new(Backend::default());
    let core = Arc::new(attach(backend).await);
    let owner = BootIdentity::new(core.clone()).unwrap();
    assert_eq!(owner.advance_generation(10).await.unwrap(), 11);
    assert_eq!(owner.advance_generation(0).await.unwrap(), 12);
    let second_node = BootIdentity::new(core).unwrap();
    assert_eq!(second_node.advance_generation(5).await.unwrap(), 13);
    assert_eq!(owner.advance_generation(13).await.unwrap(), 14);
}

#[tokio::test]
async fn generation_lost_acknowledgement_is_not_double_counted() {
    let backend = Arc::new(Backend::default());
    let owner = BootIdentity::new(Arc::new(attach(backend.clone()).await)).unwrap();
    assert_eq!(owner.advance_generation(0).await.unwrap(), 1);
    backend.lose_reply.store(true, Ordering::SeqCst);
    assert_eq!(owner.advance_generation(1).await.unwrap(), 2);
    assert_eq!(owner.advance_generation(2).await.unwrap(), 3);
}

#[tokio::test]
async fn generation_row_is_not_the_keyset_or_deployment_row() {
    let backend = Arc::new(Backend::default());
    let owner = BootIdentity::new(Arc::new(attach(backend).await)).unwrap();
    let id = owner.keep_deployment_id().await.unwrap();
    owner.advance_generation(0).await.unwrap();
    assert_eq!(owner.keep_deployment_id().await.unwrap(), id);
    let row = owner
        .records
        .records
        .get(GENERATION_SCHEMA, GENERATION_KEY)
        .await
        .unwrap()
        .expect("the generation row is kept");
    assert_eq!(
        row.expose(&crate::seal::lend()).as_slice(),
        1u64.to_be_bytes().as_slice()
    );
}
