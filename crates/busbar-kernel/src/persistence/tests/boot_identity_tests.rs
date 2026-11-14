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
