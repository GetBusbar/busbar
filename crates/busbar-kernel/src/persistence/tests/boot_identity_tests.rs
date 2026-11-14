// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::persistence::host_records::tests::{attach, Backend};
use std::sync::atomic::Ordering;

#[tokio::test]
async fn verified_imported_journal_is_discoverable_without_assignment_or_lease() {
    use crate::persistence::import_target::journal as import;
    struct Original(Vec<u8>);
    impl import::IndexedFrames for Original {
        fn count(&self) -> u64 {
            1
        }
        fn frame(&mut self, ordinal: u64) -> Result<Vec<u8>, import::Error> {
            if ordinal != 1 {
                return Err(import::Error::Invalid);
            }
            Ok(self.0.clone())
        }
    }
    let body = b"original retained journal".to_vec();
    let mut original = busbar_kernel_wal::JournalRecord {
        class: busbar_kernel_wal::RecordClass::Reconciliation,
        node: 7,
        node_seq: 9,
        lease_epoch: 1,
        policy_epoch: 1,
        wall: 10,
        mono: 1,
        body_hash: busbar_kernel_wal::journal::body_digest(&body),
        body,
        prev_hash: [17; 32],
        hash: [0; 32],
    };
    original.hash = original.digest_of_chain();
    let proof = import::verify_source(
        7,
        &mut Original(original.encode()),
        import::SourceBudget {
            max_frame_bytes: 4096,
            max_reads: 4,
        },
    )
    .unwrap();
    let (address, value) = import::inventory_row(&proof).unwrap();
    assert!(import::inventory_matches(&proof, &address, &value));
    assert!(import::inventory_address_class(&address));
    for malformed in [
        b"journal:".as_slice(),
        b"journal:x",
        b"journal:\0\0\0\0\0\0\0\0",
    ] {
        let reserved =
            super::super::scoped::migration_address(true, INSTANCE, NODE_SCHEMA, malformed)
                .unwrap();
        assert!(import::inventory_address_class(&reserved));
        assert!(!import::inventory_matches(&proof, &reserved, &value));
    }
    let assignment =
        super::super::scoped::migration_address(true, INSTANCE, NODE_SCHEMA, &host_key("host"))
            .unwrap();
    assert!(!import::inventory_address_class(&assignment));
    let key = journal_inventory_key(7);
    let bytes = value.expose(&crate::seal::lend());
    assert_eq!(journal_inventory_node(&key, bytes).unwrap(), 7);
    // Every retained field, including both historical digests, participates
    // in the inventory checksum. A different stored identity is refused.
    for at in 0..bytes.len() {
        let mut altered = bytes.clone();
        altered[at] ^= 1;
        assert!(journal_inventory_node(&key, &altered).is_err());
    }
    assert!(journal_inventory_node(&journal_inventory_key(8), bytes).is_err());
    let backend = Arc::new(Backend::default());
    let core = Arc::new(attach(backend).await);
    let owner = BootIdentity::new(core).unwrap();
    assert!(owner
        .records
        .decide(
            vec![predicate(NODE_SCHEMA, key.clone(), None)],
            vec![put(NODE_SCHEMA, key.clone(), bytes.clone())]
        )
        .await
        .unwrap());
    let nodes = owner.registered().await.unwrap();
    assert_eq!(nodes, vec![("journal:0000000000000007".into(), 7)]);
    let absent = owner
        .records
        .records
        .read(&[
            (NODE_SCHEMA, &host_key("journal:0000000000000007")),
            (NODE_SCHEMA, &lease_key("journal:0000000000000007")),
            (NODE_SCHEMA, &id_key(7)),
        ])
        .await
        .unwrap();
    assert!(absent.iter().all(Option::is_none));
    let mut corrupt = bytes.clone();
    corrupt[64] ^= 1;
    assert!(owner
        .records
        .decide(
            vec![predicate(NODE_SCHEMA, key.clone(), Some(value))],
            vec![put(NODE_SCHEMA, key, corrupt)]
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
