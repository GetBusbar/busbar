// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::persistence::record_ops::HeldOp;
pub(crate) use crate::persistence::test_backend::{attach, Backend};
use futures::FutureExt;
use std::sync::{atomic::Ordering, Mutex};

fn raw(key: &[u8]) -> Vec<u8> {
    crate::host_records::record_key("instance", key)
}
fn request(held: &HeldOp) -> conditional::Request {
    conditional::Request {
        version: conditional::VERSION,
        op_id: held.op_id(),
        predicates: vec![conditional::Predicate {
            schema: "schema".into(),
            key: raw(b"guard"),
            expected: conditional::Expected::Absent,
        }],
        mutations: vec![conditional::Mutation::Put {
            schema: "schema".into(),
            key: raw(b"guard"),
            value: vec![1],
        }],
    }
}

#[tokio::test]
async fn opaque_storage_preserves_missing_empty_large_and_host_isolation() {
    let backend = Arc::new(Backend::default());
    let store = attach(backend.clone()).await;
    let rows = HostRecords::authorized(&store, "instance", ["schema"]).unwrap();
    let host = HostRecords::host_private(&store, "instance", ["schema"]).unwrap();
    // Full owner identity keeps keys distinct even if physical namespace hashes collide.
    assert_ne!(
        rows.address("schema", &raw(b"k")).unwrap().key,
        host.address("schema", &raw(b"k")).unwrap().key
    );
    assert!(rows.get("schema", &raw(b"k")).await.unwrap().is_none());
    assert_eq!(
        rows.put("schema", &raw(b"k"), Secret::new(vec![]))
            .await
            .unwrap(),
        Outcome::Applied
    );
    assert_eq!(
        rows.get("schema", &raw(b"k")).await.unwrap().unwrap(),
        Secret::new(vec![])
    );
    assert!(host.get("schema", &raw(b"k")).await.unwrap().is_none());
    rows.put("schema", &raw(b"k"), Secret::new(vec![9; 4096]))
        .await
        .unwrap();
    assert_eq!(
        rows.get("schema", &raw(b"k")).await.unwrap().unwrap(),
        Secret::new(vec![9; 4096])
    );
    assert_eq!(
        rows.get("undeclared", &raw(b"k")).await.unwrap_err(),
        Error::Unauthorized
    );
    assert_eq!(
        rows.get("schema", &crate::host_records::record_key("other", b"k"))
            .await
            .unwrap_err(),
        Error::Unauthorized
    );
    assert_eq!(
        rows.delete("schema", &raw(b"k")).await.unwrap(),
        Outcome::Applied
    );
    assert!(rows.get("schema", &raw(b"k")).await.unwrap().is_none());
}

#[tokio::test]
async fn conditional_unknown_replays_exact_candidate_and_reconnect_receipt() {
    let backend = Arc::new(Backend::default());
    let store = attach(backend.clone()).await;
    let rows = HostRecords::authorized(&store, "instance", ["schema"]).unwrap();
    let held = store.record_op().await.unwrap();
    backend.lose_reply.store(true, Ordering::SeqCst);
    let original = request(&held);
    let Outcome::Pending(pending) = rows.conditional(&held, &original).await.unwrap() else {
        panic!("must retain unknown");
    };
    let mut changed = original.clone();
    changed.mutations = vec![conditional::Mutation::Delete {
        schema: "schema".into(),
        key: raw(b"guard"),
    }];
    assert_eq!(
        rows.conditional(&held, &changed).await.unwrap(),
        Outcome::OpIdConflict
    );
    assert_eq!(rows.retry(pending).await.unwrap(), Outcome::Applied);
    {
        let state = backend.state.lock().unwrap();
        assert_eq!(state.sent.len(), 2);
        assert_eq!(state.sent[0].fingerprint(), state.sent[1].fingerprint());
        assert!(state.sent[0].candidate().time.is_none());
    }
    let reconnected = attach(backend.clone()).await;
    let rows = HostRecords::authorized(&reconnected, "instance", ["schema"]).unwrap();
    assert_eq!(
        rows.conditional(&held, &original).await.unwrap(),
        Outcome::Applied
    );
    assert_eq!(
        rows.conditional(&held, &changed).await.unwrap(),
        Outcome::OpIdConflict
    );
    // `attach` starts `sent` after the reconnected store's generation open (86f2c543e0): the
    // receipt answers both requests without a new commit.
    assert_eq!(backend.state.lock().unwrap().sent.len(), 0);
    let private = HostRecords::host_private(&reconnected, "instance", ["schema"]).unwrap();
    assert_eq!(
        private.conditional(&held, &original).await.unwrap(),
        Outcome::OpIdConflict
    );
}

#[tokio::test]
async fn cancellation_and_same_request_retain_custody_before_crossing() {
    let backend = Arc::new(Backend::default());
    let store = attach(backend.clone()).await;
    let rows = HostRecords::authorized(&store, "instance", ["schema"]).unwrap();
    let held = store.record_op().await.unwrap();
    backend.hang.store(true, Ordering::SeqCst);
    assert!(rows
        .conditional(&held, &request(&held))
        .now_or_never()
        .is_none());
    backend.hang.store(false, Ordering::SeqCst);
    assert_eq!(
        rows.conditional(&held, &request(&held)).await.unwrap(),
        Outcome::Applied
    );
    let state = backend.state.lock().unwrap();
    assert_eq!(state.sent.len(), 2);
    assert_eq!(state.sent[0].fingerprint(), state.sent[1].fingerprint());
}

#[tokio::test]
async fn atomic_range_translation_preserves_exact_raw_key_length_and_other_schemas() {
    let backend = Arc::new(Backend::default());
    let store = attach(backend.clone()).await;
    let rows = HostRecords::authorized(&store, "instance", ["schema", "other"]).unwrap();
    let held = store.record_op().await.unwrap();
    for (schema, key) in [
        ("schema", b"ab".as_slice()),
        ("schema", b"abc"),
        ("schema", b"ac"),
        ("other", b"ab"),
    ] {
        rows.put(schema, &raw(key), Secret::new(vec![1]))
            .await
            .unwrap();
    }
    let mut conditional = request(&held);
    conditional.mutations = vec![conditional::Mutation::DeleteRange {
        schema: "schema".into(),
        prefix: raw(b"a"),
        exact_key_length: raw(b"ab").len() as u64,
    }];
    assert_eq!(
        rows.conditional(&held, &conditional).await.unwrap(),
        Outcome::Applied
    );
    assert!(rows.get("schema", &raw(b"ab")).await.unwrap().is_none());
    assert!(rows.get("schema", &raw(b"ac")).await.unwrap().is_none());
    assert!(rows.get("schema", &raw(b"abc")).await.unwrap().is_some());
    assert!(rows.get("other", &raw(b"ab")).await.unwrap().is_some());
    let state = backend.state.lock().unwrap();
    let candidate = state.sent.last().unwrap().candidate();
    let Mutation::DeleteRange {
        prefix,
        exact_key_length,
        namespace,
    } = &candidate.mutations[0]
    else {
        panic!("range must remain atomic");
    };
    let frame = keys::framed(b'R', &[&RECORDS.0, b"schema"]).unwrap();
    assert_eq!(
        *namespace,
        partition::namespace(RECORDS, &[b"schema", &raw(b"")])
    );
    assert_eq!(prefix, &[frame.as_slice(), raw(b"a").as_slice()].concat());
    assert_eq!(*exact_key_length, (frame.len() + raw(b"ab").len()) as u64);
}

#[tokio::test]
async fn scan_pages_preserve_raw_prefix_order_and_reject_stale_continuations() {
    let backend = Arc::new(Backend::default());
    let store = attach(backend.clone()).await;
    let rows = HostRecords::authorized(&store, "instance", ["schema"]).unwrap();
    for key in [b"a".as_slice(), b"aa", b"ab", b"abc"] {
        rows.put("schema", &raw(key), Secret::new(vec![1]))
            .await
            .unwrap();
    }
    let first = rows.scan("schema", &raw(b"a"), None).await.unwrap();
    assert_eq!(
        first
            .rows
            .iter()
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>(),
        vec![raw(b"a"), raw(b"aa")]
    );
    assert_eq!(first.next.as_ref().unwrap().generation, first.generation);
    let second = rows
        .scan("schema", &raw(b"a"), first.next.as_ref())
        .await
        .unwrap();
    assert_eq!(
        second
            .rows
            .iter()
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>(),
        vec![raw(b"ab"), raw(b"abc")]
    );
    assert!(second.next.is_none());
    rows.put("schema", &raw(b"az"), Secret::new(vec![1]))
        .await
        .unwrap();
    assert!(matches!(
        rows.scan("schema", &raw(b"a"), first.next.as_ref()).await,
        Err(Error::Backend(Failure::StaleScan))
    ));
}

#[tokio::test]
async fn conditional_bounds_and_scope_refuse_before_commit_and_conflicts_write_no_receipt() {
    let backend = Arc::new(Backend::default());
    let store = attach(backend.clone()).await;
    let rows = HostRecords::authorized(&store, "instance", ["schema"]).unwrap();
    let held = store.record_op().await.unwrap();
    let mut invalid = request(&held);
    invalid.mutations = vec![conditional::Mutation::Put {
        schema: "schema".into(),
        key: raw(b"guard"),
        value: vec![0; 513],
    }];
    assert_eq!(
        rows.conditional(&held, &invalid).await.unwrap_err(),
        Error::Invalid
    );
    invalid = request(&held);
    invalid.predicates[0].key = crate::host_records::record_key("other", b"guard");
    assert_eq!(
        rows.conditional(&held, &invalid).await.unwrap_err(),
        Error::Unauthorized
    );
    assert!(backend.state.lock().unwrap().sent.is_empty());
    rows.put("schema", &raw(b"guard"), Secret::new(vec![4]))
        .await
        .unwrap();
    assert_eq!(
        rows.conditional(&held, &request(&held)).await.unwrap(),
        Outcome::ConditionConflict
    );
    assert!(!backend
        .state
        .lock()
        .unwrap()
        .rows
        .keys()
        .any(|at| at.namespace
            == partition::namespace(RECORD_OPERATIONS, &[&request(&held).op_id.0[..8]]).0));
    rows.delete("schema", &raw(b"guard")).await.unwrap();
    assert_eq!(
        rows.conditional(&held, &request(&held)).await.unwrap(),
        Outcome::Applied
    );
}

#[tokio::test]
async fn conditional_accepts_512_byte_values_and_many_tiny_mutations_without_item_cap() {
    let backend = Arc::new(Backend::default());
    let store = attach(backend.clone()).await;
    let rows = HostRecords::authorized(&store, "instance", ["schema"]).unwrap();
    let held = store.record_op().await.unwrap();
    let mut request = request(&held);
    request.mutations = (0..600u32)
        .map(|n| conditional::Mutation::Put {
            schema: "schema".into(),
            key: raw(&n.to_be_bytes()),
            value: if n == 0 { vec![9; 512] } else { vec![9] },
        })
        .collect();
    assert_eq!(
        rows.conditional(&held, &request).await.unwrap(),
        Outcome::Applied
    );
    assert_eq!(
        backend.state.lock().unwrap().sent[0]
            .candidate()
            .mutations
            .len(),
        601
    );
    assert_eq!(
        rows.get("schema", &raw(&0u32.to_be_bytes()))
            .await
            .unwrap()
            .unwrap(),
        Secret::new(vec![9; 512])
    );
}

#[tokio::test]
async fn unrelated_instance_schema_and_receipt_writes_preserve_scan_generation() {
    let backend = Arc::new(Backend::default());
    let store = attach(backend.clone()).await;
    let rows = HostRecords::authorized(&store, "instance", ["schema", "other"]).unwrap();
    let other = HostRecords::authorized(&store, "other-instance", ["schema"]).unwrap();
    for key in [b"a".as_slice(), b"aa", b"ab"] {
        rows.put("schema", &raw(key), Secret::new(vec![1]))
            .await
            .unwrap();
    }
    let first = rows.scan("schema", &raw(b"a"), None).await.unwrap();
    let other_key = crate::host_records::record_key("other-instance", b"guard");
    rows.put("other", &raw(b"guard"), Secret::new(vec![2]))
        .await
        .unwrap();
    other
        .put("schema", &other_key, Secret::new(vec![3]))
        .await
        .unwrap();
    let at = rows.address("schema", &raw(b"guard")).unwrap();
    let different_schema = rows.address("other", &raw(b"guard")).unwrap();
    let different_instance = other.address("schema", &other_key).unwrap();
    assert_ne!(at.namespace, different_schema.namespace);
    assert_ne!(at.namespace, different_instance.namespace);
    assert_ne!(different_schema.namespace, different_instance.namespace);
    assert_eq!(
        at.key,
        [
            keys::framed(b'R', &[&RECORDS.0, b"schema"]).unwrap(),
            raw(b"guard")
        ]
        .concat()
    );
    // Receipts partition by generation: two mints of this store share one, a second store's
    // generation (another writer process) is a different one (DES-264 §3.1).
    let elsewhere = attach(backend.clone()).await;
    let operations = [
        store.record_op().await.unwrap(),
        elsewhere.record_op().await.unwrap(),
        store.record_op().await.unwrap(),
    ];
    for held in &operations {
        let op = held.bytes();
        let mut conditional = request(held);
        conditional.predicates[0].schema = "other".into();
        conditional.predicates[0].key = raw(&op);
        conditional.mutations = vec![conditional::Mutation::Put {
            schema: "other".into(),
            key: raw(&op),
            value: vec![op[8]],
        }];
        assert_eq!(
            rows.conditional(held, &conditional).await.unwrap(),
            Outcome::Applied
        );
    }
    let operations = operations.map(|held| held.bytes());
    let receipt_a = partition::namespace(RECORD_OPERATIONS, &[&operations[0][..8]]);
    let receipt_b = partition::namespace(RECORD_OPERATIONS, &[&operations[1][..8]]);
    assert_ne!(receipt_a, receipt_b);
    assert_eq!(
        receipt_a,
        partition::namespace(RECORD_OPERATIONS, &[&operations[2][..8]])
    );
    {
        let state = backend.state.lock().unwrap();
        for (namespace, op) in [
            (receipt_a, operations[0]),
            (receipt_b, operations[1]),
            (receipt_a, operations[2]),
        ] {
            assert!(state.rows.contains_key(&Address {
                namespace: namespace.0,
                key: keys::framed(b'R', &[&RECORD_OPERATIONS.0, &op]).unwrap(),
            }));
        }
    }
    let continued = rows
        .scan("schema", &raw(b"a"), first.next.as_ref())
        .await
        .unwrap();
    assert_eq!(continued.generation, first.generation);
    assert_eq!(continued.rows.len(), 1);
    assert_eq!(continued.rows[0].0, raw(b"ab"));
    assert!(continued.next.is_none());
}

#[tokio::test]
async fn native_scoped_transactions_keep_large_secrets_and_replay_after_reconnect() {
    use crate::persistence::scoped::{self, ScopedStore};
    let backend = Arc::new(Backend::default());
    let store = Arc::new(attach(backend.clone()).await);
    let records = ScopedStore::host_private(store, "instance", ["schema".to_string()]).unwrap();
    let value = vec![7; 2048];
    let request = scoped::Request {
        op: records.record_op().await.unwrap(),
        predicates: vec![scoped::Predicate {
            schema: "schema".into(),
            key: b"secret".to_vec(),
            expected: scoped::Expected::Absent,
        }],
        mutations: vec![scoped::Mutation::Put {
            schema: "schema".into(),
            key: b"secret".to_vec(),
            value: Secret::new(value.clone()),
        }],
    };
    backend.lose_reply.store(true, Ordering::SeqCst);
    let Outcome::Pending(id) = records.conditional_native(&request).await.unwrap() else {
        panic!("lost reply must retain original attempt")
    };
    assert_eq!(records.retry(id).await.unwrap(), Outcome::Applied);
    assert_eq!(
        records.get("schema", b"secret").await.unwrap(),
        Some(Secret::new(value))
    );
    let rebound = ScopedStore::host_private(
        Arc::new(attach(backend.clone()).await),
        "instance",
        ["schema".to_string()],
    )
    .unwrap();
    assert_eq!(
        rebound.conditional_native(&request).await.unwrap(),
        Outcome::Applied
    );
    assert_eq!(
        records.get("unlisted", b"secret").await.unwrap_err(),
        Error::Unauthorized
    );
    let wrong = ScopedStore::host_private(
        Arc::new(attach(backend.clone()).await),
        "another",
        ["schema".to_string()],
    )
    .unwrap();
    assert!(wrong.get("schema", b"secret").await.unwrap().is_none());
    assert_eq!(
        wrong.conditional_native(&request).await.unwrap(),
        Outcome::OpIdConflict
    );
}

#[tokio::test]
async fn native_write_queue_cancellation_requeues_exact_request_and_callback_after_shutdown() {
    use crate::host_records::{Owed, PendingRecords, Write, WriteBehind};
    use busbar_contract::{ids::RecordSchemaId, kinds::RecordBytes};
    let backend = Arc::new(Backend::default());
    let store = Arc::new(attach(backend.clone()).await);
    let batcher = Arc::new(WriteBehind::default());
    let pending = PendingRecords::default();
    let chains = crate::host_chains::ChainBook::default();
    let answers = Arc::new(Mutex::new(Vec::new()));
    let answered = Arc::clone(&answers);
    let instance: Arc<str> = Arc::from("instance");
    let seq = pending.enqueue(&instance, "schema", b"key", vec![8]);
    assert_eq!(
        batcher.push_native_with(|| Write {
            instance,
            schema: RecordSchemaId::new("schema"),
            key: b"key".to_vec(),
            value: RecordBytes::new(vec![8]).unwrap(),
            seq,
            owed: Owed::new(Box::new(move |result| answered
                .lock()
                .unwrap()
                .push(result))),
            chain: None
        }),
        Some(true)
    );
    backend.hang.store(true, Ordering::SeqCst);
    assert!(batcher
        .flush_native(&pending, &store, &chains)
        .now_or_never()
        .is_none());
    assert!(answers.lock().unwrap().is_empty());
    assert_eq!(pending.get("instance", "schema", b"key"), Some(vec![8]));
    assert_eq!(store.stop_admission().unwrap().len(), 1);
    backend.hang.store(false, Ordering::SeqCst);
    assert!(batcher.start());
    batcher.flush_native(&pending, &store, &chains).await;
    assert_eq!(*answers.lock().unwrap(), vec![Ok(())]);
    assert!(batcher.idle());
    assert_eq!(pending.queued(), 0);
    let state = backend.state.lock().unwrap();
    assert_eq!(state.sent.len(), 2);
    assert_eq!(state.sent[0].fingerprint(), state.sent[1].fingerprint());
}

#[tokio::test]
async fn native_chain_queue_appends_and_drops_atomically_with_legacy_framing() {
    use crate::host_records::{Owed, PendingRecords, Write, WriteBehind};
    use busbar_contract::{
        abi::plane::{RecordChain, CHAIN_PIPE_SEPARATED},
        ids::RecordSchemaId,
        kinds::RecordBytes,
    };
    let backend = Arc::new(Backend::default());
    let store = Arc::new(attach(backend.clone()).await);
    let batcher = Arc::new(WriteBehind::default());
    let pending = PendingRecords::default();
    let chains = crate::host_chains::ChainBook::default();
    let schema = RecordSchemaId::new("schema");
    let framing = crate::host_chains::ChainFraming::of(&RecordChain {
        kind: 0,
        framing: CHAIN_PIPE_SEPARATED,
        ..RecordChain::ZERO
    })
    .unwrap();
    for value in [b"first".to_vec(), b"second".to_vec(), Vec::new()] {
        let answers = Arc::new(Mutex::new(Vec::new()));
        let answered = Arc::clone(&answers);
        assert_eq!(
            batcher.push_native_with(|| Write {
                instance: Arc::from("instance"),
                schema,
                key: b"stream".to_vec(),
                value: RecordBytes::new(value).unwrap(),
                seq: 0,
                owed: Owed::new(Box::new(move |result| answered
                    .lock()
                    .unwrap()
                    .push(result))),
                chain: Some(framing)
            }),
            Some(true)
        );
        batcher.flush_native(&pending, &store, &chains).await;
        assert_eq!(*answers.lock().unwrap(), vec![Ok(())]);
    }
    let rows = HostRecords::authorized(
        &store,
        "instance",
        ["schema", crate::host_chains::CHAIN_LIFE_SCHEMA.as_str()],
    )
    .unwrap();
    assert!(rows
        .scan("schema", &raw(b"stream/"), None)
        .await
        .unwrap()
        .rows
        .is_empty());
    let life = rows
        .get(
            crate::host_chains::CHAIN_LIFE_SCHEMA.as_str(),
            &crate::host_chains::life_key("instance", schema, "stream"),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(life.expose(&crate::seal::lend()), &1u64.to_be_bytes());
    let state = backend.state.lock().unwrap();
    assert_eq!(state.sent.len(), 3);
    assert!(state
        .sent
        .last()
        .unwrap()
        .candidate()
        .mutations
        .iter()
        .any(|mutation| matches!(mutation, Mutation::DeleteRange { .. })));
}

#[tokio::test]
async fn native_host_callbacks_write_and_read_without_legacy_rows_or_blocking_pool_work() {
    use crate::host_services::{BlockingPool, InstanceFacts, KernelServices};
    use busbar_contract::{
        abi::{host::service, mechanism::KindCode},
        ids::RecordSchemaId,
        kinds::RecordBytes,
        services::{Caller, HostServices, Ran},
    };
    let backend = Arc::new(Backend::default());
    let store = Arc::new(attach(backend).await);
    let mut kernel = KernelServices::new().with_pool(Arc::new(BlockingPool::new(
        tokio::runtime::Handle::current(),
        4,
    )));
    kernel = kernel.with_persistence(store);
    kernel
        .admit(
            "instance",
            InstanceFacts {
                record_kinds: vec![RecordSchemaId::new("schema")],
                ..InstanceFacts::default()
            },
        )
        .await
        .unwrap();
    let caller = Caller::for_test(Arc::from("instance"), KindCode::Plane);
    let (sent, received) = tokio::sync::oneshot::channel();
    kernel
        .record_write(
            &caller,
            "schema",
            b"key",
            RecordBytes::new(b"value".to_vec()).unwrap(),
            Box::new(move |answer| {
                let _ = sent.send(answer);
            }),
        )
        .unwrap();
    assert_eq!(received.await.unwrap(), Ok(()));
    let (sent, received) = tokio::sync::oneshot::channel();
    assert!(matches!(
        HostServices::records_get(
            &kernel,
            &caller,
            "schema",
            b"key",
            Box::new(move |answer| {
                let _ = sent.send(answer);
            })
        ),
        Ran::Later
    ));
    let found = received.await.unwrap();
    assert_eq!(found.value, service::FOUND);
    assert_eq!(found.bytes, b"value");
}

#[tokio::test]
async fn native_ordinary_chain_continues_beyond_occupied_unreadable_tail() {
    use crate::host_records::{Owed, PendingRecords, Write, WriteBehind};
    use busbar_contract::{
        abi::plane::{RecordChain, CHAIN_PIPE_SEPARATED},
        ids::RecordSchemaId,
        kinds::RecordBytes,
    };
    let backend = Arc::new(Backend::default());
    let store = Arc::new(attach(backend).await);
    let rows = HostRecords::authorized(&store, "instance", ["schema"]).unwrap();
    let old_key = raw(&busbar_contract::services::chain_key(b"stream", 7));
    assert_eq!(
        rows.put("schema", &old_key, Secret::new(b"unreadable".to_vec()))
            .await
            .unwrap(),
        Outcome::Applied
    );
    let framing = crate::host_chains::ChainFraming::of(&RecordChain {
        kind: 0,
        framing: CHAIN_PIPE_SEPARATED,
        ..RecordChain::ZERO
    })
    .unwrap();
    let batcher = Arc::new(WriteBehind::default());
    let pending = PendingRecords::default();
    let chains = crate::host_chains::ChainBook::default();
    let answers = Arc::new(Mutex::new(Vec::new()));
    let answered = Arc::clone(&answers);
    assert_eq!(
        batcher.push_native_with(|| Write {
            instance: Arc::from("instance"),
            schema: RecordSchemaId::new("schema"),
            key: b"stream".to_vec(),
            value: RecordBytes::new(b"continues".to_vec()).unwrap(),
            seq: 0,
            owed: Owed::new(Box::new(move |result| answered
                .lock()
                .unwrap()
                .push(result))),
            chain: Some(framing)
        }),
        Some(true)
    );
    batcher.flush_native(&pending, &store, &chains).await;
    assert_eq!(*answers.lock().unwrap(), vec![Ok(())]);
    let next = rows
        .get(
            "schema",
            &raw(&busbar_contract::services::chain_key(b"stream", 8)),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        crate::host_chains::decode("stream", next.expose(&crate::seal::lend()), framing)
            .unwrap()
            .seq,
        8
    );
    assert_eq!(
        rows.get("schema", &old_key).await.unwrap(),
        Some(Secret::new(b"unreadable".to_vec()))
    );
}

#[tokio::test]
async fn native_queue_keeps_newer_put_behind_cancelled_older_attempt() {
    use crate::host_records::{Owed, PendingRecords, Write, WriteBehind};
    use busbar_contract::{ids::RecordSchemaId, kinds::RecordBytes};
    let backend = Arc::new(Backend::default());
    let store = Arc::new(attach(backend.clone()).await);
    let batcher = Arc::new(WriteBehind::default());
    let pending = PendingRecords::default();
    let chains = crate::host_chains::ChainBook::default();
    let answers = Arc::new(Mutex::new(Vec::new()));
    let make = |value: u8| {
        let answers = Arc::clone(&answers);
        let instance: Arc<str> = Arc::from("instance");
        let seq = pending.enqueue(&instance, "schema", b"key", vec![value]);
        Write {
            instance,
            schema: RecordSchemaId::new("schema"),
            key: b"key".to_vec(),
            value: RecordBytes::new(vec![value]).unwrap(),
            seq,
            owed: Owed::new(Box::new(move |result| {
                answers.lock().unwrap().push((value, result))
            })),
            chain: None,
        }
    };
    assert_eq!(batcher.push_native_with(|| make(1)), Some(true));
    backend.hang.store(true, Ordering::SeqCst);
    let mut driving = Box::pin(batcher.flush_native(&pending, &store, &chains));
    assert!(driving.as_mut().now_or_never().is_none());
    assert_eq!(batcher.push_native_with(|| make(2)), Some(false));
    drop(driving);
    backend.hang.store(false, Ordering::SeqCst);
    assert!(batcher.start());
    batcher.flush_native(&pending, &store, &chains).await;
    assert_eq!(*answers.lock().unwrap(), vec![(1, Ok(())), (2, Ok(()))]);
    let rows = HostRecords::authorized(&store, "instance", ["schema"]).unwrap();
    assert_eq!(
        rows.get("schema", &raw(b"key")).await.unwrap(),
        Some(Secret::new(vec![2]))
    );
}
