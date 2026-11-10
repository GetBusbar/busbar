// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The same core record/accounting script over two neutral planes and two independent
//! primitive store fixtures. Neither core owner receives a plane/store implementation pair.
use crate::{
    host_records_async::{AsyncHistory, HistoryOutcome},
    host_services::{InstanceFacts, KernelServices},
    persistence::facade::{CoreStore, Limits, WriterAuthority},
};
use busbar_contract::{
    abi::{
        mechanism::KindCode,
        plane::{CollectionMode, RecordCollection},
    },
    ids::RecordSchemaId,
    persistence::PersistenceBackend,
    records::{
        ModelTokensDelta, OpId, PlaneDisposition, PlaneRecord, PlaneSelector, UsageDelta,
        UsageLedger,
    },
};
use std::{collections::BTreeMap, sync::Arc};

async fn attach(backend: Arc<dyn PersistenceBackend>) -> Arc<CoreStore> {
    Arc::new(
        CoreStore::attach(
            backend,
            WriterAuthority {
                writer_epoch: 2,
                writer: [4; 16],
                execution_epoch: 3,
            },
            Limits {
                pending_operations: 64,
                conflict_retries: 2,
                scan_items: 2,
                scan_bytes: 32768,
            },
        )
        .await
        .unwrap(),
    )
}

fn facts() -> InstanceFacts {
    InstanceFacts {
        record_kinds: vec![RecordSchemaId::new("note"), RecordSchemaId::new("event")],
        record_collections: vec![
            RecordCollection {
                kind: 0,
                mode: CollectionMode::Upsert,
                parent: None,
            },
            RecordCollection {
                kind: 1,
                mode: CollectionMode::Append,
                parent: None,
            },
        ],
        ..InstanceFacts::default()
    }
}

fn record(kind: &str, id: &str, body: Vec<u8>) -> PlaneRecord {
    PlaneRecord {
        kind: kind.into(),
        id: id.into(),
        parent: None,
        seq: 0,
        ts: 100,
        disposition: PlaneDisposition::Active,
        body,
    }
}

fn usage(amount: i128) -> UsageDelta {
    UsageDelta {
        requests: 1,
        billable_requests: 1,
        models: vec![ModelTokensDelta {
            scale: 6,
            model: "neutral-unit".into(),
            usage_units: BTreeMap::from([("input".into(), amount)]),
        }],
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Transcript {
    records: Vec<Vec<PlaneRecord>>,
    usage: Vec<UsageLedger>,
}

async fn exercise(backend: Arc<dyn PersistenceBackend>) -> Transcript {
    let store = attach(backend.clone()).await;
    let host = KernelServices::new();
    assert!(host.attach_persistence(store.clone()));
    let callers = crate::host_services::caller_binding();
    let planes = ["neutral-alpha", "neutral-beta"];
    let legacy_keys: [&[u8]; 2] = [b"\x00\x0dneutral-alphan0", b"\x00\x0cneutral-betan0"];
    let mut histories = Vec::new();
    for (index, name) in planes.into_iter().enumerate() {
        let declared = facts();
        host.admit(name, declared.clone()).await.unwrap();
        let caller = callers.bind(Arc::from(name), KindCode::Plane);
        let replacement = callers.bind(Arc::from(name), KindCode::Plane);
        assert!(caller.same_incarnation(&caller.clone()));
        assert!(!caller.same_incarnation(&replacement));
        for bound in [&caller, &replacement] {
            assert_eq!(
                crate::host_records::record_key(bound.namespace(), b"n0"),
                legacy_keys[index],
                "an incarnation replacement never changes the existing durable key encoding"
            );
        }
        assert_eq!(
            host.record_kind(&caller, 0),
            Some(RecordSchemaId::new("note"))
        );
        histories.push(AsyncHistory::admitted(store.clone(), name, &declared).unwrap());
    }
    // Both planes declare the same capabilities and logical ids, but independent bytes.
    // Their differences are input data; the record/accounting owners do not branch on names.
    for (index, history) in histories.iter().enumerate() {
        let other = &histories[1 - index];
        for n in 0..5 {
            let row = record("note", &format!("n{n}"), vec![index as u8, n]);
            assert_eq!(
                history.upsert(row.view()).await.unwrap(),
                HistoryOutcome::Applied
            );
            assert_eq!(
                history.get("note", &row.id).await.unwrap(),
                Some(row.clone())
            );
            if index == 0 {
                assert_eq!(other.get("note", &row.id).await.unwrap(), None);
            } else {
                assert_eq!(
                    other.get("note", &row.id).await.unwrap().unwrap().body,
                    vec![0, n]
                );
            }
        }
        let event = record("event", "accepted", vec![index as u8, 42]);
        let operation = [10 + index as u8; 16];
        for _ in 0..2 {
            assert_eq!(
                history
                    .append_with_id(operation, event.view())
                    .await
                    .unwrap(),
                HistoryOutcome::Applied
            );
        }
        assert_eq!(
            history
                .list("event", &PlaneSelector::All)
                .await
                .unwrap()
                .len(),
            1,
            "replayed accepted work creates one business record"
        );
        let changed = record("event", "accepted", b"changed retry".to_vec());
        assert_eq!(
            history.append_with_id(operation, changed.view()).await,
            Err(crate::persistence::history::Error::Fork)
        );
        assert_eq!(
            history.list("event", &PlaneSelector::All).await.unwrap(),
            vec![event],
            "a conflicting append preserves the accepted bytes"
        );
        assert!(history.get("undeclared", "n0").await.is_err());

        let delta = usage(i128::from(i64::MAX) + 7 + index as i128);
        let op = OpId([30 + index as u8; 16]);
        let cells = [(planes[index], 100, delta.clone())];
        for _ in 0..2 {
            store
                .ledger()
                .add_usage_batch_deduped(op, &cells)
                .await
                .unwrap();
        }
        let kept = store.ledger().get_usage(planes[index], 100).await.unwrap();
        assert_eq!((kept.requests, kept.billable_requests), (1, 1));
        assert_eq!(kept.models[0].scale, 6);
        assert_eq!(
            kept.models[0].usage_units["input"],
            delta.models[0].usage_units["input"]
        );
        assert!(store
            .ledger()
            .add_usage_batch_deduped(op, &[(planes[index], 100, usage(1))])
            .await
            .is_err());
        assert_eq!(
            store.ledger().get_usage(planes[index], 100).await.unwrap(),
            kept
        );
    }

    let replacement = attach(backend).await;
    let mut transcript = Transcript {
        records: Vec::new(),
        usage: Vec::new(),
    };
    for (index, name) in planes.into_iter().enumerate() {
        let reopened = AsyncHistory::admitted(replacement.clone(), name, &facts()).unwrap();
        let before = histories[index]
            .list("note", &PlaneSelector::All)
            .await
            .unwrap();
        let after = reopened.list("note", &PlaneSelector::All).await.unwrap();
        assert_eq!(after.len(), 5, "scan spans several primitive store pages");
        assert_eq!(
            after, before,
            "namespace and bytes survive a fresh core attachment"
        );
        assert!(after.iter().all(|row| row.body[0] == index as u8));
        let delta = usage(i128::from(i64::MAX) + 7 + index as i128);
        replacement
            .ledger()
            .add_usage_batch_deduped(OpId([30 + index as u8; 16]), &[(name, 100, delta)])
            .await
            .unwrap();
        let kept = replacement.ledger().get_usage(name, 100).await.unwrap();
        assert_eq!(kept.requests, 1, "dedupe receipt survives core replacement");
        assert_eq!(kept, store.ledger().get_usage(name, 100).await.unwrap());
        transcript.records.push(after);
        transcript.usage.push(kept);
    }
    transcript
}

#[tokio::test]
async fn two_neutral_planes_by_two_independent_stores_preserve_records_and_accounting() {
    // Distinct PersistenceBackend implementations, with their own native read/scan/commit
    // and receipt state. No forwarding wrapper, product store, or per-pair integration code.
    let stores: [Arc<dyn PersistenceBackend>; 2] = [
        Arc::new(crate::persistence::host_records::tests::Backend::default()),
        Arc::new(crate::governance::persistence::prices::tests::Backend::default()),
    ];
    let mut transcripts = Vec::new();
    for backend in stores {
        transcripts.push(exercise(backend).await);
    }
    assert_eq!(transcripts[0], transcripts[1]);
}
