// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Native journal replay replaces the retired recursive part-prefix scanner.
//! Exercise complete bounded reads and fail-closed transport/record faults through
//! the actual product Store, without retaining the deleted chunk layout.
use busbar_contract::persistence::*;
use busbar_contract::Secret;
use busbar_kernel::persistence::journal::{BufferBudget, RuntimeJournal};
use busbar_kernel_wal::{Entry, RecordClass};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

const BUDGET: BufferBudget = BufferBudget {
    records: 512,
    bytes: 8 * 1024 * 1024,
};

#[derive(Clone, Copy)]
enum ReadFault {
    Healthy,
    Overloaded,
    Unavailable,
    Refused,
    Malformed,
    Missing,
}

struct ReadView {
    actual: Arc<dyn PersistenceBackend>,
    fault: ReadFault,
    enabled: AtomicBool,
    records: AtomicUsize,
}
impl PersistenceBackend for ReadView {
    fn info(&self) -> BackendInfo {
        self.actual.info()
    }
    fn clock(&self, dataset: DatasetId) -> Call<'_, ClockObservation> {
        self.actual.clock(dataset)
    }
    fn scan(&self, request: Arc<Scan>) -> Call<'_, Page> {
        self.actual.scan(request)
    }
    fn commit(&self, candidate: PreparedCandidate) -> Call<'_, Decision> {
        self.actual.commit(candidate)
    }
    fn read(&self, request: Arc<Read>) -> Call<'_, ReadResult> {
        Box::pin(async move {
            let record = self.enabled.load(Ordering::SeqCst)
                && request
                    .addresses
                    .iter()
                    .any(|at| at.key.get(24) == Some(&b'R'));
            let inject = record && self.records.fetch_add(1, Ordering::SeqCst) == 299;
            if inject {
                match self.fault {
                    ReadFault::Overloaded => return Err(Failure::Overloaded),
                    ReadFault::Unavailable => return Err(Failure::Unavailable),
                    ReadFault::Refused => return Err(Failure::Refused),
                    _ => {}
                }
            }
            let mut answer = self.actual.read(request).await?;
            if inject {
                if let ReadResult::Values { values, .. } = &mut answer {
                    match self.fault {
                        ReadFault::Malformed => values[0] = Some(Secret::new(vec![0])),
                        ReadFault::Missing => values[0] = None,
                        _ => {}
                    }
                }
            }
            Ok(answer)
        })
    }
}

async fn populated(fault: ReadFault) -> (Arc<ReadView>, Arc<RuntimeJournal>) {
    let view = Arc::new(ReadView {
        actual: crate::root::real_store::native_backend().await,
        fault,
        enabled: AtomicBool::new(false),
        records: AtomicUsize::new(0),
    });
    let core = crate::root::real_store::core_over(view.clone()).await;
    let journal = RuntimeJournal::open(core, busbar_kernel::door::op_id().counter(), BUDGET)
        .await
        .unwrap();
    for ordinal in 0u64..300 {
        let mut body = ordinal.to_be_bytes().to_vec();
        body.extend_from_slice(&vec![b'x'; 8192]);
        let run = journal
            .stage_run(&[Entry::new(RecordClass::Load, body)])
            .unwrap();
        journal.confirm(&run).await.unwrap();
    }
    view.enabled.store(true, Ordering::SeqCst);
    (view, journal)
}

#[tokio::test]
async fn native_bounded_replay_preserves_every_original_in_order() {
    let (view, journal) = populated(ReadFault::Healthy).await;
    let records = journal.read_records(BUDGET).await.unwrap();
    assert_eq!(records.len(), 300);
    assert_eq!(view.records.load(Ordering::SeqCst), 300);
    for (ordinal, record) in records.iter().enumerate() {
        assert_eq!(record.node_seq, ordinal as u64 + 1);
        assert_eq!(&record.body[..8], &(ordinal as u64).to_be_bytes());
        assert_eq!(record.body.len(), 8200);
    }
    busbar_kernel_wal::verify_journal(&records).unwrap();
    for budget in [
        BufferBudget {
            records: 299,
            ..BUDGET
        },
        BufferBudget {
            bytes: 8199,
            ..BUDGET
        },
    ] {
        assert!(
            journal.read_records(budget).await.is_err(),
            "bounded replay cannot publish a partial history as complete"
        );
    }
}

#[tokio::test]
async fn native_tail_faults_and_missing_or_malformed_originals_never_publish_a_partial_history() {
    for fault in [
        ReadFault::Overloaded,
        ReadFault::Unavailable,
        ReadFault::Refused,
        ReadFault::Malformed,
        ReadFault::Missing,
    ] {
        let (view, journal) = populated(fault).await;
        assert!(journal.read_records(BUDGET).await.is_err());
        assert_eq!(
            view.records.load(Ordering::SeqCst),
            300,
            "the last selected original is verified"
        );
        // A fresh complete read may recover; it does not reuse a failed prefix.
        let fresh = journal.read_records(BUDGET).await.unwrap();
        assert_eq!(fresh.len(), 300);
        busbar_kernel_wal::verify_journal(&fresh).unwrap();
    }
}

#[path = "store_scan_race.rs"]
mod mixed_snapshot_tests;
