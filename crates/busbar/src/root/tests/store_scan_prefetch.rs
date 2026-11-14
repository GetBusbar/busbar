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
    /// Refuse every read of more than one original, as a backend's per-read byte limit would.
    MultiRow,
}

/// The faulted original. Every read that asks for it is faulted, including a one-row retry.
const FAULTED: u64 = 300;

fn ordinal(at: &Address) -> Option<u64> {
    if at.key.get(24) != Some(&b'R') {
        return None;
    }
    Some(u64::from_be_bytes(at.key.get(25..33)?.try_into().ok()?))
}

struct ReadView {
    actual: Arc<dyn PersistenceBackend>,
    fault: ReadFault,
    enabled: AtomicBool,
    records: AtomicUsize,
    /// Set when a one-row read of [`FAULTED`] was faulted.
    single_faulted: AtomicBool,
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
    fn commit(
        &self,
        candidate: PreparedCandidate,
        key: busbar_contract::persistence::CommitKey,
    ) -> Call<'_, Decision> {
        self.actual.commit(candidate, key)
    }
    fn read(&self, request: Arc<Read>) -> Call<'_, ReadResult> {
        Box::pin(async move {
            // Count original-record ADDRESSES, not read calls: a replay may read several
            // consecutive originals in one call.
            let enabled = self.enabled.load(Ordering::SeqCst);
            let originals = request.addresses.iter().filter_map(ordinal).count();
            if enabled {
                self.records.fetch_add(originals, Ordering::SeqCst);
            }
            if enabled && matches!(self.fault, ReadFault::MultiRow) && originals > 1 {
                return Err(Failure::Refused);
            }
            let at = request
                .addresses
                .iter()
                .position(|at| ordinal(at) == Some(FAULTED))
                .filter(|_| enabled);
            if at.is_some() && request.addresses.len() == 1 {
                self.single_faulted.store(true, Ordering::SeqCst);
            }
            if at.is_some() {
                match self.fault {
                    ReadFault::Overloaded => return Err(Failure::Overloaded),
                    ReadFault::Unavailable => return Err(Failure::Unavailable),
                    ReadFault::Refused => return Err(Failure::Refused),
                    _ => {}
                }
            }
            let mut answer = self.actual.read(request).await?;
            if let (Some(at), ReadResult::Values { values, .. }) = (at, &mut answer) {
                match self.fault {
                    ReadFault::Malformed => values[at] = Some(Secret::new(vec![0])),
                    ReadFault::Missing => values[at] = None,
                    _ => {}
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
        single_faulted: AtomicBool::new(false),
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
        assert!(
            view.records.load(Ordering::SeqCst) >= 300,
            "the last selected original is read"
        );
        if matches!(
            fault,
            ReadFault::Overloaded | ReadFault::Unavailable | ReadFault::Refused
        ) {
            assert!(
                view.single_faulted.load(Ordering::SeqCst),
                "a failed multi-row read is retried one row at a time before the replay fails"
            );
        }
        // A fresh complete read may recover once the fault clears; it does not reuse a failed
        // prefix.
        view.enabled.store(false, Ordering::SeqCst);
        let fresh = journal.read_records(BUDGET).await.unwrap();
        assert_eq!(fresh.len(), 300);
        busbar_kernel_wal::verify_journal(&fresh).unwrap();
    }
}

#[tokio::test]
async fn native_replay_recovers_when_multi_row_reads_are_refused() {
    // A read-ahead window sized from small originals can exceed a backend's per-read limit once
    // the originals grow. The replay must fall back to one-row reads, not fail every replay.
    let (view, journal) = populated(ReadFault::MultiRow).await;
    let records = journal.read_records(BUDGET).await.unwrap();
    assert_eq!(records.len(), 300);
    for (ordinal, record) in records.iter().enumerate() {
        assert_eq!(record.node_seq, ordinal as u64 + 1);
        assert_eq!(&record.body[..8], &(ordinal as u64).to_be_bytes());
    }
    busbar_kernel_wal::verify_journal(&records).unwrap();
    assert!(view.records.load(Ordering::SeqCst) > 300);
}

#[path = "store_scan_race.rs"]
mod mixed_snapshot_tests;
