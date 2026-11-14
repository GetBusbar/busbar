// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! UPG-A27c (metering): `/admin/usage` reads only stored metering rows
//! (`GovState::metering_for_async`). With durable recovery attached, a
//! metering delta reaches the store only after its recovery Intent persists.
//! Request-path work (audit, usage, checkpoints) keeps appending to this
//! node's journal while that persist verifies its ancestry. A persist that
//! pins the exact journal head refuses whenever an append lands inside its
//! verification, so the flusher keeps the delta in memory and `/admin/usage`
//! misses the row for as long as traffic continues.
//!
//! The interposed in-memory store (the shared host-records test backend, so
//! the case needs no product inputs) lands one real journal append before
//! every read of a recovery selected-head row, as live traffic does.

use super::persistence::recovery::StoreRecovery;
use super::*;
use crate::persistence::facade::{CoreStore, Limits, WriterAuthority};
use crate::persistence::journal::runtime::{BufferBudget, RuntimeJournal};
use busbar_contract::persistence::{
    BackendInfo, Call, ClockObservation, DatasetId, Decision, Page, PersistenceBackend,
    PreparedCandidate, Read, ReadResult, Scan,
};
use busbar_kernel_wal::{Entry, RecordClass};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::OnceLock;
use std::time::Duration;

const NOW: u64 = 1_700_300_000;
const NODE: u64 = 7;
/// Key prefix of every recovery selected-head row.
const RECOVERY_HEAD: &[u8] = b"busbar.recover1\0";
/// The bounded settle window: periodic flush ticks before `/admin/usage` is read.
const SETTLE_TICKS: usize = 3;

struct Traffic {
    inner: Arc<dyn PersistenceBackend>,
    journal: OnceLock<Arc<RuntimeJournal>>,
    armed: AtomicBool,
    landed: AtomicUsize,
}
impl Traffic {
    /// One request-path append on this node's journal, from another task. It
    /// is awaited for a bounded time only, so a read issued while the journal
    /// driver is held cannot wedge; the append then lands after it.
    async fn request_path_append(&self) {
        let Some(journal) = self.journal.get().cloned() else {
            return;
        };
        let task = tokio::spawn(async move {
            let Ok(run) = journal.stage_run(&[Entry::new(
                RecordClass::Transaction,
                b"a27c metering request-path append".to_vec(),
            )]) else {
                return false;
            };
            journal.confirm(&run).await.is_ok()
        });
        if matches!(
            tokio::time::timeout(Duration::from_millis(300), task).await,
            Ok(Ok(true))
        ) {
            self.landed.fetch_add(1, Ordering::SeqCst);
        }
    }
}
impl PersistenceBackend for Traffic {
    fn info(&self) -> BackendInfo {
        self.inner.info()
    }
    fn read(&self, request: Arc<Read>) -> Call<'_, ReadResult> {
        Box::pin(async move {
            if self.armed.load(Ordering::SeqCst)
                && request
                    .addresses
                    .iter()
                    .any(|address| address.key.starts_with(RECOVERY_HEAD))
            {
                self.request_path_append().await;
            }
            self.inner.read(request).await
        })
    }
    fn scan(&self, request: Arc<Scan>) -> Call<'_, Page> {
        self.inner.scan(request)
    }
    fn clock(&self, dataset: DatasetId) -> Call<'_, ClockObservation> {
        self.inner.clock(dataset)
    }
    fn commit(
        &self,
        prepared: PreparedCandidate,
        key: busbar_contract::persistence::CommitKey,
    ) -> Call<'_, Decision> {
        self.inner.commit(prepared, key)
    }
}

async fn admin_usage_requests(gov: &GovState) -> u64 {
    gov.metering_for_async(metering_bucket(NOW))
        .await
        .unwrap()
        .iter()
        .map(|row| row.requests)
        .sum()
}

/// WHO: an operator reading `/admin/usage` on a gateway with durable recovery.
/// DOES: a metered request is stored within a bounded settle window while
/// request-path appends keep landing on the node journal during the flush.
/// WHY: 1.5.5 showed every served request in `/admin/usage` once the
/// write-behind flush ran; a recovery persist that refuses on every
/// concurrent append leaves the row in memory for as long as traffic lasts.
#[tokio::test]
async fn admin_usage_rows_land_within_settle_window_while_request_path_appends() {
    tokio::time::timeout(Duration::from_secs(60), async {
        let backend = Arc::new(Traffic {
            inner: Arc::new(crate::persistence::host_records::tests::Backend::default()),
            journal: OnceLock::new(),
            armed: AtomicBool::new(false),
            landed: AtomicUsize::new(0),
        });
        let core = Arc::new(
            CoreStore::attach(
                backend.clone(),
                WriterAuthority {
                    writer_epoch: 2,
                    writer: [4; 16],
                    execution_epoch: 3,
                },
                Limits {
                    pending_operations: 64,
                    conflict_retries: 2,
                    scan_items: 64,
                    scan_bytes: 1024 * 1024,
                },
            )
            .await
            .unwrap(),
        );
        let journal = RuntimeJournal::open(
            core.clone(),
            NODE,
            BufferBudget {
                records: 1024,
                bytes: 4 * 1024 * 1024,
            },
        )
        .await
        .unwrap();
        assert!(backend.journal.set(journal.clone()).is_ok());
        let gov = GovState::new_with_core(core, None, None).await.unwrap();
        gov.attach_recovery_sink(Arc::new(
            StoreRecovery::new(journal, crate::teller::Kernel::new().durability_token()).unwrap(),
        ))
        .await
        .unwrap();
        backend.armed.store(true, Ordering::SeqCst);
        let era = RawRateEra::legacy(123);
        gov.record_metered_request_dated(
            "a27c-key",
            "a27c-group",
            "model",
            "provider",
            MeterCounts {
                requests: 1,
                tokens_input: whole_count(3),
                ..Default::default()
            },
            NOW,
            &|| era.effective_from,
            &|_| era,
        );
        for _ in 0..SETTLE_TICKS {
            gov.flush_metering().await;
        }
        backend.armed.store(false, Ordering::SeqCst);
        assert!(
            backend.landed.load(Ordering::SeqCst) > 0,
            "request-path appends landed while the flush verified recovery"
        );
        assert_eq!(
            admin_usage_requests(&gov).await,
            1,
            "/admin/usage shows the served request within {SETTLE_TICKS} flush ticks"
        );
    })
    .await
    .expect("no hang");
}
