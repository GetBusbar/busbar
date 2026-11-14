// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The LR-118 cases over a store that keeps nothing per commit (passes both) and their two
//! negative controls: a store that keeps a receipt per commit must fail the growth case, and a
//! store that sweeps 24 h old receipts by its host clock must fail the clock case.

use super::*;
use crate::persistence::{
    BackendInfo, Call, ClockObservation, DatasetId, Durability, Failure, Page, Scan,
};
use std::collections::BTreeMap;
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Keeps {
    /// Data rows only.
    Nothing,
    /// A receipt per commit, never collected.
    Receipts,
    /// A receipt per commit, swept once 24 h old by the host clock.
    SweptReceipts,
}

struct Mock {
    keeps: Keeps,
    /// The host clock this store reads, in seconds; the subject's jump moves it.
    host_secs: AtomicU64,
    rows: Mutex<BTreeMap<Address, Secret<Vec<u8>>>>,
    receipts: Mutex<Vec<u64>>,
}

impl Mock {
    fn new(keeps: Keeps) -> Arc<Self> {
        Arc::new(Self {
            keeps,
            host_secs: AtomicU64::new(1),
            rows: Mutex::new(BTreeMap::new()),
            receipts: Mutex::new(Vec::new()),
        })
    }
}

impl PersistenceBackend for Mock {
    fn info(&self) -> BackendInfo {
        BackendInfo {
            dataset: DatasetId([1; 16]),
            atomic_domain: [2; 16],
            clock_authority: [3; 16],
            physical_version: 1,
            durability: Durability::Ephemeral,
        }
    }
    fn read(&self, request: Arc<Read>) -> Call<'_, ReadResult> {
        Box::pin(async move {
            let rows = self.rows.lock().unwrap();
            Ok(ReadResult::Values {
                observed_at: ClockObservation {
                    authority: [3; 16],
                    unix_seconds: self.host_secs.load(Ordering::Relaxed),
                },
                values: request
                    .addresses
                    .iter()
                    .map(|at| rows.get(at).cloned())
                    .collect(),
            })
        })
    }
    fn scan(&self, _: Arc<Scan>) -> Call<'_, Page> {
        Box::pin(async { Err(Failure::Unavailable) })
    }
    fn commit(&self, candidate: PreparedCandidate) -> Call<'_, Decision> {
        Box::pin(async move {
            let mut rows = self.rows.lock().unwrap();
            for mutation in &candidate.candidate().mutations {
                if let Mutation::Put { address, value } = mutation {
                    rows.insert(address.clone(), value.clone());
                }
            }
            let now = self.host_secs.load(Ordering::Relaxed);
            let mut receipts = self.receipts.lock().unwrap();
            if self.keeps == Keeps::SweptReceipts {
                receipts.retain(|at| now.saturating_sub(*at) < 24 * 60 * 60);
            }
            if self.keeps != Keeps::Nothing {
                receipts.push(now);
            }
            Ok(Decision::Applied(Secret::new(Vec::new())))
        })
    }
    fn clock(&self, _: DatasetId) -> Call<'_, ClockObservation> {
        Box::pin(async {
            Ok(ClockObservation {
                authority: [3; 16],
                unix_seconds: self.host_secs.load(Ordering::Relaxed),
            })
        })
    }
}

struct Counted(Arc<Mock>);

#[async_trait::async_trait]
impl Subject for Counted {
    fn store(&self) -> Arc<dyn PersistenceBackend> {
        self.0.clone()
    }
    async fn retained(&self) -> u64 {
        let rows = self.0.rows.lock().unwrap().len();
        let receipts = self.0.receipts.lock().unwrap().len();
        u64::try_from(rows + receipts).unwrap()
    }
    async fn jump(&self, by: Duration) {
        self.0.host_secs.fetch_add(by.as_secs(), Ordering::Relaxed);
    }
}

fn fails(case: impl std::future::Future<Output = ()>) -> bool {
    std::panic::catch_unwind(AssertUnwindSafe(|| futures::executor::block_on(case))).is_err()
}

#[test]
fn a_store_keeping_nothing_per_commit_passes_both_cases() {
    futures::executor::block_on(state_does_not_grow_over_commits(&Counted(Mock::new(
        Keeps::Nothing,
    ))));
    futures::executor::block_on(nothing_changes_after_clock_jump(&Counted(Mock::new(
        Keeps::Nothing,
    ))));
}

#[test]
fn a_store_keeping_a_receipt_per_commit_fails_the_growth_case() {
    assert!(fails(state_does_not_grow_over_commits(&Counted(
        Mock::new(Keeps::Receipts)
    ))));
}

#[test]
fn a_store_sweeping_receipts_by_age_fails_the_clock_case() {
    assert!(fails(nothing_changes_after_clock_jump(&Counted(
        Mock::new(Keeps::SweptReceipts)
    ))));
}
