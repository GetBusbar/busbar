// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::records::RecordStore as AbiStore;
use busbar_contract::records::{
    RecordStoreError, UNIT_CACHE_READ, UNIT_CACHE_WRITE, UNIT_INPUT, UNIT_OUTPUT,
};
use busbar_kernel_seams::migration::{
    MigrationCapDimension, MigrationFamily, MigrationFigure, MigrationFigures, MigrationHead,
    MigrationLedgerRows, MigrationSource,
};
use busbar_kernel_seams::verb_store::StoreError as VerbStoreError;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

/// A snapshot of everything the node-local shim is holding.
///
/// Read-only and cheap. It exists so the root's diagnostics (and the tests) can say what the shim
/// answered without reaching into its locks, and so "the shim answered" is an observable fact rather
/// than an absence of errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ShimState {
    /// Keys the sealed replay cache is holding, reserved or committed.
    pub replay_slots: usize,
    /// Of those, the ones with a committed response.
    pub replay_committed: usize,
}

/// The unit-side store seams over one loaded store.
///
/// Cheap to clone — every clone is the same store and the same shim — so the root can hand one
/// handle to the kernel and one to the verbs unit without threading lifetimes.
#[derive(Clone)]
pub struct StoreAdapter {
    inner: Arc<Inner>,
}

struct Inner {
    store: Arc<dyn AbiStore>,

    abi_version: u32,
    shim: Shim,

    clock: ShimClock,
}

type ReplaySlots = HashMap<(String, String), (u64, Option<Vec<u8>>)>;

pub const REPLAY_TTL_SECS: u64 = busbar_kernel_seams::verb_store::IDEMPOTENCY_TTL_SECS;

pub type ShimClock = Arc<dyn Fn() -> u64 + Send + Sync>;

fn system_clock() -> ShimClock {
    Arc::new(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    })
}

/// The node-local answer for the operations the loaded store predates.
///
/// # The lock order, stated once
///
/// The one mutex below, `replay`, is taken by every reader and writer — the diagnostics read
/// included — which copies what it wants out and drops it before doing anything else.
#[derive(Default)]
struct Shim {
    replay: Mutex<ReplaySlots>,
}

impl StoreAdapter {
    pub fn new(store: Arc<dyn AbiStore>, abi_version: u32) -> Self {
        StoreAdapter::with_clock(store, abi_version, system_clock())
    }

    pub fn with_clock(store: Arc<dyn AbiStore>, abi_version: u32, clock: ShimClock) -> Self {
        StoreAdapter {
            inner: Arc::new(Inner {
                store,
                abi_version,
                shim: Shim::default(),
                clock,
            }),
        }
    }

    pub fn native(store: Arc<dyn AbiStore>) -> Self {
        StoreAdapter::new(store, busbar_contract::abi::store::ABI_VERSION)
    }

    pub fn store(&self) -> Arc<dyn AbiStore> {
        Arc::clone(&self.inner.store)
    }

    pub fn abi_version(&self) -> u32 {
        self.inner.abi_version
    }

    pub fn shim_state(&self) -> ShimState {
        let (replay_slots, replay_committed) = {
            let replay = self.inner.shim.replay();
            (
                replay.len(),
                replay.values().filter(|(_, v)| v.is_some()).count(),
            )
        };
        ShimState {
            replay_slots,
            replay_committed,
        }
    }

    pub fn migration_audit_head(&self) -> MigrationAuditHead {
        match self.store().list_audit_tail(1) {
            Ok(tail) => MigrationAuditHead {
                head: match tail.last() {
                    Some(entry) => MigrationHead {
                        seq: Some(entry.seq),
                        hash: Some(entry.hash.clone()),
                        ..MigrationHead::empty()
                    },
                    None => MigrationHead::empty(),
                },
                unreadable: None,
            },
            Err(e) => {
                tracing::warn!(
                    reason = %e,
                    "the store would not answer for the previous release's audit tail, so the \
                     migration seals a zero opening balance over a chain whose head is unknown. \
                     If that store held audit rows, this node's chain starts again from nothing."
                );
                MigrationAuditHead {
                    head: MigrationHead::empty(),
                    unreadable: Some(format!("the previous release's audit tail: {e}")),
                }
            }
        }
    }

    pub fn migration_cells_read(&self, plan: &MigrationReadPlan) -> MigrationCells {
        let store = self.store();
        let mut cells = MigrationCells::default();

        let mut balance_at: HashMap<&str, usize> = HashMap::new();
        for (bucket, window) in &plan.windows {
            match store.get_usage(bucket, *window) {
                Err(e) => cells
                    .unreadable
                    .push(format!("the token ledger for {bucket} at {window}: {e}")),
                Ok(ledger) => {
                    if ledger.requests == 0
                        && ledger.billable_requests == 0
                        && ledger.models.is_empty()
                    {
                        continue;
                    }
                    cells.cells_read += 1;
                    let mut push = |lane: &str, dimension: MigrationCapDimension, amount: u64| {
                        if amount != 0 {
                            cells.figures.push(MigrationFigure {
                                family: MigrationFamily::Window,
                                bucket: bucket.clone(),
                                window: *window,
                                lane: lane.to_string(),
                                provider: String::new(),
                                dimension,
                                amount: i128::from(amount),
                            });
                        }
                    };
                    push("", MigrationCapDimension::Requests, ledger.requests);
                    push(
                        "",
                        MigrationCapDimension::Class(BILLABLE_REQUESTS_CLASS.to_string()),
                        ledger.billable_requests,
                    );
                    for model in &ledger.models {
                        for (unit, count) in &model.usage_units {
                            push(
                                &model.model,
                                MigrationCapDimension::Class(unit.clone()),
                                *count,
                            );
                        }
                    }

                    let total = i128::from(ledger.total_tokens());
                    match balance_at.get(bucket.as_str()) {
                        Some(at) => cells.balances[*at].1 += total,
                        None => {
                            balance_at.insert(bucket.as_str(), cells.balances.len());
                            cells.balances.push((bucket.clone(), total));
                        }
                    }
                }
            }
        }
        for day in &plan.days {
            match store.list_metering(*day) {
                Err(e) => cells
                    .unreadable
                    .push(format!("the metering rows for {day}: {e}")),
                Ok(rows) => {
                    for row in rows {
                        cells.cells_read += 1;
                        let mut push = |dimension: MigrationCapDimension, amount: u64| {
                            if amount != 0 {
                                cells.figures.push(MigrationFigure {
                                    family: MigrationFamily::Meter,
                                    bucket: row.key_id.clone(),
                                    window: *day,
                                    lane: row.model.clone(),
                                    provider: row.provider.clone(),
                                    dimension,
                                    amount: i128::from(amount),
                                });
                            }
                        };
                        push(MigrationCapDimension::Requests, row.requests);
                        push(
                            MigrationCapDimension::Class(BILLABLE_REQUESTS_CLASS.to_string()),
                            row.billable_requests,
                        );
                        for (unit, amount) in [
                            (UNIT_INPUT, row.tokens_input),
                            (UNIT_OUTPUT, row.tokens_output),
                            (UNIT_CACHE_READ, row.tokens_cache_read),
                            (UNIT_CACHE_WRITE, row.tokens_cache_write),
                        ] {
                            push(MigrationCapDimension::Class(unit.to_string()), amount);
                        }
                    }
                }
            }
        }
        cells
    }

    pub fn key_bucket_plan(
        &self,
        window: u64,
        group_buckets: &[(String, u64)],
        days: &[u64],
    ) -> Result<MigrationReadPlan, RecordStoreError> {
        let mut windows: Vec<(String, u64)> = self
            .store()
            .list_keys()?
            .into_iter()
            .map(|key| (key.id, window))
            .collect();
        windows.extend(group_buckets.iter().cloned());
        Ok(MigrationReadPlan {
            windows,
            days: days.to_vec(),
        })
    }

    pub fn migration_ledger_rows(&self, plan: MigrationReadPlan) -> MigrationStoreRows {
        MigrationStoreRows {
            adapter: self.clone(),
            plan,
            cells: std::sync::OnceLock::new(),
            audit: std::sync::OnceLock::new(),
        }
    }
}

pub const BILLABLE_REQUESTS_CLASS: &str = "billable_requests";

/// Which of the previous release's rows the migration reads.
///
/// It is a plan rather than a scan because the published store has nothing to scan WITH: a token
/// ledger is addressed by (bucket, window) and a metering row by day, and neither key space is
/// enumerable across that seam. Naming what will be read also means the read is bounded and
/// reviewable, which a full-store walk at boot would not be.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MigrationReadPlan {
    /// The (bucket, window) pairs whose token ledger to read.
    pub windows: Vec<(String, u64)>,
    /// The metering day buckets to read.
    pub days: Vec<u64>,
}

impl MigrationReadPlan {
    pub fn nothing() -> Self {
        MigrationReadPlan::default()
    }

    pub fn is_empty(&self) -> bool {
        self.windows.is_empty() && self.days.is_empty()
    }
}

/// What the previous release's chain head read as, beside the reason it could not be read.
///
/// The two travel together because the empty head has two very different meanings — "there was
/// nothing there" and "the store would not say" — and a caller handed only the head cannot tell
/// them apart. The reason joins the same named-reason channel [`MigrationCells::unreadable`] carries,
/// so one unanswered read is reported rather than either stopping a boot or vanishing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MigrationAuditHead {
    /// The head itself. Empty when the store had nothing to say AND when it would not say.
    pub head: MigrationHead,
    /// Why the head is empty, when it is empty because the store would not answer.
    pub unreadable: Option<String>,
}

/// What the previous release's cells held.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MigrationCells {
    /// One figure per bucket, day, lane, provider and dimension that held anything.
    pub figures: Vec<MigrationFigure>,
    /// The opening balance per bucket, from the enforcement ledger.
    pub balances: Vec<(String, i128)>,
    /// How many rows were read to arrive at those figures.
    pub cells_read: u64,
    /// The rows the store would not answer for, named.
    pub unreadable: Vec<String>,
}

/// The migration's source: the previous release's head and cells, over one loaded store.
///
/// Holds the adapter rather than the raw store handle so the read goes through exactly the
/// pass-through the rest of the published surface uses.
///
/// The cells are read ONCE and kept. The head and the figures are two views of one reading, and a
/// source that went back to the store for each of them would walk every named row twice on a boot
/// and — on a store being written by something else — could answer the two questions from two
/// different moments.
#[derive(Debug, Clone)]
pub struct MigrationStoreRows {
    adapter: StoreAdapter,
    plan: MigrationReadPlan,
    cells: std::sync::OnceLock<MigrationCells>,
    audit: std::sync::OnceLock<MigrationAuditHead>,
}

impl MigrationStoreRows {
    pub fn plan(&self) -> &MigrationReadPlan {
        &self.plan
    }

    pub fn cells(&self) -> &MigrationCells {
        self.cells
            .get_or_init(|| self.adapter.migration_cells_read(&self.plan))
    }

    pub fn audit_head(&self) -> &MigrationAuditHead {
        self.audit
            .get_or_init(|| self.adapter.migration_audit_head())
    }
}

impl MigrationSource for MigrationStoreRows {
    fn read_head(&self) -> MigrationHead {
        let cells = self.cells();
        MigrationHead {
            balances: cells.balances.clone(),
            cells_read: cells.cells_read,
            ..self.audit_head().head.clone()
        }
    }
}

impl MigrationLedgerRows for MigrationStoreRows {
    fn read_figures(&self) -> MigrationFigures {
        let cells = self.cells();

        let mut unreadable = cells.unreadable.clone();
        unreadable.extend(self.audit_head().unreadable.clone());
        MigrationFigures {
            figures: cells.figures.clone(),
            unreadable,
        }
    }
}

impl Shim {
    fn replay(&self) -> MutexGuard<'_, ReplaySlots> {
        self.replay.lock().unwrap_or_else(|p| p.into_inner())
    }
}

impl StoreAdapter {
    pub fn replay_new_verb(
        &self,
        key: &(String, String),
    ) -> Result<Option<Vec<u8>>, VerbStoreError> {
        let now = (self.inner.clock)();
        let mut replay = self.inner.shim.replay();
        replay.retain(|_, (written, _)| now.saturating_sub(*written) < REPLAY_TTL_SECS);
        match replay.get(key) {
            Some((_, Some(response))) => Ok(Some(response.clone())),
            Some((_, None)) => Ok(None),
            None => {
                replay.insert(key.clone(), (now, None));
                Ok(None)
            }
        }
    }

    pub fn commit_new_verb_replay(
        &self,
        key: &(String, String),
        response: &[u8],
    ) -> Result<(), VerbStoreError> {
        let now = (self.inner.clock)();
        self.inner
            .shim
            .replay()
            .insert(key.clone(), (now, Some(response.to_vec())));
        Ok(())
    }
}

impl std::fmt::Debug for StoreAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoreAdapter")
            .field("abi_version", &self.inner.abi_version)
            .field("shim", &self.shim_state())
            .finish()
    }
}

#[cfg(test)]
#[path = "tests/store_adapter_seam_tests.rs"]
mod tests;
