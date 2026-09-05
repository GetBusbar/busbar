// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The store adapter: the three unit-side store seams over ONE loaded store plugin.
//!
//! Three crates bind to a store and none of them may name one — `busbar-kernel` (slices),
//! `busbar-unit-verbs` (the disaster-recovery verbs and the sealed new-verb replay cache) and
//! `busbar-unit-wal` (shipping). The composition root binds all three to a single adapter over the
//! store this crate loaded, so there is exactly one store handle in the process and exactly one
//! place that knows what the loaded plugin can and cannot do.
//!
//! # What passes through and what is shimmed
//!
//! The architecture document's store row types the trait after the PUBLISHED store protocol and
//! extends it: twelve operations are the shapes the shadow oracle already proves against the
//! released stores, and ten are additions this release invents (`append_batch`, `reserve`,
//! `release`, `heads`, `session_put`, `session_remove`, `sessions_for`, `record_put`, `record_get`,
//! `record_scan`).
//!
//! - **The published operations pass through unchanged.** They are [`busbar_api::Store`] calls on
//!   the loaded plugin, reached through [`StoreAdapter::store`] — the same handle the ledger's
//!   legacy-rows dual write uses. Nothing in this module touches their wire; the oracle's
//!   store-persist cell is what proves it (`testing/shadow-oracle/scripts/store-persist.sh`: mint,
//!   spend, kill, boot again on the same store, read the money back).
//! - **The additions are answered by a node-local shim.** Every one of them, on a store that
//!   predates them, answers from memory: never an error, never a log line, never a boot refusal, so
//!   a deployment on a published sqlite/postgres/mysql/valkey store boots and serves exactly as it
//!   did. That is the rule in the plugin-behaviour appendix, and it is consistent with the same
//!   appendix's journal rule — with no data directory the journal is memory-buffered, and durability
//!   is the legacy rows' durability.
//!
//! # Why the shim answers on every store this binary can load
//!
//! The ten additions have no request variant on any payload schema in this binary's store window
//! ([`crate::registry::supported_abi`] pins `[2, ABI_VERSION]`, and `ABI_VERSION` is 4). They gain
//! one at [`STORE_ABI_WITH_NEW_OPS`], which is above that window's top. So for every store this
//! binary can actually load — the ABI-2 published ones included — the shim IS the answer, and
//! [`StoreAdapter::speaks_new_ops`] says so out loud rather than leaving it implied. When the wire
//! lands, it lands in the shim methods below and nowhere else: the seam impls, the constructor and
//! the root's call all stay as they are.
//!
//! # The shim's semantics, stated rather than implied
//!
//! - **Slices.** A node whose store cannot hold a fleet-wide window has exactly one generation of
//!   leases and nothing that can advance it, so [`epoch`](busbar_kernel::slice::SliceStore::epoch)
//!   is constant and a reservation is granted in full, stamped with that epoch — a request carrying
//!   some other epoch is stamped, not refused, because a stale-epoch refusal would be an error and
//!   there is no fleet for it to be stale against. The grant never expires for the same reason.
//! - **The sealed replay cache.** Node-local and process-lifetime, which is exactly the durability
//!   the journal has on such a deployment. A restore does NOT clear it: dropping a committed replay
//!   slot is precisely how a credential-minting verb re-mints, which is the one thing the sealed
//!   cache exists to prevent.
//! - **Shipping.** The shim ACKNOWLEDGES and keeps nothing but a count and the last identity. It
//!   does not retain the records: the log's own memory buffer is already the record on such a
//!   deployment, and a second copy here would be an unbounded leak on a long-running node. It never
//!   fails, because a shipping failure is a durability failure and durability here is the legacy
//!   rows', not this seam's.
//! - **The migration's marker.** The record that says this deployment has already sealed its opening
//!   balances goes where every other addition goes: the node-local shim. There is nowhere else it
//!   COULD go — the rows the migration read may be on a read-only replica, and writing a marker
//!   beside somebody else's data is a migration taking ownership of a schema it does not own.
//!
//! # The migration's read, and why it is on this side of the seam
//!
//! The first boot after an upgrade seals what the previous release already holds as the ledger's
//! opening figures. Reading it is two published operations — the audit tail for the chain head, and
//! the token-ledger and metering rows for the balances — so the read lives here, where the row shapes
//! and the loaded plugin already are, and the ledger unit is handed plain figures. That is the same
//! division the ledger's dual write makes in the other direction, for the same reason: one place that
//! knows what a legacy row looks like.
//!
//! Every method of that read is a READ. There is no write-read-back probe and no watermark stamped
//! back onto the rows, because a deployment booting on a read-only replica or a grant-restricted
//! database is the previous release's supported shape and must keep booting.

use crate::DynStore;
use busbar_api::Store as AbiStore;
use busbar_api::{StoreError, UNIT_CACHE_READ, UNIT_CACHE_WRITE, UNIT_INPUT, UNIT_OUTPUT};
use busbar_caps::AdminToken;
use busbar_kernel::slice::{Epoch, SliceError, SliceGrant, SliceId, SliceRequest, SliceStore};
use busbar_unit_ledger::legacy::{LegacyHead, LegacyMigrationSource};
use busbar_unit_ledger::migration::{
    LegacyFamily, LegacyFigure, LegacyFigures, LegacyLedgerRows, MigrationError, MigrationMarker,
    MigrationRecords,
};
use busbar_unit_ledger::totals::CapDimension;
use busbar_unit_verbs::store::{Store as VerbStore, StoreError as VerbStoreError};
use busbar_unit_wal::{Record, ShipError, Shipper};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

/// The store payload schema at which the ten operations this release adds gain a wire.
///
/// The architecture document's store row calls the extended shape the store kind's native schema.
/// It is deliberately ABOVE the top of this binary's store window, which is the whole point: no
/// store this binary can load speaks these operations, so the shim answers for all of them. This is
/// the one constant to move when the wire lands.
pub const STORE_ABI_WITH_NEW_OPS: u32 = 5;

/// Does a store at this payload schema carry the ten added operations on its own wire?
///
/// Free function so the rule is testable without a loaded plugin, and so the answer is a property
/// of the schema number rather than of whichever adapter happens to be asking.
pub fn speaks_new_ops(abi_version: u32) -> bool {
    abi_version >= STORE_ABI_WITH_NEW_OPS
}

/// A snapshot of everything the node-local shim is holding.
///
/// Read-only and cheap. It exists so the root's diagnostics (and the tests) can say what the shim
/// answered without reaching into its locks, and so "the shim answered" is an observable fact rather
/// than an absence of errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ShimState {
    /// Slices reserved and not yet released.
    pub slices_outstanding: usize,
    /// Total units granted across every reservation, released or not.
    pub slices_granted: u64,
    /// Keys the sealed replay cache is holding, reserved or committed.
    pub replay_slots: usize,
    /// Of those, the ones with a committed response.
    pub replay_committed: usize,
    /// Records the shipper acknowledged.
    pub records_shipped: u64,
    /// How many times the journal chain was broken through the verb seam.
    pub chain_breaks: u64,
    /// How many restores were requested through the verb seam.
    pub restores: u64,
    /// The epoch the floor was last resealed to.
    pub epoch_floor: u64,
}

/// The three unit-side store seams over one loaded store.
///
/// Cheap to clone — every clone is the same store and the same shim — so the root can hand one
/// handle to the kernel, one to the verbs unit and one to the log without threading lifetimes.
#[derive(Clone)]
pub struct StoreAdapter {
    inner: Arc<Inner>,
}

struct Inner {
    /// The loaded store. Every published operation is a call on this and nothing else.
    store: Arc<dyn AbiStore>,
    /// The payload schema its signed manifest declares.
    abi_version: u32,
    shim: Shim,
}

/// The sealed replay cache's map: the verb's idempotency key to the committed response bytes, or
/// `None` for a slot that is reserved and not yet committed.
type ReplaySlots = HashMap<(String, String), Option<Vec<u8>>>;

/// The node-local answer for the operations the loaded store predates.
#[derive(Default)]
struct Shim {
    slices: Mutex<Slices>,
    replay: Mutex<ReplaySlots>,
    recovery: Mutex<Recovery>,
    /// Records acknowledged by the shipper. A count, not a copy — see the module preamble.
    records_shipped: AtomicU64,
    /// The migration's marker: the record that this deployment has sealed its opening balances.
    migration: Mutex<Option<MigrationMarker>>,
    /// The identity of the last record acknowledged, which is what a `heads` read would want.
    head: Mutex<Option<(u64, u64)>>,
}

#[derive(Default)]
struct Slices {
    next_id: u64,
    granted_total: u64,
    outstanding: HashMap<u64, u64>,
}

#[derive(Default)]
struct Recovery {
    chain_breaks: u64,
    restores: u64,
    last_restore: Option<String>,
    epoch_floor: u64,
}

/// The one epoch a node-local shim has. There is no fleet to advance it and nothing that could
/// observe it advancing, so it is a constant and the code says which one.
const SHIM_EPOCH: Epoch = Epoch(0);

impl StoreAdapter {
    /// Bind the three seams to `store`, whose signed manifest declares payload schema
    /// `abi_version`.
    ///
    /// **This is the constructor the composition root calls.** It takes the store the plugin
    /// registry loaded (or the in-tree memory store, which is the default when a config names none)
    /// together with the schema the registry read off the manifest — the same pair
    /// [`crate::load_store_from_bytes_at_abi`] is given, because the registry is the only caller
    /// that has read the manifest. For a store loaded by this crate, prefer
    /// [`StoreAdapter::over_loaded_store`], which reads the schema off the loaded plugin instead of
    /// asking the caller to carry it. For an in-tree store built against the current schema, use
    /// [`StoreAdapter::native`].
    ///
    /// Infallible and does no I/O: it must be constructible before the transports listen, because
    /// the first accepted connection can settle and the ledger's dual write is already holding this
    /// adapter's legacy-rows path by then.
    pub fn new(store: Arc<dyn AbiStore>, abi_version: u32) -> Self {
        StoreAdapter {
            inner: Arc::new(Inner {
                store,
                abi_version,
                shim: Shim::default(),
            }),
        }
    }

    /// [`StoreAdapter::new`] over a store this crate loaded, reading the payload schema off the
    /// loaded plugin rather than asking the caller to repeat it.
    pub fn over_loaded_store(store: DynStore) -> Self {
        let abi_version = store.abi_version;
        StoreAdapter::new(Arc::new(store), abi_version)
    }

    /// [`StoreAdapter::new`] for a store built against the CURRENT payload schema — the in-tree
    /// memory store, which is what a config that names no store gets.
    pub fn native(store: Arc<dyn AbiStore>) -> Self {
        StoreAdapter::new(store, busbar_plugin::cold::ABI_VERSION)
    }

    /// The loaded store itself, for the published operations: keys, usage, metering, audit, and the
    /// legacy cells the ledger dual-writes onto. Passes through untouched.
    pub fn store(&self) -> Arc<dyn AbiStore> {
        Arc::clone(&self.inner.store)
    }

    /// The payload schema the loaded store's manifest declares.
    pub fn abi_version(&self) -> u32 {
        self.inner.abi_version
    }

    /// Does the loaded store carry the ten added operations on its own wire, or does the shim
    /// answer them? False for every store this binary can load — see the module preamble.
    pub fn speaks_new_ops(&self) -> bool {
        speaks_new_ops(self.inner.abi_version)
    }

    /// What the node-local shim is holding.
    pub fn shim_state(&self) -> ShimState {
        let slices = self.inner.shim.slices();
        let replay = self.inner.shim.replay();
        let recovery = self.inner.shim.recovery();
        ShimState {
            slices_outstanding: slices.outstanding.len(),
            slices_granted: slices.granted_total,
            replay_slots: replay.len(),
            replay_committed: replay.values().filter(|v| v.is_some()).count(),
            records_shipped: self.inner.shim.records_shipped.load(Ordering::Relaxed),
            chain_breaks: recovery.chain_breaks,
            restores: recovery.restores,
            epoch_floor: recovery.epoch_floor,
        }
    }

    /// The identity of the last record the shipper acknowledged, or `None` if none has been.
    pub fn head(&self) -> Option<(u64, u64)> {
        *self.inner.shim.head()
    }

    /// The backup reference the last restore named, if one was asked for.
    pub fn last_restore(&self) -> Option<String> {
        self.inner.shim.recovery().last_restore.clone()
    }

    /// The kernel's slice seam.
    pub fn slice_store(&self) -> Arc<dyn SliceStore> {
        Arc::new(self.clone())
    }

    /// The verbs unit's store seam.
    pub fn verb_store(&self) -> Arc<dyn VerbStore + Send + Sync> {
        Arc::new(self.clone())
    }

    /// The log's shipping seam. Boxed by value because the log owns its shipper; every box is the
    /// same shim, so two logs shipping through one adapter share a count rather than forking one.
    pub fn shipper(&self) -> Box<dyn Shipper> {
        Box::new(self.clone())
    }

    /// The previous release's chain head: its last administrative sequence number and the hash at
    /// that point.
    ///
    /// An EMPTY head is a legitimate answer and not a failure. A store that keeps no audit rows, a
    /// store that predates the tail read and answers that it does not know the operation, and a
    /// store that simply has an empty log all read the same way — and the migration seals a zero
    /// opening balance for all three rather than refusing to boot a configuration that worked
    /// yesterday.
    pub fn legacy_audit_head(&self) -> LegacyHead {
        match self.store().list_audit_tail(1) {
            Ok(tail) => match tail.last() {
                Some(entry) => LegacyHead {
                    seq: Some(entry.seq),
                    hash: Some(entry.hash.clone()),
                    ..LegacyHead::empty()
                },
                None => LegacyHead::empty(),
            },
            Err(_) => LegacyHead::empty(),
        }
    }

    /// Read the previous release's cells: the token ledger for each named (bucket, window) and the
    /// metering rows for each named day.
    ///
    /// Reads only. A row the store would not answer for is NAMED in
    /// [`LegacyCells::unreadable`] rather than raised, because one unreadable bucket must not stop a
    /// node booting and must not vanish either.
    pub fn legacy_cells_read(&self, plan: &LegacyReadPlan) -> LegacyCells {
        let store = self.store();
        let mut cells = LegacyCells::default();
        for (bucket, window) in &plan.windows {
            match store.get_usage(bucket, *window) {
                Err(e) => cells
                    .unreadable
                    .push(format!("the token ledger for {bucket} at {window}: {e}")),
                Ok(ledger) => {
                    // An untouched (bucket, window) reads as the EMPTY ledger, and counting that as
                    // a cell read would report a migration that walked rows which were never there.
                    if ledger.requests == 0
                        && ledger.billable_requests == 0
                        && ledger.models.is_empty()
                    {
                        continue;
                    }
                    cells.cells_read += 1;
                    let mut push = |lane: &str, dimension: CapDimension, amount: u64| {
                        if amount != 0 {
                            cells.figures.push(LegacyFigure {
                                family: LegacyFamily::Window,
                                bucket: bucket.clone(),
                                window: *window,
                                lane: lane.to_string(),
                                provider: String::new(),
                                dimension,
                                amount: i128::from(amount),
                            });
                        }
                    };
                    push("", CapDimension::Requests, ledger.requests);
                    push(
                        "",
                        CapDimension::Class(BILLABLE_REQUESTS_CLASS.to_string()),
                        ledger.billable_requests,
                    );
                    for model in &ledger.models {
                        for (unit, count) in &model.usage_units {
                            push(&model.model, CapDimension::Class(unit.clone()), *count);
                        }
                    }
                    // The bucket's balance comes from the ENFORCEMENT ledger alone. The metering
                    // rows below are the observability view of the same consumption, and adding
                    // them here would report a bucket as having consumed twice what it did.
                    let total = i128::from(ledger.total_tokens());
                    match cells.balances.iter_mut().find(|(b, _)| b == bucket) {
                        Some((_, held)) => *held += total,
                        None => cells.balances.push((bucket.clone(), total)),
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
                        let mut push = |dimension: CapDimension, amount: u64| {
                            if amount != 0 {
                                cells.figures.push(LegacyFigure {
                                    family: LegacyFamily::Meter,
                                    bucket: row.key_id.clone(),
                                    window: *day,
                                    lane: row.model.clone(),
                                    provider: row.provider.clone(),
                                    dimension,
                                    amount: i128::from(amount),
                                });
                            }
                        };
                        push(CapDimension::Requests, row.requests);
                        push(
                            CapDimension::Class(BILLABLE_REQUESTS_CLASS.to_string()),
                            row.billable_requests,
                        );
                        for (unit, amount) in [
                            (UNIT_INPUT, row.tokens_input),
                            (UNIT_OUTPUT, row.tokens_output),
                            (UNIT_CACHE_READ, row.tokens_cache_read),
                            (UNIT_CACHE_WRITE, row.tokens_cache_write),
                        ] {
                            push(CapDimension::Class(unit.to_string()), amount);
                        }
                    }
                }
            }
        }
        cells
    }

    /// The plan for a deployment whose buckets are its key rows' own: every key id at `window`, plus
    /// the group buckets the caller names, plus the metering days it names.
    ///
    /// The (bucket, window) pairs cannot be discovered from the published store — a token ledger is
    /// addressed by bucket AND window and neither is enumerable — so the enumerable half comes from
    /// the key rows, which is the same place the previous release's own boot hydration gets it, and
    /// the rest is named by the caller that holds the configuration.
    ///
    /// # Errors
    ///
    /// The key rows could not be listed.
    pub fn key_bucket_plan(
        &self,
        window: u64,
        group_buckets: &[(String, u64)],
        days: &[u64],
    ) -> Result<LegacyReadPlan, StoreError> {
        let mut windows: Vec<(String, u64)> = self
            .store()
            .list_keys()?
            .into_iter()
            .map(|key| (key.id, window))
            .collect();
        windows.extend(group_buckets.iter().cloned());
        Ok(LegacyReadPlan {
            windows,
            days: days.to_vec(),
        })
    }

    /// The migration's source over this adapter's store, reading exactly `plan`.
    pub fn legacy_ledger_rows(&self, plan: LegacyReadPlan) -> LegacyStoreRows {
        LegacyStoreRows {
            adapter: self.clone(),
            plan,
            cells: std::sync::OnceLock::new(),
        }
    }

    /// The ledger's own records for the migration marker.
    pub fn migration_records(&self) -> ShimMigrationRecords {
        ShimMigrationRecords {
            adapter: self.clone(),
        }
    }

    /// The migration marker this node is holding, if it has sealed one.
    pub fn migration_marker(&self) -> Option<MigrationMarker> {
        self.inner.shim.migration().clone()
    }
}

/// The name the previous release's billable-request count takes as a meter class.
///
/// A count of billable requests is not the same balance as a count of admitted ones — the previous
/// release refunds one and never the other — so it opens as its own declared class rather than
/// being folded into the request count it is a subset of.
pub const BILLABLE_REQUESTS_CLASS: &str = "billable_requests";

/// Which of the previous release's rows the migration reads.
///
/// It is a plan rather than a scan because the published store has nothing to scan WITH: a token
/// ledger is addressed by (bucket, window) and a metering row by day, and neither key space is
/// enumerable across that seam. Naming what will be read also means the read is bounded and
/// reviewable, which a full-store walk at boot would not be.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LegacyReadPlan {
    /// The (bucket, window) pairs whose token ledger to read.
    pub windows: Vec<(String, u64)>,
    /// The metering day buckets to read.
    pub days: Vec<u64>,
}

impl LegacyReadPlan {
    /// A plan naming nothing. Reading it produces no figures, which seals a zero opening balance.
    pub fn nothing() -> Self {
        LegacyReadPlan::default()
    }

    /// Whether this plan names anything at all.
    pub fn is_empty(&self) -> bool {
        self.windows.is_empty() && self.days.is_empty()
    }
}

/// What the previous release's cells held.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LegacyCells {
    /// One figure per bucket, day, lane, provider and dimension that held anything.
    pub figures: Vec<LegacyFigure>,
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
pub struct LegacyStoreRows {
    adapter: StoreAdapter,
    plan: LegacyReadPlan,
    cells: std::sync::OnceLock<LegacyCells>,
}

impl LegacyStoreRows {
    /// What this source will read.
    pub fn plan(&self) -> &LegacyReadPlan {
        &self.plan
    }

    /// The reading, taken on first use and kept.
    pub fn cells(&self) -> &LegacyCells {
        self.cells
            .get_or_init(|| self.adapter.legacy_cells_read(&self.plan))
    }
}

impl LegacyMigrationSource for LegacyStoreRows {
    /// The chain head, with the per-bucket balances the cells hold hung off it — one object that
    /// read one store, so the head and the figures cannot disagree about what was there.
    fn read_head(&self) -> LegacyHead {
        let cells = self.cells();
        LegacyHead {
            balances: cells.balances.clone(),
            cells_read: cells.cells_read,
            ..self.adapter.legacy_audit_head()
        }
    }
}

impl LegacyLedgerRows for LegacyStoreRows {
    fn read_figures(&self) -> LegacyFigures {
        let cells = self.cells();
        LegacyFigures {
            figures: cells.figures.clone(),
            unreadable: cells.unreadable.clone(),
        }
    }
}

/// The migration marker, in the node-local shim.
///
/// The honest place for it on every store this binary can load, and labelled as one: the marker does
/// not survive a restart, so the next boot re-reads the previous release's rows and seals a
/// checkpoint with the same body hash from the same figures. What it must never do is go into the
/// rows it read — those may be read-only, and they are not this release's to write.
#[derive(Debug, Clone)]
pub struct ShimMigrationRecords {
    adapter: StoreAdapter,
}

impl MigrationRecords for ShimMigrationRecords {
    fn read_marker(&self) -> Result<Option<MigrationMarker>, MigrationError> {
        Ok(self.adapter.migration_marker())
    }

    fn write_marker(&mut self, marker: &MigrationMarker) -> Result<(), MigrationError> {
        *self.adapter.inner.shim.migration() = Some(marker.clone());
        Ok(())
    }
}

impl Shim {
    /// A poisoned shim lock is recovered from, never propagated: a panic somewhere else must not
    /// turn every later slice draw into an error, which is exactly what the appendix forbids.
    fn slices(&self) -> MutexGuard<'_, Slices> {
        self.slices.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn replay(&self) -> MutexGuard<'_, ReplaySlots> {
        self.replay.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn recovery(&self) -> MutexGuard<'_, Recovery> {
        self.recovery.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn head(&self) -> MutexGuard<'_, Option<(u64, u64)>> {
        self.head.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn migration(&self) -> MutexGuard<'_, Option<MigrationMarker>> {
        self.migration.lock().unwrap_or_else(|p| p.into_inner())
    }
}

impl SliceStore for StoreAdapter {
    /// Draw a slice. The shim grants what was asked for, in full, at its own epoch.
    ///
    /// It is not pretending to be a fleet-wide window: a node whose store cannot hold one has no
    /// fleet to share a cap with, so the bucket's own cap — enforced by the caps unit, not here —
    /// is the whole of the limit, and a slice draw against it is bookkeeping the node already did.
    fn reserve(&self, request: &SliceRequest) -> Result<SliceGrant, SliceError> {
        let mut slices = self.inner.shim.slices();
        slices.next_id += 1;
        let id = slices.next_id;
        slices.granted_total = slices.granted_total.saturating_add(request.wanted);
        slices.outstanding.insert(id, request.wanted);
        Ok(SliceGrant {
            id: SliceId(id),
            granted: request.wanted,
            // Nothing expires a lease that no other node can take, so the grant is open-ended.
            valid_until: busbar_kernel::Millis::MAX,
            // The shim's epoch, not the requested one: stamping is not refusing.
            epoch: SHIM_EPOCH,
        })
    }

    /// Give back what was not spent. An id the shim never granted (a slice drawn before a restore,
    /// say) is accepted and forgotten rather than refused.
    fn release(&self, id: SliceId, unspent: u64) -> Result<(), SliceError> {
        let mut slices = self.inner.shim.slices();
        if let Some(granted) = slices.outstanding.remove(&id.0) {
            slices.granted_total = slices.granted_total.saturating_sub(unspent.min(granted));
        }
        Ok(())
    }

    fn epoch(&self) -> Epoch {
        SHIM_EPOCH
    }
}

impl VerbStore for StoreAdapter {
    /// Break the journal chain. On a deployment whose journal is memory-buffered, the chain is the
    /// node's own, so the break is recorded here and the node's next entry starts a new one.
    fn chain_break(&self, _admin: &AdminToken) -> Result<(), VerbStoreError> {
        let mut recovery = self.inner.shim.recovery();
        recovery.chain_breaks = recovery.chain_breaks.saturating_add(1);
        Ok(())
    }

    /// Restore from a named backup. The published store keeps its own rows and restoring THEM is an
    /// operator action off the node (the store's own tooling); what this seam can do here is record
    /// that a restore was taken and reseal the node-local state that depends on it.
    ///
    /// The sealed replay cache deliberately survives — see the module preamble.
    fn store_restore(&self, _admin: &AdminToken, backup_ref: &str) -> Result<(), VerbStoreError> {
        let mut recovery = self.inner.shim.recovery();
        recovery.restores = recovery.restores.saturating_add(1);
        recovery.last_restore = Some(backup_ref.to_string());
        drop(recovery);
        let mut slices = self.inner.shim.slices();
        slices.outstanding.clear();
        Ok(())
    }

    /// Reseal the epoch floor. The shim has one epoch, so the floor becomes it.
    fn reseal_epoch_floor(&self, _admin: &AdminToken) -> Result<(), VerbStoreError> {
        let mut recovery = self.inner.shim.recovery();
        recovery.epoch_floor = SHIM_EPOCH.0;
        Ok(())
    }

    /// Read the sealed replay slot for a credential-minting verb, reserving it on first sighting so
    /// a concurrent second call sees a reservation rather than another first sighting — the same
    /// discipline the in-process cache keeps, over the node-local shim instead of durable storage.
    ///
    /// A reserved-but-uncommitted slot reads as `None`: the first caller is still in flight and has
    /// not decided what the answer is.
    fn replay_new_verb(&self, key: &(String, String)) -> Result<Option<Vec<u8>>, VerbStoreError> {
        let mut replay = self.inner.shim.replay();
        match replay.get(key) {
            Some(Some(response)) => Ok(Some(response.clone())),
            Some(None) => Ok(None),
            None => {
                replay.insert(key.clone(), None);
                Ok(None)
            }
        }
    }

    /// Commit the response bytes into the slot, so a replay returns exactly these bytes.
    fn commit_new_verb_replay(
        &self,
        key: &(String, String),
        response: &[u8],
    ) -> Result<(), VerbStoreError> {
        self.inner
            .shim
            .replay()
            .insert(key.clone(), Some(response.to_vec()));
        Ok(())
    }
}

impl Shipper for StoreAdapter {
    /// Acknowledge a batch. Always `Ok`: the store has nowhere to put it and a refusal here is a
    /// durability failure the deployment does not actually have — its durability is the legacy
    /// rows'. The records are not retained (the log's own buffer already holds them); the count and
    /// the last identity are.
    fn ship(&mut self, records: &[Record]) -> Result<(), ShipError> {
        if records.is_empty() {
            return Ok(());
        }
        self.inner
            .shim
            .records_shipped
            .fetch_add(records.len() as u64, Ordering::Relaxed);
        if let Some(last) = records.last() {
            *self.inner.shim.head() = Some(last.identity());
        }
        Ok(())
    }
}

impl std::fmt::Debug for StoreAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoreAdapter")
            .field("abi_version", &self.inner.abi_version)
            .field("speaks_new_ops", &self.speaks_new_ops())
            .field("shim", &self.shim_state())
            .finish()
    }
}
