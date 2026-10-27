// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The store adapter: the unit-side store seams over ONE loaded store plugin.
//!
//! Two crates bind to a store and neither may name one — `busbar-kernel` (slices) and the admin
//! verb-execution unit (the sealed new-verb replay cache, which the composition root's
//! `busbar_contract::verb_store::Store` answers through this adapter). The composition root binds
//! both to a single adapter over the store this crate loaded, so there is exactly one store handle
//! in the process and one place that says what this adapter answers itself.
//!
//! The disaster-recovery verbs are not here. They act on the node's journal and on the store's
//! record slots, both of which the composition root holds (`durability::recovery`), and nothing
//! about them is kept in this adapter's memory.
//!
//! # The journal is not here
//!
//! The node's journal is kept by the configured store through its store v3 record slots
//! (`record_put` / `record_get` / `record_scan`), written by the composition root's own bounded
//! lane and read back at boot (the root's `durability::store_chain`). This adapter used to stand in
//! as the journal's shipper and acknowledge every batch while keeping only a count, which is how a
//! node with no data directory lost its whole chain on every restart. That shim is gone: nothing
//! here acknowledges a record a store did not take.
//!
//! # What passes through and what this adapter answers itself
//!
//! - **The published operations pass through unchanged.** They are
//!   [`busbar_contract::records::RecordStore`] calls on the loaded plugin, reached through
//!   [`StoreAdapter::store`] — the same handle the ledger's legacy-rows dual write uses. Nothing in
//!   this module touches their wire; the oracle's store-persist cell is what proves it
//!   (`testing/shadow-oracle/scripts/store-persist.sh`: mint, spend, kill, boot again on the same
//!   store, read the money back).
//! - **Slices and the sealed replay cache are answered from this node's
//!   memory.** The store v3 table carries slots for the ledger operations behind them (`reserve`,
//!   `slice_release`, `heads`, `append_batch`), and every store this binary loads speaks store ABI
//!   v3, which has no table without them; routing these seams to those slots is separate work, and
//!   until it lands what is said below is what they answer.
//!
//! # Those answers, stated rather than implied
//!
//! - **Slices.** A node whose slices are answered here has exactly one generation of leases and
//!   nothing that can advance it, so [`epoch`](busbar_contract::slice::SliceStore::epoch) is
//!   constant and a reservation is granted in full, stamped with that epoch — a request carrying
//!   some other epoch is stamped, not refused, because a stale-epoch refusal would be an error and
//!   there is no fleet for it to be stale against. The grant never expires for the same reason.
//! - **The sealed replay cache.** Node-local. Nothing but its TTL clears it — no restore and no
//!   other verb: dropping a committed replay slot is precisely how a credential-minting verb
//!   re-mints, which is the one thing the sealed cache exists to prevent. It is not
//!   process-lifetime, though: a slot answers for [`REPLAY_TTL_SECS`] — the same window the
//!   in-process sibling keeps — and is swept after, or the map would grow forever with every minted
//!   response the node ever served. It does not survive a restart.
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

use busbar_contract::migration::{
    LegacyCapDimension, LegacyFamily, LegacyFigure, LegacyFigures, LegacyHead, LegacyLedgerRows,
    LegacyMigrationSource,
};
use busbar_contract::records::RecordStore as AbiStore;
use busbar_contract::records::{
    RecordStoreError, UNIT_CACHE_READ, UNIT_CACHE_WRITE, UNIT_INPUT, UNIT_OUTPUT,
};
use busbar_contract::slice::{Epoch, SliceError, SliceGrant, SliceId, SliceRequest, SliceStore};
use busbar_contract::verb_store::StoreError as VerbStoreError;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

/// A snapshot of everything the node-local shim is holding.
///
/// Read-only and cheap. It exists so the root's diagnostics (and the tests) can say what the shim
/// answered without reaching into its locks, and so "the shim answered" is an observable fact rather
/// than an absence of errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ShimState {
    /// Slices reserved and not yet released.
    pub slices_outstanding: usize,
    /// Units granted and NOT given back — granted minus the unspent part every `release` returned.
    /// A net figure, not a running total: it describes what the outstanding reservations above are
    /// holding.
    pub slices_granted: u64,
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
    /// The loaded store. Every published operation is a call on this and nothing else.
    store: Arc<dyn AbiStore>,
    /// The payload schema its signed manifest declares.
    abi_version: u32,
    shim: Shim,
    /// What the sealed replay cache ages its slots against.
    clock: ShimClock,
}

/// The sealed replay cache's map: the verb's idempotency key to the moment the slot was written and
/// the committed response bytes, or `None` for a slot that is reserved and not yet committed.
///
/// The moment is held beside the slot because the seam this shim answers for names a TTL, and a map
/// with no TTL is not a cache — it is a leak that grows with every credential-minting verb the node
/// ever serves, and it holds each minted response for the life of the process.
type ReplaySlots = HashMap<(String, String), (u64, Option<Vec<u8>>)>;

/// How long a sealed replay slot answers for, in seconds.
///
/// The seam's own contract names the window, and the in-process sibling
/// [`busbar_contract::verb_store::IDEMPOTENCY_TTL_SECS`] keeps exactly this one — so a deployment whose store predates
/// the durable cache gets the same replay window it would get from the store, rather than a
/// different one because the shim is answering.
pub const REPLAY_TTL_SECS: u64 = busbar_contract::verb_store::IDEMPOTENCY_TTL_SECS;

/// The clock the sealed replay cache ages its slots against, in unix seconds.
///
/// Injected rather than read where it is needed: the sweep is the whole of the cache's bound, and a
/// bound that can only be observed by waiting ten minutes is a bound nothing checks.
pub type ShimClock = Arc<dyn Fn() -> u64 + Send + Sync>;

/// The wall clock, for an adapter whose caller did not name one.
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
/// The three mutexes below are independent, and every one of them is on the request path: a slice
/// draw takes `slices` on every reserve and release. No thread holds two at once: every reader and
/// writer — the diagnostics read included — takes one lock, copies what it wants out, drops it,
/// and only then takes the next. A thread that ever needs more than one takes them in the order
/// they are declared here — slices, then replay — and in no other order.
#[derive(Default)]
struct Shim {
    slices: Mutex<Slices>,
    replay: Mutex<ReplaySlots>,
}

#[derive(Default)]
struct Slices {
    next_id: u64,
    granted_total: u64,
    outstanding: HashMap<u64, u64>,
}

/// The one epoch a node-local shim has. There is no fleet to advance it and nothing that could
/// observe it advancing, so it is a constant and the code says which one.
const SHIM_EPOCH: Epoch = Epoch(0);

impl StoreAdapter {
    /// Bind the seams to `store`, whose signed manifest declares payload schema `abi_version`.
    ///
    /// **This is the constructor the composition root calls.** It takes the store the plugin
    /// registry loaded (or the in-tree memory store, which is the default when a config names none)
    /// together with the schema the registry read off the manifest. For an in-tree store built
    /// against the current schema, use [`StoreAdapter::native`].
    ///
    /// Infallible and does no I/O: it must be constructible before the transports listen, because
    /// the first accepted connection can settle and the ledger's dual write is already holding this
    /// adapter's legacy-rows path by then.
    pub fn new(store: Arc<dyn AbiStore>, abi_version: u32) -> Self {
        StoreAdapter::with_clock(store, abi_version, system_clock())
    }

    /// [`StoreAdapter::new`] against a named clock. The composition root has no reason to name one;
    /// anything that must watch the sealed replay cache age its slots does, because the alternative
    /// is waiting out the TTL in real time.
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

    /// [`StoreAdapter::new`] for a store built against the CURRENT payload schema — the in-tree
    /// memory store, which is what a config that names no store gets.
    pub fn native(store: Arc<dyn AbiStore>) -> Self {
        StoreAdapter::new(store, busbar_contract::abi::store::ABI_VERSION)
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

    /// What the node-local shim is holding.
    ///
    /// One lock at a time, each taken, copied out and dropped before the next — see the lock order
    /// on [`Shim`]. This is a diagnostics read on a path every slice draw also walks.
    ///
    /// What that costs is that the two groups below are read at two instants rather than one, so a
    /// caller reading while the shim is being written can see one group's figures beside a slightly
    /// older other group's. Each group is still internally whole — the two slice figures come out
    /// under one guard, and so do the two replay ones — which is what the figures actually have to
    /// promise.
    pub fn shim_state(&self) -> ShimState {
        let (slices_outstanding, slices_granted) = {
            let slices = self.inner.shim.slices();
            (slices.outstanding.len(), slices.granted_total)
        };
        let (replay_slots, replay_committed) = {
            let replay = self.inner.shim.replay();
            (
                replay.len(),
                replay.values().filter(|(_, v)| v.is_some()).count(),
            )
        };
        ShimState {
            slices_outstanding,
            slices_granted,
            replay_slots,
            replay_committed,
        }
    }

    /// The previous release's chain head: its last administrative sequence number and the hash at
    /// that point.
    ///
    /// An EMPTY head is a legitimate answer and not a failure. A store that keeps no audit rows, a
    /// store that predates the tail read and answers that it does not know the operation, and a
    /// store that simply has an empty log all read the same way — and the migration seals a zero
    /// opening balance for all three rather than refusing to boot a configuration that worked
    /// yesterday.
    ///
    /// A store that FAILED to answer said none of those things. It is empty here too, because a
    /// node whose store is briefly unreachable must still boot, but the reason travels with the
    /// answer and is said out loud: a migration that seals a zero opening balance over a chain that
    /// was really there has broken the chain, and the one thing it may not do is break it quietly.
    pub fn legacy_audit_head(&self) -> LegacyAuditHead {
        match self.store().list_audit_tail(1) {
            Ok(tail) => LegacyAuditHead {
                head: match tail.last() {
                    Some(entry) => LegacyHead {
                        seq: Some(entry.seq),
                        hash: Some(entry.hash.clone()),
                        ..LegacyHead::empty()
                    },
                    None => LegacyHead::empty(),
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
                LegacyAuditHead {
                    head: LegacyHead::empty(),
                    unreadable: Some(format!("the previous release's audit tail: {e}")),
                }
            }
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
        // Where each bucket's balance already sits in `cells.balances`. The vector's ORDER is the
        // plan's order and stays that way — this index only replaces the scan that found the slot,
        // which grew with the square of a deployment's virtual-key count on the one read that runs
        // before the node serves anything.
        let mut balance_at: HashMap<&str, usize> = HashMap::new();
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
                    let mut push = |lane: &str, dimension: LegacyCapDimension, amount: u64| {
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
                    push("", LegacyCapDimension::Requests, ledger.requests);
                    push(
                        "",
                        LegacyCapDimension::Class(BILLABLE_REQUESTS_CLASS.to_string()),
                        ledger.billable_requests,
                    );
                    for model in &ledger.models {
                        for (unit, count) in &model.usage_units {
                            push(
                                &model.model,
                                LegacyCapDimension::Class(unit.clone()),
                                *count,
                            );
                        }
                    }
                    // The bucket's balance comes from the ENFORCEMENT ledger alone. The metering
                    // rows below are the observability view of the same consumption, and adding
                    // them here would report a bucket as having consumed twice what it did.
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
                        let mut push = |dimension: LegacyCapDimension, amount: u64| {
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
                        push(LegacyCapDimension::Requests, row.requests);
                        push(
                            LegacyCapDimension::Class(BILLABLE_REQUESTS_CLASS.to_string()),
                            row.billable_requests,
                        );
                        for (unit, amount) in [
                            (UNIT_INPUT, row.tokens_input),
                            (UNIT_OUTPUT, row.tokens_output),
                            (UNIT_CACHE_READ, row.tokens_cache_read),
                            (UNIT_CACHE_WRITE, row.tokens_cache_write),
                        ] {
                            push(LegacyCapDimension::Class(unit.to_string()), amount);
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
    ) -> Result<LegacyReadPlan, RecordStoreError> {
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
            audit: std::sync::OnceLock::new(),
        }
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

/// What the previous release's chain head read as, beside the reason it could not be read.
///
/// The two travel together because the empty head has two very different meanings — "there was
/// nothing there" and "the store would not say" — and a caller handed only the head cannot tell
/// them apart. The reason joins the same named-reason channel [`LegacyCells::unreadable`] carries,
/// so one unanswered read is reported rather than either stopping a boot or vanishing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LegacyAuditHead {
    /// The head itself. Empty when the store had nothing to say AND when it would not say.
    pub head: LegacyHead,
    /// Why the head is empty, when it is empty because the store would not answer.
    pub unreadable: Option<String>,
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
    audit: std::sync::OnceLock<LegacyAuditHead>,
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

    /// The chain head, taken on first use and kept — for the same reason the cells are: the head a
    /// caller reads and the reason it reports must describe one reading of one store.
    pub fn audit_head(&self) -> &LegacyAuditHead {
        self.audit.get_or_init(|| self.adapter.legacy_audit_head())
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
            ..self.audit_head().head.clone()
        }
    }
}

impl LegacyLedgerRows for LegacyStoreRows {
    fn read_figures(&self) -> LegacyFigures {
        let cells = self.cells();
        // An unread chain head joins the unread cells on the one channel the migration report
        // already prints, so "the store would not say" reaches an operator whichever read it was.
        let mut unreadable = cells.unreadable.clone();
        unreadable.extend(self.audit_head().unreadable.clone());
        LegacyFigures {
            figures: cells.figures.clone(),
            unreadable,
        }
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
            valid_until: busbar_contract::Millis::MAX,
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

/// THE ONE RECOVERY-STATE READ the disaster-recovery verbs take from this adapter: the slice epoch
/// this node serves at, which `reseal_epoch_floor` puts in the store as the floor and the boot
/// compares with the floor the store holds. It is the door the root reads it through, so the
/// money-slice seam stays named only here and in its defining module.
impl StoreAdapter {
    /// This node's slice epoch, as a number: the value the epoch floor is resealed to and checked
    /// against.
    #[must_use]
    pub fn recovery_epoch(&self) -> u64 {
        SliceStore::epoch(self).0
    }
}

/// THE SEALED NEW-VERB REPLAY CACHE, which the composition root's verb store answers through this
/// adapter (`busbar_contract::verb_store::Store::replay_new_verb` and `commit_new_verb_replay`).
impl StoreAdapter {
    /// Read the sealed replay slot for a credential-minting verb, reserving it on first sighting so
    /// a concurrent second call sees a reservation rather than another first sighting — the same
    /// discipline the in-process cache keeps, over the node-local shim instead of durable storage.
    ///
    /// A reserved-but-uncommitted slot reads as `None`: the first caller is still in flight and has
    /// not decided what the answer is.
    ///
    /// Every probe first drops the slots past [`REPLAY_TTL_SECS`], which is what bounds the cache:
    /// the only other thing that ever touches it is a commit, so a sweep anywhere else would leave
    /// the map growing on exactly the traffic that fills it. The in-process sibling sweeps here too.
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

    /// Commit the response bytes into the slot, so a replay returns exactly these bytes.
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
