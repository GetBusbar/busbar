// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE NEUTRAL DURABLE-HANDLE ENGINE — the plane-agnostic async-handle / durable-session capability.
//!
//! Axis-C (stateful handles / async: "park a handle at a `202` and resume it later") is a capability
//! EVERY plane can want — the async-task plane, the LLM plane's stateful/batch handles, a live-session
//! plane. Its mechanics are neutral: a process-wide registry of cross-request handles keyed by an
//! opaque id, a durable write-through to the generic [`PlaneStore`] seam, a retention sweep with a hard
//! cap, a boot rehydrate that turns a restart into a pause, a monotonic inbound-push cursor, and a
//! SCOPED anti-enumeration lookup where a foreign id is indistinguishable from a missing one.
//!
//! This engine owns exactly those mechanics and NOTHING about any one plane's record. It is:
//!
//! - **Non-generic and substrate-single-compiled.** A plane's concrete row is held OPAQUELY as an
//!   `Arc<dyn Any + Send + Sync>` beside a neutral [`HandleMeta`] projection, so the engine type never
//!   names a plane type. That is deliberate: the handle store is destined to ride a per-plane opaque
//!   state slot (`Box<dyn Any>`) that core reads back, and in a dual-compiled plane test binary a
//!   GENERIC `Engine<PlaneRow>` monomorphised inside the plane crate would carry a `TypeId` that
//!   diverges across the two core instances. A single substrate-compiled non-generic type does not.
//!   The plane downcasts the `Arc<dyn Any>` back to its own row INSIDE the plane crate (same crate,
//!   same `TypeId`), so byte-identity is preserved with no re-encode round-trip.
//! - **Driven by small plane callbacks.** The plane supplies its record SHAPE, its terminal STATUSES
//!   (as the `terminal` flag on [`HandleMeta`]), its event VOCAB, and its provenance DIGEST through
//!   the closures the lifecycle/sweep/rehydrate entry points take. This is the same boxed-callback
//!   idiom [`crate::plane_host::scope`] uses to hold reclaim/settle resources without naming a plane
//!   type. No plane noun appears in this module.
//!
//! ## Lock discipline — the per-handle shard (outer map lock + per-handle inner lock)
//!
//! The correctness need is per-HANDLE serialization: a [`mutate`](DurableHandleEngine::mutate) advances
//! an EXISTING per-handle chain — the plane's seal reads `pos.tail_hash` and produces the next link — so
//! two concurrent mutations of the SAME handle MUST be serialized or they fork the chain against one
//! `tail_hash`. The engine pays exactly that, and no more, through a two-level lock:
//!
//! - The OUTER lock (`handles: Mutex<HashMap<String, Arc<Mutex<HandleSlot>>>>`) guards only the MAP
//!   STRUCTURE — insert / remove / enumerate. It is taken briefly to look up (or install) a handle's
//!   `Arc<Mutex<HandleSlot>>` and then RELEASED; it is never held across a store round-trip on the hot
//!   mutate path.
//! - The per-handle INNER lock (`Mutex<HandleSlot>`) serializes that ONE handle's chain and IS held
//!   across its durable I/O (upsert + append). Because it is per-handle, two DIFFERENT handles mutate
//!   fully concurrently — neither the outer lock nor each other's inner lock stands between them.
//!
//! So [`mutate`](DurableHandleEngine::mutate) / [`scoped_mutate`](DurableHandleEngine::scoped_mutate)
//! take the outer lock, clone out the target's `Arc<Mutex<HandleSlot>>`, DROP the outer lock, then take
//! the inner lock across the plan + persist. This preserves same-handle chain serialization (the naive
//! "drop the lock during seal/append" minimization would reopen exactly the concurrent-same-handle fork
//! the inner lock prevents) while lifting the per-ENGINE bottleneck the earlier single-global-lock shape
//! imposed on a high-concurrency SECOND consumer (voice-session frames, Responses-stateful streaming).
//!
//! - [`submit`](DurableHandleEngine::submit) still does its durable writes (`upsert_record` +
//!   `append_record`) BEFORE it takes the outer lock — a submit is a FRESH id at the genesis chain
//!   position, with no existing per-handle chain another writer could fork, so its durable write needs
//!   no cross-writer serialization. It takes the outer lock only to run the retention sweep and insert.
//! - The sweep's abandon in [`sweep_locked`](DurableHandleEngine::sweep_locked) and the boot
//!   [`rehydrate`](DurableHandleEngine::rehydrate) run under the outer lock and take inner locks beneath
//!   it. The ordering is always outer-THEN-inner (no path ever takes the outer lock while holding an
//!   inner one), so the two levels cannot deadlock. Abandon's durable I/O under the outer lock is
//!   confined to the submit-driven sweep — the hot mutate path never holds the outer lock across I/O.

// PARTLY UNMOUNTED: a bare substrate build that never constructs the engine reads some accessors as
// unused; the plane crates and the engine's own unit tests exercise the whole surface.
#![cfg_attr(not(any(test, feature = "test-support")), allow(dead_code))]

use std::any::Any;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use crate::plane::store::PlaneStore;
use busbar_api::{PlaneRecord, PlaneSelector, StoreError, StoreResult};

/// The NEUTRAL projection of a plane row the engine reads to run its mechanics WITHOUT decoding the
/// plane's opaque body: who the handle belongs to (the anti-enumeration scope key), when it last
/// changed (the retention age key), whether it has SETTLED (terminal), and the inbound-push cursor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandleMeta {
    /// The principal a handle is attributed to — the ONLY key a scoped read matches on. A caller sees
    /// its own handles and cannot tell a foreign id from a nonexistent one.
    pub owner: String,
    /// Unix seconds of the most recent change. The retention sweep's age key.
    pub updated_at: u64,
    /// Has the handle reached a FINAL state? The plane classifies this from its own status tokens; the
    /// engine only reads the boolean (sweep eviction, terminal-only compaction, terminal-only evict).
    pub terminal: bool,
    /// The monotonic inbound-push cursor — how many pushed artifacts a resumed stream has already seen.
    pub cursor: u64,
}

/// ONE CHAIN'S POSITION: the tail link and the next sequence number. The first event of a chain gets
/// `next_seq` 1 and an empty `tail_hash`. Neutral (plain strings/ints); the digest that FILLS
/// `tail_hash` is the plane's, computed in the plane's seal callback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainPosition {
    /// The preceding event's hash (empty at genesis).
    pub tail_hash: String,
    /// The sequence the next sealed event takes (1 at genesis).
    pub next_seq: u64,
}

impl ChainPosition {
    /// The genesis position: empty tail, `next_seq` 1.
    #[must_use]
    pub fn genesis() -> Self {
        ChainPosition {
            tail_hash: String::new(),
            next_seq: 1,
        }
    }

    /// Continue from a persisted tail: `tail_hash` is the last event's hash and `next_seq` is one past
    /// its sequence.
    #[must_use]
    pub fn from_tail(tail_hash: String, next_seq: u64) -> Self {
        ChainPosition {
            tail_hash,
            next_seq,
        }
    }
}

/// The retention knobs the sweep enforces — a plane supplies its own values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SweepBounds {
    /// An ACTIVE handle idle longer than this (seconds) is transitioned toward settlement by the
    /// plane's abandon callback.
    pub abandon_secs: u64,
    /// A TERMINAL handle stays in the working set this long (seconds) after settling, then is evicted.
    pub terminal_ttl_secs: u64,
    /// The hard ceiling on working-set entries; oldest TERMINAL handles are dropped first, an ACTIVE
    /// handle is never dropped to make room.
    pub max_retained: usize,
}

/// What a plane's seal callback returns: the durable event record to append, and the new chain tail
/// hash the plane computed. The engine appends the record and advances `next_seq`; the plane owns the
/// digest that produced `tail_hash`.
pub struct SealedEvent {
    /// The event to append durably (already framed by the plane into the opaque envelope).
    pub record: PlaneRecord,
    /// The event's own hash, becoming the chain's new tail.
    pub tail_hash: String,
}

/// One mutation to apply to a live handle. Every field is OPTIONAL: `None` leaves that facet
/// unchanged, so a row-only touch (no event), an event-only append (no row change), and a full
/// transition all express through the same primitive.
pub struct Mutation {
    /// The new opaque row snapshot, or `None` to keep the current one.
    pub row: Option<Arc<dyn Any + Send + Sync>>,
    /// The new neutral projection, or `None` to keep the current one.
    pub meta: Option<HandleMeta>,
    /// A durable row record to UPSERT first, or `None` to skip the row write.
    pub row_record: Option<PlaneRecord>,
    /// A sealed event to APPEND and advance the chain by, or `None` to append nothing.
    pub event: Option<SealedEvent>,
}

/// The record a fresh submit installs: its id, opaque row, projection, durable row record, and its
/// OPTIONAL genesis event.
pub struct SubmitRecord {
    /// The handle id (the working-set key and the row's primary key).
    pub id: String,
    /// The opaque row snapshot.
    pub row: Arc<dyn Any + Send + Sync>,
    /// The neutral projection.
    pub meta: HandleMeta,
    /// The durable row record to upsert.
    pub row_record: PlaneRecord,
    /// The genesis provenance event, or `None` to open a CHAINLESS durable handle. A2A always opens a
    /// chain here (an `EV_SUBMITTED` genesis); a consumer that wants a durable row WITHOUT a per-event
    /// hash chain (a Responses-stateful handle keyed by response id) passes `None` — matching
    /// [`Mutation::event`], so "every handle opens a provenance chain" is a plane CHOICE, not an engine
    /// assumption. With `None` the handle's position stays at [`ChainPosition::genesis`] (empty tail,
    /// `next_seq` 1), so a LATER `mutate` that does append an event seals the true genesis event.
    pub event: Option<SealedEvent>,
}

/// What a plane's rehydrate classifier decides for one persisted row.
pub enum RehydrateOutcome {
    /// This row could not be decoded / read back — counted, never resumed.
    Unreadable,
    /// This row is already terminal — counted and left in the store, not loaded.
    Terminal,
    /// This row is active and resumable: install it. `event_unreadable` folds in any of its OWN event
    /// records the plane could not decode (counted the same way, never aborting the whole rehydrate).
    Active {
        /// The handle id / working-set key.
        id: String,
        /// The opaque row snapshot.
        row: Arc<dyn Any + Send + Sync>,
        /// The neutral projection.
        meta: HandleMeta,
        /// The chain position resumed from the persisted events.
        pos: ChainPosition,
        /// Undecodable EVENT records for this handle — counted, not fatal.
        event_unreadable: usize,
    },
}

/// What a boot rehydrate found. Neutral counts; plane-typed provenance breaks accumulate plane-side in
/// the classifier callback.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RehydrateCounts {
    /// Active handles brought back and resumable.
    pub active: usize,
    /// Terminal handles seen and deliberately not loaded.
    pub terminal: usize,
    /// Rows/events that would not decode — counted, not silently dropped.
    pub unreadable: usize,
}

/// Why a scoped read was refused — ONE variant on purpose (a distinguishable not-found is an
/// enumeration oracle).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandleDenied {
    /// The handle does not exist, OR it belongs to somebody else.
    NotYours,
}

/// The error a plane's mutation planner returns: a domain REJECTION (the plane refused the move) or a
/// durable STORE failure while building the mutation. The engine keeps them distinct so the plane can
/// map each back to its own taxonomy.
pub enum MutateError {
    /// The plane refused the transition — carried as its already-rendered message.
    Rejected(String),
    /// A durable encode/build failed.
    Store(StoreError),
}

/// What went wrong servicing an engine operation.
#[derive(Debug)]
pub enum HandleEngineError {
    /// No live handle carries this id.
    NoSuchHandle(String),
    /// The plane's mutation planner refused the move.
    Rejected(String),
    /// A durable write failed.
    Store(StoreError),
}

impl std::fmt::Display for HandleEngineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HandleEngineError::NoSuchHandle(id) => write!(f, "no such handle `{id}`"),
            HandleEngineError::Rejected(e) => write!(f, "{e}"),
            HandleEngineError::Store(e) => write!(f, "{e}"),
        }
    }
}

/// What went wrong servicing a SCOPED mutation ([`DurableHandleEngine::scoped_mutate`]). The AUTH
/// refusal is collapsed to a single [`NotYours`](Self::NotYours) — a missing handle and a handle owned
/// by someone else are indistinguishable, exactly as [`HandleDenied`] is for a scoped READ, so an
/// untrusted write-by-correlation-id (the T3 inbound webhook receiver) cannot become the enumeration
/// oracle the read path deliberately is not. Only AFTER ownership is proven do the plane's own domain
/// [`Rejected`](Self::Rejected) and durable [`Store`](Self::Store) failures surface distinctly — those
/// facts belong to an already-authorized caller.
#[derive(Debug)]
pub enum ScopedMutateError {
    /// The handle does not exist, OR it belongs to somebody else, OR the owner is empty. ONE variant on
    /// purpose — a distinguishable refusal is an enumeration oracle.
    NotYours,
    /// The plane's mutation planner refused the move — carried as its already-rendered message. Only
    /// reachable once ownership is proven.
    Rejected(String),
    /// A durable write failed. Only reachable once ownership is proven.
    Store(StoreError),
}

impl std::fmt::Display for ScopedMutateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScopedMutateError::NotYours => write!(f, "not yours"),
            ScopedMutateError::Rejected(e) => write!(f, "{e}"),
            ScopedMutateError::Store(e) => write!(f, "{e}"),
        }
    }
}

/// One live handle in the working set: its opaque row, its neutral projection, and its chain position.
struct HandleSlot {
    row: Arc<dyn Any + Send + Sync>,
    meta: HandleMeta,
    pos: ChainPosition,
}

/// THE DURABLE-HANDLE ENGINE. Non-generic; holds opaque rows behind `Arc<dyn Any>`. No `Debug`: it
/// holds a `dyn PlaneStore`.
pub struct DurableHandleEngine {
    handles: Mutex<HashMap<String, Arc<Mutex<HandleSlot>>>>,
    /// The durable sink for row upserts AND event appends. `None` is the RAM-cache posture (a plane's
    /// `store: memory`): the persistence methods no-op and nothing survives a restart.
    sink: Mutex<Option<Arc<dyn PlaneStore>>>,
}

impl Default for DurableHandleEngine {
    fn default() -> Self {
        Self {
            handles: Mutex::new(HashMap::new()),
            sink: Mutex::new(None),
        }
    }
}

impl DurableHandleEngine {
    /// A fresh, empty engine with no durable sink (RAM-cache posture until [`set_sink`](Self::set_sink)).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Poison-recovering OUTER lock over the map structure. The critical sections only mutate a map, so
    /// the data behind the lock is always consistent after a panic and cascading a poison would wedge the
    /// whole capability. Held briefly to look up / install a handle's `Arc<Mutex<HandleSlot>>`; the hot
    /// mutate path drops it before taking the per-handle inner lock.
    fn lock(&self) -> MutexGuard<'_, HashMap<String, Arc<Mutex<HandleSlot>>>> {
        self.handles.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Poison-recovering INNER lock over one handle's slot. Same rationale as [`lock`](Self::lock): a
    /// panic leaves the slot fields consistent, and a poison must not wedge the handle forever.
    fn lock_slot(slot: &Arc<Mutex<HandleSlot>>) -> MutexGuard<'_, HandleSlot> {
        slot.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The durable sink, cloned. `None` is the RAM-cache posture.
    fn sink(&self) -> Option<Arc<dyn PlaneStore>> {
        self.sink
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .cloned()
    }

    /// Attach the durable sink. Called once at boot; with no sink the engine is a RAM cache.
    pub fn set_sink(&self, store: Arc<dyn PlaneStore>) {
        *self.sink.lock().unwrap_or_else(|e| e.into_inner()) = Some(store);
    }

    /// Drop the sink again, so a test that attached one to a process-wide engine leaves it as it found
    /// it. Not test-gated: a plane crate's OWN test build depends on this crate as a non-test library,
    /// so the method must exist there; it is inert in production (a plane only calls it under test).
    pub fn clear_sink_for_test(&self) {
        *self.sink.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }

    /// Upsert one durable row record (no-op with no sink).
    fn upsert_record(&self, record: &PlaneRecord) -> StoreResult<()> {
        if let Some(store) = self.sink() {
            store.upsert_plane_record(record)?;
        }
        Ok(())
    }

    /// Append one durable event record (no-op with no sink).
    fn append_record(&self, record: &PlaneRecord) -> StoreResult<()> {
        if let Some(store) = self.sink() {
            store.append_plane_record(record)?;
        }
        Ok(())
    }

    /// Apply one [`Mutation`] to an already-locked `slot`: durable row upsert FIRST, then event append,
    /// then — only after both persist — the in-memory row/meta/position. A durable failure returns via
    /// `?` BEFORE any in-memory field is touched, so the slot is left untouched (the caller retries).
    /// The slot is held under its per-handle inner lock across the whole call, serializing that one
    /// handle's chain against a concurrent same-handle mutation.
    fn apply_mutation_to_slot(&self, slot: &mut HandleSlot, m: Mutation) -> StoreResult<()> {
        if let Some(rec) = &m.row_record {
            self.upsert_record(rec)?;
        }
        if let Some(ev) = &m.event {
            self.append_record(&ev.record)?;
        }
        if let Some(ev) = m.event {
            slot.pos.tail_hash = ev.tail_hash;
            slot.pos.next_seq = slot.pos.next_seq.saturating_add(1);
        }
        if let Some(row) = m.row {
            slot.row = row;
        }
        if let Some(meta) = m.meta {
            slot.meta = meta;
        }
        Ok(())
    }

    /// SUBMIT a new handle: `plan` builds its row + records + genesis event from the genesis position
    /// (the plane computes the digest); the engine persists row-then-event, runs the retention sweep,
    /// and inserts. The durable writes happen BEFORE the working-set lock is taken, exactly as the
    /// handle is announced accepted only after it is durable. Returns the installed opaque row.
    pub fn submit<P, A, R>(
        &self,
        now: u64,
        bounds: SweepBounds,
        plan: P,
        abandon: A,
        report_fail: R,
    ) -> Result<Arc<dyn Any + Send + Sync>, HandleEngineError>
    where
        P: FnOnce(&ChainPosition) -> Result<SubmitRecord, StoreError>,
        A: Fn(&str, &(dyn Any + Send + Sync), &ChainPosition, u64) -> Option<Mutation>,
        R: Fn(&str, &StoreError),
    {
        let genesis = ChainPosition::genesis();
        let sr = plan(&genesis).map_err(HandleEngineError::Store)?;
        self.upsert_record(&sr.row_record)
            .map_err(HandleEngineError::Store)?;
        // A genesis event opens the chain and advances the position by one; a chainless handle keeps
        // the genesis position (empty tail, next_seq 1) so a first later event still seals the genuine
        // genesis link.
        let pos = match sr.event {
            Some(ev) => {
                self.append_record(&ev.record)
                    .map_err(HandleEngineError::Store)?;
                ChainPosition {
                    tail_hash: ev.tail_hash,
                    next_seq: genesis.next_seq.saturating_add(1),
                }
            }
            None => genesis,
        };
        let mut handles = self.lock();
        self.sweep_locked(&mut handles, now, bounds, &abandon, &report_fail);
        let row = sr.row.clone();
        handles.insert(
            sr.id,
            Arc::new(Mutex::new(HandleSlot {
                row: sr.row,
                meta: sr.meta,
                pos,
            })),
        );
        Ok(row)
    }

    /// MUTATE a live handle under the working-set lock: `plan` sees the current opaque row and chain
    /// position and returns the [`Mutation`] to apply (or `None` for a no-op that touches nothing). The
    /// engine persists then updates memory; a domain rejection and a durable failure are returned
    /// distinctly. Returns the resulting opaque row.
    ///
    /// UNSCOPED — keyed by `id` alone, authorization is the caller's to enforce upstream. This is the
    /// right primitive for a TRUSTED internal caller that has already scoped (A2A's front door scopes at
    /// its edge). An UNTRUSTED write-by-correlation-id (the T3 inbound webhook receiver) MUST instead go
    /// through [`scoped_mutate`](Self::scoped_mutate), which owner-gates the write with the same
    /// indistinguishable refusal the read path uses.
    pub fn mutate<F>(
        &self,
        id: &str,
        plan: F,
    ) -> Result<Arc<dyn Any + Send + Sync>, HandleEngineError>
    where
        F: FnOnce(
            &(dyn Any + Send + Sync),
            &ChainPosition,
        ) -> Result<Option<Mutation>, MutateError>,
    {
        // Take the outer lock only long enough to clone out the handle's shard, then release it so a
        // mutation of a DIFFERENT handle never blocks behind this one's store round-trip.
        let slot_arc = self
            .lock()
            .get(id)
            .cloned()
            .ok_or_else(|| HandleEngineError::NoSuchHandle(id.to_string()))?;
        // The per-handle inner lock serializes THIS handle's chain across its durable I/O.
        let mut slot = Self::lock_slot(&slot_arc);
        let plan_out = plan(slot.row.as_ref(), &slot.pos).map_err(|e| match e {
            MutateError::Rejected(s) => HandleEngineError::Rejected(s),
            MutateError::Store(e) => HandleEngineError::Store(e),
        })?;
        let Some(m) = plan_out else {
            // No-op: return the current row unchanged.
            return Ok(slot.row.clone());
        };
        self.apply_mutation_to_slot(&mut slot, m)
            .map_err(HandleEngineError::Store)?;
        Ok(slot.row.clone())
    }

    /// SCOPED MUTATE — the authorization gate on the WRITE/RESUME path, mirroring
    /// [`scoped_get`](Self::scoped_get) on the read path. The ownership check runs FIRST, under the
    /// working-set lock and BEFORE `plan` is ever invoked: an empty owner, a missing handle, and a
    /// handle owned by someone else all collapse to one [`ScopedMutateError::NotYours`], so `plan`'s
    /// side effects and timing never leak whether the id exists. Only once `owner` matches the slot's
    /// [`HandleMeta::owner`] does it run the identical persist-then-update path as
    /// [`mutate`](Self::mutate) (durable row upsert, event append, chain advance), surfacing the plane's
    /// domain [`Rejected`](ScopedMutateError::Rejected) and durable [`Store`](ScopedMutateError::Store)
    /// failures to the now-authorized caller. This is the exact primitive the T3 inbound webhook
    /// receiver's untrusted resume-by-correlation-id needs; the same lock discipline as `mutate` applies
    /// (see the module note on the lock-across-I/O asymmetry).
    pub fn scoped_mutate<F>(
        &self,
        owner: &str,
        id: &str,
        plan: F,
    ) -> Result<Arc<dyn Any + Send + Sync>, ScopedMutateError>
    where
        F: FnOnce(
            &(dyn Any + Send + Sync),
            &ChainPosition,
        ) -> Result<Option<Mutation>, MutateError>,
    {
        if owner.is_empty() {
            return Err(ScopedMutateError::NotYours);
        }
        // Take the outer lock only to clone out the shard; a missing id collapses to the same refusal as
        // a foreign owner, so nothing before the ownership check leaks whether the id exists.
        let Some(slot_arc) = self.lock().get(id).cloned() else {
            return Err(ScopedMutateError::NotYours);
        };
        // The per-handle inner lock serializes THIS handle's chain across its durable I/O.
        let mut slot = Self::lock_slot(&slot_arc);
        // Owner gate BEFORE plan: a foreign, missing, or empty-owner target is one refusal, so `plan`'s
        // side effects and timing never leak whether the id exists.
        if slot.meta.owner != owner {
            return Err(ScopedMutateError::NotYours);
        }
        let plan_out = plan(slot.row.as_ref(), &slot.pos).map_err(|e| match e {
            MutateError::Rejected(s) => ScopedMutateError::Rejected(s),
            MutateError::Store(e) => ScopedMutateError::Store(e),
        })?;
        let Some(m) = plan_out else {
            // No-op: return the current row unchanged.
            return Ok(slot.row.clone());
        };
        self.apply_mutation_to_slot(&mut slot, m)
            .map_err(ScopedMutateError::Store)?;
        Ok(slot.row.clone())
    }

    /// THE RETENTION SWEEP under a held working-set lock. Three rules: (0) transition an ACTIVE handle
    /// idle past `abandon_secs` via the plane's `abandon` callback (a durable-write failure leaves it
    /// active and is reported through `report_fail`); (1) evict TERMINAL handles past
    /// `terminal_ttl_secs`; (2) if still over `max_retained`, evict oldest TERMINAL first — never an
    /// active one. Its abandon transition does durable I/O while the global lock is held — see the
    /// module-level "Lock discipline" note on the per-engine-vs-per-handle asymmetry.
    fn sweep_locked<A, R>(
        &self,
        handles: &mut HashMap<String, Arc<Mutex<HandleSlot>>>,
        now: u64,
        bounds: SweepBounds,
        abandon: &A,
        report_fail: &R,
    ) where
        A: Fn(&str, &(dyn Any + Send + Sync), &ChainPosition, u64) -> Option<Mutation>,
        R: Fn(&str, &StoreError),
    {
        let abandoned: Vec<String> = handles
            .iter()
            .filter(|(_, s)| {
                let s = Self::lock_slot(s);
                !s.meta.terminal && now.saturating_sub(s.meta.updated_at) > bounds.abandon_secs
            })
            .map(|(id, _)| id.clone())
            .collect();
        for id in &abandoned {
            let Some(slot_arc) = handles.get(id).cloned() else {
                continue;
            };
            let mut slot = Self::lock_slot(&slot_arc);
            let Some(m) = abandon(id, slot.row.as_ref(), &slot.pos, now) else {
                continue;
            };
            if let Err(e) = self.apply_mutation_to_slot(&mut slot, m) {
                report_fail(id, &e);
            }
        }
        let expired: Vec<String> = handles
            .iter()
            .filter(|(_, s)| {
                let s = Self::lock_slot(s);
                s.meta.terminal && now.saturating_sub(s.meta.updated_at) > bounds.terminal_ttl_secs
            })
            .map(|(id, _)| id.clone())
            .collect();
        for id in &expired {
            handles.remove(id);
        }
        if handles.len() < bounds.max_retained {
            return;
        }
        let mut terminal: Vec<(u64, String)> = handles
            .iter()
            .filter_map(|(id, s)| {
                let s = Self::lock_slot(s);
                s.meta.terminal.then(|| (s.meta.updated_at, id.clone()))
            })
            .collect();
        terminal.sort_unstable();
        for (_, id) in terminal
            .into_iter()
            .take(handles.len().saturating_sub(bounds.max_retained) + 1)
        {
            handles.remove(&id);
        }
    }

    /// BOOT REHYDRATE. Reads every persisted row of `kind` from `store`, asks `classify` what to do
    /// with each (decode / read-back / terminal-check / chain-verify are the plane's, and it emits its
    /// own diagnostics + accumulates its own provenance breaks there), and installs the active ones.
    /// A row `classify` cannot read is counted, never aborting the whole rehydrate; only a STORE-level
    /// list failure aborts (propagated). Runs at BOOT under the global lock across `classify`'s per-row
    /// I/O; harmless there (single-threaded, no concurrency) but part of the same lock-across-I/O shape
    /// the module-level "Lock discipline" note documents.
    pub fn rehydrate<F>(
        &self,
        store: &dyn PlaneStore,
        kind: &str,
        mut classify: F,
    ) -> StoreResult<RehydrateCounts>
    where
        F: FnMut(&dyn PlaneStore, &[u8]) -> StoreResult<RehydrateOutcome>,
    {
        let bodies = store.list_plane_records(kind, &PlaneSelector::All)?;
        let mut out = RehydrateCounts::default();
        let mut handles = self.lock();
        for body in &bodies {
            match classify(store, body)? {
                RehydrateOutcome::Unreadable => out.unreadable += 1,
                RehydrateOutcome::Terminal => out.terminal += 1,
                RehydrateOutcome::Active {
                    id,
                    row,
                    meta,
                    pos,
                    event_unreadable,
                } => {
                    out.unreadable += event_unreadable;
                    handles.insert(id, Arc::new(Mutex::new(HandleSlot { row, meta, pos })));
                    out.active += 1;
                }
            }
        }
        Ok(out)
    }

    /// SCOPED READ — the authorization gate: a caller sees its own handles and cannot tell a foreign id
    /// from a nonexistent one. An empty owner sees nothing.
    pub fn scoped_get(
        &self,
        owner: &str,
        id: &str,
    ) -> Result<Arc<dyn Any + Send + Sync>, HandleDenied> {
        if owner.is_empty() {
            return Err(HandleDenied::NotYours);
        }
        let Some(slot_arc) = self.lock().get(id).cloned() else {
            return Err(HandleDenied::NotYours);
        };
        let slot = Self::lock_slot(&slot_arc);
        if slot.meta.owner == owner {
            Ok(slot.row.clone())
        } else {
            Err(HandleDenied::NotYours)
        }
    }

    /// SCOPED LIST — every handle owned by `owner`, sorted by id so the result is deterministic. An
    /// empty owner lists nothing.
    pub fn scoped_list(&self, owner: &str) -> Vec<Arc<dyn Any + Send + Sync>> {
        if owner.is_empty() {
            return Vec::new();
        }
        let mut out: Vec<(String, Arc<dyn Any + Send + Sync>)> = self
            .lock()
            .iter()
            .filter_map(|(id, s)| {
                let s = Self::lock_slot(s);
                (s.meta.owner == owner).then(|| (id.clone(), s.row.clone()))
            })
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out.into_iter().map(|(_, r)| r).collect()
    }

    /// UNSCOPED read — for the operator surface and the sweep, never for a caller.
    pub fn get_unscoped(&self, id: &str) -> Option<Arc<dyn Any + Send + Sync>> {
        self.lock().get(id).map(|s| Self::lock_slot(s).row.clone())
    }

    /// The neutral projection of a live handle, or `None`.
    pub fn meta(&self, id: &str) -> Option<HandleMeta> {
        self.lock().get(id).map(|s| Self::lock_slot(s).meta.clone())
    }

    /// How many handles are in the working set.
    #[must_use]
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// Whether the working set holds no handles.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.lock().is_empty()
    }

    /// Drop a handle from the working set once it is TERMINAL, leaving its durable rows in the store.
    /// Refuses to evict an ACTIVE handle.
    pub fn evict_if_terminal(&self, id: &str) -> bool {
        let mut handles = self.lock();
        let terminal = handles.get(id).map(|s| Self::lock_slot(s).meta.terminal);
        if terminal == Some(true) {
            handles.remove(id);
            true
        } else {
            false
        }
    }

    /// COMPACT: ask the sink to purge terminal `kind` rows older than `before`, and drop any matching
    /// terminal working-set entries. Returns how many durable rows went.
    pub fn compact(&self, before: u64, kind: &str) -> StoreResult<u64> {
        let removed = match self.sink() {
            Some(store) => store.purge_plane_records_before(kind, before)?,
            None => 0,
        };
        let mut handles = self.lock();
        let dropped: Vec<String> = handles
            .iter()
            .filter_map(|(id, s)| {
                let s = Self::lock_slot(s);
                (s.meta.terminal && s.meta.updated_at < before).then(|| id.clone())
            })
            .collect();
        for id in &dropped {
            handles.remove(id);
        }
        Ok(removed)
    }
}

#[cfg(test)]
#[path = "tests/handle_engine_tests.rs"]
mod tests;
