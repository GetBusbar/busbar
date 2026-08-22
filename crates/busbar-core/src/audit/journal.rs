// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE GENERIC SCOPE-KEYED JOURNAL — the durable seq-authority state machine, in core, naming no
//! plane.
//!
//! ## What this is, and why it is here and not in a plane
//!
//! Two of busbar's evidence streams — the MCP per-call log and the A2A per-task provenance chain —
//! each grew their OWN copy of the same durable-log machinery around [`crate::audit::Chain`]: an
//! in-RAM per-scope POSITION CACHE, a bounded LRU over it, a store-resume of an evicted tail, a
//! write-through SINK, and the WRITE-ORDERING invariant that a position is committed only after the
//! durable append succeeds. That machinery is not MCP's and it is not A2A's — it is the same answer
//! to "make a hash-chained stream survive a restart" that [`crate::admin::audit`] gives for admin
//! mutations, and by the owner's ruling (see [`crate::audit`]) auditing is CORE. So it lives here,
//! once, generic over the record type, and a plane supplies only its RECORD (which fields, which
//! framing — [`crate::audit::ChainedRecord`]) plus the neutral store envelope its rows cross the seam
//! in ([`JournalRecord::to_plane_record`]).
//!
//! It names no plane noun: the type parameter is `R`, the scope is a `&str`, and the store is the
//! narrow [`PlaneStore`] seam. A plane's record type implements [`JournalRecord`] plane-side, so the
//! coupling points AT core, never out of it.
//!
//! ## The write-ordering invariant, stated once
//!
//! [`Journal::record`] appends to the in-RAM chain to MINT the sequence and link, writes the sealed
//! row through the durable sink, and only THEN commits the advanced position. Committing first and
//! writing after would leave the process believing a record exists that a restart will un-happen and
//! — worse for a hash chain — burn a sequence number nothing occupies, so the next successful write
//! lands on a `seq` the verifier reports as a gap forever. On a failed write the position is left
//! exactly where it was, so the next call reuses the sequence and the chain stays contiguous. This is
//! the one ordering every caller inherits by delegating here instead of re-deriving it.
//!
//! ## Restore reports, it does not judge
//!
//! [`Journal::restore_from_store`] resumes every scope's position from its persisted tail and returns
//! a [`Restored`] naming what it found — the empty scopes and the chain breaks — WITHOUT logging.
//! The plane-facing wrapper owns the operator-facing words (its own diagnostic codes name which log
//! to go and look at), so the generic core stays free of any plane's vocabulary. A broken chain is
//! REPORTED and still resumed from its tail (via [`Chain::from_persisted_unverified`]): refusing to
//! restore a tamper-detected chain would convert a detection control into a deletion primitive.

// UNUSED IN PRODUCTION until the calllog/taskstore cleave wires it (Phase 3 commits 3 and 5). The
// mechanism, the write-ordering and the restore are all real and tested here over a throwaway record
// type; the plane record sites adopt them next. Scoped per-item as callers land, not left as a
// module-wide blanket, so the next method to lose its caller breaks the build.
#![cfg_attr(not(test), allow(dead_code))]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use indexmap::IndexMap;

use crate::audit::{Chain, ChainBreak, ChainedRecord};
use crate::plane::store::{decode, PlaneStore};
use busbar_api::{PlaneRecord, PlaneSelector, StoreError, StoreResult};

/// A RECORD A JOURNAL CAN PERSIST. A plane's chained record type implements this to say TWO things
/// the generic journal cannot know: which neutral store `kind` its rows are tagged with, and how one
/// sealed record becomes the neutral [`PlaneRecord`] envelope it crosses the store seam in.
///
/// Implemented PLANE-SIDE (`impl JournalRecord for McpCallRecord` in `plane::calllog`, and likewise
/// for the A2A event row), so the plane→core coupling points at core and the journal names no plane.
pub(crate) trait JournalRecord: ChainedRecord + Clone + serde::de::DeserializeOwned {
    /// The neutral store kind these rows are tagged with (`call`, `task_event`, …) — the tag
    /// [`PlaneStore::list_plane_records`] and friends branch on. Its VALUE is a plane's business;
    /// the journal only threads it through.
    const KIND: &'static str;

    /// Build the neutral durable envelope for one sealed record — the exact bytes and sidecar columns
    /// the store persists. Delegates to the plane's own `*_record` helper, so the journal never
    /// encodes a plane row itself.
    fn to_plane_record(&self) -> StoreResult<PlaneRecord>;
}

/// Why a journal write could not be made durable. ONE variant today: the durable append failed. It is
/// SURFACED rather than swallowed — an evidence record that is not durable is one a restart will lose,
/// and the caller has to be able to decide whether that is acceptable for what it is recording.
#[derive(Debug)]
pub(crate) enum JournalError {
    /// The durable write failed.
    Store(StoreError),
}

impl std::fmt::Display for JournalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JournalError::Store(e) => write!(f, "{e}"),
        }
    }
}

/// WHAT A BOOT REHYDRATE FOUND, reported rather than summed. Neutral field names: a plane wrapper
/// renames these into its own operator vocabulary (`principals`, `active`, …) and emits its own
/// diagnostics from the two that are bad news.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Restored {
    /// Scopes whose chain position was resumed.
    pub(crate) scopes: usize,
    /// Records read back across every scope. THE DURABILITY SIGNAL: zero here on a deployment that
    /// has been serving traffic means the configured backend is keeping none of them.
    pub(crate) records: usize,
    /// Scopes the store ENUMERATED but returned no records for — the one shape the verifier cannot
    /// judge on its own, and what a wholesale deletion of one scope's evidence looks like. Named (not
    /// merely counted) so the wrapper can log WHICH.
    pub(crate) empty_scopes: Vec<String>,
    /// Chains that FAILED to verify. Tamper evidence. The records are still restored and the chain
    /// still resumes from the broken tail; the break is reported, never silently re-based onto.
    pub(crate) chain_breaks: Vec<ChainBreak>,
}

/// THE GENERIC SCOPE-KEYED DURABLE JOURNAL. Holds chain POSITIONS only (a tail hash and a next
/// sequence per scope), never the records — the store owns those. No `Debug`: it holds a
/// `dyn PlaneStore`, which is deliberately not `Debug` (a backend must not be obliged to render
/// itself, where a credential could surface in a log).
pub(crate) struct Journal<R: JournalRecord> {
    /// Chain POSITIONS, keyed by scope. An [`IndexMap`] so it doubles as a bounded LRU: insertion
    /// order is recency order (most-recently-used at the back), the coldest is evicted from the front
    /// once [`Journal::cap`] is exceeded, and an evicted scope is resumed from the store on its next
    /// write so no chain ever forks.
    positions: Mutex<IndexMap<String, Chain<R>>>,
    /// Latched true the first time an eviction actually happens. Before any eviction a cache MISS is
    /// unambiguously a first-seen scope (open at seq 1, no store read); after one, a miss MIGHT be an
    /// evicted scope whose tail lives in the store, so the resume reads it back rather than risk
    /// reopening a chain the store still holds records for. Relaxed: a rare monotonic false→true
    /// transition whose only effect is whether a miss consults the store.
    overflowed: AtomicBool,
    /// The durable write-through sink, attached once at boot. `None` (or a backend implementing none
    /// of the plane-record methods, the same thing from here) means positions live in RAM and nothing
    /// survives a restart — the documented `store: memory` posture.
    sink: Mutex<Option<Arc<dyn PlaneStore>>>,
    /// The upper bound on how many scope POSITIONS the process caches in RAM at once. The map is a
    /// CACHE of the store's per-scope tail, not the system of record, so it is bounded without loss:
    /// an evicted scope is resumed from the store on its next write. `usize::MAX` opts a stream out of
    /// eviction (an unbounded working set that is bounded elsewhere, e.g. a task table).
    cap: usize,
}

impl<R: JournalRecord> Journal<R> {
    /// A journal with an LRU bound of `cap` scope positions. `cap == usize::MAX` disables eviction.
    pub(crate) fn new(cap: usize) -> Self {
        Journal {
            positions: Mutex::new(IndexMap::new()),
            overflowed: AtomicBool::new(false),
            sink: Mutex::new(None),
            cap,
        }
    }

    /// Poison-recovering lock. The data behind it stays consistent after a panic (the critical
    /// sections only mutate a map of chain positions), and cascading a poison would make every
    /// subsequent write panic too — a data plane that wedges permanently because one request panicked.
    fn positions(&self) -> MutexGuard<'_, IndexMap<String, Chain<R>>> {
        self.positions.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn sink(&self) -> Option<Arc<dyn PlaneStore>> {
        self.sink
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .cloned()
    }

    /// Attach the configured durable store as the write-through SINK. Called once at boot.
    pub(crate) fn set_sink(&self, store: Arc<dyn PlaneStore>) {
        *self.sink.lock().unwrap_or_else(|e| e.into_inner()) = Some(store);
    }

    /// Commit `chain` as `scope`'s current position and record it as the MOST-recently-used, evicting
    /// the coldest scope(s) from the front while the map exceeds [`Journal::cap`]. Shared by the write
    /// hot path and the boot rehydrate so both keep the same bound and the same recency discipline. An
    /// eviction latches `overflowed`, which is what tells a later miss to consult the store instead of
    /// assuming the scope is new.
    fn commit_position(
        positions: &mut IndexMap<String, Chain<R>>,
        overflowed: &AtomicBool,
        cap: usize,
        scope: &str,
        chain: Chain<R>,
    ) {
        match positions.get_index_of(scope) {
            Some(idx) => {
                if let Some((_, slot)) = positions.get_index_mut(idx) {
                    *slot = chain;
                }
                // Move to the back: most-recently-used, so it is the last to be evicted.
                positions.move_index(idx, positions.len() - 1);
            }
            None => {
                // A new key appends at the back (most-recently-used) by IndexMap's contract.
                positions.insert(scope.to_string(), chain);
            }
        }
        while positions.len() > cap {
            // Evict the front — the least-recently-used. Its records stay in the store; its position
            // is rebuilt from there on the scope's next write.
            positions.shift_remove_index(0);
            overflowed.store(true, Ordering::Relaxed);
        }
    }

    /// Resolve the chain position for a scope NOT currently cached.
    ///
    /// Before any eviction has ever occurred a miss is unambiguously a first-seen scope, so this opens
    /// a fresh chain at seq 1 with NO store round-trip — byte-identical to an unbounded cache, and the
    /// whole reason a small deployment (working set under the cap) pays nothing for the bound.
    ///
    /// Once the cache HAS evicted, a miss might instead be a scope evicted while its records still sit
    /// in the store. Reopening at seq 1 would FORK the durable log, so with a sink attached the resume
    /// READS THE TAIL BACK and continues from it, exactly as a boot rehydrate does. A store that cannot
    /// answer is surfaced as an error rather than papered over with a seq-1 chain that might fork. With
    /// no sink there is no durable log to fork, so a fresh chain is the honest answer.
    fn resume_missing(&self, scope: &str) -> Result<Chain<R>, JournalError> {
        if !self.overflowed.load(Ordering::Relaxed) {
            return Ok(Chain::new());
        }
        let Some(store) = self.sink() else {
            return Ok(Chain::new());
        };
        let bodies = store
            .list_plane_records(R::KIND, &PlaneSelector::Parent(scope.to_string()))
            .map_err(JournalError::Store)?;
        if bodies.is_empty() {
            return Ok(Chain::new());
        }
        let records: Vec<R> = bodies
            .iter()
            .map(|body| decode(body))
            .collect::<StoreResult<_>>()
            .map_err(JournalError::Store)?;
        // A break here was already reported at boot; resume from the tail regardless, never re-based
        // onto a fresh chain — the same judgement `restore_from_store` makes.
        Ok(Chain::from_persisted(&records)
            .unwrap_or_else(|_brk| Chain::from_persisted_unverified(&records)))
    }

    /// BOOT REHYDRATE. Enumerate the scopes the store holds records for, resume each chain from its
    /// persisted tail, and REPORT what was found — without logging (the wrapper owns the words).
    ///
    /// This is the ONLY place durability is learned. A write's `Ok(())` proves nothing (the store
    /// trait default accepts and keeps nothing), so the engine finds out what its backend actually
    /// kept by reading it back.
    pub(crate) fn restore_from_store(&self, store: &dyn PlaneStore) -> StoreResult<Restored> {
        let scopes = store.list_plane_record_parents(R::KIND)?;
        let mut out = Restored::default();
        let mut positions = self.positions();
        for scope in &scopes {
            let records: Vec<R> = store
                .list_plane_records(R::KIND, &PlaneSelector::Parent(scope.clone()))?
                .iter()
                .map(|body| decode(body))
                .collect::<StoreResult<_>>()?;
            if records.is_empty() {
                out.empty_scopes.push(scope.clone());
                Self::commit_position(
                    &mut positions,
                    &self.overflowed,
                    self.cap,
                    scope,
                    Chain::new(),
                );
                out.scopes += 1;
                continue;
            }
            let chain = match Chain::from_persisted(&records) {
                Ok(c) => c,
                Err(brk) => {
                    out.chain_breaks.push(brk);
                    Chain::from_persisted_unverified(&records)
                }
            };
            out.records += records.len();
            Self::commit_position(&mut positions, &self.overflowed, self.cap, scope, chain);
            out.scopes += 1;
        }
        Ok(out)
    }

    /// RECORD one entry: chain it to MINT the sequence and link, write it through, and advance the
    /// position only once the durable write has succeeded. See the module header for why the order is
    /// load-bearing. A cache MISS is resolved by [`Journal::resume_missing`].
    pub(crate) fn record(&self, scope: &str, input: R::Input) -> Result<R, JournalError> {
        let mut positions = self.positions();
        let mut candidate = match positions.get(scope) {
            Some(chain) => chain.clone(),
            None => self.resume_missing(scope)?,
        };
        let record = candidate.append(scope, input);
        if let Some(store) = self.sink() {
            let envelope = record.to_plane_record().map_err(JournalError::Store)?;
            store
                .append_plane_record(&envelope)
                .map_err(JournalError::Store)?;
        }
        Self::commit_position(&mut positions, &self.overflowed, self.cap, scope, candidate);
        Ok(record)
    }

    /// The sequence the next record for `scope` will carry. 1 for a scope with no cached position.
    /// A diagnostic on the position — the one piece of state the store does not own.
    pub(crate) fn next_seq(&self, scope: &str) -> u64 {
        self.positions()
            .get(scope)
            .map(Chain::next_seq)
            .unwrap_or(1)
    }

    /// How many scope positions this process is holding.
    pub(crate) fn len(&self) -> usize {
        self.positions().len()
    }
}

#[cfg(test)]
#[path = "tests/journal_tests.rs"]
mod journal_tests;
