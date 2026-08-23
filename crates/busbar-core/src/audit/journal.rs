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

// The MCP call log (`plane::calllog`, `plane-mcp`) and the A2A task store (`plane::taskstore`,
// `plane-a2a`) both wire this in production. But with BOTH planes compiled out
// (`--no-default-features`) nothing instantiates a `Journal`, so every method here is dead on that
// configuration — exactly as the plane modules themselves are, which carry the same blanket. Hence
// the module-wide allow rather than per-item: the "dead" set is the whole module under one cfg and
// fully live under another, so a per-item list would be noise that says nothing a reader can act on.
#![cfg_attr(not(test), allow(dead_code))]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use indexmap::IndexMap;

use crate::audit::{verify_chain, Chain, ChainBreak, ChainedRecord};
use crate::plane::store::{decode, encode, PlaneStore};
use busbar_api::{PlaneDisposition, PlaneRecord, PlaneSelector, StoreError, StoreResult};

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
pub(crate) struct Journal<R> {
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

impl<R: ChainedRecord> Journal<R> {
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

    /// The attached durable sink, if any. `pub(crate)` because a stream may persist OTHER durable
    /// state beside its journaled chain (the A2A task table upserts a `task` row next to its
    /// `task_event` chain) and must reach the same backend — the journal owns the one sink handle so
    /// there is not a second to keep in sync.
    pub(crate) fn sink(&self) -> Option<Arc<dyn PlaneStore>> {
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

    /// TEST ONLY: drop the sink again, so a test that attached one to a process-wide journal leaves it
    /// as it found it. No production caller: detaching a live deployment's sink mid-run would silently
    /// stop persisting evidence, the exact failure this module exists to prevent.
    #[cfg(test)]
    pub(crate) fn clear_sink_for_test(&self) {
        *self.sink.lock().unwrap_or_else(|e| e.into_inner()) = None;
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
    fn resume_missing(&self, scope: &str) -> Result<Chain<R>, JournalError>
    where
        R: JournalRecord,
    {
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
    pub(crate) fn restore_from_store(&self, store: &dyn PlaneStore) -> StoreResult<Restored>
    where
        R: JournalRecord,
    {
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

    /// SEED one scope's position from records the CALLER already read. For a rehydrate that drives its
    /// own row loop rather than the whole-store enumeration [`Journal::restore_from_store`] does — the
    /// A2A task table walks `task` rows and loads only the ACTIVE ones' event chains, so it hands each
    /// active scope's events here instead of letting the journal enumerate (and cache) every terminal
    /// task's chain too. Verifies and REPORTS a break exactly as `restore_from_store` does (the broken
    /// chain still resumes from its tail via [`Chain::from_persisted_unverified`]); returns the break
    /// for the caller to log in its own vocabulary, or `None` when the chain verifies.
    pub(crate) fn seed_position(&self, scope: &str, records: &[R]) -> Option<ChainBreak> {
        let (chain, brk) = match Chain::from_persisted(records) {
            Ok(c) => (c, None),
            Err(b) => (Chain::from_persisted_unverified(records), Some(b)),
        };
        let mut positions = self.positions();
        Self::commit_position(&mut positions, &self.overflowed, self.cap, scope, chain);
        brk
    }

    /// DROP one scope's cached position. For a stream whose scopes have a lifecycle the journal does
    /// not (a task reaches a terminal state and is evicted from the working set, or a retention sweep
    /// collects it): the durable records stay in the store, but the RAM position is released so the
    /// cache does not grow one entry per scope ever seen. Never call it on a scope that may still be
    /// appended to — reopening it would resume from the store tail (with a sink) or FORK at seq 1
    /// (without one).
    pub(crate) fn forget(&self, scope: &str) {
        self.positions().shift_remove(scope);
    }

    /// RECORD one entry: chain it to MINT the sequence and link, write it through, and advance the
    /// position only once the durable write has succeeded. See the module header for why the order is
    /// load-bearing. A cache MISS is resolved by [`Journal::resume_missing`].
    pub(crate) fn record(&self, scope: &str, input: R::Input) -> Result<R, JournalError>
    where
        R: JournalRecord,
    {
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

    /// RETENTION: ask the durable sink to drop records of this journal's kind older than `before`,
    /// returning how many durable rows went. The policy (the window) lives at the call site; this owns
    /// only the mechanism. Positions are NOT reset — reopening a scope at seq 1 after a purge would
    /// collide with a sequence the store may still hold, the one thing the append contract forbids.
    pub(crate) fn compact(&self, before: u64) -> StoreResult<u64>
    where
        R: JournalRecord,
    {
        match self.sink() {
            Some(store) => store.purge_plane_records_before(R::KIND, before),
            None => Ok(0),
        }
    }
}

// ── THE NEUTRAL DURABLE PATH — kind/framing/digests_scope as DATA, record shape as a REFRAME ──────
//
// The three shipped streams cross here as a TYPED `R: JournalRecord` whose `const KIND` and
// `to_plane_record` name the plane's own row. The DURABLE SEAM a plane reaches over the host vtable
// cannot: the host serves many streams at once, learns each stream's `kind` at REGISTER time (runtime
// DATA, never a const), and must NAME NO PLANE TYPE. So this parallel surface takes the `kind` as a
// `&str`, persists a NEUTRAL `{seq, prev_hash, hash, content}` body (the plane's `content` is an opaque
// pre-framed suffix carried verbatim), and turns a stored body back into a record through a plane-side
// REFRAME callback rather than `serde`-decoding it into a type core would have to name. The chain
// authority, the position cache, the LRU and the write-ordering are the SAME `Journal` machinery above.

/// The NEUTRAL durable body the store-backed journal persists per record — `{seq, prev_hash, hash,
/// content}`, naming no plane type. A TYPED stream persists its own serde row; this neutral journal
/// persists THIS, and a plane's reframe callback is the decode bridge that turns EITHER shape back
/// into a record on restore (so a store still holding old serde rows verifies unchanged). ADDITIVE.
#[derive(serde::Serialize, serde::Deserialize)]
pub(crate) struct NeutralBody {
    /// The chain sequence the host minted for this record.
    pub(crate) seq: u64,
    /// The link to the previous record (empty at genesis).
    pub(crate) prev_hash: String,
    /// This record's sealed digest.
    pub(crate) hash: String,
    /// The plane's OPAQUE pre-framed content suffix (the bytes the digest appends RAW).
    pub(crate) content: Vec<u8>,
}

/// A record whose durable body is the neutral [`NeutralBody`] envelope. The generic scope-keyed
/// journal persists and resumes it WITHOUT naming any plane type: `content` is the plane's opaque
/// pre-framed suffix, carried through verbatim, and `scope` is supplied by the caller (the store
/// parent), never read from the body.
pub(crate) trait NeutralRecord: ChainedRecord + Clone {
    /// The opaque pre-framed content suffix this record carries (the bytes the digest appends RAW).
    fn content(&self) -> &[u8];
}

/// A plane-side REFRAME: turn one stored body + its scope back into a record. The store bodies may be
/// this journal's own [`NeutralBody`] OR a legacy serde row from before the cleave — the callback owns
/// which, so core never decodes a plane type. Boxed as a trait object so the neutral methods take one
/// uniform argument regardless of the closure's captures (the per-scope framing/digests_scope).
pub(crate) type Reframe<'a, R> = dyn Fn(&str, &[u8]) -> StoreResult<R> + 'a;

impl<R: NeutralRecord> Journal<R> {
    /// Resolve a NOT-cached scope's position on the neutral path (the [`Journal::resume_missing`]
    /// analogue): before any eviction a miss is a first-seen scope (fresh chain, no store read); after
    /// one, a miss might be an evicted scope whose tail lives in the store, so it reads the tail back
    /// (reframing each body) and resumes from it rather than forking at seq 1.
    fn resume_scoped(
        &self,
        kind: &str,
        scope: &str,
        reframe: &Reframe<'_, R>,
    ) -> Result<Chain<R>, JournalError> {
        if !self.overflowed.load(Ordering::Relaxed) {
            return Ok(Chain::new());
        }
        let Some(store) = self.sink() else {
            return Ok(Chain::new());
        };
        let bodies = store
            .list_plane_records(kind, &PlaneSelector::Parent(scope.to_string()))
            .map_err(JournalError::Store)?;
        if bodies.is_empty() {
            return Ok(Chain::new());
        }
        let records: Vec<R> = bodies
            .iter()
            .map(|body| reframe(scope, body))
            .collect::<StoreResult<_>>()
            .map_err(JournalError::Store)?;
        Ok(Chain::from_persisted(&records)
            .unwrap_or_else(|_brk| Chain::from_persisted_unverified(&records)))
    }

    /// APPEND one neutral record: chain it to MINT the sequence and link (the SOLE chain authority),
    /// persist the neutral `{seq, prev_hash, hash, content}` envelope under `kind`/`scope`, and advance
    /// the position only once the durable write succeeded — the SAME write-ordering the typed
    /// [`Journal::record`] holds, so a failed write does not burn a sequence.
    pub(crate) fn append_scoped(
        &self,
        kind: &str,
        scope: &str,
        input: R::Input,
        reframe: &Reframe<'_, R>,
    ) -> Result<R, JournalError> {
        let mut positions = self.positions();
        let mut candidate = match positions.get(scope) {
            Some(chain) => chain.clone(),
            None => self.resume_scoped(kind, scope, reframe)?,
        };
        let record = candidate.append(scope, input);
        if let Some(store) = self.sink() {
            let body = NeutralBody {
                seq: record.seq(),
                prev_hash: record.prev_hash().to_string(),
                hash: record.hash().to_string(),
                content: record.content().to_vec(),
            };
            let envelope = PlaneRecord {
                kind: kind.to_string(),
                id: scope.to_string(),
                parent: Some(scope.to_string()),
                seq: record.seq(),
                ts: 0,
                disposition: PlaneDisposition::Active,
                body: encode(&body).map_err(JournalError::Store)?,
            };
            store
                .append_plane_record(&envelope)
                .map_err(JournalError::Store)?;
        }
        Self::commit_position(&mut positions, &self.overflowed, self.cap, scope, candidate);
        Ok(record)
    }

    /// BOOT REHYDRATE on the neutral path (the [`Journal::restore_from_store`] analogue): enumerate the
    /// scopes the store holds `kind` records for, reframe each scope's bodies, resume its chain from the
    /// persisted tail, and REPORT what was found (empty scopes + chain breaks) without logging. A broken
    /// chain is reported and STILL resumed from its tail, never re-based onto a fresh chain.
    pub(crate) fn restore_scoped(
        &self,
        kind: &str,
        store: &dyn PlaneStore,
        reframe: &Reframe<'_, R>,
    ) -> StoreResult<Restored> {
        let scopes = store.list_plane_record_parents(kind)?;
        let mut out = Restored::default();
        let mut positions = self.positions();
        for scope in &scopes {
            let records: Vec<R> = store
                .list_plane_records(kind, &PlaneSelector::Parent(scope.clone()))?
                .iter()
                .map(|body| reframe(scope, body))
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

    /// Read one scope's rows back from the store (reframed), oldest-first — the cold read the neutral
    /// `journal_read` window scans. Returns every stored row for the scope; the caller windows it.
    pub(crate) fn read_scoped(
        &self,
        kind: &str,
        scope: &str,
        store: &dyn PlaneStore,
        reframe: &Reframe<'_, R>,
    ) -> StoreResult<Vec<R>> {
        store
            .list_plane_records(kind, &PlaneSelector::Parent(scope.to_string()))?
            .iter()
            .map(|body| reframe(scope, body))
            .collect()
    }

    /// VERIFY one scope's persisted chain (reframed), returning the break if any and `None` when it
    /// verifies — the neutral analogue of the boot-verify walk, for a `verify_task_chain`-style seam.
    pub(crate) fn verify_scoped(
        &self,
        kind: &str,
        scope: &str,
        store: &dyn PlaneStore,
        reframe: &Reframe<'_, R>,
    ) -> StoreResult<Option<ChainBreak>> {
        let records = self.read_scoped(kind, scope, store, reframe)?;
        Ok(verify_chain(&records).err())
    }

    /// RETENTION on the neutral path (the [`Journal::compact`] analogue): ask the sink to drop `kind`
    /// records older than `before`. Positions are NOT reset, exactly as the typed path — reopening a
    /// scope at seq 1 after a purge would collide with a sequence the store may still hold.
    pub(crate) fn compact_scoped(&self, kind: &str, before: u64) -> StoreResult<u64> {
        match self.sink() {
            Some(store) => store.purge_plane_records_before(kind, before),
            None => Ok(0),
        }
    }
}

#[cfg(test)]
#[path = "tests/journal_tests.rs"]
mod journal_tests;
