// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE GENERIC SCOPE-KEYED JOURNAL — the durable seq-authority state machine, in core, naming no
//! plane.
//!
//! ## What this is
//!
//! Every registered durable stream ([`crate::audit::stream_registry`]: the admin audit log, the
//! usage residual log, and each stream a plane registers over the host seam) keeps its chain
//! positions here: an in-RAM per-scope POSITION CACHE, a bounded LRU over it, a store-resume of an
//! evicted or forgotten tail, a write-through SINK, and the WRITE-ORDERING invariant that a position
//! is committed only after the durable append succeeds. By the owner's ruling (see [`crate::audit`])
//! auditing is CORE, so this lives here, once, generic over the record type: a stream supplies its
//! RECORD (which fields, which framing — [`crate::audit::ChainedRecord`]) and the journal persists
//! the neutral `{seq, prev_hash, hash, content}` body ([`NeutralBody`]).
//!
//! It names no plane noun: the type parameter is `R`, the scope is a `&str`, the kind is runtime
//! data, and the store is the narrow [`PlaneStore`] seam.
//!
//! ## The write-ordering invariant, stated once
//!
//! [`Journal::append_scoped`] appends to the in-RAM chain to MINT the sequence and link, writes the
//! sealed row through the durable sink, and only THEN commits the advanced position. Committing first
//! and writing after would leave the process believing a record exists that a restart will un-happen
//! and — worse for a hash chain — burn a sequence number nothing occupies, so the next successful
//! write lands on a `seq` the verifier reports as a gap forever. On a failed write the position is
//! left exactly where it was, so the next call reuses the sequence and the chain stays contiguous.
//!
//! ## A broken tail is reported, never refused
//!
//! A boot seed ([`Journal::seed_position`]) verifies the records its caller read back and returns
//! the break for the caller to report in its own words; a broken chain still resumes from its tail
//! (via [`Chain::from_persisted_unverified`]): refusing to restore a tamper-detected chain would
//! convert a detection control into a deletion primitive.
//!
//! The RUNTIME resume path holds to the same rule. A scope evicted from the LRU (or forgotten) and
//! then written to again reads its persisted tail back to resume ([`Journal::resume_scoped`]); if
//! that tail no longer verifies it is the same tamper evidence, found after boot rather than at it.
//! The break is RECORDED on the journal ([`Journal::take_resume_breaks`] drains it) instead of
//! discarded — the resume still proceeds from the tail, but the evidence is never silently dropped.
//!
//! ## No store call under the position map
//!
//! The store is plugin code, and no plugin code runs under a host lock (BUSBAR-1.6.0.md §11.13 M1).
//! So the position map is held only to read a position or commit one, never across a store call:
//! an append CLAIMS its scope ([`Journal::claim`]), reads the cached position, crosses the store
//! with the map released, then commits. The claim orders writers of ONE scope (two appends to a
//! scope cannot both build on the same position); appends to OTHER scopes of the kind never wait
//! on it, and a store that appends to another scope from inside its own write cannot deadlock.
//!
//! ## A same-scope wait has a deadline
//!
//! A second writer of a claimed scope waits for the first one's store crossing, but never past
//! [`CLAIM_WAIT`]. The admin audit log writes ONE scope, so without a deadline one slow store write
//! would park every admin mutation's audit write, and whichever thread made it (a runtime worker
//! included), for as long as the store took. On the deadline the append is refused with a store
//! error and commits nothing, exactly like a failed durable write: the position is untouched, the
//! next append reuses the sequence, and the caller handles it as it handles any failed write (the
//! admin audit log queues the record and lands it on its next successful write).

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread::ThreadId;
use std::time::{Duration, Instant};

use indexmap::IndexMap;

use crate::audit::{Chain, ChainBreak, ChainedRecord};
use crate::store::plane_view::{encode, PlaneStore};
use busbar_contract::records::{
    PlaneDisposition, PlaneRecord, PlaneSelector, RecordStoreError, RecordStoreResult,
};

/// The longest an append waits for ANOTHER thread's store crossing on the same scope before it is
/// refused (see the module docs). Far above any healthy store write, so only a stalled store reaches
/// it.
const CLAIM_WAIT: Duration = Duration::from_secs(5);

/// Why a journal write could not be made durable. ONE variant today: the durable append failed. It is
/// SURFACED rather than swallowed — an evidence record that is not durable is one a restart will lose,
/// and the caller has to be able to decide whether that is acceptable for what it is recording.
#[derive(Debug)]
pub(crate) enum JournalError {
    /// The durable write failed.
    Store(RecordStoreError),
}

impl std::fmt::Display for JournalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JournalError::Store(e) => write!(f, "{e}"),
        }
    }
}

/// TEST ONLY: WHAT A WHOLE-STORE REHYDRATE ([`Journal::restore_scoped`]) FOUND, reported rather
/// than summed. Production seeds each scope through [`Journal::seed_position`]; the tests read a
/// stream back through this to check what a store holds. Neutral field names: a plane wrapper
/// renames these into its own operator vocabulary (`principals`, `active`, …) and emits its own
/// diagnostics from the two that are bad news.
#[cfg(test)]
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
    /// Records the reframe callback could NOT decode — a body the store held but this build cannot
    /// read back (a format from a store no released build wrote, or a corrupt row). Counted and
    /// SKIPPED per-record rather than allowed to abort the whole rehydrate: dropping every other
    /// scope's working set because one row would not decode is strictly worse than losing the one row,
    /// exactly as a chain break is tolerated per-scope rather than refused wholesale.
    pub(crate) unreadable: usize,
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
    /// Chain breaks the RUNTIME resume path detected and RECORDED rather than discarded. A scope
    /// evicted from the LRU then written to again reads its persisted tail back; if that tail fails to
    /// verify it is TAMPER EVIDENCE, exactly the kind [`Journal::seed_position`] returns for the boot
    /// seed. The runtime path has no caller waiting on a return value, so it is accumulated here
    /// instead of dropped — the resume STILL proceeds from the tail (refusing would convert a
    /// detection control into a deletion primitive), but the break is never silently lost. A wrapper
    /// drains it via [`Journal::take_resume_breaks`] and reports it in its own vocabulary; the
    /// journal itself does not judge.
    resume_breaks: Mutex<Vec<ChainBreak>>,
    /// The scopes whose store crossing is running right now, each with the thread running it. An
    /// append holds its scope here (never the position map) while the store answers,
    /// so a second writer of the SAME scope waits on [`Journal::released`] and every other scope
    /// proceeds. The thread is kept so a store that re-enters its own scope on the same thread is
    /// refused instead of waiting on itself forever.
    claimed: Mutex<HashMap<String, ThreadId>>,
    /// Signalled whenever a claim is released.
    released: Condvar,
    /// The deadline on waiting for another thread's claim: [`CLAIM_WAIT`], shortened only by tests.
    claim_wait: Duration,
}

/// One scope's claim on its store crossing. Dropping it, on success, on error and on unwind alike,
/// releases the scope and wakes the writers waiting on it.
struct ScopeClaim<'a> {
    claimed: &'a Mutex<HashMap<String, ThreadId>>,
    released: &'a Condvar,
    scope: String,
}

impl Drop for ScopeClaim<'_> {
    fn drop(&mut self) {
        self.claimed
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&self.scope);
        self.released.notify_all();
    }
}

impl<R: ChainedRecord> Journal<R> {
    /// A journal with an LRU bound of `cap` scope positions. `cap == usize::MAX` disables eviction.
    pub(crate) fn new(cap: usize) -> Self {
        Journal {
            positions: Mutex::new(IndexMap::new()),
            overflowed: AtomicBool::new(false),
            sink: Mutex::new(None),
            cap,
            resume_breaks: Mutex::new(Vec::new()),
            claimed: Mutex::new(HashMap::new()),
            released: Condvar::new(),
            claim_wait: CLAIM_WAIT,
        }
    }

    /// TEST ONLY: replace [`CLAIM_WAIT`] so a cell can watch the deadline fire without waiting
    /// seconds for it.
    #[cfg(test)]
    pub(crate) fn set_claim_wait(&mut self, wait: Duration) {
        self.claim_wait = wait;
    }

    /// CLAIM `scope` for one store crossing: wait while another thread holds it, then hold it until
    /// the returned claim drops. Only the claim map is locked, and only to test and mark it; the
    /// wait releases it. The wait is bounded by [`Journal::claim_wait`] from entry, however many
    /// releases of other scopes wake it meanwhile; past it the claim is refused, so no caller stays
    /// parked behind another thread's store crossing. A claim the CALLING thread already holds is
    /// refused at once: that is a store re-entering the journal for the scope it is writing, which
    /// would otherwise wait on itself.
    fn claim(&self, scope: &str) -> RecordStoreResult<ScopeClaim<'_>> {
        let me = std::thread::current().id();
        let deadline = Instant::now() + self.claim_wait;
        let mut claimed = self.claimed.lock().unwrap_or_else(PoisonError::into_inner);
        loop {
            let holder = claimed.get(scope).copied();
            match holder {
                None => break,
                Some(owner) if owner == me => {
                    return Err(RecordStoreError(
                        "a journal scope was re-entered from inside its own store call on the same \
                         thread; refused rather than waiting on itself"
                            .to_string(),
                    ));
                }
                Some(_) => {
                    let left = deadline.saturating_duration_since(Instant::now());
                    if left.is_zero() {
                        return Err(RecordStoreError(
                            "a journal scope stayed claimed by another thread's store write past \
                             the claim deadline; refused rather than waiting on it without end"
                                .to_string(),
                        ));
                    }
                    claimed = self
                        .released
                        .wait_timeout(claimed, left)
                        .unwrap_or_else(PoisonError::into_inner)
                        .0;
                }
            }
        }
        claimed.insert(scope.to_string(), me);
        Ok(ScopeClaim {
            claimed: &self.claimed,
            released: &self.released,
            scope: scope.to_string(),
        })
    }

    /// Commit `chain` as `scope`'s position under a short hold of the position map.
    fn commit(&self, scope: &str, chain: Chain<R>) {
        let mut positions = self.positions();
        Self::commit_position(&mut positions, &self.overflowed, self.cap, scope, chain);
    }

    /// Drain the chain breaks the RUNTIME resume path recorded since the last drain — the runtime
    /// analogue of the break [`Journal::seed_position`] returns at boot. A wrapper calls this to
    /// report resume-time tamper evidence in its own vocabulary; the breaks are TAKEN, so each is
    /// reported once. Empty when no evicted scope's persisted tail failed to verify on resume.
    pub(crate) fn take_resume_breaks(&self) -> Vec<ChainBreak> {
        std::mem::take(&mut *self.resume_breaks.lock().unwrap_or_else(|e| e.into_inner()))
    }

    /// Poison-recovering lock. The data behind it stays consistent after a panic (the critical
    /// sections only mutate a map of chain positions), and cascading a poison would make every
    /// subsequent write panic too — a data plane that wedges permanently because one request panicked.
    fn positions(&self) -> MutexGuard<'_, IndexMap<String, Chain<R>>> {
        self.positions.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The attached durable sink, if any.
    pub(crate) fn sink(&self) -> Option<Arc<dyn PlaneStore>> {
        self.sink.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Attach the configured durable store as the write-through SINK. Called once at boot.
    pub(crate) fn set_sink(&self, store: Arc<dyn PlaneStore>) {
        *self.sink.lock().unwrap_or_else(|e| e.into_inner()) = Some(store);
    }

    /// Commit `chain` as `scope`'s current position and record it as the MOST-recently-used, evicting
    /// the coldest scope(s) from the front while the map exceeds [`Journal::cap`]. Shared by the write
    /// hot path and the boot seed so both keep the same bound and the same recency discipline. An
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

    /// THE ONE RESUME of a NOT-cached scope: before any eviction a miss is
    /// a first-seen scope (fresh chain, no store read); after one, with a sink attached, it reads the
    /// scope's `kind` tail back (each body turned into a record by `read`) and resumes from it.
    ///
    /// A break here is TAMPER EVIDENCE surfaced at RUNTIME: this scope was evicted from the LRU and
    /// its persisted tail, read back to resume, no longer verifies. Resume from the tail regardless,
    /// never re-based onto a fresh chain — the same judgement [`Journal::seed_position`] makes —
    /// but RECORD the break rather than discard it, so it is never silently
    /// dropped (an evict-then-resume can happen long after boot).
    fn resume_from_store(
        &self,
        kind: &str,
        scope: &str,
        read: impl Fn(&[u8]) -> RecordStoreResult<R>,
    ) -> Result<Chain<R>, JournalError> {
        if !self.overflowed.load(Ordering::Relaxed) {
            return Ok(Chain::new());
        }
        let Some(store) = self.sink() else {
            return Ok(Chain::new());
        };
        let bodies = store
            .list_plane_records(kind, &PlaneSelector::Parent(scope.into()))
            .map_err(JournalError::Store)?;
        if bodies.is_empty() {
            return Ok(Chain::new());
        }
        let records: Vec<R> = bodies
            .iter()
            .map(|body| read(body))
            .collect::<RecordStoreResult<_>>()
            .map_err(JournalError::Store)?;
        Ok(match Chain::from_persisted(&records) {
            Ok(chain) => chain,
            Err(brk) => {
                self.resume_breaks
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(brk);
                Chain::from_persisted_unverified(&records)
            }
        })
    }

    /// SEED one scope's position from records the CALLER already read — the boot restore every
    /// registered stream runs ([`crate::audit::stream_registry::seed`]). Verifies and REPORTS a break
    /// (the broken chain still resumes from its tail via [`Chain::from_persisted_unverified`]);
    /// returns the break for the caller to log in its own vocabulary, or `None` when the chain
    /// verifies.
    pub(crate) fn seed_position(&self, scope: &str, records: &[R]) -> Option<ChainBreak> {
        let (chain, brk) = match Chain::from_persisted(records) {
            Ok(c) => (c, None),
            Err(b) => (Chain::from_persisted_unverified(records), Some(b)),
        };
        self.commit(scope, chain);
        brk
    }

    /// DROP one scope's cached position, so its next append reads the persisted tail back. The admin
    /// audit log calls it when its boot restore could not read the store, so its first append
    /// continues the persisted chain instead of opening a second one at seq 1 (Q128 p12#2). A forget
    /// IS an eviction, so it latches `overflowed` exactly as the LRU in [`Journal::commit_position`]
    /// does: the next write to the scope resumes from the store tail (with a sink) instead of
    /// reopening at seq 1 and forking the durable chain. That latch is the ONLY one a `usize::MAX` stream (every ABI-registered one) ever gets,
    /// since its LRU never evicts. Without a sink there is no durable log, so a fresh chain is honest.
    pub(crate) fn forget(&self, scope: &str) {
        self.positions().shift_remove(scope);
        self.overflowed.store(true, Ordering::Relaxed);
    }

    /// THE ONE APPEND: chain `input` onto `scope`'s position (a cache miss
    /// resolved by `resume`), write the record's `envelope` through when a sink is attached, and
    /// advance the position only once that durable write has succeeded.
    ///
    /// The scope is CLAIMED for the whole append, and the position map is held only to read the
    /// cached position and to commit the new one: the resume read and the durable write cross the
    /// store with no host lock held. The claim is what keeps two appends to one scope from minting
    /// the same sequence; waiting for it is bounded ([`CLAIM_WAIT`]), and a refused claim fails the
    /// append before anything is minted. A failed write commits nothing and FORGETS the scope's
    /// cached position, so the next append resumes from the store's tail: the sequence is reused
    /// when nothing else wrote, and a chain another node of the fleet advanced is continued rather
    /// than refused as a fork on every append after.
    /// The scope may be evicted or forgotten while its write is in flight; the commit then puts the
    /// durable tail back as the most-recently-used position, the same position a resume would read.
    fn append_with(
        &self,
        scope: &str,
        input: R::Input,
        resume: impl FnOnce() -> Result<Chain<R>, JournalError>,
        envelope: impl FnOnce(&R) -> RecordStoreResult<PlaneRecord>,
    ) -> Result<R, JournalError> {
        let _claim = self.claim(scope).map_err(JournalError::Store)?;
        let cached = self.positions().get(scope).cloned();
        let mut candidate = match cached {
            Some(chain) => chain,
            None => resume()?,
        };
        let record = candidate.append(scope, input);
        if let Some(store) = self.sink() {
            let envelope = envelope(&record).map_err(JournalError::Store)?;
            if let Err(e) = store.append_plane_record(envelope.view()) {
                self.forget(scope);
                return Err(JournalError::Store(e));
            }
        }
        self.commit(scope, candidate);
        Ok(record)
    }

    /// TEST ONLY: the sequence the next record for `scope` will carry. 1 for a scope with no cached
    /// position.
    #[cfg(test)]
    pub(crate) fn next_seq(&self, scope: &str) -> u64 {
        self.positions()
            .get(scope)
            .map(Chain::next_seq)
            .unwrap_or(1)
    }

    /// TEST ONLY: how many scope positions this process is holding.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.positions().len()
    }
}

// ── THE NEUTRAL DURABLE PATH — kind/framing/digests_scope as DATA, record shape as a REFRAME ──────
//
// The host serves many streams at once, learns each stream's `kind` at REGISTER time (runtime DATA,
// never a const), and must NAME NO PLANE TYPE. So this surface takes the `kind` as a `&str`, persists
// a NEUTRAL `{seq, prev_hash, hash, content}` body (the stream's `content` is an opaque pre-framed
// suffix carried verbatim), and turns a stored body back into a record through the stream's REFRAME
// callback rather than `serde`-decoding it into a type core would have to name. The chain authority,
// the position cache, the LRU and the write-ordering are the `Journal` machinery above.

/// The NEUTRAL durable body the store-backed journal persists per record — `{seq, prev_hash, hash,
/// content}`, naming no plane type. The journal persists THIS, and a stream's reframe callback is
/// the decode bridge that turns EITHER this shape or a legacy serde row back into a record on
/// restore (so a store still holding old serde rows verifies unchanged).
#[derive(serde::Serialize, serde::Deserialize)]
pub struct NeutralBody {
    /// The chain sequence the host minted for this record.
    pub seq: u64,
    /// The link to the previous record (empty at genesis).
    pub prev_hash: String,
    /// This record's sealed digest.
    pub hash: String,
    /// The plane's OPAQUE pre-framed content suffix (the bytes the digest appends RAW).
    pub content: Vec<u8>,
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
pub(crate) type Reframe<'a, R> = dyn Fn(&str, &[u8]) -> RecordStoreResult<R> + 'a;

impl<R: NeutralRecord> Journal<R> {
    /// Resolve a NOT-cached scope's position: before any eviction a miss is a first-seen scope
    /// (fresh chain, no store read); after one, a miss might be an evicted scope whose tail lives in
    /// the store, so it reads the tail back (reframing each body) and resumes from it rather than
    /// forking at seq 1.
    fn resume_scoped(
        &self,
        kind: &str,
        scope: &str,
        reframe: &Reframe<'_, R>,
    ) -> Result<Chain<R>, JournalError> {
        self.resume_from_store(kind, scope, |body| reframe(scope, body))
    }

    /// APPEND one neutral record: chain it to MINT the sequence and link (the SOLE chain authority),
    /// persist the neutral `{seq, prev_hash, hash, content}` envelope under `kind`/`scope`, and advance
    /// the position only once the durable write succeeded, so a failed write does not burn a
    /// sequence.
    pub(crate) fn append_scoped(
        &self,
        kind: &str,
        scope: &str,
        input: R::Input,
        reframe: &Reframe<'_, R>,
    ) -> Result<R, JournalError> {
        let envelope = |record: &R| -> RecordStoreResult<PlaneRecord> {
            let body = NeutralBody {
                seq: record.seq(),
                prev_hash: record.prev_hash().to_string(),
                hash: record.hash().to_string(),
                content: record.content().to_vec(),
            };
            Ok(PlaneRecord {
                kind: kind.to_string(),
                id: scope.to_string(),
                parent: Some(scope.to_string()),
                seq: record.seq(),
                // The real write instant, not chained/digested (the hash covers `seq`/`prev_hash`/
                // `hash`/`content` only — see `NeutralBody` — so stamping this changes no sealed
                // byte, only an existing sidecar column that was previously left unset). Read
                // through the composition-root-injected clock seam every other core call site uses
                // (`busbar_kernel::store::now()`, whose body is in
                // `crates/busbar-kernel/src/store/vocab.rs`), never `SystemTime::now()`
                // directly. A hardcoded `ts: 0` here made every row look infinitely old to
                // `purge_plane_records_before`'s `r.ts < before` check, so the FIRST retention sweep
                // deleted the whole class regardless of how recently it was written — the configured
                // retention window was not merely wrong, it was absent.
                ts: busbar_kernel::store::now(),
                disposition: PlaneDisposition::Active,
                body: encode(&body)?,
            })
        };
        self.append_with(
            scope,
            input,
            || self.resume_scoped(kind, scope, reframe),
            envelope,
        )
    }

    /// TEST ONLY: a WHOLE-STORE REHYDRATE: enumerate the
    /// scopes the store holds `kind` records for, reframe each scope's bodies, resume its chain from the
    /// persisted tail, and REPORT what was found (empty scopes + chain breaks) back on [`Restored`]. A
    /// broken chain is reported and STILL resumed from its tail, never re-based onto a fresh chain. The
    /// ONE thing this method logs directly is an UNDECODABLE row, at the skip site with a coded
    /// diagnostic: a silently lost evidence row must never be invisible, so it is surfaced loudly here
    /// rather than left to ride only on the `unreadable` aggregate a wrapper might not log.
    #[cfg(test)]
    pub(crate) fn restore_scoped(
        &self,
        kind: &str,
        store: &dyn PlaneStore,
        reframe: &Reframe<'_, R>,
    ) -> RecordStoreResult<Restored> {
        let scopes = store.list_plane_record_parents(kind)?;
        let mut out = Restored::default();
        for scope in &scopes {
            // The scope is claimed, not the position map, while the store answers and the bodies
            // are reframed.
            let _claim = self.claim(scope)?;
            // Reframe per-record: an undecodable body is SKIPPED and counted, never `?`-aborted —
            // aborting here would drop every scope after this one, the all-or-nothing failure a
            // chain break is already spared from. The skip is reported LOUDLY at the site with a
            // coded diagnostic (the peer of the chain-break report below), so a silently lost
            // evidence row is never invisible; `unreadable` still carries the count back for the
            // wrapper's aggregate. This is the one place this "reports, does not judge" journal
            // speaks in a coded word — mirroring a downstream task store's per-row skip report.
            let raw =
                store.list_plane_records(kind, &PlaneSelector::Parent(scope.as_str().into()))?;
            // Whether the store literally returned NOTHING for this scope, decided BEFORE decoding:
            // an enumerated-but-empty scope (a wholesale deletion of one scope's evidence) is a
            // different condition from a scope whose rows were all UNREADABLE, which is already
            // counted-and-reported into `unreadable`. Only the former is an `empty_scope`.
            let store_returned_nothing = raw.is_empty();
            let mut records: Vec<R> = Vec::new();
            for body in raw {
                match reframe(scope, &body) {
                    Ok(r) => records.push(r),
                    Err(e) => {
                        out.unreadable += 1;
                        crate::diagnostics::diag_error!(
                            crate::diagnostics::PLANE_JOURNAL_ROW_UNREADABLE,
                            scope = %scope,
                            error = %e,
                            "a persisted journal record could NOT be reframed on restore; it is being \
                             SKIPPED and counted rather than aborting the whole rehydrate (which would \
                             drop every other scope's working set). The evidence in this one row is \
                             lost — reported here, never skipped silently."
                        );
                    }
                }
            }
            if records.is_empty() {
                if store_returned_nothing {
                    out.empty_scopes.push(scope.clone());
                }
                self.commit(scope, Chain::new());
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
            self.commit(scope, chain);
            out.scopes += 1;
        }
        Ok(out)
    }

    /// TEST ONLY: read one scope's rows back from the store (reframed), oldest-first.
    #[cfg(test)]
    pub(crate) fn read_scoped(
        &self,
        kind: &str,
        scope: &str,
        store: &dyn PlaneStore,
        reframe: &Reframe<'_, R>,
    ) -> RecordStoreResult<Vec<R>> {
        store
            .list_plane_records(kind, &PlaneSelector::Parent(scope.into()))?
            .iter()
            .map(|body| reframe(scope, body))
            .collect()
    }

    /// TEST ONLY: verify one scope's persisted chain (reframed), returning the break if any and
    /// `None` when it verifies.
    #[cfg(test)]
    pub(crate) fn verify_scoped(
        &self,
        kind: &str,
        scope: &str,
        store: &dyn PlaneStore,
        reframe: &Reframe<'_, R>,
    ) -> RecordStoreResult<Option<ChainBreak>> {
        let records = self.read_scoped(kind, scope, store, reframe)?;
        Ok(crate::audit::verify_chain(&records).err())
    }

    /// RETENTION (the host seam's `journal_compact`): ask the sink to drop `kind` records older than
    /// `before`. The policy (the window) lives at the call site; this owns only the mechanism.
    /// Positions are NOT reset — reopening a scope at seq 1 after a purge would collide with a
    /// sequence the store may still hold. A chain stream is purged by age (`Retention::Age`): its
    /// records carry no settledness. Test-only since its one production caller (the deleted
    /// plane-host journal slot) went.
    #[cfg(test)]
    pub(crate) fn compact_scoped(&self, kind: &str, before: u64) -> RecordStoreResult<u64> {
        match self.sink() {
            Some(store) => {
                store.purge_plane_records(kind, before, busbar_contract::records::Retention::Age)
            }
            None => Ok(0),
        }
    }
}

#[cfg(test)]
#[path = "tests/journal_tests.rs"]
mod journal_tests;

#[cfg(test)]
#[path = "tests/journal_lock_tests.rs"]
mod journal_lock_tests;
