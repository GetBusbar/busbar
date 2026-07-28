// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The admin AUDIT log — every admin MUTATION is recorded, success AND failure, so a credential
//! probing the surface or an operator asking "who changed what" leaves a trail.
//!
//! This is the in-memory MVP: a bounded ring of entries behind a process-global. Audit is process-wide
//! state (NOT config-derived), so it lives as a global rather than on the swappable `App` snapshot —
//! it survives a config apply naturally. The DURABLE + hash-chained store (SQLite now, SIEM via a
//! `kind: tap` later) is an additive follow-up behind an `AuditStore` trait; the record/read shape here
//! is the stable seam it will implement.

use serde::Serialize;

/// One admin audit record. `outcome` is a stable token tooling can branch on. The record is
/// HASH-CHAINED for tamper-EVIDENCE: `hash = sha256(prev_hash | seq | ts | action | resource |
/// outcome | principal)`, and `prev_hash` is the preceding entry's `hash`. Recomputing the chain detects any
/// altered/reordered/deleted entry (detection, not prevention — a compromised host can still rewrite
/// the whole chain; prevention is shipping the log off-box to a SIEM).
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub(crate) struct AuditEntry {
    /// Monotonic sequence number (1-based), unique within a process lifetime.
    pub(crate) seq: u64,
    /// Unix seconds when the mutation was attempted.
    pub(crate) ts: u64,
    /// The action, `noun.verb` (e.g. `hook.register`, `hook.delete`).
    pub(crate) action: String,
    /// The resource acted on (e.g. `hook:compress`). Never a secret.
    pub(crate) resource: String,
    /// Stable outcome token: `applied` (mutation committed) | `rejected` (validation/conflict, nothing
    /// changed).
    pub(crate) outcome: String,
    /// WHO — the authenticated principal id that attempted the mutation (`admin` for the operator
    /// token; a virtual-key id or an external module's principal id otherwise; `anonymous` for the
    /// explicit open admin posture). Attribution, never a credential.
    pub(crate) principal: String,
    /// The preceding entry's `hash` (empty for the first entry of the process, or the oldest retained
    /// entry whose predecessor was pruned).
    pub(crate) prev_hash: String,
    /// `sha256(prev_hash | seq | ts | action | resource | outcome | principal)` — the tamper-evidence digest.
    pub(crate) hash: String,
    /// TRUE only for entries THIS process appended via `record_by`. Seeded entries — from the file
    /// snapshot or from the durable store — are FALSE. This is the ONLY thing that distinguishes an
    /// entry the durable store already holds from one it has never seen; every seq-threshold proxy
    /// for it (`seq <= durable_max` and its predecessors) is wrong on some boot path, because the two
    /// populations are not seq-separable once the sequence counter has been floored to the durable max
    /// (see `rebase_nondurable_suffix`).
    ///
    /// Every site that FILLS the ring asserts this itself: `record_by` sets it true, `from_record`
    /// (the store-seeding path) sets it false. `#[serde(skip)]` gives the right default (false) on the
    /// encoded paths, but `load` is ALSO reachable in-process from `export()`, where no encoding
    /// happens — so `load` clears it explicitly and the attribute is only belt-and-braces. Do not
    /// delete the clear in `load` on the grounds that serde already handles it.
    #[serde(skip)]
    pub(crate) recorded_here: bool,
}

impl AuditEntry {
    /// Recompute this entry's digest from its fields — the verification primitive.
    fn compute_hash(&self) -> String {
        let canonical = format!(
            "{}|{}|{}|{}|{}|{}|{}",
            self.prev_hash,
            self.seq,
            self.ts,
            self.action,
            self.resource,
            self.outcome,
            self.principal
        );
        crate::sigv4::sha256_hex(canonical.as_bytes())
    }
}

/// Outcome tokens (kept small + stable).
pub(crate) const OUTCOME_APPLIED: &str = "applied";
pub(crate) const OUTCOME_REJECTED: &str = "rejected";

/// How many entries the in-memory ring retains. Bounds RAM, not history — a durable sink keeps the
/// full log. `pub(crate)` so a test asking for "every matching row that can exist" names this rather
/// than a hand-picked page size that silently truncates once a filter matches more rows.
pub(crate) const MAX_AUDIT_ENTRIES: usize = 1000;

/// The pressure valve threshold in `record_by`: once the un-persisted tail (`seq - durable_high`)
/// reaches this many entries, the recorder stops trusting the periodic write-behind flusher and
/// pays the store round-trip INLINE again — restoring, exactly where the ring is at risk of pruning
/// an entry the store never saw, the backpressure that an unconditional inline write applies
/// everywhere today.
///
/// Sized as `MAX_AUDIT_ENTRIES / 4` (750, leaving a 250-entry reserve) so it comfortably exceeds the
/// number of threads that can be simultaneously PAST the valve check and still in flight toward
/// `record_by`'s ring push before the trip re-arms blocking — since `record_by` blocks on
/// `durable_lock` (a real `std::sync::Mutex`, which PARKS the calling Tokio worker OS thread rather
/// than yielding) once tripped, that population is bounded by the number of Tokio worker OS threads,
/// not by concurrent admin-request count (the admin surface itself has no concurrency cap — see
/// `main.rs`'s `MAX_WORKER_THREADS` clamp, the actual enforced bound this reserve depends on).
/// busbar is single-operator (PIPELINE-BRIEF: no multi-tenant trust boundary, no per-caller
/// concurrency limit on the admin surface), so there is no adversarial population that could scale
/// concurrent `record_by` callers toward this reserve — a single operator's console/CLI/automation
/// realistically tops out at low tens of concurrent admin mutations, and the worker-thread clamp
/// below keeps the hard ceiling at 128, well under 250.
const WRITE_THROUGH_HEADROOM: u64 = (MAX_AUDIT_ENTRIES - MAX_AUDIT_ENTRIES / 4) as u64;

/// Convert an in-memory [`AuditEntry`] to the store-seam [`busbar_api::AuditRecord`] (same fields).
/// The store persists records verbatim — the hash chain is computed here, in the engine.
fn to_record(e: &AuditEntry) -> busbar_api::AuditRecord {
    busbar_api::AuditRecord {
        seq: e.seq,
        ts: e.ts,
        action: e.action.clone(),
        resource: e.resource.clone(),
        outcome: e.outcome.clone(),
        principal: e.principal.clone(),
        prev_hash: e.prev_hash.clone(),
        hash: e.hash.clone(),
    }
}

/// Convert a store-seam [`busbar_api::AuditRecord`] back to an in-memory [`AuditEntry`].
fn from_record(r: busbar_api::AuditRecord) -> AuditEntry {
    AuditEntry {
        seq: r.seq,
        ts: r.ts,
        action: r.action,
        resource: r.resource,
        outcome: r.outcome,
        principal: r.principal,
        prev_hash: r.prev_hash,
        hash: r.hash,
        // This is the store-seeding path (`restore_from_store`): the store already held this entry
        // before this process started, so it is never renumbered by `rebase_nondurable_suffix`.
        recorded_here: false,
    }
}

/// The in-memory audit ring. `record` is append-only + bounded (FIFO prune of the oldest — a hot
/// cache of the recent tail); `list` returns most-recent-first. When a DURABLE store sink is attached
/// (store.module: sqlite/postgres/redis), each appended entry is ALSO write-through-persisted to
/// the store, which keeps the FULL history (never pruned) — so the ring's size bound bounds RAM, not
/// history, and a hard crash loses ~0 entries instead of up to a snapshot interval. With the RAM
/// default (`store: memory`) no sink is attached and the log stays ephemeral, exactly as before.
/// Interior-mutable so it can be a shared global.
pub(crate) struct AuditLog {
    entries: std::sync::Mutex<std::collections::VecDeque<AuditEntry>>,
    seq: std::sync::atomic::AtomicU64,
    /// The durable sink, attached once at boot when a durable store is configured. Best-effort: a
    /// write-through failure logs a warning but NEVER fails the admin mutation (the RAM ring still
    /// holds the entry; the periodic state snapshot is a second safety net). `None` = ephemeral.
    sink: std::sync::Mutex<Option<std::sync::Arc<dyn busbar_api::Store>>>,
    /// The highest CONTIGUOUS seq known to be durably persisted (0 = none yet). The write-through
    /// backfills from `durable_high + 1` up to each new entry's seq, so a TRANSIENT `append_audit`
    /// failure that previously left a permanent gap now heals: the next successful write-through
    /// catches up the skipped seq(s) from the RAM ring, keeping the durable hash chain CONTIGUOUS
    /// (which the strict `restore_from_store` linkage check requires). Serialized by `durable_lock`.
    durable_high: std::sync::atomic::AtomicU64,
    /// Serializes the write-through (backfill + append) so two concurrent recorders cannot interleave
    /// their catch-up writes and re-introduce a gap or write a seq out of order to the store.
    durable_lock: std::sync::Mutex<()>,
    /// Set when this process's RING is not yet reconciled with the durable tail: either the boot
    /// restore could not READ the durable log (a transient store error, so the durable max seq is
    /// unknown), or it read the log but the chain failed VERIFICATION (so the tail it read cannot be
    /// trusted as the anchor). Either way the sequence floor and the anchor hash for
    /// `rebase_nondurable_suffix` are not known good, so the write-through refuses to append: the
    /// sequence counter may sit below what the store already holds, and appending would OVERWRITE
    /// existing durable history at those seqs (the durable write is keyed on `seq`), silently
    /// destroying the append-only guarantee. Each write-through first RETRIES the tail read, so the
    /// log self-heals — reconciling the ring's nondurable suffix onto the recovered tail — the moment
    /// the store answers with a tail that verifies.
    durable_unreconciled: std::sync::atomic::AtomicBool,
}

impl AuditLog {
    const fn new() -> Self {
        Self {
            entries: std::sync::Mutex::new(std::collections::VecDeque::new()),
            seq: std::sync::atomic::AtomicU64::new(1),
            sink: std::sync::Mutex::new(None),
            durable_high: std::sync::atomic::AtomicU64::new(0),
            durable_lock: std::sync::Mutex::new(()),
            durable_unreconciled: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Attach the durable store sink (boot only). The last set wins. Passing a store whose
    /// `list_audit`/`append_audit` are the trait defaults (no durable audit — the memory store or an
    /// old plugin) is harmless: write-throughs no-op and restore reads nothing.
    pub(crate) fn set_sink(&self, store: std::sync::Arc<dyn busbar_api::Store>) {
        *self.sink.lock().unwrap_or_else(|e| e.into_inner()) = Some(store);
    }

    /// Restore the ring FROM the durable store at boot (the store is the source of truth when one is
    /// configured): load every persisted record, verify the hash chain, seed the ring (bounded to the
    /// most recent `MAX_AUDIT_ENTRIES` for the hot read path), and resume the sequence after the
    /// highest restored seq. Returns `Ok(count)` restored (0 = nothing to restore / no durable audit),
    /// or `Err` if the chain fails verification (a tamper signal — the caller logs it and falls back to
    /// the file snapshot).
    pub(crate) fn restore_from_store(
        &self,
        store: &dyn busbar_api::Store,
    ) -> Result<usize, String> {
        // BOUNDED read (audit issue): the durable log is never pruned and can dwarf the RAM ring; over
        // the plugin ABI the full list can exceed the response cap or OOM. Restore only the most-recent
        // `MAX_AUDIT_ENTRIES` - exactly what the ring keeps - so the read is bounded regardless of how
        // large the durable history grew. The tail is the NEWEST records, so its max seq IS the durable
        // max (the seq floor below stays correct), and tamper-evidence is verified over the loaded tail
        // (internal linkage + the tail head's self-digest). `list_audit_tail` bounds at the source for a
        // durable backend and falls back to `list_audit` + truncation for an older plugin.
        let records = match store.list_audit_tail(MAX_AUDIT_ENTRIES as u64) {
            Ok(r) => r,
            Err(e) => {
                // THE SEQ FLOOR MUST NOT BE BYPASSED. A transient read
                // error here used to return early, and the caller then fell back to the file
                // snapshot — whose `load` floors the counter only to the SNAPSHOT's max, which can
                // be far below what the store already holds (or, with no snapshot at all, leaves
                // the counter at 1). The durable write-through is keyed on `seq`, so the next
                // mutations would append AT seqs the store already occupies and OVERWRITE existing
                // history: an append-only/contiguity violation caused by a store blip.
                //
                // We cannot floor to a max we could not read, so instead we SEAL the durable
                // write-through until the floor is known. `durable_write_through` retries the floor
                // read on every mutation, so this self-heals as soon as the store answers.
                self.durable_unreconciled
                    .store(true, std::sync::atomic::Ordering::SeqCst);
                return Err(format!("audit restore read failed: {}", e.0));
            }
        };
        // The read SUCCEEDED, so the durable floor IS known (an empty log floors at 0) — but the
        // chain has not been VERIFIED yet, so this clear can still be overwritten by the
        // verify-fail arms below before this function returns.
        self.durable_unreconciled
            .store(false, std::sync::atomic::Ordering::SeqCst);
        if records.is_empty() {
            return Ok(0);
        }
        let entries: Vec<AuditEntry> = records.into_iter().map(from_record).collect();
        // FLOOR the sequence to the store's max BEFORE verification, so even a chain-verification
        // failure (where the caller falls back to a possibly-stale file snapshot) can never leave
        // the counter rewound below what the store already holds. The durable write-through is
        // keyed on `seq`, so a rewound counter would silently OVERWRITE existing durable history on
        // the next mutation; flooring here makes new entries always append past the durable max.
        let durable_max = entries.iter().map(|e| e.seq).max().unwrap_or(0);
        self.seq
            .fetch_max(durable_max + 1, std::sync::atomic::Ordering::Relaxed);
        // Seed the durable-catch-up watermark: the store already holds a contiguous chain through
        // `durable_max`, so the write-through backfill starts appending at `durable_max + 1`.
        self.durable_high
            .fetch_max(durable_max, std::sync::atomic::Ordering::Relaxed);
        // Verify the full restored chain BEFORE trusting it (tamper-evidence across restart): every
        // entry's digest recomputes, and each links to its predecessor. The first restored entry's
        // predecessor may pre-date what we hold, so only its self-digest is checked.
        let mut prev: Option<&str> = None;
        for e in &entries {
            if e.hash != e.compute_hash() {
                // The floor above is trustworthy (the read succeeded), but the TAIL is not — a
                // digest mismatch means the caller cannot rely on this entry's hash as the anchor
                // for `rebase_nondurable_suffix`. Seal until a later read confirms a verifying tail.
                self.durable_unreconciled
                    .store(true, std::sync::atomic::Ordering::SeqCst);
                return Err(format!(
                    "restored audit entry seq {} fails its digest",
                    e.seq
                ));
            }
            if let Some(p) = prev {
                if e.prev_hash != p {
                    // Same reasoning: the chain doesn't LINK, so the tail cannot anchor a rebase
                    // either. Seal until the write-through's retried read finds a verifying tail.
                    self.durable_unreconciled
                        .store(true, std::sync::atomic::Ordering::SeqCst);
                    return Err(format!(
                        "restored audit chain breaks at seq {} (prev_hash mismatch)",
                        e.seq
                    ));
                }
            }
            prev = Some(&e.hash);
        }
        let total = entries.len();
        // Seed the ring with the most-recent MAX_AUDIT_ENTRIES (the durable store keeps the rest).
        // The sequence was already floored past the durable max above.
        let tail_start = total.saturating_sub(MAX_AUDIT_ENTRIES);
        let mut q = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        q.clear();
        q.extend(entries.into_iter().skip(tail_start));
        Ok(total)
    }

    /// Record one mutation attempt. Never fails (a poisoned lock is recovered — losing the audit log
    /// to a panic would be worse than proceeding). Bounded RAM ring: prunes the oldest past the cap
    /// (the durable sink, when present, keeps the pruned tail). WITH principal attribution (:
    /// every mutation, success AND failure, attributed to WHO attempted it).
    pub(crate) fn record_by(
        &self,
        action: &str,
        resource: &str,
        outcome: &'static str,
        principal: &str,
    ) {
        // Allocate `seq` INSIDE the entries lock so it matches insertion order: fetching it before
        // the lock let two concurrent recorders interleave (thread B takes the lock with the higher
        // seq and pushes first, thread A pushes its lower seq behind it), producing out-of-order
        // seq numbers in the ring. Under the lock, Relaxed is sufficient (the mutex is the ordering
        // point).
        let record = {
            let mut q = self.entries.lock().unwrap_or_else(|e| e.into_inner());
            let seq = self.seq.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            // Chain to the most recent entry (the back), before any prune.
            let prev_hash = q.back().map(|e| e.hash.clone()).unwrap_or_default();
            let mut entry = AuditEntry {
                seq,
                ts: crate::store::now(),
                action: action.to_string(),
                resource: resource.to_string(),
                outcome: outcome.to_string(),
                principal: principal.to_string(),
                prev_hash,
                hash: String::new(),
                // THIS process is appending it right now — the one ground-truth site for provenance.
                recorded_here: true,
            };
            entry.hash = entry.compute_hash();
            while q.len() >= MAX_AUDIT_ENTRIES {
                q.pop_front();
            }
            // Snapshot the store-seam record while the seq/chain are fixed, for the write-through
            // below (done OUTSIDE the entries lock so a slow store never blocks other recorders).
            let record = to_record(&entry);
            q.push_back(entry);
            record
        };
        // Write-through to the durable sink (best-effort): the store keeps the FULL history so a hard
        // crash loses ~0 entries and pruning the RAM ring never loses durable history. A failure is
        // logged and swallowed - an audit-store hiccup must NEVER fail the admin mutation it records
        // (the RAM ring already holds it, and the periodic snapshot is a second net). No sink (memory
        // default) ⇒ no-op, ephemeral as before.
        //
        // OFF THE REACTOR IN THE COMMON CASE: the periodic write-behind flusher
        // (`governance::spawn_budget_flusher`, which now also calls `flush_durable`) owns this write
        // by default, so `record_by` returns immediately instead of blocking a Tokio worker on a
        // synchronous store round-trip. The PRESSURE VALVE below re-arms the inline write exactly
        // where skipping it would be unsafe.
        let sink = self.sink.lock().unwrap_or_else(|e| e.into_inner()).clone();
        if let Some(store) = sink {
            let unpersisted = record
                .seq
                .saturating_sub(self.durable_high.load(std::sync::atomic::Ordering::Relaxed));
            // No runtime (unit tests without a `#[tokio::test]`, `--validate`, or a boot-time caller
            // before the flusher is spawned) means no flusher will ever drain this ring, so the
            // recorder must do the write itself or the entry is never durable at all. This is a
            // proxy for "is a flusher currently draining this ring", verified by inspection of
            // today's call graph (nothing calls `record_by` with a `Handle` but no flusher spawned)
            // rather than an invariant this check itself enforces — see WRITE_THROUGH_HEADROOM.
            let no_flusher = tokio::runtime::Handle::try_current().is_err();
            if no_flusher || unpersisted >= WRITE_THROUGH_HEADROOM {
                self.durable_write_through(store.as_ref(), record.seq);
            }
            // Otherwise: headroom remains, the write-behind flusher owns this seq. Return immediately
            // without touching the store.
        }
    }

    /// RESILIENT durable write-through with GAP BACKFILL (audit chain-corruption fix). A TRANSIENT
    /// `append_audit` failure used to be swallowed while the mutation still succeeded, leaving a
    /// PERMANENT hole in the durable chain (seq N missing, N+1 present with `prev_hash` pointing at N):
    /// on restart the strict contiguous linkage check in [`restore_from_store`] hits the gap, rejects
    /// the whole durable chain, and the boot falls back to the stale file snapshot - silently
    /// discarding all durable audit history. This never self-heals.
    ///
    /// Instead of writing only `new_seq`, catch up the durable chain from `durable_high + 1` up TO AND
    /// INCLUDING `new_seq`, pulling each entry from the authoritative RAM ring. So a write that failed
    /// on seq N (leaving `durable_high = N-1`) is retried on the NEXT successful mutation: it appends N
    /// (from the ring) then N+1, keeping the durable chain CONTIGUOUS. Serialized by `durable_lock` so
    /// concurrent recorders can't interleave their catch-up writes. Best-effort throughout: any append
    /// error stops the catch-up, logs, and leaves `durable_high` where it is so the next mutation
    /// retries from the same point (the mutation itself never fails). If the gap is older than the ring
    /// bound (many consecutive failures), the un-recoverable seq(s) simply stay missing - the ring is
    /// the only in-process source - but a single transient hiccup can no longer corrupt the chain.
    /// Renumber the ring's NON-DURABLE suffix — every entry whose seq the store has not confirmed —
    /// onto consecutive seqs above `durable_max`, re-chained to `anchor_hash` (the durable tail).
    /// Returns the highest seq assigned, or `None` if nothing needed rebasing. Caller holds
    /// `durable_lock`.
    ///
    /// The suffix is taken by POSITION, not by `seq <= durable_max`: a concurrent `record_by` may
    /// already have appended an above-floor entry chained to one of the stranded hashes, and leaving
    /// it behind would break the chain at the join instead of at the skip. Rewriting the whole
    /// suffix in ring order keeps it contiguous by construction.
    ///
    /// The position itself is `recorded_here`, not a seq comparison: seeded entries (from a file
    /// snapshot or the durable store) and live entries THIS process appended are not seq-separable
    /// once the counter has been floored to the durable max — a `seq <= durable_max` predicate matches
    /// the SEEDED prefix instead of the live suffix and renumbers the wrong entries onto the durable
    /// range, duplicating them on the next backfill. The ring's invariant makes this well-defined:
    /// seeded entries are always cleared-then-extended in one shot and live entries are only ever
    /// `push_back`ed, so the `recorded_here` entries are always a contiguous suffix of the ring, and
    /// pruning (`pop_front`-only) can only shrink the seeded prefix, never split the suffix.
    ///
    /// No store I/O happens here — the entries lock is never held across a store call.
    fn rebase_nondurable_suffix(&self, durable_max: u64, anchor_hash: &str) -> Option<u64> {
        let mut q = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let first = q.iter().position(|e| e.recorded_here)?;
        // A seq must never move DOWN. `durable_max + 1` alone is right only when the durable tail is
        // at or above the ring's live head; with an empty or lagging tail (e.g. a seal against a
        // store that has never been written to) it would renumber a live entry ONTO a seeded seq
        // still in the ring, breaking the ring's seq-sorted invariant and making the backfill's
        // `find(|e| e.seq == seq)` ambiguous.
        let mut next_seq = std::cmp::max(durable_max + 1, q[first].seq);
        let mut prev = if next_seq == durable_max + 1 {
            anchor_hash.to_string()
        } else {
            // The ring holds `next_seq - 1` (a seeded entry the backfill will persist from this same
            // ring), so the head's existing link is already correct — overwriting it with the
            // durable tail's hash would MANUFACTURE a break instead of closing one.
            q[first].prev_hash.clone()
        };
        for entry in q.iter_mut().skip(first) {
            entry.seq = next_seq;
            entry.prev_hash = prev.clone();
            entry.hash = entry.compute_hash();
            prev = entry.hash.clone();
            next_seq += 1;
        }
        self.seq
            .fetch_max(next_seq, std::sync::atomic::Ordering::Relaxed);
        Some(next_seq - 1)
    }

    /// Drain every pending (not-yet-durable) entry up to the ring's current head in ONE
    /// write-through call. Called from the periodic write-behind flusher
    /// (`governance::spawn_budget_flusher`) instead of inline from `record_by` — see the pressure
    /// valve in `record_by` for why this is safe: `durable_write_through`'s unit of work is already
    /// a RANGE (`durable_high + 1 ..= new_seq`), so one call here persists every seq the flusher
    /// missed since the last tick, exactly like `flush_budgets`/`flush_metering` coalesce their own
    /// deltas. A no-op when there is no sink (ephemeral `store: memory`) or nothing pending.
    pub(crate) fn flush_durable(&self) {
        let sink = self.sink.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let Some(store) = sink else {
            return;
        };
        let top = self
            .entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .back()
            .map(|e| e.seq);
        if let Some(top) = top {
            self.durable_write_through(store.as_ref(), top);
        }
    }

    fn durable_write_through(&self, store: &dyn busbar_api::Store, mut new_seq: u64) {
        let _serial = self.durable_lock.lock().unwrap_or_else(|e| e.into_inner());
        // SEALED while this process's ring is not yet reconciled with the durable tail (the boot
        // restore's read failed, or it read but the chain failed verification): appending now could
        // overwrite durable history at seqs the store already holds, or anchor to a tail that isn't
        // trustworthy. Retry the tail read first — one small read — so the log heals (and rebases its
        // nondurable suffix onto the recovered anchor) as soon as the store answers with a tail that
        // verifies.
        if self
            .durable_unreconciled
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            match store.list_audit_tail(1) {
                Ok(tail) => {
                    // The tail's HASH, not just its seq: it is the authoritative predecessor for
                    // whatever gets appended next. Chaining the resumed range to the RAM ring's back
                    // instead is what welds a break into the durable chain.
                    let anchor = tail.iter().max_by_key(|r| r.seq);
                    let durable_max = anchor.map(|r| r.seq).unwrap_or(0);
                    let anchor_hash = anchor.map(|r| r.hash.clone()).unwrap_or_default();
                    self.durable_high
                        .fetch_max(durable_max, std::sync::atomic::Ordering::Relaxed);
                    // Entries recorded while the floor was unknown hold seqs BELOW it — seqs the
                    // store already occupies with DIFFERENT entries. They are RAM-only (never
                    // persisted), so renumbering them above the floor rewrites no durable history;
                    // it resolves an identity collision that would otherwise strand them forever.
                    // This call's captured `new_seq` names a seq that no longer exists once the
                    // suffix is renumbered, so the backfill target moves with it.
                    if let Some(top) = self.rebase_nondurable_suffix(durable_max, &anchor_hash) {
                        new_seq = top;
                    }
                    self.seq
                        .fetch_max(durable_max + 1, std::sync::atomic::Ordering::Relaxed);
                    self.durable_unreconciled
                        .store(false, std::sync::atomic::Ordering::SeqCst);
                    tracing::info!(
                        durable_max,
                        resume_at = new_seq,
                        "durable audit floor recovered; resuming the write-through above it"
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e.0,
                        "durable audit write-through skipped: this process's ring is not yet \
                         reconciled with the durable tail (the boot restore did not read or verify \
                         it, and this retry read failed too). The entry is retained in the RAM ring \
                         + state snapshot; writing now could overwrite durable history."
                    );
                    return;
                }
            }
        }
        // The backfill starts after the last CONFIRMED durable seq. It is deliberately NOT clamped
        // up to the ring's oldest retained seq: `durable_high` sitting below the ring means either
        // (a) a genuinely unpersisted, now-pruned seq — a real hole, where halting is the whole
        // point — or (b) a watermark that was never seeded, which is a RESTORE bug
        // and is fixed where it belongs, in `load`/`restore_from_store`. Clamping
        // here would paper over (a) and manufacture a false-contiguous durable tail.
        // SINGLE-WRITER CHECK. The durable audit log has exactly ONE legitimate writer: seqs are
        // allocated process-locally, so a second busbar pointed at the same store reaches for the
        // same seqs and the store's keyed upsert destroys whichever row loses. The next boot then
        // reports the resulting break as tamper evidence. Nothing reads the durable log across
        // nodes — `GET /audit` serves the RAM ring — so a second writer buys nothing and costs
        // history.
        //
        // A tail ahead of what THIS node last persisted can only be another writer. Checked on
        // every write-through, not once: the other node may boot at any time. The cost is one small
        // tail read per admin mutation, on a path that is rate-limited and already does a store
        // round-trip to append. A read error is not evidence of anything, so it is left to the
        // existing floor machinery rather than treated as a second writer.
        let persisted = self.durable_high.load(std::sync::atomic::Ordering::Relaxed);
        if let Ok(tail) = store.list_audit_tail(1) {
            let observed = tail.iter().map(|r| r.seq).max().unwrap_or(0);
            if observed > persisted {
                tracing::error!(
                    observed_tail = observed,
                    this_node_persisted = persisted,
                    "durable audit log has another writer — detaching this node's durable sink. It \
                     supports exactly ONE writer; two nodes sharing it overwrite each other's \
                     entries and break the hash chain, which the next boot reports as tampering. \
                     This node keeps auditing to its in-memory ring and state snapshot."
                );
                *self.sink.lock().unwrap_or_else(|e| e.into_inner()) = None;
                return;
            }
        }

        let start = self.durable_high.load(std::sync::atomic::Ordering::Relaxed) + 1;
        if new_seq < start {
            // This entry's seq is BELOW the durable floor. With `rebase_nondurable_suffix` always
            // returning a top `>= durable_max + 1` and `start = durable_high + 1` (`durable_high >=
            // durable_max` once the recovery branch above has run), this is NOT the floor-recovery
            // mutation itself — that case is already resolved by the rebase. It is the ordinary
            // concurrent-recorder race: a second recorder allocated a HIGHER seq, won `durable_lock`
            // first, and its backfill already persisted (and advanced `durable_high` past) THIS
            // seq — so writing it now would be a redundant, stale keyed upsert. Skipping is correct:
            // this entry is already durable under its own seq.
            tracing::warn!(
                seq = new_seq,
                durable_floor = start,
                "durable audit write-through skipped: this entry's seq predates the recovered \
                 durable floor (it is retained in the RAM ring + state snapshot)"
            );
            return;
        }
        for seq in start..=new_seq {
            // Source the record for `seq` from the RAM ring (the authoritative in-process copy).
            let record = {
                let q = self.entries.lock().unwrap_or_else(|e| e.into_inner());
                q.iter().find(|e| e.seq == seq).map(to_record)
            };
            let Some(record) = record else {
                // `seq` has already been pruned from the ring (a gap older than the ring bound); it
                // can NEVER be backfilled in-process. STOP the catch-up here and leave `durable_high`
                // BELOW the hole — do NOT `continue`, or the next successful append advances
                // `durable_high` PAST the unpersisted seq and claims a durable chain that has a hole
                // at `seq`, which is then never re-attempted. Only genuinely-persisted seqs (the
                // `fetch_max` after a successful `append_audit` below) may advance `durable_high`.
                tracing::warn!(
                    seq,
                    durable_high = self.durable_high.load(std::sync::atomic::Ordering::Relaxed),
                    "durable audit backfill: seq no longer in the RAM ring; the durable chain has an \
                     unrepairable gap here — stopping catch-up and holding durable_high below the hole"
                );
                return;
            };
            if let Err(e) = store.append_audit(&record) {
                tracing::warn!(
                    seq,
                    action = %record.action,
                    error = %e.0,
                    "durable audit write-through failed (entry retained in the in-memory ring + state \
                     snapshot; will backfill on the next successful write-through)"
                );
                // Stop the catch-up here; `durable_high` stays put so the next mutation retries from
                // this seq, keeping the durable chain contiguous once the store recovers.
                return;
            }
            self.durable_high
                .fetch_max(seq, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// Export the retained ring, oldest first — the persistence snapshotter's input (D3).
    pub(crate) fn export(&self) -> Vec<AuditEntry> {
        let q = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        q.iter().cloned().collect()
    }

    /// Seed the ring from a persisted snapshot (boot restore). Replaces the current contents and
    /// resumes the sequence AFTER the highest restored seq, so post-restart entries chain onto the
    /// restored history without seq reuse. FLOOR semantics (fetch_max, never store): a file
    /// snapshot can lag the durable store, and the durable write-through is keyed on `seq` — a
    /// blind store here would rewind the counter below the store's max and the next mutation would
    /// silently OVERWRITE durable history. The snapshot only ever RAISES the counter.
    pub(crate) fn load(&self, mut entries: Vec<AuditEntry>) {
        // `load` IS the seeding path by definition: whatever it is handed came from OUTSIDE this
        // process's append stream, even when the `Vec` was produced by this process's OWN `export()`
        // (the in-process restart-simulation path in tests, and any future in-process reconcile).
        // `#[serde(skip)]` only clears provenance on an encoded round-trip; this path never encodes,
        // so it must clear it explicitly or `rebase_nondurable_suffix` would renumber these as if they
        // were never persisted.
        for e in &mut entries {
            e.recorded_here = false;
        }
        let mut q = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let max_seq = entries.iter().map(|e| e.seq).max().unwrap_or(0);
        q.clear();
        q.extend(entries);
        self.seq
            .fetch_max(max_seq + 1, std::sync::atomic::Ordering::Relaxed);
        // Seed the durable CATCH-UP watermark too. This path only runs when the
        // durable restore did NOT supply the ring, i.e. the snapshot IS the most complete history
        // this process has. Leaving `durable_high` at 0 aimed the next write-through's backfill at
        // seq 1 — which the restored ring cannot supply once it has been pruned — so the catch-up
        // hit the unrepairable-gap branch immediately and durable audit stayed dead for the life of
        // the process. `fetch_max` only ever RAISES it, so a floor already learned from the store
        // (which is authoritative) wins.
        //
        // Seeded to the OLDEST retained seq minus one, not the highest: the snapshot is evidence of
        // what the RING holds, never of what the STORE holds. Claiming the whole range as durable
        // meant a switch to a fresh store (memory → sqlite) never backfilled any of it, and those
        // entries were lost from both sources at the next restart. One below the oldest is exactly
        // the range the ring can still supply.
        let backfill_floor = q.iter().map(|e| e.seq).min().unwrap_or(0).saturating_sub(1);
        self.durable_high
            .fetch_max(backfill_floor, std::sync::atomic::Ordering::Relaxed);
    }

    /// Verify the tamper-evidence chain over the RETAINED entries: every entry's `hash` recomputes
    /// from its fields, and each entry links to its predecessor (`prev_hash == predecessor.hash`). The
    /// oldest retained entry's `prev_hash` may point to a pruned digest, so its link is not checked —
    /// only its self-digest. Returns `true` if intact. Used by the tamper test; a live tamper-alert
    /// endpoint is a follow-up.
    #[cfg(test)]
    pub(crate) fn verify(&self) -> bool {
        let q = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let mut prev: Option<&str> = None;
        for e in q.iter() {
            if e.hash != e.compute_hash() {
                return false;
            }
            if let Some(p) = prev {
                if e.prev_hash != p {
                    return false;
                }
            }
            prev = Some(&e.hash);
        }
        true
    }

    /// A page of entries newest-first, optionally filtered by exact `action` and/or `resource`:
    /// skip `offset`, then take `limit`. `None` filters match everything.
    /// The transport fetches `limit + 1` to detect whether a further page exists (the cursor envelope).
    pub(crate) fn list_filtered(
        &self,
        offset: usize,
        limit: usize,
        action: Option<&str>,
        resource: Option<&str>,
    ) -> Vec<AuditEntry> {
        let q = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        q.iter()
            .rev()
            .filter(|e| action.is_none_or(|a| e.action == a))
            .filter(|e| resource.is_none_or(|r| e.resource == r))
            .skip(offset)
            .take(limit)
            .cloned()
            .collect()
    }

    /// The most-recent `limit` entries, newest first (unfiltered).
    #[cfg(test)]
    pub(crate) fn list(&self, limit: usize) -> Vec<AuditEntry> {
        self.list_filtered(0, limit, None, None)
    }
}

/// The process-wide admin audit log. Const-constructed, so no lazy init needed.
pub(crate) static AUDIT: AuditLog = AuditLog::new();

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn export_load_roundtrip_resumes_chain() {
        let log = AuditLog::new();
        log.record_by("hook.register", "hook:a", OUTCOME_APPLIED, "admin");
        log.record_by("hook.delete", "hook:a", OUTCOME_REJECTED, "admin");
        let exported = log.export();
        assert_eq!(exported.len(), 2);

        // Restore into a fresh log (a fresh boot): chain intact, sequence resumes AFTER max seq.
        let restored = AuditLog::new();
        restored.load(exported);
        assert!(restored.verify(), "restored chain must verify");
        restored.record_by("hook.register", "hook:b", OUTCOME_APPLIED, "admin");
        let all = restored.list(10);
        assert_eq!(all.len(), 3);
        assert!(
            all[0].seq > all[1].seq,
            "post-restore entries continue the sequence"
        );
        assert!(
            restored.verify(),
            "chain still verifies across the restore boundary"
        );
    }

    #[test]
    fn record_and_list_newest_first() {
        let log = AuditLog::new();
        log.record_by("hook.register", "hook:a", OUTCOME_APPLIED, "admin");
        log.record_by("hook.delete", "hook:a", OUTCOME_APPLIED, "admin");
        let entries = log.list(10);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].action, "hook.delete", "newest first");
        assert!(entries[0].seq > entries[1].seq, "monotonic seq");
    }

    #[test]
    fn hash_chain_links_and_verifies() {
        let log = AuditLog::new();
        log.record_by("hook.register", "hook:a", OUTCOME_APPLIED, "admin");
        log.record_by("hook.register", "hook:b", OUTCOME_REJECTED, "admin");
        log.record_by("hook.delete", "hook:a", OUTCOME_APPLIED, "admin");
        assert!(log.verify(), "an untouched chain verifies");

        // Each entry (oldest→newest) links to its predecessor's hash.
        let q = log.entries.lock().unwrap();
        assert_eq!(q[0].prev_hash, "", "first entry has no predecessor");
        assert_eq!(q[1].prev_hash, q[0].hash);
        assert_eq!(q[2].prev_hash, q[1].hash);
        drop(q);

        // Tamper: mutate a recorded field in place → verification fails.
        {
            let mut q = log.entries.lock().unwrap();
            q[1].resource = "hook:evil".to_string();
        }
        assert!(!log.verify(), "a tampered entry breaks the chain");
    }

    // ── durable audit through the configured Store (#17) ─────────────────────────────────────────

    use busbar_api::Store;
    use std::sync::Arc;

    /// WRITE-THROUGH + RESTORE across a simulated restart, over the REAL SQLite store. A first process
    /// records N mutations with the store attached as the sink (each write-through persisted); a fresh
    /// process (fresh `AuditLog`, SAME store) restores from it — the chain verifies, the entries are
    /// intact, and the sequence resumes after the max restored seq. This is the durable roundtrip.
    #[test]
    fn durable_write_through_and_restore_roundtrip() {
        let store: Arc<dyn Store> =
            Arc::new(busbar_store_sqlite::SqliteStore::open_in_memory().unwrap());

        // Process 1: record through the sink.
        let log1 = AuditLog::new();
        log1.set_sink(store.clone());
        log1.record_by("hook.register", "hook:a", OUTCOME_APPLIED, "admin");
        log1.record_by("plugin.install", "plugin:x", OUTCOME_APPLIED, "admin");
        log1.record_by("hook.delete", "hook:a", OUTCOME_REJECTED, "admin");

        // The store durably holds all three, in order, with the chain intact.
        let persisted = store.list_audit().unwrap();
        assert_eq!(persisted.len(), 3);
        assert_eq!(persisted[0].seq, 1);
        assert_eq!(persisted[2].action, "hook.delete");

        // Process 2 (a "restart"): a fresh log restores FROM the store.
        let log2 = AuditLog::new();
        let n = log2
            .restore_from_store(store.as_ref())
            .expect("restore + chain verify");
        assert_eq!(n, 3, "all three durable entries restored");
        assert!(log2.verify(), "restored chain verifies across the restart");

        // Sequence resumes AFTER the max restored seq: a new entry chains onto the restored tail.
        log2.set_sink(store.clone());
        log2.record_by("hook.register", "hook:b", OUTCOME_APPLIED, "admin");
        let all = log2.list(10);
        assert_eq!(all[0].action, "hook.register");
        assert!(all[0].seq > 3, "post-restore seq continues (> 3)");
        assert!(
            log2.verify(),
            "chain still verifies after the post-restore append"
        );
        // And the store now has 4 (the write-through of the post-restore entry landed).
        assert_eq!(store.list_audit().unwrap().len(), 4);
    }

    /// A REWOUND sequence counter must never clobber durable history. The durable write-through is
    /// keyed on `seq` (idempotent-replay upsert in the store), so if a boot path seeds the counter
    /// from a STALE file snapshot (fewer entries than the store holds — e.g. after a failed
    /// durable restore), the next mutation would reuse a durable seq and silently overwrite that
    /// entry. Both hydration paths floor instead: `restore_from_store` floors past the durable max
    /// even when chain verification fails, and `load` only ever raises the counter.
    #[test]
    fn rewound_seq_cannot_overwrite_durable_history() {
        let store: Arc<dyn Store> =
            Arc::new(busbar_store_sqlite::SqliteStore::open_in_memory().unwrap());

        // Process 1: three durable entries (seq 1..=3).
        let log1 = AuditLog::new();
        log1.set_sink(store.clone());
        log1.record_by("hook.register", "hook:a", OUTCOME_APPLIED, "admin");
        log1.record_by("hook.register", "hook:b", OUTCOME_APPLIED, "admin");
        log1.record_by("hook.delete", "hook:a", OUTCOME_APPLIED, "admin");
        assert_eq!(store.list_audit().unwrap().len(), 3);

        // Tamper the durable chain so the restart's durable restore FAILS and the boot path falls
        // back to a stale file snapshot holding only seq 1 (the rewind scenario).
        {
            let mut tampered = store.list_audit().unwrap();
            tampered[1].resource = "hook:evil".to_string();
            store.append_audit(&tampered[1]).unwrap();
        }
        let stale_snapshot: Vec<AuditEntry> = store
            .list_audit()
            .unwrap()
            .into_iter()
            .take(1)
            .map(from_record)
            .collect();

        // Process 2 (the restart): sink attached, durable restore fails on the broken chain, and
        // the stale snapshot is loaded — exactly the boot fallback ordering in main.rs.
        let log2 = AuditLog::new();
        log2.set_sink(store.clone());
        assert!(
            log2.restore_from_store(store.as_ref()).is_err(),
            "the tampered chain must fail verification"
        );
        log2.load(stale_snapshot);

        // The next mutation must APPEND past the durable max (seq 4), not reuse seq 2 and clobber
        // the existing durable entry.
        log2.record_by("hook.register", "hook:c", OUTCOME_APPLIED, "admin");
        let persisted = store.list_audit().unwrap();
        // The count/seq/untouched-entry assertions below are REGRESSION PROOFS (they already pass at
        // HEAD via the seq floor at :200-201, unrelated to change B) — kept to show B does not
        // disturb them.
        assert_eq!(persisted.len(), 4, "durable history grew; nothing replaced");
        assert_eq!(
            persisted.last().unwrap().seq,
            4,
            "the new entry appended past the durable max"
        );
        assert_eq!(
            persisted[2].action, "hook.delete",
            "the pre-existing seq-3 entry is untouched"
        );
        // THE RED ASSERTION (change B): the new entry's `prev_hash` must join the STORE's durable
        // tail, not whatever stale link the seeded ring happened to carry. At HEAD the verify-fail
        // path never engages the seal, so the recovery branch never runs and the entry chains onto
        // the stale snapshot's seq-1 hash instead of the store's seq-3 hash — a silent linkage break
        // reported as tamper on the NEXT boot, not this one.
        assert_eq!(
            persisted[3].prev_hash, persisted[2].hash,
            "the post-restart entry must re-anchor to the durable tail's actual hash, not the stale \
             snapshot's link"
        );
    }

    /// The verify-fail linkage break, with NO snapshot at all — the branch v2 missed entirely. At
    /// HEAD the ring is empty at record time (nothing was `load`ed), so `record_by`'s `q.back()` is
    /// `None` and the first post-restart entry's `prev_hash` is `""`, not the durable tail's hash — a
    /// silent break identical in kind to the with-snapshot case above, just with a different stale
    /// link (empty instead of the snapshot's).
    #[test]
    fn verify_failure_without_a_snapshot_still_anchors_to_the_durable_tail() {
        let store: Arc<dyn Store> =
            Arc::new(busbar_store_sqlite::SqliteStore::open_in_memory().unwrap());

        let log1 = AuditLog::new();
        log1.set_sink(store.clone());
        log1.record_by("hook.register", "hook:a", OUTCOME_APPLIED, "admin");
        log1.record_by("hook.register", "hook:b", OUTCOME_APPLIED, "admin");
        log1.record_by("hook.delete", "hook:a", OUTCOME_APPLIED, "admin");

        // Tamper so the restart's durable restore fails verification. No `load` follows — no
        // snapshot at all.
        {
            let mut tampered = store.list_audit().unwrap();
            tampered[1].resource = "hook:evil".to_string();
            store.append_audit(&tampered[1]).unwrap();
        }

        let log2 = AuditLog::new();
        log2.set_sink(store.clone());
        assert!(
            log2.restore_from_store(store.as_ref()).is_err(),
            "the tampered chain must fail verification"
        );

        log2.record_by("hook.register", "hook:c", OUTCOME_APPLIED, "admin");
        let persisted = store.list_audit().unwrap();
        assert_eq!(persisted.len(), 4, "durable history grew; nothing replaced");
        assert_eq!(
            persisted.last().unwrap().seq,
            4,
            "the new entry appended past the durable max"
        );
        assert_eq!(
            persisted[3].prev_hash, persisted[2].hash,
            "the post-restart entry must anchor to the durable tail's hash, not an empty prev_hash"
        );
    }

    /// The RAM ring is bounded to `MAX_AUDIT_ENTRIES`, but a durable store keeps the FULL history — so
    /// recording more than the cap prunes the RAM ring WITHOUT losing durable history (the #17 fix:
    /// the size bound bounds RAM, not history). Restoring seeds the ring with the recent tail while the
    /// store retains everything.
    #[test]
    fn durable_store_keeps_history_beyond_the_ram_cap() {
        let store: Arc<dyn Store> =
            Arc::new(busbar_store_sqlite::SqliteStore::open_in_memory().unwrap());
        let log = AuditLog::new();
        log.set_sink(store.clone());
        let total = MAX_AUDIT_ENTRIES + 25;
        for i in 0..total {
            log.record_by(
                "hook.register",
                &format!("hook:{i}"),
                OUTCOME_APPLIED,
                "admin",
            );
        }
        // The RAM ring is capped…
        assert_eq!(
            log.list(usize::MAX).len(),
            MAX_AUDIT_ENTRIES,
            "the RAM ring stays bounded"
        );
        // …but the durable store kept EVERY entry (no history lost to the ring's prune).
        let persisted = store.list_audit().unwrap();
        assert_eq!(
            persisted.len(),
            total,
            "durable store keeps the full history"
        );
        assert_eq!(
            persisted[0].seq, 1,
            "the oldest entry survives in the store"
        );
        assert_eq!(persisted.last().unwrap().seq as usize, total);

        // A restart restores the recent BOUNDED tail into the ring and resumes the sequence past the
        // max. The restore read is bounded to the ring cap (audit bounded-read fix), so it reports the
        // count it LOADED - the tail - not the full (possibly huge) durable history.
        let log2 = AuditLog::new();
        let n = log2.restore_from_store(store.as_ref()).expect("restore");
        assert_eq!(
            n, MAX_AUDIT_ENTRIES,
            "restore loads (and reports) only the bounded tail"
        );
        assert_eq!(
            log2.list(usize::MAX).len(),
            MAX_AUDIT_ENTRIES,
            "the restored ring is bounded to the recent tail"
        );
        assert!(log2.verify(), "the restored tail's chain verifies");
        // The durable store still holds the FULL history - only the RESTORE READ is bounded.
        assert_eq!(
            store.list_audit().unwrap().len(),
            total,
            "the durable store keeps the full history; only the boot read is bounded"
        );
    }

    // ── THE SEQ FLOOR IS NEVER BYPASSED ─────────────────────
    //
    // The durable write-through is keyed on `seq`, so the ONE thing boot must never do is resume
    // with a counter below the durable max. Three ways that used to happen, one class:
    // HIGH-10  a transient `list_audit_tail` failure returned EARLY, before the floor was applied,
    // and the caller fell back to a snapshot that floors only to its own (lower) max;
    // #15      the file-snapshot `load` never seeded `durable_high` at all;
    // #24      the backfill always started at `durable_high + 1`, so a restored ring whose oldest
    // seq is higher hit the unrepairable-gap branch on the first iteration and left the
    // durable log permanently stuck.

    /// A store whose AUDIT READS can be made to fail on demand (a transient backend blip), while
    /// writes and everything else delegate to a real SQLite store.
    struct FlakyAuditReads {
        inner: busbar_store_sqlite::SqliteStore,
        fail_reads: std::sync::atomic::AtomicBool,
    }

    impl FlakyAuditReads {
        fn failing(&self) -> bool {
            self.fail_reads.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl busbar_api::Store for FlakyAuditReads {
        fn put_key(&self, key: &busbar_api::VirtualKey) -> busbar_api::StoreResult<()> {
            self.inner.put_key(key)
        }
        fn get_key(&self, id: &str) -> busbar_api::StoreResult<Option<busbar_api::VirtualKey>> {
            self.inner.get_key(id)
        }
        fn list_keys(&self) -> busbar_api::StoreResult<Vec<busbar_api::VirtualKey>> {
            self.inner.list_keys()
        }
        fn delete_key(&self, id: &str) -> busbar_api::StoreResult<()> {
            self.inner.delete_key(id)
        }
        fn get_usage(
            &self,
            bucket_id: &str,
            window_start: u64,
        ) -> busbar_api::StoreResult<busbar_api::UsageLedger> {
            self.inner.get_usage(bucket_id, window_start)
        }
        fn put_usage(
            &self,
            bucket_id: &str,
            window_start: u64,
            ledger: &busbar_api::UsageLedger,
        ) -> busbar_api::StoreResult<()> {
            self.inner.put_usage(bucket_id, window_start, ledger)
        }
        fn add_metering(&self, delta: &busbar_api::MeteringDelta) -> busbar_api::StoreResult<()> {
            self.inner.add_metering(delta)
        }
        fn list_metering(
            &self,
            bucket: u64,
        ) -> busbar_api::StoreResult<Vec<busbar_api::MeteringRow>> {
            self.inner.list_metering(bucket)
        }
        fn append_audit(&self, record: &busbar_api::AuditRecord) -> busbar_api::StoreResult<()> {
            self.inner.append_audit(record)
        }
        fn list_audit(&self) -> busbar_api::StoreResult<Vec<busbar_api::AuditRecord>> {
            if self.failing() {
                return Err(busbar_api::StoreError("audit read unavailable".into()));
            }
            self.inner.list_audit()
        }
        fn list_audit_tail(
            &self,
            limit: u64,
        ) -> busbar_api::StoreResult<Vec<busbar_api::AuditRecord>> {
            if self.failing() {
                return Err(busbar_api::StoreError("audit read unavailable".into()));
            }
            self.inner.list_audit_tail(limit)
        }
    }

    /// HIGH-10: a TRANSIENT read failure at boot must not let the sequence rewind into durable
    /// history. While the floor is unknown the write-through is SEALED (nothing is written, and
    /// certainly nothing is overwritten); once the store answers again the floor is recovered and
    /// appends resume ABOVE the durable max.
    #[test]
    fn transient_restore_read_failure_cannot_rewind_the_durable_seq() {
        let inner = busbar_store_sqlite::SqliteStore::open_in_memory().unwrap();
        let store = Arc::new(FlakyAuditReads {
            inner,
            fail_reads: std::sync::atomic::AtomicBool::new(false),
        });

        // Process 1: three durable entries (seq 1..=3).
        let log1 = AuditLog::new();
        log1.set_sink(store.clone());
        log1.record_by("hook.register", "hook:a", OUTCOME_APPLIED, "admin");
        log1.record_by("hook.register", "hook:b", OUTCOME_APPLIED, "admin");
        log1.record_by("hook.delete", "hook:a", OUTCOME_APPLIED, "admin");
        assert_eq!(store.list_audit().unwrap().len(), 3);
        let before: Vec<(u64, String)> = store
            .list_audit()
            .unwrap()
            .into_iter()
            .map(|r| (r.seq, r.action))
            .collect();

        // Process 2 (the restart): the store blips, so the restore READ fails. The counter is still
        // at 1 — below the durable max of 3.
        store
            .fail_reads
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let log2 = AuditLog::new();
        log2.set_sink(store.clone());
        assert!(
            log2.restore_from_store(store.as_ref()).is_err(),
            "the read failure surfaces as a restore error"
        );

        // A mutation now: it must NOT write at seq 1/2/3 over the existing durable history.
        log2.record_by("plugin.install", "plugin:x", OUTCOME_APPLIED, "admin");
        // Read PAST the simulated blip (straight off the inner store) to see the durable truth.
        let during: Vec<(u64, String)> = store
            .inner
            .list_audit()
            .unwrap()
            .into_iter()
            .map(|r| (r.seq, r.action))
            .collect();
        assert_eq!(
            during, before,
            "durable history is untouched while the sequence floor is unknown"
        );

        // The store recovers: the next mutation recovers the floor and appends ABOVE the max.
        store
            .fail_reads
            .store(false, std::sync::atomic::Ordering::SeqCst);
        // The first mutation after recovery RECOVERS the floor. The entries recorded while the
        // floor was unknown hold seqs the store already occupies with DIFFERENT entries, so they are
        // renumbered above the floor and persisted — not dropped.
        log2.record_by("plugin.install", "plugin:y", OUTCOME_APPLIED, "admin");
        log2.record_by("plugin.install", "plugin:z", OUTCOME_APPLIED, "admin");
        let after = store.list_audit().unwrap();
        assert_eq!(
            after.len(),
            6,
            "every outage-window entry is persisted, not stranded: 3 originals + x, y, z"
        );
        let landed: Vec<&str> = after.iter().map(|r| r.resource.as_str()).collect();
        assert_eq!(
            &landed[3..],
            &["plugin:x", "plugin:y", "plugin:z"],
            "the outage-window entries kept their ORDER when renumbered"
        );
        assert!(
            after[3].seq > 3,
            "and were renumbered above the durable max, never over it: {:?}",
            after[3].seq
        );
        for (i, (seq, action)) in before.iter().enumerate() {
            assert_eq!((after[i].seq, &after[i].action), (*seq, action));
        }

        // THE POINT OF THE WHOLE FIX: a later boot must verify. Before, the chain was welded to a
        // never-persisted entry, so restore reported a break — a permanent false tamper alarm from
        // one transient read failure.
        let log3 = AuditLog::new();
        log3.set_sink(store.clone());
        let restored = log3
            .restore_from_store(store.as_ref())
            .expect("the durable chain verifies after a transient read failure");
        assert_eq!(restored, 6, "and restores every entry");
    }

    /// THE REPORTED DUPLICATION, via the IN-PROCESS seeding path. `rebase_nondurable_suffix` used to
    /// pick its suffix by `seq <= durable_max`, which matches index 0 whenever the ring's SEEDED
    /// prefix (loaded from a file snapshot / `export()`) sits at seqs the store already holds — so it
    /// renumbers the SEEDED entries instead of the live one behind them, and the backfill re-persists
    /// them as duplicates. Provenance (`recorded_here`), not a seq comparison, is the only thing that
    /// tells the two populations apart.
    ///
    /// Deliberately NOT a hash-uniqueness assertion: `compute_hash` mixes `seq`, so the renumbered
    /// duplicates get FRESH hashes and a hash-uniqueness check would pass on the corrupt state. The
    /// `(action, resource, principal)` triple is the payload identity that must not repeat.
    #[test]
    fn audit_ring_seeded_in_process_is_not_renumbered_onto_durable_history() {
        let inner = busbar_store_sqlite::SqliteStore::open_in_memory().unwrap();
        let store = Arc::new(FlakyAuditReads {
            inner,
            fail_reads: std::sync::atomic::AtomicBool::new(false),
        });

        // Process 1: 5 durable entries with DISTINCT (action, resource) pairs.
        let log1 = AuditLog::new();
        log1.set_sink(store.clone());
        for i in 0..5 {
            log1.record_by(
                "hook.register",
                &format!("hook:{i}"),
                OUTCOME_APPLIED,
                "admin",
            );
        }
        let snapshot = log1.export();
        assert_eq!(snapshot.len(), 5);

        // Process 2: sink attached, reads fail so the boot restore seals (durable floor unknown),
        // then the exported ring is seeded IN-PROCESS via `load` — no serde round-trip.
        let log2 = AuditLog::new();
        log2.set_sink(store.clone());
        store
            .fail_reads
            .store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(
            log2.restore_from_store(store.as_ref()).is_err(),
            "the read failure surfaces as a restore error and engages the seal"
        );
        log2.load(snapshot);

        // The store recovers; the next mutation resumes the write-through, which recovers the floor
        // and rebases whatever the ring's nondurable suffix is.
        store
            .fail_reads
            .store(false, std::sync::atomic::Ordering::SeqCst);
        log2.record_by("plugin.install", "plugin:x", OUTCOME_APPLIED, "admin");

        let persisted = store.list_audit().unwrap();
        assert_eq!(
            persisted.len(),
            6,
            "only the ONE live entry should be added to the 5 already-durable ones"
        );
        assert_eq!(
            persisted.iter().map(|r| r.seq).collect::<Vec<_>>(),
            vec![1, 2, 3, 4, 5, 6],
            "seqs are exactly 1..=6, nothing renumbered onto a duplicate range"
        );
        let mut triples: Vec<(String, String, String)> = persisted
            .iter()
            .map(|r| (r.action.clone(), r.resource.clone(), r.principal.clone()))
            .collect();
        triples.sort();
        triples.dedup();
        assert_eq!(
            triples.len(),
            6,
            "no (action, resource, principal) triple repeats — nothing was duplicated"
        );

        let log3 = AuditLog::new();
        assert_eq!(
            log3.restore_from_store(store.as_ref())
                .expect("the durable chain must still verify"),
            6
        );
    }

    /// #15 + #24: after a FILE-SNAPSHOT restore (the durable restore did not supply the ring), the
    /// next mutation must still reach the durable sink. Before the fix `durable_high` stayed 0, so
    /// the backfill aimed at seq 1 — a seq the restored (pruned) ring cannot supply — hit the
    /// unrepairable-gap branch immediately, and durable audit was dead for the life of the process.
    #[test]
    fn file_snapshot_restore_keeps_the_durable_write_through_alive() {
        // A snapshot of a ring that has already been pruned: it starts at seq 10, not 1.
        let source = AuditLog::new();
        for i in 0..12 {
            source.record_by(
                "hook.register",
                &format!("hook:{i}"),
                OUTCOME_APPLIED,
                "admin",
            );
        }
        let pruned_snapshot: Vec<AuditEntry> = source.export().into_iter().skip(9).collect(); // seq 10..=12

        let store: Arc<dyn Store> =
            Arc::new(busbar_store_sqlite::SqliteStore::open_in_memory().unwrap());
        let log = AuditLog::new();
        log.set_sink(store.clone());
        log.load(pruned_snapshot);

        log.record_by("plugin.install", "plugin:x", OUTCOME_APPLIED, "admin");

        let persisted = store.list_audit().unwrap();
        assert_eq!(
            persisted.len(),
            4,
            "the restored ring is BACKFILLED (seq 10..=12) and the new mutation appended — the \
             snapshot is evidence of what the RING holds, never of what the STORE holds"
        );
        assert_eq!(
            persisted.iter().map(|r| r.seq).collect::<Vec<_>>(),
            vec![10, 11, 12, 13],
            "contiguous from the ring's oldest retained seq"
        );

        // A pruned ring must still not aim the backfill at seq 1 — that hits the unrepairable-gap
        // branch and kills durable audit for the process, which is what seeding to 0 would do.
        let log2 = AuditLog::new();
        log2.set_sink(store.clone());
        assert_eq!(
            log2.restore_from_store(store.as_ref())
                .expect("the backfilled chain verifies"),
            4
        );
    }

    /// REGRESSION PROOF for change C (`max(durable_max + 1, head.seq)`), NOT a RED test against HEAD:
    /// this is GREEN at HEAD by accident (`position(|e| e.seq <= 0)` is `None` there, so the rebase is
    /// a no-op whenever the durable tail is empty). Its RED proof is the INTERMEDIATE build — change A
    /// alone, with a bare `next_seq = durable_max + 1` instead of the `max` — which renumbers a live
    /// entry BELOW a still-present seeded one and violates the ring's seq-sorted invariant.
    #[test]
    fn live_entry_is_never_renumbered_below_a_seeded_one() {
        let inner = busbar_store_sqlite::SqliteStore::open_in_memory().unwrap();
        let store = Arc::new(FlakyAuditReads {
            inner,
            fail_reads: std::sync::atomic::AtomicBool::new(true),
        });

        // Seal against an EMPTY store (the read fails before anything is ever written to it).
        let log = AuditLog::new();
        log.set_sink(store.clone());
        assert!(
            log.restore_from_store(store.as_ref()).is_err(),
            "the read failure surfaces as a restore error and engages the seal"
        );

        // A pruned snapshot seeds the ring at seqs 10..=12 (a file snapshot of a ring that had
        // already dropped its oldest entries).
        let source = AuditLog::new();
        for i in 0..12 {
            source.record_by(
                "hook.register",
                &format!("hook:{i}"),
                OUTCOME_APPLIED,
                "admin",
            );
        }
        let pruned_snapshot: Vec<AuditEntry> = source.export().into_iter().skip(9).collect(); // seq 10..=12
        log.load(pruned_snapshot);

        // The store recovers; the mutation below gets seq 13 and triggers the floor-recovery/rebase
        // path against the now-empty store (`durable_max = 0`).
        store
            .fail_reads
            .store(false, std::sync::atomic::Ordering::SeqCst);
        log.record_by("plugin.install", "plugin:x", OUTCOME_APPLIED, "admin");

        // `export()` is oldest-first (ring insertion order); `list()` is newest-first and would
        // invert this check.
        let ring = log.export();
        let seqs: Vec<u64> = ring.iter().map(|e| e.seq).collect();
        assert!(
            seqs.windows(2).all(|w| w[0] < w[1]),
            "the ring's seq-sorted invariant must hold: {seqs:?}"
        );
        let persisted: Vec<u64> = store.list_audit().unwrap().iter().map(|r| r.seq).collect();
        assert_eq!(
            persisted,
            vec![10, 11, 12, 13],
            "the seeded suffix and the live entry all persist, contiguous and in order"
        );
    }

    /// A memory store (the RAM default — trait-default `append_audit`/`list_audit`) makes durable
    /// audit a no-op: nothing persists and a restore reads nothing, so the log stays ephemeral exactly
    /// as before. This proves the default posture is unchanged.
    #[test]
    fn memory_store_keeps_audit_ephemeral() {
        let store: Arc<dyn Store> = Arc::new(busbar_store_memory::MemoryStore::new());
        let log = AuditLog::new();
        log.set_sink(store.clone());
        log.record_by("hook.register", "hook:a", OUTCOME_APPLIED, "admin");
        // The memory store's default append_audit is a no-op and list_audit is empty.
        assert!(
            store.list_audit().unwrap().is_empty(),
            "memory store persists no audit"
        );
        let log2 = AuditLog::new();
        assert_eq!(
            log2.restore_from_store(store.as_ref()).unwrap(),
            0,
            "nothing to restore from an ephemeral store"
        );
    }

    /// A TAMPERED durable record is rejected on restore (tamper-evidence survives the restart): if a
    /// stored entry's field is altered without recomputing the chain, `restore_from_store` returns an
    /// error rather than silently loading a broken chain.
    #[test]
    fn restore_rejects_a_tampered_durable_chain() {
        let store: Arc<dyn Store> =
            Arc::new(busbar_store_sqlite::SqliteStore::open_in_memory().unwrap());
        let log = AuditLog::new();
        log.set_sink(store.clone());
        log.record_by("hook.register", "hook:a", OUTCOME_APPLIED, "admin");
        log.record_by("hook.delete", "hook:a", OUTCOME_APPLIED, "admin");

        // Tamper: re-write seq 1's resource in the store WITHOUT fixing its hash (append_audit upserts
        // on seq, so this overwrites the stored record in place).
        let mut rec = store
            .list_audit()
            .unwrap()
            .into_iter()
            .find(|r| r.seq == 1)
            .unwrap();
        rec.resource = "hook:evil".to_string();
        store.append_audit(&rec).unwrap();

        let fresh = AuditLog::new();
        assert!(
            fresh.restore_from_store(store.as_ref()).is_err(),
            "a tampered durable record must fail chain verification on restore"
        );
    }

    // ── transient-failure durability + bounded restore ───────────────────────────────────────────

    /// A `Store` decorator over a real SQLite store that FAILS `append_audit` for a configured set of
    /// seqs (simulating a TRANSIENT durable-write hiccup), then behaves normally once those seqs are
    /// cleared. All reads delegate to the inner store. Used to prove the write-through backfill heals a
    /// gap rather than leaving the durable chain permanently corrupt.
    struct FlakyAuditStore {
        inner: busbar_store_sqlite::SqliteStore,
        fail_seqs: std::sync::Mutex<std::collections::HashSet<u64>>,
    }

    impl Store for FlakyAuditStore {
        fn put_key(&self, key: &busbar_api::VirtualKey) -> busbar_api::StoreResult<()> {
            self.inner.put_key(key)
        }
        fn get_key(&self, id: &str) -> busbar_api::StoreResult<Option<busbar_api::VirtualKey>> {
            self.inner.get_key(id)
        }
        fn list_keys(&self) -> busbar_api::StoreResult<Vec<busbar_api::VirtualKey>> {
            self.inner.list_keys()
        }
        fn delete_key(&self, id: &str) -> busbar_api::StoreResult<()> {
            self.inner.delete_key(id)
        }
        fn get_usage(
            &self,
            bucket_id: &str,
            window_start: u64,
        ) -> busbar_api::StoreResult<busbar_api::UsageLedger> {
            self.inner.get_usage(bucket_id, window_start)
        }
        fn put_usage(
            &self,
            bucket_id: &str,
            window_start: u64,
            ledger: &busbar_api::UsageLedger,
        ) -> busbar_api::StoreResult<()> {
            self.inner.put_usage(bucket_id, window_start, ledger)
        }
        fn add_metering(&self, delta: &busbar_api::MeteringDelta) -> busbar_api::StoreResult<()> {
            self.inner.add_metering(delta)
        }
        fn list_metering(
            &self,
            bucket: u64,
        ) -> busbar_api::StoreResult<Vec<busbar_api::MeteringRow>> {
            self.inner.list_metering(bucket)
        }
        fn append_audit(&self, entry: &busbar_api::AuditRecord) -> busbar_api::StoreResult<()> {
            if self.fail_seqs.lock().unwrap().contains(&entry.seq) {
                return Err(busbar_api::StoreError(format!(
                    "injected transient append_audit failure for seq {}",
                    entry.seq
                )));
            }
            self.inner.append_audit(entry)
        }
        fn list_audit(&self) -> busbar_api::StoreResult<Vec<busbar_api::AuditRecord>> {
            self.inner.list_audit()
        }
        fn list_audit_tail(
            &self,
            limit: u64,
        ) -> busbar_api::StoreResult<Vec<busbar_api::AuditRecord>> {
            self.inner.list_audit_tail(limit)
        }
    }

    /// AUDIT CHAIN-CORRUPTION FIX: a TRANSIENT `append_audit` failure must not permanently corrupt the
    /// durable chain. We fail the write-through for seq 2, so the old behavior left a permanent hole
    /// (1, _, 3, …) that fails the strict restore linkage check and discards ALL durable history. With
    /// the backfill, the next successful write-through (seq 3) catches seq 2 up from the RAM ring, so
    /// the durable chain is CONTIGUOUS and restores intact.
    #[test]
    fn transient_append_failure_is_backfilled_and_chain_survives_restart() {
        let store = std::sync::Arc::new(FlakyAuditStore {
            inner: busbar_store_sqlite::SqliteStore::open_in_memory().unwrap(),
            fail_seqs: std::sync::Mutex::new([2u64].into_iter().collect()),
        });
        let log = AuditLog::new();
        log.set_sink(store.clone());

        log.record_by("hook.register", "hook:a", OUTCOME_APPLIED, "admin"); // seq 1 -> durable
        log.record_by("hook.register", "hook:b", OUTCOME_APPLIED, "admin"); // seq 2 -> FAILS (gap)

        // After the injected failure, the store is missing seq 2 (the transient hiccup).
        let after_fail = store.list_audit().unwrap();
        assert_eq!(
            after_fail.iter().map(|r| r.seq).collect::<Vec<_>>(),
            vec![1],
            "seq 2's write-through failed, so only seq 1 is durable so far"
        );

        // Clear the fault (the store recovered), then record seq 3: its write-through BACKFILLS seq 2
        // from the RAM ring before appending seq 3, healing the gap.
        store.fail_seqs.lock().unwrap().clear();
        log.record_by("hook.delete", "hook:a", OUTCOME_APPLIED, "admin"); // seq 3 -> backfills 2, then 3

        let healed = store.list_audit().unwrap();
        assert_eq!(
            healed.iter().map(|r| r.seq).collect::<Vec<_>>(),
            vec![1, 2, 3],
            "the transient gap is backfilled; the durable chain is contiguous again"
        );

        // A restart restores the healed durable chain intact (no permanent loss, chain verifies).
        let store_ro: std::sync::Arc<dyn Store> = store.clone();
        let log2 = AuditLog::new();
        let n = log2
            .restore_from_store(store_ro.as_ref())
            .expect("the backfilled chain restores without a linkage break");
        assert_eq!(n, 3, "all three entries restored (nothing discarded)");
        assert!(log2.verify(), "the restored chain verifies");
    }

    /// BOUNDED RESTORE READ: with a durable history far larger than the RAM ring, `restore_from_store`
    /// must read only the bounded tail (`list_audit_tail`), never materialize the whole log. We record
    /// more than `MAX_AUDIT_ENTRIES`, then restore and assert the ring holds exactly the cap and the
    /// restored tail verifies - proving the read is bounded (the SQLite `LIMIT` tail query backs it).
    #[test]
    fn restore_read_is_bounded_to_the_ring() {
        let store: Arc<dyn Store> =
            Arc::new(busbar_store_sqlite::SqliteStore::open_in_memory().unwrap());
        let log = AuditLog::new();
        log.set_sink(store.clone());
        let total = MAX_AUDIT_ENTRIES + 50;
        for i in 0..total {
            log.record_by(
                "hook.register",
                &format!("hook:{i}"),
                OUTCOME_APPLIED,
                "admin",
            );
        }

        // The bounded tail read returns exactly the ring bound, oldest-first, chained to the head.
        let tail = store.list_audit_tail(MAX_AUDIT_ENTRIES as u64).unwrap();
        assert_eq!(
            tail.len(),
            MAX_AUDIT_ENTRIES,
            "the source-bounded read caps the tail"
        );
        assert_eq!(
            tail.last().unwrap().seq as usize,
            total,
            "the tail ends at the newest durable seq"
        );

        let log2 = AuditLog::new();
        let n = log2
            .restore_from_store(store.as_ref())
            .expect("bounded restore");
        assert_eq!(
            n, MAX_AUDIT_ENTRIES,
            "restore loads only the bounded tail, not the full history"
        );
        assert_eq!(
            log2.list(usize::MAX).len(),
            MAX_AUDIT_ENTRIES,
            "the restored ring is bounded"
        );
        assert!(log2.verify(), "the restored bounded tail's chain verifies");
    }

    /// AUDIT: a PRUNED, unpersisted seq must HALT durable catch-up — `durable_high`
    /// must never advance PAST an unrepairable hole. We permanently fail seq 2's write-through, then
    /// record far past the RAM-ring cap so seq 2 is pruned from the ring (no longer backfillable).
    /// The prior code `continue`d over the pruned gap, and the very next successful append then
    /// `fetch_max`ed `durable_high` PAST seq 2 — falsely claiming a contiguous durable tail that
    /// actually has a hole at seq 2 (which restore's strict linkage check would reject). With the
    /// fix, `durable_write_through` returns at the pruned gap and `durable_high` stays at seq 1, and
    /// nothing past the hole is persisted (the durable chain would otherwise be silently corrupt).
    #[test]
    fn pruned_gap_halts_durable_catch_up_and_does_not_advance_past_the_hole() {
        let store = std::sync::Arc::new(FlakyAuditStore {
            inner: busbar_store_sqlite::SqliteStore::open_in_memory().unwrap(),
            fail_seqs: std::sync::Mutex::new([2u64].into_iter().collect()), // seq 2 fails forever
        });
        let log = AuditLog::new();
        log.set_sink(store.clone());

        // Record well past the ring cap so seq 2 is eventually pruned from the RAM ring.
        let total = MAX_AUDIT_ENTRIES + 5;
        for i in 0..total {
            log.record_by(
                "hook.register",
                &format!("hook:{i}"),
                OUTCOME_APPLIED,
                "admin",
            );
        }

        // seq 2 was pruned from the RAM ring (only the recent tail remains), so it can never be
        // backfilled — the pre-condition for the bug.
        let ring = log.list(usize::MAX);
        assert_eq!(ring.len(), MAX_AUDIT_ENTRIES, "the ring is bounded");
        assert!(
            !ring.iter().any(|e| e.seq == 2),
            "seq 2 must have been pruned from the ring"
        );

        // durable_high must stay at 1 — the catch-up halts AT the pruned hole and never advances past
        // it (the bug was: a later successful append bumped durable_high past seq 2).
        assert_eq!(
            log.durable_high.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "durable_high must not advance past the unpersisted, pruned seq-2 gap"
        );

        // And nothing PAST the hole is persisted: the durable store holds only seq 1 (persisting seq
        // 3+ over a missing seq 2 would manufacture the very gap the strict restore check rejects).
        let persisted = store.list_audit().unwrap();
        assert_eq!(
            persisted.iter().map(|r| r.seq).collect::<Vec<_>>(),
            vec![1],
            "only seq 1 is durable; no entry past the hole leaked into the store"
        );
    }
    /// The durable audit log has exactly ONE legitimate writer. Seqs are allocated process-locally,
    /// so a second busbar pointed at the same store allocates the SAME seqs, and the store's keyed
    /// upsert destroys whichever row lost the race — then the next boot reports the resulting break
    /// as tamper evidence. Nothing reads the durable log across nodes (`GET /audit` serves the RAM
    /// ring), so a second writer buys nothing and costs history.
    ///
    /// Node A boots, adopts the tail and keeps writing. Node B boots later and writes. A's next
    /// mutation must notice the tail moved without it, detach its sink, and stop — rather than
    /// overwrite B's rows.
    #[test]
    fn a_second_writer_is_detected_and_the_sink_detaches() {
        let store: Arc<dyn Store> =
            Arc::new(busbar_store_sqlite::SqliteStore::open_in_memory().unwrap());

        let node_a = AuditLog::new();
        node_a.set_sink(store.clone());
        node_a.restore_from_store(store.as_ref()).unwrap();
        node_a.record_by("hook.register", "hook:from_a", OUTCOME_APPLIED, "admin");
        let after_a = store.list_audit().unwrap().len();
        assert_eq!(after_a, 1, "node A's entry is durable");

        // Node B boots against the same store and writes. Its seq floor comes from the same tail,
        // so it now occupies seqs node A will also reach for.
        let node_b = AuditLog::new();
        node_b.set_sink(store.clone());
        node_b.restore_from_store(store.as_ref()).unwrap();
        node_b.record_by("hook.register", "hook:from_b", OUTCOME_APPLIED, "admin");
        let after_b = store.list_audit().unwrap().len();

        // Node A mutates again. Without the check it would append over node B's row.
        node_a.record_by("hook.delete", "hook:from_a", OUTCOME_APPLIED, "admin");

        // `append_audit` is a keyed upsert on `seq`: node A and node B both restored from the same
        // tail, so both allocate seq 2. If the second-writer check were removed, node A's
        // `hook.delete` row would OVERWRITE node B's `hook.register` row in place — seq 2 is still
        // one row, so `len()` alone would stay `after_b` either way and cannot see the corruption.
        // Assert on the CONTENT of that row instead.
        let rows = store.list_audit().unwrap();
        assert_eq!(
            rows.len(),
            after_b,
            "no row was added — node A's second write must not append"
        );
        let b_row = rows
            .iter()
            .find(|r| r.seq == 2)
            .expect("node B's seq-2 row is still present");
        assert_eq!(
            b_row.resource, "hook:from_b",
            "node B's row must survive verbatim — a keyed upsert would overwrite it IN PLACE and \
             leave the row count unchanged, so the count alone cannot see this"
        );
        assert_eq!(b_row.action, "hook.register");
        assert!(
            !rows.iter().any(|r| r.action == "hook.delete"),
            "node A's post-detection mutation must not have reached the durable store at all"
        );
        assert!(
            node_a
                .sink
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_none(),
            "node A must detach its durable sink once another writer is detected"
        );
        // The entry is still audited locally — detaching the durable sink is not losing the record.
        assert!(
            node_a.list(10).iter().any(|e| e.action == "hook.delete"),
            "the mutation stays in the RAM ring and the state snapshot"
        );
    }

    // ── finding #5: durable write-through offload (write-behind flusher + pressure valve) ────────

    /// A `Store` decorator that sleeps on `append_audit` — the FIRST call only, then runs at full
    /// speed — a stand-in for a slow durable store's write round-trip. All other methods delegate.
    struct SlowAuditStore {
        inner: busbar_store_sqlite::SqliteStore,
        delay: std::time::Duration,
        fired: std::sync::atomic::AtomicBool,
    }
    impl Store for SlowAuditStore {
        fn put_key(&self, key: &busbar_api::VirtualKey) -> busbar_api::StoreResult<()> {
            self.inner.put_key(key)
        }
        fn get_key(&self, id: &str) -> busbar_api::StoreResult<Option<busbar_api::VirtualKey>> {
            self.inner.get_key(id)
        }
        fn list_keys(&self) -> busbar_api::StoreResult<Vec<busbar_api::VirtualKey>> {
            self.inner.list_keys()
        }
        fn delete_key(&self, id: &str) -> busbar_api::StoreResult<()> {
            self.inner.delete_key(id)
        }
        fn get_usage(
            &self,
            bucket_id: &str,
            window_start: u64,
        ) -> busbar_api::StoreResult<busbar_api::UsageLedger> {
            self.inner.get_usage(bucket_id, window_start)
        }
        fn put_usage(
            &self,
            bucket_id: &str,
            window_start: u64,
            ledger: &busbar_api::UsageLedger,
        ) -> busbar_api::StoreResult<()> {
            self.inner.put_usage(bucket_id, window_start, ledger)
        }
        fn add_metering(&self, delta: &busbar_api::MeteringDelta) -> busbar_api::StoreResult<()> {
            self.inner.add_metering(delta)
        }
        fn list_metering(
            &self,
            bucket: u64,
        ) -> busbar_api::StoreResult<Vec<busbar_api::MeteringRow>> {
            self.inner.list_metering(bucket)
        }
        fn append_audit(&self, entry: &busbar_api::AuditRecord) -> busbar_api::StoreResult<()> {
            if !self.fired.swap(true, std::sync::atomic::Ordering::SeqCst) {
                std::thread::sleep(self.delay);
            }
            self.inner.append_audit(entry)
        }
        fn list_audit(&self) -> busbar_api::StoreResult<Vec<busbar_api::AuditRecord>> {
            self.inner.list_audit()
        }
        fn list_audit_tail(
            &self,
            limit: u64,
        ) -> busbar_api::StoreResult<Vec<busbar_api::AuditRecord>> {
            self.inner.list_audit_tail(limit)
        }
    }

    /// THE RED PROOF FOR FINDING #5 ITSELF: today's `record_by` does the durable write-through
    /// INLINE and SYNCHRONOUSLY, so a slow store round-trip parks whatever thread called it — a
    /// Tokio worker for the ~30 `async fn` admin handler sites. `current_thread` flavor is
    /// LOAD-BEARING: on the default multi-thread runtime a second worker would pick up the second
    /// task and this test would false-green. This is a REAL thread sleep (not paused time — a
    /// blocking `std::thread::sleep` inside `record_by` is invisible to Tokio's time-auto-advance,
    /// which only fires while the runtime is idle; see `hooks/mod.rs`'s `offload_bounded_with_deadline`
    /// docs for the same trap).
    #[tokio::test(flavor = "current_thread")]
    async fn durable_audit_write_through_does_not_park_the_reactor() {
        let store = std::sync::Arc::new(SlowAuditStore {
            inner: busbar_store_sqlite::SqliteStore::open_in_memory().unwrap(),
            delay: std::time::Duration::from_millis(500),
            fired: std::sync::atomic::AtomicBool::new(false),
        });
        let log = std::sync::Arc::new(AuditLog::new());
        log.set_sink(store);

        let recorder = {
            let log = log.clone();
            tokio::spawn(async move {
                log.record_by("hook.register", "hook:x", OUTCOME_APPLIED, "admin");
            })
        };
        // A second task's short sleep must complete promptly. If `record_by` parked the single
        // `current_thread` worker for the store's 500ms, this 50ms sleep cannot be polled in time.
        let start = std::time::Instant::now();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let elapsed = start.elapsed();
        recorder.await.unwrap();
        assert!(
            elapsed < std::time::Duration::from_millis(300),
            "a 50ms sleep took {elapsed:?} — the reactor was parked by the durable write-through"
        );
    }

    /// Regression proof (passes before and after the valve exists): `flush_durable` drains the
    /// WHOLE pending range in one call, including entries recorded with NO runtime present (which
    /// always go inline, per the `no_flusher` check) and entries recorded under a runtime but below
    /// `WRITE_THROUGH_HEADROOM` (which the flusher owns).
    #[tokio::test]
    async fn flush_durable_drains_the_whole_pending_range() {
        let store =
            std::sync::Arc::new(busbar_store_sqlite::SqliteStore::open_in_memory().unwrap());
        let log = AuditLog::new();
        log.set_sink(store.clone());

        // Below the headroom threshold, recorded under a runtime: the flusher owns these, so
        // nothing should be durable yet.
        for i in 0..3 {
            log.record_by(
                "hook.register",
                &format!("hook:{i}"),
                OUTCOME_APPLIED,
                "admin",
            );
        }
        assert_eq!(
            store.list_audit().unwrap().len(),
            0,
            "below headroom, the recorder must not touch the store itself"
        );

        log.flush_durable();
        let persisted = store.list_audit().unwrap();
        assert_eq!(
            persisted.len(),
            3,
            "flush_durable must drain the whole pending range"
        );
        let mut seqs: Vec<u64> = persisted.iter().map(|r| r.seq).collect();
        seqs.sort_unstable();
        assert_eq!(seqs, vec![1, 2, 3], "contiguous, no seq skipped");
    }

    /// Regression proof (passes before and after — labeled per the design doc as
    /// RED-against-the-alternative, not RED-against-HEAD, since today's unconditional inline write
    /// already keeps this invariant): a burst that outruns one slow store round-trip must never
    /// prune an unpersisted seq. Demonstrates the pressure valve's safety property directly rather
    /// than by building-then-discarding the REFUTED bare-admission-gate design.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_burst_outrunning_store_latency_never_prunes_an_unpersisted_seq() {
        let store = std::sync::Arc::new(SlowAuditStore {
            inner: busbar_store_sqlite::SqliteStore::open_in_memory().unwrap(),
            delay: std::time::Duration::from_millis(20),
            fired: std::sync::atomic::AtomicBool::new(false),
        });
        let log = std::sync::Arc::new(AuditLog::new());
        log.set_sink(store.clone());

        let total = MAX_AUDIT_ENTRIES + 200;
        let mut handles = Vec::new();
        for i in 0..total {
            let log = log.clone();
            handles.push(tokio::spawn(async move {
                log.record_by(
                    "hook.register",
                    &format!("hook:{i}"),
                    OUTCOME_APPLIED,
                    "admin",
                );
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        log.flush_durable();

        assert!(
            log.durable_high.load(std::sync::atomic::Ordering::Relaxed) >= 1,
            "the durable tail must not be pinned at 0"
        );
        let persisted = store.list_audit().unwrap();
        let mut seqs: Vec<u64> = persisted.iter().map(|r| r.seq).collect();
        seqs.sort_unstable();
        for w in seqs.windows(2) {
            assert_eq!(
                w[1],
                w[0] + 1,
                "the durable chain must stay contiguous: {seqs:?}"
            );
        }
        assert_eq!(
            seqs.first().copied(),
            Some(1),
            "durable history starts at seq 1"
        );
    }
}
