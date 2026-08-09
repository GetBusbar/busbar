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
/// altered/reordered/deleted entry (detection, not prevention; a compromised host can still rewrite
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
    /// WHO: the authenticated principal id that attempted the mutation (`admin` for the operator
    /// token; a virtual-key id or an external module's principal id otherwise; `anonymous` for the
    /// explicit open admin posture). Attribution, never a credential.
    pub(crate) principal: String,
    /// The preceding entry's `hash` (empty for the first entry of the process, or the oldest retained
    /// entry whose predecessor was pruned).
    pub(crate) prev_hash: String,
    /// `sha256(prev_hash | seq | ts | action | resource | outcome | principal)`: the tamper-evidence digest.
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
    /// happens — so `load` clears it explicitly and the attribute is only belt-and-braces: serde
    /// alone does not cover every path that fills the ring.
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
/// busbar is single-operator (no multi-tenant trust boundary, no per-caller concurrency limit on
/// the admin surface), so there is no adversarial population that could scale
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
/// (store.module: sqlite/postgres/valkey), each appended entry is ALSO write-through-persisted to
/// the store, which keeps the FULL history (never pruned) — so the ring's size bound bounds RAM, not
/// history, and a hard crash loses ~0 entries instead of up to a snapshot interval. With the RAM
/// default (`store: memory`) no sink is attached and the log stays ephemeral, exactly as before.
/// Interior-mutable so it can be a shared global.
pub(crate) struct AuditLog {
    entries: std::sync::Mutex<std::collections::VecDeque<AuditEntry>>,
    seq: std::sync::atomic::AtomicU64,
    /// The durable sink, attached once at boot when a durable store is configured. Best-effort: a
    /// write-through failure logs a warning but NEVER fails the admin mutation (the RAM ring still
    /// holds the entry, and the write-through backfills the skipped seq on a later success). `None` = ephemeral.
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
        // BOUNDED read: the durable log is never pruned and can dwarf the RAM ring; over
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
    /// (the durable sink, when present, keeps the pruned tail). WITH principal attribution: every
    /// mutation, success AND failure, is attributed to WHO attempted it.
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
            let handle = tokio::runtime::Handle::try_current();
            let no_flusher = handle.is_err();
            if no_flusher || unpersisted >= WRITE_THROUGH_HEADROOM {
                // `record_by` is sync and cannot `.await`, so every caller — not just the ones deep
                // inside a `spawn_blocking` closure — reaches this store round-trip on whatever OS
                // thread called it. On a multi-thread runtime, that thread is a Tokio worker core:
                // parking it on a synchronous store call also stalls every OTHER task the scheduler
                // would otherwise run on that core, not just the caller's own task. `block_in_place`
                // hands the worker's core off to a freshly-promoted thread for the duration of the
                // call, so the scheduler keeps servicing other tasks while this one still waits
                // (backpressure is unchanged — the caller still blocks until the write lands, only
                // WHICH thread is parked changes). Called from a blocking-pool thread (e.g. from
                // inside another `spawn_blocking` closure) it is a documented no-op: there is no
                // worker core to hand off, so the closure just runs inline, identical to today.
                //
                // `block_in_place` PANICS on a `current_thread` runtime, which has no second thread
                // to promote. Production always builds a multi-thread runtime (`main.rs`), so this
                // guard is a defensive fallback for `#[tokio::test]`'s default flavor and any future
                // current-thread embedding, not a production code path.
                match handle {
                    Ok(h) if h.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
                        tokio::task::block_in_place(|| {
                            self.durable_write_through(store.as_ref(), record.seq)
                        });
                    }
                    _ => self.durable_write_through(store.as_ref(), record.seq),
                }
            }
            // Otherwise: headroom remains, the write-behind flusher owns this seq. Return immediately
            // without touching the store.
        }
    }

    /// RESILIENT durable write-through with GAP BACKFILL. A TRANSIENT
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
                         (write-through backfills it on a later success); writing now could \
                         overwrite durable history."
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
                     This node keeps auditing to its in-memory ring (ephemeral)."
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
                 durable floor (it is retained in the RAM ring)"
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

    /// Export the retained ring, oldest first. TEST-ONLY: the store-or-RAM rule removed the file
    /// snapshotter that used to consume this; it now backs the in-process restart-simulation tests
    /// (a fresh `AuditLog` re-seeded from this process's ring) alongside `load`.
    #[cfg(test)]
    pub(crate) fn export(&self) -> Vec<AuditEntry> {
        let q = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        q.iter().cloned().collect()
    }

    /// Seed the ring from an in-process snapshot. TEST-ONLY: the durable store is production's single
    /// restore source (`restore_from_store`); this remains as the in-process restart-simulation seam
    /// the durability tests drive. Replaces the current contents and resumes the sequence AFTER the
    /// highest restored seq, so post-restart entries chain on without seq reuse. FLOOR semantics
    /// (fetch_max, never store): a lagging snapshot must never rewind the counter below the store's
    /// max, since the durable write-through is keyed on `seq` and would otherwise OVERWRITE history.
    #[cfg(test)]
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
#[path = "tests/audit_tests.rs"]
mod tests;
