// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar/src/admin/audit.rs`.

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

// ── durable audit through the configured Store ───────────────────────────────────────────────

use busbar_api::Store;
use std::sync::Arc;

/// TEST-ONLY durable-audit double. `busbar_store_memory::MemoryStore` deliberately makes
/// `append_audit`/`list_audit` no-ops — `store: memory` is documented and relied upon elsewhere
/// (main.rs's boot-restore path, docs/configuration.md, docs/migration-1.5.md) as genuinely
/// EPHEMERAL, including its audit log, so implementing real audit persistence there would
/// silently change that product contract just to suit these tests. These tests need a store
/// that DOES persist audit records within the process, so a fresh `AuditLog` attached to the
/// SAME live `Arc<dyn Store>` handle can simulate "process 2" restoring from "process 1" left
/// off. This wraps a real `MemoryStore` for every other `Store` method (key/usage/metering/
/// denylist all behave exactly like the production RAM default) and backs ONLY
/// `append_audit`/`list_audit`/`list_audit_tail` with its own in-memory ledger keyed by `seq`
/// (an upsert-on-seq map, mirroring a real durable backend's `INSERT OR REPLACE` semantics) —
/// "durable" for exactly as long as this test process lives, never across a real restart.
struct DurableTestStore {
    inner: busbar_store_memory::MemoryStore,
    audit: std::sync::Mutex<std::collections::BTreeMap<u64, busbar_api::AuditRecord>>,
}

impl DurableTestStore {
    fn new() -> Self {
        Self {
            inner: busbar_store_memory::MemoryStore::new(),
            audit: std::sync::Mutex::new(std::collections::BTreeMap::new()),
        }
    }
}

impl Store for DurableTestStore {
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
    fn list_metering(&self, bucket: u64) -> busbar_api::StoreResult<Vec<busbar_api::MeteringRow>> {
        self.inner.list_metering(bucket)
    }
    fn append_audit(&self, entry: &busbar_api::AuditRecord) -> busbar_api::StoreResult<()> {
        self.audit
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(entry.seq, entry.clone());
        Ok(())
    }
    fn list_audit(&self) -> busbar_api::StoreResult<Vec<busbar_api::AuditRecord>> {
        Ok(self
            .audit
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .cloned()
            .collect())
    }
    fn list_audit_tail(&self, limit: u64) -> busbar_api::StoreResult<Vec<busbar_api::AuditRecord>> {
        let limit = limit as usize;
        let audit = self.audit.lock().unwrap_or_else(|e| e.into_inner());
        let len = audit.len();
        Ok(audit
            .values()
            .skip(len.saturating_sub(limit))
            .cloned()
            .collect())
    }
}

/// WRITE-THROUGH + RESTORE across a simulated restart, over an in-memory store. A first process
/// records N mutations with the store attached as the sink (each write-through persisted); a fresh
/// process (fresh `AuditLog`, SAME store) restores from it — the chain verifies, the entries are
/// intact, and the sequence resumes after the max restored seq. This is the durable roundtrip.
#[test]
fn durable_write_through_and_restore_roundtrip() {
    let store: Arc<dyn Store> = Arc::new(DurableTestStore::new());

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
    let store: Arc<dyn Store> = Arc::new(DurableTestStore::new());

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
    // The count/seq/untouched-entry assertions below cover the seq floor; the linkage assertion
    // that follows them covers the re-anchoring.
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
    // The new entry's `prev_hash` must join the STORE's durable tail, not whatever stale link
    // the seeded ring happened to carry. Without the seal engaging on the verify-fail path, the
    // recovery branch never runs and the entry chains onto the stale snapshot's seq-1 hash
    // instead of the store's seq-3 hash — a silent linkage break reported as tamper on the NEXT
    // boot, not this one.
    assert_eq!(
        persisted[3].prev_hash, persisted[2].hash,
        "the post-restart entry must re-anchor to the durable tail's actual hash, not the stale \
             snapshot's link"
    );
}

/// The verify-fail linkage break, with NO snapshot at all. The ring is empty at record time
/// (nothing was `load`ed), so an unsealed `record_by` takes `q.back() == None` and the first
/// post-restart entry's `prev_hash` is `""`, not the durable tail's hash — a silent break
/// identical in kind to the with-snapshot case above, just with a different stale link (empty
/// instead of the snapshot's).
#[test]
fn verify_failure_without_a_snapshot_still_anchors_to_the_durable_tail() {
    let store: Arc<dyn Store> = Arc::new(DurableTestStore::new());

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
/// recording more than the cap prunes the RAM ring WITHOUT losing durable history (the size
/// bound bounds RAM, not history). Restoring seeds the ring with the recent tail while the
/// store retains everything.
#[test]
fn durable_store_keeps_history_beyond_the_ram_cap() {
    let store: Arc<dyn Store> = Arc::new(DurableTestStore::new());
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
// - a transient `list_audit_tail` failure returned EARLY, before the floor was applied, and the
//   caller fell back to a snapshot that floors only to its own (lower) max;
// - the file-snapshot `load` never seeded `durable_high` at all;
// - the backfill always started at `durable_high + 1`, so a restored ring whose oldest seq is
//   higher hit the unrepairable-gap branch on the first iteration and left the durable log
//   permanently stuck.

/// A store whose AUDIT READS can be made to fail on demand (a transient backend blip), while
/// writes and everything else delegate to a real in-memory store.
struct FlakyAuditReads {
    inner: DurableTestStore,
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
    fn list_metering(&self, bucket: u64) -> busbar_api::StoreResult<Vec<busbar_api::MeteringRow>> {
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
    fn list_audit_tail(&self, limit: u64) -> busbar_api::StoreResult<Vec<busbar_api::AuditRecord>> {
        if self.failing() {
            return Err(busbar_api::StoreError("audit read unavailable".into()));
        }
        self.inner.list_audit_tail(limit)
    }
}

/// A TRANSIENT read failure at boot must not let the sequence rewind into durable
/// history. While the floor is unknown the write-through is SEALED (nothing is written, and
/// certainly nothing is overwritten); once the store answers again the floor is recovered and
/// appends resume ABOVE the durable max.
#[test]
fn transient_restore_read_failure_cannot_rewind_the_durable_seq() {
    let inner = DurableTestStore::new();
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

/// ENTRY DUPLICATION via the IN-PROCESS seeding path. `rebase_nondurable_suffix` used to
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
    let inner = DurableTestStore::new();
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

/// After a FILE-SNAPSHOT restore (the durable restore did not supply the ring), the
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

    let store: Arc<dyn Store> = Arc::new(DurableTestStore::new());
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

/// The rebase's `max(durable_max + 1, head.seq)` floor. A bare `next_seq = durable_max + 1`
/// renumbers a live entry BELOW a still-present seeded one whenever the durable tail is empty or
/// lagging, violating the ring's seq-sorted invariant (and making the backfill's
/// `find(|e| e.seq == seq)` ambiguous).
#[test]
fn live_entry_is_never_renumbered_below_a_seeded_one() {
    let inner = DurableTestStore::new();
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

/// STORE-OR-RAM (1.5.3): the audit log is STATEFUL, so its ONE durable home is the configured
/// governance store — never a side-car state file. The `BUSBAR_STATE_FILE` snapshot that used to
/// carry a DUAL audit source (store + file, reconciled by `should_load_audit_from_file_snapshot`)
/// is gone, so this pins the single source directly: entries written under a durable store survive
/// a simulated restart (a fresh `AuditLog` restoring from the SAME store, with no file to read),
/// and under the memory store the log is ephemeral by design — a fresh log restores nothing.
#[test]
fn audit_durable_home_is_the_store_and_nothing_else() {
    // Durable store: the audit survives a restart THROUGH THE STORE alone.
    let durable: Arc<dyn Store> = Arc::new(DurableTestStore::new());
    let p1 = AuditLog::new();
    p1.set_sink(durable.clone());
    p1.record_by("hook.register", "hook:a", OUTCOME_APPLIED, "admin");
    p1.record_by("plugin.install", "plugin:x", OUTCOME_APPLIED, "admin");
    let p2 = AuditLog::new(); // "process 2": a fresh ring, no file snapshot to consult
    assert_eq!(
        p2.restore_from_store(durable.as_ref())
            .expect("the chain verifies"),
        2,
        "a durable store is the SINGLE source that carries audit across a restart"
    );

    // Memory store: ephemeral BY DESIGN — nothing persists, so a restart restores nothing. With
    // the state file removed there is no longer any file that could resurrect the ephemeral log.
    let mem: Arc<dyn Store> = Arc::new(busbar_store_memory::MemoryStore::new());
    let m1 = AuditLog::new();
    m1.set_sink(mem.clone());
    m1.record_by("hook.register", "hook:a", OUTCOME_APPLIED, "admin");
    let m2 = AuditLog::new();
    assert_eq!(
        m2.restore_from_store(mem.as_ref()).expect("empty restore"),
        0,
        "with the memory store the audit log is ephemeral — no file backs it after the state \
             file removal"
    );
}

/// A TAMPERED durable record is rejected on restore (tamper-evidence survives the restart): if a
/// stored entry's field is altered without recomputing the chain, `restore_from_store` returns an
/// error rather than silently loading a broken chain.
#[test]
fn restore_rejects_a_tampered_durable_chain() {
    let store: Arc<dyn Store> = Arc::new(DurableTestStore::new());
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

/// A `Store` decorator over a real in-memory store that FAILS `append_audit` for a configured set of
/// seqs (simulating a TRANSIENT durable-write hiccup), then behaves normally once those seqs are
/// cleared. All reads delegate to the inner store. Used to prove the write-through backfill heals a
/// gap rather than leaving the durable chain permanently corrupt.
struct FlakyAuditStore {
    inner: DurableTestStore,
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
    fn list_metering(&self, bucket: u64) -> busbar_api::StoreResult<Vec<busbar_api::MeteringRow>> {
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
    fn list_audit_tail(&self, limit: u64) -> busbar_api::StoreResult<Vec<busbar_api::AuditRecord>> {
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
        inner: DurableTestStore::new(),
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
/// restored tail verifies - proving the read is bounded (the store's bounded tail-read backs it).
#[test]
fn restore_read_is_bounded_to_the_ring() {
    let store: Arc<dyn Store> = Arc::new(DurableTestStore::new());
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
        inner: DurableTestStore::new(),
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
    let store: Arc<dyn Store> = Arc::new(DurableTestStore::new());

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
        "the mutation stays in the RAM ring (ephemeral)"
    );
}

// ── durable write-through offload (write-behind flusher + pressure valve) ──────────────────────

/// A `Store` decorator that sleeps on `append_audit` — the FIRST call only, then runs at full
/// speed — a stand-in for a slow durable store's write round-trip. All other methods delegate.
struct SlowAuditStore {
    inner: DurableTestStore,
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
    fn list_metering(&self, bucket: u64) -> busbar_api::StoreResult<Vec<busbar_api::MeteringRow>> {
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
    fn list_audit_tail(&self, limit: u64) -> busbar_api::StoreResult<Vec<busbar_api::AuditRecord>> {
        self.inner.list_audit_tail(limit)
    }
}

/// An INLINE, SYNCHRONOUS durable write-through in `record_by` parks whatever thread called
/// it for the length of a slow store round-trip — a
/// Tokio worker for the ~30 `async fn` admin handler sites. `current_thread` flavor is
/// LOAD-BEARING: on the default multi-thread runtime a second worker would pick up the second
/// task and this test would false-green. This is a REAL thread sleep (not paused time — a
/// blocking `std::thread::sleep` inside `record_by` is invisible to Tokio's time-auto-advance,
/// which only fires while the runtime is idle; see `hooks/mod.rs`'s `offload_bounded_with_deadline`
/// docs for the same trap).
#[tokio::test(flavor = "current_thread")]
async fn durable_audit_write_through_does_not_park_the_reactor() {
    let store = std::sync::Arc::new(SlowAuditStore {
        inner: DurableTestStore::new(),
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

/// THE VALVE'S `block_in_place` HANDOFF: unlike its sibling above (which never
/// trips the valve — headroom is untouched, so the write-behind flusher owns the write), this
/// test drives `unpersisted` past `WRITE_THROUGH_HEADROOM` so `record_by` itself performs the
/// slow, synchronous store round-trip. Flavor choice is deliberately DIFFERENT from the sibling:
/// the sibling uses `current_thread` so there is provably only one worker to park.
/// Here `worker_threads = 1` gives the same "exactly one worker" property while still
/// being `RuntimeFlavor::MultiThread`, which is what `block_in_place` requires to hand its core
/// off — on `current_thread` the fix cannot engage (there is no second thread to promote) and
/// this test would never go green under that flavor.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn valve_write_through_does_not_park_the_reactor() {
    let log = std::sync::Arc::new(AuditLog::new());
    // Push past the valve threshold BEFORE attaching a sink: with no sink, `record_by` never
    // touches a store, so this costs nothing and leaves `durable_high` at 0.
    for i in 0..751 {
        log.record_by(
            "hook.register",
            &format!("hook:{i}"),
            OUTCOME_APPLIED,
            "admin",
        );
    }
    let store = std::sync::Arc::new(SlowAuditStore {
        inner: DurableTestStore::new(),
        delay: std::time::Duration::from_millis(500),
        fired: std::sync::atomic::AtomicBool::new(false),
    });
    log.set_sink(store.clone());

    // seq becomes 752; unpersisted = 752 - 0 >= 750 ⇒ the valve trips and this call performs the
    // slow write-through itself.
    let recorder = {
        let log = log.clone();
        tokio::spawn(async move {
            log.record_by("hook.register", "hook:valve", OUTCOME_APPLIED, "admin");
        })
    };
    let start = std::time::Instant::now();
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let elapsed = start.elapsed();
    recorder.await.unwrap();
    assert!(
        elapsed < std::time::Duration::from_millis(300),
        "a 50ms sleep took {elapsed:?} — the valve's write-through parked the only worker"
    );
    // Backpressure must be unchanged: the write really did land before the recorder task
    // finished, not fire-and-forgotten. This second assertion is what a bare `tokio::spawn` of
    // the write (which would also make the sleep above prompt) could not pass.
    let persisted = store.list_audit().unwrap();
    assert_eq!(
        persisted.len(),
        752,
        "the valve-tripped write must have landed durably before record_by returned"
    );
    for (i, r) in persisted.iter().enumerate() {
        assert_eq!(
            r.seq,
            (i + 1) as u64,
            "durable entries must be contiguous 1..=752"
        );
    }
}

/// `flush_durable` drains the WHOLE pending range in one call, including entries recorded with
/// NO runtime present (which always go inline, per the `no_flusher` check) and entries recorded
/// under a runtime but below `WRITE_THROUGH_HEADROOM` (which the flusher owns).
#[tokio::test]
async fn flush_durable_drains_the_whole_pending_range() {
    let store = std::sync::Arc::new(DurableTestStore::new());
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

/// The pressure valve's safety property: a burst that outruns one slow store round-trip must
/// never prune an unpersisted seq, so the durable chain stays contiguous no matter how far the
/// recorders run ahead of the store.
#[tokio::test(flavor = "multi_thread")]
async fn a_burst_outrunning_store_latency_never_prunes_an_unpersisted_seq() {
    let store = std::sync::Arc::new(SlowAuditStore {
        inner: DurableTestStore::new(),
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
