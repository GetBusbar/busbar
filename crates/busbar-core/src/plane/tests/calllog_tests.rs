// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DURABLE PER-CALL LOG'S TESTS.
//!
//! Three things are proven here and each one is proven the hard way:
//!
//! 1. **Durability by RESTART, not by return value.** A write's `Ok(())` proves nothing — the
//!    `Store` default accepts and keeps nothing — so every durability claim below writes through one
//!    log, DROPS it, builds a fresh one over the same store, and asserts the records back
//!    FIELD-BY-FIELD. A field compared as a whole struct would let a future field be added and never
//!    checked; the field list here is asserted to be exhaustive by a destructuring bind.
//! 2. **Tamper detection against PERSISTED ROWS.** Every tamper goes through the store's own rows
//!    (`tamper_*` mutate what the backend holds), never by hand-building a bad struct. A verifier
//!    tested on a struct the engine never wrote has been tested against a fiction.
//! 3. **The RAM default loses rows and says so.** The permanent paired NEGATIVE test. Without it the
//!    positive tests would pass identically against a store that persisted nothing, and would have
//!    proven nothing at all.

use super::super::calllog::{
    CallChain, CallInput, PlaneCallLog, OUTCOME_DISPATCHED, OUTCOME_REFUSED,
};
// The chain, the verifier and the break vocabulary are CORE's — this plane supplies only the record
// type — so the tests reach for them where they live rather than through a plane re-export.
use crate::audit::{verify_chain, ChainBreakKind};
use busbar_api::{McpCallRecord, Store};
use std::sync::Arc;

// ── the two stores these tests are held against ──────────────────────────────────────────────

/// TEST-ONLY DURABLE double. `busbar_store_memory::MemoryStore` deliberately implements none of the
/// call-log methods — `store: memory` is documented and relied on as genuinely EPHEMERAL, and making
/// it persist here to suit a test would change that product contract. So this wraps a real
/// `MemoryStore` for every other `Store` method and backs ONLY the call-log methods with its own
/// ledger: "durable" for exactly as long as this test process lives, which is all a restart
/// simulation needs.
///
/// It also enforces the append contract the trait doc states, because a double that quietly
/// overwrote would make the engine's ordering guarantees untestable: a byte-identical record on an
/// occupied `(principal, seq)` is the retry and succeeds; a DIFFERENT one is a forked log and
/// errors.
struct DurableCallStore {
    inner: busbar_store_memory::MemoryStore,
    calls: std::sync::Mutex<std::collections::BTreeMap<(String, u64), McpCallRecord>>,
    /// When set, `append_mcp_call` fails with this message instead of persisting. The write-failure
    /// axis: an evidence record that cannot be written must not burn a sequence number.
    fail_appends: std::sync::Mutex<Option<String>>,
}

impl DurableCallStore {
    fn new() -> Self {
        Self {
            inner: busbar_store_memory::MemoryStore::new(),
            calls: std::sync::Mutex::new(std::collections::BTreeMap::new()),
            fail_appends: std::sync::Mutex::new(None),
        }
    }

    fn set_failing(&self, why: Option<&str>) {
        *self.fail_appends.lock().unwrap() = why.map(str::to_string);
    }

    /// Mutate a PERSISTED row in place — the only way tampering is simulated in this file. The
    /// closure receives the backend's own stored record, exactly as an operator with write access to
    /// the backing table would have it.
    fn tamper(&self, principal: &str, seq: u64, edit: impl FnOnce(&mut McpCallRecord)) {
        let mut calls = self.calls.lock().unwrap();
        let row = calls
            .get_mut(&(principal.to_string(), seq))
            .expect("tampering with a row the store actually holds");
        edit(row);
    }

    /// Remove a PERSISTED row — the splice-out tamper.
    fn drop_row(&self, principal: &str, seq: u64) {
        self.calls
            .lock()
            .unwrap()
            .remove(&(principal.to_string(), seq))
            .expect("dropping a row the store actually holds");
    }

    /// How many rows the backend actually holds, across every principal.
    fn row_count(&self) -> usize {
        self.calls.lock().unwrap().len()
    }
}

impl Store for DurableCallStore {
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

    fn append_mcp_call(&self, record: &McpCallRecord) -> busbar_api::StoreResult<()> {
        if let Some(why) = self.fail_appends.lock().unwrap().as_ref() {
            return Err(busbar_api::StoreError(why.clone()));
        }
        let mut calls = self.calls.lock().unwrap();
        let slot = (record.principal.clone(), record.seq);
        match calls.get(&slot) {
            // The retry. Byte-identical, so nothing is lost by succeeding.
            Some(existing) if existing == record => Ok(()),
            // Two DIFFERENT records claiming one chain position: a forked or tampered log, and the
            // single most important thing this store can tell an operator.
            Some(_) => Err(busbar_api::StoreError(format!(
                "MCP call log fork: a DIFFERENT record already occupies ({}, {})",
                record.principal, record.seq
            ))),
            None => {
                calls.insert(slot, record.clone());
                Ok(())
            }
        }
    }

    fn list_mcp_calls(&self, principal: &str) -> busbar_api::StoreResult<Vec<McpCallRecord>> {
        Ok(self
            .calls
            .lock()
            .unwrap()
            .iter()
            .filter(|((p, _), _)| p == principal)
            .map(|(_, r)| r.clone())
            .collect())
    }

    fn list_mcp_call_principals(&self) -> busbar_api::StoreResult<Vec<String>> {
        let calls = self.calls.lock().unwrap();
        let mut out: Vec<String> = calls.keys().map(|(p, _)| p.clone()).collect();
        out.dedup();
        Ok(out)
    }

    fn purge_mcp_calls_before(&self, before: u64) -> busbar_api::StoreResult<u64> {
        let mut calls = self.calls.lock().unwrap();
        let before_len = calls.len();
        calls.retain(|_, r| r.ts >= before);
        Ok((before_len - calls.len()) as u64)
    }
}

/// THE RAM DEFAULT, verbatim: a store that overrides NONE of the call-log methods, so every one of
/// them is the `Store` trait's own default. This is not a weakened double — it is the exact
/// behaviour `store: memory` and every pre-existing signed store plugin present.
struct RamDefaultStore {
    inner: busbar_store_memory::MemoryStore,
}

impl RamDefaultStore {
    fn new() -> Self {
        Self {
            inner: busbar_store_memory::MemoryStore::new(),
        }
    }
}

impl Store for RamDefaultStore {
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
}

// ── fixtures ─────────────────────────────────────────────────────────────────────────────────

const P: &str = "key_alpha";

fn dispatched(ts: u64, tool: &str, digest: &str, generation: u64) -> CallInput {
    CallInput {
        ts,
        server: "fs".to_string(),
        tool: tool.to_string(),
        outcome: OUTCOME_DISPATCHED,
        reason: String::new(),
        tool_digest: digest.to_string(),
        pin_generation: generation,
        request_id: format!("req-{ts}"),
    }
}

fn refused(ts: u64, tool: &str, reason: &str) -> CallInput {
    CallInput {
        ts,
        server: "fs".to_string(),
        tool: tool.to_string(),
        outcome: OUTCOME_REFUSED,
        reason: reason.to_string(),
        tool_digest: String::new(),
        pin_generation: 7,
        request_id: format!("req-{ts}"),
    }
}

/// Write three calls through a log attached to `store`, then DROP the log. Returns what was written,
/// so the read-back can be compared against it field by field.
fn write_then_drop(store: &Arc<dyn Store>) -> Vec<McpCallRecord> {
    let log = PlaneCallLog::new();
    log.set_sink(store.clone());
    let a = log
        .record(P, dispatched(1000, "fs_read", "sha256:aaa", 7))
        .expect("first call records");
    let b = log
        .record(P, refused(1001, "fs_write", "not_approved"))
        .expect("second call records");
    let c = log
        .record(P, dispatched(1002, "fs_read", "sha256:aaa", 8))
        .expect("third call records");
    // The log goes out of scope here: every chain position this process held is gone, exactly as it
    // would be across a restart.
    vec![a, b, c]
}

/// Field-by-field equality, written as a DESTRUCTURING bind so a field added to `McpCallRecord`
/// later fails to compile here rather than silently going unchecked. A whole-struct `assert_eq!`
/// would compare a new field too, but would not force anyone to decide what it should survive as.
fn assert_same_record(got: &McpCallRecord, want: &McpCallRecord, at: &str) {
    let McpCallRecord {
        principal,
        seq,
        ts,
        server,
        tool,
        outcome,
        reason,
        tool_digest,
        pin_generation,
        request_id,
        prev_hash,
        hash,
    } = got;
    assert_eq!(principal, &want.principal, "{at}: principal");
    assert_eq!(seq, &want.seq, "{at}: seq");
    assert_eq!(ts, &want.ts, "{at}: ts");
    assert_eq!(server, &want.server, "{at}: server");
    assert_eq!(tool, &want.tool, "{at}: tool");
    assert_eq!(outcome, &want.outcome, "{at}: outcome");
    assert_eq!(reason, &want.reason, "{at}: reason");
    assert_eq!(tool_digest, &want.tool_digest, "{at}: tool_digest");
    assert_eq!(pin_generation, &want.pin_generation, "{at}: pin_generation");
    assert_eq!(request_id, &want.request_id, "{at}: request_id");
    assert_eq!(prev_hash, &want.prev_hash, "{at}: prev_hash");
    assert_eq!(hash, &want.hash, "{at}: hash");
}

// ── DURABILITY, proven by actually restarting ────────────────────────────────────────────────

/// THE DURABILITY PROOF. Write, DROP the log, rebuild a fresh one over the same store, restore, and
/// compare every field of every record. The rebuild is what makes this a restart rather than a read:
/// the second log starts with no chain position at all and learns everything from the store.
#[test]
fn a_durable_store_returns_every_record_field_for_field_across_a_restart() {
    let backing = Arc::new(DurableCallStore::new());
    let store: Arc<dyn Store> = backing.clone();
    let written = write_then_drop(&store);

    // Process 2: nothing carried over.
    let log2 = PlaneCallLog::new();
    log2.set_sink(store.clone());
    assert_eq!(
        log2.len(),
        0,
        "a fresh log holds no chain positions before it reads the store"
    );
    let restored = log2
        .restore_from_store(store.as_ref())
        .expect("the restore reads");

    assert_eq!(restored.principals, 1, "one principal had calls");
    assert_eq!(restored.records, 3, "all three records came back");
    assert_eq!(restored.empty_chains, 0);
    assert!(
        restored.chain_breaks.is_empty(),
        "an untampered chain verifies: {:?}",
        restored.chain_breaks
    );

    let read_back = log2
        .read_back(store.as_ref(), P)
        .expect("the read-back reads");
    assert_eq!(read_back.len(), written.len(), "row count survived");
    for (i, (got, want)) in read_back.iter().zip(written.iter()).enumerate() {
        assert_same_record(got, want, &format!("record {i}"));
    }

    // The chain RESUMES rather than reopening: the next record continues at 4, so nothing collides
    // with a sequence the store already holds.
    assert_eq!(
        log2.next_seq(P),
        4,
        "the restored chain resumes after the persisted tail"
    );
    let fourth = log2
        .record(P, dispatched(1003, "fs_read", "sha256:aaa", 8))
        .expect("the post-restart call records");
    assert_eq!(fourth.seq, 4);
    assert_eq!(
        fourth.prev_hash, written[2].hash,
        "the post-restart record links to the PERSISTED tail, not to a fresh chain"
    );
    assert_eq!(
        log2.verify_principal_chain(store.as_ref(), P)
            .expect("verify reads")
            .expect("the chain spanning the restart verifies"),
        4
    );
}

/// THE PERMANENT PAIRED NEGATIVE. The same sequence against a store that overrides NONE of the
/// call-log methods: every write is ACCEPTED, and nothing is kept. Without this, every assertion
/// above would pass identically on a store that persisted nothing, because the engine would be
/// reading its own RAM back.
#[test]
fn the_ram_default_accepts_every_write_and_keeps_nothing_and_says_so() {
    let store: Arc<dyn Store> = Arc::new(RamDefaultStore::new());

    // Every write SUCCEEDS. This is the trap the durability claim has to survive: an `Ok(())` from
    // the default means only "the backend did not object".
    let written = write_then_drop(&store);
    assert_eq!(written.len(), 3, "all three writes returned Ok");

    let log2 = PlaneCallLog::new();
    log2.set_sink(store.clone());
    let restored = log2
        .restore_from_store(store.as_ref())
        .expect("the restore reads");
    assert_eq!(
        restored,
        super::super::calllog::Restored::default(),
        "the RAM default restores NOTHING — no principals, no records, no empty chains, no breaks"
    );
    assert!(
        log2.read_back(store.as_ref(), P)
            .expect("the read-back reads")
            .is_empty(),
        "the RAM default hands back no rows: durability is a property of the CONFIGURED BACKEND, \
         and this is what not having it looks like"
    );
    // And the loss is not hidden by the chain either: with nothing persisted the chain reopens at 1,
    // which is the honest consequence and is what a restart on this backend really does.
    assert_eq!(
        log2.next_seq(P),
        1,
        "with nothing persisted the chain has nothing to resume from"
    );
}

/// A durable write that FAILS must not burn a sequence number. Advancing the chain first would leave
/// a `seq` nothing occupies, and the verifier would report that hole as tamper evidence forever.
#[test]
fn a_failed_durable_write_leaves_the_sequence_where_it_was() {
    let backing = Arc::new(DurableCallStore::new());
    let store: Arc<dyn Store> = backing.clone();
    let log = PlaneCallLog::new();
    log.set_sink(store.clone());

    log.record(P, dispatched(1000, "fs_read", "sha256:aaa", 7))
        .expect("the first call records");
    assert_eq!(log.next_seq(P), 2);

    backing.set_failing(Some("the backing table is unavailable"));
    let err = log
        .record(P, dispatched(1001, "fs_read", "sha256:aaa", 7))
        .expect_err("a failed durable write is SURFACED, not swallowed");
    assert!(
        err.to_string().contains("the backing table is unavailable"),
        "the store's own reason reaches the caller: {err}"
    );
    assert_eq!(
        log.next_seq(P),
        2,
        "the failed write did NOT consume seq 2 — the next call reuses it"
    );

    backing.set_failing(None);
    let second = log
        .record(P, dispatched(1002, "fs_read", "sha256:aaa", 7))
        .expect("the retry records");
    assert_eq!(second.seq, 2, "seq 2 was still free");
    assert_eq!(
        log.verify_principal_chain(store.as_ref(), P)
            .expect("verify reads")
            .expect("the chain is contiguous across the failed write"),
        2
    );
}

// ── TAMPER, applied to PERSISTED ROWS through the store ──────────────────────────────────────

/// EDIT one persisted row's field in place. The verifier names the position and calls it a digest
/// mismatch, which is the operator-visible difference between "a row was edited" and "a row is
/// missing".
#[test]
fn editing_a_persisted_row_is_reported_as_a_digest_mismatch_at_its_position() {
    let backing = Arc::new(DurableCallStore::new());
    let store: Arc<dyn Store> = backing.clone();
    write_then_drop(&store);

    let log = PlaneCallLog::new();
    assert!(
        log.verify_principal_chain(store.as_ref(), P)
            .expect("verify reads")
            .is_ok(),
        "the chain verifies BEFORE the tamper — otherwise this test proves nothing"
    );

    // The refusal at seq 2 is rewritten to look like a successful dispatch: the exact edit somebody
    // covering their tracks would make.
    backing.tamper(P, 2, |row| {
        row.outcome = OUTCOME_DISPATCHED.to_string();
        row.reason = String::new();
    });

    let brk = log
        .verify_principal_chain(store.as_ref(), P)
        .expect("verify reads")
        .expect_err("the edited row is detected");
    assert_eq!(brk.at_index, 2, "the break is reported AT the edited row");
    assert_eq!(brk.seq, 2);
    assert_eq!(brk.scope, P);
    assert!(
        matches!(brk.kind, ChainBreakKind::DigestMismatch { .. }),
        "an in-place edit is a DIGEST mismatch, not a link one: {:?}",
        brk.kind
    );
    assert!(
        brk.to_string().contains("EDITED"),
        "the operator is told which of the failures this is: {brk}"
    );
}

/// SPLICE a persisted row out. Removing the middle record leaves the survivors' sequence
/// non-contiguous, which is the failure a link check alone would misreport.
#[test]
fn removing_a_persisted_row_is_reported_as_a_sequence_break() {
    let backing = Arc::new(DurableCallStore::new());
    let store: Arc<dyn Store> = backing.clone();
    write_then_drop(&store);
    backing.drop_row(P, 2);

    let log = PlaneCallLog::new();
    let brk = log
        .verify_principal_chain(store.as_ref(), P)
        .expect("verify reads")
        .expect_err("the missing row is detected");
    assert_eq!(
        brk.at_index, 2,
        "the break is at the position that now lies"
    );
    assert_eq!(
        brk.kind,
        ChainBreakKind::SequenceBreak {
            expected: 2,
            found: 3
        }
    );
}

/// REWRITE only a persisted row's LINK. The row's own digest is repaired so a digest check alone
/// would pass — this is the axis a lazier verifier misses.
#[test]
fn rewriting_only_a_persisted_rows_link_is_reported_as_a_link_mismatch() {
    let backing = Arc::new(DurableCallStore::new());
    let store: Arc<dyn Store> = backing.clone();
    let written = write_then_drop(&store);

    // Re-point record 3 at record 1, and RECOMPUTE its digest so the row is self-consistent. Only
    // the link is now wrong, which is what an inserted or removed neighbour looks like.
    backing.tamper(P, 3, |row| {
        row.prev_hash = written[0].hash.clone();
    });
    let relinked = {
        let rows = store.list_mcp_calls(P).expect("read");
        rows[2].clone()
    };
    // Repair the self-digest THROUGH the store, using the engine's own chain arithmetic rather than
    // a hand-built hash: a chain re-derived from the tampered link.
    let mut repair = CallChain::from_persisted_unverified(&[written[0].clone()]);
    let rebuilt = repair.append(
        P,
        CallInput {
            ts: relinked.ts,
            server: relinked.server.clone(),
            tool: relinked.tool.clone(),
            outcome: OUTCOME_DISPATCHED,
            reason: relinked.reason.clone(),
            tool_digest: relinked.tool_digest.clone(),
            pin_generation: relinked.pin_generation,
            request_id: relinked.request_id.clone(),
        },
    );
    backing.tamper(P, 3, |row| {
        row.hash = rebuilt.hash.clone();
    });

    let log = PlaneCallLog::new();
    let brk = log
        .verify_principal_chain(store.as_ref(), P)
        .expect("verify reads")
        .expect_err("a self-consistent row with a rewritten link is still detected");
    assert_eq!(brk.at_index, 3);
    assert!(
        matches!(brk.kind, ChainBreakKind::LinkMismatch { .. }),
        "the LINK is the axis that failed here, and the report says so: {:?}",
        brk.kind
    );
    assert!(
        brk.to_string().contains("INSERTED, REMOVED or REORDERED"),
        "the operator is told what an unlinked row means: {brk}"
    );
}

/// A record belonging to ANOTHER principal, sitting in this principal's chain. Reported as its own
/// kind, because a chain that silently accepted it would make one caller's evidence depend on
/// another caller's rows.
#[test]
fn a_foreign_principals_record_in_a_chain_is_its_own_break_kind() {
    let backing = Arc::new(DurableCallStore::new());
    let store: Arc<dyn Store> = backing.clone();
    write_then_drop(&store);
    // The backend's principal COLUMN is corrupted: the row still sits at this principal's chain
    // position, but claims to belong to somebody else. That is what the store hands back, so that is
    // what the verifier is asked about.
    backing.tamper(P, 2, |row| row.principal = "key_beta".to_string());

    let chain = store.list_mcp_calls(P).expect("read");
    assert_eq!(chain.len(), 3, "all three rows are still returned for {P}");
    let brk = verify_chain(&chain).expect_err("the foreign row is detected");
    assert_eq!(
        brk.kind,
        ChainBreakKind::ForeignScope {
            expected: P.to_string(),
            found: "key_beta".to_string(),
        }
    );
}

/// THE JUDGEMENT CALL, pinned: a chain break at boot is REPORTED and the rows are STILL RESTORED.
///
/// Refusing to restore a chain that does not verify would hand anyone with write access to the
/// backing table a DELETION primitive — corrupt one byte of one record and a caller's entire call
/// history stops being loaded. A detection control must never be usable that way, so the break is
/// named loudly, every row is still restored, and the chain continues from the broken tail instead
/// of being silently re-based onto it.
#[test]
fn a_boot_chain_break_is_reported_while_the_rows_are_still_restored() {
    let backing = Arc::new(DurableCallStore::new());
    let store: Arc<dyn Store> = backing.clone();
    let written = write_then_drop(&store);
    backing.tamper(P, 2, |row| row.tool = "fs_exfiltrate".to_string());

    let log2 = PlaneCallLog::new();
    log2.set_sink(store.clone());
    let restored = log2
        .restore_from_store(store.as_ref())
        .expect("the restore reads");

    assert_eq!(restored.chain_breaks.len(), 1, "the break is REPORTED");
    assert_eq!(restored.chain_breaks[0].at_index, 2);
    assert_eq!(restored.principals, 1);
    assert_eq!(
        restored.records, 3,
        "and all three rows are STILL RESTORED — refusing would make this a deletion primitive"
    );
    assert_eq!(
        backing.row_count(),
        3,
        "the restore destroyed nothing in the store either"
    );
    assert_eq!(
        log2.next_seq(P),
        4,
        "the chain continues from the BROKEN TAIL rather than reopening at 1"
    );

    // The evidence survives the restore: asking again still reports the same break, so a second
    // operator looking later sees what the first one saw.
    let brk = log2
        .verify_principal_chain(store.as_ref(), P)
        .expect("verify reads")
        .expect_err("the break is still there after the restore");
    assert_eq!(brk.at_index, 2);
    assert_ne!(
        written[1].tool, "fs_exfiltrate",
        "the tamper really did change what was written"
    );
}

/// A principal the store ENUMERATES but returns no rows for is counted, not skipped. It is the one
/// shape the verifier cannot judge alone (an empty list verifies), and it is what wholesale deletion
/// of one caller's evidence looks like.
#[test]
fn an_enumerated_principal_with_no_rows_is_reported_as_an_empty_chain() {
    // First, the CONTROL: an honest backend that lost every row also stops NAMING the principal, so
    // there is nothing to count and nothing to report. Without this, the assertion below would not
    // distinguish "counted the empty chain" from "counted every principal".
    let backing = Arc::new(DurableCallStore::new());
    let store: Arc<dyn Store> = backing.clone();
    write_then_drop(&store);
    for seq in 1..=3 {
        backing.drop_row(P, seq);
    }
    assert!(
        store
            .list_mcp_call_principals()
            .expect("enumerate")
            .is_empty(),
        "with no rows at all an honest backend names no principals"
    );
    let control = PlaneCallLog::new();
    assert_eq!(
        control
            .restore_from_store(store.as_ref())
            .expect("the restore reads")
            .empty_chains,
        0,
        "nothing enumerated means nothing to count"
    );

    let store2: Arc<dyn Store> = Arc::new(NamesOnePrincipalWithNoRows);
    let log2 = PlaneCallLog::new();
    let restored = log2
        .restore_from_store(store2.as_ref())
        .expect("the restore reads");
    assert_eq!(restored.principals, 1);
    assert_eq!(restored.records, 0);
    assert_eq!(
        restored.empty_chains, 1,
        "the discrepancy is COUNTED rather than skipped silently"
    );
    assert_eq!(
        log2.next_seq(P),
        1,
        "an empty chain reopens at 1, which is all it can honestly do"
    );
}

/// A store that NAMES a principal and then hands back nothing for it — the enumerated-but-empty
/// shape, which no honest backend should produce and which is exactly why it is counted.
struct NamesOnePrincipalWithNoRows;

impl Store for NamesOnePrincipalWithNoRows {
    fn put_key(&self, _key: &busbar_api::VirtualKey) -> busbar_api::StoreResult<()> {
        Ok(())
    }
    fn get_key(&self, _id: &str) -> busbar_api::StoreResult<Option<busbar_api::VirtualKey>> {
        Ok(None)
    }
    fn list_keys(&self) -> busbar_api::StoreResult<Vec<busbar_api::VirtualKey>> {
        Ok(Vec::new())
    }
    fn delete_key(&self, _id: &str) -> busbar_api::StoreResult<()> {
        Ok(())
    }
    fn get_usage(
        &self,
        _bucket_id: &str,
        _window_start: u64,
    ) -> busbar_api::StoreResult<busbar_api::UsageLedger> {
        Ok(busbar_api::UsageLedger::default())
    }
    fn put_usage(
        &self,
        _bucket_id: &str,
        _window_start: u64,
        _ledger: &busbar_api::UsageLedger,
    ) -> busbar_api::StoreResult<()> {
        Ok(())
    }
    fn add_metering(&self, _delta: &busbar_api::MeteringDelta) -> busbar_api::StoreResult<()> {
        Ok(())
    }
    fn list_metering(&self, _bucket: u64) -> busbar_api::StoreResult<Vec<busbar_api::MeteringRow>> {
        Ok(Vec::new())
    }
    fn list_mcp_call_principals(&self) -> busbar_api::StoreResult<Vec<String>> {
        Ok(vec![P.to_string()])
    }
}

// ── the digest's coverage, stated as an exhaustive set ───────────────────────────────────────

/// EVERY chained field changes the digest, and `request_id` does NOT — asserted as a SET over the
/// record's fields rather than a handful of spot checks, so a field added later cannot quietly land
/// outside the digest.
///
/// The list is built by DESTRUCTURING the record, so adding a field to `McpCallRecord` fails to
/// compile here until somebody decides which side of the line it belongs on. The counts are exact
/// equalities, not floors: "how many fields are chained" is a number that must be re-decided, never
/// merely met.
#[test]
fn the_digest_covers_every_chained_field_and_deliberately_excludes_the_request_id() {
    let base = {
        let mut chain = CallChain::new();
        chain.append(P, dispatched(1000, "fs_read", "sha256:aaa", 7))
    };
    // Exhaustive by construction: this bind fails to compile if a field is added.
    let McpCallRecord {
        principal: _,
        seq: _,
        ts: _,
        server: _,
        tool: _,
        outcome: _,
        reason: _,
        tool_digest: _,
        pin_generation: _,
        request_id: _,
        prev_hash: _,
        hash: _,
    } = &base;

    // Each mutation is applied to a copy of the SAME record, then the chain is asked to re-derive
    // that record's digest by re-appending it. `verify_chain` is the arbiter, so this tests the
    // digest through the same door production uses.
    let mut chained_fields = 0;
    let mut ignored_fields = 0;
    let mut mutate = |name: &str, edit: fn(&mut McpCallRecord)| {
        let mut candidate = base.clone();
        edit(&mut candidate);
        let broken = verify_chain(std::slice::from_ref(&candidate)).is_err();
        if broken {
            chained_fields += 1;
        } else {
            ignored_fields += 1;
        }
        (name.to_string(), broken)
    };

    let results = [
        mutate("ts", |r| r.ts += 1),
        mutate("server", |r| r.server = "other".to_string()),
        mutate("tool", |r| r.tool = "fs_write".to_string()),
        mutate("outcome", |r| r.outcome = OUTCOME_REFUSED.to_string()),
        mutate("reason", |r| r.reason = "not_granted".to_string()),
        mutate("tool_digest", |r| r.tool_digest = "sha256:zzz".to_string()),
        mutate("pin_generation", |r| r.pin_generation += 1),
        mutate("request_id", |r| r.request_id = "req-other".to_string()),
    ];
    let results = results.to_vec();

    let chained: std::collections::BTreeSet<&str> = results
        .iter()
        .filter(|(_, broken)| *broken)
        .map(|(n, _)| n.as_str())
        .collect();
    let ignored: std::collections::BTreeSet<&str> = results
        .iter()
        .filter(|(_, broken)| !*broken)
        .map(|(n, _)| n.as_str())
        .collect();

    // SET EQUALITY both directions: under- and over-coverage both fail.
    assert_eq!(
        chained,
        [
            "ts",
            "server",
            "tool",
            "outcome",
            "reason",
            "tool_digest",
            "pin_generation"
        ]
        .into_iter()
        .collect::<std::collections::BTreeSet<&str>>(),
        "exactly these fields are inside the digest"
    );
    assert_eq!(
        ignored,
        ["request_id"]
            .into_iter()
            .collect::<std::collections::BTreeSet<&str>>(),
        "request_id is the ONLY field deliberately outside the digest — it is a join key that is \
         absent on paths with no inbound request, and a sometimes-absent field must not be able to \
         make an intact chain unverifiable"
    );
    assert_eq!(chained_fields, 7, "the mutation battery really ran");
    assert_eq!(ignored_fields, 1, "the mutation battery really ran");

    // `principal`, `seq` and `prev_hash` are covered by the chain-level kinds above rather than
    // here, because mutating them changes WHICH break is reported, not merely whether one is.
    assert_eq!(
        base.prev_hash, "",
        "the first record of a chain has no predecessor"
    );
    assert_eq!(base.seq, 1);
}

/// The framing is LENGTH-PREFIXED, so a caller who controls one field cannot forge another split
/// that hashes the same. Two records that differ only in where a boundary falls must differ.
#[test]
fn field_boundaries_cannot_be_forged_by_moving_text_across_them() {
    let mut left = CallChain::new();
    let a = left.append(
        P,
        CallInput {
            ts: 1,
            server: "fs".to_string(),
            tool: "read".to_string(),
            outcome: OUTCOME_DISPATCHED,
            reason: String::new(),
            tool_digest: String::new(),
            pin_generation: 1,
            request_id: String::new(),
        },
    );
    let mut right = CallChain::new();
    let b = right.append(
        P,
        CallInput {
            ts: 1,
            // The same concatenated bytes, split one character further along.
            server: "f".to_string(),
            tool: "sread".to_string(),
            outcome: OUTCOME_DISPATCHED,
            reason: String::new(),
            tool_digest: String::new(),
            pin_generation: 1,
            request_id: String::new(),
        },
    );
    assert_ne!(
        a.hash, b.hash,
        "`fs`+`read` and `f`+`sread` must not collide — that is what the length prefixes buy"
    );
}

// ── the append contract, and retention ───────────────────────────────────────────────────────

/// A DIFFERENT record on an occupied chain position is a fork and is refused. The retry — the
/// byte-identical write — succeeds, because failing it would make a healthy engine that reconnected
/// mid-write look broken.
#[test]
fn an_occupied_chain_position_takes_the_retry_and_refuses_the_fork() {
    let backing = Arc::new(DurableCallStore::new());
    let store: Arc<dyn Store> = backing.clone();
    let log = PlaneCallLog::new();
    log.set_sink(store.clone());
    let first = log
        .record(P, dispatched(1000, "fs_read", "sha256:aaa", 7))
        .expect("records");

    assert!(
        store.append_mcp_call(&first).is_ok(),
        "the byte-identical retry succeeds"
    );
    let mut fork = first.clone();
    fork.tool = "fs_write".to_string();
    assert!(
        store.append_mcp_call(&fork).is_err(),
        "a DIFFERENT record claiming seq 1 is a forked log and is refused, never overwritten"
    );
}

/// Retention drops old rows and does NOT reset the chain. Reopening at 1 after a purge would make
/// every subsequent record collide with a position the store may still hold.
#[test]
fn retention_purges_rows_without_rewinding_the_chain() {
    let backing = Arc::new(DurableCallStore::new());
    let store: Arc<dyn Store> = backing.clone();
    let log = PlaneCallLog::new();
    log.set_sink(store.clone());
    log.record(P, dispatched(1000, "fs_read", "sha256:aaa", 7))
        .expect("records");
    log.record(P, dispatched(2000, "fs_read", "sha256:aaa", 7))
        .expect("records");

    assert_eq!(log.compact(1500).expect("compact runs"), 1, "one row went");
    assert_eq!(backing.row_count(), 1);
    assert_eq!(
        log.next_seq(P),
        3,
        "the chain did NOT rewind: the next record still takes seq 3"
    );

    // The RAM default has nothing to purge and reports exactly that, rather than claiming a number.
    let ram = PlaneCallLog::new();
    ram.set_sink(Arc::new(RamDefaultStore::new()));
    assert_eq!(
        ram.compact(1500).expect("compact runs"),
        0,
        "the RAM default reports nothing purged rather than claiming a purge it did not do"
    );
}

/// An EMPTY chain verifies, and that is stated rather than quietly true: "this principal made no
/// calls" is indistinguishable from "every record was deleted" using the records alone. The gap is
/// closed by `list_mcp_call_principals` naming the principal, which is why the restore counts it.
#[test]
fn an_empty_chain_verifies_because_the_records_alone_cannot_say_otherwise() {
    assert!(verify_chain::<McpCallRecord>(&[]).is_ok());
}

/// THE PROCESS-GLOBAL is the seam a call site actually uses, so it is exercised here rather than
/// left to be discovered by whoever wires the dispatcher. Process state, not config-derived state:
/// a config apply must not reset a chain position, because reopening a chain at seq 1 under a
/// principal that already has one produces two chains that each verify and together describe
/// nothing.
///
/// Recorded against a principal no other test names, and with NO sink attached — the RAM posture, so
/// this asserts the seam works without making a durability claim it has not earned.
#[test]
fn the_process_global_call_log_is_the_seam_a_call_site_records_through() {
    use super::super::calllog::CALLS;
    const GLOBAL_P: &str = "key_process_global_probe";
    let before = CALLS.next_seq(GLOBAL_P);
    let rec = CALLS
        .record(GLOBAL_P, dispatched(3000, "fs_read", "sha256:ggg", 11))
        .expect("the global records with no sink attached");
    assert_eq!(
        rec.seq, before,
        "the record takes the sequence the chain offered"
    );
    assert_eq!(
        CALLS.next_seq(GLOBAL_P),
        before + 1,
        "and the global chain advanced"
    );
    assert!(
        CALLS.len() >= 1,
        "the global holds at least this principal's chain position"
    );
}

/// `CallChain::default()` MUST equal `CallChain::new()`. A derived `Default` gives `next_seq: 0`,
/// and a chain that hands out `seq` 0 is invalid at its very first record — every verifier in this
/// file reports it as a sequence break, and every restore then reports a healthy log as tampered.
///
/// This is a REGRESSION GUARD with a real regression behind it: replacing
/// `or_insert_with(CallChain::new)` with `or_default()` (a clippy suggestion) introduced exactly
/// that, and the module's own focused test run did not distinguish the two constructors.
#[test]
fn the_default_chain_is_the_new_chain_because_a_derived_default_starts_at_zero() {
    assert_eq!(CallChain::default(), CallChain::new());
    assert_eq!(
        CallChain::default().next_seq(),
        1,
        "the first record of a chain is seq 1, never 0"
    );
}
