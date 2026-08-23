// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for the generic scope-keyed [`crate::audit::journal::Journal`].
//!
//! Proven over a THROWAWAY record type (`Widget`) that exists nowhere else in the tree, so the
//! journal's behaviour is exercised WITHOUT any plane's record — the whole point of the cleave is
//! that this machinery is plane-agnostic. The record type is deliberately unlike the real two (a
//! different scope noun, a different field set) so "a stream costs a record type and an envelope" is
//! demonstrated rather than assumed from a copy.
//!
//! The load-bearing properties, each proven the hard way:
//!  1. **Durability by RESTART.** A write's `Ok` proves nothing; every durability claim writes
//!     through one journal, DROPS it, rebuilds over the same store, and reads back.
//!  2. **Write-ordering.** A failed durable append must NOT burn a sequence — the retry reuses it.
//!  3. **LRU + store-resume.** An evicted scope resumes from its persisted tail, never forking at 1.
//!  4. **Tamper is reported, not deleted.** A corrupted stored row restores AND names the break.

use super::{Journal, JournalRecord, NeutralRecord, Restored};
use crate::audit::{frame_prelude, ChainLabels, ChainedRecord, Digest, Framing};
use crate::plane::store::{decode, encode, PlaneStore};
use busbar_api::{PlaneDisposition, PlaneRecord, PlaneSelector, StoreError, StoreResult};
use std::sync::{Arc, Mutex};

// ── THE THROWAWAY RECORD ────────────────────────────────────────────────────────────────────────

/// "tenant `t` moved `amount`" — a chained record for a stream busbar does not have.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct Widget {
    tenant: String,
    seq: u64,
    amount: u64,
    prev_hash: String,
    hash: String,
}

struct WidgetInput {
    amount: u64,
}

const KIND_WIDGET: &str = "widget_test";

impl ChainedRecord for Widget {
    type Input = WidgetInput;
    const LABELS: &'static ChainLabels = &ChainLabels {
        chain: "the widget test chain",
        scope: "tenant",
    };
    const FRAMING: Framing = Framing::LengthPrefixed;
    fn scope_of(&self) -> &str {
        &self.tenant
    }
    fn seq(&self) -> u64 {
        self.seq
    }
    fn prev_hash(&self) -> &str {
        &self.prev_hash
    }
    fn hash(&self) -> &str {
        &self.hash
    }
    fn link(scope: &str, seq: u64, prev_hash: String, input: WidgetInput) -> Self {
        Widget {
            tenant: scope.to_string(),
            seq,
            amount: input.amount,
            prev_hash,
            hash: String::new(),
        }
    }
    fn set_hash(&mut self, hash: String) {
        self.hash = hash;
    }
    fn digest_fields(&self, d: &mut Digest) {
        d.text(&self.prev_hash)
            .text(&self.tenant)
            .num(self.seq)
            .num(self.amount);
    }
}

impl JournalRecord for Widget {
    const KIND: &'static str = KIND_WIDGET;
    fn to_plane_record(&self) -> StoreResult<PlaneRecord> {
        Ok(PlaneRecord {
            kind: KIND_WIDGET.to_string(),
            id: self.tenant.clone(),
            parent: Some(self.tenant.clone()),
            seq: self.seq,
            ts: 0,
            disposition: PlaneDisposition::Active,
            body: encode(self)?,
        })
    }
}

// ── A WRITABLE MOCK STORE ───────────────────────────────────────────────────────────────────────
//
// Holds appended bodies per parent, honours the append semantics the journal relies on, and can be
// told to fail appends (the write-ordering axis) or to have one of its rows tampered (the tamper
// axis) — the only two ways this file simulates a hostile backend.

#[derive(Default)]
struct MockStore {
    rows: Mutex<Vec<PlaneRecord>>,
    fail_appends: Mutex<bool>,
}

impl MockStore {
    fn new() -> Self {
        Self::default()
    }
    fn set_failing(&self, on: bool) {
        *self.fail_appends.lock().unwrap() = on;
    }
    /// Corrupt the first stored row's body so its chain no longer verifies.
    fn tamper_first(&self) {
        let mut rows = self.rows.lock().unwrap();
        if let Some(r) = rows.first_mut() {
            let mut w: Widget = serde_json::from_slice(&r.body).unwrap();
            w.amount = w.amount.wrapping_add(1); // a field the digest covers, hash left stale
            r.body = serde_json::to_vec(&w).unwrap();
        }
    }
}

impl PlaneStore for MockStore {
    fn upsert_plane_record(&self, record: &PlaneRecord) -> StoreResult<()> {
        self.rows.lock().unwrap().push(record.clone());
        Ok(())
    }
    fn get_plane_record(&self, _kind: &str, _id: &str) -> StoreResult<Option<Vec<u8>>> {
        Ok(None)
    }
    fn append_plane_record(&self, record: &PlaneRecord) -> StoreResult<()> {
        if *self.fail_appends.lock().unwrap() {
            return Err(StoreError("append refused (test)".to_string()));
        }
        self.rows.lock().unwrap().push(record.clone());
        Ok(())
    }
    fn list_plane_records(
        &self,
        kind: &str,
        selector: &PlaneSelector,
    ) -> StoreResult<Vec<Vec<u8>>> {
        let rows = self.rows.lock().unwrap();
        Ok(rows
            .iter()
            .filter(|r| r.kind == kind)
            .filter(|r| match selector {
                PlaneSelector::All => true,
                PlaneSelector::Parent(p) => r.parent.as_deref() == Some(p.as_str()),
            })
            .map(|r| r.body.clone())
            .collect())
    }
    fn list_plane_record_parents(&self, kind: &str) -> StoreResult<Vec<String>> {
        let rows = self.rows.lock().unwrap();
        let mut parents: Vec<String> = rows
            .iter()
            .filter(|r| r.kind == kind)
            .filter_map(|r| r.parent.clone())
            .collect();
        parents.sort();
        parents.dedup();
        Ok(parents)
    }
    fn purge_plane_records_before(&self, _kind: &str, _before: u64) -> StoreResult<u64> {
        Ok(0)
    }
    fn delete_plane_record(&self, _kind: &str, _id: &str) -> StoreResult<()> {
        Ok(())
    }
    fn redeem_plane_token(
        &self,
        _kind: &str,
        _token: &str,
        _expires_at: u64,
        _now: u64,
    ) -> StoreResult<bool> {
        Ok(true)
    }
}

fn write(j: &Journal<Widget>, tenant: &str, amount: u64) -> Widget {
    j.record(tenant, WidgetInput { amount }).expect("record")
}

/// Durability by restart: two records written through one journal are read back, chain intact, by a
/// fresh journal over the same store — and the fresh journal resumes the sequence at 3.
#[test]
fn records_survive_a_restart_and_the_chain_verifies() {
    let store = Arc::new(MockStore::new());
    let j1: Journal<Widget> = Journal::new(1024);
    j1.set_sink(store.clone());
    write(&j1, "acme", 10);
    write(&j1, "acme", 20);
    drop(j1);

    let j2: Journal<Widget> = Journal::new(1024);
    j2.set_sink(store.clone());
    let restored = j2.restore_from_store(store.as_ref()).unwrap();
    assert_eq!(
        restored,
        Restored {
            scopes: 1,
            records: 2,
            empty_scopes: vec![],
            chain_breaks: vec![],
        }
    );
    assert_eq!(
        j2.next_seq("acme"),
        3,
        "the resumed chain continues, not forks"
    );
}

/// The RAM default: with no sink, writes stay in RAM and a restore over an empty store finds nothing.
/// The honest zero, not a papered-over one.
#[test]
fn no_sink_is_ephemeral() {
    let j: Journal<Widget> = Journal::new(1024);
    let r = write(&j, "acme", 1);
    assert_eq!(r.seq, 1);
    assert_eq!(j.len(), 1);
    let store = MockStore::new();
    let restored = j.restore_from_store(&store).unwrap();
    assert_eq!(
        restored,
        Restored::default(),
        "nothing persisted, nothing restored"
    );
}

/// WRITE-ORDERING: a failed durable append must not burn a sequence. The failing write errors and
/// leaves the position untouched; the retry after the store recovers reuses the same `seq` and the
/// chain stays contiguous.
#[test]
fn a_failed_write_does_not_burn_a_sequence() {
    let store = Arc::new(MockStore::new());
    let j: Journal<Widget> = Journal::new(1024);
    j.set_sink(store.clone());
    write(&j, "acme", 1); // seq 1, durable
    assert_eq!(j.next_seq("acme"), 2);

    store.set_failing(true);
    let err = j.record("acme", WidgetInput { amount: 2 });
    assert!(
        err.is_err(),
        "the durable write failed, so record must surface it"
    );
    assert_eq!(
        j.next_seq("acme"),
        2,
        "a failed write left the position where it was — the seq is NOT burned"
    );

    store.set_failing(false);
    let r = write(&j, "acme", 2);
    assert_eq!(
        r.seq, 2,
        "the retry reuses the sequence the failed write did not consume"
    );
    // And the whole chain, read back fresh, verifies with no gap.
    let j2: Journal<Widget> = Journal::new(1024);
    j2.set_sink(store.clone());
    let restored = j2.restore_from_store(store.as_ref()).unwrap();
    assert!(restored.chain_breaks.is_empty());
    assert_eq!(restored.records, 2);
}

/// LRU + store-resume: with a cap of 2, writing to a third scope evicts the coldest, latches
/// overflow, and a later write to the evicted scope RESUMES from its persisted tail rather than
/// forking a second chain at seq 1.
#[test]
fn an_evicted_scope_resumes_from_the_store_not_from_seq_one() {
    let store = Arc::new(MockStore::new());
    let j: Journal<Widget> = Journal::new(2);
    j.set_sink(store.clone());
    write(&j, "a", 1);
    write(&j, "a", 1); // a: seq 1,2  (most-recently-used)
    write(&j, "b", 1);
    write(&j, "c", 1); // inserting c evicts the coldest (b), overflow latches; a and c resident
    assert_eq!(j.len(), 2);

    // `a` is still resident (it was used after b); write again — continues its own chain.
    let ra = write(&j, "a", 9);
    assert_eq!(ra.seq, 3);

    // Force `a` out: touch b then c again so a becomes coldest and is evicted.
    write(&j, "b", 1); // resumes b from store tail (b had seq 1) -> seq 2
    write(&j, "c", 1); // c -> seq 2; inserting pushed a out
                       // Now a is evicted. Its next write must resume from the store (tail seq 3), not reopen at 1.
    let ra2 = write(&j, "a", 8);
    assert_eq!(
        ra2.seq, 4,
        "the evicted scope resumed from its persisted tail (seq 3) and continued to 4"
    );

    // The whole `a` chain verifies end to end.
    let j2: Journal<Widget> = Journal::new(1024);
    j2.set_sink(store.clone());
    let restored = j2.restore_from_store(store.as_ref()).unwrap();
    assert!(
        restored.chain_breaks.is_empty(),
        "no fork: {:?}",
        restored.chain_breaks
    );
}

// ── THE NEUTRAL PATH — a record whose durable body is `{seq, prev_hash, hash, content}` ───────────
//
// Mirrors the shape a plane reaches over the host vtable: `content` is an opaque pre-framed suffix and
// the digest is `frame_prelude(..) ⧺ content` fed RAW (byte-identical to the host-side journal). The
// scope is supplied by the caller, never read from the body — so the reframe callback captures it.

/// A neutral record carrying an opaque `content` suffix. Its digest is the framed prelude followed by
/// the suffix RAW — the SAME shape `plane_host::journal::PlaneJournalRecord` uses.
#[derive(Clone)]
struct NeutralRec {
    tenant: String,
    seq: u64,
    content: Vec<u8>,
    prev_hash: String,
    hash: String,
}

struct NeutralInput {
    content: Vec<u8>,
}

const KIND_NEUTRAL: &str = "neutral_test";

impl ChainedRecord for NeutralRec {
    type Input = NeutralInput;
    const LABELS: &'static ChainLabels = &ChainLabels {
        chain: "the neutral test chain",
        scope: "tenant",
    };
    // Unused for framing: `digest_fields` frames the prelude itself and appends the suffix RAW.
    const FRAMING: Framing = Framing::LengthPrefixed;
    fn scope_of(&self) -> &str {
        &self.tenant
    }
    fn seq(&self) -> u64 {
        self.seq
    }
    fn prev_hash(&self) -> &str {
        &self.prev_hash
    }
    fn hash(&self) -> &str {
        &self.hash
    }
    fn link(scope: &str, seq: u64, prev_hash: String, input: NeutralInput) -> Self {
        NeutralRec {
            tenant: scope.to_string(),
            seq,
            content: input.content,
            prev_hash,
            hash: String::new(),
        }
    }
    fn set_hash(&mut self, hash: String) {
        self.hash = hash;
    }
    fn digest_fields(&self, d: &mut Digest) {
        d.raw(&frame_prelude(
            Framing::LengthPrefixed,
            &self.prev_hash,
            Some(&self.tenant),
            self.seq,
        ));
        d.raw(&self.content);
    }
}

impl NeutralRecord for NeutralRec {
    fn content(&self) -> &[u8] {
        &self.content
    }
}

/// The plane-side reframe for the neutral test: decode the journal's own `NeutralBody` back into a
/// `NeutralRec`, taking the scope from the store parent (never the body).
fn neutral_reframe(scope: &str, body: &[u8]) -> StoreResult<NeutralRec> {
    let nb: super::NeutralBody = decode(body)?;
    Ok(NeutralRec {
        tenant: scope.to_string(),
        seq: nb.seq,
        content: nb.content,
        prev_hash: nb.prev_hash,
        hash: nb.hash,
    })
}

fn write_neutral(j: &Journal<NeutralRec>, tenant: &str, content: &[u8]) -> NeutralRec {
    j.append_scoped(
        KIND_NEUTRAL,
        tenant,
        NeutralInput {
            content: content.to_vec(),
        },
        &neutral_reframe,
    )
    .expect("append_scoped")
}

/// The neutral durable path survives a restart: two records appended via `append_scoped` (persisting
/// the neutral `{seq, prev_hash, hash, content}` body) are read back by a fresh journal via
/// `restore_scoped` — chain intact, sequence resumed at 3, zero breaks — and `verify_scoped` agrees.
#[test]
fn neutral_records_survive_a_restart_and_the_chain_verifies() {
    let store = Arc::new(MockStore::new());
    let j1: Journal<NeutralRec> = Journal::new(1024);
    j1.set_sink(store.clone());
    write_neutral(&j1, "acme", b"|first");
    write_neutral(&j1, "acme", b"|second");
    drop(j1);

    let j2: Journal<NeutralRec> = Journal::new(1024);
    j2.set_sink(store.clone());
    let restored = j2
        .restore_scoped(KIND_NEUTRAL, store.as_ref(), &neutral_reframe)
        .unwrap();
    assert_eq!(
        restored,
        Restored {
            scopes: 1,
            records: 2,
            empty_scopes: vec![],
            chain_breaks: vec![],
        }
    );
    assert_eq!(j2.next_seq("acme"), 3, "the resumed chain continues, not forks");
    assert_eq!(
        j2.verify_scoped(KIND_NEUTRAL, "acme", store.as_ref(), &neutral_reframe)
            .unwrap(),
        None,
        "the persisted neutral chain verifies"
    );
    // Retention runs through the neutral kind (this MockStore keeps everything → 0 purged).
    assert_eq!(j2.compact_scoped(KIND_NEUTRAL, u64::MAX).unwrap(), 0);
}

/// Neutral write-ordering: a failed durable append does not burn a sequence on the neutral path
/// either — the retry reuses the sequence the failed write did not consume.
#[test]
fn neutral_failed_write_does_not_burn_a_sequence() {
    let store = Arc::new(MockStore::new());
    let j: Journal<NeutralRec> = Journal::new(1024);
    j.set_sink(store.clone());
    write_neutral(&j, "acme", b"|one");
    assert_eq!(j.next_seq("acme"), 2);

    store.set_failing(true);
    let err = j.append_scoped(
        KIND_NEUTRAL,
        "acme",
        NeutralInput {
            content: b"|two".to_vec(),
        },
        &neutral_reframe,
    );
    assert!(err.is_err(), "the durable write failed, so append must surface it");
    assert_eq!(j.next_seq("acme"), 2, "a failed write did NOT burn the sequence");

    store.set_failing(false);
    let r = write_neutral(&j, "acme", b"|two");
    assert_eq!(r.seq, 2, "the retry reuses the sequence");
}

/// TAMPER is reported and still restored: a corrupted stored row is named in `chain_breaks`, and the
/// chain still resumes from its (broken) tail — refusing would let anyone who can write the store
/// delete a scope's history by corrupting one byte.
#[test]
fn a_tampered_row_is_reported_and_still_restored() {
    let store = Arc::new(MockStore::new());
    let j1: Journal<Widget> = Journal::new(1024);
    j1.set_sink(store.clone());
    write(&j1, "acme", 10);
    write(&j1, "acme", 20);
    drop(j1);
    store.tamper_first();

    let j2: Journal<Widget> = Journal::new(1024);
    j2.set_sink(store.clone());
    let restored = j2.restore_from_store(store.as_ref()).unwrap();
    assert_eq!(restored.chain_breaks.len(), 1, "the tamper is reported");
    assert_eq!(restored.scopes, 1, "and the scope is still restored");
    assert_eq!(j2.next_seq("acme"), 3, "resumed from the tail, not refused");
}
