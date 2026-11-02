// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for the generic scope-keyed [`crate::audit::journal::Journal`].
//!
//! Proven over a THROWAWAY record type (`NeutralRec`) that exists nowhere else in the tree, so the
//! journal's behaviour is exercised WITHOUT any plane's record — this machinery is plane-agnostic.
//!
//! The load-bearing properties, each proven the hard way:
//!  1. **Durability by RESTART.** A write's `Ok` proves nothing; every durability claim writes
//!     through one journal, DROPS it, rebuilds over the same store, and reads back.
//!  2. **Write-ordering.** A failed durable append must NOT burn a sequence — the retry reuses it.
//!  3. **LRU + store-resume.** An evicted scope resumes from its persisted tail, never forking at 1.
//!  4. **Tamper is reported, not deleted.** A corrupted stored row restores AND names the break.

use super::{Journal, NeutralRecord, Restored};
use crate::audit::{frame_prelude, ChainLabels, ChainedRecord, Digest, Framing};
use crate::store::plane_view::{decode, encode, PlaneStore};
use crate::test_support::warn_capture::DiagCapture;
use busbar_contract::records::{
    PlaneRecord, PlaneRecordRef, PlaneSelector, RecordStoreError, RecordStoreResult,
};
use std::sync::{Arc, Mutex};

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

    fn tamper_first_neutral(&self) {
        let mut rows = self.rows.lock().unwrap();
        if let Some(r) = rows.first_mut() {
            let mut nb: super::NeutralBody = decode(&r.body).unwrap();
            nb.content = b"|TAMPERED".to_vec();
            r.body = encode(&nb).unwrap();
        }
    }
}

impl PlaneStore for MockStore {
    fn upsert_plane_record(&self, record: PlaneRecordRef<'_>) -> RecordStoreResult<()> {
        let record = &record.to_record();
        self.rows.lock().unwrap().push(record.clone());
        Ok(())
    }
    fn get_plane_record(&self, _kind: &str, _id: &str) -> RecordStoreResult<Option<Vec<u8>>> {
        Ok(None)
    }
    fn append_plane_record(&self, record: PlaneRecordRef<'_>) -> RecordStoreResult<()> {
        let record = &record.to_record();
        if *self.fail_appends.lock().unwrap() {
            return Err(RecordStoreError("append refused (test)".to_string()));
        }
        self.rows.lock().unwrap().push(record.clone());
        Ok(())
    }
    fn list_plane_records(
        &self,
        kind: &str,
        selector: &PlaneSelector,
    ) -> RecordStoreResult<Vec<Vec<u8>>> {
        let rows = self.rows.lock().unwrap();
        Ok(rows
            .iter()
            .filter(|r| r.kind == kind)
            .filter(|r| match selector {
                PlaneSelector::All => true,
                PlaneSelector::Parent(p) => r.parent.as_deref() == Some(&**p),
            })
            .map(|r| r.body.clone())
            .collect())
    }
    fn list_plane_record_parents(&self, kind: &str) -> RecordStoreResult<Vec<String>> {
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
    fn purge_plane_records(
        &self,
        _kind: &str,
        _before: u64,
        _retention: busbar_contract::records::Retention,
    ) -> RecordStoreResult<u64> {
        Ok(0)
    }
    fn delete_plane_record(&self, _kind: &str, _id: &str) -> RecordStoreResult<()> {
        Ok(())
    }
    fn redeem_plane_token(
        &self,
        _kind: &str,
        _token: &str,
        _expires_at: u64,
        _now: u64,
    ) -> RecordStoreResult<bool> {
        Ok(true)
    }

    fn plane_token_live(
        &self,
        _kind: &str,
        _token: &str,
        _expires_at: u64,
        _now: u64,
    ) -> RecordStoreResult<bool> {
        Ok(false)
    }
}

/// A neutral record carrying an opaque `content` suffix. Its digest is the framed prelude followed by
/// the suffix RAW — the SAME shape `audit::stream_registry::StreamRecord` uses.
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

fn neutral_reframe(scope: &str, body: &[u8]) -> RecordStoreResult<NeutralRec> {
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
            unreadable: 0,
            chain_breaks: vec![],
        }
    );
    assert_eq!(
        j2.next_seq("acme"),
        3,
        "the resumed chain continues, not forks"
    );
    assert_eq!(
        j2.verify_scoped(KIND_NEUTRAL, "acme", store.as_ref(), &neutral_reframe)
            .unwrap(),
        None,
        "the persisted neutral chain verifies"
    );

    assert_eq!(j2.compact_scoped(KIND_NEUTRAL, u64::MAX).unwrap(), 0);
}

#[test]
fn restore_scoped_skips_one_undecodable_record_and_keeps_the_rest() {
    let store = Arc::new(MockStore::new());
    let j1: Journal<NeutralRec> = Journal::new(1024);
    j1.set_sink(store.clone());
    write_neutral(&j1, "acme", b"|first");
    write_neutral(&j1, "acme", b"|second");
    drop(j1);

    store
        .append_plane_record(
            PlaneRecord {
                kind: KIND_NEUTRAL.to_string(),
                id: "acme".to_string(),
                parent: Some("acme".to_string()),
                seq: 3,
                ts: 0,
                disposition: busbar_contract::records::PlaneDisposition::Active,
                body: b"{ not a neutral body".to_vec(),
            }
            .view(),
        )
        .unwrap();

    use tracing_subscriber::layer::SubscriberExt as _;
    let j2: Journal<NeutralRec> = Journal::new(1024);
    j2.set_sink(store.clone());

    let cap = DiagCapture::default();
    let restored = {
        let subscriber = tracing_subscriber::registry().with(cap.clone());
        let _g = tracing::subscriber::set_default(subscriber);
        j2.restore_scoped(KIND_NEUTRAL, store.as_ref(), &neutral_reframe)
            .expect("one undecodable record must not abort the whole rehydrate")
    };
    assert_eq!(
        restored,
        Restored {
            scopes: 1,
            records: 2,
            empty_scopes: vec![],
            unreadable: 1,
            chain_breaks: vec![],
        }
    );
    assert_eq!(
        j2.next_seq("acme"),
        3,
        "the chain resumes from the last DECODABLE record"
    );
    let diags = cap.0.lock().unwrap();
    assert!(
        diags.iter().any(|d| d.contains("BUSBAR-2046")),
        "the undecodable row must emit PLANE_JOURNAL_ROW_UNREADABLE (BUSBAR-2046) at ERROR at its \
         skip site — a silent count is the regression being fixed; captured: {diags:?}"
    );
}

#[test]
fn a_scope_with_only_undecodable_rows_is_unreadable_not_empty() {
    let store = Arc::new(MockStore::new());

    for seq in 1..=2 {
        store
            .append_plane_record(
                PlaneRecord {
                    kind: KIND_NEUTRAL.to_string(),
                    id: "acme".to_string(),
                    parent: Some("acme".to_string()),
                    seq,
                    ts: 0,
                    disposition: busbar_contract::records::PlaneDisposition::Active,
                    body: b"{ not a neutral body".to_vec(),
                }
                .view(),
            )
            .unwrap();
    }

    let j: Journal<NeutralRec> = Journal::new(1024);
    j.set_sink(store.clone());
    let restored = j
        .restore_scoped(KIND_NEUTRAL, store.as_ref(), &neutral_reframe)
        .expect("an all-undecodable scope must not abort the whole rehydrate");
    assert_eq!(
        restored,
        Restored {
            scopes: 1,
            records: 0,
            // NOT `vec!["acme"]`: the store returned rows, they were just unreadable.
            empty_scopes: vec![],
            unreadable: 2,
            chain_breaks: vec![],
        },
        "a store that returned rows that were all unreadable is NOT an empty scope"
    );
}

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
    assert!(
        err.is_err(),
        "the durable write failed, so append must surface it"
    );
    assert_eq!(
        j.len(),
        0,
        "a failed write forgets the cached position: the next append reads the store's tail"
    );

    store.set_failing(false);
    let r = write_neutral(&j, "acme", b"|two");
    assert_eq!(r.seq, 2, "the retry reuses the sequence");
}

#[test]
fn a_tampered_row_is_reported_and_still_restored() {
    let store = Arc::new(MockStore::new());
    let j1: Journal<NeutralRec> = Journal::new(1024);
    j1.set_sink(store.clone());
    write_neutral(&j1, "acme", b"|first");
    write_neutral(&j1, "acme", b"|second");
    drop(j1);
    store.tamper_first_neutral();

    let j2: Journal<NeutralRec> = Journal::new(1024);
    j2.set_sink(store.clone());
    let restored = j2
        .restore_scoped(KIND_NEUTRAL, store.as_ref(), &neutral_reframe)
        .unwrap();
    assert_eq!(restored.chain_breaks.len(), 1, "the tamper is reported");
    assert_eq!(restored.scopes, 1, "and the scope is still restored");
    assert_eq!(j2.next_seq("acme"), 3, "resumed from the tail, not refused");
}

#[test]
fn no_sink_is_ephemeral() {
    let j: Journal<NeutralRec> = Journal::new(1024);
    let r = write_neutral(&j, "acme", b"|one");
    assert_eq!(r.seq, 1);
    assert_eq!(j.len(), 1);
    let store = MockStore::new();
    let restored = j
        .restore_scoped(KIND_NEUTRAL, &store, &neutral_reframe)
        .unwrap();
    assert_eq!(
        restored,
        Restored::default(),
        "nothing persisted, nothing restored"
    );
}

#[test]
fn an_evicted_scope_resumes_from_the_store_not_from_seq_one() {
    let store = Arc::new(MockStore::new());
    let j: Journal<NeutralRec> = Journal::new(2);
    j.set_sink(store.clone());
    write_neutral(&j, "a", b"|1");
    write_neutral(&j, "a", b"|1");
    write_neutral(&j, "b", b"|1");
    write_neutral(&j, "c", b"|1");
    assert_eq!(j.len(), 2);

    assert_eq!(write_neutral(&j, "a", b"|9").seq, 3);

    write_neutral(&j, "b", b"|1");
    write_neutral(&j, "c", b"|1");
    let ra2 = write_neutral(&j, "a", b"|8");
    assert_eq!(
        ra2.seq, 4,
        "the evicted scope resumed from its persisted tail (seq 3) and continued to 4"
    );

    let j2: Journal<NeutralRec> = Journal::new(1024);
    let restored = j2
        .restore_scoped(KIND_NEUTRAL, store.as_ref(), &neutral_reframe)
        .unwrap();
    assert!(
        restored.chain_breaks.is_empty(),
        "no fork: {:?}",
        restored.chain_breaks
    );
}

#[test]
fn an_evicted_neutral_scopes_tampered_tail_surfaces_a_break_on_resume() {
    let store = Arc::new(MockStore::new());
    let j: Journal<NeutralRec> = Journal::new(1);
    j.set_sink(store.clone());

    write_neutral(&j, "acme", b"|first");
    write_neutral(&j, "other", b"|x");
    assert_eq!(j.len(), 1);
    assert!(j.take_resume_breaks().is_empty());

    store.tamper_first_neutral();

    let resumed = write_neutral(&j, "acme", b"|second");
    assert_eq!(
        resumed.seq, 2,
        "the neutral resume STILL proceeds from the tail"
    );

    let breaks = j.take_resume_breaks();
    assert_eq!(
        breaks.len(),
        1,
        "the neutral runtime resume-path tamper must be RECORDED, not swallowed: {breaks:?}"
    );
}

#[test]
fn append_scoped_stamps_a_real_instant_so_a_fresh_row_survives_retention() {
    let store: Arc<dyn busbar_contract::records::RecordStore> = crate::real_store::store();
    let plane_store = crate::store::plane_view::PlaneStoreView::narrow(store.clone());
    let j: Journal<NeutralRec> = Journal::new(1024);
    j.set_sink(plane_store);
    write_neutral(&j, "acme", b"|fresh");

    let cutoff = busbar_kernel::store::now().saturating_sub(3600);
    let purged = store
        .purge_plane_records(
            KIND_NEUTRAL,
            cutoff,
            busbar_contract::records::Retention::Age,
        )
        .expect("purge");
    assert_eq!(
        purged, 0,
        "a row written just now must survive a retention cutoff an hour in the past — this fails \
         today because `append_scoped` stamps `ts: 0`, which is always < any positive cutoff"
    );

    let remaining = store
        .list_plane_records(KIND_NEUTRAL, &PlaneSelector::Parent("acme".into()))
        .expect("list");
    assert_eq!(
        remaining.len(),
        1,
        "the fresh record must still be present after the retention sweep"
    );
}

#[test]
fn a_forgotten_scope_on_an_uncapped_stream_resumes_from_the_store_not_seq_one() {
    let store = Arc::new(MockStore::new());
    let j: Journal<NeutralRec> = Journal::new(usize::MAX);
    j.set_sink(store.clone());
    write_neutral(&j, "acme", b"|one");
    write_neutral(&j, "acme", b"|two");
    j.forget("acme");
    assert_eq!(j.len(), 0);
    let late = write_neutral(&j, "acme", b"|late");
    assert_eq!(
        late.seq, 3,
        "the forgotten scope resumed from its tail (seq 2), not a forked seq 1"
    );
    let restored = Journal::<NeutralRec>::new(usize::MAX)
        .restore_scoped(KIND_NEUTRAL, store.as_ref(), &neutral_reframe)
        .unwrap();
    assert!(
        restored.chain_breaks.is_empty(),
        "no fork: {:?}",
        restored.chain_breaks
    );

    let bare: Journal<NeutralRec> = Journal::new(usize::MAX);
    write_neutral(&bare, "acme", b"|one");
    bare.forget("acme");
    assert_eq!(write_neutral(&bare, "acme", b"|again").seq, 1);
}

#[test]
fn a_chain_another_node_advanced_is_continued_after_a_refused_write() {
    let store = Arc::new(MockStore::new());
    let a: Journal<NeutralRec> = Journal::new(usize::MAX);
    a.set_sink(store.clone());
    let b: Journal<NeutralRec> = Journal::new(usize::MAX);
    b.set_sink(store.clone());
    write_neutral(&a, "acme", b"|one");

    b.forget("acme");
    assert_eq!(write_neutral(&b, "acme", b"|two").seq, 2);

    store.set_failing(true);
    assert!(a
        .append_scoped(
            KIND_NEUTRAL,
            "acme",
            NeutralInput {
                content: b"|three".to_vec(),
            },
            &neutral_reframe,
        )
        .is_err());
    store.set_failing(false);
    let three = write_neutral(&a, "acme", b"|three");
    assert_eq!(three.seq, 3, "node a continued node b's chain");
    let restored = Journal::<NeutralRec>::new(usize::MAX)
        .restore_scoped(KIND_NEUTRAL, store.as_ref(), &neutral_reframe)
        .unwrap();
    assert!(
        restored.chain_breaks.is_empty(),
        "no fork: {:?}",
        restored.chain_breaks
    );
}

fn append_unreadable_resume_row(store: &MockStore) {
    store
        .append_plane_record(
            PlaneRecord {
                kind: KIND_NEUTRAL.to_string(),
                id: "unreadable-resume-row".to_string(),
                parent: Some("acme".to_string()),
                seq: 99,
                ts: 0,
                disposition: busbar_contract::records::PlaneDisposition::Active,
                body: b"{ not a neutral body".to_vec(),
            }
            .view(),
        )
        .unwrap();
}

#[test]
fn a_failed_append_resumes_past_a_row_boot_already_reported_unreadable() {
    use tracing_subscriber::layer::SubscriberExt as _;
    let store = Arc::new(MockStore::new());
    let before: Journal<NeutralRec> = Journal::new(usize::MAX);
    before.set_sink(store.clone());
    write_neutral(&before, "acme", b"|one");
    write_neutral(&before, "acme", b"|two");
    append_unreadable_resume_row(&store);
    let resumed: Journal<NeutralRec> = Journal::new(usize::MAX);
    resumed.set_sink(store.clone());
    let restored = resumed
        .restore_scoped(KIND_NEUTRAL, store.as_ref(), &neutral_reframe)
        .unwrap();
    assert_eq!(restored.unreadable, 1);
    assert!(restored.chain_breaks.is_empty());
    store.set_failing(true);
    assert!(resumed
        .append_scoped(
            KIND_NEUTRAL,
            "acme",
            NeutralInput {
                content: b"|three".to_vec()
            },
            &neutral_reframe,
        )
        .is_err());
    store.set_failing(false);
    let capture = DiagCapture::default();
    let third = {
        let subscriber = tracing_subscriber::registry().with(capture.clone());
        let _guard = tracing::subscriber::set_default(subscriber);
        write_neutral(&resumed, "acme", b"|three")
    };
    assert_eq!(
        third.seq, 3,
        "continue the decodable tail without a fresh-chain fork"
    );
    assert!(resumed.take_resume_breaks().is_empty());
    let restored = Journal::<NeutralRec>::new(usize::MAX)
        .restore_scoped(KIND_NEUTRAL, store.as_ref(), &neutral_reframe)
        .unwrap();
    assert_eq!(restored.records, 3);
    assert_eq!(restored.unreadable, 1);
    assert!(restored.chain_breaks.is_empty());
    assert!(capture
        .0
        .lock()
        .unwrap()
        .iter()
        .any(|line| line.contains("BUSBAR-2046")));
}

#[test]
fn unreadable_resume_rows_do_not_hide_a_decodable_chain_break() {
    let store = Arc::new(MockStore::new());
    let journal: Journal<NeutralRec> = Journal::new(usize::MAX);
    journal.set_sink(store.clone());
    write_neutral(&journal, "acme", b"|one");
    write_neutral(&journal, "acme", b"|two");
    store.tamper_first_neutral();
    append_unreadable_resume_row(&store);
    journal.forget("acme");
    let next = write_neutral(&journal, "acme", b"|three");
    assert_eq!(next.seq, 3);
    assert!(!journal.take_resume_breaks().is_empty());
}

#[test]
fn an_entirely_unreadable_resume_never_invents_a_new_chain() {
    let store = Arc::new(MockStore::new());
    append_unreadable_resume_row(&store);
    let journal: Journal<NeutralRec> = Journal::new(usize::MAX);
    journal.set_sink(store.clone());
    journal.forget("acme");
    assert!(journal
        .append_scoped(
            KIND_NEUTRAL,
            "acme",
            NeutralInput {
                content: b"|replacement".to_vec()
            },
            &neutral_reframe,
        )
        .is_err());
    assert_eq!(store.rows.lock().unwrap().len(), 1);
}
