// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! No store call runs under the journal's position map (BUSBAR-1.6.0.md §11.13 M1: "No plugin code
//! (`dlclose` included) runs under a host lock."; audit finding kernel-K4#6).
//!
//! The store is plugin code. These cells drive [`super::Journal`] over a store double that can PARK
//! one crossing (an append, or a resume's read of one scope) until the test releases it, and that
//! can RE-ENTER the journal from inside its own write. Every wait is bounded, so a journal that
//! blocks on its own lock fails the cell instead of hanging the run.

use super::{Journal, NeutralBody};
use crate::audit::stream_registry::{StreamInput, StreamRecord};
use crate::audit::{verify_chain, ChainedRecord, Framing};
use crate::store::plane_view::{decode, PlaneStore};
use busbar_contract::records::{PlaneRecord, PlaneRecordRef, PlaneSelector, RecordStoreResult};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const KIND: &str = "journal_lock_test";

/// How long a crossing that must finish is given before the cell fails.
const WAIT: Duration = Duration::from_secs(10);

/// How long a crossing that must still be waiting is watched.
const SETTLE: Duration = Duration::from_millis(300);

/// Which store crossing a park holds.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Op {
    Append,
    List,
}

/// One parked crossing: the op and scope it holds, the signal it sends once it is inside the store,
/// and the release it waits for (a dropped sender releases it too, so a failed cell never strands
/// it).
struct Park {
    op: Op,
    scope: String,
    entered: mpsc::Sender<()>,
    release: mpsc::Receiver<()>,
}

/// One re-entry: inside the first append the store sees, append to `scope` of `journal` and send
/// the inner answer.
struct Reenter {
    journal: Arc<Journal<StreamRecord>>,
    scope: String,
    answer: mpsc::Sender<Result<u64, String>>,
}

#[derive(Default)]
struct GateStore {
    rows: Mutex<Vec<PlaneRecord>>,
    park: Mutex<Option<Park>>,
    reenter: Mutex<Option<Reenter>>,
}

impl GateStore {
    /// Park here if the armed park names this crossing. The park is taken, so it holds once.
    fn parked(&self, op: Op, scope: Option<&str>) {
        let park = {
            let mut slot = self.park.lock().unwrap();
            let hit = matches!(
                slot.as_ref(),
                Some(p) if p.op == op && Some(p.scope.as_str()) == scope
            );
            if hit {
                slot.take()
            } else {
                None
            }
        };
        if let Some(p) = park {
            let _ = p.entered.send(());
            let _ = p.release.recv();
        }
    }
}

impl PlaneStore for GateStore {
    fn upsert_plane_record(&self, record: PlaneRecordRef<'_>) -> RecordStoreResult<()> {
        self.rows.lock().unwrap().push(record.to_record());
        Ok(())
    }
    fn get_plane_record(&self, _kind: &str, _id: &str) -> RecordStoreResult<Option<Vec<u8>>> {
        Ok(None)
    }
    fn append_plane_record(&self, record: PlaneRecordRef<'_>) -> RecordStoreResult<()> {
        let row = record.to_record();
        let reenter = self.reenter.lock().unwrap().take();
        if let Some(r) = reenter {
            let inner = r
                .journal
                .append_scoped(KIND, &r.scope, input(b"inner"), &reframe)
                .map(|rec| rec.seq())
                .map_err(|e| e.to_string());
            let _ = r.answer.send(inner);
        }
        self.parked(Op::Append, row.parent.as_deref());
        self.rows.lock().unwrap().push(row);
        Ok(())
    }
    fn list_plane_records(
        &self,
        kind: &str,
        selector: &PlaneSelector,
    ) -> RecordStoreResult<Vec<Vec<u8>>> {
        let scope = match selector {
            PlaneSelector::All => None,
            PlaneSelector::Parent(p) => Some(&**p),
        };
        self.parked(Op::List, scope);
        let rows = self.rows.lock().unwrap();
        Ok(rows
            .iter()
            .filter(|r| r.kind == kind)
            .filter(|r| scope.is_none() || r.parent.as_deref() == scope)
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

fn input(content: &[u8]) -> StreamInput {
    StreamInput::new(content.to_vec(), Framing::LengthPrefixed, true)
}

fn reframe(scope: &str, body: &[u8]) -> RecordStoreResult<StreamRecord> {
    let b: NeutralBody = decode(body)?;
    Ok(StreamRecord::from_parts(
        scope.to_string(),
        b.seq,
        b.prev_hash,
        b.hash,
        b.content,
        Framing::LengthPrefixed,
        true,
    ))
}

fn journal_over(store: &Arc<GateStore>) -> Arc<Journal<StreamRecord>> {
    let j = Arc::new(Journal::<StreamRecord>::new(1024));
    j.set_sink(store.clone());
    j
}

/// Arm a park on `op` of `scope`: the receiver sees the crossing enter the store, the sender
/// releases it.
fn park(store: &GateStore, op: Op, scope: &str) -> (mpsc::Receiver<()>, mpsc::Sender<()>) {
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    *store.park.lock().unwrap() = Some(Park {
        op,
        scope: scope.to_string(),
        entered: entered_tx,
        release: release_rx,
    });
    (entered_rx, release_tx)
}

/// Append to `scope` on its own thread; the receiver carries the minted seq.
fn append_in_thread(
    j: &Arc<Journal<StreamRecord>>,
    scope: &str,
    content: &'static [u8],
) -> mpsc::Receiver<Result<u64, String>> {
    let (tx, rx) = mpsc::channel();
    let j = Arc::clone(j);
    let scope = scope.to_string();
    std::thread::spawn(move || {
        let out = j
            .append_scoped(KIND, &scope, input(content), &reframe)
            .map(|r| r.seq())
            .map_err(|e| e.to_string());
        let _ = tx.send(out);
    });
    rx
}

/// RED on the kind-wide lock: scope A's durable write is parked inside the store, and an append to
/// scope B of the same kind must still complete. It waited on the position map A's append held
/// across the store call.
#[test]
fn an_append_to_another_scope_completes_while_one_scopes_store_write_is_parked() {
    let store = Arc::new(GateStore::default());
    let j = journal_over(&store);
    let (entered, release) = park(&store, Op::Append, "scope-a");
    let a = append_in_thread(&j, "scope-a", b"a1");
    entered
        .recv_timeout(WAIT)
        .expect("scope A's write reaches the store");
    let b = append_in_thread(&j, "scope-b", b"b1");
    let b_done = b.recv_timeout(WAIT);
    let _ = release.send(());
    assert_eq!(
        b_done.expect("scope B's append finishes while scope A's store write is parked"),
        Ok(1)
    );
    assert_eq!(
        a.recv_timeout(WAIT)
            .expect("scope A's append finishes once released"),
        Ok(1)
    );
    assert_eq!(j.next_seq("scope-a"), 2);
    assert_eq!(j.next_seq("scope-b"), 2);
}

/// RED on the kind-wide lock: a store that appends to ANOTHER scope from inside its own write must
/// not deadlock the journal on its own position map.
#[test]
fn a_store_that_appends_to_another_scope_from_inside_its_write_does_not_deadlock() {
    let store = Arc::new(GateStore::default());
    let j = journal_over(&store);
    let (inner_tx, inner_rx) = mpsc::channel();
    *store.reenter.lock().unwrap() = Some(Reenter {
        journal: Arc::clone(&j),
        scope: "scope-b".to_string(),
        answer: inner_tx,
    });
    let outer = append_in_thread(&j, "scope-a", b"a1");
    assert_eq!(
        outer
            .recv_timeout(WAIT)
            .expect("the outer append returns instead of waiting on its own lock"),
        Ok(1)
    );
    assert_eq!(
        inner_rx.recv_timeout(WAIT).expect("the inner append ran"),
        Ok(1)
    );
    assert_eq!(j.next_seq("scope-a"), 2);
    assert_eq!(j.next_seq("scope-b"), 2);
}

/// A store that appends to the SAME scope from inside that scope's write is refused, not left to
/// wait on itself, and the outer append still lands with no sequence burned.
#[test]
fn a_store_that_reenters_its_own_scope_is_refused_not_deadlocked() {
    let store = Arc::new(GateStore::default());
    let j = journal_over(&store);
    let (inner_tx, inner_rx) = mpsc::channel();
    *store.reenter.lock().unwrap() = Some(Reenter {
        journal: Arc::clone(&j),
        scope: "scope-a".to_string(),
        answer: inner_tx,
    });
    let outer = append_in_thread(&j, "scope-a", b"a1");
    assert_eq!(
        outer
            .recv_timeout(WAIT)
            .expect("the outer append returns instead of waiting on itself"),
        Ok(1)
    );
    let inner = inner_rx.recv_timeout(WAIT).expect("the inner append ran");
    assert!(
        inner.is_err(),
        "the same-scope re-entry is refused: {inner:?}"
    );
    assert_eq!(j.next_seq("scope-a"), 2);
    let rows = store
        .list_plane_records(KIND, &PlaneSelector::Parent("scope-a".into()))
        .unwrap();
    assert_eq!(rows.len(), 1, "only the outer record is durable");
}

/// The claim still orders one scope: a second append to a scope whose first write is parked waits
/// for it, and the two land as seq 1 then seq 2, linked, with no gap.
#[test]
fn two_concurrent_appends_to_one_scope_still_chain_gap_free() {
    let store = Arc::new(GateStore::default());
    let j = journal_over(&store);
    let (entered, release) = park(&store, Op::Append, "scope-a");
    let first = append_in_thread(&j, "scope-a", b"first");
    entered
        .recv_timeout(WAIT)
        .expect("the first write reaches the store");
    let second = append_in_thread(&j, "scope-a", b"second");
    assert_eq!(
        second.recv_timeout(SETTLE),
        Err(RecvTimeoutError::Timeout),
        "a second append to the same scope waits for the first's durable write"
    );
    let _ = release.send(());
    assert_eq!(first.recv_timeout(WAIT).expect("first finishes"), Ok(1));
    assert_eq!(second.recv_timeout(WAIT).expect("second finishes"), Ok(2));
    let records: Vec<StreamRecord> = store
        .list_plane_records(KIND, &PlaneSelector::Parent("scope-a".into()))
        .unwrap()
        .iter()
        .map(|body| reframe("scope-a", body))
        .collect::<RecordStoreResult<_>>()
        .unwrap();
    assert_eq!(
        records.iter().map(|r| r.seq()).collect::<Vec<_>>(),
        vec![1, 2]
    );
    assert!(verify_chain(&records).is_ok(), "the two records chain");
    assert_eq!(j.next_seq("scope-a"), 3);
}

/// RED on the kind-wide lock: a resume parked reading scope A's tail back from the store (scope A
/// was forgotten, so its next append reads the tail to continue it) must not hold the position map,
/// so an append to scope B completes meanwhile. The resumed append then continues A's chain.
#[test]
fn an_append_completes_while_a_resume_is_parked_reading_another_scope() {
    let store = Arc::new(GateStore::default());
    let j = journal_over(&store);
    j.append_scoped(KIND, "scope-a", input(b"a1"), &reframe)
        .expect("seed scope A");
    j.forget("scope-a");
    let (entered, release) = park(&store, Op::List, "scope-a");
    let a = append_in_thread(&j, "scope-a", b"a2");
    entered
        .recv_timeout(WAIT)
        .expect("the resume reaches scope A's read");
    let b = append_in_thread(&j, "scope-b", b"b1");
    let b_done = b.recv_timeout(WAIT);
    let _ = release.send(());
    assert_eq!(
        b_done.expect("scope B's append finishes while the resume reads scope A"),
        Ok(1)
    );
    assert_eq!(
        a.recv_timeout(WAIT)
            .expect("the resumed append finishes once released"),
        Ok(2),
        "scope A continued its persisted tail"
    );
    assert_eq!(j.next_seq("scope-a"), 3);
}

/// RED on the unbounded claim wait (audit finding kernel-K4#9): a second append to a scope whose
/// first durable write is parked inside the store waited on the claim with no deadline, so it
/// never returned while the store held the first write. It must be refused at the claim deadline,
/// with the first write still parked, and mint nothing: the parked write lands as seq 1 once
/// released and the next append takes seq 2, linked, with no gap.
#[test]
fn a_same_scope_append_behind_a_parked_store_write_is_refused_at_the_claim_deadline() {
    let store = Arc::new(GateStore::default());
    let mut journal = Journal::<StreamRecord>::new(1024);
    journal.set_claim_wait(Duration::from_millis(50));
    journal.set_sink(store.clone());
    let j = Arc::new(journal);
    let (entered, release) = park(&store, Op::Append, "scope-a");
    let first = append_in_thread(&j, "scope-a", b"first");
    entered
        .recv_timeout(WAIT)
        .expect("the first write reaches the store");
    // The first write stays parked until `release` below, so the second append can only return
    // through the claim deadline.
    let second = append_in_thread(&j, "scope-a", b"second");
    let second_done = second.recv_timeout(WAIT);
    let _ = release.send(());
    let refused = second_done
        .expect("the second append returns while the first write is still parked in the store");
    assert!(
        refused.is_err(),
        "the second append is refused at the claim deadline: {refused:?}"
    );
    assert_eq!(first.recv_timeout(WAIT).expect("first finishes"), Ok(1));
    assert_eq!(
        j.append_scoped(KIND, "scope-a", input(b"third"), &reframe)
            .map(|r| r.seq())
            .map_err(|e| e.to_string()),
        Ok(2),
        "the refused append burned no sequence"
    );
    let records: Vec<StreamRecord> = store
        .list_plane_records(KIND, &PlaneSelector::Parent("scope-a".into()))
        .unwrap()
        .iter()
        .map(|body| reframe("scope-a", body))
        .collect::<RecordStoreResult<_>>()
        .unwrap();
    assert_eq!(
        records.iter().map(|r| r.seq()).collect::<Vec<_>>(),
        vec![1, 2]
    );
    assert!(verify_chain(&records).is_ok(), "the two records chain");
}
