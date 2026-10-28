// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SETTLE STEP'S RESIDUAL ROW: a
//! usage count no billing class records gets one `usage.residual` row, written by the kernel, naming
//! the unit, count, plane, dialect, lane and request id, outcome `unbilled`. Never billed. The row is
//! money evidence, so it lives on the DURABLE per-principal journal stream, survives a restart and
//! replays, and never touches the bounded in-RAM admin audit ring.

use crate::residual_log::{
    PlaneResidualLog, ResidualRecorded, ResidualTestHarness, USAGE_RESIDUAL_ACTION,
};
use crate::store::plane_view::{wait_for, KIND_RESIDUAL};
use busbar_contract::records::{
    PlaneRecordRef, PlaneSelector, RecordStore, RecordStoreError, RecordStoreResult,
};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

/// [`crate::residual_log::settle`], awaited on this thread.
fn settle(
    log: &PlaneResidualLog,
    residual: &BTreeMap<String, u64>,
    plane: &str,
    dialect: &str,
    lane: &str,
    request_id: u64,
    principal: &str,
) -> Option<RecordStoreResult<ResidualRecorded>> {
    wait_for(crate::residual_log::settle(
        log, residual, plane, dialect, lane, request_id, principal,
    ))
}

/// A durable store double: keeps the `usage_residual` bodies verbatim by `(principal, seq)`, as a
/// real backend's primary key would, and refuses a DIFFERENT body on an occupied position (a fork).
struct DurableResidualStore {
    inner: crate::governance::MemoryStore,
    rows: Mutex<BTreeMap<(String, u64), Vec<u8>>>,
    /// How many times a principal's rows were listed: the row reads a boot or a resume paid for.
    row_reads: AtomicUsize,
}

impl DurableResidualStore {
    fn new() -> Self {
        Self {
            inner: crate::governance::MemoryStore::new(),
            rows: Mutex::new(BTreeMap::new()),
            row_reads: AtomicUsize::new(0),
        }
    }

    fn row_reads(&self) -> usize {
        self.row_reads.load(Ordering::SeqCst)
    }

    /// Overwrite one stored row with bytes that will not decode (a corrupt or foreign row).
    fn corrupt(&self, principal: &str, seq: u64) {
        let mut rows = self.rows.lock().expect("rows");
        let row = rows
            .get_mut(&(principal.to_string(), seq))
            .expect("the row exists");
        *row = b"not a usage.residual row".to_vec();
    }
}

impl RecordStore for DurableResidualStore {
    fn put_key(&self, key: &busbar_contract::records::VirtualKey) -> RecordStoreResult<()> {
        self.inner.put_key(key)
    }
    fn get_key(&self, id: &str) -> RecordStoreResult<Option<busbar_contract::records::VirtualKey>> {
        self.inner.get_key(id)
    }
    fn list_keys(&self) -> RecordStoreResult<Vec<busbar_contract::records::VirtualKey>> {
        self.inner.list_keys()
    }
    fn delete_key(&self, id: &str) -> RecordStoreResult<()> {
        self.inner.delete_key(id)
    }
    fn get_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
    ) -> RecordStoreResult<busbar_contract::records::UsageLedger> {
        self.inner.get_usage(bucket_id, window_start)
    }
    fn put_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
        ledger: &busbar_contract::records::UsageLedger,
    ) -> RecordStoreResult<()> {
        self.inner.put_usage(bucket_id, window_start, ledger)
    }
    fn add_metering(
        &self,
        delta: &busbar_contract::records::MeteringDelta,
    ) -> RecordStoreResult<()> {
        self.inner.add_metering(delta)
    }
    fn list_metering(
        &self,
        bucket: u64,
    ) -> RecordStoreResult<Vec<busbar_contract::records::MeteringRow>> {
        self.inner.list_metering(bucket)
    }

    fn append_plane_record(&self, record: PlaneRecordRef<'_>) -> RecordStoreResult<()> {
        let record = record.to_record();
        if record.kind != KIND_RESIDUAL {
            return Ok(());
        }
        let principal = record.parent.clone().unwrap_or_else(|| record.id.clone());
        let mut rows = self.rows.lock().expect("rows");
        match rows.get(&(principal.clone(), record.seq)) {
            Some(held) if *held == record.body => Ok(()),
            Some(_) => Err(RecordStoreError(format!(
                "usage.residual fork: a DIFFERENT row already occupies ({principal}, {})",
                record.seq
            ))),
            None => {
                rows.insert((principal, record.seq), record.body);
                Ok(())
            }
        }
    }
    fn list_plane_records(
        &self,
        kind: &str,
        selector: &PlaneSelector<'_>,
    ) -> RecordStoreResult<Vec<Vec<u8>>> {
        match (kind, selector) {
            (KIND_RESIDUAL, PlaneSelector::Parent(p)) => Ok({
                self.row_reads.fetch_add(1, Ordering::SeqCst);
                self.rows
                    .lock()
                    .expect("rows")
                    .iter()
                    .filter(|((principal, _), _)| principal == p)
                    .map(|(_, body)| body.clone())
                    .collect()
            }),
            _ => Ok(Vec::new()),
        }
    }
    fn list_plane_record_parents(&self, kind: &str) -> RecordStoreResult<Vec<String>> {
        if kind != KIND_RESIDUAL {
            return Ok(Vec::new());
        }
        let mut out: Vec<String> = self
            .rows
            .lock()
            .expect("rows")
            .keys()
            .map(|(p, _)| p.clone())
            .collect();
        out.dedup();
        Ok(out)
    }
}

fn plane_store(store: &Arc<dyn RecordStore>) -> Arc<dyn crate::store::plane_view::PlaneStore> {
    crate::store::plane_view::PlaneStoreView::narrow(
        crate::test_support::record_calls::RecordCalls::over(store.clone()),
    )
}

/// ONE ROW PER NON-EMPTY MAP, ON THE DURABLE PER-PRINCIPAL JOURNAL, AND IT SURVIVES A REPLAY. The row
/// names every unit and count, the plane, the dialect, the lane and the request id, outcome
/// `unbilled`, on the settling principal's chain; an empty map writes none. A second process over the
/// SAME store (nothing carried over in RAM) reads the row back field for field, its chain verifies,
/// and the next settle continues the chain at seq 2 linked to the replayed row. RED when the row
/// leaves the durable stream, drops a fact, or does not survive the restart.
#[test]
fn a_residual_settles_as_one_unbilled_row_on_the_durable_journal_and_survives_a_replay() {
    let store: Arc<dyn RecordStore> = Arc::new(DurableResidualStore::new());
    let view = plane_store(&store);

    // Process 1.
    let first = {
        let h = ResidualTestHarness::over(store.clone());
        assert!(
            settle(
                &h.log,
                &BTreeMap::new(),
                "plane-a",
                "dialect-a",
                "lane-a",
                42,
                "key-1"
            )
            .is_none(),
            "an empty residual map writes no row"
        );
        assert!(
            wait_for(h.log.read_back(view.as_ref(), "key-1"))
                .expect("read")
                .is_empty(),
            "an empty residual map leaves the journal empty"
        );
        let residual = BTreeMap::from([
            ("usage.stated_total_gap".to_string(), 7),
            ("policy.units".to_string(), 14),
        ]);
        let row = settle(
            &h.log,
            &residual,
            "plane-a",
            "dialect-a",
            "lane-a",
            42,
            "key-1",
        )
        .expect("a non-empty map writes a row")
        .expect("the durable write succeeds");
        assert_eq!(row.seq, 1, "the principal's chain opens at seq 1");
        assert_eq!(row.principal, "key-1");
        assert_eq!(row.action, USAGE_RESIDUAL_ACTION);
        assert_eq!(USAGE_RESIDUAL_ACTION, "usage.residual");
        assert_eq!(
            (row.plane.as_str(), row.dialect.as_str(), row.lane.as_str()),
            ("plane-a", "dialect-a", "lane-a")
        );
        assert_eq!(row.request_id, 42);
        assert_eq!(row.units, residual, "every unit and its count");
        assert_eq!(row.outcome, busbar_contract::vocab::OUTCOME_UNBILLED);
        row
    };

    // Process 2: a fresh log over the SAME store, restored.
    let h2 = ResidualTestHarness::over(store.clone());
    let restored = h2.restore_from_store(view.as_ref()).expect("restore");
    assert_eq!(
        restored.principals, 1,
        "the restore finds the one principal"
    );
    assert_eq!(
        wait_for(h2.log.read_back(view.as_ref(), "key-1")).expect("read back"),
        vec![first.clone()],
        "the row is in the durable journal, field for field, after the restart"
    );

    let next = settle(
        &h2.log,
        &BTreeMap::from([("guardrail.input.text".to_string(), 3)]),
        "plane-a",
        "dialect-a",
        "lane-a",
        43,
        "key-1",
    )
    .expect("row")
    .expect("durable write");
    assert_eq!(
        next.seq, 2,
        "the chain continues after the replay, never reopens at 1"
    );
    assert_eq!(next.prev_hash, first.hash, "linked to the replayed row");
    assert_eq!(
        wait_for(h2.log.verify_principal_chain(view.as_ref(), "key-1")).expect("verify"),
        Ok(2),
        "the whole persisted chain verifies"
    );
}

/// Write `rows` settles for each of `principals` in a first process over `store`, and return each
/// principal's last row.
fn first_process(
    store: &Arc<dyn RecordStore>,
    principals: &[&str],
    rows: u64,
) -> BTreeMap<String, crate::residual_log::ResidualRecorded> {
    let h = ResidualTestHarness::over(store.clone());
    let mut last = BTreeMap::new();
    for principal in principals {
        for request_id in 1..=rows {
            let row = settle(
                &h.log,
                &BTreeMap::from([("policy.units".to_string(), request_id)]),
                "plane-a",
                "dialect-a",
                "lane-a",
                request_id,
                principal,
            )
            .expect("row")
            .expect("durable write");
            last.insert(principal.to_string(), row);
        }
    }
    last
}

/// K5#7: BOOT READS NO ROWS; EACH PRINCIPAL RESUMES FROM ITS STORED TAIL ON ITS FIRST APPEND. The
/// stream is request-rate and never evicted, so a boot that read and reframed every row of every
/// principal grew in time and peak memory with the deployment's age. The restore now lists the
/// principals and reads nothing else; a principal's rows are read once, when it next settles, and
/// its chain continues from the stored tail. RED on dev: dev's boot reads every principal's rows.
#[test]
fn a_boot_restore_reads_no_rows_and_each_principal_resumes_on_its_first_append() {
    let durable = Arc::new(DurableResidualStore::new());
    let store: Arc<dyn RecordStore> = durable.clone();
    let view = plane_store(&store);
    let last = first_process(&store, &["key-a", "key-b", "key-c"], 3);

    let h2 = ResidualTestHarness::over(store.clone());
    let before = durable.row_reads();
    let restored = h2.restore_from_store(view.as_ref()).expect("restore");
    assert_eq!(restored.principals, 3);
    assert_eq!(
        durable.row_reads() - before,
        0,
        "the boot restore read stored rows; it must only list the principals"
    );

    let next = settle(
        &h2.log,
        &BTreeMap::from([("policy.units".to_string(), 9)]),
        "plane-a",
        "dialect-a",
        "lane-a",
        9,
        "key-b",
    )
    .expect("row")
    .expect("durable write");
    assert_eq!(
        durable.row_reads() - before,
        1,
        "the first append reads its own principal's rows, and only those"
    );
    assert_eq!(next.seq, 4, "the chain continues after the restart");
    assert_eq!(
        next.prev_hash, last["key-b"].hash,
        "linked to the stored tail"
    );
    let again = settle(
        &h2.log,
        &BTreeMap::from([("policy.units".to_string(), 10)]),
        "plane-a",
        "dialect-a",
        "lane-a",
        10,
        "key-b",
    )
    .expect("row")
    .expect("durable write");
    assert_eq!(again.seq, 5);
    assert_eq!(
        durable.row_reads() - before,
        1,
        "a resumed principal appends from its cached position"
    );
    for principal in ["key-a", "key-b", "key-c"] {
        let expected = if principal == "key-b" { 5 } else { 3 };
        assert_eq!(
            wait_for(h2.log.verify_principal_chain(view.as_ref(), principal)).expect("verify"),
            Ok(expected),
            "{principal}'s persisted chain verifies"
        );
    }
}

/// A stored row that will not decode, below the tail, is skipped on the lazy resume exactly as the
/// boot replay skipped it: the principal's chain resumes from its stored tail and the next row is
/// written, rather than every row for that principal being refused from then on.
#[test]
fn an_undecodable_row_below_the_tail_is_skipped_on_resume() {
    let durable = Arc::new(DurableResidualStore::new());
    let store: Arc<dyn RecordStore> = durable.clone();
    let view = plane_store(&store);
    let last = first_process(&store, &["key-1"], 3);
    durable.corrupt("key-1", 2);

    let h2 = ResidualTestHarness::over(store.clone());
    h2.restore_from_store(view.as_ref()).expect("restore");
    let next = settle(
        &h2.log,
        &BTreeMap::from([("policy.units".to_string(), 4)]),
        "plane-a",
        "dialect-a",
        "lane-a",
        4,
        "key-1",
    )
    .expect("row")
    .expect("the append resumes past the undecodable row");
    assert_eq!(next.seq, 4);
    assert_eq!(next.prev_hash, last["key-1"].hash);
}

/// A stored TAIL that will not decode leaves the principal's position unknown, so its appends are
/// refused rather than minted below the real tail (a fork), and the refusal holds without the store
/// being read again.
#[test]
fn an_undecodable_tail_refuses_the_append_rather_than_forking() {
    let durable = Arc::new(DurableResidualStore::new());
    let store: Arc<dyn RecordStore> = durable.clone();
    let view = plane_store(&store);
    first_process(&store, &["key-1"], 2);
    durable.corrupt("key-1", 2);

    let h2 = ResidualTestHarness::over(store.clone());
    h2.restore_from_store(view.as_ref()).expect("restore");
    let units = BTreeMap::from([("policy.units".to_string(), 3)]);
    assert!(
        settle(
            &h2.log,
            &units,
            "plane-a",
            "dialect-a",
            "lane-a",
            3,
            "key-1"
        )
        .expect("a non-empty map settles")
        .is_err(),
        "an append over an undecodable tail is refused"
    );
    let reads = durable.row_reads();
    assert!(settle(
        &h2.log,
        &units,
        "plane-a",
        "dialect-a",
        "lane-a",
        3,
        "key-1"
    )
    .expect("a non-empty map settles")
    .is_err());
    assert_eq!(durable.row_reads(), reads, "the refusal is remembered");
    assert_eq!(
        durable.rows.lock().expect("rows").len(),
        2,
        "nothing was written over or below the tail"
    );
}
