// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SETTLE STEP'S RESIDUAL ROW (MONEY LAW, owner 2026-10-02; ARCHITECT ruling 2026-10-02): a
//! usage count no billing class records gets one `usage.residual` row, written by the kernel, naming
//! the unit, count, plane, dialect, lane and request id, outcome `unbilled`. Never billed. The row is
//! money evidence, so it lives on the DURABLE per-principal journal stream, survives a restart and
//! replays, and never touches the bounded in-RAM admin audit ring.

use crate::plane::calllog::CallInput;
use crate::plane::store::KIND_RESIDUAL;
use crate::plane_host::{JournalHost, USAGE_RESIDUAL_ACTION};
use crate::residual_log::{settle, ResidualTestHarness};
use busbar_contract::records::{
    PlaneRecordRef, PlaneSelector, RecordStore, RecordStoreError, RecordStoreResult,
};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

/// A durable store double: keeps the `usage_residual` bodies verbatim by `(principal, seq)`, as a
/// real backend's primary key would, and refuses a DIFFERENT body on an occupied position (a fork).
struct DurableResidualStore {
    inner: crate::governance::MemoryStore,
    rows: Mutex<BTreeMap<(String, u64), Vec<u8>>>,
}

impl DurableResidualStore {
    fn new() -> Self {
        Self {
            inner: crate::governance::MemoryStore::new(),
            rows: Mutex::new(BTreeMap::new()),
        }
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
            (KIND_RESIDUAL, PlaneSelector::Parent(p)) => Ok(self
                .rows
                .lock()
                .expect("rows")
                .iter()
                .filter(|((principal, _), _)| principal == p)
                .map(|(_, body)| body.clone())
                .collect()),
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

fn plane_store(store: &Arc<dyn RecordStore>) -> Arc<dyn crate::plane::store::PlaneStore> {
    crate::plane::store::PlaneStoreView::narrow(store.clone())
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
            h.log
                .read_back(view.as_ref(), "key-1")
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

    // Process 2: a fresh log over the SAME store, replayed.
    let h2 = ResidualTestHarness::over(store.clone());
    let restored = h2.restore_from_store(view.as_ref()).expect("replay");
    assert_eq!(
        (restored.principals, restored.records, restored.unreadable),
        (1, 1, 0),
        "the replay finds the one row"
    );
    assert!(
        restored.chain_breaks.is_empty(),
        "the replayed chain verifies"
    );
    assert_eq!(
        h2.log.read_back(view.as_ref(), "key-1").expect("read back"),
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
        h2.log
            .verify_principal_chain(view.as_ref(), "key-1")
            .expect("verify"),
        Ok(2),
        "the whole persisted chain verifies"
    );
}

/// A host that records every admin audit row it is handed.
#[derive(Default)]
struct Rows(Mutex<Vec<String>>);

impl JournalHost for Rows {
    fn audit_emit(&self, action: &str, _resource: &str, _outcome: &str, _principal: &str) {
        self.0.lock().expect("rows").push(action.to_string());
    }

    fn audit_record(
        &self,
        action: &str,
        _resource: &str,
        _outcome: &'static str,
        _principal: &str,
    ) {
        self.0.lock().expect("rows").push(action.to_string());
    }

    fn call_log_emit(&self, _principal: &str, _input: CallInput) {}

    fn call_log_emit_hostless(&self, _principal: &str, _input: CallInput) {}
}

/// THE SEAM NEVER WRITES THE ADMIN RING. `JournalHost::settle_residual` routes to the durable
/// residual journal; the operator-rate admin audit (ring or durable-only) sees no `usage.residual`
/// row, so request-rate residuals can never evict an admin mutation. RED if the settle goes back to
/// `audit_record`/`audit_emit`.
#[test]
fn the_settle_seam_writes_no_admin_audit_row() {
    let rows = Rows::default();
    rows.settle_residual(
        &BTreeMap::from([("policy.units".to_string(), 14)]),
        "plane-a",
        "dialect-a",
        "lane-a",
        42,
        "key-1",
    );
    assert!(
        rows.0.lock().expect("rows").is_empty(),
        "a residual never lands on the admin audit ring"
    );
}
