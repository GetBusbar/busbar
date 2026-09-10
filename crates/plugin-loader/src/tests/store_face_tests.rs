//! The translator's own battery.
//!
//! Written against a 1.5.5 double rather than a loaded artifact on purpose: what is under test is
//! the TRANSLATION — which 1.5.5 verb each face verb reaches, with which arguments, and what a
//! 1.5.5 failure becomes on the way back. The ABI-2 wire itself is proven by the adapter battery
//! beside this one, which this line does not touch.

use crate::store_adapter::StoreAdapter;
use crate::store_face::{StoreFace, LEGACY_CODE};
use busbar_contract::error::ErrorClass;
use busbar_contract::ids::{PrincipalId, RecordSchemaId, Registration, SessionId};
use busbar_contract::kinds::{RecordBytes, SliceGrant, Store as Face};
use busbar_contract::plugin::{Kind, Plugin};
use busbar_contract::store::{
    AuditRecord, MeteringDelta, MeteringRow, PlaneRecord, PlaneSelector, UsageLedger, VirtualKey,
};
use busbar_contract::store::{Store as AbiStore, StoreError, StoreResult};
use std::sync::{Arc, Mutex};

/// A 1.5.5 store that remembers what it was asked, so a test can assert on the ARGUMENTS the
/// translation built and not merely on the answer that came back.
#[derive(Default)]
struct Double {
    calls: Mutex<Vec<String>>,
    keys: Mutex<Vec<VirtualKey>>,
    audit: Mutex<Vec<AuditRecord>>,
    records: Mutex<Vec<PlaneRecord>>,
    /// When set, every verb that can fail answers this 1.5.5 string instead.
    fail: Option<String>,
    redeem: bool,
    live: bool,
}

impl Double {
    fn note(&self, what: impl Into<String>) {
        self.calls.lock().unwrap().push(what.into());
    }

    fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }

    fn refuse<T>(&self) -> Option<StoreResult<T>> {
        self.fail
            .as_ref()
            .map(|m| Err(StoreError(m.clone())) as StoreResult<T>)
    }
}

impl AbiStore for Double {
    fn put_key(&self, key: &VirtualKey) -> StoreResult<()> {
        self.note(format!("put_key {}", key.id));
        if let Some(refused) = self.refuse() {
            return refused;
        }
        self.keys.lock().unwrap().push(key.clone());
        Ok(())
    }

    fn get_key(&self, id: &str) -> StoreResult<Option<VirtualKey>> {
        self.note(format!("get_key {id}"));
        Ok(self
            .keys
            .lock()
            .unwrap()
            .iter()
            .find(|k| k.id == id)
            .cloned())
    }

    fn list_keys(&self) -> StoreResult<Vec<VirtualKey>> {
        self.note("list_keys");
        Ok(self.keys.lock().unwrap().clone())
    }

    fn delete_key(&self, id: &str) -> StoreResult<()> {
        self.note(format!("delete_key {id}"));
        Ok(())
    }

    fn get_usage(&self, bucket_id: &str, window_start: u64) -> StoreResult<UsageLedger> {
        self.note(format!("get_usage {bucket_id} {window_start}"));
        Ok(UsageLedger::default())
    }

    fn put_usage(&self, bucket_id: &str, window_start: u64, _l: &UsageLedger) -> StoreResult<()> {
        self.note(format!("put_usage {bucket_id} {window_start}"));
        Ok(())
    }

    fn add_metering(&self, delta: &MeteringDelta) -> StoreResult<()> {
        self.note(format!("add_metering {}", delta.key_id));
        Ok(())
    }

    fn list_metering(&self, bucket: u64) -> StoreResult<Vec<MeteringRow>> {
        self.note(format!("list_metering {bucket}"));
        Ok(Vec::new())
    }

    fn append_audit(&self, entry: &AuditRecord) -> StoreResult<()> {
        self.note(format!("append_audit {}", entry.seq));
        if let Some(refused) = self.refuse() {
            return refused;
        }
        self.audit.lock().unwrap().push(entry.clone());
        Ok(())
    }

    fn list_audit_tail(&self, limit: u64) -> StoreResult<Vec<AuditRecord>> {
        self.note(format!("list_audit_tail {limit}"));
        let all = self.audit.lock().unwrap().clone();
        let limit = limit as usize;
        Ok(if all.len() > limit {
            all[all.len() - limit..].to_vec()
        } else {
            all
        })
    }

    fn upsert_plane_record(&self, record: &PlaneRecord) -> StoreResult<()> {
        self.note(format!(
            "upsert_plane_record {} {} {:?}",
            record.kind, record.id, record.disposition
        ));
        self.records.lock().unwrap().push(record.clone());
        Ok(())
    }

    fn get_plane_record(&self, kind: &str, id: &str) -> StoreResult<Option<Vec<u8>>> {
        self.note(format!("get_plane_record {kind} {id}"));
        Ok(self
            .records
            .lock()
            .unwrap()
            .iter()
            .find(|r| r.kind == kind && r.id == id)
            .map(|r| r.body.clone()))
    }

    fn list_plane_records(
        &self,
        kind: &str,
        selector: &PlaneSelector,
    ) -> StoreResult<Vec<Vec<u8>>> {
        self.note(format!("list_plane_records {kind} {selector:?}"));
        Ok(self
            .records
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.kind == kind)
            .map(|r| r.body.clone())
            .collect())
    }

    fn purge_plane_records_before(&self, kind: &str, before: u64) -> StoreResult<u64> {
        self.note(format!("purge_plane_records_before {kind} {before}"));
        Ok(7)
    }

    fn delete_plane_record(&self, kind: &str, id: &str) -> StoreResult<()> {
        self.note(format!("delete_plane_record {kind} {id}"));
        Ok(())
    }

    fn redeem_plane_token(&self, kind: &str, token: &str, _e: u64, _n: u64) -> StoreResult<bool> {
        self.note(format!("redeem_plane_token {kind} {token}"));
        Ok(self.redeem)
    }

    fn plane_token_live(&self, kind: &str, token: &str, _e: u64, _n: u64) -> StoreResult<bool> {
        self.note(format!("plane_token_live {kind} {token}"));
        Ok(self.live)
    }
}

/// A face over `double` at payload schema `abi`, on a clock that stands still at `now`.
fn face_at(double: Arc<Double>, abi: u32, now: u64) -> StoreFace {
    let adapter = StoreAdapter::new(double, abi);
    let mut registration = Registration::new();
    StoreFace::with_clock(
        adapter,
        &mut registration,
        "store-face-battery",
        Arc::new(move || now),
    )
    .expect("the battery's key is the first thing interned in this image's vocabulary")
}

fn face(double: Arc<Double>) -> StoreFace {
    face_at(double, 4, 1_700_000_000)
}

fn schema() -> RecordSchemaId {
    RecordSchemaId::new("task")
}

#[test]
fn the_plugin_trio_answers_the_interned_key_the_store_kind_and_the_declared_schema() {
    let face = face_at(Arc::new(Double::default()), 3, 0);
    assert_eq!(face.key(), "store-face-battery");
    assert_eq!(face.kind(), Kind::Store);
    // The ARTIFACT's declared schema, not the face's own — this is what makes `speaks_new_ops` a
    // fact about the loaded store rather than about the face translating for it.
    assert_eq!(face.abi().0, 3);
}

#[test]
fn a_1_5_5_failure_arrives_as_internal_under_one_code_with_its_string_verbatim() {
    let double = Arc::new(Double {
        fail: Some("disk is full and the write did not land".to_string()),
        ..Double::default()
    });
    let face = face(Arc::clone(&double));
    let err = face
        .key_put(&VirtualKey {
            id: "k1".to_string(),
            ..VirtualKey::default()
        })
        .expect_err("the double refuses every fallible verb");
    // The wire carried a string and no class, so the class is the one the taxonomy keeps for
    // "every failure that predates a taxonomy" — and a caller must not branch on it.
    assert_eq!(err.class, ErrorClass::Internal);
    assert_eq!(err.code, LEGACY_CODE);
    assert_eq!(
        err.developer_message,
        "disk is full and the write did not land"
    );
}

#[test]
fn every_delegating_verb_reaches_its_own_1_5_5_verb_and_no_other() {
    let double = Arc::new(Double::default());
    let face = face(Arc::clone(&double));
    face.key_get("k1").unwrap();
    face.key_list().unwrap();
    face.key_revoke("k1").unwrap();
    face.usage_get("bucket", 42).unwrap();
    face.metering_list(9).unwrap();
    face.record_delete(schema(), b"t1").unwrap();
    assert_eq!(
        double.calls(),
        vec![
            "get_key k1",
            "list_keys",
            "delete_key k1",
            "get_usage bucket 42",
            "list_metering 9",
            "delete_plane_record task t1",
        ]
    );
}

#[test]
fn a_record_write_builds_an_active_row_and_reads_its_body_back() {
    let double = Arc::new(Double::default());
    let face = face(Arc::clone(&double));
    let body = RecordBytes::new(b"opaque".to_vec()).unwrap();
    face.record_put(schema(), b"t1", &body).unwrap();
    assert_eq!(face.record_get(schema(), b"t1").unwrap(), Some(body));
    // `Active`, never `Terminal`: the face's record verbs carry no terminal marker and a row marked
    // terminal is a row the next retention sweep may drop.
    assert!(double.calls()[0].ends_with("Active"));
}

#[test]
fn a_record_key_that_is_not_utf8_is_the_adapters_own_refusal_not_the_stores() {
    let double = Arc::new(Double::default());
    let face = face(Arc::clone(&double));
    let err = face
        .record_get(schema(), &[0xff, 0xfe])
        .expect_err("no spelling on the 1.5.5 wire");
    assert_eq!(err.class, ErrorClass::Malformed);
    assert_ne!(err.code, LEGACY_CODE);
    // Nothing reached the store: the translation stopped at the boundary.
    assert!(double.calls().is_empty());
}

#[test]
fn a_scan_selects_the_whole_kind_on_an_empty_prefix_and_a_parents_chain_otherwise() {
    let double = Arc::new(Double::default());
    let face = face(Arc::clone(&double));
    face.record_scan(schema(), b"", 10).unwrap();
    face.record_scan(schema(), b"parent-1", 10).unwrap();
    assert_eq!(
        double.calls(),
        vec![
            "list_plane_records task All",
            "list_plane_records task Parent(\"parent-1\")",
        ]
    );
}

#[test]
fn a_scan_over_a_1_5_5_store_answers_bodies_under_an_empty_key() {
    let double = Arc::new(Double::default());
    let face = face(Arc::clone(&double));
    let body = RecordBytes::new(b"opaque".to_vec()).unwrap();
    face.record_put(schema(), b"t1", &body).unwrap();
    let scanned = face.record_scan(schema(), b"", 10).unwrap();
    // The 1.5.5 verb answers bodies and not the ids they were stored under, so the key half is
    // EMPTY rather than fabricated — see the verb's own doc.
    assert_eq!(scanned, vec![(Vec::new(), body)]);
}

#[test]
fn the_audit_stream_round_trips_through_the_1_5_5_journal_at_the_rows_own_sequence() {
    let double = Arc::new(Double::default());
    let face = face(Arc::clone(&double));
    let row = AuditRecord {
        seq: 41,
        ts: 7,
        action: "hook.register".to_string(),
        resource: "hook:compress".to_string(),
        outcome: "applied".to_string(),
        principal: "operator".to_string(),
        prev_hash: String::new(),
        hash: "abc".to_string(),
    };
    let encoded = RecordBytes::new(serde_json::to_vec(&row).unwrap()).unwrap();
    let head = face
        .append_batch("audit", std::slice::from_ref(&encoded))
        .unwrap();
    // The chain is computed engine-side and persisted verbatim, so the head is the ROW's sequence
    // and never a count this node kept.
    assert_eq!(head.seq, 41);
    assert_eq!(face.replay_batch("audit", 0, 10).unwrap(), vec![encoded]);
    // The limit crosses the wire rather than being applied after a full list is materialised.
    assert!(double.calls().contains(&"list_audit_tail 10".to_string()));
}

#[test]
fn the_from_bound_is_applied_here_because_the_1_5_5_verb_has_none() {
    let double = Arc::new(Double::default());
    let face = face(Arc::clone(&double));
    for seq in 1..=3 {
        let row = AuditRecord {
            seq,
            ts: 0,
            action: "a".to_string(),
            resource: "r".to_string(),
            outcome: "applied".to_string(),
            principal: "p".to_string(),
            prev_hash: String::new(),
            hash: seq.to_string(),
        };
        face.append_batch(
            "audit",
            &[RecordBytes::new(serde_json::to_vec(&row).unwrap()).unwrap()],
        )
        .unwrap();
    }
    assert_eq!(face.replay_batch("audit", 3, 10).unwrap().len(), 1);
}

#[test]
fn a_record_that_is_not_an_audit_row_never_reaches_the_1_5_5_journal() {
    let double = Arc::new(Double::default());
    let face = face(Arc::clone(&double));
    let err = face
        .append_batch("audit", &[RecordBytes::new(b"not json".to_vec()).unwrap()])
        .expect_err("the 1.5.5 wire's only journal is the audit list");
    assert_eq!(err.class, ErrorClass::Malformed);
    assert!(double.calls().is_empty());
}

#[test]
fn a_stream_the_1_5_5_wire_has_no_home_for_is_counted_and_never_refused() {
    let double = Arc::new(Double::default());
    let face = face(Arc::clone(&double));
    let body = RecordBytes::new(b"x".to_vec()).unwrap();
    assert_eq!(
        face.append_batch("ledger", &[body.clone(), body])
            .unwrap()
            .seq,
        2
    );
    // Nothing was retained, so nothing replays — and saying so is not a failure.
    assert!(face.replay_batch("ledger", 0, 10).unwrap().is_empty());
    assert_eq!(
        face.heads().unwrap(),
        vec![(
            "ledger".to_string(),
            busbar_contract::kinds::Head { seq: 2, epoch: 0 }
        )]
    );
    assert!(double.calls().is_empty());
}

#[test]
fn a_purge_at_or_past_the_head_places_the_cutoff_at_the_moment_the_head_was_reached() {
    let double = Arc::new(Double::default());
    let face = face_at(Arc::clone(&double), 4, 1_700_000_000);
    face.append_batch("task", &[RecordBytes::new(b"x".to_vec()).unwrap()])
        .unwrap();
    assert_eq!(face.purge_before("task", 1).unwrap(), 7);
    assert!(double
        .calls()
        .contains(&"purge_plane_records_before task 1700000001".to_string()));
}

#[test]
fn a_purge_below_the_head_names_a_sequence_this_node_cannot_place_in_time_and_drops_nothing() {
    let double = Arc::new(Double::default());
    let face = face(Arc::clone(&double));
    let body = RecordBytes::new(b"x".to_vec()).unwrap();
    face.append_batch("task", &[body.clone(), body]).unwrap();
    // Purging the wrong rows is data loss no later read can undo, and `0` is what the 1.5.5
    // default answered before this face existed.
    assert_eq!(face.purge_before("task", 1).unwrap(), 0);
    // A stream this node never wrote is the same refusal to guess.
    assert_eq!(face.purge_before("never-written", 99).unwrap(), 0);
    assert!(!double
        .calls()
        .iter()
        .any(|c| c.starts_with("purge_plane_records_before")));
}

#[test]
fn a_claim_rides_the_single_use_test_and_set_and_is_remembered_only_when_it_was_won() {
    let won = Arc::new(Double {
        redeem: true,
        ..Double::default()
    });
    let winner = face(Arc::clone(&won));
    assert!(winner.claim_key("mint", b"idem-1", 9).unwrap());
    assert_eq!(won.calls(), vec!["redeem_plane_token mint idem-1"]);
    // The 1.5.5 wire has no un-redeem verb, so what `void_claims` drops is this node's own record
    // of what the unit claimed — and it is never a refusal.
    winner.void_claims("mint", 9).unwrap();

    let lost = face(Arc::new(Double::default()));
    assert!(!lost.claim_key("mint", b"idem-1", 9).unwrap());
}

#[test]
fn liveness_is_the_stores_own_answer_and_a_store_that_remembers_nothing_fails_closed() {
    let live = Arc::new(Double {
        live: true,
        ..Double::default()
    });
    assert!(face(live).record_live(schema(), b"tok", 100, 1).unwrap());
    // The 1.5.5 default is `false`, which IS the face's fail-closed requirement, so no default is
    // supplied here and the two agree exactly.
    let forgetful = Arc::new(Double::default());
    assert!(!face(forgetful)
        .record_live(schema(), b"tok", 100, 1)
        .unwrap());
}

#[test]
fn every_shim_verb_answers_node_locally_and_none_of_them_reaches_the_store() {
    let double = Arc::new(Double {
        fail: Some("the store is unreachable".to_string()),
        ..Double::default()
    });
    let face = face(Arc::clone(&double));
    // PB-93: never an error, never a boot refusal — even with a store that refuses everything.
    face.heartbeat("node-a", 3).unwrap();
    assert!(face.elect_checkpoint("node-a", 3).unwrap());
    let grant = face.reserve("bucket", 10, 5).unwrap();
    assert_eq!(
        grant,
        SliceGrant {
            amount: 10,
            epoch: 0
        }
    );
    face.release("bucket", grant).unwrap();
    // A grant the shim never made is forgotten rather than refused.
    face.release(
        "bucket",
        SliceGrant {
            amount: 99,
            epoch: 0,
        },
    )
    .unwrap();
    face.replay_put("ns", b"k", b"answer").unwrap();
    assert_eq!(
        face.replay_get("ns", b"k").unwrap(),
        Some(b"answer".to_vec())
    );
    face.legacy_cells_write("cell", b"v").unwrap();
    assert_eq!(face.legacy_cells_read("cell").unwrap(), Some(b"v".to_vec()));
    assert_eq!(face.legacy_cells_read("absent").unwrap(), None);
    assert_eq!(face.backup_watermark().unwrap(), None);
    assert!(face.heads().unwrap().is_empty());
    assert!(double.calls().is_empty());
}

#[test]
fn the_session_directory_is_this_nodes_own_and_answers_in_a_stable_order() {
    let double = Arc::new(Double::default());
    let face = face(double);
    let principal = PrincipalId::new("alice");
    face.session_put(SessionId(7), "node-a", &principal)
        .unwrap();
    face.session_put(SessionId(2), "node-a", &principal)
        .unwrap();
    face.session_put(SessionId(3), "node-a", &PrincipalId::new("bob"))
        .unwrap();
    assert_eq!(
        face.sessions_for(&principal).unwrap(),
        vec![
            (SessionId(2), "node-a".to_string()),
            (SessionId(7), "node-a".to_string())
        ]
    );
    face.session_remove(SessionId(2)).unwrap();
    face.session_remove(SessionId(2)).unwrap();
    assert_eq!(face.sessions_for(&principal).unwrap().len(), 1);
}

#[test]
fn the_legacy_audit_head_is_the_stores_own_tail_so_boot_and_the_face_read_the_same_rows() {
    let double = Arc::new(Double::default());
    let face = face(Arc::clone(&double));
    assert_eq!(face.legacy_audit_head().unwrap(), None);
    let row = AuditRecord {
        seq: 12,
        ts: 0,
        action: "a".to_string(),
        resource: "r".to_string(),
        outcome: "applied".to_string(),
        principal: "p".to_string(),
        prev_hash: String::new(),
        hash: "h".to_string(),
    };
    face.append_batch(
        "audit",
        &[RecordBytes::new(serde_json::to_vec(&row).unwrap()).unwrap()],
    )
    .unwrap();
    assert_eq!(face.legacy_audit_head().unwrap().map(|h| h.seq), Some(12));
}
