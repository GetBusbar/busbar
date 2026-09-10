// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The admin mutation log on the record leg: the byte-identity that lets it be one, and the
//! round trip that proves the copy-forward copies rather than re-seals.

use std::sync::Arc;

use busbar_api::{AuditRecord, PlaneRecord, PlaneSelector, StoreResult};
use busbar_plane_admin::records as audit_record;
use busbar_unit_audit::legacy::{digest, frame_prelude, sha256_hex, AuditEntry, Framing};

use super::{migrate_previous_release_table, AuditStream};

// ── THE BYTE-IDENTITY GATE ──────────────────────────────────────────────────────────────────────
//
// The plane's pre-framed suffix, appended RAW after the chain prelude framed with the scope OUT of
// the digest, reproduces the audit unit's own `AuditEntry` digest byte for byte. That equality is
// what makes the record leg and the ring ONE log rather than two that happen to agree today: the
// ring seals a record, the leg frames the same fields, and the digest either matches or the whole
// arrangement is a fiction. A perturbation of the suffix, of the prelude framing, or of the
// scope-in-digest flag fails this.

fn assert_byte_identity(
    seq: u64,
    prev_hash: &str,
    ts: u64,
    action: &str,
    resource: &str,
    outcome: &str,
    principal: &str,
) {
    let mut input = frame_prelude(Framing::PipeSeparated, prev_hash, None, seq);
    input.extend_from_slice(&audit_record::audit_suffix(
        ts, action, resource, outcome, principal,
    ));
    let via_leg = sha256_hex(&input);

    let entry = AuditEntry {
        seq,
        ts,
        action: action.to_string(),
        resource: resource.to_string(),
        outcome: outcome.to_string(),
        principal: principal.to_string(),
        prev_hash: prev_hash.to_string(),
        hash: String::new(),
        recorded_here: true,
    };
    assert_eq!(
        via_leg,
        digest(&entry),
        "the leg's digest input must byte-equal the ring's own AuditEntry digest"
    );
}

/// Genesis and a linked record. The leading vertical bar an EMPTY previous hash still produces
/// before the sequence is load-bearing: a prelude that skipped it would shift every persisted
/// digest by one separator.
#[test]
fn the_legs_framing_byte_equals_the_rings_own_digest() {
    assert_byte_identity(
        1,
        "",
        1_700_000_000,
        "hook.register",
        "hook:compress",
        "applied",
        "admin",
    );
    assert_byte_identity(
        2,
        "52258f59f0ccf11e717462b0cbd040e6bfa7f576624c77a9e332e483553f56aa",
        1_700_000_060,
        "hook.delete",
        "hook:compress",
        "applied",
        "admin",
    );
}

// ── THE COPY FORWARD ────────────────────────────────────────────────────────────────────────────

/// A store holding the previous release's audit TABLE and nothing under the leg's schema.
#[derive(Default)]
struct TableStore {
    table: std::sync::Mutex<Vec<AuditRecord>>,
    records: std::sync::Mutex<Vec<PlaneRecord>>,
}

impl busbar_api::Store for TableStore {
    fn put_key(&self, _key: &busbar_api::VirtualKey) -> StoreResult<()> {
        Ok(())
    }
    fn get_key(&self, _id: &str) -> StoreResult<Option<busbar_api::VirtualKey>> {
        Ok(None)
    }
    fn list_keys(&self) -> StoreResult<Vec<busbar_api::VirtualKey>> {
        Ok(Vec::new())
    }
    fn delete_key(&self, _id: &str) -> StoreResult<()> {
        Ok(())
    }
    fn get_usage(
        &self,
        _bucket_id: &str,
        _window_start: u64,
    ) -> StoreResult<busbar_api::UsageLedger> {
        Ok(busbar_api::UsageLedger::default())
    }
    fn put_usage(
        &self,
        _bucket_id: &str,
        _window_start: u64,
        _ledger: &busbar_api::UsageLedger,
    ) -> StoreResult<()> {
        Ok(())
    }
    fn add_metering(&self, _delta: &busbar_api::MeteringDelta) -> StoreResult<()> {
        Ok(())
    }
    fn list_metering(&self, _bucket: u64) -> StoreResult<Vec<busbar_api::MeteringRow>> {
        Ok(Vec::new())
    }

    fn list_audit(&self) -> StoreResult<Vec<AuditRecord>> {
        Ok(self.table.lock().unwrap().clone())
    }

    fn append_plane_record(&self, record: &PlaneRecord) -> StoreResult<()> {
        self.records.lock().unwrap().push(record.clone());
        Ok(())
    }

    fn list_plane_record_parents(&self, kind: &str) -> StoreResult<Vec<String>> {
        let mut parents: Vec<String> = self
            .records
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.kind == kind)
            .filter_map(|r| r.parent.clone())
            .collect();
        parents.sort();
        parents.dedup();
        Ok(parents)
    }

    fn list_plane_records(
        &self,
        kind: &str,
        selector: &PlaneSelector,
    ) -> StoreResult<Vec<Vec<u8>>> {
        let parent = match selector {
            PlaneSelector::All => None,
            PlaneSelector::Parent(p) => Some(p.clone()),
        };
        Ok(self
            .records
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.kind == kind && r.parent == parent)
            .map(|r| r.body.clone())
            .collect())
    }
}

/// The two rows the boot-verify golden freezes, as the previous release's table held them.
fn previous_release_rows() -> Vec<AuditRecord> {
    vec![
        AuditRecord {
            seq: 1,
            ts: 1_700_000_000,
            action: "hook.register".to_string(),
            resource: "hook:compress".to_string(),
            outcome: "applied".to_string(),
            principal: "admin".to_string(),
            prev_hash: String::new(),
            hash: "52258f59f0ccf11e717462b0cbd040e6bfa7f576624c77a9e332e483553f56aa".to_string(),
        },
        AuditRecord {
            seq: 2,
            ts: 1_700_000_060,
            action: "hook.delete".to_string(),
            resource: "hook:compress".to_string(),
            outcome: "applied".to_string(),
            principal: "admin".to_string(),
            prev_hash: "52258f59f0ccf11e717462b0cbd040e6bfa7f576624c77a9e332e483553f56aa"
                .to_string(),
            hash: "33a3906258375ea69278797ddd446d4f2d3f24e91eee181e1f26e0fef19a5264".to_string(),
        },
    ]
}

/// THE COPY FORWARD COPIES BYTES. Every sequence, link and digest crosses verbatim, the migrated
/// chain verifies, and the tail is the one the previous release sealed. A migration that RE-SEALED
/// would produce a chain that verifies perfectly and proves nothing, because every digest in it
/// would have been computed by the process doing the migrating.
#[test]
fn the_previous_releases_table_is_copied_forward_without_a_re_seal() {
    let store = Arc::new(TableStore::default());
    *store.table.lock().unwrap() = previous_release_rows();

    let copied =
        migrate_previous_release_table(store.as_ref()).expect("the store reads and writes");
    assert_eq!(copied, 2);

    let restored = AuditStream::over(store.clone())
        .restore()
        .expect("the copied records read back");
    assert_eq!(restored.len(), 2);
    assert_eq!(
        restored[1].hash, "33a3906258375ea69278797ddd446d4f2d3f24e91eee181e1f26e0fef19a5264",
        "the tail the previous release sealed is the tail the leg reads back"
    );
    assert_eq!(restored[0].action, "hook.register");
    assert!(
        restored.iter().all(|e| !e.recorded_here),
        "a restored record was not appended by this process"
    );
    // And the copied rows verify as a chain against their own digests.
    assert_eq!(digest(&restored[0]), restored[0].hash);
    assert_eq!(digest(&restored[1]), restored[1].hash);
}

/// IDEMPOTENT. A store already holding records under the leg's schema is left untouched, so a
/// second boot does not append the whole history a second time.
#[test]
fn the_copy_forward_runs_once_and_then_does_nothing() {
    let store = Arc::new(TableStore::default());
    *store.table.lock().unwrap() = previous_release_rows();

    assert_eq!(migrate_previous_release_table(store.as_ref()).unwrap(), 2);
    assert_eq!(
        migrate_previous_release_table(store.as_ref()).unwrap(),
        0,
        "a store that already holds the records is not migrated again"
    );
    assert_eq!(store.records.lock().unwrap().len(), 2);
}

/// A store with nothing to copy — a fresh deployment, or one that never ran the previous release —
/// is left exactly as it was found.
#[test]
fn a_store_with_no_previous_table_is_left_alone() {
    let store = Arc::new(TableStore::default());
    assert_eq!(migrate_previous_release_table(store.as_ref()).unwrap(), 0);
    assert!(store.records.lock().unwrap().is_empty());
}
