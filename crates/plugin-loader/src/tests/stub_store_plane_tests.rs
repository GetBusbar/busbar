// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The stub store keys an upsert on `(kind, id)`, parent or not (the contract's
//! `RecordStore::upsert_plane_record` / `get_plane_record`): an upserted record that names a parent
//! reads back by its own id, a second id under the same parent is a second record (never an
//! overwrite), and the parent-scoped listing still returns both.

use busbar_contract::records::{PlaneDisposition, PlaneRecord, PlaneSelector, RecordStore};
use busbar_stub_store::MemoryStore;

fn child(id: &str, body: &[u8]) -> PlaneRecord {
    PlaneRecord {
        kind: "task".to_string(),
        id: id.to_string(),
        parent: Some("ctx-1".to_string()),
        seq: 0,
        ts: 0,
        disposition: PlaneDisposition::Active,
        body: body.to_vec(),
    }
}

#[test]
fn a_parented_upserted_record_reads_back_by_its_own_id() {
    let s = MemoryStore::new();
    s.upsert_plane_record(child("t1", b"one").view()).unwrap();
    s.upsert_plane_record(child("t2", b"two").view()).unwrap();

    assert_eq!(
        s.get_plane_record("task", "t1").unwrap(),
        Some(b"one".to_vec())
    );
    assert_eq!(
        s.get_plane_record("task", "t2").unwrap(),
        Some(b"two".to_vec())
    );
    let mut listed = s
        .list_plane_records("task", &PlaneSelector::Parent("ctx-1".into()))
        .unwrap();
    listed.sort();
    assert_eq!(listed, vec![b"one".to_vec(), b"two".to_vec()]);

    // A second upsert of one id replaces it; deleting it by id removes it alone.
    s.upsert_plane_record(child("t1", b"one'").view()).unwrap();
    assert_eq!(
        s.get_plane_record("task", "t1").unwrap(),
        Some(b"one'".to_vec())
    );
    s.delete_plane_record("task", "t1").unwrap();
    assert_eq!(s.get_plane_record("task", "t1").unwrap(), None);
    assert_eq!(
        s.get_plane_record("task", "t2").unwrap(),
        Some(b"two".to_vec())
    );
}
