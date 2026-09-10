// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The two crate-level invariants of `busbar-store-memory`, held on their own terms.
//!
//! Neither closes a coverage gap in `src/tests/lib_tests.rs`. Both are properties of the backend as
//! a whole rather than of any one function, which is why they are stated once, in one place, where
//! a reader looking for them can find them.
//!
//! Its own top-level `tests/` file (rather than a case added to `src/tests/lib_tests.rs`), matching
//! this crate's existing `tests/store_conformance.rs` — a cross-cutting store contract check does
//! not belong inside the src-level unit-test file, per the repo's test-locality convention
//! (`docs/code-layout.md`).

use busbar_api::{PlaneDisposition, PlaneRecord, PlaneSelector, Store, VirtualKey};
use busbar_store_memory::MemoryStore;

fn plane_record(kind: &str, id: &str, seq: u64, body: Vec<u8>) -> PlaneRecord {
    PlaneRecord {
        kind: kind.to_string(),
        id: id.to_string(),
        parent: None,
        seq,
        ts: 0,
        disposition: PlaneDisposition::Active,
        body,
    }
}

fn key(id: &str, created_at: u64) -> VirtualKey {
    VirtualKey {
        id: id.to_string(),
        generation_hash: format!("h_{id}"),
        name: "t".to_string(),
        allowed_scopes: None,
        enabled: true,
        created_at,
        group: None,
        labels: std::collections::BTreeMap::new(),
        expires_at: None,
        deleted_at: None,
        revision: 0,
        ..Default::default()
    }
}

/// The store's one BYTE-VALUE field — `PlaneRecord::body` — must persist and reload byte-for-byte
/// identical, for every representative edge case the trait's doc calls "opaque… persisted and
/// returned verbatim": empty, large (bigger than any plausible inline-optimization threshold),
/// invalid-UTF-8 (0xFF/0xFE are never valid UTF-8 lead bytes), a NUL byte in the middle, and a
/// multi-byte UTF-8 string. `Vec<u8>` is the store's actual data model for a plane record's value
/// (see `busbar_api::store::PlaneRecord::body` and `Store::get_plane_record`'s doc: "the neutral
/// `get_task`") — this is the store's real binary-value path, not `CredentialSecret::secret` or
/// `VirtualKey` fields, which are `String` (UTF-8 only) by the trait's own type signature.
#[test]
fn plane_record_body_round_trips_byte_identical_for_every_edge_case() {
    let s = MemoryStore::new();
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("empty", Vec::new()),
        ("large", vec![0xABu8; 5 * 1024 * 1024]), // 5 MiB
        ("non_utf8_lead_bytes", vec![0xFF, 0xFE, 0x00, 0xFF, 0xFE]),
        ("embedded_nul", b"before\x00after".to_vec()),
        (
            "unicode",
            "héllo wörld 🎉 日本語 — em dash".as_bytes().to_vec(),
        ),
        ("all_256_byte_values", (0u8..=255).collect::<Vec<u8>>()),
    ];

    for (id, body) in &cases {
        let record = plane_record("task", id, 0, body.clone());
        s.upsert_plane_record(&record)
            .unwrap_or_else(|e| panic!("upsert {id} failed: {e}"));
        let got = s
            .get_plane_record("task", id)
            .unwrap_or_else(|e| panic!("get {id} failed: {e}"))
            .unwrap_or_else(|| panic!("{id} must be present after a successful upsert"));
        assert_eq!(
            &got,
            body,
            "plane record body for {id} did not round-trip byte-identical \
             (got {} bytes, expected {} bytes)",
            got.len(),
            body.len()
        );
    }
}

/// The append-only path (`append_plane_record` / `list_plane_records`) must ALSO preserve body
/// bytes exactly, for the same edge cases, when read back through a parent's ordered chain rather
/// than the single-record `get_plane_record` path — the two reads share one map internally
/// (`MemoryStore::plane_records`) but go through different code paths in `src/lib.rs`.
#[test]
fn plane_record_body_round_trips_byte_identical_through_the_append_and_list_path() {
    let s = MemoryStore::new();
    let parent = "chain_parent";
    let bodies: Vec<Vec<u8>> = vec![
        Vec::new(),
        vec![0x00, 0xFF, 0x00, 0xFF],
        "unicode 🎉 body".as_bytes().to_vec(),
        vec![0x9Du8; 1024], // a non-UTF8 byte repeated
    ];

    for (i, body) in bodies.iter().enumerate() {
        let mut r = plane_record("task_event", &format!("evt_{i}"), i as u64, body.clone());
        r.parent = Some(parent.to_string());
        s.append_plane_record(&r)
            .unwrap_or_else(|e| panic!("append {i} failed: {e}"));
    }

    let got = s
        .list_plane_records("task_event", &PlaneSelector::Parent(parent.to_string()))
        .expect("list the chain");
    assert_eq!(got.len(), bodies.len());
    for (i, (expected, actual)) in bodies.iter().zip(got.iter()).enumerate() {
        assert_eq!(
            actual, expected,
            "seq {i}'s body did not round-trip byte-identical via list_plane_records"
        );
    }
}

/// `list_keys`' own doc/comment claims a deterministic order — "mirror SqliteStore's ORDER BY
/// created_at" (`src/lib.rs`, `list_keys`) — so a caller relying on that ordering (e.g. a paged
/// admin listing) must see it hold regardless of INSERTION order. Inserted out of `created_at`
/// order on purpose: an implementation that instead returned HashMap iteration order (unspecified)
/// or insertion order would fail this.
#[test]
fn list_keys_is_ordered_by_created_at_regardless_of_insertion_order() {
    let s = MemoryStore::new();
    // Insert deliberately out of created_at order.
    s.put_key(&key("c", 30)).unwrap();
    s.put_key(&key("a", 10)).unwrap();
    s.put_key(&key("b", 20)).unwrap();

    let ids: Vec<String> = s.list_keys().unwrap().into_iter().map(|k| k.id).collect();
    assert_eq!(
        ids,
        vec!["a".to_string(), "b".to_string(), "c".to_string()],
        "list_keys must be ordered by created_at, not insertion or id order"
    );
}
