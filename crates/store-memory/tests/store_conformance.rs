// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The shared [`busbar_contract::store::Store`] contract conformance suite (`busbar-plugin-testkit`).
//!
//! Core's own reference backend runs it alongside every plugin backend on purpose: these checks
//! exist because the fleet had silently disagreed with itself about all four behaviours, and a suite
//! the reference implementation is exempt from is a suite nobody has to agree with.
//!
//! Every ruling the suite offers is wired here, including the audit-fork and plane-record ones the
//! reference backend used to sit out by taking the trait's keep-nothing defaults. Ephemeral is not
//! the same as absent: this store loses its rows on restart, but WITHIN a process it is the backend
//! an out-of-the-box deployment actually runs on, so it answers the same questions every plugin
//! backend does — a suite the default implementation is exempt from is a suite nobody has to agree
//! with.
//!
//! Its own file rather than a second inline `mod` in `src/lib.rs`, per the repo's test-locality rule
//! (at most one inline test body per file; see `docs/code-layout.md`).

use busbar_plugin_testkit::store_conformance as conf;
use busbar_store_memory::MemoryStore;

// A fresh MemoryStore per check is already an empty namespace, so `ns` only has to be stable.

#[test]
fn put_key_does_not_resurrect_a_tombstone() {
    conf::assert_put_key_does_not_resurrect_a_tombstone(&MemoryStore::new(), "conf");
}

#[test]
fn delete_key_unknown_id_is_an_error() {
    conf::assert_delete_key_unknown_id_is_an_error(&MemoryStore::new(), "conf");
}

#[test]
fn revoke_credential_unknown_id_is_an_error() {
    conf::assert_revoke_credential_unknown_id_is_an_error(&MemoryStore::new(), "conf");
}

#[test]
fn put_credential_requires_a_live_key() {
    conf::assert_put_credential_requires_a_live_key(&MemoryStore::new(), "conf");
}

#[test]
fn put_key_with_credential_is_atomic() {
    conf::assert_put_key_with_credential_is_atomic(&MemoryStore::new(), "conf");
}

#[test]
fn append_audit_settles_a_duplicate_seq() {
    conf::assert_append_audit_duplicate_seq(&MemoryStore::new(), 1);
}

#[test]
fn plane_task_upsert_get_list() {
    conf::assert_plane_task_upsert_get_list(&MemoryStore::new(), "conf");
}

#[test]
fn plane_event_chain_is_ordered_by_seq() {
    conf::assert_plane_event_chain_is_ordered_by_seq(&MemoryStore::new(), "conf");
}

#[test]
fn plane_call_parents_enumerated() {
    conf::assert_plane_call_parents_enumerated(&MemoryStore::new(), "conf");
}

#[test]
fn plane_demotion_upsert_list_delete() {
    conf::assert_plane_demotion_upsert_list_delete(&MemoryStore::new(), "conf");
}

#[test]
fn plane_purge_honours_the_cutoff() {
    conf::assert_plane_purge_honours_the_cutoff(&MemoryStore::new(), "conf");
}

#[test]
fn plane_purge_task_keeps_active_rows() {
    conf::assert_plane_purge_task_keeps_active_rows(&MemoryStore::new(), "conf");
}

#[test]
fn plane_token_is_single_use() {
    conf::assert_plane_token_is_single_use(&MemoryStore::new(), "conf");
}

// Regression for the store-conformance battery's kind-wide purge collision: `purge_plane_records_
// before(kind, before)` has no namespace of its own, so two conformance runs sharing one live
// database (modeled here as one shared `MemoryStore` driven from two threads) can each sweep rows
// the other run just wrote. Before the fix, both `assert_plane_purge_*` checks asserted an EXACT
// purged count, so a genuinely conforming backend could be marked non-conforming purely from the
// interleaving. These two tests share one store across two concurrently-running `ns`s and require
// both runs to complete without panicking.

#[test]
fn plane_purge_honours_the_cutoff_survives_two_interleaved_runs() {
    let store = MemoryStore::new();
    std::thread::scope(|scope| {
        let a = scope.spawn(|| conf::assert_plane_purge_honours_the_cutoff(&store, "confA"));
        let b = scope.spawn(|| conf::assert_plane_purge_honours_the_cutoff(&store, "confB"));
        a.join().expect("run confA must not panic");
        b.join().expect("run confB must not panic");
    });
}

#[test]
fn plane_purge_task_keeps_active_rows_survives_two_interleaved_runs() {
    let store = MemoryStore::new();
    std::thread::scope(|scope| {
        let a = scope.spawn(|| conf::assert_plane_purge_task_keeps_active_rows(&store, "confA"));
        let b = scope.spawn(|| conf::assert_plane_purge_task_keeps_active_rows(&store, "confB"));
        a.join().expect("run confA must not panic");
        b.join().expect("run confB must not panic");
    });
}
