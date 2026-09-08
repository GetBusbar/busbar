// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `admin_witness`'s own proof: what `record()` puts in and what `snapshot()` reads back.

use super::*;

// `WITNESSED` is one process-wide static that every test in this binary shares, so each test
// below records under a `rel` unique to itself (a `#[test]`-fn-local literal no other test in
// this file or crate uses) and asserts only "this exact tuple is present in the snapshot" rather
// than asserting anything about the snapshot's total size — the one assertion shape that stays
// correct under `cargo test`'s default parallel, shared-process execution.

#[test]
fn record_then_snapshot_contains_the_witnessed_tuple_verbatim() {
    record(
        "admin-witness-test/verbatim",
        "POST",
        "NotFound",
        Some("cond-a"),
    );
    let snap = snapshot();
    assert!(
        snap.contains(&(
            "admin-witness-test/verbatim".to_string(),
            "POST".to_string(),
            "NotFound".to_string(),
            Some("cond-a".to_string()),
        )),
        "the exact recorded tuple must be readable back out of the snapshot"
    );
}

#[test]
fn a_missing_condition_records_and_reads_back_as_none_not_a_sentinel_string() {
    record("admin-witness-test/no-cond", "GET", "Forbidden", None);
    let snap = snapshot();
    assert!(
        snap.contains(&(
            "admin-witness-test/no-cond".to_string(),
            "GET".to_string(),
            "Forbidden".to_string(),
            None,
        )),
        "a `None` condition must round-trip as `None`, not e.g. an empty-string stand-in"
    );
}

#[test]
fn recording_the_same_tuple_twice_is_idempotent_in_the_set() {
    for _ in 0..3 {
        record("admin-witness-test/dedup", "PUT", "Conflict", Some("x"));
    }
    let snap = snapshot();
    let matches = snap
        .iter()
        .filter(|(rel, method, kind, cond)| {
            rel == "admin-witness-test/dedup"
                && method == "PUT"
                && kind == "Conflict"
                && cond.as_deref() == Some("x")
        })
        .count();
    assert_eq!(
        matches, 1,
        "a `BTreeSet` must hold one copy of an identical tuple no matter how many times it is recorded"
    );
}

#[test]
fn distinct_fields_are_distinct_witnesses_not_folded_together() {
    record("admin-witness-test/distinct", "GET", "kind-a", None);
    record("admin-witness-test/distinct", "GET", "kind-b", None);
    let snap = snapshot();
    assert!(snap.contains(&(
        "admin-witness-test/distinct".to_string(),
        "GET".to_string(),
        "kind-a".to_string(),
        None,
    )));
    assert!(snap.contains(&(
        "admin-witness-test/distinct".to_string(),
        "GET".to_string(),
        "kind-b".to_string(),
        None,
    )));
}
