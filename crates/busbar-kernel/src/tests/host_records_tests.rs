// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The queued-write overlay and the list rule (`host_records.rs`).

use super::*;

fn kv(k: &str, v: &str) -> (Vec<u8>, Vec<u8>) {
    (k.as_bytes().to_vec(), v.as_bytes().to_vec())
}

#[test]
fn a_queued_write_reads_back_until_its_batch_is_acknowledged() {
    let p = PendingRecords::default();
    assert_eq!(p.get("i", "k", b"a"), None);
    let seq = p.enqueue("i", "k", b"a", Some(b"1".to_vec()));
    assert_eq!(p.get("i", "k", b"a"), Some(Some(b"1".to_vec())));
    assert_eq!(p.get("other", "k", b"a"), None);
    assert_eq!(p.get("i", "other", b"a"), None);
    p.acked("i", seq);
    assert_eq!(p.get("i", "k", b"a"), None);
    assert_eq!(p.queued(), 0);
}

#[test]
fn a_later_write_outlives_the_acknowledgement_of_an_earlier_one() {
    let p = PendingRecords::default();
    let first = p.enqueue("i", "k", b"a", Some(b"1".to_vec()));
    p.enqueue("i", "k", b"a", None);
    p.acked("i", first);
    assert_eq!(p.get("i", "k", b"a"), Some(None));
}

#[test]
fn the_overlay_lists_its_kind_under_the_prefix_in_key_order() {
    let p = PendingRecords::default();
    p.enqueue("i", "k", b"b2", Some(b"2".to_vec()));
    p.enqueue("i", "k", b"b1", None);
    p.enqueue("i", "k", b"c", Some(b"x".to_vec()));
    p.enqueue("i", "j", b"b3", Some(b"x".to_vec()));
    assert_eq!(
        p.under("i", "k", b"b"),
        vec![
            (b"b1".to_vec(), None),
            (b"b2".to_vec(), Some(b"2".to_vec()))
        ]
    );
}

#[test]
fn the_list_lays_queued_writes_over_the_store_then_applies_after_and_limit() {
    let stored = vec![kv("a", "s"), kv("b", "s"), kv("c", "s")];
    let queued = vec![
        (b"b".to_vec(), None),
        (b"c".to_vec(), Some(b"q".to_vec())),
        (b"d".to_vec(), Some(b"q".to_vec())),
    ];
    assert_eq!(
        merge_list(stored.clone(), queued.clone(), None, 10),
        vec![kv("a", "s"), kv("c", "q"), kv("d", "q")]
    );
    assert_eq!(
        merge_list(stored.clone(), queued.clone(), Some(b"a"), 10),
        vec![kv("c", "q"), kv("d", "q")]
    );
    assert_eq!(merge_list(stored, queued, None, 1), vec![kv("a", "s")]);
}
