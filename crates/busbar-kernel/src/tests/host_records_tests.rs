// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The queued-write overlay and the list rule (`host_records.rs`).

use super::*;

#[test]
fn a_queued_write_reads_back_until_its_batch_is_acknowledged() {
    let p = PendingRecords::default();
    assert_eq!(p.get("i", "k", b"a"), None);
    let seq = p.enqueue("i", "k", b"a", Some(b"1".to_vec()));
    assert_eq!(p.get("i", "k", b"a"), Some(Some(b"1".to_vec())));
    assert_eq!(p.get("other", "k", b"a"), None);
    assert_eq!(p.get("i", "other", b"a"), None);
    p.acked("i", "k", b"a", seq);
    assert_eq!(p.get("i", "k", b"a"), None);
    assert_eq!(p.queued(), 0);
}

#[test]
fn a_second_write_outlives_the_acknowledgement_of_the_first() {
    let p = PendingRecords::default();
    let first = p.enqueue("i", "k", b"a", Some(b"1".to_vec()));
    p.enqueue("i", "k", b"a", None);
    p.acked("i", "k", b"a", first);
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
