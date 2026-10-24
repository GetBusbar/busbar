// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The list rule (`services.rs`).

use super::*;

fn kv(k: &str, v: &str) -> (Vec<u8>, Vec<u8>) {
    (k.as_bytes().to_vec(), v.as_bytes().to_vec())
}

#[test]
fn the_list_lays_queued_writes_over_the_store_then_applies_after_and_limit() {
    let stored = vec![kv("a", "s"), kv("b", "s"), kv("c", "s")];
    let queued = vec![kv("c", "q"), kv("d", "q")];
    assert_eq!(
        merge_list(stored.clone(), queued.clone(), None, 10),
        vec![kv("a", "s"), kv("b", "s"), kv("c", "q"), kv("d", "q")]
    );
    assert_eq!(
        merge_list(stored.clone(), queued.clone(), Some(b"b"), 10),
        vec![kv("c", "q"), kv("d", "q")]
    );
    assert_eq!(merge_list(stored, queued, None, 1), vec![kv("a", "s")]);
}

#[test]
fn a_tombstone_is_absent_and_a_queued_one_hides_the_stored_row_before_the_limit() {
    let stored = vec![kv("a", "s"), kv("b", ""), kv("c", "s")];
    let queued = vec![kv("a", "")];
    assert_eq!(merge_list(stored, queued, None, 1), vec![kv("c", "s")]);
}

/// A chained record's listed key is its scope, `/` and twenty digits; the parts read back from it,
/// and a key that is no record's (a bare scope, a short or non-digit tail) names none.
#[test]
fn a_chain_key_is_its_scope_and_its_sequence_and_reads_back() {
    let key = chain_key(b"a11ce/t1", 7);
    assert_eq!(key, b"a11ce/t1/00000000000000000007".to_vec());
    assert_eq!(chain_key_parts(&key), Some((&b"a11ce/t1"[..], 7)));
    assert_eq!(
        chain_key_parts(&chain_key(b"s", u64::MAX)),
        Some((&b"s"[..], u64::MAX))
    );
    for none in [
        &b"a11ce/t1"[..],
        b"/00000000000000000007",
        b"t1/0000000000000000007",
        b"t1-00000000000000000007",
        b"t1/0000000000000000000x",
        b"t1/99999999999999999999",
    ] {
        assert_eq!(
            chain_key_parts(none),
            None,
            "{}",
            String::from_utf8_lossy(none)
        );
    }
    assert!(
        chain_key(b"t1", 9) < chain_key(b"t1", 10),
        "key order is sequence order"
    );
}
