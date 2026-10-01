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
