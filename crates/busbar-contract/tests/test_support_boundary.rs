// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TEST-SUPPORT BOUNDARY (SDK-SAFE-TEST-HOST §3.3-3.4), through its safe API only: the loans
//! own every byte their `in` points to and rewrite every pair before a crossing, and the watch
//! counts what a scope frees without ever aborting.

use busbar_contract::abi::sdk::test_support::loans::Loans;
use busbar_contract::abi::sdk::test_support::watch::Watch;
use busbar_contract::abi::transport::{IngestIn, ReadIn, WriteIn};

#[global_allocator]
static A: Watch = Watch::new();

const CANARY: &[u8] = b"r131-canary-0f3a9c27e1d4b685";

#[test]
fn a_forged_length_does_not_survive_the_seal() {
    let mut i = Loans::<WriteIn>::new();
    i.bytes(b"hello").len(999).conn(7);
    let sealed = i.seal();
    assert_eq!(
        sealed.len, 5,
        "the length is the loans' own, not the forged 999"
    );
    assert!(!sealed.bytes.is_null());
    assert_eq!(sealed.conn, 7);
}

#[test]
fn an_unset_pair_is_null_and_zero_whatever_length_was_set() {
    let mut i = Loans::<WriteIn>::new();
    i.len(4096);
    let sealed = i.seal();
    assert!(sealed.bytes.is_null());
    assert_eq!(sealed.len, 0);
}

#[test]
fn a_host_buffer_has_the_capacity_it_was_allocated_with() {
    let mut i = Loans::<ReadIn>::new();
    let buf = i.buf(4);
    i.cap(1 << 20);
    let sealed = i.seal();
    assert_eq!(sealed.cap, 4);
    assert!(!sealed.buf.is_null());
    assert_eq!(
        i.read(&buf),
        [0u8; 4],
        "a fresh host buffer reads back all zero"
    );
}

#[test]
fn a_nested_struct_s_pairs_are_its_own_storage_too() {
    let mut i = Loans::<IngestIn>::new();
    i.bytes(b"GET / HTTP/1.1\r\n\r\n").sink(|s| {
        s.wire(16);
        s.wire_cap(1 << 30).now_unix_ns(5);
    });
    let sealed = i.seal();
    assert_eq!(sealed.len, 18);
    assert_eq!(
        sealed.sink.wire_cap, 16,
        "the nested forged capacity is rewritten"
    );
    assert!(!sealed.sink.wire.is_null());
    assert_eq!(sealed.sink.now_unix_ns, 5);
    assert!(sealed.sink.frame.is_null() && sealed.sink.frame_cap == 0);
}

#[test]
fn the_watch_counts_a_freed_block_that_still_holds_the_canary() {
    let freed = A.armed(CANARY, || drop(std::hint::black_box(CANARY.to_vec())));
    assert!(freed.count >= 1 && freed.bytes >= CANARY.len(), "{freed:?}");
    assert!(freed.blocks_containing_canary >= 1, "{freed:?}");
    assert!(freed.nonzero_blocks >= 1, "{freed:?}");
}

#[test]
fn the_watch_sees_no_canary_in_a_block_wiped_before_it_was_freed() {
    let freed = A.armed(CANARY, || {
        let mut v = CANARY.to_vec();
        v.fill(0);
        drop(std::hint::black_box(v));
    });
    assert!(freed.count >= 1, "{freed:?}");
    assert_eq!(freed.blocks_containing_canary, 0, "{freed:?}");
}

#[test]
fn a_panic_inside_an_armed_scope_propagates_and_disarms() {
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        A.armed(CANARY, || panic!("inside the armed scope"))
    }));
    assert!(
        r.is_err(),
        "the scope's panic reaches the caller; it does not abort"
    );
    let freed = A.armed(CANARY, || drop(std::hint::black_box(CANARY.to_vec())));
    assert!(
        freed.blocks_containing_canary >= 1,
        "the watch arms again: {freed:?}"
    );
}
