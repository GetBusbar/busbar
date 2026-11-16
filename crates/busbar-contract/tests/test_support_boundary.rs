// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TEST-SUPPORT BOUNDARY (SDK-SAFE-TEST-HOST §3.3-3.4), through its safe API only: the loans
//! own every byte their `in` points to and rewrite every pair before a crossing, and the watch
//! counts what a scope frees without ever aborting.

use busbar_contract::abi::sdk::test_support::loans::Loans;
use busbar_contract::abi::sdk::test_support::watch::{Block, Watch};
use busbar_contract::abi::transport::{BeginIn, IngestIn, ReadIn, WriteIn};

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

#[test]
fn an_armed_here_scope_counts_this_thread_s_allocations_exactly() {
    let here = A.armed_here(b"", || drop(std::hint::black_box(vec![0u8; 100])));
    assert_eq!(
        (here.allocs, here.alloc_bytes, here.largest_alloc),
        (1, 100, 100),
        "{here:?}"
    );
    assert_eq!((here.count, here.bytes), (1, 100), "{here:?}");
}

#[test]
fn an_armed_here_scope_does_not_count_a_second_thread_s_allocations() {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    // The worker starts before any scope and is driven through atomics only, so the arming
    // thread allocates nothing itself while it waits.
    static GO: AtomicBool = AtomicBool::new(false);
    static DONE: AtomicUsize = AtomicUsize::new(0);
    let worker = std::thread::spawn(|| {
        for _ in 0..2 {
            while !GO.load(Ordering::SeqCst) {
                std::thread::yield_now();
            }
            drop(std::hint::black_box(vec![0u8; 4096]));
            GO.store(false, Ordering::SeqCst);
            DONE.fetch_add(1, Ordering::SeqCst);
        }
    });
    let round = |here: bool| {
        let want = DONE.load(Ordering::SeqCst) + 1;
        let run = || {
            GO.store(true, Ordering::SeqCst);
            while DONE.load(Ordering::SeqCst) < want {
                std::thread::yield_now();
            }
        };
        if here {
            A.armed_here(b"", run)
        } else {
            A.armed(b"", run)
        }
    };
    let here = round(true);
    assert_eq!(
        (
            here.allocs,
            here.alloc_bytes,
            here.largest_alloc,
            here.count,
            here.bytes
        ),
        (0, 0, 0, 0, 0),
        "a second thread's allocation and free are not this thread's: {here:?}"
    );
    let all = round(false);
    assert!(
        all.allocs >= 1 && all.largest_alloc >= 4096,
        "the same work is seen by an all-threads scope: {all:?}"
    );
    worker.join().expect("worker");
}

#[test]
fn a_watched_realloc_is_a_new_block_and_the_old_one_freed() {
    let here = A.armed_here(b"", || {
        let mut v = Vec::<u8>::with_capacity(8);
        v.extend_from_slice(&[1; 8]);
        v.reserve_exact(64);
        drop(std::hint::black_box(v));
    });
    assert_eq!(
        here.allocs, 2,
        "with_capacity and the grown block: {here:?}"
    );
    assert!(here.largest_alloc >= 72, "{here:?}");
    assert_eq!(here.count, 2, "the old block, then the grown one: {here:?}");
    assert!(
        here.nonzero_blocks >= 1,
        "the old block still held its bytes: {here:?}"
    );
}

#[test]
fn a_watched_block_is_read_as_it_is_freed() {
    let wiped = A.armed(CANARY, || {
        let mut v = CANARY.to_vec();
        A.block(v.as_ptr(), v.len());
        v.fill(0);
        drop(std::hint::black_box(v));
    });
    assert_eq!(
        wiped.block,
        Some(Block {
            nonzero: false,
            canary: false
        })
    );
    let kept = A.armed(CANARY, || {
        let v = CANARY.to_vec();
        A.block(v.as_ptr(), v.len());
        drop(std::hint::black_box(v));
    });
    assert_eq!(
        kept.block,
        Some(Block {
            nonzero: true,
            canary: true
        })
    );
    let v = CANARY.to_vec();
    let live = A.armed(CANARY, || A.block(v.as_ptr(), v.len()));
    assert_eq!(
        live.block, None,
        "a block not freed in the scope reads nothing"
    );
    drop(v);
}

#[cfg(unix)]
#[test]
#[cfg_attr(miri, ignore = "Miri has no thread CPU clock")]
fn the_thread_cpu_clock_moves_with_work() {
    use busbar_contract::abi::sdk::test_support::cpu;
    let before = cpu::thread_ns();
    let mut x = 0u64;
    for i in 0..2_000_000u64 {
        x = std::hint::black_box(x.wrapping_mul(31).wrapping_add(i));
    }
    std::hint::black_box(x);
    assert!(cpu::thread_ns() > before);
}

#[test]
fn a_lane_lends_its_paths_and_keying() {
    let mut b = Loans::<BeginIn>::new();
    b.lane(|l| {
        l.push(|lane| {
            lane.size(1)
                .keying(|k| {
                    k.push(|m| {
                        m.profile(1);
                    });
                })
                .paths(|p| {
                    p.push(|path| {
                        path.path(1).addr("127.0.0.1:9");
                    });
                });
        });
    });
    let sealed = b.seal();
    assert!(!sealed.lane.is_null());
}

#[test]
fn a_verify_lends_its_named_lines() {
    use busbar_contract::abi::auth::VerifyIn;
    use busbar_contract::abi::mechanism::call::BLOB_OCTETS;
    let mut v = Loans::<VerifyIn>::new();
    v.lines(|l| {
        l.push(|line| {
            line.name("authorization").value(b"Bearer t0", BLOB_OCTETS);
        });
        l.push(|line| {
            line.name("x-id").value(b"7", BLOB_OCTETS);
        });
    });
    let sealed = v.seal();
    assert!(!sealed.lines.is_null());
    assert_eq!(sealed.lines_len, 2, "both named lines are lent");
}

#[test]
fn a_check_lends_its_instances() {
    use busbar_contract::abi::export::CheckIn;
    use busbar_contract::abi::mechanism::call::BLOB_JSON;
    let mut c = Loans::<CheckIn>::new();
    c.instances(|l| {
        l.push(|i| {
            i.name("primary").settings(b"{}", BLOB_JSON);
        });
    });
    let sealed = c.seal();
    assert!(!sealed.instances.is_null());
    assert_eq!(sealed.instances_len, 1, "the instance is lent");
}
