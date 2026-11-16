// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CANARY SCAN (owner ruling Q24): a wipe proof with no `unsafe` and no custom allocator. A
//! planted canary is found while it lives and in a block freed or given up by a realloc without a
//! wipe, and is absent once wiped. Linux only (`/proc/self/maps` + `/proc/self/mem`).
#![cfg(target_os = "linux")]

use busbar_contract::abi::sdk::test_support::canary::{Canary, LEN};

/// Zero `v`, keep the stores, then free it.
fn wipe(mut v: Vec<u8>) {
    v.iter_mut().for_each(|b| *b = 0);
    std::hint::black_box(&v);
    drop(v);
}

#[test]
#[cfg_attr(miri, ignore = "Miri cannot read /proc/self/mem")]
fn a_planted_canary_is_found_while_it_lives() {
    let mut c = Canary::new().expect("open /proc/self/maps and /proc/self/mem");
    let live = c.plant();
    assert_eq!(live.len(), LEN);
    let scan = c.scan().expect("scan process memory");
    assert!(scan.bytes > 0, "the scan read process memory: {scan:?}");
    assert!(
        scan.hits.contains(&live.as_ptr().addr()),
        "the live canary is found where it lives: {scan:?}"
    );
    wipe(live);
}

#[test]
#[cfg_attr(miri, ignore = "Miri cannot read /proc/self/mem")]
fn a_wiped_and_dropped_canary_is_absent() {
    let mut c = Canary::new().expect("open /proc/self/maps and /proc/self/mem");
    wipe(c.plant());
    let scan = c.scan().expect("scan process memory");
    assert!(scan.bytes > 0, "the scan read process memory: {scan:?}");
    assert!(scan.hits.is_empty(), "no copy is left: {scan:?}");
    c.assert_absent();
}

#[test]
#[cfg_attr(miri, ignore = "Miri cannot read /proc/self/mem")]
fn a_canary_left_in_a_freed_block_is_found() {
    let mut c = Canary::new().expect("open /proc/self/maps and /proc/self/mem");
    // 64 KiB: past the allocator's per-thread caches, below its mmap threshold, so the freed block
    // stays mapped with its bytes; the guard after it keeps it from merging into the top.
    let mut victim = vec![0_u8; 64 * 1024];
    let guard = vec![1_u8; 64 * 1024];
    let at = victim.get_mut(32 * 1024..).expect("inside the block");
    c.plant_into(at);
    let address = at.as_ptr().addr();
    drop(victim);
    let scan = c.scan().expect("scan process memory");
    drop(guard);
    assert!(
        scan.hits.contains(&address),
        "the unwiped freed block still holds the canary: {scan:?}"
    );
}

#[test]
#[cfg_attr(miri, ignore = "Miri cannot read /proc/self/mem")]
fn a_canary_a_growing_buffer_left_behind_is_found() {
    let mut c = Canary::new().expect("open /proc/self/maps and /proc/self/mem");
    let mut grown = vec![0_u8; 64 * 1024];
    let guard = vec![1_u8; 64 * 1024];
    let at = grown.get_mut(32 * 1024..).expect("inside the block");
    c.plant_into(at);
    let old = at.as_ptr().addr();
    // The guard holds the next block, so growth moves the buffer and frees the old block unwiped.
    grown.resize(512 * 1024, 0);
    let moved = grown.as_ptr().addr() + 32 * 1024;
    assert_ne!(moved, old, "growth moved the buffer");
    let scan = c.scan().expect("scan process memory");
    drop(guard);
    assert!(
        scan.hits.contains(&old),
        "the block growth gave up still holds the canary: {scan:?}"
    );
    assert!(
        scan.hits.contains(&moved),
        "the grown buffer holds its copy: {scan:?}"
    );
    wipe(grown);
}
