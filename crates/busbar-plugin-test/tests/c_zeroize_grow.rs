// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-ZEROIZE-GROW (ABI-MIN3-INTERFACE §14): Growth from 4 KiB to 16 MiB frees only zeroed blocks; the crypto arena
//! never reallocates; the H1/H2 clamp (round 13; its C plugin arm included, A13's fixture).
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

use busbar_plugin_abi::host::{Pool, PooledOut};
use busbar_plugin_abi::records::{tag, Records, Writer};

/// A host-side buffer grows 4 KiB → 64 KiB → 1 MiB → 16 MiB through its Writer: every record survives every
/// copy, the block past the written bytes is zero at every size (each class block it took was zero), and every
/// block it outgrew went back zeroed (the pool's blocks drawn afterwards are all zero).
#[test]
fn every_freed_growth_block_is_zero() {
    const CHUNK: usize = 60 << 10;
    let marker = vec![0xC3u8; CHUNK];
    let mut buf = Pool::global().acquire(64 << 20);
    let mut sizes = vec![buf.capacity()];
    let mut records = 0usize;
    while buf.capacity() < 16 << 20 {
        buf.put(tag::TEXT, &marker).expect("under max_out");
        records += 1;
        if sizes.last() != Some(&buf.capacity()) {
            sizes.push(buf.capacity());
        }
        let len = buf.bytes().len();
        assert!(
            buf.whole()[len..].iter().all(|&b| b == 0),
            "past the written bytes"
        );
    }
    assert_eq!(
        sizes,
        [4 << 10, 64 << 10, 1 << 20, 16 << 20],
        "one class at a time, never realloc"
    );
    let kept = Records::new(buf.bytes())
        .filter(
            |rec| matches!(rec, Ok(rec) if rec.tag == tag::TEXT && rec.body == marker.as_slice()),
        )
        .count();
    assert_eq!(kept, records);
    drop(buf);
    let drawn: Vec<PooledOut> = (0..256).map(|_| Pool::global().acquire(1 << 20)).collect();
    for b in &drawn {
        assert!(b.whole().iter().all(|&x| x == 0));
    }
}

#[test]
#[ignore = "owner: W1-H1 (blocked: entry::guard, GetBusbar/busbar#272)"]
fn the_arena_never_reallocates_and_frees_zero_on_thread_exit() {
    todo!("owner: W1-H1 (C-ZEROIZE-GROW)")
}

#[test]
#[ignore = "owner: W1-H1 (blocked: a plugin that states out.len past its capacity, W1-A13 C fixture)"]
fn out_len_and_grow_clamps_keep_high_water_within_own_cap() {
    todo!("owner: W1-H1 (C-ZEROIZE-GROW)")
}
