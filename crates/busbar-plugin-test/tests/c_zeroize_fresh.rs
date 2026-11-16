// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-ZEROIZE-FRESH (ABI-MIN3-INTERFACE §14): A fresh pool miss parses as all zero; no secret of an earlier chain
//! is parsed; no `with_capacity`/`set_len`/`MaybeUninit` in `pool.rs` (H1 + A13 + T1).
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

use busbar_plugin_abi::host::{Pool, PooledOut};
use busbar_plugin_abi::records::{tag, Records, Writer};

/// A block drawn from the pool is zero over its whole capacity, so an answer that claims `len = cap` parses
/// zeros (never an earlier request's bytes); a block that held a credential comes back the same.
#[test]
fn a_fresh_miss_parses_as_zero() {
    const CREDENTIAL: &[u8] = b"Authorization: Bearer 9f8e7d6c";
    // More blocks than the queue can hold at once: some are misses, some reuses; all must be zero.
    let drawn: Vec<PooledOut> = (0..512).map(|_| Pool::global().acquire(1 << 20)).collect();
    for buf in &drawn {
        assert_eq!(buf.capacity(), 4096, "every entry buffer starts at 4 KiB");
        assert!(buf.whole().iter().all(|&b| b == 0));
        let parsed: Vec<_> = Records::new(buf.whole()).collect();
        assert!(
            parsed
                .iter()
                .all(|rec| matches!(rec, Ok(rec) if rec.tag == 0 && rec.body.is_empty())),
            "zeros parse as empty tag-0 records, never as data"
        );
    }
    drop(drawn);
    let mut used = Pool::global().acquire(1 << 20);
    used.put(tag::FACT_TEXT, CREDENTIAL).expect("fits");
    drop(used);
    for _ in 0..512 {
        let buf = Pool::global().acquire(1 << 20);
        assert!(!buf
            .whole()
            .windows(CREDENTIAL.len())
            .any(|w| w == CREDENTIAL));
        assert!(buf.whole().iter().all(|&b| b == 0));
    }
}

/// The source arm: pool.rs never exposes uninitialised storage as capacity.
#[test]
fn pool_rs_has_no_uninitialised_storage() {
    let source = include_str!("../../busbar-plugin-abi/src/host_side/pool.rs");
    let code: Vec<&str> = source
        .lines()
        .take_while(|line| !line.starts_with("#[cfg(test)]"))
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect();
    for banned in [
        "with_capacity",
        "set_len",
        "MaybeUninit",
        ".reserve(",
        "realloc",
    ] {
        assert!(
            !code.iter().any(|line| line.contains(banned)),
            "pool.rs uses {banned}"
        );
    }
}
