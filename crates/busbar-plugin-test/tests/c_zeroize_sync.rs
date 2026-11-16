// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-ZEROIZE-SYNC (ABI-MIN3-INTERFACE §14): Sync buffers and the arena read back zero after `Err(Full)`, a refusal
//! and an OK (round 6).
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).
//!
//! W1-H1: the sync-buffer half is the pool's (`sync_bufs`) and runs here. The arena half needs the entry guard's
//! outermost-exit reset around a real sync entry (`entry::guard`, W1-H0's file), so it waits as its own arm.

use busbar_plugin_abi::fail::refused;
use busbar_plugin_abi::host::sync_bufs;
use busbar_plugin_abi::records::{tag, FailRec, Writer};
use busbar_plugin_abi::types::Status;

const SECRET: &[u8] = b"hmac-key-0123456789abcdef";

fn zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|&b| b == 0)
}

#[test]
fn sync_buffers_read_back_zero_after_full_a_refusal_and_an_ok() {
    // Err(Full): the call fills out to max_out and the next record does not fit.
    sync_bufs(4096, |args, out| {
        args.put(tag::TEXT, SECRET).expect("args");
        out.put(tag::TEXT, &[0x5A; 4060]).expect("first");
        assert!(out.put(tag::TEXT, SECRET).is_err(), "over max_out");
    });
    // A refusal: the answer is one FAIL whose text names the secret.
    sync_bufs(4096, |args, out| {
        assert!(zero(args.whole()) && zero(out.whole()), "after Err(Full)");
        let head = FailRec {
            status: Status::REFUSED.0,
            code: refused::R_DENIED,
        };
        out.put_pod_tail(tag::FAIL, &head, SECRET).expect("fail");
    });
    // An OK.
    sync_bufs(4096, |args, out| {
        assert!(zero(args.whole()) && zero(out.whole()), "after a refusal");
        out.put(tag::TEXT, SECRET).expect("ok");
    });
    sync_bufs(4096, |args, out| {
        assert!(zero(args.whole()) && zero(out.whole()), "after an OK");
    });
}

#[test]
#[ignore = "owner: W1-H1 (blocked: entry::guard, GetBusbar/busbar#272)"]
fn the_arena_reads_back_zero_after_each_sync_entry() {
    todo!("owner: W1-H1 (C-ZEROIZE-SYNC arena arm: needs entry::guard)")
}
