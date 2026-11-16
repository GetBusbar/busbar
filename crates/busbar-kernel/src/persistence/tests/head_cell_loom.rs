// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SEALING-FIX §9 test 17, `head_cell_park_handshake_loom`: a loom model of the one writer
//! (publish, then the parked check) and the notary (read, park, re-check). Run with
//! `cargo test -p busbar-kernel --features loom-model head_cell_loom`.

use crate::persistence::journal::head_cell::{Head, HeadCell};
use loom::sync::atomic::{AtomicBool, Ordering};
use loom::sync::Arc;

const LOOM_STACK_WORDS: usize = 262_144;

fn head(n: u64) -> Head {
    Head {
        seq: n,
        node_seq: n,
        fp: [n as u8; 32],
        wall_ms: n,
    }
}

/// No wake-up is lost: if the notary decided to sleep, the writer saw it parked and woke it.
#[test]
fn head_cell_park_handshake_loom() {
    loom::model(|| {
        let cell = Arc::new(HeadCell::new());
        let woken = Arc::new(AtomicBool::new(false));
        let (seen, _) = cell.read();
        let writer = {
            let (cell, woken) = (cell.clone(), woken.clone());
            loom::thread::Builder::new()
                .stack_size(LOOM_STACK_WORDS)
                .spawn(move || {
                    if cell.publish(&head(1)) {
                        woken.store(true, Ordering::SeqCst);
                    }
                })
                .unwrap()
        };
        let sleeps = cell.park(seen);
        writer.join().unwrap();
        assert!(
            !sleeps || woken.load(Ordering::SeqCst),
            "LOST WAKE-UP: the notary parked over a published head and nobody woke it"
        );
        if !sleeps {
            assert_eq!(cell.read().1, head(1), "a moved version shows the new head");
        }
    });
}

/// A read never mixes two publishes: every field comes from one head.
#[test]
fn head_cell_read_is_never_torn_loom() {
    loom::model(|| {
        let cell = Arc::new(HeadCell::new());
        let writer = {
            let cell = cell.clone();
            loom::thread::Builder::new()
                .stack_size(LOOM_STACK_WORDS)
                .spawn(move || {
                    let _ = cell.publish(&head(1));
                    let _ = cell.publish(&head(2));
                })
                .unwrap()
        };
        let (_, read) = cell.read();
        assert!(
            read == Head::default() || read == head(1) || read == head(2),
            "TORN READ: {read:?}"
        );
        writer.join().unwrap();
    });
}
