// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HEAD CELL (SEALING-FIX r20 §3.2 "`HeadCell`"): how the audit notary learns a node's newest
//! linked line without taking the `Durability` lock.
//!
//! One writer (whoever holds the node's `Durability` lock: the request path, admin `seal_unit` and
//! recovery's publish) and one reader (the notary task). The fields are a seqlock over plain
//! atomics: no `unsafe`, no allocation, a few nanoseconds per publish.
//!
//! The PARK HANDSHAKE is sequentially consistent, so a wake-up is never lost: the reader parks by
//! storing `parked` and then loading `version`, both `SeqCst`; the writer stores `version` and then
//! loads `parked`, both `SeqCst`. In the one total order either the reader sees the new version (and
//! does not sleep), or the writer sees `parked` (and the caller wakes it). [`HeadCell::publish`]
//! returns that answer; the caller owns the wake mechanism (a `tokio::sync::Notify`, whose stored
//! permit covers a wake issued before the reader awaits).
//!
//! Under `--features loom-model` in tests the atomics are loom's, and `tests/head_cell_loom.rs`
//! model-checks both the torn-read freedom and the handshake (§9 test 17).

#[cfg(all(test, feature = "loom-model"))]
use loom::sync::atomic::{fence, AtomicBool, AtomicU64, Ordering};
#[cfg(not(all(test, feature = "loom-model")))]
use std::sync::atomic::{fence, AtomicBool, AtomicU64, Ordering};

/// ONE HEAD: the newest line a node has staged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Head {
    /// The line's chain position (its audit `seq`).
    pub seq: u64,
    /// The WAL `node_seq` of the journal record that carries it.
    pub node_seq: u64,
    /// The line's 32-byte link fingerprint.
    pub fp: [u8; 32],
    /// The line's `linked_ms`: when it was linked into the chain (never its arrival).
    pub wall_ms: u64,
}

/// THE CELL. Shared as an `Arc` by the node's `Durability` (writer) and its notary (reader).
#[derive(Debug)]
pub struct HeadCell {
    version: AtomicU64,
    seq: AtomicU64,
    node_seq: AtomicU64,
    fp: [AtomicU64; 4],
    wall_ms: AtomicU64,
    parked: AtomicBool,
}

impl Default for HeadCell {
    fn default() -> Self {
        HeadCell::new()
    }
}

impl HeadCell {
    /// An empty cell: version 0, head 0 (no line yet).
    #[must_use]
    pub fn new() -> Self {
        HeadCell {
            version: AtomicU64::new(0),
            seq: AtomicU64::new(0),
            node_seq: AtomicU64::new(0),
            fp: [
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
            ],
            wall_ms: AtomicU64::new(0),
            parked: AtomicBool::new(false),
        }
    }

    /// PUBLISH `head`. The single writer only (the caller holds the node's `Durability` lock).
    /// Returns whether the reader is parked, in which case the caller must wake it.
    #[must_use = "a parked reader must be woken"]
    pub fn publish(&self, head: &Head) -> bool {
        let v = self.version.load(Ordering::Relaxed);
        self.version.store(v.wrapping_add(1), Ordering::Relaxed);
        fence(Ordering::Release);
        self.seq.store(head.seq, Ordering::Relaxed);
        self.node_seq.store(head.node_seq, Ordering::Relaxed);
        for (word, chunk) in self.fp.iter().zip(head.fp.as_chunks::<8>().0) {
            word.store(u64::from_le_bytes(*chunk), Ordering::Relaxed);
        }
        self.wall_ms.store(head.wall_ms, Ordering::Relaxed);
        // A release store that also joins the single total order of the park handshake.
        self.version.store(v.wrapping_add(2), Ordering::SeqCst);
        self.parked.load(Ordering::SeqCst)
    }

    /// PUBLISH `head` only if it is newer than the head already published (recovery's publish,
    /// which may land after a request line with a higher `seq`, SEALING-FIX §3.5). The single
    /// writer only. Returns whether the reader must be woken (always `false` when nothing changed).
    #[must_use = "a parked reader must be woken"]
    pub fn publish_max(&self, head: &Head) -> bool {
        if head.seq <= self.seq.load(Ordering::Relaxed) {
            return false;
        }
        self.publish(head)
    }

    /// The current version (`Acquire`): even when no publish is in progress.
    #[must_use]
    pub fn version(&self) -> u64 {
        self.version.load(Ordering::Acquire)
    }

    /// READ the head consistently: retries while a publish is in progress or interleaves. Returns
    /// the version it read at and the head.
    #[must_use]
    pub fn read(&self) -> (u64, Head) {
        loop {
            let before = self.version.load(Ordering::Acquire);
            if before % 2 == 1 {
                std::hint::spin_loop();
                #[cfg(all(test, feature = "loom-model"))]
                loom::thread::yield_now();
                continue;
            }
            let mut head = Head {
                seq: self.seq.load(Ordering::Relaxed),
                node_seq: self.node_seq.load(Ordering::Relaxed),
                fp: [0; 32],
                wall_ms: self.wall_ms.load(Ordering::Relaxed),
            };
            for (chunk, word) in head.fp.as_chunks_mut::<8>().0.iter_mut().zip(&self.fp) {
                *chunk = word.load(Ordering::Relaxed).to_le_bytes();
            }
            fence(Ordering::Acquire);
            if self.version.load(Ordering::Relaxed) == before {
                return (before, head);
            }
            #[cfg(all(test, feature = "loom-model"))]
            loom::thread::yield_now();
        }
    }

    /// BEGIN TO PARK, having last read the cell at version `seen`. Returns `true` when the reader
    /// may sleep (nothing was published since `seen`; a later publish sees `parked` and wakes it),
    /// `false` when the head moved (the reader works instead; `parked` is cleared).
    #[must_use]
    pub fn park(&self, seen: u64) -> bool {
        self.parked.store(true, Ordering::SeqCst);
        if self.version.load(Ordering::SeqCst) != seen {
            self.parked.store(false, Ordering::SeqCst);
            return false;
        }
        true
    }

    /// The reader is awake again.
    pub fn unpark(&self) {
        self.parked.store(false, Ordering::SeqCst);
    }
}
