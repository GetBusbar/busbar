// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::atomic::{AtomicU32, Ordering};

use super::*;
use crate::posting::record::{Op, Rec};

fn ready(n: u8) -> Rec {
    Rec::Ready {
        op: Op(busbar_contract::abi::store::OpId([n; 16])),
    }
}

/// Fails the next `n` syncs.
struct Failing(AtomicU32);

impl Syncer for Failing {
    fn sync(&self, file: &File) -> io::Result<()> {
        if self
            .0
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_ok()
        {
            return Err(io::Error::other("injected fsync failure"));
        }
        file.sync_data()
    }
}

fn tmp() -> crate::posting::TmpDir {
    crate::posting::TmpDir::new()
}

#[test]
fn rounds_read_back_in_order_after_a_reopen() {
    let dir = tmp();
    let (mut s, recs) = Spool::open(dir.path(), Arc::new(DataSync)).expect("open");
    assert!(recs.is_empty());
    s.append(&[ready(1), ready(2)]).expect("round");
    s.append(&[ready(3)]).expect("round");
    assert_eq!(s.fsyncs().load(Ordering::Relaxed), 2, "one fsync per round");
    drop(s);
    let (_, recs) = Spool::open(dir.path(), Arc::new(DataSync)).expect("reopen");
    assert_eq!(recs, vec![ready(1), ready(2), ready(3)]);
}

#[test]
fn a_torn_tail_is_cut_and_the_next_round_follows_the_last_whole_record() {
    let dir = tmp();
    let (mut s, _) = Spool::open(dir.path(), Arc::new(DataSync)).expect("open");
    s.append(&[ready(1)]).expect("round");
    drop(s);
    let seg = std::fs::read_dir(dir.path())
        .expect("dir")
        .flatten()
        .find(|e| e.file_name().to_string_lossy().starts_with("seg-"))
        .expect("a segment")
        .path();
    let mut f = OpenOptions::new().append(true).open(&seg).expect("seg");
    f.write_all(&[9, 0, 0, 0, 1, 2]).expect("torn bytes");
    drop(f);
    let (mut s, recs) = Spool::open(dir.path(), Arc::new(DataSync)).expect("reopen");
    assert_eq!(recs, vec![ready(1)]);
    s.append(&[ready(2)]).expect("round");
    drop(s);
    let (_, recs) = Spool::open(dir.path(), Arc::new(DataSync)).expect("reopen");
    assert_eq!(recs, vec![ready(1), ready(2)]);
}

#[test]
fn a_failed_fsync_seals_the_segment_and_rewrites_the_round_into_a_new_one() {
    let dir = tmp();
    let failing = Arc::new(Failing(AtomicU32::new(0)));
    let (mut s, _) = Spool::open(dir.path(), failing.clone()).expect("open");
    s.append(&[ready(1)]).expect("round");
    failing.0.store(1, Ordering::SeqCst);
    s.append(&[ready(2)])
        .expect("the rewrite into a fresh segment takes the round");
    assert!(!s.failed());
    s.append(&[ready(3)])
        .expect("later rounds go to the fresh segment");
    drop(s);
    let (_, recs) = Spool::open(dir.path(), Arc::new(DataSync)).expect("reopen");
    // The failed segment is read only up to its last synced offset: the failed round's bytes in
    // it are never read twice.
    assert_eq!(recs, vec![ready(1), ready(2), ready(3)]);
}

#[test]
fn a_rewrite_that_fails_too_leaves_the_spool_failed_until_a_reopen() {
    let dir = tmp();
    let failing = Arc::new(Failing(AtomicU32::new(0)));
    let (mut s, _) = Spool::open(dir.path(), failing.clone()).expect("open");
    failing.0.store(2, Ordering::SeqCst);
    assert!(s.append(&[ready(1)]).is_err());
    assert!(s.failed());
    s.reopen().expect("reopen");
    s.append(&[ready(2)]).expect("round");
    drop(s);
    let (_, recs) = Spool::open(dir.path(), Arc::new(DataSync)).expect("reopen");
    assert_eq!(recs, vec![ready(2)]);
}

#[test]
fn compaction_switches_the_generation_to_the_live_records_alone() {
    let dir = tmp();
    let (mut s, _) = Spool::open(dir.path(), Arc::new(DataSync)).expect("open");
    s.append(&[ready(1), ready(2), ready(3)]).expect("round");
    s.compact(&[ready(2)]).expect("compact");
    s.append(&[ready(4)]).expect("round");
    let segs = std::fs::read_dir(dir.path())
        .expect("dir")
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().starts_with("seg-"))
        .count();
    assert_eq!(segs, 1, "the old generation's segments are removed");
    drop(s);
    let (_, recs) = Spool::open(dir.path(), Arc::new(DataSync)).expect("reopen");
    assert_eq!(recs, vec![ready(2), ready(4)]);
}

#[test]
fn the_dead_letter_file_appends_synced_framed_records() {
    let dir = tmp();
    let f = Ledgerette::at(dir.path().join("DEADLETTERS"));
    assert!(f.read().expect("read").is_empty());
    f.append(&[b"one".to_vec(), b"two".to_vec()])
        .expect("append");
    assert_eq!(
        f.read().expect("read"),
        vec![b"one".to_vec(), b"two".to_vec()]
    );
    f.discard().expect("discard");
    assert!(f.read().expect("read").is_empty());
}
