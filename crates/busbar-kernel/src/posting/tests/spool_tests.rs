// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::io::Write;
use std::sync::atomic::{AtomicU32, Ordering};

use super::*;

fn b(n: u8) -> Vec<u8> {
    vec![n; 3]
}

/// Fails the next `n` syncs.
struct Failing(AtomicU32);

impl Syncer for Failing {
    fn sync(&self, backend: &mut dyn SegmentBackend) -> io::Result<()> {
        if self
            .0
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_ok()
        {
            return Err(io::Error::other("injected fsync failure"));
        }
        backend.sync()
    }
}

fn open(dir: &Path) -> (Spool, Vec<Vec<u8>>) {
    Spool::open(dir, Arc::new(DataSync)).expect("open")
}

fn segments(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut out: Vec<_> = std::fs::read_dir(dir)
        .expect("dir")
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "wal"))
        .collect();
    out.sort();
    out
}

#[test]
fn rounds_read_back_in_order_after_a_reopen() {
    let dir = crate::posting::TmpDir::new();
    let (mut s, bodies) = open(dir.path());
    assert!(bodies.is_empty());
    s.append(&[b(1), b(2)]).expect("round");
    s.append(&[b(3)]).expect("round");
    drop(s);
    assert_eq!(open(dir.path()).1, vec![b(1), b(2), b(3)]);
}

/// A crash mid-round, at EVERY byte of the round: the reopened spool holds the rounds before it,
/// whole, and the next round follows them.
#[test]
fn a_torn_tail_at_every_offset_is_cut_to_the_last_whole_round() {
    let dir = crate::posting::TmpDir::new();
    let (mut s, _) = open(dir.path());
    s.append(&[b(1)]).expect("round");
    let whole = s.segment.write_offset();
    s.append(&[vec![7; 900]]).expect("round");
    let end = s.segment.write_offset();
    drop(s);
    let seg = segments(dir.path()).pop().expect("a segment");
    let bytes = std::fs::read(&seg).expect("read");
    for cut in whole..end {
        let mut torn = bytes[..usize::try_from(end).unwrap()].to_vec();
        torn[usize::try_from(cut).unwrap()..].fill(0);
        std::fs::write(&seg, &torn).expect("tear");
        assert_eq!(open(dir.path()).1, vec![b(1)], "cut at {cut}");
    }
    // The next round follows the last whole one.
    let (mut s, _) = open(dir.path());
    s.append(&[b(2)]).expect("round");
    drop(s);
    assert_eq!(open(dir.path()).1, vec![b(1), b(2)]);
    // A tail of foreign bytes reads as torn too.
    std::fs::write(&seg, &bytes[..usize::try_from(whole).unwrap()]).expect("reset");
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(&seg)
        .expect("seg");
    f.write_all(&[9, 0, 0, 0, 1, 2]).expect("torn bytes");
    drop(f);
    assert_eq!(open(dir.path()).1, vec![b(1)]);
}

#[test]
fn a_failed_fsync_moves_the_round_to_a_new_segment_and_reads_it_once() {
    let dir = crate::posting::TmpDir::new();
    let failing = Arc::new(Failing(AtomicU32::new(0)));
    let (mut s, _) = Spool::open(dir.path(), failing.clone()).expect("open");
    s.append(&[b(1)]).expect("round");
    failing.0.store(1, Ordering::SeqCst);
    s.append(&[b(2)])
        .expect("the rewrite into a fresh segment takes the round");
    assert!(!s.failed());
    s.append(&[b(3)])
        .expect("later rounds go to the fresh segment");
    drop(s);
    assert_eq!(segments(dir.path()).len(), 2);
    assert_eq!(open(dir.path()).1, vec![b(1), b(2), b(3)]);
}

#[test]
fn a_rewrite_that_fails_too_leaves_the_spool_failed_until_a_reopen() {
    let dir = crate::posting::TmpDir::new();
    let failing = Arc::new(Failing(AtomicU32::new(0)));
    let (mut s, _) = Spool::open(dir.path(), failing.clone()).expect("open");
    // The round's sync, the poisoned segment's cut, and the rewrite's sync.
    failing.0.store(3, Ordering::SeqCst);
    assert!(s.append(&[b(1)]).is_err());
    assert!(s.failed());
    s.append(&[b(2)]).expect("the next round reopens");
    drop(s);
    assert_eq!(open(dir.path()).1, vec![b(2)]);
}

#[test]
fn compaction_keeps_the_live_bodies_alone_and_a_crash_before_the_removal_reads_once() {
    let dir = crate::posting::TmpDir::new();
    let (mut s, _) = open(dir.path());
    s.append(&[b(1), b(2), b(3)]).expect("round");
    let old = std::fs::read(&segments(dir.path())[0]).expect("old generation");
    s.compact(&[b(2)]).expect("compact");
    s.append(&[b(4)]).expect("round");
    assert_eq!(
        segments(dir.path()).len(),
        1,
        "the old generation is removed"
    );
    drop(s);
    assert_eq!(open(dir.path()).1, vec![b(2), b(4)]);
    // A crash after the new generation synced and before the old one was removed.
    std::fs::write(dir.path().join(format!("{:016}.wal", 0)), old).expect("restore");
    assert_eq!(open(dir.path()).1, vec![b(2), b(4)]);
    assert_eq!(
        segments(dir.path()).len(),
        1,
        "the leftover is removed at open"
    );
}
