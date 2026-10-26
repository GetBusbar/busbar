// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SPOOL ON DISK (MONEY-DESIGN §3c), on `busbar-kernel-wal`'s segments: the kernel's one framed,
//! torn-tail-recovering, poison-on-failed-sync log. This module adds only what the spool needs on
//! top of it:
//!
//! - a round is one [`Segment::append_batch`]: one write and one sync;
//! - a failed write or sync poisons the segment (cut to its last good commit), and the round is
//!   written again into the NEXT segment, so nothing is ever appended after a failed sync;
//! - COMPACTION writes a new segment that opens with a BASE record and holds the live records, and
//!   only then removes the segments below it. Recovery reads from the highest segment opening with a
//!   BASE, so a crash mid-compaction leaves either generation, never both;
//! - every record carries its own sequence number, so a round present in a poisoned segment AND in
//!   the next one is read once.
//!
//! The spool takes no lock of its own: one writer thread owns it.

use std::io;
use std::path::Path;
use std::sync::Arc;

use busbar_kernel_wal::{
    recover, DirectoryFactory, Record, Segment, SegmentBackend, SegmentError, SegmentFactory,
    SEGMENT_BYTES,
};

/// A record that opens a compacted generation.
const BASE: u64 = 0;
/// A record of the spool's own.
const DATA: u64 = 1;

/// How a segment is made durable: [`DataSync`] in production; a test double fails or delays it.
pub trait Syncer: Send + Sync {
    /// Make `backend`'s written bytes durable.
    ///
    /// # Errors
    ///
    /// The medium did not confirm the bytes.
    fn sync(&self, backend: &mut dyn SegmentBackend) -> io::Result<()>;
}

/// The production syncer: the segment's own data sync.
pub struct DataSync;

impl Syncer for DataSync {
    fn sync(&self, backend: &mut dyn SegmentBackend) -> io::Result<()> {
        backend.sync()
    }
}

/// A segment whose syncs go through the [`Syncer`].
struct Synced {
    inner: Box<dyn SegmentBackend>,
    syncer: Arc<dyn Syncer>,
}

impl SegmentBackend for Synced {
    fn write_all_at(&mut self, offset: u64, bytes: &[u8]) -> io::Result<()> {
        self.inner.write_all_at(offset, bytes)
    }
    fn sync(&mut self) -> io::Result<()> {
        self.syncer.sync(self.inner.as_mut())
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read_at(offset, buf)
    }
    fn len(&self) -> io::Result<u64> {
        self.inner.len()
    }
    fn set_len(&mut self, len: u64) -> io::Result<()> {
        self.inner.set_len(len)
    }
}

/// A spool (or the dead-letter log beside it): a directory of segments.
pub struct Spool {
    dir: DirectoryFactory,
    syncer: Arc<dyn Syncer>,
    segment: Segment,
    /// The lowest segment of the live generation.
    base: u64,
    next_seq: u64,
}

impl std::fmt::Debug for Spool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Spool")
            .field("base", &self.base)
            .field("segment", &self.segment.index())
            .finish_non_exhaustive()
    }
}

impl Spool {
    /// Open the spool in `dir` (created if absent) and read back every body it holds, in order. A
    /// torn tail is cut; damage a crash does not leave is quarantined beside its segment and
    /// alarmed.
    ///
    /// # Errors
    ///
    /// The directory or a segment could not be read or written.
    pub fn open(dir: &Path, syncer: Arc<dyn Syncer>) -> io::Result<(Spool, Vec<Vec<u8>>)> {
        let mut factory = DirectoryFactory::new(dir)?;
        let top = factory.highest_index()?.unwrap_or(0);
        let mut segment = Self::segment(&mut factory, &syncer, top)?;
        let recovered = recover::recover_and_truncate(&mut segment, &mut factory, wall_ms)?;
        for q in &recovered.quarantined {
            tracing::error!(segment = q.segment, offset = q.offset, bytes = q.bytes,
                "money spool: acknowledged records failed their checks and were set aside beside the segment");
        }
        // Down from the top to the generation's BASE (or the first gap).
        let mut generations = vec![recovered.records];
        let mut base = top;
        while !generations.last().is_some_and(|r| opens_base(r)) && base > 0 {
            let Some(backend) = factory.existing(base - 1)? else {
                break;
            };
            base -= 1;
            let lower = Segment::open_at(backend, base, 0, SEGMENT_BYTES)?;
            generations.push(recover::scan(&lower)?.records);
        }
        // A compaction that crashed after its new generation was durable left the old one behind.
        remove_below(&factory, base)?;
        let mut seen = std::collections::HashSet::new();
        let mut next_seq = 0;
        let mut bodies = Vec::new();
        for r in generations.into_iter().rev().flatten() {
            next_seq = next_seq.max(r.node_seq + 1);
            if r.node == DATA && seen.insert(r.node_seq) {
                bodies.push(r.body);
            }
        }
        let spool = Spool {
            dir: factory,
            syncer,
            segment,
            base,
            next_seq,
        };
        Ok((spool, bodies))
    }

    fn segment(
        factory: &mut DirectoryFactory,
        syncer: &Arc<dyn Syncer>,
        index: u64,
    ) -> io::Result<Segment> {
        let inner = factory.open(index)?;
        let synced = Box::new(Synced {
            inner,
            syncer: Arc::clone(syncer),
        });
        Segment::open_at(synced, index, 0, SEGMENT_BYTES)
    }

    /// The bytes the live generation holds.
    #[must_use]
    pub fn bytes(&self) -> u64 {
        (self.base..self.segment.index())
            .filter_map(|i| std::fs::metadata(self.dir.segment_path(i)).ok())
            .map(|m| m.len())
            .sum::<u64>()
            + self.segment.write_offset()
    }

    /// ONE ROUND: `bodies` in one write and one sync. A failed write or sync is never appended
    /// after: the round is written again into the next segment. `Err` only when that fails too: the
    /// spool is then [`Spool::failed`], and the caller keeps the round in RAM.
    ///
    /// # Errors
    ///
    /// Neither the segment nor a fresh one would take the round durably.
    pub fn append(&mut self, bodies: &[Vec<u8>]) -> io::Result<()> {
        if bodies.is_empty() {
            return Ok(());
        }
        let records = self.records(DATA, bodies);
        self.commit(&records)
    }

    fn records(&mut self, first: u64, bodies: &[Vec<u8>]) -> Vec<Record> {
        let mut out = Vec::with_capacity(bodies.len() + 1);
        if first == BASE {
            out.push(Record::new(BASE, self.next_seq, Vec::new()));
            self.next_seq += 1;
        }
        for b in bodies {
            out.push(Record::new(DATA, self.next_seq, b.clone()));
            self.next_seq += 1;
        }
        out
    }

    fn commit(&mut self, records: &[Record]) -> io::Result<()> {
        if self.segment.is_poisoned() {
            self.reopen()?;
        }
        match self.segment.append_batch(records) {
            Ok(_) => Ok(()),
            Err(SegmentError::Full) if self.segment.write_offset() > 0 => {
                self.reopen()?;
                self.commit(records)
            }
            Err(e) => {
                tracing::error!(error = %e, segment = self.segment.index(),
                    "money spool: a round failed to sync; writing it again into a new segment");
                self.reopen()?;
                self.segment
                    .append_batch(records)
                    .map(|_| ())
                    .map_err(|e| io::Error::other(e.to_string()))
            }
        }
    }

    /// Whether the segment was poisoned by a failed round and no new segment has taken over.
    #[must_use]
    pub fn failed(&self) -> bool {
        self.segment.is_poisoned()
    }

    /// Move to a fresh segment.
    ///
    /// # Errors
    ///
    /// The fresh segment could not be created durably.
    pub fn reopen(&mut self) -> io::Result<()> {
        let next = self.segment.index() + 1;
        self.segment = Self::segment(&mut self.dir, &self.syncer, next)?;
        Ok(())
    }

    /// COMPACTION: `live` written into a new segment that opens with a BASE record, synced, and only
    /// then the generation below it removed.
    ///
    /// # Errors
    ///
    /// The new segment could not be written durably; the old generation stands.
    pub fn compact(&mut self, live: &[Vec<u8>]) -> io::Result<()> {
        let next = self.segment.index() + 1;
        let mut segment = Self::segment(&mut self.dir, &self.syncer, next)?;
        let records = self.records(BASE, live);
        segment
            .append_batch(&records)
            .map_err(|e| io::Error::other(e.to_string()))?;
        self.segment = segment;
        self.base = next;
        remove_below(&self.dir, next)
    }

    /// Discard every segment (an ephemeral store restarts at zero).
    ///
    /// # Errors
    ///
    /// The directory could not be cleared.
    pub fn discard(dir: &Path) -> io::Result<()> {
        match std::fs::remove_dir_all(dir) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        }
    }
}

fn opens_base(records: &[Record]) -> bool {
    records.first().is_some_and(|r| r.node == BASE)
}

/// Remove every segment below `base`, down to the first gap, then sync the directory.
fn remove_below(factory: &DirectoryFactory, base: u64) -> io::Result<()> {
    let mut removed = false;
    for i in (0..base).rev() {
        match std::fs::remove_file(factory.segment_path(i)) {
            Ok(()) => removed = true,
            Err(e) if e.kind() == io::ErrorKind::NotFound => break,
            Err(e) => return Err(e),
        }
    }
    match factory.segment_path(base).parent() {
        Some(dir) if removed => std::fs::File::open(dir)?.sync_all(),
        _ => Ok(()),
    }
}

fn wall_ms() -> u64 {
    crate::store::now_ms()
}

#[cfg(test)]
#[path = "tests/spool_tests.rs"]
mod tests;
