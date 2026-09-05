// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The log itself: the thing a unit waits on before it dials, and again before it ends.
//!
//! ## Two modes, and the difference is not a detail
//!
//! **Memory-buffered** is the default, and it is what a deployment that names no data directory
//! gets. There is no file, no directory probe, no preallocation and no boot warning — a node in this
//! mode leaves a disk exactly as it found it. Durability is the store's: a batch is committed to the
//! local buffer and shipped synchronously, and a shipping failure is a durability failure, because
//! the store is the only thing under this node that survives it.
//!
//! **On-disk** is what a deployment that writes a data directory gets. Segments are real files,
//! group commits are a positional write and a data sync, and a sync that fails poisons its segment.
//!
//! Everything below is written so that the mode is a value, not a set of conditionals scattered
//! through the append path. There is one `append_batch`; what differs is which factory built the
//! segments and whether the shipper's answer is allowed to fail the commit.
//!
//! ## Idempotence, on the identity a writer owns
//!
//! A batch is idempotent on `(node, node_seq)`. That pair is the writer's own name for the record,
//! so a batch that is re-offered — after a poisoned segment, after a restart that replayed a tail,
//! after a peer shipped the same run twice — appends what is new and silently passes over what is
//! already there. It does not error, because a re-offer is the normal consequence of the poison rule
//! rather than a caller's mistake.
//!
//! The check that enforces this is a BOUND, not a ledger. A writer numbers its own records upward,
//! so what the log has to remember per writer is the highest number it has taken — one mark per
//! node, whatever the run's length. The only thing a mark on its own gets wrong is a number below it
//! that was never actually written, so the log also keeps a bounded window of exactly those holes.
//! When a hole falls out of the window it reads as present, which passes over a record rather than
//! writing one twice: the safe direction for a check whose whole job is to suppress duplicates.
//!
//! ## What happens when a sync fails
//!
//! The segment is poisoned and the caller is handed a `DurabilityLost`. The failed batch is retained
//! whole. The next append rolls to a fresh segment and writes the retained batch first, then the new
//! one — batches *n* and *n+1*, in order, on a segment that has not lost anything. If the fresh
//! segment fails too, the node has a disk that cannot be written to, and the log says so on every
//! subsequent call rather than accumulating silently.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io;

use busbar_caps::{DurabilityLost, DurabilityToken, StepName};

use crate::backend::{DirectoryFactory, MemoryFactory, SegmentFactory};
use crate::record::Record;
use crate::recover::{recover_and_truncate, Recovered};
use crate::segment::{Segment, SegmentError, SEGMENT_BYTES};
use crate::ship::{NullShipper, ShipError, Shipper};

/// How many skipped numbers the idempotence check remembers below a node's mark.
///
/// A writer that numbers upward without gaps never uses one of these. The window exists so that a
/// writer that does skip — a batch a bound dropped, a run stitched from two sources — is still
/// answered exactly for as long as the skipped number could plausibly be offered again, and is
/// answered conservatively rather than expensively after that.
const RECENT_HOLES: usize = 8192;

/// Where a log keeps its bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// No data directory: nothing is written to any disk, and the store is where durability lives.
    MemoryBuffered,
    /// A data directory: segments are files, and a group commit is a write plus a data sync.
    OnDisk,
}

/// What one committed batch did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchAck {
    /// How many records of the batch were new and were written.
    pub appended: usize,
    /// How many were already in the log under the same `(node, node_seq)` and were passed over.
    pub already_present: usize,
    /// Which segment they landed in.
    pub segment: u64,
    /// Where the log ends now, inside that segment.
    pub durable_end: u64,
    /// Whether this commit also re-wrote a batch that a poisoned segment had lost.
    pub replayed_lost_batch: bool,
}

/// Why a log could not be opened.
#[derive(Debug)]
pub enum OpenError {
    /// The backing could not be opened or read.
    Io(io::Error),
}

impl std::fmt::Display for OpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OpenError::Io(e) => write!(f, "the log could not be opened: {e}"),
        }
    }
}

impl std::error::Error for OpenError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            OpenError::Io(e) => Some(e),
        }
    }
}

impl From<io::Error> for OpenError {
    fn from(e: io::Error) -> Self {
        OpenError::Io(e)
    }
}

/// The write-ahead log.
pub struct Wal {
    factory: Box<dyn SegmentFactory>,
    shipper: Box<dyn Shipper>,
    mode: Mode,
    segment: Segment,
    ceiling: u64,
    /// The highest `node_seq` the log has taken from each node. The idempotence mark.
    high_water: HashMap<u64, u64>,
    /// Numbers below a node's mark that were never written, most recent first out of the window.
    gaps: HashSet<(u64, u64)>,
    /// The order the gaps were noticed in, so the oldest is the one the window drops.
    gap_order: VecDeque<(u64, u64)>,
    /// The batch a poisoned segment lost, kept whole so it can be written again.
    lost_batch: Vec<Record>,
    /// Records recovered from the tail at open time, in order.
    recovered: Vec<Record>,
    /// How many segments have been rolled through, poison included.
    segments_used: u64,
}

impl std::fmt::Debug for Wal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Wal")
            .field("mode", &self.mode)
            .field("segment", &self.segment)
            .field("tracked_identities", &self.tracked_identities())
            .field("lost_batch", &self.lost_batch.len())
            .finish()
    }
}

impl Wal {
    /// The default log: memory-buffered, shipping nowhere, touching no disk.
    ///
    /// A node built this way cannot create a file even by mistake, because the only thing that
    /// knows how to open one is the directory factory and this log does not hold one.
    pub fn memory_buffered() -> Self {
        Wal::with_parts(
            Box::new(MemoryFactory::new()),
            Box::new(NullShipper::new()),
            Mode::MemoryBuffered,
            SEGMENT_BYTES,
        )
        .expect("a memory segment cannot fail to open")
    }

    /// A memory-buffered log shipping to `shipper`. This is the shape a deployment that names a
    /// store but no data directory runs: the buffer stages, the store keeps.
    pub fn memory_buffered_to(shipper: Box<dyn Shipper>) -> Self {
        Wal::with_parts(
            Box::new(MemoryFactory::new()),
            shipper,
            Mode::MemoryBuffered,
            SEGMENT_BYTES,
        )
        .expect("a memory segment cannot fail to open")
    }

    /// A log whose segments are files under `dir`, recovering whatever is already there.
    ///
    /// Constructing this IS the decision to write to a disk. Nothing here probes for a directory or
    /// guesses at one: a caller that has no data directory configured calls
    /// [`Wal::memory_buffered`] and never reaches this function.
    pub fn in_directory(
        dir: impl AsRef<std::path::Path>,
        shipper: Box<dyn Shipper>,
    ) -> Result<Self, OpenError> {
        let factory = DirectoryFactory::new(dir.as_ref())?;
        Wal::with_parts(Box::new(factory), shipper, Mode::OnDisk, SEGMENT_BYTES)
    }

    /// Build a log over any factory and shipper. The seam the batteries drive: a factory that fails
    /// its sync on demand is how the poison rule is checked.
    pub fn with_parts(
        mut factory: Box<dyn SegmentFactory>,
        shipper: Box<dyn Shipper>,
        mode: Mode,
        ceiling: u64,
    ) -> Result<Self, OpenError> {
        let backend = factory.open(0)?;
        let mut segment = Segment::open_at(backend, 0, 0, ceiling)?;
        // The scan decides where the writes really end, and the cut makes the backing agree with
        // that. Appending then resumes at the boundary rather than at whatever length the crash
        // happened to leave behind.
        let recovered = recover_and_truncate(&mut segment)?;
        segment.truncate_to(recovered.durable_end)?;
        let mut wal = Wal {
            factory,
            shipper,
            mode,
            segment,
            ceiling,
            high_water: HashMap::new(),
            gaps: HashSet::new(),
            gap_order: VecDeque::new(),
            lost_batch: Vec::new(),
            recovered: Vec::new(),
            segments_used: 1,
        };
        for record in &recovered.records {
            wal.mark_written(record.node, record.node_seq);
        }
        wal.recovered = recovered.records;
        Ok(wal)
    }

    /// Which mode this log is in.
    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// The records that were on the tail when the log was opened, in order.
    pub fn recovered(&self) -> &[Record] {
        &self.recovered
    }

    /// Whether the current segment has lost a durable write.
    pub fn is_poisoned(&self) -> bool {
        self.segment.is_poisoned()
    }

    /// The batch a poisoned segment lost and the log still owes, if any.
    pub fn owed(&self) -> &[Record] {
        &self.lost_batch
    }

    /// Give up on the `count` oldest records the log still owes, and hand them back.
    ///
    /// The log does not decide to do this on its own, and there is no bound in here that could make
    /// it. What it owes is bounded by whoever is writing to it — the journal, which holds the buffer
    /// bound and seals a break naming exactly what this call returned. Putting the drop here and the
    /// decision there is the point: a log that could quietly forget a durable write would be a log
    /// whose poison rule means nothing.
    ///
    /// Oldest first, because what is nearest the head is what a reader is most likely to need.
    pub fn forget_owed(&mut self, count: usize) -> Vec<Record> {
        let count = usize::min(count, self.lost_batch.len());
        self.lost_batch.drain(0..count).collect()
    }

    /// How many segments have been used, poisoned ones included.
    pub fn segments_used(&self) -> u64 {
        self.segments_used
    }

    /// Whether `(node, node_seq)` is already in the log.
    ///
    /// At or below that node's mark and not a remembered hole. A hole the window has dropped answers
    /// yes, which passes over a record rather than writing it twice.
    pub fn holds(&self, node: u64, node_seq: u64) -> bool {
        match self.high_water.get(&node) {
            Some(&mark) => node_seq <= mark && !self.gaps.contains(&(node, node_seq)),
            None => false,
        }
    }

    /// Record that `(node, node_seq)` is now in the log: move that node's mark, and remember any
    /// numbers the move skipped over as holes.
    fn mark_written(&mut self, node: u64, node_seq: u64) {
        match self.high_water.get(&node).copied() {
            Some(mark) if node_seq <= mark => {
                // A number that was a hole has now been filled.
                self.gaps.remove(&(node, node_seq));
                return;
            }
            mark => {
                // Everything strictly between the old mark and this number was never written, and
                // the mark alone would call it present. Remember the most recent of them; the
                // window is what keeps this a bound rather than a set that grows with a gappy
                // writer.
                let floor = node_seq.saturating_sub(RECENT_HOLES as u64);
                let from = mark.map_or(floor, |m| u64::max(m + 1, floor));
                for hole in from..node_seq {
                    if self.gaps.insert((node, hole)) {
                        self.gap_order.push_back((node, hole));
                    }
                }
                self.high_water.insert(node, node_seq);
            }
        }
        while self.gap_order.len() > RECENT_HOLES {
            if let Some(oldest) = self.gap_order.pop_front() {
                self.gaps.remove(&oldest);
            }
        }
    }

    /// How many identities the idempotence check is holding in memory right now.
    ///
    /// The bound, made observable: this is what a test measures to prove the check costs a mark per
    /// writer rather than an entry per record.
    pub fn tracked_identities(&self) -> usize {
        self.high_water.len() + self.gaps.len()
    }

    /// The shipper, so a caller can look at what was handed over.
    pub fn shipper(&self) -> &dyn Shipper {
        self.shipper.as_ref()
    }

    /// Commit one batch: one write, one sync, and — in memory-buffered mode — one synchronous ship.
    ///
    /// Records already in the log under the same `(node, node_seq)` are passed over rather than
    /// written twice. If the previous commit was lost to a poisoned segment, that batch is written
    /// first, on a fresh segment, and this one follows it.
    pub fn append_batch(
        &mut self,
        token: &DurabilityToken,
        at: StepName,
        records: &[Record],
    ) -> Result<BatchAck, DurabilityLost> {
        let replaying = !self.lost_batch.is_empty();
        // A poisoned segment is left behind before anything else happens. If a fresh one cannot be
        // opened either, the node has a disk it cannot write to and the caller is told so.
        if self.segment.is_poisoned() && self.roll().is_err() {
            return Err(DurabilityLost::observed(token, at));
        }

        // Batch n first, then batch n+1, so the order records went in is the order they come back.
        let owed = std::mem::take(&mut self.lost_batch);
        let mut batch: Vec<Record> = Vec::with_capacity(owed.len() + records.len());
        let mut already_present = 0usize;
        let mut staged: HashSet<(u64, u64)> = HashSet::new();
        for record in owed.iter().chain(records.iter()) {
            let id = record.identity();
            if self.holds(id.0, id.1) || !staged.insert(id) {
                already_present += 1;
                continue;
            }
            batch.push(record.clone());
        }

        if batch.is_empty() {
            return Ok(BatchAck {
                appended: 0,
                already_present,
                segment: self.segment.index(),
                durable_end: self.segment.write_offset(),
                replayed_lost_batch: replaying,
            });
        }

        match self.segment.append_batch(&batch) {
            Ok(end) => {
                if self.mode == Mode::MemoryBuffered {
                    // The store is where durability lives here, so its answer is part of the
                    // commit. A refusal is a lost durable write, and it is reported as one.
                    if let Err(_e) = self.shipper.ship(&batch) {
                        self.lost_batch = owed.into_iter().chain(records.iter().cloned()).collect();
                        return Err(DurabilityLost::observed(token, at));
                    }
                }
                for record in &batch {
                    self.mark_written(record.node, record.node_seq);
                }
                if self.mode == Mode::OnDisk {
                    // On disk the local log is the record; shipping is catch-up work and its
                    // failure does not fail the commit. The batch stays owed to the shipper.
                    let _: Result<(), ShipError> = self.shipper.ship(&batch);
                }
                Ok(BatchAck {
                    appended: batch.len(),
                    already_present,
                    segment: self.segment.index(),
                    durable_end: end,
                    replayed_lost_batch: replaying,
                })
            }
            Err(SegmentError::Full) => {
                // Not a failure: the segment reached its ceiling. Roll and write the same batch.
                // A batch that does not fit in a WHOLE empty segment is a caller error the log
                // cannot fix by rolling again, so it is reported as a loss rather than looped on.
                self.lost_batch = owed.into_iter().chain(records.iter().cloned()).collect();
                if self.segment.write_offset() == 0 || self.roll().is_err() {
                    return Err(DurabilityLost::observed(token, at));
                }
                let carried = std::mem::take(&mut self.lost_batch);
                self.append_batch(token, at, &carried)
            }
            Err(_poisoned_or_io) => {
                // The write or the sync failed. Everything after the last good commit in this
                // segment is of unknown state, so the whole batch is owed again, on a fresh segment.
                self.lost_batch = owed.into_iter().chain(records.iter().cloned()).collect();
                Err(DurabilityLost::observed(token, at))
            }
        }
    }

    /// Read every record the log holds in its current segment, verifying as it goes.
    pub fn read_back(&self) -> io::Result<Recovered> {
        crate::recover::scan(&self.segment)
    }

    /// Move to the next segment. Called when the current one is poisoned or full.
    fn roll(&mut self) -> io::Result<()> {
        let next = self.segment.index() + 1;
        let backend = self.factory.open(next)?;
        let mut segment = Segment::open_at(backend, next, 0, self.ceiling)?;
        let recovered = recover_and_truncate(&mut segment)?;
        segment.truncate_to(recovered.durable_end)?;
        self.segment = segment;
        self.segments_used += 1;
        Ok(())
    }
}
