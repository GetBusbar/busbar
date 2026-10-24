// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The log itself: the thing a unit waits on before it dials, and again before it ends.
//!
//! ## Two modes, and the difference is not a detail
//!
//! **Memory-buffered** is the default, and it is what a deployment that names no data directory
//! gets. There is no file, no directory probe, no preallocation and no boot warning — a node in this
//! mode leaves a disk exactly as it found it, and the log does not survive the process. A batch is
//! committed to the local buffer and handed synchronously to the bound shipper, and a refusal fails
//! the commit. Over a configured store the composition root binds a shipper that hands each batch to
//! the store's records and refuses when its own bounded queue is full; what survives a restart is
//! the chain the store kept, which the log is seeded with ([`Wal::memory_seeded`]). With no store
//! behind the shipper the chain lives as long as the process.
//!
//! **On-disk** is what a deployment that writes a data directory gets. Segments are real files,
//! group commits are a positional write and a data sync, and a sync that fails poisons its segment.
//! A store that refuses a batch here does not fail the commit — the bytes are on the medium — but
//! the batch stays owed to the store and is offered again on the next commit, in order, without
//! being written to the medium a second time. Past [`STORE_BACKLOG_RECORDS`] what is owed is read
//! back from the segments rather than held in memory; it is never given up on, a restart included:
//! a log that opens over records owes the store the whole of it once, because nothing durable says
//! which records the store took before the restart, and the store's put is idempotent.
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
//! The segment is poisoned, the failed batch's bytes are cut off it, the next segment is opened, and
//! the caller is handed a `DurabilityLost`. The failed batch is retained whole. The next append moves
//! to the fresh segment and writes the retained batch first, then the new one — batches *n* and
//! *n+1*, in order, on a segment that has not lost anything. If the fresh segment cannot be opened, or fails too, the node has a
//! disk that cannot be written to: the batch is retained with the one that could not follow it, and
//! the log says so on every subsequent call rather than accumulating silently or dropping either.
//!
//! ## A segment that lost a sync is never written to again, across a restart too
//!
//! Poison is a flag in the process that saw the sync fail, and the flag dies with it. So the log
//! does not leave the poisoned segment on the next append, it opens the next segment AT ONCE, before
//! the loss is reported — and the next segment's directory entry, made durable when it is created,
//! is the durable record that the poisoned one is finished. A restart appends to the newest segment
//! and never to one below it, even when the newest holds nothing yet and the tail of the log is read
//! from the one before; so the segment that lost a sync is not resumed into. The failed batch's
//! bytes were cut off it before the loss was reported, so the restart does not read them back
//! either.
//!
//! What that cannot cover is a medium that refuses everything at once: if the cut fails as well as
//! the sync, the failed batch's bytes may still be readable at a restart until the retried batch is
//! durable in the next segment; and if the next segment cannot be created either, a restart resumes
//! in the segment that lost the sync. A disk that will make nothing durable cannot be made to
//! record that it lost something; every call on it reports the loss.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io;

use busbar_contract::caps::{DurabilityLost, DurableWrite, Grant, StepName};

use crate::backend::{DirectoryFactory, MemoryFactory, SegmentFactory};
use crate::record::{Record, FRAME_BYTES};
use crate::recover::{recover_and_truncate, Quarantine, Recovered};
use crate::segment::{Segment, SegmentError, SEGMENT_BYTES};
use crate::ship::{NullShipper, ShipError, Shipper};

/// How many skipped numbers the idempotence check remembers below a node's mark.
///
/// A writer that numbers upward without gaps never uses one of these. The window exists so that a
/// writer that does skip — a batch a bound dropped, a run stitched from two sources — is still
/// answered exactly for as long as the skipped number could plausibly be offered again, and is
/// answered conservatively rather than expensively after that.
const RECENT_HOLES: usize = 8192;

/// How many records an on-disk log will hold for a store that has not taken them yet.
///
/// Pinned rather than configurable, exactly like the memory-buffered buffer's own bound: an operator
/// who could raise it could turn a store outage into an out-of-memory kill. Past it the records
/// still owed are not held in memory: the log remembers where on its medium they start and reads
/// them back from the segments, oldest first, once the store takes what the queue holds. The bound
/// costs memory, never the store's copy of a record.
pub const STORE_BACKLOG_RECORDS: usize = 8192;

/// Where a log keeps its bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// No data directory: nothing is written to any disk. The bound shipper's answer is part of the
    /// commit; over a configured store that is where the chain is kept.
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

/// THE WALL CLOCK a log is handed, in unix milliseconds. The composition root owns the clock and
/// passes it down; the log calls it only to stamp a corrupt remainder it sets aside, so this crate
/// reads no clock of its own and a test can hand it a reproducible one.
pub type Clock = fn() -> u64;

/// The write-ahead log.
pub struct Wal {
    factory: Box<dyn SegmentFactory>,
    clock: Clock,
    shipper: Box<dyn Shipper<Record>>,
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
    /// Records the store has not acknowledged, oldest first. On disk only: a refusal there does not
    /// fail the commit, so this is the only thing that remembers the store is still owed them.
    owed_to_store: Vec<Record>,
    /// How many records, in total, the store's catch-up queue has left on the medium at its bound.
    /// None is dropped: each is read back from there (see `store_owed_from`).
    store_debt_on_medium: u64,
    /// Where on the medium the store's debt continues past the queue: the segment and the byte the
    /// first record the queue did not take starts at. Every record from there to the end of the log
    /// is owed to the store, after the queue's own.
    store_owed_from: Option<(u64, u64)>,
    /// Records recovered from the tail at open time, in order.
    recovered: Vec<Record>,
    /// How many segments have been rolled through, poison included.
    segments_used: u64,
    /// Every corrupt remainder recovery set aside, at open and at any roll since, oldest first.
    quarantined: Vec<Quarantine>,
    /// The segment after a poisoned one, opened the moment the poison happened so that its
    /// directory entry records, durably, that the poisoned one is finished. The next append moves
    /// to it.
    next_segment: Option<Segment>,
}

impl std::fmt::Debug for Wal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Wal")
            .field("mode", &self.mode)
            .field("segment", &self.segment)
            .field("tracked_identities", &self.tracked_identities())
            .field("lost_batch", &self.lost_batch.len())
            .field("owed_to_store", &self.owed_to_store.len())
            .finish()
    }
}

impl Wal {
    /// A memory-buffered log shipping to `shipper`: the default, and the shape a deployment that
    /// names no data directory runs. The buffer stages, and the shipper decides what, if anything,
    /// is kept; a node over a configured store resumes through [`Wal::memory_seeded`] instead.
    ///
    /// A node built this way cannot create a file even by mistake, because the only thing that
    /// knows how to open one is the directory factory and this log does not hold one.
    pub fn memory_buffered_to(shipper: Box<dyn Shipper<Record>>, clock: Clock) -> Self {
        Wal::with_parts(
            Box::new(MemoryFactory::new()),
            shipper,
            Mode::MemoryBuffered,
            SEGMENT_BYTES,
            clock,
        )
        .expect("a memory segment cannot fail to open")
    }

    /// A memory-buffered log that already HOLDS `records`: the chain the configured store kept for a
    /// node with no data directory, read back at boot. They are written into the buffer in order and
    /// marked taken, and they are NOT shipped again — the store they were read from already has them.
    /// What the log takes from here on ships through `shipper`.
    ///
    /// This is what lets a node with no disk resume its own chain rather than start a new one: the
    /// records [`Wal::read_back`] returns are the ones the store kept, and the next number a writer can
    /// take ([`Wal::next_free_seq`]) is past them. A memory segment rolled past is released as on any
    /// memory log, so a chain longer than one segment keeps its newest segment resident and its
    /// history in the store.
    ///
    /// # Errors
    ///
    /// The records do not fit even an empty segment one batch at a time.
    pub fn memory_seeded(
        records: &[Record],
        shipper: Box<dyn Shipper<Record>>,
        clock: Clock,
    ) -> Result<Self, OpenError> {
        let mut wal = Wal::with_parts(
            Box::new(MemoryFactory::new()),
            Box::new(NullShipper::new()),
            Mode::MemoryBuffered,
            SEGMENT_BYTES,
            clock,
        )?;
        wal.seed(records)?;
        wal.shipper = shipper;
        Ok(wal)
    }

    /// Write `records` into the buffer, rolling at a full segment, and mark each one taken. Nothing
    /// is shipped: the caller read them from where they are kept.
    fn seed(&mut self, records: &[Record]) -> io::Result<()> {
        /// How many records one seeding write carries.
        const SEED_BATCH: usize = 256;
        for chunk in records.chunks(SEED_BATCH) {
            loop {
                match self.segment.append_batch(chunk) {
                    Ok(_) => break,
                    Err(SegmentError::Full) if self.segment.write_offset() > 0 => self.roll()?,
                    Err(e) => return Err(io::Error::other(e.to_string())),
                }
            }
            for record in chunk {
                self.mark_written(record.node, record.node_seq);
            }
        }
        Ok(())
    }

    /// A log whose segments are files under `dir`, recovering whatever is already there.
    ///
    /// Constructing this IS the decision to write to a disk. Nothing here probes for a directory or
    /// guesses at one: a caller that has no data directory configured calls
    /// [`Wal::memory_buffered_to`] and never reaches this function.
    pub fn in_directory(
        dir: impl AsRef<std::path::Path>,
        shipper: Box<dyn Shipper<Record>>,
        clock: Clock,
    ) -> Result<Self, OpenError> {
        let factory = DirectoryFactory::new(dir.as_ref())?;
        Wal::with_parts(
            Box::new(factory),
            shipper,
            Mode::OnDisk,
            SEGMENT_BYTES,
            clock,
        )
    }

    /// Build a log over any factory and shipper. The seam the batteries drive: a factory that fails
    /// its sync on demand is how the poison rule is checked.
    ///
    /// Opening is also RECOVERING: the factory is asked which segment the writes reached, that
    /// segment's tail is scanned, and the idempotence marks are seeded from it. See [`open_tail`]
    /// for which segment that is and what the seeding does and does not cover.
    pub fn with_parts(
        mut factory: Box<dyn SegmentFactory>,
        shipper: Box<dyn Shipper<Record>>,
        mode: Mode,
        ceiling: u64,
        clock: Clock,
    ) -> Result<Self, OpenError> {
        let (segment, recovered, quarantined, tail_index) =
            open_tail(factory.as_mut(), ceiling, clock)?;
        let quarantined = quarantine_below(
            factory.as_mut(),
            ceiling,
            clock,
            tail_index,
            &recovered,
            quarantined,
        )?;
        let segments_used = segment.index() + 1;
        // ON A DISK, WHAT THE STORE IS OWED IS ON THE MEDIUM, AND A RESTART MUST NOT FORGET IT. The
        // queue and its mark live in this process; a store that was down when it ended is owed
        // every record it had not taken, and nothing durable says which those were. So a log that
        // opens over records owes the store the whole of it, oldest segment first, read back off
        // the medium at the queue's bound like any other debt past it. The store's write is an
        // idempotent put keyed on the record's identity, so a record it already holds is
        // overwritten with the same bytes: a re-offer costs a write, never a record. (THE DESIGN,
        // BUSBAR-1.6.0.md section 7: the journal is the record, the store holds its copy.)
        let owes_store_on_open =
            mode == Mode::OnDisk && (!recovered.records.is_empty() || tail_index > 0);
        let mut wal = Wal {
            factory,
            clock,
            shipper,
            mode,
            segment,
            ceiling,
            high_water: HashMap::new(),
            gaps: HashSet::new(),
            gap_order: VecDeque::new(),
            lost_batch: Vec::new(),
            owed_to_store: Vec::new(),
            store_debt_on_medium: 0,
            store_owed_from: owes_store_on_open.then_some((0, 0)),
            recovered: Vec::new(),
            segments_used,
            quarantined: Vec::new(),
            next_segment: None,
        };
        for record in &recovered.records {
            wal.mark_written(record.node, record.node_seq);
        }
        wal.recovered = recovered.records;
        for q in quarantined {
            wal.take_quarantine(q);
        }
        if owes_store_on_open {
            // Offered at open, not on the first commit: reading the log back is boot work, beside
            // the two reads of it the boot already makes, and never a cost on a request's path. A
            // shipper that turns the run away leaves the rest owed from where it stopped.
            let at = (wal.segment.index(), wal.segment.write_offset());
            wal.offer_store_debt(&[], at);
        }
        Ok(wal)
    }

    /// Every corrupt remainder recovery set aside — at open, and at any roll since — oldest first.
    ///
    /// Empty is the only good answer. Each entry is acknowledged records that are no longer in the
    /// log: the caller raises the alarm (a log line, a counter, a durable record naming the file,
    /// the offset, the byte count and where the bytes went). A torn tail never appears here: it is
    /// a crash mid-append, and cutting it loses nothing that was acknowledged.
    pub fn quarantined(&self) -> &[Quarantine] {
        &self.quarantined
    }

    /// Hold on to a quarantine, and mark every identity in the set-aside bytes as taken.
    ///
    /// Those records were acknowledged, so a store may already hold them under the same
    /// `(node, node_seq)`. Handing one of those numbers out again would put a NEW record under an
    /// identity a deduplicating store passes over as a re-offer — a lost write reported as a
    /// success. Marking them costs a visible gap in the numbering and never a record.
    ///
    /// An UNVERIFIED identity ([`Quarantine::unverified`]) is read from a frame whose header does
    /// not check, so its number may be the damaged byte. Taken at its word, one altered frame could
    /// move the node's mark anywhere, up to the top of the range, where every number after it is
    /// one the log already holds and every record sealed under it is passed over behind an `Ok`. So
    /// an unverified number is taken only as far as the set-aside bytes could have numbered: no
    /// further past the node's verified mark than there are records in the remainder. That still
    /// covers the number the record was written under: a writer numbers without gaps, so its
    /// records in the remainder are numbered inside that run.
    fn take_quarantine(&mut self, quarantine: Quarantine) {
        for &(node, node_seq) in &quarantine.identities {
            if !quarantine.unverified.contains(&(node, node_seq)) {
                self.mark_written(node, node_seq);
            }
        }
        let reach = quarantine.identities.len() as u64;
        let ceilings: Vec<u64> = quarantine
            .unverified
            .iter()
            .map(|(node, _)| {
                self.high_water
                    .get(node)
                    .copied()
                    .unwrap_or(0)
                    .saturating_add(reach)
            })
            .collect();
        for (&(node, node_seq), ceiling) in quarantine.unverified.iter().zip(ceilings) {
            self.mark_written(node, u64::min(node_seq, ceiling));
        }
        self.quarantined.push(quarantine);
    }

    /// Which mode this log is in.
    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// The records that were on the tail when the log was opened, in order.
    ///
    /// The tail of the LAST segment that held any — which after a roll is not segment zero. This is
    /// the end of the log, so a caller that resumes a chain from it resumes from the newest record
    /// rather than from one somewhere in the middle. It is not the whole log: everything in the
    /// segments before it is still on the medium and is simply not what a resume needs.
    /// [`Wal::read_back`] is the read of the whole log.
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

    /// The records the store has not acknowledged and is still owed, oldest first.
    ///
    /// On disk this is catch-up work rather than a durability loss — the bytes are on the medium
    /// either way — so it is a separate queue from what a poisoned segment lost, and it is
    /// observable so that a node can say how far behind its store is instead of only whether it is.
    pub fn owed_to_store(&self) -> &[Record] {
        &self.owed_to_store
    }

    /// How many records, in total since open, the store's catch-up queue has left on the medium at
    /// its bound. None of them is dropped: the log reads them back from its segments and offers
    /// them, in order, once the store takes what the queue holds.
    pub fn store_debt_on_medium(&self) -> u64 {
        self.store_debt_on_medium
    }

    /// Whether the store is owed records the queue does not hold, to be read back off the medium:
    /// past the queue's bound, or everything a log opened over when it was opened. A restart
    /// cannot know which records a store took before it, so it owes the store the whole log once.
    pub fn owes_store_from_medium(&self) -> bool {
        self.store_owed_from.is_some()
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

    /// The lowest number `node` can still take without colliding with something the log already
    /// holds. One past that node's mark, or one on a node the log has never seen.
    ///
    /// A writer that numbered below this would not get an error: [`Wal::append_batch`] deduplicates
    /// on the identity alone, so a DIFFERENT record offered under a number the log already carries
    /// is passed over exactly as an honest re-offer is, and the ack says `appended: 0` either way.
    /// That is the right answer for a re-offer and the wrong one for a fresh record, and the log
    /// cannot tell them apart — so whoever allocates numbers has to ask where it is safe to start.
    pub fn next_free_seq(&self, node: u64) -> u64 {
        match self.high_water.get(&node) {
            Some(&mark) => mark.saturating_add(1),
            None => 1,
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
    pub fn shipper(&self) -> &dyn Shipper<Record> {
        self.shipper.as_ref()
    }

    /// Commit one batch: one write, one sync, and — in memory-buffered mode — one synchronous ship.
    ///
    /// Records already in the log under the same `(node, node_seq)` are passed over rather than
    /// written twice. If the previous commit was lost to a poisoned segment, that batch is written
    /// first, on a fresh segment, and this one follows it.
    pub fn append_batch(
        &mut self,
        token: &Grant<DurableWrite>,
        at: StepName,
        records: &[Record],
    ) -> Result<BatchAck, DurabilityLost> {
        let replaying = !self.lost_batch.is_empty();
        // A poisoned segment is left behind before anything else happens. If a fresh one cannot be
        // opened, the node has a disk it cannot write to and the caller is told so; the records are
        // retained exactly as on every other arm, because the journal has already chained them and
        // a record that is on no medium and in no retry queue is a hole in the chain nothing names.
        if self.segment.is_poisoned() {
            if let Err(_e) = self.roll() {
                self.lost_batch.extend(records.iter().cloned());
                return Err(DurabilityLost::observed(token, at));
            }
        }

        // Batch n first, then batch n+1, so the order records went in is the order they come back.
        let owed = std::mem::take(&mut self.lost_batch);
        // Two sets, and they are not the same set. `batch` is what the SEGMENT takes: records it
        // does not already hold. `offered` is what the STORE is owed: every distinct record on this
        // call, retained or new. They differ after a refusal, because the buffer already took a
        // record the store then declined — and writing that record again to make the ship happen is
        // how a run ends up in the log twice.
        let mut batch: Vec<Record> = Vec::with_capacity(owed.len() + records.len());
        let mut offered: Vec<Record> = Vec::with_capacity(owed.len() + records.len());
        let mut already_present = 0usize;
        let mut staged: HashSet<(u64, u64)> = HashSet::new();
        for record in owed.iter().chain(records.iter()) {
            let id = record.identity();
            if !staged.insert(id) {
                already_present += 1;
                continue;
            }
            offered.push(record.clone());
            if self.holds(id.0, id.1) {
                already_present += 1;
                continue;
            }
            batch.push(record.clone());
        }

        if batch.is_empty() {
            // Nothing new for the segment — but the store may still be owed what a refusal
            // retained, and leaving that debt until a commit that happens to carry a new record is
            // how it gets forgotten on a node that has gone quiet.
            if self.mode == Mode::MemoryBuffered && !offered.is_empty() {
                if let Err(_e) = self.shipper.ship(&offered) {
                    self.lost_batch = offered;
                    return Err(DurabilityLost::observed(token, at));
                }
            } else if self.mode == Mode::OnDisk {
                let at = (self.segment.index(), self.segment.write_offset());
                self.offer_store_debt(&[], at);
            }
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
                for record in &batch {
                    self.mark_written(record.node, record.node_seq);
                }
                if self.mode == Mode::MemoryBuffered {
                    // The store is where durability lives here, so its answer is part of the
                    // commit. A refusal is a lost durable write, and it is reported as one. What
                    // is retained is the shipping debt: the buffer already holds these records, so
                    // the retry ships them again and appends nothing.
                    if let Err(_e) = self.shipper.ship(&offered) {
                        self.lost_batch = offered;
                        return Err(DurabilityLost::observed(token, at));
                    }
                } else {
                    // On disk the local log is the record; shipping is catch-up work and its
                    // failure does not fail the commit. The batch stays owed to the store and is
                    // offered again — the seam's contract is that an error means the batch is
                    // still owed, and an answer that is discarded honours neither half of it.
                    let frames: u64 = batch.iter().map(|r| r.frame_count() as u64).sum();
                    let start = end - frames * FRAME_BYTES as u64;
                    self.offer_store_debt(&batch, (self.segment.index(), start));
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
                // segment is of unknown state — the segment has already cut it off — so the whole
                // batch is owed again, on a fresh segment.
                self.lost_batch = owed.into_iter().chain(records.iter().cloned()).collect();
                // The fresh segment is opened NOW, not on the next append: its directory entry is
                // what tells a restart, durably, not to resume in this one. If it cannot be opened,
                // the next append tries again and reports the loss again.
                if self.next_segment.is_none() {
                    self.next_segment = self.open_next().ok();
                }
                Err(DurabilityLost::observed(token, at))
            }
        }
    }

    /// Read every record the log holds, OLDEST SEGMENT FIRST, verifying as it goes.
    ///
    /// The whole log, not the segment being written: once the log has rolled, the records before
    /// the roll are history a reader of the chain needs — the card a posting priced at, the hold a
    /// predecessor opened, the audit chain's start. Every earlier segment the factory still has is
    /// scanned before the current one (a data directory keeps every one; a memory factory keeps only
    /// what is still resident, because a node with no disk keeps its history in its store).
    ///
    /// Each `(node, node_seq)` comes back once, the first time it was written. A batch a poisoned
    /// segment lost is written again, whole, on the next segment, and its bytes may have reached the
    /// poisoned one in full before the sync failed — the same record in two segments, which is one
    /// record.
    ///
    /// `records` is the whole log; every other field of the answer describes the CURRENT segment,
    /// which is the one appending resumes in.
    pub fn read_back(&self) -> io::Result<Recovered> {
        let mut seen: HashSet<(u64, u64)> = HashSet::new();
        let mut records = Vec::new();
        for index in 0..self.segment.index() {
            let Some(backend) = self.factory.existing(index)? else {
                continue;
            };
            let earlier = Segment::open_at(backend, index, 0, self.ceiling)?;
            let scanned = crate::recover::scan(&earlier)?.records;
            records.extend(scanned.into_iter().filter(|r| seen.insert(r.identity())));
        }
        let mut current = crate::recover::scan(&self.segment)?;
        let tail = std::mem::take(&mut current.records);
        records.extend(tail.into_iter().filter(|r| seen.insert(r.identity())));
        current.records = records;
        Ok(current)
    }

    /// Offer the store what it is owed: whatever a refusal retained, then `batch`, as one batch in
    /// the order the records were written. A refusal keeps the lot owed for the next commit.
    ///
    /// On disk only, and it never fails a commit: the bytes are on the medium either way. The queue
    /// in memory is bounded for the same reason the memory-buffered buffer is — a store that is
    /// unreachable for an hour must not be answered by exhausting the node's memory. Past the bound
    /// the records are not dropped: they are on the medium, so the log keeps only where they start
    /// (`batch_at`, the segment and byte `batch` was written at) and reads them back from there, in
    /// order, each time the store takes what the queue holds. A record the store was owed reaches
    /// it, whatever the outage's length.
    fn offer_store_debt(&mut self, batch: &[Record], batch_at: (u64, u64)) {
        // Already past the bound: this batch is on the medium after the mark, owed from there.
        let mut queued = 0;
        if self.store_owed_from.is_none() {
            let room = STORE_BACKLOG_RECORDS.saturating_sub(self.owed_to_store.len());
            queued = usize::min(room, batch.len());
            self.owed_to_store.extend_from_slice(&batch[..queued]);
            if queued < batch.len() {
                let frames: u64 = batch[..queued].iter().map(|r| r.frame_count() as u64).sum();
                self.store_owed_from = Some((batch_at.0, batch_at.1 + frames * FRAME_BYTES as u64));
            }
        }
        self.store_debt_on_medium = self
            .store_debt_on_medium
            .saturating_add((batch.len() - queued) as u64);
        loop {
            if self.owed_to_store.is_empty() && !self.refill_store_debt() {
                return;
            }
            let debt = std::mem::take(&mut self.owed_to_store);
            let shipped: Result<(), ShipError> = self.shipper.ship(&debt);
            if shipped.is_err() {
                self.owed_to_store = debt;
                return;
            }
            if self.store_owed_from.is_none() {
                return;
            }
        }
    }

    /// Read the next run of what the store is owed off the medium into the queue, from where the
    /// queue's bound left it, and move that mark on. `false` when there was nothing to read: the
    /// debt is all in the queue again, or the medium could not be read (the mark stays, so the
    /// next commit tries again).
    fn refill_store_debt(&mut self) -> bool {
        let Some((mut index, mut from)) = self.store_owed_from else {
            return false;
        };
        loop {
            let read = if index == self.segment.index() {
                crate::recover::records_from(&self.segment, from, STORE_BACKLOG_RECORDS)
            } else {
                match self.factory.existing(index) {
                    Ok(Some(backend)) => Segment::open_at(backend, index, 0, self.ceiling)
                        .and_then(|earlier| {
                            crate::recover::records_from(&earlier, from, STORE_BACKLOG_RECORDS)
                        }),
                    // A segment that is not there holds nothing more to read.
                    Ok(None) => Ok((Vec::new(), from)),
                    Err(e) => Err(e),
                }
            };
            let Ok((records, end)) = read else {
                self.store_owed_from = Some((index, from));
                return false;
            };
            if !records.is_empty() {
                self.owed_to_store = records;
                self.store_owed_from = Some((index, end));
                return true;
            }
            if index >= self.segment.index() {
                // Read to the end of the log: everything owed is in the queue or shipped.
                self.store_owed_from = None;
                return false;
            }
            index += 1;
            from = 0;
        }
    }

    /// Move to the next segment. Called when the current one is poisoned or full.
    fn roll(&mut self) -> io::Result<()> {
        let segment = match self.next_segment.take() {
            Some(opened) => opened,
            None => self.open_next()?,
        };
        self.segment = segment;
        self.segments_used += 1;
        Ok(())
    }

    /// Open the segment after the current one.
    fn open_next(&mut self) -> io::Result<Segment> {
        let next = self.segment.index() + 1;
        let backend = self.factory.open(next)?;
        let mut segment = Segment::open_at(backend, next, 0, self.ceiling)?;
        // A segment being rolled into is normally new and empty. If it is not, it is recovered on
        // the same terms as the one a boot resumes in: a torn tail is cut, a corrupt one is set
        // aside first.
        let recovered = recover_and_truncate(&mut segment, self.factory.as_mut(), self.clock)?;
        for q in recovered.quarantined {
            self.take_quarantine(q);
        }
        Ok(segment)
    }
}

/// Open the segment a restart appends to, and hand back the records on the log's tail.
///
/// ## Which segment the tail is in
///
/// The highest one the factory has a backing for — a directory listing on disk, the resident slots
/// in memory — and NOT index zero. A log that has rolled has its newest records in its newest
/// segment, so seeding from index zero would resume from the middle of the log: the head and the
/// sequence number would come from records that were superseded long ago, and every number the node
/// then took would be one a writer had already used. Two records under one identity is exactly what
/// a store that deduplicates on `(node, node_seq)` drops on the floor.
///
/// A roll opens the next segment before anything is written to it, so a crash in that window leaves
/// a real but empty highest segment. Resuming there would find no tail and reset the chain, so the
/// walk steps back over segments that hold no complete record until it finds the one the writes
/// actually end in, or reaches the first. In practice that is one step at most; it is a loop because
/// nothing forbids a run of them.
///
/// ## Which segment the appends go to
///
/// The highest one, ALWAYS — even when it holds nothing and the tail was read from below it. An empty
/// highest segment is one a roll opened: either the segment below it was full, or it lost a sync and
/// the log opened this one the moment it did. Either way the segment below takes no more writes,
/// and resuming in it would hand a restart the one segment a previous process knew was finished.
///
/// ## Why the seeding does not scan the earlier segments
///
/// Recovery is O(the last segment), and it is meant to stay that way: a node that has been up for a
/// year has a log measured in segments, and a restart that read all of them would turn a boot into a
/// full history replay for an answer that is already complete for every writer still writing.
///
/// The alternative that would also be O(the last segment) is a persisted mark — a side file naming
/// each node's highest number. It is not used, for the same reason the journal takes its head off
/// the log's tail rather than out of a file beside it: a mark written separately from the records it
/// describes can disagree with them after a crash between the two writes, and a disagreeing mark is
/// worse than no mark, because it is believed.
///
/// So the marks are seeded from the last segment's tail, and what that leaves is bounded and worth
/// saying plainly: a node that wrote records in an earlier segment and nothing at all in the last
/// one has no mark here, so a re-offer of one of ITS old records would be appended a second time
/// rather than passed over. It costs a duplicate in the log, never a fork in the chain — the head
/// and the next sequence number come off the newest record that exists, which is the thing this
/// function is for.
///
/// ## A corrupt segment on the way
///
/// The walk recovers each segment it steps through on the verdict's terms: a torn tail is cut;
/// acknowledged damage is copied into a quarantine and never cut — a hole is read past to the
/// records behind it, and a corrupt remainder closes the segment to writes — and every quarantine
/// met is handed back so the log can mark its identities taken and the caller can raise the alarm.
/// A segment that kept no complete record is stepped back over exactly as one a crash left empty.
/// The index returned is the segment the tail was read from; [`quarantine_below`] reads the ones
/// beneath it.
fn open_tail(
    factory: &mut dyn SegmentFactory,
    ceiling: u64,
    clock: Clock,
) -> Result<(Segment, Recovered, Vec<Quarantine>, u64), OpenError> {
    let mut index = factory.highest_index()?.unwrap_or(0);
    let mut quarantined = Vec::new();
    // The highest segment, held while the walk steps back below it for the tail: the appends go to
    // it, never to the segment the tail is found in.
    let mut newest: Option<Segment> = None;
    loop {
        let backend = factory.open(index)?;
        let mut segment = Segment::open_at(backend, index, 0, ceiling)?;
        // The scan decides where the writes really end, and the cut makes the backing agree with
        // that — on a torn tail silently, on a corrupt one only after the damaged remainder is
        // durable somewhere else. Appending then resumes at the boundary rather than at whatever
        // length the crash happened to leave behind.
        let mut recovered = recover_and_truncate(&mut segment, factory, clock)?;
        // The quarantines travel in the list, not twice.
        quarantined.append(&mut recovered.quarantined);
        if !recovered.records.is_empty() || index == 0 {
            return Ok((newest.unwrap_or(segment), recovered, quarantined, index));
        }
        if newest.is_none() {
            newest = Some(segment);
        }
        index -= 1;
    }
}

/// Scan every segment below the one the tail was read from, set aside what acknowledged damage
/// each holds, and name every quarantine's place in the log as a whole.
///
/// ## Why the segments below the tail are read at all
///
/// [`open_tail`] reads only the tail, and a segment below it is never written again — so damage in
/// one was never found by anything that could set it aside or say so. It surfaced only as a chain
/// that did not verify, and [`Wal::read_back`] read past nothing: the rest of that segment simply
/// dropped out. So each one is scanned here, its holes and a corrupt end copied into a quarantine
/// exactly as the tail's are, nothing in it cut (it is closed), and every quarantine handed to the
/// caller with the others. It costs one read of the log at open; the boot reads the whole log once
/// more when it replays the chain.
///
/// ## Where a quarantine sits in the log
///
/// A segment that kept a record: its index, the identity of its first record and of its last.
type KeptSegment = (u64, (u64, u64), (u64, u64));

/// A scan names the records on either side of a hole only inside its own segment. A hole at the
/// start of a segment follows the last record of the segment before; a remainder at the end of one
/// is followed by the first record of the next. Those are filled in here, from the records each
/// segment kept, so the chain can verify across the hole and nowhere else.
fn quarantine_below(
    factory: &mut dyn SegmentFactory,
    ceiling: u64,
    clock: Clock,
    tail_index: u64,
    tail: &Recovered,
    mut quarantined: Vec<Quarantine>,
) -> Result<Vec<Quarantine>, OpenError> {
    // Each segment that kept a record: its index, its first record and its last.
    let mut kept: Vec<KeptSegment> = Vec::new();
    for index in 0..tail_index {
        let Some(backend) = factory.existing(index)? else {
            continue;
        };
        let earlier = Segment::open_at(backend, index, 0, ceiling)?;
        let mut found = crate::recover::quarantine_in_place(&earlier, factory, clock)?;
        if let (Some(first), Some(last)) = (found.records.first(), found.records.last()) {
            kept.push((index, first.identity(), last.identity()));
        }
        quarantined.append(&mut found.quarantined);
    }
    if let (Some(first), Some(last)) = (tail.records.first(), tail.records.last()) {
        kept.push((tail_index, first.identity(), last.identity()));
    }
    quarantined.sort_by_key(|q| (q.segment, q.offset));
    for q in &mut quarantined {
        if q.before.is_none() {
            q.before = kept
                .iter()
                .rev()
                .find(|(index, _, _)| *index < q.segment)
                .map(|(_, _, last)| *last);
        }
        if q.after.is_none() {
            q.after = kept
                .iter()
                .find(|(index, _, _)| *index > q.segment)
                .map(|(_, first, _)| *first);
        }
    }
    Ok(quarantined)
}
