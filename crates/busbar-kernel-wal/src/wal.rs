// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The log itself: the thing a unit waits on before it dials, and again before it ends.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io;

use busbar_contract::caps::{DurabilityLost, DurableWrite, Grant, StepName};

use crate::backend::{DirectoryFactory, MemoryFactory, SegmentFactory};
use crate::record::{Record, FRAME_BYTES};
use crate::recover::{recover_and_truncate, Quarantine, Recovered};
use crate::segment::{Segment, SegmentError, SEGMENT_BYTES};
use crate::ship::{NullShipper, ShipError, Shipper};

/// How many skipped numbers the idempotence check remembers below a node's mark.

const RECENT_HOLES: usize = 8192;

/// How many records an on-disk log will hold for a store that has not taken them yet.

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
    owed_to_store: Vec<Record>,
    /// How many records, in total, the store's catch-up queue has left on the medium at its bound.
    store_debt_on_medium: u64,
    /// Where on the medium the store's debt continues past the queue: the segment and the byte the
    store_owed_from: Option<(u64, u64)>,
    /// Records recovered from the tail at open time, in order.
    recovered: Vec<Record>,
    /// How many segments have been rolled through, poison included.
    segments_used: u64,
    /// Every corrupt remainder recovery set aside, at open and at any roll since, oldest first.
    quarantined: Vec<Quarantine>,
    /// The segment after a poisoned one, opened the moment the poison happened so that its
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
            let at = (wal.segment.index(), wal.segment.write_offset());
            wal.offer_store_debt(&[], at);
        }
        Ok(wal)
    }

    /// Every corrupt remainder recovery set aside — at open, and at any roll since — oldest first.

    pub fn quarantined(&self) -> &[Quarantine] {
        &self.quarantined
    }

    /// Hold on to a quarantine, and mark every identity in the set-aside bytes as taken.

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

    pub fn owed_to_store(&self) -> &[Record] {
        &self.owed_to_store
    }

    /// How many records, in total since open, the store's catch-up queue has left on the medium at

    pub fn store_debt_on_medium(&self) -> u64 {
        self.store_debt_on_medium
    }

    /// Whether the store is owed records the queue does not hold, to be read back off the medium:

    pub fn owes_store_from_medium(&self) -> bool {
        self.store_owed_from.is_some()
    }

    /// Give up on the `count` oldest records the log still owes, and hand them back.

    pub fn forget_owed(&mut self, count: usize) -> Vec<Record> {
        let count = usize::min(count, self.lost_batch.len());
        self.lost_batch.drain(0..count).collect()
    }

    /// How many segments have been used, poisoned ones included.
    pub fn segments_used(&self) -> u64 {
        self.segments_used
    }

    /// Whether `(node, node_seq)` is already in the log.

    pub fn holds(&self, node: u64, node_seq: u64) -> bool {
        match self.high_water.get(&node) {
            Some(&mark) => node_seq <= mark && !self.gaps.contains(&(node, node_seq)),
            None => false,
        }
    }

    /// The lowest number `node` can still take without colliding with something the log already

    pub fn next_free_seq(&self, node: u64) -> u64 {
        match self.high_water.get(&node) {
            Some(&mark) => mark.saturating_add(1),
            None => 1,
        }
    }

    /// Record that `(node, node_seq)` is now in the log: move that node's mark, and remember any

    fn mark_written(&mut self, node: u64, node_seq: u64) {
        match self.high_water.get(&node).copied() {
            Some(mark) if node_seq <= mark => {
                self.gaps.remove(&(node, node_seq));
                return;
            }
            mark => {
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

    pub fn tracked_identities(&self) -> usize {
        self.high_water.len() + self.gaps.len()
    }

    /// The shipper, so a caller can look at what was handed over.
    pub fn shipper(&self) -> &dyn Shipper<Record> {
        self.shipper.as_ref()
    }

    /// Commit one batch: one write, one sync, and — in memory-buffered mode — one synchronous ship.

    pub fn append_batch(
        &mut self,
        token: &Grant<DurableWrite>,
        at: StepName,
        records: &[Record],
    ) -> Result<BatchAck, DurabilityLost> {
        let replaying = !self.lost_batch.is_empty();

        if self.segment.is_poisoned() {
            if let Err(_e) = self.roll() {
                self.lost_batch.extend(records.iter().cloned());
                return Err(DurabilityLost::observed(token, at));
            }
        }

        let owed = std::mem::take(&mut self.lost_batch);

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
                    if let Err(_e) = self.shipper.ship(&offered) {
                        self.lost_batch = offered;
                        return Err(DurabilityLost::observed(token, at));
                    }
                } else {
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
                self.lost_batch = owed.into_iter().chain(records.iter().cloned()).collect();
                if self.segment.write_offset() == 0 || self.roll().is_err() {
                    return Err(DurabilityLost::observed(token, at));
                }
                let carried = std::mem::take(&mut self.lost_batch);
                self.append_batch(token, at, &carried)
            }
            Err(_poisoned_or_io) => {
                self.lost_batch = owed.into_iter().chain(records.iter().cloned()).collect();

                if self.next_segment.is_none() {
                    self.next_segment = self.open_next().ok();
                }
                Err(DurabilityLost::observed(token, at))
            }
        }
    }

    /// Read every record the log holds, OLDEST SEGMENT FIRST, verifying as it goes.

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

    fn offer_store_debt(&mut self, batch: &[Record], batch_at: (u64, u64)) {
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

        let recovered = recover_and_truncate(&mut segment, self.factory.as_mut(), self.clock)?;
        for q in recovered.quarantined {
            self.take_quarantine(q);
        }
        Ok(segment)
    }
}

/// Open the segment a restart appends to, and hand back the records on the log's tail.

fn open_tail(
    factory: &mut dyn SegmentFactory,
    ceiling: u64,
    clock: Clock,
) -> Result<(Segment, Recovered, Vec<Quarantine>, u64), OpenError> {
    let mut index = factory.highest_index()?.unwrap_or(0);
    let mut quarantined = Vec::new();

    let mut newest: Option<Segment> = None;
    loop {
        let backend = factory.open(index)?;
        let mut segment = Segment::open_at(backend, index, 0, ceiling)?;

        let mut recovered = recover_and_truncate(&mut segment, factory, clock)?;

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

type KeptSegment = (u64, (u64, u64), (u64, u64));

/// A scan names the records on either side of a hole only inside its own segment. A hole at the

fn quarantine_below(
    factory: &mut dyn SegmentFactory,
    ceiling: u64,
    clock: Clock,
    tail_index: u64,
    tail: &Recovered,
    mut quarantined: Vec<Quarantine>,
) -> Result<Vec<Quarantine>, OpenError> {
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
