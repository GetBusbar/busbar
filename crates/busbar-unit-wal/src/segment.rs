// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! One segment: an append-only run of frames, grown a piece at a time, committed a batch at a time.
//!
//! ## Two rules, and they are the whole file
//!
//! **Space is claimed incrementally.** A segment's stated size is a ceiling, not an allocation. A
//! node is expected to start on a volume with less free space than that ceiling and serve anyway,
//! so the segment reaches forward by [`GROWTH_STEP_BYTES`] as it fills rather than demanding the
//! whole ceiling at boot. The grown region is zeros, which is the same thing a frame scan reads as
//! "the writes end here".
//!
//! **A failed sync poisons the segment, permanently.** Not "retries", not "degrades" — poisons. The
//! moment a sync reports an error, every byte in this segment after the last good commit is of
//! unknown state, and the one safe reading of unknown is that it is not there. So the segment is
//! closed to further writes, the caller is handed a durability loss, and the batch that failed goes
//! to a fresh segment along with the one after it. A segment that has been poisoned never un-poisons
//! itself, because nothing that happens later can tell you what landed.

use std::io;

use crate::backend::SegmentBackend;
use crate::record::{Record, FRAME_BYTES};

/// How large one segment is allowed to get before the log rolls to the next one.
pub const SEGMENT_BYTES: u64 = 64 * 1024 * 1024;

/// How much space a segment claims at a time as it fills. Small enough that a node on a nearly full
/// volume still starts and serves; large enough that the claim is not on the per-batch path.
pub const GROWTH_STEP_BYTES: u64 = 4 * 1024 * 1024;

/// Why an append did not happen.
#[derive(Debug)]
pub enum SegmentError {
    /// The segment has already lost a durable write and will not take another.
    Poisoned,
    /// The batch does not fit in what is left of the segment; the caller should roll.
    Full,
    /// The write itself failed, before any sync. The segment is poisoned by this too: a positional
    /// write that reports an error may still have put some bytes down.
    Write(io::Error),
    /// The sync failed. This is the case the poison rule exists for.
    Sync(io::Error),
}

impl std::fmt::Display for SegmentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SegmentError::Poisoned => f.write_str("the segment lost a durable write and is closed"),
            SegmentError::Full => f.write_str("the batch does not fit in this segment"),
            SegmentError::Write(e) => write!(f, "writing the batch failed: {e}"),
            SegmentError::Sync(e) => write!(f, "making the batch durable failed: {e}"),
        }
    }
}

impl std::error::Error for SegmentError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SegmentError::Write(e) | SegmentError::Sync(e) => Some(e),
            _ => None,
        }
    }
}

/// An append-only segment, open for writing.
pub struct Segment {
    backend: Box<dyn SegmentBackend>,
    index: u64,
    /// Where the next frame goes. Always a multiple of the frame size.
    write_offset: u64,
    /// How much space has been claimed so far.
    claimed: u64,
    /// The ceiling this segment rolls at.
    ceiling: u64,
    poisoned: bool,
}

impl std::fmt::Debug for Segment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Segment")
            .field("index", &self.index)
            .field("write_offset", &self.write_offset)
            .field("claimed", &self.claimed)
            .field("poisoned", &self.poisoned)
            .finish()
    }
}

impl Segment {
    /// Open a segment for appending at `write_offset` — which is where a recovery scan said the
    /// verifying frames stop, not simply the length of the backing.
    pub fn open_at(
        backend: Box<dyn SegmentBackend>,
        index: u64,
        write_offset: u64,
        ceiling: u64,
    ) -> io::Result<Self> {
        let claimed = backend.len()?;
        Ok(Segment {
            backend,
            index,
            write_offset,
            claimed,
            ceiling,
            poisoned: false,
        })
    }

    /// Which segment this is.
    pub fn index(&self) -> u64 {
        self.index
    }

    /// Where the next frame will go.
    pub fn write_offset(&self) -> u64 {
        self.write_offset
    }

    /// Whether a durable write has been lost on this segment.
    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    /// Read `len` bytes from `offset` — the recovery scan's one entry point into the backing.
    pub fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        self.backend.read_at(offset, buf)
    }

    /// How long the backing is, including any space claimed ahead of the writes.
    pub fn len(&self) -> io::Result<u64> {
        self.backend.len()
    }

    /// Whether the backing holds nothing at all.
    pub fn is_empty(&self) -> io::Result<bool> {
        Ok(self.len()? == 0)
    }

    /// Shorten the backing to `len` and resume appending there. Recovery calls this to cut a torn
    /// tail away, so that the next append starts at a frame boundary and no half-written frame is
    /// ever read again.
    pub fn truncate_to(&mut self, len: u64) -> io::Result<()> {
        self.backend.set_len(len)?;
        self.claimed = len;
        self.write_offset = len;
        Ok(())
    }

    /// Append a whole batch and make it durable: one positional write, then one sync.
    ///
    /// The batch is framed into one contiguous buffer first, so a group commit is a single write
    /// followed by a single sync however many records are in it. That is the shape the wait budget
    /// is written against — one sync per commit, not one per record.
    pub fn append_batch(&mut self, records: &[Record]) -> Result<u64, SegmentError> {
        if self.poisoned {
            return Err(SegmentError::Poisoned);
        }
        let mut buf: Vec<u8> = Vec::new();
        for record in records {
            for frame in record.encode() {
                buf.extend_from_slice(&frame);
            }
        }
        if buf.is_empty() {
            return Ok(self.write_offset);
        }
        let end = self.write_offset + buf.len() as u64;
        if end > self.ceiling {
            return Err(SegmentError::Full);
        }
        if let Err(e) = self.claim_through(end) {
            // A claim that fails is a write that may have half happened. Treated as a loss.
            self.poisoned = true;
            return Err(SegmentError::Write(e));
        }
        if let Err(e) = self.backend.write_all_at(self.write_offset, &buf) {
            self.poisoned = true;
            return Err(SegmentError::Write(e));
        }
        if let Err(e) = self.backend.sync() {
            self.poisoned = true;
            return Err(SegmentError::Sync(e));
        }
        self.write_offset = end;
        Ok(self.write_offset)
    }

    /// Claim space forward so that `end` is inside the backing, a step at a time.
    fn claim_through(&mut self, end: u64) -> io::Result<()> {
        if end <= self.claimed {
            return Ok(());
        }
        let steps = (end - self.claimed).div_ceil(GROWTH_STEP_BYTES);
        let target = u64::min(self.claimed + steps * GROWTH_STEP_BYTES, self.ceiling);
        // The ceiling is a multiple of the growth step in practice, but a caller may set a smaller
        // one for a test; never claim less than what is about to be written.
        let target = u64::max(target, end);
        self.backend.set_len(target)?;
        self.claimed = target;
        Ok(())
    }

    /// How many whole frames would fit in what is left before the ceiling.
    pub fn frames_remaining(&self) -> u64 {
        self.ceiling.saturating_sub(self.write_offset) / FRAME_BYTES as u64
    }
}
