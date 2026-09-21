// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Reading a segment back after a crash, and cutting away whatever the crash left behind.
//!
//! ## The rule, in one sentence
//!
//! The log ends at the last record every one of whose frames verifies; everything after that point
//! is removed.
//!
//! ## Why it is stated over RECORDS and not over frames
//!
//! A record whose body needs three frames is one fact, not three. If a crash landed two of its
//! frames and lost the third, keeping the two would hand the reader a truncated body — a fact that
//! was never written, invented by the recovery path. So the scan tracks the record being assembled
//! and only advances the durable end once a record is complete. Two frames of an incomplete record
//! are cut away with the damage, and the writer that meant to write it will write it again.
//!
//! ## Why every byte offset is a test and not a comment
//!
//! There is no interesting subset of the offsets a crash can stop at. So the battery truncates the
//! segment at every byte offset from zero to the end, recovers, and asserts the result is the
//! longest prefix of the records that were written. Any special-cased offset would show up as the
//! one the loop fails on.

use std::io;

use crate::record::{decode_frame, FrameError, Record, FRAME_BYTES};
use crate::segment::Segment;

/// What a scan of a segment found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recovered {
    /// Every record whose frames all verify, in the order they were written.
    pub records: Vec<Record>,
    /// The offset the last complete record ends at. This is where appending resumes.
    pub durable_end: u64,
    /// How many bytes past `durable_end` the backing held. Non-zero means a tail was cut.
    pub discarded_bytes: u64,
    /// Why the scan stopped, when it stopped on damage rather than on the end of the writes.
    pub stopped_because: Option<FrameError>,
}

impl Recovered {
    /// Whether anything at all had to be cut away.
    pub fn was_torn(&self) -> bool {
        self.discarded_bytes > 0
    }
}

/// Scan `segment` from its beginning and report the last complete, verifying record.
///
/// This does not modify anything. [`recover_and_truncate`] is the one that cuts.
pub fn scan(segment: &Segment) -> io::Result<Recovered> {
    let mut records = Vec::new();
    let mut offset: u64 = 0;
    let mut durable_end: u64 = 0;
    let mut stopped_because = None;
    // The record currently being assembled across continuation frames.
    let mut partial: Option<Partial> = None;
    let mut frame = [0u8; FRAME_BYTES];

    loop {
        let read = read_full(segment, offset, &mut frame)?;
        if !read {
            // Fewer bytes left than one frame. The writes end here; there is nothing to report as
            // damage beyond the leftover bytes, which the discard count already names.
            break;
        }
        let (header, payload) = match decode_frame(&frame) {
            Ok(decoded) => decoded,
            Err(FrameError::NotAFrame) => {
                // Zeros: preallocated space that was never written to. The ordinary end.
                break;
            }
            Err(e) => {
                stopped_because = Some(e);
                break;
            }
        };
        let mismatch = FrameError::BadParts {
            index: header.part_index,
            count: header.part_count,
        };
        match partial.as_mut() {
            None => {
                if header.part_index != 0 {
                    // A continuation with no head in front of it. The head was lost, so this is not
                    // a record — it is the tail of one that never completed.
                    stopped_because = Some(mismatch);
                    break;
                }
                partial = Some(Partial {
                    node: header.node,
                    node_seq: header.node_seq,
                    part_count: header.part_count,
                    next_part: 1,
                    body: payload.to_vec(),
                });
            }
            Some(open) => {
                if header.node != open.node
                    || header.node_seq != open.node_seq
                    || header.part_count != open.part_count
                    || header.part_index != open.next_part
                {
                    stopped_because = Some(mismatch);
                    break;
                }
                open.next_part += 1;
                open.body.extend_from_slice(payload);
            }
        }
        offset += FRAME_BYTES as u64;
        if !header.more_parts {
            if let Some(open) = partial.take() {
                records.push(Record {
                    node: open.node,
                    node_seq: open.node_seq,
                    body: open.body,
                });
                durable_end = offset;
            }
        }
    }

    let len = segment.len()?;
    Ok(Recovered {
        records,
        durable_end,
        discarded_bytes: len.saturating_sub(durable_end),
        stopped_because,
    })
}

/// Scan, then cut the segment back to the last complete record.
///
/// After this returns, the backing holds exactly the records reported and nothing else, so an
/// append lands on a frame boundary and no reader ever meets the damaged bytes again.
pub fn recover_and_truncate(segment: &mut Segment) -> io::Result<Recovered> {
    let recovered = scan(segment)?;
    if recovered.discarded_bytes > 0 {
        segment.truncate_to(recovered.durable_end)?;
    }
    Ok(recovered)
}

/// Read exactly one frame, or report that there is not a whole one left.
fn read_full(segment: &Segment, offset: u64, frame: &mut [u8; FRAME_BYTES]) -> io::Result<bool> {
    let mut filled = 0usize;
    while filled < FRAME_BYTES {
        let n = segment.read_at(offset + filled as u64, &mut frame[filled..])?;
        if n == 0 {
            return Ok(false);
        }
        filled += n;
    }
    Ok(true)
}

/// The record being assembled across continuation frames.
struct Partial {
    node: u64,
    node_seq: u64,
    part_count: u32,
    /// The part index the next frame of this record must carry.
    next_part: u32,
    body: Vec<u8>,
}
