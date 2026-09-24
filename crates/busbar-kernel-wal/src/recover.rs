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
//!
//! ## Two ways a scan stops on damage, and only one of them may be cut
//!
//! A crash in the middle of a group commit leaves a TORN tail: the last batch's bytes are partly on
//! the medium and nothing after them was ever written. Cutting that tail loses nothing that was
//! acknowledged — the sync never returned — so it is cut silently, exactly as it always was.
//!
//! A frame that fails its digest with WHOLE, VERIFYING frames after it is something else. Nothing
//! about a crash writes a good frame past a bad one: the writes are one contiguous run from the
//! durable end, and the space past them is zeros. So damage with a verifying frame beyond it is the
//! medium, or something outside this process, changing bytes that were already durable, and the
//! records behind it were acknowledged. That verdict is CORRUPT, and a corrupt segment is never cut
//! on its own say-so: the damaged remainder is first copied, byte for byte, into a quarantine the
//! factory makes durable, and only then is the segment cut back to the verified prefix. A crash
//! between the two steps leaves the copy AND the uncut segment, so it loses nothing. A frame written
//! under a layout version this build does not read is treated the same way — its bytes are whole
//! and another build can read them, so they are never simply cut.
//!
//! The verdict is returned rather than acted on further here. Raising the alarm — the log line, the
//! counter, the durable record naming what was set aside — is the caller's, which is the one place
//! that knows what the lost records meant.

use std::io;
use std::path::PathBuf;

use crate::backend::SegmentFactory;
use crate::record::{decode_frame, FrameError, Record, FRAME_BYTES};
use crate::segment::Segment;

/// How a scan of a segment ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TailVerdict {
    /// The writes end where the verified records end. Anything past them is space claimed ahead of
    /// the writes, which is zeros.
    Clean,
    /// The scan stopped on an incomplete final record — a crash mid-append. Nothing past the damage
    /// verifies, so nothing acknowledged is behind it: cut silently.
    Torn,
    /// The scan stopped on damage with whole, verifying frames beyond it (or on a frame written
    /// under a layout this build does not read). Records that were acknowledged are behind it. Never
    /// cut without a quarantine copy first.
    Corrupt {
        /// The byte offset, inside the segment, of the frame the scan stopped on.
        at: u64,
    },
}

impl TailVerdict {
    /// Whether this verdict is one the caller answers by cutting the segment with no copy kept.
    ///
    /// The question lives on the verdict rather than in each caller, because "anything that is not
    /// clean is a torn tail" is exactly the habit that turned a corrupted record into the silent
    /// loss of every good record behind it.
    #[must_use]
    pub fn truncates(self) -> bool {
        !matches!(self, TailVerdict::Corrupt { .. })
    }
}

/// Where a quarantined remainder was kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuarantineKept {
    /// In a file beside the segment, written and synced before the segment was cut.
    File(PathBuf),
    /// In the memory factory's own quarantine list. A memory-backed log has no disk to put it on,
    /// and the process holding it is the only thing that could ever have read it.
    Memory,
    /// The copy could not be made durable, so the segment was NOT cut: the damaged bytes are still
    /// in it, it is closed to writes, and the next append rolls to a fresh segment. The text is why
    /// the copy failed.
    InPlace(String),
}

/// What a corrupt segment gave up: which bytes, from where, and where they were kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Quarantine {
    /// Which segment.
    pub segment: u64,
    /// The segment's file, on a log that has one.
    pub segment_file: Option<PathBuf>,
    /// The first byte set aside — the end of the verified prefix that was kept.
    pub offset: u64,
    /// The frame the scan stopped on. At or after `offset`: frames of a record that never completed
    /// verify on their own and still go with the damage.
    pub damage_at: u64,
    /// How many bytes were set aside, from `offset` to the end of what was ever written. Space
    /// claimed ahead of the writes is zeros and is not copied.
    pub bytes: u64,
    /// Why the scan stopped, when a frame said so.
    pub why: Option<FrameError>,
    /// Every `(node, node_seq)` a verifying frame in the set-aside bytes carries. Those records were
    /// acknowledged and may already be in a store, so the log must never hand the same identities
    /// out again: it marks them taken.
    pub identities: Vec<(u64, u64)>,
    /// When recovery set them aside, in milliseconds since the Unix epoch. The quarantine file's
    /// name carries the same number.
    pub at_unix_ms: u64,
    /// Where the bytes went.
    pub kept: QuarantineKept,
}

impl Quarantine {
    /// The body of the `ChainBreak` journal record that says, durably, what was set aside: a tag,
    /// the segment file, the segment index, the first byte set aside, the frame the damage was
    /// found at, the byte count, where the bytes went, the moment, and how many record identities
    /// they held — in that order, through the journal's own body writer.
    #[must_use]
    pub fn body(&self) -> Vec<u8> {
        let segment_file = self
            .segment_file
            .as_ref()
            .map_or_else(String::new, |p| p.display().to_string());
        let kept = match &self.kept {
            QuarantineKept::File(path) => path.display().to_string(),
            QuarantineKept::Memory => "in-process".to_string(),
            QuarantineKept::InPlace(e) => format!("in-place: {e}"),
        };
        let mut body = crate::journal::BodyWriter::new();
        body.text(QUARANTINE_BODY_TAG)
            .text(&segment_file)
            .num(self.segment)
            .num(self.offset)
            .num(self.damage_at)
            .num(self.bytes)
            .text(&kept)
            .num(self.at_unix_ms)
            .num(self.identities.len() as u64);
        body.finish()
    }
}

/// The first field of a quarantine's `ChainBreak` body, which tells it apart from the break an
/// overflow seals.
pub const QUARANTINE_BODY_TAG: &str = "journal-quarantine";

impl std::fmt::Display for Quarantine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let segment = self.segment_file.as_ref().map_or_else(
            || format!("segment {}", self.segment),
            |p| p.display().to_string(),
        );
        write!(
            f,
            "journal corruption in {segment} at byte {}: {} byte(s) from byte {} holding {} \
             record identity(ies) are no longer on the book",
            self.damage_at,
            self.bytes,
            self.offset,
            self.identities.len()
        )?;
        if let Some(why) = self.why {
            write!(f, " ({why})")?;
        }
        match &self.kept {
            QuarantineKept::File(path) => write!(f, "; quarantined to {}", path.display()),
            QuarantineKept::Memory => f.write_str("; quarantined in memory"),
            QuarantineKept::InPlace(e) => write!(
                f,
                "; the quarantine copy failed ({e}), so the bytes were left in the segment and it \
                 is closed to writes"
            ),
        }
    }
}

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
    /// Which of the three endings this was.
    pub verdict: TailVerdict,
    /// Where the bytes a corrupt verdict gave up went. Set only by [`recover_and_truncate`]; a
    /// bare [`scan`] modifies nothing and so has set nothing aside.
    pub quarantined: Option<Quarantine>,
    /// The end of what was ever written past the verified prefix: the last byte that is not
    /// claimed-ahead zeros. Equal to `durable_end` when nothing was written past it.
    pub written_end: u64,
    /// Every identity a verifying frame past the stop carries. See [`Quarantine::identities`].
    pub identities_beyond: Vec<(u64, u64)>,
}

impl Recovered {
    /// Whether the scan stopped on a genuine torn tail — an incomplete final record a crash left
    /// behind, with nothing verifying past it. That, and only that, is damage cut away silently.
    pub fn was_torn(&self) -> bool {
        self.verdict == TailVerdict::Torn
    }

    /// Whether the scan stopped on damage with acknowledged records behind it.
    pub fn was_corrupt(&self) -> bool {
        matches!(self.verdict, TailVerdict::Corrupt { .. })
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
    // Where the scan stopped: the frame it could not take, or the leftover short of one.
    let mut stop_at: u64;

    loop {
        stop_at = offset;
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
    let beyond = look_past(segment, durable_end, stop_at, len)?;
    let unreadable_layout = matches!(stopped_because, Some(FrameError::UnknownVersion { .. }));
    let verdict = if beyond.verifies || unreadable_layout {
        TailVerdict::Corrupt { at: stop_at }
    } else if beyond.written_end > durable_end {
        TailVerdict::Torn
    } else {
        TailVerdict::Clean
    };
    Ok(Recovered {
        records,
        durable_end,
        discarded_bytes: len.saturating_sub(durable_end),
        stopped_because,
        verdict,
        quarantined: None,
        written_end: beyond.written_end,
        identities_beyond: beyond.identities,
    })
}

/// What lies past the verified prefix.
struct Beyond {
    /// Whether any whole frame at or after the stop verifies.
    verifies: bool,
    /// The end of the last frame-sized chunk that holds a non-zero byte.
    written_end: u64,
    /// The identities every verifying frame past the prefix carries, deduplicated, in the order
    /// they were met.
    identities: Vec<(u64, u64)>,
}

/// Walk `[from, len)` a frame at a time: note where the written bytes end, and whether any frame at
/// or after `stop_at` verifies on its own. Read in blocks, because on an ordinary boot this walks
/// the zeros claimed ahead of the writes and a read per frame would be a read per 512 bytes.
fn look_past(segment: &Segment, from: u64, stop_at: u64, len: u64) -> io::Result<Beyond> {
    const BLOCK_FRAMES: usize = 128;
    let mut beyond = Beyond {
        verifies: false,
        written_end: from,
        identities: Vec::new(),
    };
    let mut block = vec![0u8; BLOCK_FRAMES * FRAME_BYTES];
    let mut at = from;
    while at < len {
        let want = usize::try_from(u64::min(len - at, block.len() as u64)).unwrap_or(block.len());
        let mut filled = 0usize;
        while filled < want {
            let n = segment.read_at(at + filled as u64, &mut block[filled..want])?;
            if n == 0 {
                break;
            }
            filled += n;
        }
        if filled == 0 {
            break;
        }
        for (i, chunk) in block[..filled].chunks(FRAME_BYTES).enumerate() {
            let chunk_at = at + (i * FRAME_BYTES) as u64;
            if chunk.iter().any(|&b| b != 0) {
                beyond.written_end = chunk_at + chunk.len() as u64;
            }
            let Ok(whole) = <&[u8; FRAME_BYTES]>::try_from(chunk) else {
                continue;
            };
            if let Ok((header, _)) = decode_frame(whole) {
                // Frames before the stop are the head of a record that never completed: they
                // verify on their own, say nothing about what lies past the damage, and still
                // carry an identity the set-aside bytes hold.
                if chunk_at >= stop_at {
                    beyond.verifies = true;
                }
                let id = (header.node, header.node_seq);
                if !beyond.identities.contains(&id) {
                    beyond.identities.push(id);
                }
            }
        }
        at += filled as u64;
    }
    Ok(beyond)
}

/// Scan, then cut the segment back to the last complete record — branching on WHY the scan
/// stopped.
///
/// - A torn tail, or a clean end with space claimed ahead of it, is cut silently.
/// - A corrupt one first has its damaged remainder copied, byte for byte, into a quarantine
///   `factory` makes durable, and only then is the segment cut. If the copy cannot be made, the
///   segment is NOT cut: it is closed to writes instead, so the next append rolls past it and the
///   damaged bytes stay exactly where they are.
///
/// After this returns — on every arm but the last — the backing holds exactly the records reported
/// and nothing else, so an append lands on a frame boundary and no reader meets the damage again.
///
/// `clock` is the composition root's wall clock in unix milliseconds. It is read once, and only on
/// the corrupt arm, to stamp when the damage was set aside; this crate never reads a clock itself.
pub fn recover_and_truncate(
    segment: &mut Segment,
    factory: &mut dyn SegmentFactory,
    clock: crate::wal::Clock,
) -> io::Result<Recovered> {
    let mut recovered = scan(segment)?;
    if recovered.was_torn() {
        // A crash mid-append. Nothing past the damage was acknowledged.
        segment.truncate_to(recovered.durable_end)?;
        return Ok(recovered);
    }
    let TailVerdict::Corrupt { at } = recovered.verdict else {
        // Clean: the only thing past the records is space claimed ahead of them.
        segment.truncate_to(recovered.durable_end)?;
        return Ok(recovered);
    };
    let offset = recovered.durable_end;
    let bytes = recovered.written_end.saturating_sub(offset);
    let mut copy = vec![0u8; usize::try_from(bytes).unwrap_or(usize::MAX)];
    let mut filled = 0usize;
    while filled < copy.len() {
        let n = segment.read_at(offset + filled as u64, &mut copy[filled..])?;
        if n == 0 {
            break;
        }
        filled += n;
    }
    copy.truncate(filled);
    let at_unix_ms = clock();
    // The copy is durable before a single byte of the segment is cut. The order is the whole
    // guarantee: a crash between the two leaves both.
    let kept = match factory.quarantine(segment.index(), offset, at_unix_ms, &copy) {
        Ok(Some(path)) => QuarantineKept::File(path),
        Ok(None) => QuarantineKept::Memory,
        Err(e) => QuarantineKept::InPlace(e.to_string()),
    };
    if let QuarantineKept::InPlace(_) = kept {
        segment.close_to_writes();
    } else {
        segment.truncate_to(offset)?;
    }
    recovered.quarantined = Some(Quarantine {
        segment: segment.index(),
        segment_file: factory.segment_file(segment.index()),
        offset,
        damage_at: at,
        bytes: copy.len() as u64,
        why: recovered.stopped_because,
        identities: recovered.identities_beyond.clone(),
        at_unix_ms,
        kept,
    });
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
