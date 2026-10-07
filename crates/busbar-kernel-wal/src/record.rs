// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The record layout: one fixed-size frame, and the continuation rule for a body that does not fit.
//!
//! Every frame on disk is exactly [`FRAME_BYTES`] long. That is the whole reason a torn tail is
//! recoverable: a reader never has to trust a length field it just read from a half-written region
//! to find where the next frame starts, because the next frame starts at a fixed stride. The length
//! field only says how much of the frame's payload area is real, and the digest covers the header,
//! that payload and the end mark, so a frame that was partly written fails and the scan stops.
//!
//! The frame's LAST byte is its end mark, [`FRAME_END_MARK`], which is never zero. A write runs
//! front to back through a frame, so a write that stopped anywhere inside one leaves that byte as
//! the zero the segment claimed ahead of it: a frame whose end mark is there was written to its end,
//! and one whose end mark is zero was not. That is what tells a torn write from a whole frame that
//! changed afterwards, wherever inside the frame the write stopped (see `crate::recover`).
//!
//! The first frame of every group commit carries [`FrameHeader::opens_commit`]. A verifying frame
//! that opens a commit was only ever written after every commit before it had synced, so it is the
//! on-medium proof that those earlier commits were acknowledged.
//!
//! A body longer than one frame's payload area is split across frames that carry the same
//! `(node, node_seq)` and an increasing part index. A record is only considered present once every
//! one of its parts has been read and verified — a body whose first three parts landed and whose
//! fourth was torn away is not a shorter record, it is an absent one.

use ring::digest::{Context, SHA256};

/// How long one frame is, header and payload together. The record cap the contract pins.
pub const FRAME_BYTES: usize = 512;

/// How much of a frame the header takes. The last 32 bytes of it are the digest.
pub const FRAME_HEADER_BYTES: usize = 96;

/// How much of a frame follows the payload: the one end-mark byte.
pub const FRAME_TRAILER_BYTES: usize = 1;

/// How many payload bytes one frame carries.
pub const FRAME_PAYLOAD_BYTES: usize = FRAME_BYTES - FRAME_HEADER_BYTES - FRAME_TRAILER_BYTES;

/// The byte every frame ends with. Never zero, so a frame whose last byte is zero is one whose write
/// did not reach its end.
pub const FRAME_END_MARK: u8 = 0xE5;

/// Where the end mark sits: the frame's last byte.
const END_MARK_OFFSET: usize = FRAME_BYTES - FRAME_TRAILER_BYTES;

/// The four bytes every frame opens with. A frame that does not start with these is not a frame —
/// which is exactly what the zero-filled preallocated tail of a segment looks like.
pub const FRAME_MAGIC: [u8; 4] = *b"BWAL";

/// The layout version this build WRITES, and the only one it reads. A reader that meets a version it
/// does not know stops there rather than guessing at the field offsets.
///
/// Version 3 is version 2 with two additions, and the layout changed, so the number did:
///
/// - the END MARK: the frame's last byte is [`FRAME_END_MARK`], taken from the payload area (which
///   is one byte shorter for it). A torn write and a whole frame altered afterwards are told apart
///   by it wherever inside the frame the write stopped, not only inside the header;
/// - the COMMIT FLAG: the first frame of each group commit says so, which is how recovery knows a
///   damaged commit was acknowledged (a subsequent commit verifies past it) or may have been torn (no
///   subsequent commit does).
///
/// Version 2 added the HEADER CHECK (bytes `[HEADER_CHECK_OFFSET, +4)`): the first four bytes of a
/// SHA-256 over the frame's fixed header fields `[0, HEADER_CHECKED_BYTES)` — magic, version,
/// flags, identity, part numbers and the payload length. Version 3 keeps it.
///
/// Neither version 1 (before the header check) nor version 2 (before the end mark) was released —
/// 1.5.5 had no log at all — so no segment in the field holds either, and this build reads neither:
/// a frame claiming one is an unknown layout, which recovery quarantines rather than cuts. Reading
/// an older layout would only hand an attacker a downgrade (a frame relabelled to it skips a check
/// the current layout makes).
pub const FRAME_VERSION: u16 = 3;

/// How many leading header bytes the header check covers: magic, version, flags, node, node_seq,
/// part index, part count and payload length.
const HEADER_CHECKED_BYTES: usize = 34;

/// Where the header check sits.
pub(crate) const HEADER_CHECK_OFFSET: usize = 34;

/// The flag bit that says another part of this record follows.
const FLAG_MORE_PARTS: u8 = 1 << 0;

/// The flag bit that says this frame is the first one of a group commit.
const FLAG_OPENS_COMMIT: u8 = 1 << 1;

/// Where the digest sits inside the header, and therefore how much of the header it covers.
pub(crate) const DIGEST_OFFSET: usize = 64;

/// One record as a caller hands it in: who wrote it, that writer's own sequence number, and the
/// bytes of the entry.
///
/// The log has no opinion about what is inside `body`. Its two jobs are that the bytes come back
/// exactly as they went in, and that a body that was not fully written never comes back at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// Which node wrote it.
    pub node: u64,
    /// That node's own sequence number for this record. Together with `node` it is the identity a
    /// re-appended batch is deduplicated on.
    pub node_seq: u64,
    /// The entry's bytes.
    pub body: Vec<u8>,
}

impl Record {
    /// A record with the given identity and body.
    pub fn new(node: u64, node_seq: u64, body: impl Into<Vec<u8>>) -> Self {
        Record {
            node,
            node_seq,
            body: body.into(),
        }
    }

    /// The identity a re-append is deduplicated on.
    pub fn identity(&self) -> (u64, u64) {
        (self.node, self.node_seq)
    }

    /// How many frames this record occupies. A record with an empty body still takes one, so that
    /// its presence is itself a fact the log can carry.
    pub fn frame_count(&self) -> usize {
        if self.body.is_empty() {
            1
        } else {
            self.body.len().div_ceil(FRAME_PAYLOAD_BYTES)
        }
    }

    /// Frame this record, in order. Every frame is fully written, including the zero padding after
    /// a short payload and the end mark, so the bytes on disk are a function of the record alone.
    /// No frame of it opens a commit; [`Record::encode_in_commit`] is the framing a segment writes.
    pub fn encode(&self) -> Vec<[u8; FRAME_BYTES]> {
        self.encode_in_commit(false)
    }

    /// Frame this record as a group commit puts it down: when `opens_commit`, its first frame is
    /// flagged as the first frame of the commit.
    pub fn encode_in_commit(&self, opens_commit: bool) -> Vec<[u8; FRAME_BYTES]> {
        let parts = self.frame_count();
        let mut frames = Vec::with_capacity(parts);
        for index in 0..parts {
            let start = index * FRAME_PAYLOAD_BYTES;
            let end = usize::min(start + FRAME_PAYLOAD_BYTES, self.body.len());
            let payload = if start < self.body.len() {
                &self.body[start..end]
            } else {
                &[][..]
            };
            frames.push(encode_frame(
                self.node,
                self.node_seq,
                index as u32,
                parts as u32,
                opens_commit && index == 0,
                payload,
            ));
        }
        frames
    }
}

/// One frame's header as a reader recovers it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    /// Which node wrote it.
    pub node: u64,
    /// That node's own sequence number for the record this frame belongs to.
    pub node_seq: u64,
    /// This frame's position within the record, from zero.
    pub part_index: u32,
    /// How many frames the whole record takes.
    pub part_count: u32,
    /// How many payload bytes of this frame are real.
    pub payload_len: u16,
    /// Whether another part follows.
    pub more_parts: bool,
    /// Whether this frame is the first one of a group commit.
    pub opens_commit: bool,
}

/// Why a frame could not be read back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    /// The frame does not open with the magic. On the tail of a segment this is the ordinary end
    /// of the written region rather than damage: preallocated space is zeros.
    NotAFrame,
    /// A layout version this build does not know.
    UnknownVersion {
        /// The version the frame claims.
        found: u16,
    },
    /// The payload length is larger than a frame's payload area.
    PayloadTooLong {
        /// The length the frame claims.
        found: u16,
    },
    /// The part index is not inside the part count, or the count is zero.
    BadParts {
        /// The claimed index.
        index: u32,
        /// The claimed count.
        count: u32,
    },
    /// The digest over the frame's own bytes is not the digest stored in it. Reported only once the
    /// frame's header check has passed, so the frame was written whole and then altered.
    DigestMismatch,
    /// The frame's header check does not match its header. A frame whose end mark is there was
    /// written whole and then altered; one whose end mark is zero is a write that stopped (see
    /// [`written_whole`]).
    HeaderMismatch,
    /// The frame does not end with [`FRAME_END_MARK`]. Zero there is a write that did not reach the
    /// frame's end; anything else is a last byte that changed after it was written.
    EndMarkMissing,
}

impl FrameError {
    /// Whether this is a WHOLE frame whose bytes changed after they were written: a frame of this
    /// layout whose header check and end mark passed and whose digest did not. Such a frame is never
    /// a torn write, wherever it sits.
    #[must_use]
    pub fn is_altered_whole_frame(self, version: u16) -> bool {
        version == FRAME_VERSION && self == FrameError::DigestMismatch
    }
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FrameError::NotAFrame => f.write_str("not a frame (no magic)"),
            FrameError::UnknownVersion { found } => {
                write!(
                    f,
                    "frame layout version {found} is not one this build reads"
                )
            }
            FrameError::PayloadTooLong { found } => {
                write!(
                    f,
                    "frame claims {found} payload bytes, more than a frame holds"
                )
            }
            FrameError::BadParts { index, count } => {
                write!(f, "frame claims part {index} of {count}")
            }
            FrameError::DigestMismatch => {
                f.write_str("the frame's own bytes do not hash to the digest stored in it")
            }
            FrameError::HeaderMismatch => {
                f.write_str("the frame's header does not match its header check")
            }
            FrameError::EndMarkMissing => f.write_str("the frame does not end with its end mark"),
        }
    }
}

impl std::error::Error for FrameError {}

/// Build one frame. Private because the only way to make frames is to frame a whole record: a
/// caller that could mint a single part could mint an inconsistent part chain.
fn encode_frame(
    node: u64,
    node_seq: u64,
    part_index: u32,
    part_count: u32,
    opens_commit: bool,
    payload: &[u8],
) -> [u8; FRAME_BYTES] {
    debug_assert!(payload.len() <= FRAME_PAYLOAD_BYTES);
    let mut frame = [0u8; FRAME_BYTES];
    frame[0..4].copy_from_slice(&FRAME_MAGIC);
    frame[4..6].copy_from_slice(&FRAME_VERSION.to_le_bytes());
    let mut flags = 0;
    if part_index + 1 < part_count {
        flags |= FLAG_MORE_PARTS;
    }
    if opens_commit {
        flags |= FLAG_OPENS_COMMIT;
    }
    frame[6] = flags;
    frame[8..16].copy_from_slice(&node.to_le_bytes());
    frame[16..24].copy_from_slice(&node_seq.to_le_bytes());
    frame[24..28].copy_from_slice(&part_index.to_le_bytes());
    frame[28..32].copy_from_slice(&part_count.to_le_bytes());
    frame[32..34].copy_from_slice(&(payload.len() as u16).to_le_bytes());
    let check = header_check(&frame);
    frame[HEADER_CHECK_OFFSET..HEADER_CHECK_OFFSET + 4].copy_from_slice(&check);
    frame[FRAME_HEADER_BYTES..FRAME_HEADER_BYTES + payload.len()].copy_from_slice(payload);
    frame[END_MARK_OFFSET] = FRAME_END_MARK;
    let digest = frame_digest(&frame);
    frame[DIGEST_OFFSET..DIGEST_OFFSET + 32].copy_from_slice(&digest);
    frame
}

/// The header check a frame carries over its fixed header fields.
pub(crate) fn header_check(frame: &[u8; FRAME_BYTES]) -> [u8; 4] {
    let mut hasher = Context::new(&SHA256);
    hasher.update(&frame[0..HEADER_CHECKED_BYTES]);
    let digest = digest32(hasher);
    [digest[0], digest[1], digest[2], digest[3]]
}

/// The version a frame claims, read without judging it (the magic is not checked here).
#[must_use]
pub fn frame_version(frame: &[u8; FRAME_BYTES]) -> u16 {
    u16::from_le_bytes([frame[4], frame[5]])
}

/// The header of a frame whose header CHECK passes, whatever its digest says — the identity and the
/// part numbers of a whole frame that was altered after it was written. `None` for a frame of any
/// other layout version and for anything whose header does not check.
#[must_use]
pub fn checked_header(frame: &[u8; FRAME_BYTES]) -> Option<(FrameHeader, &[u8])> {
    if frame[0..4] != FRAME_MAGIC || frame_version(frame) != FRAME_VERSION {
        return None;
    }
    if header_check(frame)[..] != frame[HEADER_CHECK_OFFSET..HEADER_CHECK_OFFSET + 4] {
        return None;
    }
    let (header, payload_len) = read_header(frame).ok()?;
    let payload = &frame[FRAME_HEADER_BYTES..FRAME_HEADER_BYTES + usize::from(payload_len)];
    Some((header, payload))
}

/// Whether `frame` was WRITTEN WHOLE: the write that made it reached its last byte.
///
/// The last byte of every frame is the end mark, which is never zero, and the space a write lands
/// in is the zeros the segment claimed ahead of it. A write runs front to back, so one that stopped
/// anywhere inside the frame — in the header, in the digest, in the payload — leaves that byte zero.
/// A frame whose last byte is not zero was written in full, so if it fails any check it was
/// acknowledged and then altered, and is never a torn tail.
#[must_use]
pub fn written_whole(frame: &[u8; FRAME_BYTES]) -> bool {
    frame[END_MARK_OFFSET] != 0
}

/// Whether `frame` is what a write of a frame of THIS layout leaves when it stops before the frame's
/// end: all zeros (nothing landed), or the frame's leading bytes followed by zeros to its end.
///
/// The leading bytes it can check are checked: the magic and the version, which every frame of this
/// layout opens with, and the header check once the write got past it. Anything else is not a torn
/// write of this layout — a whole frame that changed, or a frame of a layout this build does not
/// read, whose bytes another build can still read and which is therefore never cut.
#[must_use]
pub fn unfinished_write(frame: &[u8; FRAME_BYTES]) -> bool {
    if written_whole(frame) {
        return false;
    }
    let Some(last) = frame.iter().rposition(|&b| b != 0) else {
        return true;
    };
    let reached = last + 1;
    let mut opening = [0u8; 6];
    opening[0..4].copy_from_slice(&FRAME_MAGIC);
    opening[4..6].copy_from_slice(&FRAME_VERSION.to_le_bytes());
    let n = usize::min(reached, opening.len());
    if frame[..n] != opening[..n] {
        return false;
    }
    reached < HEADER_CHECK_OFFSET + 4
        || header_check(frame)[..] == frame[HEADER_CHECK_OFFSET..HEADER_CHECK_OFFSET + 4]
}

/// The header of a frame that is not an [`unfinished_write`] but whose header does not check, read
/// as the bytes now stand; `None` for anything else. Whatever layout version it now claims: the
/// damaged byte may be the version itself (a frame relabelled to a layout this build does not read
/// is still an acknowledged record, and its identity is still taken), and a frame of a layout this
/// build does not read keeps its identity at the same offsets every layout has put it.
///
/// The identity and payload are UNVERIFIED — the damaged byte may sit in them — so they are good
/// for one thing only: naming, conservatively, what a quarantine set aside. The payload length is
/// clamped to the payload area, because the damaged byte may be the length itself.
#[must_use]
pub fn unchecked_whole(frame: &[u8; FRAME_BYTES]) -> Option<(FrameHeader, &[u8])> {
    if unfinished_write(frame) || checked_header(frame).is_some() {
        return None;
    }
    let payload_len = u16::from_le_bytes([frame[32], frame[33]]);
    let header = FrameHeader {
        node: u64::from_le_bytes(frame[8..16].try_into().unwrap_or([0; 8])),
        node_seq: u64::from_le_bytes(frame[16..24].try_into().unwrap_or([0; 8])),
        part_index: u32::from_le_bytes([frame[24], frame[25], frame[26], frame[27]]),
        part_count: u32::from_le_bytes([frame[28], frame[29], frame[30], frame[31]]),
        payload_len,
        more_parts: frame[6] & FLAG_MORE_PARTS != 0,
        opens_commit: frame[6] & FLAG_OPENS_COMMIT != 0,
    };
    let end = FRAME_HEADER_BYTES + usize::min(usize::from(payload_len), FRAME_PAYLOAD_BYTES);
    Some((header, &frame[FRAME_HEADER_BYTES..end]))
}

/// The header fields, bounds-checked. Shared by the verifying and the header-only reads.
fn read_header(frame: &[u8; FRAME_BYTES]) -> Result<(FrameHeader, u16), FrameError> {
    let payload_len = u16::from_le_bytes([frame[32], frame[33]]);
    if payload_len as usize > FRAME_PAYLOAD_BYTES {
        return Err(FrameError::PayloadTooLong { found: payload_len });
    }
    let part_index = u32::from_le_bytes([frame[24], frame[25], frame[26], frame[27]]);
    let part_count = u32::from_le_bytes([frame[28], frame[29], frame[30], frame[31]]);
    if part_count == 0 || part_index >= part_count {
        return Err(FrameError::BadParts {
            index: part_index,
            count: part_count,
        });
    }
    Ok((
        FrameHeader {
            node: u64::from_le_bytes(frame[8..16].try_into().unwrap_or([0; 8])),
            node_seq: u64::from_le_bytes(frame[16..24].try_into().unwrap_or([0; 8])),
            part_index,
            part_count,
            payload_len,
            more_parts: frame[6] & FLAG_MORE_PARTS != 0,
            opens_commit: frame[6] & FLAG_OPENS_COMMIT != 0,
        },
        payload_len,
    ))
}

/// The digest a frame carries: over the header up to the digest field, then over the payload area
/// and the end mark. The digest field itself is skipped, which is what lets it be filled in
/// afterwards.
pub(crate) fn frame_digest(frame: &[u8; FRAME_BYTES]) -> [u8; 32] {
    let mut hasher = Context::new(&SHA256);
    hasher.update(&frame[0..DIGEST_OFFSET]);
    hasher.update(&frame[FRAME_HEADER_BYTES..]);
    digest32(hasher)
}

/// A finished SHA-256 (ring, the one crypto backend) as the 32 bytes the frame and the journal store.
pub(crate) fn digest32(hasher: Context) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(hasher.finish().as_ref());
    out
}

/// Read one frame back: its header, and the payload bytes it really carries.
///
/// Every field is checked before it is used, and the digest is checked last, so a frame that was
/// half written is reported as damaged rather than acted on.
pub fn decode_frame(frame: &[u8; FRAME_BYTES]) -> Result<(FrameHeader, &[u8]), FrameError> {
    if frame[0..4] != FRAME_MAGIC {
        return Err(FrameError::NotAFrame);
    }
    let version = frame_version(frame);
    if version != FRAME_VERSION {
        return Err(FrameError::UnknownVersion { found: version });
    }
    // THE HEADER CHECK FIRST: a header whose fields do not agree with their check is not read.
    if header_check(frame)[..] != frame[HEADER_CHECK_OFFSET..HEADER_CHECK_OFFSET + 4] {
        return Err(FrameError::HeaderMismatch);
    }
    let (header, payload_len) = read_header(frame)?;
    // THE END MARK BEFORE THE DIGEST: a write that stopped inside the frame is told apart from a
    // whole frame whose bytes changed (which keeps its end mark and fails only its digest).
    if frame[END_MARK_OFFSET] != FRAME_END_MARK {
        return Err(FrameError::EndMarkMissing);
    }
    // The digest field is not itself hashed (see `frame_digest`), so the frame can be digested as
    // it stands rather than having to be copied with the field blanked first.
    if frame_digest(frame)[..] != frame[DIGEST_OFFSET..DIGEST_OFFSET + 32] {
        return Err(FrameError::DigestMismatch);
    }
    let payload = &frame[FRAME_HEADER_BYTES..FRAME_HEADER_BYTES + usize::from(payload_len)];
    Ok((header, payload))
}
