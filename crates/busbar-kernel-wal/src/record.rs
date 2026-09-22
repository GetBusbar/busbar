// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The record layout: one fixed-size frame, and the continuation rule for a body that does not fit.
//!
//! Every frame on disk is exactly [`FRAME_BYTES`] long. That is the whole reason a torn tail is
//! recoverable: a reader never has to trust a length field it just read from a half-written region
//! to find where the next frame starts, because the next frame starts at a fixed stride. The length
//! field only says how much of the frame's payload area is real, and the digest covers both the
//! header and that payload, so a frame that was partly written fails its digest and the scan stops.
//!
//! A body longer than one frame's payload area is split across frames that carry the same
//! `(node, node_seq)` and an increasing part index. A record is only considered present once every
//! one of its parts has been read and verified — a body whose first three parts landed and whose
//! fourth was torn away is not a shorter record, it is an absent one.

use sha2::{Digest as _, Sha256};

/// How long one frame is, header and payload together. The record cap the contract pins.
pub const FRAME_BYTES: usize = 512;

/// How much of a frame the header takes. The last 32 bytes of it are the digest.
pub const FRAME_HEADER_BYTES: usize = 96;

/// How many payload bytes one frame carries.
pub const FRAME_PAYLOAD_BYTES: usize = FRAME_BYTES - FRAME_HEADER_BYTES;

/// The four bytes every frame opens with. A frame that does not start with these is not a frame —
/// which is exactly what the zero-filled preallocated tail of a segment looks like.
pub const FRAME_MAGIC: [u8; 4] = *b"BWAL";

/// The layout version. A reader that meets a version it does not know stops there rather than
/// guessing at the field offsets.
pub const FRAME_VERSION: u16 = 1;

/// The flag bit that says another part of this record follows.
const FLAG_MORE_PARTS: u8 = 1 << 0;

/// Where the digest sits inside the header, and therefore how much of the header it covers.
const DIGEST_OFFSET: usize = 64;

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
    /// a short payload, so the bytes on disk are a function of the record alone.
    pub fn encode(&self) -> Vec<[u8; FRAME_BYTES]> {
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
    /// The digest over the frame's own bytes is not the digest stored in it. Either the frame was
    /// half written, or it was edited.
    DigestMismatch,
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
    payload: &[u8],
) -> [u8; FRAME_BYTES] {
    debug_assert!(payload.len() <= FRAME_PAYLOAD_BYTES);
    let mut frame = [0u8; FRAME_BYTES];
    frame[0..4].copy_from_slice(&FRAME_MAGIC);
    frame[4..6].copy_from_slice(&FRAME_VERSION.to_le_bytes());
    frame[6] = if part_index + 1 < part_count {
        FLAG_MORE_PARTS
    } else {
        0
    };
    frame[8..16].copy_from_slice(&node.to_le_bytes());
    frame[16..24].copy_from_slice(&node_seq.to_le_bytes());
    frame[24..28].copy_from_slice(&part_index.to_le_bytes());
    frame[28..32].copy_from_slice(&part_count.to_le_bytes());
    frame[32..34].copy_from_slice(&(payload.len() as u16).to_le_bytes());
    frame[FRAME_HEADER_BYTES..FRAME_HEADER_BYTES + payload.len()].copy_from_slice(payload);
    let digest = frame_digest(&frame);
    frame[DIGEST_OFFSET..DIGEST_OFFSET + 32].copy_from_slice(&digest);
    frame
}

/// The digest a frame carries: over the header up to the digest field, then over the payload area.
/// The digest field itself is skipped, which is what lets it be filled in afterwards.
fn frame_digest(frame: &[u8; FRAME_BYTES]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(&frame[0..DIGEST_OFFSET]);
    hasher.update(&frame[FRAME_HEADER_BYTES..]);
    hasher.finalize().into()
}

/// Read one frame back: its header, and the payload bytes it really carries.
///
/// Every field is checked before it is used, and the digest is checked last, so a frame that was
/// half written is reported as damaged rather than acted on.
pub fn decode_frame(frame: &[u8; FRAME_BYTES]) -> Result<(FrameHeader, &[u8]), FrameError> {
    if frame[0..4] != FRAME_MAGIC {
        return Err(FrameError::NotAFrame);
    }
    let version = u16::from_le_bytes([frame[4], frame[5]]);
    if version != FRAME_VERSION {
        return Err(FrameError::UnknownVersion { found: version });
    }
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
    // The digest field is not itself hashed (see `frame_digest`), so the frame can be digested as
    // it stands rather than having to be copied with the field blanked first.
    if frame_digest(frame)[..] != frame[DIGEST_OFFSET..DIGEST_OFFSET + 32] {
        return Err(FrameError::DigestMismatch);
    }
    let header = FrameHeader {
        node: u64::from_le_bytes(frame[8..16].try_into().unwrap_or([0; 8])),
        node_seq: u64::from_le_bytes(frame[16..24].try_into().unwrap_or([0; 8])),
        part_index,
        part_count,
        payload_len,
        more_parts: frame[6] & FLAG_MORE_PARTS != 0,
    };
    let payload = &frame[FRAME_HEADER_BYTES..FRAME_HEADER_BYTES + usize::from(header.payload_len)];
    Ok((header, payload))
}
