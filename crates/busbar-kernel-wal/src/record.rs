// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The record envelope a store hands the journal back in.

use ring::digest::Context;

/// One record as a store hands it back: who wrote it, that writer's own sequence number, and the
/// bytes of the journal record.
///
/// The envelope has no opinion about what is inside `body`. Its job is that the bytes come back
/// exactly as they went in.
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
    pub fn new(node: u64, node_seq: u64, body: Vec<u8>) -> Self {
        Record {
            node,
            node_seq,
            body,
        }
    }

    /// The identity a re-append is deduplicated on.
    pub fn identity(&self) -> (u64, u64) {
        (self.node, self.node_seq)
    }

    /// How many frames this record occupies. A record with an empty body still takes one, so that
    pub fn frame_count(&self) -> usize {
        if self.body.is_empty() {
            1
        } else {
            self.body.len().div_ceil(FRAME_PAYLOAD_BYTES)
        }
    }

    /// Frame this record, in order. Every frame is fully written, including the zero padding after
    pub fn encode(&self) -> Vec<[u8; FRAME_BYTES]> {
        self.encode_in_commit(false)
    }

    /// Frame this record as a group commit puts it down: when `opens_commit`, its first frame is
    pub fn encode_in_commit(&self, opens_commit: bool) -> Vec<[u8; FRAME_BYTES]> {
        let mut frames = vec![[0u8; FRAME_BYTES]; self.frame_count()];
        for (index, slot) in frames.iter_mut().enumerate() {
            *slot = self.frame(index, opens_commit);
        }
        frames
    }

    /// Append this record's frames, as a group commit puts them down, to `out`.
    pub fn encode_in_commit_into(&self, opens_commit: bool, out: &mut Vec<u8>) {
        let parts = self.frame_count();
        out.reserve(parts * FRAME_BYTES);
        for index in 0..parts {
            out.extend_from_slice(&self.frame(index, opens_commit));
        }
    }

    /// Frame `index` of this record.
    fn frame(&self, index: usize, opens_commit: bool) -> [u8; FRAME_BYTES] {
        let parts = self.frame_count();
        let start = index * FRAME_PAYLOAD_BYTES;
        let end = usize::min(start + FRAME_PAYLOAD_BYTES, self.body.len());
        let payload = if start < self.body.len() {
            &self.body[start..end]
        } else {
            &[][..]
        };
        encode_frame(
            self.node,
            self.node_seq,
            index as u32,
            parts as u32,
            opens_commit && index == 0,
            payload,
        )
    }
}

/// A finished SHA-256 (ring, the one crypto backend) as the 32 bytes the journal stores.
pub(crate) fn digest32(hasher: Context) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(hasher.finish().as_ref());
    out
}
