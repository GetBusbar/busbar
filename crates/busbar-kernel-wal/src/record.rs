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
}

/// A finished SHA-256 (ring, the one crypto backend) as the 32 bytes the journal stores.
pub(crate) fn digest32(hasher: Context) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(hasher.finish().as_ref());
    out
}
