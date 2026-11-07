// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Opaque operation identity shared by core records and kind ABIs.

/// An operation id: 16 bytes, the minting node's id (bytes 0..8) then that node's monotonic
/// counter (bytes 8..16), both little-endian. Minted by the KERNEL, one per batch. A store treats
/// it as opaque bytes and dedupes on it.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OpId(pub [u8; 16]);

impl OpId {
    /// The id for `(node, counter)`.
    #[must_use]
    pub const fn from_parts(node: u64, counter: u64) -> Self {
        let n = node.to_le_bytes();
        let c = counter.to_le_bytes();
        Self([
            n[0], n[1], n[2], n[3], n[4], n[5], n[6], n[7], c[0], c[1], c[2], c[3], c[4], c[5],
            c[6], c[7],
        ])
    }

    /// The minting node's id.
    #[must_use]
    pub const fn node(self) -> u64 {
        let b = self.0;
        u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
    }

    /// The node's counter.
    #[must_use]
    pub const fn counter(self) -> u64 {
        let b = self.0;
        u64::from_le_bytes([b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]])
    }
}
