// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE LEDGER'S WRITES: the operation id and the two coalesced count batches. A store keeps COUNTS
//! only; every money figure is derived in core as counts x the dated rate card. No slot here
//! carries a price, a balance, a reservation, an epoch fence or a cap.
//!
//! DEDUPE, the same on every slot here: the module rule in [`super`] ("Dedupe", S1-S5): a replay
//! with the same value fields applies nothing and returns the ORIGINAL `out`; different value
//! fields are REFUSED with [`super::DIAG_OPID_CONFLICT`]; only a READY that applied a change is
//! recorded.

use crate::abi::mechanism::call::{AbiStr, Blob, InHead};
use crate::abi::mechanism::decl::abi_struct;

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

abi_struct! {
    /// One cell of the token ledger and its signed delta: the fixed (bucket, window) plus the tree's
    /// `UsageDelta` shape as a JSON blob with the #81 scale discriminator (B.1 "Record blobs").
    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    pub struct UsageCell {
        /// The bucket id (a key's own bucket or a budget-group bucket).
        pub bucket: AbiStr,
        /// The window start.
        pub window_start: u64,
        /// The `UsageDelta`.
        pub delta: Blob,
    }

    /// `add_usage_batch`'s `in`. Off path, may pend, [`DeadlineClass::WriteBehind`](crate::abi::mechanism::call::DeadlineClass::WriteBehind).
    /// ONE `op_id` per coalesced batch; the cells apply in batch order, atomically per batch.
    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    pub struct AddUsageBatchIn {
        /// The head.
        pub head: InHead,
        /// The kernel-minted id of this batch.
        pub op_id: OpId,
        /// The cells, in batch order.
        pub cells: *const UsageCell,
        /// How many.
        pub cells_len: usize,
    }

    /// `add_metering_batch`'s `in`: ONE `op_id` per coalesced batch and the `MeteringDelta`s in batch
    /// order (the tree's shape with the scale discriminator), applied in order, atomically per batch. Off path, may pend,
    /// [`DeadlineClass::WriteBehind`](crate::abi::mechanism::call::DeadlineClass::WriteBehind).
    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    pub struct OpBlobsIn {
        /// The head.
        pub head: InHead,
        /// The kernel-minted id of this batch.
        pub op_id: OpId,
        /// The records, in batch order.
        pub records: *const Blob,
        /// How many.
        pub records_len: usize,
    }
}
