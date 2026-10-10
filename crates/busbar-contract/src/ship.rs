// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Getting the log's records off the node, behind a trait.
//!
//! Shipping is batched at the segment level and un-acked records are never overwritten. Which store
//! that is, and how it acknowledges, is not the log's business — a log that knew the name of a
//! database would be a log with an opinion about deployments.
//!
//! The mode difference is the whole reason this seam is on the write path rather than a background
//! chore. When a node has a data directory, the local log is the record and shipping is catching-up
//! work. When it does not, the local buffer is a staging area and the STORE is where durability
//! comes from, so a batch is shipped synchronously as part of committing it and a shipping failure
//! is a durability failure. Same trait, two postures, both stated out loud.
//!
//! The seam is the contract's because the store adapter implements it on the other side of it (the
//! same division as `slice::SliceStore`). The record and its framing stay with the log; a shipper
//! is generic over the record and sees it through [`ShippedRecord`] alone.

/// What a shipper may know of one record: its identity, the pair a re-appended batch is
/// deduplicated on.
pub trait ShippedRecord {
    /// Which node wrote it, and that node's own sequence number for it.
    fn identity(&self) -> (u64, u64);
}

/// Why a batch could not be shipped.
#[derive(Debug)]
pub enum ShipError {
    /// The store could not be reached, or refused the batch. The records are retained and offered
    /// again; nothing un-acked is ever overwritten.
    Unavailable(String),
}

impl std::fmt::Display for ShipError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ShipError::Unavailable(why) => write!(f, "the store did not take the batch: {why}"),
        }
    }
}

impl std::error::Error for ShipError {}

/// Where records go once they are committed locally.
pub trait Shipper<R>: Send {
    /// Offer one batch. Returning `Ok` is the acknowledgement; returning an error means the batch
    /// is still owed and will be offered again.
    fn ship(&mut self, records: &[R]) -> Result<(), ShipError>;
}
