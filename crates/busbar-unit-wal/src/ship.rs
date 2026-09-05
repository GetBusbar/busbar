// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Getting records off the node, behind a trait.
//!
//! Shipping is batched at the segment level and un-acked records are never overwritten. Which store
//! that is, and how it acknowledges, is not this crate's business — a log that knew the name of a
//! database would be a log with an opinion about deployments.
//!
//! The mode difference is the whole reason this seam is on the write path rather than a background
//! chore. When a node has a data directory, the local log is the record and shipping is catching-up
//! work. When it does not, the local buffer is a staging area and the STORE is where durability
//! comes from, so a batch is shipped synchronously as part of committing it and a shipping failure
//! is a durability failure. Same trait, two postures, both stated out loud.

use crate::record::Record;

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
pub trait Shipper: Send {
    /// Offer one batch. Returning `Ok` is the acknowledgement; returning an error means the batch
    /// is still owed and will be offered again.
    fn ship(&mut self, records: &[Record]) -> Result<(), ShipError>;
}

/// A shipper that acknowledges everything and keeps nothing.
///
/// The right default for a node whose data directory IS the record of what happened, and the right
/// thing to configure deliberately on a node that is measuring the log rather than keeping it.
#[derive(Debug, Default)]
pub struct NullShipper {
    shipped: u64,
}

impl NullShipper {
    /// A fresh one.
    pub fn new() -> Self {
        NullShipper::default()
    }

    /// How many records it has acknowledged.
    pub fn shipped(&self) -> u64 {
        self.shipped
    }
}

impl Shipper for NullShipper {
    fn ship(&mut self, records: &[Record]) -> Result<(), ShipError> {
        self.shipped += records.len() as u64;
        Ok(())
    }
}

/// A shipper that keeps every record it was handed, in order.
///
/// This is what a memory-buffered node's "store" looks like when the store is itself in memory: the
/// records are the system of record for exactly as long as the process lives, and the crate says so
/// rather than implying more.
///
/// The records are held behind a shared handle so that whoever configured the shipper can still see
/// what reached it after handing ownership to the log.
#[derive(Debug, Default, Clone)]
pub struct BufferShipper {
    records: std::sync::Arc<std::sync::Mutex<Vec<Record>>>,
}

impl BufferShipper {
    /// A fresh one.
    pub fn new() -> Self {
        BufferShipper::default()
    }

    /// A snapshot of everything shipped so far, in order.
    pub fn records(&self) -> Vec<Record> {
        self.records
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

impl Shipper for BufferShipper {
    fn ship(&mut self, records: &[Record]) -> Result<(), ShipError> {
        self.records
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .extend_from_slice(records);
        Ok(())
    }
}
