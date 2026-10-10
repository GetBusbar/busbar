// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The log's shippers. The seam itself — [`Shipper`], [`ShipError`] — is the contract's, because the
//! store adapter implements it on the other side of it; the log ships its own [`Record`]s through it.

use crate::record::Record;

pub use busbar_contract::ship::{ShipError, ShippedRecord, Shipper};

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

impl Shipper<Record> for NullShipper {
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

impl Shipper<Record> for BufferShipper {
    fn ship(&mut self, records: &[Record]) -> Result<(), ShipError> {
        self.records
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .extend_from_slice(records);
        Ok(())
    }
}
