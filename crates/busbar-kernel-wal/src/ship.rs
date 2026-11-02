// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Getting the log's records off the node, behind a trait.

use crate::record::Record;

/// What a shipper may know of one record: its identity, the pair a re-appended batch is

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

    fn ship(&mut self, records: &[R]) -> Result<(), ShipError>;
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

impl Shipper<Record> for NullShipper {
    fn ship(&mut self, records: &[Record]) -> Result<(), ShipError> {
        self.shipped += records.len() as u64;
        Ok(())
    }
}
