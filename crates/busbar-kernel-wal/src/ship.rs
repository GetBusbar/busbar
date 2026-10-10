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
