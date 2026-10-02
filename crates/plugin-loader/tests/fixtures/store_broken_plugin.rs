// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE STORE KIND'S BROKEN BOTH-WAYS FIXTURE, built with its kind's SDK door (`store_door!`): a
//! store that opens, and whose `reserve` grants HALF of each cell's amount. The store kind's
//! contract is whole-or-nothing (`check_reserve`: a READY grant is the cell's whole amount), so
//! the host must answer FAULT, through either door.
//!
//! One source, compiled into plugin-loader's test build as a module (the LINKED door) and built
//! as the `store_broken_door` example `cdylib` behind one `export_door!` line (the DROPPED door).
//! No other slot is reached by the test that drives it.
#![allow(dead_code)]

use busbar_contract::abi::sdk::store::{
    Cap, CapsRefused, Cell, Grant, OpResult, ReserveRefused, StoreSlots, Tail,
};
use busbar_contract::abi::store::OpId;
use busbar_contract::kinds::{Head, RecordBytes};
use busbar_contract::records::{
    AuditRecord, MeteringDelta, MeteringRow, PlaneRecordRef, RecordStore, RecordStoreResult,
    UsageDelta, UsageLedger, VirtualKey,
};

/// Its Statement name.
pub const NAME: &str = "both-ways-store-broken";

/// A store whose `reserve` grants part of a cell.
pub struct HalfGrants;

/// Every slot the RED arm never reaches.
macro_rules! unreached {
    ($($name:ident(&self $(, $a:ident: $t:ty)*) -> $r:ty;)*) => {$(
        fn $name(&self $(, $a: $t)*) -> $r {
            $(let _ = $a;)*
            unreachable!("the broken store's test reaches only open and reserve")
        }
    )*};
}

impl RecordStore for HalfGrants {
    unreached! {
        put_key(&self, key: &VirtualKey) -> RecordStoreResult<()>;
        get_key(&self, id: &str) -> RecordStoreResult<Option<VirtualKey>>;
        list_keys(&self) -> RecordStoreResult<Vec<VirtualKey>>;
        delete_key(&self, id: &str) -> RecordStoreResult<()>;
        get_usage(&self, bucket: &str, window_start: u64) -> RecordStoreResult<UsageLedger>;
        put_usage(&self, bucket: &str, window_start: u64, ledger: &UsageLedger)
            -> RecordStoreResult<()>;
        add_metering(&self, delta: &MeteringDelta) -> RecordStoreResult<()>;
        list_metering(&self, bucket: u64) -> RecordStoreResult<Vec<MeteringRow>>;
    }
}

impl StoreSlots for HalfGrants {
    const TAIL: Tail = Tail {
        ephemeral: true,
        durable_plane: false,
        fork_refusal: true,
    };

    fn open(_: &[u8]) -> Result<Self, String> {
        Ok(HalfGrants)
    }

    unreached! {
        add_usage_op(&self, op: OpId, bucket: &str, window_start: u64, delta: &UsageDelta)
            -> OpResult<()>;
        add_metering_op(&self, op: OpId, delta: &MeteringDelta) -> OpResult<()>;
        append_audit_op(&self, op: OpId, entry: &AuditRecord) -> OpResult<()>;
        append_plane_record_op(&self, op: OpId, record: PlaneRecordRef<'_>) -> OpResult<()>;
        append_batch(&self, op: OpId, stream: &str, records: &[RecordBytes]) -> OpResult<Head>;
        heads(&self) -> Result<Vec<(String, Head)>, String>;
        session_put(&self, session: u64, node: &str, principal: &str) -> Result<(), String>;
        session_remove(&self, session: u64) -> Result<(), String>;
        sessions_for(&self, principal: &str) -> Result<Vec<(u64, String)>, String>;
        record_put(&self, schema: &str, key: &[u8], value: &[u8]) -> Result<(), String>;
        record_get(&self, schema: &str, key: &[u8]) -> Result<Option<RecordBytes>, String>;
        record_scan(&self, schema: &str, prefix: &[u8], limit: u32)
            -> Result<Vec<(Vec<u8>, RecordBytes)>, String>;
        add_usage_batch(&self, op: OpId, cells: &[(&str, u64, UsageDelta)]) -> OpResult<()>;
        add_metering_batch(&self, op: OpId, deltas: &[MeteringDelta]) -> OpResult<()>;
        append_audit_batch(&self, op: OpId, entries: &[AuditRecord]) -> OpResult<()>;
        window_caps(&self, op: OpId, caps: &[Cap<'_>]) -> Result<(), CapsRefused>;
    }

    /// THE BREAK: half of each cell, never its whole amount.
    fn reserve<'c>(
        &self,
        _: OpId,
        _: u64,
        cells: impl Iterator<Item = Cell<'c>> + Clone,
        grants: &mut impl Extend<Grant>,
    ) -> Result<(), ReserveRefused> {
        grants.extend(cells.enumerate().map(|(i, c)| Grant {
            slice_id: i as u64 + 1,
            granted: c.amount / 2,
            valid_until_ms: u64::MAX,
        }));
        Ok(())
    }

    fn slice_release(
        &self,
        op: OpId,
        epoch: u64,
        items: impl Iterator<Item = (u64, u64)> + Clone,
        released: &mut impl Extend<u64>,
    ) -> OpResult<()> {
        let _ = (op, epoch, items, released);
        unreachable!("the broken store's test reaches only open and reserve")
    }
}

busbar_contract::store_door!(HalfGrants, NAME, "1.6.0", 8);
