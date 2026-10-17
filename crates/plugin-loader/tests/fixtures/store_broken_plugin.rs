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

use busbar_contract::abi::sdk::conn::Host;
use busbar_contract::abi::sdk::store::{
    Cap, CapsRefused, Cell, Grant, Op, OpResult, ReserveRefused, Scanned, Step, StoreSlots, Tail,
};
use busbar_contract::abi::store::OpId;
use busbar_contract::kinds::{Head, RecordBytes};
use busbar_contract::records::{
    AuditRecord, CredentialMeta, CredentialSecret, MeteringDelta, MeteringRow, PlaneRecordRef,
    PlaneSelector, RecordStoreResult, UsageDelta, UsageLedger, VirtualKey,
};

/// Its Statement name.
pub const NAME: &str = "both-ways-store-broken";

/// A store whose `reserve` grants part of a cell.
pub struct HalfGrants;

impl StoreSlots for HalfGrants {
    const TAIL: Tail = Tail {
        ephemeral: true,
        durable_plane: false,
        fork_refusal: true,
    };

    fn validate(_: &[u8]) -> Result<(), String> {
        Ok(())
    }
    fn open(_: &[u8], _: Option<Host>) -> Result<Self, String> {
        Ok(HalfGrants)
    }
    fn add_usage_op(
        &self,
        _: &mut Op<'_>,
        _: OpId,
        _: &str,
        _: u64,
        _: &UsageDelta,
    ) -> Step<OpResult<()>> {
        unreachable!("the broken store's test reaches only open and reserve")
    }
    fn add_metering_op(&self, _: &mut Op<'_>, _: OpId, _: &MeteringDelta) -> Step<OpResult<()>> {
        unreachable!("the broken store's test reaches only open and reserve")
    }
    fn append_audit_op(&self, _: &mut Op<'_>, _: OpId, _: &AuditRecord) -> Step<OpResult<()>> {
        unreachable!("the broken store's test reaches only open and reserve")
    }
    fn append_plane_record_op(
        &self,
        _: &mut Op<'_>,
        _: OpId,
        _: PlaneRecordRef<'_>,
    ) -> Step<OpResult<()>> {
        unreachable!("the broken store's test reaches only open and reserve")
    }
    fn append_batch(
        &self,
        _: &mut Op<'_>,
        _: OpId,
        _: &str,
        _: &[RecordBytes],
    ) -> Step<OpResult<Head>> {
        unreachable!("the broken store's test reaches only open and reserve")
    }
    fn heads(&self, _: &mut Op<'_>) -> Step<Result<Vec<(String, Head)>, String>> {
        unreachable!("the broken store's test reaches only open and reserve")
    }
    fn session_put(&self, _: &mut Op<'_>, _: u64, _: &str, _: &str) -> Step<Result<(), String>> {
        unreachable!("the broken store's test reaches only open and reserve")
    }
    fn session_remove(&self, _: &mut Op<'_>, _: u64) -> Step<Result<(), String>> {
        unreachable!("the broken store's test reaches only open and reserve")
    }
    fn sessions_for(&self, _: &mut Op<'_>, _: &str) -> Step<Result<Vec<(u64, String)>, String>> {
        unreachable!("the broken store's test reaches only open and reserve")
    }
    fn record_put(&self, _: &mut Op<'_>, _: &str, _: &[u8], _: &[u8]) -> Step<Result<(), String>> {
        unreachable!("the broken store's test reaches only open and reserve")
    }
    fn record_get(
        &self,
        _: &mut Op<'_>,
        _: &str,
        _: &[u8],
    ) -> Step<Result<Option<RecordBytes>, String>> {
        unreachable!("the broken store's test reaches only open and reserve")
    }
    fn record_scan(
        &self,
        _: &mut Op<'_>,
        _: &str,
        _: &[u8],
        _: u32,
    ) -> Step<Result<Scanned, String>> {
        unreachable!("the broken store's test reaches only open and reserve")
    }
    fn reserve<'c>(
        &self,
        _: &mut Op<'_>,
        _: OpId,
        _: u64,
        cells: impl Iterator<Item = Cell<'c>> + Clone,
        grants: &mut impl Extend<Grant>,
    ) -> Step<Result<(), ReserveRefused>> {
        // THE BREAK: half of each cell, never its whole amount.
        grants.extend(cells.enumerate().map(|(i, c)| Grant {
            slice_id: i as u64 + 1,
            granted: c.amount / 2,
            valid_until_ms: u64::MAX,
        }));
        Step::Ready(Ok(()))
    }
    fn slice_release(
        &self,
        _: &mut Op<'_>,
        _: OpId,
        _: u64,
        _: impl Iterator<Item = (u64, u64)> + Clone,
        _: &mut impl Extend<u64>,
    ) -> Step<OpResult<()>> {
        unreachable!("the broken store's test reaches only open and reserve")
    }
    fn add_usage_batch(
        &self,
        _: &mut Op<'_>,
        _: OpId,
        _: &[(&str, u64, UsageDelta)],
    ) -> Step<OpResult<()>> {
        unreachable!("the broken store's test reaches only open and reserve")
    }
    fn add_metering_batch(
        &self,
        _: &mut Op<'_>,
        _: OpId,
        _: &[MeteringDelta],
    ) -> Step<OpResult<()>> {
        unreachable!("the broken store's test reaches only open and reserve")
    }
    fn append_audit_batch(&self, _: &mut Op<'_>, _: OpId, _: &[AuditRecord]) -> Step<OpResult<()>> {
        unreachable!("the broken store's test reaches only open and reserve")
    }
    fn window_caps(&self, _: &mut Op<'_>, _: OpId, _: &[Cap<'_>]) -> Step<Result<(), CapsRefused>> {
        unreachable!("the broken store's test reaches only open and reserve")
    }
    fn put_key(&self, _: &mut Op<'_>, _: &VirtualKey) -> Step<RecordStoreResult<()>> {
        unreachable!("the broken store's test reaches only open and reserve")
    }
    fn get_key(&self, _: &mut Op<'_>, _: &str) -> Step<RecordStoreResult<Option<VirtualKey>>> {
        unreachable!("the broken store's test reaches only open and reserve")
    }
    fn list_keys(&self, _: &mut Op<'_>) -> Step<RecordStoreResult<Vec<VirtualKey>>> {
        unreachable!("the broken store's test reaches only open and reserve")
    }
    fn delete_key(&self, _: &mut Op<'_>, _: &str) -> Step<RecordStoreResult<()>> {
        unreachable!("the broken store's test reaches only open and reserve")
    }
    fn scrub_key(&self, _: &mut Op<'_>, _: &str) -> Step<RecordStoreResult<()>> {
        unreachable!("the broken store's test reaches only open and reserve")
    }
    fn list_keys_since(&self, _: &mut Op<'_>, _: u64) -> Step<RecordStoreResult<Vec<VirtualKey>>> {
        unreachable!("the broken store's test reaches only open and reserve")
    }
    fn get_usage(&self, _: &mut Op<'_>, _: &str, _: u64) -> Step<RecordStoreResult<UsageLedger>> {
        unreachable!("the broken store's test reaches only open and reserve")
    }
    fn put_usage(
        &self,
        _: &mut Op<'_>,
        _: &str,
        _: u64,
        _: &UsageLedger,
    ) -> Step<RecordStoreResult<()>> {
        unreachable!("the broken store's test reaches only open and reserve")
    }
    fn list_metering(&self, _: &mut Op<'_>, _: u64) -> Step<RecordStoreResult<Vec<MeteringRow>>> {
        unreachable!("the broken store's test reaches only open and reserve")
    }
    fn purge_windows_before(&self, _: &mut Op<'_>, _: u64) -> Step<RecordStoreResult<u64>> {
        unreachable!("the broken store's test reaches only open and reserve")
    }
    fn purge_metering_before(&self, _: &mut Op<'_>, _: &str) -> Step<RecordStoreResult<u64>> {
        unreachable!("the broken store's test reaches only open and reserve")
    }
    fn put_credential(&self, _: &mut Op<'_>, _: &CredentialSecret) -> Step<RecordStoreResult<()>> {
        unreachable!("the broken store's test reaches only open and reserve")
    }
    fn put_key_with_credential(
        &self,
        _: &mut Op<'_>,
        _: &VirtualKey,
        _: &CredentialSecret,
    ) -> Step<RecordStoreResult<()>> {
        unreachable!("the broken store's test reaches only open and reserve")
    }
    fn list_credentials(
        &self,
        _: &mut Op<'_>,
        _: &str,
    ) -> Step<RecordStoreResult<Vec<CredentialMeta>>> {
        unreachable!("the broken store's test reaches only open and reserve")
    }
    fn lookup_credential_secret(
        &self,
        _: &mut Op<'_>,
        _: &str,
        _: &str,
    ) -> Step<RecordStoreResult<Option<CredentialSecret>>> {
        unreachable!("the broken store's test reaches only open and reserve")
    }
    fn revoke_credential(&self, _: &mut Op<'_>, _: &str, _: &str) -> Step<RecordStoreResult<()>> {
        unreachable!("the broken store's test reaches only open and reserve")
    }
    fn list_credentials_since(
        &self,
        _: &mut Op<'_>,
        _: u64,
    ) -> Step<RecordStoreResult<Vec<CredentialSecret>>> {
        unreachable!("the broken store's test reaches only open and reserve")
    }
    fn list_audit(&self, _: &mut Op<'_>) -> Step<RecordStoreResult<Vec<AuditRecord>>> {
        unreachable!("the broken store's test reaches only open and reserve")
    }
    fn add_denylist(&self, _: &mut Op<'_>, _: &str, _: &str) -> Step<RecordStoreResult<()>> {
        unreachable!("the broken store's test reaches only open and reserve")
    }
    fn list_denylist(&self, _: &mut Op<'_>) -> Step<RecordStoreResult<Vec<String>>> {
        unreachable!("the broken store's test reaches only open and reserve")
    }
    fn list_audit_tail(&self, _: &mut Op<'_>, _: u64) -> Step<RecordStoreResult<Vec<AuditRecord>>> {
        unreachable!("the broken store's test reaches only open and reserve")
    }
    fn upsert_plane_record(
        &self,
        _: &mut Op<'_>,
        _: PlaneRecordRef<'_>,
    ) -> Step<RecordStoreResult<()>> {
        unreachable!("the broken store's test reaches only open and reserve")
    }
    fn get_plane_record(
        &self,
        _: &mut Op<'_>,
        _: &str,
        _: &str,
    ) -> Step<RecordStoreResult<Option<Vec<u8>>>> {
        unreachable!("the broken store's test reaches only open and reserve")
    }
    fn list_plane_records(
        &self,
        _: &mut Op<'_>,
        _: &str,
        _: &PlaneSelector<'_>,
    ) -> Step<RecordStoreResult<Vec<Vec<u8>>>> {
        unreachable!("the broken store's test reaches only open and reserve")
    }
    fn list_plane_record_parents(
        &self,
        _: &mut Op<'_>,
        _: &str,
    ) -> Step<RecordStoreResult<Vec<String>>> {
        unreachable!("the broken store's test reaches only open and reserve")
    }
    fn purge_plane_records_before(
        &self,
        _: &mut Op<'_>,
        _: &str,
        _: u64,
    ) -> Step<RecordStoreResult<u64>> {
        unreachable!("the broken store's test reaches only open and reserve")
    }
    fn delete_plane_record(&self, _: &mut Op<'_>, _: &str, _: &str) -> Step<RecordStoreResult<()>> {
        unreachable!("the broken store's test reaches only open and reserve")
    }
    fn redeem_plane_token(
        &self,
        _: &mut Op<'_>,
        _: &str,
        _: &str,
        _: u64,
        _: u64,
    ) -> Step<RecordStoreResult<bool>> {
        unreachable!("the broken store's test reaches only open and reserve")
    }
    fn plane_token_live(
        &self,
        _: &mut Op<'_>,
        _: &str,
        _: &str,
        _: u64,
        _: u64,
    ) -> Step<RecordStoreResult<bool>> {
        unreachable!("the broken store's test reaches only open and reserve")
    }
}

busbar_contract::store_door!(HalfGrants, NAME, "1.6.0", 8);
