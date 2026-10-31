// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A STORE THAT NEVER PENDS, SERVED WHOLE: a store whose every op answers at once (in RAM, or on a
//! local disk the host runs on its bounded disk lane) implements the 1.5.5 op set once, as its
//! [`RecordStore`], and states only what the store v3 table adds beyond it here ([`SyncStore`]).
//! The SDK serves it as a [`StoreSlots`]: every slot answers [`Step::Ready`] with the store's own
//! answer, its [`Op`] untouched, and the connect step reaches nothing. No store writes the
//! forwarding itself.

use super::{OpResult, Scanned, Step, StoreSlots, Tail};
use crate::abi::sdk::conn::Host;
use crate::abi::sdk::store::Op;
use crate::abi::store::OpId;
use crate::kinds::RecordBytes;
use crate::records::{
    AuditRecord, CredentialMeta, CredentialSecret, MeteringDelta, MeteringRow, PlaneRecordRef,
    PlaneSelector, RecordStore, RecordStoreResult, Retention, UsageDelta, UsageLedger, VirtualKey,
};

/// What a never-pending store states beyond its [`RecordStore`]: the [`StoreSlots`] items the
/// 1.5.5 op set has no counterpart for, each answered at once.
pub trait SyncStore: RecordStore + Sized + Send + Sync + 'static {
    /// [`StoreSlots::TAIL`].
    const TAIL: Tail;

    /// [`StoreSlots::validate`].
    ///
    /// # Errors
    /// The store's own refusal text.
    fn validate(settings: &[u8]) -> Result<(), String>;

    /// [`StoreSlots::open`].
    ///
    /// # Errors
    /// Why the settings do not open a store.
    fn open(settings: &[u8], host: Option<Host>) -> Result<Self, String>;

    /// [`StoreSlots::open_with_secrets`], defaulting to opening without declared secrets.
    ///
    /// # Errors
    /// Why the settings do not open a store.
    fn open_with_secrets(
        settings: &[u8],
        secrets: &[&[u8]],
        host: Option<Host>,
    ) -> Result<Self, String> {
        let _ = secrets;
        Self::open(settings, host)
    }

    /// [`StoreSlots::purge_usage_before`], refused when the backend does not implement it.
    ///
    /// # Errors
    /// The backend's refusal.
    fn purge_usage_before(&self, before: u64) -> RecordStoreResult<u64> {
        let _ = before;
        Err(crate::records::RecordStoreError(
            super::PURGE_USAGE_UNSUPPORTED.to_string(),
        ))
    }

    /// [`StoreSlots::append_plane_record_op`].
    ///
    /// # Errors
    /// [`OpRefused`](super::OpRefused).
    fn append_plane_record_op(&self, op: OpId, record: PlaneRecordRef<'_>) -> OpResult<()>;

    /// [`StoreSlots::record_put`].
    ///
    /// # Errors
    /// A backend text.
    fn record_put(&self, schema: &str, key: &[u8], value: &[u8]) -> Result<(), String>;

    /// [`StoreSlots::record_get`].
    ///
    /// # Errors
    /// A backend text.
    fn record_get(&self, schema: &str, key: &[u8]) -> Result<Option<RecordBytes>, String>;

    /// [`StoreSlots::record_scan`].
    ///
    /// # Errors
    /// A backend text.
    fn record_scan(&self, schema: &str, prefix: &[u8], limit: u32) -> Result<Scanned, String>;

    /// [`StoreSlots::add_usage_batch`].
    ///
    /// # Errors
    /// [`OpRefused`](super::OpRefused).
    fn add_usage_batch(&self, op: OpId, cells: &[(&str, u64, UsageDelta)]) -> OpResult<()>;

    /// [`StoreSlots::add_metering_batch`].
    ///
    /// # Errors
    /// [`OpRefused`](super::OpRefused).
    fn add_metering_batch(&self, op: OpId, deltas: &[MeteringDelta]) -> OpResult<()>;
}

/// Each 1.5.5 slot as its [`RecordStore`] method, answered at once.
macro_rules! ready {
    ($($name:ident($($arg:ident: $ty:ty),*) -> $out:ty;)*) => {$(
        fn $name(&self, _: &mut Op<'_>, $($arg: $ty),*) -> Step<RecordStoreResult<$out>> {
            Step::Ready(RecordStore::$name(self, $($arg),*))
        }
    )*};
}

/// Each v3 addition as its [`SyncStore`] method, answered at once.
macro_rules! extra {
    ($($name:ident($($arg:ident: $ty:ty),*) -> $out:ty;)*) => {$(
        fn $name(&self, _: &mut Op<'_>, $($arg: $ty),*) -> Step<$out> {
            Step::Ready(<T as SyncStore>::$name(self, $($arg),*))
        }
    )*};
}

impl<T: SyncStore> StoreSlots for T {
    const TAIL: Tail = <T as SyncStore>::TAIL;

    fn validate(settings: &[u8]) -> Result<(), String> {
        <T as SyncStore>::validate(settings)
    }

    fn open(settings: &[u8], host: Option<Host>) -> Result<Self, String> {
        <T as SyncStore>::open(settings, host)
    }

    fn open_with_secrets(
        settings: &[u8],
        secrets: &[&[u8]],
        host: Option<Host>,
    ) -> Result<Self, String> {
        <T as SyncStore>::open_with_secrets(settings, secrets, host)
    }

    extra! {
        purge_usage_before(before: u64) -> RecordStoreResult<u64>;
        append_plane_record_op(op: OpId, record: PlaneRecordRef<'_>) -> OpResult<()>;
        record_put(schema: &str, key: &[u8], value: &[u8]) -> Result<(), String>;
        record_get(schema: &str, key: &[u8]) -> Result<Option<RecordBytes>, String>;
        record_scan(schema: &str, prefix: &[u8], limit: u32) -> Result<Scanned, String>;
        add_usage_batch(op: OpId, cells: &[(&str, u64, UsageDelta)]) -> OpResult<()>;
        add_metering_batch(op: OpId, deltas: &[MeteringDelta]) -> OpResult<()>;
    }

    ready! {
        put_key(key: &VirtualKey) -> ();
        get_key(id: &str) -> Option<VirtualKey>;
        list_keys() -> Vec<VirtualKey>;
        delete_key(id: &str) -> ();
        list_keys_since(since: u64) -> Vec<VirtualKey>;
        get_usage(bucket_id: &str, window_start: u64) -> UsageLedger;
        put_usage(bucket_id: &str, window_start: u64, ledger: &UsageLedger) -> ();
        list_metering(bucket: u64) -> Vec<MeteringRow>;
        put_credential(secret: &CredentialSecret) -> ();
        put_key_with_credential(key: &VirtualKey, secret: &CredentialSecret) -> ();
        list_credentials(key_id: &str) -> Vec<CredentialMeta>;
        revoke_credential(id: &str, reason: &str) -> ();
        list_credentials_since(since: u64) -> Vec<CredentialSecret>;
        list_audit() -> Vec<AuditRecord>;
        add_denylist(sub: &str, reason: &str) -> ();
        list_denylist() -> Vec<String>;
        list_audit_tail(limit: u64) -> Vec<AuditRecord>;
        upsert_plane_record(record: PlaneRecordRef<'_>) -> ();
        get_plane_record(kind: &str, id: &str) -> Option<Vec<u8>>;
        list_plane_records(kind: &str, selector: &PlaneSelector<'_>) -> Vec<Vec<u8>>;
        list_plane_record_parents(kind: &str) -> Vec<String>;
        purge_plane_records_before(kind: &str, before: u64) -> u64;
        purge_plane_records(kind: &str, before: u64, retention: Retention) -> u64;
        delete_plane_record(kind: &str, id: &str) -> ();
        redeem_plane_token(kind: &str, token: &str, expires_at: u64, now: u64) -> bool;
        plane_token_live(kind: &str, token: &str, expires_at: u64, now: u64) -> bool;
    }
}
