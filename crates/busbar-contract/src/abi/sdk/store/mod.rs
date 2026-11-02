// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE STORE KIND'S TYPED SDK (THE DESIGN, the plugin ABI; ABI-b3, the SDK's typed wrappers):

pub mod conditional;
pub mod correction;
pub mod door;

pub mod dedupe;
pub mod fork;
pub mod rewrap;
pub mod wire;

pub mod column;

use crate::abi::sdk::conn::Host;
use crate::abi::store::OpId;
use crate::kinds::RecordBytes;
use crate::records::{
    AuditRecord, CredentialMeta, CredentialSecret, MeteringDelta, MeteringRow, PlaneRecordRef,
    PlaneSelector, RecordStoreResult, Retention, UsageDelta, UsageLedger, VirtualKey,
};

mod op;
pub use op::{Checkout, Op, Services, Step};

mod sync_store;
pub use sync_store::SyncStore;

/// What a store that does not implement [`StoreSlots::purge_usage_before`] answers.
pub const PURGE_USAGE_UNSUPPORTED: &str =
    "this store does not purge usage windows (StoreSlots::purge_usage_before is not implemented)";

/// What `record_scan` answers: `(key, record)` in key order.
pub type Scanned = Vec<(Vec<u8>, RecordBytes)>;

/// Why an `op_id`-carrying write answered without applying anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpRefused {
    /// The same `op_id` arrived with different value fields: REFUSED with
    /// [`DIAG_OPID_CONFLICT`](crate::abi::store::DIAG_OPID_CONFLICT), nothing applied.
    Conflict,
    /// The write could not be applied (a fork at a used `seq`, a backend error): FAILED with this
    /// text, nothing applied, nothing recorded under the `op_id`. A host cannot tell a backend error
    /// from a commit whose answer was lost, so it replays the same `op_id` (S5); a fork it never
    /// replays.
    Failed(String),
    /// The write was decided before commit and refused (a value its columns cannot hold, a
    /// constraint, a script error before any write): REFUSED with this text, PROVABLY nothing
    /// applied and nothing recorded under the `op_id` (S3, S5). A host may split or re-send the
    /// write under a new `op_id`.
    Refused(String),
}

/// An `op_id`-carrying write's answer.
pub type OpResult<T> = Result<T, OpRefused>;

/// What a store states about itself: `ephemeral` as the Statement mark `MARK_EPHEMERAL`, the rest
/// in its Statement tail (`abi::store::StoreTail`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tail {
    /// What it holds is lost on restart (the Statement mark `MARK_EPHEMERAL`).
    pub ephemeral: bool,
    /// It holds plane records durably.
    pub durable_plane: bool,
    /// A different record at a used `seq` is refused as a fork.
    pub fork_refusal: bool,
}

/// A store plugin, as the store v3 table serves it. Every method is required: the table has no
pub trait StoreSlots: Sized + Send + Sync + 'static {
    /// What this store states in its Statement tail.
    const TAIL: Tail;

    /// Explicit opt-in to the atomic conditional-record protocol. Never enabled by default.
    const RECORD_TRANSACTION: bool = false;

    /// Explicit opt-in to atomic raw-usage corrections; ordinary additive writes cannot emulate it.
    const USAGE_CORRECTION: bool = false;

    /// Compare the live key, complete metering selection and exact usage rows against one
    fn apply_usage_correction(
        &self,
        cx: &mut Op<'_>,
        request: &correction::Request,
    ) -> Step<OpResult<correction::Decision>> {
        let _ = (cx, request);
        Step::Ready(Err(OpRefused::Refused(
            "usage corrections unsupported".into(),
        )))
    }

    /// Compare all predicates against one pre-state, then atomically mutate records and record
    fn record_transaction(
        &self,
        cx: &mut Op<'_>,
        request: &conditional::Request,
    ) -> Step<OpResult<conditional::Decision>> {
        let _ = (cx, request);
        Step::Ready(Err(OpRefused::Refused(
            "record transactions unsupported".into(),
        )))
    }

    /// PARSE the operator's settings (the section's JSON) and nothing more: `validate` never opens,
    fn validate(settings: &[u8]) -> Result<(), String>;

    /// Open an instance from the operator's settings (the section's JSON) and the host tables
    #[deprecated(
        note = "implement `open_with_secrets`: a declared secret is lent there, not in the settings"
    )]
    fn open(settings: &[u8], host: Option<Host>) -> Result<Self, String> {
        let _ = (settings, host);
        Err(
            "this store implements neither `StoreSlots::open_with_secrets` nor `StoreSlots::open`"
                .to_string(),
        )
    }

    /// Open an instance from the operator's settings, its resolved `secrets` and the host tables
    fn open_with_secrets(
        settings: &[u8],
        secrets: &[&[u8]],
        host: Option<Host>,
    ) -> Result<Self, String> {
        let _ = secrets;
        #[allow(deprecated)]
        Self::open(settings, host)
    }

    /// THE CONNECT STEP of `open`: what the store reaches
    fn connect(&self, cx: &mut Op<'_>) -> Step<Result<(), String>> {
        let _ = cx;
        Step::Ready(Ok(()))
    }

    /// `append_plane_record` (slot 19): [`RecordStore::append_plane_record`], deduped on `op`.
    fn append_plane_record_op(
        &self,
        cx: &mut Op<'_>,
        op: OpId,
        record: PlaneRecordRef<'_>,
    ) -> Step<OpResult<()>>;

    /// `record_put` (slot 26): an upsert on `(schema, key)`. `value` is the host's bytes, borrowed,
    fn record_put(
        &self,
        cx: &mut Op<'_>,
        schema: &str,
        key: &[u8],
        value: &[u8],
    ) -> Step<Result<(), String>>;

    /// `record_get` (slot 27).
    fn record_get(
        &self,
        cx: &mut Op<'_>,
        schema: &str,
        key: &[u8],
    ) -> Step<Result<Option<RecordBytes>, String>>;

    /// `record_scan` (slot 28): at most `limit` records under `prefix`, in key order; `limit` 0 is
    fn record_scan(
        &self,
        cx: &mut Op<'_>,
        schema: &str,
        prefix: &[u8],
        limit: u32,
    ) -> Step<Result<Scanned, String>>;

    /// `add_usage_batch` (slot 29): the cells in order, atomically.
    fn add_usage_batch(
        &self,
        cx: &mut Op<'_>,
        op: OpId,
        cells: &[(&str, u64, UsageDelta)],
    ) -> Step<OpResult<()>>;

    /// `add_metering_batch` (slot 30): the deltas in order, atomically.
    fn add_metering_batch(
        &self,
        cx: &mut Op<'_>,
        op: OpId,
        deltas: &[MeteringDelta],
    ) -> Step<OpResult<()>>;

    /// `put_key` (slot 0): upsert `key` by its id.
    fn put_key(&self, cx: &mut Op<'_>, key: &VirtualKey) -> Step<RecordStoreResult<()>>;

    /// `get_key` (slot 1).
    fn get_key(&self, cx: &mut Op<'_>, id: &str) -> Step<RecordStoreResult<Option<VirtualKey>>>;

    /// `list_keys` (slot 2).
    fn list_keys(&self, cx: &mut Op<'_>) -> Step<RecordStoreResult<Vec<VirtualKey>>>;

    /// `delete_key` (slot 3): tombstone it.
    fn delete_key(&self, cx: &mut Op<'_>, id: &str) -> Step<RecordStoreResult<()>>;

    /// `list_keys_since` (slot 4).
    fn list_keys_since(
        &self,
        cx: &mut Op<'_>,
        since: u64,
    ) -> Step<RecordStoreResult<Vec<VirtualKey>>>;

    /// `get_usage` (slot 5).
    fn get_usage(
        &self,
        cx: &mut Op<'_>,
        bucket_id: &str,
        window_start: u64,
    ) -> Step<RecordStoreResult<UsageLedger>>;

    /// `put_usage` (slot 6).
    fn put_usage(
        &self,
        cx: &mut Op<'_>,
        bucket_id: &str,
        window_start: u64,
        ledger: &UsageLedger,
    ) -> Step<RecordStoreResult<()>>;

    /// `list_metering` (slot 7).
    fn list_metering(
        &self,
        cx: &mut Op<'_>,
        bucket: u64,
    ) -> Step<RecordStoreResult<Vec<MeteringRow>>>;

    /// `put_credential` (slot 8).
    fn put_credential(
        &self,
        cx: &mut Op<'_>,
        secret: &CredentialSecret,
    ) -> Step<RecordStoreResult<()>>;

    /// Update-only envelope CAS, carried by slot 8 with explicit rewrap intent. See
    fn rewrap_credential(
        &self,
        cx: &mut Op<'_>,
        expected: &CredentialSecret,
        replacement: &str,
    ) -> Step<RecordStoreResult<bool>> {
        let _ = (cx, expected, replacement);
        Step::Ready(Err(crate::records::RecordStoreError(
            "this Store does not support credential rewrap CAS".into(),
        )))
    }

    /// `put_key_with_credential` (slot 9): both, atomically.
    fn put_key_with_credential(
        &self,
        cx: &mut Op<'_>,
        key: &VirtualKey,
        secret: &CredentialSecret,
    ) -> Step<RecordStoreResult<()>>;

    /// `list_credentials` (slot 10).
    fn list_credentials(
        &self,
        cx: &mut Op<'_>,
        key_id: &str,
    ) -> Step<RecordStoreResult<Vec<CredentialMeta>>>;

    /// `revoke_credential` (slot 11).
    fn revoke_credential(
        &self,
        cx: &mut Op<'_>,
        id: &str,
        reason: &str,
    ) -> Step<RecordStoreResult<()>>;

    /// `list_credentials_since` (slot 12).
    fn list_credentials_since(
        &self,
        cx: &mut Op<'_>,
        since: u64,
    ) -> Step<RecordStoreResult<Vec<CredentialSecret>>>;

    /// `list_audit` (slot 13).
    fn list_audit(&self, cx: &mut Op<'_>) -> Step<RecordStoreResult<Vec<AuditRecord>>>;

    /// `add_denylist` (slot 14): deny the principal `id`, saying why.
    fn add_denylist(&self, cx: &mut Op<'_>, id: &str, reason: &str) -> Step<RecordStoreResult<()>>;

    /// `list_denylist` (slot 15).
    fn list_denylist(&self, cx: &mut Op<'_>) -> Step<RecordStoreResult<Vec<String>>>;

    /// `list_audit_tail` (slot 16).
    fn list_audit_tail(
        &self,
        cx: &mut Op<'_>,
        limit: u64,
    ) -> Step<RecordStoreResult<Vec<AuditRecord>>>;

    /// `upsert_plane_record` (slot 17).
    fn upsert_plane_record(
        &self,
        cx: &mut Op<'_>,
        record: PlaneRecordRef<'_>,
    ) -> Step<RecordStoreResult<()>>;

    /// `get_plane_record` (slot 18): the body.
    fn get_plane_record(
        &self,
        cx: &mut Op<'_>,
        kind: &str,
        id: &str,
    ) -> Step<RecordStoreResult<Option<Vec<u8>>>>;

    /// `list_plane_records` (slot 20): the bodies.
    fn list_plane_records(
        &self,
        cx: &mut Op<'_>,
        kind: &str,
        selector: &PlaneSelector<'_>,
    ) -> Step<RecordStoreResult<Vec<Vec<u8>>>>;

    /// `list_plane_record_parents` (slot 21).
    fn list_plane_record_parents(
        &self,
        cx: &mut Op<'_>,
        kind: &str,
    ) -> Step<RecordStoreResult<Vec<String>>>;

    /// `purge_plane_records_before` (slot 22) under the age rule.
    fn purge_plane_records_before(
        &self,
        cx: &mut Op<'_>,
        kind: &str,
        before: u64,
    ) -> Step<RecordStoreResult<u64>>;

    /// RETENTION, with the predicate named: slot 22 under the rule its `in` carries
    fn purge_plane_records(
        &self,
        cx: &mut Op<'_>,
        kind: &str,
        before: u64,
        retention: Retention,
    ) -> Step<RecordStoreResult<u64>> {
        match retention {
            Retention::Age => self.purge_plane_records_before(cx, kind, before),
            Retention::TerminalOnly => Step::Ready(Ok(0)),
        }
    }

    /// THE USAGE LEDGER'S PURGE: slot 22 under
    fn purge_usage_before(&self, cx: &mut Op<'_>, before: u64) -> Step<RecordStoreResult<u64>> {
        let _ = (cx, before);
        Step::Ready(Err(crate::records::RecordStoreError(
            PURGE_USAGE_UNSUPPORTED.to_string(),
        )))
    }

    /// `delete_plane_record` (slot 23); absent is `Ok`.
    fn delete_plane_record(
        &self,
        cx: &mut Op<'_>,
        kind: &str,
        id: &str,
    ) -> Step<RecordStoreResult<()>>;

    /// `redeem_plane_token` (slot 24): whether this call was the first redemption.
    fn redeem_plane_token(
        &self,
        cx: &mut Op<'_>,
        kind: &str,
        token: &str,
        expires_at: u64,
        now: u64,
    ) -> Step<RecordStoreResult<bool>>;

    /// `plane_token_live` (slot 25), including the reserved host ticket's non-consuming,
    fn plane_token_live(
        &self,
        cx: &mut Op<'_>,
        kind: &str,
        token: &str,
        expires_at: u64,
        now: u64,
    ) -> Step<RecordStoreResult<bool>>;
}
