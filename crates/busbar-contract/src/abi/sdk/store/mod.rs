// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE STORE KIND'S TYPED SDK (THE DESIGN, the plugin ABI; ABI-b3, the SDK's typed wrappers):
//! what a store plugin implements so that it can be served through the store v3 table
//! (`abi::store`) with no `unsafe` of its own.
//!
//! A store implements [`StoreSlots`]: the 1.5.5 op set reads and writes exactly the 1.5.5 records,
//! and the v3 additions are the methods here (the `op_id`-carrying count batches, plane records
//! and the kernel-held records). No slot carries money. Every argument is typed Rust: the SDK
//! reads the host's `in`, decodes each record blob, calls the method, and writes the answer into
//! the host's buffers or under a lease.
//!
//! # Dedupe is the store's (S1-S4)
//!
//! Every method that takes an [`OpId`] dedupes on it, DURABLY for a durable store: the same
//! `op_id` with the same value fields applies nothing and answers what the first call answered
//! (S1); the same `op_id` with different value fields is [`OpRefused::Conflict`] and applies nothing (S2,
//! [`DIAG_OPID_CONFLICT`](crate::abi::store::DIAG_OPID_CONFLICT)); only an answer that APPLIED a
//! change is recorded. The SDK checks every host capacity BEFORE calling the method, so a
//! short-buffer answer never reaches the store and is never recorded (the S1 addendum).

pub mod door;
pub mod wire;
// A record's fields as a backend stores them: scope columns, storable integers, counters.
pub mod column;
// A forked chain, in one wording for every store.
pub mod fork;

use crate::abi::sdk::conn::Host;
use crate::abi::store::OpId;
use crate::kinds::RecordBytes;
use crate::records::{
    AuditRecord, CredentialMeta, CredentialSecret, MeteringDelta, MeteringRow, PlaneRecordRef,
    PlaneSelector, RecordStoreResult, Retention, UsageDelta, UsageLedger, VirtualKey,
};

mod op;
pub use op::{Checkout, Op, Services, Step};

/// What `record_scan` answers: `(key, record)` in key order.
pub type Scanned = Vec<(Vec<u8>, RecordBytes)>;

/// Why an `op_id`-carrying write answered without applying anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpRefused {
    /// The same `op_id` arrived with different value fields: REFUSED with
    /// [`DIAG_OPID_CONFLICT`](crate::abi::store::DIAG_OPID_CONFLICT), nothing applied.
    Conflict,
    /// The write could not be applied (a fork at a used `seq`, a backend error): FAILED with this
    /// text, nothing applied, nothing recorded under the `op_id`. A host cannot tell this from a
    /// commit whose answer was lost, so it replays the same `op_id` (S5).
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
/// NULL slot and no UNSUPPORTED answer.
pub trait StoreSlots: Sized + Send + Sync + 'static {
    /// What this store states in its Statement tail.
    const TAIL: Tail;

    /// PARSE the operator's settings (the section's JSON) and nothing more: `validate` never opens,
    /// connects to or migrates a store (`--validate` runs no store).
    ///
    /// # Errors
    /// The store's own refusal text, carried verbatim to the operator.
    fn validate(settings: &[u8]) -> Result<(), String>;

    /// Open an instance from the operator's settings (the section's JSON), with the host tables
    /// `open` was handed (`OpenIn.host`; `None` when none): its connector is reached per op through
    /// [`Op`].
    ///
    /// # Errors
    /// A text naming why the settings do not open a store, carried verbatim to the operator.
    fn open(settings: &[u8], host: Option<Host>) -> Result<Self, String>;

    /// THE CONNECT STEP of `open` (ARCHITECT ruling 2026-10-03 on Q-L16-2): what the store reaches
    /// before the host counts it opened (its backend's first round trip, a schema check). It runs
    /// on the instance [`StoreSlots::open`] answered, on `open`'s own ticket, and may PEND on the
    /// connector exactly as an op does: the host re-enters `open` on the wake and the door hands
    /// back the same instance and [`Op`] (what it parked, its one connection), never calling
    /// [`StoreSlots::open`] again. An `Err` fails the load with its text, verbatim, as an `open`
    /// refusal does, so a store that refused at open in 1.5.5 still refuses there, in its own
    /// words. The connection it checked out is closed when the step answers. A store that reaches
    /// nothing at open answers `Ready(Ok(()))`, the default.
    ///
    /// # Errors
    /// A text naming why the store does not open, carried verbatim to the operator.
    fn connect(&self, cx: &mut Op<'_>) -> Step<Result<(), String>> {
        let _ = cx;
        Step::Ready(Ok(()))
    }

    /// `append_plane_record` (slot 19): [`RecordStore::append_plane_record`], deduped on `op`.
    ///
    /// # Errors
    /// [`OpRefused`].
    fn append_plane_record_op(
        &self,
        cx: &mut Op<'_>,
        op: OpId,
        record: PlaneRecordRef<'_>,
    ) -> Step<OpResult<()>>;

    /// `record_put` (slot 26): an upsert on `(schema, key)`. `value` is the host's bytes, borrowed,
    /// and at most `MAX_RECORD_BYTES` (the door refuses a longer one before calling).
    ///
    /// AN EMPTY `value` REMOVES THE ROW: after it, [`Self::record_get`] answers `None` for the key
    /// and [`Self::record_scan`] never returns it. The host writes every strike (a swept work
    /// handle, a dropped chain) as an empty put and reads empty as absent, so a store that kept the
    /// row would keep every strike forever. Removing a row that is not there is `Ok`.
    ///
    /// # Errors
    /// A backend text.
    fn record_put(
        &self,
        cx: &mut Op<'_>,
        schema: &str,
        key: &[u8],
        value: &[u8],
    ) -> Step<Result<(), String>>;

    /// `record_get` (slot 27).
    ///
    /// # Errors
    /// A backend text.
    fn record_get(
        &self,
        cx: &mut Op<'_>,
        schema: &str,
        key: &[u8],
    ) -> Step<Result<Option<RecordBytes>, String>>;

    /// `record_scan` (slot 28): at most `limit` records under `prefix`, in key order; `limit` 0 is
    /// nothing.
    ///
    /// # Errors
    /// A backend text.
    fn record_scan(
        &self,
        cx: &mut Op<'_>,
        schema: &str,
        prefix: &[u8],
        limit: u32,
    ) -> Step<Result<Scanned, String>>;

    /// `add_usage_batch` (slot 29): the cells in order, atomically.
    ///
    /// # Errors
    /// [`OpRefused`].
    fn add_usage_batch(
        &self,
        cx: &mut Op<'_>,
        op: OpId,
        cells: &[(&str, u64, UsageDelta)],
    ) -> Step<OpResult<()>>;

    /// `add_metering_batch` (slot 30): the deltas in order, atomically.
    ///
    /// # Errors
    /// [`OpRefused`].
    fn add_metering_batch(
        &self,
        cx: &mut Op<'_>,
        op: OpId,
        deltas: &[MeteringDelta],
    ) -> Step<OpResult<()>>;

    // ── the 1.5.5 op set (slots 0-32), each one body, served through the table ─────────────────

    /// `put_key` (slot 0): upsert `key` by its id.
    ///
    /// # Errors
    /// The store's refusal, as the 1.5.5 op set states it.
    fn put_key(&self, cx: &mut Op<'_>, key: &VirtualKey) -> Step<RecordStoreResult<()>>;

    /// `get_key` (slot 1).
    ///
    /// # Errors
    /// The store's refusal, as the 1.5.5 op set states it.
    fn get_key(&self, cx: &mut Op<'_>, id: &str) -> Step<RecordStoreResult<Option<VirtualKey>>>;

    /// `list_keys` (slot 2).
    ///
    /// # Errors
    /// The store's refusal, as the 1.5.5 op set states it.
    fn list_keys(&self, cx: &mut Op<'_>) -> Step<RecordStoreResult<Vec<VirtualKey>>>;

    /// `delete_key` (slot 3): tombstone it.
    ///
    /// # Errors
    /// The store's refusal, as the 1.5.5 op set states it.
    fn delete_key(&self, cx: &mut Op<'_>, id: &str) -> Step<RecordStoreResult<()>>;

    /// `list_keys_since` (slot 4).
    ///
    /// # Errors
    /// The store's refusal, as the 1.5.5 op set states it.
    fn list_keys_since(
        &self,
        cx: &mut Op<'_>,
        since: u64,
    ) -> Step<RecordStoreResult<Vec<VirtualKey>>>;

    /// `get_usage` (slot 5).
    ///
    /// # Errors
    /// The store's refusal, as the 1.5.5 op set states it.
    fn get_usage(
        &self,
        cx: &mut Op<'_>,
        bucket_id: &str,
        window_start: u64,
    ) -> Step<RecordStoreResult<UsageLedger>>;

    /// `put_usage` (slot 6).
    ///
    /// # Errors
    /// The store's refusal, as the 1.5.5 op set states it.
    fn put_usage(
        &self,
        cx: &mut Op<'_>,
        bucket_id: &str,
        window_start: u64,
        ledger: &UsageLedger,
    ) -> Step<RecordStoreResult<()>>;

    /// `list_metering` (slot 7).
    ///
    /// # Errors
    /// The store's refusal, as the 1.5.5 op set states it.
    fn list_metering(
        &self,
        cx: &mut Op<'_>,
        bucket: u64,
    ) -> Step<RecordStoreResult<Vec<MeteringRow>>>;

    /// `put_credential` (slot 8).
    ///
    /// # Errors
    /// The store's refusal, as the 1.5.5 op set states it.
    fn put_credential(
        &self,
        cx: &mut Op<'_>,
        secret: &CredentialSecret,
    ) -> Step<RecordStoreResult<()>>;

    /// `put_key_with_credential` (slot 9): both, atomically.
    ///
    /// # Errors
    /// The store's refusal, as the 1.5.5 op set states it.
    fn put_key_with_credential(
        &self,
        cx: &mut Op<'_>,
        key: &VirtualKey,
        secret: &CredentialSecret,
    ) -> Step<RecordStoreResult<()>>;

    /// `list_credentials` (slot 10).
    ///
    /// # Errors
    /// The store's refusal, as the 1.5.5 op set states it.
    fn list_credentials(
        &self,
        cx: &mut Op<'_>,
        key_id: &str,
    ) -> Step<RecordStoreResult<Vec<CredentialMeta>>>;

    /// `revoke_credential` (slot 11).
    ///
    /// # Errors
    /// The store's refusal, as the 1.5.5 op set states it.
    fn revoke_credential(
        &self,
        cx: &mut Op<'_>,
        id: &str,
        reason: &str,
    ) -> Step<RecordStoreResult<()>>;

    /// `list_credentials_since` (slot 12).
    ///
    /// # Errors
    /// The store's refusal, as the 1.5.5 op set states it.
    fn list_credentials_since(
        &self,
        cx: &mut Op<'_>,
        since: u64,
    ) -> Step<RecordStoreResult<Vec<CredentialSecret>>>;

    /// `list_audit` (slot 13).
    ///
    /// # Errors
    /// The store's refusal, as the 1.5.5 op set states it.
    fn list_audit(&self, cx: &mut Op<'_>) -> Step<RecordStoreResult<Vec<AuditRecord>>>;

    /// `add_denylist` (slot 14).
    ///
    /// # Errors
    /// The store's refusal, as the 1.5.5 op set states it.
    fn add_denylist(&self, cx: &mut Op<'_>, sub: &str, reason: &str)
        -> Step<RecordStoreResult<()>>;

    /// `list_denylist` (slot 15).
    ///
    /// # Errors
    /// The store's refusal, as the 1.5.5 op set states it.
    fn list_denylist(&self, cx: &mut Op<'_>) -> Step<RecordStoreResult<Vec<String>>>;

    /// `list_audit_tail` (slot 16).
    ///
    /// # Errors
    /// The store's refusal, as the 1.5.5 op set states it.
    fn list_audit_tail(
        &self,
        cx: &mut Op<'_>,
        limit: u64,
    ) -> Step<RecordStoreResult<Vec<AuditRecord>>>;

    /// `upsert_plane_record` (slot 17).
    ///
    /// # Errors
    /// The store's refusal, as the 1.5.5 op set states it.
    fn upsert_plane_record(
        &self,
        cx: &mut Op<'_>,
        record: PlaneRecordRef<'_>,
    ) -> Step<RecordStoreResult<()>>;

    /// `get_plane_record` (slot 18): the body.
    ///
    /// # Errors
    /// The store's refusal, as the 1.5.5 op set states it.
    fn get_plane_record(
        &self,
        cx: &mut Op<'_>,
        kind: &str,
        id: &str,
    ) -> Step<RecordStoreResult<Option<Vec<u8>>>>;

    /// `list_plane_records` (slot 20): the bodies.
    ///
    /// # Errors
    /// The store's refusal, as the 1.5.5 op set states it.
    fn list_plane_records(
        &self,
        cx: &mut Op<'_>,
        kind: &str,
        selector: &PlaneSelector<'_>,
    ) -> Step<RecordStoreResult<Vec<Vec<u8>>>>;

    /// `list_plane_record_parents` (slot 21).
    ///
    /// # Errors
    /// The store's refusal, as the 1.5.5 op set states it.
    fn list_plane_record_parents(
        &self,
        cx: &mut Op<'_>,
        kind: &str,
    ) -> Step<RecordStoreResult<Vec<String>>>;

    /// `purge_plane_records_before` (slot 22).
    ///
    /// # Errors
    /// The store's refusal, as the 1.5.5 op set states it.
    fn purge_plane_records_before(
        &self,
        cx: &mut Op<'_>,
        kind: &str,
        before: u64,
    ) -> Step<RecordStoreResult<u64>>;

    /// RETENTION, with the predicate named (no slot of its own yet).
    ///
    /// DEFAULTED: [`Retention::Age`] is [`StoreSlots::purge_plane_records_before`];
    /// [`Retention::TerminalOnly`] answers `Ok(0)` — a store that has not implemented the
    /// terminal-only predicate purges nothing rather than dropping an ACTIVE row.
    ///
    /// # Errors
    /// The store's refusal, as [`StoreSlots::purge_plane_records_before`] states it.
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

    /// `delete_plane_record` (slot 23); absent is `Ok`.
    ///
    /// # Errors
    /// The store's refusal, as the 1.5.5 op set states it.
    fn delete_plane_record(
        &self,
        cx: &mut Op<'_>,
        kind: &str,
        id: &str,
    ) -> Step<RecordStoreResult<()>>;

    /// `redeem_plane_token` (slot 24): whether this call was the first redemption.
    ///
    /// # Errors
    /// The store's refusal, as the 1.5.5 op set states it.
    fn redeem_plane_token(
        &self,
        cx: &mut Op<'_>,
        kind: &str,
        token: &str,
        expires_at: u64,
        now: u64,
    ) -> Step<RecordStoreResult<bool>>;

    /// `plane_token_live` (slot 25).
    ///
    /// # Errors
    /// The store's refusal, as the 1.5.5 op set states it.
    fn plane_token_live(
        &self,
        cx: &mut Op<'_>,
        kind: &str,
        token: &str,
        expires_at: u64,
        now: u64,
    ) -> Step<RecordStoreResult<bool>>;
}
