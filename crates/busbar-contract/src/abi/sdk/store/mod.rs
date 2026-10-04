// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE STORE KIND'S TYPED SDK (THE DESIGN, the plugin ABI; ABI-b3, the SDK's typed wrappers):
//! what a store plugin implements so that it can be served through the store v3 table
//! (`abi::store`) with no `unsafe` of its own.
//!
//! A store implements [`StoreSlots`]: the 1.5.5 op set is [`RecordStore`] (slots 0-32 read and
//! write exactly those records), and the v3 additions are the methods here (the `op_id`-carrying
//! writes, the ledger ops, the money slots, `window_caps`). Every argument is typed Rust: the SDK
//! reads the host's `in`, decodes each record blob, calls the method, and writes the answer into
//! the host's buffers or under a lease.
//!
//! # Dedupe is the store's (S1-S4)
//!
//! Every method that takes an [`OpId`] dedupes on it, DURABLY for a durable store: the same
//! `op_id` with the same value fields applies nothing and answers what the first call answered
//! (S1: `reserve` answers the ORIGINAL grants, `slice_release` the ORIGINAL released amounts); the
//! same `op_id` with different value fields is [`OpRefused::Conflict`] and applies nothing (S2,
//! [`DIAG_OPID_CONFLICT`](crate::abi::store::DIAG_OPID_CONFLICT)); only an answer that APPLIED a
//! change is recorded. The SDK checks every host capacity BEFORE calling the method, so a
//! short-buffer answer never reaches the store and is never recorded (the S1 addendum).

pub mod door;

use crate::abi::sdk::conn::Host;
use crate::abi::store::OpId;
use crate::kinds::{Head, RecordBytes};
use crate::records::{
    AuditRecord, CredentialMeta, CredentialSecret, MeteringDelta, MeteringRow, PlaneRecordRef,
    PlaneSelector, RecordStoreResult, UsageDelta, UsageLedger, VirtualKey,
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
    /// text, nothing applied, nothing recorded under the `op_id`.
    Failed(String),
}

/// An `op_id`-carrying write's answer.
pub type OpResult<T> = Result<T, OpRefused>;

/// A capped axis, as a cell or a cap names it (`abi::store::DIM_*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Dimension<'a> {
    /// Money, in nano-units ([`DIM_NANO_UNITS`](crate::abi::store::DIM_NANO_UNITS)).
    NanoUnits,
    /// A count of requests ([`DIM_REQUESTS`](crate::abi::store::DIM_REQUESTS)).
    Requests,
    /// A live gauge ([`DIM_CONCURRENCY`](crate::abi::store::DIM_CONCURRENCY)).
    Concurrency,
    /// A declared meter class, by key ([`DIM_CLASS`](crate::abi::store::DIM_CLASS)).
    Class(&'a str),
}

/// The slot a cell draws from and a cap bounds: `(bucket, pool, dimension, class_key,
/// window_start)` (`abi::store::UnitCell`, `WindowCap`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CellKey<'a> {
    /// The bucket id.
    pub bucket: &'a str,
    /// The pool scope; `None` = every pool.
    pub pool: Option<&'a str>,
    /// The axis.
    pub dimension: Dimension<'a>,
    /// The window (ms); `0` = no window.
    pub window_start: u64,
}

/// One cell of a `reserve` (`abi::store::UnitCell`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cell<'a> {
    /// Which slot.
    pub key: CellKey<'a>,
    /// How much; above `0`.
    pub amount: u64,
}

/// One cell's grant (`abi::store::CellGrant`): always the cell's whole `amount`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Grant {
    /// The slice.
    pub slice_id: u64,
    /// How much was granted.
    pub granted: u64,
    /// When the node must stop drawing against it (ms).
    pub valid_until_ms: u64,
}

/// Why a `reserve` applied nothing (`abi::store::RESERVE_*`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReserveRefused {
    /// Cell `cell`'s window has no headroom ([`RESERVE_EXHAUSTED`](crate::abi::store::RESERVE_EXHAUSTED)).
    Exhausted {
        /// The first cell that could not be granted.
        cell: u32,
    },
    /// The node's epoch is behind the store's ([`RESERVE_STALE_EPOCH`](crate::abi::store::RESERVE_STALE_EPOCH)).
    StaleEpoch,
    /// The store could not be reached ([`RESERVE_UNAVAILABLE`](crate::abi::store::RESERVE_UNAVAILABLE)).
    Unavailable,
    /// Cell `cell` names a slot no cap was pushed for ([`RESERVE_NO_CAP`](crate::abi::store::RESERVE_NO_CAP)).
    NoCap {
        /// The first such cell.
        cell: u32,
    },
    /// The same `op_id` with different value fields.
    Conflict,
}

/// One cap (`abi::store::WindowCap`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cap<'a> {
    /// Which slot.
    pub key: CellKey<'a>,
    /// The cap.
    pub cap: u64,
    /// The configuration generation it was read from.
    pub config_gen: u64,
}

/// Why a `window_caps` push applied nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapsRefused {
    /// Cap `index` has the same `config_gen` as the stored cap and a different value:
    /// REFUSED with [`DIAG_CAP_CONFLICT`](crate::abi::store::DIAG_CAP_CONFLICT).
    CapConflict {
        /// The first conflicting cap.
        index: usize,
    },
    /// The same `op_id` with different value fields.
    Conflict,
    /// The push could not be applied.
    Failed(String),
}

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

    /// `add_usage` (slot 8): [`RecordStore::add_usage`], deduped on `op`.
    ///
    /// # Errors
    /// [`OpRefused`].
    fn add_usage_op(
        &self,
        cx: &mut Op<'_>,
        op: OpId,
        bucket: &str,
        window_start: u64,
        delta: &UsageDelta,
    ) -> Step<OpResult<()>>;

    /// `add_metering` (slot 9): [`RecordStore::add_metering`], deduped on `op`.
    ///
    /// # Errors
    /// [`OpRefused`].
    fn add_metering_op(
        &self,
        cx: &mut Op<'_>,
        op: OpId,
        delta: &MeteringDelta,
    ) -> Step<OpResult<()>>;

    /// `append_audit` (slot 19): [`RecordStore::append_audit`], deduped on `op`.
    ///
    /// # Errors
    /// [`OpRefused`]; a different record at a used `seq` is `Failed` (a fork).
    fn append_audit_op(&self, cx: &mut Op<'_>, op: OpId, entry: &AuditRecord)
        -> Step<OpResult<()>>;

    /// `append_plane_record` (slot 26): [`RecordStore::append_plane_record`], deduped on `op`.
    ///
    /// # Errors
    /// [`OpRefused`].
    fn append_plane_record_op(
        &self,
        cx: &mut Op<'_>,
        op: OpId,
        record: PlaneRecordRef<'_>,
    ) -> Step<OpResult<()>>;

    /// `append_batch` (slot 33): append `records` to `stream`; the head it reached.
    ///
    /// # Errors
    /// [`OpRefused`].
    fn append_batch(
        &self,
        cx: &mut Op<'_>,
        op: OpId,
        stream: &str,
        records: &[RecordBytes],
    ) -> Step<OpResult<Head>>;

    /// `heads` (slot 36): where each stream has reached.
    ///
    /// # Errors
    /// A backend text.
    fn heads(&self, cx: &mut Op<'_>) -> Step<Result<Vec<(String, Head)>, String>>;

    /// `session_put` (slot 37): an upsert on `session`.
    ///
    /// # Errors
    /// A backend text.
    fn session_put(
        &self,
        cx: &mut Op<'_>,
        session: u64,
        node: &str,
        principal: &str,
    ) -> Step<Result<(), String>>;

    /// `session_remove` (slot 38); absent is `Ok`.
    ///
    /// # Errors
    /// A backend text.
    fn session_remove(&self, cx: &mut Op<'_>, session: u64) -> Step<Result<(), String>>;

    /// `sessions_for` (slot 39): the sessions `principal` holds, with their nodes.
    ///
    /// # Errors
    /// A backend text.
    fn sessions_for(
        &self,
        cx: &mut Op<'_>,
        principal: &str,
    ) -> Step<Result<Vec<(u64, String)>, String>>;

    /// `record_put` (slot 40): an upsert on `(schema, key)`. `value` is the host's bytes, borrowed,
    /// and at most `MAX_RECORD_BYTES` (the door refuses a longer one before calling).
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

    /// `record_get` (slot 41).
    ///
    /// # Errors
    /// A backend text.
    fn record_get(
        &self,
        cx: &mut Op<'_>,
        schema: &str,
        key: &[u8],
    ) -> Step<Result<Option<RecordBytes>, String>>;

    /// `record_scan` (slot 42): at most `limit` records under `prefix`, in key order; `limit` 0 is
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

    /// `reserve` (slot 34): all or nothing; on `Ok`, EXACTLY one [`Grant`] per cell, in order,
    /// into `grants` (else FAULT). `cells` reads the host's array in place (clone it to read it
    /// again) and `grants` writes into the host's, its room checked first: the request path
    /// allocates nothing in the SDK (the design's plugin memory rule). Write grants only on `Ok`.
    /// The epoch and a slice's life follow `abi::store::SLICE_TTL_MS`'s spec: a fleet store fences
    /// on its persisted epoch and bounds `valid_until_ms`; a single-node store may not.
    ///
    /// # Errors
    /// [`ReserveRefused`] (a stale epoch is `StaleEpoch`); nothing is applied.
    fn reserve<'c>(
        &self,
        cx: &mut Op<'_>,
        op: OpId,
        epoch: u64,
        cells: impl Iterator<Item = Cell<'c>> + Clone,
        grants: &mut impl Extend<Grant>,
    ) -> Step<Result<(), ReserveRefused>>;

    /// `slice_release` (slot 35): per item `(slice_id, unspent)`, the amount taken back after
    /// clamping, in item order, into `released`. As `reserve`: `items` reads the host's array in
    /// place and `released` writes into the host's. Exactly one amount per item: any other count
    /// is FAULT. Write amounts only on `Ok`. It always applies, whatever the epoch, capped at what
    /// the slice has left: a slice with nothing left returns `0`.
    ///
    /// # Errors
    /// [`OpRefused`]; a slice the store never granted is `Failed`, nothing applied.
    fn slice_release(
        &self,
        cx: &mut Op<'_>,
        op: OpId,
        epoch: u64,
        items: impl Iterator<Item = (u64, u64)> + Clone,
        released: &mut impl Extend<u64>,
    ) -> Step<OpResult<()>>;

    /// `add_usage_batch` (slot 43): the cells in order, atomically.
    ///
    /// # Errors
    /// [`OpRefused`].
    fn add_usage_batch(
        &self,
        cx: &mut Op<'_>,
        op: OpId,
        cells: &[(&str, u64, UsageDelta)],
    ) -> Step<OpResult<()>>;

    /// `add_metering_batch` (slot 44): the deltas in order, atomically.
    ///
    /// # Errors
    /// [`OpRefused`].
    fn add_metering_batch(
        &self,
        cx: &mut Op<'_>,
        op: OpId,
        deltas: &[MeteringDelta],
    ) -> Step<OpResult<()>>;

    /// `append_audit_batch` (slot 45): the records in order, atomically.
    ///
    /// # Errors
    /// [`OpRefused`]; one fork refuses the whole batch.
    fn append_audit_batch(
        &self,
        cx: &mut Op<'_>,
        op: OpId,
        entries: &[AuditRecord],
    ) -> Step<OpResult<()>>;

    /// `window_caps` (slot 46): upsert each cap by its slot, newest `config_gen` wins; atomic.
    ///
    /// # Errors
    /// [`CapsRefused`]; nothing is applied.
    fn window_caps(
        &self,
        cx: &mut Op<'_>,
        op: OpId,
        caps: &[Cap<'_>],
    ) -> Step<Result<(), CapsRefused>>;

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

    /// `scrub_key` (slot 4).
    ///
    /// # Errors
    /// The store's refusal, as the 1.5.5 op set states it.
    fn scrub_key(&self, cx: &mut Op<'_>, id: &str) -> Step<RecordStoreResult<()>>;

    /// `list_keys_since` (slot 5).
    ///
    /// # Errors
    /// The store's refusal, as the 1.5.5 op set states it.
    fn list_keys_since(
        &self,
        cx: &mut Op<'_>,
        since: u64,
    ) -> Step<RecordStoreResult<Vec<VirtualKey>>>;

    /// `get_usage` (slot 6).
    ///
    /// # Errors
    /// The store's refusal, as the 1.5.5 op set states it.
    fn get_usage(
        &self,
        cx: &mut Op<'_>,
        bucket_id: &str,
        window_start: u64,
    ) -> Step<RecordStoreResult<UsageLedger>>;

    /// `put_usage` (slot 7).
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

    /// `list_metering` (slot 10).
    ///
    /// # Errors
    /// The store's refusal, as the 1.5.5 op set states it.
    fn list_metering(
        &self,
        cx: &mut Op<'_>,
        bucket: u64,
    ) -> Step<RecordStoreResult<Vec<MeteringRow>>>;

    /// `purge_windows_before` (slot 11).
    ///
    /// # Errors
    /// The store's refusal, as the 1.5.5 op set states it.
    fn purge_windows_before(&self, cx: &mut Op<'_>, before: u64) -> Step<RecordStoreResult<u64>>;

    /// `purge_metering_before` (slot 12).
    ///
    /// # Errors
    /// The store's refusal, as the 1.5.5 op set states it.
    fn purge_metering_before(&self, cx: &mut Op<'_>, bucket: &str) -> Step<RecordStoreResult<u64>>;

    /// `put_credential` (slot 13).
    ///
    /// # Errors
    /// The store's refusal, as the 1.5.5 op set states it.
    fn put_credential(
        &self,
        cx: &mut Op<'_>,
        secret: &CredentialSecret,
    ) -> Step<RecordStoreResult<()>>;

    /// `put_key_with_credential` (slot 14): both, atomically.
    ///
    /// # Errors
    /// The store's refusal, as the 1.5.5 op set states it.
    fn put_key_with_credential(
        &self,
        cx: &mut Op<'_>,
        key: &VirtualKey,
        secret: &CredentialSecret,
    ) -> Step<RecordStoreResult<()>>;

    /// `list_credentials` (slot 15).
    ///
    /// # Errors
    /// The store's refusal, as the 1.5.5 op set states it.
    fn list_credentials(
        &self,
        cx: &mut Op<'_>,
        key_id: &str,
    ) -> Step<RecordStoreResult<Vec<CredentialMeta>>>;

    /// `lookup_credential_secret` (slot 16).
    ///
    /// # Errors
    /// The store's refusal, as the 1.5.5 op set states it.
    fn lookup_credential_secret(
        &self,
        cx: &mut Op<'_>,
        kind: &str,
        public_id: &str,
    ) -> Step<RecordStoreResult<Option<CredentialSecret>>>;

    /// `revoke_credential` (slot 17).
    ///
    /// # Errors
    /// The store's refusal, as the 1.5.5 op set states it.
    fn revoke_credential(
        &self,
        cx: &mut Op<'_>,
        id: &str,
        reason: &str,
    ) -> Step<RecordStoreResult<()>>;

    /// `list_credentials_since` (slot 18).
    ///
    /// # Errors
    /// The store's refusal, as the 1.5.5 op set states it.
    fn list_credentials_since(
        &self,
        cx: &mut Op<'_>,
        since: u64,
    ) -> Step<RecordStoreResult<Vec<CredentialSecret>>>;

    /// `list_audit` (slot 20).
    ///
    /// # Errors
    /// The store's refusal, as the 1.5.5 op set states it.
    fn list_audit(&self, cx: &mut Op<'_>) -> Step<RecordStoreResult<Vec<AuditRecord>>>;

    /// `add_denylist` (slot 21).
    ///
    /// # Errors
    /// The store's refusal, as the 1.5.5 op set states it.
    fn add_denylist(&self, cx: &mut Op<'_>, sub: &str, reason: &str)
        -> Step<RecordStoreResult<()>>;

    /// `list_denylist` (slot 22).
    ///
    /// # Errors
    /// The store's refusal, as the 1.5.5 op set states it.
    fn list_denylist(&self, cx: &mut Op<'_>) -> Step<RecordStoreResult<Vec<String>>>;

    /// `list_audit_tail` (slot 23).
    ///
    /// # Errors
    /// The store's refusal, as the 1.5.5 op set states it.
    fn list_audit_tail(
        &self,
        cx: &mut Op<'_>,
        limit: u64,
    ) -> Step<RecordStoreResult<Vec<AuditRecord>>>;

    /// `upsert_plane_record` (slot 24).
    ///
    /// # Errors
    /// The store's refusal, as the 1.5.5 op set states it.
    fn upsert_plane_record(
        &self,
        cx: &mut Op<'_>,
        record: PlaneRecordRef<'_>,
    ) -> Step<RecordStoreResult<()>>;

    /// `get_plane_record` (slot 25): the body.
    ///
    /// # Errors
    /// The store's refusal, as the 1.5.5 op set states it.
    fn get_plane_record(
        &self,
        cx: &mut Op<'_>,
        kind: &str,
        id: &str,
    ) -> Step<RecordStoreResult<Option<Vec<u8>>>>;

    /// `list_plane_records` (slot 27): the bodies.
    ///
    /// # Errors
    /// The store's refusal, as the 1.5.5 op set states it.
    fn list_plane_records(
        &self,
        cx: &mut Op<'_>,
        kind: &str,
        selector: &PlaneSelector<'_>,
    ) -> Step<RecordStoreResult<Vec<Vec<u8>>>>;

    /// `list_plane_record_parents` (slot 28).
    ///
    /// # Errors
    /// The store's refusal, as the 1.5.5 op set states it.
    fn list_plane_record_parents(
        &self,
        cx: &mut Op<'_>,
        kind: &str,
    ) -> Step<RecordStoreResult<Vec<String>>>;

    /// `purge_plane_records_before` (slot 29).
    ///
    /// # Errors
    /// The store's refusal, as the 1.5.5 op set states it.
    fn purge_plane_records_before(
        &self,
        cx: &mut Op<'_>,
        kind: &str,
        before: u64,
    ) -> Step<RecordStoreResult<u64>>;

    /// `delete_plane_record` (slot 30); absent is `Ok`.
    ///
    /// # Errors
    /// The store's refusal, as the 1.5.5 op set states it.
    fn delete_plane_record(
        &self,
        cx: &mut Op<'_>,
        kind: &str,
        id: &str,
    ) -> Step<RecordStoreResult<()>>;

    /// `redeem_plane_token` (slot 31): whether this call was the first redemption.
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

    /// `plane_token_live` (slot 32).
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
