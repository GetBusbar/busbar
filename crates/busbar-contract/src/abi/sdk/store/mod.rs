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

use crate::abi::store::OpId;
use crate::kinds::{Head, RecordBytes};
use crate::records::{AuditRecord, MeteringDelta, PlaneRecord, RecordStore, UsageDelta};

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

/// What a store states in its Statement tail (`abi::store::StoreTail`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tail {
    /// What it holds is lost on restart.
    pub ephemeral: bool,
    /// It holds plane records durably.
    pub durable_plane: bool,
    /// A different record at a used `seq` is refused as a fork.
    pub fork_refusal: bool,
}

/// A store plugin, as the store v3 table serves it. Every method is required: the table has no
/// NULL slot and no UNSUPPORTED answer.
pub trait StoreSlots: RecordStore + Sized {
    /// What this store states in its Statement tail.
    const TAIL: Tail;

    /// Open an instance from the operator's settings (the section's JSON).
    ///
    /// # Errors
    /// A text naming why the settings do not open a store.
    fn open(settings: &[u8]) -> Result<Self, String>;

    /// `add_usage` (slot 8): [`RecordStore::add_usage`], deduped on `op`.
    ///
    /// # Errors
    /// [`OpRefused`].
    fn add_usage_op(
        &self,
        op: OpId,
        bucket: &str,
        window_start: u64,
        delta: &UsageDelta,
    ) -> OpResult<()>;

    /// `add_metering` (slot 9): [`RecordStore::add_metering`], deduped on `op`.
    ///
    /// # Errors
    /// [`OpRefused`].
    fn add_metering_op(&self, op: OpId, delta: &MeteringDelta) -> OpResult<()>;

    /// `append_audit` (slot 19): [`RecordStore::append_audit`], deduped on `op`.
    ///
    /// # Errors
    /// [`OpRefused`]; a different record at a used `seq` is `Failed` (a fork).
    fn append_audit_op(&self, op: OpId, entry: &AuditRecord) -> OpResult<()>;

    /// `append_plane_record` (slot 26): [`RecordStore::append_plane_record`], deduped on `op`.
    ///
    /// # Errors
    /// [`OpRefused`].
    fn append_plane_record_op(&self, op: OpId, record: &PlaneRecord) -> OpResult<()>;

    /// `append_batch` (slot 33): append `records` to `stream`; the head it reached.
    ///
    /// # Errors
    /// [`OpRefused`].
    fn append_batch(&self, op: OpId, stream: &str, records: &[RecordBytes]) -> OpResult<Head>;

    /// `heads` (slot 36): where each stream has reached.
    ///
    /// # Errors
    /// A backend text.
    fn heads(&self) -> Result<Vec<(String, Head)>, String>;

    /// `session_put` (slot 37): an upsert on `session`.
    ///
    /// # Errors
    /// A backend text.
    fn session_put(&self, session: u64, node: &str, principal: &str) -> Result<(), String>;

    /// `session_remove` (slot 38); absent is `Ok`.
    ///
    /// # Errors
    /// A backend text.
    fn session_remove(&self, session: u64) -> Result<(), String>;

    /// `sessions_for` (slot 39): the sessions `principal` holds, with their nodes.
    ///
    /// # Errors
    /// A backend text.
    fn sessions_for(&self, principal: &str) -> Result<Vec<(u64, String)>, String>;

    /// `record_put` (slot 40): an upsert on `(schema, key)`.
    ///
    /// # Errors
    /// A backend text.
    fn record_put(&self, schema: &str, key: &[u8], value: &RecordBytes) -> Result<(), String>;

    /// `record_get` (slot 41).
    ///
    /// # Errors
    /// A backend text.
    fn record_get(&self, schema: &str, key: &[u8]) -> Result<Option<RecordBytes>, String>;

    /// `record_scan` (slot 42): at most `limit` records under `prefix`, in key order; `limit` 0 is
    /// nothing.
    ///
    /// # Errors
    /// A backend text.
    fn record_scan(
        &self,
        schema: &str,
        prefix: &[u8],
        limit: u32,
    ) -> Result<Vec<(Vec<u8>, RecordBytes)>, String>;

    /// `reserve` (slot 34): all or nothing; on `Ok`, EXACTLY one [`Grant`] per cell, in order,
    /// into `grants` (else FAULT). `cells` reads the host's array in place (clone it to read it
    /// again) and `grants` writes into the host's, its room checked first: the request path
    /// allocates nothing in the SDK (the design's plugin memory rule). Write grants only on `Ok`.
    ///
    /// # Errors
    /// [`ReserveRefused`]; nothing is applied.
    fn reserve<'c>(
        &self,
        op: OpId,
        epoch: u64,
        cells: impl Iterator<Item = Cell<'c>> + Clone,
        grants: &mut impl Extend<Grant>,
    ) -> Result<(), ReserveRefused>;

    /// `slice_release` (slot 35): per item `(slice_id, unspent)`, the amount taken back after
    /// clamping, in item order, into `released`. As `reserve`: `items` reads the host's array in
    /// place and `released` writes into the host's. Exactly one amount per item: any other count
    /// is FAULT. Write amounts only on `Ok`.
    ///
    /// # Errors
    /// [`OpRefused`]; an unknown slice or a stale epoch is `Failed`, nothing applied.
    fn slice_release(
        &self,
        op: OpId,
        epoch: u64,
        items: impl Iterator<Item = (u64, u64)> + Clone,
        released: &mut impl Extend<u64>,
    ) -> OpResult<()>;

    /// `add_usage_batch` (slot 43): the cells in order, atomically.
    ///
    /// # Errors
    /// [`OpRefused`].
    fn add_usage_batch(&self, op: OpId, cells: &[(&str, u64, UsageDelta)]) -> OpResult<()>;

    /// `add_metering_batch` (slot 44): the deltas in order, atomically.
    ///
    /// # Errors
    /// [`OpRefused`].
    fn add_metering_batch(&self, op: OpId, deltas: &[MeteringDelta]) -> OpResult<()>;

    /// `append_audit_batch` (slot 45): the records in order, atomically.
    ///
    /// # Errors
    /// [`OpRefused`]; one fork refuses the whole batch.
    fn append_audit_batch(&self, op: OpId, entries: &[AuditRecord]) -> OpResult<()>;

    /// `window_caps` (slot 46): upsert each cap by its slot, newest `config_gen` wins; atomic.
    ///
    /// # Errors
    /// [`CapsRefused`]; nothing is applied.
    fn window_caps(&self, op: OpId, caps: &[Cap<'_>]) -> Result<(), CapsRefused>;
}
