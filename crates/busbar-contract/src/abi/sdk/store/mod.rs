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
//! # Dedupe is the store's (S1-S5)
//!
//! Every method that takes an [`OpId`] dedupes on it, DURABLY for a durable store: the same
//! `op_id` with the same value fields applies nothing and answers what the first call answered
//! (S1); the same `op_id` with different value fields is [`OpRefused::Conflict`] and applies nothing (S2,
//! [`DIAG_OPID_CONFLICT`](crate::abi::store::DIAG_OPID_CONFLICT)); only an answer that APPLIED a
//! change is recorded. The SDK checks every host capacity BEFORE calling the method, so a
//! short-buffer answer never reaches the store and is never recorded (the S1 addendum). The check,
//! the answers and what is recorded are [`dedupe`]'s; the store keeps the log.

pub mod door;
// The `op_id` dedupe: the state machine and the body a store records.
pub mod dedupe;
pub mod wire;
// A record's fields as a backend stores them: scope columns, storable integers, counters.
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
// A store that never pends, served whole over its `RecordStore`.
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

    /// Open an instance from the operator's settings (the section's JSON) and the host tables
    /// `open` was handed (`OpenIn.host`; `None` when none): its connector is reached per op through
    /// [`Op`]. THE 1.6.0-dev.2 SHAPE, kept so a store built against it still compiles; a store that
    /// reads a declared secret implements [`StoreSlots::open_with_secrets`] instead (the settings
    /// it is handed no longer carry a declared secret). Defaulted to a refusal naming that method,
    /// so a store implements exactly one of the two.
    ///
    /// # Errors
    /// A text naming why the settings do not open a store, carried verbatim to the operator.
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
    /// `open` was handed: what the door calls.
    ///
    /// THE DECLARED SECRETS (`OpenIn.secrets`), as every kind's `open` takes them: one entry per
    /// Statement `secret_refs` key, in that order (a key the operator left unset is an empty
    /// entry), then each wildcard path's matches, whose places in `settings` hold a
    /// `{"$secret": <index>}` marker (`busbar_contract::secret_fields`). The host takes each
    /// declared key OUT of `settings`, so a DSN password is read here and never from the settings.
    /// The bytes are lent for the call: a store that keeps one copies it.
    ///
    /// DEFAULTED to [`StoreSlots::open`] over the settings as lent (the declared secrets taken
    /// out), so a store built against the older shape opens as before when it declares none.
    ///
    /// # Errors
    /// A text naming why the settings do not open a store, carried verbatim to the operator.
    fn open_with_secrets(
        settings: &[u8],
        secrets: &[&[u8]],
        host: Option<Host>,
    ) -> Result<Self, String> {
        let _ = secrets;
        #[allow(deprecated)]
        Self::open(settings, host)
    }

    /// THE CONNECT STEP of `open` (ARCHITECT ruling 2026-10-03 on Q-L16-2): what the store reaches
    /// before the host counts it opened (its backend's first round trip, a schema check: a backend
    /// whose stored schema is NEWER than this build's is refused, never written). It runs
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

    // ── the 1.5.5 op set, each one body, served through the table ──────────────────────────────

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

    /// `add_denylist` (slot 14): deny the principal `id`, saying why.
    ///
    /// # Errors
    /// The store's refusal, as the 1.5.5 op set states it.
    fn add_denylist(&self, cx: &mut Op<'_>, id: &str, reason: &str) -> Step<RecordStoreResult<()>>;

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

    /// `purge_plane_records_before` (slot 22) under the age rule.
    ///
    /// # Errors
    /// The store's refusal, as the 1.5.5 op set states it.
    fn purge_plane_records_before(
        &self,
        cx: &mut Op<'_>,
        kind: &str,
        before: u64,
    ) -> Step<RecordStoreResult<u64>>;

    /// RETENTION, with the predicate named: slot 22 under the rule its `in` carries
    /// (`KindBeforeIn::retention`); the door calls this, so a store that honours the terminal-only
    /// rule overrides it ([`Retention::drops`]).
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

    /// THE USAGE LEDGER'S PURGE: slot 22 under
    /// [`RETENTION_USAGE_WINDOWS`](crate::abi::store::RETENTION_USAGE_WINDOWS). Remove every usage
    /// window whose `window_start` is nonzero and earlier than `before`; never the all-time window
    /// `0`. Answers how many windows went. The kernel calls it past its own window horizon, so a
    /// durable store's ledger is bounded (a store that kept every window grew without bound).
    ///
    /// # Errors
    /// The store's refusal, as the 1.5.5 op set states it.
    ///
    /// DEFAULTED to a refusal saying so (a store built before this method purges nothing): the
    /// kernel then warns that this store's usage windows are not purged. Never a pretended count.
    fn purge_usage_before(&self, cx: &mut Op<'_>, before: u64) -> Step<RecordStoreResult<u64>> {
        let _ = (cx, before);
        Step::Ready(Err(crate::records::RecordStoreError(
            PURGE_USAGE_UNSUPPORTED.to_string(),
        )))
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
