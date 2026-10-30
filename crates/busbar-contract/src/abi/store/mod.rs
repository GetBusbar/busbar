// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE STORE KIND'S ABI (v3): its version, its table, its slots, its data shapes, its Statement
//! tail and its cancel vocabulary (THE DESIGN, the owner-locked plugin ABI: seven ABIs on one
//! mechanism, one place for every ABI shape; the signed per-kind design B.1 "store (v3)"; the
//! ARCHITECT rulings in `m3-inputs.md` "store v3 money slots" and "window caps").
//!
//! The one dispatcher calls this table (`busbar-plugin-loader`, `dispatch::kinds::store`).
//!
//! # The table
//!
//! [`Ops`] is the shared [`OpsHead`] followed by one `Option<Op>` per kind slot, contiguous: the
//! kind slot `k` is at slot index [`LIFECYCLE_SLOTS`]` + k` ([`slot`]). A NULL slot refuses the
//! load: there are no UNSUPPORTED fallbacks and no floor (B.1 "Behaviour").
//!
//! ```
//! use busbar_contract::abi::mechanism::lifecycle::{OpsHead, LIFECYCLE_SLOTS};
//! use busbar_contract::abi::store::{slot, Ops, KIND_SLOTS, NAMES, OPS, TABLE_SLOTS};
//! // Every kind slot index is LIFECYCLE_SLOTS + k, k = 0.., contiguous and in table order.
//! for (k, c) in OPS.iter().enumerate() {
//!     assert_eq!(c.slot, LIFECYCLE_SLOTS + k as u32, "{}", NAMES[k]);
//! }
//! assert_eq!(OPS.len() as u32, KIND_SLOTS);
//! assert_eq!(TABLE_SLOTS, LIFECYCLE_SLOTS + KIND_SLOTS);
//! assert_eq!(slot::PUT_KEY, LIFECYCLE_SLOTS);
//! assert_eq!(slot::ADD_METERING_BATCH, TABLE_SLOTS - 1);
//! // The table is the head plus one pointer-sized slot per kind op.
//! assert_eq!(
//!     std::mem::size_of::<Ops>(),
//!     std::mem::size_of::<OpsHead>() + KIND_SLOTS as usize * std::mem::size_of::<usize>()
//! );
//! ```
//!
//! # Paths, results and memory
//!
//! Every slot states its contract in [`OPS`]: request-path or off-path, `may_pend`, its
//! [`DeadlineClass`], its `in`/`out` sizes and its payload bound. Network stores pend through
//! driver tickets; the memory store is always READY (B.1 "Behaviour"), so every slot is `may_pend`.
//!
//! * REQUEST-PATH results go into HOST buffers the `in` names, pointer + capacity ([`HostBuf`],
//!   [`HostBlobs`], [`HostRecords`]), never in the `out`, which the host zeroes before every call (mechanism
//!   memory class (i); ARCHITECT 2026-09-28). A result that does not fit is the short-buffer answer, M-SB, stated once on
//!   [`OutHead`] and not restated here; the answer validators in [`check`] enforce it.
//! * OFF-PATH results (the 1.5.5 lists and single records) are plugin-owned under the
//!   `out`'s lease until `release(lease)` (mechanism memory class (iv)); secret material is a
//!   [`BLOB_SECRET`](crate::abi::mechanism::call::BLOB_SECRET) blob, zeroised on release.
//!
//! # Record blobs
//!
//! Every record crosses as a [`Blob`](crate::abi::mechanism::call::Blob): the tree's unit-map
//! record shapes (`records.rs`: `VirtualKey`, `UsageLedger`, `UsageDelta`, `MeteringDelta`,
//! `MeteringRow`, `CredentialSecret`, `CredentialMeta`, `AuditRecord`) as JSON plus the #81 scale
//! discriminator; a row a 1.5.5 store wrote carries no discriminator and reads as whole units.
//! Ids, cursors, windows and counts are fixed fields (B.1 "Record blobs", "Fixed fields").
//!
//! # Dedupe (every slot that carries an [`OpId`])
//!
//! Every additive or appending write carries an [`OpId`] and uses [`DeadlineClass::WriteBehind`].
//! The rule, the same on every such slot (S1-S5):
//! * S1 REPLAY: the same `op_id` replayed with the same body applies nothing and returns the
//!   ORIGINAL `out`.
//! * S2 SAME BODY means the op's VALUE fields only: the cells or records and the window fields.
//!   Host-buffer pointers and capacities are EXCLUDED. The same `op_id`
//!   with different value fields is never applied: the store answers REFUSED with the diagnostic
//!   [`DIAG_OPID_CONFLICT`].
//! * S3 WHAT IS RECORDED under an `op_id`: only an outcome that APPLIED a change (READY). A FAILED
//!   or REFUSED answer with nothing applied is NOT recorded, so a retry with the same `op_id` is
//!   evaluated afresh; a short-buffer FAILED (M-SB) is never recorded.
//! * S4 RETENTION: dedupe is DURABLE (it survives a store restart) and an `op_id` is remembered at
//!   least [`OP_ID_RETENTION_SECS`] (24 h). The kernel never re-issues an `op_id` older than that,
//!   and a store treats an `op_id` it does not know as new.
//! * S5 WHAT AN ANSWER PROVES: REFUSED is decided before commit and PROVES nothing applied (a value
//!   the store cannot hold, a constraint, a script error before any write). FAILED proves nothing:
//!   a store answers FAILED whenever it cannot know whether its commit landed (a lost commit or EXEC
//!   reply, a dropped session), so the host replays the same `op_id` with the same body until READY
//!   or REFUSED, and only a REFUSED write is ever split or re-sent under a new `op_id`.

pub mod check;
pub mod ledger;
pub mod money;
pub mod plane;
pub mod records;

pub use ledger::*;
pub use money::*;
pub use plane::*;
pub use records::*;

use super::mechanism::call::{AbiStr, Blob, DeadlineClass, InHead, Op, OutHead};
use super::mechanism::check::OpContract;
use super::mechanism::door::KindTailHead;
use super::mechanism::lifecycle::{OpsHead, LIFECYCLE_SLOTS};

/// The store kind's ABI version: v1.5.5 shipped `2` (`ABI_VERSION`), so 1.6.0 ships `3`.
pub const ABI_VERSION: u32 = 3;

/// The store kind's layout fingerprint ([`crate::abi::mechanism::layout`]): the fold of
/// [`LAYOUT_SHAPES`], the size, alignment and field offsets of every `#[repr(C)]` struct crossing
/// the store table. A door states it as built
/// ([`Door::layout`](crate::abi::mechanism::door::Door::layout)) and the loader refuses another;
/// `tests/layout_fingerprint.rs` holds it to its fold.
pub const LAYOUT_FINGERPRINT: u64 = 0x56bdc8a89ba6e6e0;

/// The store kind's shapes, in fold order ([`crate::layout_shape!`]): every `#[repr(C)]` struct
/// crossing its table, each with every field. A struct `abi/store/` gains is listed here (gate
/// `abi-location`).
pub const LAYOUT_SHAPES: &[&[u64]] = &[
    crate::layout_shape!(HostBuf => ptr, cap),
    crate::layout_shape!(HostBlobs => items, items_cap, bytes),
    crate::layout_shape!(HostBytesOut => head, found, _reserved, written, needed),
    crate::layout_shape!(HostListOut =>
        head, items_written, bytes_written, needed_items, needed_bytes
    ),
    crate::layout_shape!(LeasedBlobOut => head, found, _reserved, record),
    crate::layout_shape!(LeasedListOut => head, items, items_len),
    crate::layout_shape!(LeasedStrListOut => head, items, items_len),
    crate::layout_shape!(CountOut => head, count),
    crate::layout_shape!(VerdictOut => head, verdict, _reserved),
    crate::layout_shape!(StoreTail => head, durable_plane, fork_refusal, _reserved),
    crate::layout_shape!(OpId =>),
    crate::layout_shape!(UsageCell => bucket, window_start, delta),
    crate::layout_shape!(AddUsageBatchIn => head, op_id, cells, cells_len),
    crate::layout_shape!(OpBlobsIn => head, op_id, records, records_len),
    crate::layout_shape!(IdIn => head, id),
    crate::layout_shape!(U64In => head, value),
    crate::layout_shape!(WindowIn => head, bucket, window_start),
    crate::layout_shape!(PutUsageIn => head, bucket, window_start, ledger),
    crate::layout_shape!(BlobIn => head, record),
    crate::layout_shape!(KeyWithCredentialIn => head, key, credential),
    crate::layout_shape!(KindIdIn => head, kind, id),
    crate::layout_shape!(IdReasonIn => head, id, reason),
    crate::layout_shape!(PlaneRecordRow => kind, id, parent, seq, ts, disposition, _reserved, body),
    crate::layout_shape!(UpsertPlaneRecordIn => head, record),
    crate::layout_shape!(AppendPlaneRecordIn => head, op_id, record),
    crate::layout_shape!(GetPlaneRecordIn => head, kind, id, body),
    crate::layout_shape!(ListPlaneRecordsIn => head, kind, selector, _reserved, parent, out),
    crate::layout_shape!(KindBeforeIn => head, kind, before, retention, _reserved),
    crate::layout_shape!(TokenIn => head, kind, token, expires_at, now),
    crate::layout_shape!(RecordPutIn => head, schema, key, value),
    crate::layout_shape!(RecordGetIn => head, schema, key, value),
    crate::layout_shape!(RecordEntry => key, value),
    crate::layout_shape!(HostRecords => items, items_cap, bytes),
    crate::layout_shape!(RecordScanIn => head, schema, prefix, limit, _reserved, out),
    crate::layout_shape!(Ops =>
        head, put_key, get_key, list_keys, delete_key, list_keys_since, get_usage, put_usage,
        list_metering, put_credential, put_key_with_credential, list_credentials,
        revoke_credential, list_credentials_since, list_audit, add_denylist, list_denylist,
        list_audit_tail, upsert_plane_record, get_plane_record, append_plane_record,
        list_plane_records, list_plane_record_parents, purge_plane_records_before,
        delete_plane_record, redeem_plane_token, plane_token_live, record_put, record_get,
        record_scan, add_usage_batch, add_metering_batch
    ),
];

// ── shared host-buffer shapes (mechanism memory class (i)) ────────────────────────────────────

/// A HOST-owned byte buffer a request-path result is written into: pointer + capacity. The plugin
/// writes at most `cap` bytes and never keeps the pointer past the op.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct HostBuf {
    /// The buffer; NULL only with `cap == 0`.
    pub ptr: *mut u8,
    /// Its capacity in bytes.
    pub cap: usize,
}

/// A HOST-owned list of blobs: an array of [`Blob`] slots and one byte buffer the blobs point into.
/// The plugin copies each item into `bytes` and writes a [`Blob`] whose `ptr` points inside it.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct HostBlobs {
    /// The blob slots.
    pub items: *mut Blob,
    /// How many slots.
    pub items_cap: usize,
    /// The bytes the blobs point into.
    pub bytes: HostBuf,
}

/// The `out` of a request-path single-value read into a [`HostBuf`]: on READY `written` bytes are
/// in the buffer and `needed == 0`; a value over the capacity is the short-buffer answer (M-SB, on
/// [`OutHead`]) with `needed` its full length.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct HostBytesOut {
    /// The head.
    pub head: OutHead,
    /// [`FOUND`] or [`ABSENT`].
    pub found: u32,
    /// Alignment padding.
    pub _reserved: u32,
    /// How many bytes were written.
    pub written: u64,
    /// On a short FAILED, the value's full length; `0` otherwise.
    pub needed: u64,
}

/// The `out` of a request-path list written into host buffers: on READY `items_written` items and
/// `bytes_written` bytes are in the buffers and both `needed_*` are `0`; a list over either
/// capacity is the short-buffer answer (M-SB, on [`OutHead`]) with the full sizes in `needed_*`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct HostListOut {
    /// The head.
    pub head: OutHead,
    /// How many items were written.
    pub items_written: u64,
    /// How many bytes of the byte buffer the written items use.
    pub bytes_written: u64,
    /// On a short FAILED, how many items the whole answer holds; `0` otherwise.
    pub needed_items: u64,
    /// On a short FAILED, how many bytes the whole answer needs; `0` otherwise.
    pub needed_bytes: u64,
}

/// [`HostBytesOut::found`]: the record exists and was written.
pub const FOUND: u32 = 1;
/// [`HostBytesOut::found`] / [`LeasedBlobOut::found`]: no such record. `0`, so an `out` nobody
/// wrote reads as absent, never as a record.
pub const ABSENT: u32 = 0;

// ── shared off-path result shapes (mechanism memory class (iv)) ───────────────────────────────

/// The `out` of an off-path single-record read: a plugin-owned blob held under `head.lease`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct LeasedBlobOut {
    /// The head; `head.lease` holds `record` until `release`.
    pub head: OutHead,
    /// [`FOUND`] or [`ABSENT`].
    pub found: u32,
    /// Alignment padding.
    pub _reserved: u32,
    /// The record; absent when `found == ABSENT`.
    pub record: Blob,
}

/// The `out` of an off-path list of records: plugin-owned blobs held under `head.lease`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct LeasedListOut {
    /// The head; `head.lease` holds `items` and their bytes until `release`.
    pub head: OutHead,
    /// The records, in the op's stated order.
    pub items: *const Blob,
    /// How many.
    pub items_len: usize,
}

/// The `out` of an off-path list of strings: plugin-owned strings held under `head.lease`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct LeasedStrListOut {
    /// The head; `head.lease` holds `items` and their bytes until `release`.
    pub head: OutHead,
    /// The strings.
    pub items: *const AbiStr,
    /// How many.
    pub items_len: usize,
}

/// The `out` of a count (a purge's rows removed).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CountOut {
    /// The head.
    pub head: OutHead,
    /// The count.
    pub count: u64,
}

/// The `out` of a yes/no check. [`VERDICT_NO`] is `0`, so an `out` nobody wrote is a NO: the
/// token checks are fail-closed (records.rs:1548-1554, :1580-1587).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct VerdictOut {
    /// The head.
    pub head: OutHead,
    /// [`VERDICT_YES`] or [`VERDICT_NO`].
    pub verdict: u32,
    /// Alignment padding.
    pub _reserved: u32,
}

/// [`VerdictOut::verdict`]: no (and the fail-closed zero).
pub const VERDICT_NO: u32 = 0;
/// [`VerdictOut::verdict`]: yes.
pub const VERDICT_YES: u32 = 1;

// ── the Statement tail ───────────────────────────────────────────────────────────────────────

/// The store kind's Statement tail (B.1 "Tail": `durable_plane`, `fork_refusal`). Each fact is
/// `0` (no) or `1` (yes). `ephemeral` is a Statement mark, not a tail fact
/// ([`MARK_EPHEMERAL`](crate::abi::mechanism::door::MARK_EPHEMERAL); the design's One Statement rule).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct StoreTail {
    /// The head; `size == size_of::<StoreTail>()`.
    pub head: KindTailHead,
    /// The store keeps plane records durably (a store that does not answers the plane-record
    /// slots with nothing kept, as the 1.5.5-default RAM store did, records.rs:1481-1487).
    pub durable_plane: u8,
    /// The store refuses a DIFFERENT record at an already-used append sequence as a fork, rather
    /// than overwriting it (Q79-fork-refusal, THE DESIGN's owner questions, ruled 2026-09-27).
    pub fork_refusal: u8,
    /// Alignment padding.
    pub _reserved: [u8; 6],
}

impl StoreTail {
    /// THE EMPTY DECLARATION: every field zero (NULL lists, empty strings, no flags). A plugin
    /// builds its value as `StoreTail { …, ..StoreTail::ZERO }` so a field appended later reads as
    /// not declared.
    pub const ZERO: Self = Self {
        head: KindTailHead::ZERO,
        durable_plane: 0,
        fork_refusal: 0,
        _reserved: [0; 6],
    };
}

// ── the cancel vocabulary ────────────────────────────────────────────────────────────────────

/// [`CancelOut::disposition`](crate::abi::mechanism::lifecycle::CancelOut::disposition): the store
/// cannot say whether the cancelled op applied. `0`, so an unwritten disposition is the safe
/// reading: the kernel re-issues the op with the SAME `op_id`, and dedupe settles it.
pub const CANCEL_UNKNOWN: u32 = 0;
/// The cancelled op applied nothing.
pub const CANCEL_NOT_APPLIED: u32 = 1;
/// The cancelled op had committed; its original `out` is kept under its `op_id`, so a replay
/// returns it. A [`DeadlineClass::WriteBehind`] op is never cancelled on client drop or reload.
pub const CANCEL_APPLIED: u32 = 2;

// ── diagnostics ──────────────────────────────────────────────────────────────────────────────

/// The diagnostic id a store answers with REFUSED for an `op_id` replayed with a different body
/// (m3-inputs "store v3 money slots", DEDUPE). A store declares it in its Statement's `diag_ids`.
pub const DIAG_OPID_CONFLICT: &str = "STORE_OPID_CONFLICT";
/// How long a store remembers an `op_id`, at least (m3-inputs "store v3 money slots", DEDUPE:
/// "Retention ≥ 24h").
pub const OP_ID_RETENTION_SECS: u64 = 24 * 60 * 60;

// ── slots ────────────────────────────────────────────────────────────────────────────────────

/// Declares the kind slot indices, the table, [`OPS`], [`NAMES`] and [`MAX_PAYLOAD`] from ONE
/// list, so they cannot drift.
macro_rules! store_slots {
    ($( $k:literal $CONST:ident $field:ident $in:ty, $out:ty, $path:ident, $class:ident, $max:expr, $doc:literal; )*) => {
        /// [`InHead::op`](crate::abi::mechanism::call::InHead::op) of each store kind slot:
        /// `LIFECYCLE_SLOTS + k`.
        pub mod slot {
            use super::LIFECYCLE_SLOTS;
            $(
                #[doc = $doc]
                pub const $CONST: u32 = LIFECYCLE_SLOTS + $k;
            )*
        }

        /// The store kind's ops table: the shared [`OpsHead`], then one slot per kind op in
        /// [`slot`] order. `head.slots == TABLE_SLOTS`, `head.size == size_of::<Ops>()`.
        #[repr(C)]
        #[derive(Debug, Clone, Copy)]
        pub struct Ops {
            /// The lifecycle.
            pub head: OpsHead,
            $(
                #[doc = $doc]
                pub $field: Option<Op>,
            )*
        }

        /// Every kind slot's contract, in table order.
        ///
        /// Every op whose `out` states anything beyond [`OutHead`] has its answer validator in
        /// [`check`]. These ops are ANSWERED BY THE HEAD ONLY; CHECKED BY THE MECHANISM: their `out`
        /// is exactly [`OutHead`], which the dispatcher's mechanism checks validate on every
        /// crossing: `put_key`, `delete_key`, `put_usage`, `put_credential`,
        /// `put_key_with_credential`, `revoke_credential`, `add_denylist`, `upsert_plane_record`,
        /// `append_plane_record`, `delete_plane_record`, `record_put`, `add_usage_batch`,
        /// `add_metering_batch`.
        ///
        /// Every store op may answer PENDING: network stores use driver tickets.
        pub const OPS: [OpContract; KIND_SLOTS as usize] = [
            $(
                OpContract {
                    slot: slot::$CONST,
                    request_path: matches!(Path::$path, Path::Request),
                    may_pend: true,
                    max_in: std::mem::size_of::<$in>(),
                    max_out: std::mem::size_of::<$out>(),
                    deadline: DeadlineClass::$class,
                },
            )*
        ];

        /// Every kind slot's name, as its table field, in table order.
        pub const NAMES: [&str; KIND_SLOTS as usize] = [$(stringify!($field),)*];

        /// Every kind slot's payload bound, in table order.
        pub const MAX_PAYLOAD: [MaxPayload; KIND_SLOTS as usize] = [$($max,)*];
    };
}

/// How many kind slots the store table holds after the lifecycle.
pub const KIND_SLOTS: u32 = 31;
/// How many slots the whole store table holds, lifecycle included ([`OpsHead::slots`]).
pub const TABLE_SLOTS: u32 = LIFECYCLE_SLOTS + KIND_SLOTS;

/// Whether a slot runs on the request path: the table's row vocabulary for
/// [`OpContract::request_path`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Path {
    /// On the request path (B.1 "P").
    Request,
    /// Off the request path (B.1 "O").
    Off,
}

/// A payload bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaxPayload {
    /// Fixed fields only.
    Fixed,
    /// Each record at most this many bytes (`bounded.rs` `MAX_RECORD_BYTES`).
    PerRecord(usize),
    /// Bounded by the host's per-call response cap.
    HostCap,
}

use crate::bounded::MAX_RECORD_BYTES;
use MaxPayload::{Fixed, HostCap, PerRecord};

store_slots! {
    // ── keys (the 1.5.5 op set; v1.5.5 crates/api/src/store.rs:604-927) ──
    0 PUT_KEY put_key BlobIn, OutHead, Off, Call, HostCap,
        "`put_key`. In [`BlobIn`] (`VirtualKey`), out [`OutHead`]. TOMBSTONE PRECONDITION: a key with no `deleted_at` never overwrites a tombstoned row, FAILED instead.";
    1 GET_KEY get_key IdIn, LeasedBlobOut, Off, Call, HostCap,
        "`get_key`. In [`IdIn`] (key id), out [`LeasedBlobOut`] (`VirtualKey`).";
    2 LIST_KEYS list_keys InHead, LeasedListOut, Off, Call, HostCap,
        "`list_keys`. In [`InHead`], out [`LeasedListOut`] (`VirtualKey`s). UNFILTERED: tombstones included.";
    3 DELETE_KEY delete_key IdIn, OutHead, Off, Call, Fixed,
        "`delete_key`. In [`IdIn`], out [`OutHead`]. Tombstones atomically; already-tombstoned is READY; an unknown id is FAILED.";
    4 LIST_KEYS_SINCE list_keys_since U64In, LeasedListOut, Off, Call, HostCap,
        "`list_keys_since`. In [`U64In`] (`since`), out [`LeasedListOut`]. Tombstones included; `revision == 0` always listed.";
    // ── the ledger: counts only, never money ──
    5 GET_USAGE get_usage WindowIn, LeasedBlobOut, Off, Call, HostCap,
        "`get_usage`. In [`WindowIn`], out [`LeasedBlobOut`] (`UsageLedger`; an untouched cell is the empty ledger, FOUND).";
    6 PUT_USAGE put_usage PutUsageIn, OutHead, Off, Call, HostCap,
        "`put_usage`. In [`PutUsageIn`], out [`OutHead`]. An absolute set, single-writer only.";
    7 LIST_METERING list_metering U64In, LeasedListOut, Off, Call, HostCap,
        "`list_metering`. In [`U64In`] (metering bucket day start), out [`LeasedListOut`] (`MeteringRow`s).";
    // ── credentials ──
    8 PUT_CREDENTIAL put_credential BlobIn, OutHead, Off, Call, HostCap,
        "`put_credential`. In [`BlobIn`] (`CredentialSecret`, a secret blob), out [`OutHead`]. FAILED minting into a live slot.";
    9 PUT_KEY_WITH_CREDENTIAL put_key_with_credential KeyWithCredentialIn, OutHead, Off, Call, HostCap,
        "`put_key_with_credential`. In [`KeyWithCredentialIn`], out [`OutHead`]. Both rows or neither.";
    10 LIST_CREDENTIALS list_credentials IdIn, LeasedListOut, Off, Call, HostCap,
        "`list_credentials`. In [`IdIn`] (key id), out [`LeasedListOut`] (`CredentialMeta`s, never a secret).";
    11 REVOKE_CREDENTIAL revoke_credential IdReasonIn, OutHead, Off, Call, Fixed,
        "`revoke_credential`. In [`IdReasonIn`], out [`OutHead`]. Already-revoked is READY; an unknown id is FAILED.";
    12 LIST_CREDENTIALS_SINCE list_credentials_since U64In, LeasedListOut, Off, Call, HostCap,
        "`list_credentials_since`. In [`U64In`] (`since`), out [`LeasedListOut`] (`CredentialSecret`s, secret blobs).";
    // ── the 1.5.5 audit rows (read) and the denylist ──
    13 LIST_AUDIT list_audit InHead, LeasedListOut, Off, Call, HostCap,
        "`list_audit`. In [`InHead`], out [`LeasedListOut`] (`AuditRecord`s, oldest first).";
    14 ADD_DENYLIST add_denylist IdReasonIn, OutHead, Off, Call, Fixed,
        "`add_denylist`. In [`IdReasonIn`] (sub, reason), out [`OutHead`]. An idempotent set insert.";
    15 LIST_DENYLIST list_denylist InHead, LeasedStrListOut, Off, Call, HostCap,
        "`list_denylist`. In [`InHead`], out [`LeasedStrListOut`].";
    16 LIST_AUDIT_TAIL list_audit_tail U64In, LeasedListOut, Off, Call, HostCap,
        "`list_audit_tail`. In [`U64In`] (`limit`), out [`LeasedListOut`] (the last `limit`, oldest first).";
    // ── plane records ──
    17 UPSERT_PLANE_RECORD upsert_plane_record UpsertPlaneRecordIn, OutHead, Request, Call, HostCap,
        "`upsert_plane_record`. In [`UpsertPlaneRecordIn`], out [`OutHead`]. Keyed on (kind, id).";
    18 GET_PLANE_RECORD get_plane_record GetPlaneRecordIn, HostBytesOut, Request, Call, HostCap,
        "`get_plane_record`. In [`GetPlaneRecordIn`], out [`HostBytesOut`] (the body, into the host buffer).";
    19 APPEND_PLANE_RECORD append_plane_record AppendPlaneRecordIn, OutHead, Request, WriteBehind, HostCap,
        "`append_plane_record`. In [`AppendPlaneRecordIn`], out [`OutHead`]. Appending, op_id-deduped; a fork at a used seq is FAILED when the tail states `fork_refusal`.";
    20 LIST_PLANE_RECORDS list_plane_records ListPlaneRecordsIn, HostListOut, Request, Call, HostCap,
        "`list_plane_records`. In [`ListPlaneRecordsIn`], out [`HostListOut`] (bodies into [`HostBlobs`]).";
    21 LIST_PLANE_RECORD_PARENTS list_plane_record_parents IdIn, LeasedStrListOut, Off, Call, HostCap,
        "`list_plane_record_parents`. In [`IdIn`] (kind), out [`LeasedStrListOut`]. The boot enumeration.";
    22 PURGE_PLANE_RECORDS_BEFORE purge_plane_records_before KindBeforeIn, CountOut, Off, Call, Fixed,
        "`purge_plane_records_before`. In [`KindBeforeIn`], out [`CountOut`]. Honours `disposition` under the `retention` rule the host passes.";
    23 DELETE_PLANE_RECORD delete_plane_record KindIdIn, OutHead, Request, Call, Fixed,
        "`delete_plane_record`. In [`KindIdIn`], out [`OutHead`]. Absent is READY.";
    24 REDEEM_PLANE_TOKEN redeem_plane_token TokenIn, VerdictOut, Request, Call, Fixed,
        "`redeem_plane_token`. In [`TokenIn`], out [`VerdictOut`] (YES = this call was the first redemption). Fail-closed.";
    25 PLANE_TOKEN_LIVE plane_token_live TokenIn, VerdictOut, Request, Call, Fixed,
        "`plane_token_live`. In [`TokenIn`], out [`VerdictOut`] (spends nothing). Fail-closed.";
    // ── kernel-held records (the journal, node identity, the card history) ──
    26 RECORD_PUT record_put RecordPutIn, OutHead, Request, Call, PerRecord(MAX_RECORD_BYTES),
        "`record_put`. In [`RecordPutIn`], out [`OutHead`]. An upsert on (schema, key). An EMPTY value removes the row: `record_get` then answers absent and `record_scan` never returns it.";
    27 RECORD_GET record_get RecordGetIn, HostBytesOut, Request, Call, PerRecord(MAX_RECORD_BYTES),
        "`record_get`. In [`RecordGetIn`], out [`HostBytesOut`].";
    28 RECORD_SCAN record_scan RecordScanIn, HostListOut, Request, Call, PerRecord(MAX_RECORD_BYTES),
        "`record_scan`. In [`RecordScanIn`], out [`HostListOut`] (entries into [`HostRecords`]). `limit` 0 is nothing.";
    // ── the ledger's two writes: counts, op_id-deduped, atomic per batch ──
    29 ADD_USAGE_BATCH add_usage_batch AddUsageBatchIn, OutHead, Off, WriteBehind, HostCap,
        "`add_usage_batch`. In [`AddUsageBatchIn`], out [`OutHead`]. Additive counts; one op_id per batch; in order, atomic per batch.";
    30 ADD_METERING_BATCH add_metering_batch OpBlobsIn, OutHead, Off, WriteBehind, HostCap,
        "`add_metering_batch`. In [`OpBlobsIn`] (`MeteringDelta`s), out [`OutHead`]. Additive counts; one op_id per batch; in order, atomic per batch.";
}

// THE SDK's VIEW OF THE STORE TABLE (`abi::sdk::door`): each kind op's `in`/`out`, stated
// next to the table, so `plugin_door!` refuses a store plugin that wires a kind op to another
// op's structs. Every struct named here is plain data (integers, raw pointers, `AbiStr`/`Blob`,
// nested plain structs): every bit pattern is a valid value, which is what `AbiIn`/`AbiOut`
// promise.
//
// SAFETY (all below): `#[repr(C)]`, leading with `InHead`/`OutHead`, plain data only.
unsafe impl super::sdk::door::AbiIn for BlobIn {}
unsafe impl super::sdk::door::AbiIn for IdIn {}
unsafe impl super::sdk::door::AbiIn for U64In {}
unsafe impl super::sdk::door::AbiIn for WindowIn {}
unsafe impl super::sdk::door::AbiIn for PutUsageIn {}
unsafe impl super::sdk::door::AbiIn for KeyWithCredentialIn {}
unsafe impl super::sdk::door::AbiIn for KindIdIn {}
unsafe impl super::sdk::door::AbiIn for IdReasonIn {}
unsafe impl super::sdk::door::AbiIn for UpsertPlaneRecordIn {}
unsafe impl super::sdk::door::AbiIn for GetPlaneRecordIn {}
unsafe impl super::sdk::door::AbiIn for AppendPlaneRecordIn {}
unsafe impl super::sdk::door::AbiIn for ListPlaneRecordsIn {}
unsafe impl super::sdk::door::AbiIn for KindBeforeIn {}
unsafe impl super::sdk::door::AbiIn for TokenIn {}
unsafe impl super::sdk::door::AbiIn for RecordPutIn {}
unsafe impl super::sdk::door::AbiIn for RecordGetIn {}
unsafe impl super::sdk::door::AbiIn for RecordScanIn {}
unsafe impl super::sdk::door::AbiIn for AddUsageBatchIn {}
unsafe impl super::sdk::door::AbiIn for OpBlobsIn {}
unsafe impl super::sdk::door::AbiOut for LeasedBlobOut {}
unsafe impl super::sdk::door::AbiOut for LeasedListOut {}
unsafe impl super::sdk::door::AbiOut for CountOut {}
unsafe impl super::sdk::door::AbiOut for LeasedStrListOut {}
unsafe impl super::sdk::door::AbiOut for HostBytesOut {}
unsafe impl super::sdk::door::AbiOut for HostListOut {}
unsafe impl super::sdk::door::AbiOut for VerdictOut {}

super::sdk::door::slot_structs!(
    /// Each store kind op's `in`/`out` for [`plugin_door!`](crate::plugin_door), per [`OPS`]' table.
    /// A plugin wiring a slot to another op's structs does not compile:
    ///
    /// ```compile_fail,E0271
    /// use busbar_contract::abi::store::{AddUsageBatchIn, AppendPlaneRecordIn, BlobIn, CountOut};
    /// use busbar_contract::abi::store::{GetPlaneRecordIn, HostBytesOut, HostListOut, IdIn};
    /// use busbar_contract::abi::store::{IdReasonIn, InHead, KeyWithCredentialIn, KindBeforeIn};
    /// use busbar_contract::abi::store::{KindIdIn, LeasedBlobOut, LeasedListOut, LeasedStrListOut};
    /// use busbar_contract::abi::store::{ListPlaneRecordsIn, OpBlobsIn, OutHead, PutUsageIn};
    /// use busbar_contract::abi::store::RecordGetIn;
    /// use busbar_contract::abi::store::{RecordPutIn, RecordScanIn, TokenIn, U64In};
    /// use busbar_contract::abi::store::{UpsertPlaneRecordIn, VerdictOut, WindowIn};
    /// use busbar_contract::abi::mechanism::call::Outcome;
    /// use busbar_contract::abi::mechanism::lifecycle::*;
    /// use busbar_contract::abi::sdk::door::Slot;
    /// # use std::ffi::c_void;
    /// # macro_rules! ready { ($n:ident, $i:ty, $o:ty) => {
    /// #     struct $n;
    /// #     impl Slot for $n { type In = $i; type Out = $o;
    /// #         unsafe fn call(_: *mut c_void, _: &$i, _: &mut $o) -> Outcome { Outcome::Ready } }
    /// # } }
    /// # ready!(V, ValidateIn, OutHead); ready!(Op_, OpenIn, OpenOut); ready!(Rf, RefreshIn, OutHead);
    /// # ready!(Rt, GenIn, OutHead); ready!(Tk, TickIn, TickOut); ready!(Dr, DriveIn, OutHead);
    /// # ready!(Cn, CancelIn, CancelOut); ready!(Rl, ReleaseIn, OutHead); ready!(Cl, InHead, OutHead);
    /// # ready!(GetKey, IdIn, LeasedBlobOut); ready!(ListKeys, InHead, LeasedListOut);
    /// # ready!(DeleteKey, IdIn, OutHead); ready!(ListKeysSince, U64In, LeasedListOut);
    /// # ready!(GetUsage, WindowIn, LeasedBlobOut); ready!(PutUsage, PutUsageIn, OutHead);
    /// # ready!(ListMetering, U64In, LeasedListOut); ready!(PutCredential, BlobIn, OutHead);
    /// # ready!(PutKeyWithCredential, KeyWithCredentialIn, OutHead);
    /// # ready!(ListCredentials, IdIn, LeasedListOut);
    /// # ready!(RevokeCredential, IdReasonIn, OutHead);
    /// # ready!(ListCredentialsSince, U64In, LeasedListOut);
    /// # ready!(ListAudit, InHead, LeasedListOut); ready!(AddDenylist, IdReasonIn, OutHead);
    /// # ready!(ListDenylist, InHead, LeasedStrListOut);
    /// # ready!(ListAuditTail, U64In, LeasedListOut);
    /// # ready!(UpsertPlaneRecord, UpsertPlaneRecordIn, OutHead);
    /// # ready!(GetPlaneRecord, GetPlaneRecordIn, HostBytesOut);
    /// # ready!(AppendPlaneRecord, AppendPlaneRecordIn, OutHead);
    /// # ready!(ListPlaneRecords, ListPlaneRecordsIn, HostListOut);
    /// # ready!(ListPlaneRecordParents, IdIn, LeasedStrListOut);
    /// # ready!(PurgePlaneRecordsBefore, KindBeforeIn, CountOut);
    /// # ready!(DeletePlaneRecord, KindIdIn, OutHead);
    /// # ready!(RedeemPlaneToken, TokenIn, VerdictOut); ready!(PlaneTokenLive, TokenIn, VerdictOut);
    /// # ready!(RecordPut, RecordPutIn, OutHead); ready!(RecordGet, RecordGetIn, HostBytesOut);
    /// # ready!(RecordScan, RecordScanIn, HostListOut);
    /// # ready!(AddUsageBatch, AddUsageBatchIn, OutHead);
    /// # ready!(AddMeteringBatch, OpBlobsIn, OutHead);
    /// ready!(PutKey, IdIn, LeasedBlobOut); // `get_key`'s structs on `put_key`: refused
    /// busbar_contract::plugin_door! {
    ///     ops: busbar_contract::abi::store::Ops,
    ///     statement: busbar_contract::abi::sdk::door::statement("wrong", "0", 1),
    ///     lifecycle: { validate: V, open: Op_, refresh: Rf, retire: Rt, tick: Tk, drive: Dr,
    ///                  cancel: Cn, release: Rl, close: Cl },
    ///     kind_ops: {
    ///         put_key: PutKey, get_key: GetKey, list_keys: ListKeys, delete_key: DeleteKey,
    ///         list_keys_since: ListKeysSince, get_usage: GetUsage, put_usage: PutUsage,
    ///         list_metering: ListMetering,
    ///         put_credential: PutCredential,
    ///         put_key_with_credential: PutKeyWithCredential, list_credentials: ListCredentials,
    ///         revoke_credential: RevokeCredential, list_credentials_since: ListCredentialsSince,
    ///         list_audit: ListAudit, add_denylist: AddDenylist, list_denylist: ListDenylist,
    ///         list_audit_tail: ListAuditTail, upsert_plane_record: UpsertPlaneRecord,
    ///         get_plane_record: GetPlaneRecord, append_plane_record: AppendPlaneRecord,
    ///         list_plane_records: ListPlaneRecords,
    ///         list_plane_record_parents: ListPlaneRecordParents,
    ///         purge_plane_records_before: PurgePlaneRecordsBefore,
    ///         delete_plane_record: DeletePlaneRecord, redeem_plane_token: RedeemPlaneToken,
    ///         plane_token_live: PlaneTokenLive, record_put: RecordPut, record_get: RecordGet,
    ///         record_scan: RecordScan, add_usage_batch: AddUsageBatch,
    ///         add_metering_batch: AddMeteringBatch
    ///     },
    /// }
    /// # fn main() { let _ = door(); }
    /// ```
    ///
    /// With `PutKey` reading [`BlobIn`] and writing [`OutHead`] the same plugin
    /// compiles (`abi/sdk/tests/door_tests.rs`, `a_store_plugin_wires_every_kind_op`).
    Ops {
        slot::PUT_KEY => BlobIn, OutHead;
        slot::GET_KEY => IdIn, LeasedBlobOut;
        slot::LIST_KEYS => InHead, LeasedListOut;
        slot::DELETE_KEY => IdIn, OutHead;
        slot::LIST_KEYS_SINCE => U64In, LeasedListOut;
        slot::GET_USAGE => WindowIn, LeasedBlobOut;
        slot::PUT_USAGE => PutUsageIn, OutHead;
        slot::LIST_METERING => U64In, LeasedListOut;
        slot::PUT_CREDENTIAL => BlobIn, OutHead;
        slot::PUT_KEY_WITH_CREDENTIAL => KeyWithCredentialIn, OutHead;
        slot::LIST_CREDENTIALS => IdIn, LeasedListOut;
        slot::REVOKE_CREDENTIAL => IdReasonIn, OutHead;
        slot::LIST_CREDENTIALS_SINCE => U64In, LeasedListOut;
        slot::LIST_AUDIT => InHead, LeasedListOut;
        slot::ADD_DENYLIST => IdReasonIn, OutHead;
        slot::LIST_DENYLIST => InHead, LeasedStrListOut;
        slot::LIST_AUDIT_TAIL => U64In, LeasedListOut;
        slot::UPSERT_PLANE_RECORD => UpsertPlaneRecordIn, OutHead;
        slot::GET_PLANE_RECORD => GetPlaneRecordIn, HostBytesOut;
        slot::APPEND_PLANE_RECORD => AppendPlaneRecordIn, OutHead;
        slot::LIST_PLANE_RECORDS => ListPlaneRecordsIn, HostListOut;
        slot::LIST_PLANE_RECORD_PARENTS => IdIn, LeasedStrListOut;
        slot::PURGE_PLANE_RECORDS_BEFORE => KindBeforeIn, CountOut;
        slot::DELETE_PLANE_RECORD => KindIdIn, OutHead;
        slot::REDEEM_PLANE_TOKEN => TokenIn, VerdictOut;
        slot::PLANE_TOKEN_LIVE => TokenIn, VerdictOut;
        slot::RECORD_PUT => RecordPutIn, OutHead;
        slot::RECORD_GET => RecordGetIn, HostBytesOut;
        slot::RECORD_SCAN => RecordScanIn, HostListOut;
        slot::ADD_USAGE_BATCH => AddUsageBatchIn, OutHead;
        slot::ADD_METERING_BATCH => OpBlobsIn, OutHead;
    }
);
