// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE STORE KIND'S ABI (v3): its version, its table, its slots, its data shapes, its Statement
//! tail and its cancel vocabulary (THE DESIGN, the owner-locked plugin ABI: seven ABIs on one
//! mechanism, one place for every ABI shape; the signed per-kind design B.1 "store (v3)"; the
//! ARCHITECT rulings in `m3-inputs.md` "store v3 money slots" and "window caps").
//!
//! This is the M3 SPEC: shapes and numbers only. Nothing dispatches through them yet (M3-wire).
//!
//! # The table
//!
//! [`Ops`] is the shared [`OpsHead`] followed by one `Option<Op>` per kind slot, contiguous: the
//! kind slot `k` is at slot index [`LIFECYCLE_SLOTS`]` + k` ([`slot`]). A NULL slot refuses the
//! load: there are no UNSUPPORTED fallbacks and no floor (B.1 "Behaviour").
//!
//! ```
//! use busbar_contract::abi::mechanism::lifecycle::{OpsHead, LIFECYCLE_SLOTS};
//! use busbar_contract::abi::store::{slot, Ops, KIND_SLOTS, OPS, TABLE_SLOTS};
//! // Every kind slot index is LIFECYCLE_SLOTS + k, k = 0.., contiguous and in table order.
//! for (k, c) in OPS.iter().enumerate() {
//!     assert_eq!(c.slot, LIFECYCLE_SLOTS + k as u32, "{}", c.name);
//! }
//! assert_eq!(OPS.len() as u32, KIND_SLOTS);
//! assert_eq!(TABLE_SLOTS, LIFECYCLE_SLOTS + KIND_SLOTS);
//! assert_eq!(slot::PUT_KEY, LIFECYCLE_SLOTS);
//! assert_eq!(slot::WINDOW_CAPS, TABLE_SLOTS - 1);
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
//!   [`HostBlobs`], [`HostSessions`], [`HostRecords`], `reserve`'s grants, `slice_release`'s
//!   released amounts), never in the `out`, which the host zeroes before every call (mechanism
//!   memory class (i); ARCHITECT 2026-09-28). A result that does not fit is the short-buffer answer, M-SB, stated once on
//!   [`OutHead`] and not restated here; the answer validators in [`check`] enforce it.
//! * OFF-PATH results (the 1.5.5 lists and single records, `heads`) are plugin-owned under the
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
//! Every additive or appending write carries an [`OpId`] and uses [`DeadlineClass::WriteBehind`]
//! (B.1 "Writes"); `reserve` and `slice_release` carry one on the request path with
//! [`DeadlineClass::Call`] (m3-inputs "store v3 money slots", `reserve`/`slice_release`). The
//! rule, the same on every such slot (m3-inputs "store v3 money slots", DEDUPE, and "STORE v3 MONEY
//! RULINGS" S1-S4):
//! * S1 REPLAY: the same `op_id` replayed with the same body applies nothing and returns the
//!   ORIGINAL `out`; where the result lives in a host buffer the `in` names (`reserve`'s grants,
//!   `slice_release`'s released amounts) the replay RE-WRITES the ORIGINAL results into the NEW
//!   call's host buffers. The capacity check (M-SB) PRECEDES the replay lookup: a replay into a
//!   short buffer answers the short FAILED and writes nothing (S1 addendum).
//! * S2 SAME BODY means the op's VALUE fields only: the epoch, the cells or items, the amounts, the
//!   caps and the window fields. Host-buffer pointers and capacities are EXCLUDED. The same `op_id`
//!   with different value fields is never applied: the store answers REFUSED with the diagnostic
//!   [`DIAG_OPID_CONFLICT`].
//! * S3 WHAT IS RECORDED under an `op_id`: only an outcome that APPLIED a change (READY). A FAILED
//!   or REFUSED answer with nothing applied is NOT recorded, so a retry with the same `op_id` is
//!   evaluated afresh; a short-buffer FAILED (M-SB) is never recorded.
//! * S4 RETENTION: dedupe is DURABLE (it survives a store restart) and an `op_id` is remembered at
//!   least [`OP_ID_RETENTION_SECS`] (24 h). The kernel never re-issues an `op_id` older than that,
//!   and a store treats an `op_id` it does not know as new.

pub mod check;
mod layout;
pub mod ledger;
pub mod money;
pub mod plane;
pub mod records;

pub use ledger::*;
pub use money::*;
pub use plane::*;
pub use records::*;

use super::mechanism::call::{AbiStr, Blob, DeadlineClass, InHead, Op, OutHead};
use super::mechanism::door::KindTailHead;
use super::mechanism::lifecycle::{OpsHead, LIFECYCLE_SLOTS};

/// The store kind's ABI version: v1.5.5 shipped `2` (`ABI_VERSION`), so 1.6.0 ships `3`.
pub const ABI_VERSION: u32 = 3;

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

/// The store kind's Statement tail (B.1 "Tail": `ephemeral`, `durable_plane`, `fork_refusal`).
/// Each fact is `0` (no) or `1` (yes).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct StoreTail {
    /// The head; `size == size_of::<StoreTail>()`.
    pub head: KindTailHead,
    /// The store keeps nothing across a restart (the memory store). Was the load-time
    /// `LoadablePlugin::ephemeral` flag (registry.rs:120); now the plugin states it.
    pub ephemeral: u8,
    /// The store keeps plane records durably (a store that does not answers the plane-record
    /// slots with nothing kept, as the 1.5.5-default RAM store did, records.rs:1481-1487).
    pub durable_plane: u8,
    /// The store refuses a DIFFERENT record at an already-used append sequence as a fork, rather
    /// than overwriting it (Q79-fork-refusal, THE DESIGN's owner questions, ruled 2026-09-27).
    pub fork_refusal: u8,
    /// Alignment padding.
    pub _reserved: [u8; 5],
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
/// The diagnostic id a store answers with REFUSED for a `window_caps` cap at an EQUAL
/// `config_gen` with a different cap (m3-inputs ARCHITECT ruling "window caps").
pub const DIAG_CAP_CONFLICT: &str = "STORE_CAP_CONFLICT";
/// How long a store remembers an `op_id`, at least (m3-inputs "store v3 money slots", DEDUPE:
/// "Retention ≥ 24h").
pub const OP_ID_RETENTION_SECS: u64 = 24 * 60 * 60;

// ── slots ────────────────────────────────────────────────────────────────────────────────────

/// Declares the kind slot indices, the table and [`OPS`] from ONE list, so the three cannot drift.
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
        /// crossing: `put_key`, `delete_key`, `scrub_key`, `put_usage`, `add_usage`,
        /// `add_metering`, `put_credential`, `put_key_with_credential`, `revoke_credential`,
        /// `append_audit`, `add_denylist`, `upsert_plane_record`, `append_plane_record`,
        /// `delete_plane_record`, `session_put`, `session_remove`, `record_put`,
        /// `add_usage_batch`, `add_metering_batch`, `append_audit_batch`. (`window_caps` also
        /// answers with a bare [`OutHead`], but its REFUSED error text is checked by
        /// [`check::check_window_caps`].)
        pub const OPS: [OpContract; KIND_SLOTS as usize] = [
            $(
                OpContract {
                    slot: slot::$CONST,
                    name: stringify!($field),
                    path: Path::$path,
                    may_pend: true,
                    deadline: DeadlineClass::$class,
                    in_size: std::mem::size_of::<$in>(),
                    out_size: std::mem::size_of::<$out>(),
                    max_payload: $max,
                },
            )*
        ];
    };
}

/// How many kind slots the store table holds after the lifecycle.
pub const KIND_SLOTS: u32 = 47;
/// How many slots the whole store table holds, lifecycle included ([`OpsHead::slots`]).
pub const TABLE_SLOTS: u32 = LIFECYCLE_SLOTS + KIND_SLOTS;

/// Whether a slot runs on the request path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Path {
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

/// One kind slot's contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpContract {
    /// The slot index.
    pub slot: u32,
    /// The slot's name, as the table field.
    pub name: &'static str,
    /// Request path or off path.
    pub path: Path,
    /// Whether the op may answer PENDING (every store op may: network stores use driver tickets).
    pub may_pend: bool,
    /// The deadline class the host stamps in `InHead::deadline_class`.
    pub deadline: DeadlineClass,
    /// `size_of` the op's `in`.
    pub in_size: usize,
    /// `size_of` the op's `out`.
    pub out_size: usize,
    /// The payload bound.
    pub max_payload: MaxPayload,
}

use crate::bounded::MAX_RECORD_BYTES;
use MaxPayload::{Fixed, HostCap, PerRecord};

store_slots! {
    // ── the full 1.5.5 op set (B.1 "Slots": "the full 1.5.5 op set"; v1.5.5
    //    crates/api/src/store.rs:604-927, predev records.rs:1152-1479) ──
    0 PUT_KEY put_key BlobIn, OutHead, Off, Call, HostCap,
        "`put_key` (records.rs:1153-1175). In [`BlobIn`] (`VirtualKey`), out [`OutHead`]. B.1; TOMBSTONE PRECONDITION: a key with no `deleted_at` never overwrites a tombstoned row, FAILED instead.";
    1 GET_KEY get_key IdIn, LeasedBlobOut, Off, Call, HostCap,
        "`get_key` (records.rs:1176). In [`IdIn`] (key id), out [`LeasedBlobOut`] (`VirtualKey`). B.1.";
    2 LIST_KEYS list_keys InHead, LeasedListOut, Off, Call, HostCap,
        "`list_keys` (records.rs:1177-1183). In [`InHead`], out [`LeasedListOut`] (`VirtualKey`s). B.1; UNFILTERED: tombstones included.";
    3 DELETE_KEY delete_key IdIn, OutHead, Off, Call, Fixed,
        "`delete_key` (records.rs:1184-1207). In [`IdIn`], out [`OutHead`]. B.1; tombstones atomically; already-tombstoned is READY; an unknown id is FAILED.";
    4 SCRUB_KEY scrub_key IdIn, OutHead, Off, Call, Fixed,
        "`scrub_key` (records.rs:1208-1221). In [`IdIn`], out [`OutHead`]. B.1; FAILED for an unknown or live key.";
    5 LIST_KEYS_SINCE list_keys_since U64In, LeasedListOut, Off, Call, HostCap,
        "`list_keys_since` (records.rs:1222-1245). In [`U64In`] (`since`), out [`LeasedListOut`]. B.1; tombstones included; `revision == 0` always listed.";
    6 GET_USAGE get_usage WindowIn, LeasedBlobOut, Off, Call, HostCap,
        "`get_usage` (records.rs:1246-1250). In [`WindowIn`], out [`LeasedBlobOut`] (`UsageLedger`; an untouched cell is the empty ledger, FOUND). B.1.";
    7 PUT_USAGE put_usage PutUsageIn, OutHead, Off, Call, HostCap,
        "`put_usage` (records.rs:1252-1261). In [`PutUsageIn`], out [`OutHead`]. B.1; an absolute set, single-writer only.";
    8 ADD_USAGE add_usage AddUsageIn, OutHead, Off, WriteBehind, HostCap,
        "`add_usage` (records.rs:1263-1281). In [`AddUsageIn`] (`op_id` + one [`UsageCell`]), out [`OutHead`]. B.1 \"Writes\": additive, op_id-deduped, write_behind.";
    9 ADD_METERING add_metering OpBlobIn, OutHead, Off, WriteBehind, HostCap,
        "`add_metering` (records.rs:1283-1286). In [`OpBlobIn`] (`MeteringDelta`), out [`OutHead`]. B.1 \"Writes\": additive, op_id-deduped, write_behind.";
    10 LIST_METERING list_metering U64In, LeasedListOut, Off, Call, HostCap,
        "`list_metering` (records.rs:1288-1290). In [`U64In`] (metering bucket day start), out [`LeasedListOut`] (`MeteringRow`s). B.1.";
    11 PURGE_WINDOWS_BEFORE purge_windows_before U64In, CountOut, Off, Call, Fixed,
        "`purge_windows_before` (records.rs:1292-1304). In [`U64In`] (`before`), out [`CountOut`]. B.1; background sweeper only.";
    12 PURGE_METERING_BEFORE purge_metering_before IdIn, CountOut, Off, Call, Fixed,
        "`purge_metering_before` (records.rs:1306-1315). In [`IdIn`] (bucket), out [`CountOut`]. B.1; operator action only, never a sweeper.";
    13 PUT_CREDENTIAL put_credential BlobIn, OutHead, Off, Call, HostCap,
        "`put_credential` (records.rs:1317-1332). In [`BlobIn`] (`CredentialSecret`, a secret blob), out [`OutHead`]. B.1; FAILED minting into a live slot.";
    14 PUT_KEY_WITH_CREDENTIAL put_key_with_credential KeyWithCredentialIn, OutHead, Off, Call, HostCap,
        "`put_key_with_credential` (records.rs:1334-1345). In [`KeyWithCredentialIn`], out [`OutHead`]. B.1; both rows or neither.";
    15 LIST_CREDENTIALS list_credentials IdIn, LeasedListOut, Off, Call, HostCap,
        "`list_credentials` (records.rs:1347-1354). In [`IdIn`] (key id), out [`LeasedListOut`] (`CredentialMeta`s, never a secret). B.1.";
    16 LOOKUP_CREDENTIAL_SECRET lookup_credential_secret KindIdIn, LeasedBlobOut, Off, Call, HostCap,
        "`lookup_credential_secret` (records.rs:1356-1368). In [`KindIdIn`] (kind, public id), out [`LeasedBlobOut`] (`CredentialSecret`, a secret blob; unknown is ABSENT, never FAILED). B.1.";
    17 REVOKE_CREDENTIAL revoke_credential IdReasonIn, OutHead, Off, Call, Fixed,
        "`revoke_credential` (records.rs:1370-1384). In [`IdReasonIn`], out [`OutHead`]. B.1; already-revoked is READY; an unknown id is FAILED.";
    18 LIST_CREDENTIALS_SINCE list_credentials_since U64In, LeasedListOut, Off, Call, HostCap,
        "`list_credentials_since` (records.rs:1386-1405). In [`U64In`] (`since`), out [`LeasedListOut`] (`CredentialSecret`s, secret blobs). B.1.";
    19 APPEND_AUDIT append_audit OpBlobIn, OutHead, Off, WriteBehind, HostCap,
        "`append_audit` (records.rs:1407-1432). In [`OpBlobIn`] (`AuditRecord`), out [`OutHead`]. B.1 \"Writes\": appending, op_id-deduped, write_behind; a DIFFERENT record at a used `seq` is FAILED (a fork).";
    20 LIST_AUDIT list_audit InHead, LeasedListOut, Off, Call, HostCap,
        "`list_audit` (records.rs:1434-1440). In [`InHead`], out [`LeasedListOut`] (`AuditRecord`s, oldest first). B.1.";
    21 ADD_DENYLIST add_denylist IdReasonIn, OutHead, Off, Call, Fixed,
        "`add_denylist` (records.rs:1442-1455). In [`IdReasonIn`] (sub, reason), out [`OutHead`]. B.1; an idempotent set insert.";
    22 LIST_DENYLIST list_denylist InHead, LeasedStrListOut, Off, Call, HostCap,
        "`list_denylist` (records.rs:1457-1461). In [`InHead`], out [`LeasedStrListOut`]. B.1.";
    23 LIST_AUDIT_TAIL list_audit_tail U64In, LeasedListOut, Off, Call, HostCap,
        "`list_audit_tail` (records.rs:1463-1479). In [`U64In`] (`limit`), out [`LeasedListOut`] (the last `limit`, oldest first). B.1.";
    // ── plane records (B.1 "Slots": "plane records"; records.rs:1481-1597) ──
    24 UPSERT_PLANE_RECORD upsert_plane_record UpsertPlaneRecordIn, OutHead, Request, Call, HostCap,
        "`upsert_plane_record` (records.rs:1489-1497). In [`UpsertPlaneRecordIn`], out [`OutHead`]. B.1 plane records; keyed on (kind, id).";
    25 GET_PLANE_RECORD get_plane_record GetPlaneRecordIn, HostBytesOut, Request, Call, HostCap,
        "`get_plane_record` (records.rs:1499-1503). In [`GetPlaneRecordIn`], out [`HostBytesOut`] (the body, into the host buffer). B.1 plane records.";
    26 APPEND_PLANE_RECORD append_plane_record AppendPlaneRecordIn, OutHead, Request, WriteBehind, HostCap,
        "`append_plane_record` (records.rs:1505-1511). In [`AppendPlaneRecordIn`], out [`OutHead`]. B.1 plane records + \"Writes\": appending, op_id-deduped, write_behind; a fork at a used seq is FAILED when the tail states `fork_refusal`. A request waits on this long, never-cancelled class: B.1 makes every appending write write_behind.";
    27 LIST_PLANE_RECORDS list_plane_records ListPlaneRecordsIn, HostListOut, Request, Call, HostCap,
        "`list_plane_records` (records.rs:1513-1522). In [`ListPlaneRecordsIn`], out [`HostListOut`] (bodies into [`HostBlobs`]). B.1 plane records.";
    28 LIST_PLANE_RECORD_PARENTS list_plane_record_parents IdIn, LeasedStrListOut, Off, Call, HostCap,
        "`list_plane_record_parents` (records.rs:1524-1528). In [`IdIn`] (kind), out [`LeasedStrListOut`]. B.1 plane records; the boot enumeration.";
    29 PURGE_PLANE_RECORDS_BEFORE purge_plane_records_before KindBeforeIn, CountOut, Off, Call, Fixed,
        "`purge_plane_records_before` (records.rs:1530-1538). In [`KindBeforeIn`], out [`CountOut`]. B.1 plane records; honours `disposition`.";
    30 DELETE_PLANE_RECORD delete_plane_record KindIdIn, OutHead, Request, Call, Fixed,
        "`delete_plane_record` (records.rs:1540-1543). In [`KindIdIn`], out [`OutHead`]. B.1 plane records; absent is READY.";
    31 REDEEM_PLANE_TOKEN redeem_plane_token TokenIn, VerdictOut, Request, Call, Fixed,
        "`redeem_plane_token` (records.rs:1545-1563). In [`TokenIn`], out [`VerdictOut`] (YES = this call was the first redemption). B.1 plane records; fail-closed.";
    32 PLANE_TOKEN_LIVE plane_token_live TokenIn, VerdictOut, Request, Call, Fixed,
        "`plane_token_live` (records.rs:1565-1596). In [`TokenIn`], out [`VerdictOut`] (spends nothing). B.1 plane records; fail-closed.";
    // ── the ten 1.6.0 ledger ops (B.1 "Slots"; semantics store_adapter.rs, signatures kinds.rs:300-392) ──
    33 APPEND_BATCH append_batch AppendBatchIn, HeadOut, Off, WriteBehind, PerRecord(MAX_RECORD_BYTES),
        "`append_batch` (kinds.rs:302). In [`AppendBatchIn`], out [`HeadOut`]. B.1 ledger op + \"Writes\"; the shipping ack.";
    34 RESERVE reserve ReserveIn, ReserveOut, Request, Call, HostCap,
        "`reserve` (m3-inputs \"store v3 money slots\" `reserve`; each cell names its window and a failure names its cell per the \"window caps\" correction). In [`ReserveIn`], out [`ReserveOut`]. ATOMIC.";
    35 SLICE_RELEASE slice_release SliceReleaseIn, SliceReleaseOut, Request, Call, HostCap,
        "`slice_release` (m3-inputs \"store v3 money slots\" `slice_release`; B.1 renames the slice op `release`). In [`SliceReleaseIn`], out [`SliceReleaseOut`]. Clamped.";
    36 HEADS heads InHead, HeadsOut, Off, Call, HostCap,
        "`heads` (kinds.rs:319). In [`InHead`], out [`HeadsOut`]. B.1 ledger op.";
    37 SESSION_PUT session_put SessionPutIn, OutHead, Off, Call, Fixed,
        "`session_put` (kinds.rs:340). In [`SessionPutIn`], out [`OutHead`]. B.1 ledger op; an upsert on the session id.";
    38 SESSION_REMOVE session_remove U64In, OutHead, Off, Call, Fixed,
        "`session_remove` (kinds.rs:348). In [`U64In`] (session id), out [`OutHead`]. B.1 ledger op; absent is READY.";
    39 SESSIONS_FOR sessions_for SessionsForIn, HostListOut, Request, Call, HostCap,
        "`sessions_for` (kinds.rs:351). In [`SessionsForIn`], out [`HostListOut`] (rows into [`HostSessions`]). B.1 ledger op.";
    40 RECORD_PUT record_put RecordPutIn, OutHead, Request, Call, PerRecord(MAX_RECORD_BYTES),
        "`record_put` (kinds.rs:355). In [`RecordPutIn`], out [`OutHead`]. B.1 ledger op; an upsert on (schema, key).";
    41 RECORD_GET record_get RecordGetIn, HostBytesOut, Request, Call, PerRecord(MAX_RECORD_BYTES),
        "`record_get` (kinds.rs:363). In [`RecordGetIn`], out [`HostBytesOut`]. B.1 ledger op.";
    42 RECORD_SCAN record_scan RecordScanIn, HostListOut, Request, Call, PerRecord(MAX_RECORD_BYTES),
        "`record_scan` (kinds.rs:370). In [`RecordScanIn`], out [`HostListOut`] (entries into [`HostRecords`]). B.1 ledger op; `limit` 0 is nothing.";
    // ── batch slots (B.1 "Slots"; m3-inputs "store v3 money slots" batch ops) ──
    43 ADD_USAGE_BATCH add_usage_batch AddUsageBatchIn, OutHead, Off, WriteBehind, HostCap,
        "`add_usage_batch` (m3-inputs \"store v3 money slots\"). In [`AddUsageBatchIn`], out [`OutHead`]. One op_id per coalesced batch; in order, atomic per batch.";
    44 ADD_METERING_BATCH add_metering_batch OpBlobsIn, OutHead, Off, WriteBehind, HostCap,
        "`add_metering_batch` (m3-inputs \"store v3 money slots\"). In [`OpBlobsIn`] (`MeteringDelta`s), out [`OutHead`]. One op_id per coalesced batch; in order, atomic per batch.";
    45 APPEND_AUDIT_BATCH append_audit_batch OpBlobsIn, OutHead, Off, WriteBehind, HostCap,
        "`append_audit_batch` (m3-inputs \"store v3 money slots\"). In [`OpBlobsIn`] (`AuditRecord`s), out [`OutHead`]. One op_id per coalesced batch; in order, atomic per batch.";
    // ── the cap input (m3-inputs "store v3 money slots" line on Exhausted; ARCHITECT ruling "window caps") ──
    46 WINDOW_CAPS window_caps WindowCapsIn, OutHead, Off, Call, HostCap,
        "`window_caps` (m3-inputs ARCHITECT ruling \"window caps\"). In [`WindowCapsIn`], out [`OutHead`]. An upsert by (cell, window_start), newest `config_gen` wins; atomic per push (\"window caps\" correction (1)).";
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
unsafe impl super::sdk::door::AbiIn for AddUsageIn {}
unsafe impl super::sdk::door::AbiIn for OpBlobIn {}
unsafe impl super::sdk::door::AbiIn for KeyWithCredentialIn {}
unsafe impl super::sdk::door::AbiIn for KindIdIn {}
unsafe impl super::sdk::door::AbiIn for IdReasonIn {}
unsafe impl super::sdk::door::AbiIn for UpsertPlaneRecordIn {}
unsafe impl super::sdk::door::AbiIn for GetPlaneRecordIn {}
unsafe impl super::sdk::door::AbiIn for AppendPlaneRecordIn {}
unsafe impl super::sdk::door::AbiIn for ListPlaneRecordsIn {}
unsafe impl super::sdk::door::AbiIn for KindBeforeIn {}
unsafe impl super::sdk::door::AbiIn for TokenIn {}
unsafe impl super::sdk::door::AbiIn for AppendBatchIn {}
unsafe impl super::sdk::door::AbiIn for ReserveIn {}
unsafe impl super::sdk::door::AbiIn for SliceReleaseIn {}
unsafe impl super::sdk::door::AbiIn for SessionPutIn {}
unsafe impl super::sdk::door::AbiIn for SessionsForIn {}
unsafe impl super::sdk::door::AbiIn for RecordPutIn {}
unsafe impl super::sdk::door::AbiIn for RecordGetIn {}
unsafe impl super::sdk::door::AbiIn for RecordScanIn {}
unsafe impl super::sdk::door::AbiIn for AddUsageBatchIn {}
unsafe impl super::sdk::door::AbiIn for OpBlobsIn {}
unsafe impl super::sdk::door::AbiIn for WindowCapsIn {}
unsafe impl super::sdk::door::AbiOut for LeasedBlobOut {}
unsafe impl super::sdk::door::AbiOut for LeasedListOut {}
unsafe impl super::sdk::door::AbiOut for CountOut {}
unsafe impl super::sdk::door::AbiOut for LeasedStrListOut {}
unsafe impl super::sdk::door::AbiOut for HostBytesOut {}
unsafe impl super::sdk::door::AbiOut for HostListOut {}
unsafe impl super::sdk::door::AbiOut for VerdictOut {}
unsafe impl super::sdk::door::AbiOut for HeadOut {}
unsafe impl super::sdk::door::AbiOut for ReserveOut {}
unsafe impl super::sdk::door::AbiOut for SliceReleaseOut {}
unsafe impl super::sdk::door::AbiOut for HeadsOut {}

/// Each store kind op's `in`/`out` for [`plugin_door!`](crate::plugin_door), per [`OPS`]' table.
/// A plugin wiring a slot to another op's structs does not compile:
///
/// ```compile_fail,E0271
/// use busbar_contract::abi::store::{AddUsageBatchIn, AddUsageIn, AppendBatchIn};
/// use busbar_contract::abi::store::{AppendPlaneRecordIn, BlobIn, CountOut, GetPlaneRecordIn};
/// use busbar_contract::abi::store::{HeadOut, HeadsOut, HostBytesOut, HostListOut, IdIn};
/// use busbar_contract::abi::store::{IdReasonIn, InHead, KeyWithCredentialIn, KindBeforeIn};
/// use busbar_contract::abi::store::{KindIdIn, LeasedBlobOut, LeasedListOut, LeasedStrListOut};
/// use busbar_contract::abi::store::{ListPlaneRecordsIn, OpBlobIn, OpBlobsIn, OutHead, PutUsageIn};
/// use busbar_contract::abi::store::{RecordGetIn, RecordPutIn, RecordScanIn, ReserveIn};
/// use busbar_contract::abi::store::{ReserveOut, SessionPutIn, SessionsForIn, SliceReleaseIn};
/// use busbar_contract::abi::store::{SliceReleaseOut, TokenIn, U64In, UpsertPlaneRecordIn};
/// use busbar_contract::abi::store::{VerdictOut, WindowCapsIn, WindowIn};
/// use busbar_contract::abi::mechanism::call::Outcome;
/// use busbar_contract::abi::mechanism::lifecycle::*;
/// use busbar_contract::abi::sdk::door::Slot;
/// # use std::ffi::c_void;
/// # macro_rules! ready { ($n:ident, $i:ty, $o:ty) => {
/// #     struct $n;
/// #     impl Slot for $n { type In = $i; type Out = $o;
/// #         fn call(_: *mut c_void, _: &$i, _: &mut $o) -> Outcome { Outcome::Ready } }
/// # } }
/// # ready!(V, ValidateIn, OutHead); ready!(Op_, OpenIn, OpenOut); ready!(Rf, RefreshIn, OutHead);
/// # ready!(Rt, GenIn, OutHead); ready!(Tk, TickIn, TickOut); ready!(Dr, DriveIn, OutHead);
/// # ready!(Cn, CancelIn, CancelOut); ready!(Rl, ReleaseIn, OutHead); ready!(Cl, InHead, OutHead);
/// # ready!(GetKey, IdIn, LeasedBlobOut); ready!(ListKeys, InHead, LeasedListOut);
/// # ready!(DeleteKey, IdIn, OutHead); ready!(ScrubKey, IdIn, OutHead);
/// # ready!(ListKeysSince, U64In, LeasedListOut); ready!(GetUsage, WindowIn, LeasedBlobOut);
/// # ready!(PutUsage, PutUsageIn, OutHead); ready!(AddUsage, AddUsageIn, OutHead);
/// # ready!(AddMetering, OpBlobIn, OutHead); ready!(ListMetering, U64In, LeasedListOut);
/// # ready!(PurgeWindowsBefore, U64In, CountOut); ready!(PurgeMeteringBefore, IdIn, CountOut);
/// # ready!(PutCredential, BlobIn, OutHead);
/// # ready!(PutKeyWithCredential, KeyWithCredentialIn, OutHead);
/// # ready!(ListCredentials, IdIn, LeasedListOut);
/// # ready!(LookupCredentialSecret, KindIdIn, LeasedBlobOut);
/// # ready!(RevokeCredential, IdReasonIn, OutHead);
/// # ready!(ListCredentialsSince, U64In, LeasedListOut); ready!(AppendAudit, OpBlobIn, OutHead);
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
/// # ready!(AppendBatch, AppendBatchIn, HeadOut); ready!(Reserve, ReserveIn, ReserveOut);
/// # ready!(SliceRelease, SliceReleaseIn, SliceReleaseOut); ready!(Heads, InHead, HeadsOut);
/// # ready!(SessionPut, SessionPutIn, OutHead); ready!(SessionRemove, U64In, OutHead);
/// # ready!(SessionsFor, SessionsForIn, HostListOut); ready!(RecordPut, RecordPutIn, OutHead);
/// # ready!(RecordGet, RecordGetIn, HostBytesOut);
/// # ready!(RecordScan, RecordScanIn, HostListOut);
/// # ready!(AddUsageBatch, AddUsageBatchIn, OutHead);
/// # ready!(AddMeteringBatch, OpBlobsIn, OutHead); ready!(AppendAuditBatch, OpBlobsIn, OutHead);
/// # ready!(WindowCaps, WindowCapsIn, OutHead);
/// ready!(PutKey, IdIn, LeasedBlobOut); // `get_key`'s structs on `put_key`: refused
/// busbar_contract::plugin_door! {
///     ops: busbar_contract::abi::store::Ops,
///     statement: busbar_contract::abi::sdk::door::statement("wrong", "0", 1),
///     lifecycle: { validate: V, open: Op_, refresh: Rf, retire: Rt, tick: Tk, drive: Dr,
///                  cancel: Cn, release: Rl, close: Cl },
///     kind_ops: {
///         put_key: PutKey, get_key: GetKey, list_keys: ListKeys, delete_key: DeleteKey,
///         scrub_key: ScrubKey, list_keys_since: ListKeysSince, get_usage: GetUsage,
///         put_usage: PutUsage, add_usage: AddUsage, add_metering: AddMetering,
///         list_metering: ListMetering, purge_windows_before: PurgeWindowsBefore,
///         purge_metering_before: PurgeMeteringBefore, put_credential: PutCredential,
///         put_key_with_credential: PutKeyWithCredential, list_credentials: ListCredentials,
///         lookup_credential_secret: LookupCredentialSecret,
///         revoke_credential: RevokeCredential, list_credentials_since: ListCredentialsSince,
///         append_audit: AppendAudit, list_audit: ListAudit, add_denylist: AddDenylist,
///         list_denylist: ListDenylist, list_audit_tail: ListAuditTail,
///         upsert_plane_record: UpsertPlaneRecord, get_plane_record: GetPlaneRecord,
///         append_plane_record: AppendPlaneRecord, list_plane_records: ListPlaneRecords,
///         list_plane_record_parents: ListPlaneRecordParents,
///         purge_plane_records_before: PurgePlaneRecordsBefore,
///         delete_plane_record: DeletePlaneRecord, redeem_plane_token: RedeemPlaneToken,
///         plane_token_live: PlaneTokenLive, append_batch: AppendBatch, reserve: Reserve,
///         slice_release: SliceRelease, heads: Heads, session_put: SessionPut,
///         session_remove: SessionRemove, sessions_for: SessionsFor, record_put: RecordPut,
///         record_get: RecordGet, record_scan: RecordScan, add_usage_batch: AddUsageBatch,
///         add_metering_batch: AddMeteringBatch, append_audit_batch: AppendAuditBatch,
///         window_caps: WindowCaps
///     },
/// }
/// # fn main() { let _ = door(); }
/// ```
///
/// With `PutKey` reading [`BlobIn`] and writing [`OutHead`] the same plugin
/// compiles (`abi/sdk/tests/door_tests.rs`, `a_store_plugin_wires_every_kind_op`).
macro_rules! kind_slots {
    ($($slot:ident => $in:ty, $out:ty;)*) => {$(
        // SAFETY: the structs `OPS`' table states for this slot.
        unsafe impl super::sdk::door::KindSlot<{ slot::$slot }> for Ops {
            type In = $in;
            type Out = $out;
        }
    )*};
}

kind_slots! {
    PUT_KEY => BlobIn, OutHead;
    GET_KEY => IdIn, LeasedBlobOut;
    LIST_KEYS => InHead, LeasedListOut;
    DELETE_KEY => IdIn, OutHead;
    SCRUB_KEY => IdIn, OutHead;
    LIST_KEYS_SINCE => U64In, LeasedListOut;
    GET_USAGE => WindowIn, LeasedBlobOut;
    PUT_USAGE => PutUsageIn, OutHead;
    ADD_USAGE => AddUsageIn, OutHead;
    ADD_METERING => OpBlobIn, OutHead;
    LIST_METERING => U64In, LeasedListOut;
    PURGE_WINDOWS_BEFORE => U64In, CountOut;
    PURGE_METERING_BEFORE => IdIn, CountOut;
    PUT_CREDENTIAL => BlobIn, OutHead;
    PUT_KEY_WITH_CREDENTIAL => KeyWithCredentialIn, OutHead;
    LIST_CREDENTIALS => IdIn, LeasedListOut;
    LOOKUP_CREDENTIAL_SECRET => KindIdIn, LeasedBlobOut;
    REVOKE_CREDENTIAL => IdReasonIn, OutHead;
    LIST_CREDENTIALS_SINCE => U64In, LeasedListOut;
    APPEND_AUDIT => OpBlobIn, OutHead;
    LIST_AUDIT => InHead, LeasedListOut;
    ADD_DENYLIST => IdReasonIn, OutHead;
    LIST_DENYLIST => InHead, LeasedStrListOut;
    LIST_AUDIT_TAIL => U64In, LeasedListOut;
    UPSERT_PLANE_RECORD => UpsertPlaneRecordIn, OutHead;
    GET_PLANE_RECORD => GetPlaneRecordIn, HostBytesOut;
    APPEND_PLANE_RECORD => AppendPlaneRecordIn, OutHead;
    LIST_PLANE_RECORDS => ListPlaneRecordsIn, HostListOut;
    LIST_PLANE_RECORD_PARENTS => IdIn, LeasedStrListOut;
    PURGE_PLANE_RECORDS_BEFORE => KindBeforeIn, CountOut;
    DELETE_PLANE_RECORD => KindIdIn, OutHead;
    REDEEM_PLANE_TOKEN => TokenIn, VerdictOut;
    PLANE_TOKEN_LIVE => TokenIn, VerdictOut;
    APPEND_BATCH => AppendBatchIn, HeadOut;
    RESERVE => ReserveIn, ReserveOut;
    SLICE_RELEASE => SliceReleaseIn, SliceReleaseOut;
    HEADS => InHead, HeadsOut;
    SESSION_PUT => SessionPutIn, OutHead;
    SESSION_REMOVE => U64In, OutHead;
    SESSIONS_FOR => SessionsForIn, HostListOut;
    RECORD_PUT => RecordPutIn, OutHead;
    RECORD_GET => RecordGetIn, HostBytesOut;
    RECORD_SCAN => RecordScanIn, HostListOut;
    ADD_USAGE_BATCH => AddUsageBatchIn, OutHead;
    ADD_METERING_BATCH => OpBlobsIn, OutHead;
    APPEND_AUDIT_BATCH => OpBlobsIn, OutHead;
    WINDOW_CAPS => WindowCapsIn, OutHead;
}
