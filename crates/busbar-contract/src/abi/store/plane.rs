// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! PLANE RECORDS as store v3 slots (B.1 "Slots": "plane records"): the neutral kind-tagged verbs
//! of `records.rs:1481-1597`. The sidecar `{kind, id, parent, seq, ts, disposition}` is fixed; the
//! body is opaque octets the store keeps verbatim and never decodes. Reads on the request path
//! write into HOST buffers under the short-buffer answer (M-SB, stated on the mechanism's `OutHead`).

use super::money::OpId;
use super::{HostBlobs, HostBuf};
use crate::abi::mechanism::call::{AbiStr, Blob, InHead};
use crate::abi::mechanism::decl::abi_struct;

/// [`PlaneRecordRow::disposition`]: the record may still change (`PlaneDisposition::Active`).
/// `0`, so an unwritten disposition is kept by a terminal-only purge, never dropped.
pub const DISPOSITION_ACTIVE: u32 = 0;
/// [`PlaneRecordRow::disposition`]: the record is final (`PlaneDisposition::Terminal`).
pub const DISPOSITION_TERMINAL: u32 = 1;

/// [`ListPlaneRecordsIn::selector`]: every record of the kind (`PlaneSelector::All`).
pub const SELECT_ALL: u32 = 0;
/// [`ListPlaneRecordsIn::selector`]: one parent's records, oldest first by `seq`
/// (`PlaneSelector::Parent`).
pub const SELECT_PARENT: u32 = 1;

/// [`KindBeforeIn::retention`]: every row of the kind older than `before` goes (`Retention::Age`).
/// `0`, so an `in` that ends before the field (an older host's) purges by age, as that host did.
pub const RETENTION_AGE: u32 = 0;
/// [`KindBeforeIn::retention`]: only the kind's `DISPOSITION_TERMINAL` rows older than `before`
/// go (`Retention::TerminalOnly`); an active row is kept however old.
pub const RETENTION_TERMINAL_ONLY: u32 = 1;

/// [`KindBeforeIn::retention`]: THE USAGE LEDGER'S PURGE (open160 ST6; no slot of its own, so the
/// table's layout does not move). `kind` is empty; every usage window (the `(bucket,
/// window_start)` cells `get_usage`, `put_usage` and `add_usage_batch` keep) whose `window_start`
/// is NONZERO and earlier than `before` goes, and the answer counts the windows removed. The
/// all-time window `0` is never purged. The kernel drives it past its own 31-day window horizon:
/// nothing reads a durable window older than that. A store built before this code refuses it, as
/// any unknown code.
pub const RETENTION_USAGE_WINDOWS: u32 = 2;

abi_struct! {
    /// One plane record: `records.rs` `PlaneRecord`, its sidecar fixed and its body opaque.
    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    pub struct PlaneRecordRow {
        /// The record's kind.
        pub kind: AbiStr,
        /// Its id within the kind.
        pub id: AbiStr,
        /// Its parent; absent = `None` (a top-level kind).
        pub parent: AbiStr,
        /// Monotonic sequence within `parent`; `0` for upsert kinds.
        pub seq: u64,
        /// Its timestamp (Unix seconds), the purge axis.
        pub ts: u64,
        /// [`DISPOSITION_ACTIVE`] | [`DISPOSITION_TERMINAL`].
        pub disposition: u32,
        /// Alignment padding.
        pub _reserved: u32,
        /// The opaque body ([`BLOB_OCTETS`](crate::abi::mechanism::call::BLOB_OCTETS)).
        pub body: Blob,
    }

    /// `upsert_plane_record`'s `in`: UPSERT by `(kind, id)` (records.rs:1489-1497).
    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    pub struct UpsertPlaneRecordIn {
        /// The head.
        pub head: InHead,
        /// The record.
        pub record: PlaneRecordRow,
    }

    /// `append_plane_record`'s `in`: APPEND within `parent` at `seq` (records.rs:1505-1511); an
    /// appending write, deduped on `op_id` (B.1 "Writes"). A DIFFERENT record at an already-used
    /// `seq` is refused as a fork by a store whose tail states `fork_refusal`.
    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    pub struct AppendPlaneRecordIn {
        /// The head.
        pub head: InHead,
        /// The kernel-minted id of this write.
        pub op_id: OpId,
        /// The record.
        pub record: PlaneRecordRow,
    }

    /// `get_plane_record`'s `in` (records.rs:1499-1503): the body of `(kind, id)` into `body`.
    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    pub struct GetPlaneRecordIn {
        /// The head.
        pub head: InHead,
        /// The kind.
        pub kind: AbiStr,
        /// The id.
        pub id: AbiStr,
        /// The host buffer the body is written into.
        pub body: HostBuf,
    }

    /// `list_plane_records`' `in` (records.rs:1513-1522): a kind's bodies, narrowed by `selector`,
    /// written into `out`.
    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    pub struct ListPlaneRecordsIn {
        /// The head.
        pub head: InHead,
        /// The kind.
        pub kind: AbiStr,
        /// [`SELECT_ALL`] | [`SELECT_PARENT`].
        pub selector: u32,
        /// Alignment padding.
        pub _reserved: u32,
        /// The parent, for [`SELECT_PARENT`]; absent otherwise.
        pub parent: AbiStr,
        /// The host buffers the bodies are written into.
        pub out: HostBlobs,
    }

    /// `purge_plane_records_before`' `in` (records.rs:1530-1538).
    ///
    /// `retention` and its padding were APPENDED: the door copies the host's `in` up to its stated
    /// `head.size` into a zeroed `in` of this build's size, so an older host's shorter `in` reads
    /// [`RETENTION_AGE`], the rule it purged by.
    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    pub struct KindBeforeIn {
        /// The head.
        pub head: InHead,
        /// The kind.
        pub kind: AbiStr,
        /// The cutoff (Unix seconds).
        pub before: u64,
        /// [`RETENTION_AGE`] | [`RETENTION_TERMINAL_ONLY`]: the rule the kind's owner declared; or
        /// [`RETENTION_USAGE_WINDOWS`], the usage ledger's purge (`kind` empty); any other code is
        /// refused.
        pub retention: u32,
        /// Alignment padding.
        pub _reserved: u32,
    }

    /// `redeem_plane_token`'s and `plane_token_live`'s `in` (records.rs:1545-1596).
    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    pub struct TokenIn {
        /// The head.
        pub head: InHead,
        /// The token's kind.
        pub kind: AbiStr,
        /// The token.
        pub token: AbiStr,
        /// Valid until (Unix seconds).
        pub expires_at: u64,
        /// Now (Unix seconds).
        pub now: u64,
    }
}
