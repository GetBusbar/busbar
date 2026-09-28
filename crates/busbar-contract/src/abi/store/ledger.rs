// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE 1.6.0 LEDGER OPS as store v3 slots (B.1 "Slots": the ten 1.6.0 ledger ops, "with the
//! semantics in `store_adapter.rs` documented per slot"). `reserve` and `slice_release` are in
//! [`super::money`]; the other eight are here. The Rust signatures they lower are `kinds.rs`
//! `Store` (kinds.rs:300-392); the semantics are `store_adapter.rs`'s module doc and
//! `busbar/src/root/durability/mod.rs`'s shipper section.

use super::money::OpId;
use super::HostBuf;
use crate::abi::mechanism::call::{AbiStr, Blob, InHead, OutHead};

/// `append_batch`'s `in` (kinds.rs:302; B.1): append journal records to `stream`. THE SHIPPING
/// ACK: READY means the records are durable in the store; the answer is part of the journal's
/// commit (durability/mod.rs, "The shipper is part of the answer"). Idempotent on the
/// `(node, node_seq)` each record carries, so a re-offered batch appends what is new and passes
/// over what is there; and, as an appending write, deduped on `op_id` (B.1 "Writes"). Each record
/// is at most `MAX_RECORD_BYTES` (`bounded.rs`).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct AppendBatchIn {
    /// The head.
    pub head: InHead,
    /// The kernel-minted id of this batch.
    pub op_id: OpId,
    /// The stream.
    pub stream: AbiStr,
    /// The records ([`BLOB_OCTETS`](crate::abi::mechanism::call::BLOB_OCTETS)), in order.
    pub records: *const Blob,
    /// How many.
    pub records_len: usize,
}

/// `append_batch`'s `out`: where the stream has reached (`kinds.rs` `Head`).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct HeadOut {
    /// The head.
    pub head: OutHead,
    /// The stream's sequence number.
    pub seq: u64,
    /// The epoch that sequence belongs to.
    pub epoch: u64,
}

/// One stream's head, as `heads` lists it.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct StreamHead {
    /// The stream.
    pub stream: AbiStr,
    /// Its sequence number.
    pub seq: u64,
    /// The epoch that sequence belongs to.
    pub epoch: u64,
}

/// `heads`' `out` (kinds.rs:319): where each stream has reached, plugin-owned under `head.lease`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct HeadsOut {
    /// The head; `head.lease` holds `items` until `release`.
    pub head: OutHead,
    /// The streams' heads.
    pub items: *const StreamHead,
    /// How many.
    pub items_len: usize,
}

/// `session_put`'s `in` (kinds.rs:340): register a live session in the fleet directory, an upsert
/// on `session`; dropped by `session_remove` at close or at lease expiry.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SessionPutIn {
    /// The head.
    pub head: InHead,
    /// The session id.
    pub session: u64,
    /// The node holding it.
    pub node: AbiStr,
    /// The principal it belongs to.
    pub principal: AbiStr,
}

/// One session, as `sessions_for` writes it: `node` points into [`HostSessions::bytes`].
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SessionRow {
    /// The session id.
    pub session: u64,
    /// The node holding it.
    pub node: AbiStr,
}

/// The host buffers `sessions_for` writes into.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct HostSessions {
    /// The row slots.
    pub items: *mut SessionRow,
    /// How many.
    pub items_cap: usize,
    /// The bytes the rows' strings point into.
    pub bytes: HostBuf,
}

/// `sessions_for`'s `in` (kinds.rs:351): which sessions a principal holds across the fleet.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SessionsForIn {
    /// The head.
    pub head: InHead,
    /// The principal.
    pub principal: AbiStr,
    /// The host buffers.
    pub out: HostSessions,
}

/// `record_put`'s `in` (kinds.rs:355): write one of a plane's kernel-held durable records, an
/// upsert on `(schema, key)`. `value` is at most `MAX_RECORD_BYTES`. The kernel-held records it
/// carries include the migration marker (B.1 "Kernel side": the marker runs in the kernel over
/// `StoreClient`) and the sealed new-verb replay slots (see [`RecordGetIn`]).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RecordPutIn {
    /// The head.
    pub head: InHead,
    /// The record schema id.
    pub schema: AbiStr,
    /// The key ([`BLOB_OCTETS`](crate::abi::mechanism::call::BLOB_OCTETS)).
    pub key: Blob,
    /// The value ([`BLOB_OCTETS`](crate::abi::mechanism::call::BLOB_OCTETS)).
    pub value: Blob,
}

/// `record_get`'s `in` (kinds.rs:363): read one record into `value`; absent is ABSENT, never
/// FAILED. A `value` buffer of `MAX_RECORD_BYTES` always fits.
///
/// THE REPLAY CACHE rides here: a sealed new-verb replay slot answers for `REPLAY_TTL_SECS`
/// (store_adapter.rs:173) and a restore does NOT clear it (store_adapter.rs module doc, "The
/// sealed replay cache").
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RecordGetIn {
    /// The head.
    pub head: InHead,
    /// The record schema id.
    pub schema: AbiStr,
    /// The key.
    pub key: Blob,
    /// The host buffer the value is written into.
    pub value: HostBuf,
}

/// One record, as `record_scan` writes it: both blobs point into [`HostRecords::bytes`].
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RecordEntry {
    /// The key.
    pub key: Blob,
    /// The value.
    pub value: Blob,
}

/// The host buffers `record_scan` writes into.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct HostRecords {
    /// The entry slots.
    pub items: *mut RecordEntry,
    /// How many.
    pub items_cap: usize,
    /// The bytes the entries point into.
    pub bytes: HostBuf,
}

/// `record_scan`'s `in` (kinds.rs:370): a plane's records under `prefix`, in key order, at most
/// `limit`; `limit` 0 means NOTHING, never everything (store-memory `record_scan`).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RecordScanIn {
    /// The head.
    pub head: InHead,
    /// The record schema id.
    pub schema: AbiStr,
    /// The key prefix.
    pub prefix: Blob,
    /// At most this many.
    pub limit: u32,
    /// Alignment padding.
    pub _reserved: u32,
    /// The host buffers.
    pub out: HostRecords,
}
