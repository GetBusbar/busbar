// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE KERNEL-HELD RECORDS as store v3 slots: `record_put`, `record_get` and `record_scan`, an
//! opaque `(schema, key) -> value` map the kernel keeps its own durable records in (the journal,
//! node identity, the rate-card history). The store never interprets a value.

use super::HostBuf;
use crate::abi::mechanism::call::{AbiStr, Blob, InHead};
use crate::abi::mechanism::decl::abi_struct;

abi_struct! {
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
    /// The sealed new-verb replay slots are kernel-held records read here. The semantics the store
    /// keeps for them (store_adapter.rs module doc, "The sealed replay cache"): a restore does NOT
    /// clear them, and a slot answers for `REPLAY_TTL_SECS` (store_adapter.rs:173) after it was
    /// written.
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
    /// `limit`; `limit` 0 means NOTHING, never everything (the in-tree RAM store's `record_scan`).
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
}
