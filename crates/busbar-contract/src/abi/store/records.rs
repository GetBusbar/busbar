// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE 1.5.5 OP SET as store v3 slots (B.1 "Slots": "the full 1.5.5 op set"): the `in` shapes of
//! the 24 `RecordStore` methods (v1.5.5 `crates/api/src/store.rs:604-927`; predev
//! `records.rs:1152-1479`). Every one is off path (records.rs:1146-1149: "every method here is off
//! the request hot path"); results come back under a lease (mechanism memory class (iv)). The
//! 1.5.5 behaviour each op keeps is stated on its slot in [`super::slot`] and [`super::OPS`].

use super::money::{OpId, UsageCell};
use crate::abi::mechanism::call::{AbiStr, Blob, InHead};

/// An `in` naming one id: `get_key`, `delete_key`, `scrub_key`, `list_credentials` (a key id),
/// `purge_metering_before` (a bucket), `list_plane_record_parents` (a kind).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct IdIn {
    /// The head.
    pub head: InHead,
    /// The id.
    pub id: AbiStr,
}

/// An `in` carrying one number: `list_keys_since` and `list_credentials_since` (`since`),
/// `list_metering` (the metering bucket), `purge_windows_before` (`before`), `list_audit_tail`
/// (`limit`), `session_remove` (the session id).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct U64In {
    /// The head.
    pub head: InHead,
    /// The number.
    pub value: u64,
}

/// `get_usage`'s `in`: one (bucket, window) cell.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct WindowIn {
    /// The head.
    pub head: InHead,
    /// The bucket id.
    pub bucket: AbiStr,
    /// The window start.
    pub window_start: u64,
}

/// `put_usage`'s `in`: an ABSOLUTE set of one cell's `UsageLedger`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PutUsageIn {
    /// The head.
    pub head: InHead,
    /// The bucket id.
    pub bucket: AbiStr,
    /// The window start.
    pub window_start: u64,
    /// The `UsageLedger`.
    pub ledger: Blob,
}

/// `add_usage`'s `in`: one additive cell, deduped on `op_id` (B.1 "Writes").
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct AddUsageIn {
    /// The head.
    pub head: InHead,
    /// The kernel-minted id of this write.
    pub op_id: OpId,
    /// The cell and its delta.
    pub cell: UsageCell,
}

/// An `in` carrying one record blob: `put_key` (`VirtualKey`), `put_credential`
/// (`CredentialSecret`, a [`BLOB_SECRET`](crate::abi::mechanism::call::BLOB_SECRET) blob).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BlobIn {
    /// The head.
    pub head: InHead,
    /// The record.
    pub record: Blob,
}

/// An `in` carrying one additive or appending record, deduped on `op_id` (B.1 "Writes"):
/// `add_metering` (`MeteringDelta`), `append_audit` (`AuditRecord`).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct OpBlobIn {
    /// The head.
    pub head: InHead,
    /// The kernel-minted id of this write.
    pub op_id: OpId,
    /// The record.
    pub record: Blob,
}

/// `put_key_with_credential`'s `in`: both rows, written together or not at all.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct KeyWithCredentialIn {
    /// The head.
    pub head: InHead,
    /// The `VirtualKey`.
    pub key: Blob,
    /// The `CredentialSecret`, a [`BLOB_SECRET`](crate::abi::mechanism::call::BLOB_SECRET) blob.
    pub credential: Blob,
}

/// An `in` naming `(kind, id)`: `lookup_credential_secret` (kind, public id) and
/// `delete_plane_record` (kind, id).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct KindIdIn {
    /// The head.
    pub head: InHead,
    /// The kind.
    pub kind: AbiStr,
    /// The id.
    pub id: AbiStr,
}

/// An `in` naming an id and an operator reason (audit metadata, never a secret):
/// `revoke_credential` (credential id), `add_denylist` (subject id).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct IdReasonIn {
    /// The head.
    pub head: InHead,
    /// The id.
    pub id: AbiStr,
    /// The reason.
    pub reason: AbiStr,
}
