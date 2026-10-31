// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE 1.5.5 OP SET as store v3 slots: the `in` shapes of the `RecordStore` methods (v1.5.5
//! `crates/api/src/store.rs:604-927`). Every one is off path; results come back under a lease
//! (mechanism memory class (iv)). The 1.5.5 behaviour each op keeps is stated on its slot in
//! [`super::slot`] and [`super::OPS`].

use crate::abi::mechanism::call::{AbiStr, Blob, InHead};
use crate::abi::mechanism::decl::abi_struct;

abi_struct! {
    /// An `in` naming one id: `get_key`, `delete_key`, `list_credentials` (a key id),
    /// `list_plane_record_parents` (a kind).
    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    pub struct IdIn {
        /// The head.
        pub head: InHead,
        /// The id.
        pub id: AbiStr,
    }

    /// An `in` carrying one number: `list_keys_since` and `list_credentials_since` (`since`),
    /// `list_metering` (the metering bucket), `list_audit_tail` (`limit`).
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

    /// An `in` naming `(kind, id)`: `delete_plane_record`.
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
}
