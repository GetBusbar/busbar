// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! RE-EXPORT SHIM — the money-path durable records + the `Store` trait RELOCATED to
//! [`busbar_kernel_ledger::records`] under DECISIONS #35 (W3.a — the money one-book). The move is
//! module-path-ONLY and BYTE-IDENTICAL (serde field names / wire bytes UNCHANGED, the hand-written
//! `virtual_key_wire` mirror travels verbatim, oracle-proven).
//!
//! `busbar-api` does NOT retire yet (that is W5.b); it stays standing and re-exports the relocated
//! types under their ORIGINAL names so every existing dependent keeps naming `busbar_api::Store`,
//! `busbar_api::VirtualKey`, `busbar_api::StoreError`, … unchanged. The five false-friend names
//! de-collided on the move — the canonical spellings in the ledger are `RecordStore` /
//! `RecordStoreError` / `RecordStoreResult`; the aliases below preserve the api surface until the
//! whole crate retires.

pub use busbar_kernel_ledger::records::{
    register_scope_kind, AuditRecord, CredentialMeta, CredentialSecret, MeteringDelta,
    MeteringRow, ModelTokens, ModelTokensDelta, PlaneDisposition, PlaneRecord, PlaneRequestCtx,
    PlaneSelector, ScopeRef, SecretForm, UsageDelta, UsageLedger, VirtualKey, RESERVED_UNITS,
    UNIT_CACHE_READ, UNIT_CACHE_WRITE, UNIT_INPUT, UNIT_OUTPUT,
};

// The three de-collided false-friends, aliased back to the api-side spelling for staged back-compat.
pub use busbar_kernel_ledger::records::{
    RecordStore as Store, RecordStoreError as StoreError, RecordStoreResult as StoreResult,
};
