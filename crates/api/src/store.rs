// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! RE-EXPORT SHIM — the money-path durable record SHAPES + the `Store` trait, now living in
//! [`busbar_contract::records`] under DECISIONS #83 (contract = SHAPES, ledger = SEMANTICS) and #84
//! (nothing on the plugin path may link a crate holding semantics). Both hops of the relocation —
//! `busbar-api` → the money one-book (#35, W3.a) and the one-book → `busbar-contract` (#83/#84)
//! — are module-path-ONLY and BYTE-IDENTICAL (serde field names / wire bytes UNCHANGED,
//! the hand-written `virtual_key_wire` mirror travels verbatim, oracle-proven).
//!
//! ## This shim is why the ledger was in every plugin's build
//!
//! Every plugin in the tree names `busbar-api`, and `busbar-api` named the money one-book for
//! exactly these re-exports and nothing else — so the closure ran plugin → the author SDK →
//! `busbar-api` → the book → `busbar-contract`, and a third-party STORE plugin transitively linked
//! IT. #84: *"a kernel change shouldn't mean all 3rd party
//! plugins need updating"*. The shapes moved to the contract, this shim followed them, and the
//! ledger edge is GONE from the manifest — a store plugin can no longer name settlement, and a
//! ledger change can no longer force it to rebuild.
//!
//! `busbar-api` does NOT retire yet (that is W5.b); it stays standing and re-exports the relocated
//! types under their ORIGINAL names so every existing dependent keeps naming `busbar_api::Store`,
//! `busbar_api::VirtualKey`, `busbar_api::StoreError`, … unchanged. The five false-friend names
//! de-collided on the first move — the canonical spellings are `RecordStore` / `RecordStoreError` /
//! `RecordStoreResult`, which is what keeps them distinct from `busbar_contract::kinds::Store` now
//! that both contracts live in one crate; the aliases below preserve the api surface until the
//! whole crate retires.

pub use busbar_contract::records::{
    register_scope_kind, AuditRecord, CredentialMeta, CredentialSecret, MeteringDelta, MeteringRow,
    ModelTokens, ModelTokensDelta, PlaneDisposition, PlaneRecord, PlaneRequestCtx, PlaneSelector,
    ScopeRef, SecretForm, UsageDelta, UsageLedger, VirtualKey, RESERVED_UNITS, UNIT_CACHE_READ,
    UNIT_CACHE_WRITE, UNIT_INPUT, UNIT_OUTPUT,
};

// The three de-collided false-friends, aliased back to the api-side spelling for staged back-compat.
pub use busbar_contract::records::{
    RecordStore as Store, RecordStoreError as StoreError, RecordStoreResult as StoreResult,
};
