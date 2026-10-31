// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE STORE'S CALLS, AS THE HOST'S TWO HALVES SHARE THEM (THE DESIGN, the plugin ABI; the
//! K1 pattern of `plane_calls`): the [`StoreCalls`] trait the plugin loader implements over one
//! loaded store instance, reached through the store v3 table, and the kernel calls through. The
//! kernel names this and never a loader type.
//!
//! Every method is a FUTURE. An op crosses on a ticket's dispatcher worker; the caller's task
//! awaits its completion and no runtime thread is parked. An instance at its `max_inflight` answers
//! [`StoreFailure::Overloaded`] without a crossing (the 503 of R8).
//!
//! The 1.5.5 op set stays reachable through [`RecordStore`](crate::records::RecordStore), which
//! the loader's handle also implements, synchronously, for the consumers that have not moved here:
//! each of its ops is submitted on a ticket like these and the caller waits for the completion, so
//! a store that pends completes it there too. M6: that synchronous bridge is deleted when no
//! consumer remains (the remaining consumers are listed on the loader's implementation).

use std::future::Future;
use std::pin::Pin;

use crate::abi::store::OpId;
use crate::kinds::RecordBytes;
use crate::records::{MeteringDelta, PlaneRecordRef, PlaneSelector, UsageDelta};

/// THE NODE'S ONE `op_id` ALLOCATOR, as a store handle is handed it: every `op_id` a handle mints
/// for itself (the synchronous bridge's additive writes) comes from the kernel's one allocator, so no
/// handle owns a counter and no two handles, reloads or boots mint the same id.
pub type OpIdMint = fn() -> OpId;

/// One store call in flight.
pub type StoreCall<'a, T> = Pin<Box<dyn Future<Output = Result<T, StoreFailure>> + Send + 'a>>;

/// Why a store call answered without its result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreFailure {
    /// FAILED: the store's text. For an `op_id`-carrying write this proves nothing (S5): the commit
    /// may have landed, so the caller replays the same `op_id` with the same body.
    Failed(String),
    /// REFUSED: the store would not take the op; its text. For an `op_id`-carrying write, decided
    /// before commit: nothing applied and nothing recorded (S3, S5).
    Refused(String),
    /// The `op_id` was already used with different value fields (`STORE_OPID_CONFLICT`); nothing
    /// applied.
    Conflict,
    /// The instance is at its `max_inflight`: REFUSED without a crossing.
    Overloaded,
    /// The instance faulted, or the op did not answer within its deadline.
    Fault(String),
}

impl std::fmt::Display for StoreFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Failed(t) => write!(f, "the store failed the op: {t}"),
            Self::Refused(t) => write!(f, "the store refused the op: {t}"),
            Self::Conflict => f.write_str(crate::abi::store::DIAG_OPID_CONFLICT),
            Self::Overloaded => f.write_str("the store is at its in-flight limit"),
            Self::Fault(t) => write!(f, "the store faulted: {t}"),
        }
    }
}

impl std::error::Error for StoreFailure {}

/// ONE STORE INSTANCE'S CALLS, as the kernel makes them: the store v3 slots, typed.
pub trait StoreCalls: Send + Sync {
    /// `add_usage_batch`: one coalesced batch, one `op_id`.
    fn add_usage_batch<'a>(
        &'a self,
        op: OpId,
        cells: &'a [(&'a str, u64, UsageDelta)],
    ) -> StoreCall<'a, ()>;
    /// `add_metering_batch`.
    fn add_metering_batch<'a>(&'a self, op: OpId, deltas: &'a [MeteringDelta])
        -> StoreCall<'a, ()>;
    /// `record_put`.
    fn record_put<'a>(
        &'a self,
        schema: &'a str,
        key: &'a [u8],
        value: &'a RecordBytes,
    ) -> StoreCall<'a, ()>;
    /// `record_get`.
    fn record_get<'a>(
        &'a self,
        schema: &'a str,
        key: &'a [u8],
    ) -> StoreCall<'a, Option<RecordBytes>>;
    /// `record_scan`: at most `limit` under `prefix`, in key order.
    fn record_scan<'a>(
        &'a self,
        schema: &'a str,
        prefix: &'a [u8],
        limit: u32,
    ) -> StoreCall<'a, Vec<(Vec<u8>, RecordBytes)>>;
    /// `put_key`. An implementation that does not serve one of these 1.5.5 ops REFUSES it.
    fn put_key<'a>(&'a self, key: &'a crate::records::VirtualKey) -> StoreCall<'a, ()> {
        let _ = key;
        unserved("put_key")
    }
    /// `get_key`.
    fn get_key<'a>(&'a self, id: &'a str) -> StoreCall<'a, Option<crate::records::VirtualKey>> {
        let _ = id;
        unserved("get_key")
    }
    /// `list_keys`: every key, tombstones included.
    fn list_keys(&self) -> StoreCall<'_, Vec<crate::records::VirtualKey>> {
        unserved("list_keys")
    }
    /// `delete_key`.
    fn delete_key<'a>(&'a self, id: &'a str) -> StoreCall<'a, ()> {
        let _ = id;
        unserved("delete_key")
    }
    /// `put_key_with_credential`: the key and its credential, kept together or not at all.
    fn put_key_with_credential<'a>(
        &'a self,
        key: &'a crate::records::VirtualKey,
        secret: &'a crate::records::CredentialSecret,
    ) -> StoreCall<'a, ()> {
        let _ = (key, secret);
        unserved("put_key_with_credential")
    }
    /// `list_credentials`: a key's credentials, without their secrets.
    fn list_credentials<'a>(
        &'a self,
        key_id: &'a str,
    ) -> StoreCall<'a, Vec<crate::records::CredentialMeta>> {
        let _ = key_id;
        unserved("list_credentials")
    }
    /// `revoke_credential`.
    fn revoke_credential<'a>(&'a self, id: &'a str, reason: &'a str) -> StoreCall<'a, ()> {
        let _ = (id, reason);
        unserved("revoke_credential")
    }
    /// `list_credentials_since`.
    fn list_credentials_since(
        &self,
        since: u64,
    ) -> StoreCall<'_, Vec<crate::records::CredentialSecret>> {
        let _ = since;
        unserved("list_credentials_since")
    }
    /// `add_denylist`.
    fn add_denylist<'a>(&'a self, sub: &'a str, reason: &'a str) -> StoreCall<'a, ()> {
        let _ = (sub, reason);
        unserved("add_denylist")
    }
    /// `list_denylist`.
    fn list_denylist(&self) -> StoreCall<'_, Vec<String>> {
        unserved("list_denylist")
    }
    /// `list_metering`: one bucket's metering rows.
    fn list_metering(&self, bucket: u64) -> StoreCall<'_, Vec<crate::records::MeteringRow>> {
        let _ = bucket;
        unserved("list_metering")
    }
    /// `list_audit`: the legacy audit table, oldest first from genesis.
    fn list_audit(&self) -> StoreCall<'_, Vec<crate::records::AuditRecord>> {
        unserved("list_audit")
    }
    /// `list_audit_tail`: the legacy audit table's last `limit` records.
    fn list_audit_tail(&self, limit: u64) -> StoreCall<'_, Vec<crate::records::AuditRecord>> {
        let _ = limit;
        unserved("list_audit_tail")
    }
    /// `upsert_plane_record`.
    fn upsert_plane_record<'a>(&'a self, record: PlaneRecordRef<'a>) -> StoreCall<'a, ()>;
    /// `get_plane_record`: the body.
    fn get_plane_record<'a>(&'a self, kind: &'a str, id: &'a str)
        -> StoreCall<'a, Option<Vec<u8>>>;
    /// `append_plane_record`, deduped on `op`.
    fn append_plane_record<'a>(&'a self, op: OpId, record: PlaneRecordRef<'a>)
        -> StoreCall<'a, ()>;
    /// `list_plane_records`: the bodies.
    fn list_plane_records<'a>(
        &'a self,
        kind: &'a str,
        selector: &'a PlaneSelector<'a>,
    ) -> StoreCall<'a, Vec<Vec<u8>>>;
    /// `delete_plane_record`; absent is `Ok`.
    fn delete_plane_record<'a>(&'a self, kind: &'a str, id: &'a str) -> StoreCall<'a, ()>;
    /// `redeem_plane_token`: whether this call was the first redemption.
    fn redeem_plane_token<'a>(
        &'a self,
        kind: &'a str,
        token: &'a str,
        expires_at: u64,
        now: u64,
    ) -> StoreCall<'a, bool>;
    /// `plane_token_live`.
    fn plane_token_live<'a>(
        &'a self,
        kind: &'a str,
        token: &'a str,
        expires_at: u64,
        now: u64,
    ) -> StoreCall<'a, bool>;
    /// `list_plane_record_parents`: every distinct parent `kind`'s records name. An implementation
    /// that does not serve it REFUSES it.
    fn list_plane_record_parents<'a>(&'a self, kind: &'a str) -> StoreCall<'a, Vec<String>> {
        let _ = kind;
        not_served("list_plane_record_parents")
    }
    /// `purge_plane_records_before`: `kind`'s records older than `before` removed, as the store's
    /// retention rule for the kind reads it; how many went. An implementation that does not serve
    /// it REFUSES it.
    fn purge_plane_records_before<'a>(&'a self, kind: &'a str, before: u64) -> StoreCall<'a, u64> {
        let _ = (kind, before);
        not_served("purge_plane_records_before")
    }
    /// The usage ledger's purge: every usage window whose start is nonzero and earlier than
    /// `before` removed, the all-time window kept; how many went
    /// ([`RETENTION_USAGE_WINDOWS`](crate::abi::store::RETENTION_USAGE_WINDOWS)). An
    /// implementation that does not serve it REFUSES it.
    fn purge_usage_before(&self, before: u64) -> StoreCall<'_, u64> {
        let _ = before;
        not_served("purge_usage_before")
    }
}

/// The answer of a [`StoreCalls`] op an implementation does not serve: REFUSED, naming the op.
fn not_served<'a, T: Send + 'a>(op: &'static str) -> StoreCall<'a, T> {
    Box::pin(std::future::ready(Err(StoreFailure::Refused(format!(
        "this store does not serve {op}"
    )))))
}

// THE STORE AXIS (WIRE-STORE Q8/Q9: the kernel receives the store kind's axis from the
// composition root and never names the loader or the dispatcher) ─────────────────────────────

/// Where one store's door comes from: a compiled-in row's door, or a dropped-in plugin's verified
/// library bytes with the Statement rendering its signed manifest states.
pub enum StoreDoor {
    /// A compiled-in row's door.
    Linked(crate::abi::mechanism::door::DoorFn),
    /// A dropped-in plugin.
    Dropped {
        /// Its tarball's file name (diagnostics).
        file: String,
        /// The library bytes its signed manifest's `sha256` names.
        bytes: std::sync::Arc<Vec<u8>>,
        /// The Statement rendering its signed manifest states: what the door is admitted against.
        stated: Vec<u8>,
    },
}

impl std::fmt::Debug for StoreDoor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreDoor::Linked(_) => f.debug_tuple("Linked").finish_non_exhaustive(),
            StoreDoor::Dropped { file, .. } => f
                .debug_struct("Dropped")
                .field("file", file)
                .finish_non_exhaustive(),
        }
    }
}

/// ONE OPENED STORE, as the axis hands it to the kernel (WIRE-STORE Q9): the 1.5.5 op set
/// synchronously (`records`, the transitional bridge until M6) and the typed v3 calls.
pub struct OpenedStore {
    /// The 1.5.5 op set.
    pub records: std::sync::Arc<dyn crate::records::RecordStore>,
    /// The store v3 slots; `None` for a store reached by no door.
    pub calls: Option<std::sync::Arc<dyn StoreCalls>>,
}

impl std::fmt::Debug for OpenedStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenedStore")
            .field("calls", &self.calls.is_some())
            .finish_non_exhaustive()
    }
}

/// THE STORE AXIS, as the composition root installs it in the kernel: every store, compiled in or
/// dropped in, is loaded through the process's ONE dispatcher and opened through the store v3
/// table (`abi::store`), its bridge writes minted by the kernel's one `op_id` allocator.
pub trait StoreAxis: Send + Sync {
    /// Load `door` under the host's instance `label` and OPEN it on `settings` (the store section's
    /// JSON, its secret references already resolved).
    ///
    /// # Errors
    /// Why it will not open: the door refused the load, or the store refused its settings (in the
    /// store's own words).
    fn open(&self, door: StoreDoor, label: &str, settings: &[u8]) -> Result<OpenedStore, String>;
}

/// The answer of a 1.5.5 [`StoreCalls`] op an implementation does not serve: REFUSED, naming it.
fn unserved<'a, T: Send + 'a>(op: &'static str) -> StoreCall<'a, T> {
    Box::pin(std::future::ready(Err(StoreFailure::Refused(format!(
        "this store does not serve {op}"
    )))))
}
