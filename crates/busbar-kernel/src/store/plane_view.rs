// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLANE STORE SEAM — the narrowing adapter that lets a plane persist its own trust state
//! WITHOUT ever holding a handle that can reach the rest of the store.
//!
//! The host's one store seam, [`StoreCalls`], carries every op a store serves at once: keys,
//! credentials, usage and metering, the legacy audit table, and the per-plane durable state (a
//! plane's own kind-tagged rows, the demotion record, the spent-approval ledger). Handing a plane
//! an `Arc<dyn StoreCalls>` to persist its rows would, by the same handle, let it rewrite keys and
//! forge the audit chain's `prev_hash`/`hash` — the one thing the chain exists to make impossible.
//!
//! [`PlaneStore`] is the narrower of the two. It declares ONLY the nine neutral kind-tagged
//! PLANE-RECORD verbs (`upsert_plane_record`/`append_plane_record`/… over the [`PlaneRecord`](busbar_contract::records::PlaneRecord)
//! envelope), and NONE of the key, credential, usage, metering or audit-table ops.
//!
//! Every verb is a FUTURE, as every [`StoreCalls`] op is: an op crosses on a ticket's dispatcher
//! worker and the caller awaits it, so no thread is parked on a store. A caller that is itself a
//! blocking thread (boot, the host pool) owns its one wait ([`wait_for`]).
//!
//! ## Neutral kind-tagged verbs, OPAQUE bodies
//!
//! The neutral verbs speak in an OPAQUE `body: Vec<u8>` carried on a [`PlaneRecord`](busbar_contract::records::PlaneRecord) whose every other
//! field is a typed sidecar column. This crate names NO concrete plane record type: the mapping
//! between a plane concept and its `kind`, and how a plane row is serialized into (and back out of)
//! an opaque body, lives PLANE-SIDE now (each plane crate's own `to_plane_record`/`from_body`
//! helpers). Core keeps only the neutral pieces every plane shares: the `KIND_*` tag constants and the
//! generic `serde_json` [`encode`]/[`decode`] round-trip. The serde is `serde_json`, byte-for-byte the
//! same the store plugins decode it with, so a body written through this seam reads back identically
//! no matter which side of the plugin ABI persisted it.
//!
//! ## Digests are computed BEFORE they cross this seam
//!
//! Every hash-chained row a plane persists has its `prev_hash`/`hash` computed engine-side, in the
//! chain types under [`crate::audit`], BEFORE the row reaches a store method. The store — and this
//! wrapper — receives an already-sealed row and persists it verbatim; it never computes or recomputes
//! a digest.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use busbar_contract::records::{
    PlaneRecordRef, PlaneSelector, RecordStoreError, RecordStoreResult,
};
use busbar_contract::store_calls::{StoreCalls, StoreFailure};

// ── THE KIND TAG CONSTANTS (the neutral on-wire `PlaneRecord.kind` vocabulary) ───────────────────
//
// One constant per kind the KERNEL itself writes, so a consumer names a `kind` in exactly one place
// and a typo is a missing symbol rather than a silently-inert string. These are the on-wire tags a
// store branches on; they name no plane. A plane's own kinds are the plane's constants, declared in
// its own crate, never here.

/// The administrative AUDIT chain record kind — the neutral store tag the administrative mutation
/// log's durable journal seam persists its hash-chained records under.
pub const KIND_AUDIT: &str = "audit";
/// The `usage.residual` row kind: one per-principal hash chain of the usage counts no billing class
/// records (MONEY LAW). Durable and never purged; see [`crate::residual_log`].
pub const KIND_RESIDUAL: &str = "usage_residual";
/// The trust demotion record kind.
pub const KIND_DEMOTION: &str = "demotion";
/// The operator's trust decisions (the core-admin `/admin/trust` approve and revoke), one row per
/// trust key, replayed at admit: core-neutral, every plane's.
pub const KIND_TRUST_DECISION: &str = "trust_decision";

/// Serialize a typed plane row into an opaque [`PlaneRecord::body`](busbar_contract::records::PlaneRecord::body). `serde_json`, matching the store
/// plugins' decode, so the bytes round-trip identically across the plugin ABI. Generic over any
/// `Serialize`, so this names no plane type — the caller supplies whatever neutral or plane-owned row
/// it is persisting.
pub fn encode<T: serde::Serialize>(row: &T) -> RecordStoreResult<Vec<u8>> {
    serde_json::to_vec(row).map_err(|e| RecordStoreError(format!("plane body encode: {e}")))
}

/// Decode an opaque [`PlaneRecord::body`](busbar_contract::records::PlaneRecord::body) back into its typed plane row — the exact inverse of
/// [`encode`]. A malformed body is a STORE ERROR the caller sees, never a silently-dropped read.
pub fn decode<T: serde::de::DeserializeOwned>(body: &[u8]) -> RecordStoreResult<T> {
    serde_json::from_slice(body).map_err(|e| RecordStoreError(format!("plane body decode: {e}")))
}

#[cfg(test)]
#[path = "tests/plane_view_tests.rs"]
mod plane_view_tests;

/// One plane-store call in flight.
pub type PlaneCall<'a, T> = Pin<Box<dyn Future<Output = RecordStoreResult<T>> + Send + 'a>>;

/// The PLANE-FACING durable sink: exactly the nine neutral kind-tagged verbs of [`StoreCalls`],
/// and provably none of its key / credential / usage / audit-table authority. A plane persists its
/// trust state through this and cannot reach the rest of the store because no other op is on the
/// trait.
pub trait PlaneStore: Send + Sync + 'static {
    /// See [`StoreCalls::upsert_plane_record`] — the neutral upsert.
    fn upsert_plane_record<'a>(&'a self, record: PlaneRecordRef<'a>) -> PlaneCall<'a, ()>;
    /// See [`StoreCalls::get_plane_record`] — the neutral point read.
    fn get_plane_record<'a>(&'a self, kind: &'a str, id: &'a str)
        -> PlaneCall<'a, Option<Vec<u8>>>;
    /// See [`StoreCalls::append_plane_record`] — the neutral append.
    fn append_plane_record<'a>(&'a self, record: PlaneRecordRef<'a>) -> PlaneCall<'a, ()>;
    /// See [`StoreCalls::list_plane_records`] — the neutral list (kind × selector).
    fn list_plane_records<'a>(
        &'a self,
        kind: &'a str,
        selector: &'a PlaneSelector<'a>,
    ) -> PlaneCall<'a, Vec<Vec<u8>>>;
    /// See [`StoreCalls::list_plane_record_parents`] — the neutral parent enumeration.
    fn list_plane_record_parents<'a>(&'a self, kind: &'a str) -> PlaneCall<'a, Vec<String>>;
    /// See [`StoreCalls::purge_plane_records_before`] — the neutral retention purge (honoring the
    /// store's terminal-only-vs-all-older split per kind).
    fn purge_plane_records_before<'a>(&'a self, kind: &'a str, before: u64) -> PlaneCall<'a, u64>;
    /// See [`StoreCalls::delete_plane_record`] — the neutral delete.
    fn delete_plane_record<'a>(&'a self, kind: &'a str, id: &'a str) -> PlaneCall<'a, ()>;
    /// See [`StoreCalls::redeem_plane_token`] — the neutral single-use test-and-set.
    fn redeem_plane_token<'a>(
        &'a self,
        kind: &'a str,
        token: &'a str,
        expires_at: u64,
        now: u64,
    ) -> PlaneCall<'a, bool>;
    /// See [`StoreCalls::plane_token_live`] — the neutral MULTI-USE capability check:
    /// live while the record is present, still `Active`, and inside its deadline. Spends nothing.
    fn plane_token_live<'a>(
        &'a self,
        kind: &'a str,
        token: &'a str,
        expires_at: u64,
        now: u64,
    ) -> PlaneCall<'a, bool>;
}

/// The one bridge across the plane store seam: wraps the configured store's [`StoreCalls`] and
/// forwards each neutral verb to it, exposing ONLY [`PlaneStore`]. Boot builds one per configured
/// store via [`PlaneStoreView::narrow`] and every plane state type holds the resulting
/// `Arc<dyn PlaneStore>`, so a plane's durable writes reach the same backend the engine uses while
/// its handle carries none of the rest of the store's authority.
///
/// No `Debug`: a store handle is deliberately not `Debug` (a backend must not be obliged to render
/// itself, where a credential could surface in a log), so neither is this.
pub struct PlaneStoreView(Arc<dyn StoreCalls>);

impl PlaneStoreView {
    /// Narrow a store's calls to a plane-facing handle. The ONLY place an `Arc<dyn StoreCalls>`
    /// becomes an `Arc<dyn PlaneStore>`; called once per configured store at boot.
    pub fn narrow(calls: Arc<dyn StoreCalls>) -> Arc<dyn PlaneStore> {
        Arc::new(Self(calls))
    }
}

/// A store call's failure in the plane verbs' words: a FAILED op carries the store's own text
/// unchanged, so an operator reads the backend's text exactly as 1.5.5 printed it; the other
/// failures have no 1.5.5 counterpart and keep their typed wording.
pub(crate) fn answer<T>(r: Result<T, StoreFailure>) -> RecordStoreResult<T> {
    r.map_err(|f| match f {
        StoreFailure::Failed(text) => RecordStoreError(text),
        other => RecordStoreError(other.to_string()),
    })
}

impl PlaneStore for PlaneStoreView {
    fn upsert_plane_record<'a>(&'a self, record: PlaneRecordRef<'a>) -> PlaneCall<'a, ()> {
        Box::pin(async move { answer(self.0.upsert_plane_record(record).await) })
    }
    fn get_plane_record<'a>(
        &'a self,
        kind: &'a str,
        id: &'a str,
    ) -> PlaneCall<'a, Option<Vec<u8>>> {
        Box::pin(async move { answer(self.0.get_plane_record(kind, id).await) })
    }
    /// The append is deduped on an `op_id` from the node's one allocator ([`crate::door::op_id`]).
    fn append_plane_record<'a>(&'a self, record: PlaneRecordRef<'a>) -> PlaneCall<'a, ()> {
        let op = crate::door::op_id();
        Box::pin(async move { answer(self.0.append_plane_record(op, record).await) })
    }
    fn list_plane_records<'a>(
        &'a self,
        kind: &'a str,
        selector: &'a PlaneSelector<'a>,
    ) -> PlaneCall<'a, Vec<Vec<u8>>> {
        Box::pin(async move { answer(self.0.list_plane_records(kind, selector).await) })
    }
    fn list_plane_record_parents<'a>(&'a self, kind: &'a str) -> PlaneCall<'a, Vec<String>> {
        Box::pin(async move { answer(self.0.list_plane_record_parents(kind).await) })
    }
    fn purge_plane_records_before<'a>(&'a self, kind: &'a str, before: u64) -> PlaneCall<'a, u64> {
        Box::pin(async move { answer(self.0.purge_plane_records_before(kind, before).await) })
    }
    fn delete_plane_record<'a>(&'a self, kind: &'a str, id: &'a str) -> PlaneCall<'a, ()> {
        Box::pin(async move { answer(self.0.delete_plane_record(kind, id).await) })
    }
    fn redeem_plane_token<'a>(
        &'a self,
        kind: &'a str,
        token: &'a str,
        expires_at: u64,
        now: u64,
    ) -> PlaneCall<'a, bool> {
        Box::pin(async move {
            answer(
                self.0
                    .redeem_plane_token(kind, token, expires_at, now)
                    .await,
            )
        })
    }
    fn plane_token_live<'a>(
        &'a self,
        kind: &'a str,
        token: &'a str,
        expires_at: u64,
        now: u64,
    ) -> PlaneCall<'a, bool> {
        Box::pin(async move { answer(self.0.plane_token_live(kind, token, expires_at, now).await) })
    }
}

/// WAIT for `fut` on this thread: parks until it is woken, polling it on this thread. The ONE
/// boundary a blocking caller owns (boot before a listener binds, a host-pool job, the admin audit
/// writer's own thread): a store op crosses on a dispatcher worker, never on the waiting thread, so
/// the wait completes. Never called from a runtime worker or a dispatcher worker.
pub fn wait_for<F: Future>(fut: F) -> F::Output {
    use std::task::{Context, Poll, Wake, Waker};
    struct Unpark(std::thread::Thread);
    impl Wake for Unpark {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.unpark();
        }
    }
    let waker = Waker::from(Arc::new(Unpark(std::thread::current())));
    let mut cx = Context::from_waker(&waker);
    let mut fut = std::pin::pin!(fut);
    loop {
        if let Poll::Ready(out) = fut.as_mut().poll(&mut cx) {
            return out;
        }
        std::thread::park();
    }
}

/// TEST ONLY: a plane-store double written as plain synchronous methods. Each verb runs when it is
/// called and its future answers at once, so a cell can park, fail or re-enter inside a store
/// crossing exactly where the crossing happens.
#[cfg(test)]
pub(crate) trait SyncPlaneStore: Send + Sync + 'static {
    fn upsert_plane_record(&self, record: PlaneRecordRef<'_>) -> RecordStoreResult<()>;
    fn get_plane_record(&self, kind: &str, id: &str) -> RecordStoreResult<Option<Vec<u8>>>;
    fn append_plane_record(&self, record: PlaneRecordRef<'_>) -> RecordStoreResult<()>;
    fn list_plane_records(
        &self,
        kind: &str,
        selector: &PlaneSelector,
    ) -> RecordStoreResult<Vec<Vec<u8>>>;
    fn list_plane_record_parents(&self, kind: &str) -> RecordStoreResult<Vec<String>>;
    fn purge_plane_records_before(&self, kind: &str, before: u64) -> RecordStoreResult<u64>;
    fn delete_plane_record(&self, kind: &str, id: &str) -> RecordStoreResult<()>;
    fn redeem_plane_token(
        &self,
        kind: &str,
        token: &str,
        expires_at: u64,
        now: u64,
    ) -> RecordStoreResult<bool>;
    fn plane_token_live(
        &self,
        kind: &str,
        token: &str,
        expires_at: u64,
        now: u64,
    ) -> RecordStoreResult<bool>;
}

#[cfg(test)]
impl<S: SyncPlaneStore> PlaneStore for S {
    fn upsert_plane_record<'a>(&'a self, record: PlaneRecordRef<'a>) -> PlaneCall<'a, ()> {
        Box::pin(std::future::ready(SyncPlaneStore::upsert_plane_record(
            self, record,
        )))
    }
    fn get_plane_record<'a>(
        &'a self,
        kind: &'a str,
        id: &'a str,
    ) -> PlaneCall<'a, Option<Vec<u8>>> {
        Box::pin(std::future::ready(SyncPlaneStore::get_plane_record(
            self, kind, id,
        )))
    }
    fn append_plane_record<'a>(&'a self, record: PlaneRecordRef<'a>) -> PlaneCall<'a, ()> {
        Box::pin(std::future::ready(SyncPlaneStore::append_plane_record(
            self, record,
        )))
    }
    fn list_plane_records<'a>(
        &'a self,
        kind: &'a str,
        selector: &'a PlaneSelector<'a>,
    ) -> PlaneCall<'a, Vec<Vec<u8>>> {
        Box::pin(std::future::ready(SyncPlaneStore::list_plane_records(
            self, kind, selector,
        )))
    }
    fn list_plane_record_parents<'a>(&'a self, kind: &'a str) -> PlaneCall<'a, Vec<String>> {
        Box::pin(std::future::ready(
            SyncPlaneStore::list_plane_record_parents(self, kind),
        ))
    }
    fn purge_plane_records_before<'a>(&'a self, kind: &'a str, before: u64) -> PlaneCall<'a, u64> {
        Box::pin(std::future::ready(
            SyncPlaneStore::purge_plane_records_before(self, kind, before),
        ))
    }
    fn delete_plane_record<'a>(&'a self, kind: &'a str, id: &'a str) -> PlaneCall<'a, ()> {
        Box::pin(std::future::ready(SyncPlaneStore::delete_plane_record(
            self, kind, id,
        )))
    }
    fn redeem_plane_token<'a>(
        &'a self,
        kind: &'a str,
        token: &'a str,
        expires_at: u64,
        now: u64,
    ) -> PlaneCall<'a, bool> {
        Box::pin(std::future::ready(SyncPlaneStore::redeem_plane_token(
            self, kind, token, expires_at, now,
        )))
    }
    fn plane_token_live<'a>(
        &'a self,
        kind: &'a str,
        token: &'a str,
        expires_at: u64,
        now: u64,
    ) -> PlaneCall<'a, bool> {
        Box::pin(std::future::ready(SyncPlaneStore::plane_token_live(
            self, kind, token, expires_at, now,
        )))
    }
}
