// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The REVOCATION DENYLIST and its store re-sync — the one piece of state the otherwise-stateless
//! signed-token verify path reads, and the ONLY reason the auth hot path ever touches the `Store`.
//!
//! ## Why this is its own type
//!
//! The re-sync is a `Store` round-trip: SQL over a mutex-guarded connection (`store-sqlite`,
//! `store-postgres`), a Valkey command, or an FFI/IPC `transport_call` into a store plugin. That is
//! BLOCKING I/O, and the callers ([`GovState::verify_token`], [`GovState::is_revoked_at`]) run
//! inline inside `auth_middleware` — an `async fn` on a Tokio worker thread. Running the read there
//! parks a reactor thread for the full duration of the round-trip; with a hung store (Postgres has
//! neither reconnect nor a statement timeout **by design** — see `store-postgres/src/lib.rs`) it
//! parks it FOREVER, and one more worker every staleness window until the runtime serves nothing at
//! all — not proxied traffic, not `/healthz`, not the admin plane.
//!
//! So the request path must never perform the read. It reads the in-memory set (a microsecond
//! `RwLock` read) and, when that set is stale, *schedules* the refresh. This is the same discipline
//! the rest of the engine already applies to every other store toucher: the write-behind budget
//! flusher (`governance/mod.rs`), the metrics exporter (`metrics.rs`), `gate_transport_offloaded`
//! (`hooks/mod.rs`), and the whole `config_transaction` design (`admin/v1/json/txn.rs`).
//!
//! ## The three properties that make the offload safe
//!
//! 1. **Off the reactor.** The read runs on the blocking pool via `spawn_blocking`. With no Tokio
//!    runtime in scope (unit tests, `--validate`, boot) there is no reactor to protect, so it runs
//!    inline — the behaviour callers without a runtime already expect.
//! 2. **Bounded.** `spawn_blocking` alone is not a fix: a hung store would accumulate one parked
//!    pool thread per window until the shared 512-thread pool is exhausted and every other
//!    `spawn_blocking` in the process (budget flush, audit, config transactions) stalls behind it.
//!    `inflight` admits AT MOST ONE outstanding refresh process-wide, so a hung store costs exactly
//!    one pool thread, forever, and nothing else.
//! 3. **Attempt-stamped separately from success.** The previous implementation advanced the single
//!    staleness stamp to `now` BEFORE the read, so a read that failed — or never returned — still
//!    "closed" the window: every subsequent window looked fresh and the denylist could stay stale
//!    indefinitely while nothing ever reported a problem. Here `attempted_at` (the rate-limit
//!    anchor, advanced before the read) and `synced_at` (advanced ONLY on a successful read) are
//!    distinct, so staleness is measured against reality and a persistently failing store is
//!    visible in `synced_age_secs` on the warning it emits once per window.
//!
//! ## What the offload costs, honestly
//!
//! The request that observes staleness is served against the PREVIOUS set; the refreshed set lands
//! a round-trip later and applies to subsequent requests. So a peer's revoke is honoured within
//! roughly two staleness windows rather than one. That is the deliberate trade: a few extra seconds
//! of revocation-visibility lag on a healthy store, in exchange for a store outage degrading
//! revocation freshness instead of killing the process. A revoke performed on THIS node is still
//! applied to the set synchronously by [`RevocationSync::insert`] (zero window), and the durable
//! write still fails loud.

use crate::diagnostics::{diag_warn, REVOCATION_RESYNC_FAILED, REVOCATION_RESYNC_OUTSTANDING};
use busbar_api::Store;
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use super::REVOCATION_SYNC_TTL_SECS;

/// The in-memory revocation denylist plus the machinery that keeps it fresh against the store.
/// Held behind an `Arc` by `GovState` so a refresh can be handed to the blocking pool.
pub(crate) struct RevocationSync {
    /// The durable store the denylist is a CACHE of.
    store: Arc<dyn Store>,
    /// Revoked subject ids. Read on the auth hot path; written by a local revoke and by a refresh.
    set: RwLock<HashSet<String>>,
    /// Unix-seconds epoch of the last SUCCESSFUL store read. Advanced only when a read returns.
    synced_at: AtomicU64,
    /// Unix-seconds epoch of the last read ATTEMPT (advanced BEFORE the read, and also when an
    /// attempt is declined because one is already in flight). The rate-limit anchor: it bounds
    /// retries against a broken store to one per window regardless of request rate.
    attempted_at: AtomicU64,
    /// Whether a refresh is outstanding. The BOUND: at most one blocking-pool thread may ever be
    /// inside `list_denylist` for this node, so a store that never returns costs one thread rather
    /// than one per window until the pool is gone.
    inflight: AtomicBool,
}

impl RevocationSync {
    /// A denylist seeded with the boot-time hydration (`initial`), stamped fresh at `now`.
    pub(crate) fn new(store: Arc<dyn Store>, initial: HashSet<String>, now: u64) -> Arc<Self> {
        Arc::new(Self {
            store,
            set: RwLock::new(initial),
            synced_at: AtomicU64::new(now),
            attempted_at: AtomicU64::new(now),
            inflight: AtomicBool::new(false),
        })
    }

    /// Whether `sub` is on the denylist. A pure in-memory read — NEVER touches the store.
    pub(crate) fn contains(&self, sub: &str) -> bool {
        self.set
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .contains(sub)
    }

    /// Add a locally-revoked subject. The durable write is the caller's ([`GovState::revoke`]); this
    /// is the in-memory half, applied synchronously so the very next check rejects (zero window).
    pub(crate) fn insert(&self, sub: &str) {
        self.set
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(sub.to_string());
    }

    /// Unix-seconds epoch of the last successful store read. Test/observability accessor.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn synced_at(&self) -> u64 {
        self.synced_at.load(Ordering::Relaxed)
    }

    /// THE REQUEST-PATH ENTRY POINT. Returns immediately, always. When the cached set is older than
    /// [`REVOCATION_SYNC_TTL_SECS`] it SCHEDULES a refresh (see the module docs for why it is
    /// scheduled and not performed); the caller then reads the current set.
    ///
    /// Every gate here is a bound: the staleness check bounds refreshes to one per window, the
    /// `attempted_at` CAS single-flights the window across concurrent callers, and `inflight`
    /// bounds outstanding blocking work to one thread whatever the store does.
    pub(crate) fn refresh_if_stale(self: &Arc<Self>, now: u64) {
        // Fresh enough — the overwhelmingly common path, two relaxed atomic loads.
        if now.saturating_sub(self.synced_at.load(Ordering::Relaxed)) < REVOCATION_SYNC_TTL_SECS {
            return;
        }
        // Rate limit, applied to ATTEMPTS (so a failing or hung store is retried once per window
        // rather than on every request) and single-flighted by the CAS: exactly one caller per
        // window proceeds, everyone else returns and reads the set they already have.
        let attempted = self.attempted_at.load(Ordering::Relaxed);
        if now.saturating_sub(attempted) < REVOCATION_SYNC_TTL_SECS {
            return;
        }
        if self
            .attempted_at
            .compare_exchange(attempted, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return; // another caller owns this window
        }
        // THE BOUND. If a previous refresh has not returned, do not start another — that is the
        // difference between a hung store costing one blocking-pool thread and it draining the
        // whole pool. Report it: reaching this branch means the store has not answered for at
        // least a full window, and the CAS above rate-limits the warning to once per window.
        if self
            .inflight
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            diag_warn!(
                REVOCATION_RESYNC_OUTSTANDING,
                synced_age_secs = now.saturating_sub(self.synced_at.load(Ordering::Relaxed)),
                "revocation denylist re-sync is still outstanding from an earlier window; the \
                 store has not answered. Serving the last-known revocations - a peer's revoke may \
                 not be visible on this node until the store recovers."
            );
            return;
        }

        let this = self.clone();
        match tokio::runtime::Handle::try_current() {
            // On a Tokio runtime: the read is blocking I/O, so it goes to the blocking pool. The
            // join handle is dropped deliberately — this is a cache refresh, nothing awaits it.
            Ok(handle) => {
                handle.spawn_blocking(move || this.refresh_blocking(now));
            }
            // No runtime ⇒ no reactor to protect (unit tests, `--validate`, boot-time paths). Run
            // it inline so those callers keep the synchronous semantics they were written against.
            Err(_) => this.refresh_blocking(now),
        }
    }

    /// Perform the store read and merge the result. BLOCKING — only ever reached from the blocking
    /// pool, from a no-runtime context, or from a test driving it deliberately.
    ///
    /// UNION, never replace: the fetched subjects are merged INTO the in-memory set. A `Store` with
    /// no denylist support returns `Ok(vec![])` from the defaulted trait method, and a wholesale
    /// replace would then ERASE this node's live revocations. There is no un-revoke API, so a union
    /// is also semantically complete — and it is the fail-closed direction either way.
    ///
    /// A store error leaves the previous set in place (fail-closed: a store blip never widens
    /// access) and, crucially, leaves `synced_at` UNADVANCED, so the set is still correctly reported
    /// as stale and the next window retries.
    pub(crate) fn refresh_blocking(&self, now: u64) {
        let result = self.store.list_denylist();
        // Release the bound BEFORE handling the result: every exit from here must clear it, or one
        // failed refresh would wedge re-syncing for the life of the process.
        self.inflight.store(false, Ordering::Release);
        match result {
            Ok(subs) => {
                if !subs.is_empty() {
                    let mut set = self.set.write().unwrap_or_else(|e| e.into_inner());
                    set.extend(subs);
                }
                // Success — and ONLY success — closes the staleness window.
                self.synced_at.fetch_max(now, Ordering::Relaxed);
            }
            Err(e) => {
                diag_warn!(
                    REVOCATION_RESYNC_FAILED,
                    error = %e,
                    synced_age_secs = now.saturating_sub(self.synced_at.load(Ordering::Relaxed)),
                    "revocation denylist re-sync failed; keeping the previously-known revocations \
                     (a peer's revoke may not be visible on this node until the next successful \
                     sync)"
                );
            }
        }
    }
}

#[cfg(test)]
#[path = "tests/revocation_tests.rs"]
mod tests;
