// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The REVOCATION DENYLIST and its store re-sync — the one piece of state the otherwise-stateless
//! signed-token verify path reads, and the ONLY reason the auth hot path ever touches the `Store`.
//!
//! ## Why this is its own type
//!
//! The re-sync is a `Store` round-trip: a call into a store plugin, which may hold a local database
//! behind a mutex or talk to a network-backed store. That is BLOCKING I/O, and the callers
//! ([`GovState::verify_token`], [`GovState::is_revoked_at`]) run inline inside `auth_middleware` —
//! an `async fn` on a Tokio worker thread. Running the read there parks a reactor thread for the
//! full duration of the round-trip; with a hung store (a network-backed store plugin need have
//! neither reconnect nor a statement timeout) it parks it FOREVER, and one more worker every staleness window until the runtime serves nothing at
//! all — not proxied traffic, not `/healthz`, not the admin plane.
//!
//! So the request path must never perform the read. It reads the in-memory set (a microsecond
//! `RwLock` read) and, when that set is stale, *schedules* the refresh. This is the same discipline
//! the rest of the engine already applies to every other store toucher: the write-behind budget
//! flusher (`governance/mod.rs`), the metrics exporter (`metrics.rs`), `gate_transport_offloaded`
//! (`hooks/mod.rs`), and the whole `config_transaction` design (`config/transaction.rs`).
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
//!    indefinitely while nothing ever reported a problem. Here the attempt anchor (advanced
//!    before the read) and `synced_at` (advanced ONLY on a successful read) are
//!    distinct, so staleness is measured against reality and a persistently failing store is
//!    visible in `synced_age_secs` on the warning it emits once per window.
//!    Monotonic elapsed time also bounds both anchors: a backwards wall clock cannot make a
//!    healthy Store's peer revocations look fresh until that clock catches up.
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
use busbar_contract::records::RecordStore;
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

use super::REVOCATION_SYNC_TTL_SECS;

/// The in-memory revocation denylist plus the machinery that keeps it fresh against the store.
/// Held behind an `Arc` by `GovState` so a refresh can be handed to the blocking pool.
pub(crate) struct RevocationSync {
    /// The durable store the denylist is a CACHE of.
    store: Arc<dyn RecordStore>,
    /// Revoked subject ids. Read on the auth hot path; written by a local revoke and by a refresh.
    set: RwLock<HashSet<String>>,
    /// Unix-seconds epoch of the last SUCCESSFUL store read. Advanced only when a read returns.
    synced_at: AtomicU64,
    /// The monotonic age of this cache, in milliseconds. It never depends on node wall time.
    clock: Instant,
    synced_tick: AtomicU64,
    /// The last attempt in both clocks. The mutex is used only after the fresh-cache fast path,
    /// released before spawning work, logging or calling the Store.
    attempted: Mutex<Attempt>,
    /// Whether a refresh is outstanding. The BOUND: at most one blocking-pool thread may ever be
    /// inside `list_denylist` for this node, so a store that never returns costs one thread rather
    /// than one per window until the pool is gone.
    inflight: AtomicBool,
    /// Reloads the node's key caches from the store after the denylist read, so a key another node
    /// of the fleet minted, rotated, disabled or deleted is seen within the same window. `None` for
    /// a denylist kept on its own.
    reload_keys: Option<KeyReload>,
}

struct Attempt {
    wall: u64,
    tick: u64,
}

/// Keep the single-flight bound through result application, unwinding and a queued job's drop.
struct RefreshFlight(Arc<RevocationSync>);

impl RefreshFlight {
    fn run(self, now: u64, tick: u64) {
        self.0.refresh_blocking(now, tick);
    }
}

impl Drop for RefreshFlight {
    fn drop(&mut self) {
        self.0.inflight.store(false, Ordering::Release);
    }
}

/// What a re-sync calls to reload the node's key caches from the store.
pub(crate) type KeyReload =
    Box<dyn Fn() -> busbar_contract::records::RecordStoreResult<()> + Send + Sync>;

impl RevocationSync {
    /// A denylist seeded with the boot-time hydration (`initial`), stamped fresh at `now`.
    #[cfg(test)]
    pub(crate) fn new(
        store: Arc<dyn RecordStore>,
        initial: HashSet<String>,
        now: u64,
    ) -> Arc<Self> {
        Self::with(store, initial, now, None)
    }

    /// A denylist as [`Self::new`], whose every successful re-sync also runs `reload_keys`.
    pub(crate) fn reloading(
        store: Arc<dyn RecordStore>,
        initial: HashSet<String>,
        now: u64,
        reload_keys: KeyReload,
    ) -> Arc<Self> {
        Self::with(store, initial, now, Some(reload_keys))
    }

    fn with(
        store: Arc<dyn RecordStore>,
        initial: HashSet<String>,
        now: u64,
        reload_keys: Option<KeyReload>,
    ) -> Arc<Self> {
        Arc::new(Self {
            store,
            set: RwLock::new(initial),
            synced_at: AtomicU64::new(now),
            clock: Instant::now(),
            synced_tick: AtomicU64::new(0),
            attempted: Mutex::new(Attempt { wall: now, tick: 0 }),
            inflight: AtomicBool::new(false),
            reload_keys,
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
    /// The fresh-cache path takes no mutex. Attempts are arbitrated under one short hold, and
    /// `inflight` bounds outstanding blocking work to one thread whatever the Store does.
    pub(crate) fn refresh_if_stale(self: &Arc<Self>, now: u64) {
        let tick = u64::try_from(self.clock.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.refresh_if_stale_at(now, tick);
    }

    /// Both clocks explicit so tests can advance the real scheduler without sleeping or changing
    /// process wall time. `tick` is milliseconds since this cache was constructed.
    fn refresh_if_stale_at(self: &Arc<Self>, now: u64, tick: u64) {
        let ttl_ms = REVOCATION_SYNC_TTL_SECS * 1_000;
        let synced = self.synced_at.load(Ordering::Relaxed);
        let synced_tick = self.synced_tick.load(Ordering::Relaxed);
        if now
            .checked_sub(synced)
            .is_some_and(|age| age < REVOCATION_SYNC_TTL_SECS)
            && tick.saturating_sub(synced_tick) < ttl_ms
        {
            return;
        }
        {
            let mut attempted = self.attempted.lock().unwrap_or_else(|p| p.into_inner());
            let wall_due = now
                .checked_sub(attempted.wall)
                .is_some_and(|age| age >= REVOCATION_SYNC_TTL_SECS);
            if !wall_due && tick.saturating_sub(attempted.tick) < ttl_ms {
                return;
            }
            // A backwards clock never extends this wait beyond one monotonic window. Stamp
            // attempts separately, including while another read is still outstanding.
            *attempted = Attempt { wall: now, tick };
        }
        // THE BOUND. If a previous refresh has not returned, do not start another — that is the
        // difference between a hung store costing one blocking-pool thread and it draining the
        // whole pool. Report it: reaching this branch means the store has not answered for at
        // least a full window, and the attempt stamp rate-limits the warning to once per window.
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

        let flight = RefreshFlight(self.clone());
        match tokio::runtime::Handle::try_current() {
            // On a Tokio runtime: the read is blocking I/O, so it goes to the blocking pool. The
            // join handle is dropped deliberately — this is a cache refresh, nothing awaits it.
            Ok(handle) => {
                handle.spawn_blocking(move || flight.run(now, tick));
            }
            // No runtime ⇒ no reactor to protect (unit tests, `--validate`, boot-time paths). Run
            // it inline so those callers keep the synchronous semantics they were written against.
            Err(_) => flight.run(now, tick),
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
    fn refresh_blocking(&self, now: u64, tick: u64) {
        let denied = self.store.list_denylist();
        // The key caches reload after a denylist read that answered; a revoke seen is merged even
        // when the key reload fails, and only both together close the window.
        let keys = match (&denied, &self.reload_keys) {
            (Ok(_), Some(reload)) => reload(),
            _ => Ok(()),
        };
        let result = denied.map(|subs| {
            if !subs.is_empty() {
                let mut set = self.set.write().unwrap_or_else(|e| e.into_inner());
                set.extend(subs);
            }
        });
        match result.and(keys) {
            // Success — and ONLY success — closes the staleness window.
            Ok(()) => {
                // One flight owns both the read and this application. Reset a regressed wall
                // stamp to the actual successful read; never pin a future timestamp with max.
                self.synced_at.store(now, Ordering::Relaxed);
                self.synced_tick.store(tick, Ordering::Relaxed);
            }
            Err(e) => {
                diag_warn!(
                    REVOCATION_RESYNC_FAILED,
                    error = %e,
                    synced_age_secs = now.saturating_sub(self.synced_at.load(Ordering::Relaxed)),
                    "revocation denylist / key re-sync failed; keeping the previously-known \
                     revocations and keys (a peer's revoke or key change may not be visible on this \
                     node until the next successful sync)"
                );
            }
        }
    }
}

#[cfg(test)]
#[path = "tests/revocation_tests.rs"]
mod tests;
