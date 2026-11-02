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

pub(crate) struct RevocationSync {
    store: Arc<dyn RecordStore>,

    set: RwLock<HashSet<String>>,

    synced_at: AtomicU64,

    clock: Instant,
    synced_tick: AtomicU64,

    attempted: Mutex<Attempt>,

    inflight: AtomicBool,

    reload_keys: Option<KeyReload>,
}

struct Attempt {
    wall: u64,
    tick: u64,
}

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

pub(crate) type KeyReload =
    Box<dyn Fn() -> busbar_contract::records::RecordStoreResult<()> + Send + Sync>;

impl RevocationSync {
    #[cfg(test)]
    pub(crate) fn new(
        store: Arc<dyn RecordStore>,
        initial: HashSet<String>,
        now: u64,
    ) -> Arc<Self> {
        Self::with(store, initial, now, None)
    }

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

    pub(crate) fn contains(&self, sub: &str) -> bool {
        self.set
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .contains(sub)
    }

    pub(crate) fn insert(&self, sub: &str) {
        self.set
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(sub.to_string());
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn synced_at(&self) -> u64 {
        self.synced_at.load(Ordering::Relaxed)
    }

    pub(crate) fn refresh_if_stale(self: &Arc<Self>, now: u64) {
        let tick = u64::try_from(self.clock.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.refresh_if_stale_at(now, tick);
    }

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

            *attempted = Attempt { wall: now, tick };
        }

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
            Ok(handle) => {
                handle.spawn_blocking(move || flight.run(now, tick));
            }

            Err(_) => flight.run(now, tick),
        }
    }

    fn refresh_blocking(&self, now: u64, tick: u64) {
        let denied = self.store.list_denylist();

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
            Ok(()) => {
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
