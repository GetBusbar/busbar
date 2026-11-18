// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! In-memory revocations with bounded native asynchronous refresh. Authentication
//! reads only the cached set. One Tokio task refreshes coherent canonical identity
//! state when stale; failures retain the previous confirmed cache and success stamp.
//! Attempt and success clocks remain separate, including during wall-clock rewind.
//! A stale set is noticed at a revoked check and, once a window, by the host's refresher
//! ([`crate::refresh`]), so a node that serves no request still re-reads a peer's revokes.

use crate::diagnostics::{diag_warn, REVOCATION_RESYNC_FAILED, REVOCATION_RESYNC_OUTSTANDING};
use foldhash::HashSet;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::time::{Duration, Instant};

use super::REVOCATION_SYNC_TTL_SECS;

pub(crate) struct RevocationSync {
    /// This sync itself, for the refresher's call (it hands `&self`; a refresh needs the `Arc`).
    me: Weak<RevocationSync>,
    /// The runtime this sync was built on: the refresher's threads run outside it.
    runtime: Option<tokio::runtime::Handle>,
    native: NativeRefresh,

    set: RwLock<HashSet<String>>,

    synced_at: AtomicU64,

    /// The kernel's monotonic clock when this sync was built (`store::monotonic_ns`): a tick is
    /// the milliseconds since it.
    origin_ns: u64,
    synced_tick: AtomicU64,

    attempted: Mutex<Attempt>,

    inflight: AtomicBool,
}

struct NativeRefresh {
    core: Arc<crate::persistence::facade::CoreStore>,
    caches: Arc<RwLock<super::GovCaches>>,
    order: Arc<super::CacheOrder>,
}

struct Attempt {
    wall: u64,
    tick: u64,
}

struct RefreshFlight(Arc<RevocationSync>);

impl Drop for RefreshFlight {
    fn drop(&mut self) {
        self.0.inflight.store(false, Ordering::Release);
    }
}

impl RevocationSync {
    /// `now` and `origin_ns` are the builder's one reading: the wall clock in seconds and the
    /// kernel's monotonic clock in nanoseconds at the same instant.
    pub(super) fn native(
        core: Arc<crate::persistence::facade::CoreStore>,
        initial: HashSet<String>,
        now: u64,
        origin_ns: u64,
        caches: Arc<RwLock<super::GovCaches>>,
        order: Arc<super::CacheOrder>,
    ) -> Arc<Self> {
        Arc::new_cyclic(|me| Self {
            me: me.clone(),
            runtime: tokio::runtime::Handle::try_current().ok(),
            native: NativeRefresh {
                core,
                caches,
                order,
            },
            set: RwLock::new(initial),
            synced_at: AtomicU64::new(now),
            origin_ns,
            synced_tick: AtomicU64::new(0),
            attempted: Mutex::new(Attempt { wall: now, tick: 0 }),
            inflight: AtomicBool::new(false),
        })
    }

    pub(crate) fn contains(&self, sub: &str) -> bool {
        self.set
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .contains(sub)
    }

    pub(crate) fn insert(&self, sub: &str) {
        let mut set = self.set.write().unwrap_or_else(|e| e.into_inner());
        crate::off_path::governance::state::revocation_insert(&mut set, sub);
    }

    #[cfg(test)]
    pub(crate) fn synced_at(&self) -> u64 {
        self.synced_at.load(Ordering::Relaxed)
    }

    pub(crate) fn refresh_if_stale(self: &Arc<Self>, now: u64) {
        // Milliseconds on the monotonic clock since this sync was built, read at the check.
        let tick = crate::store::monotonic_ns().saturating_sub(self.origin_ns) / 1_000_000;
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
        if let Some(handle) = tokio::runtime::Handle::try_current()
            .ok()
            .or_else(|| self.runtime.clone())
        {
            handle.spawn(async move {
                let source = &flight.0.native;
                let result = super::state::identity_runtime::reload_native(
                    &source.core,
                    &source.caches,
                    &source.order,
                    &flight.0,
                )
                .await;
                match result {
                    Ok(()) => {
                        flight.0.synced_at.store(now, Ordering::Relaxed);
                        flight.0.synced_tick.store(tick, Ordering::Relaxed);
                    }
                    Err(error) => {
                        diag_warn!(REVOCATION_RESYNC_FAILED, error = %error,
                            "native identity re-sync failed; retaining confirmed caches");
                    }
                }
            });
        }
    }
}

/// THE IDLE NODE'S REFRESH: once a window the refresher makes the same stale check a revoked
/// check makes, at its own reading. Without it a node that serves no request never re-reads the
/// store, and its first request after a quiet spell is judged against the set it held before it.
impl crate::refresh::Refreshable for RevocationSync {
    fn refresh(&self, now: Instant) -> Instant {
        if let Some(sync) = self.me.upgrade() {
            sync.refresh_if_stale(crate::store::now());
        }
        now + Duration::from_secs(REVOCATION_SYNC_TTL_SECS)
    }
}

#[cfg(test)]
#[path = "tests/revocation_tests.rs"]
mod tests;
