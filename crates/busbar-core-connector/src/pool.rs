// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PER-WORKER POOLS (`BUSBAR-1.6.0.md` THE DESIGN, connections: the connector owns "per-worker
//! pools"). A dialled connection whose exchange finished whole is kept, and the next open to the
//! same place takes it instead of dialling: the second request rides the first one's connection (on
//! HTTP/2, the next stream of it), as 1.5.5's egress client sent it.
//!
//! The shape is 1.5.5's (`UpstreamClients` at v1.5.5, `crates/busbar/src/state.rs`): N shards, N the
//! machine's parallelism rounded up to a power of two and capped at 16, each worker thread assigned
//! one shard on first use and keeping it; the per-host idle budget
//! (`limits.pool_max_idle_per_host`) divided across the shards, never below one; an idle
//! connection reaped once it has sat `limits.pool_idle_timeout_secs`. The most recently idled
//! connection is taken first (hyper-util's pool).
//!
//! A pooled connection is keyed by everything its dial was judged and secured for: the entry, the
//! authority, the security and the name offered, and the egress class it was judged under. A dial
//! stated `within` an address set is never pooled (its landing rule is per open). A connection is
//! taken only after it has read what the far end sent while it sat idle, so one the far end closed
//! or said goodbye on is closed here, never handed out.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::compose::Connection;

/// The deployment's pool posture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolPosture {
    /// The per-host idle budget, across every shard (`limits.pool_max_idle_per_host`); `0` keeps
    /// nothing, so every open dials.
    pub max_idle_per_host: usize,
    /// How long an idle connection is kept (`limits.pool_idle_timeout_secs`).
    pub idle_timeout: Duration,
}

impl PoolPosture {
    /// No pooling: every open dials, every close closes.
    pub const NONE: Self = Self {
        max_idle_per_host: 0,
        idle_timeout: Duration::ZERO,
    };
}

impl Default for PoolPosture {
    fn default() -> Self {
        Self::NONE
    }
}

/// What a pooled connection was dialled for; an open reuses it only for the same.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct PoolKey {
    /// The entry (its table's address: one per loaded entry for the process).
    pub(crate) door: usize,
    /// The authority dialled, lower-cased.
    pub(crate) authority: String,
    /// Connection security.
    pub(crate) secure: bool,
    /// The name offered to the far end.
    pub(crate) name: Option<String>,
    /// The egress class the dial was judged under, and the need's own.
    pub(crate) class: (u32, u32),
}

type Shard = Mutex<HashMap<PoolKey, VecDeque<(Instant, Connection)>>>;

/// The pools, one per shard.
pub(crate) struct Pools {
    posture: PoolPosture,
    per_shard: usize,
    shards: Box<[Shard]>,
}

impl std::fmt::Debug for Pools {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pools")
            .field("posture", &self.posture)
            .field("shards", &self.shards.len())
            .finish_non_exhaustive()
    }
}

/// 1.5.5's shard count: the machine's parallelism, a power of two, at most 16.
fn shard_count() -> usize {
    std::thread::available_parallelism()
        .map_or(1, std::num::NonZero::get)
        .next_power_of_two()
        .min(16)
}

impl Pools {
    /// The pools for `posture`.
    pub(crate) fn new(posture: PoolPosture) -> Self {
        let count = shard_count();
        let per_shard = if posture.max_idle_per_host == 0 {
            0
        } else {
            posture.max_idle_per_host.div_ceil(count).max(1)
        };
        Self {
            posture,
            per_shard,
            shards: (0..count).map(|_| Mutex::new(HashMap::new())).collect(),
        }
    }

    /// Whether anything is ever kept.
    pub(crate) fn keeps(&self) -> bool {
        self.per_shard > 0
    }

    /// The calling thread's shard: assigned on its first use and kept (1.5.5's `get`).
    pub(crate) fn shard(&self) -> usize {
        static NEXT_THREAD: AtomicUsize = AtomicUsize::new(0);
        thread_local! {
            static SHARD: std::cell::OnceCell<usize> = const { std::cell::OnceCell::new() };
        }
        let idx = SHARD.with(|s| *s.get_or_init(|| NEXT_THREAD.fetch_add(1, Ordering::Relaxed)));
        // Mask, not modulo: the count is a power of two.
        idx & (self.shards.len() - 1)
    }

    /// The most recently idled connection for `key` on `shard` that is still fresh; every stale or
    /// spent one met on the way is closed.
    pub(crate) fn take(&self, shard: usize, key: &PoolKey) -> Option<Connection> {
        if !self.keeps() {
            return None;
        }
        let now = Instant::now();
        loop {
            let (since, mut conn) = {
                let mut map = self.shards[shard].lock().expect("pool");
                let idle = map.get_mut(key)?;
                let got = idle.pop_back();
                if idle.is_empty() {
                    map.remove(key);
                }
                got?
            };
            if now.duration_since(since) < self.posture.idle_timeout && conn.fresh() {
                return Some(conn);
            }
            conn.close();
        }
    }

    /// Keep `conn` for `key` on `shard`; past the shard's budget the oldest idle one is closed, and
    /// so is every one whose idle time ran out.
    pub(crate) fn park(&self, shard: usize, key: PoolKey, conn: Connection) {
        if !self.keeps() || !conn.reusable() {
            conn.close();
            return;
        }
        let now = Instant::now();
        let mut spent = Vec::new();
        {
            let mut map = self.shards[shard].lock().expect("pool");
            let idle = map.entry(key).or_default();
            while idle
                .front()
                .is_some_and(|(since, _)| now.duration_since(*since) >= self.posture.idle_timeout)
            {
                spent.extend(idle.pop_front().map(|(_, c)| c));
            }
            idle.push_back((now, conn));
            while idle.len() > self.per_shard {
                spent.extend(idle.pop_front().map(|(_, c)| c));
            }
        }
        for c in spent {
            c.close();
        }
    }
}
