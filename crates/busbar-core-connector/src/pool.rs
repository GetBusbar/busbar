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
//! A connection that MULTIPLEXES (an `h2` connection, agreed in the handshake or by prior
//! knowledge) is shared while it is in use: a concurrent open to the same place on the same shard
//! rides it as its next stream (ARCHITECT ruling Q-L18-MUX, 1.5.5's pooled h2 client). An HTTP/1.1
//! connection carries one exchange at a time and is lent again only once idle.
//!
//! A pooled connection is keyed by everything its dial was judged and secured for: the entry, the
//! authority, the security and the name offered, and the egress class it was judged under. A dial
//! stated `within` an address set is never pooled (its landing rule is per open). An idle
//! connection is lent only after it has read what the far end sent while it sat idle, so one the far
//! end closed or said goodbye on is closed here, never handed out.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::line::Line;

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

/// One pooled line: in use (`idle` = `None`), or idle since the instant named.
struct Entry {
    line: Arc<Line>,
    idle: Option<Instant>,
}

type Shard = Mutex<HashMap<PoolKey, Vec<Entry>>>;

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

    /// Hold a line just dialled for `key` on `shard`: in use by its first exchange, and, once it
    /// multiplexes, shared with concurrent opens to the same place.
    pub(crate) fn hold(&self, shard: usize, key: PoolKey, line: &Arc<Line>) {
        if !self.keeps() {
            return;
        }
        self.shards[shard]
            .lock()
            .expect("pool")
            .entry(key)
            .or_default()
            .push(Entry {
                line: Arc::clone(line),
                idle: None,
            });
    }

    /// A line for `key` on `shard`, LENT (its holder counted): a live multiplexing one, in use or
    /// idle, first; else the most recently idled one that is still fresh. Every stale, spent or dead
    /// line met on the way is dropped from the pool, and closed when nobody holds it.
    pub(crate) fn lend(&self, shard: usize, key: &PoolKey) -> Option<Arc<Line>> {
        if !self.keeps() {
            return None;
        }
        let now = Instant::now();
        let mut spent = Vec::new();
        let lent = {
            let mut map = self.shards[shard].lock().expect("pool");
            let entries = map.get_mut(key)?;
            let timeout = self.posture.idle_timeout;
            let mut lent = None;
            // Newest first, as hyper-util's idle list pops.
            let mut i = entries.len();
            while i > 0 {
                i -= 1;
                let e = &mut entries[i];
                let usable = match e.idle {
                    Some(since) => now.duration_since(since) < timeout && e.line.fresh(),
                    None => e.line.multiplexes(),
                };
                let dead = match e.idle {
                    Some(_) => !usable,
                    None => e.line.users() == 0,
                };
                if dead {
                    spent.push(entries.remove(i).line);
                    continue;
                }
                if usable {
                    e.idle = None;
                    e.line.lend();
                    lent = Some(Arc::clone(&e.line));
                    break;
                }
            }
            if entries.is_empty() {
                map.remove(key);
            }
            lent
        };
        for line in spent {
            if line.users() == 0 {
                line.close();
            }
        }
        lent
    }

    /// `line`'s last holder for `key` on `shard` left (`users() == 0`): kept idle when it can carry
    /// another exchange (past the shard's budget the oldest idle one is closed), else dropped and
    /// closed. A line a holder still holds is left as it is.
    pub(crate) fn release(&self, shard: usize, key: &PoolKey, line: &Arc<Line>) {
        if !self.keeps() {
            line.close();
            return;
        }
        let now = Instant::now();
        let mut spent = Vec::new();
        {
            let mut map = self.shards[shard].lock().expect("pool");
            let entries = map.entry(key.clone()).or_default();
            let at = entries.iter().position(|e| Arc::ptr_eq(&e.line, line));
            if line.users() > 0 {
                return;
            }
            let keep = line.reusable();
            match (at, keep) {
                (Some(i), true) => entries[i].idle = Some(now),
                (None, true) => entries.push(Entry {
                    line: Arc::clone(line),
                    idle: Some(now),
                }),
                (Some(i), false) => spent.push(entries.remove(i).line),
                (None, false) => spent.push(Arc::clone(line)),
            }
            // The idle time ran out, or past the budget: the oldest idle lines go.
            let timeout = self.posture.idle_timeout;
            entries.retain(|e| {
                let expired = e
                    .idle
                    .is_some_and(|since| now.duration_since(since) >= timeout);
                if expired {
                    spent.push(Arc::clone(&e.line));
                }
                !expired
            });
            let mut idle: Vec<(Instant, usize)> = entries
                .iter()
                .enumerate()
                .filter_map(|(i, e)| e.idle.map(|since| (since, i)))
                .collect();
            if idle.len() > self.per_shard {
                idle.sort();
                let mut drop: Vec<usize> = idle[..idle.len() - self.per_shard]
                    .iter()
                    .map(|(_, i)| *i)
                    .collect();
                drop.sort_unstable_by(|a, b| b.cmp(a));
                for i in drop {
                    spent.push(entries.remove(i).line);
                }
            }
            if entries.is_empty() {
                map.remove(key);
            }
        }
        for line in spent {
            if line.users() == 0 {
                line.close();
            }
        }
    }

    /// Drop `line` from the pool for `key` on `shard` (it failed its exchange's open); closed when
    /// nobody holds it.
    pub(crate) fn drop_line(&self, shard: usize, key: &PoolKey, line: &Arc<Line>) {
        {
            let mut map = self.shards[shard].lock().expect("pool");
            if let Some(entries) = map.get_mut(key) {
                entries.retain(|e| !Arc::ptr_eq(&e.line, line));
                if entries.is_empty() {
                    map.remove(key);
                }
            }
        }
        if line.users() == 0 {
            line.close();
        }
    }
}
