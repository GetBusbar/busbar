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
//! A pooled connection is keyed by everything its dial was judged and secured for: the instance and
//! the need that dialled it, the entry, the authority, the security and the name offered, the
//! egress class it was judged under, and the trust it was secured with (the client config and the
//! sealed anchors, by identity: a seal replaced is another trust, so a line verified under the old
//! one is never lent again). A dial stated `within` an address set is never pooled (its landing
//! rule is per open). An idle connection is lent only after it has read what the far end sent while
//! it sat idle, so one the far end closed or said goodbye on is closed here, never handed out. Idle
//! connections past their time are closed whenever the pool is used, on every shard and for every
//! place, never only when their own place is opened to again.

use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use busbar_contract::conn::{InstanceId, NeedId};

use crate::line::Line;
use crate::tls::client::Sealed;

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

/// What a dial trusted, compared by IDENTITY: the client config it was secured under and the
/// destination's sealed anchors it was held to. Each is held here, so neither can be freed and its
/// address reused while a line keyed by it is pooled.
#[derive(Clone)]
pub(crate) struct Trust {
    /// The client config the dial was secured under (`None`: none).
    pub(crate) config: Option<Arc<rustls::ClientConfig>>,
    /// The sealed anchors the dial was held to (`None`: none).
    pub(crate) anchors: Option<Arc<Sealed>>,
}

/// Whether `a` and `b` are the same one (or both none).
fn same<T>(a: Option<&Arc<T>>, b: Option<&Arc<T>>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(a), Some(b)) => Arc::ptr_eq(a, b),
        _ => false,
    }
}

/// The address `a` names (`0`: none).
fn address<T>(a: Option<&Arc<T>>) -> usize {
    a.map_or(0, |a| Arc::as_ptr(a).cast::<()>() as usize)
}

impl PartialEq for Trust {
    fn eq(&self, other: &Self) -> bool {
        same(self.config.as_ref(), other.config.as_ref())
            && same(self.anchors.as_ref(), other.anchors.as_ref())
    }
}

impl Eq for Trust {}

impl Hash for Trust {
    fn hash<H: Hasher>(&self, state: &mut H) {
        address(self.config.as_ref()).hash(state);
        address(self.anchors.as_ref()).hash(state);
    }
}

impl std::fmt::Debug for Trust {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Trust")
            .field("config", &address(self.config.as_ref()))
            .field("anchors", &address(self.anchors.as_ref()))
            .finish()
    }
}

/// What a pooled connection was dialled for; an open reuses it only for the same.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct PoolKey {
    /// The instance whose open dialled it: a line is never lent across instances.
    pub(crate) owner: InstanceId,
    /// The need it was dialled on: a line is never lent across needs.
    pub(crate) need: NeedId,
    /// What the dial trusted: a line is lent only to an open held to the same.
    pub(crate) trust: Trust,
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
    /// Whether the dial was judged under the need's private reach to the destination: a line
    /// dialled under one is never lent to an exchange judged without it.
    pub(crate) reach: bool,
    /// The registration whose own sealed anchors the dial was held to (`None`: the destination's):
    /// a line that presented one registration's client identity is never lent to another's open.
    pub(crate) anchored_as: Option<String>,
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
    /// When every shard was last swept for idle lines past their time ([`Pools::sweep`]).
    swept: Mutex<Instant>,
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
            swept: Mutex::new(Instant::now()),
        }
    }

    /// Close every idle line, on every shard and for every place, that has sat past the idle time:
    /// at most once per idle time, whenever the pool is used, so a place never opened to again does
    /// not keep its lines open.
    fn sweep(&self, now: Instant) {
        let timeout = self.posture.idle_timeout;
        {
            let mut swept = self.swept.lock().expect("pool sweep");
            if now.saturating_duration_since(*swept) < timeout {
                return;
            }
            *swept = now;
        }
        let mut spent = Vec::new();
        for shard in &*self.shards {
            let mut map = shard.lock().expect("pool");
            map.retain(|_, entries| {
                entries.retain(|e| {
                    let expired = e
                        .idle
                        .is_some_and(|since| now.saturating_duration_since(since) >= timeout);
                    if expired {
                        spent.push(Arc::clone(&e.line));
                    }
                    !expired
                });
                !entries.is_empty()
            });
        }
        for line in spent {
            if line.users() == 0 {
                line.close();
            }
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
        self.sweep(now);
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
        self.sweep(now);
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
