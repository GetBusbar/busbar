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
//! the need that dialled it (THE DESIGN §5, a connection belongs to the instance that opened it; §8,
//! the connector holds each need's trust), the entry, the authority, the security and the name
//! offered, the egress class it was judged under, the very client config it was secured with (a
//! need declared again under another operator CA is dialled afresh under its new trust), and the
//! very seal of trust anchors it was held to (a destination sealed again is dialled afresh under
//! its new seal). A dial
//! stated `within` an address set is never pooled (its landing rule is per open). An idle
//! connection is lent only after it has read what the far end sent while it sat idle, so one the far
//! end closed or said goodbye on is closed here, never handed out.
//!
//! An idle connection whose time ran out is closed the next time the pool is used, whatever place
//! that use is for: every shard is swept once the earliest idle deadline has passed (hyper-util's
//! idle reaper, which 1.5.5's pool ran on an interval).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
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

/// What a pooled connection was dialled for; an open reuses it only for the same.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct PoolKey {
    /// The instance whose open dialled it: a line is never lent to another instance.
    pub(crate) owner: InstanceId,
    /// The need it was dialled on, under that need's own trust: never lent to another need.
    pub(crate) need: NeedId,
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
    /// The client config the dial was secured with (`None`: none): the need's own, its operator CA
    /// on top of the public roots, or the connector's. A line verified under one is never lent to
    /// an open secured with another, even of the same need declared again.
    pub(crate) trust: Option<Same<rustls::ClientConfig>>,
    /// The seal of trust anchors the dial was held to (`None`: none): a line verified under one
    /// seal is never lent to an open held to another, even of the same destination sealed again.
    pub(crate) sealed: Option<Same<Sealed>>,
}

/// One trust a dial was held to (a client config, a seal of anchors), by identity: two are the
/// same only when they are one. The key holds it, so its address is never reused while a line
/// keyed by it is pooled.
#[derive(Debug)]
pub(crate) struct Same<T>(pub(crate) Arc<T>);

impl<T> Clone for Same<T> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<T> PartialEq for Same<T> {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl<T> Eq for Same<T> {}

impl<T> std::hash::Hash for Same<T> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        Arc::as_ptr(&self.0).hash(state);
    }
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
    /// The instant the pools were made: what [`Self::reap_due`] counts from.
    epoch: Instant,
    /// When the earliest idle line's time runs out, in nanoseconds since [`Self::epoch`]
    /// (`u64::MAX`: no line is idle): the next use of the pool at or past it sweeps every shard.
    reap_due: AtomicU64,
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
            epoch: Instant::now(),
            reap_due: AtomicU64::new(u64::MAX),
        }
    }

    /// `at`, in nanoseconds since the pools were made.
    fn since_epoch(&self, at: Instant) -> u64 {
        u64::try_from(at.saturating_duration_since(self.epoch).as_nanos()).unwrap_or(u64::MAX)
    }

    /// A line went idle at `now`: the sweep is due by the time its idle time runs out.
    fn idled(&self, now: Instant) {
        let due = now
            .checked_add(self.posture.idle_timeout)
            .map_or(u64::MAX, |ends| self.since_epoch(ends));
        self.reap_due.fetch_min(due, Ordering::AcqRel);
    }

    /// THE IDLE REAPER: once the earliest idle deadline has passed, every shard is swept and each
    /// idle line whose time ran out is dropped from the pool and closed (when nobody holds it),
    /// whatever place the use that found it due is for. Called holding no shard.
    fn reap_if_due(&self, now: Instant) {
        let at = self.since_epoch(now);
        let due = self.reap_due.load(Ordering::Acquire);
        if due > at
            || self
                .reap_due
                .compare_exchange(due, u64::MAX, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
            // Not due yet, or another use is sweeping (or a line idled since): its time stands.
            return;
        }
        let timeout = self.posture.idle_timeout;
        let mut spent = Vec::new();
        let mut next: Option<Instant> = None;
        for shard in &*self.shards {
            let mut map = shard.lock().expect("pool");
            map.retain(|_, entries| {
                entries.retain(|e| match e.idle {
                    Some(since) if now.duration_since(since) >= timeout => {
                        spent.push(Arc::clone(&e.line));
                        false
                    }
                    Some(since) => {
                        if let Some(ends) = since.checked_add(timeout) {
                            next = Some(next.map_or(ends, |n| n.min(ends)));
                        }
                        true
                    }
                    None => true,
                });
                !entries.is_empty()
            });
        }
        if let Some(next) = next {
            self.reap_due
                .fetch_min(self.since_epoch(next), Ordering::AcqRel);
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
    ///
    /// An idle line is read for freshness with NO LOCK HELD (`BUSBAR-1.6.0.md` §11: no plugin code
    /// runs under a host lock; reading it drives its connection): it is taken out of the pool while
    /// it is read, and put back where it was, lent, when it is fresh.
    pub(crate) fn lend(&self, shard: usize, key: &PoolKey) -> Option<Arc<Line>> {
        if !self.keeps() {
            return None;
        }
        let now = Instant::now();
        self.reap_if_due(now);
        let timeout = self.posture.idle_timeout;
        let mut spent = Vec::new();
        // Newest first, as hyper-util's idle list pops: the walk resumes below a line read stale.
        let mut below = usize::MAX;
        let lent = loop {
            let (at, idle) = {
                let mut map = self.shards[shard].lock().expect("pool");
                let Some(entries) = map.get_mut(key) else {
                    break None;
                };
                let mut lent = None;
                let mut claimed = None;
                let mut i = below.min(entries.len());
                while i > 0 {
                    i -= 1;
                    let (idle, users) = (entries[i].idle, entries[i].line.users());
                    match idle {
                        None if users == 0 => spent.push(entries.remove(i).line),
                        None if entries[i].line.multiplexes() => {
                            let line = Arc::clone(&entries[i].line);
                            line.lend();
                            lent = Some(line);
                            break;
                        }
                        None => {}
                        Some(since) if now.duration_since(since) < timeout => {
                            claimed = Some((i, entries.remove(i).line));
                            break;
                        }
                        Some(_) => spent.push(entries.remove(i).line),
                    }
                }
                if entries.is_empty() {
                    map.remove(key);
                }
                if lent.is_some() {
                    break lent;
                }
                let Some(claimed) = claimed else {
                    break None;
                };
                claimed
            };
            if idle.fresh() {
                idle.lend();
                let mut map = self.shards[shard].lock().expect("pool");
                let entries = map.entry(key.clone()).or_default();
                entries.insert(
                    at.min(entries.len()),
                    Entry {
                        line: Arc::clone(&idle),
                        idle: None,
                    },
                );
                break Some(idle);
            }
            spent.push(idle);
            below = at;
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
                (Some(i), true) => {
                    entries[i].idle = Some(now);
                    self.idled(now);
                }
                (None, true) => {
                    entries.push(Entry {
                        line: Arc::clone(line),
                        idle: Some(now),
                    });
                    self.idled(now);
                }
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
        self.reap_if_due(now);
    }

    /// `owner` is gone: every line dialled for it leaves the pool, and each nobody holds is
    /// closed now, never left for the idle reaper. Another instance's lines are untouched.
    pub(crate) fn forget(&self, owner: InstanceId) {
        let mut gone = Vec::new();
        for shard in &*self.shards {
            shard.lock().expect("pool").retain(|key, entries| {
                if key.owner != owner {
                    return true;
                }
                gone.extend(entries.drain(..).map(|e| e.line));
                false
            });
        }
        for line in gone {
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
