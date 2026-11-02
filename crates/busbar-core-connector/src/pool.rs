// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PER-WORKER POOLS (`BUSBAR-1.6.0.md` THE DESIGN, connections: the connector owns "per-worker

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
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
    /// An idle freshness probe owns the line, with no shard lock held.
    checking: bool,
}

type Shard = Mutex<HashMap<PoolKey, Vec<Entry>>>;

/// The pools, one per shard.
pub(crate) struct Pools {
    posture: RwLock<PoolPosture>,
    shards: Box<[Shard]>,
    /// The instant the pools were made: what [`Self::reap_due`] counts from.
    epoch: Instant,
    /// When the earliest idle line's time runs out, in nanoseconds since [`Self::epoch`]
    reap_due: AtomicU64,
}

impl std::fmt::Debug for Pools {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pools")
            .field("posture", &self.posture())
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
        Self {
            posture: RwLock::new(posture),
            shards: (0..count).map(|_| Mutex::new(HashMap::new())).collect(),
            epoch: Instant::now(),
            reap_due: AtomicU64::new(u64::MAX),
        }
    }

    /// The applied posture, copied before any connection or plugin is driven.
    fn posture(&self) -> PoolPosture {
        *self.posture.read().expect("pool posture")
    }

    fn per_shard(&self, posture: PoolPosture) -> usize {
        if posture.max_idle_per_host == 0 {
            0
        } else {
            posture.max_idle_per_host.div_ceil(self.shards.len()).max(1)
        }
    }

    /// Bootstrap recovery replaces the posture without replacing the connector or its active

    pub(crate) fn reconfigure(&self, posture: PoolPosture) {
        let mut gone = Vec::new();
        {
            let mut applied = self.posture.write().expect("pool posture");
            *applied = posture;
            for shard in &*self.shards {
                gone.push(std::mem::take(&mut *shard.lock().expect("pool")));
            }
            self.reap_due.store(u64::MAX, Ordering::Release);
        }
        for map in gone {
            for entry in map.into_values().flatten() {
                if entry.line.users() == 0 {
                    entry.line.close();
                }
            }
        }
    }

    /// `at`, in nanoseconds since the pools were made.
    fn since_epoch(&self, at: Instant) -> u64 {
        u64::try_from(at.saturating_duration_since(self.epoch).as_nanos()).unwrap_or(u64::MAX)
    }

    /// A line went idle at `now`: the sweep is due by the time its idle time runs out.
    fn idled(&self, now: Instant, timeout: Duration) {
        let due = now
            .checked_add(timeout)
            .map_or(u64::MAX, |ends| self.since_epoch(ends));
        self.reap_due.fetch_min(due, Ordering::AcqRel);
    }

    /// THE IDLE REAPER: once the earliest idle deadline has passed, every shard is swept and each

    fn reap_if_due(&self, now: Instant) {
        let posture = self.posture.read().expect("pool posture");
        let at = self.since_epoch(now);
        let due = self.reap_due.load(Ordering::Acquire);
        if due > at
            || self
                .reap_due
                .compare_exchange(due, u64::MAX, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
            return;
        }
        let timeout = posture.idle_timeout;
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
        drop(posture);
        for line in spent {
            if line.users() == 0 {
                line.close();
            }
        }
    }

    /// Whether anything is ever kept.
    pub(crate) fn keeps(&self) -> bool {
        self.posture().max_idle_per_host > 0
    }

    /// The calling thread's shard: assigned on its first use and kept (1.5.5's `get`).
    pub(crate) fn shard(&self) -> usize {
        static NEXT_THREAD: AtomicUsize = AtomicUsize::new(0);
        thread_local! {
            static SHARD: std::cell::OnceCell<usize> = const { std::cell::OnceCell::new() };
        }
        let idx = SHARD.with(|s| *s.get_or_init(|| NEXT_THREAD.fetch_add(1, Ordering::Relaxed)));

        idx & (self.shards.len() - 1)
    }

    /// Hold a line just dialled for `key` on `shard`: in use by its first exchange, and, once it

    pub(crate) fn hold(&self, shard: usize, key: PoolKey, line: &Arc<Line>) {
        let posture = self.posture.read().expect("pool posture");
        if posture.max_idle_per_host == 0 {
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
                checking: false,
            });
    }

    /// A line for `key` on `shard`, LENT (its holder counted): a live multiplexing one, in use or

    pub(crate) fn lend(&self, shard: usize, key: &PoolKey) -> Option<Arc<Line>> {
        if !self.keeps() {
            return None;
        }
        let now = Instant::now();
        self.reap_if_due(now);
        let mut spent = Vec::new();

        let mut below = usize::MAX;
        let lent = loop {
            let (at, idle) = {
                let posture = self.posture.read().expect("pool posture");
                if posture.max_idle_per_host == 0 {
                    break None;
                }
                let timeout = posture.idle_timeout;
                let mut map = self.shards[shard].lock().expect("pool");
                let Some(entries) = map.get_mut(key) else {
                    break None;
                };
                let mut lent = None;
                let mut claimed = None;
                let mut i = below.min(entries.len());
                while i > 0 {
                    i -= 1;
                    if entries[i].checking {
                        continue;
                    }
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
                            entries[i].checking = true;
                            claimed = Some((i, Arc::clone(&entries[i].line)));
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
            let fresh = idle.fresh();
            {
                let _posture = self.posture.read().expect("pool posture");
                let mut map = self.shards[shard].lock().expect("pool");
                if let Some(entries) = map.get_mut(key) {
                    if let Some(i) = entries
                        .iter()
                        .position(|e| e.checking && Arc::ptr_eq(&e.line, &idle))
                    {
                        if fresh {
                            entries[i].checking = false;
                            entries[i].idle = None;
                            idle.lend();
                            break Some(idle);
                        }

                        entries.remove(i);
                    }
                    if entries.is_empty() {
                        map.remove(key);
                    }
                }
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

    pub(crate) fn release(&self, shard: usize, key: &PoolKey, line: &Arc<Line>) {
        let applied = self.posture.read().expect("pool posture");
        let posture = *applied;
        if posture.max_idle_per_host == 0 {
            drop(applied);
            self.drop_line(shard, key, line);
            return;
        }
        let now = Instant::now();
        let mut spent = Vec::new();
        {
            let mut map = self.shards[shard].lock().expect("pool");
            if line.users() > 0 {
                return;
            }
            let Some(entries) = map.get_mut(key) else {
                drop(map);
                drop(applied);
                line.close();
                self.reap_if_due(now);
                return;
            };
            let at = entries.iter().position(|e| Arc::ptr_eq(&e.line, line));
            let keep = line.reusable();
            match (at, keep) {
                (Some(i), true) => {
                    entries[i].idle = Some(now);
                    self.idled(now, posture.idle_timeout);
                }
                (Some(i), false) => spent.push(entries.remove(i).line),
                (None, _) => spent.push(Arc::clone(line)),
            }

            let timeout = posture.idle_timeout;
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
            let per_shard = self.per_shard(posture);
            if idle.len() > per_shard {
                idle.sort();
                let mut drop: Vec<usize> = idle[..idle.len() - per_shard]
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
        drop(applied);
        for line in spent {
            if line.users() == 0 {
                line.close();
            }
        }
        self.reap_if_due(now);
    }

    /// `owner` is gone: every line dialled for it leaves the pool, and each nobody holds is

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
