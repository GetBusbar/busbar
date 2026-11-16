// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PER-WORKER POOLS (`BUSBAR-1.6.0.md` THE DESIGN, connections: the connector owns "per-worker

use std::cell::Cell;
use std::hash::{BuildHasher, Hash, Hasher};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::task::Waker;
use std::time::{Duration, Instant};

use busbar_contract::conn::{InstanceId, NeedId};
use foldhash::HashMap;

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
///
/// Built with `hash: 0` and sealed by [`Pools::keyed`], which hashes every field once; the map
/// then hashes only that `u64`. Two keys are the same only when every field is.
#[derive(Debug, Clone)]
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
    /// Every other field, hashed once by [`Pools::keyed`] with the pools' own `RandomState`.
    pub(crate) hash: u64,
}

/// Every field of a key but its `hash`: what [`Pools::keyed`] hashes, once per key.
struct Fields<'a>(&'a PoolKey);

impl Hash for Fields<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let PoolKey {
            owner,
            need,
            door,
            authority,
            secure,
            name,
            class,
            reach,
            anchored_as,
            trust,
            sealed,
            hash: _,
        } = self.0;
        owner.hash(state);
        need.hash(state);
        door.hash(state);
        authority.hash(state);
        secure.hash(state);
        name.hash(state);
        class.hash(state);
        reach.hash(state);
        anchored_as.hash(state);
        trust.hash(state);
        sealed.hash(state);
    }
}

/// A lookup hashes only the key's `hash` (its fields were hashed once, by [`Pools::keyed`]); the
/// map's own SipHash runs over that one `u64`.
impl Hash for PoolKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_u64(self.hash);
    }
}

/// Every field, not the hash alone: two keys whose hashes collide are still two keys, and a line
/// is never lent across them.
impl PartialEq for PoolKey {
    fn eq(&self, other: &Self) -> bool {
        let PoolKey {
            owner,
            need,
            door,
            authority,
            secure,
            name,
            class,
            reach,
            anchored_as,
            trust,
            sealed,
            hash,
        } = self;
        *hash == other.hash
            && *owner == other.owner
            && *need == other.need
            && *door == other.door
            && *secure == other.secure
            && *class == other.class
            && *reach == other.reach
            && *authority == other.authority
            && *name == other.name
            && *anchored_as == other.anchored_as
            && *trust == other.trust
            && *sealed == other.sealed
    }
}

impl Eq for PoolKey {}

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
pub(crate) struct Entry {
    pub(crate) line: Arc<Line>,
    pub(crate) idle: Option<Instant>,
    /// An idle freshness probe owns the line, with no shard lock held.
    checking: bool,
}

/// One key's pooled lines on one shard, and the dial claimed for it (WASTE-EGRESS rule 1): the
/// lines it keeps, the claimed dial in flight (`None`, or one whose `done` is set, counts as
/// absent), and whether the key's last claimed dial agreed a protocol that never multiplexes
/// (`solo`: later opens dial their own, as before any claim). Its fields are this module's alone,
/// so a line enters a slot only through a [`Leader`] or a [`Fill`] (LINT-RULES R62).
#[derive(Default)]
pub(crate) struct Slot {
    lines: Vec<Entry>,
    opening: Option<Arc<Opening>>,
    solo: bool,
}

impl Slot {
    /// Nothing keeps the slot: no line, and no claimed dial in flight (rule 6). Every remover
    /// removes a slot only when this holds.
    pub(crate) fn vacant(&self) -> bool {
        self.lines.is_empty() && self.opening.as_ref().is_none_or(|o| o.done())
    }

    /// The lines the slot keeps, for a remover: each leaves through [`Slot::remove`].
    pub(crate) fn lines(&self) -> &[Entry] {
        &self.lines
    }

    /// Take the line at `i` out of the slot (a remover's step).
    pub(crate) fn remove(&mut self, i: usize) -> Arc<Line> {
        self.lines.swap_remove(i).line
    }

    /// A FLUSH: every line taken out into `spent`, and the claimed dial in flight, if any, into
    /// `ended`, to be ended and its followers woken once no shard lock is held (rule 6).
    pub(crate) fn empty_into(&mut self, spent: &mut Spent, ended: &mut Vec<Arc<Opening>>) {
        spent.extend(self.lines.drain(..).map(|e| e.line));
        ended.extend(self.opening.take());
    }
}

pub(crate) type Shard = Mutex<HashMap<PoolKey, Slot>>;

/// ONE CLAIMED DIAL IN FLIGHT for a key on a shard (WASTE-EGRESS rule 1): the opens that joined it
/// park here until it ends.
#[derive(Default)]
pub(crate) struct Opening {
    done: AtomicBool,
    waiters: Mutex<Vec<Waker>>,
}

impl Opening {
    fn done(&self) -> bool {
        self.done.load(Ordering::Acquire)
    }

    /// The claimed dial ENDED (rule 5): `done` is set and every parked waker taken out, under the
    /// waiters' lock, for the caller to wake once it holds no lock ([`wake_all`]).
    pub(crate) fn end(&self) -> Vec<Waker> {
        let mut waiters = self.waiters.lock().unwrap_or_else(PoisonError::into_inner);
        self.done.store(true, Ordering::Release);
        std::mem::take(&mut *waiters)
    }
}

/// Wake every one of `wakers`, called with no lock held (rule 8: no waker is woken or dropped under
/// a lock).
pub(crate) fn wake_all(wakers: Vec<Waker>) {
    for waker in wakers {
        waker.wake();
    }
}

/// What [`Pools::take`] answers for an open's key (WASTE-EGRESS rule 1).
pub(crate) enum Take {
    /// A line LENT (its holder counted): an in-use multiplexing one, or a fresh idle one.
    Lent(Arc<Line>),
    /// A claimed dial for the key is in flight: the open parks on it.
    Join(Joined),
    /// This open is the key's claimed dial.
    Lead(Leader),
    /// The open dials unclaimed (the miss as before any claim); its line is still pooled, through
    /// [`Fill::hold`].
    Dial(Fill),
}

impl Take {
    /// The line lent, if one was (tests only: an unclaimed take is the old `lend`).
    #[cfg(test)]
    pub(crate) fn lent(self) -> Option<Arc<Line>> {
        match self {
            Self::Lent(line) => Some(line),
            Self::Join(_) | Self::Lead(_) | Self::Dial(_) => None,
        }
    }
}

/// THE CLAIMED DIAL'S TOKEN: minted only by [`Pools::take`], never cloned. Settled once its line's
/// handshake ends ([`Leader::settle`]); dropped unsettled, the dial is LOST (rule 5) and its
/// followers take again.
#[must_use = "a claimed dial ends only when its leader settles or drops"]
pub(crate) struct Leader {
    shards: Arc<[Shard]>,
    shard: usize,
    key: PoolKey,
    opening: Arc<Opening>,
    /// Settled as not multiplexing: the key is marked `solo` as the claim ends.
    solo: bool,
}

impl Leader {
    /// Hold the line this claimed dial made: in use by its first exchange.
    pub(crate) fn hold(&self, pools: &Pools, line: &Arc<Line>) {
        pools.keep(self.shard, self.key.clone(), line);
    }

    /// The claimed dial's handshake ended live: `shared` = its line multiplexes (the followers are
    /// lent it), else it agreed a protocol that does not, and the key turns `solo`.
    pub(crate) fn settle(mut self, shared: bool) {
        self.solo = !shared;
    }
}

impl Drop for Leader {
    /// Settled or lost, the claim ends (rule 5): the slot's opening is cleared only if it is still
    /// this one, `done` is always set, and the parked followers are woken with no lock held.
    fn drop(&mut self) {
        {
            let mut map = self.shards[self.shard]
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            let vacant = match map.get_mut(&self.key) {
                Some(slot)
                    if slot
                        .opening
                        .as_ref()
                        .is_some_and(|o| Arc::ptr_eq(o, &self.opening)) =>
                {
                    slot.opening = None;
                    slot.solo |= self.solo;
                    slot.vacant()
                }
                _ => false,
            };
            if vacant {
                map.remove(&self.key);
            }
        }
        wake_all(self.opening.end());
    }
}

/// AN UNCLAIMED DIAL'S TOKEN: minted only by [`Pools::take`], never cloned; the one way its line is
/// pooled.
#[must_use = "an unclaimed dial's line is pooled only through its fill"]
pub(crate) struct Fill {
    shard: usize,
    key: PoolKey,
}

impl Fill {
    /// Hold the line this dial made: in use by its first exchange (nothing, under posture `NONE`).
    pub(crate) fn hold(self, pools: &Pools, line: &Arc<Line>) {
        pools.keep(self.shard, self.key, line);
    }
}

/// A JOINED claimed dial: the follower parks on it until it ends.
pub(crate) struct Joined {
    opening: Arc<Opening>,
    /// The waker this follower last parked: a poll with a waker that wakes the same task is not
    /// parked again (rule 8's dedupe, kept per follower, so no park scans the waiters).
    parked: Option<Waker>,
}

impl Joined {
    fn new(opening: Arc<Opening>) -> Self {
        Self {
            opening,
            parked: None,
        }
    }

    /// Park `waker` until the claimed dial ends (rule 8): deduped, cloned before the lock, pushed,
    /// and `done` read under the same lock, so no wake-up is lost. `false`: it had already ended
    /// (the waker just pushed is popped again). No waker is woken or dropped under the lock.
    pub(crate) fn park(&mut self, waker: &Waker) -> bool {
        if self.parked.as_ref().is_some_and(|p| p.will_wake(waker)) {
            return !self.opening.done();
        }
        let fresh = waker.clone();
        let (parked, popped) = {
            let mut waiters = self
                .opening
                .waiters
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            waiters.push(fresh);
            if self.opening.done() {
                (false, waiters.pop())
            } else {
                (true, None)
            }
        };
        drop(popped);
        if parked {
            let previous = self.parked.replace(waker.clone());
            drop(previous);
        }
        parked
    }

    /// Whether the claimed dial ended.
    pub(crate) fn done(&self) -> bool {
        self.opening.done()
    }
}

thread_local! {
    /// The calling thread's reused list of lines leaving the pool ([`Spent`]).
    static SPENT: Cell<Vec<Arc<Line>>> = const { Cell::new(Vec::new()) };
}

/// The lines one pool op takes out, closed once no pool lock is held: the calling thread's reused
/// list, handed back empty for its next op (a re-entrant op gets a list of its own).
pub(crate) struct Spent(Vec<Arc<Line>>);

impl Spent {
    pub(crate) fn take() -> Self {
        Self(SPENT.take())
    }

    pub(crate) fn push(&mut self, line: Arc<Line>) {
        self.0.push(line);
    }

    pub(crate) fn extend(&mut self, lines: impl IntoIterator<Item = Arc<Line>>) {
        self.0.extend(lines);
    }

    /// Close every line taken out that nobody holds.
    pub(crate) fn close(mut self) {
        for line in self.0.drain(..) {
            if line.users() == 0 {
                line.close();
            }
        }
    }
}

impl Drop for Spent {
    fn drop(&mut self) {
        self.0.clear();
        SPENT.set(std::mem::take(&mut self.0));
    }
}

/// The pools, one per shard.
pub(crate) struct Pools {
    posture: RwLock<PoolPosture>,
    /// Shared with every claimed dial's [`Leader`], which ends its claim on its own shard.
    pub(crate) shards: Arc<[Shard]>,
    /// The instant the pools were made: what [`Self::reap_due`] counts from.
    epoch: Instant,
    /// When the earliest idle line's time runs out, in nanoseconds since [`Self::epoch`]
    pub(crate) reap_due: AtomicU64,
    /// The process's key hasher: [`Self::keyed`] hashes each key's fields with it once.
    keys: foldhash::fast::RandomState,
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
        Self {
            posture: RwLock::new(posture),
            shards: crate::off_path::lines::pool_shards(shard_count()),
            epoch: crate::framer::now(),
            reap_due: AtomicU64::new(u64::MAX),
            keys: foldhash::fast::RandomState::default(),
        }
    }

    /// `key` sealed for the pools: its fields hashed once, here, into its `hash`.
    pub(crate) fn keyed(&self, mut key: PoolKey) -> PoolKey {
        key.hash = self.keys.hash_one(Fields(&key));
        key
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
        let gone = {
            let mut applied = self.posture.write().expect("pool posture");
            *applied = posture;
            let gone = crate::off_path::lines::take_shards(&self.shards);
            self.reap_due.store(u64::MAX, Ordering::Release);
            gone
        };
        // A flush (rule 6): every claimed dial in flight ends with its slot, and its followers
        // are woken, with no pool lock held.
        for map in gone {
            for slot in map.into_values() {
                for entry in slot.lines {
                    if entry.line.users() == 0 {
                        entry.line.close();
                    }
                }
                if let Some(opening) = slot.opening {
                    wake_all(opening.end());
                }
            }
        }
    }

    /// `at`, in nanoseconds since the pools were made.
    pub(crate) fn since_epoch(&self, at: Instant) -> u64 {
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
        let spent = crate::off_path::lines::sweep_idle_lines(self, posture.idle_timeout, now);
        drop(posture);
        spent.close();
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

    /// Keep a line just dialled for `key` on `shard`: in use by its first exchange, and, once it
    /// finished whole, idle for the next. Reached only through a [`Leader`] or a [`Fill`].
    fn keep(&self, shard: usize, key: PoolKey, line: &Arc<Line>) {
        let posture = self.posture.read().expect("pool posture");
        if posture.max_idle_per_host == 0 {
            return;
        }
        self.shards[shard]
            .lock()
            .expect("pool")
            .entry(key)
            .or_default()
            .lines
            .push(Entry {
                line: Arc::clone(line),
                idle: None,
                checking: false,
            });
    }

    /// THE CLAIMED TAKE (WASTE-EGRESS rule 1): a line for `key` on `shard`, LENT (its holder
    /// counted): a live multiplexing one, in use or idle, or a fresh idle one after its freshness
    /// probe. On a miss, with `claim` (a core-paced open, rule 3) and `candidate` (its dial can
    /// multiplex, rule 2) and the key not `solo`, the miss is CLAIMED under the shard lock that saw
    /// it: a claimed dial in flight is joined, or this open leads one. Otherwise the open dials
    /// unclaimed, as every miss did before, its line pooled through the [`Fill`].
    pub(crate) fn take(&self, shard: usize, key: &PoolKey, claim: bool, candidate: bool) -> Take {
        if !self.keeps() {
            return Take::Dial(Fill {
                shard,
                key: key.clone(),
            });
        }
        let now = crate::framer::now();
        self.reap_if_due(now);
        let mut spent = Spent::take();

        let mut below = usize::MAX;
        let took = loop {
            let (at, idle) = {
                let posture = self.posture.read().expect("pool posture");
                if posture.max_idle_per_host == 0 {
                    break Take::Dial(Fill {
                        shard,
                        key: key.clone(),
                    });
                }
                let timeout = posture.idle_timeout;
                let mut map = self.shards[shard].lock().expect("pool");
                let mut lent = None;
                let mut claimed = None;
                let mut vacant = false;
                if let Some(slot) = map.get_mut(key) {
                    let mut multiplexing = false;
                    let entries = &mut slot.lines;
                    let mut i = below.min(entries.len());
                    while i > 0 {
                        i -= 1;
                        if entries[i].checking {
                            continue;
                        }
                        let (idle, users) = (entries[i].idle, entries[i].line.users());
                        match idle {
                            None if users == 0 => spent.push(entries.swap_remove(i).line),
                            None if entries[i].line.multiplexes() => {
                                let line = Arc::clone(&entries[i].line);
                                line.lend();
                                lent = Some(line);
                                multiplexing = true;
                                break;
                            }
                            None => {}
                            Some(since) if now.duration_since(since) < timeout => {
                                entries[i].checking = true;
                                claimed = Some((i, Arc::clone(&entries[i].line)));
                                break;
                            }
                            Some(_) => spent.push(entries.swap_remove(i).line),
                        }
                    }
                    // A multiplexing line for the key: whatever its last claim agreed, it shares.
                    if multiplexing {
                        slot.solo = false;
                    }
                    vacant = lent.is_none() && claimed.is_none() && slot.vacant();
                }
                if let Some(line) = lent {
                    break Take::Lent(line);
                }
                let Some(claimed) = claimed else {
                    break self.miss(&mut *map, shard, key, claim && candidate, vacant);
                };
                claimed
            };
            let fresh = idle.fresh();
            {
                let _posture = self.posture.read().expect("pool posture");
                let mut map = self.shards[shard].lock().expect("pool");
                let mut vacant = false;
                if let Some(slot) = map.get_mut(key) {
                    if let Some(i) = slot
                        .lines
                        .iter()
                        .position(|e| e.checking && Arc::ptr_eq(&e.line, &idle))
                    {
                        if fresh {
                            slot.lines[i].checking = false;
                            slot.lines[i].idle = None;
                            idle.lend();
                            break Take::Lent(idle);
                        }

                        slot.lines.swap_remove(i);
                    }
                    vacant = slot.vacant();
                }
                if vacant {
                    map.remove(key);
                }
            }
            spent.push(idle);
            below = at;
        };
        spent.close();
        took
    }

    /// THE MISS, under the shard lock that saw no usable line for `key` (rule 1). `claims`: the
    /// open may claim it; a `solo` key is never claimed. `vacant`: the key's slot keeps nothing,
    /// and leaves unless this open claims it.
    fn miss(
        &self,
        map: &mut HashMap<PoolKey, Slot>,
        shard: usize,
        key: &PoolKey,
        claims: bool,
        vacant: bool,
    ) -> Take {
        let slot = map.get_mut(key);
        if claims && !slot.as_ref().is_some_and(|s| s.solo) {
            let live = slot
                .as_ref()
                .and_then(|s| s.opening.as_ref())
                .filter(|o| !o.done())
                .map(Arc::clone);
            if let Some(opening) = live {
                return Take::Join(Joined::new(opening));
            }
            let opening = Arc::new(Opening::default());
            match slot {
                Some(slot) => slot.opening = Some(Arc::clone(&opening)),
                None => {
                    map.insert(
                        key.clone(),
                        Slot {
                            lines: Vec::new(),
                            opening: Some(Arc::clone(&opening)),
                            solo: false,
                        },
                    );
                }
            }
            return Take::Lead(Leader {
                shards: Arc::clone(&self.shards),
                shard,
                key: key.clone(),
                opening,
                solo: false,
            });
        }
        if vacant {
            map.remove(key);
        }
        Take::Dial(Fill {
            shard,
            key: key.clone(),
        })
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
        let now = crate::framer::now();
        let mut spent = Spent::take();
        {
            let mut map = self.shards[shard].lock().expect("pool");
            if line.users() > 0 {
                return;
            }
            let Some(slot) = map.get_mut(key) else {
                drop(map);
                drop(applied);
                line.close();
                self.reap_if_due(now);
                return;
            };
            let entries = &mut slot.lines;
            let at = entries.iter().position(|e| Arc::ptr_eq(&e.line, line));
            let keep = line.reusable();
            match (at, keep) {
                (Some(i), true) => {
                    entries[i].idle = Some(now);
                    self.idled(now, posture.idle_timeout);
                }
                (Some(i), false) => spent.push(entries.swap_remove(i).line),
                (None, _) => spent.push(Arc::clone(line)),
            }

            // One pass expires every idle line whose time ran out and counts those still idle.
            let timeout = posture.idle_timeout;
            let mut idle = 0_usize;
            let mut i = entries.len();
            while i > 0 {
                i -= 1;
                match entries[i].idle {
                    Some(since) if now.duration_since(since) >= timeout => {
                        spent.push(entries.swap_remove(i).line);
                    }
                    Some(_) => idle += 1,
                    None => {}
                }
            }
            // Over the shard's budget, the longest idle leave first.
            let per_shard = self.per_shard(posture);
            while idle > per_shard {
                let oldest = entries
                    .iter()
                    .enumerate()
                    .filter_map(|(i, e)| e.idle.map(|since| (since, i)))
                    .min();
                let Some((_, i)) = oldest else {
                    break;
                };
                spent.push(entries.swap_remove(i).line);
                idle -= 1;
            }
            // A claimed dial in flight keeps the slot (rule 6).
            if slot.vacant() {
                map.remove(key);
            }
        }
        drop(applied);
        spent.close();
        self.reap_if_due(now);
    }

    /// `owner` is gone: every line dialled for it leaves the pool, and each nobody holds is
    pub(crate) fn forget(&self, owner: InstanceId) {
        crate::off_path::lines::forget_pooled(self, owner);
    }

    /// Drop `line` from the pool for `key` on `shard` (it failed its exchange's open); closed when
    pub(crate) fn drop_line(&self, shard: usize, key: &PoolKey, line: &Arc<Line>) {
        {
            let mut map = self.shards[shard].lock().expect("pool");
            if let Some(slot) = map.get_mut(key) {
                // A line is held once per key: the dial that made it.
                if let Some(i) = slot.lines.iter().position(|e| Arc::ptr_eq(&e.line, line)) {
                    slot.lines.swap_remove(i);
                }
                // A claimed dial in flight keeps the slot (rule 6).
                if slot.vacant() {
                    map.remove(key);
                }
            }
        }
        if line.users() == 0 {
            line.close();
        }
    }

    /// Every idle line the pools keep, with its shard and key (tests only).
    #[cfg(test)]
    pub(crate) fn idle_lines(&self) -> Vec<(usize, PoolKey, Arc<Line>)> {
        let mut idle = Vec::new();
        for (shard, map) in self.shards.iter().enumerate() {
            for (key, slot) in &*map.lock().expect("pool") {
                for entry in slot.lines.iter().filter(|e| e.idle.is_some()) {
                    idle.push((shard, key.clone(), Arc::clone(&entry.line)));
                }
            }
        }
        idle
    }

    /// Whether `key`'s slot on `shard` holds a claimed dial in flight, and whether the key is
    /// `solo` (tests only).
    #[cfg(test)]
    pub(crate) fn claimed(&self, shard: usize, key: &PoolKey) -> (bool, bool) {
        self.shards[shard]
            .lock()
            .expect("pool")
            .get(key)
            .map_or((false, false), |s| {
                (s.opening.as_ref().is_some_and(|o| !o.done()), s.solo)
            })
    }
}
