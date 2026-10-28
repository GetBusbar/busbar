// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! PUBLISHED GENERATION DATA, OWNED BY THE SDK (THE DESIGN, the plugin ABI: memory a plugin returns is
//! plugin-owned and valid until that plugin's next refresh generation; a plugin crate stays
//! `#![forbid(unsafe_code)]`). A plugin that publishes a value the host reads across calls — a
//! plane's generation snapshot and the claims and routes it points at — hands the SDK an OWNED
//! description of it (a [`Publish::Spec`]: `String`s and `Vec`s). The SDK copies every list and
//! string into a [`Backing`] it owns, lowers the description into the ABI value over that backing,
//! and keeps both until `retire` of that generation ([`Generations::retire`]) or the instance
//! closes. The storage is a backing, never an "arena": that name is dead everywhere (#41).
//!
//! ```compile_fail,E0432
//! use busbar_contract::abi::sdk::publish::Arena;
//! ```
//!
//! So no safe code can hand the host a pointer into memory it later frees: the plugin never builds
//! the pointer-bearing ABI value itself (only the SDK implements [`Publish`]), and whatever the
//! plugin does with its description after publishing, the host reads the SDK's copy.
//!
//! ```
//! use busbar_contract::abi::plane::PlaneSnapshot;
//! use busbar_contract::abi::sdk::publish::{ClaimSpec, Generations, SnapshotSpec};
//! let gens: Generations<PlaneSnapshot> = Generations::new();
//! let mut target = String::from("/echo");
//! let spec = SnapshotSpec {
//!     claims: vec![ClaimSpec::new("POST", &target, "door", 0)],
//!     ..SnapshotSpec::default()
//! };
//! let _snapshot = gens.publish(1, &spec);
//! drop(spec);
//! target.clear(); // the host still reads "/echo": the SDK holds its own copy
//! assert_eq!(gens.live(), 1);
//! gens.retire(1);
//! assert_eq!(gens.live(), 0);
//! ```
//!
//! A plugin cannot publish an ABI value it built itself, pointers and all:
//!
//! ```compile_fail,E0308
//! use busbar_contract::abi::plane::PlaneSnapshot;
//! use busbar_contract::abi::sdk::publish::Generations;
//! let gens: Generations<PlaneSnapshot> = Generations::new();
//! let raw: PlaneSnapshot = unimplemented!();
//! let _ = gens.publish(1, &raw); // expects a `SnapshotSpec`
//! ```

use std::any::Any;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use crate::abi::mechanism::call::{AbiStr, Blob, BLOB_ABSENT, BLOB_JSON};
use crate::abi::plane::{AdminRoute, Claim, PlaneSnapshot, CLAIM_EXACT, CLAIM_OPEN, CLAIM_PATTERN};
use crate::abi::sdk::door::abi_str;
use crate::ids::OpClassId;

/// The storage one published generation points into. Only the SDK makes one and writes into it;
/// its contents never move (every piece is its own heap allocation) and are freed only when the
/// generation is retired.
pub struct Backing {
    bytes: Vec<Box<[u8]>>,
    lists: Vec<Box<dyn Any + Send + Sync>>,
}

impl std::fmt::Debug for Backing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Backing")
            .field("bytes", &self.bytes.len())
            .field("lists", &self.lists.len())
            .finish()
    }
}

/// A list the backing holds: plain ABI values whose pointers point into the same backing.
struct List<T> {
    _items: Box<[T]>,
}

// SAFETY: `T` is one of the SDK's sealed `Publish` types or an `AbiStr`: integers and raw
// pointers into the backing that owns this list, which nothing reads through on a safe path and
// nothing mutates.
unsafe impl<T> Send for List<T> {}
// SAFETY: as `Send`.
unsafe impl<T> Sync for List<T> {}

impl Backing {
    const fn new() -> Self {
        Self {
            bytes: Vec::new(),
            lists: Vec::new(),
        }
    }

    /// `bytes`, copied into the backing; the pointer to the copy (NULL when empty).
    fn copy(&mut self, bytes: &[u8]) -> *const u8 {
        if bytes.is_empty() {
            return std::ptr::null();
        }
        let held: Box<[u8]> = bytes.into();
        let p = held.as_ptr();
        self.bytes.push(held);
        p
    }

    /// `s`, copied, as a present string (an empty string is present, zero-length).
    fn str(&mut self, s: &str) -> AbiStr {
        let ptr = if s.is_empty() {
            // Present but empty: a non-NULL, never-read address.
            std::ptr::NonNull::<u8>::dangling().as_ptr().cast_const()
        } else {
            self.copy(s.as_bytes())
        };
        AbiStr { ptr, len: s.len() }
    }

    /// `s` copied, or absent (NULL) for `None`.
    fn opt_str(&mut self, s: Option<&str>) -> AbiStr {
        s.map_or(AbiStr::ZERO, |s| self.str(s))
    }

    /// `b` copied as a JSON blob, or absent for `None`.
    fn json(&mut self, b: Option<&[u8]>) -> Blob {
        match b {
            Some(b) => Blob {
                ptr: self.copy(b),
                len: b.len(),
                fmt: BLOB_JSON,
                ..Blob::ZERO
            },
            None => Blob {
                fmt: BLOB_ABSENT,
                ..Blob::ZERO
            },
        }
    }

    /// Each of `names` copied, held as one list of strings; its pointer (NULL when empty) and
    /// length.
    fn strs(&mut self, names: &[String]) -> (*const AbiStr, usize) {
        if names.is_empty() {
            return (std::ptr::null(), 0);
        }
        let items: Box<[AbiStr]> = names.iter().map(|n| self.str(n)).collect();
        let p = items.as_ptr();
        self.lists.push(Box::new(List { _items: items }));
        (p, names.len())
    }

    /// Each of `specs` lowered and held as one list; its pointer (NULL when empty) and length.
    fn list<T: Publish>(&mut self, specs: &[T::Spec]) -> (*const T, usize) {
        if specs.is_empty() {
            return (std::ptr::null(), 0);
        }
        let items: Box<[T]> = specs.iter().map(|s| T::lower(s, 0, self)).collect();
        let p = items.as_ptr();
        self.lists.push(Box::new(List { _items: items }));
        (p, specs.len())
    }
}

mod sealed {
    pub trait Sealed {}
    impl Sealed for crate::abi::plane::PlaneSnapshot {}
    impl Sealed for crate::abi::plane::Claim {}
    impl Sealed for crate::abi::plane::AdminRoute {}
}

/// An ABI value a plugin publishes, and the owned description it publishes it from. Only the SDK
/// implements it: lowering is where pointers are made, and they are made into the SDK's backing only.
pub trait Publish: sealed::Sealed + Copy + 'static {
    /// The owned description a plugin hands the SDK.
    type Spec;
    /// Lower `spec` for `generation`, every list and string copied into `backing`.
    #[doc(hidden)]
    fn lower(spec: &Self::Spec, generation: u64, backing: &mut Backing) -> Self;
}

/// One claim, owned: see [`Claim`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClaimSpec {
    /// The verb.
    pub verb: String,
    /// The target path.
    pub target: String,
    /// The transport claim it arrives over.
    pub carrier: String,
    /// `CLAIM_OPEN` | `CLAIM_EXACT`.
    pub flags: u32,
    /// The dialect a refusal on this route wears before `arrive` has read the arrival (see
    /// [`Claim::refusal_dialect`]); `0` for a plane with no dialects.
    pub refusal_dialect: u16,
    /// The span an arrival on it opens ([`PlaneSnapshot::arrival_spans`]); empty = none.
    pub arrival_span: String,
}

impl ClaimSpec {
    /// A claim of `verb` on `target` over `carrier`.
    #[must_use]
    pub fn new(verb: &str, target: &str, carrier: &str, flags: u32) -> Self {
        Self {
            verb: verb.to_string(),
            target: target.to_string(),
            carrier: carrier.to_string(),
            flags,
            refusal_dialect: 0,
            arrival_span: String::new(),
        }
    }

    /// The claim, its arrivals opening the span `name` ([`PlaneSnapshot::arrival_spans`]).
    #[must_use]
    pub fn with_arrival_span(mut self, name: &str) -> Self {
        self.arrival_span = name.to_string();
        self
    }
}

impl Publish for Claim {
    type Spec = ClaimSpec;
    fn lower(spec: &ClaimSpec, _: u64, backing: &mut Backing) -> Self {
        Self {
            verb: backing.str(&spec.verb),
            target: backing.str(&spec.target),
            carrier: backing.str(&spec.carrier),
            flags: spec.flags,
            refusal_dialect: spec.refusal_dialect,
            _pad: 0,
        }
    }
}

/// One admin route, owned: see [`AdminRoute`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AdminRouteSpec {
    /// The verb.
    pub verb: String,
    /// The target path.
    pub target: String,
    /// `ROUTE_PUBLIC` or `0`.
    pub flags: u32,
    /// The word the kernel audits it under; empty = never audited.
    pub audit_verb: String,
}

impl AdminRouteSpec {
    /// A route of `verb` on `target`, never audited.
    #[must_use]
    pub fn new(verb: &str, target: &str, flags: u32) -> Self {
        Self {
            verb: verb.to_string(),
            target: target.to_string(),
            flags,
            audit_verb: String::new(),
        }
    }

    /// The route, audited under `word`.
    #[must_use]
    pub fn audited(mut self, word: &str) -> Self {
        self.audit_verb = word.to_string();
        self
    }
}

impl Publish for AdminRoute {
    type Spec = AdminRouteSpec;
    fn lower(spec: &AdminRouteSpec, _: u64, backing: &mut Backing) -> Self {
        Self {
            verb: backing.str(&spec.verb),
            target: backing.str(&spec.target),
            flags: spec.flags,
            _reserved: 0,
            audit_verb: backing.str(&spec.audit_verb),
        }
    }
}

/// A generation snapshot, owned: see [`PlaneSnapshot`]. Its generation is the one it is published
/// under.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SnapshotSpec {
    /// The paths it answers on.
    pub claims: Vec<ClaimSpec>,
    /// Its admin routes.
    pub admin_routes: Vec<AdminRouteSpec>,
    /// Its OpenAPI contribution (JSON); `None` = none.
    pub openapi: Option<Vec<u8>>,
    /// The audience it binds; `None` = no receiving side.
    pub audience: Option<String>,
    /// Its resource metadata; `None` = none.
    pub resource_metadata: Option<String>,
    /// Its protected-resource facts (JSON, [`PlaneSnapshot::resource_facts`]); `None` = none.
    pub resource_facts: Option<Vec<u8>>,
    /// The names it lists ([`PlaneSnapshot::listed`]), each non-empty; empty = none.
    pub listed: Vec<String>,
}

impl Publish for PlaneSnapshot {
    type Spec = SnapshotSpec;
    fn lower(spec: &SnapshotSpec, generation: u64, backing: &mut Backing) -> Self {
        let (claims, claims_len) = backing.list::<Claim>(&spec.claims);
        let (admin_routes, admin_routes_len) = backing.list::<AdminRoute>(&spec.admin_routes);
        let (listed, listed_len) = backing.strs(&spec.listed);
        // One per claim where any claim names one; none at all otherwise.
        let spans: Vec<String> = if spec.claims.iter().any(|c| !c.arrival_span.is_empty()) {
            spec.claims.iter().map(|c| c.arrival_span.clone()).collect()
        } else {
            Vec::new()
        };
        let (arrival_spans, arrival_spans_len) = backing.strs(&spans);
        Self {
            size: std::mem::size_of::<Self>() as u32,
            _reserved: 0,
            generation,
            claims,
            claims_len,
            admin_routes,
            admin_routes_len,
            openapi: backing.json(spec.openapi.as_deref()),
            audience: backing.opt_str(spec.audience.as_deref()),
            resource_metadata: backing.opt_str(spec.resource_metadata.as_deref()),
            resource_facts: backing.json(spec.resource_facts.as_deref()),
            listed,
            listed_len,
            arrival_spans,
            arrival_spans_len,
        }
    }
}

/// One published generation: the value (boxed: its address is what the host holds), the backing
/// it points into, and the plugin's own payload for that generation.
struct Generation<T, P> {
    generation: u64,
    _value: Box<T>,
    _backing: Backing,
    payload: Arc<P>,
}

// SAFETY: `T: Publish` is plain data whose pointers point into `_backing`, owned by the same value;
// nothing reads through them on a safe path, and nothing mutates either after publishing. The
// payload is the plugin's own `Send + Sync` value behind an `Arc`.
unsafe impl<T, P: Send + Sync> Send for Generation<T, P> {}
// SAFETY: as `Send`.
unsafe impl<T, P: Send + Sync> Sync for Generation<T, P> {}

/// THE PUBLISHED GENERATIONS of one instance: instance state (`Send + Sync`), holding each
/// published value and its storage, and the plugin's payload `P` for that generation (what it
/// built from that generation's settings), until `retire` of its generation, or until it drops
/// (`close`).
///
/// [`Generations::current`] is the NEWEST live generation's payload: what a request arriving now
/// is answered from. A plugin keeps the `Arc` it took for as long as that request lives, so a
/// request keeps reading the generation it arrived under while a refresh publishes the next one.
pub struct Generations<T: Publish, P = ()> {
    live: Mutex<Vec<Generation<T, P>>>,
    /// Alive while these generations are: an answer that published from them is FAULT when they
    /// are gone by the time the body returns (`abi::sdk::out::Holders`).
    pub(crate) alive: crate::abi::sdk::out::Alive,
}

impl<T: Publish, P> std::fmt::Debug for Generations<T, P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Generations")
            .field("live", &self.live())
            .finish()
    }
}

impl<T: Publish, P> Default for Generations<T, P> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Publish> Generations<T, ()> {
    /// Publish `spec` as `generation`, with no payload: the SDK's copy, lowered; the address the
    /// host reads, valid until [`Generations::retire`] of `generation` or until this drops.
    pub fn publish(&self, generation: u64, spec: &T::Spec) -> *const T {
        self.publish_with(generation, spec, ())
    }
}

impl<T: Publish, P> Generations<T, P> {
    /// None published.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            live: Mutex::new(Vec::new()),
            alive: crate::abi::sdk::out::Alive::new(),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<Generation<T, P>>> {
        self.live
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Publish `spec` as `generation` with the plugin's `payload` for it: the SDK's copy, lowered;
    /// the address the host reads. Both are held until [`Generations::retire`] of `generation` or
    /// until this drops.
    pub fn publish_with(&self, generation: u64, spec: &T::Spec, payload: P) -> *const T {
        let mut backing = Backing::new();
        let value = Box::new(T::lower(spec, generation, &mut backing));
        let p = std::ptr::from_ref::<T>(&*value);
        self.lock().push(Generation {
            generation,
            _value: value,
            _backing: backing,
            payload: Arc::new(payload),
        });
        p
    }

    /// The newest live generation's payload; `None` when none is live.
    #[must_use]
    pub fn current(&self) -> Option<Arc<P>> {
        self.lock()
            .iter()
            .max_by_key(|g| g.generation)
            .map(|g| Arc::clone(&g.payload))
    }

    /// The payload of `generation`, while it is live.
    #[must_use]
    pub fn at(&self, generation: u64) -> Option<Arc<P>> {
        self.lock()
            .iter()
            .rev()
            .find(|g| g.generation == generation)
            .map(|g| Arc::clone(&g.payload))
    }

    /// Drop every value published as `generation`, its storage, and the SDK's hold on its
    /// payload (a request still holding the `Arc` keeps its own).
    pub fn retire(&self, generation: u64) {
        let gone: Vec<Generation<T, P>> = {
            let mut live = self.lock();
            let (gone, keep) = std::mem::take(&mut *live)
                .into_iter()
                .partition(|g| g.generation == generation);
            *live = keep;
            gone
        };
        drop(gone);
    }

    /// How many published values are held.
    #[must_use]
    pub fn live(&self) -> usize {
        self.lock().len()
    }
}

/// PER-INSTANCE KEYED STATE: a map the SDK locks for the plugin, so a `forbid(unsafe_code)` plugin
/// that holds no lock of its own can keep per-session and per-request state (what a session set,
/// what a request was admitted under) across calls.
///
/// It lives INSIDE the instance state and nowhere else: a plugin holds no process-global state, so
/// what it keeps is per-instance and dropped with the instance (`close`). It is not `const`
/// constructible, so it cannot be a `static`. The plugin bounds it: [`Keyed::len`] is what it
/// checks before an insert that grows it, and [`Keyed::with_or_insert_within`] keeps a bound
/// exactly.
///
/// ONE MAP OR SHARDS. [`Keyed::new`] is one map under one lock. [`Keyed::sharded`] (a table of
/// units, one entry per request in flight) spreads its entries over [`KEYED_SHARDS`] maps by their
/// key's hash, each with its own lock, so the per-request and per-piece ops ([`Keyed::with`],
/// [`Keyed::insert`], [`Keyed::remove`], [`Keyed::get`], [`Keyed::contains_key`],
/// [`Keyed::with_or_insert_within`]) take one shard's lock and two units never wait on each other.
/// [`Keyed::len`] is a count, read without a lock. [`Keyed::with_all`] holds every shard and hands
/// `f` the whole map, gathered and spread back: on a sharded map it is for a scan or a sweep, never
/// a per-piece path.
pub struct Keyed<K, V> {
    shards: Box<[Mutex<BTreeMap<K, V>>]>,
    shard_of: fn(&K) -> usize,
    len: std::sync::atomic::AtomicUsize,
}

/// How many shards a [`Keyed::sharded`] map spreads its entries over.
pub const KEYED_SHARDS: usize = 16;

impl<K, V> std::fmt::Debug for Keyed<K, V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Keyed")
            .field("len", &self.len())
            .field("shards", &self.shards.len())
            .finish()
    }
}

impl<K: Ord, V> Default for Keyed<K, V> {
    fn default() -> Self {
        Self::new()
    }
}

/// A shard's map, its poison recovered: an op that panicked left it as far as it got.
fn keyed_lock<K, V>(shard: &Mutex<BTreeMap<K, V>>) -> std::sync::MutexGuard<'_, BTreeMap<K, V>> {
    shard
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The shard a key of a [`Keyed::sharded`] map lives in: its hash's remainder.
fn keyed_shard<K: std::hash::Hash>(key: &K) -> usize {
    use std::hash::Hasher;
    let mut h = std::collections::hash_map::DefaultHasher::new();
    key.hash(&mut h);
    // The remainder is below `KEYED_SHARDS`, so it fits a `usize`.
    (h.finish() % KEYED_SHARDS as u64) as usize
}

impl<K, V> Keyed<K, V> {
    /// How many entries are held.
    #[must_use]
    pub fn len(&self) -> usize {
        // One map is read under its lock, as it always was; shards by their count.
        if let [one] = &*self.shards {
            return keyed_lock(one).len();
        }
        self.len.load(std::sync::atomic::Ordering::Acquire)
    }

    /// Whether none is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Count what one shard's op changed: `before` entries, now `after`.
    fn recount(&self, before: usize, after: usize) {
        use std::sync::atomic::Ordering::AcqRel;
        if after > before {
            self.len.fetch_add(after - before, AcqRel);
        } else if before > after {
            self.len.fetch_sub(before - after, AcqRel);
        }
    }

    /// `key`'s shard, locked.
    fn shard(&self, key: &K) -> std::sync::MutexGuard<'_, BTreeMap<K, V>> {
        keyed_lock(&self.shards[(self.shard_of)(key)])
    }
}

/// The whole of a sharded map, as [`Keyed::with_all`] hands it out, every shard held; on drop (a
/// panic in `f` included) each entry goes back to its shard.
struct AllShards<'a, K: Ord, V> {
    keyed: &'a Keyed<K, V>,
    held: Vec<std::sync::MutexGuard<'a, BTreeMap<K, V>>>,
    all: BTreeMap<K, V>,
}

impl<K: Ord, V> Drop for AllShards<'_, K, V> {
    fn drop(&mut self) {
        let all = std::mem::take(&mut self.all);
        // Every shard is held, so no other op moves the count meanwhile.
        self.keyed
            .len
            .store(all.len(), std::sync::atomic::Ordering::Release);
        for (k, v) in all {
            let at = (self.keyed.shard_of)(&k);
            self.held[at].insert(k, v);
        }
    }
}

impl<K: Ord, V> Keyed<K, V> {
    /// None held, in one map under one lock.
    #[must_use]
    pub fn new() -> Self {
        Self {
            shards: Box::new([Mutex::new(BTreeMap::new())]),
            shard_of: |_| 0,
            len: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// None held, spread over [`KEYED_SHARDS`] maps by key: a table of units, reached per piece.
    #[must_use]
    pub fn sharded() -> Self
    where
        K: std::hash::Hash,
    {
        Self {
            shards: (0..KEYED_SHARDS)
                .map(|_| Mutex::new(BTreeMap::new()))
                .collect(),
            shard_of: keyed_shard::<K>,
            len: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// Hold `value` under `key`, answering what it replaced.
    pub fn insert(&self, key: K, value: V) -> Option<V> {
        let mut map = self.shard(&key);
        let before = map.len();
        let replaced = map.insert(key, value);
        self.recount(before, map.len());
        replaced
    }

    /// Drop what `key` holds, answering it.
    pub fn remove(&self, key: &K) -> Option<V> {
        // Counted under the shard's lock, so a `with_all` that holds every shard sees the count
        // and the maps agree.
        let mut map = self.shard(key);
        let gone = map.remove(key);
        if gone.is_some() {
            self.recount(1, 0);
        }
        gone
    }

    /// Whether `key` holds an entry.
    #[must_use]
    pub fn contains_key(&self, key: &K) -> bool {
        self.shard(key).contains_key(key)
    }

    /// Run `f` over the entry `key` names, or `None`, under its shard's lock. `f` must not reach
    /// this same `Keyed` again.
    pub fn with<R>(&self, key: &K, f: impl FnOnce(Option<&mut V>) -> R) -> R {
        f(self.shard(key).get_mut(key))
    }

    /// Run `f` over the entry `key` names, made with `make` when it has none and fewer than
    /// `bound` are held; `None` when it has none and `bound` are held already (none is dropped to
    /// make room). The bound is kept exactly, arrivals at once included. `f` must not reach this
    /// same `Keyed` again.
    pub fn with_or_insert_within<R>(
        &self,
        key: K,
        bound: usize,
        make: impl FnOnce() -> V,
        f: impl FnOnce(&mut V) -> R,
    ) -> Option<R> {
        use std::sync::atomic::Ordering::{AcqRel, Acquire};
        let mut map = self.shard(&key);
        if let Some(v) = map.get_mut(&key) {
            return Some(f(v));
        }
        // Room is taken in the count before the entry goes in, so two arrivals at once in two
        // shards never both take the last place.
        self.len
            .fetch_update(AcqRel, Acquire, |n| (n < bound).then_some(n + 1))
            .ok()?;
        Some(f(map.entry(key).or_insert_with(make)))
    }

    /// Keep only the entries `keep` answers `true` for, one shard at a time.
    pub fn retain(&self, mut keep: impl FnMut(&K, &mut V) -> bool) {
        for shard in &*self.shards {
            let mut map = keyed_lock(shard);
            let before = map.len();
            map.retain(|k, v| keep(k, v));
            self.recount(before, map.len());
        }
    }

    /// Run `f` over the whole map, under every lock. `f` must not reach this same `Keyed` again.
    /// A sharded map is gathered for `f` and spread back after it: a scan or a sweep, never a
    /// per-piece path ([`Keyed::with`] is that).
    pub fn with_all<R>(&self, f: impl FnOnce(&mut BTreeMap<K, V>) -> R) -> R {
        if let [one] = &*self.shards {
            let mut map = keyed_lock(one);
            let before = map.len();
            let r = f(&mut map);
            self.recount(before, map.len());
            return r;
        }
        let mut whole = AllShards {
            keyed: self,
            held: self.shards.iter().map(keyed_lock).collect(),
            all: BTreeMap::new(),
        };
        for map in &mut whole.held {
            whole.all.append(map);
        }
        f(&mut whole.all)
    }

    /// A copy of what `key` holds.
    #[must_use]
    pub fn get(&self, key: &K) -> Option<V>
    where
        V: Clone,
    {
        self.shard(key).get(key).cloned()
    }
}

/// ONE ROW OF A PLANE'S ROUTE TABLE: the verb, the target, the transport claim it arrives over, and
/// whether the route admits a caller with no inbound credential at all. A plane states its routes
/// as a `const` table of these; the claim each row publishes is [`ServedRoute::claim_spec`], so
/// every plane spells a route's claim flags one way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServedRoute {
    /// The verb.
    pub verb: &'static str,
    /// The target path; a `{name}` segment is a path variable.
    pub target: &'static str,
    /// The transport claim it arrives over.
    pub carrier: &'static str,
    /// No inbound credential: a discovery document, or a callback that carries its own token.
    pub open: bool,
}

impl ServedRoute {
    /// The claim flags the route states: a target with a path variable is a pattern
    /// ([`CLAIM_PATTERN`], one level per variable), any other target matches exactly
    /// ([`CLAIM_EXACT`]); an open route adds [`CLAIM_OPEN`].
    #[must_use]
    pub fn claim_flags(&self) -> u32 {
        let mut flags = if self.target.contains('{') {
            CLAIM_PATTERN
        } else {
            CLAIM_EXACT
        };
        if self.open {
            flags |= CLAIM_OPEN;
        }
        flags
    }

    /// The route as a snapshot claim, its refusal dialect `0`.
    #[must_use]
    pub fn claim_spec(&self) -> ClaimSpec {
        ClaimSpec::new(self.verb, self.target, self.carrier, self.claim_flags())
    }
}

/// One admin route in the ABI's spelling, over `'static` strings: `route` is `(verb, target)`
/// relative to the kernel's admin mount, `flags` its route flags (`0`, or `ROUTE_PUBLIC` and what
/// rides beside it), `audit_verb` the word the kernel audits it under (empty = never audited). A
/// `const fn`, so a plane states its admin routes as a `const` table.
#[must_use]
pub const fn admin_route(
    route: (&'static str, &'static str),
    flags: u32,
    audit_verb: &'static str,
) -> AdminRoute {
    AdminRoute {
        verb: abi_str(route.0),
        target: abi_str(route.1),
        flags,
        _reserved: 0,
        audit_verb: abi_str(audit_verb),
    }
}

/// The index of `op` in a plane's operation-class list `classes`, in the order its Statement
/// tail's class table states them, which is the number `arrive` names a class by; `None` when the
/// list does not hold it.
#[must_use]
pub fn class_index(classes: &[OpClassId], op: OpClassId) -> Option<u32> {
    classes
        .iter()
        .position(|c| *c == op)
        .and_then(|i| u32::try_from(i).ok())
}

#[cfg(test)]
#[path = "tests/publish_tests.rs"]
mod tests;
