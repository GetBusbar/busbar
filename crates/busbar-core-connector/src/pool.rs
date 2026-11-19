// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PER-WORKER POOLS (`BUSBAR-1.6.0.md` THE DESIGN, connections: the connector owns "per-worker

use std::hash::{BuildHasher, Hash, Hasher};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use busbar_contract::conn::{InstanceId, NeedId};

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
/// keyed by it is pooled. It is held erased (`dyn Any`): the key compares and hashes the address
/// alone and never reads the value, so nothing in it that can change (a config's session store)
/// reaches the key's `Hash` or `Eq` (clippy `mutable_key_type`, ruling 3).
pub(crate) struct Same<T> {
    at: usize,
    _kept: Arc<dyn std::any::Any + Send + Sync>,
    _of: std::marker::PhantomData<fn() -> T>,
}

impl<T: Send + Sync + 'static> Same<T> {
    /// `value`, by identity, kept alive by the key.
    pub(crate) fn of(value: Arc<T>) -> Self {
        Self {
            at: Arc::as_ptr(&value).cast::<()>() as usize,
            _kept: value,
            _of: std::marker::PhantomData,
        }
    }
}

impl<T> std::fmt::Debug for Same<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Same").field(&self.at).finish()
    }
}

impl<T> Clone for Same<T> {
    fn clone(&self) -> Self {
        Self {
            at: self.at,
            _kept: Arc::clone(&self._kept),
            _of: std::marker::PhantomData,
        }
    }
}

impl<T> PartialEq for Same<T> {
    fn eq(&self, other: &Self) -> bool {
        self.at == other.at
    }
}

impl<T> Eq for Same<T> {}

impl<T> std::hash::Hash for Same<T> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.at.hash(state);
    }
}

/// The pools, one per shard.
pub(crate) struct Pools {
    pub(crate) posture: RwLock<PoolPosture>,
    /// How many shards ([`shard_count`], read once as the pools are made).
    pub(crate) shards: usize,
    /// The process's key hasher: [`Self::keyed`] hashes each key's fields with it once.
    pub(crate) keys: foldhash::fast::RandomState,
}

impl std::fmt::Debug for Pools {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pools")
            .field("posture", &self.posture())
            .field("shards", &self.shards)
            .finish_non_exhaustive()
    }
}

/// 1.5.5's shard count: the machine's parallelism, a power of two, at most 16.
pub(crate) fn shard_count() -> usize {
    std::thread::available_parallelism()
        .map_or(1, std::num::NonZero::get)
        .next_power_of_two()
        .min(16)
}

impl Pools {
    /// `key` sealed for the pools: its fields hashed once, here, into its `hash`.
    pub(crate) fn keyed(&self, mut key: PoolKey) -> PoolKey {
        key.hash = self.keys.hash_one(Fields(&key));
        key
    }

    /// The applied posture, copied before any connection or plugin is driven.
    pub(crate) fn posture(&self) -> PoolPosture {
        *self.posture.read().expect("pool posture")
    }
    /// The calling thread's shard: assigned on its first use and kept (1.5.5's `get`).
    pub(crate) fn shard(&self) -> usize {
        static NEXT_THREAD: AtomicUsize = AtomicUsize::new(0);
        thread_local! {
            static SHARD: std::cell::OnceCell<usize> = const { std::cell::OnceCell::new() };
        }
        let idx = SHARD.with(|s| *s.get_or_init(|| NEXT_THREAD.fetch_add(1, Ordering::Relaxed)));

        idx & (self.shards - 1)
    }
}
