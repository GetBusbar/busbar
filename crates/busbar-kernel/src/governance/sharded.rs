// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The budget shards and their "may be dirty" flags (WASTE-CORE-LIFECYCLE W6).
//!
//! A shard's map is private to this module, so every mutable access goes through
//! [`MapShard::write`], [`Sharded::write`] or [`Sharded::write_all`], and each of those sets the
//! shard's `maybe_dirty` flag after it holds the write lock. The budget flush swaps the flags into
//! a shard mask and walks only the flagged shards ([`Sharded::take_flags`],
//! [`Sharded::write_masked`]); walking never sets a flag. A periodic full walk is the backstop.

use foldhash::HashMap;
#[cfg(test)]
use std::sync::atomic::AtomicU64;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard};

use busbar_contract::kept::Text;
use std::time::{Duration, Instant};

use super::GOV_SHARDS;

const _: () = assert!(
    GOV_SHARDS <= 64 && GOV_SHARDS.is_power_of_two(),
    "the flush shard mask is one u64"
);

/// How often the budget flush walks every shard whatever its flag.
pub(super) const BUDGET_FLUSH_BACKSTOP: Duration =
    Duration::from_secs(crate::config::limits::DEFAULT_BUDGET_FLUSH_BACKSTOP_SECS);
const _: () = assert!(
    crate::config::limits::DEFAULT_BUDGET_FLUSH_BACKSTOP_SECS >= 10
        && crate::config::limits::DEFAULT_BUDGET_FLUSH_BACKSTOP_SECS <= 600,
    "the budget flush backstop stays within [10 s, 10 min]"
);

/// One shard: a map from a cell's key to the cell. The key type is the owner's: the budget cells
/// are keyed by shared text (a charge names its cell by sharing the key), the selected-resource
/// scopes by their own built key.
pub(super) struct MapShard<V, K = String> {
    map: RwLock<HashMap<K, V>>,
    maybe_dirty: AtomicBool,
    sweep_ticker: AtomicU32,
}

impl<V, K> Default for MapShard<V, K> {
    fn default() -> Self {
        Self {
            map: RwLock::new(HashMap::default()),
            maybe_dirty: AtomicBool::new(false),
            sweep_ticker: AtomicU32::new(0),
        }
    }
}

impl<V, K> MapShard<V, K> {
    /// A mutable view; marks the shard as possibly dirty once the lock is held.
    #[inline]
    pub(super) fn write(&self) -> RwLockWriteGuard<'_, HashMap<K, V>> {
        let guard = self.map.write().unwrap_or_else(|p| p.into_inner());
        self.maybe_dirty.store(true, Ordering::Release);
        guard
    }

    #[inline]
    pub(super) fn read(&self) -> RwLockReadGuard<'_, HashMap<K, V>> {
        self.map.read().unwrap_or_else(|p| p.into_inner())
    }

    #[inline]
    pub(super) fn sweep_ticker(&self) -> &AtomicU32 {
        &self.sweep_ticker
    }
}

/// Put `cell` under the bucket `name` (hydration, recovery and corrections; never a served
/// request). A bucket the map already holds keeps its key, the name its charges, flights and
/// captures share, and takes the new cell. A bucket new to the map is keyed here: its name is
/// made shared once, and the map keeps it for the cell's life.
pub(super) fn put<V>(map: &mut HashMap<Text, V>, name: &str, cell: V) {
    match map.get_mut(name) {
        Some(held) => *held = cell,
        None => {
            map.insert(Text::from(Arc::<str>::from(name)), cell);
        }
    }
}

pub(super) struct Sharded<V, K = String> {
    shards: Box<[MapShard<V, K>; GOV_SHARDS]>,
    /// When the flush last walked every shard (the backstop).
    last_full_walk: Mutex<Option<Instant>>,
    #[cfg(test)]
    pub(super) flush_shard_locks: AtomicU64,
    #[cfg(test)]
    pub(super) flush_cells_visited: AtomicU64,
}

impl<V, K> Sharded<V, K> {
    pub(super) fn new() -> Self {
        Self {
            shards: Box::new(std::array::from_fn(|_| MapShard::default())),
            last_full_walk: Mutex::new(None),
            #[cfg(test)]
            flush_shard_locks: AtomicU64::new(0),
            #[cfg(test)]
            flush_cells_visited: AtomicU64::new(0),
        }
    }

    #[inline]
    fn shard_for(&self, key_id: &str) -> &MapShard<V, K> {
        &self.shards[self.shard_index(key_id)]
    }

    #[inline]
    pub(super) fn shard_index(&self, key_id: &str) -> usize {
        (busbar_kernel::store::key_hash_u64(key_id) as usize) & (GOV_SHARDS - 1)
    }

    #[inline]
    pub(super) fn shard_at(&self, idx: usize) -> &MapShard<V, K> {
        &self.shards[idx]
    }

    #[inline]
    pub(super) fn write(&self, key_id: &str) -> RwLockWriteGuard<'_, HashMap<K, V>> {
        self.shard_for(key_id).write()
    }

    #[inline]
    pub(super) fn read(&self, key_id: &str) -> RwLockReadGuard<'_, HashMap<K, V>> {
        self.shard_for(key_id).read()
    }

    /// Every shard, mutably; marks every shard as possibly dirty.
    pub(super) fn write_all(&self) -> impl Iterator<Item = RwLockWriteGuard<'_, HashMap<K, V>>> {
        self.shards.iter().map(MapShard::write)
    }

    /// Swap every shard's flag to clean and answer the shards that were flagged, as a mask.
    pub(super) fn take_flags(&self) -> u64 {
        crate::off_path::governance::state::sharded_take_flags(
            self.shards.iter().map(|shard| &shard.maybe_dirty),
        )
    }

    /// The masked shards, mutably, for the flush walk. Never sets a flag: the flush puts a flag
    /// back with [`Self::reflag`] only for a shard it leaves dirty.
    pub(super) fn write_masked(
        &self,
        mask: u64,
    ) -> impl Iterator<Item = (usize, RwLockWriteGuard<'_, HashMap<K, V>>)> {
        // Visit only the set bits, lowest first: the walk costs the masked shards, not all of them.
        let mut rest = mask & (u64::MAX >> (64 - GOV_SHARDS));
        std::iter::from_fn(move || {
            if rest == 0 {
                return None;
            }
            let index = rest.trailing_zeros() as usize;
            rest &= rest - 1;
            #[cfg(test)]
            self.flush_shard_locks.fetch_add(1, Ordering::Relaxed);
            let shard = &self.shards[index];
            Some((index, shard.map.write().unwrap_or_else(|p| p.into_inner())))
        })
    }

    /// Mark a shard the flush left dirty, so the next tick walks it again.
    #[inline]
    pub(super) fn reflag(&self, index: usize) {
        self.shards[index]
            .maybe_dirty
            .store(true, Ordering::Release);
    }

    /// Whether the full-walk backstop is due; arms the next one when it is.
    pub(super) fn backstop_due(&self, now: Instant) -> bool {
        let mut last = self
            .last_full_walk
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        match *last {
            Some(at) if now.saturating_duration_since(at) < BUDGET_FLUSH_BACKSTOP => false,
            Some(_) => {
                *last = Some(now);
                true
            }
            None => {
                // The first flush arms the clock; flags already cover everything written so far.
                *last = Some(now);
                false
            }
        }
    }

    #[cfg(test)]
    pub(super) fn flagged(&self, key_id: &str) -> bool {
        self.shard_for(key_id).maybe_dirty.load(Ordering::Acquire)
    }

    #[cfg(test)]
    pub(super) fn flagged_at(&self, index: usize) -> bool {
        self.shards[index].maybe_dirty.load(Ordering::Acquire)
    }

    #[cfg(test)]
    pub(super) fn sweep_ticker_for(&self, key_id: &str) -> &AtomicU32 {
        &self.shard_for(key_id).sweep_ticker
    }

    #[cfg(test)]
    pub(super) fn shard_lock_for(&self, key_id: &str) -> &RwLock<HashMap<K, V>> {
        &self.shard_for(key_id).map
    }
}
