// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The budget shards and their "may be dirty" flags (WASTE-CORE-LIFECYCLE W6).
//!
//! A shard's map is private to this module, so every mutable access goes through
//! [`MapShard::write`], [`Sharded::write`] or [`Sharded::write_all`], and each of those sets the
//! shard's `maybe_dirty` flag after it holds the write lock. The budget flush swaps the flags into
//! a shard mask and walks only the flagged shards ([`Sharded::take_flags`],
//! [`Sharded::write_masked`]); walking never sets a flag. A periodic full walk is the backstop.

use std::collections::HashMap;
#[cfg(test)]
use std::sync::atomic::AtomicU64;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard};
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

pub(super) struct MapShard<V> {
    map: RwLock<HashMap<String, V>>,
    maybe_dirty: AtomicBool,
    sweep_ticker: AtomicU32,
}

impl<V> Default for MapShard<V> {
    fn default() -> Self {
        Self {
            map: RwLock::new(HashMap::new()),
            maybe_dirty: AtomicBool::new(false),
            sweep_ticker: AtomicU32::new(0),
        }
    }
}

impl<V> MapShard<V> {
    /// A mutable view; marks the shard as possibly dirty once the lock is held.
    #[inline]
    pub(super) fn write(&self) -> RwLockWriteGuard<'_, HashMap<String, V>> {
        let guard = self.map.write().unwrap_or_else(|p| p.into_inner());
        self.maybe_dirty.store(true, Ordering::Release);
        guard
    }

    #[inline]
    pub(super) fn read(&self) -> RwLockReadGuard<'_, HashMap<String, V>> {
        self.map.read().unwrap_or_else(|p| p.into_inner())
    }

    #[inline]
    pub(super) fn sweep_ticker(&self) -> &AtomicU32 {
        &self.sweep_ticker
    }
}

pub(super) struct Sharded<V> {
    shards: Box<[MapShard<V>]>,
    /// When the flush last walked every shard (the backstop).
    last_full_walk: Mutex<Option<Instant>>,
    #[cfg(test)]
    pub(super) flush_shard_locks: AtomicU64,
    #[cfg(test)]
    pub(super) flush_cells_visited: AtomicU64,
}

impl<V> Sharded<V> {
    pub(super) fn new() -> Self {
        let mut shards = Vec::with_capacity(GOV_SHARDS);
        shards.resize_with(GOV_SHARDS, MapShard::default);
        Self {
            shards: shards.into_boxed_slice(),
            last_full_walk: Mutex::new(None),
            #[cfg(test)]
            flush_shard_locks: AtomicU64::new(0),
            #[cfg(test)]
            flush_cells_visited: AtomicU64::new(0),
        }
    }

    #[inline]
    fn shard_for(&self, key_id: &str) -> &MapShard<V> {
        &self.shards[self.shard_index(key_id)]
    }

    #[inline]
    pub(super) fn shard_index(&self, key_id: &str) -> usize {
        (busbar_kernel::store::fnv1a_u64(key_id) as usize) & (GOV_SHARDS - 1)
    }

    #[inline]
    pub(super) fn shard_at(&self, idx: usize) -> &MapShard<V> {
        &self.shards[idx]
    }

    #[inline]
    pub(super) fn write(&self, key_id: &str) -> RwLockWriteGuard<'_, HashMap<String, V>> {
        self.shard_for(key_id).write()
    }

    #[inline]
    pub(super) fn read(&self, key_id: &str) -> RwLockReadGuard<'_, HashMap<String, V>> {
        self.shard_for(key_id).read()
    }

    /// Every shard, mutably; marks every shard as possibly dirty.
    pub(super) fn write_all(
        &self,
    ) -> impl Iterator<Item = RwLockWriteGuard<'_, HashMap<String, V>>> {
        self.shards.iter().map(MapShard::write)
    }

    /// Swap every shard's flag to clean and answer the shards that were flagged, as a mask.
    pub(super) fn take_flags(&self) -> u64 {
        self.shards
            .iter()
            .enumerate()
            .fold(0u64, |mask, (index, shard)| {
                if shard.maybe_dirty.swap(false, Ordering::AcqRel) {
                    mask | (1u64 << index)
                } else {
                    mask
                }
            })
    }

    /// The masked shards, mutably, for the flush walk. Never sets a flag: the flush puts a flag
    /// back with [`Self::reflag`] only for a shard it leaves dirty.
    pub(super) fn write_masked(
        &self,
        mask: u64,
    ) -> impl Iterator<Item = (usize, RwLockWriteGuard<'_, HashMap<String, V>>)> {
        self.shards
            .iter()
            .enumerate()
            .filter(move |(index, _)| mask & (1u64 << index) != 0)
            .map(|(index, shard)| {
                #[cfg(test)]
                self.flush_shard_locks.fetch_add(1, Ordering::Relaxed);
                (index, shard.map.write().unwrap_or_else(|p| p.into_inner()))
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
    pub(super) fn shard_lock_for(&self, key_id: &str) -> &RwLock<HashMap<String, V>> {
        &self.shard_for(key_id).map
    }
}
