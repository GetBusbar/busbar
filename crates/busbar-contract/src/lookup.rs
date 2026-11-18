// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Lookups that never walk: the answer is kept where the data is written.
//!
//! Every question the request path asks of a collection ("which row has this key", "is this
//! position in the set", "how many", "take this one out") is answered by a structure that is kept
//! up to date at the one place the data is inserted or removed, so the request reads an answer and
//! visits no elements.
//!
//! - [`Bits`]: a set of small numbers (positions in a frozen list), with its size kept.
//! - [`Indexed`]: rows in first-insert order, found by key in one hash.
//! - [`ByGroup`]: rows found by one key and retired together by another.
//! - [`Slots`]: values taken out by the one who put them in, by the handle the insert returned.
//!
//! The only loops in this module are these: [`Bits`] visits its `W` words (a constant of the type);
//! [`ByGroup::take_group`] visits the rows of the one group being retired, each of which is its
//! output; [`Indexed::from_rows`] visits rows once to index them, and is for off-path use.

use std::borrow::Borrow;
use std::hash::Hash;

use foldhash::HashMap;

// ---------------------------------------------------------------- Bits

/// A set of small numbers `0 .. 64 * W`, with its size kept as it changes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bits<const W: usize> {
    words: [u64; W],
    ones: u32,
}

impl<const W: usize> Bits<W> {
    /// The largest number of members: `64 * W`.
    pub const CAPACITY: usize = 64 * W;

    /// The empty set.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            words: [0; W],
            ones: 0,
        }
    }

    /// The set `{0, .., n - 1}`; `None` when `n > CAPACITY`.
    #[must_use]
    pub fn all_below(n: usize) -> Option<Self> {
        if n > Self::CAPACITY {
            return None;
        }
        let mut set = Self::new();
        let full = n / 64;
        set.words[..full].fill(u64::MAX);
        let rest = n % 64;
        if rest != 0 {
            set.words[full] = (1u64 << rest) - 1;
        }
        set.ones = u32::try_from(n).ok()?;
        Some(set)
    }

    /// Add `id`. `false` when it was already in, or `id >= CAPACITY` (nothing changes).
    pub fn insert(&mut self, id: usize) -> bool {
        let Some(word) = self.words.get_mut(id / 64) else {
            return false;
        };
        let bit = 1u64 << (id % 64);
        if *word & bit != 0 {
            return false;
        }
        *word |= bit;
        self.ones += 1;
        true
    }

    /// Take `id` out. `false` when it was not in.
    pub fn remove(&mut self, id: usize) -> bool {
        let Some(word) = self.words.get_mut(id / 64) else {
            return false;
        };
        let bit = 1u64 << (id % 64);
        if *word & bit == 0 {
            return false;
        }
        *word &= !bit;
        self.ones -= 1;
        true
    }

    /// Whether `id` is in. `false` for `id >= CAPACITY`.
    #[must_use]
    pub fn contains(&self, id: usize) -> bool {
        self.words
            .get(id / 64)
            .is_some_and(|word| word & (1u64 << (id % 64)) != 0)
    }

    /// How many are in. A stored count, not a recount.
    #[must_use]
    pub const fn len(&self) -> u32 {
        self.ones
    }

    /// Whether none are in.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.ones == 0
    }

    /// Keep only the numbers that are also in `other` (bitwise AND, `W` word operations).
    pub fn keep_only(&mut self, other: &Self) {
        let mut ones = 0;
        for (word, theirs) in self.words.iter_mut().zip(other.words) {
            *word &= theirs;
            ones += word.count_ones();
        }
        self.ones = ones;
    }

    /// Take out every number that is in `other` (AND NOT).
    pub fn drop_all(&mut self, other: &Self) {
        let mut ones = 0;
        for (word, theirs) in self.words.iter_mut().zip(other.words) {
            *word &= !theirs;
            ones += word.count_ones();
        }
        self.ones = ones;
    }

    /// The smallest number that is in and is `>= from`, by `trailing_zeros` on the words.
    #[must_use]
    pub fn next_from(&self, from: usize) -> Option<usize> {
        let mut at = from / 64;
        let mut word = *self.words.get(at)? & (u64::MAX << (from % 64));
        loop {
            if word != 0 {
                return Some(at * 64 + word.trailing_zeros() as usize);
            }
            at += 1;
            word = *self.words.get(at)?;
        }
    }
}

impl<const W: usize> Default for Bits<W> {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------- Indexed

/// Rows in the order they were first inserted, found by key in one hash.
/// For a list whose order is part of its meaning (an encoder writes it in that order).
/// Rows are never removed: a row that stops mattering is set to its empty value.
#[derive(Clone, Debug)]
pub struct Indexed<K, V> {
    rows: Vec<(K, V)>,
    at: HashMap<K, u32>,
}

impl<K: Clone + Eq + Hash, V> Indexed<K, V> {
    /// No rows.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Index rows that already exist (a record read back). The first row of a key is the one found.
    /// Off the request path only: it visits every row once.
    #[must_use]
    pub fn from_rows(rows: Vec<(K, V)>) -> Self {
        let mut at = HashMap::with_capacity_and_hasher(rows.len(), Default::default());
        for (position, (key, _)) in rows.iter().enumerate() {
            at.entry(key.clone())
                .or_insert_with(|| position_of(position));
        }
        Self { rows, at }
    }

    /// The value of the row of `key`.
    pub fn get<Q>(&self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let at = *self.at.get(key)?;
        self.rows.get(at as usize).map(|(_, value)| value)
    }

    /// The value of the row of `key`, to change in place.
    pub fn get_mut<Q>(&mut self, key: &Q) -> Option<&mut V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let at = *self.at.get(key)?;
        self.rows.get_mut(at as usize).map(|(_, value)| value)
    }

    /// The row of `key`, appended with `make()` when there is none.
    pub fn row(&mut self, key: K, make: impl FnOnce() -> V) -> &mut V {
        let at = match self.at.get(&key) {
            Some(at) => *at as usize,
            None => {
                let at = self.rows.len();
                self.at.insert(key.clone(), position_of(at));
                self.rows.push((key, make()));
                at
            }
        };
        &mut self.rows[at].1
    }

    /// Every row, in first-insert order.
    #[must_use]
    pub fn rows(&self) -> &[(K, V)] {
        &self.rows
    }

    /// How many rows.
    #[must_use]
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// Whether there are no rows.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }
}

/// A row's position as the index stores it.
fn position_of(at: usize) -> u32 {
    // PANIC: a row list longer than `u32::MAX` rows is past any memory this process holds; the
    // index cannot name such a row, so it refuses loudly rather than find the wrong one.
    u32::try_from(at).expect("an Indexed list holds at most u32::MAX rows")
}

impl<K, V> Default for Indexed<K, V> {
    fn default() -> Self {
        Self {
            rows: Vec::new(),
            at: HashMap::default(),
        }
    }
}

/// Two are equal when their rows are equal, in order. The index is derived.
impl<K: PartialEq, V: PartialEq> PartialEq for Indexed<K, V> {
    fn eq(&self, other: &Self) -> bool {
        self.rows == other.rows
    }
}

impl<K: Eq, V: Eq> Eq for Indexed<K, V> {}

// ---------------------------------------------------------------- ByGroup

/// Rows found by `K`, and retired together by `G` (the key their retire event names).
/// Each group is a doubly linked chain through its own rows, so taking one row out,
/// or a whole group out, touches only that row or that group.
#[derive(Debug)]
pub struct ByGroup<K, G, V> {
    rows: HashMap<K, Linked<K, G, V>>,
    heads: HashMap<G, K>,
}

/// One row, and its neighbours in its group's chain: `before` is the next newer row (none at the
/// head), `after` the next older one.
#[derive(Debug)]
struct Linked<K, G, V> {
    value: V,
    group: G,
    before: Option<K>,
    after: Option<K>,
}

impl<K: Copy + Eq + Hash, G: Copy + Eq + Hash, V> ByGroup<K, G, V> {
    /// No rows.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Hold `value` under `key` in `group`. A row already at `key` is taken out first and returned.
    pub fn insert(&mut self, key: K, group: G, value: V) -> Option<V> {
        let old = self.remove(&key);
        let after = self.heads.insert(group, key);
        if let Some(after) = after {
            if let Some(next) = self.rows.get_mut(&after) {
                next.before = Some(key);
            }
        }
        self.rows.insert(
            key,
            Linked {
                value,
                group,
                before: None,
                after,
            },
        );
        old
    }

    /// The value at `key`.
    pub fn get(&self, key: &K) -> Option<&V> {
        self.rows.get(key).map(|row| &row.value)
    }

    /// The value at `key`, to change in place.
    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        self.rows.get_mut(key).map(|row| &mut row.value)
    }

    /// Whether a row is at `key`.
    pub fn contains_key(&self, key: &K) -> bool {
        self.rows.contains_key(key)
    }

    /// Take the row at `key` out of the map and out of its group's chain (two neighbour updates).
    pub fn remove(&mut self, key: &K) -> Option<V> {
        let row = self.rows.remove(key)?;
        match row.before {
            Some(before) => {
                if let Some(newer) = self.rows.get_mut(&before) {
                    newer.after = row.after;
                }
            }
            None => match row.after {
                Some(after) => {
                    self.heads.insert(row.group, after);
                }
                None => {
                    self.heads.remove(&row.group);
                }
            },
        }
        if let Some(after) = row.after {
            if let Some(older) = self.rows.get_mut(&after) {
                older.before = row.before;
            }
        }
        Some(row.value)
    }

    /// Take every row of `group` out, handing each to `each` (newest first). Only that group's rows are touched.
    pub fn take_group(&mut self, group: &G, mut each: impl FnMut(K, V)) {
        let mut next = self.heads.remove(group);
        while let Some(key) = next {
            let Some(row) = self.rows.remove(&key) else {
                return;
            };
            next = row.after;
            each(key, row.value);
        }
    }

    /// Whether `group` holds no rows.
    pub fn group_is_empty(&self, group: &G) -> bool {
        !self.heads.contains_key(group)
    }

    /// How many rows in all (the map's own length).
    #[must_use]
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// Whether there are no rows.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }
}

impl<K, G, V> Default for ByGroup<K, G, V> {
    fn default() -> Self {
        Self {
            rows: HashMap::default(),
            heads: HashMap::default(),
        }
    }
}

// ---------------------------------------------------------------- Slots

/// The handle `Slots::insert` returns. It names one insert; after `remove` it names nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Slot {
    index: u32,
    generation: u32,
}

/// Values taken out by the one who put them in, without a search.
#[derive(Debug)]
pub struct Slots<T> {
    /// `(generation, value)` per entry. The generation moves on each removal.
    entries: Vec<(u32, Option<T>)>,
    /// Entries that hold no value, to reuse.
    free: Vec<u32>,
    /// How many entries hold a value.
    live: usize,
}

impl<T> Slots<T> {
    /// No values.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
            free: Vec::new(),
            live: 0,
        }
    }

    /// Hold `value`; reuse a free entry when there is one.
    pub fn insert(&mut self, value: T) -> Slot {
        self.live += 1;
        if let Some(index) = self.free.pop() {
            let entry = &mut self.entries[index as usize];
            entry.1 = Some(value);
            return Slot {
                index,
                generation: entry.0,
            };
        }
        let index = position_of(self.entries.len());
        self.entries.push((0, Some(value)));
        Slot {
            index,
            generation: 0,
        }
    }

    /// Take out the value `slot` names. `None` when it was already taken (the generation moved).
    pub fn remove(&mut self, slot: Slot) -> Option<T> {
        let entry = self.entries.get_mut(slot.index as usize)?;
        if entry.0 != slot.generation {
            return None;
        }
        let value = entry.1.take()?;
        entry.0 = entry.0.wrapping_add(1);
        self.free.push(slot.index);
        self.live -= 1;
        Some(value)
    }

    /// The value `slot` names.
    #[must_use]
    pub fn get(&self, slot: Slot) -> Option<&T> {
        self.entries
            .get(slot.index as usize)
            .filter(|entry| entry.0 == slot.generation)
            .and_then(|entry| entry.1.as_ref())
    }

    /// The value `slot` names, to change in place.
    pub fn get_mut(&mut self, slot: Slot) -> Option<&mut T> {
        self.entries
            .get_mut(slot.index as usize)
            .filter(|entry| entry.0 == slot.generation)
            .and_then(|entry| entry.1.as_mut())
    }

    /// How many values are held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.live
    }

    /// Whether no value is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.live == 0
    }
}

impl<T> Default for Slots<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "tests/lookup_tests.rs"]
mod tests;
