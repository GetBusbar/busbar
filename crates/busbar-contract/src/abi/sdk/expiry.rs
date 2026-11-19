// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Shared-state structures for request-path code whose cost must not grow with the state.
//!
//! [`Counted`] wraps an ordered map or set so that every entry an operation reads or yields is
//! counted under the `visit-count` feature and in this crate's own tests. That feature is enabled
//! only from `[dev-dependencies]`, never in a product build, where the counter does not exist. A
//! test then asserts that a hot operation's visits are the same at 10 entries and at 100k: any
//! walk of the state, in any spelling (`any`, `find`, a hand loop, `retain`, a collected copy),
//! moves the counter, because the wrapped collection is reachable only through these methods.
//! There is no `Deref`, no `&M` accessor and no `Clone`.

use std::borrow::Borrow;
use std::collections::{BTreeMap, BTreeSet};
use std::ops::RangeBounds;

/// An ordered map or set whose every visited entry is counted under `visit-count`.
#[derive(Debug, Default)]
pub struct Counted<M> {
    inner: M,
    #[cfg(any(test, feature = "visit-count"))]
    visits: std::sync::atomic::AtomicU64,
}

impl<M> Counted<M> {
    /// Wraps `inner`.
    pub fn new(inner: M) -> Self {
        Self {
            inner,
            #[cfg(any(test, feature = "visit-count"))]
            visits: std::sync::atomic::AtomicU64::new(0),
        }
    }

    #[inline]
    fn visit(&self, _n: u64) {
        #[cfg(any(test, feature = "visit-count"))]
        self.visits
            .fetch_add(_n, std::sync::atomic::Ordering::Relaxed);
    }

    /// Entries read or yielded so far by this instance.
    #[cfg(any(test, feature = "visit-count"))]
    pub fn visits(&self) -> u64 {
        self.visits.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn counting<'a, I: Iterator + 'a>(&'a self, iter: I) -> impl Iterator<Item = I::Item> + 'a {
        iter.inspect(move |_| self.visit(1))
    }
}

impl<K: Ord, V> Counted<BTreeMap<K, V>> {
    /// One visit.
    pub fn get<Q: Ord + ?Sized>(&self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
    {
        self.visit(1);
        self.inner.get(key)
    }

    /// One visit.
    pub fn get_mut<Q: Ord + ?Sized>(&mut self, key: &Q) -> Option<&mut V>
    where
        K: Borrow<Q>,
    {
        self.visit(1);
        self.inner.get_mut(key)
    }

    /// One visit.
    pub fn contains_key<Q: Ord + ?Sized>(&self, key: &Q) -> bool
    where
        K: Borrow<Q>,
    {
        self.visit(1);
        self.inner.contains_key(key)
    }

    /// One visit.
    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        self.visit(1);
        self.inner.insert(key, value)
    }

    /// One visit.
    pub fn remove<Q: Ord + ?Sized>(&mut self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
    {
        self.visit(1);
        self.inner.remove(key)
    }

    /// No visit.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// No visit.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// One visit per yielded entry.
    pub fn iter(&self) -> impl Iterator<Item = (&K, &V)> + '_ {
        self.counting(self.inner.iter())
    }

    /// One visit per yielded key.
    pub fn keys(&self) -> impl Iterator<Item = &K> + '_ {
        self.counting(self.inner.keys())
    }

    /// One visit per yielded value.
    pub fn values(&self) -> impl Iterator<Item = &V> + '_ {
        self.counting(self.inner.values())
    }

    /// One visit per yielded entry.
    pub fn range<Q: Ord + ?Sized, R: RangeBounds<Q>>(
        &self,
        range: R,
    ) -> impl Iterator<Item = (&K, &V)> + '_
    where
        K: Borrow<Q>,
    {
        self.counting(self.inner.range(range))
    }
}

impl<T: Ord> Counted<BTreeSet<T>> {
    /// One visit.
    pub fn contains<Q: Ord + ?Sized>(&self, value: &Q) -> bool
    where
        T: Borrow<Q>,
    {
        self.visit(1);
        self.inner.contains(value)
    }

    /// One visit.
    pub fn insert(&mut self, value: T) -> bool {
        self.visit(1);
        self.inner.insert(value)
    }

    /// One visit.
    pub fn remove<Q: Ord + ?Sized>(&mut self, value: &Q) -> bool
    where
        T: Borrow<Q>,
    {
        self.visit(1);
        self.inner.remove(value)
    }

    /// No visit.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// No visit.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// One visit per yielded value.
    pub fn iter(&self) -> impl Iterator<Item = &T> + '_ {
        self.counting(self.inner.iter())
    }

    /// One visit per yielded value.
    pub fn range<Q: Ord + ?Sized, R: RangeBounds<Q>>(
        &self,
        range: R,
    ) -> impl Iterator<Item = &T> + '_
    where
        T: Borrow<Q>,
    {
        self.counting(self.inner.range(range))
    }
}

