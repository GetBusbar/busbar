// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Storage made once, at setup, with a stated capacity. The makers are here and may allocate.
//! They are called only at boot, at generation build or at instance open. The request-path
//! halves are in `claim`, which carries the request-path marker.

use std::sync::{Arc, Mutex};

/// A claim found nothing left. The caller answers with its own capacity refusal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Full {
    /// Every spare seat (or every set) is taken.
    NoneLeft,
    /// The name is longer than the name buffers made at setup.
    NameTooLong,
}

/// Spare seats a default table makes.
pub const DEFAULT_SPARE: usize = 8;
/// Bytes of name a default spare seat can hold.
pub const DEFAULT_NAME_CAP: usize = 64;

/// One value per name. Every seat, every key and the index's room are made at setup.
#[derive(Debug)]
pub struct Seats<V> {
    pub(crate) index: foldhash::HashMap<String, u32>,
    pub(crate) seats: Vec<V>,
    /// Seats no name holds yet.
    pub(crate) spare_seats: Vec<u32>,
    /// One empty name per spare seat, each with `name_cap` bytes already allocated.
    pub(crate) spare_names: Vec<String>,
    pub(crate) name_cap: usize,
    pub(crate) refused: u64,
}

impl<V: Default> Seats<V> {
    /// Setup only. A seat for each planned name, and `spare` more for names not planned.
    #[must_use]
    pub fn make<'n>(
        planned: impl IntoIterator<Item = (&'n str, V)>,
        spare: usize,
        name_cap: usize,
    ) -> Self {
        let mut made = Seats {
            index: foldhash::HashMap::default(),
            seats: Vec::new(),
            spare_seats: Vec::new(),
            spare_names: Vec::new(),
            name_cap,
            refused: 0,
        };
        for (name, value) in planned {
            made.plan(name, value);
        }
        made.spare(spare);
        made
    }

    /// Setup only. Give `name` its own seat holding `value`. A name already seated keeps its
    /// seat and its value; `false` then.
    pub fn plan(&mut self, name: &str, value: V) -> bool {
        if self.index.contains_key(name) {
            return false;
        }
        let at = u32::try_from(self.seats.len()).expect("seat count fits u32");
        self.seats.push(value);
        // Room for this key and for every spare claim still to come.
        self.index.reserve(1 + self.spare_seats.len());
        self.index.insert(name.to_owned(), at);
        true
    }

    /// Setup only. Add `count` spare seats.
    pub fn spare(&mut self, count: usize) {
        self.index.reserve(self.spare_seats.len() + count);
        self.spare_seats.reserve_exact(count);
        self.spare_names.reserve_exact(count);
        for _ in 0..count {
            let at = u32::try_from(self.seats.len()).expect("seat count fits u32");
            self.seats.push(V::default());
            self.spare_seats.push(at);
            self.spare_names.push(String::with_capacity(self.name_cap));
        }
    }
}

impl<V: Default> Default for Seats<V> {
    fn default() -> Self {
        Self::make(std::iter::empty(), DEFAULT_SPARE, DEFAULT_NAME_CAP)
    }
}

/// A stated number of ready sets. A taker takes one and gives it back.
#[derive(Debug)]
pub struct Stock<T> {
    pub(crate) free: Mutex<Vec<T>>,
    pub(crate) made: usize,
}

impl<T> Stock<T> {
    /// Setup only. `count` sets, each built by `fresh`.
    #[must_use]
    pub fn make(count: usize, mut fresh: impl FnMut() -> T) -> Self {
        let mut free = Vec::with_capacity(count);
        for _ in 0..count {
            free.push(fresh());
        }
        Stock {
            free: Mutex::new(free),
            made: count,
        }
    }
}

/// What a set does before it goes back to its stock: wipe what it held.
pub trait Reset {
    /// Wipe what the set held, so the next taker sees it as made.
    fn reset(&mut self);
}

/// One set out of a stock. It goes back, reset, when this drops.
#[derive(Debug)]
pub struct Lent<T: Reset> {
    pub(crate) item: Option<T>,
    pub(crate) home: Arc<Stock<T>>,
}

// busbar:request-path
#[cfg_attr(
    not(test),
    deny(
        clippy::disallowed_macros,
        clippy::disallowed_methods,
        clippy::disallowed_types,
        clippy::redundant_clone,
        clippy::format_push_string,
        clippy::needless_collect,
        clippy::or_fun_call,
        clippy::needless_pass_by_value,
        clippy::allow_attributes,
        clippy::allow_attributes_without_reason
    )
)]
pub mod claim;

#[cfg(test)]
mod tests;
