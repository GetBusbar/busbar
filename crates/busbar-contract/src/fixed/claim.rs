// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The request-path halves of `fixed`: claim a piece that setup made, fill it, give it back.
//! Nothing here allocates, grows or shifts.

use std::ops::{Deref, DerefMut};
use std::sync::{Arc, PoisonError};

use super::{Full, Lent, Reset, Seats, Stock};

impl<V> Seats<V> {
    /// The seat `name` holds, if it holds one.
    pub fn get(&self, name: &str) -> Option<&V> {
        let at = *self.index.get(name)?;
        self.seats.get(at as usize)
    }

    /// The seat `name` holds, if it holds one, to change.
    pub fn get_mut(&mut self, name: &str) -> Option<&mut V> {
        let at = *self.index.get(name)?;
        self.seats.get_mut(at as usize)
    }

    /// The seat `name` holds, or a spare seat claimed for it now. Nothing is allocated: the
    /// seat, the name's bytes and the index's room were made at setup.
    pub fn claim(&mut self, name: &str) -> Result<&mut V, Full> {
        if let Some(&at) = self.index.get(name) {
            return self.seats.get_mut(at as usize).ok_or(Full::NoneLeft);
        }
        if name.len() > self.name_cap {
            self.refused += 1;
            return Err(Full::NameTooLong);
        }
        let (Some(at), Some(mut key)) = (self.spare_seats.pop(), self.spare_names.pop()) else {
            self.refused += 1;
            return Err(Full::NoneLeft);
        };
        key.push_str(name);
        self.index.insert(key, at);
        self.seats.get_mut(at as usize).ok_or(Full::NoneLeft)
    }

    /// Claims refused since setup.
    pub fn refused(&self) -> u64 {
        self.refused
    }
}

impl<T> Stock<T> {
    /// A ready set, or `None` when every set is out.
    pub fn take(&self) -> Option<T> {
        self.free
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pop()
    }

    /// Put a set back. The list never grows past what setup made.
    pub fn give(&self, item: T) {
        let mut free = self.free.lock().unwrap_or_else(PoisonError::into_inner);
        if free.len() < self.made {
            free.push(item);
        }
    }

    /// How many sets setup made.
    pub fn made(&self) -> usize {
        self.made
    }
}

impl<T: Reset> Lent<T> {
    /// A set from `home`, or `None` when every set is out.
    pub fn take(home: &Arc<Stock<T>>) -> Option<Self> {
        Some(Lent {
            item: Some(home.take()?),
            home: Arc::clone(home),
        })
    }
}

impl<T: Reset> Deref for Lent<T> {
    type Target = T;
    fn deref(&self) -> &T {
        self.item.as_ref().expect("a lent set is held until drop")
    }
}

impl<T: Reset> DerefMut for Lent<T> {
    fn deref_mut(&mut self) -> &mut T {
        self.item.as_mut().expect("a lent set is held until drop")
    }
}

impl<T: Reset> Drop for Lent<T> {
    fn drop(&mut self) {
        if let Some(mut item) = self.item.take() {
            item.reset();
            self.home.give(item);
        }
    }
}
