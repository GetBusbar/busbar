// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! WHAT A TRANSPORT INSTANCE HOLDS BY TOKEN (its framings, its connections, its calls), with no lock

use std::ops::{Deref, DerefMut};
use std::sync::{Mutex, MutexGuard, PoisonError, TryLockError};

/// A slot's state: the generation of the token that last named it, and the value it holds.
pub(crate) struct SlotState<T> {
    pub(crate) generation: u32,
    pub(crate) held: Option<T>,
}

/// One slot, alone on its cache lines.
#[repr(align(128))]
pub(crate) struct Slot<T>(pub(crate) Mutex<SlotState<T>>);

impl<T> Default for Slot<T> {
    fn default() -> Self {
        Self(Mutex::new(SlotState {
            generation: 0,
            held: None,
        }))
    }
}

/// Slots minted and given back.
pub(crate) struct Free {
    pub(crate) idle: Vec<u32>,
    pub(crate) next: u32,
}

/// Why a token reached no value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reach {
    /// No value holds this token (never minted, released, or outlived by a newer one).
    Gone,
    /// Another op holds the value right now: answered at once, never waited for.
    Busy,
}

impl Reach {
    /// The text an op answers with, naming what it reached for (`"framing"`, `"connection"`).
    #[must_use]
    pub fn why(self, what: &str) -> String {
        match self {
            Self::Gone => crate::abi::sdk::cold::wire::no_such(what),
            Self::Busy => crate::abi::sdk::cold::wire::busy(what),
        }
    }
}

/// The values of type `T` an instance holds, by token.
pub struct Table<T> {
    pub(crate) slots: Box<[Slot<T>]>,
    pub(crate) free: Mutex<Free>,
}

impl<T> std::fmt::Debug for Table<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Table").finish_non_exhaustive()
    }
}

fn token(index: u32, generation: u32) -> u64 {
    (u64::from(generation) << 32) | (u64::from(index) + 1)
}

fn untoken(token: u64) -> Option<(u32, u32)> {
    let index = u32::try_from(token & u64::from(u32::MAX))
        .ok()?
        .checked_sub(1)?;
    Some((index, (token >> 32) as u32))
}

/// The value a token names, held for one op: the slot's own lock, let go on drop.
pub struct Held<'a, T> {
    table: &'a Table<T>,
    index: u32,
    state: MutexGuard<'a, SlotState<T>>,
}

impl<T> std::fmt::Debug for Held<'_, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Held").field("index", &self.index).finish()
    }
}

impl<T> Deref for Held<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        self.state
            .held
            .as_ref()
            .expect("a held slot holds its value")
    }
}

impl<T> DerefMut for Held<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        self.state
            .held
            .as_mut()
            .expect("a held slot holds its value")
    }
}

impl<T> Held<'_, T> {
    /// Take the value out and give its slot back: the token reaches nothing from now on.
    #[must_use]
    pub fn release(mut self) -> T {
        let value = self.state.held.take().expect("a held slot holds its value");
        let (table, index) = (self.table, self.index);
        drop(self);
        table.lock_free().idle.push(index);
        value
    }
}

impl<T> Table<T> {
    fn lock_free(&self) -> MutexGuard<'_, Free> {
        self.free.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The slot `token` names, and its index.
    fn slot(&self, token: u64) -> Result<(&Slot<T>, u32, u32), Reach> {
        let (index, generation) = untoken(token).ok_or(Reach::Gone)?;
        let slot = self.slots.get(index as usize).ok_or(Reach::Gone)?;
        Ok((slot, index, generation))
    }

    fn held<'a>(
        &'a self,
        index: u32,
        generation: u32,
        state: MutexGuard<'a, SlotState<T>>,
    ) -> Result<Held<'a, T>, Reach> {
        if state.generation != generation || state.held.is_none() {
            return Err(Reach::Gone);
        }
        Ok(Held {
            table: self,
            index,
            state,
        })
    }

    /// Hold `value`, answering its token, or `None` when every slot is in use.
    pub fn insert(&self, value: T) -> Option<u64> {
        let index = {
            let mut free = self.lock_free();
            match free.idle.pop() {
                Some(i) => i,
                None => {
                    if free.next as usize >= self.slots.len() {
                        return None;
                    }
                    free.next += 1;
                    free.next - 1
                }
            }
        };
        let slot = self.slots.get(index as usize)?;
        let mut slot = slot.0.lock().unwrap_or_else(PoisonError::into_inner);
        slot.generation = slot.generation.wrapping_add(1);
        slot.held = Some(value);
        Some(token(index, slot.generation))
    }

    /// The value `token` names, held for one op; never waited for.
    pub fn reach(&self, token: u64) -> Result<Held<'_, T>, Reach> {
        let (slot, index, generation) = self.slot(token)?;
        let state = match slot.0.try_lock() {
            Ok(s) => s,
            Err(TryLockError::WouldBlock) => return Err(Reach::Busy),
            Err(TryLockError::Poisoned(_)) => return Err(Reach::Gone),
        };
        self.held(index, generation, state)
    }

    /// The value `token` names, held for one op, waiting while another op holds it.
    pub fn hold(&self, token: u64) -> Result<Held<'_, T>, Reach> {
        let (slot, index, generation) = self.slot(token)?;
        let state = slot.0.lock().map_err(|_| Reach::Gone)?;
        self.held(index, generation, state)
    }

    /// Drop the value `token` names and give its slot back; never waited for.
    pub fn remove(&self, token: u64) -> Result<T, Reach> {
        self.reach(token).map(Held::release)
    }
}

#[cfg(test)]
#[path = "../tests/transport_table_tests.rs"]
mod tests;
