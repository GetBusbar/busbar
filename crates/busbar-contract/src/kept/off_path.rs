// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The constructors: they allocate, and run at boot, at generation build or at restore, never per
//! request. Outside the request-path marker; a marked module of this crate that calls one is
//! reported by the lint (LR-106).

use std::sync::Arc;

use super::{Book, Kept, Text, Window};

/// Make a shared name. One allocation, made where the name is first learned.
#[must_use]
pub fn text(s: &str) -> Text {
    Text::Shared(Arc::from(s))
}

impl<'de> serde::Deserialize<'de> for Text {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Name;
        impl serde::de::Visitor<'_> for Name {
            type Value = Text;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a string")
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Text, E> {
                Ok(text(v))
            }
        }
        deserializer.deserialize_str(Name)
    }
}

/// A window of `capacity` default slots.
#[must_use]
pub fn window<T: Kept>(capacity: usize) -> Window<T> {
    let mut slots = Vec::with_capacity(capacity);
    slots.resize_with(capacity, T::default);
    Window {
        slots,
        start: 0,
        len: 0,
    }
}

/// A window of `capacity` slots holding the newest `capacity` of `run`, oldest first (restore).
#[must_use]
pub fn window_from<T: Kept>(capacity: usize, run: Vec<T>) -> Window<T> {
    let skip = run.len().saturating_sub(capacity);
    let mut slots: Vec<T> = run.into_iter().skip(skip).collect();
    let len = slots.len();
    slots.resize_with(capacity, T::default);
    Window {
        slots,
        start: 0,
        len,
    }
}

/// A book of `capacity` slots; the slots, the free list and the index are all sized to it.
#[must_use]
pub fn book<K, T: Kept>(capacity: usize) -> Book<K, T>
where
    K: Copy + Eq + std::hash::Hash,
{
    let mut slots = Vec::with_capacity(capacity);
    slots.resize_with(capacity, T::default);
    // Popped from the end, so the lowest slot is opened first.
    let free = (0..capacity)
        .rev()
        .map(|i| u32::try_from(i).unwrap_or(u32::MAX))
        .collect();
    Book {
        index: foldhash::HashMap::with_capacity_and_hasher(
            capacity,
            foldhash::fast::RandomState::default(),
        ),
        slots,
        free,
    }
}

#[cfg(feature = "test-support")]
impl From<&str> for Text {
    fn from(s: &str) -> Self {
        text(s)
    }
}
