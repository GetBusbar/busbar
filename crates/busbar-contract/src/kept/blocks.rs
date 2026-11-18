// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The marked half of [`super`]: nothing here allocates except a slot's first fill.

use std::borrow::Borrow;
use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::ops::Deref;
use std::sync::Arc;

/// Text made once and then shared. Cloning it never allocates.
#[derive(Clone, Debug)]
pub enum Text {
    /// A word fixed in the program.
    Fixed(&'static str),
    /// A name made when it was first learned (configuration, an identity), shared since.
    Shared(Arc<str>),
}

impl Text {
    /// The empty text.
    pub const EMPTY: Text = Text::Fixed("");

    /// A word fixed in the program.
    #[must_use]
    pub const fn fixed(word: &'static str) -> Text {
        Text::Fixed(word)
    }

    /// The text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Text::Fixed(word) => word,
            Text::Shared(shared) => shared,
        }
    }

    /// Whether the text is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.as_str().is_empty()
    }
}

impl Default for Text {
    fn default() -> Self {
        Text::EMPTY
    }
}

impl Deref for Text {
    type Target = str;
    fn deref(&self) -> &str {
        self.as_str()
    }
}

impl AsRef<str> for Text {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Borrow<str> for Text {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for Text {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<Arc<str>> for Text {
    fn from(shared: Arc<str>) -> Self {
        Text::Shared(shared)
    }
}

// Never derived: a derive compares the variant first, and a map keyed by `Text` must sort and
// hash exactly as the same map keyed by `String` does.
impl PartialEq for Text {
    fn eq(&self, other: &Self) -> bool {
        self.as_str() == other.as_str()
    }
}
impl Eq for Text {}
impl PartialOrd for Text {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Text {
    fn cmp(&self, other: &Self) -> Ordering {
        self.as_str().cmp(other.as_str())
    }
}
impl Hash for Text {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_str().hash(state);
    }
}
impl PartialEq<str> for Text {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}
impl PartialEq<&str> for Text {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}
impl PartialEq<String> for Text {
    fn eq(&self, other: &String) -> bool {
        self.as_str() == other.as_str()
    }
}

impl serde::Serialize for Text {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

/// A record that can be emptied and filled again in the storage it already has.
pub trait Kept: Default {
    /// Empty every field. Buffers keep their capacity.
    fn clear(&mut self);
}

/// Replace `dst`'s text with `src` in `dst`'s own storage.
pub fn set_text(dst: &mut String, src: &str) {
    dst.clear();
    dst.push_str(src);
}

/// Replace `dst`'s bytes with `src` in `dst`'s own storage.
pub fn set_bytes(dst: &mut Vec<u8>, src: &[u8]) {
    dst.clear();
    dst.extend_from_slice(src);
}

/// A list of short texts in one buffer, filled in place. Its whole text stays under 4 GiB: an
/// item that would pass that is not added.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TextList {
    text: String,
    ends: Vec<u32>,
}

impl TextList {
    /// Empty the list; the buffers keep their capacity.
    pub fn clear(&mut self) {
        self.text.clear();
        self.ends.clear();
    }

    /// Add `item` at the end, in the list's own buffers.
    pub fn push(&mut self, item: &str) {
        let Ok(end) = u32::try_from(self.text.len().saturating_add(item.len())) else {
            return;
        };
        self.text.push_str(item);
        self.ends.push(end);
    }

    /// How many items.
    #[must_use]
    pub fn len(&self) -> usize {
        self.ends.len()
    }

    /// Whether the list has no item.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ends.is_empty()
    }

    /// Item `i`.
    #[must_use]
    pub fn get(&self, i: usize) -> Option<&str> {
        let end = *self.ends.get(i)?;
        let start = match i.checked_sub(1) {
            Some(before) => *self.ends.get(before)?,
            None => 0,
        };
        self.text
            .get(usize::try_from(start).ok()?..usize::try_from(end).ok()?)
    }

    /// The items in order.
    #[must_use]
    pub fn iter(&self) -> TextListIter<'_> {
        TextListIter { list: self, at: 0 }
    }
}

/// The items of a [`TextList`], in order.
#[derive(Clone, Debug)]
pub struct TextListIter<'a> {
    list: &'a TextList,
    at: usize,
}

impl<'a> Iterator for TextListIter<'a> {
    type Item = &'a str;
    fn next(&mut self) -> Option<&'a str> {
        let item = self.list.get(self.at)?;
        self.at += 1;
        Some(item)
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        let left = self.list.len().saturating_sub(self.at);
        (left, Some(left))
    }
}

impl ExactSizeIterator for TextListIter<'_> {}

impl<'a> IntoIterator for &'a TextList {
    type Item = &'a str;
    type IntoIter = TextListIter<'a>;
    fn into_iter(self) -> TextListIter<'a> {
        self.iter()
    }
}

/// A list of kept records, filled in place: emptying the list keeps every record's storage.
#[derive(Debug, Default)]
pub struct Slots<T> {
    items: Vec<T>,
    len: usize,
}

impl<T: Kept> Slots<T> {
    /// Empty the list; the records stay, to be reused.
    pub fn clear(&mut self) {
        self.len = 0;
    }

    /// The next record, emptied, to fill in place. The list grows by one default record only when
    /// every record it ever made is in use.
    pub fn push(&mut self) -> &mut T {
        if self.len == self.items.len() {
            self.items.push(T::default());
        }
        let at = self.len;
        self.len += 1;
        let slot = &mut self.items[at];
        slot.clear();
        slot
    }

    /// How many records are in use.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether no record is in use.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The records in use.
    #[must_use]
    pub fn as_slice(&self) -> &[T] {
        self.items.get(..self.len).unwrap_or(&[])
    }

    /// The records in use, to change in place.
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        let len = self.len;
        self.items.get_mut(..len).unwrap_or_default()
    }
}

/// The newest records, oldest first, in slots made once.
#[derive(Debug)]
pub struct Window<T> {
    pub(super) slots: Vec<T>,
    pub(super) start: usize,
    pub(super) len: usize,
}

impl<T: Kept> Window<T> {
    /// How many records are held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the window holds no record.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// How many records it holds at most.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.slots.len()
    }

    fn place(&self, i: usize) -> usize {
        let cap = self.slots.len().max(1);
        (self.start + i) % cap
    }

    /// The held records, oldest first.
    pub fn iter(&self) -> impl Iterator<Item = &T> + Clone + '_ {
        (0..self.len).filter_map(move |i| self.slots.get(self.place(i)))
    }

    /// The newest record.
    #[must_use]
    pub fn back(&self) -> Option<&T> {
        let last = self.len.checked_sub(1)?;
        self.slots.get(self.place(last))
    }

    /// The newest record, to change in place.
    pub fn back_mut(&mut self) -> Option<&mut T> {
        let last = self.len.checked_sub(1)?;
        let at = self.place(last);
        self.slots.get_mut(at)
    }

    /// Put `record` in as the newest. `record` comes back emptied, holding the storage of the
    /// slot it took. True when a held record left the window to make room.
    pub fn admit(&mut self, record: &mut T) -> bool {
        let cap = self.slots.len();
        if cap == 0 {
            record.clear();
            return false;
        }
        let released = self.len == cap;
        let at = if released {
            let at = self.start;
            self.start = (self.start + 1) % cap;
            at
        } else {
            self.len += 1;
            (self.start + self.len - 1) % cap
        };
        if let Some(slot) = self.slots.get_mut(at) {
            std::mem::swap(slot, record);
        }
        record.clear();
        released
    }
}

/// Records looked up by key, in slots made once.
#[derive(Debug)]
pub struct Book<K, T> {
    pub(super) index: foldhash::HashMap<K, u32>,
    pub(super) slots: Vec<T>,
    pub(super) free: Vec<u32>,
}

impl<K: Copy + Eq + Hash, T: Kept> Book<K, T> {
    /// The record open under `key`.
    #[must_use]
    pub fn get(&self, key: K) -> Option<&T> {
        let at = *self.index.get(&key)?;
        self.slots.get(usize::try_from(at).ok()?)
    }

    /// The record open under `key`, to change in place.
    pub fn get_mut(&mut self, key: K) -> Option<&mut T> {
        let at = *self.index.get(&key)?;
        self.slots.get_mut(usize::try_from(at).ok()?)
    }

    /// A free slot for `key`, emptied, to fill in place. `None`: the book is full, or `key` is open.
    pub fn open(&mut self, key: K) -> Option<&mut T> {
        if self.index.contains_key(&key) {
            return None;
        }
        let at = self.free.pop()?;
        self.index.insert(key, at);
        let slot = self.slots.get_mut(usize::try_from(at).ok()?)?;
        slot.clear();
        Some(slot)
    }

    /// Empty `key`'s slot and free it. True when it was open.
    pub fn close(&mut self, key: K) -> bool {
        let Some(at) = self.index.remove(&key) else {
            return false;
        };
        if let Some(slot) = usize::try_from(at).ok().and_then(|i| self.slots.get_mut(i)) {
            slot.clear();
        }
        self.free.push(at);
        true
    }

    /// How many records are open.
    #[must_use]
    pub fn len(&self) -> usize {
        self.index.len()
    }

    /// Whether no record is open.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }

    /// How many records it holds at most.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.slots.len()
    }
}
