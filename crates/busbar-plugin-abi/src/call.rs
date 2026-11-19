// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The positional codec of the one call shape (core 3.0, interface revision C.3).
//!
//! Every method of every kind crosses as one `Call { session, mono_ns, head, texts, blobs }`. A method's
//! typed arguments map onto the three positional fields by one rule, applied to its arguments in
//! declaration order (a view argument contributes its fields in their declaration order):
//!
//! | Argument or view field | Goes to |
//! |---|---|
//! | `u32` | `head`, 4 bytes little-endian, at the next multiple of 4 |
//! | `u64` | `head`, 8 bytes little-endian, at the next multiple of 8 |
//! | `Str` | the next position of `texts` |
//! | `Bytes` (sync), `ChainBytes` (async) | the next position of `blobs` |
//! | `Slice<Pair>` | the next position of `blobs`: one blob lending the pair array (`Bytes::of_pairs`) |
//! | `Slice<Bytes>` (last argument only) | every remaining position of `blobs` |
//!
//! The reader takes what it knows from the front of each field and never looks further, so a number
//! appended to `head`, or a text or blob appended at the end, is invisible to an image built before it
//! (an addition: the kind's second number). A reader that finds less than it knows answers FAULT.
//! `kind!` emits both halves from the one method signature: the plugin-side read inside each shim adapter
//! and the host-side `pack::<method>`; neither is written by hand, so they cannot disagree.

use busbar_ffi::{Args, Call, ChainArgs};

use crate::need::ChainBytes;
use crate::types::{Bytes, Pair, Slice, Str};

/// The most head bytes a packer holds (the largest method today states 40).
pub const HEAD_MAX: usize = 64;
/// The most texts a packer holds (the largest method today states 5).
pub const TEXTS_MAX: usize = 8;
/// The most blobs a packer holds (the largest method today states 4).
pub const BLOBS_MAX: usize = 8;

/// The next offset at or after `at` that is a multiple of `size` (4 or 8).
const fn aligned(at: usize, size: usize) -> usize {
    (at + size - 1) & !(size - 1)
}

/// Reads a sync call positionally: three cursors, one per field.
pub struct Reader<'a> {
    args: Args<'a>,
    head_at: usize,
    text_at: usize,
    blob_at: usize,
}

impl<'a> Reader<'a> {
    pub fn new(args: Args<'a>) -> Self {
        Reader {
            args,
            head_at: 0,
            text_at: 0,
            blob_at: 0,
        }
    }
    fn number<const N: usize>(&mut self) -> Option<[u8; N]> {
        let at = aligned(self.head_at, N);
        let end = at.checked_add(N)?;
        let bytes = self.args.head().get(at..end)?.try_into().ok()?;
        self.head_at = end;
        Some(bytes)
    }
}

/// One argument (or view field) of a sync method, read from a call.
pub trait Get<'a>: Sized {
    fn get(r: &mut Reader<'a>) -> Option<Self>;
}

impl<'a> Get<'a> for u32 {
    fn get(r: &mut Reader<'a>) -> Option<Self> {
        r.number().map(u32::from_le_bytes)
    }
}
impl<'a> Get<'a> for u64 {
    fn get(r: &mut Reader<'a>) -> Option<Self> {
        r.number().map(u64::from_le_bytes)
    }
}
impl<'a> Get<'a> for Str<'a> {
    fn get(r: &mut Reader<'a>) -> Option<Self> {
        let text = r.args.text(r.text_at)?;
        r.text_at += 1;
        Some(text)
    }
}
impl<'a> Get<'a> for Bytes<'a> {
    fn get(r: &mut Reader<'a>) -> Option<Self> {
        let blob = r.args.blob(r.blob_at)?;
        r.blob_at += 1;
        Some(blob)
    }
}
impl<'a> Get<'a> for Slice<'a, Pair<'a>> {
    fn get(r: &mut Reader<'a>) -> Option<Self> {
        let pairs = r.args.pairs(r.blob_at)?;
        r.blob_at += 1;
        Some(pairs)
    }
}
/// The trailing list: every blob not yet read (possibly none). Only a method's last argument may be one.
impl<'a> Get<'a> for Slice<'a, Bytes<'a>> {
    fn get(r: &mut Reader<'a>) -> Option<Self> {
        let rest = r.args.blobs_from(r.blob_at);
        r.blob_at += rest.len();
        Some(rest)
    }
}

/// Reads an async call positionally: numbers are copied, bytes become chain-scoped handles.
pub struct ChainReader<'a> {
    args: ChainArgs<'a>,
    head_at: usize,
    blob_at: usize,
}

impl<'a> ChainReader<'a> {
    pub fn new(args: ChainArgs<'a>) -> Self {
        ChainReader {
            args,
            head_at: 0,
            blob_at: 0,
        }
    }
    fn number<const N: usize>(&mut self) -> Option<[u8; N]> {
        let at = aligned(self.head_at, N);
        let end = at.checked_add(N)?;
        let bytes = self.args.head().get(at..end)?.try_into().ok()?;
        self.head_at = end;
        Some(bytes)
    }
}

/// One argument of an async method, read from a call.
pub trait ChainGet: Sized {
    fn get(r: &mut ChainReader<'_>) -> Option<Self>;
}

impl ChainGet for u32 {
    fn get(r: &mut ChainReader<'_>) -> Option<Self> {
        r.number().map(u32::from_le_bytes)
    }
}
impl ChainGet for u64 {
    fn get(r: &mut ChainReader<'_>) -> Option<Self> {
        r.number().map(u64::from_le_bytes)
    }
}
impl ChainGet for ChainBytes {
    fn get(r: &mut ChainReader<'_>) -> Option<Self> {
        let blob = r.args.blob(r.blob_at)?;
        r.blob_at += 1;
        Some(blob)
    }
}

/// Builds a call on the caller's stack: no heap, no copy of a lent byte (only the numbers are written).
pub struct Packer<'a> {
    head: [u8; HEAD_MAX],
    head_len: usize,
    texts: [Str<'a>; TEXTS_MAX],
    text_len: usize,
    blobs: [Bytes<'a>; BLOBS_MAX],
    blob_len: usize,
    /// A field did not fit: nothing after it is taken and the call crosses empty, which a reader that
    /// knows any field answers with FAULT. The limits are checked per kind by `kind!`'s layout test.
    overflow: bool,
}

impl<'a> Default for Packer<'a> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> Packer<'a> {
    pub const fn new() -> Self {
        Packer {
            head: [0; HEAD_MAX],
            head_len: 0,
            texts: [Str::EMPTY; TEXTS_MAX],
            text_len: 0,
            blobs: [Bytes::EMPTY; BLOBS_MAX],
            blob_len: 0,
            overflow: false,
        }
    }
    fn number<const N: usize>(&mut self, bytes: [u8; N]) {
        let at = aligned(self.head_len, N);
        match self.head.get_mut(at..at + N) {
            Some(dst) if !self.overflow => {
                dst.copy_from_slice(&bytes);
                self.head_len = at + N;
            }
            _ => self.overflow = true,
        }
    }
    fn text(&mut self, text: Str<'a>) {
        match self.texts.get_mut(self.text_len) {
            Some(slot) if !self.overflow => {
                *slot = text;
                self.text_len += 1;
            }
            _ => self.overflow = true,
        }
    }
    fn blob(&mut self, blob: Bytes<'a>) {
        match self.blobs.get_mut(self.blob_len) {
            Some(slot) if !self.overflow => {
                *slot = blob;
                self.blob_len += 1;
            }
            _ => self.overflow = true,
        }
    }
    /// Whether every field fit (the layout test of each kind asserts it for its largest call).
    pub const fn fits(&self) -> bool {
        !self.overflow
    }
    /// The bytes of `head` written so far, the number of texts and the number of blobs.
    pub const fn counts(&self) -> (usize, usize, usize) {
        (self.head_len, self.text_len, self.blob_len)
    }
    /// The call, for one crossing. `mono_ns` is the host's one clock reading for the operation (0: none).
    pub fn with<R>(&self, mono_ns: u64, f: impl FnOnce(&Call<'_>) -> R) -> R {
        if self.overflow {
            return f(&Call::EMPTY.at(mono_ns));
        }
        let head = self.head.get(..self.head_len).unwrap_or(&[]);
        let texts = self.texts.get(..self.text_len).unwrap_or(&[]);
        let blobs = self.blobs.get(..self.blob_len).unwrap_or(&[]);
        f(&Call::new(mono_ns, head, texts, blobs))
    }
}

/// One argument (or view field) of a method, written into a call.
pub trait Put<'a> {
    fn put(self, w: &mut Packer<'a>);
}

impl<'a> Put<'a> for u32 {
    fn put(self, w: &mut Packer<'a>) {
        w.number(self.to_le_bytes());
    }
}
impl<'a> Put<'a> for u64 {
    fn put(self, w: &mut Packer<'a>) {
        w.number(self.to_le_bytes());
    }
}
impl<'a> Put<'a> for Str<'a> {
    fn put(self, w: &mut Packer<'a>) {
        w.text(self);
    }
}
impl<'a> Put<'a> for Bytes<'a> {
    fn put(self, w: &mut Packer<'a>) {
        w.blob(self);
    }
}
impl<'a> Put<'a> for Slice<'a, Pair<'a>> {
    fn put(self, w: &mut Packer<'a>) {
        w.blob(Bytes::of_pairs(self.get()));
    }
}
impl<'a> Put<'a> for Slice<'a, Bytes<'a>> {
    fn put(self, w: &mut Packer<'a>) {
        for blob in self.get() {
            w.blob(*blob);
        }
    }
}

/// True when the two lists share a number (`kind!`: no declared tag may be on the kind's retired list).
pub const fn shares(a: &[u16], b: &[u16]) -> bool {
    let mut i = 0;
    while i < a.len() {
        let mut j = 0;
        while j < b.len() {
            if a[i] == b[j] {
                return true;
            }
            j += 1;
        }
        i += 1;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_take_their_natural_alignment() {
        let mut w = Packer::new();
        7u32.put(&mut w);
        9u64.put(&mut w);
        3u32.put(&mut w);
        Str::new("t").put(&mut w);
        Bytes::new(b"b").put(&mut w);
        assert!(w.fits());
        assert_eq!(w.counts(), (20, 1, 1));
        w.with(5, |call| {
            assert_eq!(call.mono_ns(), 5);
            assert_eq!(call.head().len(), 20);
            assert_eq!(&call.head()[..4], &7u32.to_le_bytes());
            assert_eq!(&call.head()[8..16], &9u64.to_le_bytes());
            assert_eq!(&call.head()[16..20], &3u32.to_le_bytes());
            assert_eq!(call.texts()[0].get(), "t");
            assert_eq!(call.blobs()[0].get(), b"b");
        });
    }

    #[test]
    fn a_field_that_does_not_fit_sends_the_call_empty() {
        let mut w = Packer::new();
        for _ in 0..=BLOBS_MAX {
            Bytes::new(b"x").put(&mut w);
        }
        assert!(!w.fits());
        w.with(0, |call| assert!(call.blobs().is_empty()));
    }

    #[test]
    fn retired_numbers_are_found() {
        assert!(shares(&[1, 2, 3], &[9, 3]));
        assert!(!shares(&[1, 2, 3], &[9, 4]));
        assert!(!shares(&[], &[9, 4]));
    }
}
