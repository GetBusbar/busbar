// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CORE WIPING BUFFER (TRANSPORT-TLS §2.0). Both legs queue credential-bearing bytes (request
//! heads with the injected `Authorization`, reply heads and bodies) in buffers that must not keep
//! what they release. [`SecureVec`] is a byte queue whose consumed prefix is wiped as it is
//! consumed, whose growth never reallocates live bytes in place, and whose allocation is
//! volatile-wiped before it is freed.
//!
//! Rules: (1) [`SecureVec::consume`] wipes `[head, head + n)` and advances `head`; nothing moves.
//! (2) Compaction only when new bytes do not fit after `end` and at least half the used span is
//! consumed; growth copies only `[head, end)` into a fresh zeroed block. (3) The read surface is
//! `[head, end)` only ([`SecureVec::as_slice`], `Deref` to `[u8]`); `Clone` copies the live bytes into a new
//! `SecureVec`; no `PartialEq`, and `Debug` prints the length. (4) No `realloc` of live bytes. (5) Hot wipes are a plain fill; the
//! volatile wipe runs on the free path and when a read loan is abandoned.
//!
//! SECURE-TYPES (core #164): the zeroize crate's wiping wrapper is banned in our code (LR-094). Secret memory
//! lives in one of three types, each built on the `zeroize` crate (`Zeroize` does the volatile
//! wipe; `ZeroizeOnDrop` marks that drop runs it) and none of which hands out a growable
//! `&mut Vec` or `&mut String`: [`SecureVec`] (secret bytes, fixed or growing), [`SecureString`]
//! (secret text) and [`SecureArray`] (fixed keys, seeds, digests). Growth always moves the live
//! bytes into a fresh block and wipes the old one. `Debug` prints the length only. The
//! connector's per-thread scratch slots over [`SecureVec`] live in
//! `busbar_core_connector::secure_vec`.

#![forbid(unsafe_code)]

use std::fmt;
use std::io;

use zeroize::{Zeroize, ZeroizeOnDrop};

/// The smallest allocation a growing [`SecureVec`] makes.
const MIN_CAP: usize = 1024;

/// A byte queue that wipes what it releases.
///
/// Live bytes are `v[head..end]`. `v[..head]` and `v[end..v.len()]` are zero. `v.len()` is the
/// zero-initialised extent (allocated and zeroed once, at growth or adoption). Drop volatile-wipes
/// the live bytes before the free; the rest is zero already.
pub struct SecureVec {
    v: Vec<u8>,
    head: usize,
    end: usize,
}

/// An uncommitted read owns its whole loan, including bytes outside the live extent.
/// Abandoning it must use a volatile wipe: the buffer may itself drop during unwind.
struct ReadLoan<'a> {
    bytes: &'a mut [u8],
    committed: bool,
}

impl Drop for ReadLoan<'_> {
    fn drop(&mut self) {
        if !self.committed {
            self.bytes.zeroize();
        }
    }
}

/// A [`SecureVec`] could not get the memory it needed; nothing was written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Overflow;

impl fmt::Display for Overflow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("buffer allocation failed")
    }
}

impl Default for SecureVec {
    fn default() -> Self {
        Self::new()
    }
}

impl SecureVec {
    /// An empty buffer; allocates nothing.
    #[must_use]
    pub fn new() -> Self {
        Self {
            v: Vec::new(),
            head: 0,
            end: 0,
        }
    }

    /// An empty buffer with `cap` zeroed bytes of room, allocated once: while what it is given
    /// fits, it never grows. The exact-size form for an encoder that knows its output size.
    ///
    /// # Errors
    /// [`Overflow`] when the memory cannot be allocated.
    pub fn with_capacity(cap: usize) -> Result<Self, Overflow> {
        let mut v: Vec<u8> = Vec::new();
        v.try_reserve_exact(cap).map_err(|_| Overflow)?;
        v.resize(cap, 0);
        Ok(Self { v, head: 0, end: 0 })
    }

    /// Append one byte.
    ///
    /// # Errors
    /// [`Overflow`] when the memory for it cannot be allocated.
    pub fn push(&mut self, b: u8) -> Result<(), Overflow> {
        self.extend(&[b])
    }

    /// `n` zero bytes, all live: the buffer a reader fills in place and then [`truncate`]s to what
    /// it wrote.
    ///
    /// [`truncate`]: SecureVec::truncate
    #[must_use]
    pub fn zeroed(n: usize) -> Self {
        Self {
            v: vec![0; n],
            head: 0,
            end: n,
        }
    }

    /// Append `b`, aborting on allocation failure as `Vec` does: the infallible form of
    /// [`SecureVec::extend`] for buffers off the carrier path.
    ///
    /// # Panics
    /// When the memory for `b` cannot be allocated.
    pub fn extend_from_slice(&mut self, b: &[u8]) {
        self.extend(b).expect("secure buffer allocation");
    }

    /// Keep the first `n` live bytes; the cut tail is wiped.
    pub fn truncate(&mut self, n: usize) {
        if n < self.len() {
            let cut = self.head + n;
            fill_wipe(&mut self.v[cut..self.end]);
            self.end = cut;
            if self.head == self.end {
                self.head = 0;
                self.end = 0;
            }
        }
    }

    /// The live bytes as a plain `Vec`, without a copy when nothing was consumed (the zeroed room
    /// past them stays as spare capacity, all zero). ONLY to hand the bytes to another owner that
    /// wipes them (`Secret`, `Held`): the `Vec` itself wipes nothing.
    #[must_use]
    pub fn into_vec(mut self) -> Vec<u8> {
        if self.head != 0 {
            let live = self.len();
            self.v.copy_within(self.head..self.end, 0);
            fill_wipe(&mut self.v[live..self.end]);
            self.head = 0;
            self.end = live;
        }
        let mut v = std::mem::take(&mut self.v);
        v.truncate(self.end);
        self.head = 0;
        self.end = 0;
        v
    }

    /// The live bytes held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.end - self.head
    }

    /// Whether no live byte is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.end == self.head
    }

    /// The zero-initialised extent of the allocation.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.v.len()
    }

    /// THE read surface: the live bytes `[head, end)`, never the consumed prefix.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.v[self.head..self.end]
    }

    /// Wipe-and-advance: the first `n` live bytes are wiped and released; nothing moves. Once
    /// empty, both offsets reset for free.
    pub fn consume(&mut self, n: usize) {
        let n = n.min(self.len());
        fill_wipe(&mut self.v[self.head..self.head + n]);
        self.head += n;
        if self.head == self.end {
            self.head = 0;
            self.end = 0;
        }
    }

    /// Append `b`. On [`Overflow`] nothing is appended and the held bytes are unchanged.
    ///
    /// # Errors
    /// [`Overflow`] when the memory for `b` cannot be allocated.
    pub fn extend(&mut self, b: &[u8]) -> Result<(), Overflow> {
        self.room(b.len())?;
        self.v[self.end..self.end + b.len()].copy_from_slice(b);
        self.end += b.len();
        Ok(())
    }

    /// Only when empty (everything is zero): truncate the zero extent to `keep` and give the memory
    /// back. No wipe is needed.
    pub fn shrink_when_empty(&mut self, keep: usize) {
        if self.is_empty() && self.v.len() > keep {
            self.v.truncate(keep);
            self.v.shrink_to(keep);
        }
    }

    /// Wipe and release every live byte.
    pub fn clear(&mut self) {
        let n = self.len();
        self.consume(n);
    }

    /// Lend `[end, end + max)` (already zero) to `read` and keep the `k` bytes it reports. With
    /// [`Tail::Wipe`], whatever `read` wrote past `k` is wiped. A reader reporting `k > max` broke
    /// its contract: nothing is kept, the lent region is wiped and the answer is `InvalidData`.
    /// An error or unwind wipes the entire lent region under either tail mode, preserving the
    /// prior live bytes. The reader's panic propagates after cleanup.
    ///
    /// # Errors
    /// [`Overflow`] when the lent region cannot be allocated.
    pub fn read_into(
        &mut self,
        max: usize,
        tail: Tail,
        read: impl FnOnce(&mut [u8]) -> io::Result<usize>,
    ) -> Result<io::Result<usize>, Overflow> {
        self.room(max)?;
        let lent = self.end..self.end + max;
        let mut loan = ReadLoan {
            bytes: &mut self.v[lent],
            committed: false,
        };
        match read(loan.bytes) {
            Ok(k) if k <= max => {
                if tail == Tail::Wipe {
                    fill_wipe(&mut loan.bytes[k..]);
                }
                // `room` already checked end + max; no user code or fallible step separates
                // advancing the live extent from committing the loan.
                self.end += k;
                loan.committed = true;
                Ok(Ok(k))
            }
            Ok(_) => Ok(Err(io::ErrorKind::InvalidData.into())),
            Err(error) => Ok(Err(error)),
        }
    }

    /// Make room for `add` more bytes after `end`: compact when at least half the used span is
    /// consumed, else grow geometrically into a fresh zeroed block.
    fn room(&mut self, add: usize) -> Result<(), Overflow> {
        if self.end.checked_add(add).ok_or(Overflow)? <= self.v.len() {
            return Ok(());
        }
        let live = self.len();
        let need = live.checked_add(add).ok_or(Overflow)?;
        if self.head >= live && need <= self.v.len() {
            // At least half the used span is consumed: move the `live` (≤ `head`) bytes to 0.
            self.v.copy_within(self.head..self.end, 0);
            moved(live);
            fill_wipe(&mut self.v[live..self.end]);
            self.head = 0;
            self.end = live;
            return Ok(());
        }
        if growth_refused() {
            return Err(Overflow);
        }
        let cap = need.max(self.v.len().saturating_mul(2)).max(MIN_CAP);
        let mut n: Vec<u8> = Vec::new();
        n.try_reserve_exact(cap).map_err(|_| Overflow)?;
        n.resize(cap, 0); // the one zero-fill, at growth only
        n[..live].copy_from_slice(&self.v[self.head..self.end]);
        moved(live);
        // The old block's live span (the rest is zero) is volatile-wiped, then freed.
        let mut old = std::mem::replace(&mut self.v, n);
        old[self.head..self.end].zeroize();
        self.head = 0;
        self.end = live;
        Ok(())
    }
}

#[cfg(any(test, feature = "test-support"))]
impl SecureVec {
    /// The whole zero-initialised extent, consumed prefix and tail included (tests only).
    #[must_use]
    pub fn allocation(&self) -> &[u8] {
        &self.v
    }
}

/// Encoders (`serde_json::to_writer`, `write!`) append through [`SecureVec::extend`].
impl io::Write for SecureVec {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.extend(buf)
            .map(|()| buf.len())
            .map_err(|_| io::ErrorKind::OutOfMemory.into())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl fmt::Debug for SecureVec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecureVec")
            .field("len", &self.len())
            .finish()
    }
}

impl Zeroize for SecureVec {
    /// Volatile-wipe the live bytes (everything outside them is already zero) and hold nothing;
    /// the allocation is kept, all zero.
    fn zeroize(&mut self) {
        self.v[self.head..self.end].zeroize();
        self.head = 0;
        self.end = 0;
    }
}

/// Only the live bytes need the volatile wipe: outside `[head, end)` is zero by construction.
impl Drop for SecureVec {
    fn drop(&mut self) {
        self.v[self.head..self.end].zeroize();
    }
}

/// The live bytes only, exact size, in a new [`SecureVec`]: no copy leaves custody.
impl Clone for SecureVec {
    fn clone(&self) -> Self {
        Self::from(self.as_slice())
    }
}

impl ZeroizeOnDrop for SecureVec {}

/// Adopt `v` without a copy: its bytes are the live bytes. The spare capacity is zero-filled once
/// (no reallocation), so bytes a caller truncated away are scrubbed and the "outside live is zero"
/// rule holds.
impl From<Vec<u8>> for SecureVec {
    fn from(mut v: Vec<u8>) -> Self {
        let end = v.len();
        v.resize(v.capacity(), 0);
        Self { v, head: 0, end }
    }
}

/// One exact copy of `b`.
impl From<&[u8]> for SecureVec {
    fn from(b: &[u8]) -> Self {
        Self::from(b.to_vec())
    }
}

/// The live bytes; a slice cannot grow, so nothing reallocates through it.
impl std::ops::Deref for SecureVec {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl std::ops::DerefMut for SecureVec {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.v[self.head..self.end]
    }
}

impl AsRef<[u8]> for SecureVec {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

/// Secret text: a `String` that never hands out `&mut String`, so it grows only through
/// [`SecureString::push_str`], which moves the text into a fresh block and wipes the old one.
/// Drop wipes the live text (adoption scrubbed the spare). `Debug` prints the length; there is no `Display`. Equality is
/// constant-time. `Clone` makes another `SecureString` (exact capacity), so no copy escapes custody.
#[derive(Default)]
pub struct SecureString(String);

impl SecureString {
    /// Empty; allocates nothing.
    #[must_use]
    pub const fn new() -> Self {
        Self(String::new())
    }

    /// Empty, with room for `n` bytes before the first growth.
    #[must_use]
    pub fn with_capacity(n: usize) -> Self {
        Self(String::with_capacity(n))
    }

    /// The text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Append `text`. When it does not fit, the held text moves into a fresh block of at least
    /// twice the capacity and the old block is wiped before it is freed.
    ///
    /// # Panics
    /// When the length overflows `usize` (as `String` growth does).
    pub fn push_str(&mut self, text: &str) {
        let len = self
            .0
            .len()
            .checked_add(text.len())
            .expect("secure text length");
        if len > self.0.capacity() {
            let mut next = String::with_capacity(len.max(self.0.capacity().saturating_mul(2)));
            next.push_str(&self.0);
            // Only `len` was ever written in the old block (adoption scrubbed its spare).
            let mut old = std::mem::replace(&mut self.0, next);
            old.as_mut_str().zeroize();
        }
        self.0.push_str(text);
    }

    /// Append one character.
    pub fn push(&mut self, c: char) {
        self.push_str(c.encode_utf8(&mut [0; 4]));
    }

    /// Text formatted straight into custody (the `format!` replacement): every growth on the way
    /// wipes the block it leaves.
    #[must_use]
    pub fn from_args(args: fmt::Arguments<'_>) -> Self {
        let mut s = Self::new();
        if let Some(text) = args.as_str() {
            s.push_str(text);
        } else {
            let _ = fmt::Write::write_fmt(&mut s, args);
        }
        s
    }

    /// The text as a plain `String`, without a copy. ONLY to hand it to another owner that wipes
    /// it (a field of a self-wiping struct): the `String` itself wipes nothing.
    #[must_use]
    pub fn into_string(mut self) -> String {
        std::mem::take(&mut self.0)
    }

    /// The room held before the next growth.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.0.capacity()
    }

    /// The text's bytes, without a copy, still in custody.
    #[must_use]
    pub fn into_bytes(mut self) -> SecureVec {
        SecureVec::from(std::mem::take(&mut self.0).into_bytes())
    }
}

/// Adopt `s` without a copy. Its spare capacity is volatile-wiped once (bytes a caller truncated
/// away), so drop and growth need wipe only `len`. Adopt only text built at its final size: a
/// `String` that grew before adoption already freed its old blocks unwiped (build it with
/// [`SecureString::from_args`] or `push_str` instead).
impl From<String> for SecureString {
    fn from(s: String) -> Self {
        if s.len() == s.capacity() {
            return Self(s);
        }
        let mut v = s.into_bytes();
        v.spare_capacity_mut().zeroize();
        Self(String::from_utf8(v).expect("adopted text stays UTF-8"))
    }
}

/// One exact copy of `s`.
impl From<&str> for SecureString {
    fn from(s: &str) -> Self {
        Self(s.to_owned())
    }
}

impl Clone for SecureString {
    fn clone(&self) -> Self {
        Self::from(self.as_str())
    }
}

impl std::ops::Deref for SecureString {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for SecureString {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl PartialEq for SecureString {
    fn eq(&self, other: &Self) -> bool {
        crate::constant_time_eq(self.0.as_bytes(), other.0.as_bytes())
    }
}

impl Eq for SecureString {}

impl fmt::Write for SecureString {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.push_str(s);
        Ok(())
    }
}

impl fmt::Debug for SecureString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecureString")
            .field("len", &self.0.len())
            .finish()
    }
}

/// As a plain string (records that persist a secret today keep their shape).
impl serde::Serialize for SecureString {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

/// A plain string, adopted without a copy.
impl<'de> serde::Deserialize<'de> for SecureString {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        <String as serde::Deserialize>::deserialize(d).map(Self::from)
    }
}

impl Zeroize for SecureString {
    /// Volatile-wipe the text (only `len` was ever written) and hold none; the block is kept.
    fn zeroize(&mut self) {
        self.0.as_mut_str().zeroize();
        self.0.clear();
    }
}

impl Drop for SecureString {
    fn drop(&mut self) {
        self.0.as_mut_str().zeroize();
    }
}

impl ZeroizeOnDrop for SecureString {}

/// A fixed-size secret (a key, a seed, a digest, a MAC). It never grows and is wiped on drop. No
/// `Clone`, no `Copy`: `*a` copies the array out, and only where the code means to.
#[repr(transparent)]
pub struct SecureArray<const N: usize>([u8; N]);

impl<const N: usize> SecureArray<N> {
    /// All zero.
    #[must_use]
    pub const fn zeroed() -> Self {
        Self([0; N])
    }
}

impl<const N: usize> Default for SecureArray<N> {
    fn default() -> Self {
        Self::zeroed()
    }
}

impl<const N: usize> From<[u8; N]> for SecureArray<N> {
    fn from(a: [u8; N]) -> Self {
        Self(a)
    }
}

impl<const N: usize> std::ops::Deref for SecureArray<N> {
    type Target = [u8; N];
    fn deref(&self) -> &[u8; N] {
        &self.0
    }
}

impl<const N: usize> std::ops::DerefMut for SecureArray<N> {
    fn deref_mut(&mut self) -> &mut [u8; N] {
        &mut self.0
    }
}

impl<const N: usize> AsRef<[u8]> for SecureArray<N> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<const N: usize> PartialEq for SecureArray<N> {
    fn eq(&self, other: &Self) -> bool {
        crate::constant_time_eq(&self.0, &other.0)
    }
}

impl<const N: usize> Eq for SecureArray<N> {}

impl<const N: usize> fmt::Debug for SecureArray<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecureArray").field("len", &N).finish()
    }
}

impl<const N: usize> Zeroize for SecureArray<N> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl<const N: usize> Drop for SecureArray<N> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<const N: usize> ZeroizeOnDrop for SecureArray<N> {}
/// Whether a reader lent a region by [`SecureVec::read_into`] is trusted to have written nothing
/// past the count it reports on success. Errors, excessive counts and unwinds always wipe the
/// entire loan. Every carrier read on dev is [`Tail::Wipe`]: the carrier is a plugin
/// door, and core never names a plugin as trusted (TRANSPORT-TLS §2.0 rule 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tail {
    /// The reader copies exactly the count it returns: only rustls' plaintext `Reader::read`
    /// into a region sized to that count (T6), on successful return only.
    Trusted,
    /// Wipe `[k, max)` after the read.
    Wipe,
}

/// Wipe bytes the buffer still owns and will reuse. These are not dead stores: the allocation is
/// read again through `as_slice`/`copy_within`, and the final wipe before the free is
/// `Zeroize`'s, at drop.
fn fill_wipe(s: &mut [u8]) {
    s.fill(0);
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

/// THE FREE-PATH WIPE of bytes held outside a `Secure*` type: volatile-zero every byte of
/// `bytes`, so no write is elided before the block is freed or handed on. The length is kept. A
/// `Vec<u8>` whose spare capacity also held secret bytes wipes with
/// [`crate::abi::sdk::wipe::wipe_bytes`].
pub fn wipe(bytes: &mut [u8]) {
    bytes.zeroize();
}

/// Volatile-zero `text`'s whole allocation (its spare capacity too) and empty it. The allocation
/// is kept.
pub fn wipe_string(text: &mut String) {
    text.zeroize();
}

#[cfg(any(test, feature = "test-support"))]
thread_local! {
    static REFUSE_GROWTH: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
thread_local! {
    /// Live bytes moved by compaction or growth on this thread (the amortisation proof).
    static MOVED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn moved(n: usize) {
    MOVED.with(|m| m.set(m.get() + n));
}

#[cfg(not(test))]
const fn moved(_: usize) {}

/// Test hook: while `refuse` is set on this thread, every [`SecureVec`] growth fails with
/// [`Overflow`], as an allocator failure would.
#[cfg(any(test, feature = "test-support"))]
pub fn refuse_growth(refuse: bool) {
    REFUSE_GROWTH.with(|r| r.set(refuse));
}

#[cfg(any(test, feature = "test-support"))]
fn growth_refused() -> bool {
    REFUSE_GROWTH.with(std::cell::Cell::get)
}

#[cfg(not(any(test, feature = "test-support")))]
const fn growth_refused() -> bool {
    false
}

#[cfg(test)]
#[path = "tests/secure_tests.rs"]
mod tests;
