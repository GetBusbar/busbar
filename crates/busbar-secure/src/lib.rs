// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Shared byte custody: live bytes grow by copy-and-wipe, consumed bytes are wiped, and
//! dropping the owner wipes the live extent. Mutable borrows are slices and cannot grow.
//! Reexported by the contract and plugin ABI; plugins depend only on their ABI facade.
#![forbid(unsafe_code)]
#![doc(test(attr(forbid(unsafe_code))))]

use std::fmt;
use std::io;

use zeroize::{Zeroize, ZeroizeOnDrop};

/// The smallest allocation a growing [`SecureVec`] makes.
const MIN_CAP: usize = 1024;

/// A byte queue that wipes what it releases.
///
/// Live bytes are `v[head..end]`. `v[..head]` and `v[end..v.len()]` are zero. `v.len()` is the
/// zero-initialised extent (allocated and zeroed once, at growth or adoption). Drop wipes
/// the live bytes before the free; the rest is zero already.
pub struct SecureVec {
    v: Vec<u8>,
    head: usize,
    end: usize,
}

/// An uncommitted read owns its whole loan, including bytes outside the live extent.
/// Abandoning it wipes the whole loan (the buffer may itself drop during unwind).
struct ReadLoan<'a> {
    bytes: &'a mut [u8],
    committed: bool,
}

impl Drop for ReadLoan<'_> {
    fn drop(&mut self) {
        if !self.committed {
            wipe(self.bytes);
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
            wipe(&mut self.v[cut..self.end]);
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
            wipe(&mut self.v[live..self.end]);
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
        wipe(&mut self.v[self.head..self.head + n]);
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
                    wipe(&mut loan.bytes[k..]);
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
            wipe(&mut self.v[live..self.end]);
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
        // The old block's live span (the rest is zero) is wiped, then freed.
        let mut old = std::mem::replace(&mut self.v, n);
        wipe(&mut old[self.head..self.end]);
        wiped_growth();
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

    /// The live range within `allocation` (test observation only).
    #[must_use]
    pub fn live_range(&self) -> std::ops::Range<usize> {
        self.head..self.end
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
    /// Wipe the live bytes (everything outside them is already zero) and hold nothing; the
    /// allocation is kept, all zero.
    fn zeroize(&mut self) {
        wipe(&mut self.v[self.head..self.end]);
        self.head = 0;
        self.end = 0;
    }
}

/// Only the live bytes need the wipe: outside `[head, end)` is zero by construction.
impl Drop for SecureVec {
    fn drop(&mut self) {
        wipe(&mut self.v[self.head..self.end]);
        wiped_drop();
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

/// THE ONE WIPE RULE (owner's ruling): bytes that held input are wiped in one block store, then an
/// optimisation barrier that takes their address and is declared to read them, so the compiler
/// must keep the zeros in memory even when the next step is the free. Used for every wipe: bytes
/// the buffer keeps and reuses, and bytes about to be released.
fn wipe(s: &mut [u8]) {
    s.fill(0);
    zeroize::optimization_barrier(&*s);
}

#[cfg(any(test, feature = "test-support"))]
thread_local! {
    static REFUSE_GROWTH: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(any(test, feature = "test-support"))]
thread_local! {
    /// Live bytes moved by compaction or growth on this thread (the amortisation proof).
    static MOVED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(any(test, feature = "test-support"))]
fn moved(n: usize) {
    MOVED.with(|m| m.set(m.get() + n));
}

#[cfg(not(any(test, feature = "test-support")))]
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

#[cfg(any(test, feature = "test-support"))]
thread_local! {
    static WIPE_COUNTS: std::cell::Cell<(usize, usize)> = const { std::cell::Cell::new((0, 0)) };
}

/// Bytes moved by the shared queue on this thread (test observation only).
#[cfg(any(test, feature = "test-support"))]
#[must_use]
pub fn moved_bytes() -> usize {
    MOVED.with(std::cell::Cell::get)
}

/// Completed growth and drop wipes on this thread (test observation only).
#[cfg(any(test, feature = "test-support"))]
#[must_use]
pub fn wipe_counts() -> (usize, usize) {
    WIPE_COUNTS.with(std::cell::Cell::get)
}

#[cfg(any(test, feature = "test-support"))]
fn wiped_growth() {
    WIPE_COUNTS.with(|counts| {
        let (growth, drop) = counts.get();
        counts.set((growth + 1, drop));
    });
}
#[cfg(not(any(test, feature = "test-support")))]
const fn wiped_growth() {}

#[cfg(any(test, feature = "test-support"))]
fn wiped_drop() {
    WIPE_COUNTS.with(|counts| {
        let (growth, drop) = counts.get();
        counts.set((growth, drop + 1));
    });
}
#[cfg(not(any(test, feature = "test-support")))]
const fn wiped_drop() {}
