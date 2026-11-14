// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CORE WIPING BUFFER (TRANSPORT-TLS §2.0). Both legs queue credential-bearing bytes (request
//! heads with the injected `Authorization`, reply heads and bodies) in buffers that must not keep
//! what they release. [`SecureVec`] is a byte queue whose consumed prefix is wiped as it is
//! consumed, whose growth never reallocates live bytes in place, and whose allocation is
//! volatile-wiped before it is freed (`Zeroizing`).
//!
//! Rules: (1) [`SecureVec::consume`] wipes `[head, head + n)` and advances `head`; nothing moves.
//! (2) Compaction only when new bytes do not fit after `end` and at least half the used span is
//! consumed; growth copies only `[head, end)` into a fresh zeroed block. (3) The read surface is
//! `[head, end)` only ([`SecureVec::as_slice`]); no `Deref`, `Clone` or `PartialEq`, and `Debug`
//! prints the length. (4) No `realloc` of live bytes. (5) Hot wipes are a plain fill; the
//! volatile wipe runs only on the free path.

#![forbid(unsafe_code)]

use std::fmt;

use zeroize::Zeroizing;

/// The smallest allocation a growing [`SecureVec`] makes.
const MIN_CAP: usize = 1024;

/// A byte queue that wipes what it releases.
///
/// Live bytes are `v[head..end]`. `v[..head]` and `v[end..v.len()]` are zero. `v.len()` is the
/// zero-initialised extent (allocated and zeroed once, at growth). Dropping the `Zeroizing` wipes
/// all of `v` with volatile writes before the free.
pub struct SecureVec {
    v: Zeroizing<Vec<u8>>,
    head: usize,
    end: usize,
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
            v: Zeroizing::new(Vec::new()),
            head: 0,
            end: 0,
        }
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
        // The old block is volatile-wiped by its `Zeroizing`, then freed.
        self.v = Zeroizing::new(n);
        self.head = 0;
        self.end = live;
        Ok(())
    }
}

#[cfg(test)]
impl SecureVec {
    /// The whole zero-initialised extent, consumed prefix and tail included (tests only).
    pub(crate) fn allocation(&self) -> &[u8] {
        &self.v
    }
}

impl fmt::Debug for SecureVec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecureVec")
            .field("len", &self.len())
            .finish()
    }
}

/// Wipe bytes the buffer still owns and will reuse. These are not dead stores: the allocation is
/// read again through `as_slice`/`copy_within`, and the final wipe before the free is
/// `Zeroizing`'s.
fn wipe(s: &mut [u8]) {
    s.fill(0);
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
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
#[path = "tests/secure_vec_tests.rs"]
mod tests;
