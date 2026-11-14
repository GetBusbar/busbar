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

use std::cell::Cell;
use std::fmt;
use std::io;
use std::thread::LocalKey;

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

    /// Lend `[end, end + max)` (already zero) to `read` and keep the `k` bytes it reports. With
    /// [`Tail::Wipe`], whatever `read` wrote past `k` is wiped. A reader reporting `k > max` broke
    /// its contract: nothing is kept, the lent region is wiped and the answer is `InvalidData`.
    pub(crate) fn read_into(
        &mut self,
        max: usize,
        tail: Tail,
        read: impl FnOnce(&mut [u8]) -> io::Result<usize>,
    ) -> Result<io::Result<usize>, Overflow> {
        self.room(max)?;
        let lent = self.end..self.end + max;
        let r = read(&mut self.v[lent.clone()]);
        let overlong = matches!(r, Ok(k) if k > max);
        let k = match r {
            Ok(k) if k <= max => k,
            _ => 0,
        };
        if tail == Tail::Wipe || overlong {
            wipe(&mut self.v[self.end + k..lent.end]);
        }
        self.end += k;
        Ok(if overlong {
            Err(io::ErrorKind::InvalidData.into())
        } else {
            r
        })
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

#[cfg(any(test, feature = "test-support"))]
impl SecureVec {
    /// The whole zero-initialised extent, consumed prefix and tail included (tests only).
    pub fn allocation(&self) -> &[u8] {
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

/// Whether a reader lent a region by [`SecureVec::read_into`] is trusted to have written nothing
/// past the count it reports. Every carrier read on dev is [`Tail::Wipe`]: the carrier is a plugin
/// door, and core never names a plugin as trusted (TRANSPORT-TLS §2.0 rule 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Tail {
    /// The reader copies exactly the count it returns: only rustls' plaintext `Reader::read`
    /// into a region sized to that count (T6).
    Trusted,
    /// Wipe `[k, max)` after the read.
    Wipe,
}

/// One per-thread scratch slot: `Some` while no taker holds it.
pub(crate) type Slot = Cell<Option<SecureVec>>;

thread_local! {
    /// The carrier read's scratch (T11-dev): taken only in `Connection::read`, held until `feed`
    /// returns.
    pub(crate) static READ_SCRATCH: Slot = Cell::new(Some(SecureVec::new()));
    /// The TLS plaintext's scratch (T6): taken only in `feed`, after the `process_new_packets`
    /// loop, held until `ingest` returns. It nests inside `READ_SCRATCH` and never contends.
    pub(crate) static TLS_PLAIN: Slot = Cell::new(Some(SecureVec::new()));
}

/// A slot's buffer, taken for one read. Drop wipes what it holds and puts it back, so the slot is
/// all zero between reads. A slot found empty is a re-entrant take on this thread: the guard uses a
/// fresh buffer (never an alias) and, on Drop, the slot keeps the larger of the two.
pub(crate) struct Scratch {
    key: &'static LocalKey<Slot>,
    buf: Option<SecureVec>,
}

impl Scratch {
    /// Take `key`'s buffer.
    pub(crate) fn take(key: &'static LocalKey<Slot>) -> Self {
        let buf = key.with(Cell::take).unwrap_or_else(|| {
            scratch_missed();
            SecureVec::new()
        });
        Self {
            key,
            buf: Some(buf),
        }
    }
}

impl std::ops::Deref for Scratch {
    type Target = SecureVec;
    fn deref(&self) -> &SecureVec {
        self.buf.as_ref().expect("held until drop")
    }
}

impl std::ops::DerefMut for Scratch {
    fn deref_mut(&mut self) -> &mut SecureVec {
        self.buf.as_mut().expect("held until drop")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let Some(mut buf) = self.buf.take() else {
            return;
        };
        buf.clear();
        let _ = self.key.try_with(move |slot| {
            let keep = match slot.take() {
                Some(other) if other.capacity() >= buf.capacity() => other,
                _ => buf,
            };
            slot.set(Some(keep));
        });
    }
}

#[cfg(test)]
thread_local! {
    /// Re-entrant takes that found their slot empty, on this thread.
    static SCRATCH_MISSES: Cell<usize> = const { Cell::new(0) };
}

#[cfg(test)]
fn scratch_missed() {
    SCRATCH_MISSES.with(|m| m.set(m.get() + 1));
}

/// Re-entrant takes on this thread that found their slot held (tests only).
#[cfg(test)]
pub(crate) fn scratch_misses() -> usize {
    SCRATCH_MISSES.with(Cell::get)
}

#[cfg(not(test))]
const fn scratch_missed() {}

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
