// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Host-owned output buffers and the process-wide buffer pool (IF §10.1; W1-H1).
//!
//! UNSAFE-MIN r3.1 (owner-approved, later than the IF): an entry's out buffer reaches the plugin only as a
//! busbar-ffi `OutLease`, which owns a `Vec<u8>` for the entry and does `grow` itself. So an `OutBuf` is backed
//! by a `Vec<u8>` allocated zeroed over its whole length (`vec![0u8; cap]` is `alloc_zeroed`), where the IF wrote
//! `Vec<u64>`: the records reader copies every Pod out (`read_from_prefix`), so no reader relies on the 8-byte
//! alignment, and a `Vec<u64>` cannot be handed to busbar-ffi without a copy. `PooledOut::lend` moves the buffer
//! into the lease for one entry and takes it back after (`OutLease::into_buf`), applying the plugin-stated length
//! through the H1/H2 clamp. The buffer's length is its capacity (`own_cap`, host state); nothing here calls
//! `with_capacity`, `reserve`, `set_len` or `MaybeUninit` (C-ZEROIZE-FRESH).

use core::cell::RefCell;
use core::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

use busbar_ffi::host::OutLease;
use crossbeam_queue::ArrayQueue;

use crate::records::{
    Full, Nested, Pod, RawWrite, Writer, put_fact_in, put_fact_text_in, put_metric_in,
    put_nested_in, put_pair_in, put_parts, put_prefixed_nested_in,
};

/// The four class sizes (§10.1): 4 KiB, 64 KiB, 1 MiB, 16 MiB.
pub(crate) const CLASSES: [usize; 4] = [4 << 10, 64 << 10, 1 << 20, 16 << 20];

/// The class whose size is exactly `cap`, if any.
fn class_of(cap: usize) -> Option<usize> {
    CLASSES.iter().position(|&size| size == cap)
}

/// Zeroes `bytes` with stores the optimiser cannot drop before a free (the block may be released next).
fn wipe(bytes: &mut [u8]) {
    bytes.fill(0);
    core::hint::black_box(&*bytes);
}

/// Host-owned, 8-aligned. `max_out` from describe, clamped. Tracks a high-water mark of bytes written since the
/// last reset: by the host directly, and by the plugin as the host learns it (`out.len` on every return,
/// `len + need` on every `grow`). **Round 13 (r4 H1/H2), the mark is the host's, never the plugin's:** every
/// update is `high_water = min(own_cap, max(high_water, min(v, own_cap)))`, where `own_cap` is this buffer's
/// capacity from host state (never `out.cap`) and `v` is the plugin-stated value: `out.len` on return, or
/// `len.checked_add(need)` on `grow` (an overflow is treated as `own_cap`). A `grow` refused over max_out, or one
/// whose `checked_add` overflowed, still applies that update (so `high_water ≤ own_cap`) and changes nothing
/// else. Every zeroing below covers `[0, min(high_water, own_cap))` and nothing past it, so no plugin-written
/// value can make the host write outside its own allocation. abi's plugin-side Writer only appends, and on `Err` the shim zeroes what it
/// wrote before `len = 0` (§6.4 step 2), so `[high_water, cap)` holds no byte written since the last zeroing
/// (round 6: the capacity is never counted as exposed, so zeroing stays O(bytes written)). Implements `Writer` (so the §8.8 encoders write into it). Capacity is always one of
/// the four class sizes (4 KiB, 64 KiB, 1 MiB, 16 MiB) or, above 16 MiB (store only, ≤ max_out), exact.
/// **Growth** (Host::grow, a Writer write past capacity, NeedOut appends): take a buffer of the smallest class
/// that fits `len + need` from the pool (or allocate one), copy `[0, min(len, own_cap))`, zero the old buffer over
/// `[0, high_water)`, release the old buffer to its own class queue, carry `high_water = min(len, own_cap)` over.
/// Never `Vec::reserve`/`realloc` (I11). Over max_out: no growth, `grow` returns false.
/// **Round 23 (binding r4 H2, ABI-DECISION.md:215 "zero-initialized on growth, so no uninitialised byte is ever
/// read"), normative: every OutBuf allocation is zeroed over its whole capacity** (`vec![0u64; cap / 8]`, which
/// is `alloc_zeroed`: fresh pages from the OS cost no write), on a pool miss, on growth into a class whose queue
/// is empty, and for the exact-size store buffers above 16 MiB. `Vec::with_capacity` (or `set_len`, or
/// `MaybeUninit` storage) exposed as `cap` is forbidden: the host parses `[0, min(out.len, own_cap))` with
/// `out.len` set by the plugin, and only `[0, high_water)` is ever re-zeroed, so the claims below that
/// `[high_water, cap)` holds no byte written since the last zeroing and that no stale byte can be parsed hold
/// only because every block starts all zero and every reuse re-zeroes what was written. A plugin that answers
/// `len = cap` without writing makes the host read zeros, never old heap (another request's credential) and never
/// uninitialised memory (UB). C-ZEROIZE-FRESH (§14).
pub struct OutBuf {
    /// The block; its length is its capacity (`own_cap`) and every byte of it was initialised to zero.
    buf: Vec<u8>,
    /// Bytes written (host) or stated (plugin, clamped to `own_cap`).
    len: usize,
    /// The furthest byte written or exposed since the last zeroing, never past `own_cap`.
    high_water: usize,
    max_out: usize,
}

impl OutBuf {
    /// A fresh block of `cap` bytes, all zero.
    fn zeroed(cap: usize, max_out: usize) -> OutBuf {
        OutBuf {
            buf: vec![0u8; cap],
            len: 0,
            high_water: 0,
            max_out,
        }
    }

    fn cap(&self) -> usize {
        self.buf.len()
    }

    /// `high_water = min(own_cap, max(high_water, min(v, own_cap)))` (round 13).
    fn raise(&mut self, v: usize) {
        let cap = self.cap();
        self.high_water = self.high_water.max(v.min(cap)).min(cap);
    }

    /// Zeroes `[0, min(max(len, high_water), own_cap))` and empties the buffer.
    fn clear(&mut self) {
        let end = self.len.max(self.high_water).min(self.cap());
        if let Some(touched) = self.buf.get_mut(..end) {
            wipe(touched);
        }
        self.len = 0;
        self.high_water = 0;
    }
}

/// A pooled OutBuf. Drop zeroes `[0, high_water)` (I11: credentials pass through every kind's buffers — WRITE
/// args, FETCH headers, SET_HEADER, STATE, STORE values; O(bytes written)) and releases it to the queue of
/// **its current class** (a buffer that grew is in the larger class's queue, never the class it started in),
/// from whatever thread drops it. A buffer never exposes bytes past its own capacity (the host reads
/// `min(out.len, own_cap)`, r4 H2; `own_cap` from host state), so neither stale bytes nor memory past the block
/// can be parsed. Every PooledOut handed to an
/// entry has ≥ 4 KiB capacity, so a FAIL record always fits (§3.2).
#[derive(Default)]
pub struct PooledOut {
    buf: Option<OutBuf>,
    /// The pool it returns to (`Pool::global()` when none: a handle built by `Default` holds no buffer).
    pool: Option<&'static Pool>,
}
impl PooledOut {
    /// The empty handle, usable in a `const` thread-local.
    pub(crate) const fn empty() -> PooledOut {
        PooledOut {
            buf: None,
            pool: None,
        }
    }

    pub fn bytes(&self) -> &[u8] {
        match &self.buf {
            Some(held) => held.buf.get(..held.len.min(held.cap())).unwrap_or(&[]),
            None => &[],
        }
    }
    // zeroes [0, high_water), len = 0
    pub fn reset(&mut self) {
        if let Some(held) = &mut self.buf {
            held.clear();
        }
    }
    /// Appends `bytes` as they are, no record head: a request argument the interface states as plain bytes (a
    /// store `clock`'s 16-byte dataset, ABI-MIN3-INTERFACE §8.8). Full: nothing changed.
    pub fn put_bytes(&mut self, bytes: &[u8]) -> Result<(), Full> {
        self.room(bytes.len())?;
        self.append(bytes);
        Ok(())
    }
    /// Round 9: false for the empty handle (`PooledOut::default()`: no buffer, Drop does nothing, no queue op).
    pub fn is_held(&self) -> bool {
        self.buf.is_some()
    }
    /// The buffer's own capacity (host state, `own_cap`); 0 for the empty handle.
    pub fn capacity(&self) -> usize {
        self.buf.as_ref().map_or(0, OutBuf::cap)
    }
    /// The whole block, `[0, own_cap)`: a host-side view for the zeroing checks (C-ZEROIZE*). Never handed to
    /// a plugin and never parsed: answers are read through `bytes()`.
    pub fn whole(&self) -> &[u8] {
        self.buf
            .as_ref()
            .map_or(&[][..], |held| held.buf.as_slice())
    }

    /// Sets the growth cap (describe's `max_out`, clamped by core) for the next use.
    pub(crate) fn set_max_out(&mut self, max_out: usize) {
        if let Some(held) = &mut self.buf {
            held.max_out = max_out;
        }
    }

    /// Lends the buffer to one entry as busbar-ffi's `OutLease` (which zero-fills it and grows it within
    /// `max_out`), runs `call`, and takes the buffer back with the plugin-stated length clamped to the
    /// buffer's own capacity (r4 H2; round 13's mark update). None: the handle is empty, or the thread's ACTIVE
    /// stack is full (busbar-ffi `DEPTH`); the buffer is then gone (zeroed by the lease) and the handle empty.
    /// If `call` unwinds, the lease's Drop zeroes the buffer and the handle stays empty.
    pub(crate) fn lend<R>(&mut self, call: impl FnOnce(&mut OutLease) -> R) -> Option<R> {
        let mut held = self.buf.take()?;
        let block = core::mem::take(&mut held.buf);
        let mut lease = OutLease::new(block, held.max_out)?;
        let answer = call(&mut lease);
        let (block, len) = lease.into_buf();
        held.buf = block;
        held.len = len.min(held.cap());
        held.high_water = 0;
        held.raise(len);
        self.buf = Some(held);
        Some(answer)
    }

    fn pool(&self) -> &'static Pool {
        self.pool.unwrap_or_else(Pool::global)
    }

    /// Up to `n` writable bytes after the written ones (grown like any write, within max_out), counted as
    /// exposed (the mark covers them) so a handler that writes into them and commits less still has every
    /// byte it wrote zeroed. None: no room even for one byte.
    pub(crate) fn spare(&mut self, n: usize) -> Option<&mut [u8]> {
        let room = self.capacity().saturating_sub(self.written());
        let n = if n > room && self.room(n).is_err() {
            room
        } else {
            n
        };
        let held = self.buf.as_mut()?;
        let end = held.len.checked_add(n)?;
        held.raise(end);
        held.buf.get_mut(held.len..end)
    }
    /// Counts `n` bytes of the last `spare` as written.
    pub(crate) fn commit(&mut self, n: usize) {
        if let Some(held) = self.buf.as_mut() {
            held.len = (held.len + n).min(held.high_water);
        }
    }
}

impl RawWrite for PooledOut {
    fn written(&self) -> usize {
        self.buf.as_ref().map_or(0, |held| held.len)
    }
    /// Growth (§10.1): the smallest class that fits `len + need` (or an exact zeroed block above 16 MiB), the
    /// written bytes copied over, the old block zeroed over what was written and released to its own class.
    /// Never `reserve`/`realloc` (I11). Over max_out: Full, nothing changed. An empty handle has no room.
    fn room(&mut self, need: usize) -> Result<(), Full> {
        let pool = self.pool();
        let held = self.buf.as_mut().ok_or(Full)?;
        let want = held.len.checked_add(need).ok_or(Full)?;
        if want <= held.cap() {
            return Ok(());
        }
        if want > held.max_out {
            return Err(Full);
        }
        let mut grown = pool.take(want, held.max_out);
        if let (Some(dst), Some(src)) = (grown.buf.get_mut(..held.len), held.buf.get(..held.len)) {
            dst.copy_from_slice(src);
        }
        grown.len = held.len;
        grown.raise(held.len);
        let old = core::mem::replace(held, grown);
        pool.release(old);
        Ok(())
    }
    fn append(&mut self, bytes: &[u8]) {
        let Some(held) = self.buf.as_mut() else {
            assert!(bytes.is_empty(), "a write into an empty PooledOut");
            return;
        };
        let end = held.len + bytes.len();
        let Some(dst) = held.buf.get_mut(held.len..end) else {
            panic!("a record write past the room it made");
        };
        dst.copy_from_slice(bytes);
        held.len = end;
        held.raise(end);
    }
    fn patch(&mut self, at: usize, bytes: &[u8]) {
        if let Some(held) = self.buf.as_mut() {
            let end = at + bytes.len();
            assert!(end <= held.len, "a patch past the written bytes");
            if let Some(dst) = held.buf.get_mut(at..end) {
                dst.copy_from_slice(bytes);
            }
        }
    }
    fn truncate(&mut self, len: usize) {
        if let Some(held) = self.buf.as_mut() {
            if let Some(tail) = held.buf.get_mut(len..held.len) {
                wipe(tail);
            }
            held.len = held.len.min(len);
        }
    }
}

/// Every write goes through records.rs's own sink helpers, in place: a whole record (`put_parts`), or a nested
/// record opened, filled and back-patched in this buffer (`put_nested_in`, `put_metric_in`), with no scratch
/// allocation on the §8.8 encoder path. A nested write that runs out of room is truncated, which zeroes it.
impl Writer for PooledOut {
    fn put_parts(&mut self, tag: u16, parts: &[&[u8]]) -> Result<(), Full> {
        put_parts(self, tag, parts)
    }
    fn put_pod_nested<T: Pod>(
        &mut self,
        tag: u16,
        prefix: &T,
        fill: impl FnOnce(&mut Nested<'_>) -> Result<(), Full>,
    ) -> Result<(), Full> {
        put_prefixed_nested_in(self, tag, prefix.as_bytes(), fill)
    }
    fn put(&mut self, tag: u16, body: &[u8]) -> Result<(), Full> {
        put_parts(self, tag, &[body])
    }
    fn put_u32s(
        &mut self,
        tag: u16,
        fill: impl FnOnce(&mut crate::records::U32s<'_>) -> Result<(), Full>,
    ) -> Result<(), Full> {
        crate::records::put_u32s_in(self, tag, fill)
    }
    fn put_pod<T: Pod>(&mut self, tag: u16, v: &T) -> Result<(), Full> {
        put_parts(self, tag, &[v.as_bytes()])
    }
    fn put_pod_tail<T: Pod>(&mut self, tag: u16, v: &T, tail: &[u8]) -> Result<(), Full> {
        put_parts(self, tag, &[v.as_bytes(), tail])
    }
    fn put_text(&mut self, tag: u16, s: &str) -> Result<(), Full> {
        put_parts(self, tag, &[s.as_bytes()])
    }
    fn put_pair(&mut self, tag: u16, name: &str, value: &[u8]) -> Result<(), Full> {
        put_pair_in(self, tag, name, value)
    }
    fn put_fact(&mut self, key: u32, value: u64) -> Result<(), Full> {
        put_fact_in(self, key, value)
    }
    fn put_fact_text(&mut self, key: u32, value: &str) -> Result<(), Full> {
        put_fact_text_in(self, key, value)
    }
    fn put_metric(&mut self, id: u32, op: u32, value: f64, labels: &[&str]) -> Result<(), Full> {
        put_metric_in(self, id, op, value, labels)
    }
    fn put_nested(
        &mut self,
        tag: u16,
        f: impl FnOnce(&mut Nested<'_>) -> Result<(), Full>,
    ) -> Result<(), Full> {
        put_nested_in(self, tag, f)
    }
}

impl Drop for PooledOut {
    fn drop(&mut self) {
        if let Some(held) = self.buf.take() {
            self.pool().release(held);
        }
    }
}

/// Pool sizing. `inflight` = the number of concurrently live async chains the pool keeps allocation-free
/// (config `plugins.pool.inflight`, default 1,024; boot sets it ≥ the connector's request concurrency limit).
/// Each live chain holds at most 4 buffers (§10.1 ChainBufs; round 9: 2 until its first NEED), almost always class 0.
/// Queue capacities: class 0 (4 KiB) = 4 × inflight; class 1 (64 KiB) = inflight / 4; class 2 (1 MiB) = 16;
/// class 3 (16 MiB) = 2. Retained bytes are therefore bounded: at the default 16 MiB + 16 MiB + 16 MiB + 32 MiB
/// = 80 MiB worst case, and only what was actually used (buffers are allocated lazily, on a miss).
#[derive(Clone, Copy, Debug)]
pub struct PoolCaps {
    pub inflight: u32,
}
impl Default for PoolCaps {
    fn default() -> Self {
        PoolCaps { inflight: 1024 }
    }
}

/// The process-wide buffer pool: one bounded lock-free MPMC queue (`crossbeam_queue::ArrayQueue<OutBuf>`,
/// AGREED 209: a crate, not ours) per size class, capacities from PoolCaps. acquire = one pop of the class that
/// fits (a miss allocates, zeroed over the whole capacity, round 23: warm-up, or more than `inflight` chains
/// live; counted in `plugin_pool_miss_total`);
/// release = zero the prefix, then one push to the buffer's current class, or free the buffer when that queue
/// is full (counted in `plugin_pool_drop_total`). Buffers carry no thread affinity, so a chain that starts on
/// worker A and ends on worker B returns its buffers to the shared queue. Buffers above 16 MiB are never pooled.
pub struct Pool {
    queues: [ArrayQueue<OutBuf>; 4],
    misses: AtomicU64,
    drops: AtomicU64,
}

static GLOBAL: OnceLock<Pool> = OnceLock::new();

/// C-CANCEL-OPEN (IF §14 round 8: "a pool instrumented to record acquire/release"): one block leaving or coming
/// back to a pool, as the process's [`observe_pool`] observer sees it, on the thread that moved it.
#[derive(Clone, Copy, Debug)]
pub enum PoolEvent<'a> {
    /// A block left the pool for an acquire or a growth (popped, or allocated zeroed on a miss): its address.
    Taken { block: usize },
    /// A block came back: its address and its whole bytes, after the release zeroed what it exposed and before it
    /// is pushed to its queue or freed.
    Released { block: usize, bytes: &'a [u8] },
}

static OBSERVER: OnceLock<for<'a> fn(PoolEvent<'a>)> = OnceLock::new();

/// Installs the process's one pool observer (a conformance probe: production installs none, and every take and
/// release then costs one load). The first call wins; later ones are ignored.
pub fn observe_pool(observer: for<'a> fn(PoolEvent<'a>)) {
    let _ = OBSERVER.set(observer);
}

impl Pool {
    /// A pool sized by `caps` (tests build their own and leak it; production has the one global).
    pub(crate) fn new(caps: PoolCaps) -> Pool {
        let inflight = usize::try_from(caps.inflight).unwrap_or(usize::MAX).max(1);
        Pool {
            queues: [
                ArrayQueue::new(inflight.saturating_mul(4)),
                ArrayQueue::new((inflight / 4).max(1)),
                ArrayQueue::new(16),
                ArrayQueue::new(2),
            ],
            misses: AtomicU64::new(0),
            drops: AtomicU64::new(0),
        }
    }
    /// Set once at boot, before the first acquire (later calls are ignored and logged).
    ///
    /// W1-H1: the abi crate has no logger of its own, so "logged" is the caller's: this answers nothing and the
    /// registry, which calls it once from `Registry::new`, can compare `Pool::global()`'s queue sizes (no API
    /// call in the hot path depends on which call won).
    pub fn init_global(caps: PoolCaps) {
        let _ = GLOBAL.set(Pool::new(caps));
    }
    pub fn global() -> &'static Pool {
        GLOBAL.get_or_init(|| Pool::new(PoolCaps::default()))
    }
    pub fn acquire(&'static self, max_out: usize) -> PooledOut {
        PooledOut {
            buf: Some(self.take(CLASSES[0], max_out)),
            pool: Some(self),
        }
    }
    /// A buffer holding `bytes` verbatim (an `open` request: the bound config is not a record frame), growing up
    /// to `max_out`. Full when `bytes` does not fit.
    pub fn acquire_with(
        &'static self,
        max_out: usize,
        bytes: &[u8],
    ) -> Result<PooledOut, crate::records::Full> {
        let mut out = self.acquire(max_out);
        out.room(bytes.len())?;
        out.append(bytes);
        Ok(out)
    }
    pub fn misses(&self) -> u64 {
        self.misses.load(Ordering::Relaxed)
    }
    /// Buffers freed because their class queue was full, or because they are not a class size (above 16 MiB, or
    /// a block busbar-ffi's `grow` sized): `plugin_pool_drop_total`.
    pub fn drops(&self) -> u64 {
        self.drops.load(Ordering::Relaxed)
    }

    /// A block of the smallest class that fits `want` (one pop; a miss allocates it zeroed), or an exact zeroed
    /// block above 16 MiB (never pooled). Every block comes back with `len = high_water = 0`.
    fn take(&self, want: usize, max_out: usize) -> OutBuf {
        let buf = match CLASSES.iter().position(|&size| size >= want) {
            None => OutBuf::zeroed(want.next_multiple_of(8), max_out),
            Some(class) => match self.queues.get(class).and_then(ArrayQueue::pop) {
                Some(mut buf) => {
                    buf.max_out = max_out;
                    buf
                }
                None => {
                    self.misses.fetch_add(1, Ordering::Relaxed);
                    OutBuf::zeroed(CLASSES[class], max_out)
                }
            },
        };
        if let Some(observer) = OBSERVER.get() {
            observer(PoolEvent::Taken {
                block: buf.buf.as_ptr().addr(),
            });
        }
        buf
    }

    /// Zeroes what the block exposed, then one push to its current class; a full queue, or a block of no class,
    /// frees it.
    fn release(&self, mut buf: OutBuf) {
        buf.clear();
        if let Some(observer) = OBSERVER.get() {
            observer(PoolEvent::Released {
                block: buf.buf.as_ptr().addr(),
                bytes: &buf.buf,
            });
        }
        let pushed = match class_of(buf.cap()).and_then(|class| self.queues.get(class)) {
            Some(queue) => queue.push(buf).is_ok(),
            None => false,
        };
        if !pushed {
            self.drops.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// One thread's two sync buffers, and whether a sync call on this thread holds them (C-NESTED).
struct SyncBufs {
    args: PooledOut,
    out: PooledOut,
    busy: bool,
}

std::thread_local! {
    /// The thread's sync buffers; their destructor zeroes and releases both at thread exit (PooledOut's Drop).
    static SYNC: RefCell<SyncBufs> = const {
        RefCell::new(SyncBufs { args: PooledOut::empty(), out: PooledOut::empty(), busy: false })
    };
}

/// Hands a sync call's two buffers back after the call, on return and on unwind: both reset, a buffer that grew
/// past class 1 swapped for a class-0 one, the thread's holder marked free.
struct SyncLoan {
    args: PooledOut,
    out: PooledOut,
}

impl Drop for SyncLoan {
    fn drop(&mut self) {
        let mut args = core::mem::take(&mut self.args);
        let mut out = core::mem::take(&mut self.out);
        for buf in [&mut args, &mut out] {
            buf.reset();
            if buf.capacity() > CLASSES[1] {
                *buf = PooledOut::empty();
            }
        }
        let _ = SYNC.try_with(|cell| {
            let mut bufs = cell.borrow_mut();
            bufs.args = args;
            bufs.out = out;
            bufs.busy = false;
        });
    }
}

/// Sync calls: each thread keeps two PooledOuts in a thread-local for its sync entries (a sync call never
/// crosses a thread, I5): `args` for a records argument core encodes (hook view, render arg, transport event)
/// and `out` for the answer. Taken from `Pool::global()` once; no queue op per sync call. A thread-local buffer
/// that grew past class 1 is released and replaced by a class-0 buffer after the call, so no thread pins 16 MiB.
/// **Per-call zeroing (round 6, I11):** when `f` returns (so every `Answer` borrowing `out` is gone, which the
/// borrow checker enforces), both buffers are `reset()`: zero `[0, min(max(len, high_water), own_cap))` and `len = 0`, where
/// `high_water` is the furthest byte this call wrote or exposed through `grow` (reset to 0 by `reset`). That is
/// O(bytes the call touched), never the 4 KiB capacity: a no-op `verify` answer zeroes about 100 bytes, inside
/// the 22 ns gate. A failed call's discarded bytes were already zeroed plugin-side (§6.4 step 2), so a credential
/// a sync method wrote never outlives its call in either case. The thread-local holder's destructor zeroes and
/// releases both on thread exit. Nested sync entries on one thread (C-NESTED) take fresh buffers from the pool
/// instead (zeroed on Drop as usual).
pub fn sync_bufs<R>(
    max_out: usize,
    f: impl FnOnce(&mut PooledOut /* args */, &mut PooledOut /* out */) -> R,
) -> R {
    let loaned = SYNC
        .try_with(|cell| {
            let mut bufs = cell.borrow_mut();
            if bufs.busy {
                return None;
            }
            bufs.busy = true;
            Some((
                core::mem::take(&mut bufs.args),
                core::mem::take(&mut bufs.out),
            ))
        })
        .ok()
        .flatten();
    let Some((args, out)) = loaned else {
        // Nested (or the thread is exiting): fresh buffers, zeroed and released on drop.
        let mut args = Pool::global().acquire(max_out);
        let mut out = Pool::global().acquire(max_out);
        return f(&mut args, &mut out);
    };
    let mut loan = SyncLoan { args, out };
    for buf in [&mut loan.args, &mut loan.out] {
        if !buf.is_held() {
            *buf = Pool::global().acquire(max_out);
        }
        buf.set_max_out(max_out);
    }
    f(&mut loan.args, &mut loan.out)
}

/// The buffers one async chain owns, all from `Pool::global()`: `req` (the §8.8 request records), `out` (two,
/// ping-pong) and `results` (NEED_RES). **Round 9: at most 4, lazily.** `acquire` pops `req` and `out[0]` only
/// (2 queue ops); `out[1]` and `results` stay empty handles until the driver's first NEED calls `on_need`, which
/// pops both (2 more). A never-NEED chain therefore does 2 pops at start and 2 pushes at drop. Empty handles drop
/// as no-ops, so every Drop order of §10.5 is unchanged.
// Default: four empty handles.
#[derive(Default)]
pub struct ChainBufs {
    pub req: PooledOut,
    pub out: [PooledOut; 2],
    pub results: PooledOut,
}
impl ChainBufs {
    pub fn acquire(max_out: usize) -> Self {
        let pool = Pool::global();
        ChainBufs {
            req: pool.acquire(max_out),
            out: [pool.acquire(max_out), PooledOut::empty()],
            results: PooledOut::empty(),
        }
    }
    /// Idempotent: acquires `out[1]` and `results` (class fitting `max_out`'s first class) if not held.
    pub fn on_need(&mut self, max_out: usize) {
        let pool = Pool::global();
        for buf in [&mut self.out[1], &mut self.results] {
            if !buf.is_held() {
                *buf = pool.acquire(max_out);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::records::{Records, tag};

    /// A pool of its own, so counters and queues are this test's alone.
    fn pool(inflight: u32) -> &'static Pool {
        Box::leak(Box::new(Pool::new(PoolCaps { inflight })))
    }

    fn all_zero(bytes: &[u8]) -> bool {
        bytes.iter().all(|&b| b == 0)
    }

    #[test]
    fn flat_words_rollback_in_the_real_pooled_sink() {
        let mut out = PooledOut {
            buf: Some(OutBuf::zeroed(20, 20)),
            pool: Some(pool(1)),
        };
        out.put(tag::TEXT, b"").unwrap();
        let prefix = out.bytes().to_vec();
        assert!(
            out.put_u32s(0x101, |words| {
                words.push(7)?;
                assert!(words.push(8).is_err());
                Ok(())
            })
            .is_err()
        );
        assert_eq!(out.bytes(), prefix);
        assert!(all_zero(&out.whole()[prefix.len()..]));
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = out.put_u32s(0x101, |words| {
                words.push(9)?;
                std::panic::panic_any(())
            });
        }));
        assert!(result.is_err());
        assert_eq!(out.bytes(), prefix);
        assert!(all_zero(&out.whole()[prefix.len()..]));
    }

    #[test]
    fn a_fresh_buffer_is_class_zero_empty_and_all_zero() {
        let pool = pool(4);
        let buf = pool.acquire(1 << 20);
        assert!(buf.is_held());
        assert_eq!(buf.capacity(), CLASSES[0]);
        assert!(buf.bytes().is_empty());
        assert!(
            all_zero(buf.whole()),
            "a miss is allocated zeroed over its whole capacity"
        );
        assert_eq!(pool.misses(), 1);
        let empty = PooledOut::default();
        assert!(!empty.is_held());
        assert_eq!(empty.capacity(), 0);
        assert!(empty.bytes().is_empty() && empty.whole().is_empty());
    }

    #[test]
    fn a_released_buffer_comes_back_zeroed_from_its_own_queue() {
        let pool = pool(4);
        let mut buf = pool.acquire(1 << 20);
        buf.put(tag::TEXT, b"a credential that must not outlive the call")
            .expect("fits");
        assert!(!buf.bytes().is_empty());
        drop(buf);
        let again = pool.acquire(1 << 20);
        assert_eq!(
            pool.misses(),
            1,
            "the second acquire reused the released block"
        );
        assert!(again.bytes().is_empty());
        assert!(all_zero(again.whole()), "release zeroed every written byte");
    }

    #[test]
    fn growth_walks_the_classes_copies_what_was_written_and_frees_only_zeroed_blocks() {
        let pool = pool(4);
        let mut buf = pool.acquire(64 << 20);
        let chunk = vec![0xA5u8; 60 << 10];
        let mut written = 0usize;
        let mut caps = Vec::new();
        while buf.capacity() < CLASSES[3] {
            buf.put(tag::TEXT, &chunk).expect("under max_out");
            written += 1;
            caps.push(buf.capacity());
            let len = buf.bytes().len();
            assert!(
                all_zero(&buf.whole()[len..]),
                "past the written bytes the block is zero"
            );
        }
        assert!(caps.contains(&CLASSES[1]) && caps.contains(&CLASSES[2]));
        let texts = Records::new(buf.bytes())
            .map(|rec| rec.expect("framed"))
            .filter(|rec| rec.tag == tag::TEXT && rec.body == chunk.as_slice())
            .count();
        assert_eq!(texts, written, "every record survived every copy");
        // Each outgrown block went back to its own class queue, zeroed.
        for (class, &size) in CLASSES.iter().enumerate().take(3) {
            let reused = pool.take(size, 1 << 20);
            assert_eq!(reused.cap(), size);
            assert!(
                all_zero(&reused.buf),
                "class {class} block was zeroed before release"
            );
        }
    }

    #[test]
    fn a_write_past_max_out_is_full_and_changes_nothing() {
        let pool = pool(4);
        let mut buf = pool.acquire(CLASSES[0]);
        buf.put(tag::TEXT, &[1u8; 3000])
            .expect("fits the first block");
        let before = buf.bytes().to_vec();
        assert!(
            buf.put(tag::TEXT, &[2u8; 3000]).is_err(),
            "max_out is 4 KiB"
        );
        assert_eq!(buf.bytes(), before.as_slice());
        assert_eq!(buf.capacity(), CLASSES[0], "no growth over max_out");
    }

    #[test]
    fn a_full_queue_frees_the_block_and_counts_it() {
        let pool = pool(1); // class 0 holds 4
        let bufs: Vec<PooledOut> = (0..5).map(|_| pool.acquire(1 << 20)).collect();
        drop(bufs);
        assert_eq!(pool.drops(), 1);
        assert_eq!(pool.misses(), 5);
    }

    #[test]
    fn reset_zeroes_what_was_written_and_empties() {
        let pool = pool(4);
        let mut buf = pool.acquire(1 << 20);
        buf.put(tag::TEXT, b"secret").expect("fits");
        buf.reset();
        assert!(buf.bytes().is_empty());
        assert!(all_zero(buf.whole()));
        assert_eq!(buf.capacity(), CLASSES[0]);
    }

    #[test]
    fn truncate_zeroes_the_cut_tail() {
        let pool = pool(4);
        let mut buf = pool.acquire(1 << 20);
        buf.put(tag::TEXT, b"keep").expect("fits");
        let keep = buf.written();
        buf.put(tag::TEXT, b"drop this credential").expect("fits");
        buf.truncate(keep);
        assert_eq!(buf.written(), keep);
        assert!(all_zero(&buf.whole()[keep..]));
    }

    #[test]
    fn nested_and_framed_writes_parse_back() {
        let pool = pool(4);
        let mut buf = pool.acquire(1 << 20);
        buf.put_pair(tag::PAIR, "name", b"value").expect("pair");
        buf.put_fact(7, 9).expect("fact");
        buf.put_metric(3, 1, 2.5, &["a", "b"]).expect("metric");
        buf.put_nested(tag::TEXT, |n| n.put(tag::TEXT, b"inner"))
            .expect("nested");
        let tags: Vec<u16> = Records::new(buf.bytes())
            .map(|rec| rec.expect("framed").tag)
            .collect();
        assert_eq!(tags, [tag::PAIR, tag::FACT, tag::METRIC, tag::TEXT]);
        let pair = Records::new(buf.bytes())
            .next()
            .and_then(Result::ok)
            .and_then(|rec| rec.pair().ok());
        assert_eq!(pair, Some(("name", &b"value"[..])));
    }

    #[test]
    fn nested_writes_in_place_match_the_reply_encoding_and_a_full_one_leaves_nothing() {
        let pool = pool(4);
        let mut buf = pool.acquire(1 << 20);
        let mut reply = crate::records::Reply::new();
        buf.put_metric(3, 1, 2.5, &["a", "b"]).expect("metric");
        reply.put_metric(3, 1, 2.5, &["a", "b"]).expect("metric");
        buf.put_nested(tag::TEXT, |n| {
            n.put(tag::TEXT, b"inner")?;
            n.put_nested(tag::TEXT, |m| m.put_fact(7, 9))
        })
        .expect("nested");
        reply
            .put_nested(tag::TEXT, |n| {
                n.put(tag::TEXT, b"inner")?;
                n.put_nested(tag::TEXT, |m| m.put_fact(7, 9))
            })
            .expect("nested");
        assert_eq!(
            buf.bytes(),
            reply.as_bytes(),
            "the same records, byte for byte"
        );

        let mut small = pool.acquire(CLASSES[0]);
        small.put(tag::TEXT, b"keep").expect("fits");
        let keep = small.bytes().to_vec();
        let full = small.put_nested(tag::TEXT, |n| n.put(tag::TEXT, &[0xA5u8; 8 << 10]));
        assert!(full.is_err(), "max_out is 4 KiB");
        assert_eq!(
            small.bytes(),
            keep.as_slice(),
            "the half-written record is gone"
        );
        assert!(
            all_zero(&small.whole()[keep.len()..]),
            "and its bytes were zeroed"
        );
    }

    #[test]
    fn a_lent_buffer_comes_back_with_its_capacity() {
        let mut buf = Pool::global().acquire(1 << 20);
        let cap = buf.capacity();
        assert_eq!(buf.lend(|lease| lease.len()), Some(0));
        assert_eq!(buf.capacity(), cap);
        assert!(buf.bytes().is_empty());
        assert!(all_zero(buf.whole()));
        assert_eq!(
            PooledOut::default().lend(|_| ()),
            None,
            "an empty handle lends nothing"
        );
    }

    #[test]
    fn sync_buffers_are_reset_after_every_call_and_after_an_unwind() {
        sync_bufs(1 << 20, |args, out| {
            args.put(tag::TEXT, b"hook view").expect("fits");
            out.put(tag::TEXT, b"a credential").expect("fits");
        });
        sync_bufs(1 << 20, |args, out| {
            assert!(args.bytes().is_empty() && out.bytes().is_empty());
            assert!(all_zero(args.whole()) && all_zero(out.whole()));
        });
        let unwound = std::panic::catch_unwind(|| {
            sync_bufs(1 << 20, |_, out| {
                out.put(tag::TEXT, b"written before the panic")
                    .expect("fits");
                panic!("a host-side panic mid-call");
            })
        });
        assert!(unwound.is_err());
        sync_bufs(1 << 20, |_, out| {
            assert!(
                out.bytes().is_empty() && all_zero(out.whole()),
                "reset on unwind too"
            );
        });
    }

    #[test]
    fn a_nested_sync_call_gets_fresh_buffers() {
        sync_bufs(1 << 20, |_, outer| {
            outer.put(tag::TEXT, b"outer").expect("fits");
            sync_bufs(1 << 20, |_, inner| {
                assert!(inner.bytes().is_empty());
                inner.put(tag::TEXT, b"inner").expect("fits");
            });
            let tags = Records::new(outer.bytes()).count();
            assert_eq!(tags, 1, "the nested call left the outer buffer intact");
        });
    }

    #[test]
    fn a_sync_buffer_that_grew_past_class_one_is_swapped_for_class_zero() {
        sync_bufs(64 << 20, |_, out| {
            out.put(tag::TEXT, &vec![1u8; CLASSES[1] + 1])
                .expect("grows");
            assert_eq!(out.capacity(), CLASSES[2]);
        });
        sync_bufs(64 << 20, |_, out| {
            assert_eq!(out.capacity(), CLASSES[0], "no thread pins a large block");
        });
    }

    #[test]
    fn chain_buffers_take_two_then_two_more_on_the_first_need() {
        let mut bufs = ChainBufs::acquire(1 << 20);
        assert!(bufs.req.is_held() && bufs.out[0].is_held());
        assert!(!bufs.out[1].is_held() && !bufs.results.is_held());
        bufs.on_need(1 << 20);
        assert!(bufs.out[1].is_held() && bufs.results.is_held());
        bufs.results.put(tag::TEXT, b"x").expect("fits");
        bufs.on_need(1 << 20);
        assert!(!bufs.results.bytes().is_empty(), "on_need is idempotent");
        let empty = ChainBufs::default();
        assert!(!empty.req.is_held() && !empty.out[0].is_held());
    }

    #[test]
    fn no_uninitialised_storage_in_this_file() {
        let source = include_str!("pool.rs");
        let code: String = source
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .take_while(|line| !line.starts_with("#[cfg(test)]"))
            .collect::<Vec<_>>()
            .join("\n");
        for banned in [
            "with_capacity",
            "set_len",
            "MaybeUninit",
            ".reserve(",
            "realloc",
        ] {
            assert!(!code.contains(banned), "pool.rs uses {banned}");
        }
    }
}
