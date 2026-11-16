// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Host-owned output buffers and the process-wide buffer pool (IF §10.1). W0-ABI stub: frozen signatures, `todo!()` bodies; W1-H1 fills it.

use core::marker::PhantomData;

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
    // W0-ABI: private fields (Vec<u64> backing, allocated zeroed (never resized in place), len, high_water,
    // max_out, class) land with W1-H1.
    _stub: PhantomData<()>,
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
    // W0-ABI: private fields (OutBuf, &'static Pool) land with W1-H1.
    _stub: PhantomData<()>,
}
impl PooledOut {
    pub fn bytes(&self) -> &[u8] {
        todo!()
    }
    // zeroes [0, high_water), len = 0
    pub fn reset(&mut self) {
        todo!()
    }
    /// Round 9: false for the empty handle (`PooledOut::default()`: no buffer, Drop does nothing, no queue op).
    pub fn is_held(&self) -> bool {
        todo!()
    }
}
// W0-ABI: `impl Writer for PooledOut` (crate::records::Writer) lands with W1-H1 (A3 one-impl rule: the IF's
// other Writer impls live in records.rs).
// W0-ABI: `impl Drop for PooledOut` (zero `[0, high_water)`, release to its current class) lands with W1-H1.

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
    // W0-ABI: private fields ([ArrayQueue<OutBuf>; 4], counters) land with W1-H1 (crossbeam-queue is not a
    // wave-0 dependency).
    _stub: PhantomData<()>,
}
impl Pool {
    /// Set once at boot, before the first acquire (later calls are ignored and logged).
    pub fn init_global(caps: PoolCaps) {
        let _ = caps;
        todo!()
    }
    pub fn global() -> &'static Pool {
        todo!()
    }
    pub fn acquire(&'static self, max_out: usize) -> PooledOut {
        let _ = max_out;
        todo!()
    }
    pub fn misses(&self) -> u64 {
        todo!()
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
    let _ = (max_out, f);
    todo!()
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
        let _ = max_out;
        todo!()
    }
    /// Idempotent: acquires `out[1]` and `results` (class fitting `max_out`'s first class) if not held.
    pub fn on_need(&mut self, max_out: usize) {
        let _ = max_out;
        todo!()
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
