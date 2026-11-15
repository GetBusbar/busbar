// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Slots: the one token table, shared by chains and sessions, and the plugin instance the shims build (IF §6.5). W0-ABI stub: frozen signatures, `todo!()` bodies; A3 fills it.
//!
//! W0-ABI: the IF declares `Slots`, its methods, `pack`, `unpack` and `Inst` `pub(crate)`. Nothing in the stub
//! crate calls them yet, so as `pub(crate)` they would be dead code (no `allow` is permitted); they are
//! `#[doc(hidden)] pub` here, and W1-A3 restores `pub(crate)` when its shims use them.

use core::marker::PhantomData;

use crate::types::Token;

/// Concurrent, generation-checked table. Lookup is lock-free with no RMW: one Acquire load of the slot
/// generation and a compare (I5). Insert and remove are lock-free: the free list is a Treiber stack whose head
/// is one `AtomicU64` packing (tag: u32, index: u32), with each free slot's `next` in an `AtomicU32`; pop and
/// push are one CAS each (uncontended in the common case), and the tag, bumped on every pop, rules out ABA.
/// There is no mutex, no live counter and no process-global RMW. Slot addresses never move: page p holds
/// 32 << p slots, allocated on first use (31 pages max; the only allocation, cold). Exclusive access to one
/// **live** slot's value is guaranteed by I6, which the host enforces with types (§10.4, §10.5): the plugin side
/// receives a live token only through an entry the host made while holding `&mut` to that token's handle.
/// **Round 14: a stale token is not covered by I6 and needs no exclusivity.** The host can hold a token whose slot
/// the shim already freed (a FAULT, §6.4 step 3), and a cancel with it may run on one thread while another thread
/// inserts a new chain into the same slot. The per-slot **state word** makes that sound:
///   `state: AtomicU32` = `(generation << 1) | occupied`, generation 31 bits, never 0.
/// - `insert`: pops a free slot (CAS on the free list; the popper now owns the slot exclusively), writes the value
///   into the slot's `UnsafeCell`, then **one Release store** `state = (gen << 1) | 1` with the generation the
///   slot already carries, and returns `(index, gen)`. No new RMW: I5's one CAS per insert is the pop.
/// - lookup (`get_mut`, the first step of `remove`): **one Acquire load** of `state` and one compare against
///   `(generation << 1) | 1`. A free slot (occupied bit 0), an older or newer generation, or an index past the
///   allocated pages is `None`, and the value cell is not touched.
/// - `remove`: on a match, moves the value out of the cell, then **one Release store** `state = (next(gen) << 1) | 0`
///   (`next` wraps 2^31-1 → 1) **before** the slot is pushed on the free list (one CAS, I5's one per remove). So by
///   the time any `insert` can pop the slot, every later lookup with the old `(index, gen)` fails, and the new
///   occupant's generation is `next(gen)`, never `gen`. A stale `remove` racing a fresh `insert` into the same
///   slot sees either occupied bit 0 or `next(gen)` and returns `None` without touching the cell (C-SLOT-STALE).
/// - The plain store in `remove` is enough (no CAS): a matching `remove` is the token's last entry and I6 gives it
///   exclusivity against every other entry **for that live token**; a stale entry never matches, so it never
///   writes. Wrap: a stale `(index, gen)` could match again only after 2^31-1 further remove cycles of that one
///   slot; the host never presents a stale chain token after FAULT (the driver zeroes it, §10.5), and the stated
///   residual is a forged token, which is FAULT-class plugin misuse bounded to that image (C-GEN-WRAP).
/// **Round 18 (I5, false sharing): every slot, and the free head, owns its own 128-byte line pair.** `Slot<T>` is
/// `#[repr(C, align(128))]`: a live session's lookup (the Acquire load of its `state`) and its plugin's per-call
/// writes of `S` never share a 64- or 128-byte line with another slot's `state`, `next` or value, so one worker's
/// session writes and a neighbour's open/end (the Release store of `state`, the value write, the `next` link) never
/// invalidate the line another worker loads on its 22 ns lookup. `free_head` is `FreeHead`
/// (`#[repr(align(128))]`), so the insert/remove CAS never shares the line of `pages` that every lookup reads.
/// Cost (stated, §16.150): `size_of::<Slot<T>>()` = round_up(8 + size_of::<T>(), 128), i.e. 128 B per slot for any
/// value ≤ 120 B (`ChainBox` is 8 B; a larger session state spans whole line pairs and is still never shared);
/// page 0 (32 slots) = 4 KiB per table, allocated on first use (the five sessionless kinds never allocate a
/// session page; a chain page only for NEEDing chains); 1,024 live sessions on one instance (pages 0-5, 2,016
/// slots) = 252 KiB per table, against 31.5 KiB at 16 B per slot unpadded. B-SYNC 16-thread's churn arm (§14)
/// measures it against an unpadded negative control.
// W0-ABI: `Default` is derived only so clippy's `new_without_default` stays quiet on the stub.
#[doc(hidden)]
#[derive(Default)]
pub struct Slots<T> {
    // W0-ABI: pages: [OnceLock<Box<[Slot<T>]>>; 31], free_head: FreeHead;
    //   #[repr(C, align(128))] Slot<T> { state: AtomicU32, next: AtomicU32, value: UnsafeCell<MaybeUninit<T>> };
    //   #[repr(align(128))] FreeHead(AtomicU64)  (private, W1-A3). The real table needs `unsafe impl Sync`
    //   (W1-A3, with its escape); `fn() -> T` keeps the stub Send + Sync so a `static` of it compiles.
    _stub: PhantomData<fn() -> T>,
}
impl<T: Send> Slots<T> {
    // W0-ABI: a real (empty) body, not `todo!()`: `plugin!` builds `static GLOBAL: Slots<ChainBox>` from it.
    #[doc(hidden)]
    pub const fn new() -> Self {
        Slots { _stub: PhantomData }
    }
    /// Returns (index, generation). generation is 31 bits and never 0; it starts at 1 on a fresh slot, is advanced
    /// only by `remove` (round 14), wraps from 2^31-1 to 1 and is used only inside tokens. **Round 7: there is no
    /// per-slot serial.** The never-reused check value of a chain argument handle is `ChainId` (§6.2), built from
    /// the per-image instance serial and the starting thread's own counter; it never reads the slot table, so the
    /// token table can wrap without reopening the round-3 stale-handle hole (C-STASH-REOPEN, C-GEN-WRAP keep
    /// passing unchanged).
    #[doc(hidden)]
    pub fn insert(&self, v: T) -> (u32, u32) {
        let _ = v;
        todo!()
    }
    // W0-ABI: `pub(crate) unsafe fn get_mut(&self, index: u32, generation: u32) -> Option<&mut T>;` is in the IF
    // (with its Safety doc); it is an `unsafe fn` (CONVENTIONS rule 2) and lands with W1-A3 under its escape.
    /// Round 14: on a match, takes the value and stores the next generation with occupied clear (Release) before
    /// the free-list push; on a mismatch (free slot, other generation, unknown index) returns None and writes
    /// nothing. Safe to call with any (index, generation), concurrently with any insert.
    #[doc(hidden)]
    pub fn remove(&self, index: u32, generation: u32) -> Option<T> {
        let _ = (index, generation);
        todo!()
    }
    /// Cold (admin, tests): counts live slots by scanning the pages.
    #[doc(hidden)]
    pub fn count_live(&self) -> u32 {
        todo!()
    }
}
/// Token packing (§2): chain = (gen << 32) | index; session = TOKEN_SESSION | (gen << 32) | index.
#[doc(hidden)]
pub const fn pack(session: bool, index: u32, generation: u32) -> Token {
    let _ = (session, index, generation);
    todo!()
}
#[doc(hidden)]
pub const fn unpack(t: Token) -> (bool, u32, u32) {
    let _ = t;
    todo!()
}

/// Fields drop in declaration order: every chain (whose future borrows `plugin`) and every session drops
/// before `plugin`. No `Drop` impl. Do not reorder.
#[doc(hidden)]
pub struct Inst<T, S> {
    // W0-ABI: the frozen fields, in this order (round 11, §6.4 step 9): `serial: u64, chains: Slots<ChainBox>,
    // sessions: Slots<S>, plugin: T`. `ChainBox` is not defined by the IF (W1-A3 defines it), so the stub
    // carries only the type parameters.
    _stub: PhantomData<(T, S)>,
}
