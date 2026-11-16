// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Slots: the one token table, shared by chains and sessions; the instance the shims build; and the
//! chain box (IF §6.5, §6.4 steps 1-9; UNSAFE-MIN §2.2, §2.6).
//!
//! `unsafe` here: the value write of `insert`, `get_mut` (def and body), the value take of `remove`,
//! `Sync for Slots`, `tie` (the one lifetime erasure of a chain future that borrows its instance) and
//! `drop_inst` (def, the in-place drop and the free; the C-CLOSE-PARKED test calls it).

#![allow(unsafe_code)]

use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};
use std::sync::OnceLock;

#[cfg(loom)]
use loom::sync::atomic::{AtomicU32, AtomicU64, Ordering};
#[cfg(not(loom))]
use std::sync::atomic::Ordering;
#[cfg(all(not(loom), not(test)))]
use std::sync::atomic::{AtomicU32, AtomicU64};
// C-RMW: test builds count the slot table's RMWs (`counting`); every other build uses the std atomics.
#[cfg(all(not(loom), test))]
use counting::{AtomicU32, AtomicU64};

use crate::raw::{ChainId, CurrentGuard, TOKEN_SESSION, Token};

/// Pages: page `p` holds `32 << p` slots, allocated on first use; 27 pages cover every `u32` index.
const PAGES: usize = 27;
/// The largest slot generation; `next` wraps it to 1, so a generation is never 0.
const GEN_MAX: u32 = 0x7FFF_FFFF;
/// The low half of the free head: the top slot's index + 1 (0 = empty).
const INDEX_MASK: u64 = 0xFFFF_FFFF;

/// One slot, on its own 128-byte line pair (round 18): `state = (generation << 1) | occupied`.
#[repr(C, align(128))]
struct Slot<T> {
    state: AtomicU32,
    next: AtomicU32,
    value: UnsafeCell<Option<T>>,
}

impl<T> Slot<T> {
    fn new() -> Self {
        Slot {
            state: AtomicU32::new(1 << 1),
            next: AtomicU32::new(0),
            value: UnsafeCell::new(None),
        }
    }
}

/// The free list's head on its own line pair: (tag << 32) | (index + 1); the tag is bumped on every pop.
#[repr(align(128))]
struct FreeHead(AtomicU64);

/// Concurrent, generation-checked table (IF §6.5). Lookup is one Acquire load and a compare; insert and
/// remove are one CAS each on a Treiber free list. Slot addresses never move.
pub struct Slots<T> {
    pages: [OnceLock<Box<[Slot<T>]>>; PAGES],
    fresh: AtomicU32,
    free: FreeHead,
    /// Loom only: `OnceLock` is invisible to loom, so this lock gives the model the happens-before edge
    /// `OnceLock` gives real threads between a page's construction and every later `slot_or_alloc`.
    #[cfg(loom)]
    page_edge: loom::sync::Mutex<()>,
}

// SAFETY: every access to a slot's value is either by the thread that popped the slot off the free list
// (`insert`, which owns it exclusively until its Release store of `state`), or by an entry for that
// slot's live token, which I6 makes exclusive (`get_mut`, `remove`; the host holds `&mut` to the token's
// handle for the whole entry); a stale token never matches `state` and never touches the value. So
// sharing the table across threads hands each value to one thread at a time, which `T: Send` permits.
unsafe impl<T: Send> Sync for Slots<T> {}

/// The page and offset of slot `index`.
const fn page_of(index: u32) -> (usize, usize) {
    let q = (index as u64) / 32 + 1;
    let page = 63 - q.leading_zeros() as u64;
    let base = 32 * ((1u64 << page) - 1);
    (page as usize, (index as u64 - base) as usize)
}

const fn next_generation(generation: u32) -> u32 {
    if generation >= GEN_MAX {
        1
    } else {
        generation + 1
    }
}

impl<T: Send> Slots<T> {
    #[cfg(not(loom))]
    pub const fn new() -> Self {
        Slots {
            pages: [const { OnceLock::new() }; PAGES],
            fresh: AtomicU32::new(0),
            free: FreeHead(AtomicU64::new(0)),
        }
    }
    #[cfg(loom)]
    pub fn new() -> Self {
        Slots {
            pages: [const { OnceLock::new() }; PAGES],
            fresh: AtomicU32::new(0),
            free: FreeHead(AtomicU64::new(0)),
            page_edge: loom::sync::Mutex::new(()),
        }
    }

    fn slot(&self, index: u32) -> Option<&Slot<T>> {
        let (page, offset) = page_of(index);
        self.pages.get(page)?.get()?.get(offset)
    }

    fn slot_or_alloc(&self, index: u32) -> Option<&Slot<T>> {
        let (page, offset) = page_of(index);
        #[cfg(loom)]
        let _page_edge = self.page_edge.lock().ok();
        let slots = self
            .pages
            .get(page)?
            .get_or_init(|| (0..(32usize << page)).map(|_| Slot::new()).collect());
        slots.get(offset)
    }

    fn pop(&self) -> Option<u32> {
        loop {
            let head = self.free.0.load(Ordering::Acquire);
            let top = (head & INDEX_MASK) as u32;
            if top == 0 {
                return None;
            }
            let next = self.slot(top - 1)?.next.load(Ordering::Relaxed);
            let tag = (head >> 32).wrapping_add(1);
            let new = (tag << 32) | u64::from(next);
            if self
                .free
                .0
                .compare_exchange_weak(head, new, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Some(top - 1);
            }
        }
    }

    fn push(&self, index: u32) {
        let Some(slot) = self.slot(index) else {
            return;
        };
        loop {
            let head = self.free.0.load(Ordering::Acquire);
            slot.next
                .store((head & INDEX_MASK) as u32, Ordering::Relaxed);
            let new = (head & !INDEX_MASK) | (u64::from(index) + 1);
            if self
                .free
                .0
                .compare_exchange_weak(head, new, Ordering::Release, Ordering::Acquire)
                .is_ok()
            {
                return;
            }
        }
    }

    /// Insert `v`; returns (index, generation). None: the table is exhausted (FAULT `Exhausted`).
    pub fn insert(&self, v: T) -> Option<(u32, u32)> {
        let index = match self.pop() {
            Some(index) => index,
            None => {
                let index = self.fresh.fetch_add(1, Ordering::Relaxed);
                if index == u32::MAX {
                    return None;
                }
                index
            }
        };
        let slot = self.slot_or_alloc(index)?;
        let generation = slot.state.load(Ordering::Relaxed) >> 1;
        // SAFETY: this thread popped `index` off the free list (or took it fresh), so no other thread can
        // reach the slot's value: every lookup sees occupied = 0 until the Release store below.
        unsafe { *slot.value.get() = Some(v) };
        slot.state.store((generation << 1) | 1, Ordering::Release);
        Some((index, generation))
    }

    /// The live value of `(index, generation)`, or None for a free slot, another generation or an
    /// unknown index (one Acquire load and a compare; the value is not touched then).
    ///
    /// # Safety
    /// No other reference to this slot's value may be live while the result is: the caller is the one
    /// entry for this token (I6, which the host enforces with `&mut` handles).
    #[allow(clippy::mut_from_ref)] // `&mut` to a slot's value under the I6 contract above
    pub unsafe fn get_mut(&self, index: u32, generation: u32) -> Option<&mut T> {
        let slot = self.slot(index)?;
        if slot.state.load(Ordering::Acquire) != (generation << 1) | 1 {
            return None;
        }
        // SAFETY: the state matched, so the value was written before its Release store and is live; the
        // caller guarantees no other reference to it exists (I6).
        let value = unsafe { &mut *slot.value.get() };
        value.as_mut()
    }

    /// On a match, take the value and store the next generation with occupied clear (Release) before the
    /// free-list push; on a mismatch return None and write nothing.
    pub fn remove(&self, index: u32, generation: u32) -> Option<T> {
        let slot = self.slot(index)?;
        if slot.state.load(Ordering::Acquire) != (generation << 1) | 1 {
            return None;
        }
        // SAFETY: the state matched, so this is the live token's entry, and I6 makes it the only one: no
        // other reference to the value exists. A stale entry would not have matched.
        let value = unsafe { (*slot.value.get()).take() };
        slot.state
            .store(next_generation(generation) << 1, Ordering::Release);
        self.push(index);
        value
    }

    /// Cold (admin, tests): live slots, by scanning the pages.
    pub fn count_live(&self) -> u32 {
        let mut live = 0;
        for page in &self.pages {
            if let Some(slots) = page.get() {
                for slot in slots.iter() {
                    live += slot.state.load(Ordering::Acquire) & 1;
                }
            }
        }
        live
    }

    /// C-GEN-WRAP's hook (IF §14 round 4: the `busbar_abi_test` hook; test builds only): give free slot
    /// `index` the generation `generation`, so the next insert there takes it. False, and nothing
    /// written: an unknown index, a live slot, or no 31-bit generation (0 or above `GEN_MAX`).
    #[cfg(all(test, not(loom)))]
    fn force_generation(&self, index: u32, generation: u32) -> bool {
        let Some(slot) = self.slot(index) else {
            return false;
        };
        if generation == 0 || generation > GEN_MAX || slot.state.load(Ordering::Acquire) & 1 != 0 {
            return false;
        }
        true
    }
}

impl<T: Send> Default for Slots<T> {
    fn default() -> Self {
        Self::new()
    }
}

/// Token packing (IF §2): chain = (gen << 32) | index; session = TOKEN_SESSION | (gen << 32) | index.
pub const fn pack(session: bool, index: u32, generation: u32) -> Token {
    let space = if session { TOKEN_SESSION } else { 0 };
    space | (((generation & GEN_MAX) as u64) << 32) | index as u64
}

/// (session, index, generation).
pub const fn unpack(t: Token) -> (bool, u32, u32) {
    (
        t & TOKEN_SESSION != 0,
        t as u32,
        ((t >> 32) as u32) & GEN_MAX,
    )
}

static NEXT_INST: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

/// The plugin instance the shims build (IF §6.5). Fields drop in declaration order: every chain (whose
/// future may borrow `plugin`) and every session drops before `plugin`. No `Drop` impl; do not reorder.
pub struct Inst<P, S, R, X> {
    serial: u64,
    chains: Slots<ChainBox<R, X>>,
    sessions: Slots<S>,
    plugin: P,
}

impl<P, S: Send, R, X: Send> Inst<P, S, R, X> {
    /// A new instance with the next per-image serial (the global open slab is serial 0).
    pub fn new(plugin: P) -> Self {
        Inst {
            serial: NEXT_INST.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            chains: Slots::new(),
            sessions: Slots::new(),
            plugin,
        }
    }
    pub fn plugin(&self) -> &P {
        &self.plugin
    }
    pub fn serial(&self) -> u64 {
        self.serial
    }
    /// The session table (sessions own no borrow of the instance).
    pub fn sessions(&self) -> &Slots<S> {
        &self.sessions
    }
    /// Box the instance for INSTANCE: its address, provenance exposed (the host turns it back into the
    /// `inst` pointer of every later entry with `with_exposed_provenance`).
    pub fn into_instance(self: Box<Self>) -> u64 {
        Box::into_raw(self).expose_provenance() as u64
    }
    /// The chain table: private, because its futures borrow `plugin` (see `tie`).
    pub(crate) fn chains(&self) -> &Slots<ChainBox<R, X>> {
        &self.chains
    }
}

/// Drop an instance in place (chains, sessions, then plugin), then free it, without a `Box` retag of the
/// whole value while chain futures still hold their borrows of `plugin` (Miri: C-CLOSE-PARKED).
///
/// # Safety
/// `inst` is the address `Inst::into_instance` returned for an `I` (exposed provenance), and nothing
/// uses it again.
pub(crate) unsafe fn drop_inst<I>(inst: *const c_void) {
    let p = inst.cast::<I>().cast_mut();
    // SAFETY: by the contract `p` is the live, uniquely owned `I` from `Box::into_raw`; dropping it in place
    // through the raw pointer runs the field drops in order without invalidating the borrows the chain
    // futures hold until they are dropped first.
    unsafe { core::ptr::drop_in_place(p) };
    // SAFETY: the same allocation, now dropped; as `MaybeUninit<I>` the Box frees it without a second drop.
    drop(unsafe { Box::from_raw(p.cast::<core::mem::MaybeUninit<I>>()) });
}

/// One chain: its boxed future (I5), its check id and the adapter's per-chain state `X` (the inbox and
/// step counter). Built only inside busbar-ffi; an adapter reaches it only through `ChainRef`.
pub struct ChainBox<R, X> {
    fut: Pin<Box<dyn Future<Output = R> + Send + 'static>>,
    id: ChainId,
    extra: X,
}

impl<R, X> ChainBox<R, X> {
    pub(crate) fn new(
        fut: Pin<Box<dyn Future<Output = R> + Send + 'static>>,
        id: ChainId,
        extra: X,
    ) -> Self {
        ChainBox { fut, id, extra }
    }
    pub(crate) fn id(&self) -> &ChainId {
        &self.id
    }
}

/// Erase a chain future's borrow of its instance.
///
/// Only the async-start shim calls this, with `'i` the borrow of the instance it entered, and the box it
/// returns goes only into that instance's private chain table or is dropped inside the same shim.
pub(crate) fn tie<'i, R>(
    fut: Pin<Box<dyn Future<Output = R> + Send + 'i>>,
) -> Pin<Box<dyn Future<Output = R> + Send + 'static>> {
    // SAFETY: the two types differ only in the trait object's lifetime bound. The future borrows the
    // instance's `plugin` for `'i`; it is stored only in that instance's `chains`, which `Inst` drops before
    // `plugin` (field order), or dropped by the shim before it returns. `chains` is private to this crate
    // and adapters see a chain only through `ChainRef`, which cannot move the box out, so the future never
    // outlives the plugin it borrows.
    unsafe {
        core::mem::transmute::<
            Pin<Box<dyn Future<Output = R> + Send + 'i>>,
            Pin<Box<dyn Future<Output = R> + Send + 'static>>,
        >(fut)
    }
}

/// An adapter's view of one chain: poll it (with `CURRENT` set to its id) and reach its state; it cannot
/// move the box.
pub struct ChainRef<'c, R, X> {
    cb: &'c mut ChainBox<R, X>,
}

impl<'c, R, X> ChainRef<'c, R, X> {
    pub(crate) fn new(cb: &'c mut ChainBox<R, X>) -> Self {
        ChainRef { cb }
    }
    /// One poll with a no-op waker and `CURRENT` set by a guard (IF §6.2, §6.4 steps 1 and 4).
    pub fn poll(&mut self) -> Poll<R> {
        let _current = CurrentGuard::enter(self.cb.id);
        let mut cx = Context::from_waker(Waker::noop());
        self.cb.fut.as_mut().poll(&mut cx)
    }
    /// The adapter's per-chain state.
    pub fn extra(&mut self) -> &mut X {
        &mut self.cb.extra
    }
}

/// C-RMW's counting configuration (IF §14 round 8, §0 I5; test builds only, so a release build keeps the
/// std atomics unchanged): the slot table's `AtomicU32`/`AtomicU64` behind a wrapper that counts, on the
/// calling thread, every read-modify-write that lands: `fetch_add` and each successful CAS. A weak CAS
/// that fails (a lost race, or spuriously, as Miri makes it) is retried and counted once, when it lands.
/// Loads and stores are not RMWs and are not counted.
#[cfg(all(test, not(loom)))]
pub(crate) mod counting {
    use core::cell::Cell;
    use std::sync::atomic::{self, Ordering};

    std::thread_local! {
        static RMW: Cell<u64> = const { Cell::new(0) };
    }

    /// The slot-table RMWs this thread has made so far.
    pub(crate) fn rmw() -> u64 {
        RMW.get()
    }

    fn landed() {}

    pub(crate) struct AtomicU32(atomic::AtomicU32);

    impl AtomicU32 {
        pub(crate) const fn new(v: u32) -> Self {
            AtomicU32(atomic::AtomicU32::new(v))
        }
        pub(crate) fn load(&self, order: Ordering) -> u32 {
            self.0.load(order)
        }
        pub(crate) fn store(&self, v: u32, order: Ordering) {
            self.0.store(v, order);
        }
        pub(crate) fn fetch_add(&self, v: u32, order: Ordering) -> u32 {
            landed();
            self.0.fetch_add(v, order)
        }
    }

    pub(crate) struct AtomicU64(atomic::AtomicU64);

    impl AtomicU64 {
        pub(crate) const fn new(v: u64) -> Self {
            AtomicU64(atomic::AtomicU64::new(v))
        }
        pub(crate) fn load(&self, order: Ordering) -> u64 {
            self.0.load(order)
        }
        pub(crate) fn compare_exchange_weak(
            &self,
            current: u64,
            new: u64,
            success: Ordering,
            failure: Ordering,
        ) -> Result<u64, u64> {
            let swapped = self.0.compare_exchange_weak(current, new, success, failure);
            if swapped.is_ok() {
                landed();
            }
            swapped
        }
    }
}

#[cfg(all(test, not(loom)))]
mod tests {
    use super::*;
    use crate::raw::seal::ToChain;
    use crate::raw::{Arg, Bytes};
    use std::sync::atomic::AtomicBool;

    #[test]
    fn tokens_pack_and_unpack() {
        let t = pack(true, 7, 3);
        assert_eq!(unpack(t), (true, 7, 3));
        assert_eq!(unpack(pack(false, 0, 1)), (false, 0, 1));
        assert_ne!(pack(false, 0, 1), 0, "a token is never 0");
        assert_eq!(page_of(0), (0, 0));
        assert_eq!(page_of(31), (0, 31));
        assert_eq!(page_of(32), (1, 0));
        assert_eq!(page_of(95), (1, 63));
        assert_eq!(page_of(96), (2, 0));
    }

    /// C-SLOT-STALE through the safe API (Miri): a stale remove never touches the slot's new occupant.
    #[test]
    fn a_stale_token_never_reaches_the_new_occupant() {
        let slots: Slots<String> = Slots::new();
        let Some((index, generation)) = slots.insert("first".to_string()) else {
            panic!("insert");
        };
        assert_eq!(slots.remove(index, generation).as_deref(), Some("first"));
        let Some((again, newer)) = slots.insert("second".to_string()) else {
            panic!("insert");
        };
        assert_eq!(again, index, "the free list hands the slot back");
        assert_ne!(newer, generation, "with the next generation");
        assert_eq!(slots.remove(index, generation), None, "stale: a no-op");
        assert_eq!(slots.count_live(), 1);
        assert_eq!(slots.remove(again, newer).as_deref(), Some("second"));
        assert_eq!(slots.remove(again, newer), None, "removed once");
        assert_eq!(slots.remove(4_000, 1), None, "an unknown index");
        assert_eq!(slots.count_live(), 0);
    }

    #[test]
    fn slots_fill_past_the_first_page() {
        let slots: Slots<u64> = Slots::new();
        let mut held = Vec::new();
        for v in 0..100u64 {
            let Some(at) = slots.insert(v) else {
                panic!("insert");
            };
            held.push(at);
        }
        assert_eq!(slots.count_live(), 100);
        for (v, (index, generation)) in held.into_iter().enumerate() {
            assert_eq!(slots.remove(index, generation), Some(v as u64));
        }
    }

    /// A chain box over an empty future, with a fresh id of instance `serial`.
    fn chain_box(serial: u64) -> ChainBox<(), ()> {
        let Some(id) = ChainId::mint(serial) else {
            panic!("mint");
        };
        ChainBox::new(Box::pin(async {}), id, ())
    }

    /// C-GEN-WRAP (IF §14 round 4; §2, §6.2, §6.5, §16.27): a slot's 31-bit generation is forced to
    /// 2^31-2 and wrapped. The free list hands the same slot back every time and its generation runs
    /// 2^31-2, 2^31-1, then wraps to 1 (never 0), so the token of the slot's first chain comes round
    /// again; every older generation stays stale; and the ChainId, the never-reused check value of
    /// chain-scoped bytes, still differs, so bytes stashed by the first chain are refused under the chain
    /// that now holds its token.
    #[test]
    fn a_wrapped_generation_keeps_chain_ids_distinct() {
        static STASHED: [u8; 5] = *b"stash";
        const SERIAL: u64 = 9;
        assert_eq!(GEN_MAX - 1, (1 << 31) - 2, "2^31-2");
        let table: Slots<ChainBox<(), ()>> = Slots::new();

        let first = chain_box(SERIAL);
        let first_id = *first.id();
        let Some((index, generation)) = table.insert(first) else {
            panic!("insert");
        };
        assert_eq!(generation, 1, "a fresh slot's first generation");
        let Some(first) = table.remove(index, generation) else {
            panic!("remove");
        };
        assert_eq!(*first.id(), first_id);
        drop(first);
        assert!(
            table.force_generation(index, GEN_MAX - 1),
            "the hook takes the free slot"
        );

        let mut ids = vec![first_id];
        let mut tokens = vec![pack(false, index, generation)];
        for want in [GEN_MAX - 1, GEN_MAX, 1] {
            let next = chain_box(SERIAL);
            let id = *next.id();
            let Some((at, generation)) = table.insert(next) else {
                panic!("insert");
            };
            assert_eq!(at, index, "the free list hands the same slot back");
            assert_eq!(generation, want, "2^31-2, 2^31-1, then the wrap to 1");
            let token = pack(false, at, generation);
            assert_eq!(unpack(token), (false, at, generation), "31 bits round-trip");
            assert_eq!(
                token & TOKEN_SESSION,
                0,
                "the generation never reaches bit 63"
            );
            for old in &tokens {
                let (_, _, stale) = unpack(*old);
                if stale != generation {
                    assert!(
                        table.remove(at, stale).is_none(),
                        "an older generation never reaches the occupant"
                    );
                }
            }
            let Some(taken) = table.remove(at, generation) else {
                panic!("remove");
            };
            assert_eq!(*taken.id(), id);
            assert!(
                ids.iter().all(|seen| *seen != id),
                "a ChainId is never reused"
            );
            ids.push(id);
            tokens.push(token);
        }
        assert_eq!(
            tokens[3], tokens[0],
            "after the wrap the slot's token comes round again"
        );
        assert_ne!(ids[3], ids[0], "and the ChainId still differs");

        let stash = <Bytes<'static> as ToChain>::chain(Arg::bytes(Bytes::new(&STASHED)), &ids[0]);
        {
            let _current = CurrentGuard::enter(ids[3]);
            let read = std::panic::catch_unwind(core::panic::AssertUnwindSafe(|| stash.to_vec()));
            assert!(
                read.is_err(),
                "the first chain's bytes are refused under the chain that holds its token now"
            );
        }
        let _current = CurrentGuard::enter(ids[0]);
        assert_eq!(stash.to_vec(), b"stash", "and read under their own chain");
    }

    /// Fill pages 0 to 3 of an empty `table` (32 + 64 + 128 + 256 slots), check that every slot of every
    /// allocated page sits at a 128-byte aligned address and that `free` shares no 128-byte line with
    /// `pages`, then empty it again. Returns the pages allocated.
    fn fill_and_check<T: Send>(table: &Slots<T>, make: impl Fn(u32) -> T) -> usize {
        const LINE: usize = 128;
        let mut held = Vec::new();
        for v in 0..480u32 {
            let Some(at) = table.insert(make(v)) else {
                panic!("insert");
            };
            held.push(at);
        }
        let mut pages = 0;
        for page in &table.pages {
            let Some(slots) = page.get() else {
                continue;
            };
            pages += 1;
            for slot in slots.iter() {
                assert_eq!(
                    core::ptr::from_ref(slot).addr() % LINE,
                    0,
                    "every slot address is 128-byte aligned"
                );
            }
        }
        let pages_first = core::ptr::from_ref(&table.pages).addr();
        let pages_last = pages_first + size_of_val(&table.pages) - 1;
        let free_first = core::ptr::from_ref(&table.free).addr();
        let free_last = free_first + size_of::<FreeHead>() - 1;
        assert!(
            free_last / LINE < pages_first / LINE || free_first / LINE > pages_last / LINE,
            "free_head shares no 128-byte line with pages"
        );
        for (index, generation) in held {
            assert!(table.remove(index, generation).is_some());
        }
        pages
    }

    /// C-SLOT-ALIGN (IF §14, the B-SYNC churn arm; §6.5 round 18): every slot address of every page is
    /// 128-byte aligned, and `free_head` does not share a 128-byte line with `pages`. Checked on a table
    /// on the stack, a `static` one (an image's open slab is one) and an instance's session and chain
    /// tables, over the churn arm's 48-byte session state, a `u64` and the chain box.
    #[test]
    fn slots_are_128_byte_aligned() {
        type State = [u8; 48];
        static GLOBAL: Slots<u64> = Slots::new();
        let local: Slots<State> = Slots::new();
        assert_eq!(fill_and_check(&local, |_| [0u8; 48]), 4);
        assert_eq!(fill_and_check(&GLOBAL, u64::from), 4);
        let inst = Inst::<(), State, (), ()>::new(());
        assert_eq!(fill_and_check(inst.sessions(), |_| [0u8; 48]), 4);
        assert_eq!(
            fill_and_check(inst.chains(), |_| chain_box(inst.serial())),
            4
        );
    }

    /// C-RMW's table share (IF §14 round 8; §6.5), on the counting configuration: an insert is one RMW
    /// (the free-list pop CAS, or the fresh index's `fetch_add` while the list is empty), a remove one (the
    /// push CAS), and a lookup that misses (a stale generation, an unknown index) or a scan none.
    #[test]
    fn an_insert_and_a_remove_make_one_rmw_each_and_a_miss_none() {
        let table: Slots<u64> = Slots::new();
        let rmw = counting::rmw();
        let Some((index, generation)) = table.insert(1) else {
            panic!("insert");
        };
        assert_eq!(counting::rmw() - rmw, 1, "a fresh index: one fetch_add");
        let rmw = counting::rmw();
        assert_eq!(table.remove(index, generation), Some(1));
        assert_eq!(counting::rmw() - rmw, 1, "a remove: one push CAS");
        let rmw = counting::rmw();
        let Some((again, newer)) = table.insert(2) else {
            panic!("insert");
        };
        assert_eq!(again, index);
        assert_eq!(counting::rmw() - rmw, 1, "from the free list: one pop CAS");
        let rmw = counting::rmw();
        assert_eq!(table.remove(index, generation), None, "stale");
        assert_eq!(table.remove(4_000, 1), None, "unknown");
        assert_eq!(table.count_live(), 1);
        assert_eq!(counting::rmw(), rmw, "a miss and a scan: none");
        assert_eq!(table.remove(again, newer), Some(2));
        assert_eq!(counting::rmw() - rmw, 1);
    }

    struct Plugin {
        alive: AtomicBool,
    }
    impl Drop for Plugin {
        fn drop(&mut self) {
            self.alive.store(false, std::sync::atomic::Ordering::SeqCst);
        }
    }
    struct Parked<'p> {
        plugin: &'p Plugin,
        saw_alive: &'static AtomicBool,
    }
    impl Drop for Parked<'_> {
        fn drop(&mut self) {
            let alive = self.plugin.alive.load(std::sync::atomic::Ordering::SeqCst);
            self.saw_alive
                .store(alive, std::sync::atomic::Ordering::SeqCst);
        }
    }

    /// C-CLOSE-PARKED (Miri): a parked chain future that reads the plugin in its `Drop` runs before the
    /// plugin drops, because `Inst` drops `chains` first.
    #[test]
    fn a_parked_chain_drops_before_its_plugin() {
        type I = Inst<Plugin, (), (), ()>;
        static SAW_ALIVE: AtomicBool = AtomicBool::new(false);
        let address = Box::new(I::new(Plugin {
            alive: AtomicBool::new(true),
        }))
        .into_instance();
        let raw = core::ptr::with_exposed_provenance::<c_void>(address as usize);
        // SAFETY: `raw` is the live boxed instance just made; it is only read until `drop_inst` below.
        let inst = unsafe { &*raw.cast::<I>() };
        let parked = Parked {
            plugin: inst.plugin(),
            saw_alive: &SAW_ALIVE,
        };
        let fut: Pin<Box<dyn Future<Output = ()> + Send + '_>> = Box::pin(async move {
            let _keep = &parked;
            core::future::pending::<()>().await;
        });
        let Some(id) = ChainId::mint(inst.serial()) else {
            panic!("mint");
        };
        let mut cb = ChainBox::new(tie(fut), id, ());
        assert!(ChainRef::new(&mut cb).poll().is_pending());
        assert!(inst.chains().insert(cb).is_some());
        // SAFETY: `raw` came from `into_instance` and is not used again.
        unsafe { drop_inst::<I>(raw) };
        assert!(SAW_ALIVE.load(std::sync::atomic::Ordering::SeqCst));
    }
}
