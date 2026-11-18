// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Slots: the one token table, shared by chains and sessions; the instance the shims build; and the
//! chain box (IF §6.5, §6.4 steps 1-9; UNSAFE-MIN §2.2, §2.6).
//!
//! `unsafe` here: the value write of `insert_raw`, the `get_mut_raw` value borrow, the `remove_raw` take,
//! `Sync for Slots`, `tie` (the one lifetime erasure of a chain future that borrows its instance) and
//! `drop_inst` (def, the two in-place drops and the free; the C-CLOSE-PARKED test calls it).

#![allow(unsafe_code)]

use core::cell::{Cell, UnsafeCell};
use core::ffi::c_void;
use core::future::Future;
use core::marker::PhantomData;
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

/// Pages: page `p` holds `32 << p` slots, allocated on first use.
const PAGES: usize = 27;
/// Number of indices covered by the pages; the terminal counter value is not an index.
const SLOT_CAPACITY: u32 = (32 * ((1u64 << PAGES) - 1)) as u32;
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

/// C-CLOSE-PARKED through the real host/shim path. The host-feature Miri run covers this caller.
#[cfg(all(test, feature = "host", not(loom)))]
mod close_parked_host {
    #![forbid(unsafe_code)]

    use super::{ChainBox, ChainRef, Inst, Slots};
    use crate::header::{LinkedPlugin, STAMP_KIND_AT, STAMP_SIZE, StampBytes, plugin};
    use crate::host::{ChainBufs, OpenAnswer, OutLease, Started};
    use crate::image::Admitted;
    use crate::raw::{Arg, Bytes, ChainBytes, Host, HostFns, KindCode, Out, Status, Str, Token};
    use crate::shim::{ChainFut, Image, Opening, Start1, Step};
    use crate::vt::{Built, kind, secret};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    static SAW_ALIVE: AtomicBool = AtomicBool::new(false);
    static FUTURE_DROPS: AtomicUsize = AtomicUsize::new(0);
    static PLUGIN_DROPS: AtomicUsize = AtomicUsize::new(0);
    static PARKED: AtomicUsize = AtomicUsize::new(0);
    static GLOBAL: Slots<ChainBox<(), ()>> = Slots::new();
    static HOST: Host = Host::new(
        0,
        HostFns {
            now: None,
            mono: None,
            random: None,
            crypto: None,
            log: None,
            log_level: None,
            grow: None,
            deployment: None,
            migrate_admit: None,
        },
    );

    pub struct BorrowedPlugin {
        alive: AtomicBool,
    }

    impl Drop for BorrowedPlugin {
        fn drop(&mut self) {
            self.alive.store(false, Ordering::SeqCst);
            PLUGIN_DROPS.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct Parked<'p>(&'p BorrowedPlugin);

    impl Drop for Parked<'_> {
        fn drop(&mut self) {
            SAW_ALIVE.store(self.0.alive.load(Ordering::SeqCst), Ordering::SeqCst);
            FUTURE_DROPS.fetch_add(1, Ordering::SeqCst);
        }
    }

    pub struct Fixture;

    fn record(out: &mut Out<'_>, tag: u16, value: u64) -> bool {
        let mut bytes = [0u8; 16];
        bytes[..2].copy_from_slice(&tag.to_ne_bytes());
        bytes[4..8].copy_from_slice(&8u32.to_ne_bytes());
        bytes[8..].copy_from_slice(&value.to_le_bytes());
        out.append(&bytes)
    }

    impl Image for Fixture {
        type Plugin = BorrowedPlugin;
        type Session = ();
        type Reply = ();
        type Inbox = ();

        fn global() -> &'static Slots<ChainBox<(), ()>> {
            &GLOBAL
        }

        fn describe(_host: &'static Host, _out: &mut Out<'_>) -> Status {
            Status::OK
        }

        fn open(
            _host: &'static Host,
            _config: Bytes<'_>,
            _chained: ChainBytes,
            _flags: u32,
            out: &mut Out<'_>,
        ) -> Opening<(), ()> {
            let address = Box::new(Inst::<BorrowedPlugin, (), (), ()>::new(BorrowedPlugin {
                alive: AtomicBool::new(true),
            }))
            .into_instance();
            assert!(record(out, 0x0009, address), "INSTANCE record fits");
            Opening::Done(Status::OK)
        }

        fn poll(
            mut chain: ChainRef<'_, (), ()>,
            _results: Option<ChainBytes>,
            _out: &mut Out<'_>,
        ) -> Step {
            assert!(chain.poll().is_pending());
            Step::Need
        }

        fn parked(token: Token, out: &mut Out<'_>) -> Status {
            PARKED.fetch_add(1, Ordering::SeqCst);
            assert!(record(out, 0x0003, token), "TOKEN record fits");
            Status::NEED
        }

        fn opened(_token: Token, _out: &mut Out<'_>) -> Status {
            Status::OK
        }
    }

    impl Start1<Bytes<'static>, 0> for Fixture {
        fn start<'i>(
            plugin: &'i BorrowedPlugin,
            _host: &'static Host,
            _reference: ChainBytes,
        ) -> (ChainFut<'i, ()>, ()) {
            let parked = Parked(plugin);
            (
                Box::pin(async move {
                    let _keep = &parked;
                    core::future::pending::<()>().await;
                }),
                (),
            )
        }
    }

    static VT: Built<Fixture, secret::Vt> = secret::Vt::build::<Fixture>();
    static STAMP: StampBytes = {
        let mut bytes = [0u8; STAMP_SIZE];
        bytes[STAMP_KIND_AT] = KindCode::Secret as u8;
        StampBytes(bytes)
    };
    static PLUGIN: LinkedPlugin = plugin::<Fixture, kind::Secret>(&VT, &STAMP, Str::EMPTY);

    #[test]
    fn a_parked_chain_drops_before_its_plugin_through_host() {
        let image = Admitted::linked(&PLUGIN).expect("fixture header");
        let instance = {
            let mut lease = OutLease::new(vec![0; 64], 64).expect("open lease");
            let OpenAnswer::Done(Status::OK, Some(instance)) =
                image.open::<kind::Secret>(&HOST, Vec::new(), 0, &mut lease)
            else {
                panic!("fixture opens a real instance");
            };
            instance
        };
        {
            let mut lease = OutLease::new(vec![0; 64], 64).expect("start lease");
            let Started::Need(chain) = instance.start1(
                |vt| &vt.resolve,
                ChainBufs::new(),
                |_| Arg::bytes(Bytes::EMPTY),
                &mut lease,
            ) else {
                panic!("the real start shim parks the pending future");
            };
            assert_ne!(chain.token(), 0);
            // Keep the future in the real instance's chain table until close. Only the host handle is
            // forgotten; its buffers are empty. Dropping it would cancel before instance teardown.
            core::mem::forget(chain);
        }
        assert_eq!(
            PARKED.load(Ordering::SeqCst),
            1,
            "table insertion succeeded"
        );
        assert_eq!(FUTURE_DROPS.load(Ordering::SeqCst), 0);
        assert_eq!(PLUGIN_DROPS.load(Ordering::SeqCst), 0);
        drop(instance);
        assert!(SAW_ALIVE.load(Ordering::SeqCst));
        assert_eq!(FUTURE_DROPS.load(Ordering::SeqCst), 1);
        assert_eq!(PLUGIN_DROPS.load(Ordering::SeqCst), 1);
    }
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
// (`insert_raw`, which owns it exclusively until its Release store of `state`), or through an exclusive
// table borrow, a unique OwnedSlot, or an I6-exclusive foreign entry. The crate-private raw methods
// never hand out authority to safe external callers; OwnedSlot's value borrow cannot outlive its
// exclusive handle borrow. A stale token never matches `state` and never touches the value. So
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

    fn claim_fresh(&self) -> Option<u32> {
        self.fresh
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |index| {
                (index < SLOT_CAPACITY).then(|| index + 1)
            })
            .ok()
    }

    /// Insert a value and return its sole mutation authority. Dropping the handle retires its slot;
    /// forgetting it leaves the value occupied until exclusive table access or table destruction.
    pub fn insert(&self, v: T) -> Option<OwnedSlot<'_, T>> {
        self.insert_raw(v).map(|identity| OwnedSlot {
            table: self,
            identity: Some(identity),
            not_sync: PhantomData,
        })
    }

    /// Read a numeric identity while exclusively borrowing the entire table.
    /// An existing usable handle prevents acquiring this borrow.
    pub fn get_mut(&mut self, index: u32, generation: u32) -> Option<&mut T> {
        self.get_mut_raw(index, generation)
    }

    /// Retire a numeric identity while exclusively borrowing the entire table.
    /// Saved numbers cannot authorize mutation through a shared table.
    ///
    /// ```compile_fail,E0596
    /// use busbar_ffi::Slots;
    /// let slots = Slots::<String>::new();
    /// let shared = &slots;
    /// shared.remove(0, 1); // E0596: a shared reference is not removal authority.
    /// ```
    /// ```no_run
    /// use busbar_ffi::Slots;
    /// let mut slots = Slots::<String>::new();
    /// let exclusive = &mut slots;
    /// exclusive.remove(0, 1);
    /// ```
    ///
    /// #406's pre-fix reproducer: two scoped threads removing one copied live identity from a shared
    /// `Arc<Slots>`. Its removal expression no longer typechecks.
    ///
    /// ```compile_fail,E0596
    /// use busbar_ffi::Slots;
    /// use std::sync::Arc;
    /// let slots = Arc::new(Slots::<String>::new());
    /// let owned = slots.insert("first".into()).unwrap();
    /// let (index, generation) = owned.identity().unwrap();
    /// core::mem::forget(owned);
    /// std::thread::scope(|scope| {
    ///     for _ in 0..2 {
    ///         let slots = Arc::clone(&slots);
    ///         scope.spawn(move || drop(slots.remove(index, generation))); // E0596
    ///     }
    /// });
    /// ```
    /// ```no_run
    /// use busbar_ffi::Slots;
    /// use std::sync::Arc;
    /// let slots = Arc::new(Slots::<String>::new());
    /// let owned = slots.insert("first".into()).unwrap();
    /// let (index, generation) = owned.identity().unwrap();
    /// core::mem::forget(owned);
    /// std::thread::scope(|scope| {
    ///     for _ in 0..2 {
    ///         let slots = Arc::clone(&slots);
    ///         scope.spawn(move || drop(slots.count_live()));
    ///     }
    /// });
    /// let _ = (index, generation);
    /// ```
    pub fn remove(&mut self, index: u32, generation: u32) -> Option<T> {
        self.remove_raw(index, generation)
    }

    /// FFI-crate primitive: publish a new identity without creating an OwnedSlot. The caller transfers
    /// it to one host handle, or retains sole authority itself. Never manufacture two owners.
    pub(crate) fn insert_raw(&self, v: T) -> Option<(u32, u32)> {
        let index = match self.pop() {
            Some(index) => index,
            None => self.claim_fresh()?,
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
    /// FFI-crate caller invariant: no other reference/access/removal of this slot may overlap the
    /// result. Callers hold an exclusive table borrow, a unique OwnedSlot, or the shim's I6 authority.
    /// Public outputs shorten the result to that exclusive borrow; the raw method is never reexported.
    /// A matching generation is a freshness check, not a lock. This does not transfer ownership:
    /// end/cancel/completion, handle retirement or instance teardown drops the value later.
    #[allow(clippy::mut_from_ref)] // value exclusion is established by the private caller matrix above
    pub(crate) fn get_mut_raw(&self, index: u32, generation: u32) -> Option<&mut T> {
        let slot = self.slot(index)?;
        if slot.state.load(Ordering::Acquire) != (generation << 1) | 1 {
            return None;
        }
        // SAFETY: the state matched, so the value was written before its Release store and is live; the
        // private caller holds unique slot authority or exclusive table access until the borrow ends.
        let value = unsafe { &mut *slot.value.get() };
        value.as_mut()
    }

    /// On a match, take the value and store the next generation with occupied clear (Release) before the
    /// free-list push; on a mismatch return None and write nothing.
    /// FFI-crate caller invariant: unique table/slot authority or I6 excludes every matching entry
    /// and live value borrow. A stale-only test caller must prove the identity cannot become live.
    /// Metadata publication finishes before returning T, so a user destructor cannot repeat it.
    pub(crate) fn remove_raw(&self, index: u32, generation: u32) -> Option<T> {
        let slot = self.slot(index)?;
        if slot.state.load(Ordering::Acquire) != (generation << 1) | 1 {
            return None;
        }
        // SAFETY: the state matched and the private caller's authority makes it the only live entry;
        // no other reference/access to the value overlaps this take. A stale entry would not match.
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
        slot.state.store(generation << 1, Ordering::Release);
        true
    }
}

impl<T: Send> Default for Slots<T> {
    fn default() -> Self {
        Self::new()
    }
}

/// Unique authority over one occupant, tied to its originating table. It is Send for Send values,
/// but never Sync: sharing a handle cannot expose a Send-only value. Numeric identity is observation,
/// not ownership. No public constructor or Clone/Copy implementation can duplicate this authority.
///
/// ```compile_fail,E0382
/// use busbar_ffi::Slots;
/// let slots = Slots::new();
/// let owned = slots.insert(7).unwrap();
/// let moved = owned;
/// owned.take(); // E0382: authority moved to `moved`.
/// ```
/// ```no_run
/// use busbar_ffi::Slots;
/// let slots = Slots::new();
/// let owned = slots.insert(7).unwrap();
/// let moved = owned;
/// moved.take();
/// ```
/// ```compile_fail,E0277
/// use busbar_ffi::Slots;
/// fn require_sync<T: Sync>(_: &T) {}
/// let slots = Slots::new();
/// let owned = slots.insert(7).unwrap();
/// require_sync(&owned); // E0277: OwnedSlot cannot be shared between threads.
/// ```
/// ```no_run
/// use busbar_ffi::Slots;
/// fn require_send<T: Send>(_: T) {}
/// let slots = Slots::new();
/// let owned = slots.insert(7).unwrap();
/// require_send(owned);
/// ```
/// ```compile_fail,E0451
/// use busbar_ffi::{OwnedSlot, Slots};
/// use core::marker::PhantomData;
/// let slots = Slots::<u32>::new();
/// let forged = OwnedSlot { table: &slots, identity: Some((0, 1)), not_sync: PhantomData };
/// ```
/// ```no_run
/// use busbar_ffi::{OwnedSlot, Slots};
/// use core::marker::PhantomData;
/// let slots = Slots::<u32>::new();
/// let owned: OwnedSlot<'_, u32> = slots.insert(7).unwrap();
/// let marker: PhantomData<u32> = PhantomData;
/// ```
pub struct OwnedSlot<'t, T: Send> {
    table: &'t Slots<T>,
    identity: Option<(u32, u32)>,
    not_sync: PhantomData<Cell<T>>,
}

impl<T: Send> OwnedSlot<'_, T> {
    /// Observed numeric identity; None after a successful take_if. It never restores authority.
    pub fn identity(&self) -> Option<(u32, u32)> {
        self.identity
    }

    /// Borrow the occupant only for this exclusive handle borrow.
    ///
    /// ```compile_fail,E0499
    /// use busbar_ffi::Slots;
    /// let slots = Slots::new();
    /// let mut owned = slots.insert(7).unwrap();
    /// let value = owned.get_mut().unwrap();
    /// owned.get_mut(); // E0499: the first borrow is still used below.
    /// *value = 8;
    /// ```
    /// ```no_run
    /// use busbar_ffi::Slots;
    /// let slots = Slots::new();
    /// let mut owned = slots.insert(7).unwrap();
    /// let value = owned.get_mut().unwrap();
    /// *value = 8;
    /// owned.get_mut();
    /// ```
    /// ```compile_fail,E0505
    /// use busbar_ffi::Slots;
    /// let slots = Slots::new();
    /// let mut owned = slots.insert(7).unwrap();
    /// let value = owned.get_mut().unwrap();
    /// core::mem::forget(owned); // E0505: cannot forget authority while its borrow remains usable.
    /// *value = 8;
    /// ```
    /// ```no_run
    /// use busbar_ffi::Slots;
    /// let slots = Slots::new();
    /// let mut owned = slots.insert(7).unwrap();
    /// let value = owned.get_mut().unwrap();
    /// *value = 8;
    /// core::mem::forget(owned);
    /// ```
    /// ```compile_fail,E0505
    /// use busbar_ffi::Slots;
    /// let slots = Slots::new();
    /// let mut owned = slots.insert(7).unwrap();
    /// drop(slots); // E0505: the table cannot die before its handle.
    /// owned.get_mut();
    /// ```
    /// ```no_run
    /// use busbar_ffi::Slots;
    /// let slots = Slots::new();
    /// let mut owned = slots.insert(7).unwrap();
    /// owned.get_mut();
    /// drop(owned);
    /// drop(slots);
    /// ```
    pub fn get_mut(&mut self) -> Option<&mut T> {
        let (_, generation) = self.identity?;
        self.get_if(generation)
    }

    /// Probe this handle's own index through the production generation check. A miss leaves it live.
    fn get_if(&mut self, generation: u32) -> Option<&mut T> {
        let (index, _) = self.identity?;
        self.table.get_mut_raw(index, generation)
    }

    /// Retire this handle's own index only if the production generation check matches.
    pub fn take_if(&mut self, generation: u32) -> Option<T> {
        let (index, _) = self.identity?;
        let value = self.table.remove_raw(index, generation)?;
        self.identity = None;
        Some(value)
    }

    /// Consume authority and return the occupant. Slot publication precedes any user destructor.
    pub fn take(mut self) -> Option<T> {
        let (index, generation) = self.identity.take()?;
        self.table.remove_raw(index, generation)
    }
}

impl<T: Send> Drop for OwnedSlot<'_, T> {
    fn drop(&mut self) {
        if let Some((index, generation)) = self.identity.take() {
            drop(self.table.remove_raw(index, generation));
        }
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
/// future may borrow `plugin`) drops first, then `owned` (every session, then `plugin`). No `Drop` impl;
/// do not reorder. `owned` is one field so `drop_inst` can drop it in place apart from `chains`.
pub struct Inst<P, S, R, X> {
    serial: u64,
    chains: Slots<ChainBox<R, X>>,
    owned: Owned<P, S>,
}

/// The part of an [`Inst`] no chain future borrows into while it drops: sessions (they own no borrow of
/// the instance), then the plugin, in this order.
struct Owned<P, S> {
    sessions: Slots<S>,
    plugin: P,
}

impl<P, S: Send, R, X: Send> Inst<P, S, R, X> {
    /// A new instance with the next per-image serial (the global open slab is serial 0).
    pub fn new(plugin: P) -> Self {
        Inst {
            serial: NEXT_INST.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            chains: Slots::new(),
            owned: Owned {
                sessions: Slots::new(),
                plugin,
            },
        }
    }
    pub fn plugin(&self) -> &P {
        &self.owned.plugin
    }
    pub fn serial(&self) -> u64 {
        self.serial
    }
    /// The session table (sessions own no borrow of the instance).
    pub fn sessions(&self) -> &Slots<S> {
        &self.owned.sessions
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
/// `inst` is the address `Inst::into_instance` returned for an `Inst<P, S, R, X>` (exposed provenance), and nothing
/// uses it again.
/// It must be non-null, aligned, initialized, still allocated by `Box<Inst<P, S, R, X>>` and not previously dropped.
/// No entry may overlap teardown. For `Inst`, outstanding internal chain borrows end when its first
/// field destructors run, before `plugin` is dropped; no external reference may be used during or
/// after teardown. The caller is `shim::close` after the host's last `Instance` owner is released.
/// If a field destructor panics, unwinding skips the allocation-free step below; the caller must not
/// retry destruction of that partially dropped value. The outer shim contains the panic as FAULT.
pub(crate) unsafe fn drop_inst<P, S, R, X>(inst: *const c_void) {
    let p = inst.cast::<Inst<P, S, R, X>>().cast_mut();
    // `chains` is dropped in place apart from the rest, then `owned` (sessions, then plugin): a whole-value
    // `drop_in_place(p)` holds a unique borrow of all of `Inst` for its duration, so a parked chain future
    // reading `plugin` from its destructor read through a borrow that unique one had invalidated (Miri,
    // stacked and tree borrows, C-CLOSE-PARKED with the pointer's provenance kept). The two places are
    // computed without dereferencing `p` (offset_of, provenance kept). As in drop glue, a panicking chain
    // destructor does not stop `owned` from dropping; that panic then continues unwinding.
    let base = p.cast::<u8>();
    let chains = base
        .wrapping_add(core::mem::offset_of!(Inst<P, S, R, X>, chains))
        .cast::<Slots<ChainBox<R, X>>>();
    let owned = base
        .wrapping_add(core::mem::offset_of!(Inst<P, S, R, X>, owned))
        .cast::<Owned<P, S>>();
    let chains = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // SAFETY: by the contract `p` is the live, uniquely owned `Inst` from `Box::into_raw`; `chains` is its
        // field, dropped once, first.
        unsafe { core::ptr::drop_in_place(chains) }
    }));
    // SAFETY: the same `Inst`'s `owned` field, dropped once, after every chain that could borrow `plugin`.
    unsafe { core::ptr::drop_in_place(owned) };
    if let Err(payload) = chains {
        std::panic::resume_unwind(payload);
    }
    // SAFETY: the same Box allocation, now dropped; MaybeUninit<Inst> has Inst's size and alignment, so
    // the original allocator/layout are preserved. It frees storage without running a destructor twice.
    drop(unsafe { Box::from_raw(p.cast::<core::mem::MaybeUninit<Inst<P, S, R, X>>>()) });
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

    fn landed() {
        RMW.set(RMW.get() + 1);
    }

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
        pub(crate) fn fetch_update(
            &self,
            set_order: Ordering,
            fetch_order: Ordering,
            f: impl FnMut(u32) -> Option<u32>,
        ) -> Result<u32, u32> {
            let result = self.0.fetch_update(set_order, fetch_order, f);
            if result.is_ok() {
                landed();
            }
            result
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
    fn fresh_exhaustion_is_terminal_and_free_slots_remain_reusable() {
        let slots = Slots::new();
        let original = slots.insert("original").expect("insert");
        let (index, generation) = original.identity().expect("live");
        slots.fresh.store(SLOT_CAPACITY - 1, Ordering::Relaxed);
        assert_eq!(slots.claim_fresh(), Some(SLOT_CAPACITY - 1));
        for _ in 0..3 {
            assert_eq!(slots.claim_fresh(), None, "fresh exhaustion is permanent");
            assert_eq!(slots.fresh.load(Ordering::Relaxed), SLOT_CAPACITY);
        }
        assert_eq!(slots.count_live(), 1);
        assert_eq!(original.take(), Some("original"));
        let reused_slot = slots.insert("reused").expect("free-list reuse");
        let (reused, next) = reused_slot.identity().expect("live");
        assert_eq!(reused, index);
        assert_ne!(next, generation);
        assert_eq!(slots.fresh.load(Ordering::Relaxed), SLOT_CAPACITY);
        assert_eq!(reused_slot.take(), Some("reused"));
    }

    #[test]
    fn unique_handles_move_send_only_values_between_threads() {
        let slots = Slots::new();
        let mut first = slots.insert(Cell::new(1u32)).expect("insert");
        let mut second = slots.insert(Cell::new(2u32)).expect("insert");
        assert_ne!(first.identity().unwrap().0, second.identity().unwrap().0);
        std::thread::scope(|scope| {
            let worker = scope.spawn(move || {
                first.get_mut().expect("live").set(11);
                first.take().expect("take").get()
            });
            second.get_mut().expect("live").set(22);
            assert_eq!(worker.join().expect("worker"), 11);
            assert_eq!(second.take().expect("take").get(), 22);
        });
        assert_eq!(slots.count_live(), 0);

        static GLOBAL: Slots<Cell<u32>> = Slots::new();
        let mut owned = GLOBAL.insert(Cell::new(3)).expect("static insert");
        std::thread::scope(|scope| {
            scope.spawn(move || owned.get_mut().expect("static live").set(4));
        });
        assert_eq!(
            GLOBAL.count_live(),
            0,
            "thread drops its unique static handle"
        );
    }

    struct Counted<'a> {
        value: u32,
        panic_on_drop: bool,
        drops: &'a std::sync::atomic::AtomicUsize,
    }

    impl Drop for Counted<'_> {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::SeqCst);
            assert!(!self.panic_on_drop, "deliberate occupant destructor panic");
        }
    }

    #[test]
    fn take_drop_and_forgotten_handles_retire_exactly_once() {
        let drops = std::sync::atomic::AtomicUsize::new(0);
        let slots = Slots::new();
        let make = |value| Counted {
            value,
            panic_on_drop: false,
            drops: &drops,
        };
        let mut first = slots.insert(make(1)).expect("insert");
        let (_, generation) = first.identity().expect("live");
        let taken = first.take_if(generation).expect("matching take");
        assert_eq!(first.identity(), None);
        drop(first);
        assert_eq!(drops.load(Ordering::SeqCst), 0, "take transfers the value");
        drop(taken);
        assert_eq!(drops.load(Ordering::SeqCst), 1);

        let forgotten = slots.insert(make(2)).expect("insert");
        let forgotten_index = forgotten.identity().expect("live").0;
        core::mem::forget(forgotten);
        let third = slots.insert(make(3)).expect("insert");
        assert_ne!(third.identity().expect("live").0, forgotten_index);
        assert_eq!(slots.count_live(), 2, "forgotten occupant stays live");
        drop(third);
        assert_eq!(slots.count_live(), 1);
        assert_eq!(drops.load(Ordering::SeqCst), 2);
        drop(slots);
        assert_eq!(
            drops.load(Ordering::SeqCst),
            3,
            "table teardown owns the forgotten value"
        );
    }

    #[test]
    fn a_panicking_destructor_does_not_publish_a_free_slot_twice() {
        let drops = std::sync::atomic::AtomicUsize::new(0);
        let slots = Slots::new();
        let first = slots
            .insert(Counted {
                value: 1,
                panic_on_drop: true,
                drops: &drops,
            })
            .expect("insert");
        let retired_index = first.identity().expect("live").0;
        assert!(std::panic::catch_unwind(core::panic::AssertUnwindSafe(|| drop(first))).is_err());
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(slots.count_live(), 0);
        let make = |value| Counted {
            value,
            panic_on_drop: false,
            drops: &drops,
        };
        let second = slots.insert(make(2)).expect("insert");
        let third = slots.insert(make(3)).expect("insert");
        assert_eq!(second.identity().expect("live").0, retired_index);
        assert_ne!(
            second.identity().unwrap().0,
            third.identity().unwrap().0,
            "no duplicate free-list publication or self-loop"
        );
        assert_eq!(second.take().expect("second").value, 2);
        assert_eq!(third.take().expect("third").value, 3);
        assert_eq!(drops.load(Ordering::SeqCst), 3);
        assert_eq!(slots.count_live(), 0);
    }

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
        let mut slots: Slots<String> = Slots::new();
        let Some(first) = slots.insert("first".to_string()) else {
            panic!("insert");
        };
        let (index, generation) = first.identity().expect("live");
        assert_eq!(first.take().as_deref(), Some("first"));
        let Some(mut second) = slots.insert("second".to_string()) else {
            panic!("insert");
        };
        let (again, newer) = second.identity().expect("live");
        assert_eq!(again, index, "the free list hands the slot back");
        assert_ne!(newer, generation, "with the next generation");
        assert_eq!(second.take_if(generation), None, "stale: a no-op");
        assert_eq!(slots.count_live(), 1);
        assert_eq!(second.take().as_deref(), Some("second"));
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
        for (v, owned) in held.into_iter().enumerate() {
            assert_eq!(owned.take(), Some(v as u64));
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
        let Some(first) = table.insert(first) else {
            panic!("insert");
        };
        let (index, generation) = first.identity().expect("live");
        assert_eq!(generation, 1, "a fresh slot's first generation");
        let Some(first) = first.take() else {
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
            let Some(mut next) = table.insert(next) else {
                panic!("insert");
            };
            let (at, generation) = next.identity().expect("live");
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
                        next.take_if(stale).is_none(),
                        "an older generation never reaches the occupant"
                    );
                }
            }
            let Some(taken) = next.take() else {
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
        for owned in held {
            assert!(owned.take().is_some());
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
        let Some(first) = table.insert(1) else {
            panic!("insert");
        };
        let (index, generation) = first.identity().expect("live");
        assert_eq!(counting::rmw() - rmw, 1, "a fresh index: one fetch_add");
        let rmw = counting::rmw();
        assert_eq!(first.take(), Some(1));
        assert_eq!(counting::rmw() - rmw, 1, "a remove: one push CAS");
        let rmw = counting::rmw();
        let Some(mut second) = table.insert(2) else {
            panic!("insert");
        };
        let (again, _) = second.identity().expect("live");
        assert_eq!(again, index);
        assert_eq!(counting::rmw() - rmw, 1, "from the free list: one pop CAS");
        let rmw = counting::rmw();
        assert_eq!(second.take_if(generation), None, "stale");
        // The only insertions used index zero: this unknown index cannot hold a live value.
        assert_eq!(table.remove_raw(4_000, 1), None, "unknown");
        assert_eq!(table.count_live(), 1);
        assert_eq!(counting::rmw(), rmw, "a miss and a scan: none");
        assert_eq!(second.take(), Some(2));
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
        // The instance pointer as `into_instance` makes it (the leaked Box), kept as a pointer: through the
        // integer handle Miri sees a wildcard provenance and cannot check this drop's borrows (and the
        // miri job's -Zmiri-strict-provenance refuses the round trip). `inst` is a shared view of the same
        // allocation, taken after the pointer, and only read until `drop_inst` below.
        let leaked: &'static mut I = Box::leak(Box::new(I::new(Plugin {
            alive: AtomicBool::new(true),
        })));
        let raw = (&raw mut *leaked).cast::<c_void>().cast_const();
        let inst: &I = leaked;
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
        assert!(inst.chains().insert_raw(cb).is_some());
        // SAFETY: `raw` came from `Box::into_raw` of an `I` and is not used again.
        unsafe { drop_inst::<Plugin, (), (), ()>(raw) };
        assert!(SAW_ALIVE.load(std::sync::atomic::Ordering::SeqCst));
    }
}

/// C-SLOT-STALE uses the actual private primitives. Only the retired generation is shared between
/// threads; one insertion can advance it once, so the stale remover never acquires a live occupant.
#[cfg(all(test, loom))]
mod loom_tests {
    use super::Slots;
    use loom::sync::Arc;
    use loom::thread;

    #[test]
    fn a_stale_remove_never_reaches_a_new_occupant() {
        loom::model(|| {
            let mut slots = Arc::new(Slots::<u32>::new());
            let (index, generation) = slots.insert_raw(1).expect("insert");
            assert_eq!(slots.remove_raw(index, generation), Some(1));
            let fresh = {
                let slots = Arc::clone(&slots);
                thread::spawn(move || slots.insert_raw(2).expect("insert"))
            };
            let stale = {
                let slots = Arc::clone(&slots);
                thread::spawn(move || slots.remove_raw(index, generation))
            };
            assert_eq!(
                stale.join().expect("stale"),
                None,
                "a stale remove is a no-op"
            );
            let (again, newer) = fresh.join().expect("fresh");
            assert_ne!((again, newer), (index, generation));
            let exclusive = Arc::get_mut(&mut slots).expect("both worker clones were joined");
            assert_eq!(exclusive.get_mut(again, newer).copied(), Some(2));
            assert!(exclusive.get_mut(index, generation).is_none());
        });
    }

    #[test]
    fn concurrent_inserts_take_distinct_slots() {
        loom::model(|| {
            let slots = Arc::new(Slots::<u32>::new());
            let first = {
                let slots = Arc::clone(&slots);
                thread::spawn(move || slots.insert_raw(1).expect("insert"))
            };
            let second = slots.insert_raw(2).expect("insert");
            let first = first.join().expect("first");
            assert_ne!(first.0, second.0, "two live values never share a slot");
            assert_eq!(slots.count_live(), 2);
        });
    }
}
