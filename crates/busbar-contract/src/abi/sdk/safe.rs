// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A SLOT BODY WITH NO `unsafe` (THE DESIGN, plugins: a plugin crate stays

use std::any::{Any, TypeId};
use std::cell::{Cell, RefCell, UnsafeCell};
use std::ffi::c_void;
use std::marker::PhantomData;
use std::mem::size_of;
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicU64, Ordering};

use crate::abi::mechanism::call::{InHead, OutHead, Outcome, FLAG_RESUME};
use crate::abi::mechanism::lifecycle::{slot, CancelIn, OpenIn, OpenOut, ValidateIn};
use crate::abi::mechanism::ticket::Ticket;
use crate::abi::sdk::door::{AbiIn, AbiOut, Entry};
use crate::abi::sdk::generation::Gen;
use crate::abi::sdk::lent::Lent;
use crate::abi::sdk::out::{holders_live, Holders, Kept, Out, Reason, ReplyKey, Reporting};

/// One op's parked continuation, its type erased: an `Option<S>` kept boxed in its slot. When the

trait Continuation: Send + Sync {
    /// Drop what is held, keeping the allocation.
    fn clear(&mut self);
    /// The `Option<S>` itself, to downcast.
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

impl<S: Send + Sync + 'static> Continuation for Option<S> {
    fn clear(&mut self) {
        drop(self.take());
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

/// How many slots each segment of an instance's parked table holds. The trampoline is not handed

const SEGMENT: usize = 16;

/// A free slot's key.
const FREE: u64 = 0;

/// A ticket as a slot's key: its two words side by side, compared, never decoded (the encoding is

fn key(ticket: Ticket) -> u64 {
    (u64::from(ticket.slot) << 32) | u64::from(ticket.generation)
}

/// One parked op: its ticket's key, the slot's lock, and the pooled continuation.
struct Slot {
    /// [`FREE`], or the key of the ticket whose op is parked here. Written only under `lock`.
    key: AtomicU64,
    /// Held by whoever reads or writes `cell`: the ticket's own entry, or a `cancel` of it.
    lock: AtomicBool,
    /// The continuation's allocation, kept across the ops that park here.
    cell: UnsafeCell<Option<Box<dyn Continuation>>>,
}

// SAFETY: `cell` is reached only through a `Held`, which owns `lock` while it lives, so one thread
// at a time touches it; what it holds is `Send + Sync` (`Continuation`'s bound).
unsafe impl Sync for Slot {}

impl Slot {
    fn new() -> Self {
        Self {
            key: AtomicU64::new(FREE),
            lock: AtomicBool::new(false),
            cell: UnsafeCell::new(None),
        }
    }

    /// The slot, locked. Only parties on the slot's own ticket meet here (its entry and a `cancel`

    fn hold(&self) -> Held<'_> {
        while self
            .lock
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            std::hint::spin_loop();
        }
        Held {
            slot: self,
            free: false,
        }
    }

    /// The slot, locked, unless someone holds it.
    fn try_hold(&self) -> Option<Held<'_>> {
        if self
            .lock
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return None;
        }
        Some(Held {
            slot: self,
            free: false,
        })
    }
}

/// A slot, locked; dropping it frees the slot's key when `free` says so, then lets go of the lock

struct Held<'a> {
    slot: &'a Slot,
    free: bool,
}

impl Held<'_> {
    fn cell(&mut self) -> &mut Option<Box<dyn Continuation>> {
        // SAFETY: this guard holds the slot's lock, so no other reference to the cell exists.
        unsafe { &mut *self.slot.cell.get() }
    }
}

impl Drop for Held<'_> {
    fn drop(&mut self) {
        if self.free {
            self.slot.key.store(FREE, Ordering::Release);
        }
        self.slot.lock.store(false, Ordering::Release);
    }
}

/// A run of slots, and the next run once this one filled.
struct Segment {
    slots: [Slot; SEGMENT],
    /// The next segment, appended by [`Segment::grow`]; NULL until then. This segment owns it.
    next: AtomicPtr<Segment>,
}

impl Segment {
    fn new() -> Self {
        Self {
            slots: std::array::from_fn(|_| Slot::new()),
            next: AtomicPtr::new(std::ptr::null_mut()),
        }
    }

    fn next(&self) -> Option<&Segment> {
        // SAFETY: a non-NULL `next` is a segment `grow` published, owned by this one and freed
        // only when this one drops.
        unsafe { self.next.load(Ordering::Acquire).as_ref() }
    }

    /// The next segment, appended when there is none: the table's only allocation after `open`.
    fn grow(&self) -> &Segment {
        if let Some(next) = self.next() {
            return next;
        }
        let fresh = Box::into_raw(Box::new(Segment::new()));
        match self.next.compare_exchange(
            std::ptr::null_mut(),
            fresh,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            // SAFETY: `fresh` is published as this segment's `next`, which it owns from now on.
            Ok(_) => unsafe { &*fresh },
            Err(theirs) => {
                // SAFETY: `fresh` was never published: it is still this call's to free.
                drop(unsafe { Box::from_raw(fresh) });
                // SAFETY: `theirs` is the non-NULL `next` another worker published (as `next`).
                unsafe { &*theirs }
            }
        }
    }
}

impl Drop for Segment {
    fn drop(&mut self) {
        let next = *self.next.get_mut();
        if !next.is_null() {
            // SAFETY: a `next` `grow` published from `Box::into_raw`, owned by this segment alone.
            drop(unsafe { Box::from_raw(next) });
        }
    }
}

/// What the SDK keeps in every instance box whatever the state's type: the tag, then the parked

#[repr(C)]
struct Head {
    tag: TypeId,
    /// The parked continuations, by ticket: slots claimed by compare-and-swap on the ticket, each
    parked: Segment,
    kept: Kept,
}

impl Head {
    fn new(tag: TypeId) -> Self {
        Self {
            tag,
            parked: Segment::new(),
            kept: Kept::default(),
        }
    }

    fn slots(&self) -> impl Iterator<Item = &Slot> {
        std::iter::successors(Some(&self.parked), |&s| s.next()).flat_map(|s| s.slots.iter())
    }

    /// The slot `ticket`'s op is parked in, locked; `None` when nothing is parked on it, without

    fn find(&self, ticket: Ticket) -> Option<Held<'_>> {
        if ticket.is_none() {
            return None;
        }
        let key = key(ticket);
        for slot in self.slots() {
            if slot.key.load(Ordering::Acquire) == key {
                let held = slot.hold();

                if slot.key.load(Ordering::Acquire) == key {
                    return Some(held);
                }
            }
        }
        None
    }

    /// A free slot claimed for `ticket` by compare-and-swap, locked: first one whose pooled

    fn claim<S: Send + Sync + 'static>(&self, ticket: Ticket) -> Held<'_> {
        let key = key(ticket);
        for any in [false, true] {
            for slot in self.slots() {
                if let Some(held) = Self::claim_free::<S>(slot, key, any) {
                    return held;
                }
            }
        }
        let mut segment = &self.parked;
        loop {
            segment = segment.grow();
            for slot in &segment.slots {
                if let Some(held) = Self::claim_free::<S>(slot, key, true) {
                    return held;
                }
            }
        }
    }

    /// `slot` claimed for `key`, locked, when it is free and (unless `any`) pools an `S` or

    fn claim_free<S: 'static>(slot: &Slot, key: u64, any: bool) -> Option<Held<'_>> {
        if slot.key.load(Ordering::Relaxed) != FREE {
            return None;
        }
        let mut held = slot.try_hold()?;
        let fits = any
            || held
                .cell()
                .as_mut()
                .is_none_or(|c| c.as_any_mut().is::<Option<S>>());
        let claimed = fits
            && slot
                .key
                .compare_exchange(FREE, key, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok();

        if claimed {
            Some(held)
        } else {
            None
        }
    }

    /// Park `state` on `ticket`, replacing what was parked there, in the slot's pooled allocation

    fn park<S: Send + Sync + 'static>(&self, ticket: Ticket, state: S) {
        if ticket.is_none() {
            return;
        }
        let mut held = match self.find(ticket) {
            Some(held) => held,
            None => self.claim::<S>(ticket),
        };
        let cell = held.cell();
        if let Some(pooled) = cell
            .as_mut()
            .and_then(|c| c.as_any_mut().downcast_mut::<Option<S>>())
        {
            let old = pooled.replace(state);
            drop(held);
            drop(old);
            return;
        }

        let old = cell.replace(Box::new(Some(state)));
        drop(held);
        drop(old);
    }

    /// Take back what `ticket` parked as an `S`, freeing its slot (the allocation stays, pooled);

    fn take<S: Send + Sync + 'static>(&self, ticket: Ticket) -> Option<S> {
        let mut held = self.find(ticket)?;
        let taken = held
            .cell()
            .as_mut()?
            .as_any_mut()
            .downcast_mut::<Option<S>>()?
            .take()?;
        held.free = true;
        Some(taken)
    }

    /// Retire `ticket` before dropping its state outside the slot lock. Return the emptied pooled

    fn forget(&self, ticket: Ticket) {
        let Some(mut held) = self.find(ticket) else {
            return;
        };
        let slot = held.slot;
        let mut retired = held.cell().take();
        held.free = true;
        drop(held);
        if let Some(c) = retired.as_mut() {
            c.clear();
        }

        if let Some(mut held) = slot.try_hold() {
            if slot.key.load(Ordering::Acquire) == FREE && held.cell().is_none() {
                *held.cell() = retired.take();
            }
        }
    }

    /// How many tickets hold parked state.
    fn count(&self) -> usize {
        self.slots()
            .filter(|s| s.key.load(Ordering::Acquire) != FREE)
            .count()
    }

    /// Every slot of the table, locked: a test holds the whole table while another worker crosses.
    #[cfg(test)]
    fn parked(&self) -> Vec<Held<'_>> {
        self.slots().map(Slot::hold).collect()
    }
}

/// The box an instance pointer points to: the [`Head`] at offset `0` whatever `T` is

#[repr(C)]
struct Tagged<T> {
    head: Head,
    state: T,
}

/// The SDK's [`Head`] of a non-NULL instance.
///
/// # Safety
/// `instance` is NULL or a `Tagged<_>` box the SDK minted in `open` and has not dropped, and it
/// lives for `'a` (the call contract).
unsafe fn head<'a>(instance: *mut c_void) -> Option<&'a Head> {
    // SAFETY: the caller's contract; the `Head` is at offset 0 whatever the state's type.
    (!instance.is_null()).then(|| unsafe { &*instance.cast::<Head>() })
}

/// The plugin's instance state, as a slot body is handed it. Only the SDK makes one; it lives for

pub struct Instance<'call, T> {
    ptr: *mut c_void,
    index: u32,
    ticket: Ticket,
    resuming: bool,
    opened: &'call Cell<Option<Box<Tagged<T>>>>,
    /// INVARIANT in `'call`: an instance cannot be shortened to a local's
    _call: PhantomData<fn(&'call ()) -> &'call ()>,
}

impl<T> std::fmt::Debug for Instance<'_, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Instance")
            .field("open", &!self.ptr.is_null())
            .field("slot", &self.index)
            .field("ticket", &self.ticket)
            .field("resuming", &self.resuming)
            .finish_non_exhaustive()
    }
}

impl<'call, T: Send + Sync + 'static> Instance<'call, T> {
    /// The state `open` installed; `None` before `open` (in `validate` and `open` itself) or when

    #[must_use]
    pub fn get(&self) -> Option<&'call T> {
        if self.ptr.is_null() {
            return None;
        }
        // SAFETY: a non-NULL instance is a `Tagged<_>` box the SDK minted in `open` (`Safe` at OPEN;
        // `plugin_door!` refuses a `Safe` slot beside a raw `open`) and has not dropped (the call
        // contract), and its `TypeId` is at offset 0 whatever the state's type.
        let tag = unsafe { self.ptr.cast::<TypeId>().read() };
        if tag != TypeId::of::<T>() {
            return None;
        }
        // SAFETY: the tag says the box is a `Tagged<T>`; it lives until `close` answers READY,
        // after every other call has returned, so beyond `'call`.
        Some(unsafe { &(*self.ptr.cast::<Tagged<T>>()).state })
    }

    /// Install the state, in `open`. It becomes the instance only if `open` answers READY; a

    pub fn open(&self, state: T) {
        assert!(
            self.index == slot::OPEN,
            "Instance::open: the state is installed in `open` only"
        );
        self.opened.set(Some(Box::new(Tagged {
            head: Head::new(TypeId::of::<T>()),
            state,
        })));
    }

    /// Install the state in `open`, PRE-PARKING `parked` on this call's ticket — for an `open`

    pub fn open_parking<S: Send + Sync + 'static>(&self, state: T, parked: S) {
        assert!(
            self.index == slot::OPEN,
            "Instance::open_parking: the state is installed in `open` only"
        );
        let tagged = Box::new(Tagged {
            head: Head::new(TypeId::of::<T>()),
            state,
        });

        tagged.head.park(self.ticket, parked);
        self.opened.set(Some(tagged));
    }

    /// THE GENERATION BORROW this op is lent: a string or payload borrowed for
    /// `'call` (the instance state [`Instance::get`] answers, or the program's memory) lives at
    /// least until the instance's next refresh generation, so the runtime writers
    /// ([`AbiStr::lent`](crate::abi::mechanism::call::AbiStr::lent),
    /// [`Out::lent_str`](super::Out::lent_str)) take it as their proof. A local of the body, or a
    /// string the host lent the call, is refused at compile time.
    ///
    /// ```
    /// use busbar_contract::abi::mechanism::call::{AbiStr, OutHead, Outcome};
    /// use busbar_contract::abi::sdk::{Instance, Out};
    /// struct State {
    ///     name: String,
    /// }
    /// fn answer(instance: Instance<'_, State>, mut out: Out<'_, OutHead>) -> Outcome {
    ///     let gen = instance.generation();
    ///     if let Some(state) = instance.get() {
    ///         let _named: AbiStr = AbiStr::lent(&state.name, &gen);
    ///         out.error_lent(&state.name, &gen);
    ///     }
    ///     Outcome::Failed
    /// }
    /// ```
    #[must_use]
    pub fn generation(&self) -> Gen<'call> {
        debug_assert_ne!(
            self.index,
            slot::CLOSE,
            "Instance::generation: close frees the state the borrow names"
        );
        // SAFETY: `'call` is the instance's lifetime, which nothing but the instance state
        // (`get`) and the program's memory is borrowed for: the body's own locals and what the
        // host lent the call live for shorter, unrelated lifetimes, and `Instance` is invariant in
        // `'call`, so it is never shortened to theirs. The state lives until `close` answers
        // READY, after every other call of the instance, so past its next refresh generation.
        unsafe { Gen::assume() }
    }

    fn head(&self) -> Option<&'call Head> {
        // SAFETY: a non-NULL instance is the SDK's box, alive beyond `'call` (as `get`).
        unsafe { head(self.ptr) }
    }

    /// PARK `state` on this call's ticket across its PENDING answer: the op's own continuation

    pub fn park<S: Send + Sync + 'static>(&self, state: S) {
        if let Some(h) = self.head() {
            h.park(self.ticket, state);
        }
    }

    /// Take back what [`Instance::park`] parked on this call's ticket, in the op's RESUME, by

    #[must_use]
    pub fn resume_value<S: Send + Sync + 'static>(&self) -> Option<S> {
        if !self.resuming {
            return None;
        }
        self.head()?.take(self.ticket)
    }

    /// [`Instance::resume_value`], boxed. The box is a fresh allocation: a body on the request path

    #[must_use]
    pub fn resume<S: Send + Sync + 'static>(&self) -> Option<Box<S>> {
        self.resume_value().map(Box::new)
    }

    /// How many tickets hold parked state on this instance.
    #[must_use]
    pub fn parked_count(&self) -> usize {
        self.head().map_or(0, Head::count)
    }

    /// Whether this entry is its op's RESUME (the mechanism's `FLAG_RESUME`).
    #[must_use]
    pub const fn resuming(&self) -> bool {
        self.resuming
    }

    /// This call's ticket ([`Ticket::NONE`] for a call that may not pend).
    #[must_use]
    pub const fn ticket(&self) -> Ticket {
        self.ticket
    }
}

/// A slot body with no `unsafe`: [`RawSlot`](crate::abi::sdk::door::RawSlot)'s safe form, named in

pub trait SafeSlot {
    /// The slot's `in`.
    type In: AbiIn;
    /// The slot's `out`.
    type Out: AbiOut;
    /// The plugin's instance state: one type for every slot of the plugin.
    type State: Send + Sync + 'static;
    /// The body. `input` is the host's `in`, lent for the call; `out` a private copy of the

    fn call(
        instance: Instance<'_, Self::State>,
        input: Lent<'_, Self::In>,
        out: Out<'_, Self::Out>,
    ) -> Outcome;
}

/// A [`SafeSlot`] as a table entry: `validate: Safe<Validate>` in
/// [`plugin_door!`](crate::plugin_door).
///
/// ```
/// use busbar_contract::abi::mechanism::call::{InHead, OutHead, Outcome};
/// use busbar_contract::abi::mechanism::lifecycle::*;
/// use busbar_contract::abi::sdk::{Instance, Lent, Out, Safe, SafeSlot};
/// struct State(u64);
/// # macro_rules! ready { ($n:ident, $i:ty, $o:ty) => {
/// #     struct $n;
/// #     impl SafeSlot for $n { type In = $i; type Out = $o; type State = State;
/// #         fn call(_: Instance<'_, State>, _: Lent<'_, $i>, _: Out<'_, $o>) -> Outcome {
/// #             Outcome::Ready } }
/// # } }
/// # ready!(V, ValidateIn, OutHead); ready!(Rf, RefreshIn, OutHead); ready!(Rt, GenIn, OutHead);
/// # ready!(Dr, DriveIn, OutHead); ready!(Cn, CancelIn, CancelOut); ready!(Rl, ReleaseIn, OutHead);
/// # ready!(Cl, InHead, OutHead);
/// struct Open;
/// impl SafeSlot for Open {
///     type In = OpenIn;
///     type Out = OpenOut;
///     type State = State;
///     fn call(i: Instance<'_, State>, input: Lent<'_, OpenIn>, _: Out<'_, OpenOut>) -> Outcome {
///         i.open(State(input.field(|x| &x.settings).bytes().len() as u64));
///         Outcome::Ready
///     }
/// }
/// struct Tick;
/// impl SafeSlot for Tick {
///     type In = TickIn;
///     type Out = TickOut;
///     type State = State;
///     fn call(i: Instance<'_, State>, _: Lent<'_, TickIn>, mut out: Out<'_, TickOut>) -> Outcome {
///         out.set(|o| &o.next_tick_ns, i.get().map_or(0, |s| s.0));
///         Outcome::Ready
///     }
/// }
/// busbar_contract::plugin_door! {
///     ops: busbar_contract::abi::secret::Ops,
///     statement: busbar_contract::abi::sdk::door::statement("safe", "0", 1),
///     lifecycle: { validate: Safe<V>, open: Safe<Open>, refresh: Safe<Rf>, retire: Safe<Rt>,
///                  tick: Safe<Tick>, drive: Safe<Dr>, cancel: Safe<Cn>, release: Safe<Rl>,
///                  close: Safe<Cl> },
///     kind_ops: { resolve: Safe<Resolve> },
/// }
/// # struct Resolve;
/// # impl SafeSlot for Resolve {
/// #     type In = busbar_contract::abi::secret::ResolveIn;
/// #     type Out = busbar_contract::abi::secret::ResolveOut;
/// #     type State = State;
/// #     fn call(_: Instance<'_, State>, _: Lent<'_, Self::In>, _: Out<'_, Self::Out>) -> Outcome {
/// #         Outcome::Ready } }
/// # fn main() { let _ = door(); }
/// ```
///
/// A `Safe` slot beside a raw `open` does not compile: the instance it would read is not one the
/// SDK minted.
///
/// ```compile_fail,E0080
/// use busbar_contract::abi::mechanism::call::{InHead, OutHead, Outcome};
/// use busbar_contract::abi::mechanism::lifecycle::*;
/// use busbar_contract::abi::sdk::door::RawSlot;
/// use busbar_contract::abi::sdk::{Instance, Lent, Out, Safe, SafeSlot};
/// # use std::ffi::c_void;
/// # macro_rules! ready { ($n:ident, $i:ty, $o:ty) => {
/// #     struct $n;
/// #     impl RawSlot for $n { type In = $i; type Out = $o;
/// #         unsafe fn call(_: *mut c_void, _: &$i, _: &mut $o) -> Outcome { Outcome::Ready } }
/// # } }
/// # ready!(V, ValidateIn, OutHead); ready!(Rf, RefreshIn, OutHead); ready!(Rt, GenIn, OutHead);
/// # ready!(Dr, DriveIn, OutHead); ready!(Cn, CancelIn, CancelOut); ready!(Rl, ReleaseIn, OutHead);
/// # ready!(Cl, InHead, OutHead); ready!(Resolve, busbar_contract::abi::secret::ResolveIn,
/// #     busbar_contract::abi::secret::ResolveOut);
/// ready!(RawOpen, OpenIn, OpenOut); // a raw `open`: it answers any pointer it likes
/// struct Tick;
/// impl SafeSlot for Tick {
///     type In = TickIn;
///     type Out = TickOut;
///     type State = u64;
///     fn call(i: Instance<'_, u64>, _: Lent<'_, TickIn>, _: Out<'_, TickOut>) -> Outcome {
///         let _ = i.get();
///         Outcome::Ready
///     }
/// }
/// busbar_contract::plugin_door! {
///     ops: busbar_contract::abi::secret::Ops,
///     statement: busbar_contract::abi::sdk::door::statement("mixed", "0", 1),
///     lifecycle: { validate: V, open: RawOpen, refresh: Rf, retire: Rt, tick: Safe<Tick>,
///                  drive: Dr, cancel: Cn, release: Rl, close: Cl },
///     kind_ops: { resolve: Resolve },
/// }
/// # fn main() { let _ = door(); }
/// ```
#[derive(Debug)]
pub struct Safe<S>(PhantomData<S>);

// SAFETY: `SAFE` is true and earned: `enter` reads the instance only as the SDK's `Tagged` box,
// and an `open` behind `Safe` answers only the box it minted.
unsafe impl<S: SafeSlot> Entry for Safe<S> {
    type In = S::In;
    type Out = S::Out;
    const SAFE: bool = true;

    unsafe fn enter(instance: *mut c_void, index: u32, input: &S::In, out: &mut S::Out) -> Outcome {
        let opened = Cell::new(None);
        // SAFETY: every `in` leads with its `InHead` (`AbiIn`'s contract); `input` is live.
        let call = unsafe { std::ptr::from_ref(input).cast::<InHead>().read() };
        let resuming = call.flags & FLAG_RESUME != 0;
        // SAFETY: a non-NULL instance is the SDK's box, alive for the call (the call contract).
        let parked = unsafe { head(instance) };
        let reply_key = ReplyKey::of(call.ticket);
        let prior_report = parked.and_then(|h| h.kept.begin(reply_key));
        if let (Some(h), false) = (parked, resuming) {
            h.forget(call.ticket);
        }
        let handle = Instance {
            ptr: instance,
            index,
            ticket: call.ticket,
            resuming,
            opened: &opened,
            _call: PhantomData,
        };

        let reporting: Reporting = Cell::new(prior_report);

        let holders: Holders = RefCell::new(Vec::new());

        let written = match parked {
            Some(h) if index != slot::OPEN => Out::kept(&mut *out, &h.kept, &reporting, &holders),
            // SAFETY: `input` is the trampoline's copy of the host's `in` for slot `index`.
            _ => Out::lent(&mut *out, unsafe { lent_reason(index, input) }, &holders),
        };
        // SAFETY: `input` is the trampoline's copy of the host's `in`, whose every pointer is
        // valid for the call (`Entry::enter`'s contract), and it lives until this returns.
        let mut answered = S::call(handle, unsafe { Lent::new(input) }, written);
        if !holders_live(&holders) {
            answered = Outcome::Fault;
        }
        let reported = reporting.take();
        let kept_report = reported
            .as_ref()
            .is_some_and(|report| report.has_envelope());
        if let Some(h) = parked {
            if answered != Outcome::Pending {
                h.forget(call.ticket);
            }
            if index == slot::CANCEL {
                let any = input as &dyn Any;
                let cancelled = any
                    .downcast_ref::<CancelIn>()
                    .map(|c| c.ticket)
                    .or_else(|| {
                        any.downcast_ref::<crate::abi::plane::PlaneCancelIn>()
                            .map(|c| c.cancel.ticket)
                    });
                if let Some(ticket) = cancelled {
                    h.forget(ticket);
                }
            }
        }

        if let (Some(h), Some(r)) = (parked, reported) {
            h.kept.keep(reply_key, r);
        }
        match index {
            slot::OPEN => {
                debug_assert!(size_of::<S::Out>() >= size_of::<OpenOut>());
                let minted = match (answered, opened.take()) {
                    (Outcome::Ready | Outcome::Pending, Some(b)) => {
                        Box::into_raw(b).cast::<c_void>()
                    }
                    (_, Some(_)) => std::ptr::null_mut(),

                    (Outcome::Ready | Outcome::Pending, None) => instance,
                    (_, None) if !instance.is_null() => {
                        // SAFETY: the SDK's `Tagged<S::State>` box this open minted on its earlier
                        // PENDING; the open failed, so the host holds no instance and will not pass
                        // it again (the call contract).
                        drop(unsafe { Box::from_raw(instance.cast::<Tagged<S::State>>()) });
                        std::ptr::null_mut()
                    }
                    (_, None) => std::ptr::null_mut(),
                };
                // SAFETY: at OPEN, `S::Out` is the kind's `open` `out`, which leads with an
                // `OpenOut` (`KindOps`'s contract); `out` is a live `&mut` to it.
                unsafe { (*std::ptr::from_mut(out).cast::<OpenOut>()).instance = minted };
            }
            slot::CLOSE if answered == Outcome::Ready && !instance.is_null() => {
                // SAFETY: as `Instance::get`: the tag at offset 0 of the SDK's box.
                let tag = unsafe { instance.cast::<TypeId>().read() };
                if tag != TypeId::of::<S::State>() {
                    return Outcome::Fault;
                }
                // SAFETY: every `out` leads with its `OutHead` (`AbiOut`); `out` is live.
                let head = unsafe { &mut *std::ptr::from_mut(out).cast::<OutHead>() };

                head.error = crate::abi::mechanism::call::AbiStr::ABSENT;
                head.extensions = crate::abi::mechanism::call::Blob::ABSENT;
                if kept_report {
                    head.envelope.metrics = std::ptr::null();
                    head.envelope.metrics_len = 0;
                    head.envelope.diags = std::ptr::null();
                    head.envelope.diags_len = 0;
                }
                // SAFETY: the SDK's `Tagged<S::State>` box from `open`; `close` answered READY with
                // no other op in flight, so the host never passes it again (the call contract).
                let gone = unsafe { Box::from_raw(instance.cast::<Tagged<S::State>>()) };

                let _ = crate::abi::sdk::boundary::caught(move || drop(gone));
            }
            _ => {}
        }
        answered
    }
}

/// The reason buffer the host lent an instance-less call: `validate`'s and `open`'s (both
/// `err_buf`/`err_cap`), the secret kind's `check` (`err_buf`/`err_cap`) and the auth kind's
/// `target` (`buf`/`buf_cap`); `None` for any other slot or when none was lent.
///
/// # Safety
/// `input` is the trampoline's copy of the host's `in` for slot `index`.
unsafe fn lent_reason<I: 'static>(index: u32, input: &I) -> Option<Reason> {
    let any = input as &dyn Any;
    if let Some(c) = any.downcast_ref::<crate::abi::secret::CheckIn>() {
        return (!c.err_buf.is_null() && c.err_cap > 0).then_some(Reason {
            buf: c.err_buf,
            cap: c.err_cap,
            open: false,
        });
    }
    if let Some(t) = any.downcast_ref::<crate::abi::auth::TargetIn>() {
        return (!t.buf.is_null() && t.buf_cap > 0).then_some(Reason {
            buf: t.buf,
            cap: t.buf_cap,
            open: false,
        });
    }
    let (buf, cap, open) = match index {
        slot::VALIDATE => {
            let v = (input as &dyn Any).downcast_ref::<ValidateIn>()?;
            (v.err_buf, v.err_cap, false)
        }
        slot::OPEN => {
            debug_assert!(size_of::<I>() >= size_of::<OpenIn>());
            // SAFETY: at OPEN, `I` is the kind's `open` `in`, which leads with an `OpenIn`
            // (`KindOps`'s contract).
            let o = unsafe { &*std::ptr::from_ref(input).cast::<OpenIn>() };
            (o.err_buf, o.err_cap, true)
        }
        _ => return None,
    };
    (!buf.is_null() && cap > 0).then_some(Reason { buf, cap, open })
}

#[cfg(test)]
#[path = "tests/safe_tests.rs"]
mod tests;
