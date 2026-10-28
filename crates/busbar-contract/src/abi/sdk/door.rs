// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DOOR MACRO — the plugin side of the shared mechanism (THE DESIGN, the plugin ABI; abi-v2, the door and the SDK).
//!
//! A plugin of any kind is two crates (abi-v2, the door's "crate shape"):
//!
//! * the LOGIC crate invokes [`plugin_door!`](crate::plugin_door) once. It expands, IN THAT CRATE,
//!   to `pub extern "C" fn door() -> &'static Door` — a [`DoorFn`](crate::abi::mechanism::door::DoorFn) answering a `'static`
//!   [`Door`] (magic [`DOOR_MAGIC`], [`MECHANISM_VERSION`], the kind, the kind's ABI version, the
//!   plugin's [`Statement`] and its ops table). No `#[no_mangle]`: a composition root that links
//!   several plugins links several `door` functions, one per crate, and a compiled-in row holds
//!   exactly that `DoorFn`;
//! * the thin `cdylib` crate holds one line, [`export_door!`](crate::export_door)`(crate_x::door)`,
//!   which emits the ONE exported symbol [`DOOR_SYMBOL`](crate::abi::mechanism::DOOR_SYMBOL),
//!   forwarding to the same `door`. Compiled in or dropped in, the kernel reaches the same table.
//!
//! EVERY SLOT IS A TRAMPOLINE. A table entry is `trampoline::<S, INDEX>` over a [`Slot`] the
//! plugin implements. The trampoline is the SDK's half of the call convention, the same for every
//! slot of every kind:
//!
//! * HEAD AND SIZE CHECKS — a NULL `out`, or one whose `size` cannot hold an [`OutHead`], is
//!   answered [`Outcome::Fault`] with nothing written; a NULL `in`, an `in` shorter than its
//!   [`InHead`], or an `in.op` that is not this slot's index is [`Outcome::Fault`] (the `in.op`
//!   check is the SDK's own reading of [`InHead::op`]: a call routed to the wrong slot never runs);
//!   the host's heads are read unaligned, so a C host owes no alignment;
//! * the `in` is read up to `min(in.size, size_of In)` and an absent tail reads as zero;
//! * `catch_unwind` around the slot body: a panic is [`Outcome::Fault`], never an abort and never
//!   an unwind across the boundary (every plugin builds `panic = "unwind"`, ARCHITECT ruling,
//!   m3-inputs; both macros refuse to compile under `panic = "abort"`);
//! * PANIC-SAFE OUT WRITES — the body writes a private copy of `out`; only a body that RETURNED is
//!   written back, and then at most `min(out.size, size_of Out)` bytes, with `out.size` set to the
//!   plugin's own `size_of Out` (the host clamps) and `out.outcome` MIRRORING the returned outcome.
//!   A panicking body writes nothing but `outcome = FAULT`;
//! * [`Outcome::Pending`] answered on a [`Ticket::NONE`](crate::abi::mechanism::ticket::Ticket::NONE)
//!   call is [`Outcome::Fault`] (the mechanism's rule, `OutHead::outcome`);
//! * THE CALL CAPTURE — the body runs under the plugin image's call capture as the thread's scoped
//!   `tracing` dispatcher, and whatever it logged, through `tracing` or `log`, rides the reply's
//!   #85 envelope as log diagnostics ([`capture`](crate::abi::sdk::capture)). A body that faulted
//!   carries none.
//!
//! Every name here is a TYPE, a TRAIT or a FUNCTION: the contract crate holds no `static`
//! (`contract-stateless`). The `'static` door, Statement and table exist only as `const` items the
//! macro expands in the plugin crate, and so does the one per-thread call-capture slot
//! ([`CaptureHome`]), which is the plugin image's own. There is no load-time registration
//! (`.init_array` is retired).

use std::ffi::c_void;
use std::mem::{offset_of, size_of, MaybeUninit};
use std::panic::{catch_unwind, RefUnwindSafe, UnwindSafe};
use std::ptr;

use crate::abi::host::conn::connector::Need;
use crate::abi::mechanism::call::{AbiStr, Blob, InHead, Op, OutHead, Outcome, RawOutcome};
use crate::abi::mechanism::door::{
    Door, DoorFn, DoorParts, KindTailHead, MarkWord, MetricFamily, Rewrite, Section, Statement,
    REWRITE_ALIAS,
};
use crate::abi::mechanism::lifecycle::{
    self as lc, CancelIn, CancelOut, DriveIn, GenIn, OpenIn, OpenOut, OpsHead, ReadyIn, RefreshIn,
    ReleaseIn, TickIn, TickOut, ValidateIn,
};
use crate::abi::mechanism::{KindCode, DOOR_MAGIC, MECHANISM_VERSION};
use crate::abi::sdk::capture::CaptureHome;

/// An `in` struct a slot reads.
///
/// # Safety
/// The implementor is `#[repr(C)]`, its FIRST field is an [`InHead`] (or it is [`InHead`]), and
/// EVERY initialized bit pattern is a valid value of it — all-zero included: integers, raw pointers,
/// `Option<fn>` and `#[repr(transparent)]` bytes only; no `bool`, enum, reference or `NonNull`. The
/// trampoline copies the host's bytes into it and zero-fills an absent tail.
pub unsafe trait AbiIn: Copy + UnwindSafe + RefUnwindSafe + 'static {}

/// An `out` struct a slot writes.
///
/// # Safety
/// The implementor is `#[repr(C)]`, its FIRST field is an [`OutHead`] (or it is [`OutHead`]), and
/// EVERY initialized bit pattern is a valid value of it, as for [`AbiIn`].
pub unsafe trait AbiOut: Copy + UnwindSafe + RefUnwindSafe + 'static {}

/// A blank `in`, every byte zero: the host fills the fields it states and the dispatcher the head.
#[must_use]
pub fn blank_in<T: AbiIn>() -> T {
    // SAFETY: `AbiIn` promises all-zero is a valid value of `T`.
    unsafe { core::mem::zeroed() }
}

/// A blank `out`, every byte zero, for the plugin to answer into.
#[must_use]
pub fn blank_out<T: AbiOut>() -> T {
    // SAFETY: `AbiOut` promises all-zero is a valid value of `T`.
    unsafe { core::mem::zeroed() }
}

// SAFETY (all below): each is `#[repr(C)]`, leads with its head (or is the head), and every field
// is an integer, a raw pointer, an `Option<fn>` or a `#[repr(transparent)]` byte — all-zero valid.
// (`UnwindSafe`/`RefUnwindSafe` hold of each automatically: plain data, no interior mutability.)
unsafe impl AbiIn for InHead {}
unsafe impl AbiIn for ValidateIn {}
unsafe impl AbiIn for OpenIn {}
unsafe impl AbiIn for GenIn {}
unsafe impl AbiIn for RefreshIn {}
unsafe impl AbiIn for TickIn {}
unsafe impl AbiIn for DriveIn {}
unsafe impl AbiIn for CancelIn {}
unsafe impl AbiIn for ReleaseIn {}
unsafe impl AbiIn for ReadyIn {}
unsafe impl AbiOut for OutHead {}
unsafe impl AbiOut for OpenOut {}
unsafe impl AbiOut for TickOut {}
unsafe impl AbiOut for CancelOut {}

/// A kind's ops table: what [`plugin_door!`](crate::plugin_door) is generic over.
///
/// # Safety
/// The implementor is `#[repr(C)]`, its first field is `head: OpsHead`, and every field after it is
/// an `Option<Op>` — kind op `k` at slot index `LIFECYCLE_SLOTS + k`, contiguous (the mechanism's
/// SLOT LAYOUT rule). Its `Lifecycle`'s `out` at slot `open` leads with the lifecycle's `OpenOut`
/// (a [`Safe`](crate::abi::sdk::safe::Safe) `open` writes the instance there), and its `in` there
/// with the lifecycle's `OpenIn` (a failed `open` writes its reason into `OpenIn::err_buf`).
///
/// # Safety (the all-absent table)
///
/// Every field of the table is an integer or an `Option` of a function pointer, so the all-zero
/// bit pattern is a valid table with every op absent ([`absent_table`]).
pub unsafe trait KindOps: Copy + 'static {
    /// The kind this table belongs to; the door's `kind` and `kind_abi` follow from it.
    const KIND: KindCode;
    /// The `in`/`out` of each of the nine LIFECYCLE slots, stated as [`KindSlot`]s at the slot's
    /// index: [`Lifecycle`], or a kind's own where the kind widens a lifecycle `in`/`out` (the
    /// plane's `open`, `refresh` and `drive`).
    type Lifecycle: 'static;
}

/// The lifecycle's own `in`/`out` for every lifecycle slot (`abi::mechanism::lifecycle`): the
/// [`KindOps::Lifecycle`] of every kind that widens none.
#[derive(Debug, Clone, Copy)]
pub struct Lifecycle;

/// `unsafe impl KindSlot<{ INDEX }> for T { In, Out }`, once per row: THE ONE way every kind
/// states its slots' structs. Leading doc attributes (a kind's `compile_fail` proof that a slot
/// wired to another op's structs is refused) document an empty `impl T`.
macro_rules! slot_structs {
    ($(#[$doc:meta])+ $t:ty { $($rows:tt)* }) => {
        $(#[$doc])+
        impl $t {}
        $crate::abi::sdk::door::slot_structs!($t { $($rows)* });
    };
    ($t:ty { $($index:expr => $in:ty, $out:ty;)* }) => {$(
        // SAFETY: the structs the kind's ABI states for this slot.
        unsafe impl $crate::abi::sdk::door::KindSlot<{ $index }> for $t {
            type In = $in;
            type Out = $out;
        }
    )*};
}
pub(crate) use slot_structs;

slot_structs!(Lifecycle {
    lc::slot::VALIDATE => ValidateIn, OutHead;
    lc::slot::OPEN => OpenIn, OpenOut;
    lc::slot::REFRESH => RefreshIn, OutHead;
    lc::slot::RETIRE => GenIn, OutHead;
    lc::slot::TICK => TickIn, TickOut;
    lc::slot::DRIVE => DriveIn, OutHead;
    lc::slot::CANCEL => CancelIn, CancelOut;
    lc::slot::RELEASE => ReleaseIn, OutHead;
    lc::slot::CLOSE => InHead, OutHead;
    lc::slot::READY => ReadyIn, OutHead;
    lc::slot::MIGRATE => ValidateIn, OutHead;
});

/// The `in`/`out` of slot `INDEX` (its ABSOLUTE index, the number `InHead::op` carries). A kind
/// implements it on its `Ops` once per kind op (`LIFECYCLE_SLOTS + k`), next to the table in
/// `abi/<kind>/`, and on its [`KindOps::Lifecycle`] once per lifecycle slot;
/// [`plugin_door!`](crate::plugin_door) then refuses to compile any slot, lifecycle or kind op,
/// whose [`Slot`] reads or writes other structs.
///
/// ```
/// use busbar_contract::abi::mechanism::call::{InHead, Op, OutHead, Outcome};
/// use busbar_contract::abi::mechanism::lifecycle::*;
/// use busbar_contract::abi::mechanism::KindCode;
/// use busbar_contract::abi::sdk::door::{KindOps, KindSlot, Slot};
/// # use std::ffi::c_void;
/// #[repr(C)]
/// #[derive(Clone, Copy)]
/// pub struct OneOp { head: OpsHead, only: Option<Op> }
/// unsafe impl KindOps for OneOp {
///     const KIND: KindCode = KindCode::Store;
///     type Lifecycle = busbar_contract::abi::sdk::door::Lifecycle;
/// }
/// // Kind op 0 reads a `GenIn` and writes a `TickOut`.
/// unsafe impl KindSlot<{ LIFECYCLE_SLOTS }> for OneOp { type In = GenIn; type Out = TickOut; }
/// # macro_rules! ready { ($n:ident, $i:ty, $o:ty) => {
/// #     struct $n;
/// #     impl Slot for $n { type In = $i; type Out = $o;
/// #         fn call(_: *mut c_void, _: &$i, _: &mut $o) -> Outcome { Outcome::Ready } }
/// # } }
/// # ready!(V, ValidateIn, OutHead); ready!(Op_, OpenIn, OpenOut); ready!(Rf, RefreshIn, OutHead);
/// # ready!(Rt, GenIn, OutHead); ready!(Tk, TickIn, TickOut); ready!(Dr, DriveIn, OutHead);
/// # ready!(Cn, CancelIn, CancelOut); ready!(Rl, ReleaseIn, OutHead); ready!(Cl, InHead, OutHead);
/// ready!(Only, GenIn, TickOut); // the kind's own structs: compiles
/// busbar_contract::plugin_door! {
///     ops: OneOp,
///     statement: busbar_contract::abi::sdk::door::statement("one-op", "0", 1),
///     lifecycle: { validate: V, open: Op_, refresh: Rf, retire: Rt, tick: Tk, drive: Dr,
///                  cancel: Cn, release: Rl, close: Cl },
///     kind_ops: { only: Only },
/// }
/// # fn main() { let _ = door(); }
/// ```
///
/// The same plugin with the kind op wired to ANOTHER op's structs does not compile:
///
/// ```compile_fail,E0271
/// use busbar_contract::abi::mechanism::call::{InHead, Op, OutHead, Outcome};
/// use busbar_contract::abi::mechanism::lifecycle::*;
/// use busbar_contract::abi::mechanism::KindCode;
/// use busbar_contract::abi::sdk::door::{KindOps, KindSlot, Slot};
/// # use std::ffi::c_void;
/// #[repr(C)]
/// #[derive(Clone, Copy)]
/// pub struct OneOp { head: OpsHead, only: Option<Op> }
/// unsafe impl KindOps for OneOp {
///     const KIND: KindCode = KindCode::Store;
///     type Lifecycle = busbar_contract::abi::sdk::door::Lifecycle;
/// }
/// unsafe impl KindSlot<{ LIFECYCLE_SLOTS }> for OneOp { type In = GenIn; type Out = TickOut; }
/// # macro_rules! ready { ($n:ident, $i:ty, $o:ty) => {
/// #     struct $n;
/// #     impl Slot for $n { type In = $i; type Out = $o;
/// #         fn call(_: *mut c_void, _: &$i, _: &mut $o) -> Outcome { Outcome::Ready } }
/// # } }
/// # ready!(V, ValidateIn, OutHead); ready!(Op_, OpenIn, OpenOut); ready!(Rf, RefreshIn, OutHead);
/// # ready!(Rt, GenIn, OutHead); ready!(Tk, TickIn, TickOut); ready!(Dr, DriveIn, OutHead);
/// # ready!(Cn, CancelIn, CancelOut); ready!(Rl, ReleaseIn, OutHead); ready!(Cl, InHead, OutHead);
/// ready!(Only, CancelIn, CancelOut); // another op's structs: refused
/// busbar_contract::plugin_door! {
///     ops: OneOp,
///     statement: busbar_contract::abi::sdk::door::statement("one-op", "0", 1),
///     lifecycle: { validate: V, open: Op_, refresh: Rf, retire: Rt, tick: Tk, drive: Dr,
///                  cancel: Cn, release: Rl, close: Cl },
///     kind_ops: { only: Only },
/// }
/// # fn main() { let _ = door(); }
/// ```
///
/// # Safety
/// `In`/`Out` are exactly the structs the kind's ABI states for slot `INDEX` of `Self`; the
/// trampoline trusts them to size its copies.
pub unsafe trait KindSlot<const INDEX: u32> {
    /// The op's `in`.
    type In: AbiIn;
    /// The op's `out`.
    type Out: AbiOut;
}

// SAFETY (all seven): each kind's `Ops` is `#[repr(C)]`, leads with `head: OpsHead`, and appends
// only `Option<Op>` slots (`abi/<kind>/`).
unsafe impl KindOps for crate::abi::store::Ops {
    const KIND: KindCode = KindCode::Store;
    type Lifecycle = Lifecycle;
}
unsafe impl KindOps for crate::abi::secret::Ops {
    const KIND: KindCode = KindCode::Secret;
    type Lifecycle = Lifecycle;
}
unsafe impl KindOps for crate::abi::auth::Ops {
    const KIND: KindCode = KindCode::Auth;
    type Lifecycle = Lifecycle;
}
unsafe impl KindOps for crate::abi::hook::Ops {
    const KIND: KindCode = KindCode::Hook;
    type Lifecycle = Lifecycle;
}
unsafe impl KindOps for crate::abi::export::Ops {
    const KIND: KindCode = KindCode::Export;
    type Lifecycle = Lifecycle;
}
unsafe impl KindOps for crate::abi::plane::Ops {
    const KIND: KindCode = KindCode::Plane;
    type Lifecycle = crate::abi::plane::PlaneLifecycle;
}
unsafe impl KindOps for crate::abi::transport::Ops {
    const KIND: KindCode = KindCode::Transport;
    type Lifecycle = Lifecycle;
}

/// One slot body. A plugin implements it on a type of its own, one per slot, and names that type
/// in [`plugin_door!`](crate::plugin_door).
pub trait Slot {
    /// The slot's `in`.
    type In: AbiIn;
    /// The slot's `out`.
    type Out: AbiOut;
    /// The body. `input` is a private copy of the host's `in` (tail zero-filled), `out` a private
    /// copy of the host's `out`; the trampoline writes `out` back and mirrors the returned outcome
    /// into `out.head.outcome`, so the body need not set it.
    fn call(instance: *mut c_void, input: &Self::In, out: &mut Self::Out) -> Outcome;
}

/// What a table entry runs: a raw [`Slot`], or a [`SafeSlot`](crate::abi::sdk::safe::SafeSlot)
/// behind [`Safe`](crate::abi::sdk::safe::Safe). The trampoline is generic over this, so
/// [`plugin_door!`](crate::plugin_door) takes either in any slot position.
pub trait Entry {
    /// The slot's `in`.
    type In: AbiIn;
    /// The slot's `out`.
    type Out: AbiOut;
    /// Whether this entry reads the instance as the SDK's typed state
    /// ([`Safe`](crate::abi::sdk::safe::Safe)); `plugin_door!` then requires `open` to be one too.
    const SAFE: bool = false;
    /// The body.
    ///
    /// # Safety
    /// Called only by the trampoline, under the call contract: `input` and `out` are the
    /// trampoline's private copies of the host's `in` and `out`; every pointer the host put in
    /// `input` is valid for the call as the kind's ABI states it; `index` is the slot's own index;
    /// `instance` is NULL or the pointer this plugin's `open` answered READY, not yet answered
    /// READY by `close`, and `close` runs with no other op in flight on it.
    unsafe fn enter(
        instance: *mut c_void,
        index: u32,
        input: &Self::In,
        out: &mut Self::Out,
    ) -> Outcome;
}

impl<S: Slot> Entry for S {
    type In = S::In;
    type Out = S::Out;
    unsafe fn enter(instance: *mut c_void, _: u32, input: &S::In, out: &mut S::Out) -> Outcome {
        S::call(instance, input, out)
    }
}

/// THE TRAMPOLINE every table entry is: `S`'s body behind the SDK's checks (the module doc), under
/// the call capture `H` keeps. `INDEX` is the slot's index in its kind's table; an `in.op` naming
/// another slot is a fault.
extern "C" fn trampoline<S: Entry, H: CaptureHome, const INDEX: u32>(
    instance: *mut c_void,
    input: *const c_void,
    out: *mut c_void,
) -> RawOutcome {
    // SAFETY: the host passes `in`/`out` of this slot's types and the instance `open` answered
    // (the call convention); `enter` checks NULL and the heads' sizes before reading or writing
    // beyond them.
    RawOutcome::of(unsafe { enter::<S, H>(INDEX, instance, input.cast(), out.cast()) })
}

/// The trampoline's body.
///
/// # Safety
/// `out`, when non-NULL, points at a writable host `out` of at least `out.size` bytes whose first
/// field is an [`OutHead`]; `input`, when non-NULL, points at a readable host `in` of at least
/// `in.size` bytes whose first field is an [`InHead`].
unsafe fn enter<S: Entry, H: CaptureHome>(
    index: u32,
    instance: *mut c_void,
    input: *const S::In,
    out: *mut S::Out,
) -> Outcome {
    if out.is_null() {
        return Outcome::Fault;
    }
    let out_head = out.cast::<OutHead>();
    // SAFETY: `out` is non-NULL and leads with an `OutHead` (the caller's contract).
    let host_out = unsafe { ptr::addr_of!((*out_head).size).read_unaligned() } as usize;
    if host_out < size_of::<OutHead>() {
        // Not even the head fits: writing `outcome` would exceed what the host gave.
        return Outcome::Fault;
    }
    if input.is_null() {
        // SAFETY: the host's `out` holds at least a whole `OutHead` (checked above).
        unsafe { write_fault(out_head) };
        return Outcome::Fault;
    }
    let in_head = input.cast::<InHead>();
    // SAFETY: `input` is non-NULL and leads with an `InHead` (the caller's contract).
    let (host_in, op) = unsafe {
        (
            ptr::addr_of!((*in_head).size).read_unaligned() as usize,
            ptr::addr_of!((*in_head).op).read_unaligned(),
        )
    };
    if host_in < size_of::<InHead>() || op != index {
        // SAFETY: as above.
        unsafe { write_fault(out_head) };
        return Outcome::Fault;
    }

    // SAFETY: `S::In: AbiIn`/`S::Out: AbiOut` — all-zero is a valid value.
    let mut local_in: S::In = unsafe { MaybeUninit::zeroed().assume_init() };
    let mut local_out: S::Out = unsafe { MaybeUninit::zeroed().assume_init() };
    let in_n = host_in.min(size_of::<S::In>());
    let out_n = host_out.min(size_of::<S::Out>());
    // SAFETY: the host's `in` holds `host_in >= in_n` readable bytes and `local_in` holds
    // `size_of::<S::In>() >= in_n`; likewise `out_n` for `out`. Neither local overlaps a host buffer.
    unsafe {
        ptr::copy_nonoverlapping(
            input.cast::<u8>(),
            ptr::addr_of_mut!(local_in).cast::<u8>(),
            in_n,
        );
        ptr::copy_nonoverlapping(
            out.cast::<u8>(),
            ptr::addr_of_mut!(local_out).cast::<u8>(),
            out_n,
        );
    }

    // The body runs on COPIES moved into the closure and hands its `out` back only by returning:
    // a panic leaves nothing half-written for the trampoline to copy out. It runs under the call
    // capture, which is this thread's scoped `tracing` dispatcher for exactly as long as the body.
    let capture = H::with(|slot| slot.dispatch());
    let ran = tracing_core::dispatcher::with_default(&capture, || {
        catch_unwind(move || {
            let mut written = local_out;
            // SAFETY: `local_in`/`written` are this call's private copies of the host's `in`/`out`,
            // `index` is this slot's (checked against `in.op` above), and `instance` is what the
            // host passed: the call contract `Entry::enter` states.
            let answered = unsafe { S::enter(instance, index, &local_in, &mut written) };
            (answered, written)
        })
    });
    match ran {
        Ok((answered, mut local_out)) => {
            // SAFETY: `S::In` leads with an `InHead` (`AbiIn`).
            let ticket = unsafe { (*ptr::addr_of!(local_in).cast::<InHead>()).ticket };
            let outcome = if answered == Outcome::Pending && ticket.is_none() {
                Outcome::Fault
            } else {
                answered
            };
            // SAFETY: `S::Out` leads with an `OutHead` (`AbiOut`).
            let head = unsafe { &mut *ptr::addr_of_mut!(local_out).cast::<OutHead>() };
            head.outcome = RawOutcome::of(outcome);
            // The plugin writes back its own size (the mechanism's growth rule); the host clamps.
            head.size = size_of::<S::Out>() as u32;
            // What the body logged joins the envelope it answered.
            // SAFETY: the plugin's own `diags`, when set, point to `diags_len` live entries until
            // the next op on the ticket (the mechanism's memory rule).
            H::with(|slot| unsafe { slot.seal(&mut head.envelope) });
            // SAFETY: `out_n <= host_out` bytes of the host's `out` are writable, and
            // `out_n <= size_of::<S::Out>()` bytes of `local_out` are readable.
            unsafe {
                ptr::copy_nonoverlapping(
                    ptr::addr_of!(local_out).cast::<u8>(),
                    out.cast::<u8>(),
                    out_n,
                );
            }
            outcome
        }
        Err(payload) => {
            // A payload whose own `Drop` panics escapes here and aborts: the `extern "C"` floor.
            drop(payload);
            H::with(|slot| slot.discard());
            // SAFETY: the host's `out` holds at least a whole `OutHead` (checked above).
            unsafe { write_fault(out_head) };
            Outcome::Fault
        }
    }
}

/// A `T` table with every kind-op slot NULL (its head is the caller's to replace): the base
/// [`plugin_door!`](crate::plugin_door) fills the kind ops a door does not name from. A NULL kind op
/// is ABSENT; the loader admits one only in a slot its kind states optional (absent = pass, the
/// secret `check` and the auth `target`) and refuses a door that leaves any other slot NULL.
#[must_use]
pub const fn absent_table<T: KindOps>() -> T {
    // SAFETY: `T: KindOps` is `#[repr(C)]` with `head: OpsHead` first and only `Option<Op>` slots
    // after it; all-zero is a valid `OpsHead` (two zero `u32`s and `None` slots) and a valid `None`
    // for every slot.
    unsafe { MaybeUninit::<T>::zeroed().assume_init() }
}

/// Write `outcome = FAULT` into a host `out` head, and nothing else.
///
/// # Safety
/// `head` points at a writable [`OutHead`].
unsafe fn write_fault(head: *mut OutHead) {
    // SAFETY: the caller's contract.
    unsafe { ptr::addr_of_mut!((*head).outcome).write_unaligned(RawOutcome::of(Outcome::Fault)) };
}

/// The index of the table slot at byte `offset` of a [`KindOps`] table (the mechanism's SLOT
/// LAYOUT: the head's two `u32`s, then one `Option<Op>` per slot).
#[must_use]
pub const fn slot_at(offset: usize) -> u32 {
    ((offset - offset_of!(OpsHead, validate)) / size_of::<Option<Op>>()) as u32
}

/// How many slots a [`KindOps`] table holds, lifecycle included ([`OpsHead::slots`]).
#[must_use]
pub const fn slot_count<T: KindOps>() -> u32 {
    slot_at(size_of::<T>())
}

/// A table entry: the `trampoline` over `S` at `INDEX` under the call capture `H` keeps, refusing
/// to compile unless `S` reads and writes the structs `T` states for that slot ([`KindSlot`]): a
/// kind op's `T` is the kind's `Ops`, a lifecycle slot's its [`KindOps::Lifecycle`]. A table
/// holding any [`Safe`](crate::abi::sdk::safe::Safe) entry holds a `Safe` `open`, which mints the
/// instance the others read; [`plugin_door!`](crate::plugin_door) refuses to compile one that does
/// not, so a plugin builds its table with the macro, never by hand.
#[must_use]
pub const fn kind_op<T, S, H, const INDEX: u32>() -> Option<Op>
where
    T: KindSlot<INDEX>,
    S: Entry<In = <T as KindSlot<INDEX>>::In, Out = <T as KindSlot<INDEX>>::Out>,
    H: CaptureHome,
{
    Some(trampoline::<S, H, INDEX>)
}

/// The [`OpsHead`] of a `T` table: its `size` and `slots` stamped from `T`, the nine lifecycle
/// entries as given.
#[must_use]
#[allow(clippy::too_many_arguments)] // one argument per lifecycle slot, in table order
pub const fn ops_head<T: KindOps>(
    validate: Option<Op>,
    open: Option<Op>,
    refresh: Option<Op>,
    retire: Option<Op>,
    tick: Option<Op>,
    drive: Option<Op>,
    cancel: Option<Op>,
    release: Option<Op>,
    close: Option<Op>,
) -> OpsHead {
    OpsHead {
        size: size_of::<T>() as u32,
        slots: slot_count::<T>(),
        validate,
        open,
        refresh,
        retire,
        tick,
        drive,
        cancel,
        release,
        close,
    }
}

/// Borrowed `'static` UTF-8 as an [`AbiStr`].
#[must_use]
pub const fn abi_str(s: &'static str) -> AbiStr {
    AbiStr {
        ptr: s.as_ptr(),
        len: s.len(),
    }
}

/// The module name `from` an operator may write for the plugin, as the Statement's
/// [`REWRITE_ALIAS`] rewrite (`to` absent).
#[must_use]
pub const fn alias(from: &'static str) -> Rewrite {
    Rewrite {
        class: REWRITE_ALIAS,
        from: abi_str(from),
        ..Rewrite::ZERO
    }
}

/// A Statement naming the plugin, with no families, no diagnostic ids, no kind tail, no
/// extensions, no marks, no rewrites, no sections, no needs, no settings paths, no answers and no claims. Its `size`, `kind` and `kind_abi` are stamped by [`plugin_door!`](crate::plugin_door)
/// ([`stamp`]); a plugin extends it with struct-update syntax.
#[must_use]
pub const fn statement(name: &'static str, version: &'static str, max_inflight: u32) -> Statement {
    Statement {
        max_inflight,
        name: abi_str(name),
        version: abi_str(version),
        families: ptr::null::<MetricFamily>(),
        diag_ids: ptr::null::<AbiStr>(),
        secret_refs: ptr::null::<AbiStr>(),
        settings_schema: Blob::ABSENT,
        kind_tail: ptr::null::<KindTailHead>(),
        extensions: Blob::ABSENT,
        mark_words: ptr::null::<MarkWord>(),
        rewrites: ptr::null::<Rewrite>(),
        sections: ptr::null::<Section>(),
        needs: ptr::null::<Need>(),
        target_from: ABSENT,
        trust_from: ABSENT,
        answers: ptr::null::<AbiStr>(),
        claims: ptr::null::<AbiStr>(),
        ..Statement::ZERO
    }
}

/// An absent string.
const ABSENT: AbiStr = AbiStr::ZERO;

/// `statement` with `size`, `kind` and `kind_abi` stamped from `T`, so the Statement and the door
/// can never disagree on them.
#[must_use]
pub const fn stamp<T: KindOps>(statement: Statement) -> Statement {
    Statement {
        size: size_of::<Statement>() as u32,
        kind: T::KIND as u32,
        kind_abi: T::KIND.abi_version(),
        ..statement
    }
}

/// The [`Door`] of a `T` plugin; `ready` is its optional `ready` op (the door's tail), `None` for
/// a plugin that has none. The door macro's plumbing.
///
/// # Safety
///
/// As [`Door::__from_parts`]: `statement`'s lists, strings, blobs and kind tail point at their
/// stated counts of live `'static` data, and every non-NULL slot of `ops` honours the call
/// convention. The door macro's own `statement` and table meet it as the macro lays them out.
#[doc(hidden)]
#[must_use]
pub const unsafe fn door<T: KindOps>(
    statement: &'static Statement,
    ops: &'static T,
    ready: Option<Op>,
) -> Door {
    // SAFETY: the caller's contract; the head is the mechanism's own and `T`'s.
    unsafe {
        Door::__from_parts(DoorParts {
            magic: DOOR_MAGIC,
            mechanism_version: MECHANISM_VERSION,
            size: size_of::<Door>() as u32,
            kind: T::KIND as u32,
            kind_abi: T::KIND.abi_version(),
            statement,
            ops: ptr::from_ref(ops).cast::<OpsHead>(),
            ready,
        })
    }
}

/// THE SEALED DOOR (status row 195, ARCHITECT ruling on `admit_linked`): a [`DoorFn`] answers a
/// `&'static Door`, and a [`Door`]'s fields are private behind the `unsafe`
/// [`Door::__from_parts`] ([`door`] is `unsafe` over it), so the loader's safe `admit_linked`
/// takes any `DoorFn` safe code can name. Each refusal below has a twin that differs in the one
/// forbidden spelling and MUST compile.
///
/// A door literal is refused (its fields are private):
///
/// ```compile_fail
/// use busbar_contract::abi::mechanism::door::Door;
/// fn main() {
///     let _ = Door {
///         magic: 0,
///         mechanism_version: 0,
///         size: 0,
///         kind: 0,
///         kind_abi: 0,
///         statement: core::ptr::null(),
///         ops: core::ptr::null(),
///         ready: None,
///     };
/// }
/// ```
///
/// The constructor is refused in safe code; inside `unsafe` it is not:
///
/// ```compile_fail
/// use busbar_contract::abi::mechanism::door::{Door, DoorParts};
/// fn main() {
///     let _ = Door::__from_parts(DoorParts {
///         magic: 0,
///         mechanism_version: 0,
///         size: 0,
///         kind: 0,
///         kind_abi: 0,
///         statement: core::ptr::null(),
///         ops: core::ptr::null(),
///         ready: None,
///     });
/// }
/// ```
///
/// ```
/// use busbar_contract::abi::mechanism::door::{Door, DoorParts};
/// fn main() {
///     let _ = unsafe {
///         Door::__from_parts(DoorParts {
///             magic: 0,
///             mechanism_version: 0,
///             size: 0,
///             kind: 0,
///             kind_abi: 0,
///             statement: core::ptr::null(),
///             ops: core::ptr::null(),
///             ready: None,
///         })
///     };
/// }
/// ```
///
/// The SDK's `door` is refused in safe code too:
///
/// ```compile_fail
/// # use busbar_contract::abi::sdk::door::{absent_table, door, statement, stamp};
/// # use busbar_contract::abi::secret::Ops;
/// const ST: &busbar_contract::abi::mechanism::door::Statement =
///     &stamp::<Ops>(statement("p", "0", 1));
/// const OPS: &Ops = &absent_table::<Ops>();
/// fn main() {
///     let _ = door::<Ops>(ST, OPS, None);
/// }
/// ```
///
/// ```
/// # use busbar_contract::abi::sdk::door::{absent_table, door, statement, stamp};
/// # use busbar_contract::abi::secret::Ops;
/// const ST: &busbar_contract::abi::mechanism::door::Statement =
///     &stamp::<Ops>(statement("p", "0", 1));
/// const OPS: &Ops = &absent_table::<Ops>();
/// fn main() {
///     let _ = unsafe { door::<Ops>(ST, OPS, None) };
/// }
/// ```
///
/// A raw door function is no `DoorFn`; the door macro's `door` is:
///
/// ```compile_fail
/// extern "C" fn fake() -> *const busbar_contract::abi::mechanism::door::Door {
///     std::ptr::null()
/// }
/// fn main() {
///     let _: busbar_contract::abi::mechanism::door::DoorFn = fake;
/// }
/// ```
///
/// ```
/// # use busbar_contract::abi::sdk::life::{Life, Refreshed, Refusal};
/// # struct P;
/// # impl Life for P {
/// #     const CANCEL: u32 = 0;
/// #     fn open(_: &[u8], _: &[&[u8]], _: u64) -> Result<Self, Refusal> {
/// #         Ok(P)
/// #     }
/// #     fn refresh(&self, _: &[u8], _: &[&[u8]], _: u64) -> Result<Refreshed, Refusal> {
/// #         Ok(Refreshed::default())
/// #     }
/// # }
/// # mod plugin {
/// #     busbar_contract::plugin_door! {
/// #         ops: busbar_contract::abi::secret::Ops,
/// #         statement: busbar_contract::abi::sdk::door::statement("p", "0", 1),
/// #         lifecycle: life(super::P),
/// #     }
/// # }
/// fn main() {
///     let _: busbar_contract::abi::mechanism::door::DoorFn = plugin::door;
/// }
/// ```
///
/// A [`RawDoorFn`], by contrast, is a door function as a `dlsym` answers it and the C header
/// spells it: a raw pointer the host has not yet checked (NULL, misaligned, short or another
/// kind's are all possible). The exported [`DOOR_SYMBOL`](crate::abi::mechanism::DOOR_SYMBOL) is
/// one ([`export_door!`](crate::export_door) forwards a [`DoorFn`] through it); only a loader's
/// reviewed `unsafe` enters one.
pub type RawDoorFn = extern "C" fn() -> *const Door;

/// A door the contract's own door macro built ([`plugin_door!`](crate::plugin_door), and every
/// kind macro over it), as the `MACRO_DOOR` it expands beside `door` states it. Its one field is
/// private and its one constructor is `unsafe`, called only in the macro's expansion, so safe code
/// holds one only for a door the contract laid out, never for an arbitrary `fn() -> *const Door`.
///
/// WHAT THIS DOES NOT CLOSE: the Statement's CONTENT (its lists and their counts, every `AbiStr`,
/// `Blob` and kind tail) is the macro caller's own `const` data, written with the ABI's public
/// pointer/length fields; a count that disagrees with its storage is read as stated. That class is
/// closed by the root unsafe-ABI change on branch `lane-row159-abi-unsafe-fn` (the ABI's ptr/len
/// fields private behind `const` constructors from `'static` slices and strs).
///
/// THE SAFE SURFACE OF THE MACRO DOOR, PROVED IN PAIRS. Each `compile_fail` below has a twin that
/// differs from it in the one forbidden spelling and MUST compile, so the failure is the guard's
/// and nothing else's (stable rustdoc checks no error code). The test support's own pairs
/// (`DoorView`, the fake host) are on `busbar_test_kit::test_support`.
///
/// A literal is refused (its field is private); the macro's own value is not:
///
/// ```compile_fail
/// # use busbar_contract::abi::sdk::life::{Life, Refreshed, Refusal};
/// # struct P;
/// # impl Life for P {
/// #     const CANCEL: u32 = 0;
/// #     fn open(_: &[u8], _: &[&[u8]], _: u64) -> Result<Self, Refusal> {
/// #         Ok(P)
/// #     }
/// #     fn refresh(&self, _: &[u8], _: &[&[u8]], _: u64) -> Result<Refreshed, Refusal> {
/// #         Ok(Refreshed::default())
/// #     }
/// # }
/// # mod plugin {
/// #     busbar_contract::plugin_door! {
/// #         ops: busbar_contract::abi::secret::Ops,
/// #         statement: busbar_contract::abi::sdk::door::statement("p", "0", 1),
/// #         lifecycle: life(super::P),
/// #     }
/// # }
/// # extern "C" fn forged() -> *const busbar_contract::abi::mechanism::door::Door {
/// #     core::ptr::null()
/// # }
/// # use busbar_contract::abi::sdk::door::MacroDoor;
/// fn main() {
///     let _ = MacroDoor { door: forged };
/// }
/// ```
///
/// ```
/// # use busbar_contract::abi::sdk::life::{Life, Refreshed, Refusal};
/// # struct P;
/// # impl Life for P {
/// #     const CANCEL: u32 = 0;
/// #     fn open(_: &[u8], _: &[&[u8]], _: u64) -> Result<Self, Refusal> {
/// #         Ok(P)
/// #     }
/// #     fn refresh(&self, _: &[u8], _: &[&[u8]], _: u64) -> Result<Refreshed, Refusal> {
/// #         Ok(Refreshed::default())
/// #     }
/// # }
/// # mod plugin {
/// #     busbar_contract::plugin_door! {
/// #         ops: busbar_contract::abi::secret::Ops,
/// #         statement: busbar_contract::abi::sdk::door::statement("p", "0", 1),
/// #         lifecycle: life(super::P),
/// #     }
/// # }
/// # extern "C" fn forged() -> *const busbar_contract::abi::mechanism::door::Door {
/// #     core::ptr::null()
/// # }
/// # use busbar_contract::abi::sdk::door::MacroDoor;
/// fn main() {
///     let _: MacroDoor = plugin::MACRO_DOOR;
/// }
/// ```
///
/// The constructor is refused in safe code; inside `unsafe` it is not:
///
/// ```compile_fail
/// # use busbar_contract::abi::sdk::life::{Life, Refreshed, Refusal};
/// # struct P;
/// # impl Life for P {
/// #     const CANCEL: u32 = 0;
/// #     fn open(_: &[u8], _: &[&[u8]], _: u64) -> Result<Self, Refusal> {
/// #         Ok(P)
/// #     }
/// #     fn refresh(&self, _: &[u8], _: &[&[u8]], _: u64) -> Result<Refreshed, Refusal> {
/// #         Ok(Refreshed::default())
/// #     }
/// # }
/// # mod plugin {
/// #     busbar_contract::plugin_door! {
/// #         ops: busbar_contract::abi::secret::Ops,
/// #         statement: busbar_contract::abi::sdk::door::statement("p", "0", 1),
/// #         lifecycle: life(super::P),
/// #     }
/// # }
/// # extern "C" fn forged() -> *const busbar_contract::abi::mechanism::door::Door {
/// #     core::ptr::null()
/// # }
/// # use busbar_contract::abi::sdk::door::MacroDoor;
/// fn main() {
///     let _ = MacroDoor::__from_door_macro(plugin::door);
/// }
/// ```
///
/// ```
/// # use busbar_contract::abi::sdk::life::{Life, Refreshed, Refusal};
/// # struct P;
/// # impl Life for P {
/// #     const CANCEL: u32 = 0;
/// #     fn open(_: &[u8], _: &[&[u8]], _: u64) -> Result<Self, Refusal> {
/// #         Ok(P)
/// #     }
/// #     fn refresh(&self, _: &[u8], _: &[&[u8]], _: u64) -> Result<Refreshed, Refusal> {
/// #         Ok(Refreshed::default())
/// #     }
/// # }
/// # mod plugin {
/// #     busbar_contract::plugin_door! {
/// #         ops: busbar_contract::abi::secret::Ops,
/// #         statement: busbar_contract::abi::sdk::door::statement("p", "0", 1),
/// #         lifecycle: life(super::P),
/// #     }
/// # }
/// # extern "C" fn forged() -> *const busbar_contract::abi::mechanism::door::Door {
/// #     core::ptr::null()
/// # }
/// # use busbar_contract::abi::sdk::door::MacroDoor;
/// fn main() {
///     let _ = unsafe { MacroDoor::__from_door_macro(plugin::door) };
/// }
/// ```
#[derive(Debug, Clone, Copy)]
pub struct MacroDoor {
    door: DoorFn,
}

impl MacroDoor {
    /// The door macro's plumbing: the one constructor, named only in its expansion.
    ///
    /// # Safety
    ///
    /// `door` answers a pointer to a `'static`, fully initialised `Door` the SDK built (the `const`
    /// items [`plugin_door!`](crate::plugin_door) lays out), whose Statement lists point at their
    /// stated counts of live `'static` entries. That last part is the content of the Statement the
    /// macro's caller wrote as its own `const` data; the ABI does not yet enforce it, and the root
    /// unsafe-ABI change on branch `lane-row159-abi-unsafe-fn` closes it.
    #[doc(hidden)]
    #[must_use]
    pub const unsafe fn __from_door_macro(door: DoorFn) -> Self {
        Self { door }
    }

    /// The door function.
    #[must_use]
    pub const fn door_fn(self) -> DoorFn {
        self.door
    }
}

/// THE DOOR MACRO. The door, Statement and table are `const` items: `'static`, but Rust does not
/// promise one address per `const`, so a host compares a door's contents, never its address.
///
/// Beside `door` it expands `MACRO_DOOR`, the [`MacroDoor`] the contract's test support reads the
/// door through. The `statement` it is given is the caller's own `const` data: its lists, strings,
/// blobs and kind tail are stated through the ABI's public pointer/length fields, which the
/// root unsafe-ABI change on branch `lane-row159-abi-unsafe-fn` puts behind `const` constructors
/// from `'static` slices and strs.
/// Invoked once, in a plugin's LOGIC crate; expands there to
/// `pub extern "C" fn door() -> &'static Door` over a `'static` door, Statement and ops table.
///
/// ```ignore
/// busbar_contract::plugin_door! {
///     ops: busbar_contract::abi::secret::Ops,
///     statement: busbar_contract::abi::sdk::door::statement("my-secret", "1.0.0", 64),
///     lifecycle: {
///         validate: Validate, open: Open, refresh: Refresh, retire: Retire, tick: Tick,
///         drive: Drive, cancel: Cancel, release: Release, close: Close,
///     },
///     kind_ops: { resolve: Resolve },
/// }
/// ```
///
/// * `ops` — the kind's table type ([`KindOps`]); the door's `kind`/`kind_abi`, the table's
///   `size`/`slots` and the Statement's `size`/`kind`/`kind_abi` all follow from it.
/// * `lifecycle` — one [`Slot`] per lifecycle slot, each reading and writing the `in`/`out` the
///   kind states for that slot ([`KindOps::Lifecycle`]; a mismatch does not compile). A NULL slot
///   refuses the load, so all nine are named.
/// * `kind_ops` — one [`Slot`] per kind op, by the table's field name; its index is read off the
///   field's offset (the SLOT LAYOUT rule), and its `in`/`out` must be the ones the kind states for
///   that index ([`KindSlot`]; a mismatch does not compile). A kind op left unnamed is NULL
///   (absent), so a door written before an optional kind op was appended to its table still
///   builds; the loader admits a NULL only where the kind states the op optional.
/// * `lifecycle: life(L)` — instead of the nine: the SDK's generic lifecycle slots over the kind's
///   [`Life`](crate::abi::sdk::life::Life) `L` (`abi::sdk::life`), every one a
///   [`Safe`](crate::abi::sdk::safe::Safe) slot over `Held<L>`.
/// * `lifecycle: life(L, ready)` — the same, and the door states `ready`
///   (`abi::mechanism::lifecycle`, READY): the host calls [`Life::ready`](crate::abi::sdk::life::Life::ready)
///   after `open`, on a real ticket, before any listener binds, and boot awaits it. Without
///   `ready` the door states none and the plugin is opened exactly as before.
/// * `ready: S` (optional, after `lifecycle`) — the door's `ready` as a raw [`Slot`] or a
///   [`Safe`](crate::abi::sdk::safe::Safe) one reading `ReadyIn` and writing `OutHead`.
/// * `migrate: S` (optional, after `ready`) — the door's `migrate` (`abi::mechanism::lifecycle`,
///   MIGRATE), a raw [`Slot`] reading `ValidateIn` and writing `OutHead`: in practice
///   [`Migrator<M>`](crate::abi::sdk::migrate::Migrator) over the plugin's own
///   [`Migrate`](crate::abi::sdk::migrate::Migrate). It runs with no instance, so it cannot be a
///   [`Safe`](crate::abi::sdk::safe::Safe) slot. Without it the door states none, and
///   `busbar --migrate-config` passes the plugin's settings section through unchanged.
#[macro_export]
macro_rules! plugin_door {
    // The door's `ready` entry: none, or the trampoline over the named slot (kind-neutral: the
    // mechanism's own `ReadyIn`/`OutHead`, whatever the kind).
    (@ready $capture:ty) => { ::core::option::Option::None };
    (@ready $capture:ty, $ready:ty) => {
        $crate::abi::sdk::door::kind_op::<
            $crate::abi::sdk::door::Lifecycle,
            $ready,
            $capture,
            { $crate::abi::mechanism::lifecycle::slot::READY },
        >()
    };
    // The door's `migrate` entry, likewise (the mechanism's own `ValidateIn`/`OutHead`).
    (@migrate $capture:ty) => { ::core::option::Option::None };
    (@migrate $capture:ty, $migrate:ty) => {
        $crate::abi::sdk::door::kind_op::<
            $crate::abi::sdk::door::Lifecycle,
            $migrate,
            $capture,
            { $crate::abi::mechanism::lifecycle::slot::MIGRATE },
        >()
    };
    (
        ops: $ops:ty,
        statement: $statement:expr,
        lifecycle: life($life:ty, ready)
        $(, migrate: $migrate:ty)?
        $(, kind_ops: { $($field:ident : $slot:ty),* $(,)? })?
        $(,)?
    ) => {
        $crate::plugin_door! {
            ops: $ops,
            statement: $statement,
            lifecycle: life($life),
            ready: $crate::abi::sdk::Safe<$crate::abi::sdk::life::Ready<$life>>
            $(, migrate: $migrate)?
            $(, kind_ops: { $($field : $slot),* })?
        }
    };
    (
        ops: $ops:ty,
        statement: $statement:expr,
        lifecycle: life($life:ty)
        $(, ready: $ready:ty)?
        $(, migrate: $migrate:ty)?
        $(, kind_ops: { $($field:ident : $slot:ty),* $(,)? })?
        $(,)?
    ) => {
        $crate::plugin_door! {
            ops: $ops,
            statement: $statement,
            lifecycle: {
                validate: $crate::abi::sdk::Safe<$crate::abi::sdk::life::Validate<$life>>,
                open: $crate::abi::sdk::Safe<$crate::abi::sdk::life::Open<$life>>,
                refresh: $crate::abi::sdk::Safe<$crate::abi::sdk::life::Refresh<$life>>,
                retire: $crate::abi::sdk::Safe<$crate::abi::sdk::life::Retire<$life>>,
                tick: $crate::abi::sdk::Safe<$crate::abi::sdk::life::Tick<$life>>,
                drive: $crate::abi::sdk::Safe<$crate::abi::sdk::life::Drive<$life>>,
                cancel: $crate::abi::sdk::Safe<$crate::abi::sdk::life::Cancel<$life>>,
                release: $crate::abi::sdk::Safe<$crate::abi::sdk::life::Release<$life>>,
                close: $crate::abi::sdk::Safe<$crate::abi::sdk::life::Close<$life>>,
            }
            $(, ready: $ready)?
            $(, migrate: $migrate)?
            $(, kind_ops: { $($field : $slot),* })?
        }
    };
    (
        ops: $ops:ty,
        statement: $statement:expr,
        lifecycle: {
            validate: $validate:ty,
            open: $open:ty,
            refresh: $refresh:ty,
            retire: $retire:ty,
            tick: $tick:ty,
            drive: $drive:ty,
            cancel: $cancel:ty,
            release: $release:ty,
            close: $close:ty $(,)?
        }
        $(, ready: $ready:ty)?
        $(, migrate: $migrate:ty)?
        $(, kind_ops: { $($field:ident : $slot:ty),* $(,)? })?
        $(,)?
    ) => {
        const _: () = ::core::assert!(
            !::core::cfg!(panic = "abort"),
            "a busbar plugin builds with panic = \"unwind\": the door macro's catch_unwind answers FAULT only when a panic unwinds"
        );

        /// This plugin's door: the `'static` `Door` a compiled-in row holds and `export_door!`
        /// forwards to.
        pub extern "C" fn door() -> &'static $crate::abi::mechanism::door::Door {
            use $crate::abi::mechanism::lifecycle as __lc;
            use $crate::abi::sdk::door as __sdk;
            // A `path` fragment cannot open a struct literal; an alias can.
            type __Ops = $ops;
            type __Life = <__Ops as __sdk::KindOps>::Lifecycle;
            // A `Safe` slot reads the typed state a `Safe` `open` mints (`abi::sdk::safe`).
            const _: () = ::core::assert!(
                <$open as __sdk::Entry>::SAFE
                    || !(<$validate as __sdk::Entry>::SAFE
                        || <$refresh as __sdk::Entry>::SAFE
                        || <$retire as __sdk::Entry>::SAFE
                        || <$tick as __sdk::Entry>::SAFE
                        || <$drive as __sdk::Entry>::SAFE
                        || <$cancel as __sdk::Entry>::SAFE
                        || <$release as __sdk::Entry>::SAFE
                        || <$close as __sdk::Entry>::SAFE
                        $(|| <$ready as __sdk::Entry>::SAFE)?
                        $($(|| <$slot as __sdk::Entry>::SAFE)*)?),
                "a Safe slot reads the state a Safe open installs: name open as Safe<_> too"
            );
            // `migrate` runs with no instance: it reads none.
            $(
                const _: () = ::core::assert!(
                    !<$migrate as __sdk::Entry>::SAFE,
                    "migrate runs with no instance: name it as a raw Slot (Migrator<_>), never Safe<_>"
                );
            )?
            /// THIS PLUGIN IMAGE'S CALL CAPTURE: one slot per thread, the image's own (compiled in
            /// or dropped in, each image holds its own). Its first use on a thread makes
            /// `tracing-log`'s `LogTracer` the image's `log` logger, if nothing is yet, and opens
            /// `log` to every level: the capture keeps everything and the host filters.
            struct __Capture;
            impl $crate::abi::sdk::capture::CaptureHome for __Capture {
                fn with<R>(
                    f: impl ::core::ops::FnOnce(&mut $crate::abi::sdk::capture::CaptureSlot) -> R,
                ) -> R {
                    use $crate::abi::sdk::capture::__tracing_log as __tl;
                    ::std::thread_local! {
                        static __BUSBAR_CAPTURE: ::core::cell::RefCell<$crate::abi::sdk::capture::CaptureSlot> = {
                            let _ = __tl::LogTracer::init();
                            __tl::log::set_max_level(__tl::log::LevelFilter::Trace);
                            ::core::cell::RefCell::new($crate::abi::sdk::capture::CaptureSlot::new())
                        };
                    }
                    __BUSBAR_CAPTURE.with(|slot| f(&mut slot.borrow_mut()))
                }
            }
            const __STATEMENT: &$crate::abi::mechanism::door::Statement =
                &__sdk::stamp::<__Ops>($statement);
            // A kind op the door names no slot for is NULL (absent), so a door written before an
            // optional kind op was appended to its table still builds and states it.
            #[allow(clippy::needless_update)]
            const __OPS: &__Ops = &__Ops {
                head: __sdk::ops_head::<__Ops>(
                    __sdk::kind_op::<__Life, $validate, __Capture, { __lc::slot::VALIDATE }>(),
                    __sdk::kind_op::<__Life, $open, __Capture, { __lc::slot::OPEN }>(),
                    __sdk::kind_op::<__Life, $refresh, __Capture, { __lc::slot::REFRESH }>(),
                    __sdk::kind_op::<__Life, $retire, __Capture, { __lc::slot::RETIRE }>(),
                    __sdk::kind_op::<__Life, $tick, __Capture, { __lc::slot::TICK }>(),
                    __sdk::kind_op::<__Life, $drive, __Capture, { __lc::slot::DRIVE }>(),
                    __sdk::kind_op::<__Life, $cancel, __Capture, { __lc::slot::CANCEL }>(),
                    __sdk::kind_op::<__Life, $release, __Capture, { __lc::slot::RELEASE }>(),
                    __sdk::kind_op::<__Life, $close, __Capture, { __lc::slot::CLOSE }>(),
                ),
                $($(
                    $field: __sdk::kind_op::<__Ops, $slot, __Capture, { __sdk::slot_at(::core::mem::offset_of!(__Ops, $field)) }>(),
                )*)?
                ..__sdk::absent_table::<__Ops>()
            };
            // SAFETY: the Statement and table are the `const` items laid out just above, and
            // `migrate`, when named, is the SDK's trampoline over its `ValidateIn`/`OutHead` slot;
            // the Statement's content is the caller's own `const` data (see `MACRO_DOOR` below).
            const __DOOR: &$crate::abi::mechanism::door::Door = &unsafe {
                __sdk::door::<__Ops>(
                    __STATEMENT,
                    __OPS,
                    $crate::plugin_door!(@ready __Capture $(, $ready)?),
                )
                .__with_migrate($crate::plugin_door!(@migrate __Capture $(, $migrate)?))
            };
            __DOOR
        }

        /// This plugin's door as the door macro built it: the one value the contract's test
        /// support (`busbar_test_kit::test_support::DoorView`) reads a door through.
        #[allow(dead_code)]
        pub const MACRO_DOOR: $crate::abi::sdk::door::MacroDoor =
            // SAFETY: `door` is the function this macro expanded just above: it answers the
            // `'static`, fully initialised `Door` the SDK laid out as `const` items. The Statement's
            // content (its lists, strings, blobs and kind tail) is the caller's own `const` data;
            // that its counts match its storage is closed by the root unsafe-ABI change on branch
            // `lane-row159-abi-unsafe-fn`.
            unsafe { $crate::abi::sdk::door::MacroDoor::__from_door_macro(door) };

    };
    // `lifecycle: plane_life(P)`: the plane's nine lifecycle slots over its `PlaneLife` `P`
    // (`abi::sdk::plane_life`), every one a `Safe` slot over `P`.
    (
        ops: $ops:ty,
        statement: $statement:expr,
        lifecycle: plane_life($plane:ty)
        $(, ready: $ready:ty)?
        $(, kind_ops: { $($field:ident : $slot:ty),* $(,)? })?
        $(,)?
    ) => {
        $crate::plugin_door! {
            ops: $ops,
            statement: $statement,
            lifecycle: {
                validate: $crate::abi::sdk::Safe<$crate::abi::sdk::plane_life::Validate<$plane>>,
                open: $crate::abi::sdk::Safe<$crate::abi::sdk::plane_life::Open<$plane>>,
                refresh: $crate::abi::sdk::Safe<$crate::abi::sdk::plane_life::Refresh<$plane>>,
                retire: $crate::abi::sdk::Safe<$crate::abi::sdk::plane_life::Retire<$plane>>,
                tick: $crate::abi::sdk::Safe<$crate::abi::sdk::plane_life::Tick<$plane>>,
                drive: $crate::abi::sdk::Safe<$crate::abi::sdk::plane_life::Drive<$plane>>,
                cancel: $crate::abi::sdk::Safe<$crate::abi::sdk::plane_life::Cancel<$plane>>,
                release: $crate::abi::sdk::Safe<$crate::abi::sdk::plane_life::Release<$plane>>,
                close: $crate::abi::sdk::Safe<$crate::abi::sdk::plane_life::Close<$plane>>,
            }
            $(, ready: $ready)?
            $(, kind_ops: { $($field : $slot),* })?
        }
    };
}

/// THE ONE EXPORT. Invoked once, in a plugin's thin `cdylib` crate, with the logic crate's door:
/// `busbar_contract::export_door!(crate_x::door);`. Emits the ONE `#[no_mangle]` symbol
/// [`DOOR_SYMBOL`](crate::abi::mechanism::DOOR_SYMBOL), forwarding to that door — the same
/// [`DoorFn`](crate::abi::mechanism::door::DoorFn) a compiled-in row holds.
#[macro_export]
macro_rules! export_door {
    ($door:path $(,)?) => {
        const _: () = ::core::assert!(
            !::core::cfg!(panic = "abort"),
            "a busbar plugin builds with panic = \"unwind\": the door macro's catch_unwind answers FAULT only when a panic unwinds"
        );

        /// The ONE symbol this plugin image exports.
        #[unsafe(no_mangle)]
        pub extern "C" fn busbar_plugin_door() -> *const $crate::abi::mechanism::door::Door {
            const __DOOR_FN: $crate::abi::mechanism::door::DoorFn = $door;
            ::core::ptr::from_ref(__DOOR_FN())
        }
    };
}

#[cfg(test)]
#[path = "tests/door_tests.rs"]
mod tests;
