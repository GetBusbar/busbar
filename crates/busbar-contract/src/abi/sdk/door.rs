// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DOOR MACRO — the plugin side of the shared mechanism (THE DESIGN, the plugin ABI; abi-v2, the door and the SDK).
//!
//! A plugin of any kind is two crates (abi-v2, the door's "crate shape"):
//!
//! * the LOGIC crate invokes [`plugin_door!`](crate::plugin_door) once. It expands, IN THAT CRATE,
//!   to `pub extern "C" fn door() -> *const Door` — a [`DoorFn`](crate::abi::mechanism::door::DoorFn) answering a `'static`
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

use crate::abi::mechanism::call::{AbiStr, Blob, InHead, Op, OutHead, Outcome, RawOutcome};
use crate::abi::mechanism::door::{Door, KindTailHead, MetricFamily, Statement};
use crate::abi::mechanism::lifecycle::{
    self as lc, CancelIn, CancelOut, DriveIn, GenIn, OpenIn, OpenOut, OpsHead, RefreshIn,
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
/// (a [`Safe`](crate::abi::sdk::safe::Safe) `open` writes the instance there).
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

/// A Statement naming the plugin, with no families, no diagnostic ids, no kind tail and no
/// extensions. Its `size`, `kind` and `kind_abi` are stamped by [`plugin_door!`](crate::plugin_door)
/// ([`stamp`]); a plugin extends it with struct-update syntax.
#[must_use]
pub const fn statement(name: &'static str, version: &'static str, max_inflight: u32) -> Statement {
    Statement {
        size: 0,
        kind: 0,
        kind_abi: 0,
        max_inflight,
        name: abi_str(name),
        version: abi_str(version),
        families: ptr::null::<MetricFamily>(),
        families_len: 0,
        diag_ids: ptr::null::<AbiStr>(),
        diag_ids_len: 0,
        secret_refs: ptr::null::<AbiStr>(),
        secret_refs_len: 0,
        settings_schema: Blob::ABSENT,
        kind_tail: ptr::null::<KindTailHead>(),
        extensions: Blob::ABSENT,
    }
}

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

/// The [`Door`] of a `T` plugin.
#[must_use]
pub const fn door<T: KindOps>(statement: &'static Statement, ops: &'static T) -> Door {
    Door {
        magic: DOOR_MAGIC,
        mechanism_version: MECHANISM_VERSION,
        size: size_of::<Door>() as u32,
        kind: T::KIND as u32,
        kind_abi: T::KIND.abi_version(),
        statement,
        ops: ptr::from_ref(ops).cast::<OpsHead>(),
    }
}

/// THE DOOR MACRO. The door, Statement and table are `const` items: `'static`, but Rust does not
/// promise one address per `const`, so a host compares a door's contents, never its address.
/// Invoked once, in a plugin's LOGIC crate; expands there to
/// `pub extern "C" fn door() -> *const Door` over a `'static` door, Statement and ops table.
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
///   that index ([`KindSlot`]; a mismatch does not compile). Every field must be named (a struct
///   literal).
#[macro_export]
macro_rules! plugin_door {
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
        $(, kind_ops: { $($field:ident : $slot:ty),* $(,)? })?
        $(,)?
    ) => {
        const _: () = ::core::assert!(
            !::core::cfg!(panic = "abort"),
            "a busbar plugin builds with panic = \"unwind\": the door macro's catch_unwind answers FAULT only when a panic unwinds"
        );

        /// This plugin's door: the `'static` `Door` a compiled-in row holds and `export_door!`
        /// forwards to.
        pub extern "C" fn door() -> *const $crate::abi::mechanism::door::Door {
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
                        $($(|| <$slot as __sdk::Entry>::SAFE)*)?),
                "a Safe slot reads the state a Safe open installs: name open as Safe<_> too"
            );
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
            };
            const __DOOR: &$crate::abi::mechanism::door::Door = &__sdk::door::<__Ops>(__STATEMENT, __OPS);
            __DOOR
        }
    };
}

// M6-COLD-DELETE: rename export_door! → export_plugin! when the cold macro is deleted (abi-v2, the row-macro name)
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
            __DOOR_FN()
        }
    };
}

#[cfg(test)]
#[path = "tests/door_tests.rs"]
mod tests;
