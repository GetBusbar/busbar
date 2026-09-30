// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A SLOT BODY WITH NO `unsafe` (THE DESIGN, plugins: a plugin crate stays
//! `#![forbid(unsafe_code)]`; the plugin ABI: the SDK's typed wrappers). A plugin implements [`SafeSlot`] and names it in
//! [`plugin_door!`](crate::plugin_door) as [`Safe<S>`]. The body is handed:
//!
//! * its `in` as a [`Lent`] (`abi::sdk::lent`): host-lent memory, read and filled without
//!   `unsafe`, for the call only;
//! * its instance as an [`Instance<T>`]: the plugin's own state, typed.
//!
//! THE INSTANCE, OWNED BY THE SDK. `open` installs the state with [`Instance::open`]; the SDK boxes
//! it and answers the box as `open`'s instance, whatever the body wrote there, and only when `open`
//! answers READY (a state installed by an `open` that answers anything else, or panics, is dropped).
//! Every later call reads it with [`Instance::get`], as `&T`: ops on distinct tickets run
//! concurrently on one instance (`abi::mechanism::lifecycle`, CONCURRENCY), so the SDK never hands out
//! `&mut T` — a state that changes holds its own locks or atomics. When `close` answers READY the
//! SDK drops the state (its `Drop` runs); a `close` answering anything else leaves it in place,
//! since the host keeps calling an instance whose `close` was not READY. So the body never frees
//! it, and nothing can free it twice or use it after.
//!
//! THE CALL CONTRACT this relies on (`Entry::enter`): the host passes back the pointer `open`
//! answered READY, until `close` answers READY, and runs `close` with no other op in flight. The
//! state is boxed behind its type's `TypeId`, so a slot naming a different `T` reads `None` rather
//! than another type's bytes.

use std::any::TypeId;
use std::cell::Cell;
use std::ffi::c_void;
use std::marker::PhantomData;
use std::mem::size_of;

use crate::abi::mechanism::call::Outcome;
use crate::abi::mechanism::lifecycle::{slot, OpenOut};
use crate::abi::sdk::door::{AbiIn, AbiOut, Entry};
use crate::abi::sdk::lent::Lent;
use crate::abi::sdk::out::Out;

/// The box an instance pointer points to: the state behind its type's `TypeId`, at offset `0`
/// whatever `T` is (`#[repr(C)]`), so any slot can read the tag before it trusts the type.
#[repr(C)]
struct Tagged<T> {
    tag: TypeId,
    state: T,
}

/// The plugin's instance state, as a slot body is handed it. Only the SDK makes one; it lives for
/// the call.
pub struct Instance<'call, T> {
    ptr: *mut c_void,
    index: u32,
    opened: &'call Cell<Option<Box<Tagged<T>>>>,
}

impl<T> std::fmt::Debug for Instance<'_, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Instance")
            .field("open", &!self.ptr.is_null())
            .field("slot", &self.index)
            .finish_non_exhaustive()
    }
}

impl<'call, T: Send + Sync + 'static> Instance<'call, T> {
    /// The state `open` installed; `None` before `open` (in `validate` and `open` itself) or when
    /// it was installed as another type.
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
    /// second call replaces the first.
    ///
    /// # Panics
    /// In any slot but `open` (the trampoline answers FAULT).
    pub fn open(&self, state: T) {
        assert!(
            self.index == slot::OPEN,
            "Instance::open: the state is installed in `open` only"
        );
        self.opened.set(Some(Box::new(Tagged {
            tag: TypeId::of::<T>(),
            state,
        })));
    }
}

/// A slot body with no `unsafe`: [`Slot`](crate::abi::sdk::door::Slot)'s safe form, named in
/// [`plugin_door!`](crate::plugin_door) as [`Safe<Self>`].
pub trait SafeSlot {
    /// The slot's `in`.
    type In: AbiIn;
    /// The slot's `out`.
    type Out: AbiOut;
    /// The plugin's instance state: one type for every slot of the plugin.
    type State: Send + Sync + 'static;
    /// The body. `input` is the host's `in`, lent for the call; `out` a private copy of the
    /// host's `out`, written back when the body returns (the trampoline's rules, `abi::sdk::door`),
    /// handed as an [`Out`]: scalars set directly, every pointer through an SDK writer
    /// (`abi::sdk::out`).
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
/// use busbar_contract::abi::sdk::door::Slot;
/// use busbar_contract::abi::sdk::{Instance, Lent, Out, Safe, SafeSlot};
/// # use std::ffi::c_void;
/// # macro_rules! ready { ($n:ident, $i:ty, $o:ty) => {
/// #     struct $n;
/// #     impl Slot for $n { type In = $i; type Out = $o;
/// #         fn call(_: *mut c_void, _: &$i, _: Out<'_, $o>) -> Outcome { Outcome::Ready } }
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

impl<S: SafeSlot> Entry for Safe<S> {
    type In = S::In;
    type Out = S::Out;
    const SAFE: bool = true;

    unsafe fn enter(instance: *mut c_void, index: u32, input: &S::In, out: &mut S::Out) -> Outcome {
        // What `open` installs; dropped on the way out, a panic included, unless handed over.
        let opened = Cell::new(None);
        let handle = Instance {
            ptr: instance,
            index,
            opened: &opened,
        };
        // SAFETY: `input` is the trampoline's copy of the host's `in`, whose every pointer is
        // valid for the call (`Entry::enter`'s contract), and it lives until this returns.
        let answered = S::call(handle, unsafe { Lent::new(input) }, Out::new(&mut *out));
        match index {
            slot::OPEN => {
                // Every kind's `open` `out` leads with the lifecycle's `OpenOut` (`KindOps`).
                debug_assert!(size_of::<S::Out>() >= size_of::<OpenOut>());
                let minted = match (answered, opened.take()) {
                    (Outcome::Ready, Some(b)) => Box::into_raw(b).cast::<c_void>(),
                    _ => std::ptr::null_mut(),
                };
                // SAFETY: at OPEN, `S::Out` is the kind's `open` `out`, which leads with an
                // `OpenOut` (`KindOps`'s contract); `out` is a live `&mut` to it.
                unsafe { (*std::ptr::from_mut(out).cast::<OpenOut>()).instance = minted };
            }
            slot::CLOSE if answered == Outcome::Ready && !instance.is_null() => {
                // SAFETY: as `Instance::get`: the tag at offset 0 of the SDK's box.
                let tag = unsafe { instance.cast::<TypeId>().read() };
                if tag != TypeId::of::<S::State>() {
                    // Not this state's box: leave it rather than free it as another type.
                    return Outcome::Fault;
                }
                // SAFETY: the SDK's `Tagged<S::State>` box from `open`; `close` answered READY with
                // no other op in flight, so the host never passes it again (the call contract).
                drop(unsafe { Box::from_raw(instance.cast::<Tagged<S::State>>()) });
            }
            _ => {}
        }
        answered
    }
}

#[cfg(test)]
#[path = "tests/safe_tests.rs"]
mod tests;
