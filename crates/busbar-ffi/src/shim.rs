// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The plugin-side entries (IF §6.4, §7.6; UNSAFE-MIN §2.4) and the safe adapter traits `kind!` and
//! `plugin!` implement.
//!
//! Every shim is `entry`-shaped: no panic crosses `extern "C"` (I10), a caught panic is FAULT. The one
//! `unsafe fn enter` turns the host's `inst` into the instance; `describe` and `open` take no instance and
//! are safe fns. Adapters never see the instance, a slot table or a `RawOut`: sync methods get the plugin,
//! session methods the plugin and their own session, async starts the plugin for the chain's borrow.
//!
//! `unsafe` here: `enter` (def and body); per shim its def and its `enter` block; plus
//! the `drop_inst` block of `close`. Slot access uses crate-private primitives under each entry's I6
//! contract; they do not expose numeric mutation authority to external safe callers.
//!
//! # Entry safety contract
//!
//! Every instance-taking entry implements the corresponding `vt` alias's safety contract. `M` must
//! be the image that allocated `inst`, and the allocation must remain live for the complete entry.
//! `enter` only reconstructs a shared borrow; it does not validate an arbitrary address or lock a slot.
//! Session entries, resume, end and cancel therefore additionally require exclusive access to their
//! token (I6), supplied by the host handle's exclusive borrow. Token generation checks reject stale
//! identities but do not serialize two simultaneous entries for the same live identity.
//!
//! The host keeps borrowed argument/output memory valid for each synchronous call and retains async
//! argument/result buffers until the chain is retired. Async shims store borrowed futures only in the
//! entered instance's chain table; completion, cancellation and instance teardown drop those futures
//! before their plugin or host buffers. No shim other than `close` frees the instance. Each declaration
//! below states its additional ownership obligation; its body records the individual pointer/slot
//! operation. These are C ABI caller obligations, not checks performed by `contain`.

#![allow(unsafe_code)]

use core::ffi::c_void;
use core::future::Future;
use core::panic::AssertUnwindSafe;
use core::pin::Pin;
use std::panic::catch_unwind;

use crate::raw::{
    Arg, AsyncArg, Bytes, ChainBytes, ChainId, Host, Out, RawArg, RawOut, Status, Token,
    seal::ToChain,
};
use crate::slots::{ChainBox, ChainRef, Inst, Slots, drop_inst, pack, tie, unpack};

/// A boxed chain future that may borrow the plugin for `'i`.
pub type ChainFut<'i, R> = Pin<Box<dyn Future<Output = R> + Send + 'i>>;

/// The instance type of an image.
pub type InstOf<M> =
    Inst<<M as Image>::Plugin, <M as Image>::Session, <M as Image>::Reply, <M as Image>::Inbox>;

/// What one poll of a chain came to; the adapter has written the records already.
pub enum Step {
    /// The chain finished: OK, REFUSED or FAILED (its answer is in Out). The shim drops it.
    Ready(Status),
    /// Pending with at least one NEED written: the shim parks it and the adapter writes TOKEN.
    Need,
    /// A contract break the adapter found (Pending with no NEED): the shim drops it and answers FAULT.
    Fault,
}

/// What `open` came to.
pub enum Opening<R, X> {
    /// DRY_RUN, or an answer without a chain.
    Done(Status),
    /// The open future (it borrows nothing) and its chain state.
    Chain(ChainFut<'static, R>, X),
}

/// One image: what `plugin!` emits per plugin type, over the kind-independent header entries.
pub trait Image: Sized + 'static {
    type Plugin: Send + Sync + 'static;
    type Session: Send + 'static;
    type Reply: 'static;
    type Inbox: Send + 'static;
    /// The image's one open slab (`static GLOBAL`), for chains of `open` (inst null).
    fn global() -> &'static Slots<ChainBox<Self::Reply, Self::Inbox>>;
    /// Cold: describe items only.
    fn describe(h: &'static Host, out: &mut Out<'_>) -> Status;
    /// `open`: `config` as bytes for DRY_RUN's `check`, and the same bytes as the chain will hold them.
    fn open(
        h: &'static Host,
        config: Bytes<'_>,
        chained: ChainBytes,
        flags: u32,
        out: &mut Out<'_>,
    ) -> Opening<Self::Reply, Self::Inbox>;
    /// Poll one chain (`results` = the resume's records; None on the first poll) and write its answer.
    fn poll(
        chain: ChainRef<'_, Self::Reply, Self::Inbox>,
        results: Option<ChainBytes>,
        out: &mut Out<'_>,
    ) -> Step;
    /// After `Step::Need`: write the chain's TOKEN record; returns NEED.
    fn parked(token: Token, out: &mut Out<'_>) -> Status;
    /// After a session opener's `Ok`: write the session TOKEN first in the answer; returns OK.
    fn opened(token: Token, out: &mut Out<'_>) -> Status;
}

/// Sync method adapters, one per slot `S` (the method's index in its kind's table).
pub trait Call0<const S: usize>: Image {
    fn call(p: &Self::Plugin, h: &'static Host, out: &mut Out<'_>) -> Status;
}
pub trait Call1<A1: RawArg, const S: usize>: Image {
    fn call(p: &Self::Plugin, h: &'static Host, a1: Arg<'_, A1>, out: &mut Out<'_>) -> Status;
}
pub trait Call2<A1: RawArg, A2: RawArg, const S: usize>: Image {
    fn call(
        p: &Self::Plugin,
        h: &'static Host,
        a1: Arg<'_, A1>,
        a2: Arg<'_, A2>,
        out: &mut Out<'_>,
    ) -> Status;
}
pub trait Call3<A1: RawArg, A2: RawArg, A3: RawArg, const S: usize>: Image {
    fn call(
        p: &Self::Plugin,
        h: &'static Host,
        a1: Arg<'_, A1>,
        a2: Arg<'_, A2>,
        a3: Arg<'_, A3>,
        out: &mut Out<'_>,
    ) -> Status;
}

/// Session openers (`plane::request`, `plane::probe`, `transport::begin`): Ok = the new session, which
/// the shim inserts before `Image::opened` writes its TOKEN; Err = the status of the FAIL written.
pub trait Opener1<A1: RawArg, const S: usize>: Image {
    fn begin(
        p: &Self::Plugin,
        h: &'static Host,
        a1: Arg<'_, A1>,
        out: &mut Out<'_>,
    ) -> Result<Self::Session, Status>;
}
pub trait Opener2<A1: RawArg, A2: RawArg, const S: usize>: Image {
    fn begin(
        p: &Self::Plugin,
        h: &'static Host,
        a1: Arg<'_, A1>,
        a2: Arg<'_, A2>,
        out: &mut Out<'_>,
    ) -> Result<Self::Session, Status>;
}

/// Methods on a live session (raw: the token first).
pub trait Session0<const S: usize>: Image {
    fn on(p: &Self::Plugin, h: &'static Host, s: &mut Self::Session, out: &mut Out<'_>) -> Status;
}
pub trait Session1<A1: RawArg, const S: usize>: Image {
    fn on(
        p: &Self::Plugin,
        h: &'static Host,
        s: &mut Self::Session,
        a1: Arg<'_, A1>,
        out: &mut Out<'_>,
    ) -> Status;
}
pub trait Session2<A1: RawArg, A2: RawArg, const S: usize>: Image {
    fn on(
        p: &Self::Plugin,
        h: &'static Host,
        s: &mut Self::Session,
        a1: Arg<'_, A1>,
        a2: Arg<'_, A2>,
        out: &mut Out<'_>,
    ) -> Status;
}
pub trait Session3<A1: RawArg, A2: RawArg, A3: RawArg, const S: usize>: Image {
    fn on(
        p: &Self::Plugin,
        h: &'static Host,
        s: &mut Self::Session,
        a1: Arg<'_, A1>,
        a2: Arg<'_, A2>,
        a3: Arg<'_, A3>,
        out: &mut Out<'_>,
    ) -> Status;
}
pub trait Session4<A1: RawArg, A2: RawArg, A3: RawArg, A4: RawArg, const S: usize>: Image {
    #[allow(clippy::too_many_arguments)]
    fn on(
        p: &Self::Plugin,
        h: &'static Host,
        s: &mut Self::Session,
        a1: Arg<'_, A1>,
        a2: Arg<'_, A2>,
        a3: Arg<'_, A3>,
        a4: Arg<'_, A4>,
        out: &mut Out<'_>,
    ) -> Status;
}

/// A method that consumes its session (`plane::end`): the shim removes it first.
pub trait End0<const S: usize>: Image {
    fn end(p: &Self::Plugin, h: &'static Host, s: Self::Session, out: &mut Out<'_>) -> Status;
}

/// Async method adapters: start the chain future over the plugin it borrows.
pub trait Start0<const S: usize>: Image {
    fn start<'i>(p: &'i Self::Plugin, h: &'static Host)
    -> (ChainFut<'i, Self::Reply>, Self::Inbox);
}
pub trait Start1<A1: AsyncArg, const S: usize>: Image {
    fn start<'i>(
        p: &'i Self::Plugin,
        h: &'static Host,
        a1: A1::Chained,
    ) -> (ChainFut<'i, Self::Reply>, Self::Inbox);
}
pub trait Start2<A1: AsyncArg, A2: AsyncArg, const S: usize>: Image {
    fn start<'i>(
        p: &'i Self::Plugin,
        h: &'static Host,
        a1: A1::Chained,
        a2: A2::Chained,
    ) -> (ChainFut<'i, Self::Reply>, Self::Inbox);
}
pub trait Start4<A1: AsyncArg, A2: AsyncArg, A3: AsyncArg, A4: AsyncArg, const S: usize>:
    Image
{
    fn start<'i>(
        p: &'i Self::Plugin,
        h: &'static Host,
        a1: A1::Chained,
        a2: A2::Chained,
        a3: A3::Chained,
        a4: A4::Chained,
    ) -> (ChainFut<'i, Self::Reply>, Self::Inbox);
}

/// The entry wrapper (§6.4 step 0): a caught panic is FAULT.
fn contain(f: impl FnOnce() -> Status) -> Status {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or(Status::FAULT)
}

/// The instance behind the host's `inst`, or None for null.
///
/// # Safety
/// `inst` is null or the address `Inst::into_instance` returned for this image's `InstOf<M>`, whose
/// `close` has not run (the host's `Instance` holds it and calls with `&self`; `Drop` is the only close).
/// For non-null input it must remain allocated, aligned and initialized for the entire chosen `'e`;
/// there must be no overlapping mutable borrow of the whole instance. All callers below keep the
/// returned shared borrow inside the guarded entry; this helper does not extend the allocation's life.
unsafe fn enter<'e, M: Image>(inst: *const c_void) -> Option<&'e InstOf<M>> {
    // SAFETY: by the contract the pointer is null or a live `InstOf<M>` that outlives the entry.
    unsafe { inst.cast::<InstOf<M>>().as_ref() }
}

/// Start a fresh chain: first poll, then park it in `table` on NEED, or drop it.
fn drive_new<M: Image>(
    table: &Slots<ChainBox<M::Reply, M::Inbox>>,
    mut cb: ChainBox<M::Reply, M::Inbox>,
    out: &mut Out<'_>,
) -> Status {
    let step = catch_unwind(AssertUnwindSafe(|| {
        M::poll(ChainRef::new(&mut cb), None, &mut *out)
    }));
    match step {
        Ok(Step::Ready(status)) => status,
        Ok(Step::Need) => match table.insert_raw(cb) {
            Some((index, generation)) => M::parked(pack(false, index, generation), out),
            None => Status::FAULT,
        },
        Ok(Step::Fault) | Err(_) => Status::FAULT,
    }
}

// ---- sync methods ----

/// # Safety
/// Uphold the module entry contract and `vt::EntryFn0`: this is `M`'s live instance, borrowed only for
/// the call. The adapter receives a shared plugin borrow and cannot free the instance.
pub(crate) unsafe extern "C" fn sync0<M: Call0<S>, const S: usize>(
    inst: *const c_void,
    h: &'static Host,
    out: &mut RawOut,
) -> Status {
    // SAFETY: the host passes `inst` from this image's INSTANCE answer and calls only while its
    // `Instance` is alive, before `close` (I13, §10.4).
    let Some(i) = (unsafe { enter::<M>(inst) }) else {
        return Status::FAULT;
    };
    let mut out = Out::new(out, h);
    contain(|| <M as Call0<S>>::call(i.plugin(), h, &mut out))
}

/// # Safety
/// Uphold the module entry contract and `vt::EntryFn1`; `a1` and output remain valid throughout the
/// shared-plugin call. The instance is retained by the host, not consumed here.
pub(crate) unsafe extern "C" fn sync1<M: Call1<A1, S>, A1: RawArg, const S: usize>(
    inst: *const c_void,
    h: &'static Host,
    a1: Arg<'_, A1>,
    out: &mut RawOut,
) -> Status {
    // SAFETY: the host passes `inst` from this image's INSTANCE answer and calls only while its
    // `Instance` is alive, before `close` (I13, §10.4).
    let Some(i) = (unsafe { enter::<M>(inst) }) else {
        return Status::FAULT;
    };
    let mut out = Out::new(out, h);
    contain(|| <M as Call1<A1, S>>::call(i.plugin(), h, a1, &mut out))
}

/// # Safety
/// Uphold the module entry contract and `vt::EntryFn2`; both arguments and output remain valid
/// throughout the shared-plugin call. The instance is retained by the host.
pub(crate) unsafe extern "C" fn sync2<
    M: Call2<A1, A2, S>,
    A1: RawArg,
    A2: RawArg,
    const S: usize,
>(
    inst: *const c_void,
    h: &'static Host,
    a1: Arg<'_, A1>,
    a2: Arg<'_, A2>,
    out: &mut RawOut,
) -> Status {
    // SAFETY: the host passes `inst` from this image's INSTANCE answer and calls only while its
    // `Instance` is alive, before `close` (I13, §10.4).
    let Some(i) = (unsafe { enter::<M>(inst) }) else {
        return Status::FAULT;
    };
    let mut out = Out::new(out, h);
    contain(|| <M as Call2<A1, A2, S>>::call(i.plugin(), h, a1, a2, &mut out))
}

/// # Safety
/// Uphold the module entry contract and `vt::EntryFn3`; all arguments and output remain valid
/// throughout the shared-plugin call. The instance is retained by the host.
pub(crate) unsafe extern "C" fn sync3<
    M: Call3<A1, A2, A3, S>,
    A1: RawArg,
    A2: RawArg,
    A3: RawArg,
    const S: usize,
>(
    inst: *const c_void,
    h: &'static Host,
    a1: Arg<'_, A1>,
    a2: Arg<'_, A2>,
    a3: Arg<'_, A3>,
    out: &mut RawOut,
) -> Status {
    // SAFETY: the host passes `inst` from this image's INSTANCE answer and calls only while its
    // `Instance` is alive, before `close` (I13, §10.4).
    let Some(i) = (unsafe { enter::<M>(inst) }) else {
        return Status::FAULT;
    };
    let mut out = Out::new(out, h);
    contain(|| <M as Call3<A1, A2, A3, S>>::call(i.plugin(), h, a1, a2, a3, &mut out))
}

// ---- session openers and the consuming end ----

/// # Safety
/// Uphold the module entry contract and `vt::EntryFn1`. The new session is inserted into this same
/// instance; the host owns the returned token and must retain the instance until end/cancel.
pub(crate) unsafe extern "C" fn opener1<M: Opener1<A1, S>, A1: RawArg, const S: usize>(
    inst: *const c_void,
    h: &'static Host,
    a1: Arg<'_, A1>,
    out: &mut RawOut,
) -> Status {
    // SAFETY: the host passes `inst` from this image's INSTANCE answer and calls only while its
    // `Instance` is alive, before `close` (I13, §10.4).
    let Some(i) = (unsafe { enter::<M>(inst) }) else {
        return Status::FAULT;
    };
    let mut out = Out::new(out, h);
    contain(
        || match <M as Opener1<A1, S>>::begin(i.plugin(), h, a1, &mut out) {
            Ok(session) => match i.sessions().insert_raw(session) {
                Some((index, generation)) => M::opened(pack(true, index, generation), &mut out),
                None => Status::FAULT,
            },
            Err(status) => status,
        },
    )
}

/// # Safety
/// Uphold the module entry contract and `vt::EntryFn2`. The new session is inserted into this same
/// instance; the host owns the returned token and must retain the instance until end/cancel.
pub(crate) unsafe extern "C" fn opener2<
    M: Opener2<A1, A2, S>,
    A1: RawArg,
    A2: RawArg,
    const S: usize,
>(
    inst: *const c_void,
    h: &'static Host,
    a1: Arg<'_, A1>,
    a2: Arg<'_, A2>,
    out: &mut RawOut,
) -> Status {
    // SAFETY: the host passes `inst` from this image's INSTANCE answer and calls only while its
    // `Instance` is alive, before `close` (I13, §10.4).
    let Some(i) = (unsafe { enter::<M>(inst) }) else {
        return Status::FAULT;
    };
    let mut out = Out::new(out, h);
    contain(
        || match <M as Opener2<A1, A2, S>>::begin(i.plugin(), h, a1, a2, &mut out) {
            Ok(session) => match i.sessions().insert_raw(session) {
                Some((index, generation)) => M::opened(pack(true, index, generation), &mut out),
                None => Status::FAULT,
            },
            Err(status) => status,
        },
    )
}

/// # Safety
/// Uphold the module entry contract and `vt::EntryFn1`, with exclusive ownership of the session
/// token through removal and the adapter call. The removed session is consumed here; the host must
/// retire its handle before allowing another use, while retaining the instance through this call.
pub(crate) unsafe extern "C" fn end0<M: End0<S>, const S: usize>(
    inst: *const c_void,
    h: &'static Host,
    tok: Arg<'_, u64>,
    out: &mut RawOut,
) -> Status {
    // SAFETY: the host passes `inst` from this image's INSTANCE answer and calls only while its
    // `Instance` is alive, before `close` (I13, §10.4).
    let Some(i) = (unsafe { enter::<M>(inst) }) else {
        return Status::FAULT;
    };
    let (session, index, generation) = unpack(tok.get());
    if !session {
        return Status::FAULT;
    }
    let mut out = Out::new(out, h);
    contain(|| match i.sessions().remove_raw(index, generation) {
        Some(s) => <M as End0<S>>::end(i.plugin(), h, s, &mut out),
        None => Status::FAULT,
    })
}

// ---- methods on a live session: the token resolves to `&mut Session` ----

/// # Safety
/// Uphold the module entry contract and `vt::EntryFn1`. Exclude every other access/removal of this
/// session token until the adapter's mutable session borrow ends; the slot remains instance-owned.
pub(crate) unsafe extern "C" fn session0<M: Session0<S>, const S: usize>(
    inst: *const c_void,
    h: &'static Host,
    tok: Arg<'_, u64>,
    out: &mut RawOut,
) -> Status {
    // SAFETY: the host passes `inst` from this image's INSTANCE answer and calls only while its
    // `Instance` is alive, before `close` (I13, §10.4).
    let Some(i) = (unsafe { enter::<M>(inst) }) else {
        return Status::FAULT;
    };
    let mut out = Out::new(out, h);
    contain(|| {
        let (session, index, generation) = unpack(tok.get());
        if !session {
            return Status::FAULT;
        }
        // I6: the host makes this entry for the token while holding `&mut` to its session
        // handle, so no other entry reaches this slot's value now, and adapters cannot reach the table.
        let Some(s) = i.sessions().get_mut_raw(index, generation) else {
            return Status::FAULT;
        };
        <M as Session0<S>>::on(i.plugin(), h, s, &mut out)
    })
}

/// # Safety
/// Uphold the module entry contract and `vt::EntryFn2`. Exclude every other access/removal of this
/// session token until the adapter's mutable session borrow ends; the slot remains instance-owned.
pub(crate) unsafe extern "C" fn session1<M: Session1<A1, S>, A1: RawArg, const S: usize>(
    inst: *const c_void,
    h: &'static Host,
    tok: Arg<'_, u64>,
    a1: Arg<'_, A1>,
    out: &mut RawOut,
) -> Status {
    // SAFETY: the host passes `inst` from this image's INSTANCE answer and calls only while its
    // `Instance` is alive, before `close` (I13, §10.4).
    let Some(i) = (unsafe { enter::<M>(inst) }) else {
        return Status::FAULT;
    };
    let mut out = Out::new(out, h);
    contain(|| {
        let (session, index, generation) = unpack(tok.get());
        if !session {
            return Status::FAULT;
        }
        // I6: the host makes this entry for the token while holding `&mut` to its session
        // handle, so no other entry reaches this slot's value now, and adapters cannot reach the table.
        let Some(s) = i.sessions().get_mut_raw(index, generation) else {
            return Status::FAULT;
        };
        <M as Session1<A1, S>>::on(i.plugin(), h, s, a1, &mut out)
    })
}

/// # Safety
/// Uphold the module entry contract and `vt::EntryFn3`. Exclude every other access/removal of this
/// session token until the adapter's mutable session borrow ends; the slot remains instance-owned.
pub(crate) unsafe extern "C" fn session2<
    M: Session2<A1, A2, S>,
    A1: RawArg,
    A2: RawArg,
    const S: usize,
>(
    inst: *const c_void,
    h: &'static Host,
    tok: Arg<'_, u64>,
    a1: Arg<'_, A1>,
    a2: Arg<'_, A2>,
    out: &mut RawOut,
) -> Status {
    // SAFETY: the host passes `inst` from this image's INSTANCE answer and calls only while its
    // `Instance` is alive, before `close` (I13, §10.4).
    let Some(i) = (unsafe { enter::<M>(inst) }) else {
        return Status::FAULT;
    };
    let mut out = Out::new(out, h);
    contain(|| {
        let (session, index, generation) = unpack(tok.get());
        if !session {
            return Status::FAULT;
        }
        // I6: the host makes this entry for the token while holding `&mut` to its session
        // handle, so no other entry reaches this slot's value now, and adapters cannot reach the table.
        let Some(s) = i.sessions().get_mut_raw(index, generation) else {
            return Status::FAULT;
        };
        <M as Session2<A1, A2, S>>::on(i.plugin(), h, s, a1, a2, &mut out)
    })
}

/// # Safety
/// Uphold the module entry contract and `vt::EntryFn4`. Exclude every other access/removal of this
/// session token until the adapter's mutable session borrow ends; the slot remains instance-owned.
pub(crate) unsafe extern "C" fn session3<
    M: Session3<A1, A2, A3, S>,
    A1: RawArg,
    A2: RawArg,
    A3: RawArg,
    const S: usize,
>(
    inst: *const c_void,
    h: &'static Host,
    tok: Arg<'_, u64>,
    a1: Arg<'_, A1>,
    a2: Arg<'_, A2>,
    a3: Arg<'_, A3>,
    out: &mut RawOut,
) -> Status {
    // SAFETY: the host passes `inst` from this image's INSTANCE answer and calls only while its
    // `Instance` is alive, before `close` (I13, §10.4).
    let Some(i) = (unsafe { enter::<M>(inst) }) else {
        return Status::FAULT;
    };
    let mut out = Out::new(out, h);
    contain(|| {
        let (session, index, generation) = unpack(tok.get());
        if !session {
            return Status::FAULT;
        }
        // I6: the host makes this entry for the token while holding `&mut` to its session
        // handle, so no other entry reaches this slot's value now, and adapters cannot reach the table.
        let Some(s) = i.sessions().get_mut_raw(index, generation) else {
            return Status::FAULT;
        };
        <M as Session3<A1, A2, A3, S>>::on(i.plugin(), h, s, a1, a2, a3, &mut out)
    })
}

#[allow(clippy::too_many_arguments)]
/// # Safety
/// Uphold the module entry contract and `vt::EntryFn5`. Exclude every other access/removal of this
/// session token until the adapter's mutable session borrow ends; the slot remains instance-owned.
pub(crate) unsafe extern "C" fn session4<
    M: Session4<A1, A2, A3, A4, S>,
    A1: RawArg,
    A2: RawArg,
    A3: RawArg,
    A4: RawArg,
    const S: usize,
>(
    inst: *const c_void,
    h: &'static Host,
    tok: Arg<'_, u64>,
    a1: Arg<'_, A1>,
    a2: Arg<'_, A2>,
    a3: Arg<'_, A3>,
    a4: Arg<'_, A4>,
    out: &mut RawOut,
) -> Status {
    // SAFETY: the host passes `inst` from this image's INSTANCE answer and calls only while its
    // `Instance` is alive, before `close` (I13, §10.4).
    let Some(i) = (unsafe { enter::<M>(inst) }) else {
        return Status::FAULT;
    };
    let mut out = Out::new(out, h);
    contain(|| {
        let (session, index, generation) = unpack(tok.get());
        if !session {
            return Status::FAULT;
        }
        // I6: the host makes this entry for the token while holding `&mut` to its session
        // handle, so no other entry reaches this slot's value now, and adapters cannot reach the table.
        let Some(s) = i.sessions().get_mut_raw(index, generation) else {
            return Status::FAULT;
        };
        <M as Session4<A1, A2, A3, A4, S>>::on(i.plugin(), h, s, a1, a2, a3, a4, &mut out)
    })
}

// ---- async methods: a chain over the instance ----

/// Start a chain of instance `i` from the adapter's future.
macro_rules! start_chain {
    ($m:ty, $i:ident, $out:ident, |$id:ident| $start:expr) => {
        contain(|| {
            let Some($id) = ChainId::mint($i.serial()) else {
                return Status::FAULT;
            };
            let (fut, extra) = $start;
            drive_new::<$m>($i.chains(), ChainBox::new(tie(fut), $id, extra), &mut $out)
        })
    };
}

/// # Safety
/// Uphold the module entry contract and `vt::EntryFn0`. Keep this instance alive until any returned
/// chain retires: `tie` erases the plugin borrow, and `drive_new` parks it only in this instance.
pub(crate) unsafe extern "C" fn start0<M: Start0<S>, const S: usize>(
    inst: *const c_void,
    h: &'static Host,
    out: &mut RawOut,
) -> Status {
    // SAFETY: the host passes `inst` from this image's INSTANCE answer and calls only while its
    // `Instance` is alive, before `close` (I13, §10.4).
    let Some(i) = (unsafe { enter::<M>(inst) }) else {
        return Status::FAULT;
    };
    let mut out = Out::new(out, h);
    start_chain!(M, i, out, |id| <M as Start0<S>>::start(i.plugin(), h))
}

/// # Safety
/// Uphold the module entry contract and `vt::EntryFn1`. Retain the instance and immutable argument
/// storage until any returned chain retires; its future borrows the plugin and its chained argument.
pub(crate) unsafe extern "C" fn start1<M: Start1<A1, S>, A1: AsyncArg, const S: usize>(
    inst: *const c_void,
    h: &'static Host,
    a1: Arg<'_, A1>,
    out: &mut RawOut,
) -> Status {
    // SAFETY: the host passes `inst` from this image's INSTANCE answer and calls only while its
    // `Instance` is alive, before `close` (I13, §10.4).
    let Some(i) = (unsafe { enter::<M>(inst) }) else {
        return Status::FAULT;
    };
    let mut out = Out::new(out, h);
    start_chain!(M, i, out, |id| <M as Start1<A1, S>>::start(
        i.plugin(),
        h,
        A1::chain(a1, &id)
    ))
}

/// # Safety
/// Uphold the module entry contract and `vt::EntryFn2`. Retain the instance and both immutable
/// argument buffers until any returned chain retires; the future is parked only in this instance.
pub(crate) unsafe extern "C" fn start2<
    M: Start2<A1, A2, S>,
    A1: AsyncArg,
    A2: AsyncArg,
    const S: usize,
>(
    inst: *const c_void,
    h: &'static Host,
    a1: Arg<'_, A1>,
    a2: Arg<'_, A2>,
    out: &mut RawOut,
) -> Status {
    // SAFETY: the host passes `inst` from this image's INSTANCE answer and calls only while its
    // `Instance` is alive, before `close` (I13, §10.4).
    let Some(i) = (unsafe { enter::<M>(inst) }) else {
        return Status::FAULT;
    };
    let mut out = Out::new(out, h);
    start_chain!(M, i, out, |id| <M as Start2<A1, A2, S>>::start(
        i.plugin(),
        h,
        A1::chain(a1, &id),
        A2::chain(a2, &id)
    ))
}

/// # Safety
/// Uphold the module entry contract and `vt::EntryFn4`. Retain the instance and all immutable
/// argument buffers until any returned chain retires; the future is parked only in this instance.
pub(crate) unsafe extern "C" fn start4<
    M: Start4<A1, A2, A3, A4, S>,
    A1: AsyncArg,
    A2: AsyncArg,
    A3: AsyncArg,
    A4: AsyncArg,
    const S: usize,
>(
    inst: *const c_void,
    h: &'static Host,
    a1: Arg<'_, A1>,
    a2: Arg<'_, A2>,
    a3: Arg<'_, A3>,
    a4: Arg<'_, A4>,
    out: &mut RawOut,
) -> Status {
    // SAFETY: the host passes `inst` from this image's INSTANCE answer and calls only while its
    // `Instance` is alive, before `close` (I13, §10.4).
    let Some(i) = (unsafe { enter::<M>(inst) }) else {
        return Status::FAULT;
    };
    let mut out = Out::new(out, h);
    start_chain!(M, i, out, |id| <M as Start4<A1, A2, A3, A4, S>>::start(
        i.plugin(),
        h,
        A1::chain(a1, &id),
        A2::chain(a2, &id),
        A3::chain(a3, &id),
        A4::chain(a4, &id)
    ))
}

// ---- the header entries ----

pub(crate) extern "C" fn describe<M: Image>(h: &'static Host, out: &mut RawOut) -> Status {
    let mut out = Out::new(out, h);
    contain(|| M::describe(h, &mut out))
}

pub(crate) extern "C" fn open<M: Image>(
    h: &'static Host,
    config: Arg<'_, Bytes<'static>>,
    flags: u32,
    out: &mut RawOut,
) -> Status {
    let mut out = Out::new(out, h);
    contain(|| {
        let Some(id) = ChainId::mint(0) else {
            return Status::FAULT;
        };
        let chained = <Bytes<'static> as ToChain>::chain(config, &id);
        match M::open(h, config.get(), chained, flags, &mut out) {
            Opening::Done(status) => status,
            Opening::Chain(fut, extra) => {
                drive_new::<M>(M::global(), ChainBox::new(fut, id, extra), &mut out)
            }
        }
    })
}

/// Continue a chain (§6.4 step 4). `inst` null = the image's open slab.
/// # Safety
/// Uphold the module entry contract and `vt::ResumeFn`. The caller exclusively owns `tok` for this
/// poll and retains all argument/results storage through chain retirement. A non-null instance is
/// `M`'s live allocation; null selects `M::global`. Completion/fault removes and drops the chain here.
pub(crate) unsafe extern "C" fn resume<M: Image>(
    inst: *const c_void,
    h: &'static Host,
    tok: Arg<'_, u64>,
    results: Arg<'_, Bytes<'static>>,
    out: &mut RawOut,
) -> Status {
    // SAFETY: the host passes null (an open chain) or this image's live INSTANCE address (§6.4 step 6).
    let chains = match unsafe { enter::<M>(inst) } {
        Some(i) => i.chains(),
        None => M::global(),
    };
    let (session, index, generation) = unpack(tok.get());
    if session {
        return Status::FAULT;
    }
    let mut out = Out::new(out, h);
    contain(|| {
        // I6: the host resumes a chain token only from the one `Chain` that owns it, holding
        // `&mut` to it, so no other entry reaches this slot's value now.
        let Some(cb) = chains.get_mut_raw(index, generation) else {
            return Status::FAULT;
        };
        let results = <Bytes<'static> as ToChain>::chain(results, cb.id());
        let step = catch_unwind(AssertUnwindSafe(|| {
            M::poll(ChainRef::new(cb), Some(results), &mut out)
        }));
        match step {
            Ok(Step::Need) => M::parked(tok.get(), &mut out),
            Ok(Step::Ready(status)) => {
                drop(chains.remove_raw(index, generation));
                status
            }
            Ok(Step::Fault) | Err(_) => {
                drop(chains.remove_raw(index, generation));
                Status::FAULT
            }
        }
    })
}

/// Drop a chain or a session (§6.4 step 5). Unknown, free or stale: a no-op OK.
/// # Safety
/// Uphold the module entry contract and `vt::CancelFn`: serialize this token against every other
/// entry and keep its instance/image and any chain buffers live until its destructor finishes.
/// Repeated stale cancellation is permitted only sequentially; it does not lock a live slot.
pub(crate) unsafe extern "C" fn cancel<M: Image>(inst: *const c_void, tok: Token) -> Status {
    // SAFETY: the host passes null (an open chain) or this image's live INSTANCE address.
    let i = unsafe { enter::<M>(inst) };
    let (session, index, generation) = unpack(tok);
    contain(|| {
        match (i, session) {
            (None, false) => drop(M::global().remove_raw(index, generation)),
            (None, true) => {}
            (Some(i), false) => drop(i.chains().remove_raw(index, generation)),
            (Some(i), true) => drop(i.sessions().remove_raw(index, generation)),
        }
        Status::OK
    })
}

/// Drop the instance: chains, sessions, then the plugin (§6.4 step 9).
/// # Safety
/// Uphold `vt::CloseFn`: null or the uniquely owned, still-live `InstOf<M>` allocation from this
/// image. All entries and host borrows have ended, and no later access is permitted. `drop_inst`
/// drops fields in declaration order and releases the allocation without a second value drop.
pub(crate) unsafe extern "C" fn close<M: Image>(inst: *const c_void) -> Status {
    if inst.is_null() {
        return Status::OK;
    }
    contain(|| {
        // SAFETY: the host calls `close` once, from `Instance::drop`, after every other entry for the
        // instance, with the address its INSTANCE answer named; nothing uses it again.
        unsafe { drop_inst::<M::Plugin, M::Session, M::Reply, M::Inbox>(inst) };
        Status::OK
    })
}
