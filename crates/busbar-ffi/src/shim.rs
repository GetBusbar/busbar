// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The plugin-side entries (IF §6.4; core 3.0, interface revision C.3) and the safe adapter traits `kind!`
//! and `plugin!` implement.
//!
//! Every entry has the one shape `Entry(inst, host, &Call, &mut RawOut)`. There are five kind shims, one per
//! role a table position can have (a plain call, a session opener, a call on a live session, the consuming
//! end, an async start), and three header shims of the same shape (`describe`, `open`, `resume`), plus
//! `cancel` and `close`. None of them knows a kind: what `head`, `texts` and `blobs` mean is the adapter's.
//!
//! Every shim is `entry`-shaped: no panic crosses `extern "C"` (I10), a caught panic is FAULT. The one
//! `unsafe fn enter` turns the host's `inst` into the instance. Adapters never see the instance, a slot
//! table or a `RawOut`: sync methods get the plugin, session methods the plugin and their own session,
//! async starts the plugin for the chain's borrow.
//!
//! `unsafe` here: `enter` (def and body); per instance-taking shim its def and its `enter` block; the defs
//! of `describe` and `open` (they are `Entry`-typed); plus the `drop_inst` block of `close`. Slot access uses
//! crate-private primitives under each entry's I6 contract.
//!
//! # Entry safety contract
//!
//! Every shim implements `vt`'s entry safety contract. `M` must be the image that allocated `inst`, and the
//! allocation must remain live for the complete entry. `enter` only reconstructs a shared borrow; it does
//! not validate an arbitrary address or lock a slot. Session entries, resume, end and cancel therefore
//! additionally require exclusive access to their token (I6), supplied by the host handle's exclusive
//! borrow. Token generation checks reject stale identities but do not serialize two simultaneous entries
//! for the same live identity.
//!
//! The host keeps borrowed call and output memory valid for each synchronous call and retains async blobs
//! and results until the chain is retired. Async shims store borrowed futures only in the entered
//! instance's chain table; completion, cancellation and instance teardown drop those futures before their
//! plugin or host buffers. No shim other than `close` frees the instance.

#![allow(unsafe_code)]

use core::cell::Cell;
use core::ffi::c_void;
use core::future::Future;
use core::panic::AssertUnwindSafe;
use core::pin::Pin;
use std::panic::catch_unwind;

use crate::raw::{Bytes, ChainBytes, ChainId, Host, Out, RawOut, Status, Token};
use crate::slots::{ChainBox, ChainRef, Inst, Slots, drop_inst, pack, tie, unpack};
use crate::vt::{Args, Call, ChainArgs, Entry, Slot};

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

/// A plain sync method, one impl per slot `S` (the method's index in its kind's table). A call that does
/// not follow the method's layout (a short head, a missing text or blob) is the adapter's FAULT.
pub trait Plain<const S: usize>: Image {
    fn call(p: &Self::Plugin, h: &'static Host, args: Args<'_>, out: &mut Out<'_>) -> Status;
}

/// A session opener: Ok = the new session, which the shim inserts before `Image::opened` writes its
/// TOKEN; Err = the status of the FAIL written (or FAULT for a call off its layout).
pub trait Opens<const S: usize>: Image {
    fn begin(
        p: &Self::Plugin,
        h: &'static Host,
        args: Args<'_>,
        out: &mut Out<'_>,
    ) -> Result<Self::Session, Status>;
}

/// A method on a live session: the shim resolves `Call::session` to `&mut Session`.
pub trait OnSession<const S: usize>: Image {
    fn on(
        p: &Self::Plugin,
        h: &'static Host,
        s: &mut Self::Session,
        args: Args<'_>,
        out: &mut Out<'_>,
    ) -> Status;
}

/// A method that consumes its session: the shim removes it first.
pub trait Ends<const S: usize>: Image {
    fn end(
        p: &Self::Plugin,
        h: &'static Host,
        s: Self::Session,
        args: Args<'_>,
        out: &mut Out<'_>,
    ) -> Status;
}

/// An async method: start the chain future over the plugin it borrows. None: the call is off its layout
/// (FAULT). Nothing borrowed from `args` can enter the future: numbers are copied, bytes are `ChainBytes`.
pub trait Starts<const S: usize>: Image {
    fn start<'i>(
        p: &'i Self::Plugin,
        h: &'static Host,
        args: ChainArgs<'_>,
    ) -> Option<(ChainFut<'i, Self::Reply>, Self::Inbox)>;
}

std::thread_local! {
    /// The clock reading the host handed the entry running on this thread (`Call::mono_ns`); 0 outside one.
    static MONO: Cell<u64> = const { Cell::new(0) };
}

/// The host's one clock reading for the operation whose entry is running on this thread (monotonic
/// nanoseconds, the WAKE_AT clock), or 0 when the host gave none or no entry is running. A plugin reads the
/// time here instead of calling back into the host (core 3.0).
pub fn mono_ns() -> u64 {
    MONO.try_with(Cell::get).unwrap_or(0)
}

/// Sets the entry's clock reading and restores the enclosing entry's on return and on unwind.
struct Clock(u64);

impl Clock {
    fn enter(mono_ns: u64) -> Clock {
        Clock(MONO.try_with(|m| m.replace(mono_ns)).unwrap_or(0))
    }
}

impl Drop for Clock {
    fn drop(&mut self) {
        let _ = MONO.try_with(|m| m.set(self.0));
    }
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

// ---- the five kind shims ----

/// # Safety
/// Uphold the module entry contract: this is `M`'s live instance, borrowed only for the call; `call` and
/// `out` stay valid throughout. The adapter receives a shared plugin borrow and cannot free the instance.
unsafe extern "C" fn plain_entry<M: Plain<S>, const S: usize>(
    inst: *const c_void,
    h: &'static Host,
    call: &Call<'_>,
    out: &mut RawOut,
) -> Status {
    // SAFETY: the host passes `inst` from this image's INSTANCE answer and calls only while its
    // `Instance` is alive, before `close` (I13, §10.4).
    let Some(i) = (unsafe { enter::<M>(inst) }) else {
        return Status::FAULT;
    };
    let mut out = Out::new(out, h);
    let _clock = Clock::enter(call.mono_ns());
    contain(|| <M as Plain<S>>::call(i.plugin(), h, Args::new(call), &mut out))
}

/// # Safety
/// Uphold the module entry contract. The new session is inserted into this same instance; the host owns
/// the returned token and must retain the instance until end or cancel.
unsafe extern "C" fn opens_entry<M: Opens<S>, const S: usize>(
    inst: *const c_void,
    h: &'static Host,
    call: &Call<'_>,
    out: &mut RawOut,
) -> Status {
    // SAFETY: the host passes `inst` from this image's INSTANCE answer and calls only while its
    // `Instance` is alive, before `close` (I13, §10.4).
    let Some(i) = (unsafe { enter::<M>(inst) }) else {
        return Status::FAULT;
    };
    let mut out = Out::new(out, h);
    let _clock = Clock::enter(call.mono_ns());
    contain(
        || match <M as Opens<S>>::begin(i.plugin(), h, Args::new(call), &mut out) {
            Ok(session) => match i.sessions().insert_raw(session) {
                Some((index, generation)) => M::opened(pack(true, index, generation), &mut out),
                None => Status::FAULT,
            },
            Err(status) => status,
        },
    )
}

/// # Safety
/// Uphold the module entry contract. Exclude every other access or removal of the session
/// `call.session` names until the adapter's mutable session borrow ends; the slot remains instance-owned.
unsafe extern "C" fn on_session_entry<M: OnSession<S>, const S: usize>(
    inst: *const c_void,
    h: &'static Host,
    call: &Call<'_>,
    out: &mut RawOut,
) -> Status {
    // SAFETY: the host passes `inst` from this image's INSTANCE answer and calls only while its
    // `Instance` is alive, before `close` (I13, §10.4).
    let Some(i) = (unsafe { enter::<M>(inst) }) else {
        return Status::FAULT;
    };
    let mut out = Out::new(out, h);
    let _clock = Clock::enter(call.mono_ns());
    contain(|| {
        let (session, index, generation) = unpack(call.session());
        if !session {
            return Status::FAULT;
        }
        // I6: only the host's `Session` puts a live session token in a call, while holding `&mut` to
        // itself, so no other entry reaches this slot's value now, and adapters cannot reach the table.
        let Some(s) = i.sessions().get_mut_raw(index, generation) else {
            return Status::FAULT;
        };
        <M as OnSession<S>>::on(i.plugin(), h, s, Args::new(call), &mut out)
    })
}

/// # Safety
/// Uphold the module entry contract, with exclusive ownership of the session token through removal and
/// the adapter call. The removed session is consumed here; the host must retire its handle before
/// allowing another use, while retaining the instance through this call.
unsafe extern "C" fn ends_entry<M: Ends<S>, const S: usize>(
    inst: *const c_void,
    h: &'static Host,
    call: &Call<'_>,
    out: &mut RawOut,
) -> Status {
    // SAFETY: the host passes `inst` from this image's INSTANCE answer and calls only while its
    // `Instance` is alive, before `close` (I13, §10.4).
    let Some(i) = (unsafe { enter::<M>(inst) }) else {
        return Status::FAULT;
    };
    let (session, index, generation) = unpack(call.session());
    if !session {
        return Status::FAULT;
    }
    let mut out = Out::new(out, h);
    let _clock = Clock::enter(call.mono_ns());
    contain(|| match i.sessions().remove_raw(index, generation) {
        Some(s) => <M as Ends<S>>::end(i.plugin(), h, s, Args::new(call), &mut out),
        None => Status::FAULT,
    })
}

/// # Safety
/// Uphold the module entry contract. Retain the instance and every blob of `call` (immutable) until any
/// returned chain retires: `tie` erases the plugin borrow, and `drive_new` parks the future only in this
/// instance; its `ChainBytes` point at the blobs.
unsafe extern "C" fn starts_entry<M: Starts<S>, const S: usize>(
    inst: *const c_void,
    h: &'static Host,
    call: &Call<'_>,
    out: &mut RawOut,
) -> Status {
    // SAFETY: the host passes `inst` from this image's INSTANCE answer and calls only while its
    // `Instance` is alive, before `close` (I13, §10.4).
    let Some(i) = (unsafe { enter::<M>(inst) }) else {
        return Status::FAULT;
    };
    let mut out = Out::new(out, h);
    let _clock = Clock::enter(call.mono_ns());
    contain(|| {
        let Some(id) = ChainId::mint(i.serial()) else {
            return Status::FAULT;
        };
        let Some((fut, extra)) = <M as Starts<S>>::start(i.plugin(), h, ChainArgs::new(call, &id))
        else {
            return Status::FAULT;
        };
        drive_new::<M>(i.chains(), ChainBox::new(tie(fut), id, extra), &mut out)
    })
}

/// The table position of a plain sync method of image `M` at slot `S`.
pub const fn plain<M: Plain<S>, const S: usize>() -> Slot<M> {
    let entry: Entry = plain_entry::<M, S>;
    Slot::new(entry)
}
/// The table position of a session opener.
pub const fn opens<M: Opens<S>, const S: usize>() -> Slot<M> {
    let entry: Entry = opens_entry::<M, S>;
    Slot::new(entry)
}
/// The table position of a method on a live session.
pub const fn on_session<M: OnSession<S>, const S: usize>() -> Slot<M> {
    let entry: Entry = on_session_entry::<M, S>;
    Slot::new(entry)
}
/// The table position of the method that consumes its session.
pub const fn ends<M: Ends<S>, const S: usize>() -> Slot<M> {
    let entry: Entry = ends_entry::<M, S>;
    Slot::new(entry)
}
/// The table position of an async method.
pub const fn starts<M: Starts<S>, const S: usize>() -> Slot<M> {
    let entry: Entry = starts_entry::<M, S>;
    Slot::new(entry)
}

// ---- the header entries ----

/// The first `u32` of a head (little-endian), or None when it is shorter.
fn head_u32(head: &[u8]) -> Option<u32> {
    Some(u32::from_le_bytes(head.get(..4)?.try_into().ok()?))
}

/// Cold: describe items. `inst` and the call's fields are not read.
/// # Safety
/// Uphold the module entry contract for `call` and `out`; `inst` is ignored (the host passes null).
pub(crate) unsafe extern "C" fn describe<M: Image>(
    _inst: *const c_void,
    h: &'static Host,
    call: &Call<'_>,
    out: &mut RawOut,
) -> Status {
    let mut out = Out::new(out, h);
    let _clock = Clock::enter(call.mono_ns());
    contain(|| M::describe(h, &mut out))
}

/// `open`: head = `flags: u32` (DRY_RUN); blob 0 = the bound config, which the open chain keeps.
/// # Safety
/// Uphold the module entry contract for `call` and `out`, and keep blob 0 immutable and allocated until
/// any returned open chain retires; `inst` is ignored (the host passes null).
pub(crate) unsafe extern "C" fn open<M: Image>(
    _inst: *const c_void,
    h: &'static Host,
    call: &Call<'_>,
    out: &mut RawOut,
) -> Status {
    let mut out = Out::new(out, h);
    let _clock = Clock::enter(call.mono_ns());
    contain(|| {
        let (Some(flags), Some(config)) = (head_u32(call.head()), call.blobs().first().copied())
        else {
            return Status::FAULT;
        };
        let Some(id) = ChainId::mint(0) else {
            return Status::FAULT;
        };
        let chained = ChainBytes::of(config, &id);
        match M::open(h, config, chained, flags, &mut out) {
            Opening::Done(status) => status,
            Opening::Chain(fut, extra) => {
                drive_new::<M>(M::global(), ChainBox::new(fut, id, extra), &mut out)
            }
        }
    })
}

/// Continue a chain (§6.4 step 4): `call.session` = its token, blob 0 = the results of its NEEDs. `inst`
/// null = the image's open slab.
/// # Safety
/// Uphold the module entry contract. The caller exclusively owns the chain token for this poll and
/// retains all argument and results storage through chain retirement. A non-null instance is `M`'s live
/// allocation; null selects `M::global`. Completion or fault removes and drops the chain here.
pub(crate) unsafe extern "C" fn resume<M: Image>(
    inst: *const c_void,
    h: &'static Host,
    call: &Call<'_>,
    out: &mut RawOut,
) -> Status {
    // SAFETY: the host passes null (an open chain) or this image's live INSTANCE address (§6.4 step 6).
    let chains = match unsafe { enter::<M>(inst) } {
        Some(i) => i.chains(),
        None => M::global(),
    };
    let tok = call.session();
    let (session, index, generation) = unpack(tok);
    if session {
        return Status::FAULT;
    }
    let Some(results) = call.blobs().first().copied() else {
        return Status::FAULT;
    };
    let mut out = Out::new(out, h);
    let _clock = Clock::enter(call.mono_ns());
    contain(|| {
        // I6: the host resumes a chain token only from the one `Chain` that owns it, holding
        // `&mut` to it, so no other entry reaches this slot's value now.
        let Some(cb) = chains.get_mut_raw(index, generation) else {
            return Status::FAULT;
        };
        let results = ChainBytes::of(results, cb.id());
        let step = catch_unwind(AssertUnwindSafe(|| {
            M::poll(ChainRef::new(cb), Some(results), &mut out)
        }));
        match step {
            Ok(Step::Need) => M::parked(tok, &mut out),
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
