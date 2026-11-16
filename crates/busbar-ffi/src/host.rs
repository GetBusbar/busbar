// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The host's side of the boundary (feature `host`; IF §10.1, §10.4, §10.5, §10.7; UNSAFE-MIN §2.2).
//!
//! - `OutLease` and `grow`: the per-thread ACTIVE stack of out buffers. `grow` matches the top by the
//!   identity of the `&mut RawOut` it is handed and writes `ptr`/`cap` through that argument (A5).
//! - `Arena`: the append-only crypto arena behind `RawLent`.
//! - `Instance<K>` (built only from the INSTANCE record of an answer this crate made), `Session<K>`
//!   (holds `Arc<Instance<K>>`), `Chain<'i, K>` (borrows its instance, or is owned by the image for `open`,
//!   and keeps every argument and result buffer until its token retires).
//! - Entries are typed by role (`Plain`, `Opens`, `OnSession`, `Ends`, `Starts`), so a session method
//!   can be called only through its `Session` (`&mut`, I6) and a chain only through its `Chain`.
//!
//! `unsafe` here: one call block per entry arity (`invoke0..=invoke5`), the `resume`, `cancel` and
//! `close` calls, and `Arena::lend`'s append.

#![allow(unsafe_code)]

use core::cell::{Cell, RefCell};
use core::ffi::c_void;
use core::marker::PhantomData;
use std::sync::Arc;

use zerocopy::{FromBytes, Immutable, KnownLayout};

use crate::header::Plugin;
use crate::image::Admitted;
use crate::raw::{Arg, Bytes, Ctx, Host, RawArg, RawLent, RawOut, Status, TOKEN_SESSION, Token};
use crate::vt::{
    Ends, EntryFn0, EntryFn1, EntryFn2, EntryFn3, EntryFn4, EntryFn5, Kind, OnSession, Opens,
    Plain, Starts, VtEntry,
};

// ---- answers ----

/// A record head (IF §3): tag, reserved, body length; the body is padded to 8.
#[repr(C)]
#[derive(Clone, Copy, FromBytes, Immutable, KnownLayout)]
struct RecHead {
    tag: u16,
    _r: u16,
    len: u32,
}
const TAG_TOKEN: u16 = 0x0003;
const TAG_INSTANCE: u16 = 0x0009;

/// The records of an answer, as (tag, body), stopping at the first malformed one.
fn records(mut bytes: &[u8]) -> impl Iterator<Item = (u16, &[u8])> {
    core::iter::from_fn(move || {
        let (head, rest) = RecHead::read_from_prefix(bytes).ok()?;
        let len = usize::try_from(head.len).ok()?;
        let body = rest.get(..len)?;
        let padded = len.checked_add(7)? & !7;
        bytes = rest.get(padded..).unwrap_or(&[]);
        Some((head.tag, body))
    })
}

fn u64_of(body: &[u8]) -> Option<u64> {
    Some(u64::from_le_bytes(body.try_into().ok()?))
}

/// The leading TOKEN of a session opener's OK answer (bit 63 set).
fn leading_session(answer: &[u8]) -> Option<Token> {
    let (tag, body) = records(answer).next()?;
    let tok = u64_of(body)?;
    (tag == TAG_TOKEN && tok & TOKEN_SESSION != 0).then_some(tok)
}

/// The TOKEN of a NEED answer (a chain token: bit 63 clear, never 0).
fn chain_token(answer: &[u8]) -> Option<Token> {
    let (_, body) = records(answer).find(|(tag, _)| *tag == TAG_TOKEN)?;
    let tok = u64_of(body)?;
    (tok != 0 && tok & TOKEN_SESSION == 0).then_some(tok)
}

// ---- the out lease ----

/// Nested entries on one thread (the ACTIVE stack bound).
pub const DEPTH: usize = 16;

struct Active {
    serial: u64,
    identity: usize,
    max_out: usize,
    buf: Vec<u8>,
}

std::thread_local! {
    static ACTIVE: RefCell<Vec<Active>> = const { RefCell::new(Vec::new()) };
    static NEXT_LEASE: Cell<u64> = const { Cell::new(0) };
}

/// One entry's out buffer: a pooled `Vec` (zero-filled here) on this thread's ACTIVE stack, and the
/// `RawOut` the plugin writes through. `!Send`: it belongs to this thread's stack.
pub struct OutLease {
    raw: RawOut,
    serial: u64,
    _thread: PhantomData<*mut ()>,
}

impl OutLease {
    /// Lease `buf` (any content; it is zero-filled) for one entry, growing up to `max_out`. None: the
    /// ACTIVE stack is `DEPTH` deep.
    pub fn new(mut buf: Vec<u8>, max_out: usize) -> Option<OutLease> {
        buf.fill(0);
        let raw = RawOut::over(&mut buf);
        let serial = NEXT_LEASE.get().wrapping_add(1);
        NEXT_LEASE.set(serial);
        let pushed = ACTIVE.with_borrow_mut(|stack| {
            if stack.len() >= DEPTH {
                return false;
            }
            stack.push(Active {
                serial,
                identity: 0,
                max_out,
                buf,
            });
            true
        });
        pushed.then_some(OutLease {
            raw,
            serial,
            _thread: PhantomData,
        })
    }

    /// Bytes the plugin wrote.
    pub fn len(&self) -> usize {
        self.raw.len()
    }
    pub fn is_empty(&self) -> bool {
        self.raw.is_empty()
    }

    /// The channel for one entry, with its identity recorded on the stack (it cannot move while the
    /// entry runs: the call borrows it).
    fn arm(&mut self) -> &mut RawOut {
        let identity = self.raw.identity();
        let serial = self.serial;
        ACTIVE.with_borrow_mut(|stack| {
            if let Some(top) = stack.last_mut()
                && top.serial == serial
            {
                top.identity = identity;
            }
        });
        &mut self.raw
    }

    /// Read the answer, `[0, len)`.
    pub fn with_answer<R>(&self, f: impl FnOnce(&[u8]) -> R) -> R {
        let len = self.raw.len();
        ACTIVE.with_borrow(|stack| {
            let answer = stack
                .iter()
                .rev()
                .find(|active| active.serial == self.serial)
                .and_then(|active| active.buf.get(..len))
                .unwrap_or(&[]);
            f(answer)
        })
    }

    /// Give the buffer back to the pool (which zeroes it); `[0, len)` is the answer.
    pub fn into_buf(self) -> (Vec<u8>, usize) {
        let len = self.raw.len();
        let buf = take_lease(self.serial).unwrap_or_default();
        core::mem::forget(self);
        (buf, len)
    }
}

fn take_lease(serial: u64) -> Option<Vec<u8>> {
    ACTIVE
        .try_with(|stack| {
            let mut stack = stack.borrow_mut();
            let at = stack.iter().rposition(|active| active.serial == serial)?;
            Some(stack.remove(at).buf)
        })
        .ok()
        .flatten()
}

impl Drop for OutLease {
    fn drop(&mut self) {
        if let Some(mut buf) = take_lease(self.serial) {
            buf.fill(0);
            core::hint::black_box(&buf);
        }
    }
}

/// The host side of `Host::grow`: grow this thread's ACTIVE buffer by `need` (I10, §10.1). False if
/// there is no ACTIVE buffer, if `raw` is not the top one, if `len + need` overflows or passes max_out.
/// The old block is zeroed before release (I11), and `ptr`/`cap` are written through `raw`.
pub fn grow(raw: &mut RawOut, need: usize) -> bool {
    ACTIVE.with_borrow_mut(|stack| {
        let Some(top) = stack.last_mut() else {
            return false;
        };
        if top.identity != raw.identity() {
            return false;
        }
        let len = raw.len();
        let Some(want) = len.checked_add(need) else {
            return false;
        };
        if want > top.max_out {
            return false;
        }
        if want <= top.buf.len() {
            return true;
        }
        let cap = want.max(top.buf.len().saturating_mul(2)).min(top.max_out);
        let mut next = vec![0u8; cap];
        if let (Some(dst), Some(src)) = (next.get_mut(..len), top.buf.get(..len)) {
            dst.copy_from_slice(src);
        }
        top.buf.fill(0);
        core::hint::black_box(&top.buf);
        raw.repoint(&mut next);
        top.buf = next;
        true
    })
}

// ---- the crypto arena ----

/// One thread's append-only crypto arena (r4 H3): allocated once at its cap, never grown; every output
/// of one outermost entry gets fresh space after the previous ones.
pub struct Arena {
    store: Vec<u8>,
    len: usize,
}

impl Arena {
    pub fn new(cap: usize) -> Arena {
        Arena {
            store: vec![0u8; cap],
            len: 0,
        }
    }

    /// Append `src` and lend it for `'e`. None: it does not fit after this entry's earlier outputs
    /// (LIMIT); nothing is written then and the earlier outputs stay intact.
    pub fn lend<'e>(&mut self, ctx: Ctx<'e>, src: &[u8]) -> Option<RawLent<'e>> {
        let end = self.len.checked_add(src.len())?;
        if end > self.store.len() {
            return None;
        }
        if src.is_empty() {
            return Some(RawLent::EMPTY);
        }
        let at = self.store.as_mut_ptr().wrapping_add(self.len);
        // SAFETY: `[len, end)` lies inside the store (checked above) and was never lent in this entry
        // (append-only), so no reference into it exists; `as_mut_ptr` keeps earlier lent pointers valid
        // (it materialises no reference); `src` is the host's own output, a separate allocation.
        unsafe { core::ptr::copy_nonoverlapping(src.as_ptr(), at, src.len()) };
        self.len = end;
        Some(RawLent::lent(at.cast_const(), src.len(), ctx))
    }

    /// At the outermost entry's exit: the bytes lent in this entry, for the guard to zero, and reset.
    pub fn drain(&mut self) -> &mut [u8] {
        let len = core::mem::take(&mut self.len);
        self.store.get_mut(..len).unwrap_or(&mut [])
    }
}

// ---- instances ----

/// A live plugin instance (IF §10.4). Built only from the INSTANCE record of an `open` answer this crate
/// made; calls take `&self`, and `Drop` is the only `close`, so a close never overlaps a call.
pub struct Instance<K: Kind> {
    inst: usize,
    vt: &'static K::Vt,
    host: &'static Host,
    image: Admitted,
    _k: PhantomData<fn() -> K>,
}

fn invoke0<K: Kind>(inst: &Instance<K>, f: EntryFn0, out: &mut RawOut) -> Status {
    // SAFETY: (for all six `invoke`s) callers pass only an entry selected from `inst`'s own table, so `f` is a
    // shim of the image whose INSTANCE `inst` holds; that instance is alive (borrowed here, and `close`
    // runs only in `Instance::drop`); the arguments and `out` are borrowed for the call.
    unsafe { f(inst.ptr(), inst.host, out) }
}
fn invoke1<K: Kind, A1: RawArg>(
    inst: &Instance<K>,
    f: EntryFn1<A1>,
    a1: Arg<'_, A1>,
    out: &mut RawOut,
) -> Status {
    // SAFETY: as `invoke0`.
    unsafe { f(inst.ptr(), inst.host, a1, out) }
}
fn invoke2<K: Kind, A1: RawArg, A2: RawArg>(
    inst: &Instance<K>,
    f: EntryFn2<A1, A2>,
    a1: Arg<'_, A1>,
    a2: Arg<'_, A2>,
    out: &mut RawOut,
) -> Status {
    // SAFETY: as `invoke0`.
    unsafe { f(inst.ptr(), inst.host, a1, a2, out) }
}
fn invoke3<K: Kind, A1: RawArg, A2: RawArg, A3: RawArg>(
    inst: &Instance<K>,
    f: EntryFn3<A1, A2, A3>,
    a: (Arg<'_, A1>, Arg<'_, A2>, Arg<'_, A3>),
    out: &mut RawOut,
) -> Status {
    // SAFETY: as `invoke0`.
    unsafe { f(inst.ptr(), inst.host, a.0, a.1, a.2, out) }
}
fn invoke4<K: Kind, A1: RawArg, A2: RawArg, A3: RawArg, A4: RawArg>(
    inst: &Instance<K>,
    f: EntryFn4<A1, A2, A3, A4>,
    a: (Arg<'_, A1>, Arg<'_, A2>, Arg<'_, A3>, Arg<'_, A4>),
    out: &mut RawOut,
) -> Status {
    // SAFETY: as `invoke0`.
    unsafe { f(inst.ptr(), inst.host, a.0, a.1, a.2, a.3, out) }
}
#[allow(clippy::type_complexity)]
fn invoke5<K: Kind, A1: RawArg, A2: RawArg, A3: RawArg, A4: RawArg, A5: RawArg>(
    inst: &Instance<K>,
    f: EntryFn5<A1, A2, A3, A4, A5>,
    a: (
        Arg<'_, A1>,
        Arg<'_, A2>,
        Arg<'_, A3>,
        Arg<'_, A4>,
        Arg<'_, A5>,
    ),
    out: &mut RawOut,
) -> Status {
    // SAFETY: as `invoke0`.
    unsafe { f(inst.ptr(), inst.host, a.0, a.1, a.2, a.3, a.4, out) }
}

/// `cancel(inst, tok)` through the image's header.
fn cancel_raw(header: &Plugin, inst: *const c_void, tok: Token) -> Status {
    match header.entries().3 {
        // SAFETY: `cancel` is the image's own header entry; `inst` is null (the image's open slab) or the
        // image's live instance; the token belongs to the one `Chain` or `Session` calling this from its
        // `Drop`, so no other entry for it can run (I6). Unknown or stale tokens are a no-op.
        Some(f) => unsafe { f(inst, tok) },
        None => Status::FAULT,
    }
}

impl<K: Kind> Instance<K> {
    fn ptr(&self) -> *const c_void {
        core::ptr::with_exposed_provenance(self.inst)
    }

    fn from_answer(image: Admitted, host: &'static Host, answer: &[u8]) -> Option<Instance<K>> {
        let vt = image.vt::<K>()?;
        let (_, body) = records(answer).find(|(tag, _)| *tag == TAG_INSTANCE)?;
        let inst = usize::try_from(u64_of(body)?).ok()?;
        (inst != 0).then_some(Instance {
            inst,
            vt,
            host,
            image,
            _k: PhantomData,
        })
    }

    /// The image this instance runs in.
    pub fn image(&self) -> Admitted {
        self.image
    }

    pub fn call0(
        &self,
        sel: impl for<'v> FnOnce(&'v K::Vt) -> &'v VtEntry<Plain<EntryFn0>>,
        lease: &mut OutLease,
    ) -> Status {
        match sel(self.vt).get() {
            Some(Plain(f)) => invoke0(self, f, lease.arm()),
            None => Status::FAULT,
        }
    }
    pub fn call1<A1: RawArg>(
        &self,
        sel: impl for<'v> FnOnce(&'v K::Vt) -> &'v VtEntry<Plain<EntryFn1<A1>>>,
        a1: Arg<'_, A1>,
        lease: &mut OutLease,
    ) -> Status {
        match sel(self.vt).get() {
            Some(Plain(f)) => invoke1(self, f, a1, lease.arm()),
            None => Status::FAULT,
        }
    }
    pub fn call2<A1: RawArg, A2: RawArg>(
        &self,
        sel: impl for<'v> FnOnce(&'v K::Vt) -> &'v VtEntry<Plain<EntryFn2<A1, A2>>>,
        a1: Arg<'_, A1>,
        a2: Arg<'_, A2>,
        lease: &mut OutLease,
    ) -> Status {
        match sel(self.vt).get() {
            Some(Plain(f)) => invoke2(self, f, a1, a2, lease.arm()),
            None => Status::FAULT,
        }
    }
    pub fn call3<A1: RawArg, A2: RawArg, A3: RawArg>(
        &self,
        sel: impl for<'v> FnOnce(&'v K::Vt) -> &'v VtEntry<Plain<EntryFn3<A1, A2, A3>>>,
        a: (Arg<'_, A1>, Arg<'_, A2>, Arg<'_, A3>),
        lease: &mut OutLease,
    ) -> Status {
        match sel(self.vt).get() {
            Some(Plain(f)) => invoke3(self, f, a, lease.arm()),
            None => Status::FAULT,
        }
    }

    /// The session an opener's answer names, if the call was OK with a leading session TOKEN
    /// (OK without one is FAULT `MissingToken`).
    fn opened(self: &Arc<Self>, status: Status, lease: &OutLease) -> (Status, Option<Session<K>>) {
        if status != Status::OK {
            return (status, None);
        }
        match lease.with_answer(leading_session) {
            Some(tok) => (
                status,
                Some(Session {
                    inst: Arc::clone(self),
                    tok,
                    _ns: PhantomData,
                }),
            ),
            None => (Status::FAULT, None),
        }
    }
    pub fn open_session1<A1: RawArg>(
        self: &Arc<Self>,
        sel: impl for<'v> FnOnce(&'v K::Vt) -> &'v VtEntry<Opens<EntryFn1<A1>>>,
        a1: Arg<'_, A1>,
        lease: &mut OutLease,
    ) -> (Status, Option<Session<K>>) {
        let status = match sel(self.vt).get() {
            Some(Opens(f)) => invoke1(self, f, a1, lease.arm()),
            None => Status::FAULT,
        };
        self.opened(status, lease)
    }
    pub fn open_session2<A1: RawArg, A2: RawArg>(
        self: &Arc<Self>,
        sel: impl for<'v> FnOnce(&'v K::Vt) -> &'v VtEntry<Opens<EntryFn2<A1, A2>>>,
        a1: Arg<'_, A1>,
        a2: Arg<'_, A2>,
        lease: &mut OutLease,
    ) -> (Status, Option<Session<K>>) {
        let status = match sel(self.vt).get() {
            Some(Opens(f)) => invoke2(self, f, a1, a2, lease.arm()),
            None => Status::FAULT,
        };
        self.opened(status, lease)
    }

    /// After an async start: a chain on NEED, else the answer.
    fn started<'i>(&'i self, status: Status, bufs: ChainBufs, lease: &OutLease) -> Started<'i, K> {
        if status != Status::NEED {
            return Started::Done(status);
        }
        match lease.with_answer(chain_token) {
            Some(tok) => Started::Need(Chain {
                owner: Owner::Instance(self),
                tok,
                bufs,
            }),
            None => Started::Done(Status::FAULT),
        }
    }
    pub fn start0<'i>(
        &'i self,
        sel: impl for<'v> FnOnce(&'v K::Vt) -> &'v VtEntry<Starts<EntryFn0>>,
        lease: &mut OutLease,
    ) -> Started<'i, K> {
        let status = match sel(self.vt).get() {
            Some(Starts(f)) => invoke0(self, f, lease.arm()),
            None => Status::FAULT,
        };
        self.started(status, ChainBufs::new(), lease)
    }
    /// `make` builds the arguments from `bufs` (or from `'static` data), which the chain then keeps.
    pub fn start1<'i, A1: RawArg>(
        &'i self,
        sel: impl for<'v> FnOnce(&'v K::Vt) -> &'v VtEntry<Starts<EntryFn1<A1>>>,
        bufs: ChainBufs,
        make: impl for<'b> FnOnce(&'b ChainBufs) -> Arg<'b, A1>,
        lease: &mut OutLease,
    ) -> Started<'i, K> {
        let status = match sel(self.vt).get() {
            Some(Starts(f)) => invoke1(self, f, make(&bufs), lease.arm()),
            None => Status::FAULT,
        };
        self.started(status, bufs, lease)
    }
    pub fn start2<'i, A1: RawArg, A2: RawArg>(
        &'i self,
        sel: impl for<'v> FnOnce(&'v K::Vt) -> &'v VtEntry<Starts<EntryFn2<A1, A2>>>,
        bufs: ChainBufs,
        make: impl for<'b> FnOnce(&'b ChainBufs) -> (Arg<'b, A1>, Arg<'b, A2>),
        lease: &mut OutLease,
    ) -> Started<'i, K> {
        let status = match sel(self.vt).get() {
            Some(Starts(f)) => {
                let (a1, a2) = make(&bufs);
                invoke2(self, f, a1, a2, lease.arm())
            }
            None => Status::FAULT,
        };
        self.started(status, bufs, lease)
    }
    #[allow(clippy::type_complexity)]
    pub fn start4<'i, A1: RawArg, A2: RawArg, A3: RawArg, A4: RawArg>(
        &'i self,
        sel: impl for<'v> FnOnce(&'v K::Vt) -> &'v VtEntry<Starts<EntryFn4<A1, A2, A3, A4>>>,
        bufs: ChainBufs,
        make: impl for<'b> FnOnce(&'b ChainBufs) -> (Arg<'b, A1>, Arg<'b, A2>, Arg<'b, A3>, Arg<'b, A4>),
        lease: &mut OutLease,
    ) -> Started<'i, K> {
        let status = match sel(self.vt).get() {
            Some(Starts(f)) => invoke4(self, f, make(&bufs), lease.arm()),
            None => Status::FAULT,
        };
        self.started(status, bufs, lease)
    }
}

impl<K: Kind> Drop for Instance<K> {
    fn drop(&mut self) {
        if let Some(close) = self.image.header().entries().4 {
            // SAFETY: `close` is the image's own header entry and `inst` its live INSTANCE address. This is
            // the last use: every `Session` holds an `Arc` of this instance and every `Chain` borrows it, so
            // none is left, and no other entry for the instance can run.
            let _ = unsafe { close(self.ptr()) };
        }
    }
}

// ---- sessions ----

/// A live session (IF §10.4 `SessionHandle`): `Send`, `!Sync`, `!Clone`; methods take `&mut self`, so one
/// entry per token runs at a time (I6); `Drop` cancels it.
pub struct Session<K: Kind> {
    inst: Arc<Instance<K>>,
    tok: Token,
    _ns: PhantomData<Cell<()>>,
}

impl<K: Kind> Session<K> {
    pub fn token(&self) -> Token {
        self.tok
    }
    pub fn call0(
        &mut self,
        sel: impl for<'v> FnOnce(&'v K::Vt) -> &'v VtEntry<OnSession<EntryFn1<u64>>>,
        lease: &mut OutLease,
    ) -> Status {
        match sel(self.inst.vt).get() {
            Some(OnSession(f)) => invoke1(&self.inst, f, Arg::u64(self.tok), lease.arm()),
            None => Status::FAULT,
        }
    }
    pub fn call1<A1: RawArg>(
        &mut self,
        sel: impl for<'v> FnOnce(&'v K::Vt) -> &'v VtEntry<OnSession<EntryFn2<u64, A1>>>,
        a1: Arg<'_, A1>,
        lease: &mut OutLease,
    ) -> Status {
        match sel(self.inst.vt).get() {
            Some(OnSession(f)) => invoke2(&self.inst, f, Arg::u64(self.tok), a1, lease.arm()),
            None => Status::FAULT,
        }
    }
    pub fn call2<A1: RawArg, A2: RawArg>(
        &mut self,
        sel: impl for<'v> FnOnce(&'v K::Vt) -> &'v VtEntry<OnSession<EntryFn3<u64, A1, A2>>>,
        a: (Arg<'_, A1>, Arg<'_, A2>),
        lease: &mut OutLease,
    ) -> Status {
        match sel(self.inst.vt).get() {
            Some(OnSession(f)) => {
                invoke3(&self.inst, f, (Arg::u64(self.tok), a.0, a.1), lease.arm())
            }
            None => Status::FAULT,
        }
    }
    pub fn call3<A1: RawArg, A2: RawArg, A3: RawArg>(
        &mut self,
        sel: impl for<'v> FnOnce(&'v K::Vt) -> &'v VtEntry<OnSession<EntryFn4<u64, A1, A2, A3>>>,
        a: (Arg<'_, A1>, Arg<'_, A2>, Arg<'_, A3>),
        lease: &mut OutLease,
    ) -> Status {
        match sel(self.inst.vt).get() {
            Some(OnSession(f)) => invoke4(
                &self.inst,
                f,
                (Arg::u64(self.tok), a.0, a.1, a.2),
                lease.arm(),
            ),
            None => Status::FAULT,
        }
    }
    #[allow(clippy::type_complexity)]
    pub fn call4<A1: RawArg, A2: RawArg, A3: RawArg, A4: RawArg>(
        &mut self,
        sel: impl for<'v> FnOnce(&'v K::Vt) -> &'v VtEntry<OnSession<EntryFn5<u64, A1, A2, A3, A4>>>,
        a: (Arg<'_, A1>, Arg<'_, A2>, Arg<'_, A3>, Arg<'_, A4>),
        lease: &mut OutLease,
    ) -> Status {
        match sel(self.inst.vt).get() {
            Some(OnSession(f)) => invoke5(
                &self.inst,
                f,
                (Arg::u64(self.tok), a.0, a.1, a.2, a.3),
                lease.arm(),
            ),
            None => Status::FAULT,
        }
    }
    /// The consuming method (`plane::end`): the plugin removes the session whatever it answers.
    pub fn end(
        mut self,
        sel: impl for<'v> FnOnce(&'v K::Vt) -> &'v VtEntry<Ends<EntryFn1<u64>>>,
        lease: &mut OutLease,
    ) -> Status {
        let status = match sel(self.inst.vt).get() {
            Some(Ends(f)) => invoke1(&self.inst, f, Arg::u64(self.tok), lease.arm()),
            None => return Status::FAULT,
        };
        self.tok = 0;
        status
    }
}

impl<K: Kind> Drop for Session<K> {
    fn drop(&mut self) {
        if self.tok != 0 {
            let _ = cancel_raw(self.inst.image.header(), self.inst.ptr(), self.tok);
        }
    }
}

// ---- chains ----

/// Every argument and result buffer of one chain, kept until its token retires (the plugin's
/// `ChainBytes` point into them). Buffers are only appended, never touched again.
#[derive(Default)]
pub struct ChainBufs(Vec<Vec<u8>>);

impl Drop for ChainBufs {
    /// I11: an argument buffer can hold a credential (the host copies its request in), so each is zeroed before
    /// it is freed, the way the pooled buffers are.
    fn drop(&mut self) {
        for buf in &mut self.0 {
            buf.fill(0);
            core::hint::black_box(&*buf);
        }
    }
}

impl ChainBufs {
    pub fn new() -> Self {
        ChainBufs(Vec::new())
    }
    /// Keep `buf` for the chain; returns its index for `get`.
    pub fn push(&mut self, buf: Vec<u8>) -> usize {
        self.0.push(buf);
        self.0.len() - 1
    }
    /// Buffer `index` (empty if there is none).
    pub fn get(&self, index: usize) -> Bytes<'_> {
        Bytes::new(self.0.get(index).map_or(&[][..], Vec::as_slice))
    }
}

enum Owner<'i, K: Kind> {
    Instance(&'i Instance<K>),
    Image {
        image: Admitted,
        host: &'static Host,
    },
}

/// A parked chain (IF §10.5 `ChainGuard`): resumed only here (`&mut self`, I6); `Drop` cancels it unless
/// it retired. An `open` chain is owned by the image (`inst` null) and yields the instance.
pub struct Chain<'i, K: Kind> {
    owner: Owner<'i, K>,
    tok: Token,
    bufs: ChainBufs,
}

/// What an async start came to.
pub enum Started<'i, K: Kind> {
    Done(Status),
    Need(Chain<'i, K>),
}

/// What a resume came to: NEED again, or the final status (and, for an `open` chain answering OK, the
/// instance its INSTANCE record names).
pub enum Resumed<K: Kind> {
    Need,
    Done(Status, Option<Instance<K>>),
}

/// What `Admitted::open` came to.
pub enum OpenAnswer<K: Kind> {
    Done(Status, Option<Instance<K>>),
    Chain(Chain<'static, K>),
}

impl<K: Kind> Chain<'_, K> {
    fn parts(&self) -> (&'static Plugin, *const c_void, &'static Host) {
        match &self.owner {
            Owner::Instance(i) => (i.image.header(), i.ptr(), i.host),
            Owner::Image { image, host } => (image.header(), core::ptr::null(), *host),
        }
    }

    /// Resume with `results` (the answers to its NEEDs), which the chain keeps.
    pub fn resume(&mut self, results: Vec<u8>, lease: &mut OutLease) -> Resumed<K> {
        let (header, inst, host) = self.parts();
        let Some(resume) = header.entries().2 else {
            self.tok = 0;
            return Resumed::Done(Status::FAULT, None);
        };
        if self.tok == 0 {
            return Resumed::Done(Status::FAULT, None);
        }
        let at = self.bufs.push(results);
        let results = self.bufs.get(at);
        // SAFETY: `resume` is the image's own header entry; `inst` is null for an image-owned `open` chain
        // or the live instance this chain borrows; the token is this chain's, resumed only here under
        // `&mut self` (I6); `results` stays in `bufs` until the token retires.
        let status = unsafe {
            resume(
                inst,
                host,
                Arg::u64(self.tok),
                Arg::bytes(results),
                lease.arm(),
            )
        };
        if status == Status::NEED {
            return Resumed::Need;
        }
        self.tok = 0;
        let instance = match &self.owner {
            Owner::Image { image, host } if status == Status::OK => {
                lease.with_answer(|answer| Instance::from_answer(*image, host, answer))
            }
            _ => None,
        };
        Resumed::Done(status, instance)
    }

    pub fn token(&self) -> Token {
        self.tok
    }
}

impl<K: Kind> Drop for Chain<'_, K> {
    fn drop(&mut self) {
        if self.tok != 0 {
            let (header, inst, _) = self.parts();
            let _ = cancel_raw(header, inst, self.tok);
        }
    }
}

impl Admitted {
    /// Cold: the image's describe items.
    pub fn describe(&self, host: &'static Host, lease: &mut OutLease) -> Status {
        match self.header().entries().0 {
            Some(describe) => describe(host, lease.arm()),
            None => Status::FAULT,
        }
    }

    /// Open an instance of kind `K` with `config` (kept for the open chain) and `flags`.
    pub fn open<K: Kind>(
        &self,
        host: &'static Host,
        config: Vec<u8>,
        flags: u32,
        lease: &mut OutLease,
    ) -> OpenAnswer<K> {
        let Some(open) = self.header().entries().1 else {
            return OpenAnswer::Done(Status::FAULT, None);
        };
        let mut bufs = ChainBufs::new();
        let at = bufs.push(config);
        let status = open(host, Arg::bytes(bufs.get(at)), flags, lease.arm());
        if status == Status::NEED {
            return match lease.with_answer(chain_token) {
                Some(tok) => OpenAnswer::Chain(Chain {
                    owner: Owner::Image { image: *self, host },
                    tok,
                    bufs,
                }),
                None => OpenAnswer::Done(Status::FAULT, None),
            };
        }
        let instance = if status == Status::OK {
            lease.with_answer(|answer| Instance::from_answer(*self, host, answer))
        } else {
            None
        };
        OpenAnswer::Done(status, instance)
    }
}

/// The slot cases that need the shims (IF §14 C-TOKEN-SPACE's shim arm, C-RMW's slot share): one fixture
/// image type serving a plane and a transport table, driven through this module's safe API. A test forges
/// a token of the other space by building a `Session` or `Chain` over it, which only this module can.
#[cfg(all(test, not(loom)))]
mod tests {
    use super::*;
    use core::task::Poll;

    use crate::header::{LinkedPlugin, STAMP_KIND_AT, STAMP_SIZE, StampBytes, plugin};
    use crate::raw::{ChainBytes, HostFns, KindCode, Out, Slice, Str};
    use crate::shim::{
        Call1, Call2, Call3, ChainFut, End0, Image, InstOf, Opener1, Opener2, Opening, Session0,
        Session1, Session2, Session3, Session4, Start2, Step,
    };
    use crate::slots::{ChainBox, ChainRef, Slots, counting, unpack};
    use crate::vt::views::{ConnInfo, PlaneReq, Target};
    use crate::vt::{Built, ConnRef, PlaneRef, TargetRef, kind, plane, transport};

    type B = Bytes<'static>;
    type St = Str<'static>;

    std::thread_local! {
        static SESSION_DROPS: Cell<u32> = const { Cell::new(0) };
        static CHAIN_DROPS: Cell<u32> = const { Cell::new(0) };
    }

    // `pub`, as header.rs's fixture: the image type is only ever a type parameter.
    pub struct Fx;

    /// A session's state; its drop is counted.
    struct Sess;
    impl Drop for Sess {
        fn drop(&mut self) {
            SESSION_DROPS.set(SESSION_DROPS.get() + 1);
        }
    }

    /// Held by a chain future; its drop is the chain's, counted.
    struct Held;
    impl Drop for Held {
        fn drop(&mut self) {
            CHAIN_DROPS.set(CHAIN_DROPS.get() + 1);
        }
    }

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

    /// One record (IF §3): the head, then an 8-byte body.
    fn record(out: &mut Out<'_>, tag: u16, body: u64) -> bool {
        let mut rec = [0u8; 16];
        rec[..2].copy_from_slice(&tag.to_ne_bytes());
        rec[4..8].copy_from_slice(&8u32.to_ne_bytes());
        rec[8..].copy_from_slice(&body.to_le_bytes());
        out.append(&rec)
    }

    impl Image for Fx {
        type Plugin = ();
        type Session = Sess;
        type Reply = ();
        type Inbox = ();
        fn global() -> &'static Slots<ChainBox<(), ()>> {
            &GLOBAL
        }
        fn describe(_h: &'static Host, _out: &mut Out<'_>) -> Status {
            Status::OK
        }
        fn open(
            _h: &'static Host,
            _config: Bytes<'_>,
            _chained: ChainBytes,
            _flags: u32,
            out: &mut Out<'_>,
        ) -> Opening<(), ()> {
            let inst = Box::new(InstOf::<Fx>::new(())).into_instance();
            Opening::Done(if record(out, TAG_INSTANCE, inst) {
                Status::OK
            } else {
                Status::FAULT
            })
        }
        fn poll(
            mut chain: ChainRef<'_, (), ()>,
            _results: Option<ChainBytes>,
            _out: &mut Out<'_>,
        ) -> Step {
            match chain.poll() {
                Poll::Ready(()) => Step::Ready(Status::OK),
                Poll::Pending => Step::Need,
            }
        }
        fn parked(token: Token, out: &mut Out<'_>) -> Status {
            if record(out, TAG_TOKEN, token) {
                Status::NEED
            } else {
                Status::FAULT
            }
        }
        fn opened(token: Token, out: &mut Out<'_>) -> Status {
            if record(out, TAG_TOKEN, token) {
                Status::OK
            } else {
                Status::FAULT
            }
        }
    }

    // ---- the plane table ----

    impl Opener2<PlaneRef, B, 0> for Fx {
        fn begin(
            _p: &(),
            _h: &'static Host,
            _a1: Arg<'_, PlaneRef>,
            _a2: Arg<'_, B>,
            _out: &mut Out<'_>,
        ) -> Result<Sess, Status> {
            Ok(Sess)
        }
    }
    impl Session1<TargetRef, 1> for Fx {
        fn on(
            _p: &(),
            _h: &'static Host,
            _s: &mut Sess,
            _a1: Arg<'_, TargetRef>,
            _out: &mut Out<'_>,
        ) -> Status {
            Status::OK
        }
    }
    impl Session4<u32, u32, u32, B, 2> for Fx {
        fn on(
            _p: &(),
            _h: &'static Host,
            _s: &mut Sess,
            _a1: Arg<'_, u32>,
            _a2: Arg<'_, u32>,
            _a3: Arg<'_, u32>,
            _a4: Arg<'_, B>,
            _out: &mut Out<'_>,
        ) -> Status {
            Status::OK
        }
    }
    impl End0<3> for Fx {
        fn end(_p: &(), _h: &'static Host, _s: Sess, _out: &mut Out<'_>) -> Status {
            Status::OK
        }
    }
    impl Session1<B, 4> for Fx {
        fn on(
            _p: &(),
            _h: &'static Host,
            _s: &mut Sess,
            _a1: Arg<'_, B>,
            _out: &mut Out<'_>,
        ) -> Status {
            Status::OK
        }
    }
    impl Call3<PlaneRef, u32, B, 5> for Fx {
        fn call(
            _p: &(),
            _h: &'static Host,
            _a1: Arg<'_, PlaneRef>,
            _a2: Arg<'_, u32>,
            _a3: Arg<'_, B>,
            _out: &mut Out<'_>,
        ) -> Status {
            Status::OK
        }
    }
    /// `admin`: a chain that NEEDs `needs` times (0: first-poll Ready), then answers OK.
    impl Start2<u32, B, 6> for Fx {
        fn start<'i>(
            _p: &'i (),
            _h: &'static Host,
            needs: u32,
            _body: ChainBytes,
        ) -> (ChainFut<'i, ()>, ()) {
            let held = Held;
            let mut left = needs;
            let fut = core::future::poll_fn(move |_| {
                let _held = &held;
                if left == 0 {
                    return Poll::Ready(());
                }
                left -= 1;
                Poll::Pending
            });
            (Box::pin(fut), ())
        }
    }
    impl Opener1<TargetRef, 7> for Fx {
        fn begin(
            _p: &(),
            _h: &'static Host,
            _a1: Arg<'_, TargetRef>,
            _out: &mut Out<'_>,
        ) -> Result<Sess, Status> {
            Ok(Sess)
        }
    }
    impl Call2<St, B, 8> for Fx {
        fn call(
            _p: &(),
            _h: &'static Host,
            _a1: Arg<'_, St>,
            _a2: Arg<'_, B>,
            _out: &mut Out<'_>,
        ) -> Status {
            Status::OK
        }
    }

    // ---- the transport table ----

    impl Opener1<ConnRef, 0> for Fx {
        fn begin(
            _p: &(),
            _h: &'static Host,
            _a1: Arg<'_, ConnRef>,
            _out: &mut Out<'_>,
        ) -> Result<Sess, Status> {
            Ok(Sess)
        }
    }
    impl Session1<B, 1> for Fx {
        fn on(
            _p: &(),
            _h: &'static Host,
            _s: &mut Sess,
            _a1: Arg<'_, B>,
            _out: &mut Out<'_>,
        ) -> Status {
            Status::OK
        }
    }
    impl Session4<u64, u32, u32, B, 2> for Fx {
        fn on(
            _p: &(),
            _h: &'static Host,
            _s: &mut Sess,
            _a1: Arg<'_, u64>,
            _a2: Arg<'_, u32>,
            _a3: Arg<'_, u32>,
            _a4: Arg<'_, B>,
            _out: &mut Out<'_>,
        ) -> Status {
            Status::OK
        }
    }
    impl Session0<3> for Fx {
        fn on(_p: &(), _h: &'static Host, _s: &mut Sess, _out: &mut Out<'_>) -> Status {
            Status::OK
        }
    }
    impl Session3<u32, u32, B, 4> for Fx {
        fn on(
            _p: &(),
            _h: &'static Host,
            _s: &mut Sess,
            _a1: Arg<'_, u32>,
            _a2: Arg<'_, u32>,
            _a3: Arg<'_, B>,
            _out: &mut Out<'_>,
        ) -> Status {
            Status::OK
        }
    }
    impl Session2<u32, B, 5> for Fx {
        fn on(
            _p: &(),
            _h: &'static Host,
            _s: &mut Sess,
            _a1: Arg<'_, u32>,
            _a2: Arg<'_, B>,
            _out: &mut Out<'_>,
        ) -> Status {
            Status::OK
        }
    }
    impl Call1<u32, 6> for Fx {
        fn call(_p: &(), _h: &'static Host, _a1: Arg<'_, u32>, _out: &mut Out<'_>) -> Status {
            Status::OK
        }
    }

    const fn stamp(code: KindCode) -> StampBytes {
        let mut bytes = [0u8; STAMP_SIZE];
        bytes[STAMP_KIND_AT] = code as u8;
        StampBytes(bytes)
    }
    static PLANE_VT: Built<Fx, plane::Vt> = plane::Vt::build::<Fx>();
    static PLANE_STAMP: StampBytes = stamp(KindCode::Plane);
    static PLANE: LinkedPlugin = plugin::<Fx, kind::Plane>(&PLANE_VT, &PLANE_STAMP, Str::EMPTY);
    static TRANSPORT_VT: Built<Fx, transport::Vt> = transport::Vt::build::<Fx>();
    static TRANSPORT_STAMP: StampBytes = stamp(KindCode::Transport);
    static TRANSPORT: LinkedPlugin =
        plugin::<Fx, kind::Transport>(&TRANSPORT_VT, &TRANSPORT_STAMP, Str::EMPTY);

    const TARGET: Target<'static> = Target {
        attempt: 0,
        flags: 0,
        dialect: Str::EMPTY,
        model: Str::EMPTY,
        base_path: Str::EMPTY,
        upstream: Str::EMPTY,
        provider: Str::EMPTY,
        params: Slice::EMPTY,
    };
    const REQUEST: PlaneReq<'static> = PlaneReq {
        route: 0,
        flags: 0,
        auth: 0,
        _r: 0,
        method: Str::EMPTY,
        path: Str::EMPTY,
        query: Str::EMPTY,
        headers: Slice::EMPTY,
        identity: Bytes::EMPTY,
        request_id: 0,
        carrier: 0,
        work: Str::EMPTY,
        ticket_record: Bytes::EMPTY,
    };
    const CONN: ConnInfo<'static> = ConnInfo {
        role: 0,
        flags: 0,
        alpn: Str::EMPTY,
        sni: Str::EMPTY,
        peer: Str::EMPTY,
        local: Str::EMPTY,
        tls_peer_cert: Bytes::EMPTY,
        leftover: Bytes::EMPTY,
        head: Bytes::EMPTY,
        local_fingerprint: Str::EMPTY,
        mono_ns: 0,
    };

    /// A fresh out lease (one per entry, so an opener's TOKEN is the answer's first record).
    fn lease() -> OutLease {
        let Some(lease) = OutLease::new(vec![0; 256], 4096) else {
            panic!("the ACTIVE stack is full");
        };
        lease
    }

    fn open_fixture<K: Kind>(image: &'static LinkedPlugin) -> Arc<Instance<K>> {
        let Ok(admitted) = Admitted::linked(image) else {
            panic!("the fixture header is complete");
        };
        match admitted.open::<K>(&HOST, Vec::new(), 0, &mut lease()) {
            OpenAnswer::Done(Status::OK, Some(instance)) => Arc::new(instance),
            _ => panic!("the fixture opens with an INSTANCE record"),
        }
    }

    fn session_of<K: Kind>((status, session): (Status, Option<Session<K>>)) -> Session<K> {
        assert_eq!(status, Status::OK);
        let Some(session) = session else {
            panic!("the opener answers a session");
        };
        session
    }

    fn open_probe(inst: &Arc<Instance<kind::Plane>>) -> Session<kind::Plane> {
        session_of(inst.open_session1(|vt| &vt.probe, Arg::view(&TARGET), &mut lease()))
    }

    fn open_request(inst: &Arc<Instance<kind::Plane>>) -> Session<kind::Plane> {
        session_of(inst.open_session2(
            |vt| &vt.request,
            Arg::view(&REQUEST),
            Arg::bytes(Bytes::EMPTY),
            &mut lease(),
        ))
    }

    fn open_begin(inst: &Arc<Instance<kind::Transport>>) -> Session<kind::Transport> {
        session_of(inst.open_session1(|vt| &vt.begin, Arg::view(&CONN), &mut lease()))
    }

    fn piece(session: &mut Session<kind::Plane>) -> Status {
        session.call4(
            |vt| &vt.piece,
            (
                Arg::u32(0),
                Arg::u32(0),
                Arg::u32(0),
                Arg::bytes(Bytes::EMPTY),
            ),
            &mut lease(),
        )
    }

    fn admin(inst: &Instance<kind::Plane>, needs: u32) -> Started<'_, kind::Plane> {
        inst.start2(
            |vt| &vt.admin,
            ChainBufs::new(),
            move |_| (Arg::u32(needs), Arg::bytes(Bytes::EMPTY)),
            &mut lease(),
        )
    }

    fn resume(chain: &mut Chain<'_, kind::Plane>) -> Resumed<kind::Plane> {
        chain.resume(Vec::new(), &mut lease())
    }

    /// C-TOKEN-SPACE, the shim arm (IF §14; §2, §6.4 steps 4 and 5): with a live session and a live chain
    /// at the same index of one instance (their tokens differ in bit 63 only), a session token passed to
    /// `resume`, and a chain token passed to a session method or to `end`, are FAULT and touch nothing; a
    /// chain token passed to `cancel` with a live session at the same index drops at most the chain it
    /// names, and is a no-op once stale; a session-space token at a live chain's slot is a no-op. Nothing
    /// ever cross-drops.
    #[test]
    fn a_token_of_the_other_space_never_cross_drops() {
        let inst = open_fixture::<kind::Plane>(&PLANE);
        let sessions = SESSION_DROPS.get();
        let chains = CHAIN_DROPS.get();
        let mut session = open_probe(&inst);
        let Started::Need(mut chain) = admin(&inst, 2) else {
            panic!("a chain that NEEDs is parked");
        };
        let (_, index, _) = unpack(session.token());
        assert_eq!(
            unpack(chain.token()).1,
            index,
            "the same index in both tables"
        );
        assert_eq!(
            session.token() & !TOKEN_SESSION,
            chain.token(),
            "the two tokens differ in bit 63 only"
        );

        // A session token passed to `resume`: FAULT, and the chain at that index is not polled.
        let mut forged = Chain {
            owner: Owner::Instance(&*inst),
            tok: session.token(),
            bufs: ChainBufs::new(),
        };
        assert!(matches!(
            resume(&mut forged),
            Resumed::Done(Status::FAULT, None)
        ));
        drop(forged);

        // A chain token passed to a session method, and to the consuming `end`: FAULT.
        let mut forged = Session::<kind::Plane> {
            inst: Arc::clone(&inst),
            tok: chain.token(),
            _ns: PhantomData,
        };
        assert_eq!(piece(&mut forged), Status::FAULT);
        assert_eq!(forged.end(|vt| &vt.end, &mut lease()), Status::FAULT);
        assert_eq!(
            (SESSION_DROPS.get(), CHAIN_DROPS.get()),
            (sessions, chains),
            "nothing dropped"
        );

        // Both are intact: the session answers, and the chain still has its second NEED to make.
        assert_eq!(piece(&mut session), Status::OK);
        assert!(
            matches!(resume(&mut chain), Resumed::Need),
            "the forged resume never polled the chain"
        );

        // A chain token passed to `cancel` with a live session at the same index: its own chain only.
        let header = inst.image.header();
        assert_eq!(cancel_raw(header, inst.ptr(), chain.token()), Status::OK);
        assert_eq!(CHAIN_DROPS.get(), chains + 1, "the chain the token names");
        assert_eq!(
            SESSION_DROPS.get(),
            sessions,
            "never the session at that index"
        );
        assert_eq!(
            cancel_raw(header, inst.ptr(), chain.token()),
            Status::OK,
            "stale now: a no-op"
        );
        drop(chain);
        assert_eq!(
            (SESSION_DROPS.get(), CHAIN_DROPS.get()),
            (sessions, chains + 1)
        );
        assert_eq!(piece(&mut session), Status::OK, "the session still answers");

        // A session-space token at a live chain's slot (its index and generation): a no-op.
        let Started::Need(mut next) = admin(&inst, 1) else {
            panic!("a chain that NEEDs is parked");
        };
        assert_eq!(
            unpack(next.token()).1,
            index,
            "the chain table hands the slot back"
        );
        assert_eq!(
            cancel_raw(header, inst.ptr(), next.token() | TOKEN_SESSION),
            Status::OK
        );
        assert_eq!(
            (SESSION_DROPS.get(), CHAIN_DROPS.get()),
            (sessions, chains + 1)
        );
        assert!(matches!(resume(&mut next), Resumed::Done(Status::OK, None)));
        assert_eq!(CHAIN_DROPS.get(), chains + 2);
        assert_eq!(piece(&mut session), Status::OK);
        drop(session);
        assert_eq!(
            SESSION_DROPS.get(),
            sessions + 1,
            "its own cancel drops it, once"
        );
    }

    /// C-RMW's slot share (IF §14 round 8; §0 I5, §6.5), on the counting configuration of `slots.rs`: a
    /// plane `piece` and a transport `ingest`, `emit` and `timer` make no slot-table RMW (the session
    /// lookup is one Acquire load and a compare); a session opener (`request`, `probe`, `begin`) makes one
    /// CAS on the session table's free list and its end (`end`, or the handle's drop) one; the handle holds
    /// the instance's `Arc` (strong count +1 from open to end). Steady state: the free list holds a slot.
    #[test]
    fn session_methods_make_no_slot_rmw_and_open_and_end_one_cas_each() {
        let plane = open_fixture::<kind::Plane>(&PLANE);
        drop(open_probe(&plane));
        let strong = Arc::strong_count(&plane);
        for request in [true, false] {
            let rmw = counting::rmw();
            let mut session = if request {
                open_request(&plane)
            } else {
                open_probe(&plane)
            };
            assert_eq!(counting::rmw() - rmw, 1, "one free-list CAS per opener");
            assert_eq!(Arc::strong_count(&plane), strong + 1);
            let rmw = counting::rmw();
            for _ in 0..3 {
                assert_eq!(piece(&mut session), Status::OK);
            }
            assert_eq!(counting::rmw(), rmw, "no RMW per piece");
            assert_eq!(session.end(|vt| &vt.end, &mut lease()), Status::OK);
            assert_eq!(counting::rmw() - rmw, 1, "one free-list CAS per end");
            assert_eq!(Arc::strong_count(&plane), strong);
        }

        let transport = open_fixture::<kind::Transport>(&TRANSPORT);
        drop(open_begin(&transport));
        let strong = Arc::strong_count(&transport);
        let rmw = counting::rmw();
        let mut session = open_begin(&transport);
        assert_eq!(counting::rmw() - rmw, 1, "one free-list CAS per opener");
        assert_eq!(Arc::strong_count(&transport), strong + 1);
        let rmw = counting::rmw();
        for _ in 0..3 {
            let ingest = session.call1(|vt| &vt.ingest, Arg::bytes(Bytes::EMPTY), &mut lease());
            assert_eq!(ingest, Status::OK);
            let emit = session.call4(
                |vt| &vt.emit,
                (
                    Arg::u64(0),
                    Arg::u32(0),
                    Arg::u32(0),
                    Arg::bytes(Bytes::EMPTY),
                ),
                &mut lease(),
            );
            assert_eq!(emit, Status::OK);
            assert_eq!(session.call0(|vt| &vt.timer, &mut lease()), Status::OK);
        }
        assert_eq!(counting::rmw(), rmw, "no RMW per ingest, emit or timer");
        drop(session);
        assert_eq!(
            counting::rmw() - rmw,
            1,
            "one free-list CAS when the handle ends it"
        );
        assert_eq!(Arc::strong_count(&transport), strong);
    }

    /// C-RMW, round 10 (IF §14; §6.4 steps 1 to 3), on the counting configuration: a never-NEED chain
    /// makes no chain-slot RMW (the shim polls before it inserts); a chain that NEEDs makes exactly one
    /// insert CAS (its first NEED) and one remove CAS (its end, or its cancel), however many NEEDs it
    /// makes, because each resume's lookup makes none. Steady state: the free list holds a slot.
    #[test]
    fn a_chain_makes_one_slot_cas_on_its_first_need_and_one_at_its_end() {
        let inst = open_fixture::<kind::Plane>(&PLANE);
        let Started::Need(mut warm) = admin(&inst, 1) else {
            panic!("a chain that NEEDs is parked");
        };
        assert!(matches!(resume(&mut warm), Resumed::Done(Status::OK, None)));
        drop(warm);

        let rmw = counting::rmw();
        assert!(matches!(admin(&inst, 0), Started::Done(Status::OK)));
        assert_eq!(counting::rmw(), rmw, "no slot RMW for a never-NEED chain");

        for needs in [1, 4] {
            let rmw = counting::rmw();
            let Started::Need(mut chain) = admin(&inst, needs) else {
                panic!("a chain that NEEDs is parked");
            };
            assert_eq!(
                counting::rmw() - rmw,
                1,
                "one insert CAS, on the first NEED"
            );
            for _ in 1..needs {
                assert!(matches!(resume(&mut chain), Resumed::Need));
            }
            assert_eq!(counting::rmw() - rmw, 1, "no RMW per resume lookup");
            assert!(matches!(
                resume(&mut chain),
                Resumed::Done(Status::OK, None)
            ));
            assert_eq!(counting::rmw() - rmw, 2, "one remove CAS at its end");
        }

        let rmw = counting::rmw();
        let Started::Need(mut chain) = admin(&inst, 3) else {
            panic!("a chain that NEEDs is parked");
        };
        assert!(matches!(resume(&mut chain), Resumed::Need));
        drop(chain);
        assert_eq!(
            counting::rmw() - rmw,
            2,
            "one insert CAS and one remove CAS at its cancel"
        );
    }
}
