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
//! - Every kind method crosses through the one `invoke(inst, slot, &Call, out)` (core 3.0). A live token
//!   reaches a call only through its `Session` (`&mut`, I6) or its `Chain`: a session method called
//!   plainly carries token 0 and the shim answers FAULT.
//!
//! `unsafe` here: the one `invoke` call block, the `describe`, `open`, `resume`, `cancel` and `close`
//! calls, and `Arena::lend`'s append.

#![allow(unsafe_code)]

use core::cell::{Cell, RefCell};
use core::ffi::c_void;
use core::marker::PhantomData;
use std::sync::Arc;

use zerocopy::{FromBytes, Immutable, KnownLayout};

use crate::header::Plugin;
use crate::image::Admitted;
use crate::raw::{Bytes, Ctx, Host, RawLent, RawOut, Status, TOKEN_SESSION, Token};
use crate::vt::{Call, Kind};

// Bounded fixed output loans (bd913873ef). Inline: busbar-ffi holds only the files its register pins.
#[cfg(all(test, not(loom)))]
mod fixed_loan_tests {
    use super::*;
    use crate::raw::{HostFns, Out};

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
            service: None,
        },
    );

    #[test]
    fn fixed_output_writes_the_lent_backing_without_growth_or_copy() {
        let mut backing = [0xa5; 24];
        let original = backing.as_ptr();
        let written = OutLease::with_fixed(&mut backing, |lease| {
            assert_eq!(lease.raw.cap(), 24);
            assert!(grow(lease.arm(), 24));
            assert!(!grow(lease.arm(), 25));
            assert!(!grow(lease.arm(), usize::MAX));
            assert!(Out::new(lease.arm(), &HOST).append(b"protected reply"));
            lease.with_answer(|bytes| {
                assert_eq!(bytes.as_ptr(), original);
                assert_eq!(bytes, b"protected reply");
            });
            assert!(!grow(lease.arm(), 24));
            assert_eq!(lease.raw.cap(), 24);
            lease.len()
        })
        .expect("a fixed entry");
        assert_eq!(&backing[..written], b"protected reply");
        assert!(backing[written..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn nested_fixed_output_cannot_grow_the_outer_entry() {
        let mut outer = [0; 16];
        let mut inner = [0; 16];
        OutLease::with_fixed(&mut outer, |a| {
            assert!(grow(a.arm(), 16));
            OutLease::with_fixed(&mut inner, |b| {
                assert!(!grow(a.arm(), 1));
                assert!(grow(b.arm(), 16));
                assert!(Out::new(b.arm(), &HOST).append(b"inner"));
            })
            .expect("nested entry");
            assert!(grow(a.arm(), 16));
            assert!(Out::new(a.arm(), &HOST).append(b"outer"));
        })
        .expect("outer entry");
        assert_eq!(&outer[..5], b"outer");
        assert_eq!(&inner[..5], b"inner");
    }

    #[test]
    fn fixed_output_unregisters_on_unwind_and_after_forgotten_replacement() {
        let before = ACTIVE.with_borrow(|stack| stack.len());
        let mut backing = [0; 16];
        let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            OutLease::with_fixed(&mut backing, |lease| {
                assert!(Out::new(lease.arm(), &HOST).append(b"partial"));
                panic!("plugin callback unwound");
            });
        }));
        assert!(unwind.is_err());
        assert_eq!(ACTIVE.with_borrow(|stack| stack.len()), before);
        OutLease::with_fixed(&mut backing, |lease| {
            let replacement = OutLease::new(Vec::new(), 0).expect("owned replacement");
            let forgotten = core::mem::replace(lease, replacement);
            core::mem::forget(forgotten);
        })
        .expect("fixed entry");
        assert_eq!(ACTIVE.with_borrow(|stack| stack.len()), before);
    }

    #[test]
    fn fixed_output_has_no_owned_buffer_to_extract() {
        let mut backing = [0; 16];
        OutLease::with_fixed(&mut backing, |lease| {
            let replacement = OutLease::new(Vec::new(), 0).expect("owned replacement");
            let fixed = core::mem::replace(lease, replacement);
            let (owned, written) = fixed.into_buf();
            assert!(owned.is_empty());
            assert_eq!(written, 0);
        })
        .expect("fixed entry");
    }

    #[test]
    fn fixed_output_depth_refuses_without_touching_the_lender() {
        let held: Vec<_> = (0..DEPTH)
            .map(|_| OutLease::new(Vec::new(), 0).expect("within depth"))
            .collect();
        let mut backing = [0xa5; 16];
        assert!(OutLease::with_fixed(&mut backing, |_| panic!("must not enter")).is_none());
        assert_eq!(backing, [0xa5; 16]);
        drop(held);
        assert!(OutLease::with_fixed(&mut backing, |_| ()).is_some());
    }
}

std::thread_local! {
    static TEARDOWN: Cell<bool> = const { Cell::new(false) };
}

/// True while a native cancel or close is executing, including implicit Drop and raw fallbacks.
/// An unavailable thread-local is denied; hosts must never inherit an enclosing open's authority.
pub fn teardown_active() -> bool {
    TEARDOWN.try_with(Cell::get).unwrap_or(true)
}

struct Teardown {
    previous: Option<bool>,
    _thread: PhantomData<std::rc::Rc<()>>,
}

impl Teardown {
    fn enter() -> Self {
        Self {
            previous: TEARDOWN.try_with(|active| active.replace(true)).ok(),
            _thread: PhantomData,
        }
    }
}

impl Drop for Teardown {
    fn drop(&mut self) {
        if let Some(previous) = self.previous {
            let _ = TEARDOWN.try_with(|active| active.set(previous));
        }
    }
}

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
    buf: ActiveBuffer,
}

enum ActiveBuffer {
    Owned(Vec<u8>),
    Fixed,
}

struct ActiveStack {
    entries: [Option<Active>; DEPTH],
    len: usize,
}

impl ActiveStack {
    const fn new() -> Self {
        Self {
            entries: [const { None }; DEPTH],
            len: 0,
        }
    }

    fn len(&self) -> usize {
        self.len
    }

    fn push(&mut self, active: Active) -> bool {
        let Some(entry) = self.entries.get_mut(self.len) else {
            return false;
        };
        *entry = Some(active);
        self.len += 1;
        true
    }

    fn last_mut(&mut self) -> Option<&mut Active> {
        self.entries.get_mut(self.len.checked_sub(1)?)?.as_mut()
    }

    /// Where `serial` sits: the top in every unnested entry, so it is looked at first.
    fn index_of(&self, serial: u64) -> Option<usize> {
        let top = self.len.checked_sub(1)?;
        if self.entries[top]
            .as_ref()
            .is_some_and(|entry| entry.serial == serial)
        {
            return Some(top);
        }
        self.entries[..top]
            .iter()
            .position(|entry| entry.as_ref().is_some_and(|entry| entry.serial == serial))
    }

    fn get(&self, serial: u64) -> Option<&Active> {
        self.entries.get(self.index_of(serial)?)?.as_ref()
    }

    fn remove(&mut self, serial: u64) -> Option<ActiveBuffer> {
        let at = self.index_of(serial)?;
        let removed = self.entries[at].take()?;
        for index in at..self.len - 1 {
            self.entries[index] = self.entries[index + 1].take();
        }
        self.len -= 1;
        Some(removed.buf)
    }
}

std::thread_local! {
    static ACTIVE: RefCell<ActiveStack> = const { RefCell::new(ActiveStack::new()) };
    static NEXT_LEASE: Cell<u64> = const { Cell::new(0) };
}

/// One entry's owned output or fixed borrowed backing. `!Send`: its ACTIVE registration is
/// thread-local. A borrowed lease cannot outlive the slice lent by [`Self::with_fixed`].
pub struct OutLease<'buf> {
    raw: RawOut,
    serial: u64,
    fixed: Option<&'buf mut [u8]>,
    _thread: PhantomData<*mut ()>,
}

impl OutLease<'static> {
    /// Lease `buf` (any content; it is zero-filled) for one entry, growing up to `max_out`. None: the
    /// ACTIVE stack is `DEPTH` deep.
    pub fn new(mut buf: Vec<u8>, max_out: usize) -> Option<Self> {
        buf.fill(0);
        Self::clean(buf, max_out)
    }

    /// Lease `buf` as it is, for a block whose every byte is already zero: one that was allocated zeroed and
    /// wiped, after each entry it was lent to, over every byte that entry wrote (busbar-plugin-abi's pooled
    /// blocks; IF §10.1 and decision 60, O(bytes written)). Zeroing it again here would be the second wipe of
    /// the same bytes on every crossing. None: the ACTIVE stack is `DEPTH` deep.
    ///
    /// Custody, plainly. The host guarantees: every block starts all zero; after each entry it wipes, in one
    /// block, every byte the entry wrote as far as the length the entry stated (and every byte `grow` exposed)
    /// before the block is lent again; it reads only `[0, len)` of an answer; a block grown for a large answer is
    /// wiped and freed, not kept. It relies on the plugin for one thing: writing only within the length it
    /// states. The SDK's `Out` can do nothing else (it appends, and zeroes what it cuts). A native plugin that
    /// writes through the raw pointer past its stated length leaves those bytes for the next entry lent the
    /// block on that thread; such a plugin shares the process's memory anyway, so a wipe of the whole block
    /// would not stop a hostile one (IF decision 60, confirmed 18 Nov 2026; C-LEND-CUSTODY is the gate).
    pub fn clean(mut buf: Vec<u8>, max_out: usize) -> Option<Self> {
        let raw = RawOut::over(&mut buf);
        let serial = NEXT_LEASE.get().checked_add(1)?;
        NEXT_LEASE.set(serial);
        let pushed = ACTIVE.with_borrow_mut(|stack| {
            if stack.len() >= DEPTH {
                return false;
            }
            stack.push(Active {
                serial,
                identity: 0,
                max_out,
                buf: ActiveBuffer::Owned(buf),
            })
        });
        pushed.then_some(OutLease {
            raw,
            serial,
            fixed: None,
            _thread: PhantomData,
        })
    }

    /// Lend already charged, caller-owned backing to one synchronous entry. The ACTIVE stack
    /// stores metadata only: no allocation, copy, growth or pooled retention occurs here. A full
    /// stack refuses before touching `buf`. Output remains in `buf` when the closure returns;
    /// the caller's guarded owner is responsible for wiping/freeing it before retiring its charge.
    ///
    /// The higher-ranked closure cannot return a lease into the lender:
    /// ```compile_fail
    /// use busbar_ffi::host::OutLease;
    /// let mut bytes = [0; 32];
    /// let escaped = OutLease::with_fixed(&mut bytes, |lease| {
    ///     std::mem::replace(lease, OutLease::new(Vec::new(), 0).unwrap())
    /// });
    /// ```
    pub fn with_fixed<R>(
        buf: &mut [u8],
        call: impl for<'loan> FnOnce(&mut OutLease<'loan>) -> R,
    ) -> Option<R> {
        let serial = NEXT_LEASE.get().checked_add(1)?;
        let pushed = ACTIVE.with_borrow_mut(|stack| {
            stack.push(Active {
                serial,
                identity: 0,
                max_out: buf.len(),
                buf: ActiveBuffer::Fixed,
            })
        });
        if !pushed {
            return None;
        }
        NEXT_LEASE.set(serial);
        // This guard also removes the registration if the closure replaces and forgets its
        // lease. The fixed ACTIVE entry contains no pointer into the lender.
        let _registration = FixedRegistration(serial);
        // Core 3.0: the caller's answer block is not pre-filled. The plugin writes `[0, len)` and the
        // host reads only that.
        // The channel points through the reference the lease keeps, taken after `buf` is stored:
        // moving `buf` into the lease retags it, which would invalidate a pointer taken from it
        // before the move (Miri, stacked borrows: the plugin's first append wrote through a dead tag).
        let mut lease = OutLease {
            raw: RawOut::over(&mut []),
            serial,
            fixed: Some(buf),
            _thread: PhantomData,
        };
        if let Some(fixed) = lease.fixed.as_deref_mut() {
            lease.raw.repoint(fixed);
        }
        Some(call(&mut lease))
    }
}

struct FixedRegistration(u64);

impl Drop for FixedRegistration {
    fn drop(&mut self) {
        let _ = take_lease(self.0);
    }
}

impl OutLease<'_> {
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
        if let Some(buf) = &self.fixed {
            return f(buf.get(..len).unwrap_or(&[]));
        }
        ACTIVE.with_borrow(|stack| {
            let answer = stack
                .get(self.serial)
                .and_then(|active| match &active.buf {
                    ActiveBuffer::Owned(buf) => buf.get(..len),
                    ActiveBuffer::Fixed => None,
                })
                .unwrap_or(&[]);
            f(answer)
        })
    }

    /// Give an owned buffer back to the pool (which zeroes it); `[0, len)` is the answer.
    /// A fixed loan never transfers its caller's backing: it returns an empty buffer and zero.
    pub fn into_buf(self) -> (Vec<u8>, usize) {
        let len = self.raw.len();
        let (buf, len) = match take_lease(self.serial) {
            Some(ActiveBuffer::Owned(buf)) => (buf, len),
            Some(ActiveBuffer::Fixed) | None => (Vec::new(), 0),
        };
        core::mem::forget(self);
        (buf, len)
    }
}

fn take_lease(serial: u64) -> Option<ActiveBuffer> {
    ACTIVE
        .try_with(|stack| {
            let mut stack = stack.borrow_mut();
            stack.remove(serial)
        })
        .ok()
        .flatten()
}

impl Drop for OutLease<'_> {
    fn drop(&mut self) {
        if let Some(ActiveBuffer::Owned(mut buf)) = take_lease(self.serial) {
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
        let ActiveBuffer::Owned(buf) = &mut top.buf else {
            // The lender's pointer and capacity stay unchanged for the complete entry.
            return true;
        };
        if want <= buf.len() {
            return true;
        }
        let cap = want.max(buf.len().saturating_mul(2)).min(top.max_out);
        let mut next = vec![0u8; cap];
        if let (Some(dst), Some(src)) = (next.get_mut(..len), buf.get(..len)) {
            dst.copy_from_slice(src);
        }
        buf.fill(0);
        core::hint::black_box(&*buf);
        raw.repoint(&mut next);
        *buf = next;
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
    host: &'static Host,
    image: Admitted,
    _k: PhantomData<fn() -> K>,
}

/// What the crossing recorder is shown: the kind code, the table position (`usize::MAX` for a header
/// entry) and the whole call, before it crosses (interface revision G.1 item 7). Test builds only.
#[cfg(feature = "test-support")]
pub type Recorder = fn(u32, usize, &Call<'_>);

#[cfg(feature = "test-support")]
static RECORDER: std::sync::OnceLock<Recorder> = std::sync::OnceLock::new();

/// Install the one crossing recorder of this process (first caller wins; false: one is installed).
#[cfg(feature = "test-support")]
pub fn set_recorder(recorder: Recorder) -> bool {
    RECORDER.set(recorder).is_ok()
}

#[cfg(feature = "test-support")]
fn record(kind: u32, slot: usize, call: &Call<'_>) {
    if let Some(recorder) = RECORDER.get() {
        recorder(kind, slot, call);
    }
}

/// The one crossing toward a plugin's kind table: entry `slot` of `inst`'s image, with `call`.
fn invoke<K: Kind>(inst: &Instance<K>, slot: usize, call: &Call<'_>, out: &mut RawOut) -> Status {
    let Some(entry) = inst.image.entry(slot) else {
        return Status::FAULT;
    };
    #[cfg(feature = "test-support")]
    record(K::CODE as u32, slot, call);
    // SAFETY: `entry` comes from `inst`'s own image's table, so it is a shim of the image whose INSTANCE
    // `inst` holds; that instance is alive (borrowed here, and `close` runs only in `Instance::drop`);
    // `call` and `out` are borrowed for the call. A live session or chain token reaches a call only
    // through `Session` or `Chain` (`Call::on` is private), each under its own `&mut` (I6); the callers
    // of an async start keep every blob in the chain's `ChainBufs` (`Instance::start` checks it).
    unsafe { entry(inst.ptr(), inst.host, call, out) }
}

/// `cancel(inst, tok)` through the image's header.
fn cancel_raw(header: &Plugin, inst: *const c_void, tok: Token) -> Status {
    let _teardown = Teardown::enter();
    match header.entries().3 {
        // SAFETY: `cancel` is the image's own header entry; `inst` is null (the image's open slab) or the
        // image's live instance; the token belongs to the one `Chain` cancelling itself or the `Session`
        // being dropped, so no other entry for it can run (I6). Unknown or stale tokens are a no-op.
        Some(f) => unsafe { f(inst, tok) },
        None => Status::FAULT,
    }
}

impl<K: Kind> Instance<K> {
    fn ptr(&self) -> *const c_void {
        core::ptr::with_exposed_provenance(self.inst)
    }

    fn from_answer(image: Admitted, host: &'static Host, answer: &[u8]) -> Option<Instance<K>> {
        if !image.is::<K>() {
            return None;
        }
        let (_, body) = records(answer).find(|(tag, _)| *tag == TAG_INSTANCE)?;
        let inst = usize::try_from(u64_of(body)?).ok()?;
        (inst != 0).then_some(Instance {
            inst,
            host,
            image,
            _k: PhantomData,
        })
    }

    /// The image this instance runs in.
    pub fn image(&self) -> Admitted {
        self.image
    }

    /// How many table entries the image has: a method whose slot is at or past this does not exist in
    /// the image (it was built for an earlier second number) and a call on it is FAULT.
    pub fn entries(&self) -> usize {
        self.image.entries()
    }

    /// A plain call of table entry `slot`. A session method called this way answers FAULT (the call
    /// carries no token).
    pub fn call(&self, slot: usize, call: &Call<'_>, lease: &mut OutLease) -> Status {
        invoke(self, slot, call, lease.arm())
    }

    /// A session opener: the session its answer names, if the call was OK with a leading session TOKEN
    /// (OK without one is FAULT `MissingToken`).
    pub fn open_session(
        self: &Arc<Self>,
        slot: usize,
        call: &Call<'_>,
        lease: &mut OutLease,
    ) -> (Status, Option<Session<K>>) {
        let status = invoke(self, slot, call, lease.arm());
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

    /// An async start of table entry `slot`. `pack` builds the call (its blobs from `bufs`, which the
    /// chain then keeps) and hands it to the crossing it is given, once. A blob that does not lie in
    /// `bufs` is refused before the crossing (FAULT): the chain would read it after this call returned.
    pub fn start<'i>(
        &'i self,
        slot: usize,
        bufs: ChainBufs,
        pack: impl FnOnce(&ChainBufs, &mut dyn FnMut(&Call<'_>) -> Status) -> Status,
        lease: &mut OutLease,
    ) -> Started<'i, K> {
        let status = {
            let raw = lease.arm();
            let mut crossed = false;
            pack(&bufs, &mut |call: &Call<'_>| {
                if core::mem::replace(&mut crossed, true)
                    || !call.blobs().iter().all(|blob| bufs.holds(*blob))
                {
                    return Status::FAULT;
                }
                invoke(self, slot, call, &mut *raw)
            })
        };
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
}

impl<K: Kind> Drop for Instance<K> {
    fn drop(&mut self) {
        let _teardown = Teardown::enter();
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
    /// A call of table entry `slot` on this session: the call crosses with this session's token.
    pub fn call(&mut self, slot: usize, call: &Call<'_>, lease: &mut OutLease) -> Status {
        invoke(&self.inst, slot, &call.on(self.tok), lease.arm())
    }
    /// The consuming method: the plugin removes the session whatever it answers.
    pub fn end(mut self, slot: usize, call: &Call<'_>, lease: &mut OutLease) -> Status {
        if self.inst.image.entry(slot).is_none() {
            return Status::FAULT;
        }
        let status = invoke(&self.inst, slot, &call.on(self.tok), lease.arm());
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
/// `ChainBytes` point into them). Buffers are only appended, never touched again. The first buffer
/// (an async entry's one request) is held inline, so a chain that never NEEDs allocates no list; it may be
/// a block the host lends (`lend_block`), whose first `first_len` bytes are the argument and which goes back
/// to the host, zeroed, when the chain is done.
#[derive(Default)]
pub struct ChainBufs {
    first: Option<Vec<u8>>,
    /// The argument's bytes in `first`; the rest of a lent block is the lender's and all zero.
    first_len: usize,
    /// Where a lent `first` goes after it is zeroed; None: it is freed.
    give_back: Option<fn(Vec<u8>)>,
    rest: Vec<Vec<u8>>,
}

impl Drop for ChainBufs {
    /// I11: an argument buffer can hold a credential (the host copies its request in), so each is zeroed before
    /// it is freed or given back, the way the pooled buffers are.
    fn drop(&mut self) {
        self.zero();
        if let (Some(block), Some(give_back)) = (self.first.take(), self.give_back) {
            give_back(block);
        }
    }
}

impl ChainBufs {
    /// Zero every kept argument and result in place, lengths unchanged (I11; IF §6.1). `Drop` runs it before
    /// the buffers are freed or given back; `black_box` keeps the stores from being elided as dead.
    fn zero(&mut self) {
        if let Some(first) = &mut self.first
            && let Some(argument) = first.get_mut(..self.first_len)
        {
            argument.fill(0);
            core::hint::black_box(&*argument);
        }
        for buf in &mut self.rest {
            buf.fill(0);
            core::hint::black_box(&*buf);
        }
    }

    pub fn new() -> Self {
        ChainBufs {
            first: None,
            first_len: 0,
            give_back: None,
            rest: Vec::new(),
        }
    }
    /// Keep `buf` for the chain; returns its index for `get`.
    pub fn push(&mut self, buf: Vec<u8>) -> usize {
        if self.first.is_none() {
            self.first_len = buf.len();
            self.first = Some(buf);
            return 0;
        }
        self.rest.push(buf);
        self.rest.len()
    }
    /// Keep the host's `block` for the chain with its first `len` bytes as the argument (the rest must be all
    /// zero); when the chain is done those bytes are zeroed and the block handed to `give_back`, not freed.
    /// Returns its index for `get`. A chain that already holds a first buffer keeps a copy of the argument
    /// instead, and the block goes back at once.
    pub fn lend_block(&mut self, mut block: Vec<u8>, len: usize, give_back: fn(Vec<u8>)) -> usize {
        let len = len.min(block.len());
        if self.first.is_some() {
            let at = self.push(block.get(..len).unwrap_or_default().to_vec());
            if let Some(argument) = block.get_mut(..len) {
                argument.fill(0);
                core::hint::black_box(&*argument);
            }
            give_back(block);
            return at;
        }
        self.first_len = len;
        self.first = Some(block);
        self.give_back = Some(give_back);
        0
    }
    /// Whether `bytes` lies wholly inside one kept buffer (an empty value always does): what an async
    /// start's blobs must satisfy, because the chain reads them after the start returned.
    pub fn holds(&self, bytes: Bytes<'_>) -> bool {
        let (at, len) = bytes.span();
        if len == 0 {
            return true;
        }
        let Some(end) = at.checked_add(len) else {
            return false;
        };
        let inside = |buf: &[u8]| {
            let start = buf.as_ptr().addr();
            at >= start && end <= start.saturating_add(buf.len())
        };
        self.first
            .as_deref()
            .and_then(|first| first.get(..self.first_len))
            .is_some_and(inside)
            || self.rest.iter().any(|buf| inside(buf))
    }
    /// Buffer `index` (empty if there is none).
    pub fn get(&self, index: usize) -> Bytes<'_> {
        let kept = match index.checked_sub(1) {
            None => self
                .first
                .as_deref()
                .and_then(|first| first.get(..self.first_len)),
            Some(at) => self.rest.get(at).map(Vec::as_slice),
        };
        Bytes::new(kept.unwrap_or_default())
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
        let blobs = [self.bufs.get(at)];
        let call = Call::new(0, &[], &[], &blobs).on(self.tok);
        // SAFETY: `resume` is the image's own header entry; `inst` is null for an image-owned `open` chain
        // or the live instance this chain borrows; the token is this chain's, resumed only here under
        // `&mut self` (I6); blob 0 (the results) stays in `bufs` until the token retires.
        let status = unsafe { resume(inst, host, &call, lease.arm()) };
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

    /// Cancel this parked chain, retaining its owner and borrowed buffers until the entry returns.
    /// The token is retired before entry, so the following Drop cannot cancel it a second time.
    /// Hosts with caller attribution and fault reporting run this inside their cancellation scope.
    pub fn cancel(mut self) -> Status {
        self.cancel_once()
    }

    fn cancel_once(&mut self) -> Status {
        let token = core::mem::replace(&mut self.tok, 0);
        if token == 0 {
            return Status::OK;
        }
        let (header, inst, _) = self.parts();
        cancel_raw(header, inst, token)
    }
}

impl<K: Kind> Drop for Chain<'_, K> {
    fn drop(&mut self) {
        let _ = self.cancel_once();
    }
}

impl Admitted {
    /// Cold: the image's describe items.
    pub fn describe(&self, host: &'static Host, lease: &mut OutLease) -> Status {
        describe_header(self.header(), host, lease)
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
        let head = flags.to_le_bytes();
        let blobs = [bufs.get(at)];
        let call = Call::new(0, &head, &[], &blobs);
        // SAFETY: `open` is the image's own header entry; it takes no instance (null); head = the flags
        // and blob 0 = the config, which stays in `bufs`, kept by the open chain below until its token
        // retires (or dropped after the call when no chain was parked).
        let status = unsafe { open(core::ptr::null(), host, &call, lease.arm()) };
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

/// The describe crossing over a header, admitted or still only opened (DES-443 r3 §3.2): one body for both.
fn describe_header(header: &Plugin, host: &'static Host, lease: &mut OutLease) -> Status {
    match header.entries().0 {
        // SAFETY: `describe` is the image's own header entry (the image is mapped: the header is
        // borrowed from it); it takes no instance (null) and reads no field of the call; the call and the
        // answer block are borrowed for the call.
        Some(describe) => unsafe { describe(core::ptr::null(), host, &Call::EMPTY, lease.arm()) },
        None => Status::FAULT,
    }
}

impl crate::image::Opened {
    /// Cold: an opened image's describe items, borrowed from the opened image (no admission; DES-443 r3). The
    /// caller runs it on a permanent plugin worker and closes the image afterwards.
    pub fn describe(&self, host: &'static Host, lease: &mut OutLease) -> Status {
        describe_header(self.header(), host, lease)
    }
}
