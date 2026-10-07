// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLUGIN SIDE OF THE TRANSPORT LOWERING: a [`Carrier`] or [`Framer`] implementation, lowered to
//! the `#[repr(C)]` slots of [`crate::abi::hot::transport`] — one generic `extern "C-unwind"` slot
//! per trait method, each a one-line bridge onto the method it is named for. A transport crate does
//! not write a slot: [`export_carrier!`](crate::export_carrier) / [`export_framer!`](crate::export_framer)
//! instantiate these for its type and register the image's door, in the one module its
//! `#![deny(unsafe_code)]` allows.
//!
//! What the lowering adds, and nothing else:
//!
//! * every slot catches its own panics and answers [`WireOutcome::Fault`] — a panic never unwinds
//!   out of a dropped-in image;
//! * a carrier's poll slot turns the host's `token` into the [`Waker`] the method is polled with
//!   (one waker per connection and direction, made once per token and reused);
//! * a framer's outputs go straight to the host's callbacks ([`WireFramerOut`], [`WireBytesOut`]).
//!
//! The host's inverse — the loader's decl-backed [`Carrier`] / [`Framer`] — calls these slots, so a
//! dropped-in transport is driven through exactly the methods a linked one is.

use core::mem::MaybeUninit;
use std::collections::HashMap;
use std::os::raw::c_void;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use crate::abi::hot::decl::{DeclStr, OpaqueHandle};
use crate::abi::hot::transport::{
    code, CarrierSlots, DeclByteList, DeclClaim, DeclStrList, FramerSlots, RawWireOutcome,
    TransportDecl, WireBytesOut, WireConnFacts, WireDest, WireField, WireFramed, WireFramerOut,
    WireOutcome, WireSettings, WireWakeFn, WireWaker, FRAMED_HAS_RETRY_AFTER,
    FRAMED_HAS_STATUS_CODE, NO_WAKER, TRANSPORT_DECL_MAJOR,
};
use crate::abi::{AbiPreamble, ABI_MAGIC, ABI_MAJOR, ABI_MINOR};
use crate::grammar::SelectorForm;
use crate::ids::StreamId;
use crate::transport::wire::{CertFacts, TransportError};
use crate::transport::{
    BytesOut, Carrier, Claim, ConnFacts, Dest, Framed, Framer, FramerOut, HostTime, TransportMeta,
    TransportSettings,
};

// ── the built state ──────────────────────────────────────────────────────────────────────────────

/// One built transport behind the decl's opaque state: the implementation, the host's `wake`, and
/// the wakers its parked polls hold, keyed by handle and direction.
pub struct Lowered<T> {
    inner: T,
    wake: Option<WireWakeFn>,
    wakers: Mutex<HashMap<(u64, u8), (u64, Waker)>>,
}

/// The direction a waker is keyed under.
const ACCEPT: u8 = 0;
const READ: u8 = 1;
const WRITE: u8 = 2;
const CLOSE: u8 = 3;

/// The host's `wake(token)`, as a [`Waker`].
struct HostWake {
    wake: WireWakeFn,
    token: u64,
}

impl std::task::Wake for HostWake {
    fn wake(self: Arc<Self>) {
        (self.wake)(self.token);
    }
    fn wake_by_ref(self: &Arc<Self>) {
        (self.wake)(self.token);
    }
}

impl<T> Lowered<T> {
    /// The waker for `token` on `(handle, dir)`: made once per token, reused while the token is.
    fn waker(&self, handle: u64, dir: u8, token: u64) -> Waker {
        let Some(wake) = self.wake.filter(|_| token != NO_WAKER) else {
            return Waker::noop().clone();
        };
        let mut held = self
            .wakers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match held.get(&(handle, dir)) {
            Some((t, w)) if *t == token => w.clone(),
            _ => {
                let w = Waker::from(Arc::new(HostWake { wake, token }));
                held.insert((handle, dir), (token, w.clone()));
                w
            }
        }
    }

    /// Forget every waker `handle` holds.
    fn forget(&self, handle: u64) {
        let mut held = self
            .wakers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // A listener's accept is keyed in its own space: a connection that shares its number is not
        // it.
        for dir in [READ, WRITE, CLOSE] {
            held.remove(&(handle, dir));
        }
    }
}

extern "C-unwind" fn free_lowered<T>(state: *mut c_void) {
    if state.is_null() {
        return;
    }
    let _ = super::boundary::caught(|| {
        // SAFETY: `state` is the `Box<Lowered<T>>` `init` leaked, freed exactly once by the host.
        drop(unsafe { Box::from_raw(state.cast::<Lowered<T>>()) });
    });
}

/// INIT, for [`export_carrier!`](crate::export_carrier) / [`export_framer!`](crate::export_framer):
/// build `T` with `build` from the host's settings and hand the host the state.
///
/// # Safety
/// `settings` and `waker`, when non-null, must address the host's live sized structs; `out_state`
/// the host's writable slot.
pub unsafe fn init<T: Send + Sync + 'static>(
    settings: *const WireSettings,
    waker: *const WireWaker,
    out_state: *mut MaybeUninit<OpaqueHandle>,
    build: fn(&TransportSettings) -> T,
) -> RawWireOutcome {
    guarded(|| {
        if settings.is_null() || waker.is_null() || out_state.is_null() {
            return Err(WireOutcome::Fault);
        }
        // SAFETY: per this fn's contract; each sized struct is read only as far as its own
        // attested size reaches.
        let (settings, wake) = unsafe {
            let size = core::ptr::read_unaligned(core::ptr::addr_of!((*settings).size)) as usize;
            if size < core::mem::size_of::<WireSettings>() {
                return Err(WireOutcome::Fault);
            }
            let s = core::ptr::read_unaligned(settings);
            let wsize = core::ptr::read_unaligned(core::ptr::addr_of!((*waker).size)) as usize;
            let wake = if wsize >= core::mem::size_of::<WireWaker>() {
                core::ptr::read_unaligned(core::ptr::addr_of!((*waker).wake))
            } else {
                None
            };
            (s, wake)
        };
        let state = Box::into_raw(Box::new(Lowered {
            inner: build(&settings.settings()),
            wake,
            wakers: Mutex::new(HashMap::new()),
        }));
        // SAFETY: the host's writable slot, checked non-null above.
        unsafe {
            (*out_state).write(OpaqueHandle {
                ptr: state.cast(),
                free: Some(free_lowered::<T>),
            });
        }
        Ok(())
    })
}

// ── the slot discipline ──────────────────────────────────────────────────────────────────────────

/// Run a slot body, answering the fault byte for a panic instead of unwinding out of the image.
fn guarded(body: impl FnOnce() -> Result<(), WireOutcome>) -> RawWireOutcome {
    match super::boundary::caught(body) {
        Some(Ok(())) => RawWireOutcome::of(WireOutcome::Ok),
        Some(Err(o)) => RawWireOutcome::of(o),
        None => RawWireOutcome::of(WireOutcome::Fault),
    }
}

/// A poll's answer as a slot body's: ready (`Some`), pending, or refused.
fn polled<T>(p: Poll<Result<T, TransportError>>) -> Result<T, WireOutcome> {
    match p {
        Poll::Pending => Err(WireOutcome::Pending),
        Poll::Ready(r) => r.map_err(WireOutcome::of_error),
    }
}

/// The built transport behind `state`.
///
/// # Safety
/// `state` must be a pointer [`init`] produced for `T` and the host has not freed.
unsafe fn lowered<'a, T>(state: *mut c_void) -> Result<&'a Lowered<T>, WireOutcome> {
    // SAFETY: per this fn's contract.
    unsafe { (state as *const Lowered<T>).as_ref() }.ok_or(WireOutcome::Fault)
}

/// A borrowed byte range (NULL only when empty).
///
/// # Safety
/// `ptr`, when non-null, must address `len` readable bytes for the call.
unsafe fn bytes<'a>(ptr: *const u8, len: usize) -> Result<&'a [u8], WireOutcome> {
    if len == 0 {
        return Ok(&[]);
    }
    if ptr.is_null() {
        return Err(WireOutcome::Fault);
    }
    // SAFETY: per this fn's contract.
    Ok(unsafe { std::slice::from_raw_parts(ptr, len) })
}

/// A borrowed UTF-8 range.
///
/// # Safety
/// As [`bytes`].
unsafe fn text<'a>(ptr: *const u8, len: usize) -> Result<&'a str, WireOutcome> {
    // SAFETY: per this fn's contract.
    std::str::from_utf8(unsafe { bytes(ptr, len) }?).map_err(|_| WireOutcome::AddressRefused)
}

/// A borrowed [`DeclStr`] as text (`None` for NULL).
///
/// # Safety
/// A non-null range must address `len` readable bytes for the call.
unsafe fn decl_text<'a>(d: DeclStr) -> Result<Option<&'a str>, WireOutcome> {
    if d.ptr.is_null() {
        return Ok(None);
    }
    // SAFETY: per this fn's contract.
    unsafe { text(d.ptr, d.len) }.map(Some)
}

/// Copy `text` into the host's `(buf, cap)`, setting `out_len`.
///
/// # Safety
/// `buf` must address `cap` writable bytes and `out_len` a writable `usize`.
unsafe fn put(
    text: &str,
    buf: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> Result<(), WireOutcome> {
    if buf.is_null() || out_len.is_null() || text.len() > cap {
        return Err(WireOutcome::Fault);
    }
    // SAFETY: `text.len() <= cap` bytes into the host's writable range, then its length.
    unsafe {
        core::ptr::copy_nonoverlapping(text.as_ptr(), buf, text.len());
        *out_len = text.len();
    }
    Ok(())
}

/// Write one out-param.
///
/// # Safety
/// `out`, when non-null, must address a writable `T`.
unsafe fn set<T>(out: *mut T, v: T) -> Result<(), WireOutcome> {
    if out.is_null() {
        return Err(WireOutcome::Fault);
    }
    // SAFETY: per this fn's contract.
    unsafe { out.write(v) };
    Ok(())
}

/// THE BRIDGES, from one list per role (the TRANSPORT-STACK shrink): the role's slot table for `T`
/// and one generic `extern "C-unwind"` slot per method, each running the slot discipline — its panics
/// caught ([`guarded`]), the built transport found behind `state` — around a body that is the
/// method's own translation. Every body runs with the host's promise for the call: the state `init`
/// produced, and live ranges, callback tables and out-slots.
macro_rules! bridges {
    (
        $(#[$doc:meta])*
        pub const fn $table_fn:ident -> $table:ident for $trait:ident {
            $( fn $slot:ident($t:ident; $($arg:ident: $ty:ty),* $(,)?) $body:block )*
        }
    ) => {
        $(#[$doc])*
        #[must_use]
        pub const fn $table_fn<T: $trait>() -> $table {
            $table {
                size: core::mem::size_of::<$table>() as u32,
                _reserved: 0,
                $( $slot: Some($slot::<T>), )*
            }
        }
        $(
            extern "C-unwind" fn $slot<T: $trait>(
                state: *mut c_void,
                $($arg: $ty),*
            ) -> RawWireOutcome {
                guarded(|| {
                    // SAFETY: the host passes the state `init` produced and, for the call, its own
                    // live ranges, callback tables and out-slots (the module's slot discipline).
                    unsafe {
                        let $t = lowered::<T>(state)?;
                        $body
                    }
                })
            }
        )*
    };
}

// ── the carrier's slots ──────────────────────────────────────────────────────────────────────────

bridges! {
    /// The carrier slot table for `T`: one slot per [`Carrier`] method.
    pub const fn carrier_slots -> CarrierSlots for Carrier {
        fn listen(t; bind: *const u8, bind_len: usize, addr_buf: *mut u8, addr_cap: usize,
            out_addr_len: *mut usize, out_listener: *mut u64) {
            let (id, addr) = t.inner.listen(text(bind, bind_len)?).map_err(WireOutcome::of_error)?;
            put(&addr, addr_buf, addr_cap, out_addr_len)?;
            set(out_listener, id)
        }
        fn poll_accept(t; listener: u64, token: u64, peer_buf: *mut u8, peer_cap: usize,
            out_peer_len: *mut usize, out_conn: *mut u64) {
            let waker = t.waker(listener, ACCEPT, token);
            let (conn, peer) =
                polled(t.inner.poll_accept(listener, &mut Context::from_waker(&waker)))?;
            if let Err(e) = put(&peer, peer_buf, peer_cap, out_peer_len) {
                let _ = t.inner.poll_close(
                    conn,
                    &mut Context::from_waker(Waker::noop()),
                    crate::transport::wire::CloseReason::Normal,
                );
                return Err(e);
            }
            set(out_conn, conn)
        }
        fn dial(t; dest: *const WireDest, out_conn: *mut u64) {
            if dest.is_null() {
                return Err(WireOutcome::Fault);
            }
            // The sized struct is read only as far as it attests.
            let size = core::ptr::read_unaligned(core::ptr::addr_of!((*dest).size)) as usize;
            if size < core::mem::size_of::<WireDest>() {
                return Err(WireOutcome::Fault);
            }
            let d = core::ptr::read_unaligned(dest);
            let conn = match d.kind {
                0 => {
                    let authority = decl_text(d.authority)?.ok_or(WireOutcome::AddressRefused)?;
                    t.inner.dial(&Dest::Authority(authority))
                }
                1 => {
                    let program = decl_text(d.program)?.ok_or(WireOutcome::AddressRefused)?;
                    let (args, env) = (strs(d.args)?, pairs(d.env, d.env_len)?);
                    t.inner.dial(&Dest::Program { program, args: &args, env: &env })
                }
                _ => return Err(WireOutcome::AddressRefused),
            }
            .map_err(WireOutcome::of_error)?;
            set(out_conn, conn)
        }
        fn poll_read(t; conn: u64, token: u64, buf: *mut u8, buf_cap: usize, out_read: *mut usize) {
            // A zero-capacity read could only answer `0`, which is the end of the stream.
            if buf.is_null() || buf_cap == 0 {
                return Err(WireOutcome::Fault);
            }
            let into = std::slice::from_raw_parts_mut(buf, buf_cap);
            let waker = t.waker(conn, READ, token);
            let n = polled(t.inner.poll_read(conn, &mut Context::from_waker(&waker), into))?;
            if n > buf_cap {
                return Err(WireOutcome::Fault);
            }
            set(out_read, n)
        }
        fn poll_write(t; conn: u64, token: u64, buf: *const u8, len: usize,
            out_written: *mut usize) {
            let (offered, waker) = (bytes(buf, len)?, t.waker(conn, WRITE, token));
            let n = polled(t.inner.poll_write(conn, &mut Context::from_waker(&waker), offered))?;
            set(out_written, n)
        }
        fn poll_flush(t; conn: u64, token: u64) {
            let waker = t.waker(conn, WRITE, token);
            polled(t.inner.poll_flush(conn, &mut Context::from_waker(&waker)))
        }
        fn poll_close(t; conn: u64, token: u64, reason: u8) {
            let reason = code::close_reason_of(reason).ok_or(WireOutcome::Fault)?;
            let waker = t.waker(conn, CLOSE, token);
            let closed = polled(t.inner.poll_close(conn, &mut Context::from_waker(&waker), reason));
            if closed.is_ok() {
                t.forget(conn);
            }
            closed
        }
        fn arrival(t; conn: u64, peer_buf: *mut u8, peer_cap: usize, out_peer_len: *mut usize,
            out_local_port: *mut u16) {
            let facts = t.inner.arrival(conn).ok_or(WireOutcome::Closed)?;
            put(&facts.peer, peer_buf, peer_cap, out_peer_len)?;
            set(out_local_port, facts.local_port)
        }
    }
}

/// A borrowed string list.
///
/// # Safety
/// A non-null list must address `len` live entries, each a live range, for the call.
unsafe fn strs<'a>(list: DeclStrList) -> Result<Vec<&'a str>, WireOutcome> {
    if list.len == 0 {
        return Ok(Vec::new());
    }
    if list.ptr.is_null() {
        return Err(WireOutcome::Fault);
    }
    (0..list.len)
        .map(|i| {
            // SAFETY: per this fn's contract.
            unsafe { decl_text(core::ptr::read_unaligned(list.ptr.add(i))) }?
                .ok_or(WireOutcome::Fault)
        })
        .collect()
}

/// A borrowed environment.
///
/// # Safety
/// A non-null list must address `len` live pairs, each a live range, for the call.
unsafe fn pairs<'a>(
    ptr: *const crate::abi::hot::transport::WireEnvPair,
    len: usize,
) -> Result<Vec<(&'a str, &'a str)>, WireOutcome> {
    if len == 0 {
        return Ok(Vec::new());
    }
    if ptr.is_null() {
        return Err(WireOutcome::Fault);
    }
    (0..len)
        .map(|i| {
            // SAFETY: per this fn's contract.
            let p = unsafe { core::ptr::read_unaligned(ptr.add(i)) };
            // SAFETY: per this fn's contract.
            let (name, value) = unsafe { (decl_text(p.name)?, decl_text(p.value)?) };
            Ok((name.ok_or(WireOutcome::Fault)?, value.unwrap_or("")))
        })
        .collect()
}

// ── the framer's slots ───────────────────────────────────────────────────────────────────────────

bridges! {
    /// The framer slot table for `T`: one slot per [`Framer`] method.
    pub const fn framer_slots -> FramerSlots for Framer {
        fn locate(t; target: *const u8, target_len: usize, auth_buf: *mut u8, auth_cap: usize,
            out_auth_len: *mut usize, name_buf: *mut u8, name_cap: usize,
            out_name_len: *mut usize, out_secure: *mut u8) {
            let located = t.inner.locate(text(target, target_len)?).map_err(WireOutcome::of_error)?;
            put(&located.authority, auth_buf, auth_cap, out_auth_len)?;
            match &located.server_name {
                Some(name) => put(name, name_buf, name_cap, out_name_len)?,
                None => set(out_name_len, usize::MAX)?,
            }
            set(out_secure, u8::from(located.secure))
        }
        fn open(t; side: u8, target: *const u8, target_len: usize, facts: *const WireConnFacts,
            out: *const WireFramerOut, out_state: *mut u64) {
            let side = code::side_of(side).ok_or(WireOutcome::Fault)?;
            let (target, facts, mut out) =
                (text(target, target_len)?, facts_of(facts)?, host_out(out)?);
            let framing =
                t.inner.open(side, target, &facts, &mut out).map_err(WireOutcome::of_error)?;
            set(out_state, framing)
        }
        fn ingest(t; framing: u64, buf: *const u8, len: usize, end: u8,
            out: *const WireFramerOut) {
            let (taken, mut out) = (bytes(buf, len)?, host_out(out)?);
            t.inner.ingest(framing, taken, end == 1, &mut out).map_err(WireOutcome::of_error)
        }
        fn emit(t; framing: u64, stream: u64, buf: *const u8, len: usize, end_of_frame: u8,
            out: *const WireFramerOut) {
            let (given, mut out) = (bytes(buf, len)?, host_out(out)?);
            t.inner
                .emit(
                    framing,
                    StreamId(stream),
                    given,
                    end_of_frame == 1,
                    // The condemned HOT lane carries no text bit (`qa/abi-freeze.toml`).
                    false,
                    &mut out,
                )
                .map_err(WireOutcome::of_error)
        }
        fn encode_envelope(t; fields: *const WireField, fields_len: usize, body: *const u8,
            body_len: usize, out: *const WireBytesOut) {
            if out.is_null() || (fields.is_null() && fields_len != 0) {
                return Err(WireOutcome::Fault);
            }
            let body = bytes(body, body_len)?;
            let owned: Vec<(&str, &[u8])> = (0..fields_len)
                .map(|i| {
                    let f = core::ptr::read_unaligned(fields.add(i));
                    let name = decl_text(f.name)?.ok_or(WireOutcome::Fault)?;
                    let value = if f.value.ptr.is_null() {
                        &[][..]
                    } else {
                        bytes(f.value.ptr, f.value.len)?
                    };
                    Ok((name, value))
                })
                .collect::<Result<_, WireOutcome>>()?;
            t.inner
                .encode_envelope(&owned, body, &mut HostBytes(*out))
                .map_err(WireOutcome::of_encode)
        }
        fn refusal(t; framing: u64, has_stream: u8, stream: u64, buf: *const u8, len: usize,
            out: *const WireFramerOut) {
            let (given, mut out) = (bytes(buf, len)?, host_out(out)?);
            let stream = (has_stream == 1).then_some(StreamId(stream));
            t.inner.refusal(framing, stream, given, &mut out).map_err(WireOutcome::of_error)
        }
        fn close(t; framing: u64, reason: u8, out: *const WireFramerOut) {
            let (mut out, reason) =
                (host_out(out)?, code::close_reason_of(reason).ok_or(WireOutcome::Fault)?);
            t.inner.close(framing, reason, &mut out);
            Ok(())
        }
        fn detach(t; framing: u64, out: *const WireBytesOut) {
            if out.is_null() {
                return Err(WireOutcome::Fault);
            }
            t.inner.detach(framing, &mut HostBytes(*out)).map_err(WireOutcome::of_error)
        }
        fn adopt(t; side: u8, facts: *const WireConnFacts, leftover: *const u8,
            leftover_len: usize, out: *const WireFramerOut, out_state: *mut u64) {
            let side = code::side_of(side).ok_or(WireOutcome::Fault)?;
            let (facts, leftover, mut out) =
                (facts_of(facts)?, bytes(leftover, leftover_len)?, host_out(out)?);
            let framing = t
                .inner
                .adopt(side, &facts, leftover, &mut out)
                .map_err(WireOutcome::of_error)?;
            set(out_state, framing)
        }
        fn tick(t; framing: u64, out: *const WireFramerOut) {
            let mut out = host_out(out)?;
            t.inner.tick(framing, &mut out).map_err(WireOutcome::of_error)
        }
    }
}

/// The host's callbacks, as a [`FramerOut`].
struct HostOut(WireFramerOut);

impl FramerOut for HostOut {
    fn send(&mut self, bytes: &[u8]) {
        (self.0.send)(self.0.ctx, bytes.as_ptr(), bytes.len());
    }
    fn frame(&mut self, piece: Framed<'_>) {
        let mut flags = 0;
        if piece.status_code.is_some() {
            flags |= FRAMED_HAS_STATUS_CODE;
        }
        if piece.retry_after_secs.is_some() {
            flags |= FRAMED_HAS_RETRY_AFTER;
        }
        let framed = WireFramed {
            size: core::mem::size_of::<WireFramed>() as u32,
            end_of_frame: u8::from(piece.end_of_frame),
            status_class: code::status_class(piece.status),
            flags,
            _reserved: 0,
            stream: piece.stream.0,
            bytes: piece.bytes.as_ptr(),
            len: piece.bytes.len(),
            status_code: piece.status_code.unwrap_or(0),
            _reserved2: 0,
            retry_after_secs: piece.retry_after_secs.unwrap_or(0),
        };
        (self.0.frame)(self.0.ctx, &framed);
    }
    fn end(&mut self) {
        (self.0.end)(self.0.ctx);
    }
    fn now(&self) -> HostTime {
        HostTime {
            monotonic_nanos: self.0.now_monotonic_nanos,
            unix_nanos: self.0.now_unix_nanos,
        }
    }
    fn wake_at(&mut self, monotonic_nanos: Option<u64>) {
        (self.0.wake_at)(
            self.0.ctx,
            u8::from(monotonic_nanos.is_some()),
            monotonic_nanos.unwrap_or(0),
        );
    }
}

/// The host's callback, as a [`BytesOut`].
struct HostBytes(WireBytesOut);

impl BytesOut for HostBytes {
    fn put(&mut self, bytes: &[u8]) {
        (self.0.put)(self.0.ctx, bytes.as_ptr(), bytes.len());
    }
}

/// The host's callbacks.
///
/// # Safety
/// `out`, when non-null, must address the host's live callback table for the call.
unsafe fn host_out(out: *const WireFramerOut) -> Result<HostOut, WireOutcome> {
    // SAFETY: per this fn's contract.
    unsafe { out.as_ref() }
        .map(|o| HostOut(*o))
        .ok_or(WireOutcome::Fault)
}

/// The host's facts, owned.
///
/// # Safety
/// `facts`, when non-null, must address the host's live sized struct and its ranges for the call.
unsafe fn facts_of(facts: *const WireConnFacts) -> Result<ConnFacts, WireOutcome> {
    if facts.is_null() {
        return Ok(ConnFacts::default());
    }
    // SAFETY: per this fn's contract; the size leads the struct.
    let size = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*facts).size)) };
    // The facts up to the appended claim are every host's; the claim is read only as far as the
    // host attests (minor 33), and a host that predates it names the first claim.
    if (size as usize) < core::mem::offset_of!(WireConnFacts, claim) {
        return Err(WireOutcome::Fault);
    }
    let claim = crate::abi::read_sized_field!(facts, size, WireConnFacts, claim);
    // SAFETY: per this fn's contract; read only as far as it attests (checked above).
    unsafe {
        let f = WireConnFacts {
            size,
            version: core::ptr::read_unaligned(core::ptr::addr_of!((*facts).version)),
            sni: core::ptr::read_unaligned(core::ptr::addr_of!((*facts).sni)),
            alpn: core::ptr::read_unaligned(core::ptr::addr_of!((*facts).alpn)),
            cert_subject: core::ptr::read_unaligned(core::ptr::addr_of!((*facts).cert_subject)),
            cert_issuer: core::ptr::read_unaligned(core::ptr::addr_of!((*facts).cert_issuer)),
            cert_fingerprint: core::ptr::read_unaligned(core::ptr::addr_of!(
                (*facts).cert_fingerprint
            )),
            claim: claim.unwrap_or(DeclStr::NONE),
        };
        let owned = |d: DeclStr| -> Result<Option<String>, WireOutcome> {
            decl_text(d).map(|t| t.map(str::to_string))
        };
        let peer_cert = match owned(f.cert_fingerprint)? {
            Some(fingerprint) => Some(CertFacts {
                subject: owned(f.cert_subject)?.unwrap_or_default(),
                issuer: owned(f.cert_issuer)?.unwrap_or_default(),
                fingerprint,
            }),
            None => None,
        };
        Ok(ConnFacts {
            sni: owned(f.sni)?,
            alpn: owned(f.alpn)?,
            peer_cert,
            claim: owned(f.claim)?,
            // The far end's key pin and whether busbar presented its client identity reach a
            // plugin on the host connector's FACTS service (`connector::StreamFacts`), not here.
            ..ConnFacts::default()
        })
    }
}

// ── the decl ─────────────────────────────────────────────────────────────────────────────────────

/// `names` as borrowed ranges, in declared order.
#[must_use]
pub const fn decl_strs<const N: usize>(names: &[&'static str]) -> [DeclStr; N] {
    let mut list = [DeclStr::NONE; N];
    let mut i = 0;
    while i < N {
        list[i] = DeclStr::new(names[i]);
        i += 1;
    }
    list
}

/// `forms` as their codes, in declared order.
#[must_use]
pub const fn form_codes<const N: usize>(forms: &[SelectorForm]) -> [u8; N] {
    let mut list = [0_u8; N];
    let mut i = 0;
    while i < N {
        list[i] = code::selector_form(forms[i]);
        i += 1;
    }
    list
}

/// A list borrowed from a `'static` array.
#[must_use]
pub const fn str_list(list: &'static [DeclStr]) -> DeclStrList {
    DeclStrList {
        ptr: list.as_ptr(),
        len: list.len(),
    }
}

/// A byte list borrowed from a `'static` array.
#[must_use]
pub const fn byte_list(list: &'static [u8]) -> DeclByteList {
    DeclByteList {
        ptr: list.as_ptr(),
        len: list.len(),
    }
}

/// The borrowed lists a decl's row points into, each a `'static` array the export macro declares.
pub struct RowLists {
    /// `COMPOSES_OVER`.
    pub composes_over: &'static [DeclStr],
    /// `SELECTOR_FORMS` codes.
    pub selector_forms: &'static [u8],
    /// `EGRESS_SELECTOR_FORMS` codes.
    pub egress_selector_forms: &'static [u8],
    /// `UPGRADES_TO`.
    pub upgrades_to: &'static [DeclStr],
    /// `TRANSPORT_FACTS`.
    pub transport_facts: &'static [DeclStr],
    /// `CLAIMS`, lowered ([`decl_claims`]).
    pub claims: &'static [DeclClaim],
}

/// How many selector forms every claim of `claims` states, together: the length of the pool
/// [`claim_form_pool`] lays them out in.
#[must_use]
pub const fn claim_forms_len(claims: &[Claim]) -> usize {
    let (mut n, mut i) = (0, 0);
    while i < claims.len() {
        n += claims[i].selector_forms.len();
        i += 1;
    }
    n
}

/// How many fact keys every claim of `claims` states, together: the length of the pool
/// [`claim_fact_pool`] lays them out in.
#[must_use]
pub const fn claim_facts_len(claims: &[Claim]) -> usize {
    let (mut n, mut i) = (0, 0);
    while i < claims.len() {
        n += claims[i].transport_facts.len();
        i += 1;
    }
    n
}

/// Every claim's selector-form codes, claim after claim, in one `'static` pool.
#[must_use]
pub const fn claim_form_pool<const N: usize>(claims: &[Claim]) -> [u8; N] {
    let mut pool = [0_u8; N];
    let (mut at, mut i) = (0, 0);
    while i < claims.len() {
        let forms = claims[i].selector_forms;
        let mut j = 0;
        while j < forms.len() {
            pool[at] = code::selector_form(forms[j]);
            at += 1;
            j += 1;
        }
        i += 1;
    }
    pool
}

/// Every claim's fact keys, claim after claim, in one `'static` pool.
#[must_use]
pub const fn claim_fact_pool<const N: usize>(claims: &[Claim]) -> [DeclStr; N] {
    let mut pool = [DeclStr::NONE; N];
    let (mut at, mut i) = (0, 0);
    while i < claims.len() {
        let facts = claims[i].transport_facts;
        let mut j = 0;
        while j < facts.len() {
            pool[at] = DeclStr::new(facts[j]);
            at += 1;
            j += 1;
        }
        i += 1;
    }
    pool
}

/// `claims` lowered, each claim's lists borrowed from its stretch of the two pools.
#[must_use]
pub const fn decl_claims<const N: usize>(
    claims: &[Claim],
    forms: &'static [u8],
    facts: &'static [DeclStr],
) -> [DeclClaim; N] {
    let empty = DeclClaim {
        key: DeclStr::NONE,
        selector_forms: DeclByteList {
            ptr: core::ptr::null(),
            len: 0,
        },
        transport_facts: DeclStrList {
            ptr: core::ptr::null(),
            len: 0,
        },
        status_namespace: DeclStr::NONE,
        session: 0,
        session_bound: 0,
        unit0_trigger: 0,
        status_at: 0,
        _reserved: 0,
    };
    let mut out = [empty; N];
    let (mut form_at, mut fact_at, mut i) = (0, 0, 0);
    while i < N {
        let c = claims[i];
        let (nf, nk) = (c.selector_forms.len(), c.transport_facts.len());
        out[i] = DeclClaim {
            key: DeclStr::new(c.key),
            selector_forms: DeclByteList {
                // Within the pool: `claim_form_pool` laid out exactly these lengths in this order.
                ptr: forms.split_at(form_at).1.as_ptr(),
                len: nf,
            },
            transport_facts: DeclStrList {
                ptr: facts.split_at(fact_at).1.as_ptr(),
                len: nk,
            },
            status_namespace: match c.status_namespace {
                Some(ns) => DeclStr::new(ns),
                None => DeclStr::NONE,
            },
            session: c.session as u8,
            session_bound: c.session_bound as u8,
            unit0_trigger: code::unit0_trigger(c.unit0_trigger),
            status_at: code::status_at(c.status_at),
            _reserved: 0,
        };
        form_at += nf;
        fact_at += nk;
        i += 1;
    }
    out
}

/// THE DECL of the transport `T`: its row (read off `T`'s declaration, the lists borrowed from
/// `lists`), `init`, and exactly one role's slot table.
#[must_use]
pub const fn decl<T: TransportMeta>(
    lists: RowLists,
    init: crate::abi::hot::transport::WireInitFn,
    carrier: Option<&'static CarrierSlots>,
    framer: Option<&'static FramerSlots>,
) -> TransportDecl {
    let (handoff_from, handoff_to, handoff_binding_fact) = match T::HANDOFF {
        Some(h) => (
            DeclStr::new(h.from),
            DeclStr::new(h.to),
            DeclStr::new(h.binding_fact),
        ),
        None => (DeclStr::NONE, DeclStr::NONE, DeclStr::NONE),
    };
    let (handshake_frame_kind, handshake_max_steps) = match T::HANDSHAKE_TRIGGER {
        Some(h) => (DeclStr::new(h.frame_kind), h.max_steps),
        None => (DeclStr::NONE, 0),
    };
    TransportDecl {
        abi: AbiPreamble {
            magic: ABI_MAGIC,
            abi_major: ABI_MAJOR,
            abi_minor: ABI_MINOR,
        },
        size: core::mem::size_of::<TransportDecl>() as u32,
        version: TRANSPORT_DECL_MAJOR,
        key: DeclStr::new(T::KEY),
        composes_over: str_list(lists.composes_over),
        selector_forms: byte_list(lists.selector_forms),
        egress_selector_forms: byte_list(lists.egress_selector_forms),
        handoff_from,
        handoff_to,
        handoff_binding_fact,
        upgrades_to: str_list(lists.upgrades_to),
        handshake_frame_kind,
        transport_facts: str_list(lists.transport_facts),
        status_namespace: match T::STATUS_NAMESPACE {
            Some(ns) => DeclStr::new(ns),
            None => DeclStr::NONE,
        },
        framing: code::framing(T::FRAMING),
        session: T::SESSION as u8,
        session_bound: T::SESSION_BOUND as u8,
        decodes_payload: T::DECODES_PAYLOAD as u8,
        unit0_trigger: code::unit0_trigger(T::UNIT0_TRIGGER),
        handshake_max_steps,
        status_at: code::status_at(T::STATUS_CLASS),
        _reserved: 0,
        init: Some(init),
        carrier: match carrier {
            Some(c) => c,
            None => core::ptr::null(),
        },
        framer: match framer {
            Some(f) => f,
            None => core::ptr::null(),
        },
        claims_ptr: lists.claims.as_ptr(),
        claims_len: lists.claims.len(),
    }
}

/// Lower the CARRIER `$ty` (a [`Carrier`] + [`TransportMeta`] type) to its HOT decl and register it as
/// this image's ONE door — the dropped-in door. `$build` is the linked row's constructor,
/// `fn(&TransportSettings) -> $ty`. Expand it inside the one module a transport's
/// `#![deny(unsafe_code)]` allows (`exports`, behind the crate's `dropped-in` feature).
#[macro_export]
macro_rules! export_carrier {
    ($ty:ty, $build:path) => {
        $crate::__transport_decl!($ty, $build, carrier);
    };
}

/// Lower the FRAMER `$ty` (a [`Framer`] + [`TransportMeta`] type) to its HOT decl and register it as
/// this image's ONE door; as [`export_carrier!`](crate::export_carrier).
#[macro_export]
macro_rules! export_framer {
    ($ty:ty, $build:path) => {
        $crate::__transport_decl!($ty, $build, framer);
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __transport_decl {
    ($ty:ty, $build:path, $role:ident) => {
        static __COMPOSES_OVER: [$crate::abi::hot::DeclStr;
            <$ty as $crate::transport::TransportMeta>::COMPOSES_OVER.len()] =
            $crate::abi::sdk::transport::decl_strs(
                <$ty as $crate::transport::TransportMeta>::COMPOSES_OVER,
            );
        static __SELECTOR_FORMS: [u8; <$ty as $crate::transport::TransportMeta>::SELECTOR_FORMS
            .len()] = $crate::abi::sdk::transport::form_codes(
            <$ty as $crate::transport::TransportMeta>::SELECTOR_FORMS,
        );
        static __EGRESS_SELECTOR_FORMS: [u8;
            <$ty as $crate::transport::TransportMeta>::EGRESS_SELECTOR_FORMS.len()] =
            $crate::abi::sdk::transport::form_codes(
                <$ty as $crate::transport::TransportMeta>::EGRESS_SELECTOR_FORMS,
            );
        static __UPGRADES_TO: [$crate::abi::hot::DeclStr;
            <$ty as $crate::transport::TransportMeta>::UPGRADES_TO.len()] =
            $crate::abi::sdk::transport::decl_strs(
                <$ty as $crate::transport::TransportMeta>::UPGRADES_TO,
            );
        static __TRANSPORT_FACTS: [$crate::abi::hot::DeclStr;
            <$ty as $crate::transport::TransportMeta>::TRANSPORT_FACTS.len()] =
            $crate::abi::sdk::transport::decl_strs(
                <$ty as $crate::transport::TransportMeta>::TRANSPORT_FACTS,
            );
        static __CLAIM_FORMS: [u8; $crate::abi::sdk::transport::claim_forms_len(
            <$ty as $crate::transport::TransportMeta>::CLAIMS,
        )] = $crate::abi::sdk::transport::claim_form_pool(
            <$ty as $crate::transport::TransportMeta>::CLAIMS,
        );
        static __CLAIM_FACTS: [$crate::abi::hot::DeclStr;
            $crate::abi::sdk::transport::claim_facts_len(
                <$ty as $crate::transport::TransportMeta>::CLAIMS,
            )] = $crate::abi::sdk::transport::claim_fact_pool(
            <$ty as $crate::transport::TransportMeta>::CLAIMS,
        );
        static __CLAIMS: [$crate::abi::hot::transport::DeclClaim;
            <$ty as $crate::transport::TransportMeta>::CLAIMS.len()] =
            $crate::abi::sdk::transport::decl_claims(
                <$ty as $crate::transport::TransportMeta>::CLAIMS,
                &__CLAIM_FORMS,
                &__CLAIM_FACTS,
            );
        $crate::__transport_slots!($ty, $role);
        extern "C-unwind" fn __init(
            settings: *const $crate::abi::hot::transport::WireSettings,
            waker: *const $crate::abi::hot::transport::WireWaker,
            out_state: *mut ::core::mem::MaybeUninit<$crate::abi::hot::OpaqueHandle>,
        ) -> $crate::abi::hot::transport::RawWireOutcome {
            // SAFETY: the host calls `init` with its own live settings, waker handle and out slot.
            unsafe { $crate::abi::sdk::transport::init::<$ty>(settings, waker, out_state, $build) }
        }
        /// THE decl this image's door answers with.
        pub static TRANSPORT_DECL: $crate::abi::hot::TransportDecl =
            $crate::abi::sdk::transport::decl::<$ty>(
                $crate::abi::sdk::transport::RowLists {
                    composes_over: &__COMPOSES_OVER,
                    selector_forms: &__SELECTOR_FORMS,
                    egress_selector_forms: &__EGRESS_SELECTOR_FORMS,
                    upgrades_to: &__UPGRADES_TO,
                    transport_facts: &__TRANSPORT_FACTS,
                    claims: &__CLAIMS,
                },
                __init,
                __CARRIER,
                __FRAMER,
            );
        $crate::export_transport!(TRANSPORT_DECL);
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __transport_slots {
    ($ty:ty, carrier) => {
        static __SLOTS: $crate::abi::hot::transport::CarrierSlots =
            $crate::abi::sdk::transport::carrier_slots::<$ty>();
        const __CARRIER: Option<&'static $crate::abi::hot::transport::CarrierSlots> =
            Some(&__SLOTS);
        const __FRAMER: Option<&'static $crate::abi::hot::transport::FramerSlots> = None;
    };
    ($ty:ty, framer) => {
        static __SLOTS: $crate::abi::hot::transport::FramerSlots =
            $crate::abi::sdk::transport::framer_slots::<$ty>();
        const __CARRIER: Option<&'static $crate::abi::hot::transport::CarrierSlots> = None;
        const __FRAMER: Option<&'static $crate::abi::hot::transport::FramerSlots> = Some(&__SLOTS);
    };
}
