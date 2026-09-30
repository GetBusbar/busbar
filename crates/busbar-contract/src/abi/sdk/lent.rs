// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! WHAT THE HOST LENDS A CALL, READ AND WRITTEN WITHOUT `unsafe` (THE DESIGN, the plugin ABI: the SDK's
//! typed wrappers). A [`SafeSlot`](super::safe::SafeSlot) body is handed its `in` as a
//! [`Lent`]: a borrow of the trampoline's copy of the host's `in` that only the SDK can make. Its
//! lifetime is the call's, so nothing read through it can outlive the call.
//!
//! * A [`Blob`] or an [`AbiStr`] field is reached with [`Lent::field`] and read with
//!   [`Lent::bytes`](Lent#method-bytes) (and, for text, [`Lent::as_str`](Lent#method-as_str)).
//! * A list the host lends (`ptr` + `len`) is a [`LentList`]; one struct it points to is a
//!   nested [`Lent`]; loose bytes (`ptr` + `len`) are a `&[u8]`. Each is an accessor named after
//!   its pointer field (`input.fields()`, `input.bytes()`), stated once per `in` below.
//! * A HOST BUFFER (`ptr` + `cap` in the `in`, `*_written` + `*_needed` in the `out`) is a
//!   [`HostBuf`], also named after its pointer field (`input.units_buf()`): it fills up to the capacity and counts everything asked of it, so the `out`
//!   reports `needed` exactly under the short-buffer rule
//!   ([`OutHead`](crate::abi::mechanism::call::OutHead)).
//!
//! THE CALL CONTRACT these rely on, and nothing else: every pointer the host puts in an `in` is
//! valid, as the kind's ABI states it, until the call returns; the host's buffers are writable for
//! their stated capacity and overlap nothing else the call is lent. A call answering PENDING is
//! re-invoked with the same `in` and `out`, so the host keeps what it lent alive until the call
//! completes, even when the caller that submitted it has gone (the dispatcher's duty, not the
//! plugin's). A `Lent` never outlives one invocation: it borrows the trampoline's frame, so a body
//! that pends keeps nothing lent and re-reads its `in` on resume.

use std::marker::PhantomData;
use std::mem::size_of;
use std::ops::Deref;
use std::ptr;
use std::str::Utf8Error;

use crate::abi::mechanism::call::{AbiStr, Blob, Field, Span};
use crate::abi::sdk::out::Scalar;

/// A borrow of data the HOST lent the current call. Only the SDK makes one (the trampoline, from
/// its copy of the host's `in`, and the accessors below, from what that `in` points to), so every
/// pointer inside it is the host's, valid for `'a`.
#[derive(Debug)]
pub struct Lent<'a, T> {
    lent: &'a T,
}

// A borrow copies whatever it borrows (no `T: Copy` bound, as a derive would add).
impl<T> Clone for Lent<'_, T> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<T> Copy for Lent<'_, T> {}

impl<'a, T> Lent<'a, T> {
    /// # Safety
    /// Every pointer in `*lent` is valid, as the kind's ABI states it, for `'a`.
    pub(crate) const unsafe fn new(lent: &'a T) -> Self {
        Self { lent }
    }

    /// The plain value (also reached through `Deref`).
    #[must_use]
    pub const fn get(self) -> &'a T {
        self.lent
    }

    /// One field of the lent struct, still lent: `input.field(|i| &i.settings).bytes()`.
    ///
    /// # Panics
    /// When `pick` answers a reference that is not inside the lent struct (a value it made rather
    /// than a field it named). The trampoline answers the call FAULT.
    #[must_use]
    pub fn field<F>(self, pick: impl FnOnce(&'a T) -> &'a F) -> Lent<'a, F> {
        let f = pick(self.lent);
        let base = ptr::from_ref(self.lent) as usize;
        let at = ptr::from_ref(f) as usize;
        assert!(
            at >= base && at.saturating_add(size_of::<F>()) <= base + size_of::<T>(),
            "Lent::field: the picked reference is not a field of the lent struct"
        );
        // SAFETY: `f` lies inside `*self.lent`, whose every pointer the host lent for `'a`; so is
        // every pointer inside `*f`.
        unsafe { Lent::new(f) }
    }
}

impl<T> Deref for Lent<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        self.lent
    }
}

/// `len` bytes at `p`, or none for a NULL `p` or a zero `len`.
///
/// # Safety
/// A non-NULL `p` points at `len` readable bytes, valid and unwritten for `'a`.
unsafe fn lent_bytes<'a>(p: *const u8, len: usize) -> &'a [u8] {
    if p.is_null() || len == 0 {
        return &[];
    }
    // SAFETY: the caller's contract.
    unsafe { std::slice::from_raw_parts(p, len) }
}

impl<'a> Lent<'a, Blob> {
    /// The blob's bytes; empty when it is absent.
    #[must_use]
    pub fn bytes(self) -> &'a [u8] {
        // SAFETY: a lent blob's `ptr`/`len` are the host's, valid for the call (`Lent`).
        unsafe { lent_bytes(self.lent.ptr, self.lent.len) }
    }
}

impl<'a> Lent<'a, AbiStr> {
    /// The string's bytes; empty when it is absent.
    #[must_use]
    pub fn bytes(self) -> &'a [u8] {
        // SAFETY: a lent string's `ptr`/`len` are the host's, valid for the call (`Lent`).
        unsafe { lent_bytes(self.lent.ptr, self.lent.len) }
    }

    /// The string as UTF-8; `""` when it is absent.
    ///
    /// # Errors
    /// The bytes are not UTF-8.
    pub fn as_str(self) -> Result<&'a str, Utf8Error> {
        std::str::from_utf8(self.bytes())
    }
}

/// A list the host lent the call: `len` values at `ptr`.
#[derive(Debug)]
pub struct LentList<'a, T> {
    items: &'a [T],
}

impl<T> Clone for LentList<'_, T> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<T> Copy for LentList<'_, T> {}

impl<'a, T> LentList<'a, T> {
    /// # Safety
    /// A non-NULL `p` points at `len` initialized, aligned `T`s, each lent as [`Lent`] requires,
    /// valid and unwritten for `'a`.
    unsafe fn new(p: *const T, len: usize) -> Self {
        let items = if p.is_null() || len == 0 {
            &[]
        } else {
            // SAFETY: the caller's contract.
            unsafe { std::slice::from_raw_parts(p, len) }
        };
        Self { items }
    }

    /// How many.
    #[must_use]
    pub const fn len(self) -> usize {
        self.items.len()
    }

    /// Whether it is empty.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.items.is_empty()
    }

    /// The value at `i`, lent.
    #[must_use]
    pub fn get(self, i: usize) -> Option<Lent<'a, T>> {
        // SAFETY: an element of a lent list is lent as the list is.
        self.items.get(i).map(|v| unsafe { Lent::new(v) })
    }

    /// Every value, lent.
    pub fn iter(self) -> impl ExactSizeIterator<Item = Lent<'a, T>> + Clone + 'a {
        // SAFETY: as `get`.
        self.items.iter().map(|v| unsafe { Lent::new(v) })
    }
}

/// A HOST BUFFER the call fills: `cap` values at a host pointer. It writes while there is room and
/// COUNTS every value asked of it, so a too-small buffer is answered exactly (the short-buffer rule):
///
/// * one buffer — `out.x_written = buf.written()`, `out.x_needed = buf.needed()`, and FAILED when
///   `!buf.fits()`;
/// * several buffers in one answer — the answer is short when any one does not fit, and then EVERY
///   buffer reports its full size: `(written, needed) = buf.settle(short)`.
///
/// It never writes past `cap` and never makes a reference into the host's memory.
#[derive(Debug)]
pub struct HostBuf<'a, T> {
    ptr: *mut T,
    cap: usize,
    asked: usize,
    _lent: PhantomData<&'a mut [T]>,
}

impl<'a, T: Copy> HostBuf<'a, T> {
    /// # Safety
    /// A non-NULL `ptr` points at `cap` writable `T`s, overlapping nothing else the call is lent,
    /// for `'a`.
    unsafe fn new(ptr: *mut T, cap: usize) -> Self {
        Self {
            ptr,
            cap: if ptr.is_null() { 0 } else { cap },
            asked: 0,
            _lent: PhantomData,
        }
    }

    /// The capacity the host gave.
    #[must_use]
    pub const fn cap(&self) -> usize {
        self.cap
    }

    /// Every value asked of it so far, written or not.
    #[must_use]
    pub const fn asked(&self) -> usize {
        self.asked
    }

    /// Whether everything asked of it fits.
    #[must_use]
    pub const fn fits(&self) -> bool {
        self.asked <= self.cap
    }

    /// What `*_written` reports: everything asked when it fits, else `0`.
    #[must_use]
    pub const fn written(&self) -> usize {
        if self.fits() {
            self.asked
        } else {
            0
        }
    }

    /// What `*_needed` reports: `0` when it fits, else everything asked.
    #[must_use]
    pub const fn needed(&self) -> usize {
        if self.fits() {
            0
        } else {
            self.asked
        }
    }

    /// `(written, needed)` in an answer of several buffers that is `short` as a whole.
    #[must_use]
    pub const fn settle(&self, short: bool) -> (usize, usize) {
        if short {
            (0, self.asked)
        } else {
            (self.asked, 0)
        }
    }
}

/// Writing a host buffer: only pointer-free values ([`Scalar`]) go in by the plugin's hand, so no
/// value in a host buffer points at memory the plugin may free.
impl<T: Scalar> HostBuf<'_, T> {
    /// Write `v` at the next index while there is room; count it either way. Answers its index.
    pub fn push(&mut self, v: T) -> usize {
        let at = self.asked;
        if at < self.cap {
            // SAFETY: `at < cap`, and the host lent `cap` writable `T`s at `ptr` (`new`).
            unsafe { self.ptr.add(at).write_unaligned(v) };
        }
        self.asked = self.asked.saturating_add(1);
        at
    }

    /// Write `vs` from the next index while there is room; count all of them either way. Answers
    /// the index of the first.
    pub fn extend(&mut self, vs: &[T]) -> usize {
        let at = self.asked;
        let room = self.cap.saturating_sub(at).min(vs.len());
        if room != 0 {
            // SAFETY: `at + room <= cap` writable `T`s at `ptr` (`new`), and `vs` is the plugin's
            // own memory, which no host buffer overlaps.
            unsafe { ptr::copy_nonoverlapping(vs.as_ptr(), self.ptr.add(at), room) };
        }
        self.asked = self.asked.saturating_add(vs.len());
        at
    }

    /// Write as much of `vs` as there is room for and count only that: a streamed buffer with no
    /// short answer (backpressure). Answers how many went in.
    pub fn stream(&mut self, vs: &[T]) -> usize {
        let room = self.cap.saturating_sub(self.asked).min(vs.len());
        self.extend(&vs[..room]);
        room
    }
}

/// A signal value with no pointer in it: what a plugin writes into a host signal buffer by hand.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SignalScalar {
    /// [`SIGNAL_TAG_U64`](crate::abi::hook::SIGNAL_TAG_U64).
    U64(u64),
    /// [`SIGNAL_TAG_I64`](crate::abi::hook::SIGNAL_TAG_I64).
    I64(i64),
    /// [`SIGNAL_TAG_F64`](crate::abi::hook::SIGNAL_TAG_F64).
    F64(f64),
    /// [`SIGNAL_TAG_BOOL`](crate::abi::hook::SIGNAL_TAG_BOOL).
    Bool(bool),
}

impl HostBuf<'_, crate::abi::hook::SignalEntry> {
    /// Write the signal `id` = `value` at the next index while there is room; count it either way.
    /// Answers its index. (A string signal's value would point into memory; it is not written by
    /// hand.)
    pub fn push_signal(&mut self, id: u32, value: SignalScalar) -> usize {
        use crate::abi::hook::{
            SignalEntry, SignalValue, SIGNAL_TAG_BOOL, SIGNAL_TAG_F64, SIGNAL_TAG_I64,
            SIGNAL_TAG_U64,
        };
        let (tag, value) = match value {
            SignalScalar::U64(v) => (SIGNAL_TAG_U64, SignalValue { u64_: v }),
            SignalScalar::I64(v) => (SIGNAL_TAG_I64, SignalValue { i64_: v }),
            SignalScalar::F64(v) => (SIGNAL_TAG_F64, SignalValue { f64_: v }),
            SignalScalar::Bool(v) => (
                SIGNAL_TAG_BOOL,
                SignalValue {
                    boolean: u8::from(v),
                },
            ),
        };
        let at = self.asked;
        if at < self.cap {
            // SAFETY: `at < cap`, and the host lent `cap` writable entries at `ptr` (`new`); the
            // entry holds no pointer (its tag names a number).
            unsafe {
                self.ptr
                    .add(at)
                    .write_unaligned(SignalEntry { id, tag, value })
            };
        }
        self.asked = self.asked.saturating_add(1);
        at
    }
}

impl HostBuf<'_, u8> {
    /// Copy `bytes` into this ARENA and answer their [`Span`](Span): the
    /// offset they start at and their length.
    pub fn span(&mut self, bytes: &[u8]) -> Span {
        let at = self.extend(bytes);
        Span {
            offset: u32::try_from(at).unwrap_or(u32::MAX),
            len: u32::try_from(bytes.len()).unwrap_or(u32::MAX),
        }
    }

    /// The [`AbiStr`] naming `span` inside this ARENA, for a struct that points into it (a
    /// `project` view). It points at the host's memory; nothing here reads it.
    #[must_use]
    pub(crate) fn str_at(&self, span: Span) -> AbiStr {
        AbiStr {
            ptr: self.ptr.wrapping_add(span.offset as usize).cast_const(),
            len: span.len as usize,
        }
    }
}

impl<T> HostBuf<'_, T> {
    /// The buffer's host address, for a struct that points at it (a `project` view's signals).
    #[must_use]
    pub(crate) const fn as_ptr(&self) -> *mut T {
        self.ptr
    }
}

/// The accessors of each `in`, one per pointer field and named after it, stated once. Each is `unsafe` inside only
/// because the kind's ABI, cited beside it, is what makes the pointer valid for the call.
macro_rules! lend {
    ($($ty:ty { $($how:ident($p:ident $(, $n:ident)?) $(-> $el:ty)?;)+ })+) => {$(
        impl<'a> Lent<'a, $ty> { $( lend!(@one $p $how($p $(, $n)?) $(-> $el)?); )+ }
    )+};
    (@one $name:ident bytes($p:ident, $n:ident)) => {
        #[doc = concat!("The bytes `", stringify!($p), "`/`", stringify!($n), "` lend the call.")]
        #[must_use]
        pub fn $name(self) -> &'a [u8] {
            // SAFETY: the kind's ABI states these as bytes the host lends for the call.
            unsafe { lent_bytes(self.get().$p, self.get().$n) }
        }
    };
    (@one $name:ident list($p:ident, $n:ident) -> $el:ty) => {
        #[doc = concat!("The list `", stringify!($p), "`/`", stringify!($n), "` lends the call.")]
        #[must_use]
        pub fn $name(self) -> LentList<'a, $el> {
            // SAFETY: the kind's ABI states this as a list the host lends for the call.
            unsafe { LentList::new(self.get().$p, self.get().$n) }
        }
    };
    (@one $name:ident one($p:ident) -> $el:ty) => {
        #[doc = concat!("The struct `", stringify!($p), "` points to, if any, lent for the call.")]
        #[must_use]
        pub fn $name(self) -> Option<Lent<'a, $el>> {
            // SAFETY: the kind's ABI states this as NULL or a struct the host lends for the call.
            unsafe { self.get().$p.as_ref().map(|v| Lent::new(v)) }
        }
    };
    (@one $name:ident buf($p:ident, $n:ident) -> $el:ty) => {
        #[doc = concat!("The HOST buffer `", stringify!($p), "`/`", stringify!($n), "` the call fills.")]
        #[must_use]
        pub fn $name(self) -> HostBuf<'a, $el> {
            #[allow(clippy::unnecessary_cast)] // a capacity is a `usize` or a `u32`, by kind
            let cap = self.get().$n as usize;
            // SAFETY: the kind's ABI states this as a host buffer of `cap` writable values for the
            // call, overlapping nothing else the call is lent.
            unsafe { HostBuf::new(self.get().$p, cap) }
        }
    };
}

use crate::abi::auth::{IdentityBuf, NamedValue, VerifyIn};
use crate::abi::mechanism::lifecycle::{OpenIn, RefreshIn};
use crate::abi::plane::{
    ArriveIn, OnPieceIn, OutField, PlaneDriveIn, ProjectIn, RecordWrite, RefusalIn, ServeIn,
    UnitCount,
};
use crate::abi::transport::{
    AcceptIn, AdoptIn, ArrivalIn, BeginIn, ConnFacts, EmitIn, EncodeIn, FramePiece, FramerSink,
    IngestIn, ListenIn, LocateIn, ReadIn, RefuseIn, WriteIn,
};

lend! {
    // THE LIFECYCLE (`abi::mechanism::lifecycle`).
    OpenIn { list(secrets, secrets_len) -> Blob; }
    RefreshIn { list(secrets, secrets_len) -> Blob; }
    // THE AUTH KIND (`abi::auth`): `verify`'s carriers, and the host's identity buffer.
    VerifyIn { list(carrier, carrier_len) -> NamedValue; }
    IdentityBuf {
        buf(buf, buf_cap) -> u8;
        buf(groups, groups_cap) -> Span;
    }
    // THE PLANE KIND (`abi::plane`): request-path results go into host buffers.
    ArriveIn {
        list(fields, fields_len) -> Field;
        buf(units_buf, units_cap) -> UnitCount;
    }
    OnPieceIn {
        list(head_fields, head_fields_len) -> Field;
        buf(reply_buf, reply_cap) -> u8;
        buf(units_buf, units_cap) -> UnitCount;
        buf(records_buf, records_cap) -> RecordWrite;
        buf(fields_buf, fields_cap) -> OutField;
        buf(arena_buf, arena_cap) -> u8;
    }
    RefusalIn {
        buf(reply_buf, reply_cap) -> u8;
        buf(fields_buf, fields_cap) -> OutField;
        buf(arena_buf, arena_cap) -> u8;
    }
    ServeIn {
        list(fields, fields_len) -> Field;
        buf(reply_buf, reply_cap) -> u8;
        buf(fields_buf, fields_cap) -> OutField;
        buf(arena_buf, arena_cap) -> u8;
    }
    PlaneDriveIn { buf(sessions_buf, sessions_cap) -> u64; }
    ProjectIn {
        list(fields, fields_len) -> Field;
        buf(signals_buf, signals_cap) -> crate::abi::hook::SignalEntry;
        buf(arena_buf, arena_cap) -> u8;
    }
    // THE TRANSPORT KIND (`abi::transport`).
    FramerSink {
        buf(wire, wire_cap) -> u8;
        buf(frame, frame_cap) -> u8;
        buf(pieces, pieces_cap) -> FramePiece;
    }
    ListenIn { buf(addr_buf, addr_cap) -> u8; }
    AcceptIn { buf(peer_buf, peer_cap) -> u8; }
    ArrivalIn { buf(peer_buf, peer_cap) -> u8; }
    ReadIn { buf(buf, cap) -> u8; }
    WriteIn { bytes(bytes, len); }
    LocateIn {
        buf(authority_buf, authority_cap) -> u8;
        buf(name_buf, name_cap) -> u8;
        buf(alpn_buf, alpn_cap) -> u8;
    }
    BeginIn { one(facts) -> ConnFacts; }
    IngestIn { bytes(bytes, len); }
    EmitIn { bytes(bytes, len); }
    EncodeIn {
        list(fields, fields_len) -> Field;
        bytes(body, body_len);
    }
    RefuseIn { bytes(bytes, len); }
    AdoptIn {
        one(facts) -> ConnFacts;
        bytes(leftover, leftover_len);
    }
}

// THE STORE KIND (`abi::store`): the lists a write lends and the host buffers a request-path read
// fills. A nested host buffer (`store::HostBuf`, `HostBlobs`, `HostSessions`, `HostRecords`) is
// reached with `field()` first, then through its own row.
use crate::abi::store::{
    AddUsageBatchIn, AppendBatchIn, CellGrant, HostBlobs as StoreHostBlobs,
    HostBuf as StoreHostBuf, HostRecords, HostSessions, OpBlobsIn, RecordEntry, ReleaseItem,
    ReserveIn, SessionRow, SliceReleaseIn, UnitCell, UsageCell, WindowCap, WindowCapsIn,
};

lend! {
    AddUsageBatchIn { list(cells, cells_len) -> UsageCell; }
    OpBlobsIn { list(records, records_len) -> Blob; }
    AppendBatchIn { list(records, records_len) -> Blob; }
    ReserveIn {
        list(cells, cells_len) -> UnitCell;
        buf(grants, grants_cap) -> CellGrant;
    }
    SliceReleaseIn {
        list(items, items_len) -> ReleaseItem;
        buf(released, released_cap) -> u64;
    }
    WindowCapsIn { list(caps, caps_len) -> WindowCap; }
    StoreHostBuf { buf(ptr, cap) -> u8; }
    StoreHostBlobs { buf(items, items_cap) -> Blob; }
    HostSessions { buf(items, items_cap) -> SessionRow; }
    HostRecords { buf(items, items_cap) -> RecordEntry; }
}

#[cfg(test)]
#[path = "tests/lent_tests.rs"]
mod tests;
