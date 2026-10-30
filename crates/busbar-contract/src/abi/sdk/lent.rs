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

use crate::abi::mechanism::call::{AbiStr, Blob, Field, Outcome, Span};
use crate::abi::sdk::door::AbiOut;
use crate::abi::sdk::out::{Out, Scalar};

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

impl<'a, T: Scalar> Lent<'a, T> {
    /// The value, copied: a type with no pointer in it (a [`Scalar`]), so the copy names nothing
    /// the call lent.
    #[must_use]
    pub fn copied(self) -> T {
        *self.lent
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

    /// Its format ([`BLOB_ABSENT`](crate::abi::mechanism::call::BLOB_ABSENT), ...).
    #[must_use]
    pub fn fmt(self) -> u32 {
        self.lent.fmt
    }

    /// Its flags ([`BLOB_SECRET`](crate::abi::mechanism::call::BLOB_SECRET)).
    #[must_use]
    pub fn flags(self) -> u32 {
        self.lent.flags
    }

    /// Whether the host stated no payload: absent format or a NULL pointer.
    #[must_use]
    pub fn is_absent(self) -> bool {
        self.lent.fmt == crate::abi::mechanism::call::BLOB_ABSENT || self.lent.ptr.is_null()
    }
}

impl<'a> Lent<'a, AbiStr> {
    /// The string's bytes; empty when it is absent.
    #[must_use]
    pub fn bytes(self) -> &'a [u8] {
        // SAFETY: a lent string's `ptr`/`len` are the host's, valid for the call (`Lent`).
        unsafe { lent_bytes(self.lent.ptr, self.lent.len) }
    }

    /// Whether the host stated no string (NULL).
    #[must_use]
    pub fn is_absent(self) -> bool {
        self.lent.ptr.is_null()
    }

    /// The string as UTF-8; `""` when it is absent.
    ///
    /// # Errors
    /// The bytes are not UTF-8.
    pub fn as_str(self) -> Result<&'a str, Utf8Error> {
        std::str::from_utf8(self.bytes())
    }

    /// The string, owned, when the host states one: UTF-8 and not empty. An absent string, an
    /// empty one and one that is not UTF-8 each state nothing.
    #[must_use]
    pub fn stated(self) -> Option<String> {
        self.as_str()
            .ok()
            .filter(|s| !s.is_empty())
            .map(str::to_string)
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

impl<'a, T: Scalar> LentList<'a, T> {
    /// The values, as a slice: a type with no pointer in it (a [`Scalar`]).
    #[must_use]
    pub const fn as_slice(self) -> &'a [T] {
        self.items
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
    /// Write `v` at the next index while there is room; count it either way. Answers its index.
    /// The SDK's own writer for a row that may hold a pointer: only a kind SDK in this crate
    /// writes one, naming memory the same answer lent the host (a plugin writes [`Scalar`]s,
    /// through [`HostBuf::push`]).
    pub(crate) fn push_row(&mut self, v: T) -> usize {
        let at = self.asked;
        if at < self.cap {
            // SAFETY: `at < cap`, and the host lent `cap` writable `T`s at `ptr` (`new`).
            unsafe { self.ptr.add(at).write_unaligned(v) };
        }
        self.asked = self.asked.saturating_add(1);
        at
    }

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

    /// The room left, as the raw parts a HOST call writes into (`abi::sdk::io`: a carrier reads
    /// straight into the host's buffer): a pointer and how many `T`s fit there. NULL with `0` when
    /// none is left.
    pub(crate) fn room(&mut self) -> (*mut T, usize) {
        let left = self.cap.saturating_sub(self.asked);
        if left == 0 {
            return (ptr::null_mut(), 0);
        }
        // SAFETY: `asked < cap`, inside the `cap` `T`s the host lent at `ptr` (`new`).
        (unsafe { self.ptr.add(self.asked) }, left)
    }

    /// Count `n` values a host call wrote into [`HostBuf::room`] (at most what it offered).
    pub(crate) fn advance(&mut self, n: usize) {
        let left = self.cap.saturating_sub(self.asked);
        self.asked = self.asked.saturating_add(n.min(left));
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
        self.push_row(v)
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

impl HostBuf<'_, crate::abi::hook::MessageView> {
    /// Write one prompt turn at the next index while there is room; count it either way. Answers
    /// its index. `role` and `text` are spans the same call wrote into `arena`, the host's arena,
    /// so the turn points only at host memory.
    pub fn push_turn(&mut self, arena: &HostBuf<'_, u8>, role: Span, text: Span) -> usize {
        self.push_row(crate::abi::hook::MessageView {
            role: arena.str_at(role),
            text: arena.str_at(text),
        })
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

/// ANSWER A FAILED `open` WITH ITS REASON, for any kind: `text` goes into the host's lent reason
/// buffer ([`OpenIn::err_buf`]), cut on a char boundary to its capacity, and its length into the
/// `out`'s `err_len` (`err_len` picks it: `|o| &o.err_len`, a plane's `|o| &o.open.err_len`).
/// Nothing is kept on the plugin's side (no instance exists to keep it): the host copies the bytes
/// before the call returns to its caller. Answers [`Outcome::Failed`].
///
/// A plane's `open` passes its lifecycle half: `input.field(|i| &i.open)`.
pub fn open_failed<T: AbiOut>(
    input: Lent<'_, OpenIn>,
    out: &mut Out<'_, T>,
    err_len: impl FnOnce(&T) -> &usize,
    text: &str,
) -> Outcome {
    let mut buf = input.err_buf();
    let mut end = text.len().min(buf.cap());
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    buf.extend(&text.as_bytes()[..end]);
    out.set(err_len, end);
    Outcome::Failed
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

use crate::abi::auth::{
    BeginLoginIn, CompleteLoginIn, FieldSpan, FieldsIn, IdentityBuf, NamedValue, StripName,
    VerifyIn,
};
use crate::abi::hook::{
    BudgetBucketState as HookBudgetBucketState, CandidateDynamic as HookCandidateDynamic,
    CandidateStatic as HookCandidateStatic, DecideIn, MessageView as HookMessageView, NotifyIn,
    PromptView as HookPromptView, RequestView as HookRequestView, SignalEntry as HookSignalEntry,
};
use crate::abi::mechanism::lifecycle::{OpenIn, ReadyIn, RefreshIn, ValidateIn};
use crate::abi::mechanism::ticket::HostTables;
use crate::abi::plane::{
    ArriveIn, CatalogIn, OnPieceIn, OutField, PlaneCancelIn, PlaneDriveIn, PlaneOpenIn, ProjectIn,
    ProviderFacts, RecordWrite, RefusalIn, ServeIn, UnitCount,
};
use crate::abi::transport::route::{FieldPredicate, LineEntry, RouteMatch, RouteView};
use crate::abi::transport::{
    AcceptIn, AdoptIn, ArrivalIn, BeginIn, ConnFacts, DatagramLane, DatagramPath, DatagramRoute,
    Destination, DialIn, EmitIn, EncodeIn, FinishIn, FramePiece, FramerSink, FramingIn, HeadSlots,
    IngestIn, KeyingMaterial, ListenIn, LocateIn, ReadIn, RefuseIn, WriteIn,
};

/// The one list of these `in`s' pointer fields: [`lend!`] states their accessors from it, and the
/// test support its pointer and length pairs (status row 194).
macro_rules! lend_kinds_list {
    ($then:ident $($arg:tt)*) => {
        $then! {
            $($arg)*
            // THE LIFECYCLE (`abi::mechanism::lifecycle`).
            OpenIn {
                list(secrets, secrets_len) -> Blob;
                one(host) -> HostTables;
                buf(err_buf, err_cap) -> u8;
            }
            RefreshIn { list(secrets, secrets_len) -> Blob; }
            ReadyIn { one(host) -> HostTables; }
            // THE AUTH KIND (`abi::auth`): `verify`'s field lines and strip array, a login's requested
            // scopes and submitted form fields, and the host's identity buffer.
            VerifyIn {
                list(lines, lines_len) -> NamedValue;
                buf(strip, strip_cap) -> StripName;
            }
            // `fields`' head envelope (NULL unless the style needs it), and the host's field buffer and
            // field array.
            FieldsIn {
                list(headers, headers_len) -> NamedValue;
                buf(field_buf, field_buf_cap) -> u8;
                buf(fields, fields_cap) -> FieldSpan;
            }
            BeginLoginIn { list(scopes, scopes_len) -> AbiStr; }
            CompleteLoginIn { list(submitted, submitted_len) -> NamedValue; }
            IdentityBuf {
                buf(buf, buf_cap) -> u8;
                buf(groups, groups_cap) -> Span;
            }
            ValidateIn { buf(err_buf, err_cap) -> u8; }
            // THE SECRET KIND (`abi::secret`): the host's buffer a resolved value is written into.
            crate::abi::secret::ResolveIn { buf(secret_buf, secret_cap) -> u8; }
            // THE PLANE KIND (`abi::plane`): request-path results go into host buffers.
            PlaneOpenIn { list(providers, providers_len) -> ProviderFacts; }
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
                buf(records_buf, records_cap) -> RecordWrite;
            }
            ServeIn {
                list(fields, fields_len) -> Field;
                buf(reply_buf, reply_cap) -> u8;
                buf(fields_buf, fields_cap) -> OutField;
                buf(arena_buf, arena_cap) -> u8;
                buf(records_buf, records_cap) -> RecordWrite;
            }
            CatalogIn {
                list(fields, fields_len) -> Field;
                list(names, names_len) -> AbiStr;
                buf(reply_buf, reply_cap) -> u8;
                buf(fields_buf, fields_cap) -> OutField;
                buf(arena_buf, arena_cap) -> u8;
            }
            PlaneDriveIn { buf(sessions_buf, sessions_cap) -> u64; }
            PlaneCancelIn {
                buf(records_buf, records_cap) -> RecordWrite;
                buf(arena_buf, arena_cap) -> u8;
            }
            ProjectIn {
                list(fields, fields_len) -> Field;
                buf(signals_buf, signals_cap) -> crate::abi::hook::SignalEntry;
                buf(arena_buf, arena_cap) -> u8;
                buf(messages_buf, messages_cap) -> crate::abi::hook::MessageView;
            }
            // THE TRANSPORT KIND (`abi::transport`).
            FramerSink {
                buf(wire, wire_cap) -> u8;
                buf(frame, frame_cap) -> u8;
                buf(pieces, pieces_cap) -> FramePiece;
                buf(heads, heads_cap) -> HeadSlots;
            }
            ListenIn { buf(addr_buf, addr_cap) -> u8; }
            AcceptIn { buf(peer_buf, peer_cap) -> u8; }
            ArrivalIn { buf(peer_buf, peer_cap) -> u8; }
            DialIn { one(dest) -> Destination; }
            Destination {
                list(args, args_len) -> AbiStr;
                list(env, env_len) -> Field;
            }
            ReadIn { buf(buf, cap) -> u8; }
            WriteIn { bytes(bytes, len); }
            LocateIn {
                buf(authority_buf, authority_cap) -> u8;
                buf(name_buf, name_cap) -> u8;
                buf(alpn_buf, alpn_cap) -> u8;
                buf(defaults_buf, defaults_cap) -> u8;
            }
            BeginIn {
                one(facts) -> ConnFacts;
                list(fields, fields_len) -> Field;
                one(lane) -> DatagramLane;
                list(lines, lines_len) -> LineEntry;
            }
            RouteMatch { list(fields, fields_len) -> FieldPredicate; }
            IngestIn {
                bytes(bytes, len);
                one(lane) -> DatagramLane;
            }
            EmitIn {
                bytes(bytes, len);
                one(lane) -> DatagramLane;
            }
            EncodeIn {
                list(fields, fields_len) -> Field;
                bytes(body, body_len);
            }
            RefuseIn { bytes(bytes, len); }
            FinishIn {
                bytes(final_bytes, final_bytes_len);
                one(lane) -> DatagramLane;
            }
            FramingIn { one(lane) -> DatagramLane; }
            // THE DATAGRAM LANE (`abi::transport::datagram`): the keying-material item lent for the call
            // that presents it, and the host buffer the answer's routes go into.
            DatagramLane {
                one(keying) -> KeyingMaterial;
                buf(routes, routes_cap) -> DatagramRoute;
                list(paths, paths_len) -> DatagramPath;
            }
            KeyingMaterial { bytes(bytes, len); }
            AdoptIn {
                one(facts) -> ConnFacts;
                bytes(leftover, leftover_len);
            }
            // THE HOOK KIND (`abi::hook`): the views, and the host buffers `decide`/`transform` answer into.
            DecideIn {
                list(candidates, candidates_len) -> HookCandidateStatic;
                list(candidate_dynamics, candidates_len) -> HookCandidateDynamic;
                list(budget, budget_len) -> HookBudgetBucketState;
                buf(order_buf, order_cap) -> u32;
                buf(reject_message_buf, reject_message_cap) -> u8;
                buf(restrict_tags_buf, restrict_tags_cap) -> u8;
                buf(rewrite_buf, rewrite_cap) -> u8;
            }
            HookRequestView { list(signals, signals_len) -> HookSignalEntry; }
            HookCandidateStatic { list(tags, tags_len) -> AbiStr; }
            HookCandidateDynamic { list(signals, signals_len) -> HookSignalEntry; }
            HookPromptView { list(messages, messages_len) -> HookMessageView; }
            NotifyIn { list(signals, signals_len) -> HookSignalEntry; }
        }
    };
}

lend_kinds_list!(lend);

// THE STORE KIND (`abi::store`): the lists a write lends and the host buffers a request-path read
// fills. A nested host buffer (`store::HostBuf`, `HostBlobs`, `HostRecords`) is
// reached with `field()` first, then through its own row.
use crate::abi::store::{
    AddUsageBatchIn, HostBlobs as StoreHostBlobs, HostBuf as StoreHostBuf, HostRecords, OpBlobsIn,
    RecordEntry, UsageCell,
};

/// The one list of these `in`s' pointer fields: [`lend!`] states their accessors from it, and the
/// test support its pointer and length pairs (status row 194).
macro_rules! lend_store_list {
    ($then:ident $($arg:tt)*) => {
        $then! {
            $($arg)*
            AddUsageBatchIn { list(cells, cells_len) -> UsageCell; }
            OpBlobsIn { list(records, records_len) -> Blob; }
            StoreHostBuf { buf(ptr, cap) -> u8; }
            StoreHostBlobs { buf(items, items_cap) -> Blob; }
            HostRecords { buf(items, items_cap) -> RecordEntry; }
        }
    };
}

lend_store_list!(lend);

// THE EXPORT KIND (`abi::export`): the recorder snapshot `scrape` lends (families, their samples,
// their labels) and the host buffer it renders into, `check`'s instances and `serve`'s headers.
use crate::abi::export::{
    CheckIn, CheckInstance, ScrapeFamily, ScrapeIn, ScrapeLabel, ScrapeSample,
    ServeIn as ExportServeIn,
};

/// The one list of these `in`s' pointer fields: [`lend!`] states their accessors from it, and the
/// test support its pointer and length pairs (status row 194).
macro_rules! lend_export_list {
    ($then:ident $($arg:tt)*) => {
        $then! {
            $($arg)*
            ScrapeIn {
                list(families, families_len) -> ScrapeFamily;
                buf(buf, cap) -> u8;
            }
            ScrapeFamily { list(samples, samples_len) -> ScrapeSample; }
            ScrapeSample { list(labels, labels_len) -> ScrapeLabel; }
            CheckIn { list(instances, instances_len) -> CheckInstance; }
            ExportServeIn { list(headers, headers_len) -> AbiStr; }
        }
    };
}

lend_export_list!(lend);

/// THE FIELD ACCESSORS of every struct a call lends (status row 194), one per field and named after
/// it, so a [`Lent`] reads all of its struct without its `Deref` (which #1471 removes). A number or
/// a pointer-free struct (`val`) is copied; a string (`str`), a payload (`blob`) or an embedded
/// struct (`sub`) stays a `Lent` of the same call. One `val` is not pointer-free: a signal entry's
/// `value`, a union whose string arm is an `AbiStr`, is copied whole; its tag says which arm is
/// live, and the SDK reads a string arm only inside the call. A pointer field is read through its
/// [`lend!`] accessor above (a list, a buffer, loose bytes or one struct).
macro_rules! lent_fields {
    ($($ty:ty { $($how:ident $name:ident $(: $t:ty)?;)+ })+) => {$(
        // A field named `len` reads the field the host stated; its struct has no emptiness.
        #[allow(clippy::len_without_is_empty)]
        impl<'a> Lent<'a, $ty> { $( lent_fields!(@one $how $name $(: $t)?); )+ }
    )+};
    (@one val $name:ident: $t:ty) => {
        #[doc = concat!("`", stringify!($name), "`, as the host lent it.")]
        #[must_use]
        pub fn $name(self) -> $t {
            self.lent.$name
        }
    };
    (@one str $name:ident) => {
        #[doc = concat!("The string `", stringify!($name), "`, lent for the call.")]
        #[must_use]
        pub fn $name(self) -> Lent<'a, AbiStr> {
            Lent { lent: &self.lent.$name }
        }
    };
    (@one blob $name:ident) => {
        #[doc = concat!("The payload `", stringify!($name), "`, lent for the call.")]
        #[must_use]
        pub fn $name(self) -> Lent<'a, Blob> {
            Lent { lent: &self.lent.$name }
        }
    };
    (@one sub $name:ident: $t:ty) => {
        #[doc = concat!("The struct `", stringify!($name), "`, lent for the call.")]
        #[must_use]
        pub fn $name(self) -> Lent<'a, $t> {
            Lent { lent: &self.lent.$name }
        }
    };
}

/// THE LIST the field accessors are stated from, once: [`lent_fields!`] states them, and the tests
/// hold each one to the field it reads.
macro_rules! lent_field_list {
    ($then:ident) => {
        $then! {
            crate::abi::auth::BeginLoginIn {
                sub head: crate::abi::mechanism::call::InHead;
                str redirect_uri;
                str state;
                str nonce;
                str code_challenge;
                val scopes_len: usize;
            }
            crate::abi::auth::CompleteLoginIn {
                sub head: crate::abi::mechanism::call::InHead;
                blob code;
                str state;
                str redirect_uri;
                blob code_verifier;
                val submitted_len: usize;
                sub out_buf: crate::abi::auth::IdentityBuf;
                str nonce;
            }
            crate::abi::auth::IdentityBuf {
                val buf_cap: usize;
                val groups_cap: u32;
            }
            crate::abi::auth::NamedValue {
                str name;
                blob value;
            }
            crate::abi::auth::RequestFacts {
                str method;
                str authority;
                str canonical_path;
                str query;
                val timestamp: u64;
            }
            crate::abi::auth::StripName {
                val name: crate::abi::mechanism::call::Span;
                val place: u32;
            }
            crate::abi::auth::VerifyIn {
                sub head: crate::abi::mechanism::call::InHead;
                blob credential;
                val lines_len: usize;
                sub request: crate::abi::auth::RequestFacts;
                sub out_buf: crate::abi::auth::IdentityBuf;
                val point: u32;
                val conn: u64;
                val unit: u64;
                blob peer;
                blob body;
                val strip_cap: u32;
            }
            crate::abi::auth::FieldSpan {
                val name: crate::abi::mechanism::call::Span;
                val value: crate::abi::mechanism::call::Span;
                val flags: u32;
            }
            crate::abi::auth::FieldsIn {
                sub head: crate::abi::mechanism::call::InHead;
                val handle: u64;
                val mode: u32;
                val point: u32;
                sub request: crate::abi::auth::RequestFacts;
                blob caller_credential;
                val field_buf_cap: usize;
                val fields_cap: u32;
                val headers_len: usize;
                val conn: u64;
                val unit: u64;
                blob body;
            }
            crate::abi::auth::OpenOutboundIn {
                sub head: crate::abi::mechanism::call::InHead;
                str style;
                blob credential;
                blob settings;
            }
            crate::abi::auth::OutboundReadyIn {
                sub head: crate::abi::mechanism::call::InHead;
                val handle: u64;
            }
            crate::abi::auth::TargetIn {
                sub head: crate::abi::mechanism::call::InHead;
                str style;
                blob credential;
                blob settings;
                val buf_cap: usize;
            }
            crate::abi::export::CheckIn {
                sub head: crate::abi::mechanism::call::InHead;
                val phase: u32;
                val instances_len: usize;
            }
            crate::abi::export::CheckInstance {
                str name;
                blob settings;
            }
            crate::abi::export::DeliverIn {
                sub head: crate::abi::mechanism::call::InHead;
                val op_id: [u8; 16];
                val stream: u8;
                blob batch;
            }
            crate::abi::export::ScrapeFamily {
                str name;
                str help;
                str unit;
                val kind: u8;
                val samples_len: usize;
            }
            crate::abi::export::ScrapeIn {
                sub head: crate::abi::mechanism::call::InHead;
                val families_len: usize;
                val cap: usize;
            }
            crate::abi::export::ScrapeLabel {
                str key;
                str value;
            }
            crate::abi::export::ScrapeSample {
                str name;
                val labels_len: usize;
                str value;
            }
            crate::abi::export::ServeIn {
                sub head: crate::abi::mechanism::call::InHead;
                str method;
                str path;
                str query;
                val headers_len: usize;
                blob body;
            }
            crate::abi::hook::BudgetBucketState {
                str bucket_id;
                str budget_group;
                str pool;
                val spend_micros_at_current_rate: i64;
                val remaining_micros: i64;
                val window_start: u64;
                str budget_period;
                val present: u32;
            }
            crate::abi::hook::CandidateDynamic {
                val latency_ms: f64;
                val available_concurrency: u64;
                val budget_remaining: i64;
                val rate_headroom: f64;
                val signals_len: usize;
                val present: u32;
            }
            crate::abi::hook::CandidateStatic {
                val idx: u32;
                str model;
                str provider;
                val weight: u32;
                val context_max: u64;
                str tier;
                val cost_per_mtok: f64;
                val tags_len: usize;
                val present: u32;
            }
            crate::abi::hook::ConfigureIn {
                sub head: crate::abi::mechanism::call::InHead;
                val version: u64;
                blob settings;
                str name;
            }
            crate::abi::hook::DecideIn {
                sub head: crate::abi::mechanism::call::InHead;
                sub request: crate::abi::hook::RequestView;
                val candidates_len: usize;
                sub prompt: crate::abi::hook::PromptView;
                sub user: crate::abi::hook::UserView;
                val budget_remaining: i64;
                val budget_len: usize;
                val present: u32;
                val order_cap: usize;
                val reject_message_cap: usize;
                val restrict_tags_cap: usize;
                val rewrite_cap: usize;
            }
            crate::abi::hook::MessageView {
                str role;
                str text;
            }
            crate::abi::hook::NotifyIn {
                sub head: crate::abi::mechanism::call::InHead;
                sub stage: crate::abi::hook::StageView;
                val signals_len: usize;
                sub prompt: crate::abi::hook::PromptView;
                val present: u32;
            }
            crate::abi::hook::PromptView {
                str system;
                val message_count: u64;
                blob body;
                val messages_len: usize;
            }
            crate::abi::hook::RequestView {
                val request_id: u64;
                str pool;
                str ingress_dialect;
                val message_count: u64;
                val total_chars: u64;
                val max_tokens: u32;
                val flags: u32;
                val signals_len: usize;
                blob session;
            }
            crate::abi::hook::ServeIn {
                sub head: crate::abi::mechanism::call::InHead;
                str method;
                str path;
                str query;
                val headers_len: usize;
                blob body;
            }
            crate::abi::hook::SignalEntry {
                val id: u32;
                val tag: u32;
                val value: crate::abi::hook::SignalValue;
            }
            crate::abi::hook::StageView {
                val request_id: u64;
                str pool;
                str ingress_dialect;
                val message_count: u64;
                val total_chars: u64;
                val remaining_candidates: u64;
                str model;
                str previous_failure;
                str outcome;
                val max_tokens: u32;
                val flags: u32;
                val at: u32;
                val attempt_number: u32;
                val status: u16;
                val stage_present: u32;
            }
            crate::abi::hook::UserView {
                str key_id;
                str key_name;
                str user;
            }
            crate::abi::mechanism::call::Field {
                str name;
                str value;
            }
            crate::abi::mechanism::call::InHead {
                val size: u32;
                val op: u32;
                val flags: u32;
                val deadline_class: u8;
                val host: crate::abi::mechanism::ticket::HostCtx;
                val ticket: crate::abi::mechanism::ticket::Ticket;
                val deadline_ns: u64;
                val trace_id: [u8; 16];
                val parent_span_id: u64;
                blob extensions;
            }
            crate::abi::mechanism::call::Span {
                val offset: u32;
                val len: u32;
            }
            crate::abi::mechanism::lifecycle::CancelIn {
                sub head: crate::abi::mechanism::call::InHead;
                val ticket: crate::abi::mechanism::ticket::Ticket;
            }
            crate::abi::mechanism::lifecycle::DriveIn {
                sub head: crate::abi::mechanism::call::InHead;
                val driver: crate::abi::mechanism::ticket::Ticket;
            }
            crate::abi::mechanism::lifecycle::GenIn {
                sub head: crate::abi::mechanism::call::InHead;
                val generation: u64;
            }
            crate::abi::mechanism::lifecycle::OpenIn {
                sub head: crate::abi::mechanism::call::InHead;
                blob settings;
                val secrets_len: usize;
                val generation: u64;
                val err_cap: usize;
            }
            crate::abi::mechanism::lifecycle::ReadyIn {
                sub head: crate::abi::mechanism::call::InHead;
            }
            crate::abi::mechanism::lifecycle::RefreshIn {
                sub head: crate::abi::mechanism::call::InHead;
                val generation: u64;
                blob settings;
                val secrets_len: usize;
            }
            crate::abi::mechanism::lifecycle::ReleaseIn {
                sub head: crate::abi::mechanism::call::InHead;
                val lease: u64;
            }
            crate::abi::mechanism::lifecycle::TickIn {
                sub head: crate::abi::mechanism::call::InHead;
                val now_ns: u64;
            }
            crate::abi::mechanism::lifecycle::ValidateIn {
                sub head: crate::abi::mechanism::call::InHead;
                blob settings;
                val err_cap: usize;
            }
            crate::abi::mechanism::ticket::HostCtx {
                val handle: u64;
            }
            crate::abi::mechanism::ticket::Ticket {
                val slot: u32;
                val generation: u32;
            }
            crate::abi::plane::ArriveIn {
                sub head: crate::abi::mechanism::call::InHead;
                val unit: u64;
                val claim: u32;
                str target;
                val fields_len: usize;
                blob body;
                val units_cap: usize;
                str method;
            }
            crate::abi::plane::CatalogIn {
                sub head: crate::abi::mechanism::call::InHead;
                str method;
                str target;
                val fields_len: usize;
                val names_len: usize;
                val reply_cap: usize;
                val fields_cap: usize;
                val arena_cap: usize;
            }
            crate::abi::plane::OnPieceIn {
                sub head: crate::abi::mechanism::call::InHead;
                val unit: u64;
                val from: u32;
                val flags: u32;
                val stream: u64;
                blob bytes;
                val status_code: u32;
                val status_class: u32;
                val reply_cap: usize;
                val units_cap: usize;
                val records_cap: usize;
                val fields_cap: usize;
                val arena_cap: usize;
                str member;
                val attempt_no: u32;
                str pool;
                str caller_ref;
                val claim: u32;
                val dialect: u32;
                val head_fields_len: usize;
                val passthrough: u32;
                val reason: u32;
            }
            crate::abi::plane::OutField {
                val name: crate::abi::mechanism::call::Span;
                val value: crate::abi::mechanism::call::Span;
            }
            crate::abi::plane::PlaneCancelIn {
                sub cancel: crate::abi::mechanism::lifecycle::CancelIn;
                val records_cap: usize;
                val arena_cap: usize;
                val unit: u64;
            }
            crate::abi::plane::PlaneDriveIn {
                sub drive: crate::abi::mechanism::lifecycle::DriveIn;
                val sessions_cap: usize;
            }
            crate::abi::plane::PlaneOpenIn {
                sub open: crate::abi::mechanism::lifecycle::OpenIn;
                str public_url;
                blob owned;
                val providers_len: usize;
            }
            crate::abi::plane::ProjectIn {
                sub head: crate::abi::mechanism::call::InHead;
                val claim: u32;
                str target;
                val fields_len: usize;
                blob body;
                val signals_cap: usize;
                val arena_cap: usize;
                blob rewrite;
                val messages_cap: usize;
                val unit: u64;
            }
            crate::abi::plane::ProviderFacts {
                str name;
                str protocol;
                blob error_map;
            }
            crate::abi::plane::RecordWrite {
                val kind: u32;
                val op: u32;
                val key: crate::abi::mechanism::call::Span;
                val value: crate::abi::mechanism::call::Span;
            }
            crate::abi::plane::RefusalIn {
                sub head: crate::abi::mechanism::call::InHead;
                val cause: u32;
                val status: u32;
                val dialect: u32;
                val reason: u32;
                str text;
                val reply_cap: usize;
                val fields_cap: usize;
                val arena_cap: usize;
                val unit: u64;
                val plane_code: u32;
                val retry_after_s: u32;
                str target;
                val records_cap: usize;
                str hook;
                val trust: u32;
                val _trust_reserved: u32;
            }
            crate::abi::plane::ServeIn {
                sub head: crate::abi::mechanism::call::InHead;
                val route: u32;
                str target;
                val fields_len: usize;
                blob body;
                val reply_cap: usize;
                val fields_cap: usize;
                val arena_cap: usize;
                val records_cap: usize;
            }
            crate::abi::plane::UnitCount {
                val class: u32;
                val source: u32;
                val amount: u64;
            }
            crate::abi::secret::CheckIn {
                sub head: crate::abi::mechanism::call::InHead;
                blob settings;
                val err_cap: usize;
            }
            crate::abi::secret::ResolveIn {
                sub head: crate::abi::mechanism::call::InHead;
                blob settings;
                val secret_cap: usize;
            }
            crate::abi::store::ledger::HostRecords {
                val items_cap: usize;
                sub bytes: crate::abi::store::HostBuf;
            }
            crate::abi::store::ledger::RecordEntry {
                blob key;
                blob value;
            }
            crate::abi::store::ledger::RecordGetIn {
                sub head: crate::abi::mechanism::call::InHead;
                str schema;
                blob key;
                sub value: crate::abi::store::HostBuf;
            }
            crate::abi::store::ledger::RecordPutIn {
                sub head: crate::abi::mechanism::call::InHead;
                str schema;
                blob key;
                blob value;
            }
            crate::abi::store::ledger::RecordScanIn {
                sub head: crate::abi::mechanism::call::InHead;
                str schema;
                blob prefix;
                val limit: u32;
                sub out: crate::abi::store::ledger::HostRecords;
            }
            crate::abi::store::HostBlobs {
                val items_cap: usize;
                sub bytes: crate::abi::store::HostBuf;
            }
            crate::abi::store::HostBuf {
                val cap: usize;
            }
            crate::abi::store::money::AddUsageBatchIn {
                sub head: crate::abi::mechanism::call::InHead;
                val op_id: crate::abi::store::OpId;
                val cells_len: usize;
            }
            crate::abi::store::money::OpBlobsIn {
                sub head: crate::abi::mechanism::call::InHead;
                val op_id: crate::abi::store::OpId;
                val records_len: usize;
            }
            crate::abi::store::money::UsageCell {
                str bucket;
                val window_start: u64;
                blob delta;
            }
            crate::abi::store::plane::AppendPlaneRecordIn {
                sub head: crate::abi::mechanism::call::InHead;
                val op_id: crate::abi::store::OpId;
                sub record: crate::abi::store::plane::PlaneRecordRow;
            }
            crate::abi::store::plane::GetPlaneRecordIn {
                sub head: crate::abi::mechanism::call::InHead;
                str kind;
                str id;
                sub body: crate::abi::store::HostBuf;
            }
            crate::abi::store::plane::KindBeforeIn {
                sub head: crate::abi::mechanism::call::InHead;
                str kind;
                val before: u64;
            }
            crate::abi::store::plane::ListPlaneRecordsIn {
                sub head: crate::abi::mechanism::call::InHead;
                str kind;
                val selector: u32;
                str parent;
                sub out: crate::abi::store::HostBlobs;
            }
            crate::abi::store::plane::PlaneRecordRow {
                str kind;
                str id;
                str parent;
                val seq: u64;
                val ts: u64;
                val disposition: u32;
                blob body;
            }
            crate::abi::store::plane::TokenIn {
                sub head: crate::abi::mechanism::call::InHead;
                str kind;
                str token;
                val expires_at: u64;
                val now: u64;
            }
            crate::abi::store::plane::UpsertPlaneRecordIn {
                sub head: crate::abi::mechanism::call::InHead;
                sub record: crate::abi::store::plane::PlaneRecordRow;
            }
            crate::abi::store::records::BlobIn {
                sub head: crate::abi::mechanism::call::InHead;
                blob record;
            }
            crate::abi::store::records::IdIn {
                sub head: crate::abi::mechanism::call::InHead;
                str id;
            }
            crate::abi::store::records::IdReasonIn {
                sub head: crate::abi::mechanism::call::InHead;
                str id;
                str reason;
            }
            crate::abi::store::records::KeyWithCredentialIn {
                sub head: crate::abi::mechanism::call::InHead;
                blob key;
                blob credential;
            }
            crate::abi::store::records::KindIdIn {
                sub head: crate::abi::mechanism::call::InHead;
                str kind;
                str id;
            }
            crate::abi::store::records::PutUsageIn {
                sub head: crate::abi::mechanism::call::InHead;
                str bucket;
                val window_start: u64;
                blob ledger;
            }
            crate::abi::store::records::U64In {
                sub head: crate::abi::mechanism::call::InHead;
                val value: u64;
            }
            crate::abi::store::records::WindowIn {
                sub head: crate::abi::mechanism::call::InHead;
                str bucket;
                val window_start: u64;
            }
            crate::abi::transport::datagram::DatagramLane {
                val size: u32;
                val lane: u32;
                val path: u32;
                val bound: u32;
                str path_addr;
                str local_addr;
                val verified: u32;
                val routes_cap: usize;
                val paths_len: usize;
            }
            crate::abi::transport::datagram::DatagramPath {
                val path: u32;
                str addr;
            }
            crate::abi::transport::datagram::DatagramRoute {
                val offset: u64;
                val len: u64;
                val path: u32;
                val lane: u32;
            }
            crate::abi::transport::datagram::KeyingMaterial {
                val size: u32;
                val profile: u32;
                val len: usize;
            }
            crate::abi::transport::AcceptIn {
                sub head: crate::abi::mechanism::call::InHead;
                val listener: u64;
                val peer_cap: usize;
            }
            crate::abi::transport::AdoptIn {
                sub head: crate::abi::mechanism::call::InHead;
                val side: u32;
                val leftover_len: usize;
                sub sink: crate::abi::transport::FramerSink;
            }
            crate::abi::transport::ArrivalIn {
                sub head: crate::abi::mechanism::call::InHead;
                val conn: u64;
                val peer_cap: usize;
            }
            crate::abi::transport::BeginIn {
                sub head: crate::abi::mechanism::call::InHead;
                val side: u32;
                str target;
                sub sink: crate::abi::transport::FramerSink;
                val fields_len: usize;
            }
            crate::abi::transport::ConnFacts {
                val size: u32;
                str offered_name;
                str agreed_protocol;
                str peer_subject;
                str peer_issuer;
                str peer_fingerprint;
                str claim;
                str local_certificate;
            }
            crate::abi::transport::ConnIn {
                sub head: crate::abi::mechanism::call::InHead;
                val conn: u64;
            }
            crate::abi::transport::Destination {
                val kind: u32;
                str authority;
                str program;
                val args_len: usize;
                val env_len: usize;
            }
            crate::abi::transport::DialIn {
                sub head: crate::abi::mechanism::call::InHead;
                val supervision_key: u64;
            }
            crate::abi::transport::EmitIn {
                sub head: crate::abi::mechanism::call::InHead;
                val framing: u64;
                val stream: u64;
                val len: usize;
                val end_of_frame: u32;
                val flags: u32;
                sub sink: crate::abi::transport::FramerSink;
                val deadline_ns: u64;
                val status: u32;
                val _status_reserved: u32;
            }
            crate::abi::transport::EncodeIn {
                sub head: crate::abi::mechanism::call::InHead;
                val fields_len: usize;
                val body_len: usize;
                sub sink: crate::abi::transport::FramerSink;
                str method;
                str target;
            }
            crate::abi::transport::FinishIn {
                sub head: crate::abi::mechanism::call::InHead;
                val framing: u64;
                val reason: u32;
                sub sink: crate::abi::transport::FramerSink;
                val final_status: u32;
                val _final_reserved: u32;
                val final_message: crate::abi::mechanism::call::Span;
                val final_details: crate::abi::mechanism::call::Span;
                val final_bytes_len: usize;
            }
            crate::abi::transport::FramePiece {
                val stream: u64;
                val offset: u64;
                val len: u64;
                val code: u32;
                val status_class: u8;
                val fault: u8;
                val flags: u16;
                val retry_after_secs: u64;
                val declared_len: u64;
            }
            crate::abi::transport::FrameSpan {
                val offset: u64;
                val len: u64;
            }
            crate::abi::transport::FramerSink {
                val wire_cap: usize;
                val frame_cap: usize;
                val pieces_cap: usize;
                val now_monotonic_ns: u64;
                val now_unix_ns: u64;
                val heads_cap: usize;
            }
            crate::abi::transport::FramingIn {
                sub head: crate::abi::mechanism::call::InHead;
                val framing: u64;
                sub sink: crate::abi::transport::FramerSink;
            }
            crate::abi::transport::HeadSlots {
                val stream: u64;
                val method: crate::abi::transport::FrameSpan;
                val target: crate::abi::transport::FrameSpan;
                val authority: crate::abi::transport::FrameSpan;
                val reason: crate::abi::transport::FrameSpan;
            }
            crate::abi::transport::IngestIn {
                sub head: crate::abi::mechanism::call::InHead;
                val framing: u64;
                val len: usize;
                val end: u32;
                sub sink: crate::abi::transport::FramerSink;
            }
            crate::abi::transport::ListenIn {
                sub head: crate::abi::mechanism::call::InHead;
                str bind;
                val addr_cap: usize;
            }
            crate::abi::transport::LocateIn {
                sub head: crate::abi::mechanism::call::InHead;
                str target;
                val authority_cap: usize;
                val name_cap: usize;
                val alpn_cap: usize;
                val accept: u32;
                val _accept_reserved: u32;
                val defaults_cap: usize;
            }
            crate::abi::transport::ReadIn {
                sub head: crate::abi::mechanism::call::InHead;
                val conn: u64;
                val cap: usize;
            }
            crate::abi::transport::RefuseIn {
                sub head: crate::abi::mechanism::call::InHead;
                val framing: u64;
                val stream: u64;
                val has_stream: u32;
                val len: usize;
                sub sink: crate::abi::transport::FramerSink;
                val status: u32;
                val head_sent: u32;
            }
            crate::abi::transport::ShutIn {
                sub head: crate::abi::mechanism::call::InHead;
                val conn: u64;
                val reason: u32;
            }
            crate::abi::transport::WriteIn {
                sub head: crate::abi::mechanism::call::InHead;
                val conn: u64;
                val len: usize;
                val flags: u32;
            }
        }
    };
}

lent_field_list!(lent_fields);

#[cfg(test)]
#[path = "tests/lent_tests.rs"]
mod tests;

impl<'a> Lent<'a, LineEntry> {
    /// The line's route as the route vocabulary reads it ([`RouteView`]): what an accepting
    /// transport matches a decoded head against, in table order (`path_and_fields_match`, then
    /// `admits` for the method). `None` when the host lent a path or a predicate name that is not
    /// UTF-8.
    #[must_use]
    pub fn route_view(self) -> Option<RouteView<'a>> {
        let route = self.field(|l| &l.route);
        let path = route.field(|r| &r.path).as_str().ok()?;
        let fields = route
            .fields()
            .iter()
            .map(|p| {
                let name = p.field(|f| &f.name).as_str().ok()?;
                Some((p.get().op, name, p.field(|f| &f.value).bytes()))
            })
            .collect::<Option<Vec<_>>>()?;
        let r = route.get();
        Some(RouteView {
            methods: r.methods,
            path_form: r.path_form,
            path,
            fields,
            rung: r.rung,
        })
    }
}

#[cfg(test)]
#[path = "tests/expand_tests.rs"]
mod expand_tests;
