// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A SLOT'S `out`, WRITTEN BY THE SDK (THE DESIGN, plugins: a plugin crate stays
//! `#![forbid(unsafe_code)]`; memory a plugin returns stays valid for as long as the ABI says).
//! A [`SafeSlot`](crate::abi::sdk::safe::SafeSlot) body is handed its `out` as an [`Out`], never as
//! `&mut`: it READS any field, SETS a pointer-free field ([`Scalar`]) of its kind's own directly
//! (never one of the [`OutHead`]'s: its lengths and lease have their writers), and hands every
//! pointer-bearing field — a string, a blob, a list, a published value, a view into a host buffer —
//! to an SDK writer that takes the memory it points into from a place that outlives the answer:
//!
//! * [`Out::fail`] — the answer's error text, kept where the answer's instance keeps it or, with no
//!   instance yet (`validate`, `open`), written into the host's lent reason buffer;
//! * [`Out::lease`] / [`Out::lease_secret`] — owned bytes, held under a lease until `release`;
//! * [`Out::text`] / [`Out::list`] — `'static` strings and lists;
//! * [`Out::publish`] — generation data the SDK owns until that generation's `retire`;
//! * [`Out::host_str`] / [`Out::host_list`] — a view into a host buffer lent for the call.
//!
//! So safe code cannot store a pointer the host would read after its memory is gone.
//!
//! WHERE AN ANSWER'S OWN MEMORY LIVES. Nothing here is per thread or per process: the SDK holds no
//! `static` and no `thread_local` (the ABI's shared mechanism: memory a plugin returns is
//! plugin-owned and valid until that plugin's next refresh generation; no allocation on the hot
//! path). What an answer names that the SDK allocated — a failure's owned text, the envelope's
//! metrics and diagnostics — is kept by THE INSTANCE THAT ANSWERED ([`Kept`], in the SDK's instance
//! box), by the full ticket identity. A new crossing retires only its own preceding reply; another
//! ticket cannot evict it. Recycled host slots reuse storage after the prior generation ended.
//! Unticketed calls use their actual crossing thread. A call with no instance yet
//! (`validate`, `open`) writes its owned text into the reason buffer the host lent it
//! (`ValidateIn::err_buf`, `OpenIn::err_buf`), reports no envelope, and, only when the host lent
//! no buffer, answers a fixed text.
//!
//! ```compile_fail,E0277
//! use busbar_contract::abi::mechanism::call::{AbiStr, OutHead};
//! fn body(mut out: busbar_contract::abi::sdk::Out<'_, OutHead>, s: &String) {
//!     // An `AbiStr` is not a `Scalar`: its pointer would outlive `s`.
//!     out.set(|o| &o.error, AbiStr { ptr: s.as_ptr(), len: s.len() });
//! }
//! ```
//!
//! ```compile_fail,E0277
//! use busbar_contract::abi::plane::{PlaneOpenOut, PlaneSnapshot};
//! fn body(mut out: busbar_contract::abi::sdk::Out<'_, PlaneOpenOut>, snap: &PlaneSnapshot) {
//!     out.set(|o| &o.snapshot, std::ptr::from_ref(snap)); // a raw pointer is not a `Scalar`
//! }
//! ```
//!
//! ```compile_fail,E0277
//! use busbar_contract::abi::mechanism::call::Blob;
//! use busbar_contract::abi::export::StatusOut;
//! fn body(mut out: busbar_contract::abi::sdk::Out<'_, StatusOut>, b: &[u8]) {
//!     out.set(|o| &o.status, Blob { ptr: b.as_ptr(), len: b.len(), fmt: 1, flags: 0 });
//! }
//! ```
//!
//! ```compile_fail,E0594
//! use busbar_contract::abi::mechanism::call::{AbiStr, OutHead};
//! fn body(out: busbar_contract::abi::sdk::Out<'_, OutHead>, s: &'static str) {
//!     out.get().error = AbiStr { ptr: s.as_ptr(), len: s.len() }; // `get` is read-only
//! }
//! ```

use std::borrow::Cow;
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::mem::size_of;
use std::ptr;
use std::sync::atomic::{AtomicPtr, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};

use crate::abi::mechanism::call::{
    AbiStr, Blob, Diag, MetricEntry, OutHead, Outcome, MAX_ENVELOPE_ENTRIES,
};
use crate::abi::mechanism::lifecycle::OpenOut;
use crate::abi::mechanism::ticket::Ticket;
use crate::abi::sdk::door::AbiOut;
use crate::abi::sdk::generation::Gen;
use crate::abi::sdk::lent::HostBuf;
use crate::abi::sdk::life::{Leases, Refusal};
use crate::abi::sdk::publish::{Generations, Publish};

/// The former FIFO size, retained as a source-compatible constant. Answers are now retained by

pub const KEPT_RING: usize = 4096;

/// A reply's full identity. Unticketed replies belong to the actual crossing thread, not a
/// worker that submitted work to that thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct ReplyKey {
    ticket: Ticket,
    thread: Option<std::thread::ThreadId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum ReplySlot {
    Ticket(u32),
    Thread(std::thread::ThreadId),
}

impl ReplyKey {
    pub(crate) fn of(ticket: Ticket) -> Self {
        Self {
            ticket,
            thread: ticket.is_none().then(|| std::thread::current().id()),
        }
    }

    fn slot(self) -> ReplySlot {
        match self.thread {
            Some(thread) => ReplySlot::Thread(thread),
            None => ReplySlot::Ticket(self.ticket.slot),
        }
    }
}

/// Storage indexed by host slot, retaining its full ticket identity. A host cannot

pub(crate) struct Replies<T>(Mutex<HashMap<ReplySlot, (ReplyKey, T)>>);

impl<T> Default for Replies<T> {
    fn default() -> Self {
        Self(Mutex::new(HashMap::new()))
    }
}

impl<T> Replies<T> {
    pub(crate) fn take(&self, key: ReplyKey) -> Option<T> {
        let retired = lock(&self.0).remove(&key.slot());
        retired.map(|(_, value)| value)
    }

    pub(crate) fn insert(&self, key: ReplyKey, value: T) {
        let retired = lock(&self.0).insert(key.slot(), (key, value));
        drop(retired);
    }

    #[cfg(test)]
    pub(crate) fn with<R>(&self, key: ReplyKey, f: impl FnOnce(&T) -> R) -> Option<R> {
        let held = lock(&self.0);
        held.get(&key.slot())
            .filter(|(stored, _)| *stored == key)
            .map(|(_, value)| f(value))
    }
}

/// A failure's owned text with no instance to keep it and no reason buffer lent by the host: the

pub const NO_REASON_BUFFER: &str =
    "the plugin's reason was not kept: the host lent no reason buffer";

/// THE ENVELOPE ONE SAFE CALL REPORTS (#85): the metrics and declared diagnostics its body added
/// with [`Out::metric`] and [`Out::diag`], with the texts the diagnostics point into.
#[derive(Default)]
pub(crate) struct Report {
    metrics: Vec<MetricEntry>,
    diags: Vec<Diag>,
    texts: Vec<Box<str>>,
    owned: Vec<Box<str>>,
}

// SAFETY: a `Report` owns everything its entries point to (`label_vals` is always NULL; a `Diag`'s
// text is one of its own `texts`), and it is only reached through the instance's lock.
unsafe impl Send for Report {}

impl Report {
    pub(crate) fn has_envelope(&self) -> bool {
        !self.metrics.is_empty() || !self.diags.is_empty()
    }

    fn clear(&mut self) {
        self.metrics.clear();
        self.diags.clear();
        self.texts.clear();
        self.owned.clear();
    }
}

/// What a call's body reported, held by the call until it returns: the SDK then hands it to the

pub(crate) type Reporting = Cell<Option<Box<Report>>>;

/// WHAT ONE INSTANCE'S ANSWERS NAME, kept by the instance (the SDK's instance box,
/// `abi::sdk::safe`): each ticket's owned texts and reported envelope, until its next crossing or
/// the host recycles the ticket's slot. Dropped with the instance.
#[derive(Default)]
pub(crate) struct Kept {
    replies: Replies<Box<Report>>,
    routes: Routes,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Kept {
    /// Start the next crossing on this ticket (or this actual unticketed thread). Retired owners

    pub(crate) fn begin(&self, key: ReplyKey) -> Option<Box<Report>> {
        self.replies.take(key).map(|mut report| {
            report.clear();
            report
        })
    }

    /// An empty envelope for a call that did not inherit one from its preceding crossing.
    fn report(&self) -> Box<Report> {
        Box::default()
    }

    /// Keep a returned call's envelope (its entries do not move: they live on the heap).
    pub(crate) fn keep(&self, key: ReplyKey, report: Box<Report>) {
        self.replies.insert(key, report);
    }

    /// How many texts and envelopes the instance holds.
    #[cfg(test)]
    pub(crate) fn held(&self) -> (usize, usize) {
        let held = lock(&self.replies.0);
        (
            held.values().map(|(_, reply)| reply.owned.len()).sum(),
            held.values()
                .filter(|(_, reply)| reply.has_envelope())
                .count(),
        )
    }
}

/// How many distinct route entry names one instance keeps for its lifetime. A plane names the

pub(crate) const KEPT_ROUTES: usize = 64;

/// THE ROUTE NAMES AN INSTANCE HAS ANSWERED, each kept once for the instance's lifetime: a slot is

pub(crate) struct Routes {
    slots: [AtomicPtr<Box<str>>; KEPT_ROUTES],
}

impl Default for Routes {
    fn default() -> Self {
        Self {
            slots: [const { AtomicPtr::new(ptr::null_mut()) }; KEPT_ROUTES],
        }
    }
}

impl Routes {
    /// The kept copy of `entry`, keeping it in a free slot if no slot holds it; `None` when every

    fn name(&self, entry: &str) -> Option<AbiStr> {
        for slot in &self.slots {
            let mut at = slot.load(Ordering::Acquire);
            if at.is_null() {
                let fresh = Box::into_raw(Box::new(Box::<str>::from(entry)));
                match slot.compare_exchange(
                    ptr::null_mut(),
                    fresh,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => at = fresh,
                    Err(won) => {
                        // SAFETY: `fresh` was made above and never published.
                        drop(unsafe { Box::from_raw(fresh) });
                        at = won;
                    }
                }
            }
            // SAFETY: a non-NULL slot holds a box published by `compare_exchange` and freed only
            // when the table drops, after every call on the instance has returned.
            let name: &str = unsafe { &*at };
            if name == entry {
                return Some(AbiStr {
                    ptr: name.as_ptr(),
                    len: name.len(),
                });
            }
        }
        None
    }
}

impl Drop for Routes {
    fn drop(&mut self) {
        for slot in &mut self.slots {
            let at = *slot.get_mut();
            if !at.is_null() {
                // SAFETY: published once by `name` and owned by this table alone.
                drop(unsafe { Box::from_raw(at) });
            }
        }
    }
}

/// The host's reason buffer lent to an instance-less call (`validate`, `open`): its address and
/// capacity, and whether the `out` is an `open`'s (which states the length in `err_len`).
#[derive(Debug, Clone, Copy)]
pub(crate) struct Reason {
    pub(crate) buf: *mut u8,
    pub(crate) cap: usize,
    pub(crate) open: bool,
}

/// WHETHER WHAT AN ANSWER LEASED OR PUBLISHED FROM IS STILL THERE (C1 M5 b). [`Leases`] and
/// [`Generations`] each carry one; a writer that names memory they hold records it in the call's
/// [`Holders`], and the SDK answers FAULT, so the host reads nothing, when one of them is gone by
/// the time the body returns: a table the body made for itself and dropped would have freed the
/// memory the host is about to read.
/// Its token is made at the first writer that needs it, so a table is still built in a `const`
/// context.
#[derive(Default)]
pub(crate) struct Alive(Mutex<Option<Arc<()>>>);

impl Alive {
    pub(crate) const fn new() -> Self {
        Self(Mutex::new(None))
    }

    fn token(&self) -> Weak<()> {
        let mut held = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        Arc::downgrade(held.get_or_insert_with(|| Arc::new(())))
    }
}

/// What one call's writers leased or published from (their [`Alive`] tokens), checked when its

pub(crate) type Holders = RefCell<Vec<Weak<()>>>;

/// Whether every table the call's answer names memory from outlived its body.
pub(crate) fn holders_live(holders: &Holders) -> bool {
    holders.borrow().iter().all(|w| w.strong_count() > 0)
}

/// How many pointer-bearing fields one `out` records exactly; past that, the last mark widens to

const MARKS: usize = 16;

/// A value with no pointer in it, anywhere: a safe body may set it into an `out` directly.
///
/// # Safety
/// The implementor holds no pointer, reference or union reaching one, at any depth.
pub unsafe trait Scalar: Copy + 'static {}

macro_rules! scalar {
    ($($t:ty),* $(,)?) => {$(
        // SAFETY: a plain number (or an array of them); no pointer.
        unsafe impl Scalar for $t {}
    )*};
}
scalar!(u8, u16, u32, u64, usize, i8, i16, i32, i64, isize, f32, f64);
// SAFETY: an array of pointer-free values holds no pointer.
unsafe impl<T: Scalar, const N: usize> Scalar for [T; N] {}
// SAFETY (all below): fixed-layout ABI structs of integers only.
unsafe impl Scalar for crate::abi::mechanism::call::RawOutcome {}
unsafe impl Scalar for crate::abi::mechanism::ticket::Ticket {}
unsafe impl Scalar for crate::abi::mechanism::call::Span {}
unsafe impl Scalar for crate::abi::auth::StripName {}
unsafe impl Scalar for crate::abi::auth::FieldSpan {}
unsafe impl Scalar for crate::abi::plane::UnitCount {}
unsafe impl Scalar for crate::abi::plane::RecordWrite {}
unsafe impl Scalar for crate::abi::plane::OutField {}
unsafe impl Scalar for crate::abi::transport::FramePiece {}
unsafe impl Scalar for crate::abi::transport::FramerYield {}
unsafe impl Scalar for crate::abi::transport::HeadSlots {}
unsafe impl Scalar for crate::abi::transport::FrameSpan {}
unsafe impl Scalar for crate::abi::transport::DatagramRoute {}
unsafe impl Scalar for crate::abi::transport::RendezvousTerms {}
unsafe impl Scalar for crate::abi::transport::DatagramYield {}

/// A slot's `out`, as a safe body is handed it: read anything, set scalars, and hand pointers to

pub struct Out<'a, T> {
    out: &'a mut T,
    /// The answering instance's memory; `None` with no instance yet.
    kept: Option<&'a Kept>,
    /// Where this call's envelope is built; `None` when there is no instance to keep it.
    reporting: Option<&'a Reporting>,
    /// The host's lent reason buffer, on an instance-less call that was lent one.
    reason: Option<Reason>,
    /// The tables this call's answer leased or published from; `None` in the unit tests.
    holders: Option<&'a Holders>,
    /// The byte ranges of the `out` an SDK writer set to name memory (a pointer and the length
    marks: [(usize, usize); MARKS],
    marked: usize,
}

impl<T> std::fmt::Debug for Out<'_, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Out")
            .field("instance", &self.kept.is_some())
            .field("reason", &self.reason)
            .finish_non_exhaustive()
    }
}

impl Out<'_, crate::abi::plane::ArriveOut> {
    /// THE ROUTE a READY arrival names: `class`

    pub fn route(&mut self, class: u8, entry: &str) {
        self.set(|o| &o.route, class);
        if let Some(kept) = self.kept {
            let name = kept
                .routes
                .name(entry)
                .unwrap_or_else(|| self.owned_text(entry.to_string()));
            self.put(|o| &o.pool, name);
        }
    }

    /// The unit is the plane's own to answer ([`crate::abi::plane::ROUTE_LOCAL`]): it names

    pub fn local(&mut self) {
        self.set(|o| &o.route, crate::abi::plane::ROUTE_LOCAL);
    }

    /// THE PLANE'S OWN ANSWER IS AN ADMITTED CALL ([`crate::abi::plane::ROUTE_COUNTED`], on a

    pub fn counted(&mut self) {
        let flags = self.get().route_flags | crate::abi::plane::ROUTE_COUNTED;
        self.set(|o| &o.route_flags, flags);
    }

    /// THE UNIT'S OPERATION IS PERFORMED AT MOST ONCE ([`crate::abi::plane::ROUTE_ONCE`]): a member

    pub fn once(&mut self) {
        let flags = self.get().route_flags | crate::abi::plane::ROUTE_ONCE;
        self.set(|o| &o.route_flags, flags);
    }

    /// THE UNIT IS SERVED AS A DUPLEX SESSION ([`crate::abi::plane::ROUTE_SESSION`]): its pieces

    pub fn session(&mut self) {
        let flags = self.get().route_flags | crate::abi::plane::ROUTE_SESSION;
        self.set(|o| &o.route_flags, flags);
    }

    /// THE CALLER ASKED FOR ITS ANSWER STREAMED ([`crate::abi::plane::ROUTE_STREAM`]): the kernel

    pub fn stream(&mut self) {
        let flags = self.get().route_flags | crate::abi::plane::ROUTE_STREAM;
        self.set(|o| &o.route_flags, flags);
    }

    /// THE UNIT'S STICKY-ROUTING KEY ([`crate::abi::plane::ArriveOut::affinity`]), opaque to the

    pub fn affinity(&mut self, key: &str) {
        if key.is_empty() {
            return;
        }
        if self.kept.is_some() {
            let key = self.owned_text(key.to_string());
            self.put(|o| &o.affinity, key);
        }
    }

    /// THE UNIT'S TRUST FACTS ([`crate::abi::plane::ArriveOut::trust_counterparty`], and the item

    pub fn trust(&mut self, counterparty: &str, item: Option<&str>, digest: Option<&str>) {
        if counterparty.is_empty() {
            return;
        }
        if self.kept.is_some() {
            let c = self.owned_text(counterparty.to_string());
            self.put(|o| &o.trust_counterparty, c);
            if let Some(item) = item.filter(|s| !s.is_empty()) {
                let i = self.owned_text(item.to_string());
                self.put(|o| &o.trust_item, i);
            }
            if let Some(digest) = digest.filter(|s| !s.is_empty()) {
                let d = self.owned_text(digest.to_string());
                self.put(|o| &o.trust_digest, d);
            }
        }
    }
}

impl Out<'_, crate::abi::plane::ServeOut> {
    /// A `serve` ANSWER, written whole into the host buffers `input` lends: `body`, the head

    pub fn answer(
        &mut self,
        input: &crate::abi::sdk::Lent<'_, crate::abi::plane::ServeIn>,
        status: u32,
        fields: &[(&str, &str)],
        body: &[u8],
        audit: u32,
    ) -> crate::abi::mechanism::call::Outcome {
        use crate::abi::plane::OutField;
        let (mut reply, mut field_buf, mut arena) =
            (input.reply_buf(), input.fields_buf(), input.arena_buf());
        reply.extend(body);
        for (name, value) in fields {
            field_buf.push(OutField {
                name: arena.span(name.as_bytes()),
                value: arena.span(value.as_bytes()),
            });
        }
        let short = !(reply.fits() && field_buf.fits() && arena.fits());
        let (rw, rnd) = reply.settle(short);
        let (fw, fnd) = field_buf.settle(short);
        let (aw, and) = arena.settle(short);
        self.set(|o| &o.reply_written, rw as u64);
        self.set(|o| &o.reply_needed, rnd as u64);
        self.set(|o| &o.fields_written, fw as u32);
        self.set(|o| &o.fields_needed, fnd as u32);
        self.set(|o| &o.arena_written, aw as u64);
        self.set(|o| &o.arena_needed, and as u64);
        if short {
            return crate::abi::mechanism::call::Outcome::Failed;
        }
        self.set(|o| &o.status, status);
        self.set(|o| &o.audit, audit);
        crate::abi::mechanism::call::Outcome::Ready
    }
}

impl<'a, T: AbiOut> Out<'a, T> {
    /// An `out` with no instance and no lent reason buffer (the unit tests' writer).
    #[cfg(test)]
    pub(crate) fn new(out: &'a mut T) -> Self {
        Self::of(out, None, None, None, None)
    }

    /// An `out` whose writers record what they lease or publish from in `holders`.
    #[cfg(test)]
    pub(crate) fn witnessed(out: &'a mut T, holders: &'a Holders) -> Self {
        Self::of(out, None, None, None, Some(holders))
    }

    /// An `out` answered for the instance that keeps `kept`, its envelope built in `reporting`.
    pub(crate) fn kept(
        out: &'a mut T,
        kept: &'a Kept,
        reporting: &'a Reporting,
        holders: &'a Holders,
    ) -> Self {
        Self::of(out, Some(kept), Some(reporting), None, Some(holders))
    }

    /// An instance-less `out` (`validate`, `open`) lent the host's reason buffer `reason`.
    pub(crate) fn lent(out: &'a mut T, reason: Option<Reason>, holders: &'a Holders) -> Self {
        Self::of(out, None, None, reason, Some(holders))
    }

    fn of(
        out: &'a mut T,
        kept: Option<&'a Kept>,
        reporting: Option<&'a Reporting>,
        reason: Option<Reason>,
        holders: Option<&'a Holders>,
    ) -> Self {
        Self {
            out,
            kept,
            reporting,
            reason,
            holders,
            marks: [(0, 0); MARKS],
            marked: 0,
        }
    }

    /// Record that this answer names memory `alive` guards.
    fn held_by(&self, alive: &Alive) {
        if let Some(h) = self.holders {
            h.borrow_mut().push(alive.token());
        }
    }

    /// Record the byte range `[at, end)` of the `out` as set by a writer.
    fn mark(&mut self, at: usize, end: usize) {
        if self.marked < MARKS {
            self.marks[self.marked] = (at, end);
            self.marked += 1;
        } else {
            let last = &mut self.marks[MARKS - 1];
            *last = (last.0.min(at), last.1.max(end));
        }
    }

    /// The `out` as the SDK's own code writes it (the kind SDKs in this crate).
    pub(crate) fn raw(&mut self) -> &mut T {
        self.out
    }

    /// Read the `out`.
    #[must_use]
    pub fn get(&self) -> &T {
        self.out
    }

    /// Read the pointer-free field `pick` names (a [`Scalar`]), as written so far. `pick` is

    #[must_use]
    pub fn pick<F: Scalar>(&self, pick: impl FnOnce(&T) -> &F) -> F {
        // SAFETY: `T: AbiOut`, whose contract is that every initialized bit pattern, all-zero
        // included, is a valid `T`.
        let blank: T = unsafe { std::mem::zeroed() };
        let base = ptr::from_ref::<T>(&blank) as usize;
        let at = ptr::from_ref(pick(&blank)) as usize;
        assert!(
            at >= base && at.saturating_add(size_of::<F>()) <= base + size_of::<T>(),
            "Out: the picked reference is not a field of the out"
        );
        // SAFETY: `at - base` is the offset of a field of type `F` inside a `T` (checked above),
        // and `self.out` is a live `T`; `read_unaligned` needs no alignment and `F` is `Copy`.
        unsafe {
            ptr::from_ref::<T>(self.out)
                .cast::<u8>()
                .add(at - base)
                .cast::<F>()
                .read_unaligned()
        }
    }

    /// The address of the field `pick` names, checked to lie inside the `out`.
    fn at<F>(&mut self, pick: impl FnOnce(&T) -> &F) -> *mut F {
        let base = ptr::from_ref::<T>(self.out) as usize;
        let at = ptr::from_ref(pick(self.out)) as usize;
        assert!(
            at >= base && at.saturating_add(size_of::<F>()) <= base + size_of::<T>(),
            "Out: the picked reference is not a field of the out"
        );

        ptr::from_mut::<T>(self.out)
            .cast::<u8>()
            .wrapping_add(at - base)
            .cast::<F>()
    }

    /// Write `value` into the field `pick` names (any field, however nested): an SDK writer's

    fn put<F>(&mut self, pick: impl FnOnce(&T) -> &F, value: F) {
        let p = self.at(pick);
        let at = p as usize - ptr::from_ref::<T>(self.out) as usize;
        self.mark(at, at + size_of::<F>());
        // SAFETY: `p` is a field of `*self.out` (checked by `at`), derived from the exclusive
        // borrow this `Out` holds; `write_unaligned` needs no alignment and drops nothing (the ABI
        // structs are `Copy`).
        unsafe { p.write_unaligned(value) };
    }

    /// Set the pointer-free field `pick` names to `value`: a field of the kind's own, after the

    pub fn set<F: Scalar>(&mut self, pick: impl FnOnce(&T) -> &F, value: F) {
        let p = self.at(pick);
        let offset = p as usize - ptr::from_ref::<T>(self.out) as usize;
        assert!(
            offset >= size_of::<OutHead>(),
            "Out::set: the head is written by the SDK's writers only"
        );
        let end = offset + size_of::<F>();
        assert!(
            !self.marks[..self.marked]
                .iter()
                .any(|&(a, b)| offset < b && a < end),
            "Out::set: the field names memory an SDK writer set"
        );
        // SAFETY: as `put`: `p` is a field of `*self.out` (checked by `at`).
        unsafe { p.write_unaligned(value) };
    }

    /// The `out`'s head (every `out` leads with an [`OutHead`], [`AbiOut`]).
    fn head(&mut self) -> &mut OutHead {
        // SAFETY: `AbiOut`'s contract: the implementor's first field is an `OutHead`.
        unsafe { &mut *ptr::from_mut::<T>(self.out).cast::<OutHead>() }
    }

    /// Append one negotiated inspection request to the existing main reply extensions, holding

    pub fn inspection_request(
        &mut self,
        leases: &Leases,
        request: &crate::abi::mechanism::inspection::InspectionRequest,
    ) -> Result<(), crate::abi::mechanism::inspection::InspectionError> {
        use crate::abi::mechanism::inspection::{self, InspectionError};
        let ext = self.head().extensions;
        if ext.len > inspection::MAX_BYTES
            || (ext.len != 0
                && (ext.ptr.is_null() || ext.fmt != crate::abi::mechanism::call::BLOB_OCTETS))
        {
            return Err(InspectionError::Invalid);
        }
        let existing = if ext.len == 0 {
            &[][..]
        } else {
            // SAFETY: only SDK writers can name this output field; their owned/lent bytes are
            // still live for this call, and the bounded nonempty range was checked above.
            unsafe { std::slice::from_raw_parts(ext.ptr, ext.len) }
        };
        use crate::abi::sdk::plane::conditional as wire;
        for key in [
            wire::INTENT,
            wire::OBSERVE,
            wire::RESULT,
            wire::OBSERVED,
            wire::CAPABILITY,
            wire::SETTLEMENT,
            wire::SETTLEMENT_ACK,
        ] {
            if wire::entry(existing, key)
                .map_err(|_| InspectionError::Invalid)?
                .is_some()
            {
                return Err(InspectionError::Busy);
            }
        }
        if let Some(held) = inspection::read_request(existing)? {
            return if held == *request {
                Ok(())
            } else {
                Err(InspectionError::Busy)
            };
        }
        if !inspection::query_fits(&request.query, existing.len()) {
            return Err(InspectionError::Invalid);
        }
        let bytes = inspection::append_request(existing, request)?;
        self.held_by(&leases.alive);
        let mut blob = if ext.flags & crate::abi::mechanism::call::BLOB_SECRET != 0 {
            leases.secret_blob(self.head(), bytes, crate::abi::mechanism::call::BLOB_OCTETS)
        } else {
            leases.blob(self.head(), bytes, crate::abi::mechanism::call::BLOB_OCTETS)
        };
        blob.flags = ext.flags;
        self.put(
            |out| {
                // SAFETY: AbiOut starts with OutHead; this selects a field inside that head.
                unsafe { &(*ptr::from_ref(out).cast::<OutHead>()).extensions }
            },
            blob,
        );
        Ok(())
    }

    /// Acknowledge explicitly consumed terminal service results on this driver. The bytes are

    pub fn completion_ack(
        &mut self,
        leases: &Leases,
        ack: &crate::abi::sdk::completion_retirement::Acknowledgement,
    ) -> Result<(), crate::abi::sdk::completion_retirement::Error> {
        use crate::abi::mechanism::call::{BLOB_OCTETS, BLOB_SECRET};
        use crate::abi::sdk::completion_retirement::{self as wire, Error};
        let ext = self.head().extensions;
        if ext.len > crate::abi::mechanism::check::HARD_MAX_BYTES as usize
            || (ext.len != 0 && (ext.ptr.is_null() || ext.fmt != BLOB_OCTETS))
        {
            return Err(Error::Invalid);
        }
        let prior = if ext.len == 0 {
            &[][..]
        } else {
            // SAFETY: prior SDK output writers retain these bytes for this answer.
            unsafe { std::slice::from_raw_parts(ext.ptr, ext.len) }
        };
        if let Some(previous) = wire::read_ack(prior)? {
            return if previous == *ack {
                Ok(())
            } else {
                Err(Error::Invalid)
            };
        }
        let bytes = wire::append_ack(prior, ack)?;
        self.held_by(&leases.alive);
        let mut blob = if ext.flags & BLOB_SECRET != 0 {
            leases.secret_blob(self.head(), bytes, BLOB_OCTETS)
        } else {
            leases.blob(self.head(), bytes, BLOB_OCTETS)
        };
        blob.flags = ext.flags;
        self.head().extensions = blob;
        Ok(())
    }

    /// For a PENDING answer: resume this op no later than `mono_ns` on the host's monotonic clock

    pub fn wake_at(&mut self, mono_ns: u64) {
        self.head().wake_at_ns = mono_ns;
    }

    /// Lease an immutable logical publication intent. Return PENDING with no ordinary output;

    pub fn conditional_request(
        &mut self,
        leases: &Leases,
        request: &crate::abi::sdk::plane::conditional::Request,
    ) -> Result<(), &'static str> {
        use crate::abi::sdk::plane::conditional as wire;
        self.conditional_extension(leases, wire::INTENT, wire::encode_request_held(request)?)
    }

    /// Lease a read-only original-incarnation observation. Return PENDING, then issue fresh

    pub fn conditional_observation(
        &mut self,
        leases: &Leases,
        request: &crate::abi::sdk::plane::conditional::Observation,
    ) -> Result<(), &'static str> {
        use crate::abi::sdk::plane::conditional as wire;
        self.conditional_extension(
            leases,
            wire::OBSERVE,
            zeroize::Zeroizing::new(wire::encode_observation(request)?),
        )
    }

    /// Lease an exact outcome-only settlement acknowledgement. Return PENDING from DRIVE/TICK

    pub fn conditional_settlement_ack(
        &mut self,
        leases: &Leases,
        settlement: &crate::abi::sdk::plane::conditional::Settlement,
    ) -> Result<(), &'static str> {
        use crate::abi::sdk::plane::conditional as wire;
        let encoded = zeroize::Zeroizing::new(wire::encode_settlement_ack(settlement));
        wire::read_settlement_ack(&encoded)?;
        self.conditional_extension(leases, wire::SETTLEMENT_ACK, encoded)
    }

    fn conditional_extension(
        &mut self,
        leases: &Leases,
        key: &str,
        encoded: zeroize::Zeroizing<Vec<u8>>,
    ) -> Result<(), &'static str> {
        use crate::abi::mechanism::call::{BLOB_OCTETS, BLOB_SECRET};
        use crate::abi::sdk::plane::conditional as wire;
        let ext = self.head().extensions;
        if ext.len > crate::abi::mechanism::check::HARD_MAX_BYTES as usize
            || (ext.len != 0 && (ext.ptr.is_null() || ext.fmt != BLOB_OCTETS))
        {
            return Err(wire::INVALID);
        }
        let prior = if ext.len == 0 {
            &[][..]
        } else {
            // SAFETY: SDK writers retain this bounded output blob for the answer's lifetime.
            unsafe { std::slice::from_raw_parts(ext.ptr, ext.len) }
        };
        let mut repeated = false;
        for other in [
            wire::INTENT,
            wire::OBSERVE,
            wire::RESULT,
            wire::OBSERVED,
            wire::CAPABILITY,
            wire::SETTLEMENT,
            wire::SETTLEMENT_ACK,
        ] {
            if let Some(value) = wire::entry(prior, other)? {
                if other != key || wire::entry(&encoded, key)? != Some(value) {
                    return Err(wire::INVALID);
                }
                repeated = true;
            }
        }
        if crate::abi::mechanism::extensions::get(
            prior,
            crate::abi::mechanism::inspection::EXT_REQUEST,
        )
        .is_some()
        {
            return Err(wire::INVALID);
        }
        if repeated {
            return Ok(());
        }
        let len = prior
            .len()
            .checked_add(encoded.len())
            .filter(|&n| n <= crate::abi::mechanism::check::HARD_MAX_BYTES as usize)
            .ok_or(wire::INVALID)?;
        let mut bytes = crate::abi::sdk::secret_bytes::SecretBytes::with_capacity(len);
        bytes.extend_from_slice(prior);
        bytes.extend_from_slice(&encoded);
        self.held_by(&leases.alive);

        let flags = ext.flags | if key == wire::INTENT { BLOB_SECRET } else { 0 };
        let mut blob = if flags & BLOB_SECRET != 0 {
            leases.secret_blob(self.head(), bytes.into_vec(), BLOB_OCTETS)
        } else {
            leases.blob(self.head(), bytes.into_vec(), BLOB_OCTETS)
        };
        blob.flags = flags;
        self.head().extensions = blob;
        Ok(())
    }

    /// Answer `refusal`: its outcome, the head's error naming its text. A `'static` text is named

    pub fn fail(&mut self, refusal: Refusal) -> Outcome {
        let (outcome, text) = refusal.into_parts();
        let error = match text {
            None => AbiStr {
                ptr: ptr::null(),
                len: 0,
            },
            Some(Cow::Borrowed(s)) => AbiStr {
                ptr: s.as_ptr(),
                len: s.len(),
            },
            Some(Cow::Owned(s)) => self.owned_text(s),
        };
        self.head().error = error;
        outcome
    }

    /// Name WHY a READY answer declined, in the head's error text, for the host's log of the

    pub fn reason(&mut self, text: impl Into<Cow<'static, str>>) {
        let error = match text.into() {
            Cow::Borrowed(s) => AbiStr {
                ptr: s.as_ptr(),
                len: s.len(),
            },
            Cow::Owned(s) => self.owned_text(s),
        };
        self.head().error = error;
    }

    /// Where an owned failure text lives: the instance, else the host's lent reason buffer, else

    fn owned_text(&mut self, text: String) -> AbiStr {
        if self.kept.is_some() {
            let mut report = self.report().expect("an instance has reply storage");
            let text: Box<str> = text.into();
            let named = AbiStr {
                ptr: text.as_ptr(),
                len: text.len(),
            };
            report.owned.push(text);
            self.hand_back(report);
            return named;
        }
        let Some(r) = self.reason else {
            return AbiStr {
                ptr: NO_REASON_BUFFER.as_ptr(),
                len: NO_REASON_BUFFER.len(),
            };
        };
        let mut end = text.len().min(r.cap);
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        // SAFETY: `r.buf` is the host's reason buffer of `r.cap >= end` writable bytes, lent for
        // this call and overlapping nothing the body holds (`ValidateIn::err_buf`,
        // `OpenIn::err_buf`); `text` is the body's own.
        unsafe { ptr::copy_nonoverlapping(text.as_ptr(), r.buf, end) };
        if r.open {
            // SAFETY: an `open`'s `out` leads with the lifecycle's `OpenOut` (`KindOps`'s
            // contract), and `self.out` is the exclusive borrow of it.
            unsafe { (*ptr::from_mut::<T>(self.out).cast::<OpenOut>()).err_len = end };
        }
        AbiStr {
            ptr: r.buf.cast_const(),
            len: end,
        }
    }

    /// This call's envelope for a writer to fill (the call's own, or a fresh one from the

    fn report(&self) -> Option<Box<Report>> {
        let (kept, reporting) = (self.kept?, self.reporting?);
        Some(reporting.take().unwrap_or_else(|| kept.report()))
    }

    /// Name `text`, which lives for the program, as the answer's error text; the outcome is the

    pub fn error(&mut self, text: &'static str) {
        self.head().error = AbiStr {
            ptr: text.as_ptr(),
            len: text.len(),
        };
    }

    /// REPORT one metric in the reply's envelope: `value` for the family at `family_idx` in the

    pub fn metric(&mut self, family_idx: u32, kind: u8, value: f64) -> bool {
        let Some(mut r) = self.report() else {
            return false;
        };
        let added = r.metrics.len() < MAX_ENVELOPE_ENTRIES;
        if added {
            r.metrics.push(MetricEntry {
                family_idx,
                kind,
                _reserved: [0; 3],
                value,
                label_vals: ptr::null(),
                label_vals_len: 0,
            });
            let head = self.head();
            head.envelope.metrics = r.metrics.as_ptr();
            head.envelope.metrics_len = r.metrics.len();
        }
        self.hand_back(r);
        added
    }

    /// REPORT one declared diagnostic in the reply's envelope: the id at `id_idx` in the

    pub fn diag(&mut self, id_idx: u32, severity: u8, text: impl Into<Box<str>>) -> bool {
        let Some(mut r) = self.report() else {
            return false;
        };
        let added = r.diags.len() < MAX_ENVELOPE_ENTRIES;
        if added {
            let text: Box<str> = text.into();
            let named = AbiStr {
                ptr: text.as_ptr(),
                len: text.len(),
            };

            r.texts.push(text);
            r.diags.push(Diag {
                id_idx,
                severity,
                _reserved: [0; 3],
                text: named,
            });
            let head = self.head();
            head.envelope.diags = r.diags.as_ptr();
            head.envelope.diags_len = r.diags.len();
        }
        self.hand_back(r);
        added
    }

    /// Hand the envelope back to the call (moving the box moves none of its entries).
    fn hand_back(&self, r: Box<Report>) {
        if let Some(reporting) = self.reporting {
            reporting.set(Some(r));
        }
    }

    /// Set the string field `pick` names to `s`, which lives at least until the instance's next

    pub fn lent_str<'g>(&mut self, pick: impl FnOnce(&T) -> &AbiStr, s: &'g str, gen: &Gen<'g>) {
        self.put(pick, AbiStr::lent(s, gen));
    }

    /// As [`Out::lent_str`], for the blob field `pick` names: `bytes` of format `fmt`.
    pub fn lent_blob<'g>(
        &mut self,
        pick: impl FnOnce(&T) -> &Blob,
        bytes: &'g [u8],
        fmt: u32,
        gen: &Gen<'g>,
    ) {
        self.put(pick, Blob::lent(bytes, gen).with_fmt(fmt));
    }

    /// Name `text`, which lives at least until the instance's next refresh generation

    pub fn error_lent<'g>(&mut self, text: &'g str, gen: &Gen<'g>) {
        self.head().error = AbiStr::lent(text, gen);
    }

    /// Hold `bytes` in `leases` under a new lease (named in the head) and set the blob `pick`

    pub fn lease(
        &mut self,
        pick: impl FnOnce(&T) -> &Blob,
        leases: &Leases,
        bytes: Vec<u8>,
        fmt: u32,
    ) {
        self.held_by(&leases.alive);
        let blob = leases.blob(self.head(), bytes, fmt);
        self.put(pick, blob);
    }

    /// As [`Out::lease`], for secret material (flagged secret, zeroized on release).
    pub fn lease_secret(
        &mut self,
        pick: impl FnOnce(&T) -> &Blob,
        leases: &Leases,
        bytes: Vec<u8>,
        fmt: u32,
    ) {
        #[cfg(test)]
        // SAFETY: this owned initialized Vec stays on the probe's thread through lease release.
        unsafe {
            crate::alloc_counter::watch_initialized_payload(&bytes);
        }
        self.held_by(&leases.alive);
        let blob = leases.secret_blob(self.head(), bytes, fmt);
        self.put(pick, blob);
    }

    /// As [`Out::lease`], for a string: set the string field `pick` names to `text`, held by

    pub fn lease_str(&mut self, pick: impl FnOnce(&T) -> &AbiStr, leases: &Leases, text: String) {
        self.held_by(&leases.alive);
        let s = leases.str(self.head(), text);
        self.put(pick, s);
    }

    /// Set the string field `pick` names to `text`, which lives for the program.
    pub fn text(&mut self, pick: impl FnOnce(&T) -> &AbiStr, text: &'static str) {
        self.put(
            pick,
            AbiStr {
                ptr: text.as_ptr(),
                len: text.len(),
            },
        );
    }

    /// Hold `owned` under this answer's lease (named in `head.lease`) until the host's `release`

    pub fn keep<O: Send + Sync + 'static>(&mut self, leases: &Leases, owned: O) {
        self.held_by(&leases.alive);
        leases.keep(self.head(), owned);
    }

    /// Set the list `ptr`/`len` name to `items`, which live for the program (NULL when empty).
    pub fn list<E: 'static>(
        &mut self,
        ptr: impl FnOnce(&T) -> &*const E,
        len: impl FnOnce(&T) -> &usize,
        items: &'static [E],
    ) {
        let p = if items.is_empty() {
            ptr::null()
        } else {
            items.as_ptr()
        };
        self.put(ptr, p);
        self.put(len, items.len());
    }

    /// Publish `spec` as `generation` in `gens` and set the field `pick` names to the published

    pub fn publish<P: Publish>(
        &mut self,
        pick: impl FnOnce(&T) -> &*const P,
        gens: &Generations<P>,
        generation: u64,
        spec: &P::Spec,
    ) {
        self.held_by(&gens.alive);
        let p = gens.publish(generation, spec);
        self.put(pick, p);
    }

    /// [`Out::publish`] with the plugin's `payload` for that generation, held beside it

    pub fn publish_with<P: Publish, D>(
        &mut self,
        pick: impl FnOnce(&T) -> &*const P,
        gens: &Generations<P, D>,
        generation: u64,
        spec: &P::Spec,
        payload: D,
    ) {
        self.held_by(&gens.alive);
        let p = gens.publish_with(generation, spec, payload);
        self.put(pick, p);
    }

    /// Set the string field `pick` names to the bytes `span` names in the host buffer `buf`,

    pub fn host_str(
        &mut self,
        pick: impl FnOnce(&T) -> &AbiStr,
        buf: &HostBuf<'_, u8>,
        span: crate::abi::mechanism::call::Span,
    ) {
        let s = buf.str_at(span);
        self.put(pick, s);
    }

    /// Set the blob field `pick` names to the first `len` bytes of `buf`, the host's secret buffer

    pub(crate) fn host_secret(
        &mut self,
        pick: impl FnOnce(&T) -> &crate::abi::mechanism::call::Blob,
        buf: &HostBuf<'_, u8>,
        len: usize,
    ) {
        use crate::abi::mechanism::call::{Blob, BLOB_OCTETS, BLOB_SECRET};
        let blob = if len == 0 {
            Blob {
                ptr: ptr::null(),
                len: 0,
                fmt: 0,
                flags: 0,
            }
        } else {
            Blob {
                ptr: buf.as_ptr().cast_const(),
                len,
                fmt: BLOB_OCTETS,
                flags: BLOB_SECRET,
            }
        };
        self.put(pick, blob);
    }

    /// Point the field `pick` names at the rows of `buf`, a host buffer lent for this call; the

    pub fn host_rows<E: Copy>(&mut self, pick: impl FnOnce(&T) -> &*const E, buf: &HostBuf<'_, E>) {
        let p = buf.as_ptr().cast_const();
        self.put(pick, p);
    }

    /// Set the blob field `pick` names to the opaque octets

    pub fn host_octets(
        &mut self,
        pick: impl FnOnce(&T) -> &crate::abi::mechanism::call::Blob,
        buf: &HostBuf<'_, u8>,
        span: crate::abi::mechanism::call::Span,
    ) {
        let s = buf.str_at(span);
        self.put(
            pick,
            crate::abi::mechanism::call::Blob {
                ptr: s.ptr,
                len: s.len,
                fmt: crate::abi::mechanism::call::BLOB_OCTETS,
                flags: 0,
            },
        );
    }

    /// Set the list `ptr`/`len` name to what `buf`, a host buffer lent for this call, holds.
    pub fn host_list<E: Copy>(
        &mut self,
        ptr: impl FnOnce(&T) -> &*const E,
        len: impl FnOnce(&T) -> &usize,
        buf: &HostBuf<'_, E>,
    ) {
        let p = buf.as_ptr().cast_const();
        self.put(ptr, p);
        self.put(len, buf.written());
    }
}

#[cfg(test)]
#[path = "tests/out_tests.rs"]
mod tests;
