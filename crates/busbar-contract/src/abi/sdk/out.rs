// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A SLOT'S `out`, WRITTEN BY THE SDK (THE DESIGN, plugins: a plugin crate stays
//! `#![forbid(unsafe_code)]`; memory a plugin returns stays valid for as long as the ABI says).
//! A [`SafeSlot`](crate::abi::sdk::safe::SafeSlot) body is handed its `out` as an [`Out`], never as
//! `&mut`: it READS any field, SETS a pointer-free field ([`Scalar`]) directly, and hands every
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
//! box), in a bounded ring of the last [`KEPT_RING`] answers, so two instances of one plugin never
//! share or overwrite each other's answers, on one thread or many. A call with no instance yet
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
use std::cell::Cell;
use std::collections::VecDeque;
use std::mem::size_of;
use std::ptr;
use std::sync::{Mutex, MutexGuard, PoisonError};

use crate::abi::mechanism::call::{
    AbiStr, Blob, Diag, MetricEntry, OutHead, Outcome, MAX_ENVELOPE_ENTRIES,
};
use crate::abi::mechanism::lifecycle::OpenOut;
use crate::abi::sdk::door::AbiOut;
use crate::abi::sdk::lent::HostBuf;
use crate::abi::sdk::life::{Leases, Refusal};
use crate::abi::sdk::publish::{Generations, Publish};

/// How many answers one instance keeps alive at once, per kind of memory (owned failure texts;
/// envelopes), oldest dropped first: the store door's and the hook door's bound. The host copies
/// each as its crossing returns, so an answer is dropped only once this many newer answers of the
/// same instance have been kept.
pub const KEPT_RING: usize = 4096;

/// A failure's owned text with no instance to keep it and no reason buffer lent by the host: the
/// only case the SDK answers a fixed text for.
pub const NO_REASON_BUFFER: &str =
    "the plugin's reason was not kept: the host lent no reason buffer";

/// THE ENVELOPE ONE SAFE CALL REPORTS (#85): the metrics and declared diagnostics its body added
/// with [`Out::metric`] and [`Out::diag`], with the texts the diagnostics point into.
#[derive(Default)]
pub(crate) struct Report {
    metrics: Vec<MetricEntry>,
    diags: Vec<Diag>,
    texts: Vec<Box<str>>,
}

// SAFETY: a `Report` owns everything its entries point to (`label_vals` is always NULL; a `Diag`'s
// text is one of its own `texts`), and it is only reached through the instance's lock.
unsafe impl Send for Report {}

impl Report {
    fn clear(&mut self) {
        self.metrics.clear();
        self.diags.clear();
        self.texts.clear();
    }
}

/// What a call's body reported, held by the call until it returns: the SDK then hands it to the
/// instance's [`Kept`].
pub(crate) type Reporting = Cell<Option<Box<Report>>>;

/// WHAT ONE INSTANCE'S ANSWERS NAME, kept by the instance (the SDK's instance box,
/// `abi::sdk::safe`): the owned failure texts and the reported envelopes of its last [`KEPT_RING`]
/// answers each. Dropped with the instance.
#[derive(Default)]
pub(crate) struct Kept {
    texts: Mutex<VecDeque<Box<str>>>,
    reports: Mutex<VecDeque<Box<Report>>>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Kept {
    /// Keep `text` and answer the string naming it, valid until [`KEPT_RING`] newer texts of this
    /// instance.
    pub(crate) fn text(&self, text: String) -> AbiStr {
        let kept: Box<str> = text.into();
        let named = AbiStr {
            ptr: kept.as_ptr(),
            len: kept.len(),
        };
        let mut ring = lock(&self.texts);
        if ring.len() >= KEPT_RING {
            ring.pop_front();
        }
        ring.push_back(kept);
        named
    }

    /// An empty envelope for a call to fill: the oldest kept one, reused, once the ring is full
    /// (no allocation from then on), else a new one.
    fn report(&self) -> Box<Report> {
        let mut ring = lock(&self.reports);
        if ring.len() >= KEPT_RING {
            if let Some(mut r) = ring.pop_front() {
                r.clear();
                return r;
            }
        }
        Box::default()
    }

    /// Keep a returned call's envelope (its entries do not move: they live on the heap).
    pub(crate) fn keep(&self, report: Box<Report>) {
        let mut ring = lock(&self.reports);
        if ring.len() >= KEPT_RING {
            ring.pop_front();
        }
        ring.push_back(report);
    }

    /// How many texts and envelopes the instance holds.
    #[cfg(test)]
    pub(crate) fn held(&self) -> (usize, usize) {
        (lock(&self.texts).len(), lock(&self.reports).len())
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
unsafe impl Scalar for crate::abi::plane::UnitCount {}
unsafe impl Scalar for crate::abi::plane::RecordWrite {}
unsafe impl Scalar for crate::abi::plane::OutField {}
unsafe impl Scalar for crate::abi::transport::FramePiece {}
unsafe impl Scalar for crate::abi::transport::FramerYield {}
unsafe impl Scalar for crate::abi::transport::HeadSlots {}
unsafe impl Scalar for crate::abi::store::CellGrant {}

/// A slot's `out`, as a safe body is handed it: read anything, set scalars, and hand pointers to
/// the SDK's writers. Only the SDK makes one; it lives for the call.
pub struct Out<'a, T> {
    out: &'a mut T,
    /// The answering instance's memory; `None` with no instance yet.
    kept: Option<&'a Kept>,
    /// Where this call's envelope is built; `None` when there is no instance to keep it.
    reporting: Option<&'a Reporting>,
    /// The host's lent reason buffer, on an instance-less call that was lent one.
    reason: Option<Reason>,
}

impl<T> std::fmt::Debug for Out<'_, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Out")
            .field("instance", &self.kept.is_some())
            .field("reason", &self.reason)
            .finish_non_exhaustive()
    }
}

impl<'a, T: AbiOut> Out<'a, T> {
    /// An `out` with no instance and no lent reason buffer (the unit tests' writer).
    #[cfg(test)]
    pub(crate) fn new(out: &'a mut T) -> Self {
        Self {
            out,
            kept: None,
            reporting: None,
            reason: None,
        }
    }

    /// An `out` answered for the instance that keeps `kept`, its envelope built in `reporting`.
    pub(crate) fn kept(out: &'a mut T, kept: &'a Kept, reporting: &'a Reporting) -> Self {
        Self {
            out,
            kept: Some(kept),
            reporting: Some(reporting),
            reason: None,
        }
    }

    /// An instance-less `out` (`validate`, `open`) lent the host's reason buffer `reason`.
    pub(crate) fn lent(out: &'a mut T, reason: Option<Reason>) -> Self {
        Self {
            out,
            kept: None,
            reporting: None,
            reason,
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

    /// The address of the field `pick` names, checked to lie inside the `out`.
    fn at<F>(&mut self, pick: impl FnOnce(&T) -> &F) -> *mut F {
        let base = ptr::from_ref::<T>(self.out) as usize;
        let at = ptr::from_ref(pick(self.out)) as usize;
        assert!(
            at >= base && at.saturating_add(size_of::<F>()) <= base + size_of::<T>(),
            "Out: the picked reference is not a field of the out"
        );
        // The same allocation as `self.out`, derived from the `&mut` so writing through it is
        // allowed.
        ptr::from_mut::<T>(self.out)
            .cast::<u8>()
            .wrapping_add(at - base)
            .cast::<F>()
    }

    /// Write `value` into the field `pick` names (any field, however nested).
    fn put<F>(&mut self, pick: impl FnOnce(&T) -> &F, value: F) {
        let p = self.at(pick);
        // SAFETY: `p` is a field of `*self.out` (checked by `at`), derived from the exclusive
        // borrow this `Out` holds; `write_unaligned` needs no alignment and drops nothing (the ABI
        // structs are `Copy`).
        unsafe { p.write_unaligned(value) };
    }

    /// Set the pointer-free field `pick` names to `value`.
    ///
    /// # Panics
    /// When `pick` answers a reference that is not a field of the `out`.
    pub fn set<F: Scalar>(&mut self, pick: impl FnOnce(&T) -> &F, value: F) {
        self.put(pick, value);
    }

    /// The `out`'s head (every `out` leads with an [`OutHead`], [`AbiOut`]).
    fn head(&mut self) -> &mut OutHead {
        // SAFETY: `AbiOut`'s contract: the implementor's first field is an `OutHead`.
        unsafe { &mut *ptr::from_mut::<T>(self.out).cast::<OutHead>() }
    }

    /// For a PENDING answer: resume this op no later than `mono_ns` on the host's monotonic clock
    /// (`clock.now`'s `mono_ns`) even if nothing wakes it — the host's timer, never earlier than
    /// `mono_ns` (a wake may still resume it sooner: see `abi::sdk::conn::not_before`).
    pub fn wake_at(&mut self, mono_ns: u64) {
        self.head().wake_at_ns = mono_ns;
    }

    /// Answer `refusal`: its outcome, the head's error naming its text. A `'static` text is named
    /// where it lives. An owned text is kept by the answering instance until [`KEPT_RING`] newer
    /// texts of it; with no instance yet it is written into the host's lent reason buffer (cut on a
    /// char boundary to its capacity; an `open` states its length in `err_len`), and only when the
    /// host lent none is it answered as [`NO_REASON_BUFFER`].
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

    /// Where an owned failure text lives: the instance, else the host's lent reason buffer, else
    /// nowhere (the fixed text).
    fn owned_text(&mut self, text: String) -> AbiStr {
        if let Some(kept) = self.kept {
            return kept.text(text);
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
    /// instance); `None` with no instance.
    fn report(&self) -> Option<Box<Report>> {
        let (kept, reporting) = (self.kept?, self.reporting?);
        Some(reporting.take().unwrap_or_else(|| kept.report()))
    }

    /// Name `text`, which lives for the program, as the answer's error text; the outcome is the
    /// caller's to answer.
    pub fn error(&mut self, text: &'static str) {
        self.head().error = AbiStr {
            ptr: text.as_ptr(),
            len: text.len(),
        };
    }

    /// REPORT one metric in the reply's envelope: `value` for the family at `family_idx` in the
    /// Statement's `families`, as `kind` (`METRIC_ADD` | `METRIC_SET` | `METRIC_OBSERVE`), unlabelled.
    /// `false` when the envelope is full ([`MAX_ENVELOPE_ENTRIES`]), or when the call has no
    /// instance to keep it (`validate`, `open`): the entry is not reported.
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
    /// Statement's `diag_ids`, its `severity` and `text`. The call capture's log records join after
    /// it. `false` when the envelope is full: the entry is not reported.
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
            // The `Box<str>`'s bytes stay put while the vector of them grows.
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

    /// Hold `bytes` in `leases` under a new lease (named in the head) and set the blob `pick`
    /// names over them, of format `fmt`.
    pub fn lease(
        &mut self,
        pick: impl FnOnce(&T) -> &Blob,
        leases: &Leases,
        bytes: Vec<u8>,
        fmt: u32,
    ) {
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
        let blob = leases.secret_blob(self.head(), bytes, fmt);
        self.put(pick, blob);
    }

    /// As [`Out::lease`], for a string: set the string field `pick` names to `text`, held by
    /// `leases` under `head.lease` until the host's `release` of it, across refresh generations.
    pub fn lease_str(&mut self, pick: impl FnOnce(&T) -> &AbiStr, leases: &Leases, text: String) {
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
    /// value, which the SDK holds until that generation's `retire`.
    pub fn publish<P: Publish>(
        &mut self,
        pick: impl FnOnce(&T) -> &*const P,
        gens: &Generations<P>,
        generation: u64,
        spec: &P::Spec,
    ) {
        let p = gens.publish(generation, spec);
        self.put(pick, p);
    }

    /// Set the string field `pick` names to the bytes `span` names in the host buffer `buf`,
    /// which the host lent for this call and reads when it returns.
    pub fn host_str(
        &mut self,
        pick: impl FnOnce(&T) -> &AbiStr,
        buf: &HostBuf<'_, u8>,
        span: crate::abi::mechanism::call::Span,
    ) {
        let s = buf.str_at(span);
        self.put(pick, s);
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
