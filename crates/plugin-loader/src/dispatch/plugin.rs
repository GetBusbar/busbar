// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! [`Plugin`]`<K>`: the instance handle and THE ONE CROSSING.
//!
//! OUTCOME AUTHORITY. The value the slot RETURNS decides. An unknown byte is FAULT; an
//! `OutHead.outcome` that differs from the return value is FAULT; an answer that fails
//! [`super::validate`] (an `OutHead.size` outside `size_of::<OutHead>()..=` the host's `out`, error
//! text NULL-with-length or over-long, a #85 array NULL-with-length or over-long) is FAULT; PENDING on [`Ticket::NONE`] (a call that may not pend) is FAULT. The host
//! zeroes the whole `out` before every crossing (then states its size), so an `out` nobody wrote
//! reads as a fault.
//!
//! OUT-MEMORY. Every plugin pointer in an `out` head (the error text, the #85 envelope) is read
//! and COPIED before the crossing returns to its caller — before the next op on the ticket, and for
//! [`Ticket::NONE`] before [`Plugin::call`] returns. A kind's reply data lives in HOST buffers named
//! in its own `in`/`out` (the kind's rule); a lease is handed back to the caller, who calls
//! `release`.
//!
//! THE #85 ENVELOPE. Every metric names a family by INDEX: an index out of the Statement's range,
//! a metric kind the family does not have (ADD↔counter, SET↔gauge, OBSERVE↔histogram), a label
//! count that is not the family's, or a non-finite value drops THAT entry; a diagnostic whose id
//! index is out of range, or whose severity is not 0..=2, is dropped. What survives goes to the
//! [`EnvelopeSink`], which names no kernel type. Each drop is reported to the sink as [`Dropped`].
//!
//! `max_inflight`. The Statement's figure, clamped by the host to `1..=`[`Bind::max_inflight_cap`].
//! Every op holds one unit from submission to completion (driver tickets hold none); over the cap
//! the op answers REFUSED and the plugin is never called.

use std::marker::PhantomData;
use std::mem::size_of;
use std::os::raw::c_void;
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, Ordering};
use std::sync::Arc;

use busbar_contract::abi::mechanism::call::{
    AbiStr, DeadlineClass, Diag, InHead, MetricEntry, Op, OutHead, Outcome, RawOutcome, METRIC_ADD,
    METRIC_OBSERVE, METRIC_SET,
};
use busbar_contract::abi::mechanism::door::{FAMILY_COUNTER, FAMILY_GAUGE, FAMILY_HISTOGRAM};
use busbar_contract::abi::mechanism::lifecycle::{slot, OpenIn, OpenOut};
use busbar_contract::abi::mechanism::ticket::{HostCtx, HostTables, Ticket};
use busbar_contract::abi::mechanism::KindCode;

use super::load::{Lib, LoadError, Validated};
use super::ticket::{host_wake, InstanceWake};
use super::{validate, Frame, InFrame, Kind, OutFrame};

/// The most entries one envelope array may carry; a longer array is dropped whole.
pub const MAX_ENVELOPE_ENTRIES: usize = 256;
/// The most bytes of error or diagnostic text the host copies; longer text is cut.
pub const MAX_TEXT: usize = 4096;

/// One ingested metric, borrowed for the duration of [`EnvelopeSink::metric`]: copy what you keep.
#[derive(Debug, Clone, Copy)]
pub struct Metric<'a> {
    /// The family's index in the Statement.
    pub family: u32,
    /// `METRIC_ADD` | `METRIC_SET` | `METRIC_OBSERVE`.
    pub kind: u8,
    /// The value; always finite.
    pub value: f64,
    /// One value per label key, in the family's order.
    pub labels: &'a [&'a [u8]],
}

/// One ingested diagnostic, borrowed for the duration of [`EnvelopeSink::diag`].
#[derive(Debug, Clone, Copy)]
pub struct Diagnostic<'a> {
    /// The id's index in the Statement.
    pub id: u32,
    /// `0` info, `1` warn, `2` error.
    pub severity: u8,
    /// The text (at most [`MAX_TEXT`] bytes).
    pub text: &'a [u8],
}

/// An envelope entry the host dropped, and why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dropped {
    /// A metric's family index is out of the Statement's range.
    FamilyOutOfRange(u32),
    /// A metric's kind is not its family's.
    KindMismatch {
        /// The family.
        family: u32,
        /// The metric's kind.
        kind: u8,
    },
    /// A metric's value is NaN or infinite.
    NonFinite(u32),
    /// A metric's label count is not its family's.
    LabelCount(u32),
    /// A diagnostic's id index is out of range.
    DiagOutOfRange(u32),
    /// A diagnostic's severity is not 0..=2.
    Severity(u32),
    /// An array is NULL with a non-zero length, or longer than [`MAX_ENVELOPE_ENTRIES`].
    BadArray,
}

/// Where the #85 envelope goes. Names no kernel type; the kernel implements it per kind (M3).
pub trait EnvelopeSink: Send + Sync {
    /// A metric that passed every check.
    fn metric(&self, m: Metric<'_>);
    /// A diagnostic that passed every check.
    fn diag(&self, d: Diagnostic<'_>);
    /// An entry the host dropped.
    fn dropped(&self, why: Dropped);
}

/// The sink that discards everything.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoSink;

impl EnvelopeSink for NoSink {
    fn metric(&self, _: Metric<'_>) {}
    fn diag(&self, _: Diagnostic<'_>) {}
    fn dropped(&self, _: Dropped) {}
}

/// What the host binds a loaded plugin to.
#[derive(Clone)]
pub struct Bind {
    /// The host's clamp on the Statement's `max_inflight`.
    pub max_inflight_cap: u32,
    /// Where the envelope goes.
    pub sink: Arc<dyn EnvelopeSink>,
}

impl std::fmt::Debug for Bind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Bind")
            .field("max_inflight_cap", &self.max_inflight_cap)
            .finish_non_exhaustive()
    }
}

/// What one ticket-less call answered, copied out of the plugin's memory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Called {
    /// The authoritative outcome.
    pub outcome: Outcome,
    /// The error text, for FAILED/REFUSED.
    pub error: Option<Vec<u8>>,
    /// A lease the caller hands back to `release`; `0` = none.
    pub lease: u64,
}

/// What one crossing answered.
#[derive(Debug, Clone)]
pub(crate) struct Crossed {
    pub(crate) outcome: Outcome,
    pub(crate) error: Option<Vec<u8>>,
    pub(crate) lease: u64,
    pub(crate) wake_at_ns: u64,
    /// A FAILED answer the kind calls short ([`Kind::short`]).
    pub(crate) short: bool,
}

impl Crossed {
    pub(crate) fn host(outcome: Outcome) -> Self {
        Self {
            outcome,
            error: None,
            lease: 0,
            wake_at_ns: 0,
            short: false,
        }
    }
}

/// The host tables `open` is handed; immutable after construction.
struct Tables(Box<HostTables>);
// SAFETY: the tables are written once at bind and only read after; `ctx` points to a leaked,
// `Sync` [`InstanceWake`].
unsafe impl Send for Tables {}
unsafe impl Sync for Tables {}

/// One family's shape, copied from the Statement: its kind and its label count.
#[derive(Debug, Clone, Copy)]
struct FamilyShape {
    kind: u8,
    labels: usize,
}

/// THE INSTANCE, kind-erased: what every crossing needs. Shared across workers.
pub(crate) struct Instance {
    pub(crate) kind: KindCode,
    name: String,
    slots: Box<[Op]>,
    families: Box<[FamilyShape]>,
    diag_ids: usize,
    ptr: AtomicPtr<c_void>,
    pub(crate) faulted: AtomicBool,
    inflight: AtomicU32,
    /// Ops in flight that a reload drain waits for: every op but WriteBehind.
    pub(crate) drainable: AtomicU32,
    pub(crate) cap: u32,
    lifecycle_busy: AtomicBool,
    pub(crate) timeout: Outcome,
    /// [`Kind::check`] of the bound kind.
    check: fn(u32, *const InHead, *const OutHead) -> bool,
    /// [`Kind::short`] of the bound kind.
    short: fn(u32, *const OutHead) -> bool,
    sink: Arc<dyn EnvelopeSink>,
    pub(crate) wake: &'static InstanceWake,
    tables: Tables,
    /// Last: the library outlives everything above.
    _lib: Option<Lib>,
}

/// Whether `slot` is one of the four that never overlap on one instance.
pub(crate) fn is_lifecycle(s: u32) -> bool {
    matches!(s, slot::OPEN | slot::REFRESH | slot::RETIRE | slot::CLOSE)
}

impl Instance {
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    pub(crate) fn ctx(&self) -> HostCtx {
        HostCtx {
            ptr: std::ptr::from_ref(self.wake).cast_mut().cast(),
        }
    }

    pub(crate) fn slot_count(&self) -> u32 {
        self.slots.len() as u32
    }

    pub(crate) fn is_open(&self) -> bool {
        !self.ptr.load(Ordering::Acquire).is_null()
    }

    /// Take one `max_inflight` unit; `false` over the cap.
    pub(crate) fn acquire(&self) -> bool {
        self.inflight
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < self.cap).then_some(n + 1)
            })
            .is_ok()
    }

    pub(crate) fn release(&self) {
        self.inflight.fetch_sub(1, Ordering::AcqRel);
    }

    pub(crate) fn inflight(&self) -> u32 {
        self.inflight.load(Ordering::Acquire)
    }

    /// Take the lifecycle exclusion; `false` while another lifecycle op is in flight.
    pub(crate) fn enter_lifecycle(&self) -> bool {
        self.lifecycle_busy
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    pub(crate) fn leave_lifecycle(&self) {
        self.lifecycle_busy.store(false, Ordering::Release);
    }

    /// What the host answers WITHOUT calling the plugin, if anything: a faulted instance, a slot
    /// the table does not have, an instance-less call before `open`, a second `open`, or an `open`
    /// whose frame cannot hold `OpenIn`/`OpenOut`.
    pub(crate) fn refuse(&self, s: u32, in_size: usize, out_size: usize) -> Option<Outcome> {
        if self.faulted.load(Ordering::Acquire) {
            return Some(Outcome::Fault);
        }
        if s >= self.slot_count() {
            return Some(Outcome::Refused);
        }
        let open = self.is_open();
        match s {
            slot::VALIDATE => None,
            slot::OPEN if open => Some(Outcome::Refused),
            slot::OPEN if in_size < size_of::<OpenIn>() || out_size < size_of::<OpenOut>() => {
                Some(Outcome::Refused)
            }
            slot::OPEN => None,
            _ if !open => Some(Outcome::Refused),
            _ => None,
        }
    }

    /// THE CROSSING: pre-fill the head, call the slot, judge the answer, copy what the host keeps.
    ///
    /// # Safety
    /// `input`/`out` lead with their heads and are `in_size`/`out_size` bytes, live and not
    /// aliased for the call; `s` passed [`Instance::refuse`].
    pub(crate) unsafe fn cross(
        &self,
        s: u32,
        input: *mut InHead,
        out: *mut OutHead,
        out_size: u32,
    ) -> Crossed {
        // SAFETY: the caller's contract.
        let (ticket, instance) = unsafe {
            let head = &mut *input;
            head.op = s;
            head.host = self.ctx();
            (head.ticket, self.ptr.load(Ordering::Acquire))
        };
        if s == slot::OPEN {
            // SAFETY: `refuse` checked the frame holds an `OpenIn`.
            unsafe { (*input.cast::<OpenIn>()).host = &*self.tables.0 };
        }
        // THE HOST ZEROES THE WHOLE `out` BEFORE EVERY CALL, RESUME included (FAULT = 0, every
        // tail field absent), then states its size: the plugin writes at most min(out.size, own).
        // SAFETY: `out` is the host's own `out_size` bytes.
        unsafe {
            std::ptr::write_bytes(out.cast::<u8>(), 0, out_size as usize);
            (*out).size = out_size;
        }
        let op = self.slots[s as usize];
        let raw = op(instance, input.cast_const().cast(), out.cast());
        // SAFETY: the plugin wrote at most the host's `out`; read it back.
        let head = unsafe { *out };
        let outcome = judge(raw, &head, ticket, out_size);
        if outcome == Outcome::Fault {
            return Crossed::host(Outcome::Fault);
        }
        let answered = matches!(outcome, Outcome::Ready | Outcome::Failed);
        if answered && !(self.check)(s, input.cast_const(), out.cast_const()) {
            return Crossed::host(Outcome::Fault);
        }
        let short = outcome == Outcome::Failed && (self.short)(s, out.cast_const());
        self.ingest(&head);
        let error = matches!(outcome, Outcome::Failed | Outcome::Refused)
            .then(|| copy_str(head.error))
            .flatten();
        match (s, outcome) {
            (slot::OPEN, Outcome::Ready) => {
                // SAFETY: `refuse` checked the frame holds an `OpenOut`.
                let inst = unsafe { (*out.cast::<OpenOut>()).instance };
                if inst.is_null() {
                    return Crossed::host(Outcome::Fault);
                }
                self.ptr.store(inst, Ordering::Release);
            }
            (slot::CLOSE, Outcome::Ready) => {
                self.ptr.store(std::ptr::null_mut(), Ordering::Release)
            }
            _ => {}
        }
        Crossed {
            outcome,
            error,
            lease: head.lease,
            wake_at_ns: if outcome == Outcome::Pending {
                head.wake_at_ns
            } else {
                0
            },
            short,
        }
    }

    /// The #85 envelope, range-checked against the Statement and handed to the sink.
    fn ingest(&self, head: &OutHead) {
        let env = head.envelope;
        // SAFETY: the envelope's arrays are plugin memory valid until the next op on the ticket
        // (NONE: until this crossing returned); read here, before either.
        let metrics = unsafe { array(env.metrics, env.metrics_len) };
        match metrics {
            Some(ms) => ms.iter().for_each(|m| self.metric(m)),
            None => self.sink.dropped(Dropped::BadArray),
        }
        let diags = unsafe { array(env.diags, env.diags_len) };
        match diags {
            Some(ds) => ds.iter().for_each(|d| self.diag(d)),
            None => self.sink.dropped(Dropped::BadArray),
        }
    }

    fn metric(&self, m: &MetricEntry) {
        let Some(fam) = self.families.get(m.family_idx as usize) else {
            return self.sink.dropped(Dropped::FamilyOutOfRange(m.family_idx));
        };
        let fits = matches!(
            (m.kind, fam.kind),
            (METRIC_ADD, FAMILY_COUNTER)
                | (METRIC_SET, FAMILY_GAUGE)
                | (METRIC_OBSERVE, FAMILY_HISTOGRAM)
        );
        if !fits {
            return self.sink.dropped(Dropped::KindMismatch {
                family: m.family_idx,
                kind: m.kind,
            });
        }
        if !m.value.is_finite() {
            return self.sink.dropped(Dropped::NonFinite(m.family_idx));
        }
        if m.label_vals_len != fam.labels {
            return self.sink.dropped(Dropped::LabelCount(m.family_idx));
        }
        // SAFETY: as `ingest`.
        let Some(vals) = (unsafe { array(m.label_vals, m.label_vals_len) }) else {
            return self.sink.dropped(Dropped::BadArray);
        };
        let labels: Vec<&[u8]> = vals.iter().map(|v| str_bytes(*v)).collect();
        self.sink.metric(Metric {
            family: m.family_idx,
            kind: m.kind,
            value: m.value,
            labels: &labels,
        });
    }

    fn diag(&self, d: &Diag) {
        if d.id_idx as usize >= self.diag_ids {
            return self.sink.dropped(Dropped::DiagOutOfRange(d.id_idx));
        }
        if d.severity > 2 {
            return self.sink.dropped(Dropped::Severity(d.id_idx));
        }
        let text = str_bytes(d.text);
        self.sink.diag(Diagnostic {
            id: d.id_idx,
            severity: d.severity,
            text: &text[..text.len().min(MAX_TEXT)],
        });
    }
}

/// OUTCOME AUTHORITY: the return value decides; see the module docs.
pub(crate) fn judge(raw: RawOutcome, head: &OutHead, ticket: Ticket, out_size: u32) -> Outcome {
    if !(1..=4).contains(&raw.0) || head.outcome != raw {
        return Outcome::Fault;
    }
    // Validated before a byte is read through it (`validate`): size, error text, #85 arrays.
    if let Err(v) = validate::out_head(head, out_size) {
        return v.outcome();
    }
    match raw.outcome() {
        Outcome::Pending if ticket.is_none() => Outcome::Fault,
        o => o,
    }
}

/// `len` entries at `p`, or `None` for NULL-with-length or an over-long array.
///
/// # Safety
/// A non-NULL `p` points to `len` live `T`s.
unsafe fn array<'a, T>(p: *const T, len: usize) -> Option<&'a [T]> {
    match (p.is_null(), len) {
        (_, 0) => Some(&[]),
        (true, _) => None,
        (false, n) if n > MAX_ENVELOPE_ENTRIES => None,
        // SAFETY: the caller's contract.
        (false, n) => Some(unsafe { std::slice::from_raw_parts(p, n) }),
    }
}

/// A borrowed string's bytes; NULL reads as empty.
fn str_bytes<'a>(s: AbiStr) -> &'a [u8] {
    if s.ptr.is_null() || s.len == 0 {
        return &[];
    }
    // SAFETY: a non-NULL `AbiStr` in an `out` names `len` live bytes until the next op on the ticket.
    unsafe { std::slice::from_raw_parts(s.ptr, s.len) }
}

/// A copy of at most [`MAX_TEXT`] bytes; `None` for absent text.
fn copy_str(s: AbiStr) -> Option<Vec<u8>> {
    (!s.ptr.is_null()).then(|| {
        let b = str_bytes(s);
        b[..b.len().min(MAX_TEXT)].to_vec()
    })
}

/// A loaded plugin of kind `K`: one instance, called through its table. Cheap to clone; every clone
/// is the same instance.
pub struct Plugin<K: Kind> {
    pub(crate) inner: Arc<Instance>,
    _k: PhantomData<fn() -> K>,
}

impl<K: Kind> Clone for Plugin<K> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            _k: PhantomData,
        }
    }
}

impl<K: Kind> std::fmt::Debug for Plugin<K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Plugin")
            .field("kind", &self.inner.kind)
            .field("name", &self.inner.name())
            .field("max_inflight", &self.inner.cap)
            .finish_non_exhaustive()
    }
}

impl<K: Kind> Plugin<K> {
    pub(crate) fn bind(v: Validated, lib: Option<Lib>, bind: Bind) -> Result<Self, LoadError> {
        let st = v.statement;
        let families = (0..st.families_len)
            .map(|i| {
                // SAFETY: `validate` checked `families` holds `families_len` entries.
                let f = unsafe { st.families.add(i).read_unaligned() };
                FamilyShape {
                    kind: f.kind,
                    labels: f.label_keys_len,
                }
            })
            .collect();
        // One small leak per instance: a plugin may call `wake` with this context at any time, even
        // late, so it must never dangle.
        let wake: &'static InstanceWake = Box::leak(Box::default());
        let tables = Tables(Box::new(HostTables {
            size: size_of::<HostTables>() as u32,
            _reserved: 0,
            ctx: HostCtx {
                ptr: std::ptr::from_ref(wake).cast_mut().cast(),
            },
            wake: Some(host_wake),
            conns: std::ptr::null(),
        }));
        Ok(Self {
            inner: Arc::new(Instance {
                kind: v.kind,
                name: String::from_utf8_lossy(str_bytes(st.name)).into_owned(),
                slots: v.slots,
                families,
                diag_ids: st.diag_ids_len,
                ptr: AtomicPtr::new(std::ptr::null_mut()),
                faulted: AtomicBool::new(false),
                inflight: AtomicU32::new(0),
                drainable: AtomicU32::new(0),
                cap: st.max_inflight.clamp(1, bind.max_inflight_cap.max(1)),
                lifecycle_busy: AtomicBool::new(false),
                timeout: K::TIMEOUT,
                check: K::check,
                short: K::short,
                sink: bind.sink,
                wake,
                tables,
                _lib: lib,
            }),
            _k: PhantomData,
        })
    }

    /// The kind.
    pub fn kind(&self) -> KindCode {
        self.inner.kind
    }

    /// The Statement's name.
    pub fn name(&self) -> &str {
        self.inner.name()
    }

    /// `max_inflight`, as the host clamped it.
    pub fn max_inflight(&self) -> u32 {
        self.inner.cap
    }

    /// Ops holding a `max_inflight` unit now.
    pub fn inflight(&self) -> u32 {
        self.inner.inflight()
    }

    /// Whether the watchdog faulted this instance. A faulted instance is never called again: every
    /// op on it answers FAULT without a crossing.
    pub fn is_faulted(&self) -> bool {
        self.inner.faulted.load(Ordering::Acquire)
    }

    /// Whether `open` answered READY and `close` has not.
    pub fn is_open(&self) -> bool {
        self.inner.is_open()
    }

    /// A TICKET-LESS call ([`Ticket::NONE`]): on the caller's thread, never serialized, may not
    /// pend (PENDING is FAULT). Everything the plugin pointed at is copied before this returns.
    pub fn call<I: InFrame, O: OutFrame>(&self, s: u32, frame: &mut Frame<I, O>) -> Called {
        let inst = &*self.inner;
        if let Some(o) = inst.refuse(s, size_of::<I>(), size_of::<O>()) {
            return Called::from(Crossed::host(o));
        }
        let lifecycle = is_lifecycle(s);
        if lifecycle && !inst.enter_lifecycle() {
            return Called::from(Crossed::host(Outcome::Refused));
        }
        if !inst.acquire() {
            if lifecycle {
                inst.leave_lifecycle();
            }
            return Called::from(Crossed::host(Outcome::Refused));
        }
        let (i, o, out_size) = frame.heads();
        // SAFETY: the frame is ours for the call; its heads lead the structs.
        let crossed = unsafe {
            let head = &mut *i;
            head.size = size_of::<I>() as u32;
            head.flags = 0;
            head.deadline_class = DeadlineClass::Call as u8;
            head.ticket = Ticket::NONE;
            inst.cross(s, i, o, out_size)
        };
        inst.release();
        if lifecycle {
            inst.leave_lifecycle();
        }
        Called::from(crossed)
    }
}

impl From<Crossed> for Called {
    fn from(c: Crossed) -> Self {
        Self {
            outcome: c.outcome,
            error: c.error,
            lease: c.lease,
        }
    }
}
