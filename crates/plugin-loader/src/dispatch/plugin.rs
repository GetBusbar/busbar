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
//! PLUGIN LOGGING rides the same envelope: a [`DIAG_LOG`] entry is a log record the plugin emitted
//! during the call (severity 0..=4), and a [`DIAG_LOG_DROPPED`] entry counts the records its own
//! capture could not keep. The host bounds the records of one reply at [`MAX_LOG_RECORDS`] and
//! [`MAX_LOG_BYTES`]; whatever is over, plus what the plugin counted, is ONE
//! [`Dropped::Logs`] per reply. The sink writes the rest to the plugin's own log file.
//!
//! `max_inflight`. The Statement's figure, clamped by the host to `1..=`[`Bind::max_inflight_cap`].
//! Every op holds one unit from submission to completion (driver tickets hold none); over the cap
//! the op answers REFUSED and the plugin is never called.

use std::marker::PhantomData;
use std::mem::size_of;
use std::os::raw::c_void;
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use busbar_contract::abi::mechanism::call::{
    AbiStr, DeadlineClass, Diag, InHead, MetricEntry, Op, OutHead, Outcome, RawOutcome, DIAG_LOG,
    DIAG_LOG_DROPPED, METRIC_ADD, METRIC_OBSERVE, METRIC_SET, SEVERITY_ERROR, SEVERITY_TRACE,
};
use busbar_contract::abi::mechanism::door::{FAMILY_COUNTER, FAMILY_GAUGE, FAMILY_HISTOGRAM};
use busbar_contract::abi::mechanism::lifecycle::{slot, OpenIn, OpenOut};
use busbar_contract::abi::mechanism::ticket::{HostCtx, HostTables, Ticket};
use busbar_contract::abi::mechanism::KindCode;

use super::answer::Answer;
use super::load::{Lib, LoadError, Validated};
use super::ticket::{host_wake, InstanceWake};
use super::{validate, Frame, InFrame, Kind, OutFrame};
use busbar_contract::abi::mechanism::check::Fault;

/// The most entries one envelope array may carry; a longer array is dropped whole.
pub const MAX_ENVELOPE_ENTRIES: usize = busbar_contract::abi::mechanism::call::MAX_ENVELOPE_ENTRIES;
/// The most bytes of error or diagnostic text the host copies; longer text is cut.
pub const MAX_TEXT: usize = busbar_contract::abi::mechanism::call::MAX_TEXT;
/// The most log records the host keeps from one reply; the rest count as [`Dropped::Logs`].
pub const MAX_LOG_RECORDS: usize = 128;
/// The most bytes of log-record text the host keeps from one reply; the record that would pass it,
/// and every one after, count as [`Dropped::Logs`].
pub const MAX_LOG_BYTES: usize = 64 * 1024;

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
    /// The id's index in the Statement, or [`DIAG_LOG`] for a log record.
    pub id: u32,
    /// The declared id's name; empty for a log record.
    pub name: &'a [u8],
    /// `0` info, `1` warn, `2` error; a log record may also be `3` debug or `4` trace.
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
    /// A diagnostic's severity is not 0..=2 (0..=4 for a log record).
    Severity(u32),
    /// Log records of one reply the host did not keep: those over its bound, plus those the
    /// plugin's own capture counted as dropped. At most one per reply.
    Logs(u64),
    /// An array is NULL with a non-zero length, or longer than [`MAX_ENVELOPE_ENTRIES`].
    BadArray,
}

/// Where the #85 envelope goes. Names no kernel type; the kernel implements it per kind.
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
    /// The dispatcher that ADOPTS the instance at bind: its wakes route there and its watchdog
    /// watches every crossing from the first (a ticket-less `validate` or `open` included).
    /// REQUIRED: a production bind cannot skip the watchdog.
    ///
    /// ```compile_fail
    /// let sink = std::sync::Arc::new(busbar_plugin_loader::dispatch::NoSink);
    /// // missing field `dispatcher`: there is no unwatched production bind
    /// let _ = busbar_plugin_loader::dispatch::Bind { max_inflight_cap: 1, sink };
    /// ```
    pub dispatcher: super::worker::Adopter,
}

impl std::fmt::Debug for Bind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Bind")
            .field("max_inflight_cap", &self.max_inflight_cap)
            .finish_non_exhaustive()
    }
}

/// THE ONE RE-CALL a SHORT answer earns: consumed by [`Plugin::recall`], and neither `Clone` nor
/// `Copy`, so it cannot be spent twice.
///
/// ```compile_fail
/// fn twice<K: busbar_plugin_loader::dispatch::Kind>(
///     p: &busbar_plugin_loader::dispatch::Plugin<K>,
///     r: busbar_plugin_loader::dispatch::Recall,
///     f: &mut busbar_plugin_loader::dispatch::Frame<
///         busbar_contract::abi::mechanism::call::InHead,
///         busbar_contract::abi::mechanism::call::OutHead,
///     >,
/// ) {
///     let _ = p.recall(r, 4, f);
///     let _ = p.recall(r, 4, f); // use of moved value: a token is spent once
/// }
/// ```
#[derive(Debug, PartialEq, Eq)]
pub struct Recall {
    /// The instance that answered short.
    instance: usize,
    /// The op that answered short.
    slot: u32,
}

/// What one ticket-less call answered, copied out of the plugin's memory.
#[derive(Debug, PartialEq, Eq)]
pub struct Called {
    /// The authoritative outcome.
    pub outcome: Outcome,
    /// The error text, for FAILED/REFUSED.
    pub error: Option<Vec<u8>>,
    /// A lease the caller hands back to `release`; `0` = none.
    pub lease: u64,
    /// For a FAILED answer the kind calls SHORT ([`Kind::short`]): the token for the ONE re-call,
    /// through [`Plugin::recall`], with bigger buffers.
    pub recall: Option<Recall>,
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
    /// `cancel`'s `CancelOut.disposition`, when the op ended through `cancel`.
    pub(crate) disposition: Option<u32>,
}

impl Crossed {
    pub(crate) fn host(outcome: Outcome) -> Self {
        Self {
            outcome,
            error: None,
            lease: 0,
            wake_at_ns: 0,
            short: false,
            disposition: None,
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
    diag_ids: DiagIds,
    ptr: AtomicPtr<c_void>,
    pub(crate) faulted: AtomicBool,
    /// `close` answered READY: every later op answers FAULT without a crossing.
    closed: AtomicBool,
    /// THE CROSSING GATE: the count of crossings in progress, with [`CLOSING`] set while `close`
    /// crosses (and kept once it closed). `close` enters only when nothing else is crossing, and
    /// nothing enters while it is set, so no crossing ever meets a freed instance.
    gate: AtomicU32,
    /// Crossings actually made (the witness of "without a crossing").
    pub(crate) crossings: AtomicU64,
    /// The ticket-less crossings in progress, for the watchdog: `(id, started, slot)`.
    pub(crate) calls: Mutex<Vec<(u64, Instant, u32)>>,
    next_call: AtomicU64,
    inflight: AtomicU32,
    /// Ops in flight that a reload drain waits for: every op but WriteBehind.
    pub(crate) drainable: AtomicU32,
    pub(crate) cap: u32,
    lifecycle_busy: AtomicBool,
    pub(crate) timeout: Outcome,
    /// [`Kind::check`] of the bound kind.
    check: fn(&Answer) -> Result<(), Fault>,
    /// [`Kind::short`] of the bound kind.
    short: fn(&Answer) -> bool,
    /// [`Kind::op_name`] of the bound kind.
    op_name: fn(u32) -> &'static str,
    /// [`Kind::context`] of the bound kind, built from the Statement at bind.
    context: Option<Box<super::Context>>,
    sink: Arc<dyn EnvelopeSink>,
    pub(crate) wake: &'static InstanceWake,
    tables: Tables,
    /// Last: the library outlives everything above.
    _lib: Option<Lib>,
}

/// The Statement's declared diagnostic ids: `'static` door data, alive while the instance holds its
/// library, read when a diagnostic names one.
struct DiagIds {
    ptr: *const AbiStr,
    len: usize,
}
// SAFETY: the ids are immutable `'static` door data, only ever read.
unsafe impl Send for DiagIds {}
unsafe impl Sync for DiagIds {}

impl DiagIds {
    fn name(&self, idx: u32) -> Option<&[u8]> {
        let i = idx as usize;
        if i >= self.len {
            return None;
        }
        // SAFETY: `validate` checked `diag_ids` holds `diag_ids_len` entries.
        str_bytes(unsafe { self.ptr.add(i).read_unaligned() })
    }
}

/// What one reply's log records have used of the host's bound.
#[derive(Default)]
struct LogBudget {
    records: usize,
    bytes: usize,
    dropped: u64,
}

/// The gate bit `close` holds.
const CLOSING: u32 = 1 << 31;

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

    /// Take the `max_inflight` units op `s` needs: one, or for `close` ALL of them and only when
    /// no other op is in flight (one atomic step). `None` over the cap, or `close` with ops in
    /// flight.
    pub(crate) fn acquire(&self, s: u32) -> Option<u32> {
        let close = s == slot::CLOSE;
        let want = if close { self.cap } else { 1 };
        self.inflight
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                let fits = if close { n == 0 } else { n < self.cap };
                fits.then_some(n + want)
            })
            .ok()
            .map(|_| want)
    }

    pub(crate) fn release(&self, units: u32) {
        self.inflight.fetch_sub(units, Ordering::AcqRel);
    }

    /// Enter the crossing gate for op `s`; see [`Instance::gate`].
    fn enter_gate(&self, s: u32) -> bool {
        if s == slot::CLOSE {
            return self
                .gate
                .compare_exchange(0, CLOSING | 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok();
        }
        self.gate
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |g| {
                (g & CLOSING == 0).then_some(g + 1)
            })
            .is_ok()
    }

    fn leave_gate(&self, s: u32, closed: bool) {
        match (s == slot::CLOSE, closed) {
            // Closed for good: the gate stays shut.
            (true, true) => self.gate.store(CLOSING, Ordering::Release),
            (true, false) => self.gate.store(0, Ordering::Release),
            _ => {
                self.gate.fetch_sub(1, Ordering::AcqRel);
            }
        }
    }

    pub(crate) fn lock_calls(&self) -> std::sync::MutexGuard<'_, Vec<(u64, Instant, u32)>> {
        self.calls.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Whether `close` answered READY.
    pub(crate) fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
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
        if self.faulted.load(Ordering::Acquire) || self.is_closed() {
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
        if !self.enter_gate(s) {
            // `close` with a crossing in progress is refused; anything after `close` is FAULT.
            let o = if s == slot::CLOSE {
                Outcome::Refused
            } else {
                Outcome::Fault
            };
            return Crossed::host(o);
        }
        // SAFETY: the caller's contract.
        let crossed = unsafe { self.cross_gated(s, input, out, out_size) };
        self.leave_gate(s, s == slot::CLOSE && crossed.outcome == Outcome::Ready);
        crossed
    }

    /// [`Instance::cross`] inside the gate.
    ///
    /// # Safety
    /// As [`Instance::cross`].
    unsafe fn cross_gated(
        &self,
        s: u32,
        input: *mut InHead,
        out: *mut OutHead,
        out_size: u32,
    ) -> Crossed {
        let needs_instance = !matches!(s, slot::VALIDATE | slot::OPEN);
        if self.is_closed() || (needs_instance && !self.is_open()) {
            return Crossed::host(Outcome::Fault);
        }
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
        self.crossings.fetch_add(1, Ordering::Relaxed);
        let raw = op(instance, input.cast_const().cast(), out.cast());
        // SAFETY: the plugin wrote at most the host's `out`; read it back.
        let head = unsafe { *out };
        let outcome = judge(raw, &head, ticket, out_size);
        if outcome == Outcome::Fault {
            return Crossed::host(Outcome::Fault);
        }
        // SAFETY: the op's own host `in`/`out`; the host wrote `in.size` itself.
        let answer = unsafe {
            Answer::new(
                s,
                outcome,
                input.cast_const(),
                (*input).size as usize,
                out.cast_const(),
                out_size as usize,
            )
        };
        // Every outcome but FAULT is judged: each kind's check decides what an outcome carries.
        let answer = answer.with_context(self.context.as_deref());
        {
            if let Err(f) = (self.check)(&answer) {
                tracing::warn!(
                    plugin = %self.name,
                    kind = ?self.kind,
                    op = (self.op_name)(s),
                    rule = ?f.rule,
                    field = f.field,
                    "a plugin answer broke its kind's rule; the op answers FAULT"
                );
                return Crossed::host(Outcome::Fault);
            }
        }
        let short = outcome == Outcome::Failed && (self.short)(&answer);
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
                self.closed.store(true, Ordering::Release);
                self.ptr.store(std::ptr::null_mut(), Ordering::Release);
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
            disposition: None,
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
        let mut budget = LogBudget::default();
        match diags {
            Some(ds) => ds.iter().for_each(|d| self.diag(d, &mut budget)),
            None => self.sink.dropped(Dropped::BadArray),
        }
        if budget.dropped > 0 {
            self.sink.dropped(Dropped::Logs(budget.dropped));
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
        let Some(labels) = vals
            .iter()
            .map(|v| str_bytes(*v))
            .collect::<Option<Vec<&[u8]>>>()
        else {
            return self.sink.dropped(Dropped::BadArray);
        };
        self.sink.metric(Metric {
            family: m.family_idx,
            kind: m.kind,
            value: m.value,
            labels: &labels,
        });
    }

    fn diag(&self, d: &Diag, budget: &mut LogBudget) {
        match d.id_idx {
            DIAG_LOG_DROPPED => {
                // What the plugin's capture could not keep; malformed text counts as one.
                let n = str_bytes(d.text)
                    .and_then(|t| std::str::from_utf8(t).ok())
                    .and_then(|t| t.parse::<u64>().ok())
                    .unwrap_or(1);
                budget.dropped = budget.dropped.saturating_add(n);
            }
            DIAG_LOG => self.log(d, budget),
            id => {
                let Some(name) = self.diag_ids.name(id) else {
                    return self.sink.dropped(Dropped::DiagOutOfRange(id));
                };
                if d.severity > SEVERITY_ERROR {
                    return self.sink.dropped(Dropped::Severity(id));
                }
                let Some(text) = str_bytes(d.text) else {
                    return self.sink.dropped(Dropped::BadArray);
                };
                self.sink.diag(Diagnostic {
                    id,
                    name,
                    severity: d.severity,
                    text,
                });
            }
        }
    }

    /// One log record, inside the reply's [`LogBudget`].
    fn log(&self, d: &Diag, budget: &mut LogBudget) {
        if d.severity > SEVERITY_TRACE {
            return self.sink.dropped(Dropped::Severity(DIAG_LOG));
        }
        let Some(text) = str_bytes(d.text) else {
            return self.sink.dropped(Dropped::BadArray);
        };
        if budget.records >= MAX_LOG_RECORDS || budget.bytes + text.len() > MAX_LOG_BYTES {
            // Once over, every later record of the reply is over too: counts stay exact.
            budget.records = MAX_LOG_RECORDS;
            budget.dropped += 1;
            return;
        }
        budget.records += 1;
        budget.bytes += text.len();
        self.sink.diag(Diagnostic {
            id: DIAG_LOG,
            name: &[],
            severity: d.severity,
            text,
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

/// A borrowed string's bytes; NULL-and-empty reads as empty. The length is capped BEFORE any
/// slice is made: over [`MAX_TEXT`], or non-empty behind NULL, is `None` (a malformed answer).
pub(crate) fn str_bytes<'a>(s: AbiStr) -> Option<&'a [u8]> {
    if s.len == 0 {
        return Some(&[]);
    }
    if s.ptr.is_null() || s.len > MAX_TEXT {
        return None;
    }
    // SAFETY: a non-NULL `AbiStr` in an `out` names `len` (<= MAX_TEXT) live bytes until the next
    // op on the ticket.
    Some(unsafe { std::slice::from_raw_parts(s.ptr, s.len) })
}

/// A copy of the text; `None` for absent (or malformed, which `validate` refused before).
fn copy_str(s: AbiStr) -> Option<Vec<u8>> {
    (!s.ptr.is_null())
        .then(|| str_bytes(s).map(<[u8]>::to_vec))
        .flatten()
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
            services: &super::services::HOST_SLOTS,
        }));
        let name = str_bytes(st.name)
            .ok_or_else(|| LoadError::BadStatement("the name is NULL or over-long".into()))?;
        let context = K::context(&st).map_err(LoadError::KindTail)?;
        let plugin = Self {
            inner: Arc::new(Instance {
                kind: v.kind,
                name: String::from_utf8_lossy(name).into_owned(),
                slots: v.slots,
                families,
                diag_ids: DiagIds {
                    ptr: st.diag_ids,
                    len: st.diag_ids_len,
                },
                ptr: AtomicPtr::new(std::ptr::null_mut()),
                faulted: AtomicBool::new(false),
                closed: AtomicBool::new(false),
                gate: AtomicU32::new(0),
                crossings: AtomicU64::new(0),
                calls: Mutex::new(Vec::new()),
                next_call: AtomicU64::new(0),
                inflight: AtomicU32::new(0),
                drainable: AtomicU32::new(0),
                cap: st.max_inflight.clamp(1, bind.max_inflight_cap.max(1)),
                lifecycle_busy: AtomicBool::new(false),
                timeout: K::TIMEOUT,
                check: K::check,
                short: K::short,
                op_name: K::op_name,
                context,
                sink: bind.sink.clone(),
                wake,
                tables,
                _lib: lib,
            }),
            _k: PhantomData,
        };
        bind.dispatcher.adopt(&plugin.inner);
        Ok(plugin)
    }

    /// What the kind read from the Statement at bind ([`Kind::context`]), as the kind's type `T`.
    pub fn context<T: 'static>(&self) -> Option<&T> {
        self.inner
            .context
            .as_deref()
            .and_then(|c| c.downcast_ref::<T>())
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
    /// pend (PENDING is FAULT). Everything the plugin pointed at is copied before this returns. The
    /// crossing is recorded for the watchdog of the dispatcher that adopted the instance: past its
    /// budget the instance is faulted (the caller's thread cannot be replaced).
    pub fn call<I: InFrame, O: OutFrame>(&self, s: u32, frame: &mut Frame<I, O>) -> Called {
        self.call_once(s, frame, false)
    }

    /// THE ONE RE-CALL of a SHORT answer, spending its [`Recall`] token, with the caller's bigger
    /// buffers in `frame`. REFUSED without a crossing when the token is another instance's or
    /// another op's; a second short answer is FAULT (the short-buffer rule on `OutHead`).
    pub fn recall<I: InFrame, O: OutFrame>(
        &self,
        token: Recall,
        s: u32,
        frame: &mut Frame<I, O>,
    ) -> Called {
        if token.instance != self.instance_id() || token.slot != s {
            return Called::from(Crossed::host(Outcome::Refused));
        }
        self.call_once(s, frame, true)
    }

    fn instance_id(&self) -> usize {
        Arc::as_ptr(&self.inner) as usize
    }

    fn call_once<I: InFrame, O: OutFrame>(
        &self,
        s: u32,
        frame: &mut Frame<I, O>,
        recall: bool,
    ) -> Called {
        let inst = &*self.inner;
        if let Some(o) = inst.refuse(s, size_of::<I>(), size_of::<O>()) {
            return Called::from(Crossed::host(o));
        }
        let lifecycle = is_lifecycle(s);
        if lifecycle && !inst.enter_lifecycle() {
            return Called::from(Crossed::host(Outcome::Refused));
        }
        let Some(units) = inst.acquire(s) else {
            if lifecycle {
                inst.leave_lifecycle();
            }
            return Called::from(Crossed::host(Outcome::Refused));
        };
        let (i, o, out_size) = frame.heads();
        let id = inst.next_call.fetch_add(1, Ordering::Relaxed);
        inst.lock_calls().push((id, Instant::now(), s));
        // SAFETY: the frame is ours for the call; its heads lead the structs.
        let crossed = unsafe {
            let head = &mut *i;
            head.size = size_of::<I>() as u32;
            head.flags = 0;
            head.deadline_class = DeadlineClass::Call as u8;
            head.ticket = Ticket::NONE;
            inst.cross(s, i, o, out_size)
        };
        inst.lock_calls().retain(|c| c.0 != id);
        inst.release(units);
        if lifecycle {
            inst.leave_lifecycle();
        }
        if recall && crossed.short {
            return Called::from(Crossed::host(Outcome::Fault));
        }
        let token = crossed.short.then(|| Recall {
            instance: self.instance_id(),
            slot: s,
        });
        Called {
            recall: token,
            ..Called::from(crossed)
        }
    }
}

impl From<Crossed> for Called {
    fn from(c: Crossed) -> Self {
        Self {
            outcome: c.outcome,
            error: c.error,
            lease: c.lease,
            recall: None,
        }
    }
}
