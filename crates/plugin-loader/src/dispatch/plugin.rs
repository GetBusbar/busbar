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

use busbar_contract::abi::host::conn::connector::DIRECTION_OUTBOUND;
use busbar_contract::abi::mechanism::call::{
    AbiStr, Blob, DeadlineClass, Diag, InHead, MetricEntry, Op, OutHead, Outcome, RawOutcome,
    DIAG_LOG, DIAG_LOG_DROPPED, FLAG_RESUME, METRIC_ADD, METRIC_OBSERVE, METRIC_SET,
    SEVERITY_ERROR, SEVERITY_TRACE,
};
use busbar_contract::abi::mechanism::door::{FAMILY_COUNTER, FAMILY_GAUGE, FAMILY_HISTOGRAM};
use busbar_contract::abi::mechanism::lifecycle::{
    slot, OpenIn, OpenOut, ReadyIn, RefreshIn, ValidateIn,
};
use busbar_contract::abi::mechanism::rendering::ReadNeed;
use busbar_contract::abi::mechanism::ticket::{HostCtx, HostTables, Ticket};
use busbar_contract::abi::mechanism::KindCode;
use busbar_contract::conn::{InstanceId, NeedId};

use super::answer::Answer;
use super::load::{Lib, LoadError, Validated};
use super::ticket::{host_wake, InstanceWake};
use super::{validate, Frame, InFrame, Kind, OutFrame};
use busbar_contract::abi::mechanism::check::Fault;

/// The most entries one envelope array may carry; a longer array is dropped whole.
pub const MAX_ENVELOPE_ENTRIES: usize = busbar_contract::abi::mechanism::call::MAX_ENVELOPE_ENTRIES;
/// The most bytes of error or diagnostic text the host copies; longer text is cut.
pub const MAX_TEXT: usize = busbar_contract::abi::mechanism::call::MAX_TEXT;
/// How many bytes of reason the host lends every `open` ([`OpenIn::err_cap`]).
pub const OPEN_REASON_CAP: usize = MAX_TEXT;
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

/// The next instance identity bind mints; `0` is never minted.
static NEXT_INSTANCE: AtomicU64 = AtomicU64::new(1);

/// MINT ONE INSTANCE IDENTITY off `next`, never `0`: `0` is the composition root's own identity on
/// the one connector (`busbar`'s `root::connector::ROOT_OWNER`, the authorization server's needs),
/// so a plugin minted `0` would share that table's needs and connections. A counter that wraps
/// past `u64::MAX` skips `0` rather than handing it out.
fn mint_instance(next: &AtomicU64) -> InstanceId {
    loop {
        let id = next.fetch_add(1, Ordering::Relaxed);
        if id != 0 {
            return InstanceId(id);
        }
    }
}

/// What the host binds a loaded plugin to.
#[derive(Clone)]
pub struct Bind {
    /// The host's label for this opened instance, unique per instance: two instances of one plugin
    /// share a Statement name and never a label. The host services know the instance by it.
    pub instance: Arc<str>,
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
    /// let _ = busbar_plugin_loader::dispatch::Bind { instance: "a".into(), max_inflight_cap: 1, sink };
    /// ```
    pub dispatcher: super::worker::Adopter,
    /// The host's ONE connection table, or why the bind has none, stated at every call site
    /// ([`ConnTable`]). An instance whose Statement declares a need is declared on the table at bind
    /// (each need under its Statement index) and handed the connector slots
    /// ([`super::conn_services::CONN_SLOTS`]); any other instance is handed none.
    pub conns: ConnTable,
}

/// THE BIND'S CONNECTION TABLE (Q-P4-3): the host's table, or, explicitly, why there is none. A
/// door that declares a need and is bound to serve with no table is REFUSED at bind, naming the
/// plugin ([`LoadError::NoConnectionTable`]); only a probe binds it with none.
#[derive(Clone)]
pub enum ConnTable {
    /// The host's one connection table: a need the Statement declares is declared on it.
    Host(Arc<dyn busbar_contract::conn::DeclaredConns>),
    /// A PROBE or CHECK bind: the instance is only validated or read for its facts, never opened to
    /// serve, so a need it declares is not declared and it is handed no table (nothing is opened to
    /// the network while a configuration is judged). Not refused.
    Probe,
    /// A bind to SERVE with no connection table: the door must declare no need. One that declares
    /// a need is refused ([`LoadError::NoConnectionTable`]).
    NoNeeds,
}

impl ConnTable {
    /// A SERVING bind over the table an axis holds: [`ConnTable::Host`] when it holds one, else
    /// [`ConnTable::NoNeeds`] (an axis handed no table serves only doors that declare no need).
    #[must_use]
    pub fn serving(table: Option<Arc<dyn busbar_contract::conn::DeclaredConns>>) -> Self {
        table.map_or(Self::NoNeeds, Self::Host)
    }

    /// The table, when the bind has one.
    #[must_use]
    pub fn table(&self) -> Option<&Arc<dyn busbar_contract::conn::DeclaredConns>> {
        match self {
            Self::Host(t) => Some(t),
            Self::Probe | Self::NoNeeds => None,
        }
    }
}

impl std::fmt::Debug for ConnTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Host(_) => "Host",
            Self::Probe => "Probe",
            Self::NoNeeds => "NoNeeds",
        })
    }
}

impl std::fmt::Debug for Bind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Bind")
            .field("instance", &self.instance)
            .field("max_inflight_cap", &self.max_inflight_cap)
            .field("conns", &self.conns)
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

impl Called {
    /// THE OPERATOR'S TEXT FOR AN `open` THAT DID NOT ANSWER READY, 1.5.5's wording rebuilt from
    /// the host's own context: `plugin '{display}' open failed: {reason}`, `display` being the name
    /// the host knows the plugin by. The reason is what the plugin wrote into the host's lent
    /// reason buffer (or its error text), lossily UTF-8. A plugin that wrote nothing reads as
    /// 1.5.5 read a constructor error with no text, `status 1`; a FAULT (a panic, or an answer that
    /// broke the call contract) as `status 3`, 1.5.5's panic status.
    #[must_use]
    pub fn open_failure(&self, display: &str) -> String {
        let reason = match (&self.error, self.outcome) {
            (Some(e), _) if !e.is_empty() => String::from_utf8_lossy(e).into_owned(),
            (_, Outcome::Fault) => "status 3".to_string(),
            _ => "status 1".to_string(),
        };
        format!("plugin '{display}' open failed: {reason}")
    }
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
    /// The record writes that `cancel` carried (a plane's, SEAM-L(r)).
    pub(crate) cancel_writes: Vec<busbar_contract::plane_calls::CancelWrite>,
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
            cancel_writes: Vec::new(),
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
    /// The instance's identity on the host's connection table.
    pub(crate) instance: InstanceId,
    /// The needs its Statement declares, in Statement order (empty when it was handed no table).
    /// Each whose `target_from` or `trust_from` names a config path is declared at every `open` and
    /// `refresh`, with what those paths resolve to in the settings it is handed.
    needs: Box<[ReadNeed]>,
    /// The settings keys its Statement names as secret references (`Statement::secret_refs`), in
    /// order: the host resolves each and lends the material in `open`/`refresh`'s `secrets`.
    secret_refs: Box<[String]>,
    pub(crate) kind: KindCode,
    name: String,
    slots: Box<[Op]>,
    /// The door's optional `ready` ([`slot::READY`]); `None` = the instance has none.
    ready: Option<Op>,
    families: Box<[FamilyShape]>,
    diag_ids: DiagIds,
    /// The instance box: set by an `open` that answered READY, and ALSO by one that answered
    /// PENDING (its half-open box, which its RESUME runs on); nulled when an `open` ends any other
    /// way (FAULT included) and when `close` answered READY. An `open` the plugin answered READY or
    /// PENDING but the host judged FAULT leaves the plugin's live box half-open, and the host
    /// closes it at once ([`Instance::close_half_open`]); so does a pended `open` the host
    /// cancels (a deadline or a client drop: the worker's `cancel`, then its `close`).
    ptr: AtomicPtr<c_void>,
    /// `open` answered READY and `close` has not: what [`Instance::is_open`] reads. A half-open box
    /// (an `open` in flight that pended) is not open.
    opened: AtomicBool,
    pub(crate) faulted: AtomicBool,
    /// `close` of an OPEN instance answered READY, or any `close` answered FAULT: every later op
    /// answers FAULT without a crossing. (Closing a half-open box frees the box; the instance never
    /// opened, so it is not closed.)
    closed: AtomicBool,
    /// THE CROSSING GATE: the count of crossings in progress, with [`CLOSING`] set while `close`
    /// crosses (and kept once it closed). `close` enters only when nothing else is crossing, and
    /// nothing enters while it is set, so no crossing ever meets a freed instance.
    gate: AtomicU32,
    /// Crossings actually made (the witness of "without a crossing"), RESUMES included.
    pub(crate) crossings: AtomicU64,
    /// Of [`Instance::crossings`], the RESUME re-invocations ([`FLAG_RESUME`]: the same op
    /// re-entered on its ticket after it answered PENDING; THE DESIGN §11.2, A.3 "Resume"). An
    /// op's FIRST invocations are `crossings - resumes`: "one op = one crossing", however often
    /// the op pends.
    pub(crate) resumes: AtomicU64,
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
    /// [`Kind::unit_of`] of the bound kind.
    unit_of: fn(u32, *const InHead, usize) -> Option<u64>,
    /// [`Kind::cancel_frame`] of the bound kind.
    pub(crate) cancel_frame: fn() -> Box<dyn super::CancelFrame>,
    /// [`Kind::context`] of the bound kind, built from the Statement at bind.
    context: Option<Box<super::Context>>,
    sink: Arc<dyn EnvelopeSink>,
    pub(crate) wake: &'static InstanceWake,
    tables: Tables,
    /// THE OPEN REASON BUFFER lent to `open` ([`OpenIn::err_buf`]): made at the first `open`
    /// crossing and held, at one address, until the `open` completes (a PENDING `open` keeps what
    /// it was lent), then handed to the caller as the reason. Empty at any other time.
    open_reason: Mutex<Vec<u8>>,
    /// What its driver ticket's READY `drive` answers named, until the host collects them.
    pub(crate) driven: super::worker::Driven,
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

/// An `open`'s crossing, armed with the instance pointer: dropped armed (the host's judgement did
/// not end the `open` READY or PENDING), it leaves the pointer at `live`, whichever way the
/// crossing returned: the box the plugin still holds (it answered READY or PENDING, so it freed
/// nothing; the host then closes it), else NULL (any other answer frees the box).
struct OpenEnded<'a> {
    ptr: Option<&'a AtomicPtr<c_void>>,
    live: *mut c_void,
}

impl Drop for OpenEnded<'_> {
    fn drop(&mut self) {
        if let Some(ptr) = self.ptr {
            ptr.store(self.live, Ordering::Release);
        }
    }
}

/// Whether `slot` is one of the five that never overlap on one instance (`ready` among them).
/// THE FFI CALL of a lifecycle slot (`validate`, `open`, `refresh`, `retire`, `close`, `ready`):
/// `op` entered, after asserting in debug builds that the thread is a permanent FFI worker
/// ([`crate::ffi_thread`]). [`Instance::cross_gated`] calls it only from inside
/// [`crate::ffi_thread::on_plugin_thread`]; a lifecycle slot entered on any other thread trips the
/// assertion.
pub(crate) fn enter_lifecycle(
    what: &str,
    op: Op,
    instance: *mut c_void,
    input: *const c_void,
    output: *mut c_void,
) -> RawOutcome {
    crate::ffi_thread::debug_assert_permanent(what);
    op(instance, input, output)
}

pub(crate) fn is_lifecycle(s: u32) -> bool {
    matches!(
        s,
        slot::OPEN | slot::REFRESH | slot::RETIRE | slot::CLOSE | slot::READY
    )
}

impl Instance {
    /// [`Kind::context`] of the bound kind, as `T`.
    pub(crate) fn context<T: 'static>(&self) -> Option<&T> {
        self.context.as_deref().and_then(|c| c.downcast_ref::<T>())
    }

    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    /// The connector table the instance was handed (NULL = none).
    #[cfg(test)]
    pub(crate) fn conns_table(
        &self,
    ) -> *const busbar_contract::abi::host::conn::connector::ConnectorSlots {
        self.tables.0.conns
    }

    pub(crate) fn ctx(&self) -> HostCtx {
        HostCtx {
            ptr: std::ptr::from_ref(self.wake).cast_mut().cast(),
        }
    }

    /// Whether the door states `ready` ([`slot::READY`]).
    pub(crate) fn has_ready(&self) -> bool {
        self.ready.is_some()
    }

    pub(crate) fn slot_count(&self) -> u32 {
        self.slots.len() as u32
    }

    /// Whether `open` answered READY and `close` has not.
    pub(crate) fn is_open(&self) -> bool {
        self.opened.load(Ordering::Acquire)
    }

    /// Whether the host holds a HALF-OPEN box: an `open` that pended and has not answered READY
    /// (still in flight, or ended without an answer, e.g. cancelled).
    pub(crate) fn half_open(&self) -> bool {
        !self.is_open() && !self.ptr.load(Ordering::Acquire).is_null()
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

    /// Whether `close` answered READY or FAULT.
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

    /// Declare each need whose `target_from` or `trust_from` names a config path, with what that
    /// path resolves to in `settings` (the settings `open` or `refresh` hands the plugin), before
    /// the plugin sees them: the target it is pinned to, and the operator CA PEM its connections
    /// trust on top of the public roots. A path that resolves to nothing is declared without its
    /// value, which the table refuses; a refresh re-declares, so a changed value moves the pin or
    /// the trust.
    fn declare_targeted(&self, settings: Blob) {
        let Some((instance, table)) = self.wake.conn.get() else {
            return;
        };
        let bytes: &[u8] = if settings.ptr.is_null() {
            &[]
        } else {
            // SAFETY: the host's own settings blob, live for the crossing it is handed to.
            unsafe { std::slice::from_raw_parts(settings.ptr, settings.len) }
        };
        let doc = serde_json::from_slice::<serde_json::Value>(bytes).ok();
        for (i, need) in self.needs.iter().enumerate() {
            if !from_settings(need) {
                continue;
            }
            let id = NeedId(u32::try_from(i).unwrap_or(u32::MAX));
            // THE MEMBER-PROGRAM PATH (ARCHITECT round 5 Q-L3B-STDIO-UPSTREAM (A)): each
            // registration that names a program is a member, its `command`/`args`/`env` its
            // program (every other key its own), sealed per member: the table keeps one long-lived
            // program per member, and a re-declaration retires a member that changed or is gone.
            if busbar_contract::section::member_program(&need.target_from) {
                let programs = doc.as_ref().map(member_programs).unwrap_or_default();
                let _ = table.declare_member_programs(*instance, id, need, &programs);
                continue;
            }
            // A PROGRAM the settings spell at the path (`{command, args, env}`) is declared as one:
            // the table spawns it (ARCHITECT round 4 (e)). One the settings misspell is declared
            // with no target, which the table refuses.
            let at = doc.as_ref().and_then(|d| setting_at(d, &need.target_from));
            if let Some(value) = at.filter(|v| v.is_object()) {
                let _ = match busbar_contract::conn::Program::from_settings(value) {
                    Ok(program) => table.declare_program(*instance, id, need, &program),
                    Err(_) => table.declare(*instance, id, need, None, None),
                };
                continue;
            }
            let target = doc
                .as_ref()
                .and_then(|d| resolve_target(d, &need.target_from));
            let trust = doc
                .as_ref()
                .and_then(|d| resolve_setting(d, &need.trust_from));
            let _ = table.declare(*instance, id, need, target.as_deref(), trust.as_deref());
        }
    }

    /// Bind each DESTINATION key the instance was granted to the file `settings` (the settings
    /// `open` or `refresh` hands the plugin) give it, before the plugin sees them: a non-empty path
    /// under the key, rotated at the `rotate_mb` (the host's rotation key,
    /// [`busbar_contract::services::DISK_ROTATE_KEY`]) beside it, keeping
    /// [`busbar_contract::services::DISK_KEEP`] archives. A key the settings leave unset is not
    /// bound, and `disk.append` refuses it. A refresh re-binds, so a changed path moves the file.
    fn bind_destinations(&self, settings: Blob) {
        let Some(keys) = self.wake.destinations.get() else {
            return;
        };
        let bytes: &[u8] = if settings.ptr.is_null() {
            &[]
        } else {
            // SAFETY: the host's own settings blob, live for the crossing it is handed to.
            unsafe { std::slice::from_raw_parts(settings.ptr, settings.len) }
        };
        let doc = serde_json::from_slice::<serde_json::Value>(bytes).unwrap_or_default();
        let rotate_at = doc
            .get(busbar_contract::services::DISK_ROTATE_KEY)
            .and_then(serde_json::Value::as_u64)
            .map(|mb| mb.saturating_mul(1024 * 1024));
        let bound = keys
            .iter()
            .filter_map(|key| {
                let path = doc.get(key)?.as_str()?;
                (!path.is_empty() && !path.contains('\0')).then(|| {
                    busbar_contract::services::DiskDest {
                        key: key.clone(),
                        path: path.to_owned(),
                        rotate_at,
                        keep: busbar_contract::services::DISK_KEEP,
                    }
                })
            })
            .collect();
        *self
            .wake
            .bound
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = bound;
    }

    pub(crate) fn leave_lifecycle(&self) {
        self.lifecycle_busy.store(false, Ordering::Release);
    }

    /// The open reason buffer, made on first use and kept at one address until
    /// [`Instance::take_open_reason`]: its pointer and capacity, for [`OpenIn::err_buf`].
    fn lend_open_reason(&self) -> (*mut u8, usize) {
        let mut buf = self.open_reason.lock().unwrap_or_else(|e| e.into_inner());
        if buf.is_empty() {
            *buf = vec![0; OPEN_REASON_CAP];
        }
        (buf.as_mut_ptr(), buf.len())
    }

    /// The open reason buffer, taken back once its `open` completed.
    fn take_open_reason(&self) -> Vec<u8> {
        std::mem::take(&mut *self.open_reason.lock().unwrap_or_else(|e| e.into_inner()))
    }

    /// What the host answers WITHOUT calling the plugin, if anything: a faulted instance, a slot
    /// the table does not have, an instance-less call before `open` answered READY (a half-open
    /// box admits only its `close`, once its `open` is over: the lifecycle exclusion), a second
    /// `open`, an `open` whose frame cannot hold `OpenIn`/`OpenOut`, or a `validate` whose frame
    /// cannot hold `ValidateIn`.
    pub(crate) fn refuse(&self, s: u32, in_size: usize, out_size: usize) -> Option<Outcome> {
        if self.faulted.load(Ordering::Acquire) || self.is_closed() {
            return Some(Outcome::Fault);
        }
        if s == slot::READY {
            // The door's optional tail op: only on an open instance that states it, in a frame
            // that holds a `ReadyIn`.
            let fits = self.ready.is_some() && self.is_open() && in_size >= size_of::<ReadyIn>();
            return (!fits).then_some(Outcome::Refused);
        }
        if s >= self.slot_count() {
            return Some(Outcome::Refused);
        }
        let open = self.is_open();
        let half_open = self.half_open();
        match s {
            slot::VALIDATE if in_size < size_of::<ValidateIn>() => Some(Outcome::Refused),
            slot::VALIDATE => None,
            slot::OPEN if open || half_open => Some(Outcome::Refused),
            slot::OPEN if in_size < size_of::<OpenIn>() || out_size < size_of::<OpenOut>() => {
                Some(Outcome::Refused)
            }
            slot::OPEN => None,
            slot::CLOSE if half_open => None,
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
        // A `close` that answered FAULT may already have freed the instance (a teardown that
        // failed after its memory went): the host treats it as closed, never crossing into the
        // pointer again. That can leak a live instance; it never uses a freed one. A READY `close`
        // of a half-open box frees the box only; the instance never opened, so it is not closed.
        let mut shut = false;
        if s == slot::CLOSE && matches!(crossed.outcome, Outcome::Ready | Outcome::Fault) {
            let was_open = self.opened.swap(false, Ordering::AcqRel);
            shut = was_open || crossed.outcome == Outcome::Fault;
            if shut {
                self.closed.store(true, Ordering::Release);
            }
            self.ptr.store(std::ptr::null_mut(), Ordering::Release);
        }
        self.leave_gate(s, shut);
        let ended = !matches!(crossed.outcome, Outcome::Ready | Outcome::Pending);
        if s == slot::OPEN && ended && self.half_open() && !self.faulted.load(Ordering::Acquire) {
            self.close_half_open();
        }
        crossed
    }

    /// CLOSE THE LIVE BOX OF AN `open` THE HOST JUDGED FAULT: the plugin answered READY or PENDING,
    /// so it freed nothing and holds a live box, but the op is over (no RESUME will come). The host
    /// sends it `close` (the `close` a half-open box admits), so nothing dangles and nothing leaks.
    /// Called with the `open`'s lifecycle exclusion still held, so nothing else crosses meanwhile.
    fn close_half_open(&self) {
        let mut input = super::in_head();
        let mut out = super::out_head();
        // SAFETY: the host's own head-only `close` frame (`close`'s `in`/`out` are the heads),
        // live and unaliased for the call.
        let closed = unsafe {
            self.cross(
                slot::CLOSE,
                &raw mut input,
                &raw mut out,
                size_of::<OutHead>() as u32,
            )
        };
        if closed.outcome != Outcome::Ready {
            tracing::warn!(
                plugin = %self.name,
                kind = ?self.kind,
                outcome = ?closed.outcome,
                "the close of a FAULTed open's live box did not answer READY"
            );
        }
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
        // A half-open box is crossed only by the `cancel` of its pended `open` and its `close`.
        let crossable =
            self.is_open() || (matches!(s, slot::CANCEL | slot::CLOSE) && self.half_open());
        if self.is_closed() || (needs_instance && !crossable) {
            return Crossed::host(Outcome::Fault);
        }
        // SAFETY: the caller's contract.
        let (ticket, instance, resumed) = unsafe {
            let head = &mut *input;
            head.op = s;
            head.host = self.ctx();
            (
                head.ticket,
                self.ptr.load(Ordering::Acquire),
                head.flags & busbar_contract::abi::mechanism::call::FLAG_RESUME != 0,
            )
        };
        // A `validate`, of every kind, is lent a reason buffer for its crossing alone (it never
        // pends): it names what it wrote in `head.error`, read below while the buffer lives.
        let mut validate_reason = (s == slot::VALIDATE).then(|| vec![0_u8; OPEN_REASON_CAP]);
        if let Some(buf) = validate_reason.as_mut() {
            // SAFETY: `refuse` checked the frame holds a `ValidateIn`.
            unsafe {
                let v = &mut *input.cast::<ValidateIn>();
                v.err_buf = buf.as_mut_ptr();
                v.err_cap = buf.len();
            }
        }
        if s == slot::OPEN {
            // Every `open`, of every kind, is lent the host's reason buffer: a failed open has no
            // instance to hold its reason. The same buffer is re-lent on a resume.
            let (err_buf, err_cap) = self.lend_open_reason();
            // SAFETY: `refuse` checked the frame holds an `OpenIn`.
            unsafe {
                let open = &mut *input.cast::<OpenIn>();
                open.host = &*self.tables.0;
                open.err_buf = err_buf;
                open.err_cap = err_cap;
            }
            // SAFETY: as above.
            let settings = unsafe { (*input.cast::<OpenIn>()).settings };
            self.declare_targeted(settings);
            self.bind_destinations(settings);
        }
        if s == slot::READY {
            // `ready` is handed the same host tables `open` was.
            // SAFETY: `refuse` checked the frame holds a `ReadyIn`.
            unsafe { (*input.cast::<ReadyIn>()).host = &*self.tables.0 };
        }
        // SAFETY: the host wrote `in.size`; a frame that holds a `RefreshIn` is read as one.
        if s == slot::REFRESH && unsafe { (*input).size } as usize >= size_of::<RefreshIn>() {
            // SAFETY: as above.
            let settings = unsafe { (*input.cast::<RefreshIn>()).settings };
            self.declare_targeted(settings);
            self.bind_destinations(settings);
        }
        // THE HOST ZEROES THE WHOLE `out` BEFORE EVERY CALL, RESUME included (FAULT = 0, every
        // tail field absent), then states its size: the plugin writes at most min(out.size, own).
        // SAFETY: `out` is the host's own `out_size` bytes.
        unsafe {
            std::ptr::write_bytes(out.cast::<u8>(), 0, out_size as usize);
            (*out).size = out_size;
        }
        let op = match (s, self.ready) {
            (slot::READY, Some(ready)) => ready,
            (slot::READY, None) => return Crossed::host(Outcome::Refused),
            _ => self.slots[s as usize],
        };
        self.crossings.fetch_add(1, Ordering::Relaxed);
        if resumed {
            self.resumes.fetch_add(1, Ordering::Relaxed);
        }
        // SAFETY: the host wrote `in.size` itself.
        let in_size = unsafe { (*input).size } as usize;
        // The unit this crossing serves, for the host services it calls.
        let unit = (self.unit_of)(s, input.cast_const(), in_size);
        let _unit = super::services::serving(unit);
        // From here an `open` that does not end READY or PENDING, FAULT included, leaves no
        // instance published: the SDK frees a half-open box on any answer but READY/PENDING, so a
        // pointer kept to it would hand a later crossing freed memory; a box the plugin still
        // holds (it answered READY/PENDING, the host judged FAULT) is closed by the host.
        let mut open_ended = OpenEnded {
            ptr: (s == slot::OPEN).then_some(&self.ptr),
            live: std::ptr::null_mut(),
        };
        let raw = if s == slot::VALIDATE || is_lifecycle(s) {
            // A LIFECYCLE CROSSING RUNS ON A PERMANENT FFI WORKER (`crate::ffi_thread`), whoever
            // called it: a dispatcher worker that may later exit, or a ticket-less caller thread
            // (a libtest thread, a reload's thread) that will. `open` is where a plugin first
            // touches its thread-locals and `close` runs its `Drop`; either on a thread that
            // exits after the library is unmapped runs the plugin's thread-local destructor out
            // of unmapped memory. What the crossing's thread states for the host services the
            // plugin calls goes with it: the unit it serves, the dispatcher worker it acts for and
            // the runtime that thread is inside.
            let acting = super::worker::worker_mark();
            let runtime = tokio::runtime::Handle::try_current().ok();
            let (input, output): (*const c_void, *mut c_void) =
                (input.cast_const().cast(), out.cast());
            let routed = crate::ffi_thread::on_plugin_thread(|| {
                let _runtime = runtime.as_ref().map(tokio::runtime::Handle::enter);
                let _acting = super::worker::acting_for(acting);
                let _unit = super::services::serving(unit);
                enter_lifecycle((self.op_name)(s), op, instance, input, output)
            });
            match routed {
                Ok(raw) => raw,
                // Only a host-side panic on the worker reaches here (an escaping slot panic
                // aborts): the crossing answers FAULT.
                Err(_) => return Crossed::host(Outcome::Fault),
            }
        } else {
            op(instance, input.cast_const().cast(), out.cast())
        };
        if s == slot::OPEN
            && (raw == RawOutcome::of(Outcome::Ready) || raw == RawOutcome::of(Outcome::Pending))
        {
            // What the plugin answered READY or PENDING still holds its box, whatever the host
            // judges below.
            // SAFETY: `refuse` checked the frame holds an `OpenOut`.
            open_ended.live = unsafe { (*out.cast::<OpenOut>()).instance };
        }
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
        // An `open` that completed hands back the buffer it was lent, holding its reason.
        let reason = if s == slot::OPEN && outcome != Outcome::Pending {
            // SAFETY: `refuse` checked the frame holds an `OpenOut`.
            let len = unsafe { (*out.cast::<OpenOut>()).err_len };
            let mut buf = self.take_open_reason();
            if len > buf.len() {
                // A reason longer than the buffer lent is a malformed answer.
                return Crossed::host(Outcome::Fault);
            }
            buf.truncate(len);
            Some(buf).filter(|b| !b.is_empty())
        } else {
            None
        };
        self.ingest(&head);
        let error = match outcome {
            Outcome::Failed | Outcome::Refused => reason.or_else(|| copy_str(head.error)),
            _ => None,
        };
        // A `validate`'s reason is copied: the buffer it was lent goes.
        drop(validate_reason);
        // THE VALIDATE REFUSAL RULE (`abi::mechanism::lifecycle::check_validate_refusal`): the
        // host renders a FAILED `validate`'s lines, so malformed lines are FAULT.
        if s == slot::VALIDATE && outcome == Outcome::Failed {
            let text = error.as_deref().unwrap_or_default();
            if let Err(f) = busbar_contract::abi::mechanism::lifecycle::check_validate_refusal(text)
            {
                tracing::warn!(
                    plugin = %self.name,
                    kind = ?self.kind,
                    rule = ?f.rule,
                    field = f.field,
                    "a validate refusal broke the refusal rule; the op answers FAULT"
                );
                return Crossed::host(Outcome::Fault);
            }
        }
        // An open that FAILED or was REFUSED (fresh, or on its RESUME) gets no instance: the
        // plugin's trampoline freed the box a prior PENDING minted; `open_ended` drops our pointer
        // to it. `close` (READY or FAULT) shuts the instance in `Instance::cross`.
        if s == slot::OPEN && matches!(outcome, Outcome::Ready | Outcome::Pending) {
            // An open that answered READY (done) or PENDING (its connect step pends) hands back
            // its instance box; the host keeps it so a PENDING open's RESUME runs on the SAME
            // box — plugin-owned memory carries the half-open state across the pend (no module
            // static in the contract).
            // SAFETY: `refuse` checked the frame holds an `OpenOut`.
            let inst = unsafe { (*out.cast::<OpenOut>()).instance };
            if inst.is_null() {
                return Crossed::host(Outcome::Fault);
            }
            open_ended.ptr = None;
            self.ptr.store(inst, Ordering::Release);
            // Only READY opens it; a PENDING open's box is half-open until its RESUME answers.
            if outcome == Outcome::Ready {
                self.opened.store(true, Ordering::Release);
            }
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
            cancel_writes: Vec::new(),
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

/// `st`'s kind tail as this host's `T`, by THE KIND TAIL GROWTH RULE
/// (`abi::mechanism::door::tail_read_len`): the plugin's first `min(size, host)` bytes, the rest
/// zero (a field the plugin predates reads absent); refused when NULL or smaller than `frozen`, the
/// kind's last frozen size. `who` names the plugin in the refusal.
///
/// # Safety
/// `T` is a `#[repr(C)]` kind tail of plain integers and pointers leading with a `KindTailHead`, so
/// all-zero bytes are a valid `T`; a non-NULL `st.kind_tail` is `'static` plugin data of at least its
/// stated size.
pub(crate) unsafe fn kind_tail<T: Copy>(
    st: &busbar_contract::abi::mechanism::door::Statement,
    who: &str,
    frozen: usize,
) -> Result<T, String> {
    let p = st.kind_tail;
    if p.is_null() {
        return Err(format!("{who} states no kind tail"));
    }
    // SAFETY: a non-NULL kind tail leads with a `KindTailHead` (the caller's contract).
    let size = unsafe { (*p).size };
    let read = busbar_contract::abi::mechanism::door::tail_read_len(size, frozen, size_of::<T>())
        .ok_or_else(|| {
        format!("{who} states a {size}-byte tail, smaller than its frozen {frozen}")
    })?;
    let mut tail = std::mem::MaybeUninit::<T>::zeroed();
    // SAFETY: `read` is at most the plugin's stated size and at most `size_of::<T>()`; the rest of
    // `tail` stays zero, a valid `T` (the caller's contract).
    unsafe {
        std::ptr::copy_nonoverlapping(p.cast::<u8>(), tail.as_mut_ptr().cast::<u8>(), read);
        Ok(tail.assume_init())
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
pub(crate) fn copy_str(s: AbiStr) -> Option<Vec<u8>> {
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

/// The kind's name as the host's observer knows it (the cold wire's kind words).
fn kind_word(kind: KindCode) -> &'static str {
    use busbar_contract::abi::mechanism::kind;
    match kind {
        KindCode::Store => kind::STORE,
        KindCode::Secret => kind::SECRET,
        KindCode::Auth => kind::AUTH,
        KindCode::Hook => kind::HOOK,
        KindCode::Export => kind::EXPORT,
        KindCode::Plane => kind::PLANE,
        KindCode::Transport => kind::TRANSPORT,
    }
}

/// THE #85 ENVELOPE, OBSERVED FOR EVERY KIND (ARCHITECT ruling ENVELOPE-ALL 2026-10-03): the
/// binder's sink, with the host's observability standing before it
/// ([`crate::observe::EnvelopeObserver`]): every metric of a family the Statement declares and every
/// declared diagnostic reach the installed observer, under the plugin's name and kind, whoever bound
/// the door, and the binder's sink is still handed every entry.
fn observed(
    then: &Arc<dyn EnvelopeSink>,
    st: &busbar_contract::abi::mechanism::door::Statement,
    kind: KindCode,
    name: &[u8],
) -> Arc<dyn EnvelopeSink> {
    // SAFETY: `validate` ran `check_statement` on this Statement; the rendering reads its
    // `'static` lists.
    let families = unsafe { busbar_contract::abi::mechanism::rendering::render(st) }
        .ok()
        .and_then(|b| busbar_contract::abi::mechanism::rendering::read(&b).ok())
        .map(|r| r.families)
        .unwrap_or_default();
    Arc::new(crate::observe::EnvelopeObserver::before(
        then.clone(),
        &String::from_utf8_lossy(name),
        kind_word(kind),
        families,
    ))
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
        // THE CONNECTION TABLE: minted an identity and declared on the host's one table, need by
        // need under its Statement index, when the Statement declares a need; otherwise none.
        let instance = mint_instance(&NEXT_INSTANCE);
        let mut declared_needs: Box<[ReadNeed]> = Box::default();
        let conns: *const busbar_contract::abi::host::conn::connector::ConnectorSlots =
            match (&bind.conns, st.needs_len) {
                (ConnTable::NoNeeds, n) if n > 0 => {
                    return Err(LoadError::NoConnectionTable {
                        plugin: str_bytes(st.name)
                            .map(|n| String::from_utf8_lossy(n).into_owned())
                            .unwrap_or_default(),
                        needs: n,
                    });
                }
                (ConnTable::Host(table), n) if n > 0 => {
                    // SAFETY: `validate` ran `check_statement`, which refused a NULL list with a
                    // count; the rendering reads the Statement's `'static` lists.
                    let needs = unsafe { busbar_contract::abi::mechanism::rendering::render(&st) }
                        .ok()
                        .and_then(|r| busbar_contract::abi::mechanism::rendering::read(&r).ok())
                        .map(|r| r.needs)
                        .ok_or_else(|| LoadError::BadStatement("the needs do not render".into()))?;
                    for (i, need) in needs.iter().enumerate() {
                        // THE BOOT'S SCHEME MATCH (spec Part 0: core refuses at boot; Part 2
                        // #50): a need, outbound or inbound, over a scheme no loaded transport
                        // serves refuses the load, naming the plugin and the scheme — fail closed
                        // now, never at the need's first open or listen.
                        if !need.transport.is_empty() && !table.serves_scheme(&need.transport) {
                            return Err(LoadError::UnservedScheme {
                                plugin: str_bytes(st.name)
                                    .map(|n| String::from_utf8_lossy(n).into_owned())
                                    .unwrap_or_default(),
                                inbound: need.direction != DIRECTION_OUTBOUND,
                                scheme: need.transport.clone(),
                            });
                        }
                        // A need whose target or trust comes from config is declared once its
                        // settings arrive (`open`, `refresh`); until then an open on it is
                        // undeclared.
                        if from_settings(need) {
                            continue;
                        }
                        let id = NeedId(u32::try_from(i).unwrap_or(u32::MAX));
                        // The answer is the connection table's to keep (`need.admit` reads it);
                        // its scheme was matched above.
                        let _ = table.declare(instance, id, need, None, None);
                    }
                    declared_needs = needs.into_boxed_slice();
                    let _ = wake.conn.set((instance, Arc::clone(table)));
                    &super::conn_services::CONN_SLOTS
                }
                _ => std::ptr::null(),
            };
        let tables = Tables(Box::new(HostTables {
            size: size_of::<HostTables>() as u32,
            _reserved: 0,
            ctx: HostCtx {
                ptr: std::ptr::from_ref(wake).cast_mut().cast(),
            },
            wake: Some(host_wake),
            conns,
            services: &super::services::HOST_SLOTS,
        }));
        let name = str_bytes(st.name)
            .ok_or_else(|| LoadError::BadStatement("the name is NULL or over-long".into()))?;
        let secret_refs: Box<[String]> = (0..st.secret_refs_len)
            .map(|i| {
                // SAFETY: `validate` ran `check_statement`, which refused a NULL list with a count;
                // the list holds `secret_refs_len` `'static` strings.
                let key = unsafe { st.secret_refs.add(i).read_unaligned() };
                str_bytes(key)
                    .map(|k| String::from_utf8_lossy(k).into_owned())
                    .ok_or_else(|| LoadError::BadStatement("a secret ref is malformed".into()))
            })
            .collect::<Result<_, _>>()?;
        let _ = wake.caller.set(busbar_contract::services::Caller {
            instance: Arc::clone(&bind.instance),
            plugin: Arc::from(String::from_utf8_lossy(name).as_ref()),
            kind: v.kind,
        });
        let context = K::context(&st).map_err(LoadError::KindTail)?;
        let _ = wake
            .credential_kinds
            .set(K::credential_kinds(context.as_deref()));
        let plugin = Self {
            inner: Arc::new(Instance {
                instance,
                needs: declared_needs,
                secret_refs,
                kind: v.kind,
                name: String::from_utf8_lossy(name).into_owned(),
                slots: v.slots,
                ready: v.ready,
                families,
                diag_ids: DiagIds {
                    ptr: st.diag_ids,
                    len: st.diag_ids_len,
                },
                ptr: AtomicPtr::new(std::ptr::null_mut()),
                opened: AtomicBool::new(false),
                faulted: AtomicBool::new(false),
                closed: AtomicBool::new(false),
                gate: AtomicU32::new(0),
                crossings: AtomicU64::new(0),
                resumes: AtomicU64::new(0),
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
                unit_of: K::unit_of,
                cancel_frame: K::cancel_frame,
                context,
                sink: observed(&bind.sink, &st, v.kind, name),
                wake,
                tables,
                open_reason: Mutex::new(Vec::new()),
                driven: super::worker::Driven::default(),
                _lib: lib,
            }),
            _k: PhantomData,
        };
        bind.dispatcher.adopt(&plugin.inner);
        Ok(plugin)
    }

    /// The envelope sink the dispatcher ingests this instance's replies into (a witness).
    #[cfg(test)]
    pub(crate) fn envelope_sink(&self) -> Arc<dyn EnvelopeSink> {
        self.inner.sink.clone()
    }

    /// GRANT this instance the DESTINATIONS its manifest declares (the settings keys that name a
    /// file the host appends to for it, `declares.destinations`), before it opens: its `open` and
    /// `refresh` bind each to the path its settings give, and `disk.append` serves it those only.
    /// Granted once; a second grant is ignored.
    pub fn grant_destinations(&self, keys: &[String]) {
        let _ = self.inner.wake.destinations.set(keys.to_vec());
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

    /// The settings keys its Statement names as secret references, in the Statement's order.
    #[must_use]
    pub fn secret_refs(&self) -> &[String] {
        &self.inner.secret_refs
    }

    /// The instance's identity on the host's connection table (minted at bind, one per instance).
    pub fn instance(&self) -> InstanceId {
        self.inner.instance
    }

    /// The host's connection table the instance's needs were declared on at bind; `None` when its
    /// Statement declares no need or the bind lent none (the composition root holds its members'
    /// auth bindings on it).
    pub fn conn_table(&self) -> Option<Arc<dyn busbar_contract::conn::DeclaredConns>> {
        self.inner
            .wake
            .conn
            .get()
            .map(|(_, table)| Arc::clone(table))
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

    /// Whether the Statement declares a need whose target comes from the instance's settings
    /// (`target_from`), on the connection table it was handed (none without one).
    pub fn targets_from_settings(&self) -> bool {
        self.inner.needs.iter().any(|n| !n.target_from.is_empty())
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
            // The dispatcher owns only the mechanism's own bit; a kind's bit the caller set on the
            // head (the export scrape's `SCRAPE_FLAG_HOOK_FAMILIES`) rides through untouched.
            head.flags &= !FLAG_RESUME;
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

/// The open-reason witness, compiled in: the LINKED door of `open_reason_tests` (the same source is
/// the `open_reason_store_door` example `cdylib`, the DROPPED door).
#[cfg(test)]
#[path = "../../tests/fixtures/open_reason_plugins.rs"]
mod open_reason_plugins;

#[cfg(test)]
#[path = "../tests/open_reason_tests.rs"]
mod open_reason_tests;

#[cfg(test)]
#[path = "../tests/lifecycle_worker_tests.rs"]
mod lifecycle_worker_tests;

/// Whether a need takes a value from its instance's settings (`target_from` or `trust_from`), so it
/// is declared at `open` and `refresh` rather than at bind.
fn from_settings(need: &ReadNeed) -> bool {
    !need.target_from.is_empty() || !need.trust_from.is_empty()
}

/// What a need's `target_from` or `trust_from` names in an instance's settings:
/// `settings.<key>[.<key>...]`, walked through the settings object to a non-empty string. Anything
/// else resolves to nothing.
pub(crate) fn resolve_setting(settings: &serde_json::Value, path: &str) -> Option<String> {
    let rest = path.strip_prefix("settings.")?;
    rest.split('.')
        .try_fold(settings, |v, key| v.get(key))
        .and_then(serde_json::Value::as_str)
        .filter(|t| !t.is_empty())
        .map(str::to_owned)
}

/// How a member program's `env` secret REFERENCE turns into its value: a string secret resolved
/// through the secret plugins the build links (the root installs it once, at boot). `Err` names
/// the reference's source, never a byte of the secret.
pub type MemberSecretFn = fn(&busbar_contract::secret_ref::SecretRef) -> Result<String, String>;

/// The installed [`MemberSecretFn`]; until one is installed no reference resolves (fail-closed: a
/// member whose program needs one is no member).
static MEMBER_SECRETS: std::sync::OnceLock<MemberSecretFn> = std::sync::OnceLock::new();

/// Install how a member program's `env` secret references resolve ([`member_programs`]); the first
/// install holds. Answers whether this one was installed.
pub fn install_member_secrets(resolve: MemberSecretFn) -> bool {
    MEMBER_SECRETS.set(resolve).is_ok()
}

/// EVERY MEMBER'S PROGRAM a member-program need reaches (`busbar_contract::section::MEMBER_PROGRAM`):
/// each registration of the settings that names a `command`, read by
/// [`busbar_contract::conn::Program::of_member`] (its other keys ignored), in the settings' order.
/// An `env` value written as a secret REFERENCE (`{ env: X }`, `{ file: P }`) is resolved here, by
/// the installed [`MemberSecretFn`], as the previous release resolved it at the spawn: the program is handed
/// the value, the settings keep the reference. A registration whose program does not read (a
/// relative command, a reference that does not resolve) is no member: an open naming it is refused.
pub(crate) fn member_programs(
    settings: &serde_json::Value,
) -> Vec<(String, busbar_contract::conn::Program)> {
    let Some(map) = settings.as_object() else {
        return Vec::new();
    };
    map.iter()
        .filter_map(|(name, registration)| {
            let mut registration = registration.clone();
            if let Some(env) = registration
                .get_mut("env")
                .and_then(serde_json::Value::as_object_mut)
            {
                for value in env.values_mut() {
                    if value.is_string() {
                        continue;
                    }
                    let reference =
                        serde_json::from_value::<busbar_contract::secret_ref::SecretRef>(
                            value.clone(),
                        )
                        .ok()?;
                    *value = serde_json::Value::String(MEMBER_SECRETS.get()?(&reference).ok()?);
                }
            }
            let program = busbar_contract::conn::Program::of_member(&registration)?.ok()?;
            Some((name.clone(), program))
        })
        .collect()
}

/// The value a need's `target_from` path (`settings.<key>[.<key>...]`) names in an instance's
/// settings, whatever it is.
pub(crate) fn setting_at<'v>(
    settings: &'v serde_json::Value,
    path: &str,
) -> Option<&'v serde_json::Value> {
    let rest = path.strip_prefix("settings.")?;
    rest.split('.').try_fold(settings, |v, key| v.get(key))
}

/// What a need's `target_from` names in an instance's settings: `settings.<key>[.<key>...]`, walked
/// through the settings object to a non-empty string. Anything else resolves to nothing.
pub(crate) fn resolve_target(settings: &serde_json::Value, path: &str) -> Option<String> {
    setting_at(settings, path)
        .and_then(serde_json::Value::as_str)
        .filter(|t| !t.is_empty())
        .map(str::to_owned)
}

#[cfg(test)]
#[path = "../tests/instance_id_tests.rs"]
mod instance_id_tests;
