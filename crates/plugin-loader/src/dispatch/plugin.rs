// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::HashMap;
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
    slot, OpenIn, OpenOut, ReadyIn, RefreshIn, ReleaseIn, ValidateIn,
};
use busbar_contract::abi::mechanism::rendering::ReadNeed;
use busbar_contract::abi::mechanism::ticket::{HostCtx, HostTables, Ticket};
use busbar_contract::abi::mechanism::KindCode;
use busbar_contract::abi::plane::{PlaneOpenIn, EXT_OWNED};
use busbar_contract::conn::{InstanceId, NeedId};

use super::answer::Answer;
use super::load::{Lib, LoadError, Validated};
use super::ticket::{host_wake, InstanceWake};
use super::{validate, Frame, InFrame, Kind, OutFrame};
use busbar_contract::abi::mechanism::check::Fault;

pub const MAX_ENVELOPE_ENTRIES: usize = busbar_contract::abi::mechanism::call::MAX_ENVELOPE_ENTRIES;

pub const MAX_TEXT: usize = busbar_contract::abi::mechanism::call::MAX_TEXT;

pub const OPEN_REASON_CAP: usize = MAX_TEXT;

pub const MAX_LOG_RECORDS: usize = 128;

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

pub trait EnvelopeSink: Send + Sync {
    fn metric(&self, m: Metric<'_>);

    fn diag(&self, d: Diagnostic<'_>);

    fn dropped(&self, why: Dropped);

    fn refused(&self, _instance: &str, _refusal: crate::observe::BindRefusal<'_>) {}
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
    #[must_use]
    pub fn serving(table: Option<Arc<dyn busbar_contract::conn::DeclaredConns>>) -> Self {
        table.map_or(Self::NoNeeds, Self::Host)
    }

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
/// `Copy`, so it cannot be spent twice. Dropping a negotiated token returns its retained answer
/// to the originating instance, even when the caller abandons the recall.
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
pub struct Recall {
    instance: usize,

    slot: u32,
    ticket: Ticket,
    kept: Option<RecallLease>,
}

impl std::fmt::Debug for Recall {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Recall")
            .field("instance", &self.instance)
            .field("slot", &self.slot)
            .field("ticket", &self.ticket)
            .finish_non_exhaustive()
    }
}
impl PartialEq for Recall {
    fn eq(&self, other: &Self) -> bool {
        (
            self.instance,
            self.slot,
            self.ticket,
            self.kept.as_ref().map(|k| k.id),
        ) == (
            other.instance,
            other.slot,
            other.ticket,
            other.kept.as_ref().map(|k| k.id),
        )
    }
}
impl Eq for Recall {}

struct RecallLease {
    instance: Arc<Instance>,
    framing: Option<Arc<dyn busbar_contract::framing_scope::FramingScope>>,
    id: u64,
}
impl Drop for RecallLease {
    fn drop(&mut self) {
        let _scope = super::framing_context::enter(self.framing.clone());
        self.instance.release_unread(self.id);
    }
}

pub(crate) struct RecallInput {
    head: *mut InHead,
    prior: Blob,
    _bytes: zeroize::Zeroizing<Vec<u8>>,
}
impl RecallInput {
    /// # Safety
    /// `head` and its extension bytes are exclusively held and live through this guard.
    pub(crate) unsafe fn new(head: *mut InHead, lease: u64) -> Result<Self, ()> {
        use busbar_contract::abi::mechanism::call::BLOB_OCTETS;
        let prior = unsafe { (*head).extensions };
        let mut bytes = zeroize::Zeroizing::new(
            busbar_contract::abi::sdk::auth_door::short_reply::encode(lease),
        );
        if prior.len > busbar_contract::abi::mechanism::check::HARD_MAX_BYTES as usize - bytes.len()
            || (prior.len != 0 && (prior.ptr.is_null() || prior.fmt != BLOB_OCTETS))
        {
            return Err(());
        }
        bytes.extend_from_slice(unsafe { blob_bytes(prior) });
        unsafe {
            (*head).extensions = Blob {
                ptr: bytes.as_ptr(),
                len: bytes.len(),
                fmt: BLOB_OCTETS,
                flags: prior.flags,
            };
        }
        Ok(Self {
            head,
            prior,
            _bytes: bytes,
        })
    }
}
impl Drop for RecallInput {
    fn drop(&mut self) {
        // SAFETY: this guard owns the temporary head assignment and precedes frame destruction.
        unsafe {
            (*self.head).extensions = self.prior;
        }
    }
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
    /// Negotiated immutable SHORT storage; private host custody, never public Done.lease.
    pub(crate) short_lease: u64,
    /// `cancel`'s `CancelOut.disposition`, when the op ended through `cancel`.
    pub(crate) disposition: Option<u32>,
    /// The record writes that `cancel` carried (a plane's, SEAM-L(r)).
    pub(crate) cancel_writes: Vec<busbar_contract::plane_calls::CancelWrite>,
    /// A lease the plugin named on an answer that hands none to the caller (any outcome but READY
    /// or PENDING, a FAULT the host judged included): released by the host as the crossing ends.
    pub(crate) unread: u64,
}

impl Crossed {
    pub(crate) fn host(outcome: Outcome) -> Self {
        Self {
            outcome,
            error: None,
            lease: 0,
            wake_at_ns: 0,
            short: false,
            short_lease: 0,
            disposition: None,
            cancel_writes: Vec::new(),
            unread: 0,
        }
    }

    fn unread(self, lease: u64) -> Self {
        Self {
            unread: lease,
            ..self
        }
    }
}

struct HeadSnapshot {
    output: *mut OutHead,
    original: OutHead,
    bytes: Vec<Box<[u8]>>,
    labels: Vec<Box<[AbiStr]>>,
    metrics: Box<[MetricEntry]>,
    diags: Box<[Diag]>,
}

impl HeadSnapshot {
    fn text(&mut self, text: AbiStr) -> AbiStr {
        let Some(bytes) = str_bytes(text) else {
            return AbiStr {
                ptr: std::ptr::null(),
                len: text.len,
            };
        };
        if text.ptr.is_null() {
            return text;
        }
        let owned: Box<[u8]> = bytes.into();
        let named = AbiStr {
            ptr: owned.as_ptr(),
            len: owned.len(),
        };
        self.bytes.push(owned);
        named
    }

    /// # Safety
    /// This is the returning plugin's live output, still on its actual FFI worker. Every
    /// pointer reached after the existing mechanism and per-entry bounds names live data.
    unsafe fn capture(
        instance: &Instance,
        raw: RawOutcome,
        output: *mut OutHead,
        out_size: u32,
        ticket: Ticket,
    ) -> Option<Self> {
        if instance.faulted.load(Ordering::Acquire) {
            return None;
        }
        // SAFETY: the crossing owns the host output frame, which starts with OutHead.
        let original = unsafe { *output };
        if judge(raw, &original, ticket, out_size) == Outcome::Fault {
            return None;
        }
        let mut snapshot = Self {
            output,
            original,
            bytes: Vec::new(),
            labels: Vec::new(),
            metrics: Box::default(),
            diags: Box::default(),
        };
        let error = if matches!(raw.outcome(), Outcome::Failed | Outcome::Refused) {
            snapshot.text(original.error)
        } else {
            original.error
        };
        let mut envelope = original.envelope;
        // SAFETY: the plugin's arrays remain live on this worker; array checks count and alignment.
        if let Some(metrics) = unsafe { array(envelope.metrics, envelope.metrics_len) } {
            let mut metrics = metrics.to_vec();
            for metric in &mut metrics {
                let reads_labels = instance
                    .families
                    .get(metric.family_idx as usize)
                    .is_some_and(|family| {
                        matches!(
                            (metric.kind, family.kind),
                            (METRIC_ADD, FAMILY_COUNTER)
                                | (METRIC_SET, FAMILY_GAUGE)
                                | (METRIC_OBSERVE, FAMILY_HISTOGRAM)
                        ) && metric.value.is_finite()
                            && metric.label_vals_len == family.labels
                    });
                if !reads_labels {
                    continue;
                }
                // SAFETY: the same bounded reader metric() uses, while source storage is live.
                if let Some(labels) = unsafe { array(metric.label_vals, metric.label_vals_len) } {
                    let labels: Box<[AbiStr]> =
                        labels.iter().map(|value| snapshot.text(*value)).collect();
                    metric.label_vals = labels.as_ptr();
                    snapshot.labels.push(labels);
                } else {
                    metric.label_vals = std::ptr::null();
                }
            }
            snapshot.metrics = metrics.into_boxed_slice();
            envelope.metrics = snapshot.metrics.as_ptr();
        }
        // SAFETY: as the metrics array above; diag() uses the same bounded reader.
        if let Some(diags) = unsafe { array(envelope.diags, envelope.diags_len) } {
            let mut diags = diags.to_vec();
            for diag in &mut diags {
                let reads_text = match diag.id_idx {
                    DIAG_LOG_DROPPED => true,
                    DIAG_LOG => diag.severity <= SEVERITY_TRACE,
                    id => diag.severity <= SEVERITY_ERROR && instance.diag_ids.name(id).is_some(),
                };
                if reads_text {
                    diag.text = snapshot.text(diag.text);
                }
            }
            snapshot.diags = diags.into_boxed_slice();
            envelope.diags = snapshot.diags.as_ptr();
        }
        // SAFETY: this crossing exclusively owns the host head; snapshot owns every substituted
        // buffer until its Drop restores the original pointers.
        unsafe {
            (*output).error = error;
            (*output).envelope = envelope;
        }
        Some(snapshot)
    }
}

impl Drop for HeadSnapshot {
    fn drop(&mut self) {
        // SAFETY: the snapshot never outlives this crossing's host output frame, and restoration
        // happens before any of the owned arrays or nested strings are destroyed.
        unsafe {
            *self.output = self.original;
        }
    }
}

#[cfg(test)]
#[path = "../tests/head_snapshot_tests.rs"]
mod head_snapshot_tests;

struct Tables(Box<HostTables>);
// SAFETY: the tables are written once at bind and only read after; `ctx` is a plain handle (#74)
// and every pointer in them is to `'static` host tables.
unsafe impl Send for Tables {}
unsafe impl Sync for Tables {}

thread_local! {
    /// The instance whose crossing is on this thread (innermost first), for what a host entry needs
    /// it for (#74): the instance a context must name, and the quarantine of a forged one.
    static CROSSING: std::cell::Cell<*const Instance> = const { std::cell::Cell::new(std::ptr::null()) };
}

pub(crate) fn with_crossing<R>(inst: Option<&Instance>, f: impl FnOnce() -> R) -> R {
    struct Restore(*const Instance);
    impl Drop for Restore {
        fn drop(&mut self) {
            CROSSING.with(|c| c.set(self.0));
        }
    }
    let mark = inst.map_or(std::ptr::null(), std::ptr::from_ref);
    let _restore = Restore(CROSSING.with(|c| c.replace(mark)));
    f()
}

#[cfg(test)]
pub(crate) fn without_crossing<R>(f: impl FnOnce() -> R) -> R {
    with_crossing(None, f)
}

pub(crate) fn crossing_wake() -> Option<&'static InstanceWake> {
    let p = CROSSING.with(std::cell::Cell::get);
    // SAFETY: `CROSSING` is non-null only inside `with_crossing(Some(&*p), ..)`, which borrows the
    // instance for the whole span; its `wake` entry is leaked (`'static`).
    (!p.is_null()).then(|| unsafe { (*p).wake })
}

pub(crate) fn quarantine_crossing() -> bool {
    let p = CROSSING.with(std::cell::Cell::get);
    if p.is_null() {
        return false;
    }
    // SAFETY: `CROSSING` is non-null only inside `with_crossing(Some(&*p), ..)`, which borrows the
    // instance for the whole span.
    let inst = unsafe { &*p };
    inst.revoke();
    inst.wake.exports.wake_waiters(inst.wake);
    inst.let_go_held();
    tracing::warn!(
        plugin = %inst.name,
        "a plugin handed the host a context the host did not mint; the instance is quarantined"
    );
    true
}

struct Unbound(Option<&'static InstanceWake>);

impl Drop for Unbound {
    fn drop(&mut self) {
        if let Some(wake) = self.0 {
            wake.revoked.store(true, Ordering::Release);
        }
    }
}

struct PolicyReply {
    input: *mut InHead,
    original: Blob,
    _bytes: Arc<[u8]>,
}

struct FramingFailure {
    scope: Option<Arc<dyn busbar_contract::framing_scope::FramingScope>>,
    ticket: Ticket,
}

struct RefreshBinding<'a> {
    instance: &'a Instance,
    ticket: Ticket,
    generation: Option<Arc<super::export_bindings::Generation>>,
    pending: bool,
}

impl RefreshBinding<'_> {
    fn stage(&mut self, generation: Arc<super::export_bindings::Generation>) {
        let prior = self
            .instance
            .wake
            .exports
            .stage(self.ticket, generation.clone());
        self.generation = Some(generation);
        if let Some(prior) = prior {
            let closes = self.instance.wake.conn_state.retire_binding(&prior);
            super::worker::drop_after_lock(Box::new((closes, prior)));
        }
    }
    fn retain(&mut self) {
        self.pending = true;
    }

    fn commit(&mut self) {
        if let Some(generation) = self.generation.take() {
            self.instance.wake.exports.publish(generation);
            let staged = self.instance.wake.exports.take_staged(self.ticket);
            super::worker::drop_after_lock(Box::new(staged));
        }
    }
}

impl Drop for RefreshBinding<'_> {
    fn drop(&mut self) {
        if self.pending {
            return;
        }
        if let Some(generation) = self.generation.take() {
            let staged = self.instance.wake.exports.take_staged(self.ticket);
            let closes = self.instance.wake.conn_state.retire_binding(&generation);
            super::worker::drop_after_lock(Box::new((closes, staged, generation)));
        }
    }
}

impl Drop for FramingFailure {
    fn drop(&mut self) {
        if let Some(scope) = &self.scope {
            scope.operation_finished(self.ticket, true);
        }
    }
}

impl Drop for PolicyReply {
    fn drop(&mut self) {
        // SAFETY: the host frame outlives its crossing, including every early return.
        unsafe {
            (*self.input).extensions = self.original;
        }
    }
}

impl Instance {
    pub(crate) fn let_go_held(&self) {
        if let Some(route) = self.wake.route.get().and_then(std::sync::Weak::upgrade) {
            if let Some(served) = route.services() {
                served
                    .store
                    .conditional_teardown(std::ptr::from_ref(self.wake) as usize);
            }
        }
        if let Some((id, table)) = self.wake.conn.get() {
            super::conn_services::purge(*id, table);
        }
        self.wake.exports.clear();
        let io = self
            .wake
            .route
            .get()
            .and_then(std::sync::Weak::upgrade)
            .and_then(|route| route.io());
        if let Some(io) = io {
            io.reap(self.ctx().handle);
        }
    }

    pub(crate) fn revoke(&self) {
        self.faulted.store(true, Ordering::Release);
        self.wake.revoked.store(true, Ordering::Release);
    }
}

pub(crate) fn quarantine_entry(wake: &'static InstanceWake) {
    quarantine(
        wake,
        "a plugin woke a ticket generation the host never minted; the instance is quarantined",
    );
}

pub(crate) fn quarantine(wake: &'static InstanceWake, why: &'static str) {
    wake.revoked.store(true, Ordering::Release);
    let Some(inst) = wake.instance.get().and_then(std::sync::Weak::upgrade) else {
        return;
    };
    inst.revoke();
    inst.wake.exports.wake_waiters(inst.wake);
    inst.let_go_held();
    tracing::warn!(plugin = %inst.name, "{why}");
}

/// One family's shape, copied from the Statement: its kind and its label count.
#[derive(Debug, Clone, Copy)]
struct FamilyShape {
    kind: u8,
    labels: usize,
}

/// THE INSTANCE, kind-erased: what every crossing needs. Shared across workers.
#[doc(hidden)]
pub struct Instance {
    pub(crate) instance: InstanceId,

    needs: Box<[ReadNeed]>,

    secret_refs: Box<[String]>,

    reference_fields: Box<[String]>,
    pub(crate) kind: KindCode,
    name: String,
    slots: Box<[Op]>,

    ready: Option<Op>,
    families: Box<[FamilyShape]>,
    diag_ids: DiagIds,

    ptr: AtomicPtr<c_void>,

    opened: AtomicBool,
    pub(crate) faulted: AtomicBool,

    pub(crate) breaches: AtomicU32,

    closed: AtomicBool,

    gate: AtomicU32,
    /// Crossings actually made (the witness of "without a crossing"), RESUMES included.
    #[doc(hidden)]
    pub crossings: AtomicU64,
    /// Of [`Instance::crossings`], the RESUME re-invocations ([`FLAG_RESUME`]: the same op
    /// re-entered on its ticket after it answered PENDING; THE DESIGN §11.2, A.3 "Resume"). An
    /// op's FIRST invocations are `crossings - resumes`: "one op = one crossing", however often
    /// the op pends.
    #[doc(hidden)]
    pub resumes: AtomicU64,

    pub(crate) calls: Mutex<HashMap<u64, (Instant, u32, bool)>>,
    next_call: AtomicU64,
    inflight: AtomicU32,

    pub(crate) drainable: AtomicU32,

    pub(crate) unit_ops: AtomicU32,
    pub(crate) cap: u32,
    lifecycle_busy: AtomicBool,
    pub(crate) timeout: Outcome,

    check: fn(&Answer) -> Result<(), Fault>,

    short: fn(&Answer) -> bool,

    op_name: fn(u32) -> &'static str,

    pub(crate) unit_of: fn(u32, *const InHead, usize) -> Option<u64>,

    pub(crate) cancel_frame: fn() -> Box<dyn super::CancelFrame>,

    context: Option<Box<super::Context>>,
    sink: Arc<dyn EnvelopeSink>,
    pub(crate) wake: &'static InstanceWake,
    tables: Tables,

    open_reason: Mutex<Vec<u8>>,
    /// What its driver ticket's READY `drive` answers named, until the host collects them.
    #[doc(hidden)]
    pub driven: super::worker::Driven,

    _lib: Option<Lib>,
}

impl Drop for Instance {
    fn drop(&mut self) {
        self.wake.revoked.store(true, Ordering::Release);
        self.let_go_held();
    }
}

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

const CLOSING: u32 = 1 << 31;

const EXPORT_BINDINGS_KEY: &str = "busbar.export.ticket-bindings";
const EXPORT_BINDINGS_VERSION: &[u8] = b"1";
static EXPORT_BINDINGS: [u8; busbar_contract::abi::mechanism::extensions::entry_len(
    EXPORT_BINDINGS_KEY,
    EXPORT_BINDINGS_VERSION,
)] = busbar_contract::abi::mechanism::extensions::entry(
    EXPORT_BINDINGS_KEY,
    EXPORT_BINDINGS_VERSION,
);

struct ExportExtensions {
    input: *mut InHead,
    original: Blob,
    _bytes: Option<zeroize::Zeroizing<Vec<u8>>>,
}

impl ExportExtensions {
    /// # Safety
    /// `input` is the host's live, exclusive frame for this crossing, including its extensions.
    unsafe fn install(input: *mut InHead) -> Self {
        // SAFETY: the caller's host-owned frame and its lent extension bytes.
        let original = unsafe { (*input).extensions };
        let original_bytes = unsafe { blob_bytes(original) };
        let bytes = (!original_bytes.is_empty()).then(|| {
            let mut bytes = EXPORT_BINDINGS.to_vec();
            bytes.extend_from_slice(original_bytes);
            zeroize::Zeroizing::new(bytes)
        });
        let extended = bytes
            .as_ref()
            .map(|bytes| bytes.as_slice())
            .unwrap_or(&EXPORT_BINDINGS);
        // SAFETY: the bytes are static or owned by this guard until the original blob is restored.
        unsafe {
            (*input).extensions = super::lifecycle::blob(
                extended,
                busbar_contract::abi::mechanism::call::BLOB_OCTETS,
                0,
            );
        }
        Self {
            input,
            original,
            _bytes: bytes,
        }
    }
}

impl Drop for ExportExtensions {
    fn drop(&mut self) {
        // SAFETY: the frame outlives its crossing guard. Restore before the lent bytes are freed.
        unsafe { (*self.input).extensions = self.original };
    }
}

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

pub(crate) fn enter_lifecycle(
    what: &str,
    op: Op,
    instance: *mut c_void,
    input: *const c_void,
    output: *mut c_void,
) -> RawOutcome {
    crate::ffi_thread::debug_assert_permanent(what);
    // SAFETY: this private crossing is reached after cross_gated validates its selected slot
    // and lends its initialized host frames and live instance for the synchronous worker call.
    // The fixture caller selects a slot explicitly accepting NULL frames without reading them.
    unsafe { op(instance, input, output) }
}

pub(crate) fn is_lifecycle(s: u32) -> bool {
    matches!(
        s,
        slot::OPEN | slot::REFRESH | slot::RETIRE | slot::CLOSE | slot::READY
    )
}

impl Instance {
    pub(crate) fn context<T: 'static>(&self) -> Option<&T> {
        self.context.as_deref().and_then(|c| c.downcast_ref::<T>())
    }

    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    #[cfg(test)]
    pub(crate) fn conns_table(
        &self,
    ) -> *const busbar_contract::abi::host::conn::connector::ConnectorSlots {
        self.tables.0.conns
    }

    /// The instance's handle (#74): what the plugin is handed and hands back, verified by the host
    /// on every call ([`super::handle::resolve`]).
    #[doc(hidden)]
    pub fn ctx(&self) -> HostCtx {
        self.tables.0.ctx
    }

    pub(crate) fn has_ready(&self) -> bool {
        self.ready.is_some()
    }

    pub(crate) fn slot_count(&self) -> u32 {
        self.slots.len() as u32
    }

    pub(crate) fn is_open(&self) -> bool {
        self.opened.load(Ordering::Acquire)
    }

    pub(crate) fn half_open(&self) -> bool {
        !self.is_open() && !self.ptr.load(Ordering::Acquire).is_null()
    }

    pub(crate) fn acquire(&self, s: u32) -> Option<u32> {
        if self.kind == KindCode::Export
            && matches!(s, slot::REFRESH | slot::CANCEL | slot::RELEASE)
        {
            return Some(0);
        }
        let close = s == slot::CLOSE;
        if close && self.unit_ops.load(Ordering::SeqCst) != 0 {
            return None;
        }
        let want = if close { self.cap } else { 1 };
        let taken = self
            .inflight
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                let fits = if close { n == 0 } else { n < self.cap };
                n.checked_add(want).filter(|_| fits)
            })
            .ok()
            .map(|_| want)?;
        if close && self.unit_ops.load(Ordering::SeqCst) != 0 {
            self.release(taken);
            return None;
        }
        Some(taken)
    }

    pub(crate) fn release(&self, units: u32) {
        self.inflight.fetch_sub(units, Ordering::AcqRel);
    }

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
            (true, true) => self.gate.store(CLOSING, Ordering::Release),
            (true, false) => self.gate.store(0, Ordering::Release),
            _ => {
                self.gate.fetch_sub(1, Ordering::AcqRel);
            }
        }
    }

    pub(crate) fn lock_calls(
        &self,
    ) -> std::sync::MutexGuard<'_, HashMap<u64, (Instant, u32, bool)>> {
        self.calls.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn watched<R>(&self, s: u32, cross: impl FnOnce() -> R) -> R {
        let id = self.next_call.fetch_add(1, Ordering::Relaxed);
        self.lock_calls().insert(id, (Instant::now(), s, false));
        let crossed = cross();
        self.lock_calls().remove(&id);
        crossed
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    pub(crate) fn inflight(&self) -> u32 {
        self.inflight.load(Ordering::Acquire)
    }

    pub(crate) fn enter_lifecycle(&self) -> bool {
        self.lifecycle_busy
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    pub(crate) fn export_admission(
        &self,
        op: u32,
        ticket: Ticket,
    ) -> Result<Option<super::export_bindings::Admission>, ()> {
        if !self.uses_bindings()
            || self.faulted.load(Ordering::Acquire)
            || matches!(op, slot::CANCEL | slot::CLOSE | slot::RELEASE)
        {
            return Ok(None);
        }
        self.wake
            .exports
            .admit(self.wake, op, ticket)
            .map(Some)
            .ok_or(())
    }

    pub(crate) fn binding_resume_admission(
        &self,
        op: u32,
        ticket: Ticket,
    ) -> Result<Option<super::export_bindings::Admission>, ()> {
        // Export's Pending refresh gates new entries, while already admitted work may finish.
        if self.kind == KindCode::Export {
            Ok(None)
        } else {
            self.export_admission(op, ticket)
        }
    }

    fn uses_bindings(&self) -> bool {
        self.kind == KindCode::Export
            || self.needs.iter().any(from_settings)
            || self
                .wake
                .destinations
                .get()
                .is_some_and(|keys| !keys.is_empty())
    }

    fn declare_targeted(&self, settings: Blob, owned: Option<&[u8]>) -> Option<String> {
        self.declare_targeted_on(settings, owned, self.wake.conn.get())
    }

    fn declare_targeted_on(
        &self,
        settings: Blob,
        owned: Option<&[u8]>,
        connection: Option<&(InstanceId, Arc<dyn busbar_contract::conn::DeclaredConns>)>,
    ) -> Option<String> {
        let (instance, table) = connection?;
        let mut trust_refused = None;
        let bytes: &[u8] = if settings.ptr.is_null() {
            &[]
        } else {
            // SAFETY: the host's own settings blob, live for the crossing it is handed to.
            unsafe { std::slice::from_raw_parts(settings.ptr, settings.len) }
        };
        let doc = serde_json::from_slice::<serde_json::Value>(bytes).ok();
        let owned = owned
            .filter(|b| !b.is_empty())
            .and_then(|b| serde_json::from_slice::<serde_json::Value>(b).ok());
        for (i, need) in self.needs.iter().enumerate() {
            if !from_settings(need) {
                continue;
            }
            let id = NeedId(u32::try_from(i).unwrap_or(u32::MAX));

            if busbar_contract::section::member_program(&need.target_from) {
                let programs = doc.as_ref().map(member_programs).unwrap_or_default();
                let answer = table.declare_member_programs(*instance, id, need, &programs);
                self.need_refused(id, answer.map_err(crate::observe::conn_reason));
                continue;
            }

            let at = doc.as_ref().and_then(|d| setting_at(d, &need.target_from));
            if let Some(value) = at.filter(|v| v.is_object()) {
                let answer = match busbar_contract::conn::Program::from_settings(value) {
                    Ok(program) => table
                        .declare_program(*instance, id, need, &program)
                        .map_err(crate::observe::conn_reason),
                    Err(_) => table
                        .declare(*instance, id, need, None, None)
                        .map_err(|_| "program_malformed"),
                };
                self.need_refused(id, answer);
                continue;
            }
            let target = doc
                .as_ref()
                .and_then(|d| resolve_target(d, &need.target_from));
            let trust = match busbar_contract::section::owned_path(&need.trust_from) {
                Some(at) => owned.as_ref().and_then(|o| resolve_owned(o, at)),
                None => doc
                    .as_ref()
                    .and_then(|d| resolve_setting(d, &need.trust_from)),
            };

            let unresolved = target.is_none()
                && !need.target_from.is_empty()
                && busbar_contract::section::member_target(&need.target_from).is_none();

            let trust_unwritten = trust.is_none()
                && !need.trust_from.is_empty()
                && busbar_contract::section::owned_path(&need.trust_from).is_none()
                && busbar_contract::section::member_target(&need.trust_from).is_none();
            let answer = table
                .declare(*instance, id, need, target.as_deref(), trust.as_deref())
                .map_err(|e| {
                    if unresolved {
                        "target_unresolved"
                    } else {
                        crate::observe::conn_reason(e)
                    }
                });
            if let (Err(reason), Some(_), None) = (answer, &trust, &trust_refused) {
                trust_refused = Some(format!(
                    "{}: the host refused the CA certificate it names for need {i} ({reason}); \
                     it must be PEM that parses into a trust anchor",
                    need.trust_from
                ));
            }
            if unresolved || !trust_unwritten {
                self.need_refused(id, answer);
            }
        }
        trust_refused
    }

    fn need_refused(&self, need: NeedId, answer: Result<(), &'static str>) {
        if let Err(reason) = answer {
            self.refused(crate::observe::BindRefusal::Need {
                need: need.0,
                reason,
            });
        }
    }

    fn refused(&self, refusal: crate::observe::BindRefusal<'_>) {
        let label = self
            .wake
            .caller
            .get()
            .map_or(self.name.as_str(), |c| &*c.instance);
        self.sink.refused(label, refusal);
    }

    fn flagged(&self, head: &OutHead, lifecycle: bool) {
        let env = head.envelope;
        // SAFETY: as `ingest`, which read the same arrays on this crossing.
        let Some(diags) = (unsafe { array(env.diags, env.diags_len) }) else {
            return;
        };
        for d in diags {
            let flags = match d.severity {
                SEVERITY_ERROR => true,
                busbar_contract::abi::mechanism::call::SEVERITY_WARN => lifecycle,
                _ => false,
            };
            if !flags {
                continue;
            }
            let Some(code) = self.diag_ids.name(d.id_idx) else {
                continue;
            };
            let code = String::from_utf8_lossy(code);
            self.refused(if lifecycle {
                crate::observe::BindRefusal::Open { code: &code }
            } else {
                crate::observe::BindRefusal::Op { code: &code }
            });
        }
    }

    fn bind_destinations(&self, settings: Blob) {
        let bound = self.destinations(settings);
        *self
            .wake
            .bound
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = bound;
    }

    fn destinations(&self, settings: Blob) -> Vec<busbar_contract::services::DiskDest> {
        let Some(keys) = self.wake.destinations.get() else {
            return Vec::new();
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
        let operator_keep = doc
            .get(busbar_contract::services::DISK_KEEP_KEY)
            .and_then(serde_json::Value::as_u64)
            .map(|n| u32::try_from(n).unwrap_or(u32::MAX));
        keys.iter()
            .filter_map(|key| {
                let path = doc.get(key)?.as_str()?;
                (!path.is_empty() && !path.contains('\0')).then(|| {
                    busbar_contract::services::DiskDest {
                        key: key.clone(),
                        path: path.to_owned(),
                        rotate_at,

                        rotate: busbar_contract::services::DiskRotate::declared(
                            operator_keep
                                .or_else(|| self.wake.keep.get().and_then(|k| k.get(key)).copied()),
                        ),
                    }
                })
            })
            .collect()
    }

    fn binding_generation(
        &self,
        settings: Blob,
        owned: Option<&[u8]>,
        initial: bool,
    ) -> Result<Arc<super::export_bindings::Generation>, String> {
        let conn = match self.wake.conn.get() {
            Some((owner, table)) => {
                let owner = if initial && !self.wake.conn_forgotten.load(Ordering::Acquire) {
                    *owner
                } else {
                    super::handle::mint(self.wake)
                        .map(super::handle::instance_id)
                        .map_err(|error| error.to_string())?
                };
                if self.kind == KindCode::Auth {
                    table.hold_authority(owner);
                }
                Some((owner, table.clone()))
            }
            None => None,
        };
        let generation = Arc::new(super::export_bindings::Generation {
            conn,
            destinations: self.destinations(settings),
        });
        if let Some((owner, table)) = &generation.conn {
            for (index, need) in self
                .needs
                .iter()
                .enumerate()
                .filter(|(_, need)| !from_settings(need))
            {
                let id = NeedId(index as u32);
                if table.declared(*owner, id).is_none() {
                    table
                        .declare(*owner, id, need, None, None)
                        .map_err(|error| crate::observe::conn_reason(error).to_string())?;
                }
            }
        }
        if let Some(error) = self.declare_targeted_on(settings, owned, generation.conn.as_ref()) {
            return Err(error);
        }
        Ok(generation)
    }

    pub(crate) fn leave_lifecycle(&self) {
        self.lifecycle_busy.store(false, Ordering::Release);
    }

    fn lend_open_reason(&self) -> (*mut u8, usize) {
        let mut buf = self.open_reason.lock().unwrap_or_else(|e| e.into_inner());
        if buf.is_empty() {
            *buf = vec![0; OPEN_REASON_CAP];
        }
        (buf.as_mut_ptr(), buf.len())
    }

    fn take_open_reason(&self) -> Vec<u8> {
        std::mem::take(&mut *self.open_reason.lock().unwrap_or_else(|e| e.into_inner()))
    }

    fn instance_free(&self, s: u32) -> bool {
        self.kind == KindCode::Secret && s == busbar_contract::abi::secret::slot::CHECK
    }

    pub(crate) fn refuse(&self, s: u32, in_size: usize, out_size: usize) -> Option<Outcome> {
        if self.faulted.load(Ordering::Acquire) || self.is_closed() {
            return Some(Outcome::Fault);
        }
        if s == slot::READY {
            let fits = self.ready.is_some() && self.is_open() && in_size >= size_of::<ReadyIn>();
            return (!fits).then_some(Outcome::Refused);
        }
        if s >= self.slot_count() {
            return Some(Outcome::Refused);
        }
        if self.instance_free(s) {
            let fits = in_size >= size_of::<busbar_contract::abi::secret::CheckIn>()
                && out_size >= size_of::<OutHead>();
            return (!fits).then_some(Outcome::Refused);
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
        use busbar_contract::abi::transport::slot as transport_slot;
        let framing_op = self.kind == KindCode::Transport
            && (s == slot::CANCEL || (transport_slot::BEGIN..=transport_slot::TIMER).contains(&s));
        let mut failure = FramingFailure {
            scope: framing_op.then(super::framing_context::current).flatten(),
            // SAFETY: every host frame leads with InHead. CANCEL names the operation it ends
            // in its own checked frame, independently of the cancellation crossing's ticket.
            ticket: unsafe {
                if s == slot::CANCEL
                    && (*input).size as usize
                        >= size_of::<busbar_contract::abi::mechanism::lifecycle::CancelIn>()
                {
                    (*input.cast::<busbar_contract::abi::mechanism::lifecycle::CancelIn>()).ticket
                } else {
                    (*input).ticket
                }
            },
        };
        if !self.enter_gate(s) {
            let o = if s == slot::CLOSE {
                Outcome::Refused
            } else {
                Outcome::Fault
            };
            if self.kind == KindCode::Export && s == slot::REFRESH {
                // SAFETY: the caller owns a checked frame whose first field is InHead.
                self.wake
                    .exports
                    .finish_refresh(self.wake, unsafe { (*input).ticket });
            }
            return Crossed::host(o);
        }
        let _extensions =
            if self.kind == KindCode::Export && s == busbar_contract::abi::export::slot::DELIVER {
                // SAFETY: this crossing owns the input until the guard restores its original blob.
                Some(unsafe { ExportExtensions::install(input) })
            } else {
                None
            };
        // SAFETY: the caller's contract.
        let crossed = unsafe { self.cross_gated(s, input, out, out_size) };
        if s != slot::CANCEL && matches!(crossed.outcome, Outcome::Ready | Outcome::Pending) {
            failure.scope = None;
        }
        if self.kind == KindCode::Export {
            if s == slot::REFRESH {
                // SAFETY: the checked frame is live for the crossing.
                let ticket = unsafe { (*input).ticket };
                if crossed.outcome == Outcome::Pending {
                    self.wake.exports.pending_refresh(ticket);
                } else {
                    self.wake.exports.finish_refresh(self.wake, ticket);
                }
            } else if s == slot::CANCEL {
                // SAFETY: every kind's checked cancellation frame starts with CancelIn.
                let ticket = unsafe {
                    (*input.cast::<busbar_contract::abi::mechanism::lifecycle::CancelIn>()).ticket
                };
                self.wake.exports.finish_refresh(self.wake, ticket);
            }
        }

        let mut shut = false;
        if s == slot::CLOSE && matches!(crossed.outcome, Outcome::Ready | Outcome::Fault) {
            let was_open = self.opened.swap(false, Ordering::AcqRel);
            shut = was_open || crossed.outcome == Outcome::Fault;
            if shut {
                self.closed.store(true, Ordering::Release);

                self.wake.revoked.store(true, Ordering::Release);
            }
            self.ptr.store(std::ptr::null_mut(), Ordering::Release);
        }
        self.leave_gate(s, shut);
        if shut && self.uses_bindings() {
            let closes = self.wake.conn_state.retire_all();
            super::worker::drop_after_lock(Box::new(closes));
            self.wake.exports.clear();
            self.wake.exports.wake_waiters(self.wake);
        }
        let ended = !matches!(crossed.outcome, Outcome::Ready | Outcome::Pending);
        if s == slot::OPEN && ended && self.half_open() && !self.faulted.load(Ordering::Acquire) {
            self.close_half_open();
        }
        if crossed.unread != 0 && s != slot::RELEASE {
            self.release_unread(crossed.unread);
        }
        Crossed {
            unread: 0,
            ..crossed
        }
    }

    pub(crate) fn release_unread(&self, lease: u64) {
        if !self.is_open() || self.faulted.load(Ordering::Acquire) {
            return;
        }
        let mut input = ReleaseIn {
            head: InHead {
                size: size_of::<ReleaseIn>() as u32,
                ..super::in_head()
            },
            lease,
        };
        let mut out = super::out_head();
        // SAFETY: the host's own `release` frame (`ReleaseIn` leads with its head, the `out` is
        // the head), live and unaliased for the call.
        let released = unsafe {
            self.cross(
                slot::RELEASE,
                (&raw mut input).cast::<InHead>(),
                &raw mut out,
                size_of::<OutHead>() as u32,
            )
        };
        if released.outcome != Outcome::Ready {
            tracing::warn!(
                plugin = %self.name,
                kind = ?self.kind,
                outcome = ?released.outcome,
                "the release of a lease named on an answer that was not READY did not answer READY"
            );
        }
    }

    pub(crate) fn cancel_abandoned(
        &self,
        ticket: Ticket,
        class: DeadlineClass,
        unit: Option<u64>,
        framing: Option<Arc<dyn busbar_contract::framing_scope::FramingScope>>,
    ) -> Crossed {
        let mut frame = (self.cancel_frame)();
        frame.name_unit(unit.unwrap_or(0));
        let (input, out, out_size) = frame.prepare(ticket, class as u8);
        let crossed = self.watched(slot::CANCEL, || {
            crate::ffi_thread::on_plugin_thread(|| {
                let _framing = super::framing_context::enter(framing.clone());
                // SAFETY: the kind's own `cancel` frame, live and unaliased for the call.
                let mut crossed = unsafe { self.cross(slot::CANCEL, input, out, out_size) };
                if crossed.outcome == Outcome::Ready {
                    crossed.disposition = Some(frame.disposition());
                    crossed.cancel_writes = frame.writes();
                }

                if crossed.lease != 0 {
                    self.release_unread(crossed.lease);
                    crossed.lease = 0;
                }
                crossed
            })
        });
        let id = super::handle::instance_id(self.ctx());
        let (_, forgotten) = super::conn_services::forget(id, ticket);
        super::worker::drop_after_lock(Box::new(forgotten));
        crossed.unwrap_or_else(|_| Crossed::host(Outcome::Fault))
    }

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
        let instance_free = self.instance_free(s);
        // SAFETY: the caller owns a frame whose leading input head is live throughout the call.
        let ticket = unsafe { (*input).ticket };
        let mut refresh_binding = RefreshBinding {
            instance: self,
            ticket,
            generation: None,
            pending: false,
        };
        let needs_instance = !matches!(s, slot::VALIDATE | slot::OPEN) && !instance_free;

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
                if instance_free {
                    std::ptr::null_mut()
                } else {
                    self.ptr.load(Ordering::Acquire)
                },
                head.flags & busbar_contract::abi::mechanism::call::FLAG_RESUME != 0,
            )
        };
        let scope = (self.kind == KindCode::Transport)
            .then(super::framing_context::current)
            .flatten();
        let _policy_reply = match scope
            .as_ref()
            .and_then(|scope| scope.operation_reply(ticket))
        {
            Some(reply) => {
                // SAFETY: the host owns this input head and its original extension bytes.
                let original = unsafe { (*input).extensions };
                // SAFETY: the original host blob lives with this operation's frame.
                let prior = unsafe { blob_bytes(original) };
                let bytes = if prior.is_empty() || reply.ends_with(prior) {
                    reply
                } else {
                    let mut joined = reply.to_vec();
                    joined.extend_from_slice(prior);
                    Arc::from(joined)
                };
                if let Some(scope) = &scope {
                    scope.hold_operation_reply(ticket, Arc::clone(&bytes));
                }
                // SAFETY: the guard restores the head; Scope retains bytes across PENDING.
                unsafe {
                    (*input).extensions = Blob {
                        ptr: bytes.as_ptr(),
                        len: bytes.len(),
                        fmt: busbar_contract::abi::mechanism::call::BLOB_OCTETS,
                        flags: 0,
                    };
                }
                Some(PolicyReply {
                    input,
                    original,
                    _bytes: bytes,
                })
            }
            None => None,
        };

        let mut validate_reason = (s == slot::VALIDATE).then(|| vec![0_u8; OPEN_REASON_CAP]);
        if let Some(buf) = validate_reason.as_mut() {
            // SAFETY: `refuse` checked the frame holds a `ValidateIn`.
            unsafe {
                let v = &mut *input.cast::<ValidateIn>();
                v.err_buf = buf.as_mut_ptr();
                v.err_cap = buf.len();
            }
        }

        let mut trust_refused = None;
        let mut proposed_binding = None;
        if s == slot::OPEN {
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
            // A PLANE's open frame is a `PlaneOpenIn` (its `OpenIn` first): its owned sections are
            // read when the host wrote one that large.
            // SAFETY: the host wrote `in.size` itself; the cast is read only when it covers the
            // whole `PlaneOpenIn`, and its `owned` blob is the host's own, live for the crossing.
            let owned = (self.kind == KindCode::Plane
                && unsafe { (*input).size } as usize >= size_of::<PlaneOpenIn>())
            .then(|| unsafe { blob_bytes((*input.cast::<PlaneOpenIn>()).owned) });
            if self.kind == KindCode::Export {
                if !resumed {
                    match self.binding_generation(settings, None, true) {
                        Ok(binding) => proposed_binding = Some(binding),
                        Err(error) => trust_refused = Some(error),
                    }
                }
            } else {
                trust_refused = self.declare_targeted(settings, owned);
                self.bind_destinations(settings);
            }
        }
        if s == slot::READY {
            // `ready` is handed the same host tables `open` was.
            // SAFETY: `refuse` checked the frame holds a `ReadyIn`.
            unsafe { (*input.cast::<ReadyIn>()).host = &*self.tables.0 };
        }
        // SAFETY: the host wrote `in.size`; a frame that holds a `RefreshIn` is read as one.
        if s == slot::REFRESH && unsafe { (*input).size } as usize >= size_of::<RefreshIn>() {
            // SAFETY: as above.
            let (settings, extensions) = unsafe {
                let refresh = &*input.cast::<RefreshIn>();
                (refresh.settings, refresh.head.extensions)
            };
            // A plane's owned sections ride a refresh's extensions blob ([`EXT_OWNED`]).
            // SAFETY: the host's own extensions blob, live for the crossing it is handed to.
            let owned = unsafe { blob_bytes(extensions) };
            let owned = busbar_contract::abi::mechanism::extensions::get(owned, EXT_OWNED);
            if self.uses_bindings() {
                if resumed {
                    proposed_binding = self.wake.exports.staged(ticket);
                    if proposed_binding.is_none() {
                        return Crossed::host(Outcome::Fault);
                    }
                    refresh_binding.generation = proposed_binding.clone();
                } else {
                    match self.binding_generation(settings, owned, false) {
                        Ok(binding) => {
                            refresh_binding.stage(binding.clone());
                            proposed_binding = Some(binding);
                        }
                        Err(error) => trust_refused = Some(error),
                    }
                }
            } else {
                let _ = self.declare_targeted(settings, owned);
                self.bind_destinations(settings);
            }
        }
        // THE HOST ZEROES THE WHOLE `out` BEFORE EVERY CALL, RESUME included (FAULT = 0, every
        // tail field absent), then states its size: the plugin writes at most min(out.size, own).
        // SAFETY: `out` is the host's own `out_size` bytes.
        unsafe {
            std::ptr::write_bytes(out.cast::<u8>(), 0, out_size as usize);
            (*out).size = out_size;
        }

        if let Some(reason) = trust_refused.filter(|_| !resumed) {
            return Crossed {
                error: Some(reason.into_bytes()),
                ..Crossed::host(Outcome::Failed)
            };
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

        let unit = (self.unit_of)(s, input.cast_const(), in_size);
        let _unit = super::services::serving(unit);
        let _ticket = super::services::crossing(ticket);
        // The copied receipt uses the existing epoch; its composed input loan lasts this call.
        // SAFETY: this crossing owns the host input frame and its original extension blob.
        let _inspection_input =
            match unsafe { super::inspection::prepare(self.wake, s, input, unit) } {
                Ok(loan) => loan,
                Err(()) => return Crossed::host(Outcome::Fault),
            };
        // SAFETY: host-owned frame; each guard restores the preceding input loan in reverse order.
        let _conditional_input = match unsafe {
            super::conditional::prepare(
                self.wake,
                self.context
                    .as_deref()
                    .and_then(|c| c.downcast_ref::<super::kinds::plane::PlaneFacts>())
                    .is_some_and(|f| f.declared.conditional_records),
                s,
                input,
                unit,
            )
        } {
            Ok(loan) => loan,
            Err(()) => return Crossed::host(Outcome::Refused),
        };
        // SAFETY: the host owns the frame; this final input loan restores prior extensions.
        let completion_input =
            match unsafe { super::completion_retirement::prepare(self.wake, s, input) } {
                Ok(loan) => loan,
                Err(()) => return Crossed::host(Outcome::Fault),
            };
        // The deadline of the op this crossing is, for the host services it calls (`auth.call`).
        // SAFETY: the host's own `in`, led by its head, live for the crossing.
        let _deadline = super::services::op_deadline(unsafe { &*input });
        let binding_ticket = if s == slot::CANCEL {
            // SAFETY: the kind's cancel frame starts with the mechanism CancelIn.
            unsafe {
                (*input.cast::<busbar_contract::abi::mechanism::lifecycle::CancelIn>()).ticket
            }
        } else {
            ticket
        };
        let binding = proposed_binding.clone().or_else(|| {
            self.uses_bindings()
                .then(|| self.wake.exports.pin(binding_ticket))
                .flatten()
        });

        let mut open_ended = OpenEnded {
            ptr: (s == slot::OPEN).then_some(&self.ptr),
            live: std::ptr::null_mut(),
        };
        let (raw, _head_snapshot) = if s == slot::VALIDATE || is_lifecycle(s) {
            let acting = super::worker::worker_mark();
            let runtime = tokio::runtime::Handle::try_current().ok();
            let framing = super::framing_context::current();
            let (input, output): (*const c_void, *mut c_void) =
                (input.cast_const().cast(), out.cast());
            let routed = crate::ffi_thread::on_plugin_thread(|| {
                let _framing = super::framing_context::enter(framing);
                let _runtime = runtime.as_ref().map(tokio::runtime::Handle::enter);
                let _acting = super::worker::acting_for(acting);
                let _unit = super::services::serving(unit);
                let _ticket = super::services::crossing(ticket);
                super::export_bindings::crossing(binding.clone(), || {
                    with_crossing(Some(self), || {
                        let raw = enter_lifecycle((self.op_name)(s), op, instance, input, output);

                        let readable = if self.faulted.load(Ordering::Acquire) {
                            false
                        } else {
                            // SAFETY: these are the crossing's own initialized host frames.
                            let head = unsafe { *output.cast::<OutHead>() };
                            let outcome = judge(raw, &head, ticket, out_size);
                            if outcome == Outcome::Fault {
                                false
                            } else {
                                // SAFETY: the host owns both frames and their input buffers; the
                                // plugin's leased answer ranges remain live on this worker.
                                let answer = unsafe {
                                    Answer::new(
                                        s,
                                        outcome,
                                        input.cast(),
                                        (*input.cast::<InHead>()).size as usize,
                                        output.cast(),
                                        out_size as usize,
                                    )
                                }
                                .with_context(self.context.as_deref());
                                (self.check)(&answer).is_ok()
                            }
                        };
                        let snapshot = if readable {
                            // SAFETY: the returning plugin's output remains live on its actual
                            // FFI worker. Copy consumed ranges before releasing that worker.
                            unsafe {
                                HeadSnapshot::capture(self, raw, output.cast(), out_size, ticket)
                            }
                        } else {
                            None
                        };
                        (raw, snapshot)
                    })
                })
            });
            match routed {
                Ok(raw) => raw,

                Err(_) => return Crossed::host(Outcome::Fault),
            }
        } else {
            let raw = super::export_bindings::crossing(binding, || {
                with_crossing(Some(self), || {
                    op(instance, input.cast_const().cast(), out.cast())
                })
            });
            (raw, None)
        };
        if s == slot::OPEN
            && (raw == RawOutcome::of(Outcome::Ready) || raw == RawOutcome::of(Outcome::Pending))
        {
            // What the plugin answered READY or PENDING still holds its box, whatever the host
            // judges below.
            // SAFETY: `refuse` checked the frame holds an `OpenOut`.
            open_ended.live = unsafe { (*out.cast::<OpenOut>()).instance };
        }

        if self.faulted.load(Ordering::Acquire) {
            return Crossed::host(Outcome::Fault);
        }
        // SAFETY: the plugin wrote at most the host's `out`; read it back.
        let head = unsafe { *out };
        let outcome = judge(raw, &head, ticket, out_size);
        if outcome == Outcome::Fault {
            return Crossed::host(Outcome::Fault).unread(head.lease);
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
                return Crossed::host(Outcome::Fault).unread(head.lease);
            }
        }
        // SAFETY: the validated answer is still under its lease. Inspection requests are
        // copied before release; no plugin callback runs inside the host's receipt locks.
        let inspection_ticket = if s == slot::CANCEL {
            // SAFETY: the host's validated cancel frame starts with CancelIn.
            unsafe {
                (*input.cast::<busbar_contract::abi::mechanism::lifecycle::CancelIn>()).ticket
            }
        } else {
            ticket
        };
        // Copy and validate the transaction before any independent inspection effect or lease release.
        // SAFETY: the answer remains live under its lease and its kind's checks passed.
        if unsafe {
            super::conditional::answer(
                self.wake,
                self.kind,
                inspection_ticket,
                unit,
                &head,
                &answer,
            )
        }
        .is_err()
        {
            return Crossed::host(Outcome::Refused).unread(head.lease);
        }
        // SAFETY: the same validated answer remains live under its lease.
        if unsafe {
            super::inspection::answer(self.wake, s, inspection_ticket, unit, outcome, &head)
        }
        .is_err()
        {
            return Crossed::host(Outcome::Fault).unread(head.lease);
        }
        if self.kind == KindCode::Transport {
            use busbar_contract::abi::mechanism::{call::BLOB_OCTETS, extensions};
            use busbar_contract::abi::transport::{guest_policy, FramerOut, YIELD_MORE};
            if outcome != Outcome::Pending {
                if let Some(scope) = &scope {
                    scope.operation_done(ticket);
                }
            }
            // SAFETY: plugin extension ranges are bounded before the slice is formed and read
            // before its answer lease or ticket can be released/reused.
            let Some(bytes) = (unsafe { validate::lent(head.extensions.ptr, head.extensions.len) })
            else {
                return Crossed::host(Outcome::Fault).unread(head.lease);
            };
            match busbar_contract::abi::sdk::transport::receive::decode(bytes) {
                Ok(Some(retained)) => {
                    if head.extensions.fmt != BLOB_OCTETS
                        || !matches!(outcome, Outcome::Ready | Outcome::Pending)
                        || (out_size as usize) < size_of::<FramerOut>()
                    {
                        return Crossed::host(Outcome::Fault).unread(head.lease);
                    }
                    let Some(scope) = &scope else {
                        return Crossed::host(Outcome::Fault).unread(head.lease);
                    };
                    scope.set_retained_input(retained);
                }
                Ok(None) => {}
                Err(_) => return Crossed::host(Outcome::Fault).unread(head.lease),
            }
            if let Some(value) = extensions::get(bytes, guest_policy::EXT_GUEST_OPEN) {
                if head.extensions.fmt != BLOB_OCTETS
                    || outcome != Outcome::Ready
                    || (out_size as usize) < size_of::<FramerOut>()
                {
                    return Crossed::host(Outcome::Fault).unread(head.lease);
                }
                // SAFETY: this transport answer was checked by its kind and holds FramerOut.
                let framed = unsafe { &*out.cast::<FramerOut>() };
                if framed.yielded.flags & YIELD_MORE == 0
                    || framed.yielded.wire_len != 0
                    || framed.yielded.frame_len != 0
                    || framed.yielded.pieces_len != 0
                {
                    return Crossed::host(Outcome::Fault).unread(head.lease);
                }
                let opened = guest_policy::Open::decode(value).and_then(|open| {
                    scope
                        .as_ref()
                        .ok_or(super::framing_context::CONTEXT_REFUSED)?
                        .open_stream(ticket, open)
                });
                if let Err(error) = opened {
                    return Crossed {
                        error: Some(error.as_bytes().to_vec()),
                        ..Crossed::host(Outcome::Refused).unread(head.lease)
                    };
                }
            }
        }
        let short = outcome == Outcome::Failed && (self.short)(&answer);
        let Some(reply_extensions) =
            (unsafe { validate::lent(head.extensions.ptr, head.extensions.len) })
        else {
            return Crossed::host(Outcome::Fault).unread(head.lease);
        };
        let short_lease =
            match busbar_contract::abi::sdk::auth_door::short_reply::decode(reply_extensions) {
                Ok(Some(lease))
                    if short
                        && head.extensions.fmt
                            == busbar_contract::abi::mechanism::call::BLOB_OCTETS
                        && lease == head.lease =>
                {
                    lease
                }
                Ok(None) => 0,
                _ => return Crossed::host(Outcome::Fault).unread(head.lease),
            };

        let reason = if s == slot::OPEN && outcome != Outcome::Pending {
            // SAFETY: `refuse` checked the frame holds an `OpenOut`.
            let len = unsafe { (*out.cast::<OpenOut>()).err_len };
            let mut buf = self.take_open_reason();
            if len > buf.len() {
                return Crossed::host(Outcome::Fault).unread(head.lease);
            }
            buf.truncate(len);
            Some(buf).filter(|b| !b.is_empty())
        } else {
            None
        };
        self.ingest(&head);
        self.flagged(&head, s == slot::OPEN || s == slot::REFRESH);
        let error = match outcome {
            Outcome::Failed | Outcome::Refused => reason.or_else(|| copy_str(head.error)),
            _ => None,
        };

        drop(validate_reason);

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
                return Crossed::host(Outcome::Fault).unread(head.lease);
            }
        }

        if s == slot::OPEN && matches!(outcome, Outcome::Ready | Outcome::Pending) {
            // An open that answered READY (done) or PENDING (its connect step pends) hands back
            // its instance box; the host keeps it so a PENDING open's RESUME runs on the SAME
            // box — plugin-owned memory carries the half-open state across the pend (no module
            // static in the contract).
            // SAFETY: `refuse` checked the frame holds an `OpenOut`.
            let inst = unsafe { (*out.cast::<OpenOut>()).instance };
            if inst.is_null() {
                return Crossed::host(Outcome::Fault).unread(head.lease);
            }
            open_ended.ptr = None;
            self.ptr.store(inst, Ordering::Release);

            if outcome == Outcome::Ready {
                self.opened.store(true, Ordering::Release);
            }
        }
        // No result retirement precedes an output validation that could still reject this
        // crossing. The exact ACK is copied while its answer lease remains live.
        // SAFETY: the validated answer is still under its lease.
        if unsafe {
            super::completion_retirement::answer(
                self.wake,
                s,
                outcome,
                &head,
                completion_input.as_ref(),
            )
        }
        .is_err()
        {
            return Crossed::host(Outcome::Fault).unread(head.lease);
        }
        if s == slot::REFRESH {
            if outcome == Outcome::Ready {
                refresh_binding.commit();
            } else if outcome == Outcome::Pending {
                refresh_binding.retain();
            }
        } else if outcome == Outcome::Ready || (s == slot::OPEN && outcome == Outcome::Pending) {
            if let Some(binding) = proposed_binding {
                self.wake.exports.publish(binding);
            } else if s == slot::OPEN
                && self.uses_bindings()
                && self.wake.exports.pin(Ticket::NONE).is_none()
            {
                // Non-export OPEN already declared its original authority. Keep that same
                // authority alive while later accepted refreshes publish isolated generations.
                self.wake
                    .exports
                    .publish(Arc::new(super::export_bindings::Generation {
                        conn: self.wake.conn.get().cloned(),
                        destinations: self
                            .wake
                            .bound
                            .read()
                            .unwrap_or_else(|p| p.into_inner())
                            .clone(),
                    }));
            }
        }

        let handed = matches!(outcome, Outcome::Ready | Outcome::Pending);
        Crossed {
            outcome,
            error,
            lease: if handed { head.lease } else { 0 },
            unread: if handed || short_lease != 0 {
                0
            } else {
                head.lease
            },
            wake_at_ns: if outcome == Outcome::Pending {
                head.wake_at_ns
            } else {
                0
            },
            short,
            short_lease,
            disposition: None,
            cancel_writes: Vec::new(),
        }
    }

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

    fn log(&self, d: &Diag, budget: &mut LogBudget) {
        if d.severity > SEVERITY_TRACE {
            return self.sink.dropped(Dropped::Severity(DIAG_LOG));
        }
        let Some(text) = str_bytes(d.text) else {
            return self.sink.dropped(Dropped::BadArray);
        };
        if budget.records >= MAX_LOG_RECORDS || budget.bytes + text.len() > MAX_LOG_BYTES {
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

pub(crate) fn judge(raw: RawOutcome, head: &OutHead, ticket: Ticket, out_size: u32) -> Outcome {
    if !(1..=4).contains(&raw.0) || head.outcome != raw {
        return Outcome::Fault;
    }

    if let Err(v) = validate::out_head(head, out_size) {
        return v.outcome();
    }
    match raw.outcome() {
        Outcome::Pending if ticket.is_none() => Outcome::Fault,
        o => o,
    }
}

/// `len` entries at `p`, or `None` for NULL-with-length, an over-long array, or one misaligned for
/// `T`: formed only through the one capped, validated reader ([`validate::lent`], THE DESIGN
/// §11.13 M1).
///
/// # Safety
/// A range that passes the checks names `len` live `T`s.
unsafe fn array<'a, T>(p: *const T, len: usize) -> Option<&'a [T]> {
    if len > MAX_ENVELOPE_ENTRIES {
        return None;
    }
    // SAFETY: the caller's contract.
    unsafe { validate::lent(p, len) }
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
#[doc(hidden)]
pub fn str_bytes<'a>(s: AbiStr) -> Option<&'a [u8]> {
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

pub(crate) fn copy_str(s: AbiStr) -> Option<Vec<u8>> {
    (!s.ptr.is_null())
        .then(|| str_bytes(s).map(<[u8]>::to_vec))
        .flatten()
}

pub struct Plugin<K: Kind> {
    #[doc(hidden)]
    pub inner: Arc<Instance>,
    _k: PhantomData<fn() -> K>,
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

fn observed(
    observing: Arc<crate::observe::Observing>,
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
        observing,
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

        let wake: &'static InstanceWake = Box::leak(Box::default());

        let ctx = super::handle::mint(wake)?;

        let mut unbound = Unbound(Some(wake));

        let instance = super::handle::instance_id(ctx);
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
                    if v.kind == KindCode::Auth {
                        table.hold_authority(instance);
                    }
                    // SAFETY: `validate` ran `check_statement`, which refused a NULL list with a
                    // count; the rendering reads the Statement's `'static` lists.
                    let needs = unsafe { busbar_contract::abi::mechanism::rendering::render(&st) }
                        .ok()
                        .and_then(|r| busbar_contract::abi::mechanism::rendering::read(&r).ok())
                        .map(|r| r.needs)
                        .ok_or_else(|| LoadError::BadStatement("the needs do not render".into()))?;
                    wake.conn_state.declare_needs(ctx, &needs);
                    for (i, need) in needs.iter().enumerate() {
                        if !need.transport.is_empty() && !table.serves_scheme(&need.transport) {
                            return Err(LoadError::UnservedScheme {
                                plugin: str_bytes(st.name)
                                    .map(|n| String::from_utf8_lossy(n).into_owned())
                                    .unwrap_or_default(),
                                inbound: need.direction != DIRECTION_OUTBOUND,
                                scheme: need.transport.clone(),
                            });
                        }

                        if from_settings(need) {
                            continue;
                        }
                        let id = NeedId(u32::try_from(i).unwrap_or(u32::MAX));

                        if let Err(e) = table.declare(instance, id, need, None, None) {
                            table.forget(instance);
                            return Err(LoadError::NeedRefused {
                                plugin: str_bytes(st.name)
                                    .map(|n| String::from_utf8_lossy(n).into_owned())
                                    .unwrap_or_default(),
                                need: id.0,
                                transport: need.transport.clone(),
                                reason: crate::observe::conn_reason(e),
                            });
                        }
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
            ctx,
            wake: Some(host_wake),
            conns,
            services: &super::services::HOST_SLOTS,
            io: &super::io_slots::IO_SLOTS,
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
        let reference_fields = super::load::reference_fields(&st)?.into_boxed_slice();
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
                reference_fields,
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
                breaches: AtomicU32::new(0),
                closed: AtomicBool::new(false),
                gate: AtomicU32::new(0),
                crossings: AtomicU64::new(0),
                resumes: AtomicU64::new(0),
                calls: Mutex::new(HashMap::new()),
                next_call: AtomicU64::new(0),
                inflight: AtomicU32::new(0),
                drainable: AtomicU32::new(0),
                unit_ops: AtomicU32::new(0),
                cap: st.max_inflight.clamp(1, bind.max_inflight_cap.max(1)),
                lifecycle_busy: AtomicBool::new(false),
                timeout: K::TIMEOUT,
                check: K::check,
                short: K::short,
                op_name: K::op_name,
                unit_of: K::unit_of,
                cancel_frame: K::cancel_frame,
                context,
                sink: observed(
                    bind.dispatcher.observing().unwrap_or_default(),
                    &bind.sink,
                    &st,
                    v.kind,
                    name,
                ),
                wake,
                tables,
                open_reason: Mutex::new(Vec::new()),
                driven: super::worker::Driven::default(),
                _lib: lib,
            }),
            _k: PhantomData,
        };
        let _ = plugin
            .inner
            .wake
            .instance
            .set(Arc::downgrade(&plugin.inner));
        bind.dispatcher.adopt(&plugin.inner);
        unbound.0 = None;
        Ok(plugin)
    }

    #[cfg(test)]
    pub(crate) fn envelope_sink(&self) -> Arc<dyn EnvelopeSink> {
        self.inner.sink.clone()
    }

    pub fn grant_destinations(&self, declares: &crate::sign::Declares) {
        let _ = self.inner.wake.keep.set(declares.keep.clone());
        let _ = self
            .inner
            .wake
            .destinations
            .set(declares.destinations.clone());
    }

    pub fn context<T: 'static>(&self) -> Option<&T> {
        self.inner
            .context
            .as_deref()
            .and_then(|c| c.downcast_ref::<T>())
    }

    pub fn kind(&self) -> KindCode {
        self.inner.kind
    }

    pub fn name(&self) -> &str {
        self.inner.name()
    }

    pub(crate) fn note(&self, severity: u8, text: &str) {
        self.inner.sink.diag(Diagnostic {
            id: DIAG_LOG,
            name: &[],
            severity,
            text: text.as_bytes(),
        });
    }

    #[must_use]
    pub fn secret_refs(&self) -> &[String] {
        &self.inner.secret_refs
    }

    #[must_use]
    pub fn reference_fields(&self) -> &[String] {
        &self.inner.reference_fields
    }

    pub fn instance(&self) -> InstanceId {
        self.inner.instance
    }

    pub fn conn_table(&self) -> Option<Arc<dyn busbar_contract::conn::DeclaredConns>> {
        self.inner
            .wake
            .conn
            .get()
            .map(|(_, table)| Arc::clone(table))
    }

    pub fn max_inflight(&self) -> u32 {
        self.inner.cap
    }

    pub fn inflight(&self) -> u32 {
        self.inner.inflight()
    }

    pub fn is_faulted(&self) -> bool {
        self.inner.faulted.load(Ordering::Acquire)
    }

    pub fn targets_from_settings(&self) -> bool {
        self.inner.needs.iter().any(|n| !n.target_from.is_empty())
    }

    pub fn is_open(&self) -> bool {
        self.inner.is_open()
    }

    pub fn call<I: InFrame, O: OutFrame>(&self, s: u32, frame: &mut Frame<I, O>) -> Called {
        self.call_on(s, frame, Ticket::NONE, false)
    }

    pub fn recall<I: InFrame, O: OutFrame>(
        &self,
        token: Recall,
        s: u32,
        frame: &mut Frame<I, O>,
    ) -> Called {
        if token.instance != self.instance_id() || token.slot != s {
            return Called::from(Crossed::host(Outcome::Refused));
        }
        let _reference = match token.kept.as_ref() {
            Some(kept) => match unsafe { RecallInput::new(frame.heads().0, kept.id) } {
                Ok(reference) => Some(reference),
                Err(()) => return Called::from(Crossed::host(Outcome::Refused)),
            },
            None => None,
        };
        let called = if token.ticket.is_none() {
            self.call_on(s, frame, token.ticket, false)
        } else {
            self.call_inline(token.ticket, true, s, frame)
        };
        if called.recall.is_some() {
            return Called::from(Crossed::host(Outcome::Fault));
        }
        called
    }

    pub fn call_inline<I: InFrame, O: OutFrame>(
        &self,
        ticket: Ticket,
        resume: bool,
        s: u32,
        frame: &mut Frame<I, O>,
    ) -> Called {
        let inline = self
            .inner
            .wake
            .route
            .get()
            .and_then(std::sync::Weak::upgrade)
            .and_then(|route| route.inline());
        if let Some(tickets) = &inline {
            if !tickets.starting(ticket, self.inner.instance, s, resume) {
                return Called::from(Crossed::host(Outcome::Refused));
            }
        }
        let called = self.call_on(s, frame, ticket, resume);
        if let Some(tickets) = &inline {
            tickets.ended(ticket, s, called.recall.is_some());
        }
        called
    }

    fn instance_id(&self) -> usize {
        Arc::as_ptr(&self.inner) as usize
    }

    fn call_on<I: InFrame, O: OutFrame>(
        &self,
        s: u32,
        frame: &mut Frame<I, O>,
        ticket: Ticket,
        resume: bool,
    ) -> Called {
        let inst = &*self.inner;
        if let Some(o) = inst.refuse(s, size_of::<I>(), size_of::<O>()) {
            return Called::from(Crossed::host(o));
        }

        let owner = super::handle::instance_id(inst.ctx()).0;
        if let Some(o) = K::admit(s, frame.heads().0.cast_const(), size_of::<I>(), owner) {
            return Called::from(Crossed::host(o));
        }
        let lifecycle = is_lifecycle(s);
        if lifecycle && !inst.enter_lifecycle() {
            return Called::from(Crossed::host(Outcome::Refused));
        }
        let admission = if resume {
            inst.binding_resume_admission(s, ticket)
        } else {
            inst.export_admission(s, ticket)
        };
        let Ok(_admission) = admission else {
            if lifecycle {
                inst.leave_lifecycle();
            }
            return Called::from(Crossed::host(Outcome::Refused));
        };
        let Some(units) = inst.acquire(s) else {
            if lifecycle {
                inst.leave_lifecycle();
            }
            return Called::from(Crossed::host(Outcome::Refused));
        };

        if !ticket.is_none() && !resume {
            super::services::new_op(inst.wake, ticket);
        }
        let (i, o, out_size) = frame.heads();
        // SAFETY: the frame is ours for the call; its heads lead the structs.
        let crossed = inst.watched(s, || unsafe {
            let head = &mut *i;
            head.size = size_of::<I>() as u32;

            head.flags = (head.flags & !FLAG_RESUME) | if resume { FLAG_RESUME } else { 0 };
            head.deadline_class = stamped_class::<K>(s, ticket) as u8;
            head.ticket = ticket;
            inst.cross(s, i, o, out_size)
        });
        inst.release(units);
        if lifecycle {
            inst.leave_lifecycle();
        }
        let token = crossed.short.then(|| Recall {
            instance: self.instance_id(),
            slot: s,
            ticket,
            kept: (crossed.short_lease != 0).then(|| RecallLease {
                instance: Arc::clone(&self.inner),
                framing: super::framing_context::current(),
                id: crossed.short_lease,
            }),
        });
        Called {
            recall: token,
            ..Called::from(crossed)
        }
    }
}

pub(crate) fn stamped_class<K: Kind>(s: u32, ticket: Ticket) -> DeadlineClass {
    if ticket.is_none() {
        DeadlineClass::Call
    } else {
        K::ticketed_class(s)
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

#[cfg(test)]
#[path = "../tests/open_reason_tests.rs"]
mod open_reason_tests;

#[cfg(test)]
#[path = "../tests/lifecycle_worker_tests.rs"]
mod lifecycle_worker_tests;

fn from_settings(need: &ReadNeed) -> bool {
    !need.target_from.is_empty() || !need.trust_from.is_empty()
}

pub(crate) fn resolve_owned(owned: &serde_json::Value, at: &str) -> Option<String> {
    at.split('.')
        .try_fold(owned, |v, key| v.get(key))
        .and_then(serde_json::Value::as_str)
        .filter(|t| !t.is_empty())
        .map(str::to_owned)
}

/// The bytes of a host blob: empty when it is absent.
///
/// # Safety
///
/// `blob` is the host's own, its `ptr` valid for `len` bytes for as long as the slice is read.
pub(crate) unsafe fn blob_bytes<'b>(blob: Blob) -> &'b [u8] {
    if blob.ptr.is_null() || blob.len == 0 {
        &[]
    } else {
        // SAFETY: the caller's contract.
        unsafe { std::slice::from_raw_parts(blob.ptr, blob.len) }
    }
}

pub(crate) fn resolve_setting(settings: &serde_json::Value, path: &str) -> Option<String> {
    let rest = path.strip_prefix("settings.")?;
    rest.split('.')
        .try_fold(settings, |v, key| v.get(key))
        .and_then(serde_json::Value::as_str)
        .filter(|t| !t.is_empty())
        .map(str::to_owned)
}

pub(crate) fn member_programs(
    settings: &serde_json::Value,
) -> Vec<(String, busbar_contract::conn::Program)> {
    let Some(map) = settings.as_object() else {
        return Vec::new();
    };
    map.iter()
        .filter_map(|(name, registration)| {
            let program = busbar_contract::conn::Program::of_member(registration)?.ok()?;
            Some((name.clone(), program))
        })
        .collect()
}

pub(crate) fn setting_at<'v>(
    settings: &'v serde_json::Value,
    path: &str,
) -> Option<&'v serde_json::Value> {
    let rest = path.strip_prefix("settings.")?;
    rest.split('.').try_fold(settings, |v, key| v.get(key))
}

pub(crate) fn resolve_target(settings: &serde_json::Value, path: &str) -> Option<String> {
    setting_at(settings, path)
        .and_then(serde_json::Value::as_str)
        .filter(|t| !t.is_empty())
        .map(str::to_owned)
}

#[cfg(test)]
#[path = "../tests/instance_id_tests.rs"]
mod instance_id_tests;

#[cfg(test)]
#[path = "../tests/envelope_array_tests.rs"]
mod envelope_array_tests;
