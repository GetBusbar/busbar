// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! [`PlaneHostVtable`] — the plane→core inbound capability seam, as a `#[repr(C)]` struct of
//! `extern "C-unwind"` fn-pointers.
//!
//! POD args by pointer; small results BY VALUE ([`Decision`], [`AdmissionId`], [`Seq`],
//! [`MeterOutcome`], a `u64` clock); large results into a caller `&mut MaybeUninit<Out>` written
//! INSIDE the callee's `catch_unwind` and marked init only on [`StatusClass::Ok`] (see
//! [`write_out`](crate::write_out)). NO `Vec` return on any hot call.
//!
//! Each slot is `Option<…Fn>`: a `None` slot is an ABSENT (not-granted) capability — the in-process
//! `NotGranted` of the shipped `plane/host.rs`, rendered as a NULL vtable slot. The set is the NEUTRAL
//! capability taxonomy (protocol-noun-free): govern / meter / breaker / verify / egress / journal /
//! nested-dispatch / work-handle / trust (drift-quarantine + approval-redeem) / metrics / clock /
//! auth. There is deliberately NO `secret_resolve` — credentials resolve host-side by REF.
//!
//! ## EXTENSION POINT (reserved, NOT in the hot vtable)
//!
//! Metering `reserve`/`settle` (a `CostHold`) is an append-only extension for a future high-rate
//! carrier. It is DELIBERATELY absent from this vtable: adding it is a new trailing slot + a minor
//! bump, never a reshape. Do not add it to the hot set until a real carrier needs it.

use super::pod::{
    AdmissionId, AdmitRefusal, ApprovalQuery, AuthQuery, AuthResolved, CallerRef, ContentChunk,
    CounterpartyRef, Decision, EgressDesc, EgressId, EgressOpen, Facts, FramingDesc, GateDecision,
    GovRefusal, JournalQuery, Key, MeterOutcome, MetricSample, OpDesc, OpResult, Seq, Signal,
    StatusClass, TargetRef, TrustVerdict, Usage, VerifyDecision, VerifyLease, VerifyQuery,
    VerifyVerdict, WorkHandleDesc, WorkHandleId,
};
use crate::AbiPreamble;
use core::mem::MaybeUninit;
use std::os::raw::c_void;

/// The opaque host-context pointer threaded as the first arg of every host call. The plane never
/// dereferences it; it passes it back so the host recovers its own state. Never null in a live call.
pub type HostCtx = *mut c_void;

// ── hot fn-pointer signatures (small results BY VALUE) ──────────────────────────────────────────

/// Admit (authorize + budget-reserve) a unit of work.
pub type GovernAdmitFn = extern "C-unwind" fn(host: HostCtx, facts: *const Facts) -> Decision;
/// Charge opaque-component consumption against a grant/budget.
pub type MeterChargeFn = extern "C-unwind" fn(host: HostCtx, usage: *const Usage) -> MeterOutcome;
/// Acquire a breaker/failover admission grant for a circuit key.
pub type BreakerAdmitFn = extern "C-unwind" fn(host: HostCtx, key: *const Key) -> AdmissionId;
/// Acquire a breaker/failover admission grant WITH REFUSAL FIDELITY: the host always initializes `out`
/// (never uninitialized), writing the fine [`AdmitRefusal`] reason on a refusal (a returned
/// [`AdmissionId::NONE`]) and leaving it at [`Unavailability`](super::pod::Unavailability)`::Unspecified`
/// on a live id. The append-only counterpart of [`BreakerAdmitFn`], so a refusal keeps its specific
/// meaning across the boundary; the caller reads `out` when the returned id is `NONE`.
pub type BreakerAdmitReasonFn = extern "C-unwind" fn(
    host: HostCtx,
    key: *const Key,
    out: *mut MaybeUninit<AdmitRefusal>,
) -> AdmissionId;
/// Admit (authorize + budget-reserve) a unit of work WITH REFUSAL FIDELITY: the host always
/// initializes `out`, and on a blocked limit (a returned [`Decision::Deny`]) it RENDERS the blocking
/// limit's reason into the caller's `reason_buf` (up to `reason_cap` bytes, the `egress_poll`
/// variable-length pattern) and records its length + recovery hint in [`GovRefusal`], leaving
/// `reason_len == 0` on a [`Decision::Admit`]. The append-only counterpart of [`GovernAdmitFn`], so a
/// budget refusal keeps its specific meaning across the boundary (the meaning the wired `govern_admit`
/// slot drops); the caller reads `reason_buf[..out.reason_len]` when the returned decision is `Deny`.
pub type GovernAdmitReasonFn = extern "C-unwind" fn(
    host: HostCtx,
    facts: *const Facts,
    reason_buf: *mut u8,
    reason_cap: usize,
    out: *mut MaybeUninit<GovRefusal>,
) -> Decision;
/// Settle a breaker admission with the observed outcome signal.
pub type BreakerSettleFn =
    extern "C-unwind" fn(host: HostCtx, admission: AdmissionId, signal: *const Signal) -> StatusClass;
/// Append content-suffix bytes to a scope's hash-chained journal; the host frames the prelude.
pub type JournalAppendFn = extern "C-unwind" fn(
    host: HostCtx,
    scope: u32,
    content_ptr: *const u8,
    content_len: usize,
    framing: *const FramingDesc,
) -> Seq;
/// Open a durable work-handle (durable scope; survives the process).
pub type WorkHandleOpenFn =
    extern "C-unwind" fn(host: HostCtx, desc: *const WorkHandleDesc) -> WorkHandleId;
/// Resume a durable work-handle by lookup.
pub type WorkHandleResumeFn =
    extern "C-unwind" fn(host: HostCtx, handle: WorkHandleId) -> StatusClass;
/// Quarantine / demote a counterparty on drift.
pub type DriftQuarantineFn = extern "C-unwind" fn(host: HostCtx, key: *const Key) -> StatusClass;
/// Redeem a one-time approval / single-use nonce for a counterparty.
pub type ApprovalRedeemFn = extern "C-unwind" fn(host: HostCtx, key: *const Key) -> StatusClass;
/// Emit a plane metric sample (label passthrough).
pub type MetricsEmitFn = extern "C-unwind" fn(host: HostCtx, sample: *const MetricSample) -> StatusClass;
/// The host clock, in Unix nanoseconds (so a plane takes no ambient clock).
pub type ClockNowFn = extern "C-unwind" fn(host: HostCtx) -> u64;

// ── hot fn-pointer signatures (large results into `&mut MaybeUninit<Out>`) ───────────────────────

/// Look up a counterparty-verification verdict (host cache + single-flight leadership).
pub type VerifyLookupFn = extern "C-unwind" fn(
    host: HostCtx,
    key: *const Key,
    out: *mut MaybeUninit<VerifyVerdict>,
) -> StatusClass;
/// Store a fetched verification verdict under a leadership lease with a TTL.
pub type VerifyStoreFn = extern "C-unwind" fn(
    host: HostCtx,
    key: *const Key,
    lease: VerifyLease,
    ttl_secs: u64,
) -> StatusClass;
/// Open a governed egress; writes an [`EgressOpen`] on Ok.
pub type EgressOpenFn = extern "C-unwind" fn(
    host: HostCtx,
    desc: *const EgressDesc,
    out: *mut MaybeUninit<EgressOpen>,
) -> StatusClass;
/// Poll readable bytes from a governed egress into a caller buffer; sets `out_written`.
pub type EgressPollFn = extern "C-unwind" fn(
    host: HostCtx,
    egress: EgressId,
    buf: *mut u8,
    buf_cap: usize,
    out_written: *mut usize,
) -> StatusClass;
/// Write bytes to a governed egress.
pub type EgressWriteFn =
    extern "C-unwind" fn(host: HostCtx, egress: EgressId, buf: *const u8, len: usize) -> StatusClass;
/// Close a governed egress (idempotent).
pub type EgressCloseFn = extern "C-unwind" fn(host: HostCtx, egress: EgressId) -> StatusClass;
/// Read journal rows into a caller buffer; sets `out_written`.
pub type JournalReadFn = extern "C-unwind" fn(
    host: HostCtx,
    query: *const JournalQuery,
    buf: *mut u8,
    buf_cap: usize,
    out_written: *mut usize,
) -> StatusClass;
/// Route an opaque sub-request through the SAME router (depth-bounded); writes an [`OpResult`] on Ok.
pub type NestedDispatchFn =
    extern "C-unwind" fn(host: HostCtx, desc: *const OpDesc, out: *mut MaybeUninit<OpResult>) -> StatusClass;
/// Resolve a credential REF to a host-side reference (NEVER plaintext); writes an [`AuthResolved`].
pub type AuthResolveFn =
    extern "C-unwind" fn(host: HostCtx, query: *const AuthQuery, out: *mut MaybeUninit<AuthResolved>) -> StatusClass;
/// Evaluate the stateful admission-time trust of a counterparty (sightings/approvals/drift live
/// host-side); returns a [`TrustVerdict`] BY VALUE. The trust-family's stateful evaluator, distinct
/// from the `verify_*` digest cache.
pub type TrustEvaluateFn =
    extern "C-unwind" fn(host: HostCtx, counterparty: *const CounterpartyRef) -> TrustVerdict;
/// Check whether a caller is entitled to use a target (the host owns the caller's scopes/keys).
/// Returns a bool BY VALUE — the catalogue visibility/entitlement filter.
pub type EntitlementCheckFn =
    extern "C-unwind" fn(host: HostCtx, caller: *const CallerRef, target: *const TargetRef) -> bool;
/// Feed one content chunk to the streaming content-governance gate; returns a [`GateDecision`] BY
/// VALUE (Continue / Block). The host owns the gate policy; the plane scans incrementally.
pub type GateScanFn = extern "C-unwind" fn(host: HostCtx, chunk: *const ContentChunk) -> GateDecision;
/// The STATELESS verify-freshness DECISION over a [`VerifyQuery`] (`last_checked_ms` + `ttl_ms` +
/// `now_ms`): returns [`VerifyDecision::Fresh`] (reuse the snapshot) or [`VerifyDecision::Stale`]
/// (re-verify), reproducing `reverify::due`'s arithmetic EXACTLY. The host owns NO freshness cache
/// and NO single-flight — the plane keeps its ledger/coalescing; only the arithmetic crosses here.
pub type VerifyDecideFn =
    extern "C-unwind" fn(host: HostCtx, query: *const VerifyQuery) -> VerifyDecision;
/// Redeem a one-time approval over a richer [`ApprovalQuery`] (nonce + the seal's `expires_at` +
/// `now`), so the host spends against the EXACT expiry the seal minted. The expiry-carrying sibling
/// of [`ApprovalRedeemFn`].
pub type ApprovalRedeemQFn =
    extern "C-unwind" fn(host: HostCtx, query: *const ApprovalQuery) -> StatusClass;

/// The `#[repr(C)]` inbound-capability vtable a plane calls back into. Leads with the FROZEN
/// [`AbiPreamble`] (a receiver `check_preamble`s it before using any slot) and a `size`/`version`
/// pair (the sized-struct discipline for the table itself — new slots append at the TAIL and bump the
/// airlock MINOR). Every slot is `Option`: `None` = an absent/not-granted capability.
#[repr(C)]
pub struct PlaneHostVtable {
    /// The FROZEN airlock header — checked before any slot is invoked.
    pub abi: AbiPreamble,
    /// `size_of::<PlaneHostVtable>()` at construction (the table's sized-struct guard).
    pub size: u32,
    /// Table schema version (bumped when a trailing slot is appended).
    pub version: u32,

    /// Admit a unit of work.
    pub govern_admit: Option<GovernAdmitFn>,
    /// Charge consumption.
    pub meter_charge: Option<MeterChargeFn>,
    /// Acquire a breaker admission.
    pub breaker_admit: Option<BreakerAdmitFn>,
    /// Settle a breaker admission.
    pub breaker_settle: Option<BreakerSettleFn>,
    /// Look up a counterparty verdict.
    pub verify_lookup: Option<VerifyLookupFn>,
    /// Store a counterparty verdict.
    pub verify_store: Option<VerifyStoreFn>,
    /// Open a governed egress.
    pub egress_open: Option<EgressOpenFn>,
    /// Poll a governed egress.
    pub egress_poll: Option<EgressPollFn>,
    /// Write to a governed egress.
    pub egress_write: Option<EgressWriteFn>,
    /// Close a governed egress.
    pub egress_close: Option<EgressCloseFn>,
    /// Append to a journal scope.
    pub journal_append: Option<JournalAppendFn>,
    /// Read a journal scope.
    pub journal_read: Option<JournalReadFn>,
    /// Route a nested sub-operation.
    pub nested_dispatch: Option<NestedDispatchFn>,
    /// Open a durable work-handle.
    pub workhandle_open: Option<WorkHandleOpenFn>,
    /// Resume a durable work-handle.
    pub workhandle_resume: Option<WorkHandleResumeFn>,
    /// Quarantine a drifted counterparty.
    pub drift_quarantine: Option<DriftQuarantineFn>,
    /// Redeem a one-time approval.
    pub approval_redeem: Option<ApprovalRedeemFn>,
    /// Emit a metric sample.
    pub metrics_emit: Option<MetricsEmitFn>,
    /// The host clock.
    pub clock_now: Option<ClockNowFn>,
    /// Resolve a credential reference.
    pub auth_resolve: Option<AuthResolveFn>,
    // ── APPENDED (Phase-2 edge audit): three production dual-plane capabilities. Trailing slots,
    //    append-only, added under the same sized/versioned discipline (a MINOR bump). ─────────────
    /// Evaluate stateful admission-time counterparty trust.
    pub trust_evaluate: Option<TrustEvaluateFn>,
    /// Check caller→target entitlement (catalogue visibility filter).
    pub entitlement_check: Option<EntitlementCheckFn>,
    /// Scan a streaming content chunk through the governance gate.
    pub gate_scan: Option<GateScanFn>,
    // ── APPENDED (refusal fidelity): a refusal-carrying acquire. Trailing slot, append-only, added
    //    under the same sized/versioned discipline (a MINOR bump). ──────────────────────────────────
    /// Acquire a breaker admission, carrying the fine [`AdmitRefusal`] reason out on a refusal.
    pub breaker_admit_reason: Option<BreakerAdmitReasonFn>,
    // ── APPENDED (verify/approval faithfulness): the STATELESS verify-freshness DECISION and the
    //    expiry-carrying approval redemption, so the host reproduces `reverify::due` and the seal's
    //    expiry EXACTLY. Trailing slots, append-only, same sized/versioned discipline (a MINOR
    //    bump). The plane keeps its own ledger/coalescing — only the arithmetic crosses. ────────────
    /// Decide verify freshness over a [`VerifyQuery`] (`last_checked_ms` + `ttl_ms` + `now_ms`).
    pub verify_decide: Option<VerifyDecideFn>,
    /// Redeem a one-time approval over an [`ApprovalQuery`] (nonce + seal `expires_at` + `now`).
    pub approval_redeem_q: Option<ApprovalRedeemQFn>,
    // ── APPENDED (govern refusal fidelity): the admit-side analogue of `breaker_admit_reason`, so a
    //    blocked BUDGET limit carries its rendered reason out instead of the wired `govern_admit`
    //    dropping it to a bare `Deny`. Trailing slot, append-only, same sized/versioned discipline
    //    (a MINOR bump). ─────────────────────────────────────────────────────────────────────────
    /// Admit a unit of work, rendering a blocked limit's reason into `reason_buf` on a `Deny`.
    pub govern_admit_reason: Option<GovernAdmitReasonFn>,
    // ── EXTENSION POINT (reserved) ──────────────────────────────────────────────────────────────
    // Metering reserve/settle (a `CostHold`) is DELIBERATELY NOT a slot here. When a high-rate
    // carrier needs it, add `cost_reserve`/`cost_settle` as trailing `Option` slots below this line
    // and bump the airlock MINOR — an append-only add, never a reshape.
}

// SAFETY: the vtable holds only `AbiPreamble` scalars and `Option<extern "C-unwind" fn>` pointers —
// all `Copy`, address-stable, and safe to share across threads (a plane holds `&PlaneHostVtable`
// across `.await` and worker threads). No slot owns or aliases mutable state.
unsafe impl Send for PlaneHostVtable {}
// SAFETY: see the `Send` impl above.
unsafe impl Sync for PlaneHostVtable {}

impl PlaneHostVtable {
    /// An EMPTY vtable: the FROZEN preamble/size/version filled, EVERY capability `None` (absent /
    /// not-granted). This is the honest default a host starts from and grants into — the NULL-slot
    /// analogue of the shipped trait whose default grants nothing.
    pub const EMPTY: PlaneHostVtable = PlaneHostVtable {
        abi: AbiPreamble::CURRENT,
        size: core::mem::size_of::<PlaneHostVtable>() as u32,
        version: crate::ABI_MINOR,
        govern_admit: None,
        meter_charge: None,
        breaker_admit: None,
        breaker_settle: None,
        verify_lookup: None,
        verify_store: None,
        egress_open: None,
        egress_poll: None,
        egress_write: None,
        egress_close: None,
        journal_append: None,
        journal_read: None,
        nested_dispatch: None,
        workhandle_open: None,
        workhandle_resume: None,
        drift_quarantine: None,
        approval_redeem: None,
        metrics_emit: None,
        clock_now: None,
        auth_resolve: None,
        trust_evaluate: None,
        entitlement_check: None,
        gate_scan: None,
        breaker_admit_reason: None,
        verify_decide: None,
        approval_redeem_q: None,
        govern_admit_reason: None,
    };

    /// A fully-populated STUB vtable: every slot points at an `unimplemented!()` stub. It exists to
    /// PROVE every signature is a real, well-typed `extern "C-unwind"` fn-pointer (it type-checks the
    /// whole surface). Downstream agents replace each stub with a real host impl. Invoking any slot
    /// panics — it is a compile-surface fixture, not a runnable host.
    pub const STUB: PlaneHostVtable = PlaneHostVtable {
        abi: AbiPreamble::CURRENT,
        size: core::mem::size_of::<PlaneHostVtable>() as u32,
        version: crate::ABI_MINOR,
        govern_admit: Some(stub::govern_admit),
        meter_charge: Some(stub::meter_charge),
        breaker_admit: Some(stub::breaker_admit),
        breaker_settle: Some(stub::breaker_settle),
        verify_lookup: Some(stub::verify_lookup),
        verify_store: Some(stub::verify_store),
        egress_open: Some(stub::egress_open),
        egress_poll: Some(stub::egress_poll),
        egress_write: Some(stub::egress_write),
        egress_close: Some(stub::egress_close),
        journal_append: Some(stub::journal_append),
        journal_read: Some(stub::journal_read),
        nested_dispatch: Some(stub::nested_dispatch),
        workhandle_open: Some(stub::workhandle_open),
        workhandle_resume: Some(stub::workhandle_resume),
        drift_quarantine: Some(stub::drift_quarantine),
        approval_redeem: Some(stub::approval_redeem),
        metrics_emit: Some(stub::metrics_emit),
        clock_now: Some(stub::clock_now),
        auth_resolve: Some(stub::auth_resolve),
        trust_evaluate: Some(stub::trust_evaluate),
        entitlement_check: Some(stub::entitlement_check),
        gate_scan: Some(stub::gate_scan),
        breaker_admit_reason: Some(stub::breaker_admit_reason),
        verify_decide: Some(stub::verify_decide),
        approval_redeem_q: Some(stub::approval_redeem_q),
        govern_admit_reason: Some(stub::govern_admit_reason),
    };
}

/// The `unimplemented!()` stub host-calls backing [`PlaneHostVtable::STUB`]. Each has the EXACT
/// fn-pointer signature of its slot, so this module is the type-level proof that the surface compiles.
/// A real host replaces each with an impl that does the work INSIDE a `catch_unwind` and writes any
/// out-param only on the Ok path.
pub mod stub {
    use super::*;

    /// Stub: see module docs.
    pub extern "C-unwind" fn govern_admit(_host: HostCtx, _facts: *const Facts) -> Decision {
        unimplemented!("PlaneHost::govern_admit — stub; wired in a later phase")
    }
    /// Stub: see module docs.
    pub extern "C-unwind" fn meter_charge(_host: HostCtx, _usage: *const Usage) -> MeterOutcome {
        unimplemented!("PlaneHost::meter_charge — stub")
    }
    /// Stub: see module docs.
    pub extern "C-unwind" fn breaker_admit(_host: HostCtx, _key: *const Key) -> AdmissionId {
        unimplemented!("PlaneHost::breaker_admit — stub")
    }
    /// Stub: see module docs.
    pub extern "C-unwind" fn govern_admit_reason(
        _host: HostCtx,
        _facts: *const Facts,
        _reason_buf: *mut u8,
        _reason_cap: usize,
        _out: *mut MaybeUninit<GovRefusal>,
    ) -> Decision {
        unimplemented!("PlaneHost::govern_admit_reason — stub")
    }
    /// Stub: see module docs.
    pub extern "C-unwind" fn breaker_admit_reason(
        _host: HostCtx,
        _key: *const Key,
        _out: *mut MaybeUninit<AdmitRefusal>,
    ) -> AdmissionId {
        unimplemented!("PlaneHost::breaker_admit_reason — stub")
    }
    /// Stub: see module docs.
    pub extern "C-unwind" fn breaker_settle(
        _host: HostCtx,
        _admission: AdmissionId,
        _signal: *const Signal,
    ) -> StatusClass {
        unimplemented!("PlaneHost::breaker_settle — stub")
    }
    /// Stub: see module docs.
    pub extern "C-unwind" fn verify_lookup(
        _host: HostCtx,
        _key: *const Key,
        _out: *mut MaybeUninit<VerifyVerdict>,
    ) -> StatusClass {
        unimplemented!("PlaneHost::verify_lookup — stub")
    }
    /// Stub: see module docs.
    pub extern "C-unwind" fn verify_store(
        _host: HostCtx,
        _key: *const Key,
        _lease: VerifyLease,
        _ttl_secs: u64,
    ) -> StatusClass {
        unimplemented!("PlaneHost::verify_store — stub")
    }
    /// Stub: see module docs.
    pub extern "C-unwind" fn verify_decide(
        _host: HostCtx,
        _query: *const VerifyQuery,
    ) -> VerifyDecision {
        unimplemented!("PlaneHost::verify_decide — stub")
    }
    /// Stub: see module docs.
    pub extern "C-unwind" fn approval_redeem_q(
        _host: HostCtx,
        _query: *const ApprovalQuery,
    ) -> StatusClass {
        unimplemented!("PlaneHost::approval_redeem_q — stub")
    }
    /// Stub: see module docs.
    pub extern "C-unwind" fn egress_open(
        _host: HostCtx,
        _desc: *const EgressDesc,
        _out: *mut MaybeUninit<EgressOpen>,
    ) -> StatusClass {
        unimplemented!("PlaneHost::egress_open — stub")
    }
    /// Stub: see module docs.
    pub extern "C-unwind" fn egress_poll(
        _host: HostCtx,
        _egress: EgressId,
        _buf: *mut u8,
        _buf_cap: usize,
        _out_written: *mut usize,
    ) -> StatusClass {
        unimplemented!("PlaneHost::egress_poll — stub")
    }
    /// Stub: see module docs.
    pub extern "C-unwind" fn egress_write(
        _host: HostCtx,
        _egress: EgressId,
        _buf: *const u8,
        _len: usize,
    ) -> StatusClass {
        unimplemented!("PlaneHost::egress_write — stub")
    }
    /// Stub: see module docs.
    pub extern "C-unwind" fn egress_close(_host: HostCtx, _egress: EgressId) -> StatusClass {
        unimplemented!("PlaneHost::egress_close — stub")
    }
    /// Stub: see module docs.
    pub extern "C-unwind" fn journal_append(
        _host: HostCtx,
        _scope: u32,
        _content_ptr: *const u8,
        _content_len: usize,
        _framing: *const FramingDesc,
    ) -> Seq {
        unimplemented!("PlaneHost::journal_append — stub")
    }
    /// Stub: see module docs.
    pub extern "C-unwind" fn journal_read(
        _host: HostCtx,
        _query: *const JournalQuery,
        _buf: *mut u8,
        _buf_cap: usize,
        _out_written: *mut usize,
    ) -> StatusClass {
        unimplemented!("PlaneHost::journal_read — stub")
    }
    /// Stub: see module docs.
    pub extern "C-unwind" fn nested_dispatch(
        _host: HostCtx,
        _desc: *const OpDesc,
        _out: *mut MaybeUninit<OpResult>,
    ) -> StatusClass {
        unimplemented!("PlaneHost::nested_dispatch — stub")
    }
    /// Stub: see module docs.
    pub extern "C-unwind" fn workhandle_open(
        _host: HostCtx,
        _desc: *const WorkHandleDesc,
    ) -> WorkHandleId {
        unimplemented!("PlaneHost::workhandle_open — stub")
    }
    /// Stub: see module docs.
    pub extern "C-unwind" fn workhandle_resume(
        _host: HostCtx,
        _handle: WorkHandleId,
    ) -> StatusClass {
        unimplemented!("PlaneHost::workhandle_resume — stub")
    }
    /// Stub: see module docs.
    pub extern "C-unwind" fn drift_quarantine(_host: HostCtx, _key: *const Key) -> StatusClass {
        unimplemented!("PlaneHost::drift_quarantine — stub")
    }
    /// Stub: see module docs.
    pub extern "C-unwind" fn approval_redeem(_host: HostCtx, _key: *const Key) -> StatusClass {
        unimplemented!("PlaneHost::approval_redeem — stub")
    }
    /// Stub: see module docs.
    pub extern "C-unwind" fn metrics_emit(_host: HostCtx, _sample: *const MetricSample) -> StatusClass {
        unimplemented!("PlaneHost::metrics_emit — stub")
    }
    /// Stub: see module docs.
    pub extern "C-unwind" fn clock_now(_host: HostCtx) -> u64 {
        unimplemented!("PlaneHost::clock_now — stub")
    }
    /// Stub: see module docs.
    pub extern "C-unwind" fn auth_resolve(
        _host: HostCtx,
        _query: *const AuthQuery,
        _out: *mut MaybeUninit<AuthResolved>,
    ) -> StatusClass {
        unimplemented!("PlaneHost::auth_resolve — stub")
    }
    /// Stub: see module docs.
    pub extern "C-unwind" fn trust_evaluate(
        _host: HostCtx,
        _counterparty: *const CounterpartyRef,
    ) -> TrustVerdict {
        unimplemented!("PlaneHost::trust_evaluate — stub")
    }
    /// Stub: see module docs.
    pub extern "C-unwind" fn entitlement_check(
        _host: HostCtx,
        _caller: *const CallerRef,
        _target: *const TargetRef,
    ) -> bool {
        unimplemented!("PlaneHost::entitlement_check — stub")
    }
    /// Stub: see module docs.
    pub extern "C-unwind" fn gate_scan(_host: HostCtx, _chunk: *const ContentChunk) -> GateDecision {
        unimplemented!("PlaneHost::gate_scan — stub")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_vtable_grants_nothing() {
        let vt = &PlaneHostVtable::EMPTY;
        assert!(vt.govern_admit.is_none());
        assert!(vt.egress_open.is_none());
        assert!(vt.auth_resolve.is_none());
        assert_eq!(crate::check_preamble(&vt.abi), Ok(()));
    }

    #[test]
    fn stub_vtable_populates_every_slot() {
        let vt = &PlaneHostVtable::STUB;
        assert!(vt.govern_admit.is_some());
        assert!(vt.meter_charge.is_some());
        assert!(vt.breaker_admit.is_some());
        assert!(vt.breaker_settle.is_some());
        assert!(vt.verify_lookup.is_some());
        assert!(vt.verify_store.is_some());
        assert!(vt.egress_open.is_some());
        assert!(vt.egress_poll.is_some());
        assert!(vt.egress_write.is_some());
        assert!(vt.egress_close.is_some());
        assert!(vt.journal_append.is_some());
        assert!(vt.journal_read.is_some());
        assert!(vt.nested_dispatch.is_some());
        assert!(vt.workhandle_open.is_some());
        assert!(vt.workhandle_resume.is_some());
        assert!(vt.drift_quarantine.is_some());
        assert!(vt.approval_redeem.is_some());
        assert!(vt.metrics_emit.is_some());
        assert!(vt.clock_now.is_some());
        assert!(vt.auth_resolve.is_some());
        assert!(vt.trust_evaluate.is_some());
        assert!(vt.entitlement_check.is_some());
        assert!(vt.gate_scan.is_some());
        assert_eq!(vt.size as usize, core::mem::size_of::<PlaneHostVtable>());
    }

    #[test]
    #[should_panic(expected = "govern_admit")]
    fn stub_slot_is_unimplemented() {
        let vt = &PlaneHostVtable::STUB;
        let g = Facts::new(1, 10, 0, 0, 0, b"p");
        (vt.govern_admit.unwrap())(core::ptr::null_mut(), &*g as *const Facts);
    }
}
