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
//! ## Metering-lease seam (minor-19) + the extension point
//!
//! Metering `cost_reserve`/`cost_settle` (a reserve-then-settle `CostHold`) is the continuous-metering
//! counterpart of the one-shot `meter_charge`, for a HIGH-RATE carrier (a live voice/stream session) a
//! plane cannot price after the fact. It was added as two trailing slots + a minor bump (never a
//! reshape) — the pattern every future capability follows: append at the TAIL, bump the airlock MINOR,
//! re-seed the layout golden. The slots stay `None` in the wired host until the carrier that needs them
//! lands. Do not add a new capability to the hot set until a real plane needs it.

use super::pod::{
    AdmissionId, AdmitRefusal, ApprovalQuery, AuthQuery, AuthResolved, CallerRef, ChainBreakHdr,
    ContentChunk, CostLeaseId, CostSettleOut, CounterpartyRef, Decision, EgressDesc, EgressFault,
    EgressId, EgressOpen, Facts, FramingDesc, GateDecision, GateSubjectRef, GateVerdictOut,
    GovRefusal, GuardVerdict, IdentityAdmitted, IdentityQuery, JournalQuery, JournalStreamDesc,
    Key, MeterOutcome, MetricSample, OpDesc, OpResult, PipeId, ReframeOut, RestoredHdr, Seq,
    Signal, StatusClass, TargetRef, TrustVerdict, Usage, VerifyChainHdr, VerifyDecision,
    VerifyLease, VerifyQuery, VerifyVerdict, WorkHandleDesc, WorkHandleId,
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
pub type BreakerSettleFn = extern "C-unwind" fn(
    host: HostCtx,
    admission: AdmissionId,
    signal: *const Signal,
) -> StatusClass;
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
pub type MetricsEmitFn =
    extern "C-unwind" fn(host: HostCtx, sample: *const MetricSample) -> StatusClass;
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
pub type EgressWriteFn = extern "C-unwind" fn(
    host: HostCtx,
    egress: EgressId,
    buf: *const u8,
    len: usize,
) -> StatusClass;
/// Close a governed egress (idempotent).
pub type EgressCloseFn = extern "C-unwind" fn(host: HostCtx, egress: EgressId) -> StatusClass;
/// Retrieve the neutral FAILURE detail of the last failed `egress_open` in this dispatch scope: writes
/// an [`EgressFault`] header (class + status + the two lengths) and copies the flattened CAUSE-message
/// bytes and the TARGET-url bytes into SEPARATE caller buffers, so a plane composes its own operator
/// string (one keeps the url, another strips it). `Ok` when a fault was stashed (and consumed);
/// `Gone` when none is pending. The host formats no operator string. The failure-side counterpart of
/// the Ok-path [`EgressHead`].
pub type EgressFaultFn = extern "C-unwind" fn(
    host: HostCtx,
    out: *mut MaybeUninit<EgressFault>,
    cause_buf: *mut u8,
    cause_cap: usize,
    url_buf: *mut u8,
    url_cap: usize,
) -> StatusClass;
/// Read readable bytes from a governed byte-duplex PIPE (raw-connection / subprocess tier) into a
/// caller buffer; sets `out_written`. The host moves RAW BYTES only — line/message framing stays
/// PLANE-side, layered on top (the CLUSTER-3 (c) decision: the host is byte-level, the plane frames).
/// `Ok` with `out_written = 0` is a clean end of stream (the child closed its output). The duplex
/// counterpart of [`EgressPollFn`], keyed by a [`PipeId`] rather than an [`EgressId`].
pub type PipeReadFn = extern "C-unwind" fn(
    host: HostCtx,
    pipe: PipeId,
    buf: *mut u8,
    buf_cap: usize,
    out_written: *mut usize,
) -> StatusClass;
/// Write RAW BYTES to a governed byte-duplex PIPE (the child's input / the raw socket). The plane
/// frames on top; the host moves bytes. The duplex counterpart of [`EgressWriteFn`], keyed by a
/// [`PipeId`].
pub type PipeWriteFn =
    extern "C-unwind" fn(host: HostCtx, pipe: PipeId, buf: *const u8, len: usize) -> StatusClass;
/// Read journal rows into a caller buffer; sets `out_written`.
pub type JournalReadFn = extern "C-unwind" fn(
    host: HostCtx,
    query: *const JournalQuery,
    buf: *mut u8,
    buf_cap: usize,
    out_written: *mut usize,
) -> StatusClass;
// ── APPENDED (minor-9, the DURABLE journal seam): the append-only trailing family that makes the
//    journal store-backed. A plane REGISTERS a stream (its neutral `kind`, framing, digests_scope +
//    a plane-provided REFRAME callback), then addresses every scoped op by the host-assigned
//    `kind_id`. The host owns the ONE chain authority (seq/prev_hash/hash minted via the core audit
//    chain) and the durable store; the plane owns only its record shape, carried as an opaque
//    pre-framed content suffix in and reconstructed by its reframe out. Core names no plane type. ──

/// PLANE-PROVIDED: reconstruct one record's chain fields from an opaque stored `body` and its `scope`,
/// WITHOUT the host decoding a plane type. The plane decodes the body (its own serde row, OR the
/// journal's neutral `{seq, prev_hash, hash, content}` body) and writes the minted [`ReframeOut`] plus
/// the `prev_hash`, `hash` and pre-framed content `suffix` bytes into the three caller buffers (the
/// `egress_poll` variable-length pattern: on a too-small buffer, report the required length in
/// `ReframeOut` and return [`StatusClass::Refused`]). The suffix carries its own leading `|` for
/// [`Framing::PipeSeparated`] (Option A), so the host appends it RAW after the framed prelude.
pub type JournalReframeFn = extern "C-unwind" fn(
    host: HostCtx,
    kind_id: u32,
    body_ptr: *const u8,
    body_len: usize,
    out: *mut MaybeUninit<ReframeOut>,
    prev_buf: *mut u8,
    prev_cap: usize,
    hash_buf: *mut u8,
    hash_cap: usize,
    suffix_buf: *mut u8,
    suffix_cap: usize,
) -> StatusClass;
/// Register a durable journal stream: the host records its neutral `kind`/framing/`digests_scope` and
/// its plane-provided [`JournalReframeFn`] under the descriptor's `kind_id`, so later scoped ops
/// address it by that integer. Idempotent per `kind_id`.
pub type JournalRegisterFn = extern "C-unwind" fn(
    host: HostCtx,
    desc: *const JournalStreamDesc,
    reframe: JournalReframeFn,
) -> StatusClass;
/// APPEND one record to a registered stream's `scope` (a DURABLE `String` key, e.g. `task-1`): the
/// host MINTS the seq/prev_hash/hash via the ONE core chain, frames the prelude in the stream's
/// framing, joins the plane's opaque pre-framed content SUFFIX, digests, and persists — returning the
/// assigned [`Seq`] (or [`Seq::NONE`] fail-closed). The stream's framing/digests_scope come from its
/// registration; the plane supplies only the content suffix.
pub type JournalAppendScopedFn = extern "C-unwind" fn(
    host: HostCtx,
    kind_id: u32,
    scope_ptr: *const u8,
    scope_len: usize,
    content_ptr: *const u8,
    content_len: usize,
) -> Seq;
/// Read a registered stream's `scope` window (the durable cold read) into a caller buffer; sets
/// `out_written`. Same bytes-tier encoding as [`JournalReadFn`], keyed by `kind_id` + a `String` scope.
pub type JournalReadScopedFn = extern "C-unwind" fn(
    host: HostCtx,
    kind_id: u32,
    scope_ptr: *const u8,
    scope_len: usize,
    from_seq: u64,
    limit: u64,
    buf: *mut u8,
    buf_cap: usize,
    out_written: *mut usize,
) -> StatusClass;
/// BOOT REHYDRATE a registered stream from the durable store: resume every scope's position and write
/// the neutral [`RestoredHdr`] counts on Ok. The host reframes each stored body through the stream's
/// registered callback; no scope name crosses.
pub type JournalRestoreFn = extern "C-unwind" fn(
    host: HostCtx,
    kind_id: u32,
    out: *mut MaybeUninit<RestoredHdr>,
) -> StatusClass;
/// SEED one scope's position from a packed set of already-read stored bodies (a `u32` count, then per
/// body a `u32` little-endian length + bytes) — the caller-driven rehydrate the A2A task table uses
/// for its active tasks. Writes a [`ChainBreakHdr`] (reporting a broken-but-resumed chain) on Ok.
pub type JournalSeedFn = extern "C-unwind" fn(
    host: HostCtx,
    kind_id: u32,
    scope_ptr: *const u8,
    scope_len: usize,
    bodies_ptr: *const u8,
    bodies_len: usize,
    out: *mut MaybeUninit<ChainBreakHdr>,
) -> StatusClass;
/// FORGET one scope's cached position (a terminal task evicted from the working set); the durable rows
/// stay in the store. Keyed by `kind_id` + a `String` scope.
pub type JournalForgetFn = extern "C-unwind" fn(
    host: HostCtx,
    kind_id: u32,
    scope_ptr: *const u8,
    scope_len: usize,
) -> StatusClass;
/// RETENTION: drop a registered stream's durable rows older than `before`, writing the number removed
/// into `out_removed` on Ok. Positions are not reset (reopening at seq 1 after a purge would collide).
pub type JournalCompactFn = extern "C-unwind" fn(
    host: HostCtx,
    kind_id: u32,
    before: u64,
    out_removed: *mut u64,
) -> StatusClass;
/// VERIFY one scope's persisted chain (reframed) and write a [`VerifyChainHdr`] on Ok — the durable
/// `verify_task_chain` seam. A too-small/unknown scope verifies vacuously; a tamper is reported, not
/// a fault.
pub type JournalVerifyScopedFn = extern "C-unwind" fn(
    host: HostCtx,
    kind_id: u32,
    scope_ptr: *const u8,
    scope_len: usize,
    out: *mut MaybeUninit<VerifyChainHdr>,
) -> StatusClass;

/// Route an opaque sub-request through the SAME router (depth-bounded); writes an [`OpResult`] on Ok.
pub type NestedDispatchFn = extern "C-unwind" fn(
    host: HostCtx,
    desc: *const OpDesc,
    out: *mut MaybeUninit<OpResult>,
) -> StatusClass;
/// Resolve a credential REF to a host-side reference (NEVER plaintext); writes an [`AuthResolved`].
pub type AuthResolveFn = extern "C-unwind" fn(
    host: HostCtx,
    query: *const AuthQuery,
    out: *mut MaybeUninit<AuthResolved>,
) -> StatusClass;
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
pub type GateScanFn =
    extern "C-unwind" fn(host: HostCtx, chunk: *const ContentChunk) -> GateDecision;
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
/// Sign a detached-JWS signing input with a HOST-OWNED signing subkey. The plane builds the RFC 7515
/// signing input (`<protected>.<payload>`) and passes its bytes as `(input_ptr, input_len)`; the host
/// derives its domain-separated signing subkey, signs, and writes the 64-byte Ed25519 signature into
/// `out` (a caller-provided 64-byte buffer) on [`StatusClass::Ok`]. The signing SECRET is derived and
/// held host-side and NEVER crosses to the plane. (The a2a plane uses this to sign its agent cards,
/// but the capability is named for what it does — sign a caller-framed input with a host subkey —
/// not for any one protocol's document.) [`StatusClass::Refused`] when the host holds no signing
/// subkey (nothing to sign with); [`StatusClass::Fault`] on a caught panic — `out` is left untouched
/// on any non-`Ok` return.
pub type SubkeySignFn = extern "C-unwind" fn(
    host: HostCtx,
    input_ptr: *const u8,
    input_len: usize,
    out: *mut u8,
) -> StatusClass;
/// Judge a URL-shaped tool ARGUMENT through the HOST-OWNED structural URL guard — the SSRF/URL-guard
/// chokepoint the host owns, so a plane never names the host's `net_guard` internals. The plane passes
/// the URL bytes `(url_ptr, url_len)` and whether private addressing is opted in for the target
/// (`allow_private`: `1` = yes, `0` = no); the host judges it STRUCTURALLY — the `http(s)` scheme
/// allowlist, the normalized host, and the cloud-metadata / obfuscated-encoding / internal-address
/// checks — and RESOLVES NO NAME (adding a lookup would change the answer). The host writes the
/// [`GuardVerdict`] (allow/deny + the refusal [`GuardClass`] + reason length) into `out` on
/// [`StatusClass::Ok`] and copies the offending host/url bytes into `reason_buf` (up to `reason_cap`,
/// the [`EgressFault`] cause-buffer pattern). [`StatusClass::Refused`] on a null URL pointer (`out`
/// untouched); [`StatusClass::Fault`] on a caught panic (`out` untouched).
pub type GuardUrlFn = extern "C-unwind" fn(
    host: HostCtx,
    url_ptr: *const u8,
    url_len: usize,
    allow_private: u8,
    out: *mut MaybeUninit<GuardVerdict>,
    reason_buf: *mut u8,
    reason_cap: usize,
) -> StatusClass;
/// Resolve INBOUND data-plane identity: run the configured auth chain + the one verdict resolution over
/// the caller's OWN wire credential (the [`IdentityQuery`]) and the live governance state, writing an
/// [`IdentityAdmitted`] on [`StatusClass::Ok`]. On an admit the out-param names an [`IdentityId`] handle
/// the plane consumes ONCE to recover the resolved (neutral principal, gov context); on a refusal the
/// [`IdentityOutcome`](super::pod::IdentityOutcome) names the specific reason and the handle is
/// [`IdentityId::NONE`]. The (sensitive) gov key never crosses as bytes — only the opaque handle does.
/// [`StatusClass::Refused`] on a null query (`out` untouched); [`StatusClass::Fault`] on a caught panic
/// (`out` untouched) — the plane fails closed (refuse to admit) on either.
pub type IdentityAdmitFn = extern "C-unwind" fn(
    host: HostCtx,
    query: *const IdentityQuery,
    out: *mut MaybeUninit<IdentityAdmitted>,
) -> StatusClass;
/// Fire the operator's REQUEST-ADMISSION hook gates over a neutral [`GateSubjectRef`] and return the
/// gate's verdict. The host re-selects the resolved gate set by `(plane_key, container)` (it owns the
/// `ResolvedPolicy` set the plane never holds), reconstructs the same `InvokeReq`-shaped facts the
/// in-process firing site builds, and runs the SAME async gate decision on a fresh runtime — so a plane
/// admits a request through its hook gates without naming `crate::hooks::gate::decide`. On a REJECT the
/// host writes the clamped 4xx status into [`GateVerdictOut`] and copies the hook's `message`/`hook`
/// strings into the caller's `msg_buf`/`hook_buf` (the `govern_admit_reason` copy-out, twice). `out` is
/// ALWAYS initialized up front to a fail-closed reject, so a null subject ([`StatusClass::Refused`]) or a
/// caught panic ([`StatusClass::Fault`]) both leave a refusal the plane reads as "the gate stopped it".
/// The async gate is driven on a fresh current-thread runtime, so this slot is invoked from a BLOCKING
/// thread (`spawn_blocking`) — calling it from a runtime worker would panic.
pub type GateDecideFn = extern "C-unwind" fn(
    host: HostCtx,
    subject: *const GateSubjectRef,
    msg_buf: *mut u8,
    msg_cap: usize,
    hook_buf: *mut u8,
    hook_cap: usize,
    out: *mut MaybeUninit<GateVerdictOut>,
) -> StatusClass;
/// Open a reserve-then-settle metering LEASE for a high-rate carrier (a live voice/stream session the
/// plane cannot price after the fact). The plane hands ALREADY-PRICED money in nanodollars — core
/// prices NOTHING: `reserve_nanos` is the coarse over-estimate the host debits against the grant NOW,
/// `flat_fee_nanos` a once-per-lease session fee (`0` = none), and `cap_nanos` the TRUE budget ceiling
/// exhaustion is later judged against. `cap_present == false` ⇒ uncapped (never exhausted);
/// `cap_present == true` with `cap_nanos == 0` ⇒ refuse-all. Per-lease amounts fit `u64` (a ~$18.4B
/// ceiling, far above any single session) and NO `u128` crosses the seam; the host widens to its
/// internal `CostAmount` (u128 nanodollars). Writes the opaque [`CostLeaseId`] into `out` on
/// [`StatusClass::Ok`]; [`StatusClass::Refused`] when the grant/budget denies the reserve (`out`
/// untouched ⇒ the plane reads [`CostLeaseId::NONE`] and fails closed); [`StatusClass::Fault`] on a
/// caught panic (`out` untouched).
pub type CostReserveFn = extern "C-unwind" fn(
    host: HostCtx,
    reserve_nanos: u64,
    flat_fee_nanos: u64,
    cap_nanos: u64,
    cap_present: bool,
    out: *mut MaybeUninit<CostLeaseId>,
) -> StatusClass;
/// Settle ONE exact money increment (nanodollars) against an open lease and read back whether the
/// lease's budget is now exhausted — so the plane can hard-close a live carrier mid-stream. The host
/// accrues ONLY the scalar `settle_nanos` toward the cap; the optional itemized `breakdown` crosses as
/// an OPAQUE byte suffix the host never parses (an audit tap only — `breakdown_len == 0` ⇒ none).
/// Writes [`CostSettleOut`] into `out` on [`StatusClass::Ok`]; [`StatusClass::Refused`] on an unknown /
/// already-closed lease (`out` untouched); [`StatusClass::Fault`] on a caught panic (`out` untouched)
/// — on either the plane fails closed and hard-closes the carrier.
pub type CostSettleFn = extern "C-unwind" fn(
    host: HostCtx,
    lease: CostLeaseId,
    settle_nanos: u64,
    breakdown_ptr: *const u8,
    breakdown_len: usize,
    out: *mut MaybeUninit<CostSettleOut>,
) -> StatusClass;

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
    // ── APPENDED (CLUSTER-3 egress): the byte-duplex PIPE read/write, shared by the raw-connection
    //    and subprocess egress tiers (both are byte channels keyed by a `PipeId`; the kind is a field
    //    on the open POD, not a separate slot). The host moves RAW BYTES; the plane frames on top.
    //    Trailing slots, append-only, same sized/versioned discipline (the cluster's MINOR bump). ──
    /// Read raw bytes from a governed byte-duplex pipe (raw-connection / subprocess).
    pub pipe_read: Option<PipeReadFn>,
    /// Write raw bytes to a governed byte-duplex pipe (raw-connection / subprocess).
    pub pipe_write: Option<PipeWriteFn>,
    // ── APPENDED (CLUSTER-3 egress, rich return surface): the FAILURE-side counterpart of the
    //    Ok-path `EgressHead` — the neutral failure detail (class + flattened cause + url) for the last
    //    failed `egress_open`, so a plane reproduces its own failover/refusal taxonomy byte for byte.
    //    Trailing slot, append-only, same sized/versioned discipline (the Stage-A MINOR bump). ───────
    /// Retrieve the last failed egress's neutral fault detail (class + cause bytes + url bytes).
    pub egress_fault: Option<EgressFaultFn>,
    // ── APPENDED (minor-9, the DURABLE journal seam): the store-backed journal family. A plane
    //    REGISTERS a stream and then addresses append/read/restore/seed/forget/compact/verify by the
    //    host-assigned `kind_id`. The host owns the ONE chain authority + the durable store; the plane
    //    owns only its record shape (carried as an opaque suffix in, reconstructed by its reframe out).
    //    Trailing slots, append-only, same sized/versioned discipline (the minor-9 bump). ────────────
    /// Register a durable journal stream (neutral kind/framing/digests_scope + a reframe callback).
    pub journal_register: Option<JournalRegisterFn>,
    /// Append one record to a registered stream's durable `String` scope (host mints the chain).
    pub journal_append_scoped: Option<JournalAppendScopedFn>,
    /// Read a registered stream's durable `String` scope window (cold bytes tier).
    pub journal_read_scoped: Option<JournalReadScopedFn>,
    /// Boot-rehydrate a registered stream from the durable store (writes neutral counts).
    pub journal_restore: Option<JournalRestoreFn>,
    /// Seed one scope's position from already-read stored bodies (writes a chain-break report).
    pub journal_seed: Option<JournalSeedFn>,
    /// Forget one scope's cached position (durable rows stay).
    pub journal_forget: Option<JournalForgetFn>,
    /// Drop a registered stream's durable rows older than a cutoff (writes the count removed).
    pub journal_compact: Option<JournalCompactFn>,
    /// Verify one scope's persisted chain (writes a verify report).
    pub journal_verify_scoped: Option<JournalVerifyScopedFn>,
    // ── APPENDED (minor-10, the SUBKEY-SIGN seam): the host-owned subkey signer (the a2a plane uses
    //    it to sign agent cards). The plane frames the RFC 7515 signing input and passes the bytes; the
    //    host derives the domain-separated signing subkey, signs, and returns the 64-byte Ed25519
    //    signature — so the signing SECRET is derived and held host-side and never crosses to the
    //    plane. Trailing slot, append-only, same sized/versioned discipline (the minor-10 bump). ──────
    /// Sign a caller-framed signing input with the host-owned signing subkey (writes 64 signature bytes).
    pub subkey_sign: Option<SubkeySignFn>,
    // ── APPENDED (minor-12, the URL-GUARD seam): the host-owned structural SSRF/URL guard for a
    //    URL-shaped tool argument. The host owns the scheme allowlist + host normalization + the
    //    cloud-metadata / obfuscated-encoding / internal-address checks (its `net_guard` internals a
    //    plane cannot name), judges STRUCTURALLY with no name resolution, and writes an allow/deny
    //    verdict + refusal class + the offending bytes back. Trailing slot, append-only, same
    //    sized/versioned discipline (the minor-12 bump). ──────────────────────────────────────────────
    /// Judge a URL-shaped tool argument through the host-owned structural URL guard (writes a verdict).
    pub guard_url: Option<GuardUrlFn>,
    // ── APPENDED (minor-17, the INBOUND-IDENTITY seam): the host runs the configured auth chain + the
    //    one verdict resolution over the caller's OWN wire credential and the live governance state, and
    //    hands back an opaque resolved-identity handle — so a plane admits an inbound session without
    //    naming `crate::auth` and the gov key material never crosses as bytes. Trailing slot,
    //    append-only, same sized/versioned discipline (the minor-17 bump). ─────────────────────────────
    /// Resolve inbound data-plane identity from the caller's own credential (writes an admitted handle).
    pub identity_admit: Option<IdentityAdmitFn>,
    // ── APPENDED (minor-18, the REQUEST-GATE seam): the host fires the operator's request-admission
    //    hook gates ([`crate::hooks::gate::decide`] in core) over a neutral subject and hands back the
    //    verdict — so an MCP/A2A plane body admits a request through its `tools.hooks:` / `agents.hooks:`
    //    gates without naming the gate engine and without holding the resolved `ResolvedPolicy` set.
    //    Trailing slot, append-only, same sized/versioned discipline (the minor-18 bump). ────────────────
    /// Fire the operator's request-admission hook gates over a neutral subject (writes a verdict).
    pub gate_decide: Option<GateDecideFn>,
    // ── APPENDED (minor-19, the METERING-LEASE seam): a high-rate carrier (a live voice/stream
    //    session) cannot be priced after the fact the way a one-shot `meter_charge` prices a
    //    completed call. These two slots open a host-owned reserve-then-settle `CostHold` and settle
    //    EXACT increments against it, reading back exhaustion so the plane hard-closes the carrier
    //    mid-stream — the plane hands already-priced nanodollars and never holds the grant/budget
    //    state. Trailing slots, append-only, same sized/versioned discipline (the minor-19 bump). ──────
    /// Open a reserve-then-settle metering lease over already-priced nanodollars (writes a lease id).
    pub cost_reserve: Option<CostReserveFn>,
    /// Settle one exact increment against an open lease and read back exhaustion (writes settle-out).
    pub cost_settle: Option<CostSettleFn>,
    // ── EXTENSION POINT (reserved) ──────────────────────────────────────────────────────────────
    // New inbound capabilities append as trailing `Option` slots BELOW this line and bump the
    // airlock MINOR — an append-only add, never a reshape of an existing slot.
}

// `PlaneHostVtable` holds only `AbiPreamble` scalars and `Option<extern "C-unwind" fn>` slots — all
// `Copy`, and function pointers are unconditionally `Send + Sync`. So the compiler ALREADY derives
// both auto-traits; a hand-written `unsafe impl Send/Sync` here would only suppress the compiler's
// re-check as this append-only struct grows a slot — the one moment we WANT the check to fire (a
// future non-auto slot must be caught, not silently blessed). We assert the auto-traits at compile
// time instead: if a later slot loses `Send`/`Sync`, this fails to build rather than lying.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<PlaneHostVtable>();
};

/// Why a peer-attested [`PlaneHostVtable`] was REFUSED. Fail-closed: any non-`Ok` outcome means the
/// table must not be read at all — never a partial read, never a slot call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VtableRefusal {
    /// The FROZEN airlock header did not check out (bad magic / incompatible major).
    Preamble(crate::PreambleError),
    /// The attested `size` does not even cover the frozen header (`abi` + `size` + `version`), so it
    /// cannot describe a `PlaneHostVtable` at all.
    SizeTooSmall {
        /// The size the peer attested.
        advertised: u32,
        /// The smallest size that could describe this table.
        minimum: u32,
    },
    /// The attested `size` is LARGER than this build's own `PlaneHostVtable`. Nothing on this side
    /// can verify a claim about bytes it has no definition for, and the cost of being wrong is a
    /// garbage fn-pointer this side CALLS — so the over-claim is refused rather than clamped.
    SizeTooLarge {
        /// The size the peer attested.
        advertised: u32,
        /// `size_of::<PlaneHostVtable>()` in this build.
        ours: u32,
    },
}

impl core::fmt::Display for VtableRefusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            VtableRefusal::Preamble(e) => {
                write!(f, "host vtable preamble refused: {e:?}")
            }
            VtableRefusal::SizeTooSmall {
                advertised,
                minimum,
            } => write!(
                f,
                "host vtable attested size {advertised} is below the {minimum}-byte frozen header, \
                 so it cannot describe a PlaneHostVtable"
            ),
            VtableRefusal::SizeTooLarge { advertised, ours } => write!(
                f,
                "host vtable attested size {advertised} exceeds this build's own \
                 PlaneHostVtable ({ours} bytes); this build has no definition for the extra bytes \
                 and will not call a slot it cannot describe — rebuild both sides against one \
                 busbar-plugin ABI minor"
            ),
        }
    }
}

impl std::error::Error for VtableRefusal {}

impl PlaneHostVtable {
    /// The smallest attested `size` that could describe this table: the FROZEN header alone
    /// (`abi` + `size` + `version`), before the first slot.
    pub const MIN_SIZE: u32 = (core::mem::size_of::<AbiPreamble>() + 8) as u32;

    /// CHECK a peer-supplied `*const PlaneHostVtable` before ANY slot is read, and return the number
    /// of bytes this side will honour — the missing half of the sized-struct discipline on the table
    /// itself. `size` was written at construction (`EMPTY`/`STUB`) and, until this existed, was never
    /// read by anything: the field the guard was written for was inert.
    ///
    /// Two refusals and one clamp:
    ///
    /// * the FROZEN preamble is checked FIRST (magic, then major) — before any other byte is
    ///   interpreted, exactly as `check_preamble` is used everywhere else;
    /// * an attested `size` below [`MIN_SIZE`](Self::MIN_SIZE) cannot describe this table at all;
    /// * an attested `size` LARGER than this build's own `size_of::<PlaneHostVtable>()` is refused.
    ///   A newer peer's trailing bytes are unverifiable from here, and unlike a POD field — where an
    ///   over-claim yields at worst bad data — a vtable slot is a fn-pointer this side then CALLS, so
    ///   the honest answer is to refuse rather than clamp. The forward path for a newer table is a
    ///   MINOR bump on BOTH sides (the hot lane's planes are version-locked to this crate; a
    ///   published cold-lane plugin never sees this table, so wire compatibility is untouched).
    ///
    /// A SHORTER attested size is NOT a refusal — that is the append-only rule working as intended
    /// (an older host simply granted fewer slots). It is the returned honoured size that makes it
    /// safe: read every slot through [`read_sized_field`](crate::read_sized_field) against it, so a
    /// trailing slot the peer never wrote reads as absent instead of as bytes past the end of its
    /// allocation.
    ///
    /// # Safety
    /// `vt` must be non-null and address at least [`MIN_SIZE`](Self::MIN_SIZE) live, initialized
    /// bytes laid out as the leading prefix of a `PlaneHostVtable`. It need not be aligned, and it
    /// need NOT be a whole table — that latitude is the entire reason this takes a raw pointer and
    /// never forms a `&PlaneHostVtable`.
    ///
    /// # Errors
    /// [`VtableRefusal`], whose `Display` is the operator diagnostic.
    pub unsafe fn check(vt: *const PlaneHostVtable) -> Result<u32, VtableRefusal> {
        // The frozen header is read WITHOUT forming a reference to the whole table: the peer's
        // allocation may be shorter than this build's struct, and `&PlaneHostVtable` would assert the
        // whole thing is there the instant it exists — the claim this check is here to avoid making.
        // SAFETY: the caller guarantees `vt` addresses at least `MIN_SIZE` live bytes shaped as the
        // leading prefix of the table, which covers `abi`, `size` and `version`; `addr_of!` computes
        // addresses only and `read_unaligned` assumes no alignment the peer did not promise.
        let (abi, advertised) = unsafe {
            (
                core::ptr::read_unaligned(core::ptr::addr_of!((*vt).abi)),
                core::ptr::read_unaligned(core::ptr::addr_of!((*vt).size)),
            )
        };
        crate::check_preamble(&abi).map_err(VtableRefusal::Preamble)?;
        if advertised < Self::MIN_SIZE {
            return Err(VtableRefusal::SizeTooSmall {
                advertised,
                minimum: Self::MIN_SIZE,
            });
        }
        let ours = core::mem::size_of::<PlaneHostVtable>() as u32;
        if advertised > ours {
            return Err(VtableRefusal::SizeTooLarge { advertised, ours });
        }
        Ok(advertised)
    }
}

/// Read ONE capability slot out of a peer-attested [`PlaneHostVtable`], yielding `None` unless the
/// table's own attested `size` proves the peer WROTE that slot. The vtable-shaped spelling of
/// [`read_sized_field`](crate::read_sized_field): `Some(fn)` = granted, `None` = absent (an older
/// peer that never had the slot, or a peer that left it null).
///
/// This is what makes a trailing slot safe. Without it, a build whose `PlaneHostVtable` has more
/// slots than the peer's forms the reference over the peer's SHORTER allocation and loads a trailing
/// slot from bytes past the end — a garbage fn-pointer it then calls.
///
/// `$size` must be the honoured size [`PlaneHostVtable::check`] returned, not the raw attested field.
///
/// # Safety
/// Expands inline, so its obligation is documented rather than compiler-enforced: `$ptr` must address
/// at least `$size` live, initialized bytes laid out as the leading prefix of a `PlaneHostVtable` —
/// which is exactly what a successful `check` establishes about its argument.
#[macro_export]
macro_rules! host_slot {
    ($ptr:expr, $size:expr, $slot:ident) => {{
        $crate::read_sized_field!($ptr, $size, $crate::hot::host::PlaneHostVtable, $slot).flatten()
    }};
}

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
        pipe_read: None,
        pipe_write: None,
        egress_fault: None,
        journal_register: None,
        journal_append_scoped: None,
        journal_read_scoped: None,
        journal_restore: None,
        journal_seed: None,
        journal_forget: None,
        journal_compact: None,
        journal_verify_scoped: None,
        subkey_sign: None,
        guard_url: None,
        identity_admit: None,
        gate_decide: None,
        cost_reserve: None,
        cost_settle: None,
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
        pipe_read: Some(stub::pipe_read),
        pipe_write: Some(stub::pipe_write),
        egress_fault: Some(stub::egress_fault),
        journal_register: Some(stub::journal_register),
        journal_append_scoped: Some(stub::journal_append_scoped),
        journal_read_scoped: Some(stub::journal_read_scoped),
        journal_restore: Some(stub::journal_restore),
        journal_seed: Some(stub::journal_seed),
        journal_forget: Some(stub::journal_forget),
        journal_compact: Some(stub::journal_compact),
        journal_verify_scoped: Some(stub::journal_verify_scoped),
        subkey_sign: Some(stub::subkey_sign),
        guard_url: Some(stub::guard_url),
        identity_admit: Some(stub::identity_admit),
        gate_decide: Some(stub::gate_decide),
        cost_reserve: Some(stub::cost_reserve),
        cost_settle: Some(stub::cost_settle),
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
    pub extern "C-unwind" fn metrics_emit(
        _host: HostCtx,
        _sample: *const MetricSample,
    ) -> StatusClass {
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
    pub extern "C-unwind" fn gate_scan(
        _host: HostCtx,
        _chunk: *const ContentChunk,
    ) -> GateDecision {
        unimplemented!("PlaneHost::gate_scan — stub")
    }
    /// Stub: see module docs.
    pub extern "C-unwind" fn pipe_read(
        _host: HostCtx,
        _pipe: PipeId,
        _buf: *mut u8,
        _buf_cap: usize,
        _out_written: *mut usize,
    ) -> StatusClass {
        unimplemented!("PlaneHost::pipe_read — stub")
    }
    /// Stub: see module docs.
    pub extern "C-unwind" fn pipe_write(
        _host: HostCtx,
        _pipe: PipeId,
        _buf: *const u8,
        _len: usize,
    ) -> StatusClass {
        unimplemented!("PlaneHost::pipe_write — stub")
    }
    /// Stub: see module docs.
    pub extern "C-unwind" fn egress_fault(
        _host: HostCtx,
        _out: *mut MaybeUninit<EgressFault>,
        _cause_buf: *mut u8,
        _cause_cap: usize,
        _url_buf: *mut u8,
        _url_cap: usize,
    ) -> StatusClass {
        unimplemented!("PlaneHost::egress_fault — stub")
    }
    /// Stub: see module docs.
    pub extern "C-unwind" fn journal_register(
        _host: HostCtx,
        _desc: *const JournalStreamDesc,
        _reframe: JournalReframeFn,
    ) -> StatusClass {
        unimplemented!("PlaneHost::journal_register — stub")
    }
    /// Stub: see module docs.
    pub extern "C-unwind" fn journal_append_scoped(
        _host: HostCtx,
        _kind_id: u32,
        _scope_ptr: *const u8,
        _scope_len: usize,
        _content_ptr: *const u8,
        _content_len: usize,
    ) -> Seq {
        unimplemented!("PlaneHost::journal_append_scoped — stub")
    }
    /// Stub: see module docs.
    pub extern "C-unwind" fn journal_read_scoped(
        _host: HostCtx,
        _kind_id: u32,
        _scope_ptr: *const u8,
        _scope_len: usize,
        _from_seq: u64,
        _limit: u64,
        _buf: *mut u8,
        _buf_cap: usize,
        _out_written: *mut usize,
    ) -> StatusClass {
        unimplemented!("PlaneHost::journal_read_scoped — stub")
    }
    /// Stub: see module docs.
    pub extern "C-unwind" fn journal_restore(
        _host: HostCtx,
        _kind_id: u32,
        _out: *mut MaybeUninit<RestoredHdr>,
    ) -> StatusClass {
        unimplemented!("PlaneHost::journal_restore — stub")
    }
    /// Stub: see module docs.
    pub extern "C-unwind" fn journal_seed(
        _host: HostCtx,
        _kind_id: u32,
        _scope_ptr: *const u8,
        _scope_len: usize,
        _bodies_ptr: *const u8,
        _bodies_len: usize,
        _out: *mut MaybeUninit<ChainBreakHdr>,
    ) -> StatusClass {
        unimplemented!("PlaneHost::journal_seed — stub")
    }
    /// Stub: see module docs.
    pub extern "C-unwind" fn journal_forget(
        _host: HostCtx,
        _kind_id: u32,
        _scope_ptr: *const u8,
        _scope_len: usize,
    ) -> StatusClass {
        unimplemented!("PlaneHost::journal_forget — stub")
    }
    /// Stub: see module docs.
    pub extern "C-unwind" fn journal_compact(
        _host: HostCtx,
        _kind_id: u32,
        _before: u64,
        _out_removed: *mut u64,
    ) -> StatusClass {
        unimplemented!("PlaneHost::journal_compact — stub")
    }
    /// Stub: see module docs.
    pub extern "C-unwind" fn journal_verify_scoped(
        _host: HostCtx,
        _kind_id: u32,
        _scope_ptr: *const u8,
        _scope_len: usize,
        _out: *mut MaybeUninit<VerifyChainHdr>,
    ) -> StatusClass {
        unimplemented!("PlaneHost::journal_verify_scoped — stub")
    }
    /// Stub: see module docs.
    pub extern "C-unwind" fn subkey_sign(
        _host: HostCtx,
        _input_ptr: *const u8,
        _input_len: usize,
        _out: *mut u8,
    ) -> StatusClass {
        unimplemented!("PlaneHost::subkey_sign — stub")
    }
    /// Stub: see module docs.
    pub extern "C-unwind" fn guard_url(
        _host: HostCtx,
        _url_ptr: *const u8,
        _url_len: usize,
        _allow_private: u8,
        _out: *mut MaybeUninit<GuardVerdict>,
        _reason_buf: *mut u8,
        _reason_cap: usize,
    ) -> StatusClass {
        unimplemented!("PlaneHost::guard_url — stub")
    }
    /// Stub: see module docs.
    pub extern "C-unwind" fn identity_admit(
        _host: HostCtx,
        _query: *const IdentityQuery,
        _out: *mut MaybeUninit<IdentityAdmitted>,
    ) -> StatusClass {
        unimplemented!("PlaneHost::identity_admit — stub")
    }
    /// Stub: see module docs.
    #[allow(clippy::too_many_arguments)]
    pub extern "C-unwind" fn gate_decide(
        _host: HostCtx,
        _subject: *const GateSubjectRef,
        _msg_buf: *mut u8,
        _msg_cap: usize,
        _hook_buf: *mut u8,
        _hook_cap: usize,
        _out: *mut MaybeUninit<GateVerdictOut>,
    ) -> StatusClass {
        unimplemented!("PlaneHost::gate_decide — stub")
    }
    /// Stub: see module docs.
    pub extern "C-unwind" fn cost_reserve(
        _host: HostCtx,
        _reserve_nanos: u64,
        _flat_fee_nanos: u64,
        _cap_nanos: u64,
        _cap_present: bool,
        _out: *mut MaybeUninit<CostLeaseId>,
    ) -> StatusClass {
        unimplemented!("PlaneHost::cost_reserve — stub")
    }
    /// Stub: see module docs.
    pub extern "C-unwind" fn cost_settle(
        _host: HostCtx,
        _lease: CostLeaseId,
        _settle_nanos: u64,
        _breakdown_ptr: *const u8,
        _breakdown_len: usize,
        _out: *mut MaybeUninit<CostSettleOut>,
    ) -> StatusClass {
        unimplemented!("PlaneHost::cost_settle — stub")
    }
}

#[cfg(test)]
#[path = "tests/host_tests.rs"]
mod tests;
