// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! [`PlaneHostVtable`] — the plane→core inbound capability seam, as a `#[repr(C)]` struct of
//! `extern "C-unwind"` fn-pointers.
//!
//! POD args by pointer; small results BY VALUE ([`Decision`], [`AdmissionId`], [`Seq`],
//! [`MeterOutcome`], a `u64` clock); large results into a caller `&mut MaybeUninit<Out>` written
//! INSIDE the callee's `catch_unwind` and marked init only on [`StatusClass::Ok`] (see
//! [`write_out`](crate::abi::write_out)). NO `Vec` return on any hot call.
//!
//! Each slot is `Option<…Fn>`: a `None` slot is an ABSENT (not-granted) capability — the in-process
//! `NotGranted` of the shipped `plane/host.rs`, rendered as a NULL vtable slot. The set is the NEUTRAL
//! capability taxonomy (protocol-noun-free): govern / meter / breaker / verify / egress / journal /
//! nested-dispatch / work-handle / trust (drift-quarantine + approval-redeem) / metrics / clock /
//! auth. There is deliberately NO `secret_resolve` — credentials resolve host-side by REF.
//!
//! ## The extension point
//!
//! A capability is added as trailing slots + a minor bump (never a reshape): append at the TAIL, bump
//! the airlock MINOR, re-seed the layout golden. Do not add a new capability to the hot set until a
//! real plane needs it. (The minor-19 metering-lease slots `cost_reserve`/`cost_settle` were retired
//! by KERNEL<>PLUGINS step 16: a plane never prices, #43/#71.)

use super::pod::{
    AdmissionId, AdmitRefusal, ApprovalQuery, AuthQuery, AuthResolved, CallerRef, ChainBreakHdr,
    ContentChunk, CounterpartyRef, Decision, EgressDesc, EgressFault, EgressId, EgressOpen, Facts,
    FramingDesc, GateDecision, GateSubjectRef, GateVerdictOut, GovRefusal, GuardVerdict,
    IdentityAdmitted, IdentityQuery, JournalQuery, JournalStreamDesc, Key, MeterOutcome,
    MetricSample, OpDesc, OpResult, PipeId, ReframeOut, RestoredHdr, Seq, Signal, StatusClass,
    TargetRef, TrustVerdict, Usage, VerifyChainHdr, VerifyDecision, VerifyLease, VerifyQuery,
    VerifyVerdict, WorkHandleDesc, WorkHandleId,
};
use crate::abi::AbiPreamble;
use core::mem::MaybeUninit;
use std::os::raw::c_void;

/// The host-context HANDLE threaded as the first arg of every host call. The plane never dereferences
/// it; it passes it back so the host recovers its own state.
///
/// ## Generation guard — ABI review A6 use-after-free hardening (DECISIONS #30 hot `repr(C)`, #40 opaque handles)
///
/// A6 found the previous `HostCtx = *mut c_void` carried NO generation: a plane that stashed the raw
/// pointer and called back AFTER the host slot the pointer addressed was reclaimed/reused would hand the
/// host a STALE pointer it then dereferenced — a use-after-free. `HostCtx` is now a `#[repr(C)]` opaque
/// HANDLE (#40) that carries, beside the pointer, a `generation` stamp the host mints per live dispatch
/// (see [`HostGeneration`]) and a `kind` tag. The host checks the generation (and kind) at slot entry
/// BEFORE dereferencing `ptr` (core's `recover`/`try_recover`), so a call carrying a stale generation is
/// REJECTED, never dereferenced.
///
/// The HOT plane/transport ABI is NEW in 1.6.0 (no 1.5.5 byte-identity constraint, nothing on the
/// money JSON path) and its planes are version-locked to this crate. The change was stamped as
/// [`ABI_MINOR`](crate::abi::ABI_MINOR) 21, but it RESIZED `BuildCtx.host_ctx` (8 → 16 bytes) and shifted
/// the fields after it, so it is carried under [`ABI_MAJOR`](crate::abi::ABI_MAJOR) 2 (item 410). The struct stays a
/// small `#[repr(C)]` `Copy` value passed by register/stack across the `extern "C-unwind"` boundary,
/// exactly as the bare pointer was.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct HostCtx {
    /// The host's own state pointer — opaque to the plane. The host recovers its state from it, but
    /// ONLY after the generation/kind check passes.
    ptr: *mut c_void,
    /// The generation stamp of the live dispatch that minted this handle. A host slot rejects the call
    /// when this generation is not currently live (a stale handle outliving its dispatch).
    generation: u32,
    /// A discriminant of what `ptr` addresses, so a handle minted for one host role cannot be replayed
    /// as another (a type-confusion guard). `0` is the reserved null/invalid tag.
    kind: u8,
}

impl HostCtx {
    /// The `kind` tag for a plane-host state handle (core's `HostState`). Non-zero, so the null handle
    /// (`kind == 0`) can never be mistaken for a live one.
    pub const KIND_PLANE_HOST: u8 = 1;

    /// The null/invalid handle: a null pointer, generation `0`, kind `0`. Never live — a host rejects
    /// it. Used only where a slot is known to ignore its host argument (bench fixtures, host-free
    /// reframes), never in a live plane call.
    pub const NULL: HostCtx = HostCtx {
        ptr: core::ptr::null_mut(),
        generation: 0,
        kind: 0,
    };

    /// Mint a handle over a host state `ptr`, its live-dispatch `generation` stamp, and a `kind` tag.
    #[must_use]
    pub const fn new(ptr: *mut c_void, generation: u32, kind: u8) -> Self {
        HostCtx {
            ptr,
            generation,
            kind,
        }
    }

    /// The opaque host state pointer. A host dereferences this ONLY after the generation/kind check.
    #[must_use]
    pub const fn ptr(self) -> *mut c_void {
        self.ptr
    }

    /// The live-dispatch generation stamp a host checks before dereferencing [`ptr`](Self::ptr).
    #[must_use]
    pub const fn generation(self) -> u32 {
        self.generation
    }

    /// The `kind` discriminant of what [`ptr`](Self::ptr) addresses.
    #[must_use]
    pub const fn kind(self) -> u8 {
        self.kind
    }

    /// Whether the underlying pointer is null (a [`NULL`](Self::NULL) or unset handle).
    #[must_use]
    pub fn is_null(self) -> bool {
        self.ptr.is_null()
    }
}

thread_local! {
    /// The generations of the dispatches currently LIVE on this thread (a small nesting stack). A
    /// [`HostCtx`] is honoured only while its generation is in this set; when a dispatch ends, its
    /// [`HostGeneration`] token drops and removes it — so a handle outliving its dispatch (the A6
    /// use-after-free) is no longer live and the host rejects it before any dereference.
    ///
    /// Thread-local by the SAME invariant core's `recover` already documents: a `HostCtx` is valid only
    /// on the dispatch frame that minted it and must not escape it (the sync dogfood AND the
    /// `spawn_blocking` legs each mint and call on one thread). A handle replayed on another thread is
    /// already a contract violation and is now additionally rejected there (its generation is not live).
    static LIVE_GENERATIONS: core::cell::RefCell<Vec<u32>> = const { core::cell::RefCell::new(Vec::new()) };
}

/// Process-monotonic source of dispatch generation stamps. A wrapping `u32` gives ~4.29e9 distinct
/// stamps before reuse; because a generation is removed the moment its token drops, a wrap can only ever
/// re-mint one that is no longer live — at worst aliasing a CONCURRENTLY-live dispatch, never
/// resurrecting an ended one.
static NEXT_GENERATION: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(1);

/// A RAII token that marks one dispatch's generation LIVE on the current thread while it is held and
/// removes it on drop — the host side of the [`HostCtx`] use-after-free guard (ABI review A6).
///
/// The host opens one per dispatch (beside the stack `HostState` whose address becomes the [`HostCtx`]
/// pointer), stamps its [`value`](Self::value) into every `HostCtx` it mints for that dispatch, and
/// holds it across every host call the plane makes. When it drops (the dispatch ends — normally or by
/// unwind), the generation stops being live, so the same handle used afterwards is refused.
#[derive(Debug)]
pub struct HostGeneration {
    generation: u32,
}

impl HostGeneration {
    /// Open a fresh generation and mark it live on the current thread.
    #[must_use]
    pub fn open() -> Self {
        let generation = NEXT_GENERATION.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        LIVE_GENERATIONS.with(|live| live.borrow_mut().push(generation));
        HostGeneration { generation }
    }

    /// The generation stamp to write into a [`HostCtx::new`] for this dispatch.
    #[must_use]
    pub fn value(&self) -> u32 {
        self.generation
    }

    /// Whether `generation` is currently live on THIS thread — the host's use-after-free check at slot
    /// entry. A stale handle (its dispatch ended, its token dropped) is not live and is rejected.
    #[must_use]
    pub fn is_live(generation: u32) -> bool {
        LIVE_GENERATIONS.with(|live| live.borrow().contains(&generation))
    }
}

impl Drop for HostGeneration {
    fn drop(&mut self) {
        LIVE_GENERATIONS.with(|live| {
            let mut live = live.borrow_mut();
            if let Some(pos) = live.iter().rposition(|&g| g == self.generation) {
                live.remove(pos);
            }
        });
    }
}

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
/// body a `u32` little-endian length + bytes) — the caller-driven rehydrate a plane's own record table
/// uses for its active entries. Writes a [`ChainBreakHdr`] (reporting a broken-but-resumed chain) on Ok.
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
/// held host-side and NEVER crosses to the plane. (A plane may use this to sign its own protocol-specific
/// documents, but the capability is named for what it does — sign a caller-framed input with a host
/// subkey — not for any one protocol's document.) [`StatusClass::Refused`] when the host holds no signing
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
/// Add `delta` to one series of a metric family the calling plane DECLARED (its declaration's
/// metric families; minor 25). `family_ptr`/`family_len` is the family's name; `values_ptr`/
/// `values_len` is one borrowed [`DeclStr`](super::decl::DeclStr) label VALUE per declared label key,
/// in the declared order — every range live for the call only. The host decodes the values for a
/// declared family only and renders exactly the declared name and keys.
///
/// [`StatusClass::Ok`] when added; [`StatusClass::Refused`] for a handle the host attributes to no
/// plane, a family the plane did not declare, a value count that is not the key count, a value that
/// is not bounded UTF-8, or a label set over the host's cardinality budget; [`StatusClass::Fault`]
/// on a caught panic.
pub type CounterAddFn = extern "C-unwind" fn(
    host: HostCtx,
    family_ptr: *const u8,
    family_len: usize,
    values_ptr: *const super::decl::DeclStr,
    values_len: usize,
    delta: u64,
) -> StatusClass;

// ── THE HOST SERVICES (minor 30; ARCHITECT SD-3 queue (6), DEC-SERVE G2). The contract ports a
//    codec reaches — `busbar_contract::codec::{fill_entropy, wall_clock_now,
//    usage_tap_fault_should_warn, max_translate_body_bytes}` — are process-wide `OnceLock`s the host
//    arms in ITS image. A plane dropped in as a `cdylib` carries its own copy of the contract, whose
//    ports nothing armed, so it read the failure path of every one. These four slots carry the
//    host's own services across the seam; the dropped-in door arms the plane image's ports over
//    them (`services::arm`) when the host opens the door. Process-wide, so `host` may be
//    `HostCtx::NULL`. ──
/// Fill `out_len` bytes at `out` from the host's entropy source (its CSPRNG). [`StatusClass::Ok`]
/// when every byte was written; [`StatusClass::Refused`] when the host has no entropy to give or
/// `out` is NULL with a non-zero length (the bytes are then unspecified); [`StatusClass::Fault`] on
/// a caught panic.
pub type EntropyFillFn =
    extern "C-unwind" fn(host: HostCtx, out: *mut u8, out_len: usize) -> StatusClass;
/// The host's wall clock in whole seconds since the Unix epoch; `0` when the host holds no clock
/// (the fail-closed reading, never a real second).
pub type WallClockFn = extern "C-unwind" fn(host: HostCtx) -> u64;
/// Count one usage-tap fault of `reason` for `protocol` (two borrowed UTF-8 ranges, live for the
/// call) and answer `true` only the FIRST time the host sees that pair, so the caller warns once.
/// `false` for a range that is not UTF-8 or a caught panic.
pub type TapFaultLatchFn = extern "C-unwind" fn(
    host: HostCtx,
    protocol_ptr: *const u8,
    protocol_len: usize,
    reason_ptr: *const u8,
    reason_len: usize,
) -> bool;
/// The operator's per-response translation cap in bytes, as the host holds it NOW (the operator may
/// reload it live).
pub type TranslateCapFn = extern "C-unwind" fn(host: HostCtx) -> u64;

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
    // ── APPENDED (minor-10, the SUBKEY-SIGN seam): the host-owned subkey signer (a plane may use it
    //    to sign its own protocol-specific documents). The plane frames the RFC 7515 signing input
    //    and passes the bytes; the host derives the domain-separated signing subkey, signs, and
    //    returns the 64-byte Ed25519 signature — so the signing SECRET is derived and held host-side
    //    and never crosses to the plane. Trailing slot, append-only, same sized/versioned discipline
    //    (the minor-10 bump). ──────────────────────────────────────────────────────────────────────
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
    // ── APPENDED (minor-25, the METRIC-FAMILY seam): a plane adds to a counter family it DECLARED
    //    (name, kind, label keys) and the host renders it — the only way a plane reaches a series in
    //    the reserved `busbar_` namespace, and only one the host lists. Trailing slot, append-only,
    //    same sized/versioned discipline (the minor-25 bump). ──────────────────────────────────────────
    /// Add to one series of a metric family the plane declared.
    pub counter_add: Option<CounterAddFn>,
    // ── APPENDED (minor-30, the HOST-SERVICES seam): the contract ports a codec reaches (entropy,
    //    wall clock, usage-tap fault latch, translate cap), so a dropped-in plane gets the services a
    //    linked one does. Trailing slots, append-only, same sized/versioned discipline. ─────────────
    /// Fill a buffer from the host's entropy source.
    pub entropy_fill: Option<EntropyFillFn>,
    /// Read the host's wall clock (whole Unix seconds).
    pub wall_clock: Option<WallClockFn>,
    /// Count a usage-tap fault and answer whether it is the first of its kind.
    pub tap_fault_latch: Option<TapFaultLatchFn>,
    /// Read the operator's live translation cap.
    pub translate_cap: Option<TranslateCapFn>,
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
    Preamble(crate::abi::PreambleError),
    /// The attested `size` does not even cover the frozen header (`abi` + `size` + `version`), so it
    /// cannot describe a `PlaneHostVtable` at all.
    SizeUnderHeader {
        /// The size the peer attested.
        advertised: u32,
        /// The smallest size that could describe this table.
        minimum: u32,
    },
    /// The attested `size` is LARGER than this build's own `PlaneHostVtable`. Nothing on this side
    /// can verify a claim about bytes it has no definition for, and the cost of being wrong is a
    /// garbage fn-pointer this side CALLS — so the over-claim is refused rather than clamped.
    SizeOverBuild {
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
            VtableRefusal::SizeUnderHeader {
                advertised,
                minimum,
            } => write!(
                f,
                "host vtable attested size {advertised} is below the {minimum}-byte frozen header, \
                 so it cannot describe a PlaneHostVtable"
            ),
            VtableRefusal::SizeOverBuild { advertised, ours } => write!(
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
    /// itself. `size` was written at construction (`EMPTY`/`SERVICES`) and, until this existed, was never
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
        crate::abi::check_preamble(&abi).map_err(VtableRefusal::Preamble)?;
        if advertised < Self::MIN_SIZE {
            return Err(VtableRefusal::SizeUnderHeader {
                advertised,
                minimum: Self::MIN_SIZE,
            });
        }
        let ours = core::mem::size_of::<PlaneHostVtable>() as u32;
        if advertised > ours {
            return Err(VtableRefusal::SizeOverBuild { advertised, ours });
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
        $crate::read_sized_field!($ptr, $size, $crate::abi::hot::host::PlaneHostVtable, $slot)
            .flatten()
    }};
}

impl PlaneHostVtable {
    /// An EMPTY vtable: the FROZEN preamble/size/version filled, EVERY capability `None` (absent /
    /// not-granted). This is the honest default a host starts from and grants into — the NULL-slot
    /// analogue of the shipped trait whose default grants nothing.
    pub const EMPTY: PlaneHostVtable = PlaneHostVtable {
        abi: AbiPreamble::CURRENT,
        size: core::mem::size_of::<PlaneHostVtable>() as u32,
        version: crate::abi::ABI_MINOR,
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
        counter_add: None,
        entropy_fill: None,
        wall_clock: None,
        tap_fault_latch: None,
        translate_cap: None,
    };

    /// [`EMPTY`](Self::EMPTY) plus the four HOST SERVICES, each served from THIS image's own armed
    /// contract ports ([`super::services`]). A host grants them by building its table over this
    /// (`..PlaneHostVtable::SERVICES`): the services are the contract's, so the host adds no code.
    pub const SERVICES: PlaneHostVtable = PlaneHostVtable {
        entropy_fill: Some(super::services::entropy_fill),
        wall_clock: Some(super::services::wall_clock),
        tap_fault_latch: Some(super::services::tap_fault_latch),
        translate_cap: Some(super::services::translate_cap),
        ..Self::EMPTY
    };
}

#[cfg(test)]
#[path = "tests/host_tests.rs"]
mod tests;
