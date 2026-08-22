// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `#[repr(C)]` PLAIN-OLD-DATA types crossing the hot seam, and the `#[repr(u8)]` enums they
//! carry. Every struct here LEADS with `size: u32` and `version: u16` (the sized-struct discipline)
//! and every variable field is a BORROWED `(ptr, len)` the caller keeps alive — no owned heap field
//! lives in any struct, so passing one by pointer moves no ownership and allocates nothing.
//!
//! APPEND-ONLY: new fields go at the TAIL, a receiver reads them only when `size` proves they were
//! written (see `read_sized_field!`). Reorder/resize/insert is a MAJOR airlock bump, caught by the
//! layout golden.

use std::os::raw::c_void;

/// The POD schema version stamped into each struct's `version` field at construction. Distinct from
/// the airlock [`ABI_MAJOR`](crate::ABI_MAJOR): this bumps additively as fields are appended.
pub const POD_VERSION: u16 = 2;

// ─────────────────────────────────────────────────────────────────────────────────────────────
// Handle-id newtypes — opaque host-side references a plane holds. `#[repr(transparent)]` over u64
// so they cross the seam as a bare register and cannot be confused for one another Rust-side.
// A niche-free `0` is reserved as "none/invalid" for every handle.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// Declare a `#[repr(transparent)]` u64 handle newtype with a reserved `NONE` (= 0) sentinel.
macro_rules! handle_newtype {
    ($(#[$m:meta])* $name:ident) => {
        $(#[$m])*
        #[repr(transparent)]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(pub u64);

        impl $name {
            /// The reserved "none / invalid / not-yet-assigned" handle.
            pub const NONE: $name = $name(0);
            /// True iff this is the reserved [`NONE`](Self::NONE) sentinel.
            #[inline]
            #[must_use]
            pub const fn is_none(self) -> bool {
                self.0 == 0
            }
        }
    };
}

handle_newtype!(
    /// A breaker/failover admission grant; the scope's Drop reclaims it (runs the real
    /// `Admission::drop`) when the work item's future ends or is dropped.
    AdmissionId
);
handle_newtype!(
    /// An open governed egress (HTTP request or raw byte channel) the host owns end to end.
    EgressId
);
handle_newtype!(
    /// A duplex BYTE channel a plane frames on top of (raw-connection / subprocess egress tier).
    PipeId
);
handle_newtype!(
    /// A durable unit-of-work handle parked at the durable scope; survives the process and is
    /// resumed by lookup, NOT reclaimed at future-drop.
    WorkHandleId
);
handle_newtype!(
    /// A single-flight leadership lease for counterparty verification (the plane holding it is the
    /// leader that fetches; followers wait on the host cache).
    VerifyLease
);
handle_newtype!(
    /// A monotonic journal sequence number returned by an append.
    Seq
);

// ─────────────────────────────────────────────────────────────────────────────────────────────
// Small `#[repr(u8)]` outcome/kind enums returned BY VALUE or embedded in POD structs.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// The neutral outcome class of a host call whose result is written into an out-param. `Ok` is the
/// ONLY value on which the caller may read the out-slot (init-only-on-Ok). Append-only: new classes
/// go at the tail with a fresh discriminant.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusClass {
    /// Success; the out-param (if any) is initialized and readable.
    Ok = 0,
    /// The operation was refused (policy/budget/validation); out-param NOT written.
    Refused = 1,
    /// The host-side handle is stale (its scope/session ended); out-param NOT written.
    Gone = 2,
    /// This build does not implement the requested capability; out-param NOT written.
    Unsupported = 3,
    /// An internal fault (a caught panic maps here); out-param NOT written.
    Fault = 4,
}

/// The governance admit decision, returned BY VALUE.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Refuse the work item.
    Deny = 0,
    /// Admit the work item.
    Admit = 1,
    /// Admit but throttle (soft-limit).
    Throttle = 2,
}

/// The result of a metering charge, returned BY VALUE.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeterOutcome {
    /// The usage was charged against the budget.
    Charged = 0,
    /// The charge was rejected (over budget / closed ledger).
    Rejected = 1,
}

/// The component a [`Usage`] scalar measures. Opaque to the engine, which meters the money scalar the
/// same regardless of component. Reserves the four shapes the shipping planes report.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsageComponent {
    /// Unit-of-inference component.
    Tokens = 0,
    /// Raw byte component (e.g. a metered byte channel).
    Bytes = 1,
    /// Discrete framed-message component.
    Frames = 2,
    /// Discrete backend-query component.
    Queries = 3,
}

/// The egress tier/kind — DATA, not a capability. The governance path (resolve-then-pin, SPKI, mTLS,
/// breaker, meter) is ONE regardless of kind; the kind only selects the channel shape.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressKind {
    /// A one-shot HTTP request over the host's pinned client.
    Http = 0,
    /// A governed raw duplex byte channel (host opens a pinned, SSRF-checked, metered socket).
    RawConn = 1,
    /// A governed child process, framed over stdio as a raw byte channel (NOT a separate capability).
    Subprocess = 2,
}

/// The wire framing the host reproduces for a journal stream's prelude, so stored bytes stay
/// byte-identical to every deployed store.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Framing {
    /// A length-prefixed record framing.
    LengthPrefixed = 0,
    /// A pipe-separated record framing.
    PipeSeparated = 1,
}

/// The counterparty-verification verdict class (host cache hit, or a single-flight leadership split).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyOutcome {
    /// A cached verdict is available (see the verdict payload).
    Hit = 0,
    /// This caller is the single-flight LEADER and must fetch, then `verify_store`.
    Lead = 1,
    /// This caller is a FOLLOWER and should await the leader's store.
    Follow = 2,
}

/// The stateful admission-time trust verdict for a counterparty (the neutral term for the remote a
/// plane dispatches to). The host owns the trust state (sightings / approvals / drift); this is the
/// answer to "may I dispatch to this counterparty NOW?". Append-only.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustVerdict {
    /// Trusted — dispatch may proceed.
    Allow = 0,
    /// Quarantined on drift — refuse until re-established.
    Quarantined = 1,
    /// Explicitly denied by policy.
    Denied = 2,
    /// Not yet approved — a one-time approval must be redeemed first.
    NeedsApproval = 3,
}

/// The decision of a streaming content-governance scan. `Continue` lets the chunk (and the stream)
/// proceed; `Block` halts it. The block REASON is retrieved by a follow-up cold read (kept out of the
/// hot POD so this stays a by-value `#[repr(u8)]`). Append-only.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateDecision {
    /// Content is permitted; continue the stream.
    Continue = 0,
    /// Content is refused; block the stream (reason via a follow-up read).
    Block = 1,
}

/// The FINE, dialect-normalized health class a plane reports for a FAILED guarded operation — the
/// refinement of the coarse [`StatusClass`] that lets the host reproduce the breaker's exact
/// disposition (transient cooldown vs. sticky hard-down vs. relay-verbatim) instead of a lossy
/// 5-way guess. Carried in [`Signal::fault_class`]; only meaningful when the coarse class is a
/// failure (`Gone`/`Unsupported`/`Fault`). Names are protocol-NEUTRAL (no protocol/role noun).
/// Append-only: new classes go at the tail with a fresh discriminant, and `Unspecified` (= 0) is the
/// forward-compat default a sender that predates this field leaves, so the host falls back to the
/// coarse mapping rather than misreading it.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultClass {
    /// No fine classification supplied — the host falls back to the coarse [`StatusClass`] mapping.
    Unspecified = 0,
    /// Rate-limited / slow-down — transient; honors a [`Signal::retry_after_secs`] cooldown floor.
    RateLimit = 1,
    /// Upstream reported itself overloaded — transient.
    Overloaded = 2,
    /// Upstream internal error (5xx-shaped) — transient.
    UpstreamError = 3,
    /// The call timed out — transient.
    Timeout = 4,
    /// A network-level failure reaching the upstream — transient.
    Network = 5,
    /// An authentication/authorization rejection — sticky hard-down (credential invalid).
    Auth = 6,
    /// A billing / balance rejection — sticky hard-down (account issue).
    Billing = 7,
    /// A caller-side request error (4xx-shaped other than auth) — relay verbatim, penalize nothing.
    ClientError = 8,
    /// The request exceeded the target's context/size window — the target is healthy; fail over
    /// WITHOUT penalizing it.
    ContextLength = 9,
}

/// WHY an admit was REFUSED — the fine reason a refused acquire carries out through the host so a
/// refusal keeps its specific meaning instead of collapsing to a bare [`AdmissionId::NONE`]. It is the
/// admit-side counterpart of [`FaultClass`] (the settle-side fine class): where `FaultClass` refines a
/// FAILURE signal, this refines a REFUSAL. Names are protocol-NEUTRAL (a health/availability taxonomy,
/// no protocol/role noun). Append-only: new reasons at the tail with a fresh discriminant, and
/// [`Unspecified`](Self::Unspecified) (= 0) is the forward-compat default a caller reads when the host
/// wrote no fine reason (so it falls back to the coarse "refused" meaning rather than misreading it).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unavailability {
    /// No fine reason supplied — a bare refusal, no self-recovery estimate.
    Unspecified = 0,
    /// The circuit is open (or inside a pending cooldown); recovery time is known — see
    /// [`AdmitRefusal::retry_after_secs`].
    Open = 1,
    /// Lost the single-flight half-open probe race to a peer; the peer's probe resolves it within one
    /// request (a "next tick" transient).
    ProbeInFlight = 2,
    /// Administratively down — does not self-recover until a configuration change.
    Dead = 3,
    /// The lifetime request budget is spent — does not self-recover.
    Budget = 4,
    /// All concurrency permits are held; the recovery hint is an ESTIMATE, not exact.
    AtCapacity = 5,
    /// Shed by inbound backpressure before selection.
    Shedding = 6,
    /// A selection over a set found NOTHING admissible (every interchangeable member refused) — the
    /// set-level refusal a single-cell reason cannot express.
    NoneAdmissible = 7,
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// The POD structs. Each leads with `size`/`version`; the shared preamble macro keeps that uniform.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// A `#[repr(C)]` governance fact bundle passed to `govern_admit` BY POINTER. Sized/versioned
/// preamble, then scalars, then a BORROWED pool-name `(ptr, len)`.
///
/// # Safety / discipline
/// `pool_name_ptr`/`pool_name_len` MUST describe a live, initialized byte range for any call that
/// receives `&Facts`. Construct via [`Facts::new`], which ties the borrow to a [`FactsGuard`].
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Facts {
    /// `size_of::<Facts>()` at construction — the receiver rejects a smaller advertised size.
    pub size: u32,
    /// POD schema version (see [`POD_VERSION`]).
    pub version: u16,
    /// Explicit preamble tail padding, kept in the layout so the struct is fully defined.
    pub _reserved: u16,
    /// Units of work this item wants to admit.
    pub tokens: u64,
    /// Budget remaining for the tenant, same unit as `tokens`.
    pub budget_remaining: u64,
    /// Opaque tenant identifier.
    pub tenant_id: u64,
    /// Request priority (higher = more important).
    pub priority: u32,
    /// Bitflags (bit 0 = "trusted caller", etc.).
    pub flags: u32,
    /// Borrowed pointer to the variable pool-name bytes (NOT owned by `Facts`).
    pub pool_name_ptr: *const u8,
    /// Length of the borrowed pool-name range.
    pub pool_name_len: usize,
}

impl Facts {
    /// Build a `Facts` borrowing `pool_name` for `'a`; returns a [`FactsGuard`] so the borrow can't
    /// outlive the name. No allocation, no copy.
    #[allow(clippy::new_ret_no_self)]
    pub fn new<'a>(
        tokens: u64,
        budget_remaining: u64,
        tenant_id: u64,
        priority: u32,
        flags: u32,
        pool_name: &'a [u8],
    ) -> FactsGuard<'a> {
        FactsGuard {
            facts: Facts {
                size: core::mem::size_of::<Facts>() as u32,
                version: POD_VERSION,
                _reserved: 0,
                tokens,
                budget_remaining,
                tenant_id,
                priority,
                flags,
                pool_name_ptr: pool_name.as_ptr(),
                pool_name_len: pool_name.len(),
            },
            _borrow: core::marker::PhantomData,
        }
    }
}

/// A [`Facts`] tied to the lifetime of its borrowed pool-name so the borrow can't dangle.
pub struct FactsGuard<'a> {
    facts: Facts,
    _borrow: core::marker::PhantomData<&'a [u8]>,
}

impl core::ops::Deref for FactsGuard<'_> {
    type Target = Facts;
    #[inline]
    fn deref(&self) -> &Facts {
        &self.facts
    }
}

/// A metering charge: an opaque-component money scalar. `reserve/settle` (a `CostHold`) is
/// DELIBERATELY NOT here and NOT on the hot vtable — it is an append-only EXTENSION POINT for a
/// future high-rate carrier (see [`host`](super::host)).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Usage {
    /// `size_of::<Usage>()` at construction.
    pub size: u32,
    /// POD schema version.
    pub version: u16,
    /// The component `amount` measures.
    pub component: UsageComponent,
    /// Preamble tail padding.
    pub _reserved: u8,
    /// The quantity consumed, in units of `component`.
    pub amount: u64,
    /// Per-unit cost in micro-currency (the neutral money scalar).
    pub unit_cost_micros: u64,
    /// The admission grant this consumption is charged against.
    pub admission: AdmissionId,
}

/// A routing / circuit / verification key: a borrowed opaque key material `(ptr, len)` plus a scope.
///
/// # Safety / discipline
/// `key_ptr`/`key_len` MUST describe a live, initialized byte range for any call that receives it.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Key {
    /// `size_of::<Key>()` at construction.
    pub size: u32,
    /// POD schema version.
    pub version: u16,
    /// Preamble tail padding.
    pub _reserved: u16,
    /// The scope this key is interpreted within (host-defined namespace id).
    pub scope: u32,
    /// Preamble/alignment padding before the borrowed range.
    pub _reserved2: u32,
    /// Borrowed pointer to the opaque key bytes (NOT owned).
    pub key_ptr: *const u8,
    /// Length of the borrowed key range.
    pub key_len: usize,
}

/// The post-call signal a plane reports back to the breaker at `breaker_settle`: the outcome class
/// plus cheap health scalars the breaker folds.
///
/// The tail block (`fault_class` … `provider_signal_len`) is an APPEND-ONLY minor-`1` extension: it
/// refines the coarse [`class`](Self::class) into the FINE breaker disposition the host reproduces
/// (transient-upstream cooldown vs. sticky hard-down vs. relay-verbatim), the upstream `Retry-After`
/// cooldown floor, and a borrowed provider error-code the reason lines record. A sender that predates
/// this block advertises the shorter `size`; the host reads the tail only when `size` proves it was
/// written (the sized-struct guard) and otherwise falls back to the coarse mapping — so the addition
/// is a MINOR airlock bump, never a MAJOR.
///
/// # Safety / discipline
/// `provider_signal_ptr`/`provider_signal_len`, when non-null/non-zero, MUST describe a live,
/// initialized byte range (a provider error CODE, NOT owned by `Signal`) for any call that receives
/// `&Signal`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Signal {
    /// `size_of::<Signal>()` at construction.
    pub size: u32,
    /// POD schema version.
    pub version: u16,
    /// The outcome class observed for the guarded operation.
    pub class: StatusClass,
    /// Preamble tail padding.
    pub _reserved: u8,
    /// Observed latency in nanoseconds.
    pub latency_nanos: u64,
    /// Bytes transferred (0 if not applicable).
    pub bytes: u64,
    /// (minor-1) The FINE breaker class refining a FAILURE `class`. [`FaultClass::Unspecified`] (the
    /// zero default) means "no refinement — use the coarse mapping".
    pub fault_class: FaultClass,
    /// (minor-1) Bit 0: a `Retry-After` floor is present in [`retry_after_secs`](Self::retry_after_secs)
    /// (distinguishes "no header" from a header value of `0`). Other bits reserved (must be 0).
    pub fault_flags: u8,
    /// (minor-1) Alignment padding before the scalars.
    pub _reserved2: u16,
    /// (minor-1) Alignment padding before the 8-byte-aligned tail.
    pub _reserved3: u32,
    /// (minor-1) The upstream `Retry-After` cooldown floor in whole seconds; read only when bit 0 of
    /// [`fault_flags`](Self::fault_flags) is set.
    pub retry_after_secs: u64,
    /// (minor-1) Borrowed provider error-CODE bytes recorded into the transient/hard-down reason
    /// (NOT owned; null/len 0 = none). NEVER a secret.
    pub provider_signal_ptr: *const u8,
    /// (minor-1) Length of the borrowed provider-code range.
    pub provider_signal_len: usize,
}

/// The out-param a REFUSAL-fidelity acquire writes when it refuses — the fine [`Unavailability`] reason
/// plus its recovery hint — so a refused acquire keeps its specific meaning across the host boundary
/// instead of collapsing to a bare [`AdmissionId::NONE`]. The host ALWAYS initializes it (so the slot
/// is never left uninitialized): a live [`AdmissionId`] return leaves it at
/// [`Unavailability::Unspecified`], and a refusal writes the specific reason. The caller reads it
/// exactly when the returned id [`is_none`](AdmissionId::is_none).
///
/// APPEND-ONLY minor extension alongside the [`Unavailability`] enum: a sender that predates it advertises
/// the shorter table (its acquire has no such out-param), and a reader reads this only through a slot
/// that exists in the bumped-minor table — a MINOR airlock bump, never a MAJOR.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct AdmitRefusal {
    /// `size_of::<AdmitRefusal>()` when the host writes it.
    pub size: u32,
    /// POD schema version.
    pub version: u16,
    /// The fine refusal reason ([`Unavailability::Unspecified`] if the host wrote no fine reason).
    pub reason: Unavailability,
    /// Preamble tail padding.
    pub _reserved: u8,
    /// The known/estimated recovery floor in whole seconds (`0` when there is no basis to estimate,
    /// e.g. an administratively-down or budget-exhausted refusal that does not self-recover).
    pub retry_after_secs: u64,
}

/// The descriptor for opening a governed egress. Carries a credential-REF (which pool/hop/exchange),
/// NEVER plaintext — the host mints and injects the credential app-layer. Also carries the mTLS
/// client-identity REF for pinned client auth.
///
/// # Safety / discipline
/// `target_ptr`/`target_len` MUST describe a live, initialized byte range (URL / address / program).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct EgressDesc {
    /// `size_of::<EgressDesc>()` at construction.
    pub size: u32,
    /// POD schema version.
    pub version: u16,
    /// The egress tier/kind (data, not a capability).
    pub kind: EgressKind,
    /// Preamble tail padding.
    pub _reserved: u8,
    /// The host-defined allowlist scope this egress is checked against.
    pub allowlist_scope: u32,
    /// Alignment padding before the borrowed range.
    pub _reserved2: u32,
    /// Borrowed target bytes: an HTTP URL, a raw address, or a subprocess program+argv blob.
    pub target_ptr: *const u8,
    /// Length of the borrowed target range.
    pub target_len: usize,
    /// A REF to the mTLS client identity the host presents (0 = none). Never a key.
    pub client_identity_ref: u64,
    /// A REF to the credential the host mints and injects (0 = none). NEVER plaintext.
    pub credential_ref: u64,
}

/// What the host observed at connect time (post-connect, pre-body), handed back with an [`EgressOpen`].
///
/// # Safety / discipline
/// `observed_spki_ptr`/`observed_spki_len`, when non-null, borrow host-owned bytes valid for the call.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct EgressHead {
    /// `size_of::<EgressHead>()` at construction.
    pub size: u32,
    /// POD schema version.
    pub version: u16,
    /// The observed status/response code (0 for a raw channel).
    pub status_code: u16,
    /// Borrowed pointer to the observed peer SPKI bytes (host-owned; NOT owned by the plane).
    pub observed_spki_ptr: *const u8,
    /// Length of the observed SPKI range.
    pub observed_spki_len: usize,
}

/// The out-param an `egress_open` writes on `StatusClass::Ok`: the egress id, an optional duplex
/// [`PipeId`] (for `RawConn`/`Subprocess`), and the observed [`EgressHead`].
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct EgressOpen {
    /// `size_of::<EgressOpen>()` when the host writes it.
    pub size: u32,
    /// POD schema version.
    pub version: u16,
    /// Preamble tail padding.
    pub _reserved: u16,
    /// The opened egress handle.
    pub id: EgressId,
    /// The duplex byte-channel handle for raw/subprocess kinds ([`PipeId::NONE`] for HTTP).
    pub pipe: PipeId,
    /// What the host observed at connect.
    pub head: EgressHead,
}

/// A subprocess command descriptor (used when [`EgressKind::Subprocess`]). Borrowed program +
/// packed-argv bytes; the host owns lifecycle and the COMMAND-ALLOWLIST.
///
/// # Safety / discipline
/// Both borrowed ranges MUST be live for the call.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CmdDesc {
    /// `size_of::<CmdDesc>()` at construction.
    pub size: u32,
    /// POD schema version.
    pub version: u16,
    /// Number of argv entries packed in `argv_ptr`.
    pub argv_count: u16,
    /// Borrowed program-path bytes (NOT owned).
    pub program_ptr: *const u8,
    /// Length of the program-path range.
    pub program_len: usize,
    /// Borrowed packed-argv bytes (length-prefixed entries; NOT owned).
    pub argv_ptr: *const u8,
    /// Length of the packed-argv range.
    pub argv_len: usize,
}

/// A per-stream journal framing descriptor: the host re-frames the prelude in this framing and joins
/// the plane's content suffix, so stored bytes are byte-identical to every deployed store.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FramingDesc {
    /// `size_of::<FramingDesc>()` at construction.
    pub size: u32,
    /// POD schema version.
    pub version: u16,
    /// The prelude framing this stream uses.
    pub framing: Framing,
    /// `1` if the scope field participates in the digest, `0` if it does not (some streams omit it).
    pub digests_scope: u8,
}

/// A journal read query (cold/bytes tier).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct JournalQuery {
    /// `size_of::<JournalQuery>()` at construction.
    pub size: u32,
    /// POD schema version.
    pub version: u16,
    /// Preamble tail padding.
    pub _reserved: u16,
    /// The journal scope to read.
    pub scope: u32,
    /// Preamble/alignment padding.
    pub _reserved2: u32,
    /// The first sequence number to return (inclusive).
    pub from_seq: u64,
    /// The maximum number of rows to return.
    pub limit: u64,
}

/// A depth-bounded nested-dispatch descriptor: the host routes an opaque sub-request through the SAME
/// router, never knowing what it is. Carries a depth bound and a correlation id so a re-entrant call
/// reuses the originating budget/audit correlation (RR7) instead of double-counting.
///
/// # Safety / discipline
/// `work_ptr`/`work_len` MUST describe a live, initialized byte range for the call.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct OpDesc {
    /// `size_of::<OpDesc>()` at construction.
    pub size: u32,
    /// POD schema version.
    pub version: u16,
    /// Preamble tail padding.
    pub _reserved: u16,
    /// The remaining depth budget; the host refuses at zero (bounds re-entrancy).
    pub depth: u32,
    /// Preamble/alignment padding.
    pub _reserved2: u32,
    /// The originating request's correlation id (reused for budget/audit; 0 if top-level).
    pub correlation_id: u64,
    /// Borrowed opaque sub-request bytes (NOT owned).
    pub work_ptr: *const u8,
    /// Length of the borrowed sub-request range.
    pub work_len: usize,
}

/// The out-param a `nested_dispatch` writes on `StatusClass::Ok`. The result BODY (variable bytes)
/// is fetched separately (bytes tier); this POD header carries the outcome class and the body length.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct OpResult {
    /// `size_of::<OpResult>()` when the host writes it.
    pub size: u32,
    /// POD schema version.
    pub version: u16,
    /// The sub-operation outcome class.
    pub class: StatusClass,
    /// Preamble tail padding.
    pub _reserved: u8,
    /// The length of the result body the host holds for retrieval (0 if none).
    pub body_len: u64,
    /// A journal sequence correlating the sub-operation (see [`Seq`]).
    pub seq: Seq,
}

/// A durable work-handle descriptor: the durable-scope primitive. Parking one at (e.g.) a 202 lets a
/// plane resume later by lookup; it survives the process and is NOT reclaimed at future-drop.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct WorkHandleDesc {
    /// `size_of::<WorkHandleDesc>()` at construction.
    pub size: u32,
    /// POD schema version.
    pub version: u16,
    /// Preamble tail padding.
    pub _reserved: u16,
    /// The durable scope namespace.
    pub scope: u32,
    /// Time-to-live in seconds before the durable handle expires.
    pub ttl_secs: u32,
    /// A correlation id for the durable unit of work.
    pub correlation_id: u64,
}

/// The out-param a `verify_lookup` writes on `StatusClass::Ok`: the outcome, a leadership lease (when
/// `Lead`), and a borrowed cached-digest range (when `Hit`, host-owned).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct VerifyVerdict {
    /// `size_of::<VerifyVerdict>()` when the host writes it.
    pub size: u32,
    /// POD schema version.
    pub version: u16,
    /// The verdict class (Hit / Lead / Follow).
    pub outcome: VerifyOutcome,
    /// Preamble tail padding.
    pub _reserved: u8,
    /// The single-flight leadership lease ([`VerifyLease::NONE`] unless `outcome == Lead`).
    pub lease: VerifyLease,
    /// Borrowed cached-digest bytes (host-owned; valid only for `Hit`, else null/len 0).
    pub digest_ptr: *const u8,
    /// Length of the cached-digest range.
    pub digest_len: usize,
}

/// A credential-resolution query: resolve a credential REF to a host-side lease/expiry, NEVER to
/// plaintext. The plane names a ref and audience; the host owns the mint/exchange.
///
/// # Safety / discipline
/// `audience_ptr`/`audience_len`, when non-null, borrow live bytes for the call.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct AuthQuery {
    /// `size_of::<AuthQuery>()` at construction.
    pub size: u32,
    /// POD schema version.
    pub version: u16,
    /// Preamble tail padding.
    pub _reserved: u16,
    /// The credential reference to resolve (0 = none).
    pub credential_ref: u64,
    /// Borrowed audience bytes (NOT owned; null/len 0 if not scoped to an audience).
    pub audience_ptr: *const u8,
    /// Length of the audience range.
    pub audience_len: usize,
}

/// The out-param an `auth_resolve` writes on `StatusClass::Ok`: a host-side credential REF the plane
/// may pass to `egress_open`, plus its expiry. NEVER plaintext.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct AuthResolved {
    /// `size_of::<AuthResolved>()` when the host writes it.
    pub size: u32,
    /// POD schema version.
    pub version: u16,
    /// Preamble tail padding.
    pub _reserved: u16,
    /// Preamble/alignment padding.
    pub _reserved2: u32,
    /// The resolved host-side credential reference (opaque; NEVER a secret).
    pub resolved_ref: u64,
    /// Unix-seconds expiry of the resolved reference.
    pub expires_unix: u64,
}

/// A metric sample a plane emits (label passthrough; the host interprets no label).
///
/// # Safety / discipline
/// Both borrowed ranges MUST be live for the call.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MetricSample {
    /// `size_of::<MetricSample>()` at construction.
    pub size: u32,
    /// POD schema version.
    pub version: u16,
    /// Preamble tail padding.
    pub _reserved: u16,
    /// Preamble/alignment padding.
    pub _reserved2: u32,
    /// The IEEE-754 bit pattern of the sample value (POD; no float in the wire type).
    pub value_bits: u64,
    /// Borrowed metric-name bytes (NOT owned).
    pub name_ptr: *const u8,
    /// Length of the metric-name range.
    pub name_len: usize,
    /// Borrowed packed-labels bytes (NOT owned; host does not interpret them).
    pub labels_ptr: *const u8,
    /// Length of the packed-labels range.
    pub labels_len: usize,
}

/// A reference to a COUNTERPARTY — the neutral term for the remote a plane dispatches to. Borrowed
/// opaque identity bytes plus a scope; the host resolves it against its trust state.
///
/// # Safety / discipline
/// `ref_ptr`/`ref_len`, when non-null, borrow live bytes for the call.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CounterpartyRef {
    /// `size_of::<CounterpartyRef>()` at construction.
    pub size: u32,
    /// POD schema version.
    pub version: u16,
    /// Preamble tail padding.
    pub _reserved: u16,
    /// The scope this counterparty identity is interpreted within.
    pub scope: u32,
    /// Preamble/alignment padding before the borrowed range.
    pub _reserved2: u32,
    /// Borrowed opaque counterparty-identity bytes (NOT owned).
    pub ref_ptr: *const u8,
    /// Length of the borrowed identity range.
    pub ref_len: usize,
}

/// A reference to a CALLER — the entitled principal (the host owns the caller's scopes/keys). Borrowed
/// opaque identity bytes plus a scope.
///
/// # Safety / discipline
/// `ref_ptr`/`ref_len`, when non-null, borrow live bytes for the call.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CallerRef {
    /// `size_of::<CallerRef>()` at construction.
    pub size: u32,
    /// POD schema version.
    pub version: u16,
    /// Preamble tail padding.
    pub _reserved: u16,
    /// The scope this caller identity is interpreted within.
    pub scope: u32,
    /// Preamble/alignment padding before the borrowed range.
    pub _reserved2: u32,
    /// Borrowed opaque caller-identity bytes (NOT owned).
    pub ref_ptr: *const u8,
    /// Length of the borrowed identity range.
    pub ref_len: usize,
}

/// A reference to a dispatch TARGET — an entry in a plane's catalogue of things a caller may use.
/// Borrowed opaque target bytes plus a scope kind.
///
/// # Safety / discipline
/// `ref_ptr`/`ref_len`, when non-null, borrow live bytes for the call.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TargetRef {
    /// `size_of::<TargetRef>()` at construction.
    pub size: u32,
    /// POD schema version.
    pub version: u16,
    /// Preamble tail padding.
    pub _reserved: u16,
    /// The scope KIND this target belongs to (host-defined namespace id).
    pub scope_kind: u32,
    /// Preamble/alignment padding before the borrowed range.
    pub _reserved2: u32,
    /// Borrowed opaque target bytes (NOT owned).
    pub ref_ptr: *const u8,
    /// Length of the borrowed target range.
    pub ref_len: usize,
}

/// One chunk of streaming content fed to the content-governance gate. The gate scans incrementally,
/// so a plane feeds chunks in order and gets a [`GateDecision`] per chunk; `is_final` marks the last.
///
/// # Safety / discipline
/// `data_ptr`/`data_len`, when non-null, borrow live bytes for the call.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ContentChunk {
    /// `size_of::<ContentChunk>()` at construction.
    pub size: u32,
    /// POD schema version.
    pub version: u16,
    /// `1` if this is the final chunk of the content stream, else `0`.
    pub is_final: u8,
    /// Preamble tail padding.
    pub _reserved: u8,
    /// The host-side scan-session id correlating chunks of one stream (0 for a single-shot scan).
    pub session_id: u64,
    /// The byte offset of this chunk within the overall content stream.
    pub offset: u64,
    /// Borrowed content bytes for this chunk (NOT owned).
    pub data_ptr: *const u8,
    /// Length of the borrowed content range.
    pub data_len: usize,
}

/// The opaque `*mut c_void` state handle a plane owns and hands the host, wrapped so the compiler
/// treats it as `Send + Sync` (a plane may hold it across `.await` and worker threads). Paired with
/// its own [`free`](Self::free) fn, which must NEVER panic (wrap the body in `catch_unwind`).
///
/// This lives in `pod` because both a [`PlaneDecl`](super::decl::PlaneDecl) build result and any
/// host-side slot store it.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct OpaqueState {
    /// The plane-allocated state pointer; the host stores it and NEVER downcasts it.
    pub ptr: *mut c_void,
    /// The plane's free function, run by the host on config swap. MUST NOT panic (catch internally).
    pub free: Option<extern "C-unwind" fn(*mut c_void)>,
}

// SAFETY: an OpaqueState is a plane-owned handle the plane guarantees is safe to move/share across
// threads (the plane synchronizes its own interior). The host never dereferences `ptr`; it only
// stores it and later calls `free`. This is the design's `Send + Sync` opaque-handle requirement.
unsafe impl Send for OpaqueState {}
// SAFETY: see the `Send` impl above.
unsafe impl Sync for OpaqueState {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handles_reserve_zero_as_none() {
        assert!(AdmissionId::NONE.is_none());
        assert!(EgressId::NONE.is_none());
        assert!(PipeId::NONE.is_none());
        assert!(WorkHandleId::NONE.is_none());
        assert!(VerifyLease::NONE.is_none());
        assert!(Seq::NONE.is_none());
        assert!(!AdmissionId(1).is_none());
    }

    #[test]
    fn every_pod_leads_with_size_version() {
        // The sized-struct discipline: `size` at offset 0, `version` at offset 4, on every struct.
        macro_rules! assert_preamble {
            ($t:ty) => {{
                assert_eq!(core::mem::offset_of!($t, size), 0, "size@0 on {}", stringify!($t));
                assert_eq!(
                    core::mem::offset_of!($t, version),
                    4,
                    "version@4 on {}",
                    stringify!($t)
                );
            }};
        }
        assert_preamble!(Facts);
        assert_preamble!(Usage);
        assert_preamble!(Key);
        assert_preamble!(Signal);
        assert_preamble!(AdmitRefusal);
        assert_preamble!(EgressDesc);
        assert_preamble!(EgressHead);
        assert_preamble!(EgressOpen);
        assert_preamble!(CmdDesc);
        assert_preamble!(FramingDesc);
        assert_preamble!(JournalQuery);
        assert_preamble!(OpDesc);
        assert_preamble!(OpResult);
        assert_preamble!(WorkHandleDesc);
        assert_preamble!(VerifyVerdict);
        assert_preamble!(AuthQuery);
        assert_preamble!(AuthResolved);
        assert_preamble!(MetricSample);
        assert_preamble!(CounterpartyRef);
        assert_preamble!(CallerRef);
        assert_preamble!(TargetRef);
        assert_preamble!(ContentChunk);
    }
}
