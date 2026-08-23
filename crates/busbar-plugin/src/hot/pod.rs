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

/// WHY a governed egress FAILED — the neutral failure CLASS the host surfaces on a non-`Ok`
/// `egress_open`, so the plane reproduces its OWN failover/refusal taxonomy (the mcp `Unreachable` vs
/// `Io` split, the a2a transport-error framing) instead of a lossy coarse [`StatusClass`]. The host
/// classifies the underlying transport outcome; the plane keeps every operator string. Names are
/// protocol-NEUTRAL (a connectivity taxonomy, no protocol/role noun). Append-only: new classes at the
/// tail with a fresh discriminant; [`Unspecified`](Self::Unspecified) (= 0) is the forward-compat
/// default a reader sees when the host wrote no fine class (fall back to the coarse meaning).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressFailClass {
    /// No fine class supplied — fall back to the coarse [`StatusClass`] mapping.
    Unspecified = 0,
    /// The hop could not REACH the upstream (connect / TLS / DNS-pin failure) — the "unreachable"
    /// class a plane fails over on without penalising a healthy-but-unreached target.
    Connect = 1,
    /// The connection was made but the exchange failed mid-flight (a read/write/body I/O failure).
    Io = 2,
    /// The governance guard REFUSED the hop before any socket (SSRF / scheme / metadata / allowlist).
    Refused = 3,
    /// An internal host fault (a caught panic, a runtime that would not start) — never the upstream's.
    Fault = 4,
}

/// The out-param an `egress_fault` writes: the neutral failure detail for the LAST failed
/// `egress_open` in this dispatch scope. The variable CAUSE-message bytes and the TARGET-url bytes are
/// copied into SEPARATE caller buffers (so each plane chooses to include or strip the url — one keeps
/// it, another strips it), and this header carries the class, the observed status (0 when none), and
/// the two lengths. The host formats NO operator string; it hands back the flattened cause and the url
/// as neutral bytes.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct EgressFault {
    /// `size_of::<EgressFault>()` when the host writes it.
    pub size: u32,
    /// POD schema version.
    pub version: u16,
    /// The neutral failure class (see [`EgressFailClass`]).
    pub fail_class: EgressFailClass,
    /// Preamble tail padding.
    pub _reserved: u8,
    /// The observed response/status code, or `0` when the failure was before a response head.
    pub status_code: u16,
    /// Alignment padding before the lengths.
    pub _reserved2: u16,
    /// The number of CAUSE-message bytes the host copied into the caller's cause buffer.
    pub cause_len: u32,
    /// The number of TARGET-url bytes the host copied into the caller's url buffer.
    pub url_len: u32,
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
    /// STEP 1 refusal — the principal is no longer live (deleted / disabled / expired). Append-only
    /// minor-3: the host folds the plane's ordered validator, so a refusal keeps its SPECIFIC step
    /// rather than collapsing to a bare `Denied`.
    IdentityNotLive = 4,
    /// STEP 2 refusal — the caller's grant does not reach the named capability.
    NotGranted = 5,
    /// STEP 2 refusal — the target's standing egress list does not name this caller.
    EgressDenied = 6,
    /// STEP 3 refusal — the named capability is offered at a fingerprint nobody approved (or the
    /// reader could produce no fingerprint that could match).
    ArtifactDrifted = 7,
    /// STEP 4 refusal — the registry snapshot moved between admission and dispatch.
    GenerationMoved = 8,
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

/// The decision of a STATELESS verify-freshness check (`verify_decide` over a [`VerifyQuery`]): may
/// the plane reuse its recorded observation, or must it re-verify — and, when it must, WHY? Returned
/// BY VALUE (kept out of the hot PODs so it stays a bare `#[repr(u8)]`, like [`GateDecision`]).
/// [`Fresh`](Self::Fresh) (= 0) is the pass; every other value is a "must re-verify" carrying the
/// specific REASON, so the plane reconstructs the rich `reverify::Due` it audits rather than a lossy
/// bool. [`Stale`](Self::Stale) is the GENERIC due — the FAIL-CLOSED default a null query or a caught
/// panic answers, so an undecidable freshness re-verifies rather than serving unchecked; a real query
/// resolves to one of the specific reasons below. Append-only: new reasons go at the tail with a fresh
/// discriminant, and a reader that predates a reason treats any "not `Fresh`" as due (re-verify).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyDecision {
    /// The recorded observation is still within `ttl_ms`; reuse the snapshot (no re-fetch). Maps the
    /// plane's `reverify::Due::No`.
    Fresh = 0,
    /// GENERIC due — must re-verify, reason unspecified. The fail-closed default (null query / caught
    /// panic); a real query resolves to one of the specific reasons below rather than this.
    Stale = 1,
    /// The subject was approved from a declarative pin and never actually contacted. Maps
    /// `reverify::Due::NeverChecked`.
    NeverChecked = 2,
    /// The operator's freshness window elapsed (reaching the ttl is due). Maps `reverify::Due::TtlExpired`.
    TtlExpired = 3,
    /// An operator asked explicitly — outranks the timer. Maps `reverify::Due::OperatorSync`. (The
    /// stateless slot keeps `operator_sync` its false default, so this reason is decided plane-side;
    /// it is carried here for completeness of the neutral reason mapping.)
    OperatorSync = 4,
    /// The clock moved BACKWARDS since the last check, so freshness cannot be trusted — treated as due
    /// rather than as permanent freshness. Maps `reverify::Due::ClockWentBackwards`.
    ClockWentBackwards = 5,
}

impl VerifyDecision {
    /// Whether the plane must re-verify: TRUE for every reason except [`Fresh`](Self::Fresh). The
    /// by-value mirror of `reverify::Due::should_check`, so a caller that only needs the bool decision
    /// (not the reason) reads it off the neutral decision the same way.
    #[must_use]
    pub fn should_check(self) -> bool {
        self != VerifyDecision::Fresh
    }
}

/// WHY a URL-shaped tool ARGUMENT was refused by the host's structural URL guard (`guard_url`) — the
/// neutral class carried in a [`GuardVerdict`], so the plane reproduces its own operator wording for a
/// refusal instead of the host formatting one. The host judges the URL STRUCTURALLY (scheme + host +
/// the cloud-metadata / obfuscated-encoding / internal-address checks) and resolves NO name; the class
/// is the shape of the refusal, and the offending host/url bytes ride the paired reason buffer.
/// [`Allowed`](Self::Allowed) (= 0) is the pass; every other value is a refusal. Append-only: new
/// classes go at the tail with a fresh discriminant.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardClass {
    /// The URL is admissible — no structural refusal applies.
    Allowed = 0,
    /// An absolute-URL field carrying something that is not `http(s)`.
    Scheme = 1,
    /// The value has no host component to judge.
    NoHost = 2,
    /// The host is a cloud-metadata endpoint (by address, an alternate encoding of one, or a metadata
    /// DNS name). Refused unconditionally, whatever the private-address policy.
    CloudMetadata = 3,
    /// The host is an alternate IPv4 encoding a resolver expands but a canonical IP-literal check
    /// misses. Refused unconditionally.
    ObfuscatedHost = 4,
    /// The host is internal (loopback / RFC-1918 / link-local / CGNAT / unique-local / the `localhost`
    /// family / an IPv4-mapped IPv6 spelling of any of them). Refused unless private addressing is
    /// opted into for the target.
    InternalHost = 5,
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
/// ## The identity tail (append-only minor extension)
///
/// The tail block (`identity_id_ptr` … `group_len`) is an APPEND-ONLY minor extension carrying the
/// caller's RESOLVED admission identity: the attribution-bucket id (the real key id) and the key's
/// enforcement `group` (empty = ungrouped). Without it the host can only admit against a SYNTHESIZED
/// ungrouped key; with it the host drives the SAME `try_admit` chain — the key's own `total` bucket
/// plus every ancestor group's window/concurrent caps — the in-process budget plane enforces. A
/// sender that predates the tail advertises the shorter `size`; the host reads the tail only when
/// `size` proves it was written (the sized-struct guard) AND `identity_id_len != 0`, otherwise it
/// falls back to the synthesized key — a MINOR airlock bump, never a MAJOR.
///
/// # Safety / discipline
/// `pool_name_ptr`/`pool_name_len` — and, when present, `identity_id_ptr`/`identity_id_len` and
/// `group_ptr`/`group_len` — MUST describe a live, initialized byte range for any call that receives
/// `&Facts`. Construct via [`Facts::new`] (no identity) or [`Facts::with_attribution`] (with the
/// identity tail), which tie every borrow to a [`FactsGuard`].
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
    /// (minor-5) Borrowed pointer to the resolved attribution-bucket id (the real key id). A null
    /// pointer / zero [`identity_id_len`](Self::identity_id_len) means "no resolved identity — the
    /// host synthesizes one", the pre-enrichment behaviour.
    pub identity_id_ptr: *const u8,
    /// (minor-5) Length of the borrowed attribution-id range (`0` = absent).
    pub identity_id_len: usize,
    /// (minor-5) Borrowed pointer to the key's enforcement `group` name (NOT owned). A null pointer /
    /// zero [`group_len`](Self::group_len) means the key is UNGROUPED (an unlimited 1-bucket chain).
    pub group_ptr: *const u8,
    /// (minor-5) Length of the borrowed group-name range (`0` = ungrouped).
    pub group_len: usize,
}

impl Facts {
    /// Build a `Facts` borrowing `pool_name` for `'a`, WITHOUT a resolved identity (the identity tail
    /// is null → the host admits against a synthesized ungrouped key). Returns a [`FactsGuard`] so the
    /// borrow can't outlive the name. No allocation, no copy.
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
                identity_id_ptr: core::ptr::null(),
                identity_id_len: 0,
                group_ptr: core::ptr::null(),
                group_len: 0,
            },
            _borrow: core::marker::PhantomData,
        }
    }

    /// Build a `Facts` carrying the RESOLVED admission identity: the attribution-bucket id
    /// (`identity_id`) and the key's enforcement `group` (`None` = ungrouped). Every borrow —
    /// `pool_name`, `identity_id`, and the optional `group` — is tied to the returned [`FactsGuard`]'s
    /// lifetime `'a`. This is the enriched path the host drives the real `try_admit` chain over.
    #[allow(clippy::new_ret_no_self)]
    #[allow(clippy::too_many_arguments)]
    pub fn with_attribution<'a>(
        tokens: u64,
        budget_remaining: u64,
        tenant_id: u64,
        priority: u32,
        flags: u32,
        pool_name: &'a [u8],
        identity_id: &'a [u8],
        group: Option<&'a [u8]>,
    ) -> FactsGuard<'a> {
        let (group_ptr, group_len) = match group {
            Some(g) => (g.as_ptr(), g.len()),
            None => (core::ptr::null(), 0),
        };
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
                identity_id_ptr: identity_id.as_ptr(),
                identity_id_len: identity_id.len(),
                group_ptr,
                group_len,
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
///
/// ## The attribution tail (append-only minor extension)
///
/// The tail block (`key_id_ptr` … `provider_len`) is an APPEND-ONLY minor extension carrying the
/// RESOLVED metering attribution: the `(key_id, model, provider)` the write-behind series records
/// against. Without it the host records against a SYNTHETIC attribution derived from the admission id;
/// with it the host records the EXACT `(key_id, model, provider)` the in-process meter would. A sender
/// that predates the tail advertises the shorter `size`; the host reads the tail only when `size`
/// proves it was written (the sized-struct guard) AND `key_id_len != 0`, otherwise it falls back to
/// the synthetic attribution — a MINOR airlock bump, never a MAJOR.
///
/// # Safety / discipline
/// When present, `key_id_ptr`/`key_id_len`, `model_ptr`/`model_len`, and `provider_ptr`/`provider_len`
/// MUST describe live, initialized byte ranges (NOT owned by `Usage`) for any call receiving `&Usage`.
/// Construct via [`Usage::charge`] (no attribution) or [`Usage::with_attribution`], which tie every
/// borrow to a [`UsageGuard`].
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
    /// (minor-5) Borrowed pointer to the resolved metering key id (NOT owned). A null pointer / zero
    /// [`key_id_len`](Self::key_id_len) means "no resolved attribution — the host synthesizes one".
    pub key_id_ptr: *const u8,
    /// (minor-5) Length of the borrowed key-id range (`0` = absent).
    pub key_id_len: usize,
    /// (minor-5) Borrowed pointer to the metering `model` word (NOT owned).
    pub model_ptr: *const u8,
    /// (minor-5) Length of the borrowed model range (`0` = absent).
    pub model_len: usize,
    /// (minor-5) Borrowed pointer to the metering `provider` word (NOT owned).
    pub provider_ptr: *const u8,
    /// (minor-5) Length of the borrowed provider range (`0` = absent).
    pub provider_len: usize,
}

impl Usage {
    /// Build a `Usage` charging `amount × unit_cost_micros` against `admission`, WITHOUT a resolved
    /// attribution (the tail is null → the host records against a synthetic attribution derived from
    /// the admission id). Returns a [`UsageGuard`] (no borrows to tie yet, but uniform with
    /// [`with_attribution`](Self::with_attribution)).
    #[allow(clippy::new_ret_no_self)]
    pub fn charge<'a>(
        component: UsageComponent,
        amount: u64,
        unit_cost_micros: u64,
        admission: AdmissionId,
    ) -> UsageGuard<'a> {
        UsageGuard {
            usage: Usage {
                size: core::mem::size_of::<Usage>() as u32,
                version: POD_VERSION,
                component,
                _reserved: 0,
                amount,
                unit_cost_micros,
                admission,
                key_id_ptr: core::ptr::null(),
                key_id_len: 0,
                model_ptr: core::ptr::null(),
                model_len: 0,
                provider_ptr: core::ptr::null(),
                provider_len: 0,
            },
            _borrow: core::marker::PhantomData,
        }
    }

    /// Build a `Usage` carrying the RESOLVED metering attribution `(key_id, model, provider)`. Every
    /// borrow is tied to the returned [`UsageGuard`]'s lifetime `'a`. This is the enriched path the
    /// host records the EXACT `(key_id, model, provider)` metering row over.
    #[allow(clippy::new_ret_no_self)]
    #[allow(clippy::too_many_arguments)]
    pub fn with_attribution<'a>(
        component: UsageComponent,
        amount: u64,
        unit_cost_micros: u64,
        admission: AdmissionId,
        key_id: &'a [u8],
        model: &'a [u8],
        provider: &'a [u8],
    ) -> UsageGuard<'a> {
        UsageGuard {
            usage: Usage {
                size: core::mem::size_of::<Usage>() as u32,
                version: POD_VERSION,
                component,
                _reserved: 0,
                amount,
                unit_cost_micros,
                admission,
                key_id_ptr: key_id.as_ptr(),
                key_id_len: key_id.len(),
                model_ptr: model.as_ptr(),
                model_len: model.len(),
                provider_ptr: provider.as_ptr(),
                provider_len: provider.len(),
            },
            _borrow: core::marker::PhantomData,
        }
    }
}

/// A [`Usage`] tied to the lifetime of its borrowed attribution words so the borrows can't dangle.
pub struct UsageGuard<'a> {
    usage: Usage,
    _borrow: core::marker::PhantomData<&'a [u8]>,
}

impl core::ops::Deref for UsageGuard<'_> {
    type Target = Usage;
    #[inline]
    fn deref(&self) -> &Usage {
        &self.usage
    }
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

    // ── APPEND-ONLY minor-11 tail: the drift DISPOSITION the `drift_quarantine` slot settles for
    //    this key, so the slot records the CALLER's trust-state (demote OR clear) instead of a
    //    hardcoded quarantine. Read ONLY by `drift_quarantine`, and ONLY when `size` proves it was
    //    written (the sized-struct guard); every other slot that takes a `Key` ignores it. A sender
    //    that predates this field advertises the shorter `size`; the drift slot then falls back to
    //    the pre-extension demote-only disposition (`Quarantined`), so the addition is a MINOR
    //    airlock bump, never a MAJOR — no existing member changes meaning. ──
    /// The trust-state the caller settles for this key on the drift path — a neutral u8 mirror of the
    /// plane's lifecycle state: `0` absent/unspecified (the drift slot fails safe to a demotion), `1`
    /// pending, `2` approved (CLEARS the durable demotion), `3` quarantined (RECORDS it), `4`
    /// suspended, `5` failed. Only `drift_quarantine` reads it; on every other slot it is inert.
    pub drift_state: u8,
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

/// The out-param a REFUSAL-fidelity ADMIT (`govern_admit_reason`) writes when a limit blocks — the
/// recovery hint plus the LENGTH of the rendered refusal reason the host copied into the caller's
/// `reason_buf` — so a blocked admission keeps its SPECIFIC meaning (which group / metric / window
/// blocked) across the host boundary instead of collapsing to a bare [`Decision::Deny`]. It is the
/// admit-side counterpart of [`AdmitRefusal`] (the breaker refusal): where `AdmitRefusal` carries a
/// fine [`Unavailability`] enum, this carries a variable-length rendered reason via the `egress_poll`
/// `(reason_buf, reason_cap, reason_len)` pattern — the blocking limit's own rendering, which the
/// plane cannot hold, formatted host-side. The host ALWAYS initializes it: a [`Decision::Admit`] leaves
/// `reason_len == 0`, and a [`Decision::Deny`] on a blocked limit writes the reason bytes and their
/// length. The caller reads `reason_buf[..reason_len]` exactly when the returned [`Decision`] is `Deny`.
///
/// APPEND-ONLY minor extension alongside the [`host::GovernAdmitReasonFn`](super::host::GovernAdmitReasonFn)
/// slot: a sender that predates it has no such slot, and a reader reads this only through a slot that
/// exists in the bumped-minor table — a MINOR airlock bump, never a MAJOR.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct GovRefusal {
    /// `size_of::<GovRefusal>()` when the host writes it.
    pub size: u32,
    /// POD schema version.
    pub version: u16,
    /// Preamble tail padding.
    pub _reserved: u16,
    /// The known/estimated recovery floor in whole seconds (`0` when there is no basis to estimate —
    /// a `total`-window budget block never rolls, a missing-group / disabled-group block does not
    /// self-recover).
    pub retry_after_secs: u64,
    /// The number of rendered-reason bytes the host copied into the caller's `reason_buf` (`0` on an
    /// [`Decision::Admit`], or when no buffer was supplied). Read `reason_buf[..reason_len]`.
    pub reason_len: usize,
}

/// The out-param the host's structural URL guard (`guard_url`) writes on [`StatusClass::Ok`]: whether
/// the judged URL is admissible, the refusal CLASS when it is not, and the LENGTH of the offending
/// host/url bytes the host copied into the caller's paired reason buffer — so a refused URL keeps its
/// specific meaning (which endpoint, which shape) across the host boundary and the plane composes its
/// own operator string. The judgement is STRUCTURAL and resolves no name; the host formats no operator
/// string. The reason bytes ride the same variable-length pattern as [`EgressFault`]'s cause buffer:
/// the host writes at most the caller's capacity and reports the length here.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct GuardVerdict {
    /// `size_of::<GuardVerdict>()` when the host writes it.
    pub size: u32,
    /// POD schema version.
    pub version: u16,
    /// Preamble tail padding.
    pub _reserved: u16,
    /// The disposition: `0` = allow, `1` = deny. Read `class`/`reason_len` on a deny.
    pub verdict: u8,
    /// The refusal class (see [`GuardClass`]); [`GuardClass::Allowed`] on an allow.
    pub class: u8,
    /// Alignment padding before the length.
    pub _reserved2: u16,
    /// The number of offending host/url bytes the host copied into the caller's reason buffer (`0` on
    /// an allow, or when no buffer was supplied). Read `reason_buf[..reason_len]`.
    pub reason_len: u32,
}

/// The descriptor for opening a governed egress. Carries a credential-REF (which pool/hop/exchange),
/// NEVER plaintext — the host mints and injects the credential app-layer. Also carries the mTLS
/// client-identity REF for pinned client auth.
///
/// ## The outbound-request tail (append-only minor-7 extension)
///
/// The tail block (`verb_ptr` … `cred_scheme_len`) is an APPEND-ONLY minor-7 extension carrying
/// everything an OUTBOUND request needs as neutral DATA — the request `verb` (e.g. `GET`/`POST`), a
/// packed `header set`, the request `body`, and the credential PLACEMENT (the header name + auth scheme
/// the host injects the resolved credential under). It carries NO policy: the SSRF/allowlist/mint
/// governance is the host's, applied identically whatever the plane sends. A sender that predates the
/// tail advertises the shorter `size`; the host reads each tail field only when `size` proves it was
/// written (the sized-struct guard), otherwise it falls back to a bodyless `GET` with no injected
/// credential — the pre-enrichment behaviour. A MINOR airlock bump, never a MAJOR.
///
/// The packed header set (`headers_ptr`/`headers_len`) is a sequence of records, each a little-endian
/// `u32 name_len`, `name_len` name bytes, a little-endian `u32 value_len`, then `value_len` value
/// bytes. The host forwards the names/values verbatim and interprets none of them.
///
/// # Safety / discipline
/// `target_ptr`/`target_len` MUST describe a live, initialized byte range (URL / address / program).
/// Each tail `(ptr, len)`, when non-null/non-zero, MUST likewise describe a live borrowed range for
/// the call.
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
    /// (minor-7) Borrowed request VERB bytes (e.g. `POST`). Null/empty ⇒ the host defaults to `GET`.
    pub verb_ptr: *const u8,
    /// (minor-7) Length of the borrowed verb range (`0` = default `GET`).
    pub verb_len: usize,
    /// (minor-7) Borrowed packed header-set bytes (length-prefixed name/value records; NOT owned).
    pub headers_ptr: *const u8,
    /// (minor-7) Length of the packed header-set range (`0` = no extra headers).
    pub headers_len: usize,
    /// (minor-7) Borrowed request BODY bytes (NOT owned). Null/`0` ⇒ a bodyless request.
    pub body_ptr: *const u8,
    /// (minor-7) Length of the borrowed body range (`0` = no body).
    pub body_len: usize,
    /// (minor-7) Borrowed credential-placement HEADER-NAME bytes (e.g. `authorization`) the host
    /// injects the resolved credential under. Null/`0` ⇒ no credential injection. NEVER a secret.
    pub cred_header_ptr: *const u8,
    /// (minor-7) Length of the credential header-name range (`0` = no injection).
    pub cred_header_len: usize,
    /// (minor-7) Borrowed credential-placement SCHEME-prefix bytes (e.g. `Bearer `). The host renders
    /// `{scheme}{resolved-credential}` into the credential header. Null/`0` ⇒ raw value, no prefix.
    pub cred_scheme_ptr: *const u8,
    /// (minor-7) Length of the credential scheme-prefix range (`0` = no scheme prefix).
    pub cred_scheme_len: usize,
    /// (minor-8) Borrowed packed subprocess-ENVIRONMENT records (SUBPROCESS kind only). The child gets
    /// ONLY these, never the host's own environment — the host applies `env_clear()` first, so a
    /// provider secret in the host's environment cannot leak into an operator-configured child. Each
    /// record is `u32 name_len` (LE), `name_len` name bytes, a `u8` VALUE-KIND (`0` = a literal value,
    /// `1` = a host-resolved secret reference), a `u32 value_len` (LE), then `value_len` value bytes.
    /// For a literal the value is the environment value verbatim; for a secret reference the value is
    /// an OPAQUE host-resolved reference the host turns into plaintext at spawn (never the plaintext
    /// itself). Null/`0` ⇒ an empty child environment. NOT interpreted for non-subprocess kinds.
    pub env_ptr: *const u8,
    /// (minor-8) Length of the packed environment-records range (`0` = an empty child environment).
    pub env_len: usize,
    /// (minor-8) Borrowed subprocess WORKING-DIRECTORY bytes (SUBPROCESS kind only). Null/`0` ⇒ the
    /// child inherits the host's own working directory (the host does not call `current_dir`).
    pub cwd_ptr: *const u8,
    /// (minor-8) Length of the working-directory range (`0` = inherit the host's cwd).
    pub cwd_len: usize,
    /// (minor-8) Subprocess STDERR disposition (SUBPROCESS kind only): `0` = discard (the child's
    /// stderr goes to the null device — the forward-compatible default a sender that predates this
    /// field leaves), `1` = inherit (the child's stderr is the host's own stderr, where an operator
    /// reads a child's diagnostics). Any other value is read as the `0` default.
    pub stderr_inherit: u8,
    /// (minor-8) Preamble/alignment padding after the stderr byte.
    pub _reserved3: [u8; 7],
    /// (minor-15) A REF to the set of EXTRA trust anchors (private-CA roots) the host adds to the
    /// pinned client for this hop (`0` = none — trust only the platform roots). Never certificate
    /// bytes: the host resolves the ref to the parsed roots it owns (see
    /// [`crate::plane_host`](super)'s `trust_anchor` registry) and adds them, so a plane whose upstream
    /// chains to a private CA names it by ref exactly as it names its client identity by ref. A sender
    /// that predates this field advertises the shorter `size`; the host reads it only when `size`
    /// proves it was written (the sized-struct guard), otherwise it falls back to no extra roots — a
    /// MINOR airlock bump, never a MAJOR.
    pub trust_anchor_ref: u64,
    /// (minor-16) The per-hop end-to-end DEADLINE in milliseconds (`0` ⇒ the host's default ceiling).
    /// The host applies it to the request AND the connect-head wait, so a plane whose registration
    /// carries an operator `timeout:` (or a distinct card/relay/stream ceiling) gets exactly that
    /// deadline rather than the host's fixed fallback. A sender that predates this field advertises the
    /// shorter `size`; the host reads it only when `size` proves it was written (the sized-struct
    /// guard), otherwise it falls back to the default — a MINOR airlock bump, never a MAJOR.
    pub timeout_ms: u64,
    /// (minor-16) The plane's ALREADY-JUDGED pinned address for this hop (Design A). When
    /// [`resolved_addr_kind`](Self::resolved_addr_kind) is non-zero the host connects to THIS address
    /// and does NOT resolve the URL host itself — preserving a plane that resolves-then-pins plane-side
    /// and hands the host the surviving address (the a2a card-fetch/relay posture) byte-for-byte. The
    /// URL host is still used for SNI / certificate-name / mTLS. A v4 address occupies the first 4
    /// bytes; a v6 address occupies all 16. NEVER a name — the host performs no lookup on this path.
    pub resolved_addr: [u8; 16],
    /// (minor-16) How to read [`resolved_addr`](Self::resolved_addr): `0` = none (the host resolves the
    /// URL host itself, the pre-enrichment behaviour), `4` = an IPv4 address (first 4 bytes), `6` = an
    /// IPv6 address (all 16 bytes). Any other value is read as `0`. A reader that predates this field
    /// sees the shorter `size` and reads `0`.
    pub resolved_addr_kind: u8,
    /// (minor-16) Preamble/alignment padding after the resolved-address kind byte.
    pub _reserved4: [u8; 7],
}

/// What the host observed at connect time (post-connect, pre-body), handed back with an [`EgressOpen`].
///
/// # Safety / discipline
/// `observed_spki_ptr`/`observed_spki_len`, when non-null, borrow host-owned bytes valid for the call.
/// ## The response-header tail (append-only minor-8 extension)
///
/// The tail block (`resp_headers_ptr`/`resp_headers_len`) is an APPEND-ONLY minor-8 extension carrying
/// the small set of RESPONSE headers the plane classifies on — at least `content-type` (SSE vs JSON
/// detection) and `Location` (redirect refusal) — as neutral length-prefixed name/value records (the
/// SAME packing as the request header set: `u32 name_len` LE, name, `u32 value_len` LE, value). The
/// host surfaces the bytes verbatim and formats NONE of them; every operator/cold-wire string the
/// plane builds from them stays plane-side. The bytes are host-owned and live as long as the egress is
/// open. A reader that predates the tail sees the shorter `size` and reads no response headers.
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
    /// (minor-8) Borrowed packed RESPONSE-header records (host-owned; at least `content-type` and, on a
    /// redirect, `Location`). Null/`0` ⇒ none surfaced. Same name/value packing as the request set.
    pub resp_headers_ptr: *const u8,
    /// (minor-8) Length of the packed response-header range (`0` = none).
    pub resp_headers_len: usize,
    /// (minor-14) BUSBAR'S OWN END OF THE HANDSHAKE: `1` when this hop carried a client certificate
    /// into the TLS handshake (so it was presented if the peer's `CertificateRequest` asked), `0`
    /// otherwise. `0` also on a plaintext or raw hop (nothing was offered). A plane reads this as the
    /// mutual-TLS half of the connection the response arrived over — it CANNOT mean "the peer did not
    /// ask", because TLS gives a client no after-the-fact way to tell a handshake in which the peer
    /// sent no `CertificateRequest` from one in which it did. A reader that predates this field sees
    /// the shorter `size` and reads `0`.
    pub client_identity_offered: u8,
    /// (minor-14) Preamble/alignment padding after the client-identity byte.
    pub _reserved4: [u8; 7],
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

/// A DURABLE journal-stream registration descriptor (minor-9): the plane names a stream's neutral
/// `kind` bytes (e.g. `task_event` — OPAQUE to the host), the prelude `framing`, whether the scope
/// participates in the digest, and a host-assigned `kind_id` it will address every later scoped op by.
/// The host learns the `kind` as DATA at register time and NAMES no plane type; the `kind_id` is the
/// cheap integer handle the hot append/read/restore path keys on.
///
/// # Safety / discipline
/// `kind_ptr`/`kind_len` MUST describe a live, initialized byte range for the register call.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct JournalStreamDesc {
    /// `size_of::<JournalStreamDesc>()` at construction.
    pub size: u32,
    /// POD schema version.
    pub version: u16,
    /// The prelude framing this stream reproduces (byte-identical to its deployed store).
    pub framing: Framing,
    /// `1` if the scope field participates in the digest, `0` if it does not.
    pub digests_scope: u8,
    /// The host-assigned integer handle the scoped ops address this stream by.
    pub kind_id: u32,
    /// Preamble/alignment padding before the borrowed range.
    pub _reserved: u32,
    /// Borrowed opaque neutral-kind bytes (e.g. `task_event`; NOT owned; the host stores them verbatim).
    pub kind_ptr: *const u8,
    /// Length of the borrowed kind range.
    pub kind_len: usize,
}

/// The out-param a plane-provided REFRAME writes (minor-9): the chain fields the host needs to
/// reconstruct one record from an opaque stored body, WITHOUT the host decoding a plane type. The
/// plane decodes the body (its own serde row, OR the journal's neutral body) and reports the minted
/// `seq`, whether the scope digests, and the LENGTHS of the `prev_hash`, `hash` and pre-framed content
/// `suffix` it copied into the caller's three buffers (the `egress_poll` variable-length pattern).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ReframeOut {
    /// `size_of::<ReframeOut>()` when the plane writes it.
    pub size: u32,
    /// POD schema version.
    pub version: u16,
    /// `1` if the scope participates in the digest for this record, `0` if not.
    pub digests_scope: u8,
    /// Preamble tail padding.
    pub _r: u8,
    /// The record's chain sequence.
    pub seq: u64,
    /// The number of `prev_hash` bytes the plane copied into the caller's prev buffer.
    pub prev_len: usize,
    /// The number of `hash` bytes the plane copied into the caller's hash buffer.
    pub hash_len: usize,
    /// The number of pre-framed content-SUFFIX bytes the plane copied into the caller's suffix buffer.
    pub suffix_len: usize,
}

/// The out-param a `journal_restore` writes (minor-9): the neutral COUNTS a boot rehydrate found —
/// the [`crate::hot`]-neutral mirror of core's `Restored`. No scope names cross (a plane logs its own
/// vocabulary from its own rows); only the four counts do.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RestoredHdr {
    /// `size_of::<RestoredHdr>()` when the host writes it.
    pub size: u32,
    /// POD schema version.
    pub version: u16,
    /// Preamble tail padding.
    pub _reserved: u16,
    /// Scopes whose chain position was resumed.
    pub scopes: u64,
    /// Records read back across every scope (the durability signal — zero on a serving deployment
    /// means the backend kept none).
    pub records: u64,
    /// Scopes the store enumerated but returned no records for.
    pub empty_scopes: u64,
    /// Chains that FAILED to verify (tamper evidence; still restored from the broken tail).
    pub chain_breaks: u64,
}

/// The out-param a `journal_seed` writes (minor-9): whether the seeded chain verified, and WHERE it
/// broke if not. A break is REPORTED and the chain still resumes from its tail (never re-based).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ChainBreakHdr {
    /// `size_of::<ChainBreakHdr>()` when the host writes it.
    pub size: u32,
    /// POD schema version.
    pub version: u16,
    /// `1` if the chain broke (read `at_index`/`seq`), `0` if it verified.
    pub broke: u8,
    /// Preamble tail padding.
    pub _reserved: u8,
    /// Preamble/alignment padding before the 8-byte-aligned tail.
    pub _reserved2: u32,
    /// The 1-based slice index at which the break was found (`0` when it verified).
    pub at_index: u64,
    /// The claimed sequence at the break (`0` when it verified).
    pub seq: u64,
}

/// The out-param a `journal_verify_scoped` writes (minor-9): whether one scope's persisted chain
/// verifies, and where it breaks if not. Same shape as [`ChainBreakHdr`] but a distinct type so the
/// two seams (seed vs. verify) stay independently versionable.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct VerifyChainHdr {
    /// `size_of::<VerifyChainHdr>()` when the host writes it.
    pub size: u32,
    /// POD schema version.
    pub version: u16,
    /// `1` if the chain verified, `0` if it broke (read `at_index`/`seq`).
    pub verified: u8,
    /// Preamble tail padding.
    pub _reserved: u8,
    /// Preamble/alignment padding before the 8-byte-aligned tail.
    pub _reserved2: u32,
    /// The 1-based slice index at which a break was found (`0` when verified).
    pub at_index: u64,
    /// The claimed sequence at the break (`0` when verified).
    pub seq: u64,
}

/// A depth-bounded nested-dispatch descriptor: the host routes an opaque sub-request through the SAME
/// router, never knowing what it is. Carries a depth bound and a correlation id so a re-entrant call
/// reuses the originating budget/audit correlation instead of double-counting.
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

/// A counterparty-verification FRESHNESS query — the input to the STATELESS `verify_decide` slot
/// (added append-only, the `breaker_admit_reason` precedent). It carries ONLY the freshness scalars
/// `reverify::due` reads: the plane's authoritative `last_checked_ms` (with a present flag, so
/// `None`/never-checked marshals faithfully), the operator's `ttl_ms`, and the caller's `now_ms`.
///
/// There is NO subject key and NO host cache: `verify_decide` is a pure decision over these three
/// inputs. The plane keeps its OWN ledger, coalescing and single-flight — only the `reverify::due`
/// arithmetic crosses this seam, so the plane's freshness state never has to live host-side.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct VerifyQuery {
    /// `size_of::<VerifyQuery>()` at construction.
    pub size: u32,
    /// POD schema version.
    pub version: u16,
    /// Preamble tail padding.
    pub _reserved: u16,
    /// Whether `last_checked_ms` carries the plane's last-checked stamp (`1`), or the subject was
    /// NEVER checked (`0` — `reverify::due`'s `NeverChecked`). The marshalled form of `Option<u64>`.
    pub last_checked_present: u32,
    /// Preamble/alignment padding.
    pub _reserved2: u32,
    /// The operator's freshness window in milliseconds (the plane's `Policy::ttl_ms`). Reaching it is
    /// stale, exactly as `reverify::due` reads it.
    pub ttl_ms: u64,
    /// The caller's clock reading in milliseconds — captured once by the plane and reused for the
    /// whole freshness decision, so a fixed-clock test decides identically to the async gate.
    pub now_ms: u64,
    /// The plane's authoritative last-checked stamp, on OUR clock (valid ONLY when
    /// `last_checked_present != 0`). Supplied by the plane's ledger; never a value the upstream gave.
    pub last_checked_ms: u64,
}

/// A one-time-approval REDEMPTION query — the input to the richer `approval_redeem_q` slot (added
/// append-only alongside the original `approval_redeem`). It carries the sealed-state nonce PLUS the
/// seal's own `expires_at` and the caller's `now`, so the host spends against the ledger with the
/// EXACT expiry the seal minted rather than recomputing a default TTL — the behavior-identity the
/// call site (`mcp::callerask`) requires.
///
/// # Safety / discipline
/// `key_ptr`/`key_len`, when non-null, borrow live bytes for the call.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ApprovalQuery {
    /// `size_of::<ApprovalQuery>()` at construction.
    pub size: u32,
    /// POD schema version.
    pub version: u16,
    /// Preamble tail padding.
    pub _reserved: u16,
    /// The scope this nonce is interpreted within (host-defined namespace id).
    pub scope: u32,
    /// Preamble/alignment padding.
    pub _reserved2: u32,
    /// The seal's own expiry, in the ledger's time unit — the value the plane sealed the state with.
    pub expires_at: u64,
    /// The caller's clock reading, in the ledger's time unit.
    pub now: u64,
    /// Borrowed pointer to the opaque nonce bytes (NOT owned).
    pub key_ptr: *const u8,
    /// Length of the borrowed nonce range.
    pub key_len: usize,
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

    // ── APPEND-ONLY minor-3 tail: the marshalled per-step FACTS of the plane's ordered
    //    `crate::trust::validate::validate_request` (identity → grant → artifact → generation), so
    //    the host `trust_evaluate` FOLDS them in the SAME order and reproduces the plane's
    //    disposition — the `Signal`→`classify` precedent applied to trust. A sender that predates
    //    this tail advertises the shorter `size`; the host reads the tail ONLY when `size` proves it
    //    was written (the sized-struct guard) AND bit 0 of `fact_flags` is set, and otherwise falls
    //    back to the legacy drift-map disposition. So the addition is a MINOR airlock bump. ──
    /// STEP 1 — identity liveness fact: `0` not-live, `1` live, `2` no-principal (the honest
    /// ungoverned `None`, which is not a way past the gate — the steps below still run).
    pub identity_live: u8,
    /// STEP 2 — grant fact for the FIRST failing grant: `0` all held, `1` not-granted, `2`
    /// egress-denied.
    pub grant_outcome: u8,
    /// STEP 3a — registration-state fact, a neutral mirror of the plane's lifecycle state: `0`
    /// absent/unspecified, `1` pending, `2` approved, `3` quarantined, `4` suspended, `5` failed.
    pub registration_state: u8,
    /// STEP 3b — artifact fact: `0` no-capability (the ask names none), `1` serves, `2` drifted, `3`
    /// unobservable.
    pub artifact_outcome: u8,
    /// Tail flags. Bit 0 set ⇒ the fact tail (`identity_live` … `generation_live`) was written by
    /// the sender; a `0` here (or a `size` too short to reach it) selects the legacy drift map.
    pub fact_flags: u8,
    /// Preamble/alignment padding.
    pub _reserved3: u8,
    /// Preamble/alignment padding.
    pub _reserved4: u16,
    /// STEP 4 — the generation the request was admitted under. Compared to `generation_live`.
    pub generation_admitted: u64,
    /// STEP 4 — the generation live now. A move (`admitted != live`) is `GenerationMoved`.
    pub generation_live: u64,
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
                assert_eq!(
                    core::mem::offset_of!($t, size),
                    0,
                    "size@0 on {}",
                    stringify!($t)
                );
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
        assert_preamble!(GovRefusal);
        assert_preamble!(GuardVerdict);
        assert_preamble!(EgressDesc);
        assert_preamble!(EgressHead);
        assert_preamble!(EgressOpen);
        assert_preamble!(EgressFault);
        assert_preamble!(CmdDesc);
        assert_preamble!(FramingDesc);
        assert_preamble!(JournalQuery);
        assert_preamble!(JournalStreamDesc);
        assert_preamble!(ReframeOut);
        assert_preamble!(RestoredHdr);
        assert_preamble!(ChainBreakHdr);
        assert_preamble!(VerifyChainHdr);
        assert_preamble!(OpDesc);
        assert_preamble!(OpResult);
        assert_preamble!(WorkHandleDesc);
        assert_preamble!(VerifyQuery);
        assert_preamble!(ApprovalQuery);
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
