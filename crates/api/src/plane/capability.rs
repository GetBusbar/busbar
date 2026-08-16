// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLANE CAPABILITIES — what a plane may ask of the engine, and the exact limit of each ask.
//!
//! ## The organising principle, and it is one sentence
//!
//! **The plane supplies the payload; the CORE supplies the linkage.**
//!
//! That is not a slogan, it is the security property. Every tamper-evidence digest in busbar is
//! computed engine-side and persisted verbatim by the backend — so a plane holding a raw
//! [`crate::Store`] could write rows with `prev_hash` and `hash` of its own choosing and forge a
//! chain that verifies. Every capability below is shaped so the plane hands over CONTENT and core
//! computes the linkage, the sequence, the kind stamp and the scope. A plugin cannot forge what it
//! is never allowed to write.
//!
//! ## Why not just hand over `Store`
//!
//! Because `Store` is ONE trait that bundles the audit chain with per-plane working state. That
//! bundling is correct for a *backend* (a `kind: db` plugin implements the whole persistence
//! contract) and catastrophic for a *plane* (a protocol plugin would inherit the append-only chain
//! as a side effect of wanting to store a task row). The capabilities here are FACADES over the
//! same backend: core holds the `Store`, and grants a plane only its own slice of it.
//!
//! The record TYPES are unchanged and already live in this crate ([`crate::TaskRow`],
//! [`crate::McpCallRecord`], …). Nothing new had to be invented — what was wrong was the GRANT, not
//! the vocabulary.
//!
//! ## Reading the list
//!
//! ## LAYER 1 vs LAYER 2 — which of these a NON-LLM plane could use
//!
//! Owner: *"make the design robust enough to not just work with llm mcp and a2a today, but anything
//! else we can design in future."* The IR is a PROTOCOL-FAMILY property (a request carrying messages
//! and tools produces a response), not a PLANE property — so it must not be the contract's universal
//! currency, or the contract can only ever express one family.
//!
//! **LAYER 1, universal and IR-free:** [`PlaneClock`], [`PlaneJournal`], [`PlaneTasks`],
//! [`PlaneApprovals`], [`PlaneQuarantine`], [`PlaneGovernance`], [`PlaneMetering`],
//! [`PlaneCatalogue`], [`PlaneSecrets`], [`PlaneMetrics`]. A session-oriented plane with no messages,
//! no tools and no request/response framing uses only these.
//!
//! **LAYER 2, LLM/agentic family:** the IR itself, and [`PlaneEgress`]'s HTTP-shaped request — see
//! that type's doc for why it is marked family-specific rather than quietly generalised.
//!
//! Each capability's doc states which layer it is in. Where something is deliberately
//! family-specific it SAYS SO, so the next reader knows it was a decision rather than an oversight.
//!
//! Every capability is `Send + Sync`, object-safe, and scoped by core to the calling plane's
//! [`super::PlaneDecl::key`] / [`super::PlaneDecl::audit_kind`]. None of them takes a scope
//! parameter the plane could lie about: the scope is bound when core constructs the handle, so a
//! plane cannot reach another plane's data by passing a different string.

use crate::plane::PlaneError;
use crate::{McpCallRecord, McpDemotionRow, TaskEventRow, TaskRow};

/// THE CLOCK, granted rather than imported.
///
/// A module import is not grantable, not mockable and not auditable — so any core service a plugin
/// reaches by path is a missing capability. This is the smallest one, and the pattern for the rest.
pub trait PlaneClock: Send + Sync {
    /// Unix epoch seconds. `u64` to match core's own clock exactly: a narrowing conversion here
    /// would put a panic or a silent clamp between core's time and the plane's, and a clamped `now`
    /// is how a durable ledger sweeps itself and then reports a replay as a first redemption.
    fn now_secs(&self) -> u64;
}

/// APPEND-ONLY, PLANE-SCOPED JOURNAL — the narrow slice of durability that replaces `Store`.
///
/// Append-only BY SIGNATURE: there is no update and no delete. Core stamps every record with the
/// plane's own audit kind and computes the chain linkage, so a plane can neither file under another
/// plane's kind nor choose its own `prev_hash`.
///
/// [`Self::verify`] is safe to grant even though writing a chain is not: verification READS the
/// linkage core computed and reports whether it holds. A plane that persists provenance needs to be
/// able to answer "is my chain intact?" — MCP's call log does exactly this — and answering it
/// confers no ability to forge one.
pub trait PlaneJournal: Send + Sync {
    /// Append one record. `payload` is the plane's own JSON; core supplies kind, sequence and
    /// linkage.
    fn append(&self, subject: &str, payload: &str) -> Result<(), PlaneError>;
    /// This plane's own records for one subject, oldest first, bounded by `limit`.
    fn read(&self, subject: &str, limit: usize) -> Result<Vec<String>, PlaneError>;
    /// Verify the persisted chain for one subject. READ-ONLY over linkage core computed.
    fn verify(&self, subject: &str) -> Result<ChainVerdict, PlaneError>;
}

/// The result of verifying a persisted chain. A verdict, not the linkage itself: a plane learns
/// WHETHER its chain holds and where it first broke, never the digests it would need to forge one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainVerdict {
    /// Every record links to its predecessor.
    Intact { records: usize },
    /// The chain breaks at this zero-based index. The plane may surface the fact; only core can act
    /// on it.
    Broken { at: usize },
    /// No records exist for this subject — distinct from `Intact { records: 0 }` so "nothing was
    /// ever written" cannot be reported as "nothing was tampered with".
    Absent,
}

/// KEYED, MUTABLE, PLANE-SCOPED TASK STATE — what [`PlaneJournal`] deliberately cannot do.
///
/// A2A's task row is mutated on every transition (submitted → working → completed), which is a
/// keyed upsert and therefore genuinely not journal-shaped. Rather than weaken the journal, this is
/// a SECOND capability with a different contract, and the split is the point: a plane holds both
/// and neither one grants the other's powers.
///
/// [`Self::purge_before`] is a RETENTION operation bounded to this plane's own namespace. It is not
/// an audit deletion and cannot reach the journal: the provenance chain for a task lives in
/// [`PlaneJournal`], survives the row's purge, and is what an incident is reconstructed from.
pub trait PlaneTasks: Send + Sync {
    fn put(&self, task: &TaskRow) -> Result<(), PlaneError>;
    fn get(&self, task_id: &str) -> Result<Option<TaskRow>, PlaneError>;
    fn list(&self) -> Result<Vec<TaskRow>, PlaneError>;
    /// Retention sweep over THIS PLANE's task rows only. Returns the number removed.
    fn purge_before(&self, before_secs: u64) -> Result<u64, PlaneError>;
    /// Per-task provenance. Append-only and separately chained by core, exactly as
    /// [`PlaneJournal`] is — a purged task row does not erase what happened to it.
    fn append_event(&self, event: &TaskEventRow) -> Result<(), PlaneError>;
    fn list_events(&self, task_id: &str) -> Result<Vec<TaskEventRow>, PlaneError>;
}

/// THE PER-CALL LOG — MCP's durable record of what it dispatched, as a capability.
///
/// Kept separate from [`PlaneJournal`] because its record type is already defined
/// ([`McpCallRecord`]) and its chain is scoped to the PRINCIPAL rather than to a subject the plane
/// names. Core supplies `prev_hash` and `hash`; the plane supplies everything else.
pub trait PlaneCallLog: Send + Sync {
    /// Record one dispatched call. Core computes the chain linkage over the principal's chain.
    fn record(&self, call: &McpCallRecord) -> Result<(), PlaneError>;
    /// This principal's records, oldest first.
    fn list_for_principal(
        &self,
        principal: &str,
        limit: usize,
    ) -> Result<Vec<McpCallRecord>, PlaneError>;
    /// Verify the persisted chain for one principal.
    fn verify(&self, principal: &str) -> Result<ChainVerdict, PlaneError>;
}

/// QUARANTINE STATE — the durable demotion record.
///
/// This is trust state, and it is granted rather than reached for because getting it wrong has a
/// known cost: a demoted upstream that lived only in process memory was re-served against the
/// operator-approved digest after a restart, so *a restart handed a quarantined upstream its
/// approval back*. Core owns the durability; the plane owns the observation that triggers it.
pub trait PlaneQuarantine: Send + Sync {
    /// Is this subject currently quarantined? Read on the serving path.
    fn is_quarantined(&self, subject: &str) -> Result<bool, PlaneError>;
    /// Record a demotion. Core stamps and persists it.
    fn demote(&self, row: &McpDemotionRow) -> Result<(), PlaneError>;
    /// Clear a demotion after an agreeing observation. Deliberately NOT a general delete: it clears
    /// exactly one subject's quarantine and cannot reach any other record.
    fn clear(&self, subject: &str) -> Result<(), PlaneError>;
}

/// SINGLE-USE APPROVAL REDEMPTION — the spent-approval ledger, as one indivisible question.
///
/// The whole security property is atomicity across nodes and across restarts: a sealed single-use
/// approval is byte-identical on second presentation, so without a durable ledger one operator
/// confirmation executes once per node AND once per restart. That atomicity is the ENGINE's and is
/// not expressible as a get-then-put a plane could race. Hence one method that both asks and
/// consumes.
pub trait PlaneApprovals: Send + Sync {
    /// Redeem `nonce` exactly once. `Ok(true)` = this caller redeemed it; `Ok(false)` = it was
    /// already spent. The plane MUST treat `false` as a refusal.
    fn redeem_once(&self, nonce: &str) -> Result<bool, PlaneError>;
}

/// GOVERNANCE ADMISSION — the plane DESCRIBES what it is about to do; the CORE JUDGES.
///
/// The [`crate::LoginHop`] shape, applied to admission. A plane never holds a governance context,
/// never resolves a principal's budget, and never decides its own admission — it states the ask and
/// receives a verdict. This is what keeps *"a protocol doesn't change breakers or failover or
/// auditing"* structurally true: a plane cannot serve a request it did not get admitted.
pub trait PlaneGovernance: Send + Sync {
    fn admit(&self, ask: &PlaneAsk) -> Result<PlaneVerdict, PlaneError>;
}

/// One admission ask. Everything core needs to judge, and nothing the plane could use to judge for
/// itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlaneAsk {
    /// The authenticated principal, as core established it.
    pub principal: String,
    /// The operation word, from this plane's declared verb vocabulary.
    pub operation: String,
    /// The subject being acted on (a tool name, an agent id, a task id).
    pub subject: String,
    /// Units the plane expects to consume, when it can estimate them. Core charges the real amount
    /// afterwards; this is for pre-admission budget refusal.
    pub estimated_units: Option<u64>,
}

/// Core's verdict. `Refused` carries an operator-facing reason the plane relays verbatim — the plane
/// does not get to rewrite why it was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlaneVerdict {
    Admitted { grant: PlaneGrant },
    Refused { reason: String },
}

/// An admission receipt. Opaque by construction: the plane returns it to core when the work is done
/// so core can charge, record and close the span. A plane cannot mint one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlaneGrant {
    /// Core's handle for this admission. Meaningless to the plane, and deliberately so.
    pub token: String,
}

/// THE ONLY WAY OUT — plane-originated outbound traffic, and the reason it is a capability.
///
/// A plane that could open its own socket would bypass the SSRF guard, the circuit breaker, the
/// failover walk and the audit record in one step — and the equality ledger already records that
/// busbar-originated traffic is the ungoverned direction on every plane except LLM. Routing every
/// egress through core makes those cross-cutting capabilities apply BY CONSTRUCTION rather than by
/// each plane author remembering to call them.
///
/// This is the capability that closes the reroute/breaker/audit parity cells for a plane rather
/// than merely relocating them, and it is why a plane crate needs no HTTP client of its own.
pub trait PlaneEgress: Send + Sync {
    /// Perform one governed outbound call. Core applies the SSRF guard (resolve-then-pin), the
    /// per-pool breaker, the failover walk and the audit record; the plane supplies the request and
    /// receives the response or a classified failure.
    fn call(&self, req: &PlaneEgressRequest) -> Result<PlaneEgressResponse, PlaneError>;
}

/// **LAYER 2 — LLM/agentic family, and this is a DECISION not an oversight.**
///
/// `{pool, method, path, headers, body}` is an HTTP request. A packet-oriented plane forwards
/// packets and cannot use this shape at all; A2A's gRPC egress does not fit it comfortably either,
/// so the limitation is not hypothetical. The Layer 1 primitive underneath is a byte-channel egress
/// (`open_upstream(pool)`) with core applying the same SSRF guard, breaker and failover; this type is
/// the convenience form built on it for planes that really are speaking HTTP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlaneEgressRequest {
    /// The operator-configured pool this call routes through. A plane names a POOL, never a URL —
    /// which is what keeps the destination set operator-controlled and the SSRF guard meaningful.
    pub pool: String,
    pub method: String,
    /// Path and query, appended to the pool member's base. Never a full URL.
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// The admission receipt this call is made under, so core can attribute and charge it.
    pub grant: PlaneGrant,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlaneEgressResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// READ-ONLY VIEW of what this plane is configured to serve. A plane reads its own registrations
/// (tool names, agent ids, lanes) without holding the config types or the app state that own them.
pub trait PlaneCatalogue: Send + Sync {
    /// The registration names this plane serves, in operator-declared order.
    fn subjects(&self) -> Vec<String>;
    /// One registration's opaque settings, as the operator wrote them. Typed by the PLANE, exactly
    /// as its config section is.
    fn settings_for(&self, subject: &str) -> Option<String>;
}

/// SECRET RESOLUTION, fail-closed. A plane resolves an operator's secret REFERENCE to bytes without
/// ever holding the secret store, the vault handle or the resolution policy.
pub trait PlaneSecrets: Send + Sync {
    /// Resolve a config secret reference. The value is [`crate::Redacted`] so a plane cannot log it
    /// by accident — `Debug` and `Display` never print it.
    fn resolve(&self, reference: &str) -> Result<crate::Redacted<String>, PlaneError>;
}

/// METERING — report consumption against an admission.
///
/// **This capability exists because a VPN stress test found it missing, and MCP and A2A need it
/// too.** The original design assumed core would charge from the RESPONSE, which is only true when
/// there is a response — an LLM assumption baked in without noticing. A tool call charges per call, a
/// task charges per task, and a session charges per byte and per second; none of those is "read the
/// token count off the completion".
///
/// `unit` is the PLANE'S OWN vocabulary (`"tokens"`, `"bytes"`, `"seconds"`). Core owns the ledger,
/// the budget and the refusal — the plane reports what it consumed and does not decide what that
/// costs or whether it was affordable. Same division as everywhere else: the plane supplies the
/// payload, the core supplies the linkage.
///
/// LAYER 1 (universal). Nothing here is family-specific.
pub trait PlaneMetering: Send + Sync {
    /// Report `amount` of `unit` consumed under `grant`. Called after the work, not before —
    /// pre-admission budget refusal is [`PlaneGovernance::admit`]'s job.
    fn charge(&self, grant: &PlaneGrant, unit: &str, amount: u64) -> Result<(), PlaneError>;
}

/// TELEMETRY, kind-stamped. Core prefixes every series with the plane's key, so a plane can neither
/// collide with a first-party series nor forge another plane's metrics.
pub trait PlaneMetrics: Send + Sync {
    fn counter(&self, name: &str, value: u64, labels: &[(&str, &str)]);
    fn histogram(&self, name: &str, value: f64, labels: &[(&str, &str)]);
}
