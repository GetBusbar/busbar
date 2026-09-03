// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The NEUTRAL HOST SEAM — the trait a plane calls to reach the engine's host capabilities WITHOUT
//! naming a core type, and the lifecycle [`scope`] arena those capabilities register handles into.
//!
//! ## Why a trait object, not a `HostCtx`
//!
//! The HOT-lane ABI ([`busbar_plugin::hot`]) threads an opaque `HostCtx` (a `*mut c_void` aliasing a
//! stack `HostState` that borrows the live engine) through every host call. That pointer is `!Send`
//! and valid ONLY inside the synchronous frame that minted it — it MUST NOT be stored on a context
//! struct that crosses an `.await`. So the neutral seam a plane holds across async work CANNOT be "a
//! `HostCtx` on a ctx struct".
//!
//! [`EngineHost`] is that seam instead: an `Arc<dyn EngineHost>` a plane holds and calls typed, safe
//! methods on. Core implements it over its live `App`; each method mints the transient `HostCtx`
//! INTERNALLY, drives the relevant vtable slot SYNCHRONOUSLY, and returns an owned value — the raw
//! host pointer never escapes the call, so the trait object is freely `Send + Sync` and safe to carry
//! across `.await`. A core reach thereby becomes a Rust trait method with ZERO C-ABI impact.
//!
//! This seam begins with the CLOCK reaches; later stages append one method per remaining host reach
//! (gate-decide, govern-admit, breaker-admit, identity-admit, approval-redeem, …).

pub mod breaker;
// THE NEUTRAL LLM-RUNTIME BUILD CARRIER (1.6.0 money-path Phase 3-4 C): the single-compiled `PlaneBuildInput`
// DTO `busbar-core`'s `appbuild` populates and hands to the LLM plane's `build_runtime` seam.
pub mod build_input;
// THE NEUTRAL READ-SIDE PROJECTION of a data-plane's routing tables (1.6.0 money-path Phase 3-4 B):
// the `EngineTablesView` trait + `LaneView` + the zero-plane `EMPTY_VIEW` the core scrape/discovery
// readers name so they need not move when the tables relocate into `busbar-llm`.
pub mod engine_view;
// The mTLS client-identity registry, the extra-root trust-anchor registry and the peer-certificate
// SPKI DER walk — PURE host-side TLS helpers (process-atomic registries + an RFC 5280 length-skip; no
// `App`, no engine, no FFI). They live here so the host egress chokepoint and the A2A plane both name
// one neutral home; core re-exports them under their historical `crate::plane_host::{identity,
// trust_anchor,spki}` paths.
pub mod identity;
pub mod scope;
pub mod spki;
pub mod trust_anchor;

use crate::breaker::CanonicalSignal;
use crate::plane::approvals::Sealer;
use crate::plane::calllog::CallInput;
pub use crate::plane_host::build_input::{
    AffinityInput, AuthStyleInput, BreakerInput, ClientSettingsInput, FailoverInput, HealthInput,
    HealthModeInput, LaneInput, OnExhaustedInput, PlaneBuildInput, PoolInput, PoolMemberInput,
    TripInput, TripModeInput,
};
pub use crate::plane_host::engine_view::{
    EmptyEngineTablesView, EngineTablesView, LaneView, EMPTY_VIEW,
};
pub use crate::plane_host::scope::{DispatchScope, DurableScope, SessionScope};
use crate::store::Unavailable;
use crate::trust::validate::{Lapsed, Standing};
use crate::trust::TrustState;
use busbar_api::{AuthPrincipal, IdentityRefusal, PlaneRequestCtx, VirtualKey};
use busbar_plugin::hot::{AdmissionId, Signal, StatusClass};
use std::sync::Arc;

/// The outcome of a refusal-fidelity admit driven over the host `govern_admit_reason` seam.
#[cfg_attr(not(any(feature = "dispatch", feature = "relay")), allow(dead_code))]
pub enum GovAdmit {
    /// Admitted — the RAII grant is registered in the arena the caller passed.
    Admitted,
    /// A limit blocked — the RENDERED reason (byte-identical to the plane's own
    /// `format!("{blocked:?}")`) and the block's recovery floor in whole seconds.
    Blocked {
        /// The rendered reason bytes the host copied out (the exact `{blocked:?}` the plane surfaces).
        reason: String,
        /// The recovery floor in whole seconds (`0` when the block does not self-recover / never rolls).
        retry_after_secs: u64,
    },
}

/// The verdict of a request-admission gate fired over the host `gate_decide` seam.
#[cfg_attr(not(any(feature = "dispatch", feature = "relay")), allow(dead_code))]
pub enum GateOutcome {
    /// No gate objected (or none is attached) — the request proceeds.
    Proceed,
    /// A gate refused the request. Reconstructed from the `GateVerdictOut` header + the copied-out
    /// buffers, byte-identical to the in-process `GateVerdict::Reject`.
    Reject {
        /// The hook's refusal status, already clamped to the 4xx band by the gate.
        status: u16,
        /// The hook's own refusal message (empty on a fail-closed refusal).
        message: String,
        /// The transport/policy name, for the audit row and the log line (empty on a fail-closed refusal).
        hook: String,
    },
}

/// The verdict of a request-admission TRANSFORM (`prompt: rw` rewrite) chain fired over the host
/// `transform_over` seam — the TAP/observe-transform half of the hook surface, the twin of
/// [`GateOutcome`] for the rewrite pass. When no rewrite hook is attached the plane never calls the
/// seam (it guards on [`AdmissionHost::tap_attached`]), so the request/response path is BYTE-IDENTICAL
/// to a deployment with the seam absent: the tap is a no-op absent hooks.
#[cfg_attr(not(any(feature = "dispatch", feature = "relay")), allow(dead_code))]
pub enum TransformVerdict {
    /// The transform chain ran. `args_json` is the (possibly rewritten) payload the plane should send
    /// upstream; `applied` is `true` IFF a hook actually committed a rewrite (so the plane can keep
    /// its original bytes untouched — and therefore byte-identical — when no rewrite landed, even
    /// though a chain of purely-abstaining hooks fired). Reconstructed byte-for-byte from the same
    /// serde_json round-trip the gate seam uses (`preserve_order` OFF ⇒ a `Value` object is a
    /// sorted-stable `BTreeMap`).
    Proceed {
        /// Whether ANY hook in the chain committed a rewrite to the payload.
        applied: bool,
        /// The payload bytes to send upstream — the rewritten `arguments`/`params` when `applied`, or
        /// a faithful re-serialization of the original otherwise (the plane uses its own bytes then).
        args_json: Vec<u8>,
    },
    /// A `prompt: rw` gate REJECTED the request on the transform path (reject > rewrite > abstain).
    /// Same clamped/sanitized semantics as a decide-path reject, reconstructed identically to
    /// [`GateOutcome::Reject`].
    Reject {
        /// The hook's refusal status, already clamped to the 4xx band.
        status: u16,
        /// The hook's own refusal message (empty on a fail-closed refusal).
        message: String,
        /// The transport/policy name, for the audit row and the log line (empty on a fail-closed refusal).
        hook: String,
    },
}

/// What could be established about a presented bearer's RFC 8707 audience binding — the outcome of
/// the host `identity_audience_binding` pre-filter, for credentials busbar did not mint.
///
/// Relocated here from `busbar_core::auth::audience` so a plane reads the pre-filter verdict without
/// naming the core auth module; the binding JUDGEMENT (which reaches core's governance token prefix)
/// stays core behind [`EngineHost::identity_audience_binding`]. Core re-exports this at
/// `crate::auth::audience::Binding`, so its own callers and the enum's variants are unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AudienceBinding {
    /// A busbar-signed token. The real audience check happens in the verifier, which has the
    /// signature and the claims; the pre-filter must not pre-judge it.
    Deferred,
    /// A JWT whose `aud` includes the expected value. Not an admission — the chain still verifies it.
    Bound,
    /// A JWT whose `aud` does not include the expected value, or which carries no `aud` at all. Both
    /// are refused for the same reason: minted for someone else, or for nobody in particular.
    Mismatch,
    /// Not a JWT and not a busbar token: nothing to read. Refused.
    Opaque,
}

/// The raw wire outcome of a host-driven completion: the pipeline's HTTP status and body bytes,
/// for the plane to shape into its protocol's own result. Neutral — no axum `Response`, no `App`.
#[cfg_attr(not(any(feature = "dispatch", feature = "relay")), allow(dead_code))]
pub struct HostCompletion {
    /// The pipeline's HTTP status.
    pub status: u16,
    /// The pipeline's response body bytes (bounded by the `max_body_bytes` the caller passed).
    pub body: bytes::Bytes,
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// THE GAUNTLET SEAM — one shared request sequence every protocol plane rides.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// The neutral per-request facts of ONE gauntlet traversal that the SHARED sequence
/// ([`run_gauntlet`]) reads and threads — the resolved identity, the destination the pre-admission
/// verify judges, and the correlation/timing a plane's stage-6 record joins on. Everything protocol-
/// or dialect-specific (the parsed body, the dialect handler, the wire framing, the plane's engine)
/// lives in the plane's own [`GauntletPlane`] value, NEVER here — so this names no plane type.
pub struct GauntletRequest<'a> {
    /// Stage 1 — the resolved caller identity/scope, threaded from the auth layer that ran upstream.
    pub gov: &'a busbar_api::PlaneRequestCtx,
    /// The destination key the pre-admission `verify_destination` judges — a model for the LLM plane,
    /// a tool/server for the MCP plane. Opaque to the shared sequence; each plane spells its meaning.
    pub destination: &'a str,
    /// The per-request correlation id the plane's stage-6 audit record joins on (single-accounting).
    pub correlation_id: u64,
    /// The header-arrival epoch (whole seconds) the request was admitted at — the metering window base.
    pub charged_at: u64,
    /// The monotonic start instant for the request-duration metric.
    pub started: std::time::Instant,
}

/// The outcome of the pre-admission destination verification (stage 2).
pub enum VerifyOutcome {
    /// The destination is permitted; the sequence proceeds to the plane's `drive`.
    Proceed,
    /// The destination is refused. The plane returns its OWN already-finished, protocol-native
    /// response (metrics/webhook already emitted plane-side); [`run_gauntlet`] returns it verbatim,
    /// so refusal shaping stays byte-identical to the plane's in-place rejection.
    Refuse(axum::response::Response),
}

/// A protocol plane's contribution to the shared gauntlet: the pre-admission destination check
/// (stage 2, sync) and the byte-identical engine that admits, routes, meters and finishes the
/// request (stages 4+5, async). The SHARED sequence ([`run_gauntlet`]) owns only stage 1 (identity,
/// already resolved and threaded via `req.gov`) and the stage-2→drive ORDER — verify strictly before
/// any charge, so nothing can reject an already-charged request. The sequence pulls NOTHING out of
/// `drive`: the plane's admission/route/metering/finish stay inside it, byte-identical. Names are
/// neutral; a plane implements this in its own crate (`busbar-mcp`/`busbar-a2a`) or in core (the LLM
/// native plane) identically — they are siblings on this one seam.
#[async_trait::async_trait]
pub trait GauntletPlane: Send + Sync {
    /// STAGE 2 — pre-admission destination verification. Sync; runs BEFORE `drive`. `Proceed` clears
    /// the request to admission; `Refuse` carries the plane's OWN finished, protocol-native rejection.
    fn verify_destination(&self, req: &GauntletRequest<'_>) -> VerifyOutcome;

    /// STAGES 4+5 — the plane's OWN engine: budget-admission, route/failover, egress, and the plane's
    /// own metering, returning the (possibly streaming) response. Byte-identical to the plane's
    /// in-place dispatch. Takes `self: Box<Self>` so the plane moves its owned per-request payload
    /// (body/parsed form/grant) into the engine; object-safe, so `run_gauntlet` drives it as `dyn`.
    async fn drive(self: Box<Self>, req: GauntletRequest<'_>) -> axum::response::Response;
}

/// The successful OPEN-PASS ADMISSION result of [`admit_open`] — the request cleared the verify-before-
/// charge gate. Carries the per-request `correlation_id` so a SESSION opener ([`run_gauntlet_session`])
/// can join its own later durable/audit rows on it. A one-shot [`run_gauntlet`] discards it and proceeds
/// straight to `drive`; a session opener returns it to the plane, which then reserves/binds/opens its
/// live carrier AFTER (nothing charged before the gate cleared).
#[cfg_attr(not(any(feature = "dispatch", feature = "relay")), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Admitted {
    /// The per-request correlation id the caller threads into its stage-6 / durable-session record.
    pub correlation_id: u64,
}

/// THE ONE OPEN-PASS ADMISSION GATE both gauntlet siblings share — the pre-admission `verify_destination`
/// (stage 2) in its correct verify-STRICTLY-before-charge position, so NOTHING may reject an already-
/// charged request. Returns [`Admitted`] on `Proceed`, or the plane's OWN finished, protocol-native
/// refusal on `Refuse` (returned verbatim so refusal shaping stays byte-identical to the plane's in-place
/// rejection). A pure factor-out: the shared verify order lives HERE once, so [`run_gauntlet`] (the
/// one-shot Response path) and [`run_gauntlet_session`] (the duplex session opener) can never drift on
/// it. The plane's OWN govern/breaker/charge stay inside its `drive` (run_gauntlet) or its post-admit
/// reserve/bind/open (the session) — this gate owns only the ORDER, matching the LLM plane's real
/// verify-before-admission-door sequence.
///
/// (`result_large_err`: the `Err` is the plane's OWN finished refusal `Response`, carried BY VALUE so
/// refusal shaping stays byte-identical to [`run_gauntlet`]'s verbatim return — the same type that path
/// returns un-boxed. Boxing it here to shrink the cold refuse path would diverge the two siblings.)
#[allow(clippy::result_large_err)]
fn admit_open(
    req: &GauntletRequest<'_>,
    plane: &(dyn GauntletPlane + '_),
) -> Result<Admitted, axum::response::Response> {
    match plane.verify_destination(req) {
        VerifyOutcome::Refuse(resp) => Err(resp),
        VerifyOutcome::Proceed => Ok(Admitted {
            correlation_id: req.correlation_id,
        }),
    }
}

/// THE SHARED GAUNTLET SEQUENCE — the ONE request path every protocol plane rides. Stage 1 identity
/// is already resolved (threaded via `req.gov`); this runs the shared [`admit_open`] gate (the plane's
/// `verify_destination`, stage 2) in the correct PRE-ADMISSION position and, only if it proceeds, the
/// plane's `drive` (stages 4+5, its own byte-identical engine + metering). Returns the plane's (possibly
/// streaming) response verbatim. The plane owns admission/route/metering/finish; the sequence owns solely
/// the verify-before-admit order (nothing may reject after a charge) — so all planes enforce that
/// invariant in ONE place rather than each re-implementing it.
pub async fn run_gauntlet(
    req: GauntletRequest<'_>,
    plane: Box<dyn GauntletPlane + '_>,
) -> axum::response::Response {
    match admit_open(&req, &*plane) {
        Err(resp) => resp,
        Ok(_admitted) => plane.drive(req).await,
    }
}

/// THE SESSION SIBLING of [`run_gauntlet`] — the OPEN-PASS admission for a live, session-oriented plane
/// (voice/duplex) that has no one-shot `drive`-shaped Response to return. It runs the SAME shared
/// [`admit_open`] gate (verify STRICTLY before any charge) and returns the [`Admitted`] result instead of
/// driving a request: the plane's own reserve/bind/open + socket bind proceed only on `Ok`, so a `Refuse`
/// costs ZERO bytes and ZERO charge (nothing opened before the gate cleared). Distinct from
/// [`run_gauntlet`] (one Response) but a TRUE sibling — they share `admit_open`, so a refactor can neither
/// inline nor foreclose this opener, and both enforce the one verify-before-charge order.
///
/// Synchronous: the admission gate is `verify_destination` (sync), so a session opener (a sync
/// `begin_session`) calls this directly — there is no async `drive` leg on the session path.
///
/// (`result_large_err`: the `Err` is the plane's OWN finished refusal `Response`, carried BY VALUE so
/// refusal shaping stays byte-identical to [`run_gauntlet`]'s verbatim return — boxing it would diverge
/// the two siblings on the type they carry a refusal in.)
#[allow(clippy::result_large_err)]
pub fn run_gauntlet_session(
    req: GauntletRequest<'_>,
    plane: Box<dyn GauntletPlane + '_>,
) -> Result<Admitted, axum::response::Response> {
    admit_open(&req, &*plane)
}

/// The `plane_slots` companion key under which a plane's ALWAYS-PRESENT per-generation runtime object
/// is carried — DERIVED from the plane's own decl `key` by the neutral `"<key>:runtime"` convention,
/// so core spells no plane token. It is deliberately distinct from the plane's config-conditional
/// dispatch slot (carried under the bare decl key): the runtime bundle exists on every generation
/// whereas the dispatch slot is absent when the plane's config block is unspecified, so folding them
/// onto one key would change the bare key's presence semantics (and the dispatch table `build_dispatch`
/// derives from it). Named by both core's `appbuild` (which composes the slot) and the owning plane
/// (which reads it back through [`EngineHost::plane_slot`]) — each passes its decl key and gets the
/// SAME interned `&'static str`, so it lives in the neutral substrate rather than either crate.
///
/// Interned process-lifetime (leaked once per distinct key, bounded by the plane count) so the
/// companion key is a stable `&'static str` fit for the `plane_slots` map's key type without either
/// caller holding a hard-coded literal.
pub fn runtime_slot_key(plane_key: &str) -> &'static str {
    static INTERNED: std::sync::Mutex<std::collections::BTreeMap<String, &'static str>> =
        std::sync::Mutex::new(std::collections::BTreeMap::new());
    let composed = format!("{plane_key}:runtime");
    let mut interned = INTERNED.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(k) = interned.get(&composed) {
        return k;
    }
    let leaked: &'static str = Box::leak(composed.clone().into_boxed_str());
    interned.insert(composed, leaked);
    leaked
}

/// A source of freshly live-bound hosts: each call returns a host reading the current snapshot,
/// so a config swap between calls is seen. Handed to transports that re-mint per frame.
pub type LiveHostFactory = std::sync::Arc<dyn Fn() -> std::sync::Arc<dyn EngineHost> + Send + Sync>;

// ─────────────────────────────────────────────────────────────────────────────────────────────
// OPAQUE GOVERNANCE HANDLES (App-retype WEDGE 2) — the neutral carrier tokens a plane HOLDS on its
// per-request sink so the sink's field types stop naming `busbar_core::governance::GovState` /
// `busbar_core::cost::CostModel` / `busbar_core::governance::AdmitGrant`. Each wraps an
// `Arc<dyn Any + Send + Sync>` the host minted over the concrete engine value; the plane never
// introspects it — it hands [`GovHandle`]/[`CostHandle`] BACK to the metering seams
// ([`EngineHost::meter_ledger`]/[`EngineHost::meter_series`]), which downcast host-side. This keeps
// the byte-identical `sink.gov`/`sink.cost` the plane minted (a custom test cost, the live app cost —
// whichever the sink was built from), NOT a re-read of the host snapshot.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// An OPAQUE, cheaply-cloned (one `Arc` bump) handle to the deployment's governance state — minted
/// host-side ([`EngineHost::governance`]) and consumed host-side ([`EngineHost::meter_ledger`] /
/// [`EngineHost::meter_series`]). The plane holds it on its per-request sink WITHOUT naming
/// `busbar_core::governance::GovState`.
#[derive(Clone)]
pub struct GovHandle(pub Arc<dyn std::any::Any + Send + Sync>);

/// The cost-model twin of [`GovHandle`] — an opaque handle to the resolved `CostModel` the sink was
/// built from, produced by [`EngineHost::cost`] and consumed by [`EngineHost::meter_ledger`].
#[derive(Clone)]
pub struct CostHandle(pub Arc<dyn std::any::Any + Send + Sync>);

/// An opaque handle to a governance ADMISSION grant (`AdmitGrant`), held DROP-ONLY on a plane's
/// per-request sink so the admission's in-flight concurrency holds release when the last sink clone
/// drops. The plane never introspects it; it exists purely so its `Drop` (on the last clone) releases
/// the gauges — byte-identical to the sink's current `Option<Arc<busbar_core::governance::AdmitGrant>>`.
#[derive(Clone)]
pub struct AdmitHandle(pub Arc<dyn std::any::Any + Send + Sync>);

/// BRAKE (audit D): the BREAKER-family slice of the host seam, split off `EngineHost` as a supertrait
/// so the circuit-breaker admission/settle/record cluster stays a cohesive, bounded ABI rather than
/// dissolving into the ~30-method god-trait. Groups the five `(pool, lane)` breaker seams a plane's
/// dispatch/failover legs drive: win a probe ([`breaker_admit`](Self::breaker_admit)), fold a leg's
/// outcome ([`breaker_settle`](Self::breaker_settle)), the in-place record fallbacks
/// ([`breaker_record_success`](Self::breaker_record_success) /
/// [`breaker_record_signal`](Self::breaker_record_signal)), and the cooldown read
/// ([`breaker_retry_after_secs`](Self::breaker_retry_after_secs)). PURE STRUCTURAL: every method keeps
/// its exact signature and same-dispatch body; a plane that names `EngineHost` still calls these
/// through the inherited supertrait bound.
pub trait BreakerHost: Send + Sync {
    /// WIN ONE `(pool, lane)` breaker probe through the host `breaker_admit` seam, leaving the
    /// settle-capable admission REGISTERED in `scope`'s arena and returning the POD [`AdmissionId`] —
    /// or the store's own [`Unavailable`] refusal. Identical to
    /// `busbar_core::plane_host::breaker::breaker_admit_over`.
    fn breaker_admit(
        &self,
        scope: &DispatchScope,
        pool: &[u8],
        lane: u32,
    ) -> Result<AdmissionId, Unavailable>;

    /// Fold a leg's classified outcome through the host `breaker_settle` seam over `admission` (looked
    /// up in `scope`'s arena). `Ok` means the live admission was found and settled; a `Gone` means it
    /// was already settled — the caller falls back to an in-place record. Byte-identical disposition
    /// to the plane's own `record_signal`/`record_success`.
    fn breaker_settle(
        &self,
        scope: &DispatchScope,
        admission: AdmissionId,
        signal: &Signal,
    ) -> StatusClass;

    /// Record a SUCCESS against the `(pool, lane)` breaker cell in place — the fallback a settle leg
    /// takes when no arena owns the probe (or a multi-round leg whose probe was already settled).
    /// Identical to the plane's own `PlaneBreakers::record_success`.
    fn breaker_record_success(&self, pool: &str, lane: usize);

    /// Record a canonical failure signal against the `(pool, lane)` breaker cell in place — the
    /// fallback twin of [`breaker_record_success`](Self::breaker_record_success). Identical to the
    /// plane's own `PlaneBreakers::record_signal`.
    fn breaker_record_signal(&self, pool: &str, lane: usize, sig: &CanonicalSignal);

    /// The seconds until the `(pool, lane)` breaker cell's cooldown expires — the honest `Retry-After`
    /// for a refused pooled dispatch, read PER MEMBER so a pool whose members trip independently
    /// answers with the soonest. Identical to the plane's own `PlaneBreakers::retry_after_secs`; a
    /// pure read, so it needs no `HostCtx`.
    fn breaker_retry_after_secs(&self, pool: &str, lane: usize) -> u64;
}

/// BRAKE (audit D): the LANE/POOL-family slice of the host seam, split off `EngineHost` as a supertrait
/// so the lane-runtime + pool-membership + probe-default cluster stays a cohesive, bounded ABI. Groups
/// the five seams a plane's routing/health machinery reads: the neutral breaker/lane store view
/// ([`lane_store`](Self::lane_store)), the two process-wide active-probe fallbacks
/// ([`default_probe_interval_secs`](Self::default_probe_interval_secs) /
/// [`default_probe_timeout_secs`](Self::default_probe_timeout_secs)), and the failover-pool membership
/// resolvers ([`tool_pool_members`](Self::tool_pool_members) /
/// [`plane_pool_members`](Self::plane_pool_members)). PURE STRUCTURAL: signatures and bodies are
/// unchanged; a plane that names `EngineHost` reaches these through the inherited supertrait bound.
pub trait LanePoolHost: Send + Sync {
    /// The breaker/lane store this deployment routes through, as the NEUTRAL
    /// [`busbar_substrate::store::LaneRuntime`](crate::store::LaneRuntime) view — the seam the engine's
    /// `app.store` reads (select/health/pipeline lane admit/settle/snapshot) resolve to WITHOUT naming
    /// core's `state::App`. A pure borrow of the bound snapshot's store, no `HostCtx`; the returned
    /// `&dyn LaneRuntime` shares the live in-memory breaker engine, identical to `&*App::store`.
    ///
    /// WEDGE 2 (App-retype): additive — the transitional seam the wedge-3 `app.store → host.lane_store()`
    /// flip targets. The `LaneRuntime` trait already lives in substrate (wedge 1), so this names no core type.
    fn lane_store(&self) -> &dyn crate::store::LaneRuntime;

    /// The process-wide active-probe INTERVAL fallback (whole seconds) a lane with no
    /// `health.interval_secs` inherits — the host-read form of `busbar_core::limits::default_probe_interval_secs`.
    /// A pure read of the live limits registry, no `HostCtx`; byte-identical to that free fn.
    ///
    /// WEDGE 2 (App-retype): additive — the seam the wedge-3 `health.rs` probe-spawn flip targets. The
    /// limits fns read core's runtime `LIMITS` global, so they CANNOT relocate to substrate by-identity;
    /// this host seam is the neutral home instead.
    fn default_probe_interval_secs(&self) -> u64;

    /// The process-wide active-probe TIMEOUT fallback (whole seconds) a lane with no `health.timeout_secs`
    /// inherits — the host-read twin of [`default_probe_interval_secs`](Self::default_probe_interval_secs).
    /// Byte-identical to `busbar_core::limits::default_probe_timeout_secs`.
    fn default_probe_timeout_secs(&self) -> u64;

    /// The `(pool_name, members, repeatable)` of the `tool_pools:` failover pool `server` belongs to,
    /// off the BOUND snapshot; `None` when `server` is un-pooled. `repeatable` is the pool's
    /// `repeatable:` operation list (what `CandidatePoolCfg::repeatability` consults). Identical to
    /// scanning `App::tool_pools`.
    fn tool_pool_members(&self, server: &str) -> Option<(String, Vec<String>, Vec<String>)>;

    /// The `(pool_name, members)` of the failover pool `member` belongs to on the plane identified by
    /// the opaque registry `plane_key`, off the BOUND snapshot; `None` when `member` is un-pooled. The
    /// member-selection walk derives each candidate's lane from the member's position in the returned
    /// list, so name + members is the whole seam. Identical to scanning the plane's pool map.
    fn plane_pool_members(&self, plane_key: &str, member: &str) -> Option<(String, Vec<String>)>;
}

/// An OPAQUE handle to ONE open host-owned reserve-then-settle cost lease, minted by
/// [`MeteringHost::cost_reserve`] and handed back to [`MeteringHost::cost_settle`] /
/// [`cost_settled`](MeteringHost::cost_settled) / [`cost_close`](MeteringHost::cost_close). The
/// reserve/settled/cap money state lives HOST-side behind this id; only the `u64` handle crosses the
/// seam. Substrate-native (not the frozen hot-ABI POD) so the neutral seam stays independent of the
/// C-ABI, though the two are structurally the same `u64` handle.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CostLeaseId(pub u64);

impl CostLeaseId {
    /// The reserved sentinel a REFUSED reserve reads as — never a live lease (ids are minted `≥ 1`).
    pub const NONE: CostLeaseId = CostLeaseId(0);
}

/// The post-settle state [`MeteringHost::cost_settle`] reads back — the neutral twin of the hot-ABI
/// `CostSettleOut.exhausted` flag. A live carrier reads `exhausted` after each settle and HARD-CLOSES
/// the instant it is set (`settled ≥ cap`), the one thing post-hoc metering structurally cannot do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SettleOutcome {
    /// Whether the caller's budget is now DRY (`settled ≥ cap`) — the carrier must hard-close.
    pub exhausted: bool,
}

/// BRAKE (minor-19): the METERING-LEASE slice of the host seam, split off `EngineHost` as a supertrait
/// so the reserve-then-settle cost-lease cluster stays a cohesive, bounded ABI rather than swelling the
/// god-trait. It gives a statically-linked plane (a live voice/stream carrier a plane cannot price after
/// the fact) the SAME reserve-then-settle lease the hot-ABI `cost_reserve`/`cost_settle` slots expose to
/// a dlopen plane — reachable as a plain Rust trait method rather than the C-ABI vtable, so a compiled-in
/// plane meters a live carrier CONTINUOUSLY against the real grant/budget: open a lease over
/// already-priced nanodollars at session start, settle EXACT increments per turn, and read back
/// exhaustion so the carrier is hard-closed the moment `settled ≥ cap`.
///
/// Money-denominated end to end in `u128` nanodollars (1e-9 USD): core prices nothing, so the PLANE
/// hands already-priced amounts (see the design's `plane4-duplex-session.md` §2.5). `u128` is used directly here — `EngineHost` is
/// a plain Rust trait, NOT the frozen hot FFI, so it carries rich neutral types without the `u64`
/// narrowing the C-ABI slot demands; the host widens/narrows at its own boundaries.
pub trait MeteringHost: Send + Sync {
    /// OPEN a host-owned reserve-then-settle cost lease over ALREADY-PRICED nanodollars and return its
    /// opaque [`CostLeaseId`]. `estimate_nanos` is the coarse over-estimate debited up front,
    /// `fee_nanos` the once-per-lease flat session fee (`0` = none), and `cap_nanos` the TRUE budget
    /// ceiling exhaustion is judged against: `None` leaves the lease UNCAPPED (never exhausts);
    /// `Some(0)` is a REFUSE-ALL cap, DENIED at the door — the method returns `None` and the session
    /// must fail closed (never open). Any other `Some(cap)` opens a live lease.
    fn cost_reserve(
        &self,
        estimate_nanos: u128,
        fee_nanos: u128,
        cap_nanos: Option<u128>,
    ) -> Option<CostLeaseId>;

    /// ACCRUE one EXACT already-priced increment (`exact_nanos`) against the open lease `lease` and read
    /// back the post-settle [`SettleOutcome`]. The lease STAYS open after a settle — a live carrier keeps
    /// settling increments until it hard-closes. `None` iff `lease` names no open lease (unknown /
    /// already-closed / the [`CostLeaseId::NONE`] sentinel); on `None` the caller fails CLOSED and
    /// hard-closes the carrier, exactly as it would on `exhausted`.
    fn cost_settle(&self, lease: CostLeaseId, exact_nanos: u128) -> Option<SettleOutcome>;

    /// The total nanodollars SETTLED so far against `lease` — the audit tap the caller journals (and the
    /// tests assert). `None` for an unknown / already-closed lease.
    fn cost_settled(&self, lease: CostLeaseId) -> Option<u128>;

    /// CLOSE and forget the lease `lease`, returning its finalize()'d ledgered total (the exact settled
    /// sum — never the coarse reserve). `None` for an unknown / already-closed lease. Idempotent: a
    /// second close reads `None`. Bounds the host registry so a finished carrier's lease does not leak.
    fn cost_close(&self, lease: CostLeaseId) -> Option<u128>;

    /// PRICE a plane's neutral [`billing::Usage`](crate::billing::Usage) for `model` into nanodollars
    /// via the deployment's rate card — the SAME `CostModel` arithmetic the LLM enforcement/derive path
    /// uses (a new ENTRY POINT over the same function, so the LLM money path is byte-for-byte untouched).
    /// A live carrier a plane cannot price after the fact folds each turn's usage_units and calls this to
    /// get the already-priced nanodollar increment it then hands to [`cost_settle`](Self::cost_settle),
    /// so the plane stays PLANE-NEUTRAL (it never names core's pricer) yet meters against the real rates.
    ///
    /// Semantics mirror the host's per-model rate lookup exactly:
    /// - no rate card configured ⇒ `Some(0)` (pricing off — every model prices at 0, as core does);
    /// - card present, `model` priced ⇒ `Some(nanos)`;
    /// - card present, `model` UNKNOWN ⇒ `None` — the caller FAILS CLOSED (an unpriced passthrough model
    ///   must not meter as free).
    ///
    /// Amounts are u128 nanodollars — the plain-Rust neutral seam carries the rich type directly (unlike
    /// the frozen hot FFI). Core prices nothing of its own here: it projects the caller's already-mapped
    /// reserved-unit counts through the configured rate card, the one authoritative cost source.
    fn price_usage(&self, model: &str, usage: &crate::billing::Usage) -> Option<u128>;
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// CAPABILITY SLICES (M4 god-trait split) — the residual flat host seam, cut into cohesive capability
// supertraits so a plane depends ONLY on the slices it uses. `EngineHost` is the SUM (a supertrait of
// every slice), so an existing `Arc<dyn EngineHost>` caller is unaffected — it still reaches every
// method through the inherited bound — while a plane that needs a narrower capability (a voice/bytes
// port that must NOT name LLM-only `synthesize_completion`) can take `&dyn SliceX` instead. PURELY
// STRUCTURAL: every method keeps its exact signature, doc and same-dispatch body; nothing moves in the
// wire/ABI/money plane. The single `EngineHostImpl` (busbar-core) implements each slice.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// The CLOCK slice: the host wall-clock reads a plane's timing/window arithmetic needs, in whole
/// seconds and milliseconds. Split off `EngineHost` as a supertrait; a plane that only needs the
/// clock can take `&dyn ClockHost`.
pub trait ClockHost: Send + Sync {
    /// Read the host wall clock in whole SECONDS through the `clock_now` seam — the host-driven form
    /// of a plane's in-place seconds clock. Identical to `busbar_core::plane_host::clock_now_secs_over`.
    fn clock_now_secs(&self) -> u64;

    /// Read the host wall clock in MILLISECONDS through the `clock_now` seam — the host-driven form of
    /// a plane's in-place millis clock. Identical to `busbar_core::plane_host::clock_now_ms_over`.
    fn clock_now_ms(&self) -> u64;
}

/// The TELEMETRY slice: the plane-labelled metric emits a plane fires to close a request out and to
/// count its dispatch/failover/translation events, plus the `pool_label` cardinality bound every emit
/// path runs first. Split off `EngineHost` as a supertrait; each emit is snapshot-scoped, no `HostCtx`.
pub trait TelemetryHost: Send + Sync {
    /// Stamp the plane-labelled request-completion metric family for a MOUNTED plane through the host.
    /// A neutral trait seam: the plane hands its own `(plane, ingress_protocol, pool, outcome, seconds)`
    /// and the host records the completion, so the plane never names core's engine snapshot to close a
    /// request out. Identical to `busbar_core::telemetry::request_finished` over the bound snapshot.
    fn request_finished(
        &self,
        plane: &str,
        ingress_protocol: &str,
        pool: &str,
        outcome: &'static str,
        seconds: f64,
    );

    /// Count ONE dispatch ATTEMPT on `(pool_label, lane)` — the `busbar_upstream_attempts_total`
    /// upstream-attempt metric — through the host, so the engine emits it without naming core's
    /// telemetry module. `pool_label` is the bounded metric label (a named pool, or the routed model
    /// name for the default `""` cell); `lane` is the lane index the host resolves the `lane` label
    /// from off the bound snapshot. A pure snapshot-scoped metric emit, no `HostCtx`; identical to
    /// `busbar_core::telemetry::upstream_attempt` over the bound snapshot.
    fn telemetry_upstream_attempt(&self, pool_label: &str, lane: usize);

    /// Count ONE classified upstream FAILURE on `(pool_label, lane)` by `disposition` — the
    /// `busbar_upstream_failures_total` metric — through the host. The telemetry twin of
    /// [`telemetry_upstream_attempt`](Self::telemetry_upstream_attempt); identical to
    /// `busbar_core::telemetry::upstream_failure` over the bound snapshot.
    fn telemetry_upstream_failure(&self, pool_label: &str, lane: usize, disposition: &'static str);

    /// Count ONE logical Closed→Open breaker TRIP on `(pool_label, lane)` — the
    /// `busbar_breaker_trips_total` metric — through the host. Identical to
    /// `busbar_core::telemetry::breaker_trip` over the bound snapshot.
    fn telemetry_breaker_trip(&self, pool_label: &str, lane: usize);

    /// Count ONE FAILOVER event on `pool_label` by `reason` — the `busbar_failovers_total` metric —
    /// through the host. Identical to `busbar_core::telemetry::failover` over the bound snapshot.
    fn telemetry_failover(&self, pool_label: &str, reason: &'static str);

    /// Count ONE cross-protocol TRANSLATION hop `from → to` — the `busbar_translations_total`
    /// metric — through the host. Both names come from the fixed protocol vocabulary, so the emit is
    /// snapshot-independent; identical to `busbar_core::telemetry::translation`.
    fn telemetry_translation(&self, from: &str, to: &str);

    /// Map a client-supplied model/name string to the BOUNDED `pool` metric label through the host:
    /// the string verbatim when it names a configured pool or by-model lane, else the fixed
    /// `"unresolved"` sentinel. Bounds the Prometheus label cardinality on every finish/webhook path.
    /// Identical to `busbar_core::ingress::pool_label` over the bound snapshot; the returned slice
    /// borrows `model` (or a `'static` sentinel), independent of the host.
    fn pool_label<'a>(&self, model: &'a str) -> &'a str;
}

/// The JOURNAL slice: the durable admin-audit / call-log emits a plane writes as a side effect of the
/// mutation it records. All fire-and-forget (a store miss never fails the recorded action). Split off
/// `EngineHost` as a supertrait.
pub trait JournalHost: Send + Sync {
    /// Emit ONE hostless admin-audit record `(action, resource, outcome, principal)` to the shared
    /// admin audit log. Fire-and-forget, loudly: a store write failure NEVER fails the mutation it
    /// records. Identical to `busbar_core::plane::auditlog::emit_admin_hostless_now` — this seam needs
    /// no `HostCtx`, so it is a plain forward to that engine (which stays unchanged in core).
    fn audit_emit(&self, action: &str, resource: &str, outcome: &str, principal: &str);

    /// Record ONE admin-audit event `(action, resource, outcome, principal)` through the IN-PROCESS
    /// ADMIN RING (`busbar_core::admin::audit::AUDIT::record_by`), which seals it into the retained ring
    /// AND cascades the SAME record onto the durable hostless journal seam. Distinct from
    /// [`audit_emit`](Self::audit_emit) (durable-only): this is the seam the DATA-plane egress
    /// audit-and-allow path (a dropped cross-dialect control) writes through, so the record lands in the
    /// in-process ring the egress audit-trail assertions read. `outcome` is a fixed vocabulary literal.
    ///
    /// WEDGE 3 (App-retype): the neutral home of the engine's `AUDIT.record_by(...)` reach.
    fn audit_record(&self, action: &str, resource: &str, outcome: &'static str, principal: &str);

    /// Emit ONE per-call record through the durable MCP call-log engine. The transient `HostCtx` the
    /// chain seam needs is minted INTERNALLY (a fresh per-call arena over the live engine — the append
    /// registers no host handle, so the arena choice is immaterial). Identical to
    /// `busbar_core::calllog::emit`.
    fn call_log_emit(&self, principal: &str, input: CallInput);

    /// The DEFERRED-SITE twin of [`call_log_emit`](Self::call_log_emit): emit through the
    /// HOSTLESS call-log path, for a client-leg site that has no `HostCtx` to open. Identical to
    /// `busbar_core::calllog::emit_hostless`.
    fn call_log_emit_hostless(&self, principal: &str, input: CallInput);
}

/// The MOUNT slice: the pure mount-table reads that shape an arrival's dialect and its pre-collapse
/// fallback error. Split off `EngineHost` as a supertrait; both are pure snapshot reads, no `HostCtx`.
pub trait MountHost: Send + Sync {
    /// The mount-aware dialect an answer to `path` is SHAPED in — the host-driven form of
    /// `busbar_core::ingress::native::envelope_dialect(App::planes.ingress_of(path))`. A pure snapshot
    /// mount-table read, no `HostCtx`.
    ///
    /// WEDGE 3 (App-retype — THE FLIP): the seam core's `ArrivalHost` impl reads instead of the dropped
    /// `ArrivalPayload::app`; the neutral `ArrivalPayload` now carries only the host, so this mount read
    /// crosses the host seam like every other.
    fn arrival_envelope_dialect(&self, path: &str) -> &'static str;

    /// The pre-collapse fallback error SHAPE by `path` — the host-driven form of
    /// `busbar_core::fallback_error_response(&App::planes, path, status, kind, message)`. Renders the
    /// unmatched-path/404 envelope in the dialect the deployment mounted `path` under; a pure snapshot
    /// mount-table read, no `HostCtx`. The twin of [`arrival_envelope_dialect`](Self::arrival_envelope_dialect).
    fn arrival_fallback_error(
        &self,
        path: &str,
        status: axum::http::StatusCode,
        kind: &str,
        message: &str,
    ) -> axum::response::Response;
}

/// The REGISTRY slice: the per-generation registry/snapshot reads a plane pulls off the bound (or
/// live) snapshot — its type-erased runtime slot, its type-erased defs, the request-id counter, the
/// neutral secret resolver, and the host-held card-signing key. Split off `EngineHost` as a supertrait.
pub trait RegistryHost: Send + Sync {
    /// Stamp the NEXT per-request correlation id — one relaxed `fetch_add` on the host-owned counter.
    /// Identical to `busbar_core::state::App::next_request_id` (the counter is boot-seeded and carried
    /// across config swaps, so the value is engine-snapshot independent).
    fn next_request_id(&self) -> u64;

    /// The plane's type-erased runtime object off the BOUND snapshot (the one this host was minted
    /// over), owned (an `Arc` clone) so it outlives the call. `None` when the plane contributed no
    /// slot under `key` this generation. Identical to `busbar_core::state::App::plane_slot(key)`
    /// cloned — a pure `plane_slots` map read, no `HostCtx` (mirrors [`next_request_id`]).
    ///
    /// [`next_request_id`]: RegistryHost::next_request_id
    fn plane_slot(&self, key: &str) -> Option<Arc<dyn std::any::Any + Send + Sync>>;

    /// The plane's slot off the CURRENT snapshot — re-reads the LIVE handle so a config swap AFTER
    /// this host was minted is seen (the dispatch-time re-validation / per-round revocation / watch
    /// loops depend on this). Falls back to the bound snapshot for a snapshot-only mint (one built
    /// without a live handle). A pure map read, no `HostCtx`.
    fn plane_slot_live(&self, key: &str) -> Option<Arc<dyn std::any::Any + Send + Sync>>;

    /// The deployment's NEUTRAL secret resolver, behind the `busbar_api::SecretResolve` seam, so a
    /// plane mints a delegation credential (and loads its outbound TLS PEM) WITHOUT naming the
    /// engine's concrete `SecretResolver`. A pure snapshot read of `App::secret_resolver`, no
    /// `HostCtx`; the returned `Arc<dyn SecretResolve>` shares the live resolver (built-ins plus any
    /// wired `kind: secret` plugin), fail-closed exactly as core resolution.
    fn secret_resolver(&self) -> Arc<dyn busbar_api::SecretResolve>;

    /// Sign a plane-framed agent-card signing input, returning the 64-byte Ed25519 signature (None
    /// when this deployment holds no card-signing key). The card subkey is derived and held HOST-side;
    /// only the bytes to sign cross in and only the signature crosses out — no key material reaches the
    /// plane. Mints its transient HostCtx internally over a fresh per-call DispatchScope, drives the
    /// slot synchronously, returns owned bytes — no HostCtx crosses an `.await`.
    fn card_sign(&self, signing_input: &[u8]) -> Option<[u8; 64]>;

    /// The deployment's type-erased plane definitions (`Arc<dyn Any + Send + Sync>` holding the
    /// per-plane config object the owning plane downcasts), off the BOUND snapshot — the
    /// `App::agent_defs` field that is NOT a `plane_slots` entry. Owned (an `Arc` clone) so it
    /// outlives the call; a pure snapshot read, no `HostCtx` (mirrors [`secret_resolver`](Self::secret_resolver)).
    fn agent_defs(&self) -> Arc<dyn std::any::Any + Send + Sync>;
}

/// The HOOK/CONFIG-FACADE slice (App-retype WEDGE 2d): the residual `busbar-llm` request-path reads off
/// the resolved hook/config facades — the rewrite/tap/gate chains, the routing policy, the requested-
/// signal bitmask and the group-membership walk. Each is a pure borrow of the bound snapshot tied to
/// `&self`, no `HostCtx`. Split off `EngineHost` as a supertrait; every borrow is byte-identical to the
/// `App::X` field read the wedge-3 flip targets.
pub trait HookConfigHost: Send + Sync {
    /// Whether `caller_group` sits within (any ancestor of) one of `hook_groups` — the group-membership
    /// walk a hook's `groups:` filter consults, resolved against this deployment's group registry.
    /// Identical to `busbar_core::config::caller_in_hook_groups(caller_group, hook_groups, &App::groups_registry)`;
    /// a pure tree walk over the bound snapshot's registry, no `HostCtx`.
    ///
    /// WEDGE 2 (App-retype): additive — the seam the wedge-3 `pipeline.rs` flip targets. Folding the
    /// `&App::groups_registry` argument HOST-side means the engine reads group membership without naming
    /// `busbar_core::config` or `App::groups_registry`.
    fn caller_in_hook_groups(&self, caller_group: Option<&str>, hook_groups: &[String]) -> bool;

    /// This pool's resolved REWRITE chain `(timeout, policy)` — the phase-1 transform hooks fired for
    /// requests routed to `pool`, empty (the default) ⇒ no pool rewrites. Byte-identical to
    /// `busbar_core::state::App::pool_rewrites(pool)`; a pure keyed map read, no `HostCtx`. The tuple is
    /// purely neutral (`Duration`, the [`RoutingPolicy`](busbar_api::RoutingPolicy) trait object — api).
    fn pool_rewrites(
        &self,
        pool: &str,
    ) -> &[(
        std::time::Duration,
        std::sync::Arc<dyn busbar_api::RoutingPolicy>,
    )];

    /// The GLOBAL (all-pools) rewrite chain `(timeout, policy)` fired in the phase-1 transform pass
    /// BEFORE any pool rewrites — the borrow of `App::rewrite_hooks`. Empty (the default) ⇒ no globals.
    /// Same neutral tuple shape as [`pool_rewrites`](Self::pool_rewrites).
    fn rewrite_hooks(
        &self,
    ) -> &[(
        std::time::Duration,
        std::sync::Arc<dyn busbar_api::RoutingPolicy>,
    )];

    /// Whether ANY registered hook holds a prompt-CONTENT grant (`prompt: ro`/`rw`) this generation —
    /// the deployment gate that decides whether the request IR is built for the hook seam. A single
    /// bool load of `App::any_content_hook`, byte-identical; `false` (the default) is the whole
    /// zero-cost-when-off property.
    fn any_content_hook(&self) -> bool;

    /// The GLOBAL request-stage `kind: tap` observers — the borrow of `App::tap_hooks`. Each
    /// [`TapEntry`](crate::hooks::TapEntry) is a neutral `(deadline, prompt-grant, transport, groups)`
    /// tuple. Held BY REF across the forward await-loop (the tap-fire pass reads it after each hop), so
    /// the borrow is deliberately tied to the stable host `&self`, not a per-call temporary.
    fn tap_hooks(&self) -> &[crate::hooks::TapEntry];

    /// The RESPONSE-stage tap observers — the borrow of `App::tap_hooks_response`. Same
    /// [`TapEntry`](crate::hooks::TapEntry) shape as [`tap_hooks`](Self::tap_hooks); fired once the
    /// upstream response outcome is known.
    fn tap_hooks_response(&self) -> &[crate::hooks::TapEntry];

    /// The ROUTING-stage tap observers — the borrow of `App::tap_hooks_routing`. Fired per failover hop
    /// with the routing/attempt projection; same [`TapEntry`](crate::hooks::TapEntry) shape.
    fn tap_hooks_routing(&self) -> &[crate::hooks::TapEntry];

    /// The CANDIDATE-stage tap observers — the borrow of `App::tap_hooks_candidate`. Fired once the
    /// decision reconcile has produced the final candidate set; same [`TapEntry`](crate::hooks::TapEntry)
    /// shape.
    fn tap_hooks_candidate(&self) -> &[crate::hooks::TapEntry];

    /// This pool's resolved DECISION GATES `(priority, policy)` in config order — the borrow of
    /// `App::pool_gates(pool)`. Empty ⇒ no pool gates. The [`ResolvedPolicy`](crate::hooks::ResolvedPolicy)
    /// carrier is already neutral substrate; a pure keyed map read, no `HostCtx`.
    fn pool_gates(&self, pool: &str) -> &[(u16, crate::hooks::ResolvedPolicy)];

    /// The GLOBAL decision gates `(priority, policy)` fired alongside the pool gates in the phase-2
    /// reconcile — the borrow of `App::global_gates`. Empty (the default) ⇒ the phase-2 pass is skipped.
    /// Same neutral `(u16, ResolvedPolicy)` shape as [`pool_gates`](Self::pool_gates).
    fn global_gates(&self) -> &[(u16, crate::hooks::ResolvedPolicy)];

    /// This pool's resolved routing POLICY, or `None` for the zero-cost weighted/SWRR default — the
    /// borrow of `App::pool_policy(pool)`. The [`ResolvedPolicy`](crate::hooks::ResolvedPolicy) is
    /// neutral substrate; a pure keyed map read, no `HostCtx`.
    fn pool_policy(&self, pool: &str) -> Option<&crate::hooks::ResolvedPolicy>;

    /// The config generation's declared-signal bitmask — the borrow of `App::requested_signals`. A
    /// single load of the neutral [`RequestedSignals`](crate::hooks::RequestedSignals) newtype the
    /// candidate-signal loop gates on (`requested.is_empty()` / `requested.wants(sig)`); the all-zero
    /// default short-circuits the whole loop. Byte-identical to the field read.
    fn requested_signals(&self) -> &crate::hooks::RequestedSignals;
}

/// The BUDGET/METERING slice: the money-path seams — the opaque gov/cost handle mints, the record-usage
/// / record-metering accruals, the reserve-then-charge meter, and the pure headroom/budget projections.
/// Split off `EngineHost` as a supertrait; the accrual seams downcast the opaque handles host-side and
/// drive the SAME accrual the plane's sink did, no `HostCtx`.
pub trait BudgetHost: Send + Sync {
    /// Whether governance is configured for this deployment. Identical to
    /// `busbar_core::state::App::governance.is_some()`.
    fn governance_enabled(&self) -> bool;

    /// Record ONE metered, attributed event through the host `meter_charge` seam over `scope`'s arena.
    /// `usage` carries the resolved `(key_id, model, provider)` attribution the host writes the cost row
    /// from; the transient `HostCtx` is minted over `scope` and consumed SYNCHRONOUSLY inside the call.
    /// Fire-and-forget: a store miss is not surfaced, exactly as the plane's in-place `record_metering`
    /// was. Identical to driving the `meter_charge` vtable slot under a `with_borrowed_host` over `scope`.
    fn meter_charge(&self, scope: &DispatchScope, usage: &busbar_plugin::hot::Usage);

    /// The per-caller RATE HEADROOM (min fraction of remaining request/token budget across the key's
    /// chain, `None` when unconstrained) — the host-driven form of
    /// `gov.rate_headroom(&app.cost, key, pool, now)`. `gov`/`cost` are the opaque handles the caller
    /// minted (via [`governance`](Self::governance)/[`cost`](Self::cost)); the host downcasts them to the
    /// concrete `GovState`/`CostModel` and drives the SAME pure observation (no cell mutation). No
    /// `HostCtx`. `key` is the already-neutral [`VirtualKey`](busbar_api::VirtualKey) (api).
    ///
    /// WEDGE 2 (App-retype): additive — the seam the wedge-3 `hooks.rs::decide_policy_order` `&app.cost`
    /// read flips onto (the `gov` object is already the sink's own via the handle, so byte-identical).
    fn rate_headroom(
        &self,
        gov: &GovHandle,
        cost: &CostHandle,
        key: &busbar_api::VirtualKey,
        pool: Option<&str>,
        now: u64,
    ) -> Option<f64>;

    /// The HOOK-seam budget projection for `key`: `{bucket_id, spend_at_current_rate, remaining, window}`
    /// per chain bucket, derived fresh from the token ledger × the current rate card — the host-driven
    /// form of `gov.budget_state(&app.cost, key, now)`. `gov`/`cost` are the opaque handles; the host
    /// downcasts and drives the SAME read. Returns the neutral
    /// [`BudgetBucketState`](busbar_api::BudgetBucketState) vec (empty when the key has no chain), built
    /// ONLY on a routing-policy pool. No `HostCtx`.
    ///
    /// WEDGE 2 (App-retype): additive — the twin of [`rate_headroom`](Self::rate_headroom) for the
    /// budget-chain projection the wedge-3 flip targets.
    fn budget_state(
        &self,
        gov: &GovHandle,
        cost: &CostHandle,
        key: &busbar_api::VirtualKey,
        now: u64,
    ) -> Vec<busbar_api::BudgetBucketState>;

    /// Mint the OPAQUE [`GovHandle`] for this deployment's governance state — `Some` iff governance is
    /// configured. One `Arc` bump, no `HostCtx`. Byte-identical to cloning `App::governance`; the plane
    /// holds the handle on its per-request sink and hands it back to the metering seams.
    ///
    /// WEDGE 2 (App-retype): additive — the neutral producer of the sink's `gov` field, so wedge 3 can
    /// retype `sink.gov: Arc<busbar_core::governance::GovState>` to [`GovHandle`].
    fn governance(&self) -> Option<GovHandle>;

    /// Mint the OPAQUE [`CostHandle`] for this deployment's resolved cost model — one `Arc` bump, no
    /// `HostCtx`. Byte-identical to cloning `App::cost`; the twin of [`governance`](Self::governance)
    /// for the sink's `cost` field.
    fn cost(&self) -> CostHandle;

    /// LEDGER one delivered response's tier-split token usage against the key's budget chain — the
    /// host-driven form of `sink.gov.record_usage(&sink.cost, key, pool, model, tokens, now)`. `gov`
    /// and `cost` are the opaque handles the sink minted (via [`governance`](Self::governance) /
    /// [`cost`](Self::cost)); the host downcasts them to the concrete `GovState`/`CostModel` and drives
    /// the SAME accrual. A no-op on an all-zero tier, exactly as `record_usage`. No `HostCtx`.
    ///
    /// WEDGE 2 (App-retype): additive — the seam the wedge-3 `usage.rs::ledger_and_meter` flip targets.
    #[allow(clippy::too_many_arguments)]
    fn meter_ledger(
        &self,
        gov: &GovHandle,
        cost: &CostHandle,
        key: &busbar_api::VirtualKey,
        pool: &str,
        model: &str,
        usage: &crate::billing::Usage,
        now: u64,
    );

    /// Record one delivered response's RAW consumption into the per-(key, bucket, model, provider)
    /// metering series — the host-driven form of
    /// `sink.gov.record_metering(key_id, model, provider, usage, now)`. `gov` is the opaque handle the
    /// sink minted; the host downcasts it and drives the SAME write-behind accrual (a zero-token
    /// response still counts its request). No `HostCtx`.
    ///
    /// WEDGE 2 (App-retype): additive — the seam the wedge-3 `usage.rs` metering flips target.
    fn meter_series(
        &self,
        gov: &GovHandle,
        key_id: &str,
        model: &str,
        provider: &str,
        usage: Option<&crate::billing::TokenUsage>,
        now: u64,
    );
}

/// The IDENTITY/TRUST slice: inbound identity resolution + the trust/approval seams around it — the
/// audience pre-filter, the auth-chain admit, the standing re-ask, the ask-state sealer derivation, the
/// drift quarantine settle, the one-time approval redeem, and the test-only token verifier. Split off
/// `EngineHost` as a supertrait. `#[async_trait]` because [`identity_admit`](Self::identity_admit) is
/// the one async method (it awaits a `spawn_blocking` join over the host auth chain).
#[async_trait::async_trait]
pub trait IdentityHost: Send + Sync {
    /// Settle a drift disposition for `subject` through the host `drift_quarantine` seam, pulling the
    /// demotion store host-side. Returns whether the slot answered `Ok`; the settle is
    /// fire-and-forget, so a non-`Ok` is a durability miss, not a refusal. Identical to
    /// `busbar_core::plane_host::trust::quarantine_settle_over`.
    fn quarantine_settle(&self, subject: &str, state: TrustState) -> bool;

    /// Redeem a one-time approval against the shared spent-approval ledger the host pulls, spending
    /// against the seal's own `expires_at` and the caller's `now`. `true` iff this is the FIRST
    /// redemption; `false` when already spent OR the durable ledger could not answer (fail-closed).
    /// Identical to `busbar_core::plane_host::trust::approval_redeem_q`.
    fn approval_redeem(&self, nonce: &str, expires_at: u64, now: u64) -> bool;

    /// TEST-ONLY raw-token → resolved `VirtualKey` resolution over this deployment's governance state
    /// (the data-plane boundary: no audience). The host-driven form of
    /// `App::governance.and_then(|g| g.verify_token(token, now, None))`, for the test paths that
    /// exercise the routing-policy seam WITHOUT building a full `PlaneRequestCtx` (production always
    /// threads a resolved key, so this never runs there). Gated to test / `test-support` builds so no
    /// production binary carries a raw-token verifier on the neutral seam.
    #[cfg(any(test, feature = "test-support"))]
    fn verify_token_test(&self, token: &str) -> Option<Arc<busbar_api::VirtualKey>>;

    /// Establish what can be established about a presented bearer's RFC 8707 audience binding against
    /// `expected_aud` — the fail-closed pre-filter a plane runs BEFORE the auth chain, for credentials
    /// busbar did not mint. A pure judgement (it reaches only core's governance token prefix, no live
    /// engine state), so it needs no `HostCtx`. Identical to `busbar_core::auth::audience::inspect_bearer`.
    fn identity_audience_binding(&self, token: &str, expected_aud: &str) -> AudienceBinding;

    /// Resolve INBOUND data-plane identity: run the configured auth chain + the ONE verdict resolution
    /// over the caller's OWN wire credential and the live governance state, returning the resolved
    /// `(AuthPrincipal, PlaneRequestCtx)` or the specific [`IdentityRefusal`]. Identical to
    /// `busbar_core::plane_host::identity_admit_over`.
    ///
    /// The ONE async method: the core impl awaits a `spawn_blocking` that mints AND consumes the
    /// `HostCtx` INSIDE the blocking closure, so the `!Send` pointer never crosses this `.await` and
    /// the future stays `Send`. Fail-closed: a join panic maps to [`IdentityRefusal::Denied`].
    async fn identity_admit(
        &self,
        token: Option<String>,
        audience: String,
        resource: String,
    ) -> Result<(AuthPrincipal, PlaneRequestCtx), IdentityRefusal>;

    /// RE-ASK a [`Standing`] permission against the LIVE governance registry: hand back the principal
    /// AS IT IS NOW, or the [`Lapsed`] reason it no longer stands. Injects the host's `GovState`
    /// (through the `GovResolve` seam) INTERNALLY, so the plane holds only the `Standing`. Identical to
    /// `Standing::still_permitted(app.governance, live, now)`.
    fn principal_standing(
        &self,
        standing: &Standing,
        live_gen: u64,
        now: u64,
    ) -> Result<Option<Arc<VirtualKey>>, Lapsed>;

    /// Derive this deployment's ask-state [`Sealer`] from governance's fleet-shared signing secret,
    /// WITHOUT the raw secret crossing to the plane. `None` when governance is disabled. Identical to
    /// `busbar_core::plane::approvals::ask_state_sealer(app.governance)` — the derivation stays core
    /// behind this seam.
    fn ask_state_sealer(&self) -> Option<Sealer>;
}

/// The ADMISSION slice: the request-admission gauntlet seams — the gate decision + presence pre-filter,
/// the governance admit-reason, the destination guard, the budget-admission door, the audience-bound
/// mount read, and the post-admission/not-charged finishes. Split off `EngineHost` as a supertrait.
pub trait AdmissionHost: Send + Sync {
    /// Fire the operator's REQUEST-ADMISSION hook gates over the host `gate_decide` seam and
    /// reconstruct the [`GateOutcome`]. Identical to `busbar_core::plane_host::gate_decide_over`:
    /// same reconstructed facts, same key identity, same gate decision. Drives the ASYNC gate on a
    /// fresh runtime, so it MUST be called from a BLOCKING thread (`spawn_blocking`).
    ///
    /// `plane_key` is the opaque registry key (the plane's stable decl key) the host resolves the
    /// gate set and the `ingress_protocol` label from. `key` is the caller's resolved `(id, name)`;
    /// `session_id` is the caller's session, `Some` only when non-empty.
    #[allow(clippy::too_many_arguments)]
    fn gate_decide(
        &self,
        plane_key: &str,
        container: &str,
        request_id: u64,
        tool: &str,
        args_json: &[u8],
        key: Option<(&str, &str)>,
        session_id: Option<&str>,
    ) -> GateOutcome;

    /// Cheap presence pre-filter: is any request-admission hook gate attached to `container` on the
    /// plane identified by the opaque registry `plane_key` (the plane's stable decl key)? Lets a plane
    /// skip the blocking `gate_decide` hop when nothing is attached. Identical to
    /// `App::plane_gates(plane_key).contains_key(container)`.
    fn gate_attached(&self, plane_key: &str, container: &str) -> bool;

    /// Cheap presence pre-filter for the TAP/TRANSFORM half: is any `prompt: rw` rewrite hook attached
    /// to `container` on the plane identified by the opaque registry `plane_key`? Lets a plane skip the
    /// blocking `transform_over` hop — and stay BYTE-IDENTICAL to a build without the seam — when
    /// nothing is attached. Identical to `App::plane_rewrites(plane_key).get(container).is_some()`.
    ///
    /// The presence check is the whole zero-cost guarantee: absent a rewrite hook a plane never
    /// serializes the payload, never spawns the blocking hop, and never touches its own bytes.
    fn tap_attached(&self, plane_key: &str, container: &str) -> bool;

    /// Fire the operator's REQUEST-ADMISSION TRANSFORM (`<section>.hooks:` `prompt: rw`) chain over the
    /// host `transform_over` seam and reconstruct the [`TransformVerdict`] — the TAP/observe-transform
    /// twin of [`gate_decide`](Self::gate_decide). The host re-selects the rewrite chain by
    /// `(plane_key, container)` (the Seam-B inversion: the plane body names no core hook symbol), builds
    /// the SAME `InvokeReq` projection the gate builds from `(tool, args_json)`, runs each hook's
    /// `transform` in priority order (each seeing the prior's output — a true transform chain), and
    /// returns the rewritten payload or a reject. Drives the ASYNC hooks on a fresh runtime, so it MUST
    /// be called from a BLOCKING thread (`spawn_blocking`), exactly like `gate_decide`.
    ///
    /// `plane_key`/`container`/`request_id`/`tool`/`args_json`/`key`/`session_id` carry the identical
    /// meaning they do on [`gate_decide`](Self::gate_decide).
    #[allow(clippy::too_many_arguments)]
    fn transform_over(
        &self,
        plane_key: &str,
        container: &str,
        request_id: u64,
        tool: &str,
        args_json: &[u8],
        key: Option<(&str, &str)>,
        session_id: Option<&str>,
    ) -> TransformVerdict;

    /// Admit one unit of work over the host `govern_admit_reason` seam, REGISTERING the RAII grant in
    /// `scope`'s arena on success and returning the RENDERED refusal reason on a blocked limit.
    /// Identical to `busbar_core::plane_host::govern_admit_reason_over`.
    fn govern_admit_reason(
        &self,
        scope: &DispatchScope,
        pool: &[u8],
        identity_id: &[u8],
        group: Option<&[u8]>,
    ) -> GovAdmit;

    /// STAGE 2 pre-admission DESTINATION guard through the host: the pool ACL, the fallback-pool ACL,
    /// and the all-or-nothing unpriced-model gate. `Ok(())` admits; `Err` is the already-finished,
    /// protocol-native rejection response (finished via the not-charged terminal). Identical to
    /// `busbar_core::ingress::destination_guard` over the bound snapshot + `gov` scope.
    fn destination_guard(
        &self,
        gov: &PlaneRequestCtx,
        proto: &'static str,
        pool: &str,
        started: std::time::Instant,
        charged_at: u64,
    ) -> Result<(), Box<axum::response::Response>>;

    /// STAGE 3–4 budget-admission door: charge the chain buckets for one request under `gov` on
    /// `pool`, returning the ADMISSION grant (as the opaque [`AdmitHandle`] the sink holds Drop-only)
    /// and any budget DOWNGRADE re-pool, or the already-finished not-charged rejection. Identical to
    /// `busbar_core::ingress::admission_door` over the bound snapshot; the returned `AdmitHandle`
    /// wraps the SAME `AdmitGrant` the in-place door produced, so `.is_some()` (charged?) and the
    /// gauge-releasing `Drop` are byte-identical. No `HostCtx` on this path.
    ///
    /// WEDGE 2 (App-retype): additive — the seam the wedge-3 `native_ingress::drive` flip targets
    /// (a host is already minted there). The `AdmitGrant`→[`AdmitHandle`] carrier-field retype
    /// (`response_body.rs` / `native_ingress.rs`) rides the same wedge-3 governance flip.
    fn admission_door(
        &self,
        gov: &PlaneRequestCtx,
        proto: &'static str,
        pool: &str,
        started: std::time::Instant,
        charged_at: u64,
    ) -> Result<(Option<AdmitHandle>, Option<String>), Box<axum::response::Response>>;

    /// POST-ADMISSION finish through the host: emit the per-request metric family + request-log
    /// webhook and, on a NON-2xx outcome, REFUND the flat per-request fee IFF it actually landed at
    /// admission (`charged`). Identical to `busbar_core::ingress::finish_admitted` over the bound
    /// snapshot + `gov` scope.
    #[allow(clippy::too_many_arguments)]
    fn finish_admitted(
        &self,
        gov: &PlaneRequestCtx,
        ingress_protocol: &str,
        pool: &str,
        started: std::time::Instant,
        charged_at: u64,
        resp: axum::response::Response,
        charged: bool,
    ) -> axum::response::Response;

    /// NOT-CHARGED (pre-charge turn-away) finish through the host: emit metrics + the webhook with NO
    /// refund, for a request rejected BEFORE the admission charge ever ran (governance guard denial or
    /// a pre-routing failure). Identical to `busbar_core::ingress::finish_rejected` over the bound
    /// snapshot + `gov` scope.
    #[allow(clippy::too_many_arguments)]
    fn finish_rejected(
        &self,
        gov: &PlaneRequestCtx,
        ingress_protocol: &str,
        pool: &str,
        started: std::time::Instant,
        charged_at: u64,
        resp: axum::response::Response,
    ) -> axum::response::Response;

    /// Whether the plane identified by the opaque registry `plane_key` is mounted under an
    /// AUDIENCE-BOUND door — the deployment gate a request path reads before it trusts an inbound
    /// audience claim. Identical to
    /// `App::planes.mount_of(plane_key).and_then(|m| App::planes.admission_for(m)).is_some()`. A pure
    /// snapshot read, no `HostCtx`.
    fn plane_audience_bound(&self, plane_key: &str) -> bool;
}

/// The COMPLETION slice — LLM-ONLY. The single seam that drives a non-streaming chat completion through
/// the resolved ingress pipeline. Split off `EngineHost` as a supertrait SPECIFICALLY so a non-LLM plane
/// (a voice/bytes port) is NOT forced to name it: such a plane takes the slices it uses and never sees
/// this one. `#[async_trait]` because [`synthesize_completion`](Self::synthesize_completion) is async.
#[async_trait::async_trait]
pub trait CompletionHost: Send + Sync {
    /// Synthesize ONE non-streaming chat completion by driving `body` through the ENTIRE resolved
    /// ingress pipeline (governance → pools → breaker/failover → metering → request log) under `gov`,
    /// on the operator's declared `model`, and return the raw wire outcome. The dialect the request is
    /// driven as is NEUTRAL to this seam: the host resolves it from the registry's residual-default
    /// chat protocol (`None` — no chat dialect installed — surfaces as an error, not a hard-coded
    /// identity), so MCP's `sampling/complete` bridge names no LLM dialect to reach a completion.
    ///
    /// The ONE async method beside [`IdentityHost::identity_admit`] — but simpler:
    /// the host drives a NATIVE core async fn (no C-ABI slot, no `spawn_blocking`), so this only
    /// `.await`s it. No `HostCtx` crosses the `.await`; the future is `Send`. `max_body_bytes`
    /// bounds the response body read.
    async fn synthesize_completion(
        &self,
        gov: &busbar_api::PlaneRequestCtx,
        model: &str,
        body: bytes::Bytes,
        max_body_bytes: usize,
    ) -> Result<HostCompletion, String>;
}

/// The neutral HOST seam a plane calls to reach the engine's host-owned capabilities.
///
/// A plane holds an `Arc<dyn EngineHost>` (minted core-side over the live engine) and calls these
/// typed methods rather than naming `busbar_core::plane_host::*_over(&App, …)`. Each method reaches
/// the SAME host vtable slot the in-core veneer drives, so the value is identical — this is a
/// same-dispatch relocation of the reach, not a new behaviour.
///
/// `Send + Sync` because a plane carries the handle across `.await` and between threads (e.g. into a
/// `spawn_blocking` breaker leg). That is sound precisely because no method exposes the `!Send`
/// `HostCtx`: each mints it internally, uses it synchronously, and drops it before returning.
///
/// ## M4 — `EngineHost` is the SUM of the capability slices
///
/// The residual flat method set has been cut into cohesive capability SUPERTRAITS
/// ([`ClockHost`], [`TelemetryHost`], [`JournalHost`], [`MountHost`], [`RegistryHost`],
/// [`HookConfigHost`], [`BudgetHost`], [`IdentityHost`], [`AdmissionHost`], [`CompletionHost`]),
/// alongside the earlier braking slices ([`BreakerHost`], [`LanePoolHost`], [`MeteringHost`]).
/// `EngineHost` now declares NO methods of its own beyond the provided [`run_gauntlet`](Self::run_gauntlet)
/// ergonomic entry — it is the SUM (a supertrait bound of every slice). An existing
/// `Arc<dyn EngineHost>` caller is unaffected (it still reaches every method through the inherited
/// bound); a plane that needs a narrower capability takes `&dyn SliceX` and depends only on what it
/// uses — a voice/bytes port never names LLM-only [`CompletionHost::synthesize_completion`].
///
/// `#[async_trait]` is inherited via the async slices; `EngineHost` itself carries only the provided
/// `run_gauntlet` future, so the attribute leaves it a thin sum.
#[async_trait::async_trait]
pub trait EngineHost:
    BreakerHost
    + LanePoolHost
    + MeteringHost
    + ClockHost
    + TelemetryHost
    + JournalHost
    + MountHost
    + RegistryHost
    + HookConfigHost
    + BudgetHost
    + IdentityHost
    + AdmissionHost
    + CompletionHost
    + Send
    + Sync
{
    // The cross-protocol translation seam's global-fallback max-output-tokens and effort→budget-table
    // reads are GONE from this neutral host trait: they are LLM-plane vocabulary, so the engine now
    // reads them off the LLM plane's own per-generation runtime (`NativeRuntime`) rather than through a
    // neutral `PlaneHost` method over `App`. See busbar-llm `engine/wire.rs`.

    /// Run one request through THE shared gauntlet sequence ([`run_gauntlet`]) — the ergonomic entry
    /// for a plane that already holds an `Arc<dyn EngineHost>`. A PROVIDED method: it delegates to the
    /// free [`run_gauntlet`] (which needs no host — the sequence is verify→drive over the plane), so
    /// every host impl shares one body and core's own callers can use the free fn directly.
    async fn run_gauntlet<'a>(
        &self,
        req: GauntletRequest<'a>,
        plane: Box<dyn GauntletPlane + 'a>,
    ) -> axum::response::Response {
        run_gauntlet(req, plane).await
    }
}

/// Compile-time witness for the M4 god-trait split: any `EngineHost` implementor IS every capability
/// slice. If a future edit dropped any supertrait bound (or an impl stopped satisfying it), this stops
/// compiling — so `EngineHost` cannot silently cease to equal the SUM of its slices (the families
/// cannot re-dissolve back into the flat god-trait).
const _: () = {
    fn _assert_engine_host_is_sum_of_slices<T: EngineHost + ?Sized>() {
        fn _needs_breaker<U: BreakerHost + ?Sized>() {}
        fn _needs_lane_pool<U: LanePoolHost + ?Sized>() {}
        fn _needs_metering<U: MeteringHost + ?Sized>() {}
        fn _needs_clock<U: ClockHost + ?Sized>() {}
        fn _needs_telemetry<U: TelemetryHost + ?Sized>() {}
        fn _needs_journal<U: JournalHost + ?Sized>() {}
        fn _needs_mount<U: MountHost + ?Sized>() {}
        fn _needs_registry<U: RegistryHost + ?Sized>() {}
        fn _needs_hook_config<U: HookConfigHost + ?Sized>() {}
        fn _needs_budget<U: BudgetHost + ?Sized>() {}
        fn _needs_identity<U: IdentityHost + ?Sized>() {}
        fn _needs_admission<U: AdmissionHost + ?Sized>() {}
        fn _needs_completion<U: CompletionHost + ?Sized>() {}
        _needs_breaker::<T>();
        _needs_lane_pool::<T>();
        _needs_metering::<T>();
        _needs_clock::<T>();
        _needs_telemetry::<T>();
        _needs_journal::<T>();
        _needs_mount::<T>();
        _needs_registry::<T>();
        _needs_hook_config::<T>();
        _needs_budget::<T>();
        _needs_identity::<T>();
        _needs_admission::<T>();
        _needs_completion::<T>();
    }
};

/// THE NEUTRAL TYPE-ERASED SLOT-READ SEAM the core-owned `PlaneDecl` callbacks that today force a
/// `&busbar_core::state::App` are neutralised over — so a plane's `on_swap` / `registry_contains` /
/// `retain_verify_gates` hook reads its own per-generation runtime object off the snapshot WITHOUT
/// the callback fn-pointer signature naming a core type. Core `impl`s it for `App` as a thin delegate
/// to the inherent `App::plane_slot`; an EXTRACTED plane reaches only [`Self::plane_slot`] and
/// stays neutral. [`Self::as_any`] is the recovery hatch an in-core plane twin uses to downcast back
/// to its concrete snapshot for a field that does not live in `plane_slots` (`agent_defs`); an
/// extracted plane never calls it.
pub trait PlaneSlots {
    /// The plane's type-erased runtime object for THIS generation, keyed by the plane's decl key —
    /// a pure `plane_slots` map read, borrowed (mirrors the inherent `App::plane_slot`).
    fn plane_slot(&self, key: &str) -> Option<&Arc<dyn std::any::Any + Send + Sync>>;

    /// Recover the concrete engine snapshot as `&dyn Any` — the hatch an in-core plane twin downcasts
    /// through to reach the snapshot fields that are not `plane_slots` entries. An extracted plane
    /// never names a concrete type through this, so it never calls it.
    fn as_any(&self) -> &dyn std::any::Any;
}

/// THE NEUTRAL `&mut` GATE-REBUILD SINK the core-owned `PlaneDecl::reresolve_gates` callback is
/// neutralised over — the config-swap re-resolution of a plane's per-registration hook gates, moved
/// behind a trait so the fn-pointer signature names no `&mut busbar_core::state::App`. A `PlaneSlots`
/// (its supertrait) so the plane can read its own registry object off the same `&mut` receiver before
/// it writes the resolved gates back. The resolve-and-store is ONE method (rather than the spec's
/// `resolve` + `set` pair) because the resolved gate map value type is core-owned
/// (`Vec<(u16, busbar_core::hooks::ResolvedPolicy)>`) and cannot be named in this crate — so the map
/// never crosses the seam; it is built and stored entirely core-side, keyed by `plane_key`.
pub trait ContainerGateSink: PlaneSlots {
    /// Resolve `containers` (each `(name, its-own-hooks)`) unioned with `section_hooks` against this
    /// snapshot's hook registry, and store the resolved per-container gates under the opaque registry
    /// `plane_key` (the plane's stable decl key) in the generic `App::plane_gates` map. Byte-identical
    /// to the old inline `next.plane_gates.insert(plane_key, next.resolve_container_gates(...))`.
    fn reresolve_container_gates(
        &mut self,
        plane_key: &str,
        containers: &[(&str, &[String])],
        section_hooks: &[String],
    );
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// D3 WITNESS — the gauntlet siblings COEXIST and share ONE `admit_open` gate. (That `begin_session`
// actually CALLS `run_gauntlet_session` at its call site is pinned in busbar-voice's topology tests.)
// ─────────────────────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod gauntlet_session_tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    /// A stub plane that records whether its `drive` (stages 4+5, the CHARGE-bearing leg) ran, and either
    /// proceeds or refuses at the verify gate — so a test can prove NEITHER sibling drives on a refuse
    /// (verify strictly before charge) and the one-shot path drives on a proceed.
    struct StubPlane {
        refuse: bool,
        drove: Arc<AtomicBool>,
    }

    #[async_trait::async_trait]
    impl GauntletPlane for StubPlane {
        fn verify_destination(&self, _req: &GauntletRequest<'_>) -> VerifyOutcome {
            if self.refuse {
                VerifyOutcome::Refuse(
                    axum::response::Response::builder()
                        .status(429)
                        .body(axum::body::Body::from("refused"))
                        .expect("refusal response"),
                )
            } else {
                VerifyOutcome::Proceed
            }
        }

        async fn drive(self: Box<Self>, _req: GauntletRequest<'_>) -> axum::response::Response {
            self.drove.store(true, Ordering::SeqCst);
            axum::response::Response::builder()
                .status(200)
                .body(axum::body::Body::from("driven"))
                .expect("driven response")
        }
    }

    fn req(gov: &busbar_api::PlaneRequestCtx) -> GauntletRequest<'_> {
        GauntletRequest {
            gov,
            destination: "model-x",
            correlation_id: 77,
            charged_at: 1,
            started: std::time::Instant::now(),
        }
    }

    #[tokio::test]
    async fn siblings_coexist_and_share_the_admit_open_gate() {
        let gov = busbar_api::PlaneRequestCtx::default();

        // PROCEED: run_gauntlet DRIVES (charge leg runs); run_gauntlet_session ADMITS (no drive) and the
        // Admitted carries the correlation id — the same shared gate said "proceed" to both.
        let drove_rg = Arc::new(AtomicBool::new(false));
        let resp = run_gauntlet(
            req(&gov),
            Box::new(StubPlane {
                refuse: false,
                drove: Arc::clone(&drove_rg),
            }),
        )
        .await;
        assert_eq!(resp.status(), 200, "proceed drives the one-shot path");
        assert!(
            drove_rg.load(Ordering::SeqCst),
            "run_gauntlet drove on proceed"
        );

        let drove_rgs = Arc::new(AtomicBool::new(false));
        let admitted = run_gauntlet_session(
            req(&gov),
            Box::new(StubPlane {
                refuse: false,
                drove: Arc::clone(&drove_rgs),
            }),
        )
        .expect("proceed admits the session");
        assert_eq!(
            admitted.correlation_id, 77,
            "the admitted session joins on the correlation id"
        );
        assert!(
            !drove_rgs.load(Ordering::SeqCst),
            "the session opener NEVER drives a one-shot response"
        );

        // REFUSE: BOTH siblings return the plane's OWN refusal verbatim and NEITHER drives — the one
        // shared verify-before-charge gate rejects before any charge in both paths.
        let drove_rg_r = Arc::new(AtomicBool::new(false));
        let resp = run_gauntlet(
            req(&gov),
            Box::new(StubPlane {
                refuse: true,
                drove: Arc::clone(&drove_rg_r),
            }),
        )
        .await;
        assert_eq!(
            resp.status(),
            429,
            "refuse returns the plane's refusal verbatim"
        );
        assert!(
            !drove_rg_r.load(Ordering::SeqCst),
            "refuse never drives (run_gauntlet)"
        );

        let drove_rgs_r = Arc::new(AtomicBool::new(false));
        let refusal = run_gauntlet_session(
            req(&gov),
            Box::new(StubPlane {
                refuse: true,
                drove: Arc::clone(&drove_rgs_r),
            }),
        )
        .expect_err("refuse denies the session before any charge");
        assert_eq!(
            refusal.status(),
            429,
            "the session refusal is the plane's own response"
        );
        assert!(
            !drove_rgs_r.load(Ordering::SeqCst),
            "refuse never drives (run_gauntlet_session) — zero bytes, zero charge"
        );
    }
}
