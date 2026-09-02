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
    AffinityInput, AuthStyleInput, BreakerInput, PlaneBuildInput, ClientSettingsInput,
    FailoverInput, HealthInput, HealthModeInput, LaneInput, OnExhaustedInput, PoolInput,
    PoolMemberInput, TripInput, TripModeInput,
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
// THE GAUNTLET SEAM — one shared request sequence every protocol plane rides (design §10, M3).
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

/// THE SHARED GAUNTLET SEQUENCE — the ONE request path every protocol plane rides. Stage 1 identity
/// is already resolved (threaded via `req.gov`); this calls the plane's `verify_destination` (stage
/// 2) in the correct PRE-ADMISSION position and, only if it proceeds, the plane's `drive` (stages
/// 4+5, its own byte-identical engine + metering). Returns the plane's (possibly streaming) response
/// verbatim. The plane owns admission/route/metering/finish; the sequence owns solely the
/// verify-before-admit order (nothing may reject after a charge) — so all planes enforce that
/// invariant in ONE place rather than each re-implementing it.
pub async fn run_gauntlet(
    req: GauntletRequest<'_>,
    plane: Box<dyn GauntletPlane + '_>,
) -> axum::response::Response {
    match plane.verify_destination(&req) {
        VerifyOutcome::Refuse(resp) => resp,
        VerifyOutcome::Proceed => plane.drive(req).await,
    }
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
/// `#[async_trait]` because ONE method — [`identity_admit`](EngineHost::identity_admit) — is `async`
/// (it awaits a `spawn_blocking` join over the host auth chain). Every other method is a plain sync
/// fn the attribute leaves untouched; only the async one is desugared to a boxed `Send` future.
#[async_trait::async_trait]
pub trait EngineHost: Send + Sync {
    /// Read the host wall clock in whole SECONDS through the `clock_now` seam — the host-driven form
    /// of a plane's in-place seconds clock. Identical to `busbar_core::plane_host::clock_now_secs_over`.
    fn clock_now_secs(&self) -> u64;

    /// Read the host wall clock in MILLISECONDS through the `clock_now` seam — the host-driven form of
    /// a plane's in-place millis clock. Identical to `busbar_core::plane_host::clock_now_ms_over`.
    fn clock_now_ms(&self) -> u64;

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

    /// Settle a drift disposition for `subject` through the host `drift_quarantine` seam, pulling the
    /// demotion store host-side. Returns whether the slot answered `Ok`; the settle is
    /// fire-and-forget, so a non-`Ok` is a durability miss, not a refusal. Identical to
    /// `busbar_core::plane_host::trust::quarantine_settle_over`.
    fn quarantine_settle(&self, subject: &str, state: TrustState) -> bool;

    /// Record ONE metered, attributed event through the host `meter_charge` seam over `scope`'s arena.
    /// `usage` carries the resolved `(key_id, model, provider)` attribution the host writes the cost row
    /// from; the transient `HostCtx` is minted over `scope` and consumed SYNCHRONOUSLY inside the call.
    /// Fire-and-forget: a store miss is not surfaced, exactly as the plane's in-place `record_metering`
    /// was. Identical to driving the `meter_charge` vtable slot under a `with_borrowed_host` over `scope`.
    fn meter_charge(&self, scope: &DispatchScope, usage: &busbar_plugin::hot::Usage);

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

    /// Redeem a one-time approval against the shared spent-approval ledger the host pulls, spending
    /// against the seal's own `expires_at` and the caller's `now`. `true` iff this is the FIRST
    /// redemption; `false` when already spent OR the durable ledger could not answer (fail-closed).
    /// Identical to `busbar_core::plane_host::trust::approval_redeem_q`.
    fn approval_redeem(&self, nonce: &str, expires_at: u64, now: u64) -> bool;

    /// Stamp the NEXT per-request correlation id — one relaxed `fetch_add` on the host-owned counter.
    /// Identical to `busbar_core::state::App::next_request_id` (the counter is boot-seeded and carried
    /// across config swaps, so the value is engine-snapshot independent).
    fn next_request_id(&self) -> u64;

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

    /// Whether governance is configured for this deployment. Identical to
    /// `busbar_core::state::App::governance.is_some()`.
    fn governance_enabled(&self) -> bool;

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

    /// Whether `caller_group` sits within (any ancestor of) one of `hook_groups` — the group-membership
    /// walk a hook's `groups:` filter consults, resolved against this deployment's group registry.
    /// Identical to `busbar_core::config::caller_in_hook_groups(caller_group, hook_groups, &App::groups_registry)`;
    /// a pure tree walk over the bound snapshot's registry, no `HostCtx`.
    ///
    /// WEDGE 2 (App-retype): additive — the seam the wedge-3 `pipeline.rs` flip targets. Folding the
    /// `&App::groups_registry` argument HOST-side means the engine reads group membership without naming
    /// `busbar_core::config` or `App::groups_registry`.
    fn caller_in_hook_groups(&self, caller_group: Option<&str>, hook_groups: &[String]) -> bool;

    /// Emit ONE hostless admin-audit record `(action, resource, outcome, principal)` to the shared
    /// admin audit log. Fire-and-forget, loudly: a store write failure NEVER fails the mutation it
    /// records. Identical to `busbar_core::plane::auditlog::emit_admin_hostless_now` — this seam needs
    /// no `HostCtx`, so it is a plain forward to that engine (which stays unchanged in core).
    fn audit_emit(&self, action: &str, resource: &str, outcome: &str, principal: &str);

    /// Emit ONE per-call record through the durable MCP call-log engine. The transient `HostCtx` the
    /// chain seam needs is minted INTERNALLY (a fresh per-call arena over the live engine — the append
    /// registers no host handle, so the arena choice is immaterial). Identical to
    /// `busbar_core::calllog::emit`.
    fn call_log_emit(&self, principal: &str, input: CallInput);

    /// The DEFERRED-SITE twin of [`call_log_emit`](EngineHost::call_log_emit): emit through the
    /// HOSTLESS call-log path, for a client-leg site that has no `HostCtx` to open. Identical to
    /// `busbar_core::calllog::emit_hostless`.
    fn call_log_emit_hostless(&self, principal: &str, input: CallInput);

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

    /// The plane's type-erased runtime object off the BOUND snapshot (the one this host was minted
    /// over), owned (an `Arc` clone) so it outlives the call. `None` when the plane contributed no
    /// slot under `key` this generation. Identical to `busbar_core::state::App::plane_slot(key)`
    /// cloned — a pure `plane_slots` map read, no `HostCtx` (mirrors [`next_request_id`]).
    ///
    /// [`next_request_id`]: EngineHost::next_request_id
    fn plane_slot(&self, key: &str) -> Option<Arc<dyn std::any::Any + Send + Sync>>;

    /// The plane's slot off the CURRENT snapshot — re-reads the LIVE handle so a config swap AFTER
    /// this host was minted is seen (the dispatch-time re-validation / per-round revocation / watch
    /// loops depend on this). Falls back to the bound snapshot for a snapshot-only mint (one built
    /// without a live handle). A pure map read, no `HostCtx`.
    fn plane_slot_live(&self, key: &str) -> Option<Arc<dyn std::any::Any + Send + Sync>>;

    /// The `(pool_name, members, repeatable)` of the `tool_pools:` failover pool `server` belongs to,
    /// off the BOUND snapshot; `None` when `server` is un-pooled. `repeatable` is the pool's
    /// `repeatable:` operation list (what `CandidatePoolCfg::repeatability` consults). Identical to
    /// scanning `App::tool_pools`.
    fn tool_pool_members(&self, server: &str) -> Option<(String, Vec<String>, Vec<String>)>;

    /// Cheap presence pre-filter: is any request-admission hook gate attached to `container` on the
    /// plane identified by the opaque registry `plane_key` (the plane's stable decl key)? Lets a plane
    /// skip the blocking `gate_decide` hop when nothing is attached. Identical to
    /// `App::plane_gates(plane_key).contains_key(container)`.
    fn gate_attached(&self, plane_key: &str, container: &str) -> bool;

    /// The `(pool_name, members)` of the failover pool `member` belongs to on the plane identified by
    /// the opaque registry `plane_key`, off the BOUND snapshot; `None` when `member` is un-pooled. The
    /// member-selection walk derives each candidate's lane from the member's position in the returned
    /// list, so name + members is the whole seam. Identical to scanning the plane's pool map.
    fn plane_pool_members(&self, plane_key: &str, member: &str) -> Option<(String, Vec<String>)>;

    /// Whether the plane identified by the opaque registry `plane_key` is mounted under an
    /// AUDIENCE-BOUND door — the deployment gate a request path reads before it trusts an inbound
    /// audience claim. Identical to
    /// `App::planes.mount_of(plane_key).and_then(|m| App::planes.admission_for(m)).is_some()`. A pure
    /// snapshot read, no `HostCtx`.
    fn plane_audience_bound(&self, plane_key: &str) -> bool;

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

    /// Synthesize ONE non-streaming chat completion by driving `body` through the ENTIRE resolved
    /// ingress pipeline (governance → pools → breaker/failover → metering → request log) under `gov`,
    /// on the operator's declared `model`, and return the raw wire outcome. The dialect the request is
    /// driven as is NEUTRAL to this seam: the host resolves it from the registry's residual-default
    /// chat protocol (`None` — no chat dialect installed — surfaces as an error, not a hard-coded
    /// identity), so MCP's `sampling/complete` bridge names no LLM dialect to reach a completion.
    ///
    /// The ONE async method beside [`identity_admit`](EngineHost::identity_admit) — but simpler:
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
