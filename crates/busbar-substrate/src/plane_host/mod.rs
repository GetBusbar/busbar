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
pub mod scope;

use crate::breaker::CanonicalSignal;
use crate::plane::approvals::Sealer;
use crate::plane::calllog::CallInput;
pub use crate::plane_host::scope::{DispatchScope, DurableScope, SessionScope};
use crate::store::Unavailable;
use crate::trust::validate::{Lapsed, Standing};
use crate::trust::TrustState;
use busbar_api::{AuthPrincipal, IdentityRefusal, PlaneRequestCtx, VirtualKey};
use busbar_plugin::hot::{AdmissionId, Signal, StatusClass};
use std::sync::Arc;

/// The outcome of a refusal-fidelity admit driven over the host `govern_admit_reason` seam.
#[cfg_attr(
    not(any(feature = "plane-mcp", feature = "plane-a2a")),
    allow(dead_code)
)]
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
#[cfg_attr(
    not(any(feature = "plane-mcp", feature = "plane-a2a")),
    allow(dead_code)
)]
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
#[cfg_attr(
    not(any(feature = "plane-mcp", feature = "plane-a2a")),
    allow(dead_code)
)]
pub struct HostCompletion {
    /// The pipeline's HTTP status.
    pub status: u16,
    /// The pipeline's response body bytes (bounded by the `max_body_bytes` the caller passed).
    pub body: bytes::Bytes,
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
/// `#[async_trait]` because ONE method — [`identity_admit`](EngineHost::identity_admit) — is `async`
/// (it awaits a `spawn_blocking` join over the host auth chain). Every other method is a plain sync
/// fn the attribute leaves untouched; only the async one is desugared to a boxed `Send` future.
/// The `plane_slots` companion key under which the MCP plane's always-present per-generation runtime
/// object is carried, distinct from the plane's config-conditional decl key (`"mcp"`). Named by both
/// core's `appbuild` (which composes the slot) and the MCP plane (which reads it back through
/// [`EngineHost::plane_slot`]), so it lives in the neutral substrate rather than either crate. Core
/// re-exports it as `busbar_core::state::MCP_RUNTIME_SLOT` so in-core names are unchanged.
pub const MCP_RUNTIME_SLOT: &str = "mcp:runtime";

/// A source of freshly live-bound hosts: each call returns a host reading the current snapshot,
/// so a config swap between calls is seen. Handed to transports that re-mint per frame.
pub type LiveHostFactory = std::sync::Arc<dyn Fn() -> std::sync::Arc<dyn EngineHost> + Send + Sync>;

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
    /// `plane_key`: `0` = MCP, `1` = A2A. `key` is the caller's resolved `(id, name)`; `session_id`
    /// is the caller's session, `Some` only when non-empty.
    #[allow(clippy::too_many_arguments)]
    fn gate_decide(
        &self,
        plane_key: u8,
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

    /// Whether governance is configured for this deployment. Identical to
    /// `busbar_core::state::App::governance.is_some()`.
    fn governance_enabled(&self) -> bool;

    /// Emit ONE hostless admin-audit record `(action, resource, outcome, principal)` to the shared
    /// admin audit log. Fire-and-forget, loudly: a store write failure NEVER fails the mutation it
    /// records. Identical to `busbar_core::plane::auditlog::emit_admin_hostless_now` — this seam needs
    /// no `HostCtx`, so it is a plain forward to that engine (which stays unchanged in core).
    fn audit_emit(&self, action: &str, resource: &str, outcome: &str, principal: &str);

    /// Emit ONE per-call record through the durable MCP call-log engine. The transient `HostCtx` the
    /// chain seam needs is minted INTERNALLY (a fresh per-call arena over the live engine — the append
    /// registers no host handle, so the arena choice is immaterial). Identical to
    /// `busbar_core::plane::calllog::emit`.
    fn call_log_emit(&self, principal: &str, input: CallInput);

    /// The DEFERRED-SITE twin of [`call_log_emit`](EngineHost::call_log_emit): emit through the
    /// HOSTLESS call-log path, for a client-leg site that has no `HostCtx` to open. Identical to
    /// `busbar_core::plane::calllog::emit_hostless`.
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

    /// Every durably-recorded upstream demotion, the boot-replay source. Identical to
    /// `App::demotion_record.list()`; the row type is the neutral `busbar_api::McpDemotionRow`.
    fn demotion_rows(&self) -> Vec<busbar_api::McpDemotionRow>;

    /// The `(pool_name, members, repeatable)` of the `tool_pools:` failover pool `server` belongs to,
    /// off the BOUND snapshot; `None` when `server` is un-pooled. `repeatable` is the pool's
    /// `repeatable:` operation list (what `CandidatePoolCfg::repeatability` consults). Identical to
    /// scanning `App::tool_pools`.
    fn tool_pool_members(&self, server: &str) -> Option<(String, Vec<String>, Vec<String>)>;

    /// Cheap presence pre-filter: is any request-admission hook gate attached to `container` on this
    /// plane (`plane_key` `0` = MCP, `1` = A2A)? Lets a plane skip the blocking `gate_decide` hop when
    /// nothing is attached. Identical to `App::mcp_server_gates.contains_key(container)` for MCP and
    /// `App::a2a_agent_gates.contains_key(container)` for A2A.
    fn gate_attached(&self, plane_key: u8, container: &str) -> bool;

    /// The `(pool_name, members)` of the `agent_pools:` failover pool `agent` belongs to, off the
    /// BOUND snapshot; `None` when `agent` is un-pooled. The A2A twin of
    /// [`tool_pool_members`](Self::tool_pool_members) — the member-selection walk derives each
    /// candidate's lane from the member's position in the returned list, so name + members is the
    /// whole seam (the A2A walk fixes `Repeatable::No`, so the pool's `repeatable:` list is not
    /// consulted on this plane). Identical to scanning `App::agent_pools`.
    fn a2a_agent_pool_members(&self, agent: &str) -> Option<(String, Vec<String>)>;

    /// Whether the A2A plane is mounted under an AUDIENCE-BOUND door — the deployment gate the A2A
    /// request path reads before it trusts an inbound audience claim. Identical to
    /// `App::planes.mount_of("a2a").and_then(|m| App::planes.admission_for(m)).is_some()`. A pure
    /// snapshot read, no `HostCtx`.
    fn a2a_audience_bound(&self) -> bool;

    /// The deployment's NEUTRAL secret resolver, behind the `busbar_api::SecretResolve` seam, so the
    /// A2A plane mints a delegation credential (and loads its outbound TLS PEM) WITHOUT naming the
    /// engine's concrete `SecretResolver`. A pure snapshot read of `App::secret_resolver`, no
    /// `HostCtx`; the returned `Arc<dyn SecretResolve>` shares the live resolver (built-ins plus any
    /// wired `kind: secret` plugin), fail-closed exactly as core resolution.
    fn a2a_secret_resolver(&self) -> Arc<dyn busbar_api::SecretResolve>;

    /// Drive ONE non-streaming `openai`-dialect completion through the ENTIRE resolved ingress
    /// pipeline (governance → pools → breaker/failover → metering → request log) under `gov`, on the
    /// operator's declared `model`, and return the raw wire outcome. Identical to calling
    /// `busbar_core::ingress::operation_resolved` with the `openai` chat handler over the live App.
    ///
    /// The ONE async method beside [`identity_admit`](EngineHost::identity_admit) — but simpler:
    /// `operation_resolved` is a NATIVE core async fn (no C-ABI slot, no `spawn_blocking`), so this
    /// only `.await`s it. No `HostCtx` crosses the `.await`; the future is `Send`. `max_body_bytes`
    /// bounds the response body read.
    async fn drive_openai_completion(
        &self,
        gov: &busbar_api::PlaneRequestCtx,
        model: &str,
        body: bytes::Bytes,
        max_body_bytes: usize,
    ) -> Result<HostCompletion, String>;
}

/// THE NEUTRAL TYPE-ERASED SLOT-READ SEAM the core-owned `PlaneDecl` callbacks that today force a
/// `&busbar_core::state::App` are neutralised over — so a plane's `on_swap` / `registry_contains` /
/// `retain_verify_gates` hook reads its own per-generation runtime object off the snapshot WITHOUT
/// the callback fn-pointer signature naming a core type. Core `impl`s it for `App` as a thin delegate
/// to the inherent `App::plane_slot`; an EXTRACTED plane (MCP) reaches only [`Self::plane_slot`] and
/// stays neutral. [`Self::as_any`] is the recovery hatch an IN-CORE plane twin (A2A, still in core)
/// uses to downcast back to its concrete snapshot for the fields that do not live in `plane_slots`
/// (`agent_defs`, `a2a_verify`); an extracted plane never calls it.
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
    /// snapshot's hook registry, and store the resolved per-container gates under `plane_key`
    /// (`0` = MCP `mcp_server_gates`, else A2A `a2a_agent_gates`). Byte-identical to the old inline
    /// `next.<field> = next.resolve_container_gates(...)`.
    fn reresolve_container_gates(
        &mut self,
        plane_key: u8,
        containers: &[(&str, &[String])],
        section_hooks: &[String],
    );
}
