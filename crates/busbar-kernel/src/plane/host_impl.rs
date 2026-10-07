// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE KERNEL'S [`EngineHost`] OVER THE LIVE [`App`]: [`EngineHostImpl`], the constructors a
//! composition root and the plane driver mint it through ([`engine_host`], [`engine_host_value`],
//! [`engine_host_from_handle`], [`live_host_factory`]), the live standing ([`live_standing`],
//! [`standing_over`]) and the container rewrite chain ([`transform_over_over`]).
//!
//! The methods that still reach the HOT host vtable (breaker admit/settle, metering, the govern
//! admit, approvals, identity admission, card signing, the call log, the container gate) are thin
//! calls into `crate::plane_host`'s `*_over` functions; they leave with the HOT lane (D2 step 4b),
//! no caller outside it remaining.

use crate::plane::dispatch_scope::DispatchScope;
use crate::plane::host::TransformVerdict;
use crate::state::App;
use std::sync::Arc;

/// Core's implementation of the neutral [`EngineHost`](busbar_kernel::plane::host::EngineHost)
/// seam over the live [`App`]. A plane holds this behind an
/// `Arc<dyn busbar_kernel::plane::host::EngineHost>` and calls typed, safe methods on it INSTEAD of
/// naming `plane_host::*_over(&App, …)` — so a plane compiled apart from the host reaches the same
/// host vtable slots without ever naming a core type.
///
/// Owns an `Arc<App>` (the config generation the reaches run against) so the handle is
/// `Send + Sync + 'static` and safe to carry across `.await`. That is sound precisely because no
/// method exposes the `!Send` [`HostCtx`]: each mints the transient `HostCtx` INTERNALLY (via
/// [`with_borrowed_host`] over a fresh per-call [`DispatchScope`]), drives the slot SYNCHRONOUSLY,
/// and returns an owned value — the raw host pointer never escapes the call.
#[derive(Clone)]
pub struct EngineHostImpl {
    /// The BOUND engine snapshot the host reaches run against — loaded once at mint. Serves
    /// `plane_slot` and every existing method, byte-identically to the pre-`handle` host.
    app: Arc<App>,
    /// The LIVE handle, retained so `plane_slot_live` re-reads the CURRENT snapshot after a config
    /// swap. `None` for a snapshot-only mint (the `Fn(&Arc<App>)` factory / [`new`](Self::new)), where
    /// the bound snapshot is the only snapshot the host was ever handed.
    handle: Option<Arc<crate::state::AppHandle>>,
}

impl EngineHostImpl {
    /// Build the host implementation over the live `app` — a SNAPSHOT-ONLY mint (no live handle, so
    /// `plane_slot_live` degrades to the bound snapshot).
    #[must_use]
    pub fn new(app: Arc<App>) -> Self {
        EngineHostImpl { app, handle: None }
    }

    /// Build the host over a live [`AppHandle`](crate::state::AppHandle): the bound snapshot is the
    /// handle's CURRENT load (keeping frozen-snapshot semantics byte-identical to `new(handle.load())`),
    /// and the handle is retained so `plane_slot_live` sees a later config swap.
    #[must_use]
    pub fn from_handle(handle: Arc<crate::state::AppHandle>) -> Self {
        EngineHostImpl {
            app: handle.load(),
            handle: Some(handle),
        }
    }
}

// AUDIT-D BRAKE: the BREAKER family, split off `EngineHost` into its `BreakerHost` supertrait. The
// bodies are relocated byte-for-byte — same-dispatch reaches, same arenas — so the split is purely
// structural. `EngineHost: BreakerHost` (in substrate) makes these visible on every `dyn EngineHost`.
impl busbar_kernel::plane::host::BreakerHost for EngineHostImpl {
    fn breaker_admit(
        &self,
        scope: &DispatchScope,
        pool: &[u8],
        lane: u32,
    ) -> Result<busbar_contract::abi::hot::AdmissionId, busbar_kernel::store::Unavailable> {
        crate::plane_host::breaker::breaker_admit_over(&self.app, scope, pool, lane)
    }

    fn breaker_settle(
        &self,
        scope: &DispatchScope,
        admission: busbar_contract::abi::hot::AdmissionId,
        signal: &busbar_contract::abi::hot::Signal,
    ) -> busbar_contract::abi::hot::StatusClass {
        crate::plane_host::breaker_settle_over(&self.app, scope, admission, signal)
    }

    fn breaker_record_success(&self, pool: &str, lane: usize) {
        self.app.plane_breakers.record_success(pool, lane);
    }

    fn breaker_record_signal(
        &self,
        pool: &str,
        lane: usize,
        sig: &busbar_contract::upstream::CanonicalSignal,
    ) {
        self.app.plane_breakers.record_signal(pool, lane, sig);
    }

    fn breaker_retry_after_secs(&self, pool: &str, lane: usize) -> u64 {
        self.app.plane_breakers.retry_after_secs(pool, lane)
    }
}

// AUDIT-D BRAKE: the LANE/POOL family, split off `EngineHost` into its `LanePoolHost` supertrait.
// Relocated byte-for-byte from the flat impl; `EngineHost: LanePoolHost` keeps every call site working.
impl busbar_kernel::plane::host::LanePoolHost for EngineHostImpl {
    fn lane_store(&self) -> &dyn busbar_kernel::store::LaneRuntime {
        // A pure borrow of the bound snapshot's store: `App::store` is `Arc<dyn LaneRuntime>` where
        // `LaneRuntime` is re-exported from `busbar_kernel::store` (wedge 1), so the returned
        // trait object IS the substrate one — byte-identical to the engine's `&*app.store`.
        &*self.app.store
    }

    fn default_probe_interval_secs(&self) -> u64 {
        crate::limits::default_probe_interval_secs()
    }

    fn default_probe_timeout_secs(&self) -> u64 {
        crate::limits::default_probe_timeout_secs()
    }

    fn pool_members_repeatable(&self, member: &str) -> Option<(String, Vec<String>, Vec<String>)> {
        self.app
            .tool_pools
            .iter()
            .find(|(_, cfg)| cfg.members.iter().any(|m| m == member))
            .map(|(name, cfg)| (name.clone(), cfg.members.clone(), cfg.repeatable.clone()))
    }

    fn plane_pool_members(&self, plane_key: &str, member: &str) -> Option<(String, Vec<String>)> {
        // Scan the plane's failover pool map for the pool `member` belongs to and return its name +
        // members (the walk derives lanes from member position). A pure snapshot read over the generic
        // per-plane pool map, keyed by the opaque registry key.
        self.app
            .plane_pools(plane_key)?
            .iter()
            .find(|(_, cfg)| cfg.members.iter().any(|m| m == member))
            .map(|(name, cfg)| (name.clone(), cfg.members.clone()))
    }
}

// THE KERNEL'S OWN PRICING (#43): `MeteringHost` is NOT a supertrait of `EngineHost`, so no plane-side
// host implements it and no plane names it. The pricing is this host's: its bound snapshot's rate card.
impl busbar_kernel::plane::host::MeteringHost for EngineHostImpl {
    fn price_usage(&self, model: &str, usage: &busbar_contract::billing::Usage) -> Option<u128> {
        // Price against the BOUND snapshot's resolved `CostModel` — the SAME rate card + arithmetic the
        // LLM enforcement/derive path prices with (a new reader, not a new pricer), so a live voice
        // carrier meters against the deployment's real rates while staying plane-neutral.
        self.app.cost.price_usage_nanos(model, usage)
    }
}

// M4 (god-trait split): the single `EngineHostImpl` implements each capability slice `EngineHost` now
// sums. Every method body is byte-identical to the pre-split flat `impl EngineHost` — only the impl
// block it lives in changed. `EngineHost` itself declares no method of its own (beyond the provided
// `run_gauntlet`), so the blanket `impl EngineHost for EngineHostImpl` below is empty: the sum is
// satisfied entirely through the slice impls.

impl busbar_kernel::plane::host::ClockHost for EngineHostImpl {
    fn clock_now_secs(&self) -> u64 {
        // SAME dispatch as the veneer: a fresh per-call `DispatchScope`, the `clock_now` slot driven
        // synchronously over a stack-pinned `HostState`, the `HostCtx` never escaping the call.
        busbar_kernel::store::now_ms() / 1_000
    }

    fn clock_now_ms(&self) -> u64 {
        busbar_kernel::store::now_ms()
    }
}

impl busbar_kernel::plane::host::TelemetryHost for EngineHostImpl {
    fn request_finished(
        &self,
        plane: &str,
        ingress_protocol: &str,
        pool: &str,
        outcome: &'static str,
        seconds: f64,
    ) {
        // Same frozen-snapshot semantics as every sibling: the completion is stamped against the BOUND
        // snapshot this host was minted over, byte-identically to the plane's own in-place call.
        crate::telemetry::request_finished(
            &self.app,
            plane,
            ingress_protocol,
            pool,
            outcome,
            seconds,
        );
    }

    fn telemetry_upstream_attempt(&self, pool_label: &str, lane: usize) {
        crate::telemetry::upstream_attempt(&self.app, pool_label, lane);
    }

    fn telemetry_upstream_failure(&self, pool_label: &str, lane: usize, disposition: &'static str) {
        crate::telemetry::upstream_failure(&self.app, pool_label, lane, disposition);
    }

    fn telemetry_breaker_trip(&self, pool_label: &str, lane: usize) {
        crate::telemetry::breaker_trip(&self.app, pool_label, lane);
    }

    fn telemetry_failover(&self, pool_label: &str, reason: &'static str) {
        crate::telemetry::failover(&self.app, pool_label, reason);
    }

    fn telemetry_translation(&self, from: &str, to: &str) {
        crate::telemetry::translation(from, to);
    }

    fn pool_label<'a>(&self, model: &'a str) -> &'a str {
        crate::ingress::pool_label(&self.app, model)
    }
}

impl busbar_kernel::plane::host::JournalHost for EngineHostImpl {
    fn audit_emit(&self, action: &str, resource: &str, outcome: &str, principal: &str) {
        // Hostless: the admin-audit engine reads `store::now` + the global ring and needs no `HostCtx`.
        // A plain forward to the UNCHANGED core engine.
        crate::audit::auditlog::emit_admin_hostless_now(action, resource, outcome, principal);
    }

    fn audit_record(&self, action: &str, resource: &str, outcome: &'static str, principal: &str) {
        // The in-process admin ring `record_by` seals into the retained ring AND cascades the SAME
        // sealed record onto the durable hostless journal — the superset of `audit_emit`'s durable-only
        // path. The egress audit-and-allow trail reads this ring, so a dropped cross-dialect control
        // lands here byte-identically to the pre-flip `AUDIT.record_by(...)` reach.
        crate::audit_ring::AUDIT.record_by(action, resource, outcome, principal);
    }

    fn call_log_emit(&self, principal: &str, input: busbar_kernel::plane::calllog::CallInput) {
        // Mint a fresh per-call arena over the live engine and drive the chain seam SYNCHRONOUSLY — the
        // `HostCtx` never escapes the call. The plane's former `Some(scope)`/`None` selection (reuse the
        // request arena vs open a fresh one) was a no-op distinction for THIS write: a chain append
        // registers no host handle, so which arena reclaims is immaterial. Same dispatch as the plane's
        // in-place `with_dispatch_scope` leg.
        crate::plane_host::call_log_emit_over(&self.app, principal, input);
    }

    fn call_log_emit_hostless(
        &self,
        principal: &str,
        input: busbar_kernel::plane::calllog::CallInput,
    ) {
        crate::calllog::emit_hostless(principal, input);
    }
}

impl busbar_kernel::plane::host::MountHost for EngineHostImpl {
    fn arrival_envelope_dialect(&self, path: &str) -> &'static str {
        // Pure snapshot mount-table read — the host-driven form of the dropped `ArrivalPayload::app`
        // reach `envelope_dialect(app.planes.ingress_of(path))`.
        crate::ingress::native::envelope_dialect(self.app.planes.ingress_of(path))
    }

    fn arrival_fallback_error(
        &self,
        path: &str,
        status: axum::http::StatusCode,
        kind: &str,
        message: &str,
    ) -> axum::response::Response {
        // Pure snapshot mount-table read — the host-driven form of the dropped `ArrivalPayload::app`
        // reach `fallback_error_response(&app.planes, …)`.
        crate::fallback_error_response(&self.app.planes, path, status, kind, message)
    }
}

impl busbar_kernel::plane::host::RegistryHost for EngineHostImpl {
    fn next_request_id(&self) -> u64 {
        self.app.next_request_id()
    }

    fn plane_slot(&self, key: &str) -> Option<Arc<dyn std::any::Any + Send + Sync>> {
        // Pure map read + Arc clone, mirroring next_request_id: no HostCtx, no vtable slot.
        self.app.plane_slot(key).cloned()
    }

    fn plane_slot_live(&self, key: &str) -> Option<Arc<dyn std::any::Any + Send + Sync>> {
        match &self.handle {
            // Re-read the CURRENT snapshot so a swap after mint is seen.
            Some(h) => h.load().plane_slot(key).cloned(),
            // Snapshot-only mint: the bound snapshot is the only snapshot this host was handed.
            None => self.app.plane_slot(key).cloned(),
        }
    }

    fn secret_resolver(&self) -> Arc<dyn busbar_contract::secret::SecretResolve> {
        // Pure snapshot read: hand the plane the live `Arc<SecretResolver>` behind the neutral
        // `busbar_contract::secret::SecretResolve` seam. The concrete resolver impls the trait (same crate), so the
        // clone coerces to the trait object — no wrapping, the SAME resolver (built-ins + any wired
        // `kind: secret` plugin), fail-closed exactly as core resolution.
        self.app.secret_resolver.clone()
    }

    fn subkey_sign(&self, signing_input: &[u8]) -> Option<[u8; 64]> {
        // SAME dispatch as the veneer: a fresh per-call `DispatchScope`, the `card_sign` slot driven
        // synchronously over a stack-pinned `HostState`, the `HostCtx` never escaping the call. `None`
        // when no card-signing key is held (or, in a build without `plane-a2a`, the slot is unwired).
        crate::plane_host::card_sign_over(&self.app, signing_input)
    }

    fn plane_defs(&self) -> Arc<dyn std::any::Any + Send + Sync> {
        // Pure snapshot read: the type-erased per-plane config the owning plane downcasts, cloned so it
        // outlives the call. Already an `Arc<dyn Any + Send + Sync>` on `App`, so the clone is the whole seam.
        self.app.agent_defs.clone()
    }
}

impl busbar_kernel::plane::host::HookConfigHost for EngineHostImpl {
    fn caller_in_hook_groups(&self, caller_group: Option<&str>, hook_groups: &[String]) -> bool {
        // Fold the `&App::groups_registry` argument host-side; the walk itself is byte-identical.
        crate::config::caller_in_hook_groups(caller_group, hook_groups, &self.app.groups_registry)
    }

    fn plane_gates_of(
        &self,
        plane_key: &str,
        container: &str,
    ) -> Vec<(u16, busbar_kernel::hooks::ResolvedPolicy)> {
        // The set the previous release's gate seam fired, as resolved (`gate::decide` orders it).
        self.app
            .plane_gates(plane_key)
            .and_then(|m| m.get(container))
            .cloned()
            .unwrap_or_default()
    }

    fn plane_rewrites_of(
        &self,
        plane_key: &str,
        container: &str,
    ) -> Vec<(
        std::time::Duration,
        Arc<dyn busbar_contract::hooks::RoutingPolicy>,
    )> {
        self.app
            .plane_rewrites(plane_key)
            .and_then(|m| m.get(container))
            .cloned()
            .unwrap_or_default()
    }

    fn gate_scan(&self) -> Option<(Arc<busbar_kernel::session::SessionStore>, u64)> {
        self.app
            .incremental_scan
            .then(|| (Arc::clone(&self.app.session_store), self.app.config_version))
    }

    // ── HOOK/CONFIG FACADE READS (App-retype WEDGE 2d) — each a pure borrow of the bound snapshot ──

    fn pool_rewrites(
        &self,
        pool: &str,
    ) -> &[(
        std::time::Duration,
        Arc<dyn busbar_contract::hooks::RoutingPolicy>,
    )] {
        // `App::pool_rewrites` already returns the neutral api tuple slice; byte-identical borrow.
        self.app.pool_rewrites(pool)
    }

    fn rewrite_hooks(
        &self,
    ) -> &[(
        std::time::Duration,
        Arc<dyn busbar_contract::hooks::RoutingPolicy>,
    )] {
        &self.app.rewrite_hooks
    }

    fn any_content_hook(&self) -> bool {
        self.app.any_content_hook
    }

    fn tap_hooks(&self) -> &[busbar_kernel::hooks::TapEntry] {
        &self.app.tap_hooks
    }

    fn tap_hooks_response(&self) -> &[busbar_kernel::hooks::TapEntry] {
        &self.app.tap_hooks_response
    }

    fn tap_hooks_routing(&self) -> &[busbar_kernel::hooks::TapEntry] {
        &self.app.tap_hooks_routing
    }

    fn tap_hooks_candidate(&self) -> &[busbar_kernel::hooks::TapEntry] {
        &self.app.tap_hooks_candidate
    }

    fn pool_gates(&self, pool: &str) -> &[(u16, busbar_kernel::hooks::ResolvedPolicy)] {
        self.app.pool_gates(pool)
    }

    fn global_gates(&self) -> &[(u16, busbar_kernel::hooks::ResolvedPolicy)] {
        &self.app.global_gates
    }

    fn pool_policy(&self, pool: &str) -> Option<&busbar_kernel::hooks::ResolvedPolicy> {
        self.app.pool_policy(pool)
    }

    fn requested_signals(&self) -> &busbar_kernel::hooks::RequestedSignals {
        &self.app.requested_signals
    }
}

impl busbar_kernel::plane::host::BudgetHost for EngineHostImpl {
    fn governance_enabled(&self) -> bool {
        self.app.governance.is_some()
    }

    fn meter_charge(
        &self,
        scope: &DispatchScope,
        caller: &busbar_contract::records::PlaneRequestCtx,
        usage: &busbar_contract::abi::hot::Usage,
    ) {
        // Mint the transient `HostCtx` over the caller's arena CARRYING the middleware-resolved
        // `caller` (DEC-SERVE G1b — the host bills that key, never the `Usage` tail's), fire the
        // `meter_charge` slot, and drop the host pointer without letting it escape. Fire-and-forget.
        crate::plane_host::meter_charge_over(&self.app, scope, caller, usage);
    }

    fn rate_headroom(
        &self,
        pin: &busbar_kernel::plane::host::MeterPin,
        key: &busbar_contract::records::VirtualKey,
        pool: Option<&str>,
        now: u64,
    ) -> Option<f64> {
        // Recover the concrete gov/cost the caller's pin was minted over and drive the SAME pure
        // observation `gov.rate_headroom(&app.cost, …)` did — byte-identical, no re-read of the host
        // snapshot. A downcast miss (never in practice) reads as no constraint, matching the
        // `gov`-absent arm at the engine call site.
        pin_models(pin).and_then(|(g, c)| g.rate_headroom(&c, key, pool, now))
    }

    fn budget_state(
        &self,
        pin: &busbar_kernel::plane::host::MeterPin,
        key: &busbar_contract::records::VirtualKey,
        now: u64,
    ) -> Vec<busbar_contract::hooks::BudgetBucketState> {
        pin_models(pin).map_or_else(Vec::new, |(g, c)| g.budget_state(&c, key, now))
    }

    fn governance(&self) -> Option<busbar_kernel::plane::host::GovHandle> {
        // One Arc bump, erased to `dyn Any` — byte-identical to the sink's `app.governance.clone()`.
        self.app.governance.clone().map(|g| {
            busbar_kernel::plane::host::GovHandle(g as Arc<dyn std::any::Any + Send + Sync>)
        })
    }

    // The pin carries THIS snapshot's card (one Arc bump) — the card a request's money is settled
    // against for its whole life, whatever a reload does meanwhile. Only the kernel's host can pin one.
    fn meter_pin(&self) -> Option<busbar_kernel::plane::host::MeterPin> {
        let cost = busbar_kernel::plane::host::CostHandle(self.app.cost.clone());
        self.governance()
            .map(|gov| busbar_kernel::plane::host::MeterPin { gov, cost })
    }

    fn cost_model_unpriced(&self, model: &str) -> bool {
        // The SAME read the in-place pre-admission guard makes off `app.cost`: `false` for every name
        // when no card is configured (there is no card to miss).
        self.app.cost.model_unpriced(model)
    }

    fn meter_ledger(
        &self,
        pin: &busbar_kernel::plane::host::MeterPin,
        key: &busbar_contract::records::VirtualKey,
        pool: &str,
        model: &str,
        usage: &busbar_contract::billing::Usage,
        now: u64,
    ) {
        // Recover the concrete gov/cost the plane's pin was minted over and drive the SAME accrual
        // `sink.gov.record_usage(&sink.cost, …)` did. The neutral `Usage` carries the one name-keyed
        // unit map (reserved four + opens); accrual folds it straight into the cell. A downcast miss
        // (never in practice — the pin is minted here) is a silent no-op, matching `record_usage`'s
        // own fail-soft posture.
        if let Some((g, c)) = pin_models(pin) {
            g.record_usage(&c, key, pool, model, &usage.usage_units, now);
        }
    }

    fn meter_refund_fee(
        &self,
        pin: &busbar_kernel::plane::host::MeterPin,
        key: &busbar_contract::records::VirtualKey,
        pool: &str,
        plane: &str,
        fee_unit: &str,
        now: u64,
    ) {
        // The refund primitive reads a plane-qualified pool: the plane names the fee lane, the pool
        // the buckets the count reached.
        if let Some((g, c)) = pin_models(pin) {
            let pool = format!("{plane}{}{pool}", crate::governance::PLANE_LANE_SEP);
            g.refund_fee_unit(&c, key, &pool, now, fee_unit);
        }
    }

    fn meter_series(
        &self,
        gov: &busbar_kernel::plane::host::GovHandle,
        key_id: &str,
        model: &str,
        provider: &str,
        usage: Option<&busbar_contract::billing::TokenUsage>,
        now: u64,
    ) {
        if let Ok(g) = gov.0.clone().downcast::<crate::governance::GovState>() {
            g.record_metering(key_id, model, provider, usage, now);
        }
    }
}

/// Recover the concrete `CostModel` an opaque [`CostHandle`](busbar_kernel::plane::host::CostHandle)
/// was minted over; `None` on a handle the kernel's host did not mint (a plane-side host's pin).
fn cost_model(
    cost: &busbar_kernel::plane::host::CostHandle,
) -> Option<Arc<crate::cost::CostModel>> {
    cost.0.clone().downcast().ok()
}

/// The `(GovState, CostModel)` pair behind a [`MeterPin`](busbar_kernel::plane::host::MeterPin) — the
/// one recovery every pinned budget seam above makes; `None` when either handle misses.
fn pin_models(
    pin: &busbar_kernel::plane::host::MeterPin,
) -> Option<(
    Arc<crate::governance::GovState>,
    Arc<crate::cost::CostModel>,
)> {
    Some((pin.gov.0.clone().downcast().ok()?, cost_model(&pin.cost)?))
}

#[async_trait::async_trait]
impl busbar_kernel::plane::host::IdentityHost for EngineHostImpl {
    fn quarantine_settle(&self, subject: &str, state: crate::trust::TrustState) -> bool {
        crate::plane_host::trust::quarantine_settle_over(&self.app, subject, state)
    }

    fn approval_redeem(&self, nonce: &str, expires_at: u64, now: u64) -> bool {
        // A fresh per-call arena backs the borrow; the redemption registers no host handle, so which
        // arena reclaims is immaterial. The `ApprovalQuery` is built HERE so the plane passes only the
        // nonce/expiry/now — it never names the `#[repr(C)]` POD or the `SpentTokenLedger`.
        crate::plane_host::approval_redeem_over(&self.app, nonce, expires_at, now)
    }

    #[cfg(any(test, feature = "test-support"))]
    fn verify_token_test(&self, token: &str) -> Option<Arc<busbar_contract::records::VirtualKey>> {
        self.app
            .governance
            .as_ref()
            .and_then(|g| g.verify_token(token, busbar_kernel::store::now(), None))
    }

    fn identity_audience_binding(
        &self,
        token: &str,
        expected_aud: &str,
    ) -> busbar_kernel::plane::host::AudienceBinding {
        // A pure judgement — no `HostCtx`, no engine state. `inspect_bearer` returns the enum this
        // trait method's type re-exports, so this is a direct forward to the UNCHANGED core seam.
        crate::auth::audience::inspect_bearer(token, expected_aud)
    }

    async fn identity_admit(
        &self,
        token: Option<String>,
        audience: String,
        resource: String,
    ) -> Result<
        (
            busbar_contract::auth::AuthPrincipal,
            busbar_contract::records::PlaneRequestCtx,
        ),
        busbar_contract::auth::IdentityRefusal,
    > {
        // The veneer already spawns a blocking closure that mints + consumes the `HostCtx` on a
        // blocking thread; this only awaits the join, so no `HostCtx` crosses the `.await` and the
        // future stays `Send`.
        crate::plane_host::identity_admit_over(Arc::clone(&self.app), token, audience, resource)
            .await
    }

    fn principal_standing(
        &self,
        standing: &busbar_kernel::trust::validate::Standing,
        live_gen: u64,
        now: u64,
    ) -> Result<
        Option<Arc<busbar_contract::records::VirtualKey>>,
        busbar_kernel::trust::validate::Lapsed,
    > {
        // Inject the host's live `GovState` AND the live `role_bindings` through the `GovResolve` seam
        // so the plane holds only the `Standing`. The bindings are per-snapshot (rebuilt on every
        // config apply), so they are read off the CURRENT snapshot when the host retains the live
        // handle: a role-bound principal is re-checked against the bindings in force now, never the
        // ones it was admitted under. A registry key re-resolves exactly as before.
        let live = self.handle.as_ref().map(|h| h.load());
        let app = live.as_ref().unwrap_or(&self.app);
        let resolve = crate::governance::LiveResolve {
            governance: app.governance.as_deref(),
            role_bindings: &app.role_bindings,
        };
        standing.still_permitted(
            Some(&resolve as &dyn busbar_kernel::trust::validate::GovResolve),
            live_gen,
            now,
        )
    }

    fn ask_state_sealer(&self) -> Option<busbar_kernel::plane::approvals::Sealer> {
        self.app
            .governance
            .as_ref()
            .and_then(|g| crate::plane::approvals::ask_state_sealer(g))
    }
}

impl busbar_kernel::plane::host::AdmissionHost for EngineHostImpl {
    fn gate_decide(
        &self,
        plane_key: &str,
        container: &str,
        request_id: u64,
        tool: &str,
        args_json: &[u8],
        key: Option<(&str, &str)>,
        session_id: Option<&str>,
    ) -> busbar_kernel::plane::host::GateOutcome {
        crate::plane_host::gate_decide_over(
            &self.app, plane_key, container, request_id, tool, args_json, key, session_id,
        )
    }

    fn gate_attached(&self, plane_key: &str, container: &str) -> bool {
        // Pure snapshot read of the generic per-plane gate map, keyed by the opaque registry key.
        self.app
            .plane_gates(plane_key)
            .is_some_and(|g| g.contains_key(container))
    }

    fn tap_attached(&self, plane_key: &str, container: &str) -> bool {
        // Pure snapshot read of the generic per-plane REWRITE map — the tap twin of `gate_attached`.
        // `resolve_container_rewrites` never files an empty chain, so presence == a real rewrite hook.
        self.app
            .plane_rewrites(plane_key)
            .and_then(|m| m.get(container))
            .is_some_and(|c| !c.is_empty())
    }

    fn transform_over(
        &self,
        plane_key: &str,
        container: &str,
        request_id: u64,
        tool: &str,
        args_json: &[u8],
        _key: Option<(&str, &str)>,
        _session_id: Option<&str>,
    ) -> busbar_kernel::plane::host::TransformVerdict {
        transform_over_over(&self.app, plane_key, container, request_id, tool, args_json)
    }

    fn govern_admit_reason(
        &self,
        scope: &DispatchScope,
        caller: &busbar_contract::records::PlaneRequestCtx,
        pool: &[u8],
    ) -> busbar_kernel::plane::host::GovAdmit {
        crate::plane_host::govern_admit_reason_over(&self.app, scope, caller, pool)
    }

    fn destination_guard(
        &self,
        gov: &busbar_contract::records::PlaneRequestCtx,
        proto: &'static str,
        pool: &str,
        started: std::time::Instant,
        charged_at: u64,
    ) -> Result<(), Box<axum::response::Response>> {
        crate::ingress::destination_guard(&self.app, gov, proto, pool, started, charged_at)
    }

    fn admission_door(
        &self,
        gov: &busbar_contract::records::PlaneRequestCtx,
        proto: &'static str,
        pool: &str,
        started: std::time::Instant,
        charged_at: u64,
    ) -> Result<
        (
            Option<busbar_kernel::plane::host::AdmitHandle>,
            Option<String>,
        ),
        Box<axum::response::Response>,
    > {
        // Byte-identical to the in-place door (`GovCtx` IS `PlaneRequestCtx`); the produced `AdmitGrant`
        // is wrapped in the opaque `AdmitHandle` the plane's sink holds Drop-only. The `Arc::new` here
        // mirrors the engine's own `admit.map(Arc::new)` at the sink-build site.
        crate::ingress::admission_door(&self.app, gov, proto, pool, started, charged_at).map(
            |(admit, downgraded)| {
                (
                    admit.map(|a| {
                        busbar_kernel::plane::host::AdmitHandle(
                            Arc::new(a) as Arc<dyn std::any::Any + Send + Sync>
                        )
                    }),
                    downgraded,
                )
            },
        )
    }

    fn admission_check(
        &self,
        gov: &busbar_contract::records::PlaneRequestCtx,
        proto: &'static str,
        pool: &str,
        charged_at: u64,
    ) -> Result<
        (
            Option<busbar_kernel::plane::host::AdmitHandle>,
            Option<String>,
        ),
        Box<axum::response::Response>,
    > {
        // The door's own body, minus the `finish_rejected` the door wraps its refusing arm in: same
        // buckets, same charge, same downgrade, same bytes. The grant is wrapped in the opaque
        // handle exactly as `admission_door` wraps it, so the two seams differ in nothing but which
        // side of them posts the refusal.
        crate::ingress::admit_check(&self.app, gov, proto, pool, charged_at).map(
            |(admit, downgraded)| {
                (
                    admit.map(|a| {
                        busbar_kernel::plane::host::AdmitHandle(
                            Arc::new(a) as Arc<dyn std::any::Any + Send + Sync>
                        )
                    }),
                    downgraded,
                )
            },
        )
    }

    fn finish_admitted(
        &self,
        gov: &busbar_contract::records::PlaneRequestCtx,
        ingress_protocol: &str,
        pool: &str,
        started: std::time::Instant,
        charged_at: u64,
        resp: axum::response::Response,
        charged: Option<&busbar_kernel::plane::host::AdmitHandle>,
    ) -> axum::response::Response {
        // The handle is the grant `admission_check`/`admission_door` wrapped: its charge is what a
        // non-2xx end refunds.
        let grant = charged.and_then(|h| h.0.downcast_ref::<crate::governance::AdmitGrant>());
        crate::ingress::finish_admitted(
            &self.app,
            gov,
            ingress_protocol,
            pool,
            started,
            charged_at,
            resp,
            grant.map(crate::governance::AdmitGrant::charge),
        )
    }

    fn finish_rejected(
        &self,
        gov: &busbar_contract::records::PlaneRequestCtx,
        ingress_protocol: &str,
        pool: &str,
        started: std::time::Instant,
        charged_at: u64,
        resp: axum::response::Response,
    ) -> axum::response::Response {
        crate::ingress::finish_rejected(
            &self.app,
            gov,
            ingress_protocol,
            pool,
            started,
            charged_at,
            resp,
        )
    }

    fn plane_audience_bound(&self, plane_key: &str) -> bool {
        // Pure snapshot read: is the plane identified by the opaque registry key mounted under an
        // audience-bound door?
        self.app
            .planes
            .mount_of(plane_key)
            .and_then(|m| self.app.planes.admission_for(m))
            .is_some()
    }
}

#[async_trait::async_trait]
impl busbar_kernel::plane::host::CompletionHost for EngineHostImpl {
    async fn synthesize_completion(
        &self,
        _gov: &busbar_contract::records::PlaneRequestCtx,
        _model: &str,
        _body: bytes::Bytes,
        _max_body_bytes: usize,
    ) -> Result<
        busbar_kernel::plane::host::HostCompletion,
        busbar_kernel::plane::host::CompletionRefusal,
    > {
        // No linked plane installs a resolved-completion synthesizer (the seam left with the engine
        // that installed it), so there is no dialect to drive: the caller gets the neutral refusal
        // and words it in its own vocabulary.
        Err(busbar_kernel::plane::host::CompletionRefusal::NotInstalled)
    }
}

// `EngineHost` declares no method of its own beyond the provided `run_gauntlet`; it is purely the SUM
// of the capability slices above. This blanket impl is therefore empty — the sum is satisfied through
// the slice impls, and the substrate-side compile-time witness enforces that equality.
#[async_trait::async_trait]
impl busbar_kernel::plane::host::EngineHost for EngineHostImpl {}

/// Mint an `Arc<dyn EngineHost>` over the live `app` — the constructor core hands a plane so the
/// plane calls the neutral seam instead of naming `plane_host::*_over(&App, …)`. Cheap: one `Arc`
/// clone; the transient `HostCtx` is minted per method call, never here.
#[must_use]
pub fn engine_host(app: &Arc<App>) -> Arc<dyn busbar_kernel::plane::host::EngineHost> {
    Arc::new(EngineHostImpl::new(Arc::clone(app)))
}

/// THE ALLOC-FREE BORROWED HOST CARRIER (1.6.0 KEYSTONE): an owned [`EngineHost`] value the caller
/// keeps on its STACK and coerces to `&dyn EngineHost`, so a plane reaches the host seam WITHOUT the
/// per-request `Arc::new` heap allocation [`engine_host`] pays. The whole cost is one `Arc::clone` of
/// the snapshot (an atomic refcount bump — NOT a heap allocation, so it never touches the engine's
/// alloc-gate count), and the `&dyn` coercion of the stack value allocates nothing. Returned opaque
/// (`impl EngineHost`) so the plane names no core type. The two async seam methods
/// (`identity_admit`/`synthesize_completion`) still work — they `Arc::clone` internally — but the
/// engine hot path calls only the SYNC methods, so this borrowed carrier is the right one there.
#[must_use]
pub fn engine_host_value(app: &Arc<App>) -> impl busbar_kernel::plane::host::EngineHost + 'static {
    EngineHostImpl::new(Arc::clone(app))
}

/// Mint an `Arc<dyn EngineHost>` over the CURRENT snapshot of a live [`AppHandle`] — the form the
/// route adapter and the detached-runner / stdio paths reach for, which hold a swappable handle
/// rather than a pinned `Arc<App>`. Loads the handle once; the clock the seam reads is engine-snapshot
/// independent (it drives the host wall clock), so a later config swap does not change the value.
#[must_use]
pub fn engine_host_from_handle(
    handle: &Arc<crate::state::AppHandle>,
) -> Arc<dyn busbar_kernel::plane::host::EngineHost> {
    // `from_handle` (not `engine_host(&handle.load())`): retains the live handle so `plane_slot_live`
    // re-reads the CURRENT snapshot on the route/detached-runner/stdio paths, which must see a config
    // swap that lands after admission. The bound snapshot stays `handle.load()` — byte-identical.
    Arc::new(EngineHostImpl::from_handle(Arc::clone(handle)))
}

/// Mint a NEUTRAL [`LiveHostFactory`](busbar_kernel::plane::host::LiveHostFactory) closing over a live
/// [`AppHandle`](crate::state::AppHandle): each call returns a fresh `from_handle` host whose BOUND
/// snapshot is the handle's CURRENT load and whose `plane_slot_live` re-reads the live handle — so a
/// transport that re-mints per frame sees a config swap that lands between calls. Byte-identical to
/// calling [`engine_host_from_handle`] on each frame, handed to a plane that must not name the handle.
#[must_use]
pub fn live_host_factory(
    handle: std::sync::Arc<crate::state::AppHandle>,
) -> busbar_kernel::plane::host::LiveHostFactory {
    std::sync::Arc::new(move || {
        std::sync::Arc::new(EngineHostImpl::from_handle(std::sync::Arc::clone(&handle)))
            as Arc<dyn busbar_kernel::plane::host::EngineHost>
    })
}

/// THE LIVE RE-RESOLUTION a door unit's entitlement asks through (`entitlement.check`, ARCHITECT
/// round 4 Q-L3B-SURFACES (a)): an admitted principal re-resolved against the CURRENT snapshot's
/// governance registry (a registry key, by id) and `role_bindings` (a role-bound key), exactly as
/// [`EngineHost::principal_standing`] judges a long-lived response's frame. `None` when it no longer
/// stands; a deployment with governance off stands as admitted.
#[must_use]
pub fn live_standing(
    handle: std::sync::Arc<crate::state::AppHandle>,
) -> crate::host_services::Standing {
    std::sync::Arc::new(move |admitted, now| {
        let app = handle.load();
        standing_in(&app, admitted, now)
    })
}

/// [`live_standing`] over one fixed generation `app` (a composition with no live handle).
#[must_use]
pub fn standing_over(app: std::sync::Arc<crate::state::App>) -> crate::host_services::Standing {
    std::sync::Arc::new(move |admitted, now| standing_in(&app, admitted, now))
}

/// `admitted` as it stands in `app` at `now`.
fn standing_in(
    app: &crate::state::App,
    admitted: &Arc<busbar_contract::records::VirtualKey>,
    now: u64,
) -> Option<Arc<busbar_contract::records::VirtualKey>> {
    let resolve = crate::governance::LiveResolve {
        governance: app.governance.as_deref(),
        role_bindings: &app.role_bindings,
    };
    let standing = busbar_kernel::trust::validate::Standing::opened(
        Some(admitted),
        busbar_kernel::trust::validate::Snapshot::Watching,
        std::time::Duration::MAX,
    );
    match standing.still_permitted(
        Some(&resolve as &dyn busbar_kernel::trust::validate::GovResolve),
        0,
        now,
    ) {
        Ok(Some(live)) => Some(live),
        Ok(None) => Some(Arc::clone(admitted)),
        Err(_) => None,
    }
}

// The request-admission gate verdict is a pure POD naming only `busbar_contract::abi::hot` + std, so it now
// lives in the substrate beside the neutral `EngineHost` seam; core re-exports it so every in-core
// caller (`gate_decide_over`, a2a) is unchanged.

/// Fire the operator's REQUEST-ADMISSION TRANSFORM (`<section>.hooks:` `prompt: rw`) chain over the
/// container's resolved rewrite hooks and reconstruct the [`TransformVerdict`] — the TAP/observe-
/// transform twin of [`gate_decide_over`]. The host owns and re-selects the chain by `(plane_key,
/// container)`, so an MCP/A2A plane body admits a rewrite pass over its payload without ever naming
/// `crate::hooks` or holding the resolved `Arc<dyn RoutingPolicy>` set (the Seam-B inversion), exactly
/// as it fires the gate.
///
/// The projection is the SAME `InvokeReq` the gate builds from `(tool, arguments)` — rebuilt from the
/// CURRENT arguments on every iteration so a later hook sees the earlier rewrite (a true transform
/// chain, mirroring the LLM `apply_global_rewrites` seam). Precedence on the transform path is the
/// canonical **reject > rewrite > abstain**.
///
/// FAIL-SAFE, not fail-closed: a rewrite is an OBSERVE/transform pass (the admission GATE already ran
/// and screened the request), so a hook that errors, times out or abstains — or a runtime that will
/// not start — proceeds with the ORIGINAL payload, byte-for-byte. Only an explicit `reject` stops the
/// request, and only a committed `rewrite` changes a byte.
///
/// Drives the ASYNC hooks on a fresh current-thread runtime, so it MUST be called from a BLOCKING
/// thread (`spawn_blocking`) — `block_on` on a runtime worker would panic — exactly like
/// [`gate_decide_over`].
#[allow(dead_code)]
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn transform_over_over(
    app: &App,
    plane_key: &str,
    container: &str,
    request_id: u64,
    tool: &str,
    args_json: &[u8],
) -> busbar_kernel::plane::host::TransformVerdict {
    // Resolve THIS container's rewrite chain. Empty ⇒ nothing attached ⇒ byte-identical no-op. The
    // caller already guards on `tap_attached`; the re-check keeps the fn correct if invoked directly.
    let chain: &[(std::time::Duration, Arc<dyn crate::hooks::RoutingPolicy>)] = app
        .plane_rewrites(plane_key)
        .and_then(|m| m.get(container))
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    if chain.is_empty() {
        return TransformVerdict::Proceed {
            applied: false,
            args_json: args_json.to_vec(),
        };
    }
    // Rebuild the caller's arguments `Value`. Byte-safe because `serde_json`'s `preserve_order` is OFF
    // (a `Value` object is a sorted-stable `BTreeMap`), so `to_vec`→`from_slice` round-trips to the
    // identical `Value` — the same guarantee the gate seam relies on.
    let mut arguments: serde_json::Value =
        serde_json::from_slice(args_json).unwrap_or(serde_json::Value::Null);
    // The `ingress_protocol` label IS the plane's stable decl key (the gate seam's convention).
    let ingress = plane_key;
    // Drive the async chain on a fresh current-thread runtime (the gate precedent). A runtime that will
    // not start is FAIL-SAFE here (proceed with the original body) because the admission gate already
    // ran — a transform is not an admission point.
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(_) => {
            return TransformVerdict::Proceed {
                applied: false,
                args_json: args_json.to_vec(),
            }
        }
    };
    let mut applied = false;
    for (timeout, hook) in chain {
        // Re-read the InvokeReq facts from the CURRENT arguments so a later hook sees the earlier
        // rewrite — a true transform chain.
        let facts = busbar_contract::ir::invoke::InvokeReq {
            tool: tool.to_string(),
            arguments: arguments.clone(),
            extra: Default::default(),
        };
        let req = build_invoke_rewrite_request(&facts, ingress, request_id);
        crate::audit::amend::hook_read(hook.name(), None, ingress, false);
        let outcome = rt.block_on(hook.transform(&req, *timeout));
        drop(req); // end the immutable borrow of `facts` before the next iteration reuses `arguments`
        match outcome {
            busbar_contract::hooks::TransformOutcome::Rewrite(rw) => {
                applied |= apply_rewrite_to_invoke_args(&mut arguments, &rw);
            }
            busbar_contract::hooks::TransformOutcome::Reject { status, message } => {
                // Already status-clamped + message-sanitized at the wire seam.
                return TransformVerdict::Reject {
                    status,
                    message,
                    hook: hook.name().to_string(),
                };
            }
            busbar_contract::hooks::TransformOutcome::Abstain => {}
            // The hook could not answer, and its disposition says to carry on — a load-bearing
            // hook's failed call arrived as `Reject` above, applied by the resolver's decorator
            // before it reached this (or any other) firing site. Logged, never silent.
            busbar_contract::hooks::TransformOutcome::Failed { message } => {
                tracing::warn!(
                    hook = hook.name(),
                    error = %message,
                    "invoke rewrite hook could not answer; proceeding with the original arguments"
                );
            }
        }
    }
    // Re-serialize ONLY when a rewrite actually landed; otherwise hand back the caller's ORIGINAL bytes
    // untouched, so a chain of purely-abstaining hooks is byte-identical to no chain at all.
    let out = if applied {
        serde_json::to_vec(&arguments).unwrap_or_else(|_| args_json.to_vec())
    } else {
        args_json.to_vec()
    };
    TransformVerdict::Proceed {
        applied,
        args_json: out,
    }
}

/// Build the rewrite (`prompt: rw`) request projection over the NEUTRAL [`IrFacts`] content walk — the
/// core-side, chat-type-free twin of the LLM plane's `build_rewrite_request`. A rewrite hook is a
/// content hook, so the prompt is ALWAYS sent (a `prompt: rw` grant is the resolution ticket); identity
/// is omitted (rewrite operates on content, not caller identity). For the invoke family this projects
/// ONE `("user", <arguments json>)` message — the arguments are the untrusted content a screening
/// rewrite hook acts on. The content ceiling is enforced on serialized bytes exactly as the LLM seam
/// enforces it.
///
/// [`IrFacts`]: busbar_contract::ir::facts::IrFacts
fn build_invoke_rewrite_request<'a>(
    facts: &'a dyn busbar_contract::ir::facts::IrFacts,
    ingress_protocol: &'a str,
    request_id: u64,
) -> busbar_contract::hooks::RoutingRequest<'a> {
    use busbar_contract::ir::facts::Slot;
    use std::borrow::Cow;
    let shape = facts.shape();
    let mut system_pieces: Vec<String> = Vec::new();
    let mut messages: Vec<(Cow<'a, str>, Cow<'a, str>)> = Vec::new();
    for item in facts.content() {
        let text = item.screenable_text().into_owned();
        if matches!(item.slot(), Slot::System) {
            system_pieces.push(text);
        } else {
            messages.push((Cow::Borrowed(item.author()), Cow::Owned(text)));
        }
    }
    let system = if system_pieces.is_empty() {
        None
    } else {
        Some(Cow::Owned(system_pieces.join("\n")))
    };
    let prompt =
        crate::hooks::content_capped(busbar_contract::hooks::PromptProjection { system, messages });
    busbar_contract::hooks::RoutingRequest {
        request_id,
        // A rewrite over a plane payload has no LLM routing pool; the wire omits it for the rewrite
        // projection (RESERVED field, no reader), so the empty label is neutral.
        pool: "",
        ingress_protocol,
        requested_model: None,
        message_count: shape.turn_count,
        tool_count: shape.tool_count,
        has_tools: shape.has_tools,
        total_chars: shape.text_chars,
        system_chars: shape.system_chars,
        max_tokens: shape.max_tokens,
        stream: facts.wants_stream(),
        prompt: Some(prompt),
        identity: None,
        signals: Default::default(),
        session: None,
    }
}

/// Apply a hook's `rewrite` reply to an INVOKE payload's `arguments` — the invoke-family twin of the
/// LLM plane's `apply_rewrite_to_body`. This seam names no dialect: an invocation has no conversation
/// container to reframe, it has one untrusted content member (the `arguments` object), and the rewrite
/// REPLACES it.
///
/// # The invoke rewrite contract
///
/// A `prompt: rw` hook rewrites a tool call by returning a replacement arguments OBJECT, carried as a
/// rewrite `messages` entry — either the message's `content` (an object verbatim, or a JSON string
/// that parses to an object) or, for a bare message with no `role`, the message value itself. The LAST
/// message that yields a usable object wins (a true chain: a later hook overrides an earlier one).
///
/// FAIL-CLOSED end to end: a reply with no usable object (empty messages, plain-text content, a
/// non-object) leaves `arguments` UNTOUCHED and returns `false` — never a corrupted call.
fn apply_rewrite_to_invoke_args(
    args: &mut serde_json::Value,
    rw: &busbar_contract::hooks::RewriteReply,
) -> bool {
    let mut new_args: Option<serde_json::Value> = None;
    for msg in &rw.messages {
        // Prefer an explicit `content`; fall back to the message value itself only when it carries no
        // `role` (a bare args object), so a `{role, content:"text"}` message never leaks its role key
        // into the arguments.
        let candidate = match msg.get("content") {
            Some(c) => c,
            None if msg.get("role").is_none() => msg,
            None => continue,
        };
        let resolved = match candidate {
            serde_json::Value::Object(_) => Some(candidate.clone()),
            serde_json::Value::String(s) => serde_json::from_str::<serde_json::Value>(s)
                .ok()
                .filter(serde_json::Value::is_object),
            _ => None,
        };
        if resolved.is_some() {
            new_args = resolved;
        }
    }
    match new_args {
        Some(v) => {
            *args = v;
            true
        }
        None => false,
    }
}

#[cfg(test)]
#[path = "tests/host_impl_tests.rs"]
mod tests;
