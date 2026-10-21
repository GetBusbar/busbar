// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `plane_host` — the HOST side of a plane's calls into the kernel: the [`EngineHost`] seam and its
//! capability bodies.
//!
//! A plane reaches the kernel through the [`EngineHost`] supertraits; the kernel answers by calling
//! its own functions directly over plain Rust types. No plugin is on the other side of this seam, so
//! it carries no C-layout shape (BUSBAR-1.6.0.md THE DESIGN §11.5 l.1338-1349); the old HOT lane's
//! `PlaneHostVtable` and its PODs are retired (§11.11 l.1444-1446).
//!
//! The per-dispatch arena (`scope`), the plane-side breaker admission (`breaker`) and the
//! arena-billed governance charge (`govern`) are gone with the plane-side failover walk and the
//! gauntlet riders they served: a door plane's admission, breaker and money run on the kernel's
//! plane driver (`crate::plane_driver`) over the kernel's own breaker store and governance book.

use crate::state::App;
use std::sync::Arc;

/// The host wall clock in Unix NANOSECONDS: `busbar_kernel::store::now_ms` scaled up, so a plane
/// reads the kernel's one clock and no ambient one. `0` if the read panics, never a wild value.
fn clock_now_nanos() -> u64 {
    std::panic::catch_unwind(|| busbar_kernel::store::now_ms().saturating_mul(1_000_000))
        .unwrap_or(0)
}

/// Read the host wall clock in whole SECONDS — the host-driven form of a plane's
/// [`busbar_kernel::store::now`]. The clock is read in Unix NANOSECONDS (`clock_now_nanos`) and
/// scaled back down, so the value is identical to reading `store::now` in place.
#[must_use]
pub fn clock_now_secs_over(_app: &App) -> u64 {
    clock_now_nanos() / 1_000_000_000
}

/// Read the host wall clock in MILLISECONDS — the host-driven form of
/// [`busbar_kernel::store::now_ms`], read through `clock_now_nanos` and scaled back, so the value is
/// identical to reading `store::now_ms` in place. `store::now_ms` is crate-private, so this is the
/// form a plane compiled apart from the host reaches the same clock through.
#[must_use]
pub fn clock_now_ms_over(_app: &App) -> u64 {
    clock_now_nanos() / 1_000_000
}

/// Core's implementation of the neutral [`EngineHost`](busbar_kernel::plane_host::EngineHost)
/// seam over the live [`App`]. A plane holds this behind an
/// `Arc<dyn busbar_kernel::plane_host::EngineHost>` and calls typed, safe methods on it INSTEAD of
/// naming `plane_host::*_over(&App, …)` — so a plane compiled apart from the host reaches the same
/// host functions without ever naming a core type.
///
/// Owns an `Arc<App>` (the config generation the reaches run against) so the handle is
/// `Send + Sync + 'static` and safe to carry across `.await`: each method builds whatever borrowed
/// state it needs for the duration of the call, drives the kernel function SYNCHRONOUSLY, and
/// returns an owned value.
#[derive(Clone)]
pub struct EngineHostImpl {
    /// The BOUND engine snapshot the host reaches run against — loaded once at mint. Serves every
    /// method.
    app: Arc<App>,
}

impl EngineHostImpl {
    /// Build the host implementation over the live `app`.
    #[must_use]
    pub fn new(app: Arc<App>) -> Self {
        EngineHostImpl { app }
    }

    /// Build the host over a live [`AppHandle`](crate::state::AppHandle): the bound snapshot is the
    /// handle's CURRENT load, byte-identical to `new(handle.load())`.
    #[must_use]
    pub fn from_handle(handle: Arc<crate::state::AppHandle>) -> Self {
        EngineHostImpl { app: handle.load() }
    }
}

// AUDIT-D BRAKE: the LANE/POOL family, split off `EngineHost` into its `LanePoolHost` supertrait.
// Relocated byte-for-byte from the flat impl; `EngineHost: LanePoolHost` keeps every call site working.
impl busbar_kernel::plane_host::LanePoolHost for EngineHostImpl {
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
impl busbar_kernel::plane_host::MeteringHost for EngineHostImpl {
    fn price_usage(&self, model: &str, usage: &busbar_contract::billing::Usage) -> Option<u128> {
        // Price against the BOUND snapshot's resolved `CostModel` — the SAME rate card + arithmetic the
        // LLM enforcement/derive path prices with (a new reader, not a new pricer), so a live voice
        // carrier meters against the deployment's real rates while staying plane-neutral.
        self.app.cost.price_usage_nanos(model, usage)
    }
}

// M4 (god-trait split): the single `EngineHostImpl` implements each capability slice `EngineHost`
// now sums. Every method body is byte-identical to the pre-split flat `impl EngineHost` — only the
// impl block it lives in changed. `EngineHost` itself declares no method of its own, so the blanket
// `impl EngineHost for EngineHostImpl` below is empty: the sum is satisfied entirely through the
// slice impls.

impl busbar_kernel::plane_host::ClockHost for EngineHostImpl {
    fn clock_now_secs(&self) -> u64 {
        // The same read as the veneer: the kernel's one clock, scaled to seconds.
        clock_now_secs_over(&self.app)
    }

    fn clock_now_ms(&self) -> u64 {
        clock_now_ms_over(&self.app)
    }
}

impl busbar_kernel::plane_host::TelemetryHost for EngineHostImpl {
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

impl busbar_kernel::plane_host::JournalHost for EngineHostImpl {
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
}

impl busbar_kernel::plane_host::MountHost for EngineHostImpl {
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

impl busbar_kernel::plane_host::RegistryHost for EngineHostImpl {
    fn next_request_id(&self) -> u64 {
        self.app.next_request_id()
    }

    fn plane_slot(&self, key: &str) -> Option<Arc<dyn std::any::Any + Send + Sync>> {
        // Pure map read + Arc clone, mirroring next_request_id: no HostCtx, no vtable slot.
        self.app.plane_slot(key).cloned()
    }

    fn secret_resolver(&self) -> Arc<dyn busbar_contract::secret::SecretResolve> {
        // Pure snapshot read: hand the plane the live `Arc<SecretResolver>` behind the neutral
        // `busbar_contract::secret::SecretResolve` seam. The concrete resolver impls the trait (same crate), so the
        // clone coerces to the trait object — no wrapping, the SAME resolver (built-ins + any wired
        // `kind: secret` plugin), fail-closed exactly as core resolution.
        self.app.secret_resolver.clone()
    }
}

impl busbar_kernel::plane_host::HookConfigHost for EngineHostImpl {
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

impl busbar_kernel::plane_host::BudgetHost for EngineHostImpl {
    fn governance_enabled(&self) -> bool {
        self.app.governance.is_some()
    }

    fn rate_headroom(
        &self,
        pin: &busbar_kernel::plane_host::MeterPin,
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
        pin: &busbar_kernel::plane_host::MeterPin,
        key: &busbar_contract::records::VirtualKey,
        now: u64,
    ) -> Vec<busbar_contract::hooks::BudgetBucketState> {
        pin_models(pin).map_or_else(Vec::new, |(g, c)| g.budget_state(&c, key, now))
    }

    fn governance(&self) -> Option<busbar_kernel::plane_host::GovHandle> {
        // One Arc bump, erased to `dyn Any` — byte-identical to the sink's `app.governance.clone()`.
        self.app.governance.clone().map(|g| {
            busbar_kernel::plane_host::GovHandle(g as Arc<dyn std::any::Any + Send + Sync>)
        })
    }

    // The pin carries THIS snapshot's card (one Arc bump) — the card a request's money is settled
    // against for its whole life, whatever a reload does meanwhile. Only the kernel's host can pin one.
    fn meter_pin(&self) -> Option<busbar_kernel::plane_host::MeterPin> {
        let cost = busbar_kernel::plane_host::CostHandle(self.app.cost.clone());
        self.governance()
            .map(|gov| busbar_kernel::plane_host::MeterPin { gov, cost })
    }

    fn cost_model_unpriced(&self, model: &str) -> bool {
        // The SAME read the in-place pre-admission guard makes off `app.cost`: `false` for every name
        // when no card is configured (there is no card to miss).
        self.app.cost.model_unpriced(model)
    }

    fn meter_ledger(
        &self,
        pin: &busbar_kernel::plane_host::MeterPin,
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
        pin: &busbar_kernel::plane_host::MeterPin,
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
        gov: &busbar_kernel::plane_host::GovHandle,
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

/// Recover the concrete `CostModel` an opaque [`CostHandle`](busbar_kernel::plane_host::CostHandle)
/// was minted over; `None` on a handle the kernel's host did not mint (a plane-side host's pin).
fn cost_model(cost: &busbar_kernel::plane_host::CostHandle) -> Option<Arc<crate::cost::CostModel>> {
    cost.0.clone().downcast().ok()
}

/// The `(GovState, CostModel)` pair behind a [`MeterPin`](busbar_kernel::plane_host::MeterPin) — the
/// one recovery every pinned budget seam above makes; `None` when either handle misses.
fn pin_models(
    pin: &busbar_kernel::plane_host::MeterPin,
) -> Option<(
    Arc<crate::governance::GovState>,
    Arc<crate::cost::CostModel>,
)> {
    Some((pin.gov.0.clone().downcast().ok()?, cost_model(&pin.cost)?))
}

impl busbar_kernel::plane_host::IdentityHost for EngineHostImpl {
    #[cfg(any(test, feature = "test-support"))]
    fn verify_token_test(&self, token: &str) -> Option<Arc<busbar_contract::records::VirtualKey>> {
        self.app
            .governance
            .as_ref()
            .and_then(|g| g.verify_token(token, busbar_kernel::store::now(), None))
    }
}

impl busbar_kernel::plane_host::AdmissionHost for EngineHostImpl {
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
            Option<busbar_kernel::plane_host::AdmitHandle>,
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
                        busbar_kernel::plane_host::AdmitHandle(
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
            Option<busbar_kernel::plane_host::AdmitHandle>,
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
                        busbar_kernel::plane_host::AdmitHandle(
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
        charged: Option<&busbar_kernel::plane_host::AdmitHandle>,
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

// `EngineHost` declares no method of its own; it is purely the SUM of the capability slices above.
// This blanket impl is therefore empty — the sum is satisfied through the slice impls, and the
// substrate-side compile-time witness enforces that equality.
impl busbar_kernel::plane_host::EngineHost for EngineHostImpl {}

/// Mint an `Arc<dyn EngineHost>` over the live `app` — the constructor core hands a plane so the
/// plane calls the neutral seam instead of naming `plane_host::*_over(&App, …)`. Cheap: one `Arc`
/// clone; the transient `HostCtx` is minted per method call, never here.
#[must_use]
pub fn engine_host(app: &Arc<App>) -> Arc<dyn busbar_kernel::plane_host::EngineHost> {
    Arc::new(EngineHostImpl::new(Arc::clone(app)))
}

/// THE ALLOC-FREE BORROWED HOST CARRIER (1.6.0 KEYSTONE): an owned [`EngineHost`] value the caller
/// keeps on its STACK and coerces to `&dyn EngineHost`, so a plane reaches the host seam WITHOUT the
/// per-request `Arc::new` heap allocation [`engine_host`] pays. The whole cost is one `Arc::clone` of
/// the snapshot (an atomic refcount bump — NOT a heap allocation, so it never touches the engine's
/// alloc-gate count), and the `&dyn` coercion of the stack value allocates nothing. Returned opaque
/// (`impl EngineHost`) so the plane names no core type.
#[must_use]
pub fn engine_host_value(app: &Arc<App>) -> impl busbar_kernel::plane_host::EngineHost + 'static {
    EngineHostImpl::new(Arc::clone(app))
}

/// Mint an `Arc<dyn EngineHost>` over the CURRENT snapshot of a live [`AppHandle`] — the form the
/// route adapter and the detached-runner / stdio paths reach for, which hold a swappable handle
/// rather than a pinned `Arc<App>`. Loads the handle once; the clock the seam reads is engine-snapshot
/// independent (it drives the host wall clock), so a later config swap does not change the value.
#[must_use]
pub fn engine_host_from_handle(
    handle: &Arc<crate::state::AppHandle>,
) -> Arc<dyn busbar_kernel::plane_host::EngineHost> {
    Arc::new(EngineHostImpl::from_handle(Arc::clone(handle)))
}

/// Mint a NEUTRAL [`LiveHostFactory`](busbar_kernel::plane_host::LiveHostFactory) closing over a
/// live [`AppHandle`](crate::state::AppHandle): each call returns a fresh `from_handle` host whose
/// BOUND snapshot is the handle's CURRENT load — so a transport that re-mints per frame sees a
/// config swap that lands between calls. Byte-identical to calling [`engine_host_from_handle`] on
/// each frame, handed to a plane that must not name the handle.
#[must_use]
pub fn live_host_factory(
    handle: std::sync::Arc<crate::state::AppHandle>,
) -> busbar_kernel::plane_host::LiveHostFactory {
    std::sync::Arc::new(move || {
        std::sync::Arc::new(EngineHostImpl::from_handle(std::sync::Arc::clone(&handle)))
            as Arc<dyn busbar_kernel::plane_host::EngineHost>
    })
}

/// THE LIVE RE-RESOLUTION a door unit's entitlement asks through (`entitlement.check`, ARCHITECT
/// round 4 Q-L3B-SURFACES (a)): an admitted principal re-resolved against the CURRENT snapshot's
/// governance registry (a registry key, by id) and `role_bindings` (a role-bound key), through
/// [`Standing::still_permitted`](busbar_kernel::trust::validate::Standing::still_permitted). `None`
/// when it no longer stands; a deployment with governance off stands as admitted.
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

#[cfg(test)]
#[path = "tests/mod_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/residual_tests.rs"]
mod residual_tests;

// ==== merged from busbar-substrate (W4.b P2 engine drain) ====
// THE NEUTRAL LLM-RUNTIME BUILD CARRIER (1.6.0 money-path Phase 3-4 C): the single-compiled `PlaneBuildInput`
// DTO `busbar-core`'s `appbuild` populates and hands to the LLM plane's `build_runtime` seam.
pub mod build_input;
// The route tables' read view and the slots a plane reads live in the plane driver
// (`crate::plane_driver::{route_tables, slots}`); re-exported at their former paths below.
pub use crate::plane_driver::slots::{ContainerGateSink, PlaneSlots};
// The egress-trust primitives (client identity, extra trust anchors, the peer-SPKI pin) live on the
// kernel's outbound surface, `crate::egress::trust`. This re-export only keeps the legacy plane crates'
// `busbar_kernel::plane_host::{identity, spki, trust_anchor}` paths resolving; it leaves with them.
pub use crate::egress::trust::{identity, spki, trust_anchor};

pub use crate::plane_driver::route_tables::{
    set_pool_queued_depth, ConfigTables, EmptyEngineTablesView, EngineTablesView, LaneView,
    EMPTY_VIEW,
};
pub use crate::plane_host::build_input::{
    AffinityInput, AuthReach, AuthStyleInput, BreakerInput, ClientSettingsInput, FailoverInput,
    HealthInput, HealthModeInput, LaneInput, LegacyLaneKeys, OnExhaustedInput, PlaneBuildInput,
    PoolInput, PoolMemberInput, TripInput, TripModeInput,
};
use busbar_contract::records::PlaneRequestCtx;

/// What could be established about a presented bearer's RFC 8707 audience binding — the outcome of
/// the audience pre-filter (`crate::auth::audience::inspect_bearer`), for credentials busbar did
/// not mint. Core re-exports this at `crate::auth::audience::Binding`, so its own callers and the
/// enum's variants are unchanged.
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

/// THE LOOP'S ANSWER SHAPE at the unified boundary (DECISIONS #28), plane-neutral.
///
/// When a rider runs on the kernel Teller loop (`busbar_kernel::teller::run_unit`), the loop returns
/// only the money/lifecycle `Ended`; the request's ANSWER bytes are read back out of the plane's own
/// `ctx.key`-keyed binding table (the admin template — `AdminUnitTable`). `PlaneAnswer` is what a
/// rider stashes into that table and the outer async handler serves. Two shapes, per #28:
///
/// - [`PlaneAnswer::Unary`] — buffered status + headers + body, crosses the sync channel and settles
///   at Encode on the final byte count (the admin cleanliness caller and every unary verb, including
///   an SSE body materialised after dispatch).
/// - [`PlaneAnswer::Live`] — a live body the outer handler serves directly, governed at admit
///   (auth/verify/approve/admit/audit ran unary), bypassing the Encode-emits-bytes path (the llm
///   RouteLeg emits this).
///
/// NEUTRAL BY CONSTRUCTION: nothing here names a plane, a dialect or a verb, and it lives in the
/// neutral substrate tier — NOT in `busbar-kernel`, which keeps naming zero planes and zero answer
/// shapes.
pub enum PlaneAnswer {
    /// Buffered: status, headers, body bytes. Settles at Encode on the final byte count.
    Unary(
        axum::http::StatusCode,
        axum::http::HeaderMap,
        axum::body::Bytes,
    ),
    /// A live body the outer async handler serves directly, governed at admit.
    Live(axum::response::Response),
}

impl PlaneAnswer {
    /// Materialise either shape into the one response the outer handler serves. `Unary` is rebuilt
    /// status-for-header-for-byte so a buffered answer serves byte-identically to the response the
    /// plane shaped; `Live` is handed through untouched.
    pub fn into_response(self) -> axum::response::Response {
        match self {
            PlaneAnswer::Unary(status, headers, body) => {
                let mut resp = axum::response::Response::new(axum::body::Body::from(body));
                *resp.status_mut() = status;
                *resp.headers_mut() = headers;
                resp
            }
            PlaneAnswer::Live(resp) => resp,
        }
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

// ─────────────────────────────────────────────────────────────────────────────────────────────
// OPAQUE GOVERNANCE HANDLES (App-retype WEDGE 2) — the neutral carrier tokens a plane HOLDS on its
// per-request sink so the sink's field types stop naming `busbar_kernel::governance::GovState` /
// `busbar_kernel::cost::CostModel` / `busbar_kernel::governance::AdmitGrant`. Each wraps an
// `Arc<dyn Any + Send + Sync>` the host minted over the concrete engine value; the plane never
// introspects it — it hands [`GovHandle`]/[`CostHandle`] BACK to the metering seams
// ([`EngineHost::meter_ledger`]/[`EngineHost::meter_series`]), which downcast host-side. This keeps
// the byte-identical `sink.gov`/`sink.cost` the plane minted (a custom test cost, the live app cost —
// whichever the sink was built from), NOT a re-read of the host snapshot.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// An OPAQUE, cheaply-cloned (one `Arc` bump) handle to the deployment's governance state — minted
/// host-side ([`EngineHost::governance`]) and consumed host-side ([`EngineHost::meter_ledger`] /
/// [`EngineHost::meter_series`]). The plane holds it on its per-request sink WITHOUT naming
/// `busbar_kernel::governance::GovState`.
#[derive(Clone)]
pub struct GovHandle(pub Arc<dyn std::any::Any + Send + Sync>);

/// The cost-model twin of [`GovHandle`] — an opaque handle to a resolved `CostModel`. KERNEL-SIDE
/// ONLY: it rides inside a [`MeterPin`] and no plane-facing signature names it (#43).
#[derive(Clone)]
pub struct CostHandle(pub Arc<dyn std::any::Any + Send + Sync>);

/// THE METER PIN — what a plane holds on its per-request sink so its counts land against the
/// governance state AND the rate card that were in force when the request was admitted. OPAQUE: the
/// fields are private and only the kernel's host pins a card ([`BudgetHost::meter_pin`]), so a plane
/// carries its request's pricing context without naming a cost or price type (#43: a plane is
/// PRICING-BLIND; #71: its money obligation is one raw count per class). The plane hands the pin BACK
/// to the metering seams ([`BudgetHost::meter_ledger`], [`BudgetHost::rate_headroom`],
/// [`BudgetHost::budget_state`], [`BudgetHost::meter_series`]), which read it kernel-side. A plane
/// calls [`BudgetHost::meter_series`] UNCONDITIONALLY with the counts it observed (#43: no branch, no
/// knowledge of billing state) — #42's billing-off posture is the VIEW's job (the served figure reads
/// zero), not the write's; nothing kernel-side gates the row on the pinned card any more (that gate,
/// `meter_series_billed`, was dead code with no production caller after d09c2e0b0 and is gone).
///
/// A plane-side host (a test double) pins NO card: its pin answers the no-card posture everywhere.
#[derive(Clone)]
pub struct MeterPin {
    gov: GovHandle,
    cost: CostHandle,
}

impl MeterPin {
    /// Pin `gov` and the card `cost` names. Kernel-side; a TEST that hand-builds a card pins it here.
    #[cfg(any(test, feature = "test-support"))]
    pub fn new(gov: GovHandle, cost: CostHandle) -> Self {
        MeterPin { gov, cost }
    }

    /// The governance handle the pin carries — what [`BudgetHost::meter_series`] takes.
    pub fn gov(&self) -> &GovHandle {
        &self.gov
    }
}

/// An opaque handle to a governance ADMISSION grant (`AdmitGrant`), held DROP-ONLY on a plane's
/// per-request sink so the admission's in-flight concurrency holds release when the last sink clone
/// drops. The plane never introspects it; it exists purely so its `Drop` (on the last clone) releases
/// the gauges — byte-identical to the sink's current `Option<Arc<busbar_kernel::governance::AdmitGrant>>`.
#[derive(Clone)]
pub struct AdmitHandle(pub Arc<dyn std::any::Any + Send + Sync>);

/// BRAKE (audit D): the LANE/POOL-family slice of the host seam, split off `EngineHost` as a
/// supertrait so the lane-runtime + pool-membership + probe-default cluster stays a cohesive,
/// bounded ABI. Groups the four seams a plane's routing/health machinery reads: the neutral
/// breaker/lane store view ([`lane_store`](Self::lane_store)), the two process-wide active-probe
/// fallbacks ([`default_probe_interval_secs`](Self::default_probe_interval_secs) /
/// [`default_probe_timeout_secs`](Self::default_probe_timeout_secs)), and the failover-pool
/// membership resolver ([`plane_pool_members`](Self::plane_pool_members)). PURE STRUCTURAL:
/// signatures and bodies are unchanged; a plane that names `EngineHost` reaches these through the
/// inherited supertrait bound.
pub trait LanePoolHost: Send + Sync {
    /// The breaker/lane store this deployment routes through, as the NEUTRAL
    /// [`busbar_kernel::store::LaneRuntime`](crate::store::LaneRuntime) view — the seam the engine's
    /// `app.store` reads (select/health/pipeline lane admit/settle/snapshot) resolve to WITHOUT naming
    /// core's `state::App`. A pure borrow of the bound snapshot's store, no `HostCtx`; the returned
    /// `&dyn LaneRuntime` shares the live in-memory breaker engine, identical to `&*App::store`.
    ///
    /// WEDGE 2 (App-retype): additive — the transitional seam the wedge-3 `app.store → host.lane_store()`
    /// flip targets. The `LaneRuntime` trait already lives in substrate (wedge 1), so this names no core type.
    fn lane_store(&self) -> &dyn crate::store::LaneRuntime;

    /// The process-wide active-probe INTERVAL fallback (whole seconds) a lane with no
    /// `health.interval_secs` inherits — the host-read form of `busbar_kernel::limits::default_probe_interval_secs`.
    /// A pure read of the live limits registry, no `HostCtx`; byte-identical to that free fn.
    ///
    /// WEDGE 2 (App-retype): additive — the seam the wedge-3 `health.rs` probe-spawn flip targets. The
    /// limits fns read core's runtime `LIMITS` global, so they CANNOT relocate to substrate by-identity;
    /// this host seam is the neutral home instead.
    fn default_probe_interval_secs(&self) -> u64;

    /// The process-wide active-probe TIMEOUT fallback (whole seconds) a lane with no `health.timeout_secs`
    /// inherits — the host-read twin of [`default_probe_interval_secs`](Self::default_probe_interval_secs).
    /// Byte-identical to `busbar_kernel::limits::default_probe_timeout_secs`.
    fn default_probe_timeout_secs(&self) -> u64;

    /// The `(pool_name, members)` of the failover pool `member` belongs to on the plane identified by
    /// the opaque registry `plane_key`, off the BOUND snapshot; `None` when `member` is un-pooled. The
    /// member-selection walk derives each candidate's lane from the member's position in the returned
    /// list, so name + members is the whole seam. Identical to scanning the plane's pool map.
    fn plane_pool_members(&self, plane_key: &str, member: &str) -> Option<(String, Vec<String>)>;
}

/// THE KERNEL'S PRICING SIDE of a live carrier — the rate card that prices each increment. KERNEL-INTERNAL (#43: "a plane plugin NEVER sees its rate card or
/// fees"): it is NOT a supertrait of [`EngineHost`], so no plane-side host implements it and no plane
/// names it. A plane's live carrier is metered by counts alone, through the kernel plane driver's
/// money seam, which prices nothing (Q21b). (The reserve-then-settle lease slots that once drove
/// this trait were retired by KERNEL<>PLUGINS step 16: a plane never hands the kernel a price,
/// #43/#71.) Money-denominated end to end in `u128` nanodollars; a plain Rust trait.
pub trait MeteringHost: Send + Sync {
    /// PRICE a turn's neutral [`billing::Usage`](crate::billing::Usage) counts for `model` into
    /// nanodollars via the deployment's rate card — the SAME `CostModel` arithmetic the LLM
    /// enforcement/derive path uses (a new ENTRY POINT over the same function).
    ///
    /// Semantics mirror the host's per-model rate lookup exactly:
    /// - no rate card configured ⇒ `Some(0)` (pricing off — every model prices at 0, as core does);
    /// - card present, `model` priced ⇒ `Some(nanos)`;
    /// - card present, `model` UNKNOWN ⇒ `None` — the caller FAILS CLOSED (an unpriced passthrough model
    ///   must not meter as free).
    fn price_usage(&self, model: &str, usage: &crate::billing::Usage) -> Option<u128>;
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// CAPABILITY SLICES (M4 god-trait split) — the residual flat host seam, cut into cohesive capability
// supertraits so a plane depends ONLY on the slices it uses. `EngineHost` is the SUM (a supertrait of
// every slice), so an existing `Arc<dyn EngineHost>` caller is unaffected — it still reaches every
// method through the inherited bound — while a plane that needs a narrower capability can take
// `&dyn SliceX` instead. PURELY
// STRUCTURAL: every method keeps its exact signature, doc and same-dispatch body; nothing moves in the
// wire/ABI/money plane. The single `EngineHostImpl` (busbar-core) implements each slice.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// The CLOCK slice: the host wall-clock reads a plane's timing/window arithmetic needs, in whole
/// seconds and milliseconds. Split off `EngineHost` as a supertrait; a plane that only needs the
/// clock can take `&dyn ClockHost`.
pub trait ClockHost: Send + Sync {
    /// Read the host wall clock in whole SECONDS through the `clock_now` seam — the host-driven form
    /// of a plane's in-place seconds clock. Identical to `busbar_kernel::plane_host::clock_now_secs_over`.
    fn clock_now_secs(&self) -> u64;

    /// Read the host wall clock in MILLISECONDS through the `clock_now` seam — the host-driven form of
    /// a plane's in-place millis clock. Identical to `busbar_kernel::plane_host::clock_now_ms_over`.
    fn clock_now_ms(&self) -> u64;
}

/// The TELEMETRY slice: the plane-labelled metric emits a plane fires to close a request out and to
/// count its dispatch/failover/translation events, plus the `pool_label` cardinality bound every emit
/// path runs first. Split off `EngineHost` as a supertrait; each emit is snapshot-scoped, no `HostCtx`.
pub trait TelemetryHost: Send + Sync {
    /// Stamp the plane-labelled request-completion metric family for a MOUNTED plane through the host.
    /// A neutral trait seam: the plane hands its own `(plane, ingress_protocol, pool, outcome, seconds)`
    /// and the host records the completion, so the plane never names core's engine snapshot to close a
    /// request out. Identical to `busbar_kernel::telemetry::request_finished` over the bound snapshot.
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
    /// `busbar_kernel::telemetry::upstream_attempt` over the bound snapshot.
    fn telemetry_upstream_attempt(&self, pool_label: &str, lane: usize);

    /// Count ONE classified upstream FAILURE on `(pool_label, lane)` by `disposition` — the
    /// `busbar_upstream_failures_total` metric — through the host. The telemetry twin of
    /// [`telemetry_upstream_attempt`](Self::telemetry_upstream_attempt); identical to
    /// `busbar_kernel::telemetry::upstream_failure` over the bound snapshot.
    fn telemetry_upstream_failure(&self, pool_label: &str, lane: usize, disposition: &'static str);

    /// Count ONE logical Closed→Open breaker TRIP on `(pool_label, lane)` — the
    /// `busbar_breaker_trips_total` metric — through the host. Identical to
    /// `busbar_kernel::telemetry::breaker_trip` over the bound snapshot.
    fn telemetry_breaker_trip(&self, pool_label: &str, lane: usize);

    /// Count ONE FAILOVER event on `pool_label` by `reason` — the `busbar_failovers_total` metric —
    /// through the host. Identical to `busbar_kernel::telemetry::failover` over the bound snapshot.
    fn telemetry_failover(&self, pool_label: &str, reason: &'static str);

    /// Count ONE cross-protocol TRANSLATION hop `from → to` — the `busbar_translations_total`
    /// metric — through the host. Both names come from the fixed protocol vocabulary, so the emit is
    /// snapshot-independent; identical to `busbar_kernel::telemetry::translation`.
    fn telemetry_translation(&self, from: &str, to: &str);

    /// Map a client-supplied model/name string to the BOUNDED `pool` metric label through the host:
    /// the string verbatim when it names a configured pool or by-model lane, else the fixed
    /// `"unresolved"` sentinel. Bounds the Prometheus label cardinality on every finish/webhook path.
    /// Identical to `busbar_kernel::ingress::pool_label` over the bound snapshot; the returned slice
    /// borrows `model` (or a `'static` sentinel), independent of the host.
    fn pool_label<'a>(&self, model: &'a str) -> &'a str;
}

/// The audit action of a residual row ([`JournalHost::settle_residual`]): counts reported, never billed.
pub const USAGE_RESIDUAL_ACTION: &str = "usage.residual";

/// The JOURNAL slice: the durable admin-audit / call-log emits a plane writes as a side effect of the
/// mutation it records. All fire-and-forget (a store miss never fails the recorded action). Split off
/// `EngineHost` as a supertrait.
pub trait JournalHost: Send + Sync {
    /// Emit ONE hostless admin-audit record `(action, resource, outcome, principal)` to the shared
    /// admin audit log. Fire-and-forget, loudly: a store write failure NEVER fails the mutation it
    /// records. Identical to `busbar_kernel::audit::auditlog::emit_admin_hostless_now` — this seam needs
    /// no `HostCtx`, so it is a plain forward to that engine (which stays unchanged in core).
    fn audit_emit(&self, action: &str, resource: &str, outcome: &str, principal: &str);

    /// Record ONE admin-audit event `(action, resource, outcome, principal)` through the IN-PROCESS
    /// ADMIN RING (`busbar_kernel::admin::audit::AUDIT::record_by`), which seals it into the retained ring
    /// AND cascades the SAME record onto the durable hostless journal seam. Distinct from
    /// [`audit_emit`](Self::audit_emit) (durable-only): this is the seam the DATA-plane egress
    /// audit-and-allow path (a dropped cross-dialect control) writes through, so the record lands in the
    /// in-process ring the egress audit-trail assertions read. `outcome` is a fixed vocabulary literal.
    ///
    /// WEDGE 3 (App-retype): the neutral home of the engine's `AUDIT.record_by(...)` reach.
    fn audit_record(&self, action: &str, resource: &str, outcome: &'static str, principal: &str);

    /// THE SETTLE STEP'S RESIDUAL ROW (MONEY LAW, owner 2026-10-02; ARCHITECT ruling 2026-10-02): a
    /// usage count no billing class records is WARNed where the reader found it, never billed, and
    /// recorded here as ONE `usage.residual` row per non-empty `residual` map on the DURABLE
    /// PER-PRINCIPAL journal stream ([`crate::residual_log`]): store-backed, hash-chained per
    /// `principal`, replayed at boot, never evicted. NOT the admin audit ring
    /// ([`audit_record`](Self::audit_record)), which is operator-rate and bounded in RAM. The row names
    /// every unit and its count, the plane, the dialect that reported them, the serving lane and the
    /// request id, outcome `unbilled`; `principal` is the caller the units settled against. An empty
    /// map writes nothing. The row is the kernel's, so a plane hands the counts over and never spells
    /// the row itself.
    fn settle_residual(
        &self,
        residual: &std::collections::BTreeMap<String, u64>,
        plane: &str,
        dialect: &str,
        lane: &str,
        request_id: u64,
        principal: &str,
    ) {
        crate::residual_log::emit(residual, plane, dialect, lane, request_id, principal);
    }
}

/// The MOUNT slice: the pure mount-table reads that shape an arrival's dialect and its pre-collapse
/// fallback error. Split off `EngineHost` as a supertrait; both are pure snapshot reads, no `HostCtx`.
pub trait MountHost: Send + Sync {
    /// The mount-aware dialect an answer to `path` is SHAPED in — the host-driven form of
    /// `busbar_kernel::ingress::native::envelope_dialect(App::planes.ingress_of(path))`. A pure snapshot
    /// mount-table read, no `HostCtx`.
    ///
    /// WEDGE 3 (App-retype — THE FLIP): the seam core's `ArrivalHost` impl reads instead of the dropped
    /// `ArrivalPayload::app`; the neutral `ArrivalPayload` now carries only the host, so this mount read
    /// crosses the host seam like every other.
    fn arrival_envelope_dialect(&self, path: &str) -> &'static str;

    /// The pre-collapse fallback error SHAPE by `path` — the host-driven form of
    /// `busbar_kernel::fallback_error_response(&App::planes, path, status, kind, message)`. Renders the
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
/// neutral secret resolver. Split off `EngineHost` as a supertrait.
pub trait RegistryHost: Send + Sync {
    /// Stamp the NEXT per-request correlation id — one relaxed `fetch_add` on the host-owned counter.
    /// Identical to `busbar_kernel::state::App::next_request_id` (the counter is boot-seeded and carried
    /// across config swaps, so the value is engine-snapshot independent).
    fn next_request_id(&self) -> u64;

    /// The plane's type-erased runtime object off the BOUND snapshot (the one this host was minted
    /// over), owned (an `Arc` clone) so it outlives the call. `None` when the plane contributed no
    /// slot under `key` this generation. Identical to `busbar_kernel::state::App::plane_slot(key)`
    /// cloned — a pure `plane_slots` map read, no `HostCtx` (mirrors [`next_request_id`]).
    ///
    /// [`next_request_id`]: RegistryHost::next_request_id
    fn plane_slot(&self, key: &str) -> Option<Arc<dyn std::any::Any + Send + Sync>>;

    /// The deployment's NEUTRAL secret resolver, behind the `busbar_contract::secret::SecretResolve` seam, so a
    /// plane mints a delegation credential (and loads its outbound TLS PEM) WITHOUT naming the
    /// engine's concrete `SecretResolver`. A pure snapshot read of `App::secret_resolver`, no
    /// `HostCtx`; the returned `Arc<dyn SecretResolve>` shares the live resolver (built-ins plus any
    /// wired `kind: secret` plugin), fail-closed exactly as core resolution.
    fn secret_resolver(&self) -> Arc<dyn busbar_contract::secret::SecretResolve>;
}

/// The HOOK/CONFIG-FACADE slice (App-retype WEDGE 2d): the residual the retired engine crate request-path reads off
/// the resolved hook/config facades — the rewrite/tap/gate chains, the routing policy, the requested-
/// signal bitmask and the group-membership walk. Each is a pure borrow of the bound snapshot tied to
/// `&self`, no `HostCtx`. Split off `EngineHost` as a supertrait; every borrow is byte-identical to the
/// `App::X` field read the wedge-3 flip targets.
pub trait HookConfigHost: Send + Sync {
    /// Whether `caller_group` sits within (any ancestor of) one of `hook_groups` — the group-membership
    /// walk a hook's `groups:` filter consults, resolved against this deployment's group registry.
    /// Identical to `busbar_kernel::config::caller_in_hook_groups(caller_group, hook_groups, &App::groups_registry)`;
    /// a pure tree walk over the bound snapshot's registry, no `HostCtx`.
    ///
    /// WEDGE 2 (App-retype): additive — the seam the wedge-3 `pipeline.rs` flip targets. Folding the
    /// `&App::groups_registry` argument HOST-side means the engine reads group membership without naming
    /// `busbar_kernel::config` or `App::groups_registry`.
    fn caller_in_hook_groups(&self, caller_group: Option<&str>, hook_groups: &[String]) -> bool;

    /// This pool's resolved REWRITE chain `(timeout, policy)` — the phase-1 transform hooks fired for
    /// requests routed to `pool`, empty (the default) ⇒ no pool rewrites. Byte-identical to
    /// `busbar_kernel::state::App::pool_rewrites(pool)`; a pure keyed map read, no `HostCtx`. The tuple is
    /// purely neutral (`Duration`, the [`RoutingPolicy`](busbar_contract::hooks::RoutingPolicy) trait object — api).
    fn pool_rewrites(
        &self,
        pool: &str,
    ) -> &[(
        std::time::Duration,
        std::sync::Arc<dyn busbar_contract::hooks::RoutingPolicy>,
    )];

    /// The GLOBAL (all-pools) rewrite chain `(timeout, policy)` fired in the phase-1 transform pass
    /// BEFORE any pool rewrites — the borrow of `App::rewrite_hooks`. Empty (the default) ⇒ no globals.
    /// Same neutral tuple shape as [`pool_rewrites`](Self::pool_rewrites).
    fn rewrite_hooks(
        &self,
    ) -> &[(
        std::time::Duration,
        std::sync::Arc<dyn busbar_contract::hooks::RoutingPolicy>,
    )];

    /// Whether ANY registered hook holds a prompt-CONTENT grant (`prompt: ro`/`rw`) this generation —
    /// the deployment gate that decides whether the request IR is built for the hook seam. A single
    /// bool load of `App::any_content_hook`, byte-identical; `false` (the default) is the whole
    /// zero-cost-when-off property.
    fn any_content_hook(&self) -> bool;

    /// A hook was handed a unit's content (and the caller's identity, when `identity`): leave the
    /// one access amendment the kernel's own gate and rewrite seams leave, on the node journal.
    /// `principal` is whose content it was; `op` the ingress label — data, never branched on.
    /// PROVIDED, so a plane's own hook call sites record through the same seam as the kernel's.
    fn hook_read(&self, name: &str, principal: Option<&str>, op: &str, identity: bool) {
        crate::audit::amend::hook_read(name, principal, op, identity);
    }

    /// The DECISION GATES the plane `plane_key` attached to its entry `container` this generation
    /// (the plane's per-entry `hooks:`), as resolved; empty = none. A gate-first plane's units
    /// are screened by them (`abi::plane::TAIL_HOOKS_GATED`). PROVIDED: a host with no per-plane
    /// gate map attaches none.
    fn plane_gates_of(
        &self,
        plane_key: &str,
        container: &str,
    ) -> Vec<(u16, crate::hooks::ResolvedPolicy)> {
        let _ = (plane_key, container);
        Vec::new()
    }

    /// The REWRITE chain the plane `plane_key` attached to its entry `container` this generation;
    /// empty = none. PROVIDED: a host with no per-plane rewrite map attaches none.
    fn plane_rewrites_of(
        &self,
        plane_key: &str,
        container: &str,
    ) -> Vec<(
        std::time::Duration,
        std::sync::Arc<dyn busbar_contract::hooks::RoutingPolicy>,
    )> {
        let _ = (plane_key, container);
        Vec::new()
    }

    /// The gate's INCREMENTAL-SCAN substrate under the operator's opt-in: the node's session store
    /// and the hook-config generation a clearance is bound to; `None` = every request is screened
    /// whole. PROVIDED: `None`.
    fn gate_scan(&self) -> Option<(std::sync::Arc<crate::session::SessionStore>, u64)> {
        None
    }

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

/// The BUDGET/METERING slice: the money-path seams a plane drives — COUNTS in, VERDICTS out. The
/// governance handle and [`MeterPin`] mints, the record-usage / record-metering accruals, the
/// reserve-then-charge meter, and the pure headroom/budget projections. No method names a cost or
/// price type: pricing is the kernel's
/// ([`MeteringHost`], #43), so a plane-side host implements this slice without naming one. Split off
/// `EngineHost` as a supertrait; the accrual seams read the pin kernel-side, no `HostCtx`.
pub trait BudgetHost: Send + Sync {
    /// Whether governance is configured for this deployment. Identical to
    /// `busbar_kernel::state::App::governance.is_some()`.
    fn governance_enabled(&self) -> bool;

    /// The per-caller RATE HEADROOM (min fraction of remaining request/token budget across the key's
    /// chain, `None` when unconstrained) — the host-driven form of
    /// `gov.rate_headroom(&app.cost, key, pool, now)` over the governance state and card `pin` carries
    /// (a pure observation, no cell mutation). No `HostCtx`. `key` is the already-neutral
    /// [`VirtualKey`](busbar_contract::records::VirtualKey) (api).
    fn rate_headroom(
        &self,
        pin: &MeterPin,
        key: &busbar_contract::records::VirtualKey,
        pool: Option<&str>,
        now: u64,
    ) -> Option<f64>;

    /// The HOOK-seam budget projection for `key`: `{bucket_id, spend_at_current_rate, remaining, window}`
    /// per chain bucket, derived fresh from the token ledger × the card `pin` carries — the host-driven
    /// form of `gov.budget_state(&app.cost, key, now)`. Returns the neutral
    /// [`BudgetBucketState`](busbar_contract::hooks::BudgetBucketState) vec (empty when the key has no chain). No
    /// `HostCtx`.
    fn budget_state(
        &self,
        pin: &MeterPin,
        key: &busbar_contract::records::VirtualKey,
        now: u64,
    ) -> Vec<busbar_contract::hooks::BudgetBucketState>;

    /// Mint the OPAQUE [`GovHandle`] for this deployment's governance state — `Some` iff governance is
    /// configured. One `Arc` bump, no `HostCtx`. Byte-identical to cloning `App::governance`.
    fn governance(&self) -> Option<GovHandle>;

    /// PIN this request's metering context — `Some` iff governance is configured. The plane holds the
    /// pin on its per-request sink and hands it back to the metering seams. The kernel's host pins its
    /// bound snapshot's card; a plane-side host keeps this default, which pins NO card (every card read
    /// through the pin answers the no-card posture).
    fn meter_pin(&self) -> Option<MeterPin> {
        let cost = CostHandle(Arc::new(()));
        self.governance().map(|gov| MeterPin { gov, cost })
    }

    /// The pre-admission pricing guard's VERDICT: does a PRESENT rate card leave `model` unpriced?
    /// `false` for every name when no card is configured (there is no card to miss). A verdict, not a
    /// rate: the plane fails the request closed on `true` and never learns a figure.
    fn cost_model_unpriced(&self, model: &str) -> bool;

    /// LEDGER one delivered response's tier-split counts against the key's budget chain — the
    /// host-driven form of `sink.gov.record_usage(&sink.cost, key, pool, model, tokens, now)` over the
    /// governance state and card `pin` carries. A no-op on an all-zero tier, exactly as
    /// `record_usage`. No `HostCtx`.
    fn meter_ledger(
        &self,
        pin: &MeterPin,
        key: &busbar_contract::records::VirtualKey,
        pool: &str,
        model: &str,
        usage: &crate::billing::Usage,
        now: u64,
    );

    /// GIVE BACK ONE FEE UNIT `fee_unit` a plane's admission counted on its own fee lane, across the
    /// buckets of the key's chain `pool` reaches, in the window `now` (the count's own clock reading)
    /// reached: the host-driven form of `GovState::refund_fee_unit` over the state `pin` carries. The
    /// budget book only; the metering row stays. Floored at 0.
    fn meter_refund_fee(
        &self,
        pin: &MeterPin,
        key: &busbar_contract::records::VirtualKey,
        pool: &str,
        plane: &str,
        fee_unit: &str,
        now: u64,
    );

    /// Record one delivered response's RAW consumption into the per-(key, bucket, model, provider)
    /// metering series — the host-driven form of
    /// `sink.gov.record_metering(key_id, model, provider, usage, now)`. `gov` is the opaque handle the
    /// sink minted; the host downcasts it and drives the SAME write-behind accrual (a zero-token
    /// response still counts its request). No `HostCtx`.
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

/// The IDENTITY slice: the test-only token verifier. Split off `EngineHost` as a supertrait.
pub trait IdentityHost: Send + Sync {
    /// TEST-ONLY raw-token → resolved `VirtualKey` resolution over this deployment's governance state
    /// (the data-plane boundary: no audience). The host-driven form of
    /// `App::governance.and_then(|g| g.verify_token(token, now, None))`, for the test paths that
    /// exercise the routing-policy seam WITHOUT building a full `PlaneRequestCtx` (production always
    /// threads a resolved key, so this never runs there). Gated to test / `test-support` builds so no
    /// production binary carries a raw-token verifier on the neutral seam.
    ///
    /// DEFAULT `None` (resolves nothing): the method exists only when THIS crate's `test-support` is
    /// on, and a downstream implementor cannot see that feature — cargo may unify it on through some
    /// other crate's dev-deps. A default lets an implementor compile either way; a host that actually
    /// verifies tokens overrides it (item 115).
    #[cfg(any(test, feature = "test-support"))]
    fn verify_token_test(&self, token: &str) -> Option<Arc<busbar_contract::records::VirtualKey>> {
        let _ = token;
        None
    }
}

/// The ADMISSION slice: the request-admission seams — the destination guard, the budget-admission door, the audience-bound
/// mount read, and the post-admission/not-charged finishes. Split off `EngineHost` as a supertrait.
pub trait AdmissionHost: Send + Sync {
    /// STAGE 2 pre-admission DESTINATION guard through the host: the pool ACL, the fallback-pool ACL,
    /// and the all-or-nothing unpriced-model gate. `Ok(())` admits; `Err` is the already-finished,
    /// protocol-native rejection response (finished via the not-charged terminal). Identical to
    /// `busbar_kernel::ingress::destination_guard` over the bound snapshot + `gov` scope.
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
    /// `busbar_kernel::ingress::admission_door` over the bound snapshot; the returned `AdmitHandle`
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

    /// THE SAME DOOR, WITHOUT THE TERMINAL — the check-and-charge on its own.
    ///
    /// [`admission_door`](Self::admission_door) is exactly this call followed by
    /// `finish_rejected` on the refusing arm, which is right for a caller whose refusal ends there
    /// and wrong for one whose terminal is a step of its own: posting the refusal at the door and
    /// then posting it again at the terminal would put two links on one unit's chain. So a plane
    /// that owns an Audit step takes this one and hands the refusal — bytes, not a posted record —
    /// to that step, and a unit posts exactly one link whichever way it ended.
    ///
    /// Identical to `busbar_kernel::ingress::admit_check` over the bound snapshot: the same buckets,
    /// the same charge, the same downgrade re-pool, and on the refusing arm the same
    /// protocol-native bytes the door would have finished. The label the terminal records those
    /// bytes under is [`pool_label`](EngineHost::pool_label) of the same `pool`, which is what the
    /// door computes for itself before it finishes.
    fn admission_check(
        &self,
        gov: &PlaneRequestCtx,
        proto: &'static str,
        pool: &str,
        charged_at: u64,
    ) -> Result<(Option<AdmitHandle>, Option<String>), Box<axum::response::Response>>;

    /// POST-ADMISSION finish through the host: emit the per-request metric family + request-log
    /// webhook and, on a NON-2xx outcome, REFUND the flat per-request fee IFF it actually landed at
    /// admission (`charged`: the admission's own handle, `None` when nothing was charged) — from
    /// exactly the cells that admission's charge reached. Identical to
    /// `busbar_kernel::ingress::finish_admitted` over the bound snapshot + `gov` scope.
    #[allow(clippy::too_many_arguments)]
    fn finish_admitted(
        &self,
        gov: &PlaneRequestCtx,
        ingress_protocol: &str,
        pool: &str,
        started: std::time::Instant,
        charged_at: u64,
        resp: axum::response::Response,
        charged: Option<&AdmitHandle>,
    ) -> axum::response::Response;

    /// NOT-CHARGED (pre-charge turn-away) finish through the host: emit metrics + the webhook with NO
    /// refund, for a request rejected BEFORE the admission charge ever ran (governance guard denial or
    /// a pre-routing failure). Identical to `busbar_kernel::ingress::finish_rejected` over the bound
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

/// The neutral HOST seam a plane calls to reach the engine's host-owned capabilities.
///
/// A plane holds an `Arc<dyn EngineHost>` (minted core-side over the live engine) and calls these
/// typed methods rather than naming `busbar_kernel::plane_host::*_over(&App, …)`. Each method reaches
/// the SAME kernel function the in-core veneer drives, so the value is identical — this is a
/// relocation of the reach, not a new behaviour.
///
/// `Send + Sync` because a plane carries the handle across `.await` and between threads (e.g. into a
/// `spawn_blocking` breaker leg); no method hands out borrowed host state.
///
/// ## M4 — `EngineHost` is the SUM of the capability slices
///
/// The residual flat method set has been cut into cohesive capability SUPERTRAITS ([`ClockHost`],
/// [`TelemetryHost`], [`JournalHost`], [`MountHost`], [`RegistryHost`], [`HookConfigHost`],
/// [`BudgetHost`], [`IdentityHost`], [`AdmissionHost`]), alongside the earlier braking slice
/// ([`LanePoolHost`]). Every slice is PLANE-FACING and pricing-blind; the kernel's
/// pricing ([`MeteringHost`]) is deliberately NOT one of them, so a plane-side host implements the
/// whole sum without naming a cost or price type (#43). `EngineHost` declares NO methods of its own
/// — it is the SUM (a supertrait bound of every slice). An existing `Arc<dyn EngineHost>` caller is
/// unaffected (it still reaches every method through the inherited bound); a plane that needs a
/// narrower capability takes `&dyn SliceX` and depends only on what it uses.
pub trait EngineHost:
    LanePoolHost
    + ClockHost
    + TelemetryHost
    + JournalHost
    + MountHost
    + RegistryHost
    + HookConfigHost
    + BudgetHost
    + IdentityHost
    + AdmissionHost
    + Send
    + Sync
{
    // The cross-protocol translation seam's global-fallback max-output-tokens and effort→budget-table
    // reads are GONE from this neutral host trait: they are LLM-plane vocabulary, so the engine now
    // reads them off the LLM plane's own per-generation runtime (`NativeRuntime`) rather than through a
    // neutral `PlaneHost` method over `App`. See the retired engine crate `engine/wire.rs`.
}

/// Compile-time witness for the M4 god-trait split: any `EngineHost` implementor IS every capability
/// slice. If a future edit dropped any supertrait bound (or an impl stopped satisfying it), this stops
/// compiling — so `EngineHost` cannot silently cease to equal the SUM of its slices (the families
/// cannot re-dissolve back into the flat god-trait).
const _: () = {
    fn _assert_engine_host_is_sum_of_slices<T: EngineHost + ?Sized>() {
        fn _needs_lane_pool<U: LanePoolHost + ?Sized>() {}
        fn _needs_clock<U: ClockHost + ?Sized>() {}
        fn _needs_telemetry<U: TelemetryHost + ?Sized>() {}
        fn _needs_journal<U: JournalHost + ?Sized>() {}
        fn _needs_mount<U: MountHost + ?Sized>() {}
        fn _needs_registry<U: RegistryHost + ?Sized>() {}
        fn _needs_hook_config<U: HookConfigHost + ?Sized>() {}
        fn _needs_budget<U: BudgetHost + ?Sized>() {}
        fn _needs_identity<U: IdentityHost + ?Sized>() {}
        fn _needs_admission<U: AdmissionHost + ?Sized>() {}
        _needs_lane_pool::<T>();
        _needs_clock::<T>();
        _needs_telemetry::<T>();
        _needs_journal::<T>();
        _needs_mount::<T>();
        _needs_registry::<T>();
        _needs_hook_config::<T>();
        _needs_budget::<T>();
        _needs_identity::<T>();
        _needs_admission::<T>();
    }
};

#[cfg(test)]
#[path = "tests/plane_answer_tests.rs"]
mod plane_answer_tests;
