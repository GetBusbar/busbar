// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE NEUTRAL FIXTURE HOST — an in-memory [`EngineHost`] a plane crate's tests drive INSTEAD of
//! minting a host over the engine's `App`. A plane is a plugin on the plane ABI, and its tests must
//! not reach into core any more than its production code does; before this fixture a plane test that
//! needed a host had to build `busbar_core::test_support::TestApp` and call
//! `busbar_core::plane_host::engine_host(&app)` — the exact backwards reach the purity lint forbids.
//!
//! This host models, in memory, just the host-side state a plane's production path drives through the
//! seam and a test then reads back:
//!
//! * the `(pool, lane)` BREAKER cells (`breaker_admit` / `breaker_record_*` / `breaker_retry_after_secs`),
//!   readable through [`FixtureHost::breaker_state`];
//! * the OPERATOR HOOK gate / rewrite chains keyed by `(plane_key, container)`, attached as scripted
//!   verdicts ([`FixtureHost::attach_gate`] / [`FixtureHost::attach_rewrite`]) so the `gate_attached` /
//!   `gate_decide` / `tap_attached` / `transform_over` legs run exactly as they do over a configured
//!   deployment;
//! * the per-key usage LEDGER the metering seams land on (`meter_ledger` / `meter_series`), readable
//!   through [`FixtureHost::ledger_usage`] once the host is [`governed`](FixtureHost::governed);
//! * the reserve-then-settle cost LEASES of the [`MeteringHost`] slice.
//!
//! Everything else on the seam answers the neutral "nothing configured" value (no pools, no secrets,
//! no identity chain, no completion pipeline). It is a test double: a leg the fixture does not model
//! answers its documented empty value rather than pretending to be the engine.

use crate::billing::{TokenUsage, Usage};
use crate::breaker::{CanonicalSignal, Disposition};
use crate::hooks::{RequestedSignals, ResolvedPolicy, TapEntry};
use crate::plane::approvals::Sealer;
use crate::plane::calllog::CallInput;
use crate::plane_host::{
    AdmissionHost, AdmitHandle, AudienceBinding, BreakerHost, BudgetHost, ClockHost,
    CompletionHost, CostHandle, CostLeaseId, DispatchScope, EngineHost, GateOutcome, GovAdmit,
    GovHandle, HookConfigHost, HostCompletion, IdentityHost, JournalHost, LanePoolHost,
    MeteringHost, MountHost, RegistryHost, SettleOutcome, TelemetryHost, TransformVerdict,
};
use crate::store::{
    Admit, BreakerCfg, BreakerState, LaneHealthSnapshot, LaneRuntime, LaneSnapshot, Permit,
    Unavailable,
};
use crate::trust::validate::{Lapsed, Standing};
use crate::trust::TrustState;
use busbar_api::{AuthPrincipal, IdentityRefusal, PlaneRequestCtx, VirtualKey};
use busbar_plugin::hot::{AdmissionId, Signal};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// A scripted gate verdict for one `(plane_key, container)`: handed the serialized request payload the
/// plane projected for the hook, answers the [`GateOutcome`] the real hook chain would.
pub type GateScript = Arc<dyn Fn(&[u8]) -> GateOutcome + Send + Sync>;

/// A scripted rewrite verdict for one `(plane_key, container)`: handed the serialized payload, answers
/// the [`TransformVerdict`] the real `prompt: rw` chain would (a committed rewrite, an abstain, or a
/// reject).
pub type RewriteScript = Arc<dyn Fn(&[u8]) -> TransformVerdict + Send + Sync>;

/// The usage a key has ledgered through the fixture's metering seams — the read-back twin of the
/// engine's `usage_for(key)`: `tokens` is every unit `meter_ledger` accrued, `requests` the billable
/// request count the ADMIT step's per-request fee increments (never the Meter step).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LedgerUsage {
    pub tokens: u64,
    pub requests: u64,
}

/// One `(pool, lane)` breaker cell of the fixture.
#[derive(Clone, Copy, Debug)]
struct Cell {
    state: BreakerState,
}

/// The seconds an OPEN cell stays open after a definitive (hard-down) record — the engine's first
/// cooldown step, so a `Retry-After` read off the fixture is a plausible whole-second floor.
const OPEN_COOLDOWN_SECS: u64 = 15;

/// One open reserve-then-settle cost lease.
#[derive(Clone, Copy, Debug)]
struct Lease {
    settled: u128,
    cap: Option<u128>,
}

/// One admin-audit row [`JournalHost::audit_record`] landed on the fixture — the read-back a plane's
/// exit-path/mutation test asserts against (action literal, resource, outcome, principal), the fixture
/// twin of the engine's in-process admin audit ring.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FixtureAuditEntry {
    pub action: String,
    pub resource: String,
    pub outcome: String,
    pub principal: String,
}

#[derive(Default)]
struct Inner {
    cells: BTreeMap<(String, usize), Cell>,
    gates: BTreeMap<(String, String), GateScript>,
    rewrites: BTreeMap<(String, String), RewriteScript>,
    ledger: BTreeMap<String, LedgerUsage>,
    leases: BTreeMap<u64, Lease>,
    slots: BTreeMap<String, Arc<dyn std::any::Any + Send + Sync>>,
    audit: Vec<FixtureAuditEntry>,
}

/// The in-memory engine host a plane's tests drive through the neutral seam. Build one with
/// [`FixtureHost::new`], configure it with the builder methods, then hand it to the plane as an
/// `Arc<dyn EngineHost>` (an `Arc<FixtureHost>` coerces) while keeping your own `Arc` to read the
/// state back.
pub struct FixtureHost {
    inner: Mutex<Inner>,
    governed: bool,
    next_request_id: AtomicU64,
    next_lease: AtomicU64,
    lanes: InertLanes,
    /// No hook on the fixture requests a candidate signal (the all-zero mask).
    signals: RequestedSignals,
}

impl Default for FixtureHost {
    fn default() -> Self {
        Self::new()
    }
}

impl FixtureHost {
    /// A bare host: no governance, no hooks attached, every breaker cell Closed.
    #[must_use]
    pub fn new() -> Self {
        FixtureHost {
            inner: Mutex::new(Inner::default()),
            governed: false,
            next_request_id: AtomicU64::new(1),
            next_lease: AtomicU64::new(1),
            lanes: InertLanes,
            signals: RequestedSignals::default(),
        }
    }

    /// Turn governance ON: `governance()` mints a handle and the metering seams land on the fixture's
    /// per-key ledger (read back with [`Self::ledger_usage`]). Off, `governance()` is `None` and the
    /// metering seams are never reached — exactly an ungoverned deployment.
    #[must_use]
    pub fn governed(mut self) -> Self {
        self.governed = true;
        self
    }

    /// Attach a scripted request-admission GATE to `container` on plane `plane_key`, so
    /// `gate_attached` answers true and `gate_decide` runs `script` over the projected payload.
    #[must_use]
    pub fn attach_gate(self, plane_key: &str, container: &str, script: GateScript) -> Self {
        self.lock()
            .gates
            .insert((plane_key.to_string(), container.to_string()), script);
        self
    }

    /// Attach a scripted `prompt: rw` REWRITE to `container` on plane `plane_key`, so `tap_attached`
    /// answers true and `transform_over` runs `script` over the projected payload.
    #[must_use]
    pub fn attach_rewrite(self, plane_key: &str, container: &str, script: RewriteScript) -> Self {
        self.lock()
            .rewrites
            .insert((plane_key.to_string(), container.to_string()), script);
        self
    }

    /// Install a type-erased plane runtime slot under `key`, read back through `plane_slot`.
    #[must_use]
    pub fn with_plane_slot(self, key: &str, slot: Arc<dyn std::any::Any + Send + Sync>) -> Self {
        self.lock().slots.insert(key.to_string(), slot);
        self
    }

    /// Finish the builder as the `Arc<dyn EngineHost>` a plane's production path takes.
    #[must_use]
    pub fn into_host(self) -> Arc<dyn EngineHost> {
        Arc::new(self)
    }

    /// The `(pool, lane)` breaker cell's current state — Closed until something is recorded.
    #[must_use]
    pub fn breaker_state(&self, pool: &str, lane: usize) -> BreakerState {
        self.lock()
            .cells
            .get(&(pool.to_string(), lane))
            .map_or(BreakerState::Closed, |c| c.state)
    }

    /// What `key_id` has ledgered through the metering seams, or `None` if nothing ever landed.
    #[must_use]
    pub fn ledger_usage(&self, key_id: &str) -> Option<LedgerUsage> {
        self.lock().ledger.get(key_id).copied()
    }

    /// How many cost leases were opened over this host's lifetime.
    #[must_use]
    pub fn leases_opened(&self) -> u64 {
        self.next_lease.load(Ordering::SeqCst) - 1
    }

    /// Every admin-audit row [`JournalHost::audit_record`] has landed on this host, in emission order —
    /// the read-back a plane's audit/exit-path test asserts an exact count and shape against.
    #[must_use]
    pub fn audit_log(&self) -> Vec<FixtureAuditEntry> {
        self.lock().audit.clone()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn now() -> u64 {
        crate::store::now()
    }
}

// ── The breaker slice: one in-memory cell per (pool, lane) ─────────────────────────────────────────

impl BreakerHost for FixtureHost {
    fn breaker_admit(
        &self,
        scope: &DispatchScope,
        pool: &[u8],
        lane: u32,
    ) -> Result<AdmissionId, Unavailable> {
        let pool = String::from_utf8_lossy(pool).into_owned();
        let state = self.breaker_state(&pool, lane as usize);
        if let BreakerState::Open { until } = state {
            if Self::now() < until {
                return Err(Unavailable::BreakerOpen { until });
            }
        }
        Ok(scope.register_admission(Box::new(())))
    }

    fn breaker_settle(
        &self,
        scope: &DispatchScope,
        admission: AdmissionId,
        signal: &Signal,
    ) -> busbar_plugin::hot::StatusClass {
        scope
            .settle_admission(admission, signal)
            .unwrap_or(signal.class)
    }

    fn breaker_record_success(&self, pool: &str, lane: usize) {
        self.lock().cells.insert(
            (pool.to_string(), lane),
            Cell {
                state: BreakerState::Closed,
            },
        );
    }

    fn breaker_record_signal(&self, pool: &str, lane: usize, sig: &CanonicalSignal) {
        // The same fold the engine applies: a definitive signal (auth / billing) opens the cell on
        // the first record; a client fault or context-length miss never penalizes it; a transient
        // blip is noted but a single one does not trip the fixture cell.
        if let Disposition::HardDown = crate::breaker::classify(sig) {
            self.lock().cells.insert(
                (pool.to_string(), lane),
                Cell {
                    state: BreakerState::Open {
                        until: Self::now() + OPEN_COOLDOWN_SECS,
                    },
                },
            );
        }
    }

    fn breaker_retry_after_secs(&self, pool: &str, lane: usize) -> u64 {
        match self.breaker_state(pool, lane) {
            BreakerState::Open { until } => until.saturating_sub(Self::now()).max(1),
            _ => 0,
        }
    }
}

// ── The lane/pool slice: no pools configured ─────────────────────────────────────────────────────

impl LanePoolHost for FixtureHost {
    fn lane_store(&self) -> &dyn LaneRuntime {
        &self.lanes
    }
    fn default_probe_interval_secs(&self) -> u64 {
        30
    }
    fn default_probe_timeout_secs(&self) -> u64 {
        5
    }
    fn pool_members_repeatable(&self, _member: &str) -> Option<(String, Vec<String>, Vec<String>)> {
        None
    }
    fn plane_pool_members(&self, _plane_key: &str, _member: &str) -> Option<(String, Vec<String>)> {
        None
    }
}

// ── The metering-lease slice: reserve-then-settle in memory, pricing off (no rate card) ──────────

impl MeteringHost for FixtureHost {
    fn cost_reserve(
        &self,
        _estimate_nanos: u128,
        _fee_nanos: u128,
        cap_nanos: Option<u128>,
    ) -> Option<CostLeaseId> {
        if cap_nanos == Some(0) {
            return None;
        }
        let id = self.next_lease.fetch_add(1, Ordering::SeqCst);
        self.lock().leases.insert(
            id,
            Lease {
                settled: 0,
                cap: cap_nanos,
            },
        );
        Some(CostLeaseId(id))
    }

    fn cost_settle(&self, lease: CostLeaseId, exact_nanos: u128) -> Option<SettleOutcome> {
        let mut inner = self.lock();
        let l = inner.leases.get_mut(&lease.0)?;
        l.settled = l.settled.saturating_add(exact_nanos);
        Some(SettleOutcome {
            exhausted: l.cap.is_some_and(|cap| l.settled >= cap),
        })
    }

    fn cost_settled(&self, lease: CostLeaseId) -> Option<u128> {
        self.lock().leases.get(&lease.0).map(|l| l.settled)
    }

    fn cost_close(&self, lease: CostLeaseId) -> Option<u128> {
        self.lock().leases.remove(&lease.0).map(|l| l.settled)
    }

    fn price_usage(&self, _model: &str, _usage: &Usage) -> Option<u128> {
        // No rate card configured: every model prices at zero, as the engine does.
        Some(0)
    }
}

impl ClockHost for FixtureHost {
    fn clock_now_secs(&self) -> u64 {
        Self::now()
    }
    fn clock_now_ms(&self) -> u64 {
        crate::store::now_ms()
    }
}

// ── Telemetry / journal: the fixture records nothing (the plane's own emits are what tests read) ──

impl TelemetryHost for FixtureHost {
    fn request_finished(
        &self,
        _plane: &str,
        _ingress_protocol: &str,
        _pool: &str,
        _outcome: &'static str,
        _seconds: f64,
    ) {
    }
    fn telemetry_upstream_attempt(&self, _pool_label: &str, _lane: usize) {}
    fn telemetry_upstream_failure(&self, _pool_label: &str, _lane: usize, _d: &'static str) {}
    fn telemetry_breaker_trip(&self, _pool_label: &str, _lane: usize) {}
    fn telemetry_failover(&self, _pool_label: &str, _reason: &'static str) {}
    fn telemetry_translation(&self, _from: &str, _to: &str) {}
    fn pool_label<'a>(&self, _model: &'a str) -> &'a str {
        "unresolved"
    }
}

impl JournalHost for FixtureHost {
    fn audit_emit(&self, _action: &str, _resource: &str, _outcome: &str, _principal: &str) {}
    fn audit_record(&self, action: &str, resource: &str, outcome: &'static str, principal: &str) {
        // Recorded (not a no-op): this is the ONE JournalHost leg a plane's exit-path test needs read
        // back — every other JournalHost leg stays a no-op fixture default (nothing today reads them).
        self.lock().audit.push(FixtureAuditEntry {
            action: action.to_string(),
            resource: resource.to_string(),
            outcome: outcome.to_string(),
            principal: principal.to_string(),
        });
    }
    fn call_log_emit(&self, _principal: &str, _input: CallInput) {}
    fn call_log_emit_hostless(&self, _principal: &str, _input: CallInput) {}
}

impl MountHost for FixtureHost {
    fn arrival_envelope_dialect(&self, _path: &str) -> &'static str {
        ""
    }
    fn arrival_fallback_error(
        &self,
        _path: &str,
        status: axum::http::StatusCode,
        kind: &str,
        message: &str,
    ) -> axum::response::Response {
        axum::response::Response::builder()
            .status(status)
            .header(axum::http::header::CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(
                serde_json::json!({ "error": { "type": kind, "message": message } }).to_string(),
            ))
            .expect("a static response builds")
    }
}

/// A resolver with no secrets behind it: every reference fails closed.
struct NoSecrets;

impl busbar_api::SecretResolve for NoSecrets {
    fn resolve(&self, _secret: &busbar_api::SecretRef) -> Result<Vec<u8>, String> {
        Err("the fixture host resolves no secrets".to_string())
    }
    fn resolve_string(&self, _secret: &busbar_api::SecretRef) -> Result<String, String> {
        Err("the fixture host resolves no secrets".to_string())
    }
}

impl RegistryHost for FixtureHost {
    fn next_request_id(&self) -> u64 {
        self.next_request_id.fetch_add(1, Ordering::Relaxed)
    }
    fn plane_slot(&self, key: &str) -> Option<Arc<dyn std::any::Any + Send + Sync>> {
        self.lock().slots.get(key).cloned()
    }
    fn plane_slot_live(&self, key: &str) -> Option<Arc<dyn std::any::Any + Send + Sync>> {
        self.plane_slot(key)
    }
    fn secret_resolver(&self) -> Arc<dyn busbar_api::SecretResolve> {
        Arc::new(NoSecrets)
    }
    fn subkey_sign(&self, _signing_input: &[u8]) -> Option<[u8; 64]> {
        None
    }
    fn plane_defs(&self) -> Arc<dyn std::any::Any + Send + Sync> {
        Arc::new(())
    }
}

impl HookConfigHost for FixtureHost {
    fn caller_in_hook_groups(&self, _caller_group: Option<&str>, _hook_groups: &[String]) -> bool {
        false
    }
    fn pool_rewrites(
        &self,
        _pool: &str,
    ) -> &[(std::time::Duration, Arc<dyn busbar_api::RoutingPolicy>)] {
        &[]
    }
    fn rewrite_hooks(&self) -> &[(std::time::Duration, Arc<dyn busbar_api::RoutingPolicy>)] {
        &[]
    }
    fn any_content_hook(&self) -> bool {
        false
    }
    fn tap_hooks(&self) -> &[TapEntry] {
        &[]
    }
    fn tap_hooks_response(&self) -> &[TapEntry] {
        &[]
    }
    fn tap_hooks_routing(&self) -> &[TapEntry] {
        &[]
    }
    fn tap_hooks_candidate(&self) -> &[TapEntry] {
        &[]
    }
    fn pool_gates(&self, _pool: &str) -> &[(u16, ResolvedPolicy)] {
        &[]
    }
    fn global_gates(&self) -> &[(u16, ResolvedPolicy)] {
        &[]
    }
    fn pool_policy(&self, _pool: &str) -> Option<&ResolvedPolicy> {
        None
    }
    fn requested_signals(&self) -> &RequestedSignals {
        &self.signals
    }
}

// ── The budget slice: the per-key ledger the metering seams land on ─────────────────────────────

impl BudgetHost for FixtureHost {
    fn governance_enabled(&self) -> bool {
        self.governed
    }
    fn meter_charge(&self, _scope: &DispatchScope, _usage: &busbar_plugin::hot::Usage) {}
    fn rate_headroom(
        &self,
        _gov: &GovHandle,
        _cost: &CostHandle,
        _key: &VirtualKey,
        _pool: Option<&str>,
        _now: u64,
    ) -> Option<f64> {
        None
    }
    fn budget_state(
        &self,
        _gov: &GovHandle,
        _cost: &CostHandle,
        _key: &VirtualKey,
        _now: u64,
    ) -> Vec<busbar_api::BudgetBucketState> {
        Vec::new()
    }
    fn governance(&self) -> Option<GovHandle> {
        self.governed.then(|| GovHandle(Arc::new(())))
    }
    fn cost(&self) -> CostHandle {
        CostHandle(Arc::new(()))
    }
    // The fixture carries no cost model, so it prices nothing and nothing is left unpriced — the
    // posture of a deployment with no rate card, which is what the fixture's `cost()` hands back.
    fn cost_pricing_enabled(&self, _cost: &CostHandle) -> bool {
        false
    }
    fn cost_model_unpriced(&self, _cost: &CostHandle, _model: &str) -> bool {
        false
    }
    fn meter_ledger(
        &self,
        _gov: &GovHandle,
        _cost: &CostHandle,
        key: &VirtualKey,
        _pool: &str,
        _model: &str,
        usage: &Usage,
        _now: u64,
    ) {
        let tokens: u64 = usage.usage_units.values().sum();
        if tokens == 0 {
            return;
        }
        let mut inner = self.lock();
        let entry = inner.ledger.entry(key.id.clone()).or_default();
        entry.tokens = entry.tokens.saturating_add(tokens);
    }
    fn meter_series(
        &self,
        _gov: &GovHandle,
        _key_id: &str,
        _model: &str,
        _provider: &str,
        _usage: Option<&TokenUsage>,
        _now: u64,
    ) {
    }
}

#[async_trait::async_trait]
impl IdentityHost for FixtureHost {
    fn quarantine_settle(&self, _subject: &str, _state: TrustState) -> bool {
        false
    }
    fn approval_redeem(&self, _nonce: &str, _expires_at: u64, _now: u64) -> bool {
        false
    }
    fn verify_token_test(&self, _token: &str) -> Option<Arc<VirtualKey>> {
        None
    }
    fn identity_audience_binding(&self, _token: &str, _expected_aud: &str) -> AudienceBinding {
        AudienceBinding::Opaque
    }
    async fn identity_admit(
        &self,
        _token: Option<String>,
        _audience: String,
        _resource: String,
    ) -> Result<(AuthPrincipal, PlaneRequestCtx), IdentityRefusal> {
        Err(IdentityRefusal::Denied)
    }
    fn principal_standing(
        &self,
        _standing: &Standing,
        _live_gen: u64,
        _now: u64,
    ) -> Result<Option<Arc<VirtualKey>>, Lapsed> {
        Ok(None)
    }
    fn ask_state_sealer(&self) -> Option<Sealer> {
        None
    }
}

// ── The admission slice: the scripted hook gate / rewrite chains ────────────────────────────────

impl AdmissionHost for FixtureHost {
    fn gate_decide(
        &self,
        plane_key: &str,
        container: &str,
        _request_id: u64,
        _tool: &str,
        args_json: &[u8],
        _key: Option<(&str, &str)>,
        _session_id: Option<&str>,
    ) -> GateOutcome {
        let script = self
            .lock()
            .gates
            .get(&(plane_key.to_string(), container.to_string()))
            .cloned();
        match script {
            Some(s) => s(args_json),
            None => GateOutcome::Proceed,
        }
    }
    fn gate_attached(&self, plane_key: &str, container: &str) -> bool {
        self.lock()
            .gates
            .contains_key(&(plane_key.to_string(), container.to_string()))
    }
    fn tap_attached(&self, plane_key: &str, container: &str) -> bool {
        self.lock()
            .rewrites
            .contains_key(&(plane_key.to_string(), container.to_string()))
    }
    fn transform_over(
        &self,
        plane_key: &str,
        container: &str,
        _request_id: u64,
        _tool: &str,
        args_json: &[u8],
        _key: Option<(&str, &str)>,
        _session_id: Option<&str>,
    ) -> TransformVerdict {
        let script = self
            .lock()
            .rewrites
            .get(&(plane_key.to_string(), container.to_string()))
            .cloned();
        match script {
            Some(s) => s(args_json),
            None => TransformVerdict::Proceed {
                applied: false,
                args_json: args_json.to_vec(),
            },
        }
    }
    fn govern_admit_reason(
        &self,
        _scope: &DispatchScope,
        _pool: &[u8],
        _identity_id: &[u8],
        _group: Option<&[u8]>,
    ) -> GovAdmit {
        GovAdmit::Admitted
    }
    fn destination_guard(
        &self,
        _gov: &PlaneRequestCtx,
        _proto: &'static str,
        _pool: &str,
        _started: std::time::Instant,
        _charged_at: u64,
    ) -> Result<(), Box<axum::response::Response>> {
        Ok(())
    }
    fn admission_door(
        &self,
        _gov: &PlaneRequestCtx,
        _proto: &'static str,
        _pool: &str,
        _started: std::time::Instant,
        _charged_at: u64,
    ) -> Result<(Option<AdmitHandle>, Option<String>), Box<axum::response::Response>> {
        Ok((None, None))
    }
    fn admission_check(
        &self,
        _gov: &PlaneRequestCtx,
        _proto: &'static str,
        _pool: &str,
        _charged_at: u64,
    ) -> Result<(Option<AdmitHandle>, Option<String>), Box<axum::response::Response>> {
        Ok((None, None))
    }
    fn finish_admitted(
        &self,
        _gov: &PlaneRequestCtx,
        _ingress_protocol: &str,
        _pool: &str,
        _started: std::time::Instant,
        _charged_at: u64,
        resp: axum::response::Response,
        _charged: bool,
    ) -> axum::response::Response {
        resp
    }
    fn finish_rejected(
        &self,
        _gov: &PlaneRequestCtx,
        _ingress_protocol: &str,
        _pool: &str,
        _started: std::time::Instant,
        _charged_at: u64,
        resp: axum::response::Response,
    ) -> axum::response::Response {
        resp
    }
    fn plane_audience_bound(&self, _plane_key: &str) -> bool {
        false
    }
}

#[async_trait::async_trait]
impl CompletionHost for FixtureHost {
    async fn synthesize_completion(
        &self,
        _gov: &PlaneRequestCtx,
        _model: &str,
        _body: bytes::Bytes,
        _max_body_bytes: usize,
    ) -> Result<HostCompletion, String> {
        Err("the fixture host drives no completion pipeline".to_string())
    }
}

#[async_trait::async_trait]
impl EngineHost for FixtureHost {}

// ── An inert lane store: no lanes configured, nothing admits, nothing records ───────────────────

/// The `LaneRuntime` view of a deployment with no model lanes at all — every query answers the empty
/// value, every record is a no-op. The fixture host's `lane_store` hands this out.
struct InertLanes;

impl LaneRuntime for InertLanes {
    fn usable(&self, _lane: usize, _now: u64) -> bool {
        false
    }
    fn usable_in(&self, _pool: &str, _lane: usize, _now: u64) -> bool {
        false
    }
    fn is_ready(&self, _lane: usize, _now: u64) -> bool {
        false
    }
    fn is_ready_any_cell(&self, _lane: usize, _now: u64) -> bool {
        false
    }
    fn ready_in(&self, _pool: &str, _lane: usize, _now: u64) -> bool {
        false
    }
    fn breaker_state_snapshot_in(&self, _pool: &str, _lane: usize) -> BreakerState {
        BreakerState::Closed
    }
    fn error_rate_in(&self, _pool: &str, _lane: usize, _now: u64) -> Option<f64> {
        None
    }
    fn available_permits(&self, _lane: usize) -> usize {
        0
    }
    fn lane_budget_remaining(&self, _lane: usize) -> Option<i64> {
        None
    }
    fn lane_admissible(&self, _lane: usize) -> bool {
        false
    }
    fn lane_latency_ms(&self, _lane: usize) -> Option<f64> {
        None
    }
    fn record_latency_in(&self, _pool: &str, _lane: usize, _latency_ms: f64) {}
    fn acquire_for_dispatch_in(&self, _pool: &str, _lane: usize, _now: u64) -> bool {
        false
    }
    fn classify(&self, _pool: &str, _lane: usize, _now: u64) -> Result<(), Unavailable> {
        Err(Unavailable::Dead)
    }
    fn try_admit(&self, _pool: &str, _lane: usize, _now: u64) -> Result<Admit, Unavailable> {
        Err(Unavailable::Dead)
    }
    fn lane_semaphore(&self, _lane: usize) -> Option<Arc<tokio::sync::Semaphore>> {
        None
    }
    fn try_admit_breaker(
        &self,
        _pool: &str,
        _lane: usize,
        _now: u64,
    ) -> Result<Option<u64>, Unavailable> {
        Err(Unavailable::Dead)
    }
    fn release_probe_in(&self, _pool: &str, _lane: usize) {}
    fn probe_epoch_in(&self, _pool: &str, _lane: usize) -> u64 {
        0
    }
    fn release_probe_owned_in(&self, _pool: &str, _lane: usize, _owned_epoch: u64) {}
    fn breaker_state(&self, _lane: usize) -> BreakerState {
        BreakerState::Closed
    }
    fn breaker_state_in(&self, _pool: &str, _lane: usize) -> BreakerState {
        BreakerState::Closed
    }
    fn force_open_in(&self, _pool: &str, _lane: usize, _cooldown_until: u64) {}
    fn cooldown_remaining(&self, _lane: usize, _now: u64) -> u64 {
        0
    }
    fn cooldown_remaining_in(&self, _pool: &str, _lane: usize, _now: u64) -> u64 {
        0
    }
    fn lane_needs_probe(&self, _lane: usize, _now: u64) -> bool {
        false
    }
    fn record_success(&self, _lane: usize) {}
    fn record_success_in(&self, _pool: &str, _lane: usize) {}
    fn record_probe_success_all_cells(&self, _lane: usize) {}
    fn record_client_fault(&self, _lane: usize) {}
    fn record_transient(
        &self,
        _lane: usize,
        _what: &str,
        _cfg: &BreakerCfg,
        _retry_after: Option<u64>,
    ) -> bool {
        false
    }
    fn record_transient_in(
        &self,
        _pool: &str,
        _lane: usize,
        _what: &str,
        _cfg: &BreakerCfg,
        _retry_after: Option<u64>,
    ) -> bool {
        false
    }
    fn record_rate_limit(
        &self,
        _lane: usize,
        _now: u64,
        _cfg: &BreakerCfg,
        _retry_after: Option<u64>,
    ) -> bool {
        false
    }
    fn record_rate_limit_in(
        &self,
        _pool: &str,
        _lane: usize,
        _now: u64,
        _cfg: &BreakerCfg,
        _retry_after: Option<u64>,
    ) -> bool {
        false
    }
    fn record_hard_down(&self, _lane: usize, _reason: &str) {}
    fn record_hard_down_all_cells(&self, _lane: usize, _reason: &str) -> bool {
        false
    }
    fn recover_lane(&self, _lane: usize) {}
    fn record_probe_failure_all_cells(
        &self,
        _lane: usize,
        _what: &str,
        _resolve_cfg: &dyn Fn(&str) -> BreakerCfg,
        _retry_after: Option<u64>,
    ) {
    }
    fn try_acquire(&self, _lane: usize) -> Option<Permit> {
        None
    }
    fn spend_budget(&self, _lane: usize) -> bool {
        false
    }
    fn refund_budget(&self, _lane: usize) {}
    fn select_weighted(&self, _candidates: &[usize], _weights: &[u32], _now: u64) -> Option<usize> {
        None
    }
    fn select_weighted_in(
        &self,
        _pool: &str,
        _candidates: &[usize],
        _weights: &[u32],
        _now: u64,
    ) -> Option<usize> {
        None
    }
    fn snapshot(&self, _lane: usize, _now: u64) -> LaneSnapshot {
        unreachable!("the inert lane store has no lanes to snapshot")
    }
    fn export_health(&self) -> Vec<LaneHealthSnapshot> {
        Vec::new()
    }
}
