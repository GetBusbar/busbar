// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE NEUTRAL FIXTURE HOST — an in-memory [`EngineHost`] a plane crate's tests drive INSTEAD of
//! minting a host over the engine's `App`. A plane is a plugin on the plane ABI, and its tests must
//! not reach into core any more than its production code does; before this fixture a plane test that
//! needed a host had to build `busbar_kernel::test_support::TestApp` and call
//! `busbar_kernel::plane_host::engine_host(&app)` — the exact backwards reach the purity lint forbids.
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
//!   through [`FixtureHost::ledger_usage`], per `(lane, class)` through [`FixtureHost::ledger_rows`],
//!   and per series row through [`FixtureHost::series_rows`] once the host is
//!   [`governed`](FixtureHost::governed);
//! * the key's BUDGET VIEW (`budget_state`): a chain a test sets outright
//!   ([`FixtureHost::with_budget_chain`] / [`FixtureHost::set_budget_chain`]), or a count cap
//!   ([`FixtureHost::with_count_cap`]) whose remaining is the cap less every count ledgered — so the
//!   kernel's session account, which reads this view after each turn, can be driven dry.
//!
//! The fixture implements ONLY the plane-facing seam: it names no cost or price type (#43 — a plane is
//! pricing-blind, and so is the host its tests stand in). What a count is WORTH is the kernel's
//! read-time view, proven over the real engine in the composition root's tests.
//!
//! Everything else on the seam answers the neutral "nothing configured" value (no pools, no secrets,
//! no identity chain, no completion pipeline). It is a test double: a leg the fixture does not model
//! answers its documented empty value rather than pretending to be the engine.

use busbar_contract::auth::{AuthPrincipal, IdentityRefusal};
use busbar_contract::records::{PlaneRequestCtx, VirtualKey};
use busbar_kernel::billing::{TokenUsage, Usage};
use busbar_kernel::breaker::{CanonicalSignal, Disposition};
use busbar_kernel::hooks::{RequestedSignals, ResolvedPolicy, TapEntry};
use busbar_kernel::plane::approvals::Sealer;
use busbar_kernel::plane::calllog::CallInput;
use busbar_kernel::plane_host::{
    AdmissionHost, AdmitHandle, AudienceBinding, BreakerHost, BudgetHost, ClockHost,
    CompletionHost, DispatchScope, EngineHost, GateOutcome, GovAdmit, GovHandle, HookConfigHost,
    HostCompletion, IdentityHost, JournalHost, LanePoolHost, MeterPin, MountHost, RegistryHost,
    TelemetryHost, TransformVerdict,
};
use busbar_kernel::store::{BreakerState, HealthState, LaneRuntime, Unavailable};
use busbar_kernel::trust::validate::{Lapsed, Standing};
use busbar_kernel::trust::TrustState;
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
    /// Sessions the kernel counted as opened, on the plane's own fee lane (#47 `fees.per_session`) —
    /// kept apart from the turn counts above and from [`FixtureHost::ledger_rows`].
    pub sessions: u64,
}

/// One `(pool, lane)` breaker cell of the fixture.
#[derive(Clone, Copy, Debug)]
struct Cell {
    state: BreakerState,
}

/// The seconds an OPEN cell stays open after a definitive (hard-down) record — the engine's first
/// cooldown step, so a `Retry-After` read off the fixture is a plausible whole-second floor.
const OPEN_COOLDOWN_SECS: u64 = 15;

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
    slots: BTreeMap<String, Arc<dyn std::any::Any + Send + Sync>>,
    audit: Vec<FixtureAuditEntry>,
    /// The budget chain `budget_state` answers for every key — empty (uncapped) unless a test sets one.
    budget: Vec<busbar_contract::hooks::BudgetBucketState>,
    /// A count cap `budget_state` answers as one bucket, remaining the cap less the key's counts.
    count_cap: Option<i64>,
    /// Every count `meter_ledger` landed, per key, per `(lane, class)`.
    rows: BTreeMap<String, BTreeMap<(String, String), u64>>,
    /// Every series row `meter_series` wrote, per key, as `(model, provider)`, in order.
    series: BTreeMap<String, Vec<(String, String)>>,
    /// Every request a plane reported through `request_finished`, in order.
    finished: Vec<FinishedRequest>,
}

/// One request a plane reported through [`TelemetryHost::request_finished`] — the read-back twin of the
/// engine's plane-labelled request counter and duration sample.
#[derive(Clone, Debug, PartialEq)]
pub struct FinishedRequest {
    pub plane: String,
    pub ingress_protocol: String,
    pub pool: String,
    pub outcome: &'static str,
    pub seconds: f64,
}

/// The in-memory engine host a plane's tests drive through the neutral seam. Build one with
/// [`FixtureHost::new`], configure it with the builder methods, then hand it to the plane as an
/// `Arc<dyn EngineHost>` (an `Arc<FixtureHost>` coerces) while keeping your own `Arc` to read the
/// state back.
pub struct FixtureHost {
    inner: Mutex<Inner>,
    governed: bool,
    next_request_id: AtomicU64,
    /// The lane store `lane_store` hands out: the kernel's OWN `LaneRuntime` implementor with no
    /// lanes configured, so this double never re-implements (and never drifts from) that trait.
    lanes: HealthState,
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
            lanes: HealthState::new(Vec::new()),
            signals: RequestedSignals::default(),
        }
    }

    /// Answer `chain` as every key's budget chain.
    #[must_use]
    pub fn with_budget_chain(self, chain: Vec<busbar_contract::hooks::BudgetBucketState>) -> Self {
        self.set_budget_chain(chain);
        self
    }

    /// Replace the budget chain every key reads, mid-test — the view a live session's next turn meets.
    pub fn set_budget_chain(&self, chain: Vec<busbar_contract::hooks::BudgetBucketState>) {
        self.lock().budget = chain;
    }

    /// Answer every key's budget view as ONE bucket capped at `cap` counts: its remaining is the cap
    /// less every count the key has ledgered. A stand-in for a card that makes each count worth one
    /// unit, without this host naming a card.
    #[must_use]
    pub fn with_count_cap(self, cap: i64) -> Self {
        self.lock().count_cap = Some(cap);
        self
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

    /// Every request reported through `request_finished`, in order.
    #[must_use]
    pub fn finished_requests(&self) -> Vec<FinishedRequest> {
        self.lock().finished.clone()
    }

    /// Every count `key_id` has ledgered, per `(lane, class)` — the rows a plane's metering wrote.
    #[must_use]
    pub fn ledger_rows(&self, key_id: &str) -> BTreeMap<(String, String), u64> {
        self.lock().rows.get(key_id).cloned().unwrap_or_default()
    }

    /// Every series row `key_id`'s metering wrote through `meter_series`, as `(model, provider)`, in
    /// order — the rows whose `provider` column decides which plane `GET /admin/usage` prices them as.
    #[must_use]
    pub fn series_rows(&self, key_id: &str) -> Vec<(String, String)> {
        self.lock().series.get(key_id).cloned().unwrap_or_default()
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

    /// The ADMIT step's per-request FEE, landed on the presenting key's ledger row — the write side of
    /// [`LedgerUsage::requests`]. Governance off, or a request that carries no resolved key, is charged
    /// nothing (the ungoverned posture: there is no key to bill). Called once per admission decision,
    /// so a plane that runs the door twice for one request reads back two fees, exactly as a
    /// double-charging deployment would.
    fn charge_request_fee(&self, gov: &PlaneRequestCtx) {
        if !self.governed {
            return;
        }
        let Some(key) = gov.key() else { return };
        let mut inner = self.lock();
        let entry = inner.ledger.entry(key.id.clone()).or_default();
        entry.requests = entry.requests.saturating_add(1);
    }

    fn now() -> u64 {
        busbar_substrate_values::store::now()
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
            .unwrap_or(signal.class.class())
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
        if let Disposition::HardDown = busbar_kernel::breaker::classify(sig) {
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

impl ClockHost for FixtureHost {
    fn clock_now_secs(&self) -> u64 {
        Self::now()
    }
    fn clock_now_ms(&self) -> u64 {
        busbar_substrate_values::store::now_ms()
    }
}

// ── Telemetry / journal: the fixture records nothing (the plane's own emits are what tests read) ──

impl TelemetryHost for FixtureHost {
    fn request_finished(
        &self,
        plane: &str,
        ingress_protocol: &str,
        pool: &str,
        outcome: &'static str,
        seconds: f64,
    ) {
        self.lock().finished.push(FinishedRequest {
            plane: plane.to_string(),
            ingress_protocol: ingress_protocol.to_string(),
            pool: pool.to_string(),
            outcome,
            seconds,
        });
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

impl busbar_contract::secret::SecretResolve for NoSecrets {
    fn resolve(&self, _secret: &busbar_contract::secret_ref::SecretRef) -> Result<Vec<u8>, String> {
        Err("the fixture host resolves no secrets".to_string())
    }
    fn resolve_string(
        &self,
        _secret: &busbar_contract::secret_ref::SecretRef,
    ) -> Result<String, String> {
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
    fn secret_resolver(&self) -> Arc<dyn busbar_contract::secret::SecretResolve> {
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
    ) -> &[(
        std::time::Duration,
        Arc<dyn busbar_contract::hooks::RoutingPolicy>,
    )] {
        &[]
    }
    fn rewrite_hooks(
        &self,
    ) -> &[(
        std::time::Duration,
        Arc<dyn busbar_contract::hooks::RoutingPolicy>,
    )] {
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
        _pin: &MeterPin,
        _key: &VirtualKey,
        _pool: Option<&str>,
        _now: u64,
    ) -> Option<f64> {
        None
    }
    fn budget_state(
        &self,
        _pin: &MeterPin,
        key: &VirtualKey,
        _now: u64,
    ) -> Vec<busbar_contract::hooks::BudgetBucketState> {
        let inner = self.lock();
        let Some(cap) = inner.count_cap else {
            return inner.budget.clone();
        };
        let counted = inner.ledger.get(&key.id).map_or(0, |u| u.tokens);
        let counted = i64::try_from(counted).unwrap_or(i64::MAX);
        vec![busbar_contract::hooks::BudgetBucketState {
            bucket_id: key.id.clone(),
            budget_group: None,
            pool: None,
            spend_micros_at_current_rate: counted,
            remaining_micros: Some(cap.saturating_sub(counted).max(0)),
            window_start: 0,
            budget_period: "day".to_string(),
        }]
    }
    fn governance(&self) -> Option<GovHandle> {
        self.governed.then(|| GovHandle(Arc::new(())))
    }
    // No card here, so nothing a card could miss.
    fn cost_model_unpriced(&self, _model: &str) -> bool {
        false
    }
    fn meter_ledger(
        &self,
        _pin: &MeterPin,
        key: &VirtualKey,
        _pool: &str,
        lane: &str,
        usage: &Usage,
        _now: u64,
    ) {
        if lane.ends_with(busbar_kernel::governance::PLANE_LANE_SEP) {
            // The kernel's session count on the plane's fee lane: not a turn's count.
            let n = usage.usage_units.values().sum::<u64>();
            let mut inner = self.lock();
            let entry = inner.ledger.entry(key.id.clone()).or_default();
            entry.sessions = entry.sessions.saturating_add(n);
            return;
        }
        let tokens: u64 = usage.usage_units.values().sum();
        if tokens == 0 {
            return;
        }
        let mut inner = self.lock();
        let entry = inner.ledger.entry(key.id.clone()).or_default();
        entry.tokens = entry.tokens.saturating_add(tokens);
        let rows = inner.rows.entry(key.id.clone()).or_default();
        for (class, n) in &usage.usage_units {
            let row = rows.entry((lane.to_string(), class.clone())).or_default();
            *row = row.saturating_add(*n);
        }
    }
    fn meter_series(
        &self,
        _gov: &GovHandle,
        key_id: &str,
        model: &str,
        provider: &str,
        _usage: Option<&TokenUsage>,
        _now: u64,
    ) {
        self.lock()
            .series
            .entry(key_id.to_string())
            .or_default()
            .push((model.to_string(), provider.to_string()));
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
        gov: &PlaneRequestCtx,
        _proto: &'static str,
        _pool: &str,
        _started: std::time::Instant,
        _charged_at: u64,
    ) -> Result<(Option<AdmitHandle>, Option<String>), Box<axum::response::Response>> {
        self.charge_request_fee(gov);
        Ok((None, None))
    }
    fn admission_check(
        &self,
        gov: &PlaneRequestCtx,
        _proto: &'static str,
        _pool: &str,
        _charged_at: u64,
    ) -> Result<(Option<AdmitHandle>, Option<String>), Box<axum::response::Response>> {
        self.charge_request_fee(gov);
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
        Err("the fixture host drives no dispatch pipeline".to_string())
    }
}

#[async_trait::async_trait]
impl EngineHost for FixtureHost {}

#[cfg(test)]
#[path = "tests/fixture_host_tests.rs"]
mod tests;
