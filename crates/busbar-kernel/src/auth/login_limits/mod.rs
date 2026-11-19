// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE LOGIN ATTEMPT LIMITER (design `login-attempt-limiter.md`, Revision 2).
//!
//! Every hosted credential sign-in passes here BEFORE the login plugin is called:
//!
//! 1. the method's outage breaker (503, no plugin call, nothing counted);
//! 2. the submission is canonicalised against the method's DECLARED form (declared names only,
//!    each at most once; a duplicate is refused) — the account key is the first Text field;
//! 3. no signing key or no core store: refused 503 (fail closed);
//! 4. per source (memory, this node): submission rate and failure ceilings, /64 /48 /32 for IPv6,
//!    tightened while the global alarm holds;
//! 5. per account (core store, fleet-wide): one claim slot is taken before the call.
//!
//! Then the plugin runs, and its answer settles the reservations: only a `NotRun` (core knows the
//! plugin was never entered) is refunded; a success clears the account; every plugin answer and a
//! fault keep the reservation, because the bind may have been sent.

pub(crate) mod account;
pub mod key;
pub(crate) mod node;
pub mod policy;
pub mod source;

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use busbar_contract::auth::{FieldKind, LoginForm, LoginOutcome, Principal};
use busbar_contract::auth_calls::RejectHint;
use foldhash::HashMap;

use crate::auth::login::LoginJudged;
use crate::diagnostics::{
    diag_debug, diag_warn, LOGIN_ACCOUNT_THROTTLE_SUSTAINED, LOGIN_CLIENT_ADDRESS_UNKNOWN,
    LOGIN_GLOBAL_ALARM, LOGIN_LIMITER_DISABLED, LOGIN_LIMITER_NO_KEY,
    LOGIN_LIMITER_STORE_UNAVAILABLE, LOGIN_PROVIDER_BREAKER_OPEN, LOGIN_THROTTLED_ACCOUNT,
    LOGIN_THROTTLED_SOURCE,
};
use crate::persistence::facade::CoreStore;

pub use policy::LoginLimitsPolicy;
pub use source::{client_source, ClientAddr, ClientSource, TrustedProxies, UnknownSource};

/// A boxed future the limiter's plugin door answers with.
pub type DoorFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Where an audit record goes: `(action, resource, outcome, principal)`.
pub type AuditSink = fn(&str, &str, &'static str, &str);

fn ring_audit(action: &str, resource: &str, outcome: &'static str, principal: &str) {
    crate::audit_ring::AUDIT.record_by(action, resource, outcome, principal);
}

/// THE NODE'S LIMITER STATE, carried across config reloads (like the mutation limiter); the
/// policy is re-published by each generation's build.
pub struct LoginGuard {
    policy: RwLock<Arc<LoginLimitsPolicy>>,
    sources: Mutex<node::SourceTable>,
    alarm: Mutex<node::GlobalAlarm>,
    breakers: Mutex<HashMap<String, node::Breaker>>,
    admin: Mutex<node::AdminTable>,
    audit: Mutex<node::AuditGate>,
    sustained: Mutex<node::Sustained>,
    store_degraded: AtomicBool,
    no_key_warned: AtomicBool,
    unknown_warned: AtomicBool,
    sink: AuditSink,
}

impl Default for LoginGuard {
    fn default() -> Self {
        Self::with_sink(ring_audit)
    }
}

impl std::fmt::Debug for LoginGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LoginGuard(..)")
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl LoginGuard {
    /// A guard whose audit records go to `sink` (tests capture them).
    #[must_use]
    pub fn with_sink(sink: AuditSink) -> Self {
        Self {
            policy: RwLock::new(Arc::new(LoginLimitsPolicy::default())),
            sources: Mutex::default(),
            alarm: Mutex::default(),
            breakers: Mutex::default(),
            admin: Mutex::default(),
            audit: Mutex::default(),
            sustained: Mutex::default(),
            store_degraded: AtomicBool::new(false),
            no_key_warned: AtomicBool::new(false),
            unknown_warned: AtomicBool::new(false),
            sink,
        }
    }

    /// Publish this generation's policy; a disabled limiter is logged (BUSBAR-4037) every time.
    pub fn configure(&self, policy: LoginLimitsPolicy) {
        for (on, which) in [
            (policy.source.enabled, "auth.login_limits.per_source"),
            (policy.global.enabled, "auth.login_limits.global"),
        ] {
            if !on {
                diag_warn!(
                    LOGIN_LIMITER_DISABLED,
                    limiter = which,
                    "{which} is disabled: credential sign-ins are not limited by it (the \
                     per-account limiter still applies)"
                );
            }
        }
        *self.policy.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(policy);
    }

    /// The policy in force.
    #[must_use]
    pub fn policy(&self) -> Arc<LoginLimitsPolicy> {
        self.policy
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Resolve a request's client, raising BUSBAR-4036 (latched) when it cannot be told.
    #[must_use]
    pub fn source_of(
        &self,
        peer: Option<std::net::IpAddr>,
        headers: &axum::http::HeaderMap,
    ) -> ClientSource {
        let source = client_source(peer, headers, &self.policy().proxies);
        if let ClientSource::Unknown(why) = source {
            if !self.unknown_warned.swap(true, Ordering::Relaxed) {
                diag_warn!(LOGIN_CLIENT_ADDRESS_UNKNOWN, reason = ?why,
                    "the client address of a sign-in or admin request is unknown; per-source \
                     limits are skipped for it (set client_address.trusted_proxies when an ingress \
                     forwards for clients)");
            } else {
                diag_debug!(LOGIN_CLIENT_ADDRESS_UNKNOWN, reason = ?why,
                    "the client address of a sign-in or admin request is unknown");
            }
        }
        source
    }

    fn audit(&self, action: &str, resource: &str, principal: &str, window: u64, now: u64) -> bool {
        let decision = lock(&self.audit).admit(action, principal, window, now);
        if let Some(count) = decision.summary {
            (self.sink)(
                "auth.login_throttled.suppressed",
                &crate::cold::auth::login::suppressed_count(count),
                crate::audit_ring::OUTCOME_REJECTED,
                "login-limiter",
            );
        }
        if decision.record {
            let outcome = match action {
                "auth.login_succeeded" => crate::audit_ring::OUTCOME_APPLIED,
                "auth.login_alarm" => crate::audit_ring::OUTCOME_DEGRADED,
                _ => crate::audit_ring::OUTCOME_REJECTED,
            };
            (self.sink)(action, resource, outcome, principal);
        }
        decision.record
    }

    fn store_failed(&self, during: &'static str) {
        if !self.store_degraded.swap(true, Ordering::Relaxed) {
            diag_warn!(
                LOGIN_LIMITER_STORE_UNAVAILABLE,
                during,
                "the login attempt limiter cannot reach the core store; credential sign-ins are \
                 refused (503) without calling the login plugin until it answers"
            );
        } else {
            diag_debug!(
                LOGIN_LIMITER_STORE_UNAVAILABLE,
                during,
                "the login attempt limiter cannot reach the core store"
            );
        }
    }

    fn store_answered(&self) {
        if self.store_degraded.swap(false, Ordering::Relaxed) {
            tracing::info!(
                diag = %LOGIN_LIMITER_STORE_UNAVAILABLE.banner(),
                "the login attempt limiter reaches the core store again; credential sign-ins resume"
            );
        }
    }

    fn global_failure(&self, policy: &LoginLimitsPolicy, method: &str, now: u64) {
        if !policy.global.enabled {
            return;
        }
        let change = lock(&self.alarm).failure(policy.global.failures_per_minute, now);
        if let Some(node::AlarmChange::Tripped(rate)) = change {
            diag_warn!(LOGIN_GLOBAL_ALARM, method = %method, failures_per_minute = rate,
                "credential sign-in failures on this node passed the global alarm threshold; \
                 per-source limits are tightened while it holds");
            self.audit("auth.login_alarm", method, "global", 60, now);
        }
    }

    fn tightened(&self, policy: &LoginLimitsPolicy, now: u64) -> bool {
        if !policy.global.enabled {
            return false;
        }
        let (on, change) = lock(&self.alarm).poll(policy.global.failures_per_minute, now);
        if change == Some(node::AlarmChange::Cleared) {
            tracing::info!(diag = %LOGIN_GLOBAL_ALARM.banner(),
                "credential sign-in failures fell below the global alarm threshold; per-source \
                 limits are restored");
        }
        on
    }

    /// `Some(retry_after_secs)` when `source` has spent its admin-door budget.
    #[must_use]
    pub fn admin_throttled(&self, source: ClientSource, now: u64) -> Option<u64> {
        let ClientSource::Known(ip) = source else {
            return None;
        };
        let limit = self.policy().admin;
        lock(&self.admin).throttled(ip, limit, now)
    }

    /// Count one PRESENTED-AND-REFUSED admin credential from `source` (never a request that
    /// presented none). The refusal that spends the budget is logged and audited once.
    pub fn admin_refused(&self, source: ClientSource, now: u64) {
        let ClientSource::Known(ip) = source else {
            return;
        };
        let limit = self.policy().admin;
        if lock(&self.admin).refused(ip, limit, now) {
            let label = source::SourceBucket::base(ip).label();
            crate::diagnostics::diag_warn!(
                crate::diagnostics::ADMIN_AUTH_THROTTLED_SOURCE,
                source = %label,
                "one source spent its budget of refused admin credentials; it is answered 429 \
                 until the window passes"
            );
            (self.sink)(
                "admin.auth_throttled",
                &label,
                crate::audit_ring::OUTCOME_REJECTED,
                &crate::cold::auth::login::source_principal(&label),
            );
        }
    }
}

impl crate::state::App {
    /// The node's login attempt limiter.
    #[must_use]
    pub fn login_guard(&self) -> &LoginGuard {
        &self.login_guard
    }
}

/// One credential submission, as the hosted flow hands it over.
#[derive(Debug, Clone)]
pub struct CredentialAttempt {
    /// The method (`identity-providers.<name>`) the login cookie names.
    pub method: String,
    /// The login's state (already checked against the cookie).
    pub state: String,
    /// The form as posted, `__state` removed, in order, duplicates kept (they are judged here).
    pub form: Vec<(String, String)>,
    /// Who sent it.
    pub source: ClientSource,
}

/// What the limiter and the plugin came to; the hosted flow renders it.
#[derive(Debug, Clone, PartialEq)]
pub enum CredentialVerdict {
    /// Signed in.
    Identified(Principal),
    /// The plugin declined the credential (401), or faulted (401, as before).
    Declined,
    /// The plugin could not reach its directory or IdP (503).
    Outage {
        /// The IdP's stated delay.
        retry_after_secs: Option<u64>,
    },
    /// Any other plugin answer (502 "didn't finish").
    Unfinished,
    /// Refused by a limiter, before the plugin (429).
    Throttled {
        /// The method's window in whole minutes.
        retry_after_secs: u64,
    },
    /// Refused before the plugin because busbar could not judge it safely: the store or the key
    /// is unavailable, the method's breaker is open, or the plugin was never entered (503).
    Unavailable {
        /// The delay to state; `None` = the default.
        retry_after_secs: Option<u64>,
    },
    /// A declared field was posted twice (400), refused before the plugin.
    Malformed,
}

/// The plugin, as the limiter calls it.
pub trait CredentialDoor: Send + Sync {
    /// The form `method` declares.
    fn declared_form<'a>(&'a self, method: &'a str) -> DoorFuture<'a, Option<LoginForm>>;
    /// Hand the canonical submission to `method`'s `complete_login`.
    fn complete<'a>(
        &'a self,
        method: &'a str,
        state: String,
        submitted: Vec<(String, String)>,
    ) -> DoorFuture<'a, (LoginJudged, Option<RejectHint>)>;
}

/// The canonical submission: what is forwarded, and the account identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Canonical {
    /// Declared names only, in declared order, each once.
    pub forwarded: Vec<(String, String)>,
    /// The first declared Text field's value; `None` when the form declares no Text field.
    pub account: Option<String>,
}

/// A declared name was posted more than once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DuplicateField(pub std::sync::Arc<str>);

/// Reduce a posted form to the declared one.
pub fn canonicalise(
    form: &LoginForm,
    posted: &[(String, String)],
) -> Result<Canonical, DuplicateField> {
    let mut forwarded = Vec::with_capacity(form.fields.len());
    let mut account = None;
    let mut seen_text = false;
    for field in &form.fields {
        let mut values = posted.iter().filter(|(k, _)| k.as_str() == &*field.name);
        let value = values.next();
        if values.next().is_some() {
            return Err(DuplicateField(std::sync::Arc::clone(&field.name)));
        }
        if field.kind == FieldKind::Text && !seen_text {
            seen_text = true;
            account = Some(value.map(|(_, v)| v.clone()).unwrap_or_default());
        }
        if let Some((k, v)) = value {
            forwarded.push((k.clone(), v.clone()));
        }
    }
    Ok(Canonical { forwarded, account })
}

/// What the limiter needs from the running app.
pub struct Context<'a> {
    /// The node's limiter state.
    pub guard: &'a LoginGuard,
    /// The core store; `None` = unavailable.
    pub store: Option<&'a CoreStore>,
    /// The account key; `None` = no signing key.
    pub keyer: Option<key::AccountKeyer>,
    /// The plugin.
    pub door: &'a dyn CredentialDoor,
    /// Now, Unix seconds.
    pub now: u64,
}

/// `busbar_login_attempts_total{method,outcome}`: every credential submission, by outcome.
pub(crate) const LOGIN_ATTEMPTS_TOTAL: &str = "busbar_login_attempts_total";
/// `busbar_login_throttled_total{method,limiter}`: every throttled submission, by limiter.
pub(crate) const LOGIN_THROTTLED_TOTAL: &str = "busbar_login_throttled_total";

fn outcome_label(v: &CredentialVerdict) -> &'static str {
    match v {
        CredentialVerdict::Identified(_) => "identified",
        CredentialVerdict::Declined => "declined",
        CredentialVerdict::Outage { .. } => "outage",
        CredentialVerdict::Unfinished => "unfinished",
        CredentialVerdict::Throttled { .. } => "throttled",
        CredentialVerdict::Unavailable { .. } => "unavailable",
        CredentialVerdict::Malformed => "malformed",
    }
}

/// Judge one credential submission and, when it is admitted, run it.
pub async fn judge(cx: Context<'_>, attempt: CredentialAttempt) -> CredentialVerdict {
    let method = attempt.method.clone();
    let verdict = judge_inner(cx, attempt).await;
    metrics::counter!(
        LOGIN_ATTEMPTS_TOTAL,
        "method" => method,
        "outcome" => outcome_label(&verdict)
    )
    .increment(1);
    verdict
}

async fn judge_inner(cx: Context<'_>, attempt: CredentialAttempt) -> CredentialVerdict {
    let guard = cx.guard;
    let policy = guard.policy();
    let method = attempt.method.as_str();
    let now = cx.now;
    // The store's own clock, read once for the op: the account slots' expiries.
    let store_now = crate::store::now();
    let retry_after_secs = policy.retry_after_secs(method);
    let window = policy.account_for(method).window_secs;

    let open = lock(&guard.breakers)
        .get(method)
        .is_some_and(|b| b.open(now));
    if open {
        return CredentialVerdict::Unavailable {
            retry_after_secs: Some(node::BREAKER_OPEN_SECS),
        };
    }

    let Some(form) = cx.door.declared_form(method).await else {
        return CredentialVerdict::Unavailable {
            retry_after_secs: None,
        };
    };
    let canonical = match canonicalise(&form, &attempt.form) {
        Ok(c) => c,
        Err(DuplicateField(name)) => {
            tracing::debug!(method = %method, field = %name,
                "credential sign-in refused: a declared field was posted more than once");
            return CredentialVerdict::Malformed;
        }
    };

    let Some(keyer) = cx.keyer.as_ref() else {
        if !guard.no_key_warned.swap(true, Ordering::Relaxed) {
            diag_warn!(LOGIN_LIMITER_NO_KEY, method = %method,
                "credential sign-in refused: no auth.signing_key is configured to key the login \
                 attempt limiter");
        } else {
            diag_debug!(LOGIN_LIMITER_NO_KEY, method = %method,
                "credential sign-in refused: no auth.signing_key");
        }
        return CredentialVerdict::Unavailable {
            retry_after_secs: None,
        };
    };
    let Some(store) = cx.store else {
        guard.store_failed("no core store");
        return CredentialVerdict::Unavailable {
            retry_after_secs: None,
        };
    };
    let fingerprint = canonical.account.as_deref().map(|a| keyer.fingerprint(a));
    // `fp:` and the fingerprint's first eight hex characters, spelled on the stack.
    let mut principal_buf = *b"fp:00000000";
    let principal: &str = match fingerprint.as_deref() {
        None => "fp:none",
        Some(f) => {
            principal_buf[3..].copy_from_slice(&f.as_bytes()[..8]);
            std::str::from_utf8(&principal_buf).unwrap_or("fp:none")
        }
    };

    // Per source, this node.
    let source_ticket = match attempt.source {
        ClientSource::Known(ip) if policy.source.enabled => {
            let tightened = guard.tightened(&policy, now);
            match lock(&guard.sources).reserve(ip, &policy, tightened, now) {
                Ok(ticket) => Some(ticket),
                Err(node::SourceRefusal::Failures(b) | node::SourceRefusal::Submissions(b)) => {
                    let label = b.label();
                    let first = guard.audit(
                        "auth.login_throttled",
                        method,
                        &crate::cold::auth::login::source_principal(&label),
                        policy.source.failures.window_secs,
                        now,
                    );
                    if first {
                        diag_warn!(LOGIN_THROTTLED_SOURCE, method = %method, source = %label,
                            retry_after = retry_after_secs,
                            "credential sign-in throttled: the source spent its budget");
                    } else {
                        diag_debug!(LOGIN_THROTTLED_SOURCE, method = %method, source = %label,
                            "credential sign-in throttled: the source spent its budget");
                    }
                    crate::cold::auth::login::throttled_metric(method, "source");
                    return CredentialVerdict::Throttled { retry_after_secs };
                }
            }
        }
        _ => None,
    };
    let refund_source = |guard: &LoginGuard| {
        if let Some(t) = &source_ticket {
            lock(&guard.sources).refund(t);
        }
    };

    // Per account, fleet-wide.
    let account_limit = policy.account_for(method);
    let slot = match &fingerprint {
        None => None,
        Some(fp) => match account::reserve(store, fp, account_limit, store_now).await {
            Ok(account::Reserved::Held(ticket)) => {
                guard.store_answered();
                Some(ticket)
            }
            Ok(account::Reserved::Full) => {
                guard.store_answered();
                refund_source(guard);
                let first = guard.audit("auth.login_throttled", method, principal, window, now);
                if first {
                    diag_warn!(LOGIN_THROTTLED_ACCOUNT, method = %method, key = %principal,
                        retry_after = retry_after_secs,
                        "credential sign-in throttled: the account's failure ceiling is reached; \
                         the login plugin was not called");
                } else {
                    diag_debug!(LOGIN_THROTTLED_ACCOUNT, method = %method, key = %principal,
                        "credential sign-in throttled: the account's failure ceiling is reached");
                }
                if lock(&guard.sustained).throttled(fp, window, now) {
                    diag_warn!(LOGIN_ACCOUNT_THROTTLE_SUSTAINED, method = %method, key = %principal,
                        windows = node::SUSTAINED_WINDOWS,
                        "an account has been throttled for more than {} consecutive windows: a \
                         targeted account", node::SUSTAINED_WINDOWS);
                }
                crate::cold::auth::login::throttled_metric(method, "account");
                return CredentialVerdict::Throttled { retry_after_secs };
            }
            Err(account::StoreUnavailable) => {
                refund_source(guard);
                guard.store_failed("reserve");
                return CredentialVerdict::Unavailable {
                    retry_after_secs: None,
                };
            }
        },
    };

    let (judged, hint) = cx
        .door
        .complete(method, attempt.state, canonical.forwarded)
        .await;

    match judged {
        LoginJudged::NotRun => {
            refund_source(guard);
            if let Some(t) = &slot {
                if account::refund(store, t).await.is_err() {
                    guard.store_failed("refund");
                }
            }
            CredentialVerdict::Unavailable {
                retry_after_secs: None,
            }
        }
        LoginJudged::Plugin(LoginOutcome::Identify(principal_id)) => {
            refund_source(guard);
            if let Some(fp) = &fingerprint {
                if account::clear(store, fp, account_limit).await.is_err() {
                    guard.store_failed("clear");
                }
            }
            guard.audit("auth.login_succeeded", method, principal, window, now);
            CredentialVerdict::Identified(principal_id)
        }
        LoginJudged::Plugin(LoginOutcome::Reject) | LoginJudged::Faulted => {
            guard.global_failure(&policy, method, now);
            guard.audit("auth.login_failed", method, principal, window, now);
            if let (Some(h), Some(fp)) = (hint, &fingerprint) {
                let widest = policy
                    .per_method
                    .values()
                    .copied()
                    .chain([policy.account, account_limit])
                    .max_by_key(|l| l.max)
                    .unwrap_or(account_limit);
                let held = Limit {
                    max: widest.max,
                    window_secs: account_limit.window_secs,
                };
                if account::saturate(store, fp, held, store_now).await.is_err() {
                    guard.store_failed("saturate");
                }
                let action = match h {
                    RejectHint::AccountLocked => "auth.login_account_locked",
                    RejectHint::Throttled => "auth.login_plugin_throttled",
                };
                (guard.sink)(
                    action,
                    method,
                    crate::audit_ring::OUTCOME_REJECTED,
                    principal,
                );
            }
            CredentialVerdict::Declined
        }
        LoginJudged::Plugin(LoginOutcome::Outage { retry_after_secs }) => {
            let opened = {
                let mut breakers = lock(&guard.breakers);
                if !breakers.contains_key(method) {
                    breakers.insert(
                        crate::cold::auth::login::owned_name(method),
                        node::Breaker::default(),
                    );
                }
                breakers.get_mut(method).is_some_and(|b| b.outage(now))
            };
            if opened {
                diag_warn!(LOGIN_PROVIDER_BREAKER_OPEN, method = %method,
                    outages = node::BREAKER_OUTAGES, open_secs = node::BREAKER_OPEN_SECS,
                    "a credential method's identity provider failed repeatedly; sign-ins to it are \
                     answered 503 for {}s without calling it", node::BREAKER_OPEN_SECS);
            }
            CredentialVerdict::Outage { retry_after_secs }
        }
        LoginJudged::Plugin(_) => CredentialVerdict::Unfinished,
    }
}

use policy::Limit;

/// The running app's plugin door.
struct AppDoor<'a>(&'a crate::state::App);

impl CredentialDoor for AppDoor<'_> {
    fn declared_form<'a>(&'a self, method: &'a str) -> DoorFuture<'a, Option<LoginForm>> {
        Box::pin(crate::auth::login::declared_login_form(self.0, method))
    }

    fn complete<'a>(
        &'a self,
        method: &'a str,
        state: String,
        submitted: Vec<(String, String)>,
    ) -> DoorFuture<'a, (LoginJudged, Option<RejectHint>)> {
        let request = busbar_contract::auth_calls::LoginCallback {
            state,
            nonce: None,
            login: busbar_contract::auth::CompleteLogin {
                submitted: submitted
                    .into_iter()
                    .map(|(k, v)| (k, busbar_contract::redacted::Secret::new(v)))
                    .collect(),
                ..Default::default()
            },
        };
        Box::pin(crate::auth::login::login_step_judged(
            self.0,
            method,
            crate::auth::login::LoginStep::Complete(request),
        ))
    }
}

/// Judge and run one credential submission against the running app.
pub async fn credential_attempt(
    app: &crate::state::App,
    attempt: CredentialAttempt,
) -> CredentialVerdict {
    let gov = app.governance.as_deref();
    let door = AppDoor(app);
    judge(
        Context {
            guard: &app.login_guard,
            store: gov.and_then(|g| g.core_store().ok()),
            keyer: gov.and_then(|g| g.login_account_keyer()),
            door: &door,
            now: crate::store::now(),
        },
        attempt,
    )
    .await
}

/// The login-state cookie's MAC key: derived from the signing key, or (no signing key: such a
/// deployment cannot issue keys) one random key per process.
#[must_use]
pub fn state_key(app: &crate::state::App) -> Arc<key::StateKey> {
    static PROCESS: std::sync::LazyLock<Arc<key::StateKey>> = std::sync::LazyLock::new(|| {
        let mut material = [0u8; 32];
        busbar_contract::crypto::fill(&mut material)
            .expect("OS randomness for the login-state key");
        Arc::new(key::StateKey::derive(&material))
    });
    app.governance
        .as_deref()
        .and_then(|g| g.login_state_key())
        .map_or_else(|| PROCESS.clone(), Arc::new)
}

/// The claims owner and kind of single-use login states.
const STATE_OWNER: &str = "busbar.login-state";
const STATE_KIND: &str = "state-v1";

/// What claiming a login state answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateClaim {
    /// First use.
    Fresh,
    /// Already used: a replayed cookie.
    Replayed,
    /// The core store could not say (fail closed).
    Unavailable,
}

/// Make a login state single-use: the first completion of it wins, until `expires_at`.
pub async fn claim_login_state(
    app: &crate::state::App,
    state: &str,
    expires_at: u64,
) -> StateClaim {
    let Some(store) = app.governance.as_deref().and_then(|g| g.core_store().ok()) else {
        app.login_guard.store_failed("claim login state");
        return StateClaim::Unavailable;
    };
    claim_state_in(&app.login_guard, store, state, expires_at).await
}

pub(crate) async fn claim_state_in(
    guard: &LoginGuard,
    store: &CoreStore,
    state: &str,
    expires_at: u64,
) -> StateClaim {
    let _ = store.register_claim_scope(STATE_OWNER, STATE_KIND);
    let mut attempt = [0u8; 16];
    if busbar_contract::crypto::fill(&mut attempt).is_err() {
        return StateClaim::Unavailable;
    }
    // A distinct attempt per completion: two concurrent replays of one cookie are two attempts,
    // and exactly one of them wins.
    match crate::persistence::claims::Claims::authorized(store, STATE_OWNER, STATE_KIND)
        .redeem_as(state, expires_at, &attempt)
        .await
    {
        Ok(crate::persistence::claims::Outcome::Claimed) => {
            guard.store_answered();
            StateClaim::Fresh
        }
        Ok(
            crate::persistence::claims::Outcome::AlreadyClaimed
            | crate::persistence::claims::Outcome::Expired,
        ) => {
            guard.store_answered();
            StateClaim::Replayed
        }
        Ok(_) | Err(_) => {
            guard.store_failed("claim login state");
            StateClaim::Unavailable
        }
    }
}

#[cfg(test)]
#[path = "../tests/login_limits_tests.rs"]
mod tests;
