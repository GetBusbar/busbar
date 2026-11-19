// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;
use std::time::Duration;

use indexmap::IndexMap;

use busbar_contract::auth::{BeginLogin, LoginOutcome, Principal};
use busbar_contract::auth_calls::{AuthCalls, LoginCallback};

use super::self_keys::{
    admit_identified_self_mint, issue_key, DeterministicEd25519Keys, ExchangeError,
    HandleProvisioner, SelfMint,
};
use crate::diagnostics::{diag_debug, diag_warn, LOGIN_OFFLOAD_SATURATED, LOGIN_PLUGIN_PANICKED};
use crate::state::{App, AppHandle};

/// One resolved hosted-login method (`identity-providers.<name>`): the login-capable plugin instance
/// the build's auth axis opened ON THE AUTH KIND'S DOOR (THE DESIGN 6.7; WIRE-AUTH (A)(3)), its
/// `begin_login`/`complete_login` submitted on the one dispatcher and awaited (no thread parked).
/// The plugin makes its own token exchange over its own declared need with the client secret the
/// host lent it at `open`, and binds the IdP's answer to the login's nonce itself; the core holds no
/// secret for it and runs no hop.
#[derive(Clone)]
pub(crate) struct LoginMethod {
    pub(crate) module: Arc<dyn AuthCalls>,
    /// `true` ⇒ this method has a `browser_login` block and renders a button (and accepts `begin`).
    pub(crate) has_button: bool,
    /// The plugin's redirect-vs-credential classification, as its tail states it, read ONCE at
    /// build. Read by `credential_submit` to gate the credential POST to `Credential` methods only
    /// (a redirect method never completes via the form POST).
    pub(crate) login_kind: busbar_contract::auth::LoginKind,
    /// The credential form this method last declared (`begin_login`'s `Prompt`), kept server-side
    /// so a submission is canonicalised against what the plugin asked for, never against what the
    /// browser (or a forged cookie) sent. Lives on this generation's method, so a reload or REFRESH
    /// drops it.
    pub(crate) form: Arc<std::sync::RwLock<Option<busbar_contract::auth::LoginForm>>>,
}

/// The resolved hosted-login map — insertion-ordered (config order = button order), keyed by the
/// method/module name. Built on boot AND reload in `build_app_from_config`.
#[derive(Clone)]
pub(crate) struct LoginMethods {
    pub(crate) methods: IndexMap<String, LoginMethod>,
}

const LOGIN_OFFLOAD_MAX_INFLIGHT: usize = 16;

const LOGIN_OFFLOAD_WAIT: Duration = Duration::from_secs(5);

static LOGIN_OFFLOAD_PERMITS: std::sync::LazyLock<tokio::sync::Semaphore> =
    std::sync::LazyLock::new(|| tokio::sync::Semaphore::new(LOGIN_OFFLOAD_MAX_INFLIGHT));

async fn login_permit(
    method: &str,
    op: &'static str,
) -> Option<tokio::sync::SemaphorePermit<'static>> {
    static LOGIN_OFFLOAD_SATURATED_WARNED: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);
    match tokio::time::timeout(LOGIN_OFFLOAD_WAIT, LOGIN_OFFLOAD_PERMITS.acquire()).await {
        Ok(Ok(p)) => {
            LOGIN_OFFLOAD_SATURATED_WARNED.store(false, std::sync::atomic::Ordering::Relaxed);
            Some(p)
        }

        _ => {
            if !LOGIN_OFFLOAD_SATURATED_WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
                diag_warn!(
                    LOGIN_OFFLOAD_SATURATED,
                    method = %method, op,
                    "login plugin offload could not be started within {LOGIN_OFFLOAD_WAIT:?} \
                     ({LOGIN_OFFLOAD_MAX_INFLIGHT} already in flight); a login plugin is not \
                     returning. Rejecting (fail-closed) rather than completing a login it never ran."
                );
            } else {
                diag_debug!(
                    LOGIN_OFFLOAD_SATURATED,
                    method = %method, op,
                    "login plugin offload could not be started within {LOGIN_OFFLOAD_WAIT:?} \
                     ({LOGIN_OFFLOAD_MAX_INFLIGHT} already in flight); a login plugin is not \
                     returning. Rejecting (fail-closed) rather than completing a login it never ran."
                );
            }
            None
        }
    }
}

pub enum LoginStep {
    Begin(BeginLogin),

    Complete(LoginCallback),
}

fn submit_door(
    calls: &dyn AuthCalls,
    step: LoginStep,
) -> Box<dyn busbar_contract::auth_calls::LoginCall> {
    match step {
        LoginStep::Begin(request) => calls.begin_login(request),
        LoginStep::Complete(request) => calls.complete_login(request),
    }
}

async fn door_login_call(
    method: &str,
    op: &'static str,
    calls: Arc<dyn AuthCalls>,
    step: LoginStep,
) -> LoginOutcome {
    match door_login_judged(method, op, calls, step).await.0 {
        LoginJudged::Plugin(outcome) => outcome,
        LoginJudged::NotRun | LoginJudged::Faulted => LoginOutcome::Reject,
    }
}

/// What one login step came to, as only the kernel can tell it: the plugin was NEVER ENTERED (no
/// offload permit inside the wait, or no such method), it FAULTED, or it answered. Callers that
/// only render pages fold the first two into `Reject`; the attempt limiter must not, because it
/// refunds an attempt the directory never judged and keeps one it may have.
#[derive(Debug, Clone, PartialEq)]
pub enum LoginJudged {
    /// Core knows the plugin was never entered.
    NotRun,
    /// The plugin broke its contract (a caught panic); its answer is discarded.
    Faulted,
    /// The plugin's own answer.
    Plugin(LoginOutcome),
}

async fn door_login_judged(
    method: &str,
    op: &'static str,
    calls: Arc<dyn AuthCalls>,
    step: LoginStep,
) -> (LoginJudged, Option<busbar_contract::auth_calls::RejectHint>) {
    let Some(permit) = login_permit(method, op).await else {
        return (LoginJudged::NotRun, None);
    };
    let mut call = submit_door(&*calls, step);
    let outcome = (&mut call).await;
    drop(permit);
    if call.faulted() {
        let _ = finish_door_login(method, op, true, outcome);
        return (LoginJudged::Faulted, None);
    }
    let hint = matches!(outcome, LoginOutcome::Reject)
        .then(|| call.reject_hint())
        .flatten();
    (LoginJudged::Plugin(outcome), hint)
}

fn finish_door_login(
    method: &str,
    op: &'static str,
    faulted: bool,
    outcome: LoginOutcome,
) -> LoginOutcome {
    if faulted {
        diag_warn!(LOGIN_PLUGIN_PANICKED, method = %method, op, error = "the login plugin faulted", "login plugin call panicked; rejecting (fail-closed)");
        return LoginOutcome::Reject;
    }
    outcome
}

impl std::fmt::Debug for LoginMethods {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoginMethods")
            .field("methods", &self.methods.keys())
            .finish()
    }
}

fn unregistered_browser_response() -> axum::response::Response {
    use axum::response::IntoResponse;
    axum::http::StatusCode::NOT_FOUND.into_response()
}

impl LoginMethods {
    #[cfg(any(test, feature = "test-support"))]
    pub fn empty() -> Self {
        Self {
            methods: IndexMap::new(),
        }
    }
}

/// One hosted-login method: its admitted presentation and login classification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginMethodView {
    /// The provider name (`identity-providers.<name>`).
    pub name: String,
    /// `true` = it has a `browser_login` block: a button, and a `begin`.
    pub has_button: bool,
    /// Provider-owned inert presentation from the current successful lifecycle generation.
    pub presentation: Option<busbar_contract::auth_calls::LoginPresentation>,
    /// Redirect or credential, as its tail states it.
    pub login_kind: busbar_contract::auth::LoginKind,
}

/// The configured hosted-login methods, in config (button) order, each read as it stands now.
pub fn login_methods(app: &App) -> impl Iterator<Item = LoginMethodView> + '_ {
    app.login_methods
        .methods
        .iter()
        .map(|(name, m)| LoginMethodView {
            name: name.clone(),
            has_button: m.has_button,
            presentation: m.module.login_presentation(),
            login_kind: m.login_kind,
        })
}

#[must_use]
pub fn login_method(app: &App, name: &str) -> Option<LoginMethodView> {
    app.login_methods
        .methods
        .get_key_value(name)
        .map(|(name, m)| LoginMethodView {
            name: name.clone(),
            has_button: m.has_button,
            presentation: m.module.login_presentation(),
            login_kind: m.login_kind,
        })
}
pub async fn login_step(app: &App, method: &str, step: LoginStep) -> LoginOutcome {
    let Some(calls) = app
        .login_methods
        .methods
        .get(method)
        .map(|m| m.module.clone())
    else {
        return LoginOutcome::Reject;
    };
    let op = match step {
        LoginStep::Begin(_) => "begin_login",
        LoginStep::Complete(_) => "complete_login",
    };
    door_login_call(method, op, calls, step).await
}

/// One login step, told apart as [`LoginJudged`], with the plugin's reject hint when it declined.
pub async fn login_step_judged(
    app: &App,
    method: &str,
    step: LoginStep,
) -> (LoginJudged, Option<busbar_contract::auth_calls::RejectHint>) {
    let Some(calls) = app
        .login_methods
        .methods
        .get(method)
        .map(|m| m.module.clone())
    else {
        return (LoginJudged::NotRun, None);
    };
    let op = match step {
        LoginStep::Begin(_) => "begin_login",
        LoginStep::Complete(_) => "complete_login",
    };
    door_login_judged(method, op, calls, step).await
}

/// Keep the credential form `method` just declared (its `begin_login` answered `Prompt`).
pub fn remember_login_form(app: &App, method: &str, form: &busbar_contract::auth::LoginForm) {
    if let Some(m) = app.login_methods.methods.get(method) {
        *m.form.write().unwrap_or_else(|e| e.into_inner()) = Some(form.clone());
    }
}

/// The credential form `method` declared, from this generation's cache or, on a miss, from one
/// `begin_login` (a forged-cookie submission may arrive before any page was rendered).
pub(crate) async fn declared_login_form(
    app: &App,
    method: &str,
) -> Option<busbar_contract::auth::LoginForm> {
    let cached = app
        .login_methods
        .methods
        .get(method)?
        .form
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    if cached.is_some() {
        return cached;
    }
    let random = |n: usize| {
        let mut buf = [0u8; 32];
        let buf = &mut buf[..n];
        busbar_contract::crypto::fill(buf).ok()?;
        Some(hex::encode(buf))
    };
    let begin = BeginLogin {
        redirect_uri: crate::cold::auth::login::token_redirect_uri(app.public_url.as_deref()),
        state: random(24)?,
        code_challenge: random(32)?,
        nonce: None,
        scopes: Vec::new(),
    };
    match login_step(app, method, LoginStep::Begin(begin)).await {
        LoginOutcome::Prompt(form) => {
            remember_login_form(app, method, &form);
            Some(form)
        }
        _ => None,
    }
}

/// What [`issue_self_key`] answered: the key, or why none was issued (each its own page).
#[derive(Debug)]
pub enum SelfKeyIssue {
    /// Issued: the subject, the group the key is bound to, and the key (shown once).
    Issued {
        /// The verified subject.
        subject: String,
        /// The group the key is bound to.
        group: String,
        /// The key's secret, shown once.
        secret: busbar_contract::redacted::Secret<String>,
    },
    /// The mint ceiling refused the key this identity would mint.
    OverCeiling,
    /// The identity holds no self-serve grant.
    NoGrant,
    /// No governance to issue from.
    NoGovernance,
    /// The subject's key is disabled, or another identity provider minted it.
    Unbound,
    /// The subject's self-serve key is on hold, and why.
    Held(crate::governance::SelfMintRefusal),
    /// The mint failed.
    Failed,
}

pub async fn issue_self_key(
    app: &App,
    handle: &Arc<AppHandle>,
    module: &str,
    principal: Principal,
    refresh: bool,
) -> SelfKeyIssue {
    let SelfMint {
        principal,
        team,
        granted_scopes: pools,
        ttl,
    } = match admit_identified_self_mint(
        module,
        &principal,
        &app.role_bindings,
        &app.mint_policy,
        app.self_key_ttl_secs,
    ) {
        Ok(v) => v,
        Err(ExchangeError::OverCeiling(_)) => return SelfKeyIssue::OverCeiling,
        Err(_) => return SelfKeyIssue::NoGrant,
    };
    let Some(gov) = app.governance.clone() else {
        return SelfKeyIssue::NoGovernance;
    };

    let provisioner = Arc::new(HandleProvisioner::new(handle.clone(), principal.id.clone()));
    let keys = DeterministicEd25519Keys::new(gov, module, team, pools, provisioner);
    match issue_key(&keys, principal, ttl, refresh).await {
        Ok(k) => SelfKeyIssue::Issued {
            subject: principal.id.clone(),
            group: k.group,
            secret: k.secret,
        },
        Err(ExchangeError::Unbound) => SelfKeyIssue::Unbound,
        Err(ExchangeError::Held(reason)) => SelfKeyIssue::Held(reason),
        Err(_) => SelfKeyIssue::Failed,
    }
}

pub mod seam {
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;

    use axum::body::Body;
    use axum::extract::State;
    use axum::http::Request;
    use axum::response::Response;

    use crate::state::AppHandle;

    pub type Answer<T> = Pin<Box<dyn Future<Output = T> + Send>>;

    pub type FormAnswer = Result<Response, Box<Request<Body>>>;

    pub type CredentialFormFn = fn(Arc<AppHandle>, Request<Body>) -> Answer<FormAnswer>;

    /// The flow's two handlers.
    #[derive(Clone, Copy)]
    pub struct LoginSeam {
        /// `GET /auth/token`: the hosted browser login page.
        pub browser: fn(Arc<AppHandle>, Request<Body>) -> Answer<Response>,
        /// A `POST /auth/token` the flow owns (a credential-form submission): its answer, or the
        /// request handed back untouched when it is not the flow's (the headless exchange then
        /// judges it).
        pub credential_form: CredentialFormFn,
    }

    pub fn install(seam: LoginSeam) {
        crate::oauth_as::seam::install_hosted_login(seam);
    }

    pub(crate) async fn browser(
        State(handle): State<Arc<AppHandle>>,
        req: Request<Body>,
    ) -> Response {
        match crate::oauth_as::seam::hosted_login() {
            Some(seam) => (seam.browser)(handle, req).await,
            None => super::unregistered_browser_response(),
        }
    }

    pub(crate) async fn credential_form(handle: Arc<AppHandle>, req: Request<Body>) -> FormAnswer {
        match crate::oauth_as::seam::hosted_login() {
            Some(seam) => (seam.credential_form)(handle, req).await,
            None => Err(Box::new(req)),
        }
    }
}

#[cfg(test)]
#[path = "tests/login_tests.rs"]
mod login_tests;

#[cfg(test)]
#[path = "tests/login_fault_tests.rs"]
mod login_fault_tests;
