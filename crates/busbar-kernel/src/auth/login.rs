// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;
use std::time::Duration;

use indexmap::IndexMap;

use busbar_contract::auth::{BeginLogin, LoginOutcome, Principal};
use busbar_contract::auth_calls::{AuthCalls, LoginCallback};

use super::self_keys::{
    admit_self_mint, issue_key, DeterministicEd25519Keys, ExchangeError, HandleProvisioner,
    SelfMint,
};
use super::ChainVerdict;
use crate::config::AuthCfg;
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
    pub(crate) inbound_style: Option<busbar_contract::auth_calls::InboundStyle>,
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

pub struct InboundAuthProvider {
    pub provider: String,

    pub module: String,

    pub calls: Arc<dyn AuthCalls>,

    pub points: busbar_contract::abi::auth::AuthPoints,
}

impl App {
    pub fn inbound_default_auth(&self, style: &str) -> Result<Option<InboundAuthProvider>, String> {
        self.login_methods.inbound_default_auth(style)
    }
}

impl LoginMethods {
    fn inbound_default_auth(&self, style: &str) -> Result<Option<InboundAuthProvider>, String> {
        // busbar:expect(bp::state_scan, reason = "config: a plane's inbound style resolves to its configured provider once, at config load")
        let Some(provider) = select_inbound_provider(
            style,
            self.methods.iter().filter_map(|(provider, method)| {
                Some((provider.as_str(), method.inbound_style.as_ref()?))
            }),
        )?
        else {
            return Ok(None);
        };
        let method = &self.methods[provider];
        let declared = method
            .inbound_style
            .as_ref()
            .expect("selected declared style");
        #[expect(
            clippy::disallowed_methods,
            reason = "config: a plane's inbound auth provider, resolved once at config load"
        )]
        let selected = InboundAuthProvider {
            provider: provider.to_string(),
            module: declared.module.clone(),
            calls: Arc::clone(&method.module),
            points: declared.points,
        };
        Ok(Some(selected))
    }
}

fn select_inbound_provider<'a>(
    style: &str,
    declarations: impl Iterator<Item = (&'a str, &'a busbar_contract::auth_calls::InboundStyle)>,
) -> Result<Option<&'a str>, String> {
    if style.is_empty() {
        return Ok(None);
    }
    let mut matching = declarations.filter_map(|(provider, declared)| {
        declared
            .names
            .iter()
            .any(|name| name == style)
            .then_some(provider)
    });
    let Some(provider) = matching.next() else {
        #[expect(
            clippy::disallowed_methods,
            reason = "config: an inbound auth style refusal at config load"
        )]
        return Err(format!(
            "inbound auth style '{style}' has no configured ordinary identity provider"
        ));
    };
    if let Some(other) = matching.next() {
        #[expect(
            clippy::disallowed_methods,
            reason = "config: an inbound auth style refusal at config load"
        )]
        return Err(format!(
            "inbound auth style '{style}' is ambiguous between identity providers '{provider}' and '{other}'"
        ));
    }
    if crate::config::is_builtin_identity_module(provider) {
        #[expect(
            clippy::disallowed_methods,
            reason = "config: an inbound auth style refusal at config load"
        )]
        return Err(format!(
            "inbound auth style '{style}' selects identity provider '{provider}', whose name is reserved for a configured host auth position"
        ));
    }
    Ok(Some(provider))
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

fn login_module_refusal(name: &str, module: &str, reason: &str) -> String {
    #[expect(
        clippy::disallowed_methods,
        reason = "config: an identity-provider refusal at config load"
    )]
    let refusal = format!(
        "identity-providers.{name} (module '{module}') could not be loaded as a `kind: auth` login plugin: {reason}"
    );
    refusal
}

fn missing_login_axis(name: &str, module: &str) -> String {
    #[expect(
        clippy::disallowed_methods,
        reason = "config: an identity-provider refusal at config load"
    )]
    let reason = format!("no `kind: auth` plugin answers to '{module}'");
    login_module_refusal(name, module, &reason)
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

    /// The hosted login methods over the build's shared `instances`: a provider the chain or
    /// admin_auth already opened is handed over, not opened again (WASTE-AUTH-SECRETS W1).
    pub(crate) fn build_on(
        cfg: &AuthCfg,
        registry: &dyn busbar_contract::plugin_rows::PluginRows,
        secret_resolver: &crate::config::secret::SecretResolver,
        instances: &mut super::instances::AuthInstances,
        open_axis: &dyn Fn() -> Option<Arc<dyn busbar_contract::auth_calls::AuthAxis>>,
    ) -> Result<Self, String> {
        let mut methods = IndexMap::new();

        let mut axis: Option<Arc<dyn busbar_contract::auth_calls::AuthAxis>> = None;
        for (name, mc) in &cfg.methods {
            #[expect(
                clippy::disallowed_methods,
                reason = "config: an identity-provider refusal at config load"
            )]
            let mut resolved = crate::config::secret::resolve_settings(
                &mc.settings,
                &registry.secret_slots(&mc.module),
                &registry.reference_slots(&mc.module),
                &mc.module,
                secret_resolver,
                &busbar_contract::config_time::ConfigScope::config_time(),
            )
            .map_err(|e| format!("identity-providers.{name} settings: {e}"))?;

            if let Some(bl) = &mc.browser_login {
                if let Some(cid) = &bl.client_id {
                    resolved.default_text("client_id", cid.clone());
                }
            }
            let refused = |e: String| login_module_refusal(name, &mc.module, &e);
            let axis = match &axis {
                Some(a) => a.clone(),
                None => axis
                    .insert(open_axis().ok_or_else(|| missing_login_axis(name, &mc.module))?)
                    .clone(),
            };

            if !axis.answers(&mc.module) {
                return Err(refused(super::auth_refusal(registry, &mc.module)));
            }

            let has_button = mc.browser_login.is_some();

            lend_browser_login_secret(
                name,
                &mc.module,
                mc.browser_login.as_ref(),
                &registry.secret_slots(&mc.module),
                secret_resolver,
                &mut resolved,
            )?;

            let reresolve = super::relender(&mc.settings, registry, &mc.module, secret_resolver)
                .map(|base| -> super::relend::Reresolve {
                    let (name, module, browser) =
                        (name.clone(), mc.module.clone(), mc.browser_login.clone());
                    let (slots, resolver) =
                        (registry.secret_slots(&mc.module), secret_resolver.clone());
                    Box::new(move || {
                        let mut resolved = base()?;
                        if let Some(cid) = browser.as_ref().and_then(|bl| bl.client_id.clone()) {
                            resolved.default_text("client_id", cid);
                        }
                        lend_browser_login_secret(
                            &name,
                            &module,
                            browser.as_ref(),
                            &slots,
                            &resolver,
                            &mut resolved,
                        )?;
                        Ok(resolved)
                    })
                });
            let opened =
                super::relend::open(&axis, &mc.module, &login_label(name), &resolved, reresolve);

            drop(resolved);
            let calls = opened.map_err(&refused)?;
            let inbound_style = axis.inbound_style(&mc.module);
            if inbound_style.as_ref().is_some_and(|style| {
                style.points != calls.inbound_points()
                    || calls.facts()
                        & (busbar_contract::abi::auth::FACT_OPERATOR
                            | busbar_contract::abi::auth::FACT_READS_CREDENTIALS)
                        != 0
            }) {
                return Err(refused(
                    "the opened verifier disagrees with its inbound style".into(),
                ));
            }

            let login_kind = match (calls.login_kind(), &mc.browser_login) {
                (Some(kind), _) => kind,
                (None, None) => busbar_contract::auth::LoginKind::Redirect,
                (None, Some(_)) => {
                    #[expect(
                        clippy::disallowed_methods,
                        reason = "config: an identity-provider refusal at config load"
                    )]
                    return Err(format!(
                        "identity-providers.{name} sets browser_login but its plugin serves \
                         no login; a hosted login button requires a login-capable auth plugin"
                    ));
                }
            };

            if let Some(bl) = &mc.browser_login {
                #[expect(
                    clippy::disallowed_methods,
                    reason = "config: an identity-provider refusal at config load"
                )]
                validate_browser_login_secret(login_kind, bl.client_secret.is_some())
                    .map_err(|e| format!("identity-providers.{name} browser_login: {e}"))?;
            }
            methods.insert(
                name.clone(),
                LoginMethod {
                    module: calls,
                    inbound_style,
                    has_button,
                    login_kind,
                    form: Arc::default(),
                },
            );
        }
        Ok(Self { methods })
    }
}

const CLIENT_SECRET_SLOT: &str = "client_secret";

pub(super) fn lend_browser_login_secret(
    name: &str,
    module: &str,
    browser: Option<&crate::config::BrowserLoginCfg>,
    secret_slots: &[String],
    secret_resolver: &crate::config::secret::SecretResolver,
    resolved: &mut busbar_contract::plugin_settings::ResolvedSettings,
) -> Result<(), String> {
    let Some(sref) = browser.and_then(|bl| bl.client_secret.as_ref()) else {
        return Ok(());
    };
    if !secret_slots.iter().any(|key| key == CLIENT_SECRET_SLOT) {
        #[expect(
            clippy::disallowed_methods,
            reason = "config: an identity-provider refusal at config load"
        )]
        return Err(format!(
            "identity-providers.{name} browser_login.client_secret: the login plugin \
             '{module}' states no `{CLIENT_SECRET_SLOT}` secret reference, so it cannot be \
             lent the client secret as a secret"
        ));
    }
    #[expect(
        clippy::disallowed_methods,
        reason = "config: an identity-provider refusal at config load"
    )]
    let secret = secret_resolver
        .resolve_string_at_config(
            sref,
            &busbar_contract::config_time::ConfigScope::config_time(),
        )
        .map_err(|e| format!("identity-providers.{name} browser_login.client_secret: {e}"))?;
    resolved.insert_secret(CLIENT_SECRET_SLOT, secret_slots, secret)
}

fn login_label(name: &str) -> String {
    #[expect(
        clippy::disallowed_methods,
        reason = "config: an identity provider's login label, named once at config load"
    )]
    let label = format!("{name}#login");
    label
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

#[must_use]
pub fn login_methods(app: &App) -> Vec<LoginMethodView> {
    #[expect(
        clippy::disallowed_methods,
        reason = "config: the login page lists the configured identity providers"
    )]
    let methods = app
        .login_methods
        .methods
        .iter()
        .map(|(name, m)| LoginMethodView {
            name: name.clone(),
            has_button: m.has_button,
            presentation: m.module.login_presentation(),
            login_kind: m.login_kind,
        })
        .collect();
    methods
}

#[must_use]
pub fn login_method(app: &App, name: &str) -> Option<LoginMethodView> {
    login_methods(app).into_iter().find(|m| m.name == name)
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
        let mut buf = vec![0u8; n];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut buf).ok()?;
        Some(hex::encode(buf))
    };
    let begin = BeginLogin {
        redirect_uri: format!("{}/auth/token", app.public_url.as_deref().unwrap_or("")),
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
    #[expect(
        clippy::disallowed_methods,
        reason = "config: a self-serve key is provisioned once per login, under its provider's name"
    )]
    let verdict = ChainVerdict::Identified {
        module: module.to_string(),
        principal,
        resolved: None,
    };
    let SelfMint {
        principal,
        team,
        granted_scopes: pools,
        ttl,
    } = match admit_self_mint(
        &verdict,
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
    let keys = DeterministicEd25519Keys::new(gov, module.to_string(), team, pools, provisioner);
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

pub(crate) fn validate_browser_login_secret(
    login_kind: busbar_contract::auth::LoginKind,
    has_secret: bool,
) -> Result<(), &'static str> {
    match (login_kind, has_secret) {
        (busbar_contract::auth::LoginKind::Redirect, false) => Err(
            "a redirect (OAuth) login method requires browser_login.client_secret (it is a \
             confidential client)",
        ),
        (busbar_contract::auth::LoginKind::Credential, true) => Err(
            "a credential login method must not set browser_login.client_secret (it has no \
             confidential-client secret to hold)",
        ),
        _ => Ok(()),
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
