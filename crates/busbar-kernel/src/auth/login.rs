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
    /// The OIDC issuer from the method's opaque settings, used only to infer a button icon/label.
    pub(crate) issuer: Option<String>,
    /// The plugin's redirect-vs-credential classification, as its tail states it, read ONCE at
    /// build. Read by `credential_submit` to gate the credential POST to `Credential` methods only
    /// (a redirect method never completes via the form POST).
    pub(crate) login_kind: busbar_contract::auth::LoginKind,
}

/// The resolved hosted-login map — insertion-ordered (config order = button order), keyed by the
/// method/module name. Built on boot AND reload in `build_app_from_config`.
#[derive(Clone)]
pub(crate) struct LoginMethods {
    pub(crate) methods: IndexMap<String, LoginMethod>,
}

#[cfg(any(test, feature = "test-support"))]
pub fn install_method(
    app: &mut App,
    name: &str,
    calls: Arc<dyn AuthCalls>,
    login_kind: busbar_contract::auth::LoginKind,
    has_button: bool,
) {
    Arc::make_mut(&mut app.login_methods).methods.insert(
        name.to_string(),
        LoginMethod {
            module: calls,
            inbound_style: None,
            has_button,
            issuer: None,
            login_kind,
        },
    );
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
        if style.is_empty() {
            return Ok(None);
        }
        let mut matching = self.methods.iter().filter_map(|(provider, method)| {
            let declared = method.inbound_style.as_ref()?;
            declared
                .names
                .iter()
                .any(|name| name == style)
                .then_some((provider, method, declared))
        });
        let Some((provider, method, declared)) = matching.next() else {
            return Err(format!(
                "inbound auth style '{style}' has no configured ordinary identity provider"
            ));
        };
        if let Some((other, _, _)) = matching.next() {
            return Err(format!(
                "inbound auth style '{style}' is ambiguous between identity providers '{provider}' and '{other}'"
            ));
        }
        if crate::config::is_builtin_identity_module(provider) {
            return Err(format!(
                "inbound auth style '{style}' selects identity provider '{provider}', whose name is reserved for a configured host auth position"
            ));
        }
        Ok(Some(InboundAuthProvider {
            provider: provider.clone(),
            module: declared.module.clone(),
            calls: Arc::clone(&method.module),
            points: declared.points,
        }))
    }
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
    let Some(permit) = login_permit(method, op).await else {
        return LoginOutcome::Reject;
    };
    let mut call = submit_door(&*calls, step);
    let outcome = (&mut call).await;
    drop(permit);
    finish_door_login(method, op, call.faulted(), outcome)
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
            .field("methods", &self.methods.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl LoginMethods {
    #[cfg(any(test, feature = "test-support"))]
    pub fn empty() -> Self {
        Self {
            methods: IndexMap::new(),
        }
    }

    pub(crate) fn build(
        cfg: &AuthCfg,
        registry: &Arc<dyn busbar_contract::plugin_rows::PluginRows>,
        secret_resolver: &crate::config::secret::SecretResolver,
    ) -> Result<Self, String> {
        Self::build_on(cfg, registry.as_ref(), secret_resolver, || {
            crate::preflight::auth_axis(registry.clone())
        })
    }

    fn build_on(
        cfg: &AuthCfg,
        registry: &dyn busbar_contract::plugin_rows::PluginRows,
        secret_resolver: &crate::config::secret::SecretResolver,
        open_axis: impl Fn() -> Option<Arc<dyn busbar_contract::auth_calls::AuthAxis>>,
    ) -> Result<Self, String> {
        let mut methods = IndexMap::new();

        let mut axis: Option<Arc<dyn busbar_contract::auth_calls::AuthAxis>> = None;
        for (name, mc) in &cfg.methods {
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
                    resolved
                        .map_mut()
                        .entry("client_id".to_string())
                        .or_insert_with(|| serde_json::Value::String(cid.clone()));
                }
            }
            let refused = |e: String| {
                format!(
                    "identity-providers.{name} (module '{}') could not be loaded as a \
                     `kind: auth` login plugin: {e}",
                    mc.module
                )
            };
            let axis = match &axis {
                Some(a) => a.clone(),
                None => axis
                    .insert(open_axis().ok_or_else(|| {
                        refused(format!("no `kind: auth` plugin answers to '{}'", mc.module))
                    })?)
                    .clone(),
            };

            if !axis.answers(&mc.module) {
                return Err(refused(super::auth_refusal(registry, &mc.module)));
            }

            let issuer = mc
                .settings
                .get("issuer")
                .and_then(|v| v.as_str())
                .map(str::to_string);
            let has_button = mc.browser_login.is_some();

            if let Some(sref) = mc
                .browser_login
                .as_ref()
                .and_then(|bl| bl.client_secret.as_ref())
            {
                if !states_secret_slot(registry, &mc.module, CLIENT_SECRET_SLOT) {
                    return Err(format!(
                        "identity-providers.{name} browser_login.client_secret: the login plugin \
                         '{}' states no `{CLIENT_SECRET_SLOT}` secret reference, so it cannot be \
                         lent the client secret as a secret",
                        mc.module
                    ));
                }
                let secret = secret_resolver
                    .resolve_string_at_config(
                        sref,
                        &busbar_contract::config_time::ConfigScope::config_time(),
                    )
                    .map_err(|e| {
                        format!("identity-providers.{name} browser_login.client_secret: {e}")
                    })?;

                resolved.map_mut().insert(
                    CLIENT_SECRET_SLOT.to_string(),
                    serde_json::Value::String(secret.expose(&crate::seal::lend()).clone()),
                );
            }

            let opened = axis.open(&mc.module, &login_label(name), resolved.as_value());

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
                    return Err(format!(
                        "identity-providers.{name} sets browser_login but its plugin serves \
                         no login; a hosted login button requires a login-capable auth plugin"
                    ))
                }
            };

            if let Some(bl) = &mc.browser_login {
                validate_browser_login_secret(login_kind, bl.client_secret.is_some())
                    .map_err(|e| format!("identity-providers.{name} browser_login: {e}"))?;
            }
            methods.insert(
                name.clone(),
                LoginMethod {
                    module: calls,
                    inbound_style,
                    has_button,
                    issuer,
                    login_kind,
                },
            );
        }
        Ok(Self { methods })
    }
}

const CLIENT_SECRET_SLOT: &str = "client_secret";

fn states_secret_slot(
    registry: &dyn busbar_contract::plugin_rows::PluginRows,
    module: &str,
    key: &str,
) -> bool {
    registry.secret_slots(module).iter().any(|k| k == key)
}

fn login_label(name: &str) -> String {
    format!("{name}#login")
}

/// One hosted-login method as the flow reads it: whether it renders a button, the issuer its
/// settings name (for the button's brand), and how its login starts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginMethodView {
    /// The provider name (`identity-providers.<name>`).
    pub name: String,
    /// `true` = it has a `browser_login` block: a button, and a `begin`.
    pub has_button: bool,
    /// The OIDC issuer its opaque settings name, if any.
    pub issuer: Option<String>,
    /// Redirect or credential, as its tail states it.
    pub login_kind: busbar_contract::auth::LoginKind,
}

#[must_use]
pub fn login_methods(app: &App) -> Vec<LoginMethodView> {
    app.login_methods
        .methods
        .iter()
        .map(|(name, m)| LoginMethodView {
            name: name.clone(),
            has_button: m.has_button,
            issuer: m.issuer.clone(),
            login_kind: m.login_kind,
        })
        .collect()
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
    use axum::http::{Request, StatusCode};
    use axum::response::{IntoResponse, Response};

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
            None => StatusCode::NOT_FOUND.into_response(),
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
