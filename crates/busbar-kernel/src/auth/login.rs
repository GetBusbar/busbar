// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE LOGIN METHODS the hosted browser login reads (row 159, K3#2): the identity side of it, which
//! stays the kernel's. Each `identity-providers:` entry's login-capable auth plugin, opened through
//! the build's auth axis on boot and reload ([`LoginMethods`]); one login step on its door, under
//! the anonymous-flood budget ([`login_step`]); and the self-serve key a verified identity is
//! issued through the shared mint seam ([`issue_self_key`]).
//!
//! The HOSTED LOGIN FLOW itself (the `GET /auth/token` chooser, begin and callback, the PKCE,
//! state and nonce minting, the login cookie, the credential form and every page) is
//! `busbar-core-oauth2`'s (THE DESIGN §8: "the authorization server and the hosted login flow"). It
//! reaches the kernel through these functions and is reached through [`seam`]: the kernel mounts
//! the path and names no page, cookie or brand.

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

// ── login-method registry (App.login_methods) ───────────────────────────────────────────────────

/// One resolved hosted-login method (`identity-providers.<name>`): the login-capable plugin instance
/// the build's auth axis opened ON THE AUTH KIND'S DOOR (THE DESIGN 6.7; WIRE-AUTH (A)(3)), its
/// `begin_login`/`complete_login` submitted on the one dispatcher and awaited (no thread parked).
/// The plugin makes its own token exchange over its own declared need with the client secret the
/// host lent it at `open`, and binds the IdP's answer to the login's nonce itself; the core holds no
/// secret for it and runs no hop.
pub(crate) struct LoginMethod {
    pub(crate) module: Arc<dyn AuthCalls>,
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
pub(crate) struct LoginMethods {
    pub(crate) methods: IndexMap<String, LoginMethod>,
}

// ── the login budget (the anonymous-flood class) ─────────────────────────────────────────────────

/// The bound on CONCURRENT in-flight login-plugin steps, and a SEPARATE budget from the data-plane
/// auth chain's admission budget and the admin chain's: `/auth/token` is reachable ANONYMOUSLY (it is mounted on the data
/// router and the auth middleware bypasses that exact path — `auth/mod.rs`'s bypass list), so its
/// concurrency is attacker-chosen. Sharing a budget with the credential-verifying chain would let an
/// unauthenticated flood of logins deny auth to authenticated traffic. Smaller than the auth chain's
/// 64 for the same reason: a human login round-trip is not customer request volume.
const LOGIN_OFFLOAD_MAX_INFLIGHT: usize = 16;

/// How long a login request waits for a permit before giving up. A login that cannot even be
/// STARTED in this window is not going to complete, so it is answered rather than left hanging.
const LOGIN_OFFLOAD_WAIT: Duration = Duration::from_secs(5);

/// The permit pool for [`LOGIN_OFFLOAD_MAX_INFLIGHT`]. Process-wide (not per-`LoginMethods`) on
/// purpose — the resource being bounded is the process's ONE dispatcher the login steps are
/// submitted on, and a config reload swaps `App::login_methods` while in-flight steps from the
/// previous one still hold permits. Same construction as `auth::AUTH_OFFLOAD_PERMITS`.
static LOGIN_OFFLOAD_PERMITS: std::sync::LazyLock<tokio::sync::Semaphore> =
    std::sync::LazyLock::new(|| tokio::sync::Semaphore::new(LOGIN_OFFLOAD_MAX_INFLIGHT));

/// A slot in the login budget ([`LOGIN_OFFLOAD_PERMITS`]) for one login-plugin call, waited for at
/// most [`LOGIN_OFFLOAD_WAIT`]; `None` = none came free (the caller answers
/// [`LoginOutcome::Reject`]: the plugin never ran, so no identity was established).
async fn login_permit(
    method: &str,
    op: &'static str,
) -> Option<tokio::sync::SemaphorePermit<'static>> {
    // Warn-once transition latch: a saturated login budget persists per request until the wedged
    // plugin recovers, and this path is anonymously reachable, so warn on the TRANSITION into the
    // saturated state and hold subsequent rejections at debug. Reset when a permit is acquired again.
    static LOGIN_OFFLOAD_SATURATED_WARNED: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);
    match tokio::time::timeout(LOGIN_OFFLOAD_WAIT, LOGIN_OFFLOAD_PERMITS.acquire()).await {
        Ok(Ok(p)) => {
            LOGIN_OFFLOAD_SATURATED_WARNED.store(false, std::sync::atomic::Ordering::Relaxed);
            Some(p)
        }
        // Timed out waiting, or the semaphore was closed. Either way the plugin never ran, so no
        // identity was established — reject.
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

/// One login step for a door plugin: its `begin_login`, or its `complete_login`.
pub enum LoginStep {
    /// `begin_login`: the authorize URL, or the credential form.
    Begin(BeginLogin),
    /// `complete_login`: who, a declined login, an unreachable IdP, or a failed security check.
    Complete(LoginCallback),
}

/// SUBMIT `step` to the door plugin `calls`: a plain `fn`, because nothing here crosses into the
/// plugin on the caller's thread — the step is queued on the one dispatcher, the plugin runs it on
/// a dispatcher worker, and the answer is the future handed back ([`door_login_call`] awaits it).
fn submit_door(
    calls: &dyn AuthCalls,
    step: LoginStep,
) -> Box<dyn busbar_contract::auth_calls::LoginCall> {
    match step {
        LoginStep::Begin(request) => calls.begin_login(request),
        LoginStep::Complete(request) => calls.complete_login(request),
    }
}

/// ONE LOGIN STEP ON THE DOOR: submitted on the one dispatcher ([`submit_door`]) and its answer
/// awaited, so no thread is parked; it holds a slot of the anonymous-flood budget
/// ([`login_permit`]), released when the step answers. A step that answered no verdict
/// is [`LoginOutcome::Reject`] (the loader's door, fail-closed). A step the plugin FAULTED (a caught
/// panic, a malformed answer: [`busbar_contract::auth_calls::LoginCall::faulted`]) is a Reject too,
/// and says so as 1.5.5 said a panicked login plugin call ([`LOGIN_PLUGIN_PANICKED`]).
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
    if call.faulted() {
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
    /// The empty map (no hosted login) — the default for tests and configs with no `identity-providers:`.
    #[cfg(any(test, feature = "test-support"))]
    pub fn empty() -> Self {
        Self {
            methods: IndexMap::new(),
        }
    }

    /// Resolve every `identity-providers:` entry as a login-capable `kind: auth` plugin on the auth
    /// kind's door, opened through the build's auth axis over the validated `registry` — the same
    /// trust/load pipeline as the data-plane chain. SecretRef-typed module settings resolve before
    /// the config crosses the ABI; the `browser_login.client_secret` resolves and is lent to the
    /// plugin at `open`. A module no door answers is refused in the loader's words (a 1.5.5 JSON
    /// auth plugin does not load). FAIL-CLOSED: any unresolvable method aborts the boot/reload
    /// build. Runs inside `build_app_from_config`.
    pub(crate) fn build(
        cfg: &AuthCfg,
        registry: &Arc<dyn busbar_contract::plugin_rows::PluginRows>,
        secret_resolver: &crate::config::secret::SecretResolver,
    ) -> Result<Self, String> {
        Self::build_on(cfg, registry.as_ref(), secret_resolver, || {
            crate::preflight::auth_axis(registry.clone())
        })
    }

    /// [`Self::build`] over the auth axis `open_axis` answers (opened on first use).
    fn build_on(
        cfg: &AuthCfg,
        registry: &dyn busbar_contract::plugin_rows::PluginRows,
        secret_resolver: &crate::config::secret::SecretResolver,
        open_axis: impl Fn() -> Option<Arc<dyn busbar_contract::auth_calls::AuthAxis>>,
    ) -> Result<Self, String> {
        let mut methods = IndexMap::new();
        // The build's auth axis, opened on first use: every method's plugin opens there (the
        // chain's own rows, the same dispatcher and connection table).
        let mut axis: Option<Arc<dyn busbar_contract::auth_calls::AuthAxis>> = None;
        for (name, mc) in &cfg.methods {
            let mut resolved = crate::config::secret::resolve_settings(
                &mc.settings,
                &registry.secret_slots(&mc.module),
                &mc.module,
                secret_resolver,
                &busbar_contract::config_time::ConfigScope::config_time(),
            )
            .map_err(|e| format!("identity-providers.{name} settings: {e}"))?;
            // The OAuth `client_id` (the PUBLIC half) rides the module's settings so the module can
            // build the authorize URL + token-exchange with it. It is NOT a secret and is passed
            // through.
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
                    .insert(
                        // No auth axis at all: 1.5.5's words, never the registry's (they stay
                        // internal to the loader).
                        open_axis().ok_or_else(|| {
                            refused(format!("no `kind: auth` plugin answers to '{}'", mc.module))
                        })?,
                    )
                    .clone(),
            };
            // A module no door answers is refused in the registry's own words.
            if !axis.answers(&mc.module) {
                return Err(refused(super::auth_refusal(registry, &mc.module)));
            }
            // 1.5.5 PARITY (crates/busbar/src/auth/token.rs:221-227 and :244-246 at v1.5.5): the
            // public `client_id` rides the method's settings and the `issuer` is read off them to
            // pick the chooser button's brand, exactly as 1.5.5 read and wrote them.
            let issuer = mc
                .settings
                .get("issuer")
                .and_then(|v| v.as_str())
                .map(str::to_string);
            let has_button = mc.browser_login.is_some();
            // The confidential-client secret is the PLUGIN's to hold (THE DESIGN §6 item 7: "IdP
            // logins hold their own client secret"): it is lent at `open` as the Statement's
            // `client_secret` secret reference (the loader lifts each key the Statement names in
            // `secret_refs` out of the settings and hands it over as a secret blob), never kept
            // here, and the plugin makes its own token exchange with it.
            if let Some(sref) = mc
                .browser_login
                .as_ref()
                .and_then(|bl| bl.client_secret.as_ref())
            {
                // A plugin whose Statement names no `client_secret` slot would receive the secret
                // inline in its plain settings text, never as a secret blob. 1.5.5 never handed
                // the secret to a plugin at all (it held it core-side, token.rs:253-277 at
                // v1.5.5), so such a plugin is refused at build rather than lent it in the clear.
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
                // OWED (row 7): the client secret is lent inline, as a JSON string.
                resolved.map_mut().insert(
                    CLIENT_SECRET_SLOT.to_string(),
                    serde_json::Value::String(secret.expose(&crate::seal::lend()).clone()),
                );
            }
            // Opened by the provider definition's `module:` (the plugin), REGISTERED under the
            // provider NAME (the instance): two named providers may share one login plugin with
            // different issuers/clients.
            let opened = axis.open(&mc.module, &login_label(name), resolved.as_value());
            // The kernel's copy of the lent settings (the resolved client secret and every
            // resolved secret reference among them) is wiped the moment `open` answers, whatever
            // it answered (THE DESIGN §6 K2: "auth material is zeroised"): the holder overwrites
            // every string in it as it drops.
            drop(resolved);
            let calls = opened.map_err(&refused)?;
            // The plugin's login kind, as its tail states it (read without a `begin_login`).
            // A plugin whose tail states no login serves only the headless method; a
            // `browser_login` button needs one that logs in.
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
            // Per-kind rule: a Redirect (OAuth) method REQUIRES the confidential-client secret; a
            // Credential (LDAP/AD-bind) method must NOT carry one (it has nothing to hold).
            if let Some(bl) = &mc.browser_login {
                validate_browser_login_secret(login_kind, bl.client_secret.is_some())
                    .map_err(|e| format!("identity-providers.{name} browser_login: {e}"))?;
            }
            methods.insert(
                name.clone(),
                LoginMethod {
                    module: calls,
                    has_button,
                    issuer,
                    login_kind,
                },
            );
        }
        Ok(Self { methods })
    }
}

/// The settings key a login plugin's Statement names in `secret_refs` to be lent the resolved
/// `browser_login.client_secret` at `open`.
const CLIENT_SECRET_SLOT: &str = "client_secret";

/// Whether `module`'s Statement (as `registry` holds it) names `key` among its `secret_refs`: the
/// keys the loader lifts out of the settings and lends as secret blobs. A module the registry does
/// not resolve, or whose Statement does not read back, states none.
fn states_secret_slot(
    registry: &dyn busbar_contract::plugin_rows::PluginRows,
    module: &str,
    key: &str,
) -> bool {
    registry.secret_slots(module).iter().any(|k| k == key)
}

/// The host's instance label of a hosted-login method's plugin instance: the provider's name, set
/// apart from the same provider's chain instance (labels are unique per opened instance).
fn login_label(name: &str) -> String {
    format!("{name}#login")
}

// ── what the hosted login flow reads ─────────────────────────────────────────────────────────────

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

/// `app`'s hosted-login methods, in config order (the chooser's button order).
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

/// `app`'s hosted-login method `name`, if it has one.
#[must_use]
pub fn login_method(app: &App, name: &str) -> Option<LoginMethodView> {
    login_methods(app).into_iter().find(|m| m.name == name)
}

/// ONE LOGIN STEP of `app`'s method `method` on its plugin's door, under the anonymous-flood budget
/// ([`door_login_call`]). A method `app` does not hold answers [`LoginOutcome::Reject`]: no plugin
/// ran, so no identity was established.
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

/// THE SELF-SERVE KEY a hosted-login identity is issued, through the SAME admission and mint seam
/// the headless `POST /auth/token` uses ([`admit_self_mint`], [`issue_key`]): `principal`, verified
/// by `app`'s method `module`, admitted against the role bindings and the mint policy, its
/// `user:<sub>` leaf auto-provisioned, and its key minted (`refresh` rotates it). No second mint
/// path.
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
        granted_pools: pools,
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
    // Auto-provision the `user:<sub>` leaf under `team` (from the team's `child_default`) before the
    // mint, so the browser-issued key is usable immediately (no 429 MissingGroup).
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

/// Per-`login_kind` rule for a `browser_login` method's `client_secret`: a Redirect (OAuth-family,
/// confidential-client) method REQUIRES it; a Credential (LDAP/AD-bind) method must NOT set one (it
/// has no confidential-client secret to hold). Pure, so it is unit-tested without a plugin registry.
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

/// THE HOSTED LOGIN FLOW'S SEAM: the two handlers `busbar-core-oauth2` registers (its `install`),
/// so the kernel mounts `GET /auth/token` and routes a credential-form `POST /auth/token` without
/// naming the flow's crate, page, cookie or brand.
pub mod seam {
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::{Arc, OnceLock};

    use axum::body::Body;
    use axum::extract::State;
    use axum::http::{Request, StatusCode};
    use axum::response::{IntoResponse, Response};

    use crate::state::AppHandle;

    /// A boxed, sendable handler future.
    pub type Answer<T> = Pin<Box<dyn Future<Output = T> + Send>>;

    /// A credential-form answer: the flow's response, or the request handed back (boxed: it is the
    /// large arm) when the submission is not the flow's.
    pub type FormAnswer = Result<Response, Box<Request<Body>>>;

    /// The flow's `POST /auth/token` handler.
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

    static SEAM: OnceLock<LoginSeam> = OnceLock::new();

    /// Register the flow's handlers (the first registration stands).
    pub fn install(seam: LoginSeam) {
        let _ = SEAM.set(seam);
    }

    /// `GET /auth/token`: the registered flow's page; a build that registered none serves no
    /// hosted login there (404).
    pub(crate) async fn browser(
        State(handle): State<Arc<AppHandle>>,
        req: Request<Body>,
    ) -> Response {
        match SEAM.get() {
            Some(seam) => (seam.browser)(handle, req).await,
            None => StatusCode::NOT_FOUND.into_response(),
        }
    }

    /// A `POST /auth/token`: the flow's answer when it is the flow's, else the request back.
    pub(crate) async fn credential_form(handle: Arc<AppHandle>, req: Request<Body>) -> FormAnswer {
        match SEAM.get() {
            Some(seam) => (seam.credential_form)(handle, req).await,
            None => Err(Box::new(req)),
        }
    }
}

#[cfg(test)]
#[path = "tests/login_tests.rs"]
mod login_tests;
