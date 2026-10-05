// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `GET /auth/token` — the HOSTED BROWSER LOGIN page (1.5.2).
//!
//! One param-less path, three sub-states read off the query string:
//! * **chooser** (no params): one button per `identity-providers:` entry that has a `browser_login` block,
//!   in config order. `base_url` (= `public_url`, verbatim, no `/v1`) is shown for BYOK.
//! * **begin** (`?method=<name>`): the CORE mints PKCE (`code_verifier`/`code_challenge` S256),
//!   `state`, and `nonce`, stores them in a hand-rolled HttpOnly+Secure+SameSite=Lax cookie, and
//!   302s to the IdP authorize URL the module's `begin_login` returned.
//! * **callback** (`?code=&state=`): the CORE validates `state` against the cookie BEFORE anything
//!   is asked of the plugin (CSRF), then hands the plugin ONE `complete_login` on the auth kind's
//!   door carrying the cookie's state and nonce — the plugin makes its own token exchange with the
//!   client secret it was lent at `open` and binds the IdP's answer to the nonce — and on `Identify`
//!   mints the caller's key through the SAME [`super::self_keys`] seam the headless `POST` uses (no
//!   second mint path). The cookie is cleared on completion.
//!
//! SECURITY: `state` is validated before identity is established; the `client_secret` is the
//! plugin's (lent at `open`, never in the cookie, never logged, never rendered); the login page
//! issues via the shared self-serve seam.

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::State;
use axum::http::{header, Request, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use base64::Engine as _;
use indexmap::IndexMap;

use busbar_contract::auth::{BeginLogin, CompleteLogin, LoginOutcome, Principal};
use busbar_contract::auth_calls::{AuthCalls, LoginCallback};

use super::self_keys::{issue_key, resolve_exchange, DeterministicEd25519Keys, HandleProvisioner};
use super::ChainVerdict;
use crate::config::AuthCfg;
use crate::diagnostics::{diag_debug, diag_warn, LOGIN_OFFLOAD_SATURATED};
use crate::state::{App, AppHandle};

/// The login-state cookie name. Scoped to `/auth/token` (Path), HttpOnly + Secure + SameSite=Lax.
const LOGIN_COOKIE: &str = "busbar_login";
/// The hidden CSRF field the credential form carries (matched against the cookie's `state`). Reserved:
/// it is stripped from the submitted map, so a plugin can never declare a field with this name.
const FORM_STATE_FIELD: &str = "__state";
/// Short cookie lifetime — a login round-trip is seconds-to-minutes; the cookie is single-purpose.
const LOGIN_COOKIE_MAX_AGE: u32 = 600;
/// The URL-safe, no-pad base64 engine used for PKCE and the cookie payload.
const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::URL_SAFE_NO_PAD;

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
/// auth chain's [`super::AUTH_OFFLOAD_MAX_INFLIGHT`] and the admin chain's
/// `ADMIN_OFFLOAD_MAX_INFLIGHT`: `/auth/token` is reachable ANONYMOUSLY (it is mounted on the data
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

/// One login step for a door plugin.
enum DoorStep {
    Begin(BeginLogin),
    Complete(LoginCallback),
}

/// SUBMIT `step` to the door plugin `calls`: a plain `fn`, because nothing here crosses into the
/// plugin on the caller's thread — the step is queued on the one dispatcher, the plugin runs it on
/// a dispatcher worker, and the answer is the future handed back ([`door_login_call`] awaits it).
fn submit_door(
    calls: &dyn AuthCalls,
    step: DoorStep,
) -> Box<dyn busbar_contract::auth_calls::LoginCall> {
    match step {
        DoorStep::Begin(request) => calls.begin_login(request),
        DoorStep::Complete(request) => calls.complete_login(request),
    }
}

/// ONE LOGIN STEP ON THE DOOR: submitted on the one dispatcher ([`submit_door`]) and its answer
/// awaited, so no thread is parked; it holds a slot of the anonymous-flood budget
/// ([`login_permit`]), released when the step answers. A step that answered no verdict
/// is [`LoginOutcome::Reject`] (the loader's door, fail-closed).
async fn door_login_call(
    method: &str,
    op: &'static str,
    calls: Arc<dyn AuthCalls>,
    step: DoorStep,
) -> LoginOutcome {
    let Some(permit) = login_permit(method, op).await else {
        return LoginOutcome::Reject;
    };
    let outcome = submit_door(&*calls, step).await;
    drop(permit);
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
        registry: &Arc<busbar_plugin_loader::PluginRegistry>,
        secret_resolver: &crate::config::secret::SecretResolver,
    ) -> Result<Self, String> {
        let mut methods = IndexMap::new();
        // The build's auth axis, opened on first use: every method's plugin opens there (the
        // chain's own rows, the same dispatcher and connection table).
        let mut axis: Option<Arc<dyn busbar_contract::auth_calls::AuthAxis>> = None;
        for (name, mc) in &cfg.methods {
            let mut resolved =
                crate::config::secret::resolve_settings(&mc.settings, secret_resolver)
                    .map_err(|e| format!("identity-providers.{name} settings: {e}"))?;
            // The OAuth `client_id` (the PUBLIC half) rides the module's settings so the module can
            // build the authorize URL + token-exchange with it. It is NOT a secret and is passed
            // through.
            if let Some(bl) = &mc.browser_login {
                if let Some(cid) = &bl.client_id {
                    resolved
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
                        crate::preflight::auth_axis(registry.clone()).ok_or_else(|| {
                            refused(super::auth_refusal(registry, &mc.module))
                        })?,
                    )
                    .clone(),
            };
            // A module no door answers is refused in the registry's own words.
            if !axis.answers(&mc.module) {
                return Err(refused(super::auth_refusal(registry, &mc.module)));
            }
            let issuer = mc
                .settings
                .get("issuer")
                .and_then(|v| v.as_str())
                .map(str::to_string);
            let has_button = mc.browser_login.is_some();
            // The confidential-client secret is the PLUGIN's to hold (THE DESIGN 6.7): it is lent
            // at `open` as the Statement's `client_secret` secret reference (the loader takes it
            // out of the settings), never kept here, and the plugin makes its own token exchange
            // with it.
            if let Some(sref) = mc
                .browser_login
                .as_ref()
                .and_then(|bl| bl.client_secret.as_ref())
            {
                let secret = secret_resolver.resolve_string(sref).map_err(|e| {
                    format!("identity-providers.{name} browser_login.client_secret: {e}")
                })?;
                resolved.insert(
                    "client_secret".to_string(),
                    serde_json::Value::String(secret),
                );
            }
            // Opened by the provider definition's `module:` (the plugin), REGISTERED under the
            // provider NAME (the instance): two named providers may share one login plugin with
            // different issuers/clients.
            let calls = axis
                .open(
                    &mc.module,
                    &login_label(name),
                    &serde_json::Value::Object(resolved),
                )
                .map_err(&refused)?;
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

/// The host's instance label of a hosted-login method's plugin instance: the provider's name, set
/// apart from the same provider's chain instance (labels are unique per opened instance).
fn login_label(name: &str) -> String {
    format!("{name}#login")
}

// ── the GET handler + its three sub-states ──────────────────────────────────────────────────────

/// `GET /auth/token`: the hosted browser-login page. Reads the query to pick chooser / begin /
/// callback. Mounted DATA-plane only; the auth middleware bypasses this exact path.
pub(crate) async fn browser(State(handle): State<Arc<AppHandle>>, req: Request<Body>) -> Response {
    let app = handle.load();
    // Extract everything needed from `req` UP FRONT (owned) — never hold `&Request<Body>` across an
    // `.await` (axum's `Body` is not `Sync`, so the handler future would not be `Send`).
    let params = parse_query(req.uri().query().unwrap_or(""));
    let cookie_raw = read_cookie(&req);
    drop(req);
    let get = |k: &str| params.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());

    // logout FIRST (`?logout=1`): the "Sign out" action from the key-issued page. Ends the browser
    // view and defensively clears the login cookie. Stateless — see `signed_out`.
    if get("logout").is_some() {
        return signed_out();
    }
    // callback next (`?code=` present) — the IdP always returns `code`+`state`.
    if let Some(code) = get("code") {
        return callback(&app, &handle, cookie_raw, code, get("state")).await;
    }
    match get("method") {
        // `?refresh=1` marks a ROTATE ("Refresh key"): the completing handler mints with refresh=true.
        Some(method) => begin(&app, &method, get("refresh").as_deref() == Some("1")).await,
        None => chooser(&app),
    }
}

/// The chooser: one button per method that has a `browser_login` block, in config order.
fn chooser(app: &App) -> Response {
    let base_url = app.public_url.as_deref().unwrap_or("");
    let buttons: Vec<(String, ProviderBrand)> = app
        .login_methods
        .methods
        .iter()
        .filter(|(_, m)| m.has_button)
        .map(|(name, m)| {
            (
                name.clone(),
                ProviderBrand::infer(name, m.issuer.as_deref()),
            )
        })
        .collect();
    html_no_store(render_chooser(&buttons, base_url))
}

/// begin: mint PKCE/state/nonce, call the module's `begin_login`, and either 302 to the IdP authorize
/// URL (REDIRECT flow) or render the credential FORM (CREDENTIAL flow). `refresh` marks a rotate.
async fn begin(app: &App, method: &str, refresh: bool) -> Response {
    let Some(calls) = app
        .login_methods
        .methods
        .get(method)
        .filter(|m| m.has_button)
        .map(|m| m.module.clone())
    else {
        // Unknown / headless-only method — nothing to begin in the browser.
        return error_page(
            StatusCode::NOT_FOUND,
            "Sign-in method not found",
            "That sign-in method isn't available here. Head back and choose one of the listed options.",
        );
    };
    let redirect_uri = format!("{}/auth/token", app.public_url.as_deref().unwrap_or(""));
    let code_verifier = random_b64url(32);
    let code_challenge = code_challenge_s256(&code_verifier);
    let state = random_b64url(24);
    let nonce = random_b64url(24);

    let begin = BeginLogin {
        redirect_uri,
        state: state.clone(),
        code_challenge,
        nonce: Some(nonce.clone()),
        scopes: Vec::new(),
    };
    // BOUNDED: this data-plane path is ANONYMOUSLY reachable, so the step holds a slot of the login
    // budget; it is submitted on the one dispatcher and awaited (no worker parked).
    let outcome = door_login_call(method, "begin_login", calls, DoorStep::Begin(begin)).await;
    match outcome {
        // REDIRECT (OAuth) flow: 302 to the IdP; the callback (a GET) completes it.
        LoginOutcome::Authorize(url) => {
            // The `Location` value is the PLUGIN's, not ours — the one plugin-authored header on
            // this path. `HeaderValue` refuses
            // CR, LF and NUL, so an authorize URL carrying a raw newline (a `login_hint`/
            // `domain_hint` a module interpolated without encoding it) is unrepresentable. Building
            // it with `expect` treated it as static and turned that plugin bug into a panic on an
            // ANONYMOUSLY-reachable path, with no catch-panic layer anywhere in the tree — the
            // request task dies and the connection is aborted with no response at all. Convert it
            // fallibly instead and fall into the SAME fail-closed "misbehaving module" answer the
            // match's last arm gives, which is what an unusable authorize URL is.
            let Ok(location) = header::HeaderValue::try_from(url) else {
                return error_page(
                    StatusCode::BAD_GATEWAY,
                    "Sign-in unavailable",
                    "This sign-in method couldn't be started right now. Please try again in a moment.",
                );
            };
            let cookie = LoginCookie {
                method: method.to_string(),
                code_verifier,
                state,
                nonce,
                refresh,
            }
            .encode();
            let mut resp = Response::builder()
                .status(StatusCode::FOUND)
                .header(header::LOCATION, location)
                .header(header::CACHE_CONTROL, "no-store")
                .body(Body::empty())
                .expect("302 with a pre-validated Location");
            resp.headers_mut().append(
                header::SET_COOKIE,
                set_cookie(&cookie).parse().expect("cookie"),
            );
            resp
        }
        // CREDENTIAL flow: render the declared form; the browser POSTs the field values back to
        // /auth/token (with this cookie for CSRF), where `credential_submit` completes it. No PKCE /
        // nonce is used (there is no IdP round-trip) — only `state` binds the form to this cookie.
        LoginOutcome::Prompt(form) => {
            let cookie = LoginCookie {
                method: method.to_string(),
                code_verifier: String::new(),
                state: state.clone(),
                nonce: String::new(),
                refresh,
            }
            .encode();
            let base_url = app.public_url.as_deref().unwrap_or("");
            let page = render_login_form(method, &form, &state, base_url, refresh);
            let mut resp = html_no_store(page);
            resp.headers_mut().append(
                header::SET_COOKIE,
                set_cookie(&cookie).parse().expect("cookie"),
            );
            resp
        }
        // A verify-only / misbehaving module fails closed here.
        _ => error_page(
            StatusCode::BAD_GATEWAY,
            "Sign-in unavailable",
            "This sign-in method couldn't be started right now. Please try again in a moment.",
        ),
    }
}

/// callback: validate `state` vs the cookie (CSRF) BEFORE anything is asked of the plugin, hand the
/// door ONE `complete_login` carrying the cookie's state and nonce, then mint via the shared
/// self-serve seam.
async fn callback(
    app: &App,
    handle: &Arc<AppHandle>,
    cookie_raw: Option<String>,
    code: String,
    state: Option<String>,
) -> Response {
    // Parse the cookie; absent ⇒ 400 (no login in flight).
    let Some(cookie) = cookie_raw.and_then(|raw| LoginCookie::decode(&raw)) else {
        return error_page(
            StatusCode::BAD_REQUEST,
            "Sign-in session expired",
            "Your sign-in session expired or was already used. Head back and start again.",
        );
    };
    // CSRF: the returned `state` MUST equal the cookie's, checked BEFORE any token exchange. Compared
    // in constant time (the state is anti-CSRF secret material minted per login).
    let state_ok = state
        .as_deref()
        .map(|s| busbar_contract::redacted::constant_time_eq(s, &cookie.state))
        .unwrap_or(false);
    if !state_ok {
        return clear_and(security_check_failed());
    }
    let Some(m) = app
        .login_methods
        .methods
        .get(&cookie.method)
        .filter(|m| m.has_button)
    else {
        return clear_and(error_page(
            StatusCode::BAD_REQUEST,
            "Sign-in method not found",
            "That sign-in method is no longer available. Head back and choose one of the listed \
             options.",
        ));
    };
    let redirect_uri = format!("{}/auth/token", app.public_url.as_deref().unwrap_or(""));

    // ON THE DOOR: ONE `complete_login`. The plugin redeems the code at its token endpoint itself
    // (its own need, its own lent client secret) and binds the IdP's identity token to the nonce
    // the core minted at `begin` (carried in the cookie, handed over here): it answers who, a
    // declined login, an unreachable IdP, or a failed security check.
    let request = LoginCallback {
        state: cookie.state.clone(),
        nonce: Some(cookie.nonce.clone()),
        login: CompleteLogin {
            code: Some(code),
            redirect_uri: Some(redirect_uri),
            code_verifier: Some(cookie.code_verifier.clone()),
            ..Default::default()
        },
    };
    let principal = match door_login_call(
        &cookie.method,
        "complete_login",
        m.module.clone(),
        DoorStep::Complete(request),
    )
    .await
    {
        LoginOutcome::Identify(p) => p,
        LoginOutcome::Outage => return clear_and(provider_unreachable()),
        // The IdP's answer failed the login's security check: 1.5.5's verification page, the one
        // the state mismatch renders.
        LoginOutcome::SecurityCheckFailed => return clear_and(security_check_failed()),
        LoginOutcome::Reject => {
            return clear_and(error_page(
                StatusCode::UNAUTHORIZED,
                "Sign-in was declined",
                "Your identity provider declined this sign-in. Check with your Busbar admin if \
                 this keeps happening.",
            ));
        }
        // A module must not (re)authorize or (re)prompt on the callback path — fail closed.
        LoginOutcome::Authorize(_) | LoginOutcome::Prompt(_) | LoginOutcome::Exchange(_) => {
            return clear_and(error_page(
                StatusCode::BAD_GATEWAY,
                "Sign-in unavailable",
                "Something went wrong completing this sign-in. Please head back and try again.",
            ));
        }
    };

    // Feed the verified identity through the SAME admission + mint seam as the headless POST and the
    // credential flow (`issue_and_render`), then CLEAR the single-use cookie. No second mint path.
    clear_and(issue_and_render(app, handle, &cookie.method, principal, cookie.refresh).await)
}

/// The SHARED identify→admit→mint→render tail used by BOTH the redirect callback and the credential
/// POST (`credential_submit`): builds the `Identified` verdict, runs `resolve_exchange`, and mints via
/// the ONE `issue_key` seam (`refresh` rotates — the "Refresh key" action). Returns the key-issued
/// page or a typed refusal; it NEVER clears the cookie (the caller wraps the result in `clear_and`).
async fn issue_and_render(
    app: &App,
    handle: &Arc<AppHandle>,
    module_name: &str,
    principal: Principal,
    refresh: bool,
) -> Response {
    let verdict = ChainVerdict::Identified {
        module: module_name.to_string(),
        principal,
        resolved: None,
    };
    let (principal, team, pools) =
        match resolve_exchange(&verdict, &app.role_bindings, app.mint_policy.self_mint) {
            Ok(v) => v,
            Err(_) => return error_page(
                StatusCode::FORBIDDEN,
                "No access yet",
                "Your account isn't granted a self-serve key yet. Ask your Busbar admin to assign \
                 you a role.",
            ),
        };
    let Some(gov) = app.governance.clone() else {
        return error_page(
            StatusCode::BAD_GATEWAY,
            "Key issuing unavailable",
            "Busbar can't issue keys right now. Please contact your Busbar admin.",
        );
    };
    let ttl = Duration::from_secs(app.self_key_ttl_secs);
    // Auto-provision the `user:<sub>` leaf under `team` (from the team's `child_default`) before the
    // mint, so the browser-issued key is usable immediately (no 429 MissingGroup).
    let provisioner = Arc::new(HandleProvisioner::new(handle.clone(), principal.id.clone()));
    let keys = DeterministicEd25519Keys::new(gov, team, pools, provisioner);
    let issued =
        match issue_key(&keys, principal, ttl, refresh).await {
            Ok(k) => k,
            Err(_) => return error_page(
                StatusCode::BAD_GATEWAY,
                "Couldn't issue your key",
                "We couldn't issue your key this time. Please head back and try again in a moment.",
            ),
        };
    let base_url = app.public_url.as_deref().unwrap_or("");
    let page = render_key_issued(
        &principal.id,
        &issued.group,
        // `.expose_secret()`: the once-shown "key issued" page is the intended plaintext egress.
        issued.secret.expose_secret(),
        base_url,
        module_name,
    );
    html_no_store(page)
}

/// `credential_submit`: complete a CREDENTIAL-flow login. Called by the POST `/auth/token` handler
/// (`exchange`) when a login cookie is present. Validates CSRF (`__state` vs the cookie), builds
/// [`CompleteLogin`] from the submitted field values (each [`busbar_contract::redacted::Redacted`]), runs the
/// module's `complete_login` (the plugin verifies the credential itself, e.g. an LDAP bind), and — on
/// `Identify` — issues through the SAME `issue_and_render` seam. Redirect methods never reach here.
pub(crate) async fn credential_submit(
    app: &App,
    handle: &Arc<AppHandle>,
    cookie_raw: String,
    form: Vec<(String, String)>,
) -> Response {
    let Some(cookie) = LoginCookie::decode(&cookie_raw) else {
        return clear_and(error_page(
            StatusCode::BAD_REQUEST,
            "Sign-in session expired",
            "Your sign-in session expired or was already used. Head back and start again.",
        ));
    };
    // CSRF: the form's `__state` must equal the cookie's (constant-time).
    let submitted_state = form
        .iter()
        .find(|(k, _)| k == FORM_STATE_FIELD)
        .map(|(_, v)| v.as_str())
        .unwrap_or("");
    if !busbar_contract::redacted::constant_time_eq(submitted_state, &cookie.state) {
        return clear_and(security_check_failed());
    }
    let Some(m) = app
        .login_methods
        .methods
        .get(&cookie.method)
        .filter(|m| m.has_button)
    else {
        return clear_and(error_page(
            StatusCode::BAD_REQUEST,
            "Sign-in method not found",
            "That sign-in method is no longer available. Head back and choose one of the listed \
             options.",
        ));
    };
    // Only a Credential method may complete via the form POST.
    if m.login_kind != busbar_contract::auth::LoginKind::Credential {
        return clear_and(error_page(
            StatusCode::BAD_REQUEST,
            "Sign-in unavailable",
            "This sign-in method can't be completed here. Please head back and start again.",
        ));
    }
    // Build the submitted map (every field EXCEPT the CSRF token), Redacted the moment it is held.
    let submitted: Vec<(String, busbar_contract::redacted::Redacted<String>)> = form
        .into_iter()
        .filter(|(k, _)| k != FORM_STATE_FIELD)
        .map(|(k, v)| (k, busbar_contract::redacted::Redacted::new(v)))
        .collect();
    let cl = CompleteLogin {
        submitted,
        ..Default::default()
    };
    // A credential module verifies the credential itself (e.g. an LDAP bind) over its own need and
    // returns `Identify`. BOUNDED: this POST is anonymously reachable (the `__state` check is
    // satisfied by a cookie the caller minted for themselves via `begin`), so the step holds a slot
    // of the login budget; it is submitted on the one dispatcher and awaited (no worker parked).
    let request = LoginCallback {
        state: cookie.state.clone(),
        nonce: None,
        login: cl,
    };
    let outcome = door_login_call(
        &cookie.method,
        "complete_login",
        m.module.clone(),
        DoorStep::Complete(request),
    )
    .await;
    let principal = match outcome {
        LoginOutcome::Identify(p) => p,
        LoginOutcome::Outage => return clear_and(provider_unreachable()),
        LoginOutcome::Reject => {
            return clear_and(error_page(
                StatusCode::UNAUTHORIZED,
                "Sign-in was declined",
                "Those credentials weren't accepted. Please check them and try again.",
            ))
        }
        _ => {
            return clear_and(error_page(
                StatusCode::BAD_GATEWAY,
                "Sign-in didn't finish",
                "This sign-in didn't complete. Please head back and try again.",
            ))
        }
    };
    clear_and(issue_and_render(app, handle, &cookie.method, principal, cookie.refresh).await)
}

// ── the login cookie (hand-rolled, HttpOnly+Secure+SameSite=Lax) ─────────────────────────────────

#[derive(serde::Serialize, serde::Deserialize)]
struct LoginCookie {
    method: String,
    code_verifier: String,
    state: String,
    nonce: String,
    /// `true` when this login was started as a ROTATE ("Refresh key") — the completing handler mints
    /// with `refresh=true` so the prior token is revoked and a new one issued. `#[serde(default)]`
    /// keeps older cookies decoding.
    #[serde(default)]
    refresh: bool,
}

impl LoginCookie {
    fn encode(&self) -> String {
        B64.encode(serde_json::to_vec(self).expect("serialize login cookie"))
    }
    fn decode(raw: &str) -> Option<Self> {
        let bytes = B64.decode(raw).ok()?;
        serde_json::from_slice(&bytes).ok()
    }
}

/// The `Set-Cookie` value for a begin: HttpOnly + Secure + SameSite=Lax, scoped to `/auth/token`.
fn set_cookie(value: &str) -> String {
    format!(
        "{LOGIN_COOKIE}={value}; HttpOnly; Secure; SameSite=Lax; Path=/auth/token; Max-Age={LOGIN_COOKIE_MAX_AGE}"
    )
}
/// The `Set-Cookie` value that CLEARS the login cookie (Max-Age=0).
fn clear_cookie() -> String {
    format!("{LOGIN_COOKIE}=; HttpOnly; Secure; SameSite=Lax; Path=/auth/token; Max-Age=0")
}

/// Read the login cookie's raw value from the request `Cookie` header. Exposed so the POST handler
/// (`exchange`) can detect a credential-form submission (login cookie present) and route it here.
pub(crate) fn read_login_cookie(req: &Request<Body>) -> Option<String> {
    read_cookie(req)
}

/// Read the login cookie's raw value from the request `Cookie` header.
fn read_cookie(req: &Request<Body>) -> Option<String> {
    let raw = req.headers().get(header::COOKIE)?.to_str().ok()?;
    for part in raw.split(';') {
        let part = part.trim();
        if let Some(v) = part.strip_prefix(&format!("{LOGIN_COOKIE}=")) {
            return Some(v.to_string());
        }
    }
    None
}

/// Attach a cookie-clearing `Set-Cookie` to an existing response (used on every callback exit so a
/// failed/completed login never leaves the single-use cookie behind).
fn clear_and(mut resp: Response) -> Response {
    resp.headers_mut()
        .append(header::SET_COOKIE, clear_cookie().parse().expect("cookie"));
    resp
}

// ── browser_login configuration ───────────────────────────────────────────────────────────────────

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

// ── PKCE + randomness ────────────────────────────────────────────────────────────────────────────

/// A URL-safe, no-pad base64 string of `n_bytes` of OS randomness.
fn random_b64url(n_bytes: usize) -> String {
    let mut buf = vec![0u8; n_bytes];
    getrandom::fill(&mut buf).expect("OS randomness for PKCE/state/nonce");
    B64.encode(buf)
}

/// The PKCE S256 `code_challenge` = base64url(sha256(code_verifier)).
fn code_challenge_s256(code_verifier: &str) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, code_verifier.as_bytes());
    B64.encode(digest.as_ref())
}

// ── query parsing + response helpers ─────────────────────────────────────────────────────────────

/// Minimal `application/x-www-form-urlencoded` query parser (percent + `+` decoding). Sufficient for
/// the small, known param set (`method`/`code`/`state`).
fn parse_query(q: &str) -> Vec<(String, String)> {
    q.split('&')
        .filter(|s| !s.is_empty())
        .map(|pair| {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            (pct_decode(k), pct_decode(v))
        })
        .collect()
}

/// Parse an `application/x-www-form-urlencoded` BODY (same grammar as a query string) into ordered
/// key/value pairs. Used by the POST handler to read the credential form.
pub(crate) fn parse_form_urlencoded(body: &str) -> Vec<(String, String)> {
    parse_query(body)
}

/// Percent-decode a query component (`%XX` and `+` → space).
fn pct_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < bytes.len() => {
                let hi = (bytes[i + 1] as char).to_digit(16);
                let lo = (bytes[i + 2] as char).to_digit(16);
                match (hi, lo) {
                    (Some(h), Some(l)) => {
                        out.push((h * 16 + l) as u8);
                        i += 2;
                    }
                    _ => out.push(b'%'),
                }
            }
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn html_no_store(body: String) -> Response {
    ([(header::CACHE_CONTROL, "no-store")], Html(body)).into_response()
}

/// The shared branded error for a failed anti-CSRF / nonce check (a mismatched `state` on the
/// callback or credential POST, or a login plugin answering that the IdP's answer failed the
/// login's security check, [`LoginOutcome::SecurityCheckFailed`]). One copy for every "the security
/// check didn't match" case — honest without hinting at WHICH check failed. HTTP 400.
fn security_check_failed() -> Response {
    error_page(
        StatusCode::BAD_REQUEST,
        "Sign-in couldn't be verified",
        "We couldn't verify this sign-in (the security check didn't match). Please head back and \
         start again.",
    )
}

// ── rendering (the login HTML template, scaffolds stripped) ──────────────────────────────────────

/// The shared `<title>` + `<style>` head (`.note`/`.screen-label`
/// review scaffolds stripped). `include_str!` so the visual is the reviewed asset, not hand-retyped.
const HEAD: &str = include_str!("busbar-login.html");

/// The busbar glyph SVG (brand lockup), verbatim from the mockup.
const GLYPH: &str = r##"<svg viewBox="0 0 128 128" xmlns="http://www.w3.org/2000/svg" style="color:#A3E635" aria-hidden="true"><g transform="translate(64 64) scale(1.46) translate(-62 -64)"><g transform="translate(3 0)"><rect x="46" y="39" width="9" height="50" rx="4.5" fill="currentColor"/><g stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round"><line x1="36" y1="64" x2="41" y2="64" stroke-width="5"/><path d="M60 45 L79 45 Q87 45 87 55" stroke-width="5"/><line x1="60" y1="64" x2="72" y2="64" stroke-width="5"/><path d="M60 83 L79 83 Q87 83 87 73" stroke-width="5"/></g><g fill="currentColor"><circle cx="31" cy="64" r="4.6"/><circle cx="87" cy="55" r="4.6"/><circle cx="76" cy="64" r="4.6"/><circle cx="87" cy="73" r="4.6"/></g></g></g></svg>"##;

/// A known provider brand, inferred from the method/module name (and OIDC issuer host) — NOT from any
/// operator-set display string. Drives the button icon + "Continue with X" label.
enum ProviderBrand {
    Microsoft,
    GitHub,
    Google,
    Generic(String),
}

impl ProviderBrand {
    fn infer(name: &str, issuer: Option<&str>) -> Self {
        let hay = format!("{} {}", name, issuer.unwrap_or("")).to_ascii_lowercase();
        if [
            "microsoft",
            "entra",
            "azure",
            "msft",
            "aad",
            "login.microsoftonline",
        ]
        .iter()
        .any(|k| hay.contains(k))
        {
            ProviderBrand::Microsoft
        } else if hay.contains("github") {
            ProviderBrand::GitHub
        } else if hay.contains("google") || hay.contains("accounts.google") {
            ProviderBrand::Google
        } else {
            ProviderBrand::Generic(titlecase(name))
        }
    }
    fn label(&self) -> String {
        match self {
            ProviderBrand::Microsoft => "Microsoft".to_string(),
            ProviderBrand::GitHub => "GitHub".to_string(),
            ProviderBrand::Google => "Google".to_string(),
            ProviderBrand::Generic(n) => n.clone(),
        }
    }
    fn icon(&self) -> &'static str {
        match self {
            ProviderBrand::Microsoft => {
                r##"<svg class="picon" viewBox="0 0 21 21" aria-hidden="true"><rect x="1" y="1" width="9" height="9" fill="#f25022"/><rect x="11" y="1" width="9" height="9" fill="#7fba00"/><rect x="1" y="11" width="9" height="9" fill="#00a4ef"/><rect x="11" y="11" width="9" height="9" fill="#ffb900"/></svg>"##
            }
            ProviderBrand::GitHub => {
                r##"<svg class="picon" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0016 8c0-4.42-3.58-8-8-8z"/></svg>"##
            }
            ProviderBrand::Google => {
                r##"<svg class="picon" viewBox="0 0 18 18" aria-hidden="true"><path fill="#4285F4" d="M17.64 9.2c0-.64-.06-1.25-.16-1.84H9v3.48h4.84a4.14 4.14 0 01-1.8 2.72v2.26h2.92c1.7-1.57 2.68-3.88 2.68-6.62z"/><path fill="#34A853" d="M9 18c2.43 0 4.47-.8 5.96-2.18l-2.92-2.26c-.8.54-1.84.86-3.04.86-2.34 0-4.32-1.58-5.03-3.7H.96v2.33A9 9 0 009 18z"/><path fill="#FBBC05" d="M3.97 10.72a5.4 5.4 0 010-3.44V4.95H.96a9 9 0 000 8.1l3.01-2.33z"/><path fill="#EA4335" d="M9 3.58c1.32 0 2.5.45 3.44 1.35l2.58-2.58C13.47.9 11.43 0 9 0A9 9 0 00.96 4.95l3.01 2.33C4.68 5.16 6.66 3.58 9 3.58z"/></svg>"##
            }
            ProviderBrand::Generic(_) => {
                r##"<svg class="picon" viewBox="0 0 16 16" fill="none" aria-hidden="true"><circle cx="6" cy="6" r="3.2" stroke="currentColor" stroke-width="1.4"/><path d="M8.3 8.3l4.2 4.2M10.5 12.5l1.2-1.2M12 11l1.2-1.2" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/></svg>"##
            }
        }
    }
}

const CHEVRON: &str = r##"<svg class="chev" viewBox="0 0 16 16" fill="none" aria-hidden="true"><path d="M6 4l4 4-4 4" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg>"##;

/// The alert glyph shown on a branded error page (a filled roundel with an exclamation).
const ERR_ICON: &str = r##"<svg viewBox="0 0 16 16" fill="none" aria-hidden="true"><path d="M8 4.5v4" stroke="currentColor" stroke-width="2" stroke-linecap="round"/><circle cx="8" cy="11.4" r="1.05" fill="currentColor"/></svg>"##;

/// The left-arrow shown on the "Back to sign in" link of a branded error page.
const BACK_ARROW: &str = r##"<svg viewBox="0 0 16 16" fill="none" aria-hidden="true"><path d="M9.5 4l-4 4 4 4" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/><path d="M5.5 8H12" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/></svg>"##;

/// The clipboard glyph shown on the "Copy" buttons of the key-issued (success) page.
const COPY_ICON: &str = r##"<svg viewBox="0 0 16 16" fill="none" aria-hidden="true"><rect x="5.5" y="5.5" width="8" height="8" rx="1.6" stroke="currentColor" stroke-width="1.4"/><path d="M3.4 10.4A1.5 1.5 0 012 9V3.4A1.5 1.5 0 013.4 2H9a1.5 1.5 0 011.4 1.4" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round"/></svg>"##;

/// The door/arrow-out glyph shown on the quiet "Sign out" link of the key-issued page.
const LOGOUT_ICON: &str = r##"<svg viewBox="0 0 16 16" fill="none" aria-hidden="true"><path d="M6.5 2.5H4A1.5 1.5 0 002.5 4v8A1.5 1.5 0 004 13.5h2.5" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round"/><path d="M10 10.5L12.5 8 10 5.5" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round"/><path d="M12.5 8H6.5" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/></svg>"##;

/// Render a friendly, BRANDED error page for the hosted browser-login flow: the same card chrome as
/// the sign-in / key-issued pages (brand lockup, shared CSS, dark-mode aware), an alert glyph, a
/// human-readable heading + message, and a "Back to sign in" link to `GET /auth/token`. EVERY
/// browser-flow failure (chooser / begin / callback / credential POST) routes through here with an
/// honest, secret-free message and the right HTTP status. The HEADLESS JSON `POST /auth/token` path
/// keeps its `{"error":…}` body (see `exchange::refusal`) — this is the browser branch ONLY.
/// 1.5.5's page for an identity provider that could not be reached: a login plugin that answered
/// `LOGIN_OUTAGE` ([`LoginOutcome::Outage`]).
fn provider_unreachable() -> Response {
    error_page(
        StatusCode::BAD_GATEWAY,
        "Couldn't reach your provider",
        "We couldn't reach your identity provider to finish signing you in. Please try again \
         shortly.",
    )
}

fn error_page(status: StatusCode, heading: &str, message: &str) -> Response {
    let body = page(&format!(
        "<div class=\"brand\"><span class=\"glyph\">{GLYPH}</span><span class=\"wordmark\">Busbar</span></div>\
         <div class=\"errhead\"><span class=\"erricon\">{ERR_ICON}</span><h1 style=\"margin:0;\">{heading}</h1></div>\
         <p class=\"sub\">{message}</p>\
         <a class=\"backlink\" href=\"/auth/token\">{BACK_ARROW}Back to sign in</a>",
        heading = esc(heading),
        message = esc(message),
    ));
    (status, [(header::CACHE_CONTROL, "no-store")], Html(body)).into_response()
}

/// Render the "Signed out" confirmation page (the `?logout=1` action from the key-issued page) and
/// defensively expire the login cookie. The hosted login is STATELESS after issuance: the single-use
/// `busbar_login` cookie is already cleared when the key page renders, and the minted key is a bearer
/// the caller keeps — so there is NO persistent server session to kill. "Sign out" therefore ENDS THE
/// BROWSER VIEW (navigating here drops the key + BYOK block from the DOM so it isn't left displayed on
/// a shared machine) and offers a clean re-entry. It does NOT revoke the issued key, and does NOT end
/// the IdP (Entra) session — an IdP end-session (RP-initiated logout) redirect could be layered on
/// later, but is intentionally out of scope here. Reuses the branded card chrome.
fn signed_out() -> Response {
    let body = page(&format!(
        "<div class=\"brand\"><span class=\"glyph\">{GLYPH}</span><span class=\"wordmark\">Busbar</span></div>\
         <div class=\"issued-head\"><span class=\"check\">{LOGOUT_ICON}</span><h1 style=\"margin:0;\">Signed out</h1></div>\
         <p class=\"sub\">Your key is no longer shown here. It still works — sign in again anytime to view or rotate it.</p>\
         <div class=\"providers\"><a class=\"provider\" href=\"/auth/token\" aria-label=\"Sign in again\"><span class=\"plabel\">Sign in again</span>{CHEVRON}</a></div>\
         <p class=\"foot\">Signing out here only ends this browser view; it doesn't revoke your key or your identity-provider session.</p>"
    ));
    clear_and(html_no_store(body))
}

/// Render the CHOOSER page (sign-in). One anchor per `(method-name, brand)`; `base_url` shown in the
/// footer (verbatim, no `/v1`). Zero buttons → a "no browser login configured" message.
fn render_chooser(buttons: &[(String, ProviderBrand)], base_url: &str) -> String {
    let mut body = String::new();
    if buttons.is_empty() {
        body.push_str(
            "<p class=\"sub\">No browser login is configured. Ask your Busbar admin, or use the \
             headless <span class=\"mono\">POST /auth/token</span> exchange.</p>",
        );
    } else {
        body.push_str("<div class=\"providers\">");
        for (name, brand) in buttons {
            let label = esc(&brand.label());
            body.push_str(&format!(
                "<a class=\"provider\" href=\"/auth/token?method={href}\" aria-label=\"Continue with {label}\">{icon}<span class=\"plabel\">Continue with {label}</span>{chev}</a>",
                href = esc(name),
                label = label,
                icon = brand.icon(),
                chev = CHEVRON,
            ));
        }
        body.push_str("</div>");
    }
    let footer = if base_url.is_empty() {
        String::new()
    } else {
        format!(
            "<p class=\"foot\">Your key is issued to <b>you</b>, tracked against your own budget, and \
             managed by your Busbar admin. Signing in at <span class=\"mono\">{}</span>.</p>",
            esc(base_url)
        )
    };
    page(
        &format!(
            "<div class=\"brand\"><span class=\"glyph\">{GLYPH}</span><span class=\"wordmark\">Busbar</span></div>\
             <h1>Get your API key</h1>\
             <p class=\"sub\">Sign in with your organization account. Busbar issues a personal key scoped to your budget.</p>\
             {body}{footer}"
        ),
    )
}

/// Render the CREDENTIAL-LOGIN FORM (the `Prompt` shape): one input per plugin-declared field
/// (`Password` masked), a hidden CSRF `__state`, POSTing the values to `/auth/token`. Generic — the
/// core renders WHATEVER fields the plugin declared, not a hardcoded username/password.
fn render_login_form(
    method: &str,
    form: &busbar_contract::auth::LoginForm,
    state: &str,
    base_url: &str,
    refresh: bool,
) -> String {
    let brand = ProviderBrand::infer(method, None);
    let title = if refresh {
        "Refresh your API key"
    } else {
        "Sign in"
    };
    let mut fields = String::new();
    for f in &form.fields {
        let input_type = match f.kind {
            busbar_contract::auth::FieldKind::Password => "password",
            busbar_contract::auth::FieldKind::Text => "text",
        };
        let required = if f.required { " required" } else { "" };
        fields.push_str(&format!(
            "<label class=\"flabel\">{label}<input class=\"finput\" type=\"{ty}\" name=\"{name}\" \
             autocomplete=\"off\"{req}></label>",
            label = esc(&f.label),
            ty = input_type,
            name = esc(&f.name),
            req = required,
        ));
    }
    let footer = if base_url.is_empty() {
        String::new()
    } else {
        format!(
            "<p class=\"foot\">Your key is issued to <b>you</b>, tracked against your own budget. \
             Signing in at <span class=\"mono\">{}</span>.</p>",
            esc(base_url)
        )
    };
    page(&format!(
        "<div class=\"brand\"><span class=\"glyph\">{GLYPH}</span><span class=\"wordmark\">Busbar</span></div>\
         <h1>{title}</h1>\
         <p class=\"sub\">Sign in with your {provider} credentials. Busbar issues a personal key scoped to your budget.</p>\
         <form class=\"credform\" method=\"post\" action=\"/auth/token\">\
         <input type=\"hidden\" name=\"{state_field}\" value=\"{state}\">\
         {fields}\
         <button class=\"provider\" type=\"submit\"><span class=\"plabel\">{title}</span></button>\
         </form>{footer}",
        title = esc(title),
        provider = esc(&brand.label()),
        state_field = FORM_STATE_FIELD,
        state = esc(state),
        fields = fields,
        footer = footer,
    ))
}

/// Render the KEY-ISSUED page. RE-SHOWABLE (not "shown once"): the key can be re-shown by signing in
/// again; the "Refresh key" action ROTATES it (`?refresh=1` → the prior token stops verifying).
/// `base_url` is printed verbatim (no `/v1`) for BYOK.
fn render_key_issued(
    sub: &str,
    group: &str,
    api_key: &str,
    base_url: &str,
    method: &str,
) -> String {
    let refresh_href = format!("/auth/token?method={}&refresh=1", esc(method));
    let team = if group.is_empty() {
        String::new()
    } else {
        format!(" · group <b>{}</b>", esc(group))
    };
    let snippet = format!(
        "<div class=\"snippet mono\"><span class=\"k\">base_url:</span> <span class=\"v\">{}</span><br><span class=\"k\">api_key:&nbsp;</span> <span class=\"v\">{}</span></div>",
        esc(base_url),
        esc(api_key),
    );
    // The one-click "Copy" button beside the key. `data-copy` carries the value the inline `bbCopy`
    // handler writes to the clipboard (attribute-escaped; the browser decodes entities on read).
    let key_copy = format!(
        "<button type=\"button\" class=\"copy\" aria-label=\"Copy your API key\" data-copy=\"{key}\" onclick=\"bbCopy(this)\">{COPY_ICON}<span class=\"clabel\">Copy</span></button>",
        key = esc(api_key),
    );
    // The BYOK block's "Copy" button copies the whole `base_url:\napi_key:` pair (one paste for
    // Cursor/VS Code). `&#10;` is the literal newline the browser decodes when reading `data-copy`.
    let byok_copy = format!(
        "<button type=\"button\" class=\"copymini\" aria-label=\"Copy the base URL and API key\" data-copy=\"base_url: {url}&#10;api_key: {key}\" onclick=\"bbCopy(this)\">{COPY_ICON}<span class=\"clabel\">Copy</span></button>",
        url = esc(base_url),
        key = esc(api_key),
    );
    page(&format!(
        "<div class=\"brand\"><span class=\"glyph\">{GLYPH}</span><span class=\"wordmark\">Busbar</span></div>\
         <div class=\"issued-head\"><span class=\"check\"><svg viewBox=\"0 0 16 16\" fill=\"none\" aria-hidden=\"true\"><path d=\"M3 8.5l3 3 7-7\" stroke=\"#0f172a\" stroke-width=\"2.2\" stroke-linecap=\"round\" stroke-linejoin=\"round\"/></svg></span><h1 style=\"margin:0;\">You're in</h1></div>\
         <p class=\"sub\">Signed in as <span class=\"mono\">{sub}</span>{team}</p>\
         <div class=\"keyrow\"><span class=\"keyval mono\" id=\"key\">{key}</span>{key_copy}</div>\
         <div class=\"reshow\"><svg viewBox=\"0 0 16 16\" fill=\"none\" aria-hidden=\"true\"><path d=\"M2 8a6 6 0 1111.5 2.4\" stroke=\"currentColor\" stroke-width=\"1.4\" stroke-linecap=\"round\"/><path d=\"M13 4v3h-3\" stroke=\"currentColor\" stroke-width=\"1.4\" stroke-linecap=\"round\" stroke-linejoin=\"round\"/></svg>Re-showable — <a href=\"{refresh}\">Refresh key</a> to rotate or view it again.</div>\
         <div class=\"useinrow\"><span class=\"usein\">Paste into Cursor or VS Code (BYOK) — base URL + this key:</span>{byok_copy}</div>{snippet}\
         <p class=\"foot\">Manage keys anytime by signing in again.</p>\
         <a class=\"signout\" href=\"/auth/token?logout=1\" aria-label=\"Sign out and hide this key\">{LOGOUT_ICON}Sign out</a>",
        sub = esc(sub),
        team = team,
        key = esc(api_key),
        key_copy = key_copy,
        refresh = refresh_href,
        byok_copy = byok_copy,
        snippet = snippet,
    ))
}

/// Wrap a card body in the full HTML document (shared head + `.stack`/`.card` chrome).
fn page(card_inner: &str) -> String {
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">{HEAD}</head><body><div class=\"stack\"><div class=\"card\">{card_inner}</div></div></body></html>"
    )
}

/// Minimal HTML-attribute/text escaping for server-injected values.
fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Title-case a method/module name for the fallback button label (`my-idp` → `My-Idp`).
fn titlecase(name: &str) -> String {
    name.split(['-', '_', ' '])
        .filter(|s| !s.is_empty())
        .map(|w| {
            let mut c = w.chars();
            match c.next() {
                Some(f) => f.to_ascii_uppercase().to_string() + c.as_str(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
#[path = "tests/token_tests.rs"]
mod token_tests;
