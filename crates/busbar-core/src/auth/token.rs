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
//! * **callback** (`?code=&state=`): the CORE validates `state` against the cookie BEFORE any token
//!   exchange (CSRF), then loops `complete_login` — executing each module-described token-exchange
//!   hop and INJECTING the confidential-client `client_secret` (the module only ever writes the KEY,
//!   never the value) — verifies the returned id_token's `nonce` claim against the cookie nonce, and
//!   on `Identify` mints the caller's key through the SAME [`super::self_keys`] seam the headless
//!   `POST` uses (no second mint path). The cookie is cleared on completion.
//!
//! SECURITY: `state` and `nonce` are validated before identity is established; the `client_secret`
//! value is core-only (never crosses the ABI, never in the cookie, never logged, never rendered); the
//! login page issues via the shared self-serve seam.

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::State;
use axum::http::{header, Request, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use base64::Engine as _;
use indexmap::IndexMap;

use busbar_api::{
    AuthPlugin, BeginLogin, CompleteLogin, LoginHttpResponse, LoginOutcome, Principal,
};

use super::self_keys::{issue_key, resolve_exchange, DeterministicEd25519Keys, HandleProvisioner};
use super::ChainVerdict;
use crate::config::AuthCfg;
use crate::state::{App, AppHandle};

/// The login-state cookie name. Scoped to `/auth/token` (Path), HttpOnly + Secure + SameSite=Lax.
const LOGIN_COOKIE: &str = "busbar_login";
/// The hidden CSRF field the credential form carries (matched against the cookie's `state`). Reserved:
/// it is stripped from the submitted map, so a plugin can never declare a field with this name.
const FORM_STATE_FIELD: &str = "__state";
/// Short cookie lifetime — a login round-trip is seconds-to-minutes; the cookie is single-purpose.
const LOGIN_COOKIE_MAX_AGE: u32 = 600;
/// The maximum number of `complete_login` turns per callback (each `Exchange` hop the CORE executes,
/// plus the terminal `Identify`, is one turn). Sized for the LONGEST first-party redirect flow:
/// GitHub is code→token (1) + `GET /user` (2) + `GET /user/orgs` (3) THEN `Identify` on the 4th turn,
/// so a bound of 3 would fail-close GitHub's org flow one turn short of identity. 6 keeps the loop
/// firmly bounded (a module that never `Identify`s is still fail-closed) while covering every shipped
/// flow with headroom (OIDC code→token is a single hop). Raising this is safe: the hop-cap test asserts
/// the loop runs EXACTLY this many turns for a never-identifying module, symbolically, not a literal.
const MAX_HOPS: usize = 6;
/// The URL-safe, no-pad base64 engine used for PKCE and the cookie payload.
const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::URL_SAFE_NO_PAD;

// ── login-method registry (App.login_methods) ───────────────────────────────────────────────────

/// One resolved hosted-login method (`identity-providers.<name>`). Holds the login-capable plugin handle,
/// the OAuth `client_id`, and — for a `browser_login` method — the resolved confidential-client
/// secret VALUE, which is CORE-ONLY: never serialized to the plugin, never in the cookie, never
/// logged, never rendered; injected ONLY into a token-exchange hop's `secret_form_field`.
pub(crate) struct LoginMethod {
    pub(crate) module: Box<dyn AuthPlugin>,
    /// The resolved confidential-client secret, held [`busbar_api::Redacted`] so it never leaks via
    /// `Debug`/logs and zeroizes on drop. CORE-ONLY: exposed only into a token-exchange hop's
    /// `secret_form_field`, never serialized to the plugin, never rendered.
    pub(crate) client_secret: Option<busbar_api::Redacted<String>>,
    /// `true` ⇒ this method has a `browser_login` block and renders a button (and accepts `begin`).
    pub(crate) has_button: bool,
    /// The OIDC issuer from the method's opaque settings, used only to infer a button icon/label.
    pub(crate) issuer: Option<String>,
    /// The plugin's pure redirect-vs-credential classification, resolved ONCE at build (a
    /// side-effect-free `login_kind` call). Read by `credential_submit` to gate the credential POST to
    /// `Credential` methods only (a redirect method never completes via the form POST).
    pub(crate) login_kind: busbar_api::LoginKind,
    /// The set of hosts (lowercased) a token-exchange/userinfo hop may target, derived CORE-SIDE from
    /// this method's OPERATOR config (the `issuer` + any absolute-URL settings values like
    /// `api_base`/`token_base`/`authorize_base`). A module-described hop to any host NOT in this set is
    /// REFUSED before the request is built — so a signed-but-malicious login plugin can neither exfil
    /// the core-injected `client_secret` nor a bearer to an attacker host, nor use the core as a blind
    /// SSRF proxy. Empty ⇒ no hop is permitted (fail closed).
    pub(crate) allowed_hosts: std::collections::HashSet<String>,
}

/// The resolved hosted-login map — insertion-ordered (config order = button order), keyed by the
/// method/module name. Built on boot AND reload in `build_app_from_config`.
pub(crate) struct LoginMethods {
    pub(crate) methods: IndexMap<String, LoginMethod>,
}

// ── the login-plugin OFFLOAD (the blocking-FFI class) ───────────────────────────────────────────

/// The bound on CONCURRENT offloaded login-plugin calls, and a SEPARATE budget from the data-plane
/// auth chain's [`super::AUTH_OFFLOAD_MAX_INFLIGHT`] and the admin chain's
/// `ADMIN_OFFLOAD_MAX_INFLIGHT`: `/auth/token` is reachable ANONYMOUSLY (it is mounted on the data
/// router and the auth middleware bypasses that exact path — `auth/mod.rs`'s bypass list), so its
/// concurrency is attacker-chosen. Sharing a budget with the credential-verifying chain would let an
/// unauthenticated flood of logins deny auth to authenticated traffic. Smaller than the auth chain's
/// 64 for the same reason: a human login round-trip is not customer request volume.
const LOGIN_OFFLOAD_MAX_INFLIGHT: usize = 16;

/// How long a login request waits for an offload permit before giving up. A login that cannot even be
/// STARTED in this window is not going to complete, so it is answered rather than left hanging.
const LOGIN_OFFLOAD_WAIT: Duration = Duration::from_secs(5);

/// The permit pool for [`LOGIN_OFFLOAD_MAX_INFLIGHT`]. Process-wide (not per-`LoginMethods`) on
/// purpose — the resource being bounded is the process's ONE shared blocking pool, and a config
/// reload swaps `App::login_methods` while in-flight offloads from the previous one still hold
/// threads. Same construction, and the same reason, as `auth::AUTH_OFFLOAD_PERMITS`.
static LOGIN_OFFLOAD_PERMITS: std::sync::LazyLock<tokio::sync::Semaphore> =
    std::sync::LazyLock::new(|| tokio::sync::Semaphore::new(LOGIN_OFFLOAD_MAX_INFLIGHT));

/// THE ONE PLACE a login plugin's synchronous FFI is called from the request path.
///
/// `LoginModule::begin_login` / `complete_login` are SYNCHRONOUS `transport_call`s into a dlopened
/// plugin, and behind that call is real network I/O: an LDAP/AD bind for a credential method, an
/// authorize-URL mint or a userinfo/token round-trip for a redirect one. Called inline from the
/// `async fn` handlers, each in-flight login parks a Tokio worker for the plugin's full timeout;
/// since `/auth/token` is ANONYMOUSLY reachable, an attacker picks how many. Once every worker is
/// parked NOTHING in the process is polled — not other requests, not the admin plane, not `/healthz`
/// (exempt from auth, but still needing a worker to run at all) — and the node fails its liveness
/// probe. This is the hazard `AuthMiddleware::run_chain_on_request_path` documents and offloads for;
/// the login path needs the same treatment, with its own budget (see [`LOGIN_OFFLOAD_MAX_INFLIGHT`]).
///
/// So the call runs on the blocking pool, BOUNDED by [`LOGIN_OFFLOAD_PERMITS`], and FAIL-CLOSED at
/// every failure: a permit that cannot be acquired in time, a method that vanished under a concurrent
/// reload, and a panicking plugin (join error) are all [`LoginOutcome::Reject`] — the same posture
/// `map_begin_login`/`map_complete_login` already take on a transport error, so a caller that cannot
/// distinguish them does not have to.
///
/// The method is re-looked-up by NAME on the blocking thread rather than borrowed across the offload:
/// the closure must be `'static`, and cloning the `Arc<LoginMethods>` snapshot is what makes the
/// module handle outlive a concurrent config swap.
async fn offload_login_call<F>(
    methods: &Arc<LoginMethods>,
    method: &str,
    op: &'static str,
    call: F,
) -> LoginOutcome
where
    F: FnOnce(&LoginMethod) -> LoginOutcome + Send + 'static,
{
    let permit = match tokio::time::timeout(LOGIN_OFFLOAD_WAIT, LOGIN_OFFLOAD_PERMITS.acquire())
        .await
    {
        Ok(Ok(p)) => p,
        // Timed out waiting, or the semaphore was closed. Either way the plugin never ran, so no
        // identity was established — reject.
        _ => {
            tracing::warn!(
                method = %method, op,
                "login plugin offload could not be started within {LOGIN_OFFLOAD_WAIT:?} \
                 ({LOGIN_OFFLOAD_MAX_INFLIGHT} already in flight); a login plugin is not \
                 returning. Rejecting (fail-closed) rather than completing a login it never ran."
            );
            return LoginOutcome::Reject;
        }
    };
    let (methods, method_name) = (methods.clone(), method.to_string());
    let joined = tokio::task::spawn_blocking(move || {
        let outcome = match methods.methods.get(&method_name) {
            Some(m) => call(m),
            // The method disappeared between the handler's lookup and this thread (a config reload
            // swapped `login_methods`). Nothing verified anyone — reject.
            None => LoginOutcome::Reject,
        };
        // Released when the blocking work is DONE, not when the awaiting future is dropped: a
        // cancelled request must not hand its slot to another while the plugin thread it started is
        // still wedged.
        drop(permit);
        outcome
    })
    .await;
    match joined {
        Ok(outcome) => outcome,
        Err(e) => {
            tracing::warn!(method = %method, op, error = %e, "login plugin call panicked; rejecting (fail-closed)");
            LoginOutcome::Reject
        }
    }
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

    /// Resolve every `identity-providers:` entry as a login-capable `kind: auth` plugin (ABI v2) via the
    /// validated `registry` — the same trust/load pipeline as the data-plane chain. SecretRef-typed
    /// module settings resolve before the config crosses the ABI; the `browser_login.client_secret`
    /// resolves to a plaintext held CORE-ONLY. CAPABILITY GATE: a `browser_login` method whose plugin
    /// advertises `abi_version < 2` is a HARD build error (never a 500 at request time). FAIL-CLOSED:
    /// any unresolvable method aborts the boot/reload build. Runs inside `build_app_from_config`.
    pub(crate) fn build(
        cfg: &AuthCfg,
        registry: &busbar_plugin_loader::PluginRegistry,
        secret_resolver: &crate::config::secret::SecretResolver,
    ) -> Result<Self, String> {
        let mut methods = IndexMap::new();
        for (name, mc) in &cfg.methods {
            let mut resolved =
                crate::config::secret::resolve_settings(&mc.settings, secret_resolver)
                    .map_err(|e| format!("identity-providers.{name} settings: {e}"))?;
            // The OAuth `client_id` (the PUBLIC half) rides the module's settings so the module can
            // build the authorize URL + token-exchange with it. It is NOT a secret and is passed
            // through; the confidential-client secret is held CORE-only below and never crosses here.
            if let Some(bl) = &mc.browser_login {
                if let Some(cid) = &bl.client_id {
                    resolved
                        .entry("client_id".to_string())
                        .or_insert_with(|| serde_json::Value::String(cid.clone()));
                }
            }
            let cfg_json = serde_json::Value::Object(resolved).to_string();
            // Opened by the provider definition's `module:` (the plugin), REGISTERED under the
            // provider NAME (the instance). 1.5.3: `auth.methods:` folded into
            // `identity-providers:`, so the two are no longer the same string — two named providers
            // may legitimately share one login plugin with different issuers/clients.
            let (module, abi_version) =
                registry.open_login(&mc.module, &cfg_json).map_err(|e| {
                    format!(
                        "identity-providers.{name} (module '{}') could not be loaded as a \
                         `kind: auth` login plugin: {e}",
                        mc.module
                    )
                })?;
            let issuer = mc
                .settings
                .get("issuer")
                .and_then(|v| v.as_str())
                .map(str::to_string);
            // Resolve the plugin's classification ONCE here (side-effect-free) so the chooser reads it
            // off the registry entry without a per-render call — and so `client_secret` can be
            // validated per the method's login_kind below.
            let login_kind = module.login_kind();
            let (client_secret, has_button) = match &mc.browser_login {
                Some(bl) => {
                    if abi_version < 2 {
                        return Err(format!(
                            "identity-providers.{name} sets browser_login but its plugin advertises \
                             abi_version {abi_version}; a hosted login button requires an ABI v2 \
                             login-capable auth plugin (rebuild the plugin against auth ABI v2)"
                        ));
                    }
                    // Per-kind rule: a Redirect (OAuth) method REQUIRES the confidential-client secret;
                    // a Credential (LDAP/AD-bind) method must NOT carry one (it has nothing to hold).
                    validate_browser_login_secret(login_kind, bl.client_secret.is_some())
                        .map_err(|e| format!("identity-providers.{name} browser_login: {e}"))?;
                    let client_secret = match &bl.client_secret {
                        Some(sref) => {
                            let secret = secret_resolver.resolve_string(sref).map_err(|e| {
                                format!(
                                    "identity-providers.{name} browser_login.client_secret: {e}"
                                )
                            })?;
                            Some(busbar_api::Redacted::new(secret))
                        }
                        None => None,
                    };
                    (client_secret, true)
                }
                None => (None, false),
            };
            // Derive the hop host-allowlist from the OPERATOR's config (issuer + any URL settings) —
            // NEVER from anything the untrusted plugin returns.
            let allowed_hosts = collect_allowed_hosts(&mc.settings, issuer.as_deref());
            methods.insert(
                name.clone(),
                LoginMethod {
                    module,
                    client_secret,
                    has_button,
                    issuer,
                    login_kind,
                    allowed_hosts,
                },
            );
        }
        Ok(Self { methods })
    }
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
    // Existence + button check ONLY: the `LoginMethod` is deliberately NOT bound here. The one call
    // this function makes into it is the offloaded `begin_login` below, which re-looks-up the method
    // by name on the blocking thread — so there is no handle in scope an inline FFI call could be
    // written against.
    if !app
        .login_methods
        .methods
        .get(method)
        .is_some_and(|m| m.has_button)
    {
        // Unknown / headless-only method — nothing to begin in the browser.
        return error_page(
            StatusCode::NOT_FOUND,
            "Sign-in method not found",
            "That sign-in method isn't available here. Head back and choose one of the listed options.",
        );
    }
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
    // OFFLOADED + BOUNDED: `begin_login` is synchronous plugin FFI on an ANONYMOUSLY-reachable data-
    // plane path (see `offload_login_call`). `m` is not used past this point, so nothing borrows the
    // App across the offload.
    match offload_login_call(&app.login_methods, method, "begin_login", move |m| {
        m.module.begin_login(&begin)
    })
    .await
    {
        // REDIRECT (OAuth) flow: 302 to the IdP; the callback (a GET) completes it.
        LoginOutcome::Authorize(url) => {
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
                .header(header::LOCATION, url)
                .header(header::CACHE_CONTROL, "no-store")
                .body(Body::empty())
                .expect("static 302");
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

/// callback: validate `state` vs the cookie (CSRF) BEFORE any exchange, run the hop loop injecting
/// the client_secret, verify the id_token nonce, then mint via the shared self-serve seam.
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
        .map(|s| busbar_api::constant_time_eq(s, &cookie.state))
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

    // The complete_login hop loop. The module DESCRIBES each token-exchange hop; the CORE executes it
    // and injects the client_secret into the named form field. Bounded to MAX_HOPS; a module that
    // never Identifies is fail-closed.
    let mut cl = CompleteLogin {
        code: Some(code),
        redirect_uri: Some(redirect_uri),
        code_verifier: Some(cookie.code_verifier.clone()),
        ..Default::default()
    };
    let http = hop_client();
    let mut principal: Option<Principal> = None;
    for _ in 0..MAX_HOPS {
        // OFFLOADED + BOUNDED per hop: `complete_login` is synchronous plugin FFI (the token
        // exchange / userinfo decode) and this loop runs up to `MAX_HOPS` of them on an anonymously-
        // reachable callback. The hop request itself (`execute_hop`) is already async and stays on
        // the reactor; only the plugin call crosses to the blocking pool.
        let turn = cl.clone();
        match offload_login_call(
            &app.login_methods,
            &cookie.method,
            "complete_login",
            move |m| m.module.complete_login(&turn),
        )
        .await
        {
            LoginOutcome::Identify(p) => {
                principal = Some(p);
                break;
            }
            LoginOutcome::Exchange(hop) => {
                // Execute the hop, CORE-injecting the client_secret VALUE into the named form field.
                let (status, body) =
                    match execute_hop(
                        http,
                        &hop,
                        m.client_secret.as_ref().map(|r| r.expose_secret().as_str()),
                        &m.allowed_hosts,
                    )
                    .await
                    {
                        Ok(v) => v,
                        Err(_) => return clear_and(error_page(
                            StatusCode::BAD_GATEWAY,
                            "Couldn't reach your provider",
                            "We couldn't reach your identity provider to finish signing you in. \
                             Please try again shortly.",
                        )),
                    };
                // NONCE BINDING (core's job — the ABI CompleteLogin has no nonce field): if the hop
                // body carries an id_token, its `nonce` claim MUST equal the cookie nonce BEFORE any
                // identity is trusted. A mismatch is a rejected callback with NO identity established.
                if let Some(id_token) = extract_id_token(&body) {
                    match id_token_nonce(&id_token) {
                        // Constant-time compare (the nonce is per-login secret material).
                        Some(n) if busbar_api::constant_time_eq(&n, &cookie.nonce) => {}
                        _ => {
                            return clear_and(security_check_failed());
                        }
                    }
                }
                cl.token_response = Some(LoginHttpResponse { status, body });
            }
            LoginOutcome::Reject => {
                return clear_and(error_page(
                    StatusCode::UNAUTHORIZED,
                    "Sign-in was declined",
                    "Your identity provider declined this sign-in. Check with your Busbar admin if \
                     this keeps happening.",
                ));
            }
            // A module must not (re)authorize or (re)prompt on the callback path — fail closed.
            LoginOutcome::Authorize(_) | LoginOutcome::Prompt(_) => {
                return clear_and(error_page(
                    StatusCode::BAD_GATEWAY,
                    "Sign-in unavailable",
                    "Something went wrong completing this sign-in. Please head back and try again.",
                ));
            }
        }
    }
    let Some(principal) = principal else {
        return clear_and(error_page(
            StatusCode::BAD_GATEWAY,
            "Sign-in didn't finish",
            "This sign-in didn't complete. Please head back and try again.",
        ));
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
        match resolve_exchange(&verdict, &app.role_bindings) {
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
        &issued.secret,
        base_url,
        module_name,
    );
    html_no_store(page)
}

/// `credential_submit`: complete a CREDENTIAL-flow login. Called by the POST `/auth/token` handler
/// (`exchange`) when a login cookie is present. Validates CSRF (`__state` vs the cookie), builds
/// [`CompleteLogin`] from the submitted field values (each [`busbar_api::Redacted`]), runs the
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
    if !busbar_api::constant_time_eq(submitted_state, &cookie.state) {
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
    if m.login_kind != busbar_api::LoginKind::Credential {
        return clear_and(error_page(
            StatusCode::BAD_REQUEST,
            "Sign-in unavailable",
            "This sign-in method can't be completed here. Please head back and start again.",
        ));
    }
    // Build the submitted map (every field EXCEPT the CSRF token), Redacted the moment it is held.
    let submitted: Vec<(String, busbar_api::Redacted<String>)> = form
        .into_iter()
        .filter(|(k, _)| k != FORM_STATE_FIELD)
        .map(|(k, v)| (k, busbar_api::Redacted::new(v)))
        .collect();
    let cl = CompleteLogin {
        submitted,
        ..Default::default()
    };
    // A credential module verifies the credential itself (e.g. an LDAP bind) and returns `Identify`.
    // OFFLOADED + BOUNDED: that bind is the longest synchronous FFI call in the engine and this POST
    // is anonymously reachable (the `__state` check is satisfied by a cookie the caller minted for
    // themselves via `begin`), so it must never run on a reactor worker.
    let principal = match offload_login_call(
        &app.login_methods,
        &cookie.method,
        "complete_login",
        move |m| m.module.complete_login(&cl),
    )
    .await
    {
        LoginOutcome::Identify(p) => p,
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

// ── core-executed token-exchange hop + nonce verification ────────────────────────────────────────

/// The per-hop HTTP request timeout — a hostile/slow token endpoint (which the plugin chooses) must
/// not hold the callback future open indefinitely.
const HOP_TIMEOUT_SECS: u64 = 10;

/// The ONE pooled HTTP client every hop reuses (connection pooling; not a fresh `Client::new()` per
/// callback). Bounded by [`HOP_TIMEOUT_SECS`] and — critically — with redirects DISABLED: an
/// auto-followed 3xx could bounce the core-injected secret/bearer to an off-allowlist host.
fn hop_client() -> &'static reqwest::Client {
    static CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(HOP_TIMEOUT_SECS))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("static hop http client")
    })
}

/// The header names a module-described hop may NEVER set (hop-control headers): letting a plugin set
/// these would let it desync the request framing or override the target authority.
const FORBIDDEN_HOP_HEADERS: [&str; 3] = ["host", "content-length", "transfer-encoding"];

/// Collect the host-allowlist for a method's hops from the OPERATOR's config: the `issuer` plus the
/// host of any absolute http(s) URL anywhere in the method's opaque settings (`api_base`,
/// `token_base`, `authorize_base`, …). Hosts are lowercased. NEVER derived from plugin output.
/// Per-`login_kind` rule for a `browser_login` method's `client_secret`: a Redirect (OAuth-family,
/// confidential-client) method REQUIRES it; a Credential (LDAP/AD-bind) method must NOT set one (it
/// has no confidential-client secret to hold). Pure, so it is unit-tested without a plugin registry.
pub(crate) fn validate_browser_login_secret(
    login_kind: busbar_api::LoginKind,
    has_secret: bool,
) -> Result<(), &'static str> {
    match (login_kind, has_secret) {
        (busbar_api::LoginKind::Redirect, false) => Err(
            "a redirect (OAuth) login method requires browser_login.client_secret (it is a \
             confidential client)",
        ),
        (busbar_api::LoginKind::Credential, true) => Err(
            "a credential login method must not set browser_login.client_secret (it has no \
             confidential-client secret to hold)",
        ),
        _ => Ok(()),
    }
}

pub(crate) fn collect_allowed_hosts(
    settings: &serde_json::Map<String, serde_json::Value>,
    issuer: Option<&str>,
) -> std::collections::HashSet<String> {
    let mut hosts = std::collections::HashSet::new();
    let mut add = |url: &str| {
        if let Some(h) = crate::config_validate::extract_normalized_host(url) {
            hosts.insert(h.to_ascii_lowercase());
        }
    };
    if let Some(iss) = issuer {
        add(iss);
    }
    // Walk every string value in the settings tree; an absolute http(s) URL contributes its host.
    fn walk(v: &serde_json::Value, add: &mut impl FnMut(&str)) {
        match v {
            serde_json::Value::String(s) => {
                if s.starts_with("http://") || s.starts_with("https://") {
                    add(s);
                }
            }
            serde_json::Value::Array(a) => a.iter().for_each(|x| walk(x, add)),
            serde_json::Value::Object(o) => o.values().for_each(|x| walk(x, add)),
            _ => {}
        }
    }
    for v in settings.values() {
        walk(v, &mut add);
    }
    hosts
}

/// Vet a module-described hop URL BEFORE any request is built (so the secret is never sent on a
/// refusal). The host MUST be in the operator-derived `allowed` set; the scheme MUST be https for a
/// public host (http tolerated only for a loopback/private endpoint, matching
/// `oauth_client_credentials::validate_token_url`); and a cloud-metadata/link-local host is refused
/// outright. Returns the normalized host on success.
fn vet_hop_url(url: &str, allowed: &std::collections::HashSet<String>) -> Result<(), ()> {
    use crate::config_validate::{
        extract_normalized_host, host_is_private_or_loopback, scheme_is, ssrf_blocked_host,
    };
    let Some(host) = extract_normalized_host(url) else {
        return Err(());
    };
    // PRIMARY control: the host must be one the operator configured for this method.
    if !allowed.contains(&host.to_ascii_lowercase()) {
        return Err(());
    }
    let host_private = host_is_private_or_loopback(&host);
    // https for public hosts; http only for loopback/private (a local/on-prem IdP).
    if !(scheme_is(url, "https") || (host_private && scheme_is(url, "http"))) {
        return Err(());
    }
    // Defense-in-depth: never a cloud-metadata/IMDS/link-local target, even if somehow allowlisted.
    if ssrf_blocked_host(url, &[], false, &[]).is_some() {
        return Err(());
    }
    Ok(())
}

/// Sanitize a module-described header: reject CR/LF/NUL (request-splitting) in the name or value and
/// the hop-control headers (`Host`/`Content-Length`/`Transfer-Encoding`). Returns the parsed
/// name+value on success, `Err` if the header must cause the whole hop to be refused.
fn sanitize_hop_header(
    name: &str,
    value: &str,
) -> Result<(reqwest::header::HeaderName, reqwest::header::HeaderValue), ()> {
    let bad = |s: &str| s.contains('\r') || s.contains('\n') || s.contains('\0');
    if bad(name) || bad(value) {
        return Err(());
    }
    if FORBIDDEN_HOP_HEADERS.contains(&name.to_ascii_lowercase().as_str()) {
        return Err(());
    }
    let hn = reqwest::header::HeaderName::from_bytes(name.as_bytes()).map_err(|_| ())?;
    let hv = reqwest::header::HeaderValue::from_str(value).map_err(|_| ())?;
    Ok((hn, hv))
}

/// Execute a module-described hop, CORE-INJECTING the `client_secret` VALUE into the field the
/// module named in `secret_form_field` (the module only ever wrote the KEY). The secret VALUE lives
/// ONLY in this outbound form — never in the cookie, never logged, never rendered. The hop URL is
/// VETTED against the method's operator-derived host allowlist (`allowed`) BEFORE the request is
/// built (so the secret is never sent to an off-allowlist host), and the module's extra `headers` are
/// SANITIZED (CR/LF/NUL + hop-control headers rejected).
async fn execute_hop(
    http: &reqwest::Client,
    hop: &busbar_api::LoginHop,
    client_secret: Option<&str>,
    allowed: &std::collections::HashSet<String>,
) -> Result<(u16, String), ()> {
    // VET THE URL FIRST — a refusal here means no request is built and no secret leaves the process.
    vet_hop_url(&hop.url, allowed)?;

    let mut form: Vec<(String, String)> = hop.form.clone();
    if let Some(field) = hop.secret_form_field.as_deref() {
        match client_secret {
            // Overwrite the placeholder value the plugin wrote for the secret key with the real value.
            Some(secret) => {
                if let Some(slot) = form.iter_mut().find(|(k, _)| k == field) {
                    slot.1 = secret.to_string();
                } else {
                    form.push((field.to_string(), secret.to_string()));
                }
            }
            // NO secret configured: DROP the placeholder rather than sending it empty.
            //
            // A plugin writes the key with an empty value and lets the core fill it in, so leaving
            // it alone here puts `client_secret=` on the wire. An empty secret is NOT the same as an
            // absent one: for a PUBLIC client (the shape with no secret at all) the parameter should
            // simply not be there, and an IdP is entitled to read an empty string as a WRONG secret
            // and answer `invalid_client` rather than as "this client is public". Removing it makes
            // the request the correct shape for the configuration the operator actually has, and
            // cannot affect the confidential path, which takes the arm above.
            None => form.retain(|(k, _)| k != field),
        }
    }
    let method =
        reqwest::Method::from_bytes(hop.method.as_bytes()).unwrap_or(reqwest::Method::POST);
    let mut req = http.request(method, &hop.url).form(&form);
    for (name, value) in &hop.headers {
        // Any invalid/forbidden header fails the WHOLE hop closed (a plugin injecting CRLF is hostile).
        let (hn, hv) = sanitize_hop_header(name, value)?;
        req = req.header(hn, hv);
    }
    let resp = req.send().await.map_err(|_| ())?;
    let status = resp.status().as_u16();
    let body = resp.text().await.map_err(|_| ())?;
    Ok((status, body))
}

/// Pull the `id_token` string out of an OAuth/OIDC token-endpoint JSON body, if present.
fn extract_id_token(body: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    v.get("id_token")?.as_str().map(str::to_string)
}

/// Decode a JWT's payload (segment 2, base64url) and read its `nonce` claim. NO signature check —
/// the auth module verified iss/aud/exp/sig; the CORE only binds the nonce it minted at begin.
fn id_token_nonce(id_token: &str) -> Option<String> {
    let payload_b64 = id_token.split('.').nth(1)?;
    let bytes = B64.decode(payload_b64).ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    claims.get("nonce")?.as_str().map(str::to_string)
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
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(code_verifier.as_bytes());
    B64.encode(digest)
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
/// callback or credential POST, or a mismatched id_token `nonce`). One copy for every "the security
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
    form: &busbar_api::LoginForm,
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
            busbar_api::FieldKind::Password => "password",
            busbar_api::FieldKind::Text => "text",
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
