// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `GET /auth/token` — the HOSTED BROWSER LOGIN flow (1.5.2), this crate's (THE DESIGN §8:
//! `busbar-core-oauth2` owns "the authorization server and the hosted login flow"; row 159, K3#2).
//!
//! One param-less path, three sub-states read off the query string:
//! * **chooser** (no params): one button per `identity-providers:` entry that has a `browser_login`
//!   block, in config order. `base_url` (= `public_url`, verbatim, no `/v1`) is shown for BYOK.
//! * **begin** (`?method=<name>`): this flow mints PKCE (`code_verifier`/`code_challenge` S256),
//!   `state`, and `nonce`, stores them in a hand-rolled HttpOnly+Secure+SameSite=Lax cookie, and
//!   302s to the IdP authorize URL the module's `begin_login` returned.
//! * **callback** (`?code=&state=`): this flow validates `state` against the cookie BEFORE anything
//!   is asked of the plugin (CSRF), then hands the plugin ONE `complete_login` carrying the cookie's
//!   state and nonce — the plugin makes its own token exchange with the client secret it was lent
//!   at `open` and binds the IdP's answer to the nonce — and on `Identify` the kernel mints the
//!   caller's key through the SAME self-serve seam the headless `POST` uses (no second mint path).
//!   The cookie is cleared on completion.
//!
//! The identity side stays the kernel's ([`busbar_kernel::auth::login`]): the login methods it
//! opened, one login step on a plugin's door under the anonymous-flood budget, and the self-serve
//! key. The kernel mounts the path and reaches this flow through its seam ([`SEAM`]); it names no
//! page, cookie or brand. Every byte here is 1.5.5's.
//!
//! SECURITY: `state` is validated before identity is established; the `client_secret` is the
//! plugin's (lent at `open`, never in the cookie, never logged, never rendered); the login page
//! issues via the shared self-serve seam.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use base64::Engine as _;

use busbar_contract::auth::{BeginLogin, CompleteLogin, LoginOutcome, Principal};
use busbar_contract::auth_calls::LoginCallback;
use busbar_kernel::auth::login::seam::{Answer, FormAnswer, LoginSeam};
use busbar_kernel::auth::login::{
    issue_self_key, login_method, login_methods, login_step, LoginStep, SelfKeyIssue,
};
use busbar_kernel::state::{App, AppHandle};

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

/// `GET /auth/token`: the hosted browser-login page. Reads the query to pick chooser / begin /
/// callback. Mounted DATA-plane only; the auth middleware bypasses this exact path.
async fn browser(handle: Arc<AppHandle>, req: Request<Body>) -> Response {
    let app = handle.load();
    // Extract everything needed from `req` UP FRONT (owned) — never hold `&Request<Body>` across an
    // `.await` (axum's `Body` is not `Sync`, so the handler future would not be `Send`).
    let params = parse_query(req.uri().query().unwrap_or(""));
    let cookie_raw = read_cookie(&req);
    // The navigation's `Sec-Fetch-Site`, read for [`refresh_rotates`] (absent: an old browser or a
    // non-browser).
    let sec_fetch_site = req
        .headers()
        .get("sec-fetch-site")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
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
        // `?refresh=1` marks a ROTATE ("Refresh key"): the completing handler mints with refresh=true,
        // under the rule [`refresh_rotates`] states.
        Some(method) => {
            let refresh = refresh_rotates(
                get("refresh").as_deref() == Some("1"),
                sec_fetch_site.as_deref(),
            );
            begin(&app, &method, refresh).await
        }
        None => chooser(&app),
    }
}

/// Whether a `?refresh=1` rotation is honoured only on a navigation from busbar's OWN page
/// (`Sec-Fetch-Site: same-origin`, the key-issued page's "Refresh key" link). A rotate revokes the
/// user's key, and any site can navigate a signed-in user to `?refresh=1` while the IdP approves
/// silently (K3 #20). 1.5.5 rotated whatever the navigation's origin (v1.5.5
/// crates/busbar/src/auth/token.rs:324). OWNER-SIGNED 2026-10-24 (M29): only a same-origin navigation
/// rotates; any other `?refresh=1` is a plain issue that re-shows the key.
pub(crate) const REFRESH_NEEDS_SAME_ORIGIN: bool = true;

/// Whether a `begin` asked to rotate (`refresh_param`) rotates the key, given the navigation's
/// `Sec-Fetch-Site`, under [`REFRESH_NEEDS_SAME_ORIGIN`].
fn refresh_rotates(refresh_param: bool, sec_fetch_site: Option<&str>) -> bool {
    refresh_rotates_under(REFRESH_NEEDS_SAME_ORIGIN, refresh_param, sec_fetch_site)
}

/// [`refresh_rotates`] under a stated `needs_same_origin`. Browsers set `Sec-Fetch-Site` themselves
/// and a page cannot forge it: `cross-site` is a link from another site, `none` a typed, bookmarked
/// or mail-app URL, `same-site` a sibling subdomain, and an absent header an old browser or a
/// non-browser. With `needs_same_origin`, only `same-origin` rotates; every other navigation is a
/// plain issue that re-shows the key.
fn refresh_rotates_under(
    needs_same_origin: bool,
    refresh_param: bool,
    sec_fetch_site: Option<&str>,
) -> bool {
    refresh_param && (!needs_same_origin || sec_fetch_site == Some("same-origin"))
}

/// The chooser: one button per method that has a `browser_login` block, in config order.
fn chooser(app: &App) -> Response {
    let base_url = app.public_url.as_deref().unwrap_or("");
    let buttons: Vec<(String, (String, &'static str))> = login_methods(app)
        .into_iter()
        .filter(|m| m.has_button)
        .map(|m| {
            let brand = button_brand(&m.name, m.issuer.as_deref());
            (m.name, brand)
        })
        .collect();
    html_no_store(render_chooser(&buttons, base_url))
}

/// begin: mint PKCE/state/nonce, call the module's `begin_login`, and either 302 to the IdP authorize
/// URL (REDIRECT flow) or render the credential FORM (CREDENTIAL flow). `refresh` marks a rotate.
async fn begin(app: &App, method: &str, refresh: bool) -> Response {
    if login_method(app, method).filter(|m| m.has_button).is_none() {
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
    // BOUNDED: this data-plane path is ANONYMOUSLY reachable, so the step holds a slot of the login
    // budget; it is submitted on the one dispatcher and awaited (no worker parked).
    let outcome = login_step(app, method, LoginStep::Begin(begin)).await;
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
    // 1.5.5 PARITY (Q128 p9#4, coordinator ruling 2026-10-19): the callback admits any method with
    // a button, a credential one included, and leaves the refusal of an authorization code it never
    // asked for to the plugin, exactly as 1.5.5's callback did (crates/busbar/src/auth/token.rs
    // :466-470 at v1.5.5 filters on `has_button` alone). A method-kind check here would answer 400
    // where 1.5.5 answered the plugin's verdict; pinned by
    // `a_credential_method_on_the_redirect_callback_is_answered_as_1_5_5_answered_it`.
    if login_method(app, &cookie.method)
        .filter(|m| m.has_button)
        .is_none()
    {
        return clear_and(error_page(
            StatusCode::BAD_REQUEST,
            "Sign-in method not found",
            "That sign-in method is no longer available. Head back and choose one of the listed \
             options.",
        ));
    }
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
    let principal = match login_step(app, &cookie.method, LoginStep::Complete(request)).await {
        LoginOutcome::Identify(p) => p,
        LoginOutcome::Outage => return clear_and(provider_unavailable(&cookie.method)),
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
/// POST (`credential_submit`): the kernel's self-serve seam issues the key
/// ([`busbar_kernel::auth::login::issue_self_key`], the SAME admission and mint the headless `POST`
/// uses; `refresh` rotates — the "Refresh key" action), and this renders the key-issued page or the
/// refusal's page. It NEVER clears the cookie (the caller wraps the result in `clear_and`).
async fn issue_and_render(
    app: &App,
    handle: &Arc<AppHandle>,
    module_name: &str,
    principal: Principal,
    refresh: bool,
) -> Response {
    match issue_self_key(app, handle, module_name, principal, refresh).await {
        SelfKeyIssue::Issued {
            subject,
            group,
            secret,
        } => {
            let base_url = app.public_url.as_deref().unwrap_or("");
            let page = render_key_issued(
                &subject,
                &group,
                // `.expose(..)`: the once-shown "key issued" page is the intended plaintext egress.
                secret.expose(&busbar_kernel::seal::lend()),
                base_url,
                module_name,
            );
            html_no_store(page)
        }
        // The mint ceiling refused the key this identity would mint (X-1001).
        SelfKeyIssue::OverCeiling => error_page(
            StatusCode::FORBIDDEN,
            "Key not permitted",
            "Your Busbar policy does not allow the key your account would be issued. Ask your \
             Busbar admin to review your access.",
        ),
        // No grant; or (only with the unsigned `SELF_MINT_HOLDS_ADMIN_AND_PROVIDER_STATE` on) the
        // subject's key is disabled, or another identity provider minted it: the same refusal page.
        SelfKeyIssue::NoGrant | SelfKeyIssue::Unbound => error_page(
            StatusCode::FORBIDDEN,
            "No access yet",
            "Your account isn't granted a self-serve key yet. Ask your Busbar admin to assign \
             you a role.",
        ),
        SelfKeyIssue::NoGovernance => error_page(
            StatusCode::BAD_GATEWAY,
            "Key issuing unavailable",
            "Busbar can't issue keys right now. Please contact your Busbar admin.",
        ),
        SelfKeyIssue::Failed => error_page(
            StatusCode::BAD_GATEWAY,
            "Couldn't issue your key",
            "We couldn't issue your key this time. Please head back and try again in a moment.",
        ),
    }
}

/// `credential_submit`: complete a CREDENTIAL-flow login. Called by the POST `/auth/token` handler
/// (`exchange`) when a login cookie is present. Validates CSRF (`__state` vs the cookie), builds
/// [`CompleteLogin`] from the submitted field values (each [`busbar_contract::redacted::Secret`]), runs the
/// module's `complete_login` (the plugin verifies the credential itself, e.g. an LDAP bind), and — on
/// `Identify` — issues through the SAME `issue_and_render` seam. Redirect methods never reach here.
async fn credential_submit(
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
    let Some(m) = login_method(app, &cookie.method).filter(|m| m.has_button) else {
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
    // Build the submitted map (every field EXCEPT the CSRF token), Secret the moment it is held.
    let submitted: Vec<(String, busbar_contract::redacted::Secret<String>)> = form
        .into_iter()
        .filter(|(k, _)| k != FORM_STATE_FIELD)
        .map(|(k, v)| (k, busbar_contract::redacted::Secret::new(v)))
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
    let outcome = login_step(app, &cookie.method, LoginStep::Complete(request)).await;
    let principal = match outcome {
        LoginOutcome::Identify(p) => p,
        LoginOutcome::Outage => return clear_and(provider_unavailable(&cookie.method)),
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

// ── PKCE + randomness ────────────────────────────────────────────────────────────────────────────

/// A URL-safe, no-pad base64 string of `n_bytes` of OS randomness.
fn random_b64url(n_bytes: usize) -> String {
    let mut buf = vec![0u8; n_bytes];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut buf)
        .expect("OS randomness for PKCE/state/nonce");
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

/// A sign-in button's brand — its label and icon — inferred from the method name and OIDC issuer
/// host, NOT from any operator-set display string. The brands are the root legacy table's
/// `login_brands` row (frozen 1.5.5 login-page data, `<match tokens> : <label> : <icon ref>` per
/// brand, in 1.5.5's match order): the first brand any of whose tokens the lower-cased method name
/// and issuer contain names the button; a method no brand matches is its title-cased name under the
/// generic icon. The kernel names no brand.
fn button_brand(name: &str, issuer: Option<&str>) -> (String, &'static str) {
    brand_from(
        busbar_kernel::config::legacy::text("login_brands"),
        name,
        issuer,
    )
}

/// [`button_brand`] over a given `login_brands` row (`""`: no row, every method generic).
fn brand_from(row: &str, name: &str, issuer: Option<&str>) -> (String, &'static str) {
    let hay = format!("{} {}", name, issuer.unwrap_or("")).to_ascii_lowercase();
    for brand in row.split(" | ").filter(|b| !b.is_empty()) {
        let mut fields = brand.split(" : ");
        let (Some(tokens), Some(label), Some(icon)) = (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        if tokens.split(' ').any(|t| !t.is_empty() && hay.contains(t)) {
            if let Some((_, svg)) = BRAND_ICONS.iter().find(|(r, _)| *r == icon) {
                return (label.to_string(), svg);
            }
        }
    }
    (titlecase(name), GENERIC_ICON)
}

/// The button icons a brand row names by its icon ref: plain assets, 1.5.5's own marks.
const BRAND_ICONS: &[(&str, &str)] = &[
    (
        "squares",
        r##"<svg class="picon" viewBox="0 0 21 21" aria-hidden="true"><rect x="1" y="1" width="9" height="9" fill="#f25022"/><rect x="11" y="1" width="9" height="9" fill="#7fba00"/><rect x="1" y="11" width="9" height="9" fill="#00a4ef"/><rect x="11" y="11" width="9" height="9" fill="#ffb900"/></svg>"##,
    ),
    (
        "octocat",
        r##"<svg class="picon" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0016 8c0-4.42-3.58-8-8-8z"/></svg>"##,
    ),
    (
        "g-mark",
        r##"<svg class="picon" viewBox="0 0 18 18" aria-hidden="true"><path fill="#4285F4" d="M17.64 9.2c0-.64-.06-1.25-.16-1.84H9v3.48h4.84a4.14 4.14 0 01-1.8 2.72v2.26h2.92c1.7-1.57 2.68-3.88 2.68-6.62z"/><path fill="#34A853" d="M9 18c2.43 0 4.47-.8 5.96-2.18l-2.92-2.26c-.8.54-1.84.86-3.04.86-2.34 0-4.32-1.58-5.03-3.7H.96v2.33A9 9 0 009 18z"/><path fill="#FBBC05" d="M3.97 10.72a5.4 5.4 0 010-3.44V4.95H.96a9 9 0 000 8.1l3.01-2.33z"/><path fill="#EA4335" d="M9 3.58c1.32 0 2.5.45 3.44 1.35l2.58-2.58C13.47.9 11.43 0 9 0A9 9 0 00.96 4.95l3.01 2.33C4.68 5.16 6.66 3.58 9 3.58z"/></svg>"##,
    ),
];

/// The generic sign-in icon (a key), for a method no brand matches.
const GENERIC_ICON: &str = r##"<svg class="picon" viewBox="0 0 16 16" fill="none" aria-hidden="true"><circle cx="6" cy="6" r="3.2" stroke="currentColor" stroke-width="1.4"/><path d="M8.3 8.3l4.2 4.2M10.5 12.5l1.2-1.2M12 11l1.2-1.2" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/></svg>"##;

const CHEVRON: &str = r##"<svg class="chev" viewBox="0 0 16 16" fill="none" aria-hidden="true"><path d="M6 4l4 4-4 4" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg>"##;

/// The alert glyph shown on a branded error page (a filled roundel with an exclamation).
const ERR_ICON: &str = r##"<svg viewBox="0 0 16 16" fill="none" aria-hidden="true"><path d="M8 4.5v4" stroke="currentColor" stroke-width="2" stroke-linecap="round"/><circle cx="8" cy="11.4" r="1.05" fill="currentColor"/></svg>"##;

/// The left-arrow shown on the "Back to sign in" link of a branded error page.
const BACK_ARROW: &str = r##"<svg viewBox="0 0 16 16" fill="none" aria-hidden="true"><path d="M9.5 4l-4 4 4 4" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/><path d="M5.5 8H12" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/></svg>"##;

/// The clipboard glyph shown on the "Copy" buttons of the key-issued (success) page.
const COPY_ICON: &str = r##"<svg viewBox="0 0 16 16" fill="none" aria-hidden="true"><rect x="5.5" y="5.5" width="8" height="8" rx="1.6" stroke="currentColor" stroke-width="1.4"/><path d="M3.4 10.4A1.5 1.5 0 012 9V3.4A1.5 1.5 0 013.4 2H9a1.5 1.5 0 011.4 1.4" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round"/></svg>"##;

/// The door/arrow-out glyph shown on the quiet "Sign out" link of the key-issued page.
const LOGOUT_ICON: &str = r##"<svg viewBox="0 0 16 16" fill="none" aria-hidden="true"><path d="M6.5 2.5H4A1.5 1.5 0 002.5 4v8A1.5 1.5 0 004 13.5h2.5" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round"/><path d="M10 10.5L12.5 8 10 5.5" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round"/><path d="M12.5 8H6.5" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/></svg>"##;

/// The page for an identity provider that could not answer: a login plugin that answered
/// `LOGIN_OUTAGE` ([`LoginOutcome::Outage`]), for an IdP that was unreachable or answered 5xx or
/// 429. 503, so the client may retry (owner ruling 2026-10-27; 1.5.5 answered 502), and the
/// refusal is logged with its cause and the login method.
fn provider_unavailable(method: &str) -> Response {
    tracing::warn!(
        method = %method,
        cause = "identity provider unavailable",
        "sign-in refused (503, retryable): the login plugin answered that the identity provider \
         could not answer"
    );
    provider_unreachable()
}

/// How long [`provider_unavailable`]'s `Retry-After` asks the client to wait, in seconds.
pub const PROVIDER_RETRY_AFTER_SECS: u64 = 5;

/// The page [`provider_unavailable`] renders: 503 with `Retry-After`. It never counts as a failed
/// login: nothing was declined.
fn provider_unreachable() -> Response {
    let mut page = error_page(
        StatusCode::SERVICE_UNAVAILABLE,
        "Couldn't reach your provider",
        "We couldn't reach your identity provider to finish signing you in. Please try again \
         shortly.",
    );
    page.headers_mut().insert(
        header::RETRY_AFTER,
        header::HeaderValue::from(PROVIDER_RETRY_AFTER_SECS),
    );
    page
}

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
fn render_chooser(buttons: &[(String, (String, &'static str))], base_url: &str) -> String {
    let mut body = String::new();
    if buttons.is_empty() {
        body.push_str(
            "<p class=\"sub\">No browser login is configured. Ask your Busbar admin, or use the \
             headless <span class=\"mono\">POST /auth/token</span> exchange.</p>",
        );
    } else {
        body.push_str("<div class=\"providers\">");
        for (name, (label, icon)) in buttons {
            let label = esc(label);
            body.push_str(&format!(
                "<a class=\"provider\" href=\"/auth/token?method={href}\" aria-label=\"Continue with {label}\">{icon}<span class=\"plabel\">Continue with {label}</span>{chev}</a>",
                href = esc(name),
                label = label,
                icon = icon,
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
    let (provider, _) = button_brand(method, None);
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
        provider = esc(&provider),
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

// ── the kernel's seam ────────────────────────────────────────────────────────────────────────────

/// The seam's `GET /auth/token` handler: [`browser`], boxed.
fn seam_browser(handle: Arc<AppHandle>, req: Request<Body>) -> Answer<Response> {
    Box::pin(browser(handle, req))
}

/// The seam's `POST /auth/token` handler: a CREDENTIAL-flow form submission carries the browser
/// login cookie (set by `begin` when a Credential method rendered its form) and is completed here;
/// a request with no login cookie is not the flow's and goes back to the headless exchange (a
/// CI/BYOK IdP-bearer exchange has none).
fn seam_credential_form(handle: Arc<AppHandle>, req: Request<Body>) -> Answer<FormAnswer> {
    Box::pin(async move {
        let Some(cookie) = read_cookie(&req) else {
            return Err(Box::new(req));
        };
        // Small, bounded read of the form body (credential fields + the CSRF `__state`).
        let bytes = axum::body::to_bytes(req.into_body(), 64 * 1024)
            .await
            .unwrap_or_default();
        let form = parse_query(&String::from_utf8_lossy(&bytes));
        let app = handle.load();
        Ok(credential_submit(&app, &handle, cookie, form).await)
    })
}

/// The flow's handlers, as `crate::install` registers them on the kernel.
pub(crate) const SEAM: LoginSeam = LoginSeam {
    browser: seam_browser,
    credential_form: seam_credential_form,
};

#[cfg(test)]
#[path = "tests/hosted_login_tests.rs"]
mod hosted_login_tests;
