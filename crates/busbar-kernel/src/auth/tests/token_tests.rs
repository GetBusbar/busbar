// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for the `GET /auth/token` hosted browser-login flow (1.5.2). `token_tests` is a
//! submodule of `auth::token`, so it can drive the private sub-state handlers (`chooser`/`begin`/
//! `callback`), the render fns, and the cookie/PKCE helpers directly. Every login plugin here is on
//! the auth kind's door ([`DoorLogin`]): the plugin makes its own token exchange and binds the IdP's
//! answer to the nonce itself; the host mints PKCE/state/nonce, checks `state`, bounds the
//! anonymous flood, and renders.

use super::*;
use busbar_contract::auth::{
    BeginLogin, FieldKind, LoginField, LoginForm, LoginKind, LoginOutcome, Principal,
};
use busbar_contract::auth_calls::{LoginCall, LoginCallback, LoginSettled};

/// A door stand-in: an opened `kind: auth` instance answering `begin_login`/`complete_login` (the
/// plugin on the auth kind's door), recording every `complete_login` it was handed. `park` holds
/// each answer back that long on a thread of its own — the dispatcher worker the plugin runs on —
/// never on the caller's. `faults`: every step FAULTS (the plugin broke its contract, a caught
/// panic), answered as the loader answers one: a Reject that says it faulted.
struct DoorLogin {
    kind: LoginKind,
    begin: LoginOutcome,
    complete: Box<dyn Fn(&LoginCallback) -> LoginOutcome + Send + Sync>,
    park: Option<std::time::Duration>,
    faults: bool,
    seen: std::sync::Mutex<Vec<LoginCallback>>,
}

impl DoorLogin {
    /// A redirect plugin whose authorize URL is the IdP's and whose `complete_login` answers
    /// `complete(request)`.
    fn answering(
        complete: impl Fn(&LoginCallback) -> LoginOutcome + Send + Sync + 'static,
    ) -> Self {
        Self {
            kind: LoginKind::Redirect,
            begin: LoginOutcome::Authorize("https://idp.example.com/authorize?x=1".into()),
            complete: Box::new(complete),
            park: None,
            faults: false,
            seen: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// A redirect plugin whose `complete_login` always answers `complete`.
    fn new(complete: LoginOutcome) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self::answering(move |_| complete.clone()))
    }

    /// The step's answer: on the spot, or after `park` from the plugin's own thread.
    fn answer(&self, outcome: LoginOutcome) -> Box<dyn LoginCall> {
        if self.faults {
            return Box::new(Faulted);
        }
        let Some(park) = self.park else {
            return Box::new(LoginSettled(Some(outcome)));
        };
        let (tx, rx) = tokio::sync::oneshot::channel();
        std::thread::spawn(move || {
            std::thread::sleep(park);
            let _ = tx.send(outcome);
        });
        Box::new(Parked(rx))
    }
}

/// A login step the plugin FAULTED: answered as a Reject, saying it faulted.
struct Faulted;

impl std::future::Future for Faulted {
    type Output = LoginOutcome;
    fn poll(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<LoginOutcome> {
        std::task::Poll::Ready(LoginOutcome::Reject)
    }
}

impl LoginCall for Faulted {
    fn settled(&mut self) -> Option<LoginOutcome> {
        Some(LoginOutcome::Reject)
    }
    fn faulted(&self) -> bool {
        true
    }
}

/// A login step the plugin answers later, from its own thread.
struct Parked(tokio::sync::oneshot::Receiver<LoginOutcome>);

impl std::future::Future for Parked {
    type Output = LoginOutcome;
    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<LoginOutcome> {
        std::future::Future::poll(std::pin::Pin::new(&mut self.0), cx)
            .map(|answer| answer.unwrap_or(LoginOutcome::Reject))
    }
}

impl LoginCall for Parked {
    fn settled(&mut self) -> Option<LoginOutcome> {
        self.0.try_recv().ok()
    }
}

impl busbar_contract::auth_calls::AuthCalls for DoorLogin {
    fn name(&self) -> &str {
        "door-login"
    }
    fn facts(&self) -> u32 {
        0
    }
    fn verify_now(
        &self,
        _: &busbar_contract::auth_calls::VerifyRequest,
    ) -> Option<busbar_contract::auth_calls::VerifyAnswer> {
        None
    }
    fn verify(
        &self,
        _: busbar_contract::auth_calls::VerifyRequest,
    ) -> Box<dyn busbar_contract::auth_calls::Verifying> {
        unreachable!("the login flow never verifies")
    }
    fn refresh(&self) -> Result<u64, String> {
        Ok(0)
    }
    fn login_kind(&self) -> Option<LoginKind> {
        Some(self.kind)
    }
    fn begin_login(&self, _: BeginLogin) -> Box<dyn LoginCall> {
        self.answer(self.begin.clone())
    }
    fn complete_login(&self, request: LoginCallback) -> Box<dyn LoginCall> {
        let outcome = (self.complete)(&request);
        self.seen.lock().unwrap().push(request);
        self.answer(outcome)
    }
}

/// The IdP's identity for a redirect login: alice, a `members`.
fn alice() -> LoginOutcome {
    let mut p = Principal::from_id("alice");
    p.roles = vec!["members".into()];
    LoginOutcome::Identify(p)
}

/// An app whose hosted-login methods are redirect plugins on the door, one per `(name, has_button)`.
fn test_app_with_methods(methods: Vec<(&str, bool)>) -> std::sync::Arc<crate::state::App> {
    let mut b = crate::test_support::TestApp::new().public_url("https://busbar.example.com");
    for (name, has_button) in methods {
        b = b.login_method_door(
            name,
            DoorLogin::new(alice()),
            LoginKind::Redirect,
            has_button,
        );
    }
    b.build()
}

// ── chooser ──────────────────────────────────────────────────────────────────────────────────────

#[test]
fn chooser_renders_0_1_n_buttons() {
    // 0 buttons (no browser_login method).
    let app0 = test_app_with_methods(vec![]);
    let body0 = body_of(chooser(&app0));
    assert_eq!(body0.matches("class=\"provider\"").count(), 0);
    assert!(body0.contains("No browser login"));

    // 1 button.
    let app1 = test_app_with_methods(vec![("microsoft", true)]);
    let body1 = body_of(chooser(&app1));
    assert_eq!(body1.matches("class=\"provider\"").count(), 1);
    assert!(body1.contains("/auth/token?method=microsoft"));

    // N buttons — plus a GUI-OFF method (has_button=false) that is ABSENT from the chooser.
    let appn = test_app_with_methods(vec![
        ("microsoft", true),
        ("github", true),
        ("headless-only", false),
    ]);
    let bodyn = body_of(chooser(&appn));
    assert_eq!(
        bodyn.matches("class=\"provider\"").count(),
        2,
        "only the two browser_login methods render buttons; the gui-off method is excluded"
    );
    assert!(
        !bodyn.contains("method=headless-only"),
        "gui-off method not shown"
    );
    // base_url is injected verbatim (no /v1).
    assert!(bodyn.contains("https://busbar.example.com"));
    assert!(!bodyn.contains("https://busbar.example.com/v1"));
}

/// A gui-off (no browser_login) method still works HEADLESS via POST /auth/token — the chooser
/// exclusion does not disable the method. (The POST path is unaffected; asserting the
/// route still serves POST is the observable proof here.)
#[tokio::test]
async fn gui_off_method_still_works_via_post() {
    let app = test_app_with_methods(vec![("headless-only", false)]);
    let (base, handle) = serve(app).await;
    let client = reqwest::Client::new();
    // POST /auth/token with no auth ⇒ the exchange runs the chain (401 unauth), NOT a 404/405: the
    // route exists and serves POST regardless of the chooser exclusion.
    let r = client
        .post(format!("{base}/auth/token"))
        .send()
        .await
        .unwrap();
    assert_ne!(r.status().as_u16(), 404, "POST /auth/token must exist");
    assert_ne!(r.status().as_u16(), 405, "POST /auth/token must be allowed");
    handle.abort();
}

// ── begin: PKCE + cookie ─────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn begin_sets_httponly_secure_cookie_and_redirects() {
    let app = test_app_with_methods(vec![("microsoft", true)]);
    let resp = begin(&app, "microsoft", false).await;
    assert_eq!(resp.status().as_u16(), 302);
    let loc = resp.headers().get("location").unwrap().to_str().unwrap();
    assert!(loc.starts_with("https://idp.example.com/authorize"));
    let sc = resp.headers().get("set-cookie").unwrap().to_str().unwrap();
    assert!(sc.contains("HttpOnly"), "cookie must be HttpOnly: {sc}");
    assert!(sc.contains("Secure"), "cookie must be Secure: {sc}");
    assert!(
        sc.contains("SameSite=Lax"),
        "cookie must be SameSite=Lax: {sc}"
    );
    // The cookie carries no secret — only method/verifier/state/nonce.
    let raw = sc
        .split(';')
        .next()
        .unwrap()
        .strip_prefix(&format!("{LOGIN_COOKIE}="))
        .unwrap();
    let cookie = LoginCookie::decode(raw).expect("cookie round-trips");
    assert_eq!(cookie.method, "microsoft");
    assert!(
        !cookie.code_verifier.is_empty() && !cookie.state.is_empty() && !cookie.nonce.is_empty()
    );
}

/// An authorize URL a `HeaderValue` cannot represent must FAIL CLOSED, not panic. `Location` carries
/// `LoginOutcome::Authorize(url)` verbatim from the login plugin — the one plugin-authored header on
/// this path — and `GET /auth/token` is anonymously reachable with no catch-panic layer anywhere in
/// the tree, so building the 302 with `.expect("static 302")` turns a login-module bug (a raw newline
/// interpolated into a hint, say) into a dead request task and an aborted connection. Each byte class
/// below is one `HeaderValue` refuses; obs-text (>= 0x80) is NOT among them, so a non-ASCII authorize
/// URL is representable and still redirects (not asserted here — this test only pins the refused set).
#[tokio::test]
async fn begin_with_an_unrepresentable_authorize_url_fails_closed_not_panics() {
    for bad in [
        "https://idp.example.com/authorize\r\nX-Evil: 1", // CRLF
        "https://idp.example.com/authorize\nX-Evil: 1",   // bare LF
        "https://idp.example.com/authorize?x=\u{0}",      // NUL
        "https://idp.example.com/authorize?x=\u{7f}",     // DEL
    ] {
        let app = crate::test_support::TestApp::new()
            .public_url("https://busbar.example.com")
            .login_method_door(
                "microsoft",
                std::sync::Arc::new(DoorLogin {
                    begin: LoginOutcome::Authorize(bad.to_string()),
                    ..DoorLogin::answering(|_| alice())
                }),
                LoginKind::Redirect,
                true,
            )
            .build();
        let resp = begin(&app, "microsoft", false).await;
        assert_eq!(
            resp.status().as_u16(),
            502,
            "an unrepresentable authorize URL must fail closed as a misbehaving module: {bad:?}"
        );
        assert!(
            resp.headers().get("location").is_none(),
            "no Location may be emitted for {bad:?}"
        );
        assert!(
            resp.headers().get("set-cookie").is_none(),
            "no login cookie may be handed out for {bad:?}"
        );
    }
}

// ── callback: state + nonce guards ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn callback_state_mismatch_400() {
    let door = DoorLogin::new(alice());
    let app = crate::test_support::TestApp::new()
        .public_url("https://busbar.example.com")
        .login_method_door("microsoft", door.clone(), LoginKind::Redirect, true)
        .build();
    let cookie = LoginCookie {
        method: "microsoft".into(),
        code_verifier: "v".into(),
        state: "the-real-state".into(),
        nonce: "n".into(),
        refresh: false,
    };
    // Wrong state ⇒ 400 BEFORE the plugin is asked anything (no token exchange is started).
    let resp = callback(
        &app,
        &cred_handle(&app),
        Some(cookie.encode()),
        "code123".into(),
        Some("WRONG-STATE".into()),
    )
    .await;
    assert_eq!(
        resp.status().as_u16(),
        400,
        "state mismatch must be a clean 400"
    );
    // Absent cookie ⇒ 400 too.
    let resp2 = callback(
        &app,
        &cred_handle(&app),
        None,
        "code123".into(),
        Some("the-real-state".into()),
    )
    .await;
    assert_eq!(resp2.status().as_u16(), 400, "no cookie ⇒ 400");
    assert!(
        door.seen.lock().unwrap().is_empty(),
        "no complete_login is handed to the plugin on a refused callback"
    );
}

/// NONCE BINDING: the host hands the plugin the nonce it minted at `begin` (carried in the cookie),
/// and the plugin binds the IdP's identity token to it. An IdP whose id_token carries ANOTHER nonce
/// is a failed security check: rejected, no key issued.
#[tokio::test]
async fn callback_nonce_mismatch_rejected() {
    // The IdP's id_token carries `WRONG-NONCE`; the plugin compares it with the nonce it was handed.
    let door = std::sync::Arc::new(DoorLogin::answering(|request| {
        if request.nonce.as_deref() == Some("WRONG-NONCE") {
            alice()
        } else {
            LoginOutcome::SecurityCheckFailed
        }
    }));
    let app = crate::test_support::TestApp::new()
        .public_url("https://busbar.example.com")
        .login_method_door("microsoft", door.clone(), LoginKind::Redirect, true)
        .build();
    let cookie = LoginCookie {
        method: "microsoft".into(),
        code_verifier: "v".into(),
        state: "st".into(),
        nonce: "the-core-nonce".into(),
        refresh: false,
    };
    let resp = callback(
        &app,
        &cred_handle(&app),
        Some(cookie.encode()),
        "code123".into(),
        Some("st".into()),
    )
    .await;
    assert_eq!(
        resp.status().as_u16(),
        400,
        "an id_token whose nonce ≠ the cookie nonce must be rejected (no key issued)"
    );
    assert!(!body_of(resp).contains("bbk_"), "no key issued");
    assert_eq!(
        door.seen.lock().unwrap()[0].nonce.as_deref(),
        Some("the-core-nonce"),
        "the plugin is handed the cookie's nonce"
    );
}

// ── branded error pages (hosted browser flow) vs JSON (headless API) ─────────────────────────────

/// Markers of the shared branded error card (see `token::error_page`): the Busbar brand lockup, the
/// alert glyph roundel, the error heading/message, and the "Back to sign in" link to GET /auth/token.
fn assert_branded_error_page(body: &str, heading: &str) {
    assert!(
        body.starts_with("<!doctype html>"),
        "a browser-flow failure must be a full styled HTML document, not plain text: {body}"
    );
    assert!(
        body.contains("class=\"wordmark\">Busbar"),
        "the error card carries the Busbar brand lockup: {body}"
    );
    assert!(
        body.contains("class=\"erricon\""),
        "the error card shows the alert glyph: {body}"
    );
    // The heading is server-escaped in the page (e.g. `'` → `&#39;`), so compare against the escaped
    // form the renderer emits.
    let heading_esc = heading.replace('\'', "&#39;");
    assert!(
        body.contains(&heading_esc),
        "the error card heading is human-readable ({heading}): {body}"
    );
    assert!(
        body.contains("class=\"backlink\"") && body.contains("href=\"/auth/token\""),
        "the error card links back to sign in: {body}"
    );
    assert!(
        body.contains("Back to sign in"),
        "the back link is labeled: {body}"
    );
}

/// A browser-flow failure (here a callback `state` mismatch) renders the BRANDED, styled
/// HTML error page — not bare plain text — with the correct status. Before this change: the
/// callback returned `(400, "state mismatch")` plain text (no `<!doctype`, no error card).
#[tokio::test]
async fn browser_callback_failure_renders_branded_html() {
    let app = test_app_with_methods(vec![("microsoft", true)]);
    let cookie = LoginCookie {
        method: "microsoft".into(),
        code_verifier: "v".into(),
        state: "the-real-state".into(),
        nonce: "n".into(),
        refresh: false,
    };
    let resp = callback(
        &app,
        &cred_handle(&app),
        Some(cookie.encode()),
        "code123".into(),
        Some("WRONG-STATE".into()),
    )
    .await;
    assert_eq!(resp.status().as_u16(), 400);
    // A failed browser login must still clear the single-use cookie.
    assert!(resp
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .any(|v| v.to_str().unwrap_or("").contains("Max-Age=0")));
    let body = body_of(resp);
    assert_branded_error_page(&body, "Sign-in couldn't be verified");
    assert!(
        !body.contains("state mismatch"),
        "the internal reason is not leaked to the user: {body}"
    );
}

/// The flagship copy case: a verified identity with NO self-serve grant gets the friendly "No access
/// yet" card (403), not the bare "no self-serve grant for this identity" text. Driven through the FULL
/// redirect callback (the plugin `Identify`s) with no role binding ⇒ `Unbound`.
#[tokio::test]
async fn no_self_serve_grant_renders_branded_html() {
    // No governance / role_bindings ⇒ the Identified principal resolves to `Unbound`.
    let app = test_app_with_methods(vec![("microsoft", true)]);
    let cookie = LoginCookie {
        method: "microsoft".into(),
        code_verifier: "v".into(),
        state: "st".into(),
        nonce: "match-nonce".into(),
        refresh: false,
    };
    let resp = callback(
        &app,
        &cred_handle(&app),
        Some(cookie.encode()),
        "code123".into(),
        Some("st".into()),
    )
    .await;
    assert_eq!(resp.status().as_u16(), 403, "no grant ⇒ 403");
    let body = body_of(resp);
    assert_branded_error_page(&body, "No access yet");
    assert!(
        body.contains("admin"),
        "the copy tells the user to ask their admin: {body}"
    );
}

/// A rejected credential (wrong password) renders the branded 401 card via the POST/credential path,
/// which is ALSO a browser flow (it carries the login cookie).
#[tokio::test]
async fn credential_reject_renders_branded_html() {
    let app = cred_app();
    let form = vec![
        ("__state".to_string(), "csrf-1".to_string()),
        ("username".to_string(), "alice".to_string()),
        ("password".to_string(), "WRONG".to_string()),
    ];
    let resp =
        credential_submit(&app, &cred_handle(&app), cred_cookie("csrf-1", false), form).await;
    assert_eq!(resp.status().as_u16(), 401);
    assert_branded_error_page(&body_of(resp), "Sign-in was declined");
}

/// GATE ON THE BRANCH: the HEADLESS/API path (POST /auth/token, no login cookie — a curl/CI client)
/// keeps returning the JSON `{"error":…}` shape. HTML is the BROWSER branch only; the API must never
/// receive a styled page. Here an unauthenticated POST ⇒ 401 JSON, not the branded HTML card.
#[tokio::test]
async fn api_json_path_stays_json_not_html() {
    let app = test_app_with_methods(vec![("microsoft", true)]);
    let (base, handle) = serve(app).await;
    let client = reqwest::Client::new();
    let r = client
        .post(format!("{base}/auth/token"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status().as_u16(),
        401,
        "unauthenticated API exchange ⇒ 401"
    );
    let ctype = r
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(
        ctype.contains("application/json"),
        "the API path returns JSON, not text/html: {ctype}"
    );
    let body = r.text().await.unwrap();
    assert!(
        !body.contains("<!doctype") && !body.contains("class=\"backlink\""),
        "the API path must NOT return the styled HTML error card: {body}"
    );
    let json: serde_json::Value = serde_json::from_str(&body).expect("API error is JSON");
    assert!(
        json.get("error").and_then(|e| e.as_str()).is_some(),
        "the API keeps the {{\"error\":…}} shape: {body}"
    );
    handle.abort();
}

// ── credential flow: Prompt form, POST submit, Refresh rotation ──────────────────────────────────

/// A CREDENTIAL-kind login plugin on the door (the LDAP shape): begin returns a `Prompt` form;
/// complete verifies the submitted username/password ITSELF and `Identify`s (no client_secret).
fn cred_login() -> std::sync::Arc<DoorLogin> {
    std::sync::Arc::new(DoorLogin {
        kind: LoginKind::Credential,
        begin: LoginOutcome::Prompt(LoginForm {
            fields: vec![
                LoginField {
                    name: "username".into(),
                    label: "Username".into(),
                    kind: FieldKind::Text,
                    required: true,
                },
                LoginField {
                    name: "password".into(),
                    label: "Password".into(),
                    kind: FieldKind::Password,
                    required: true,
                },
            ],
        }),
        ..DoorLogin::answering(|request| {
            let get = |k: &str| {
                request
                    .login
                    .submitted
                    .iter()
                    .find(|(n, _)| n == k)
                    .map(|(_, v)| v.expose_secret().as_str())
            };
            if get("username") == Some("alice") && get("password") == Some("pw") {
                let mut p = Principal::from_id("test-login-double:alice");
                p.roles = vec!["members".into()];
                LoginOutcome::Identify(p)
            } else {
                LoginOutcome::Reject
            }
        })
    })
}

fn cred_gov() -> std::sync::Arc<crate::governance::GovState> {
    std::sync::Arc::new(
        crate::governance::GovState::new_with_signer(
            std::sync::Arc::new(crate::governance::MemoryStore::new()),
            None,
            Some(crate::governance::signing::TokenSigner::from_secret_bytes(
                &[7u8; 32],
                crate::governance::signing::DEFAULT_KID,
            )),
        )
        .unwrap(),
    )
}

fn cred_bindings() -> crate::config::RoleBindings {
    use std::collections::BTreeMap;
    let mut role = BTreeMap::new();
    role.insert(
        "members".to_string(),
        crate::config::RoleBindingCfg {
            allowed_pools: None,
            group: Some("team".into()),
            admin_scope: None,
        },
    );
    let mut outer: crate::config::RoleBindings = BTreeMap::new();
    outer.insert("test-login-double".to_string(), role);
    outer
}

fn cred_app() -> std::sync::Arc<crate::state::App> {
    // The `team` group the role binds to MUST be a real configured group (parent of the
    // auto-provisioned `user:<sub>` leaf), carrying a `child_default` the leaf inherits — the
    // production shape (role_bindings.<module>.<role>.group names a configured team).
    let team: crate::config::GroupCfg =
        serde_yaml::from_str("child_default:\n  limits:\n    - { budget: 500, per: month }\n")
            .expect("team group parses");
    let mut groups = std::collections::BTreeMap::new();
    groups.insert("team".to_string(), team);
    crate::test_support::TestApp::new()
        .public_url("https://busbar.example.com")
        .governance(cred_gov())
        .role_bindings(cred_bindings())
        .groups_tree(groups)
        .login_method_door(
            "test-login-double",
            cred_login(),
            LoginKind::Credential,
            true,
        )
        .build()
}

/// Wrap a `cred_app` snapshot in a live `AppHandle` so `credential_submit` can auto-provision the
/// `user:<sub>` leaf (persist-then-swap) exactly as the running server does.
fn cred_handle(app: &std::sync::Arc<crate::state::App>) -> std::sync::Arc<crate::state::AppHandle> {
    std::sync::Arc::new(crate::state::AppHandle::new(app.clone()))
}

fn cred_cookie(state: &str, refresh: bool) -> String {
    LoginCookie {
        method: "test-login-double".into(),
        code_verifier: String::new(),
        state: state.into(),
        nonce: String::new(),
        refresh,
    }
    .encode()
}

/// Extract the first `bbk_…` token from a rendered page.
fn extract_key(body: &str) -> String {
    let start = body.find("bbk_").expect("a bbk_ key in the issued page");
    body[start..]
        .chars()
        .take_while(|c| c.is_alphanumeric() || matches!(c, '_' | '-' | '.'))
        .collect()
}

/// A Credential method's `begin` renders the declared FORM (not a 302): a text `username` and a
/// MASKED `password`, POSTing to /auth/token with a hidden CSRF `__state`.
#[tokio::test]
async fn credential_begin_renders_the_form() {
    let app = cred_app();
    let resp = begin(&app, "test-login-double", false).await;
    assert_eq!(
        resp.status().as_u16(),
        200,
        "credential begin renders a form, not a 302"
    );
    let body = body_of(resp);
    assert!(body.contains("method=\"post\"") && body.contains("action=\"/auth/token\""));
    assert!(body.contains("name=\"username\"") && body.contains("type=\"text\""));
    assert!(
        body.contains("name=\"password\"") && body.contains("type=\"password\""),
        "the password field must be masked"
    );
    assert!(
        body.contains("name=\"__state\""),
        "a CSRF field must be present"
    );
}

/// A Redirect method's `begin` still 302s (credential UI must not change the OAuth path).
#[tokio::test]
async fn redirect_begin_still_redirects() {
    let app = test_app_with_methods(vec![("microsoft", true)]);
    let resp = begin(&app, "microsoft", false).await;
    assert_eq!(resp.status().as_u16(), 302);
}

/// POSTing valid credentials runs `complete_login` (which reads the SUBMITTED map) and issues a key
/// through the SAME seam — grouped under `user:test-login-double:alice` (the module-namespaced sub).
#[tokio::test]
async fn credential_submit_issues_via_shared_seam() {
    let app = cred_app();
    let form = vec![
        ("__state".to_string(), "csrf-1".to_string()),
        ("username".to_string(), "alice".to_string()),
        ("password".to_string(), "pw".to_string()),
    ];
    let resp =
        credential_submit(&app, &cred_handle(&app), cred_cookie("csrf-1", false), form).await;
    assert_eq!(resp.status().as_u16(), 200);
    let body = body_of(resp);
    assert!(
        body.contains("test-login-double:alice"),
        "the issued page shows the identity: {body}"
    );
    // The issued token verifies through the ordinary path.
    let key = extract_key(&body);
    assert!(app
        .governance
        .as_ref()
        .unwrap()
        .verify_token(&key, busbar_kernel::store::now(), None)
        .is_some());
}

/// Wrong credentials → the plugin `Reject`s → 401, no key.
#[tokio::test]
async fn credential_submit_wrong_password_401() {
    let app = cred_app();
    let form = vec![
        ("__state".to_string(), "csrf-1".to_string()),
        ("username".to_string(), "alice".to_string()),
        ("password".to_string(), "WRONG".to_string()),
    ];
    let resp =
        credential_submit(&app, &cred_handle(&app), cred_cookie("csrf-1", false), form).await;
    assert_eq!(resp.status().as_u16(), 401);
}

/// CSRF: a form `__state` that does not match the cookie is a clean 400 (no complete_login).
#[tokio::test]
async fn credential_submit_state_mismatch_400() {
    let app = cred_app();
    let form = vec![
        ("__state".to_string(), "WRONG".to_string()),
        ("username".to_string(), "alice".to_string()),
        ("password".to_string(), "pw".to_string()),
    ];
    let resp =
        credential_submit(&app, &cred_handle(&app), cred_cookie("csrf-1", false), form).await;
    assert_eq!(resp.status().as_u16(), 400);
}

/// The WIRED Refresh action ROTATES: a refresh-marked submit yields a DIFFERENT key, and the prior
/// token STOPS verifying. Before the wiring: Refresh re-hit `issue_self` (idempotent) → same key,
/// old token still valid.
#[tokio::test]
async fn refresh_rotates_key_and_revokes_the_old_one() {
    let app = cred_app();
    let creds = || {
        vec![
            ("username".to_string(), "alice".to_string()),
            ("password".to_string(), "pw".to_string()),
        ]
    };
    // First login (issue).
    let mut f1 = vec![("__state".to_string(), "s1".to_string())];
    f1.extend(creds());
    let body1 =
        body_of(credential_submit(&app, &cred_handle(&app), cred_cookie("s1", false), f1).await);
    let key1 = extract_key(&body1);
    // Refresh (rotate).
    let mut f2 = vec![("__state".to_string(), "s2".to_string())];
    f2.extend(creds());
    let body2 =
        body_of(credential_submit(&app, &cred_handle(&app), cred_cookie("s2", true), f2).await);
    let key2 = extract_key(&body2);

    assert_ne!(key1, key2, "Refresh must mint a DIFFERENT token");
    let gov = app.governance.as_ref().unwrap();
    let now = busbar_kernel::store::now();
    assert!(
        gov.verify_token(&key1, now, None).is_none(),
        "the prior token must stop verifying after Refresh (rotation)"
    );
    assert!(
        gov.verify_token(&key2, now, None).is_some(),
        "the new token verifies"
    );
}

// ── config: client_secret required/absent per login_kind ─────────────────────────────────────────

#[test]
fn browser_login_secret_required_for_redirect_absent_for_credential() {
    use busbar_contract::auth::LoginKind;
    // Redirect (OAuth confidential client): secret REQUIRED.
    assert!(validate_browser_login_secret(LoginKind::Redirect, true).is_ok());
    assert!(
        validate_browser_login_secret(LoginKind::Redirect, false).is_err(),
        "a redirect method with no client_secret must be refused"
    );
    // Credential (LDAP/AD-bind): secret must be ABSENT.
    assert!(validate_browser_login_secret(LoginKind::Credential, false).is_ok());
    assert!(
        validate_browser_login_secret(LoginKind::Credential, true).is_err(),
        "a credential method that sets client_secret must be refused"
    );
}

// ── render: base_url verbatim ────────────────────────────────────────────────────────────────────

#[test]
fn key_page_injects_base_url_verbatim() {
    let page = render_key_issued(
        "sam@acme.com",
        "user:sam",
        "bb_live_7Qm2",
        "https://busbar.example.com",
        "microsoft",
    );
    assert!(
        page.contains("https://busbar.example.com"),
        "base_url must be rendered verbatim"
    );
    assert!(
        !page.contains("https://busbar.example.com/v1"),
        "base_url must NOT carry a /v1 suffix (BYOK clients append their own)"
    );
    assert!(page.contains("bb_live_7Qm2"), "the key is shown");
    // Re-showable, not shown-once: a Refresh action re-hits the exchange.
    assert!(page.contains("Refresh key"));
    assert!(page.contains("/auth/token?method=microsoft"));
    assert!(!page.contains("won't see this key again"));
}

/// The success page carries ONE-CLICK COPY: a `.copy` button beside the key and a `.copymini` button
/// for the BYOK block, each wired to the inline `bbCopy` handler with the exact value to copy in
/// `data-copy`. Before this change: the key/BYOK block rendered with no copy button at all.
#[test]
fn key_page_has_copy_buttons_wired_to_clipboard() {
    let page = render_key_issued(
        "sam@acme.com",
        "user:sam",
        "bb_live_7Qm2",
        "https://busbar.example.com",
        "microsoft",
    );
    // The inline clipboard handler ships with the page (Clipboard API + execCommand fallback).
    assert!(
        page.contains("function bbCopy(") && page.contains("navigator.clipboard"),
        "the self-contained copy JS is inlined"
    );
    assert!(
        page.contains("document.execCommand('copy')"),
        "a non-secure-context fallback is present"
    );
    // Key copy button: correct class, accessible label, click wiring, and the key as the copy value.
    assert!(
        page.contains("class=\"copy\"")
            && page.contains("aria-label=\"Copy your API key\"")
            && page.contains("onclick=\"bbCopy(this)\""),
        "the key has an accessible, wired Copy button: {page}"
    );
    assert!(
        page.contains("data-copy=\"bb_live_7Qm2\""),
        "the key Copy button carries the key value to copy: {page}"
    );
    // BYOK block copy button: copies the whole base_url + api_key pair (newline-separated).
    assert!(
        page.contains("class=\"copymini\"")
            && page.contains("aria-label=\"Copy the base URL and API key\""),
        "the BYOK block has its own Copy button: {page}"
    );
    assert!(
        page.contains(
            "data-copy=\"base_url: https://busbar.example.com&#10;api_key: bb_live_7Qm2\""
        ),
        "the BYOK Copy button copies the base_url + api_key block: {page}"
    );
    // A quiet, accessible "Sign out" exit that ends the browser view (so the key isn't left shown).
    assert!(
        page.contains("class=\"signout\"")
            && page.contains("href=\"/auth/token?logout=1\"")
            && page.contains("Sign out"),
        "the success page offers a Sign out control: {page}"
    );
}

/// The `?logout=1` "Sign out" action renders the branded "Signed out" page, EXPIRES the login cookie
/// (defensive — the flow is stateless post-issuance), and offers a clean "Sign in again" re-entry. It
/// does not revoke the key or the IdP session (honest copy). Before this change: `?logout=1` was
/// an unknown param that fell through to the chooser (no signed-out page, no cookie clear).
#[tokio::test]
async fn logout_renders_signed_out_and_clears_cookie() {
    let app = test_app_with_methods(vec![("microsoft", true)]);
    let handle = cred_handle(&app);
    let req = axum::http::Request::builder()
        .uri("/auth/token?logout=1")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = browser(axum::extract::State(handle), req).await;
    assert_eq!(resp.status().as_u16(), 200);
    // The single-use login cookie is expired on the way out.
    assert!(
        resp.headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .any(|v| v.to_str().unwrap_or("").contains("Max-Age=0")),
        "logout must clear the busbar login cookie"
    );
    let body = body_of(resp);
    assert!(body.starts_with("<!doctype html>"), "branded HTML card");
    assert!(body.contains("Signed out"), "the heading confirms sign-out");
    assert!(
        body.contains("href=\"/auth/token\"") && body.contains("Sign in again"),
        "offers a clean re-entry: {body}"
    );
    // Honest: we don't claim to revoke the key or end the IdP session.
    assert!(
        body.contains("doesn't revoke your key"),
        "copy is honest about scope: {body}"
    );
}

#[test]
fn pkce_code_challenge_is_s256_of_verifier() {
    use sha2::{Digest, Sha256};
    let verifier = random_b64url(32);
    let challenge = code_challenge_s256(&verifier);
    let expected = B64.encode(Sha256::digest(verifier.as_bytes()));
    assert_eq!(challenge, expected);
    // base64url no-pad ⇒ no '+', '/', or '=' in the challenge.
    assert!(!challenge.contains('+') && !challenge.contains('/') && !challenge.contains('='));
}

// ── routing: bypass + admin-absence ──────────────────────────────────────────────────────────────

/// GET AND POST `/auth/token` are exempt from the auth chain (they run it themselves); `/healthz`
/// stays exempt; `/metrics` still 401s; and the bypass is EXACT-MATCH (no `/auth` prefix over-match).
#[tokio::test]
async fn auth_token_bypasses_middleware_exact_match() {
    crate::snapshot::init();
    // A chain that 401s every un-exempt request: the built-in `keys` verifier with no key presented.
    let mut cfg = crate::config::AuthCfg::default_none();
    cfg.chain = vec![crate::config::AuthChainEntry::bare("keys")];
    let auth = std::sync::Arc::new(crate::auth::AuthMiddleware::new_builtin(&cfg));
    let app = crate::test_support::TestApp::new()
        .auth(auth)
        .public_url("https://busbar.example.com")
        .build();
    let (base, handle) = serve(app).await;
    let client = reqwest::Client::new();

    // GET /auth/token (chooser) is NOT 401 — it bypasses the chain.
    let g = client
        .get(format!("{base}/auth/token"))
        .send()
        .await
        .unwrap();
    assert_ne!(
        g.status().as_u16(),
        401,
        "GET /auth/token must bypass the chain"
    );
    assert!(g.status().is_success(), "chooser renders 200");
    // POST /auth/token also bypasses (runs the chain itself → unauth here, but not the middleware 401
    // envelope — it reaches the handler). Either way it is not a middleware short-circuit 404/405.
    let p = client
        .post(format!("{base}/auth/token"))
        .send()
        .await
        .unwrap();
    assert_ne!(p.status().as_u16(), 404);
    assert_ne!(p.status().as_u16(), 405);

    // /healthz stays exempt.
    let h = client.get(format!("{base}/healthz")).send().await.unwrap();
    assert!(h.status().is_success() || h.status().as_u16() == 503);

    // /metrics still goes through the chain ⇒ 401 (fingerprinting surface stays gated).
    let m = client.get(format!("{base}/metrics")).send().await.unwrap();
    assert_eq!(m.status().as_u16(), 401, "/metrics must still be gated");

    // EXACT-MATCH: a sibling path is NOT bypassed — it hits the chain (401) or 404, never the login
    // page. `/auth/tokenx` is not a real route ⇒ the fallback runs under the chain ⇒ 401.
    let x = client
        .get(format!("{base}/auth/tokenx"))
        .send()
        .await
        .unwrap();
    assert_ne!(
        x.status().as_u16(),
        200,
        "no /auth prefix over-match onto the login page"
    );
    handle.abort();
}

#[tokio::test]
async fn auth_token_absent_from_admin_router() {
    crate::snapshot::init();
    let app = crate::test_support::TestApp::new()
        .admin_chain(vec![]) // open admin posture so a hit would reach a handler, not 401
        .public_url("https://busbar.example.com")
        .build();
    let (data, admin, _handle) = crate::build_split_routers_with_limits(app, 1 << 20, 0, false);

    // Serve the ADMIN router: /auth/token must be ABSENT (404), while the DATA router serves it.
    let admin_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let admin_addr = admin_listener.local_addr().unwrap();
    let ah = tokio::spawn(async move { axum::serve(admin_listener, admin).await.unwrap() });
    let data_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let data_addr = data_listener.local_addr().unwrap();
    let dh = tokio::spawn(async move { axum::serve(data_listener, data).await.unwrap() });
    let client = reqwest::Client::new();

    let admin_hit = client
        .get(format!("http://{admin_addr}/auth/token"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        admin_hit.status().as_u16(),
        404,
        "/auth/token is data-plane only; it must be absent from the admin router"
    );
    let data_hit = client
        .get(format!("http://{data_addr}/auth/token"))
        .send()
        .await
        .unwrap();
    assert!(
        data_hit.status().is_success(),
        "the data router DOES serve /auth/token (control)"
    );
    ah.abort();
    dh.abort();
}

/// THE BYPASS IS PER-ROUTER, NOT PER-PROCESS (1.6.0).
/// `/auth/token` is mounted on the DATA router only (`auth_token_absent_from_admin_router` pins
/// that). Its auth bypass must be equally absent from the admin plane: a bypass declared by the
/// PROCESS rather than by the ROUTER that mounted the route means the admin listener waves through
/// a path it does not serve, answering an unauthenticated caller 404 (the path is unknown here)
/// instead of 401 (you are not admitted here). That is the exact drift a core route-auth table
/// generated at mount time exists to make impossible.
#[tokio::test]
async fn auth_token_bypass_does_not_apply_on_the_admin_router() {
    crate::snapshot::init();
    let app = crate::test_support::TestApp::new()
        .keys_chain() // a CLOSED data-plane posture: no credential ⇒ 401
        .public_url("https://busbar.example.com")
        .build();
    let (_data, admin, _handle) = crate::build_split_routers_with_limits(app, 1 << 20, 0, false);

    let admin_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let admin_addr = admin_listener.local_addr().unwrap();
    let ah = tokio::spawn(async move { axum::serve(admin_listener, admin).await.unwrap() });
    let client = reqwest::Client::new();

    let hit = client
        .get(format!("http://{admin_addr}/auth/token"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        hit.status().as_u16(),
        401,
        "the /auth/token bypass belongs to the DATA router that mounts it; on the admin router the \
         path is unmounted and unauthenticated, so the auth chain must answer it"
    );

    // /healthz IS mounted on the admin router and IS declared open there — the control that proves
    // the assertion above is about the declaration, not about admin being closed to everything.
    let health = client
        .get(format!("http://{admin_addr}/healthz"))
        .send()
        .await
        .unwrap();
    assert_ne!(
        health.status().as_u16(),
        401,
        "/healthz is declared open on the admin router and must stay open (this app has no lanes, \
         so the probe itself answers 503 — what matters is that auth did not answer it)"
    );
    ah.abort();
}

/// NEAR-MISS MATRIX for the core route-auth table (1.6.0).
/// A bypass is worth exactly as much as its exactness: a
/// declaration that matched a prefix, a trailing slash, a case fold, or any method would hand every
/// neighbouring path the same free pass, which is how an authorization server's public metadata
/// route ends up opening the routes beside it.
///
/// The METHOD axis is new with the table and is the one that could not be stated in terms of the
/// old middleware: the bypass was a bare path equality, so `PUT /auth/token` rode it and was
/// answered by axum's 405 without the chain ever running. A declaration is per method, so an
/// undeclared method on a declared-open path takes the normal bar.
#[tokio::test]
async fn core_route_bypass_is_exact_in_path_and_method() {
    crate::snapshot::init();
    let mut cfg = crate::config::AuthCfg::default_none();
    cfg.chain = vec![crate::config::AuthChainEntry::bare("keys")];
    let auth = std::sync::Arc::new(crate::auth::AuthMiddleware::new_builtin(&cfg));
    let app = crate::test_support::TestApp::new()
        .auth(auth)
        .public_url("https://busbar.example.com")
        .build();
    let (base, handle) = serve(app).await;
    let client = reqwest::Client::new();

    // Controls: the two declarations themselves, on their declared methods. HEAD is included
    // because axum serves it from the GET arm, so the table must resolve it there too — the
    // half-closed hazard `plugin_routes::route_method_of` already documents.
    for (method, path) in [
        (reqwest::Method::GET, "/healthz"),
        (reqwest::Method::HEAD, "/healthz"),
        (reqwest::Method::GET, "/auth/token"),
    ] {
        let r = client
            .request(method.clone(), format!("{base}{path}"))
            .send()
            .await
            .unwrap();
        assert_ne!(
            r.status().as_u16(),
            401,
            "{method} {path} is declared open and must bypass the chain"
        );
    }
    // POST /auth/token bypasses the MIDDLEWARE and then runs the chain in its own handler, so an
    // unauthenticated POST legitimately ends in 401 — from the handler, not from the middleware.
    // What proves the bypass is that the request REACHED a handler at all.
    let p = client
        .post(format!("{base}/auth/token"))
        .send()
        .await
        .unwrap();
    assert!(
        p.status().as_u16() != 404 && p.status().as_u16() != 405,
        "POST /auth/token is declared open and must reach its handler, which runs the chain itself"
    );

    // Near misses: every one takes the normal bar (401), never the bypass.
    for (method, path) in [
        (reqwest::Method::PUT, "/auth/token"),
        (reqwest::Method::DELETE, "/auth/token"),
        (reqwest::Method::PUT, "/healthz"),
        (reqwest::Method::GET, "/auth"),
        (reqwest::Method::GET, "/auth/"),
        (reqwest::Method::GET, "/auth/token/"),
        (reqwest::Method::GET, "/auth/tokenx"),
        (reqwest::Method::GET, "/healthz/"),
        (reqwest::Method::GET, "/healthzx"),
        (reqwest::Method::GET, "/HEALTHZ"),
        (reqwest::Method::GET, "/AUTH/TOKEN"),
        // Forward guards for the authorization-server surface (par. 5.3): none of these is mounted
        // yet, and until one is DECLARED open it must answer with the chain, not with a bypass.
        (reqwest::Method::GET, "/.well-known"),
        (
            reqwest::Method::GET,
            "/.well-known/oauth-authorization-server",
        ),
        (reqwest::Method::GET, "/oauth"),
        (reqwest::Method::GET, "/oauth/authorize"),
        (reqwest::Method::POST, "/oauth/token"),
    ] {
        let r = client
            .request(method.clone(), format!("{base}{path}"))
            .send()
            .await
            .unwrap();
        assert_eq!(
            r.status().as_u16(),
            401,
            "{method} {path} is a near miss on a declared-open route and must take the normal bar"
        );
    }
    handle.abort();
}

// ── test helpers: serve an app ───────────────────────────────────────────────────────────────────

async fn serve(app: std::sync::Arc<crate::state::App>) -> (String, tokio::task::JoinHandle<()>) {
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (format!("http://{addr}"), handle)
}

fn body_of(resp: Response) -> String {
    let bytes = futures::executor::block_on(async {
        axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap()
    });
    String::from_utf8(bytes.to_vec()).unwrap()
}

// ── the anonymous-flood class: a slow login plugin must not park Tokio workers ──────────────────

/// A login plugin on the door whose `begin_login` / `complete_login` answer only after `park`, the
/// way a real one does: an LDAP/AD bind or an OIDC token exchange is a network round-trip. The
/// plugin runs on its own (dispatcher) thread; the HOST, not the plugin, is responsible for awaiting
/// the step rather than parking a reactor worker on it.
fn parking_login(kind: LoginKind) -> std::sync::Arc<DoorLogin> {
    std::sync::Arc::new(DoorLogin {
        kind,
        begin: LoginOutcome::Authorize("https://idp.example.com/authorize".into()),
        park: Some(std::time::Duration::from_secs(3)),
        ..DoorLogin::answering(|_| LoginOutcome::Reject)
    })
}

/// The runtime this class is about: a SMALL, fixed worker pool, exactly like a busy node whose
/// workers are all already serving. Two workers makes "every worker is parked" reachable with a
/// handful of requests instead of a hundred; the defect is identical at 8 workers and 9 requests.
fn two_worker_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("test runtime")
}

/// Assert the runtime is STILL POLLING: spawn a trivial task (it needs a worker and nothing else —
/// this is `/healthz`, the admin plane, and every other in-flight request, in miniature) and wait for
/// it from OUTSIDE the runtime on wall-clock time.
///
/// The wait deliberately uses `std::thread::sleep` and `Instant`, never a Tokio timer: when every
/// worker is parked inside plugin FFI the TIME DRIVER is parked with them, so a `tokio::time::timeout`
/// does not fire either — it simply returns late, and the assertion it guards passes against a runtime
/// that was dead for the whole window. (Observed: a `sleep(300ms).await` inside `block_on` on such a
/// runtime returned at 12s, after the blocking tasks had drained.) Wall clock is the only honest
/// instrument here.
fn assert_runtime_still_polls(
    rt: &tokio::runtime::Runtime,
    budget: std::time::Duration,
    msg: &str,
) {
    let canary = rt.spawn(async {});
    let deadline = std::time::Instant::now() + budget;
    while std::time::Instant::now() < deadline {
        if canary.is_finished() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    panic!("{msg}");
}

/// UNAUTHENTICATED DATA PLANE. `GET /auth/token?method=…` is mounted on the DATA router
/// (`main.rs`'s data-router mount) and the auth middleware bypasses that exact path, so ANONYMOUS
/// callers reach `begin` — and `begin` asks the plugin's `begin_login`. Four concurrent
/// anonymous requests on a two-worker runtime must not stop the runtime from polling anything else.
#[test]
fn concurrent_anonymous_begin_does_not_starve_the_runtime() {
    let rt = two_worker_runtime();
    let app = rt.block_on(async {
        crate::test_support::TestApp::new()
            .public_url("https://busbar.example.com")
            .login_method_door(
                "test-login-double",
                parking_login(LoginKind::Redirect),
                LoginKind::Redirect,
                true,
            )
            .build()
    });
    // Four anonymous begins — two more than the runtime has workers.
    let tasks: Vec<_> = (0..4)
        .map(|_| {
            let a = app.clone();
            rt.spawn(async move { begin(&a, "test-login-double", false).await.status() })
        })
        .collect();
    // Wall-clock (not a Tokio timer): let the begins actually reach the plugin.
    std::thread::sleep(std::time::Duration::from_millis(200));
    assert_runtime_still_polls(
        &rt,
        std::time::Duration::from_millis(750),
        "the runtime stopped polling while four ANONYMOUS /auth/token begins sat inside the login \
         plugin's begin_login: every Tokio worker is parked on the plugin, so nothing else in \
         the process — other requests, the admin plane, /healthz — can run",
    );
    for t in tasks {
        rt.block_on(async { t.await.ok() });
    }
}

/// The credential POST (`POST /auth/token` carrying a login cookie) asks the plugin's
/// `complete_login` — the LDAP/AD bind itself. The `__state` CSRF check does not gate an attacker:
/// they call `begin` themselves and echo back the state from the cookie they were handed, which is
/// exactly what this test does. Same anonymous reachability, same runtime-starvation shape.
#[test]
fn concurrent_credential_submit_does_not_starve_the_runtime() {
    let rt = two_worker_runtime();
    let (app, handle) = rt.block_on(async {
        let app = crate::test_support::TestApp::new()
            .public_url("https://busbar.example.com")
            .login_method_door(
                "test-login-double",
                parking_login(LoginKind::Credential),
                LoginKind::Credential,
                true,
            )
            .build();
        let handle = std::sync::Arc::new(crate::state::AppHandle::new(app.clone()));
        (app, handle)
    });
    // The cookie an attacker mints for themselves by calling `begin` first — its `state` is theirs to
    // echo in `__state`, so CSRF is satisfied without any prior authentication.
    let cookie = LoginCookie {
        method: "test-login-double".to_string(),
        code_verifier: String::new(),
        state: "S".to_string(),
        nonce: String::new(),
        refresh: false,
    }
    .encode();
    let tasks: Vec<_> = (0..4)
        .map(|_| {
            let (a, h, c) = (app.clone(), handle.clone(), cookie.clone());
            rt.spawn(async move {
                credential_submit(
                    &a,
                    &h,
                    c,
                    vec![
                        (FORM_STATE_FIELD.to_string(), "S".to_string()),
                        ("password".to_string(), "hunter2".to_string()),
                    ],
                )
                .await
                .status()
            })
        })
        .collect();
    std::thread::sleep(std::time::Duration::from_millis(200));
    assert_runtime_still_polls(
        &rt,
        std::time::Duration::from_millis(750),
        "the runtime stopped polling while four ANONYMOUS credential POSTs sat inside the login \
         plugin's complete_login",
    );
    for t in tasks {
        rt.block_on(async { t.await.ok() });
    }
}

/// RED: a login plugin answering SecurityCheckFailed (the LOGIN_SECURITY_CHECK_FAILED verdict) on
/// the redirect callback renders 1.5.5's verification page (400 "Sign-in couldn't be verified",
/// no-store), byte for byte the page a `state` mismatch renders, and clears the login cookie.
#[tokio::test]
async fn callback_security_check_failed_renders_the_state_mismatch_bytes() {
    let app = crate::test_support::TestApp::new()
        .public_url("https://busbar.example.com")
        .login_method_door(
            "fails",
            DoorLogin::new(LoginOutcome::SecurityCheckFailed),
            LoginKind::Redirect,
            true,
        )
        .build();
    let cookie = LoginCookie {
        method: "fails".into(),
        code_verifier: "v".into(),
        state: "st".into(),
        nonce: "n".into(),
        refresh: false,
    };
    let failed = callback(
        &app,
        &cred_handle(&app),
        Some(cookie.encode()),
        "code".into(),
        Some("st".into()),
    )
    .await;
    let mismatch = callback(
        &app,
        &cred_handle(&app),
        Some(cookie.encode()),
        "code".into(),
        Some("WRONG".into()),
    )
    .await;
    assert_eq!(failed.status().as_u16(), 400);
    assert_eq!(failed.status(), mismatch.status());
    for h in [header::CACHE_CONTROL, header::SET_COOKIE] {
        assert_eq!(
            failed.headers().get(&h),
            mismatch.headers().get(&h),
            "{h} matches the state mismatch's"
        );
    }
    assert!(failed
        .headers()
        .get(header::SET_COOKIE)
        .is_some_and(|v| v.to_str().is_ok_and(|v| v.contains("Max-Age=0"))));
    let (a, b) = (body_of(failed), body_of(mismatch));
    assert!(
        a.contains("Sign-in couldn&#39;t be verified")
            || a.contains("Sign-in couldn't be verified")
    );
    assert_eq!(
        a, b,
        "one page for a state mismatch and a failed security check"
    );
}

// ── THE LOGIN ON THE AUTH KIND'S DOOR ─────────────────────────────────────────────────────────────
//
// A login plugin on the door (an IdP module the auth axis opened) makes its own token exchange over
// its own need with the client secret it was lent at `open`, and binds the IdP's answer to the
// login's nonce itself (THE DESIGN 6.7). The core still mints PKCE/state/nonce, checks `state`
// against the cookie before anything is asked, hands the plugin ONE `complete_login` carrying the
// cookie's state and nonce, and renders the plugin's answer as 1.5.5 rendered the same outcome.

fn door_app(door: std::sync::Arc<DoorLogin>) -> std::sync::Arc<crate::state::App> {
    crate::test_support::TestApp::new()
        .public_url("https://busbar.example.com")
        .login_method_door("idp", door, LoginKind::Redirect, true)
        .build()
}

fn door_cookie() -> LoginCookie {
    LoginCookie {
        method: "idp".into(),
        code_verifier: "the-verifier".into(),
        state: "st".into(),
        nonce: "the-core-nonce".into(),
        refresh: false,
    }
}

/// `begin` on the door 302s to the plugin's authorize URL and sets the login cookie.
#[tokio::test]
async fn a_door_login_begins_with_the_plugins_authorize_url() {
    let app = door_app(DoorLogin::new(LoginOutcome::Reject));
    let resp = begin(&app, "idp", false).await;
    assert_eq!(resp.status().as_u16(), 302);
    assert_eq!(
        resp.headers().get(header::LOCATION).unwrap(),
        "https://idp.example.com/authorize?x=1"
    );
    assert!(resp
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .any(|v| v.to_str().unwrap_or("").starts_with("busbar_login=")));
}

/// The callback hands the door ONE `complete_login` carrying the code, the redirect URI, the PKCE
/// verifier and the cookie's state and nonce (the plugin binds the IdP's answer to the nonce).
#[tokio::test]
async fn a_door_callback_hands_the_plugin_the_cookies_state_and_nonce() {
    let door = DoorLogin::new(LoginOutcome::Reject);
    let app = door_app(door.clone());
    let resp = callback(
        &app,
        &cred_handle(&app),
        Some(door_cookie().encode()),
        "the-code".into(),
        Some("st".into()),
    )
    .await;
    assert_eq!(resp.status().as_u16(), 401, "a declined login");
    let seen = door.seen.lock().unwrap();
    assert_eq!(seen.len(), 1, "one complete_login: {seen:?}");
    assert_eq!(seen[0].state, "st");
    assert_eq!(seen[0].nonce.as_deref(), Some("the-core-nonce"));
    assert_eq!(seen[0].login.code.as_deref(), Some("the-code"));
    assert_eq!(
        seen[0].login.redirect_uri.as_deref(),
        Some("https://busbar.example.com/auth/token")
    );
    assert_eq!(seen[0].login.code_verifier.as_deref(), Some("the-verifier"));
    assert!(
        seen[0].login.token_response.is_none(),
        "the core runs no token exchange for a door plugin"
    );
}

/// RED: a callback whose `state` is not the cookie's never reaches the door.
#[tokio::test]
async fn a_door_callback_with_a_foreign_state_asks_the_plugin_nothing() {
    let door = DoorLogin::new(LoginOutcome::Identify(Principal::from_id("alice")));
    let app = door_app(door.clone());
    let resp = callback(
        &app,
        &cred_handle(&app),
        Some(door_cookie().encode()),
        "the-code".into(),
        Some("FOREIGN".into()),
    )
    .await;
    assert_eq!(resp.status().as_u16(), 400);
    assert!(door.seen.lock().unwrap().is_empty());
}

/// Every door answer renders 1.5.5's page for the same outcome: a failed security check, an
/// unreachable IdP, a declined login, and an identity with no self-serve grant.
#[tokio::test]
async fn a_door_callback_renders_each_answer_on_its_page() {
    for (outcome, status, heading) in [
        (
            LoginOutcome::SecurityCheckFailed,
            400,
            "Sign-in couldn't be verified",
        ),
        (LoginOutcome::Reject, 401, "Sign-in was declined"),
        (
            LoginOutcome::Identify(Principal::from_id("alice")),
            403,
            "No access yet",
        ),
    ] {
        let app = door_app(DoorLogin::new(outcome.clone()));
        let resp = callback(
            &app,
            &cred_handle(&app),
            Some(door_cookie().encode()),
            "the-code".into(),
            Some("st".into()),
        )
        .await;
        assert_eq!(resp.status().as_u16(), status, "{outcome:?}");
        assert_branded_error_page(&body_of(resp), heading);
    }
    let app = door_app(DoorLogin::new(LoginOutcome::Outage));
    let unreachable = callback(
        &app,
        &cred_handle(&app),
        Some(door_cookie().encode()),
        "the-code".into(),
        Some("st".into()),
    )
    .await;
    let page = provider_unreachable();
    assert_eq!(unreachable.status(), page.status());
    assert_eq!(body_of(unreachable), body_of(page));
}

/// A login plugin that FAULTS (its SDK shim caught a panic and answered FAULT) on begin, on the
/// redirect callback and on the credential POST: each fails closed as the decline renders it, and
/// says so as 1.5.5 said a panicked login plugin call (4003 `login-plugin-panicked`, "login plugin
/// call panicked; rejecting (fail-closed)", naming the method and the op). RED arm: the SAME
/// outcome answered by a plugin that merely DECLINED says nothing — 4003 is the fault's, not the
/// Reject's.
#[test]
fn a_faulting_login_plugin_is_rejected_and_says_it_panicked_and_a_declining_one_says_nothing() {
    use tracing_subscriber::layer::SubscriberExt as _;
    let run = |faults: bool| {
        let door = |kind: LoginKind| {
            std::sync::Arc::new(DoorLogin {
                kind,
                faults,
                ..DoorLogin::answering(|_| LoginOutcome::Reject)
            })
        };
        let cap = crate::test_support::warn_capture::WarnCapture::default();
        let subscriber = tracing_subscriber::registry().with(cap.clone());
        let statuses = tracing::subscriber::with_default(subscriber, || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime");
            rt.block_on(async {
                let app = crate::test_support::TestApp::new()
                    .public_url("https://busbar.example.com")
                    .login_method_door("idp", door(LoginKind::Redirect), LoginKind::Redirect, true)
                    .login_method_door(
                        "test-login-double",
                        door(LoginKind::Credential),
                        LoginKind::Credential,
                        true,
                    )
                    .build();
                let handle = cred_handle(&app);
                let begun = begin(&app, "idp", false).await.status().as_u16();
                let called = callback(
                    &app,
                    &handle,
                    Some(door_cookie().encode()),
                    "the-code".into(),
                    Some("st".into()),
                )
                .await
                .status()
                .as_u16();
                let form = vec![
                    (FORM_STATE_FIELD.to_string(), "csrf-1".to_string()),
                    ("password".to_string(), "pw".to_string()),
                ];
                let submitted =
                    credential_submit(&app, &handle, cred_cookie("csrf-1", false), form)
                        .await
                        .status()
                        .as_u16();
                (begun, called, submitted)
            })
        });
        (statuses, cap.messages())
    };

    let (faulted, said) = run(true);
    assert_eq!(
        faulted,
        (502, 401, 401),
        "a faulting step fails closed as a decline renders it (begin, callback, credential POST)"
    );
    let panicked: Vec<_> = said
        .iter()
        .filter(|m| m.contains("login plugin call panicked; rejecting (fail-closed)"))
        .collect();
    assert_eq!(panicked.len(), 3, "one 4003 per faulted step: {said:?}");
    for op in ["op=\"begin_login\"", "op=\"complete_login\""] {
        assert!(
            panicked
                .iter()
                .any(|m| m.contains(op) || m.contains(&op.replace('"', ""))),
            "4003 names the op {op}: {said:?}"
        );
    }
    assert!(
        panicked.iter().any(|m| m.contains("idp"))
            && panicked.iter().any(|m| m.contains("test-login-double")),
        "4003 names the method: {said:?}"
    );

    // RED: the same answers from a plugin that DECLINED say nothing about a panic.
    let (declined, said) = run(false);
    assert_eq!(declined.1, faulted.1, "a decline renders as the fault does");
    assert_eq!(declined.2, faulted.2, "a decline renders as the fault does");
    assert!(
        !said
            .iter()
            .any(|m| m.contains("login plugin call panicked")),
        "a declining plugin emits no 4003: {said:?}"
    );
}

/// THE CLIENT SECRET IS THE PLUGIN'S, LENT AT `open` AND HELD NOWHERE ELSE (THE DESIGN 6.7). The
/// host resolves `browser_login.client_secret` and hands it to the plugin's `open` beside the
/// public `client_id` (the plugin makes its own token exchange with it); after that it rides
/// NOTHING the host makes: not the login cookie, not the authorize redirect, not the
/// `complete_login` the callback hands the plugin, not the pages it renders. (Where the secret may
/// be SENT — the operator's own IdP hosts only — is the plugin's to enforce, ruling R8.)
#[tokio::test]
async fn the_client_secret_is_lent_at_open_and_rides_nothing_the_host_makes() {
    const SECRET: &str = "REAL-SECRET-XYZ";
    struct Recording {
        opened: std::sync::Mutex<Vec<(String, String, serde_json::Value)>>,
        door: std::sync::Arc<DoorLogin>,
    }
    impl busbar_contract::auth_calls::AuthAxis for Recording {
        fn linked_names(&self) -> Vec<String> {
            Vec::new()
        }
        fn answers(&self, module: &str) -> bool {
            module == "idp-plugin"
        }
        fn linked(&self, _: &str) -> bool {
            false
        }
        fn operator(&self) -> Option<(String, String)> {
            None
        }
        fn open(
            &self,
            module: &str,
            label: &str,
            settings: &serde_json::Value,
        ) -> Result<std::sync::Arc<dyn AuthCalls>, String> {
            self.opened.lock().unwrap().push((
                module.to_string(),
                label.to_string(),
                settings.clone(),
            ));
            Ok(self.door.clone())
        }
    }
    let axis = std::sync::Arc::new(Recording {
        opened: std::sync::Mutex::new(Vec::new()),
        door: DoorLogin::new(alice()),
    });
    std::env::set_var("BUSBAR_TEST_LOGIN_SECRET_LENT", SECRET);
    let mut cfg = crate::config::AuthCfg::default_none();
    cfg.methods.insert(
        "idp".into(),
        crate::config::AuthMethodCfg {
            module: "idp-plugin".into(),
            browser_login: Some(crate::config::BrowserLoginCfg {
                client_secret: Some(crate::config::SecretRef::env(
                    "BUSBAR_TEST_LOGIN_SECRET_LENT",
                )),
                client_id: Some("client-abc".into()),
            }),
            settings: serde_json::Map::new(),
        },
    );
    let methods = LoginMethods::build_on(
        &cfg,
        &busbar_plugin_loader::PluginRegistry::empty(),
        &crate::config::secret::SecretResolver::builtins_only(),
        || Some(axis.clone() as std::sync::Arc<dyn busbar_contract::auth_calls::AuthAxis>),
    )
    .expect("the method opens on the door");

    // LENT AT OPEN: the plugin's instance is opened over the resolved secret and the public id.
    let opened = axis.opened.lock().unwrap().clone();
    assert_eq!(opened.len(), 1, "one instance opened: {opened:?}");
    assert_eq!(opened[0].0, "idp-plugin");
    assert_eq!(opened[0].1, "idp#login");
    assert_eq!(
        opened[0].2["client_secret"], SECRET,
        "the secret is lent at open"
    );
    assert_eq!(opened[0].2["client_id"], "client-abc");

    // HELD NOWHERE ELSE: drive the whole redirect login over the method the build opened.
    let method = methods.methods.get("idp").expect("the method");
    let app = crate::test_support::TestApp::new()
        .public_url("https://busbar.example.com")
        .login_method_door(
            "idp",
            method.module.clone(),
            method.login_kind,
            method.has_button,
        )
        .build();
    let begun = begin(&app, "idp", false).await;
    assert_eq!(begun.status().as_u16(), 302);
    let location = begun
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(!location.contains(SECRET), "not on the authorize redirect");
    let set = begun
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap();
    let raw = set
        .split(';')
        .next()
        .unwrap()
        .strip_prefix(&format!("{LOGIN_COOKIE}="))
        .unwrap();
    let decoded = String::from_utf8(B64.decode(raw).unwrap()).unwrap();
    assert!(
        !decoded.contains(SECRET) && !set.contains(SECRET),
        "not in the login cookie: {decoded}"
    );
    let cookie = LoginCookie::decode(raw).expect("the cookie");
    let called = callback(
        &app,
        &cred_handle(&app),
        Some(cookie.encode()),
        "the-code".into(),
        Some(cookie.state.clone()),
    )
    .await;
    let seen = format!("{:?}", axis.door.seen.lock().unwrap());
    assert!(
        !seen.contains(SECRET),
        "not in the complete_login the plugin is handed: {seen}"
    );
    assert!(
        !body_of(called).contains(SECRET),
        "not on the page rendered"
    );
    let page = render_key_issued(
        "alice",
        "user:alice",
        "bb_live_abc",
        "https://busbar.example.com",
        "idp",
    );
    assert!(!page.contains(SECRET), "not on the key-issued page");
}

/// NO AUTH AXIS AT ALL: a hosted-login method is refused in 1.5.5's words, byte for byte — "no
/// `kind: auth` plugin answers to '<module>'" — never the loader registry's refusal (which stays
/// internal). RED: the registry's words ("no plugin named or aliased …") reach the operator.
#[test]
fn a_login_method_with_no_auth_axis_is_refused_in_1_5_5_words() {
    let mut cfg = crate::config::AuthCfg::default_none();
    cfg.methods.insert(
        "idp".into(),
        crate::config::AuthMethodCfg {
            module: "idp-plugin".into(),
            browser_login: None,
            settings: serde_json::Map::new(),
        },
    );
    let Err(refusal) = LoginMethods::build_on(
        &cfg,
        &busbar_plugin_loader::PluginRegistry::empty(),
        &crate::config::secret::SecretResolver::builtins_only(),
        || None,
    ) else {
        panic!("no axis answers the method");
    };
    assert_eq!(
        refusal,
        "identity-providers.idp (module 'idp-plugin') could not be loaded as a `kind: auth` login \
         plugin: no `kind: auth` plugin answers to 'idp-plugin'"
    );
    assert!(
        !refusal.contains("no plugin named or aliased"),
        "the registry's words stay internal: {refusal}"
    );
}
