// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for the `GET /auth/token` hosted browser-login flow (1.5.2). `token_tests` is a
//! submodule of `auth::token`, so it can drive the private sub-state handlers (`chooser`/`begin`/
//! `callback`), the render fns, and the cookie/PKCE/hop helpers directly.

use super::*;
use busbar_api::{
    AuthModule, AuthOutcome, BeginLogin, CompleteLogin, FieldKind, LoginField, LoginForm, LoginHop,
    LoginKind, LoginModule, LoginOutcome, Principal,
};

/// A test login module (AuthPlugin = AuthModule + LoginModule). `begin` returns a fixed authorize
/// URL; `complete` returns a token-exchange hop pointing at `token_url` (with a `client_secret`
/// placeholder + `secret_form_field`), then — once a token_response is fed back — `Identify`s alice.
struct TestLogin {
    authorize_url: String,
    token_url: String,
}
impl AuthModule for TestLogin {
    fn name(&self) -> &'static str {
        "test-login"
    }
    fn authenticate(&self, _c: Option<&str>) -> AuthOutcome {
        AuthOutcome::Pass
    }
}
impl LoginModule for TestLogin {
    fn begin_login(&self, _r: &BeginLogin) -> LoginOutcome {
        LoginOutcome::Authorize(self.authorize_url.clone())
    }
    fn complete_login(&self, r: &CompleteLogin) -> LoginOutcome {
        if r.token_response.is_none() {
            LoginOutcome::Exchange(LoginHop {
                method: "POST".into(),
                url: self.token_url.clone(),
                form: vec![
                    ("grant_type".into(), "authorization_code".into()),
                    // The plugin writes only the KEY (+ a placeholder value); the CORE injects the
                    // real secret. This proves the plugin never holds the secret value.
                    ("client_secret".into(), "__PLACEHOLDER__".into()),
                ],
                secret_form_field: Some("client_secret".into()),
                headers: vec![],
            })
        } else {
            let mut p = Principal::from_id("alice");
            p.roles = vec!["members".into()];
            LoginOutcome::Identify(p)
        }
    }
}

fn test_app_with_methods(
    methods: Vec<(&str, bool)>,
    token_url: &str,
) -> std::sync::Arc<crate::state::App> {
    let mut b = crate::test_support::TestApp::new().public_url("https://busbar.example.com");
    for (name, has_button) in methods {
        b = b.login_method(
            name,
            Box::new(TestLogin {
                authorize_url: "https://idp.example.com/authorize?x=1".into(),
                token_url: token_url.to_string(),
            }),
            Some("REAL-CLIENT-SECRET".into()),
            // The issuer hint carries the mock IdP host so the hop executor's allowlist admits it
            // (the token endpoint the plugin will describe lives at this host).
            Some(token_url.to_string()),
            has_button,
        );
    }
    b.build()
}

// ── chooser ──────────────────────────────────────────────────────────────────────────────────────

#[test]
fn chooser_renders_0_1_n_buttons() {
    // 0 buttons (no browser_login method).
    let app0 = test_app_with_methods(vec![], "");
    let body0 = body_of(chooser(&app0));
    assert_eq!(body0.matches("class=\"provider\"").count(), 0);
    assert!(body0.contains("No browser login"));

    // 1 button.
    let app1 = test_app_with_methods(vec![("microsoft", true)], "");
    let body1 = body_of(chooser(&app1));
    assert_eq!(body1.matches("class=\"provider\"").count(), 1);
    assert!(body1.contains("/auth/token?method=microsoft"));

    // N buttons — plus a GUI-OFF method (has_button=false) that is ABSENT from the chooser.
    let appn = test_app_with_methods(
        vec![
            ("microsoft", true),
            ("github", true),
            ("headless-only", false),
        ],
        "",
    );
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
    let app = test_app_with_methods(vec![("headless-only", false)], "");
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
    let app = test_app_with_methods(vec![("microsoft", true)], "");
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

// ── callback: state + nonce guards ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn callback_state_mismatch_400() {
    let app = test_app_with_methods(vec![("microsoft", true)], "http://127.0.0.1:1/unused");
    let cookie = LoginCookie {
        method: "microsoft".into(),
        code_verifier: "v".into(),
        state: "the-real-state".into(),
        nonce: "n".into(),
        refresh: false,
    };
    // Wrong state ⇒ 400 BEFORE any token exchange (the token_url above is unreachable; if an
    // exchange were attempted this would hang/error, not cleanly 400).
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
}

#[tokio::test]
async fn callback_nonce_mismatch_rejected() {
    // Mock token endpoint returns an id_token whose `nonce` claim is WRONG.
    let (token_url, mock) = mock_token_endpoint("WRONG-NONCE".into()).await;
    let app = test_app_with_methods(vec![("microsoft", true)], &token_url);
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
    mock.abort();
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
    let app = test_app_with_methods(vec![("microsoft", true)], "http://127.0.0.1:1/unused");
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
/// redirect callback (mock token endpoint → Identify) with no role binding ⇒ `Unbound`.
#[tokio::test]
async fn no_self_serve_grant_renders_branded_html() {
    let (token_url, mock) = mock_token_endpoint("match-nonce".into()).await;
    // No governance / role_bindings ⇒ the Identified principal resolves to `Unbound`.
    let app = test_app_with_methods(vec![("microsoft", true)], &token_url);
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
    mock.abort();
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
    let app = test_app_with_methods(vec![("microsoft", true)], "");
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

// ── client_secret injection (CORE-only) ──────────────────────────────────────────────────────────

#[tokio::test]
async fn client_secret_is_core_injected_only() {
    // A mock endpoint that ECHOES the received form body so we can inspect what the core sent.
    let (url, mock) = mock_echo_endpoint().await;
    let allowed = allowed_hosts_for(&url);
    let hop = LoginHop {
        method: "POST".into(),
        url,
        form: vec![
            ("grant_type".into(), "authorization_code".into()),
            ("client_secret".into(), "__PLACEHOLDER__".into()),
        ],
        secret_form_field: Some("client_secret".into()),
        headers: vec![],
    };
    let (_status, echoed) = execute_hop(
        hop_client(),
        &hop,
        Some("REAL-SECRET-XYZ"),
        &allowed,
        std::time::Duration::from_secs(10),
    )
    .await
    .expect("hop executes");
    assert!(
        echoed.contains("client_secret=REAL-SECRET-XYZ"),
        "the CORE injects the real secret value into the hop form: {echoed}"
    );
    assert!(
        !echoed.contains("__PLACEHOLDER__"),
        "the plugin's placeholder must be overwritten by the core"
    );
    mock.abort();

    // The secret NEVER appears in the login cookie (structurally — no secret field)...
    let cookie = LoginCookie {
        method: "m".into(),
        code_verifier: "v".into(),
        state: "s".into(),
        nonce: "n".into(),
        refresh: false,
    }
    .encode();
    let decoded = String::from_utf8(B64.decode(&cookie).unwrap()).unwrap();
    assert!(!decoded.contains("REAL-SECRET-XYZ") && !cookie.contains("REAL-SECRET-XYZ"));
    // ...nor in the rendered key-issued page.
    let page = render_key_issued(
        "alice",
        "user:alice",
        "bb_live_abc",
        "https://busbar.example.com",
        "microsoft",
    );
    assert!(!page.contains("REAL-SECRET-XYZ"));
}

// ── credential flow: Prompt form, POST submit, Refresh rotation ──────────────────────────────────

/// A CREDENTIAL-kind login module (the LDAP shape): begin returns a `Prompt` form; complete verifies
/// the submitted username/password ITSELF and `Identify`s (no hop, no client_secret).
struct CredLogin;
impl AuthModule for CredLogin {
    fn name(&self) -> &'static str {
        "ldap"
    }
    fn authenticate(&self, _c: Option<&str>) -> AuthOutcome {
        AuthOutcome::Pass
    }
}
impl LoginModule for CredLogin {
    fn login_kind(&self) -> LoginKind {
        LoginKind::Credential
    }
    fn begin_login(&self, _r: &BeginLogin) -> LoginOutcome {
        LoginOutcome::Prompt(LoginForm {
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
        })
    }
    fn complete_login(&self, r: &CompleteLogin) -> LoginOutcome {
        let get = |k: &str| {
            r.submitted
                .iter()
                .find(|(n, _)| n == k)
                .map(|(_, v)| v.expose_secret().as_str())
        };
        if get("username") == Some("alice") && get("password") == Some("pw") {
            let mut p = Principal::from_id("ldap:alice");
            p.roles = vec!["members".into()];
            LoginOutcome::Identify(p)
        } else {
            LoginOutcome::Reject
        }
    }
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
    outer.insert("ldap".to_string(), role);
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
        .login_method("ldap", Box::new(CredLogin), None, None, true)
        .build()
}

/// Wrap a `cred_app` snapshot in a live `AppHandle` so `credential_submit` can auto-provision the
/// `user:<sub>` leaf (persist-then-swap) exactly as the running server does.
fn cred_handle(app: &std::sync::Arc<crate::state::App>) -> std::sync::Arc<crate::state::AppHandle> {
    std::sync::Arc::new(crate::state::AppHandle::new(app.clone()))
}

fn cred_cookie(state: &str, refresh: bool) -> String {
    LoginCookie {
        method: "ldap".into(),
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
    let resp = begin(&app, "ldap", false).await;
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
    let app = test_app_with_methods(vec![("microsoft", true)], "");
    let resp = begin(&app, "microsoft", false).await;
    assert_eq!(resp.status().as_u16(), 302);
}

/// POSTing valid credentials runs `complete_login` (which reads the SUBMITTED map) and issues a key
/// through the SAME seam — grouped under `user:ldap:alice` (the module-namespaced sub).
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
        body.contains("ldap:alice"),
        "the issued page shows the identity: {body}"
    );
    // The issued token verifies through the ordinary path.
    let key = extract_key(&body);
    assert!(app
        .governance
        .as_ref()
        .unwrap()
        .verify_token(&key, crate::store::now(), None)
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
    let now = crate::store::now();
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
    use busbar_api::LoginKind;
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

// ── hop security: URL allowlist, header sanitize, no-redirect, timeout, hop cap ──────────────────

/// The operator-derived allowlist for a single mock host (mirrors the core-side rule).
fn allowed_hosts_for(url: &str) -> std::collections::HashSet<String> {
    collect_allowed_hosts(&serde_json::Map::new(), Some(url))
}

/// SSRF / client_secret-exfil guard: a hop to a host NOT in the method's operator-derived allowlist
/// is REFUSED before the request is built, so the injected secret is never sent. Before the fix:
/// `execute_hop` sent to any plugin-chosen URL and returned Ok, exfiltrating the secret.
#[tokio::test]
async fn execute_hop_refuses_non_allowlisted_host() {
    let (url, mock) = mock_echo_endpoint().await;
    let empty = std::collections::HashSet::new(); // nothing allow-listed
    let hop = LoginHop {
        method: "POST".into(),
        url,
        form: vec![("client_secret".into(), "__PLACEHOLDER__".into())],
        secret_form_field: Some("client_secret".into()),
        headers: vec![],
    };
    let r = execute_hop(
        hop_client(),
        &hop,
        Some("REAL-SECRET-XYZ"),
        &empty,
        std::time::Duration::from_secs(10),
    )
    .await;
    assert!(
        r.is_err(),
        "a hop to a non-allowlisted host must be refused (secret never sent)"
    );
    mock.abort();
}

/// Header sanitize: CR/LF/NUL (request-splitting) and the hop-control headers are rejected; a
/// legitimate `Authorization` bearer is allowed. Before the fix: no header path existed / no
/// sanitization.
#[test]
fn sanitize_hop_header_rejects_crlf_and_hop_control() {
    assert!(sanitize_hop_header("Authorization", "Bearer abc.def").is_ok());
    assert!(sanitize_hop_header("X-Evil", "a\r\nInjected: 1").is_err());
    assert!(sanitize_hop_header("Bad\nName", "v").is_err());
    assert!(sanitize_hop_header("X-Nul", "a\0b").is_err());
    for forbidden in ["Host", "content-length", "Transfer-Encoding"] {
        assert!(
            sanitize_hop_header(forbidden, "x").is_err(),
            "{forbidden} must be refused"
        );
    }
}

/// A hop carrying a CR/LF-injected header fails the WHOLE hop closed (no request sent).
#[tokio::test]
async fn execute_hop_refuses_a_crlf_injected_header() {
    let (url, mock) = mock_echo_endpoint().await;
    let allowed = allowed_hosts_for(&url);
    let hop = LoginHop {
        method: "POST".into(),
        url,
        form: vec![],
        secret_form_field: None,
        headers: vec![("X-Evil".into(), "a\r\nInjected: 1".into())],
    };
    assert!(execute_hop(
        hop_client(),
        &hop,
        None,
        &allowed,
        std::time::Duration::from_secs(10)
    )
    .await
    .is_err());
    mock.abort();
}

/// vet_hop_url: https required for a public host; http tolerated for loopback; a metadata/link-local
/// host is refused even if allowlisted.
#[test]
fn vet_hop_url_enforces_https_allowlist_and_blocks_metadata() {
    let pub_ok: std::collections::HashSet<String> =
        ["idp.example.com".into()].into_iter().collect();
    assert!(vet_hop_url("https://idp.example.com/token", &pub_ok).is_ok());
    assert!(
        vet_hop_url("https://attacker.com/token", &pub_ok).is_err(),
        "off-allowlist host refused"
    );
    assert!(
        vet_hop_url("http://idp.example.com/token", &pub_ok).is_err(),
        "public host must be https"
    );
    let loop_ok: std::collections::HashSet<String> = ["127.0.0.1".into()].into_iter().collect();
    assert!(
        vet_hop_url("http://127.0.0.1:9/token", &loop_ok).is_ok(),
        "http tolerated for loopback"
    );
    let meta: std::collections::HashSet<String> = ["169.254.169.254".into()].into_iter().collect();
    assert!(
        vet_hop_url("https://169.254.169.254/latest", &meta).is_err(),
        "cloud-metadata/link-local refused even if allowlisted"
    );
}

/// No-redirect: the hop client does NOT follow a 302, so the client_secret can never be re-POSTed to
/// a redirect target. Before the fix: `reqwest::Client::new()` follows redirects, so a 302 from
/// the allowlisted endpoint to an attacker host re-sends the secret (status would be the target's).
#[tokio::test]
async fn execute_hop_does_not_follow_redirect() {
    let (url, mock) = mock_redirect_endpoint("https://attacker.example.com/steal").await;
    let allowed = allowed_hosts_for(&url);
    let hop = LoginHop {
        method: "POST".into(),
        url,
        form: vec![("client_secret".into(), "__PLACEHOLDER__".into())],
        secret_form_field: Some("client_secret".into()),
        headers: vec![],
    };
    let (status, _body) = execute_hop(
        hop_client(),
        &hop,
        Some("SECRET"),
        &allowed,
        std::time::Duration::from_secs(10),
    )
    .await
    .expect("hop returns the 302 itself");
    assert_eq!(
        status, 302,
        "the hop must NOT follow the redirect (else the secret is re-POSTed to the target)"
    );
    mock.abort();
}

/// Timeout: `execute_hop` honors the client's request timeout, so a hanging token endpoint cannot
/// hold the callback open. Before the fix: `Client::new()` has no timeout and the call hangs.
#[tokio::test]
async fn execute_hop_times_out_on_a_hanging_endpoint() {
    let (url, mock) = mock_hang_endpoint().await;
    let allowed = allowed_hosts_for(&url);
    // The 300ms bound rides the hop's own timeout argument now — the knob the retired
    // client-level reqwest timeout carried.
    let hop = LoginHop {
        method: "POST".into(),
        url,
        form: vec![],
        secret_form_field: None,
        headers: vec![],
    };
    let r = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        execute_hop(
            hop_client(),
            &hop,
            None,
            &allowed,
            std::time::Duration::from_millis(300),
        ),
    )
    .await
    .expect("execute_hop returns within the outer bound (did not hang)");
    assert!(
        r.is_err(),
        "a hanging endpoint must surface as an error, not hang"
    );
    mock.abort();
}

/// The callback hop loop runs at most `MAX_HOPS` times (not `MAX_HOPS + 1`). A module that only ever
/// `Exchange`s is fail-closed after exactly `MAX_HOPS` core-executed hops. Before the fix: the
/// `0..=MAX_HOPS` loop ran `MAX_HOPS + 1` times.
#[tokio::test]
async fn hop_loop_runs_at_most_max_hops_times() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc as StdArc;

    struct CountingLogin {
        calls: StdArc<AtomicUsize>,
        token_url: String,
    }
    impl AuthModule for CountingLogin {
        fn name(&self) -> &'static str {
            "counting"
        }
        fn authenticate(&self, _c: Option<&str>) -> AuthOutcome {
            AuthOutcome::Pass
        }
    }
    impl LoginModule for CountingLogin {
        fn complete_login(&self, _r: &CompleteLogin) -> LoginOutcome {
            self.calls.fetch_add(1, Ordering::SeqCst);
            // Never Identify — always ask for another hop (fail-closed exercise).
            LoginOutcome::Exchange(LoginHop {
                method: "POST".into(),
                url: self.token_url.clone(),
                form: vec![],
                secret_form_field: None,
                headers: vec![],
            })
        }
    }

    let (token_url, mock) = mock_echo_endpoint().await;
    let calls = StdArc::new(AtomicUsize::new(0));
    let app = crate::test_support::TestApp::new()
        .public_url("https://busbar.example.com")
        .login_method(
            "counting",
            Box::new(CountingLogin {
                calls: calls.clone(),
                token_url: token_url.clone(),
            }),
            Some("SECRET".into()),
            Some(token_url.clone()),
            true,
        )
        .build();
    let cookie = LoginCookie {
        method: "counting".into(),
        code_verifier: "v".into(),
        state: "st".into(),
        nonce: "n".into(),
        refresh: false,
    };
    let _ = callback(
        &app,
        &cred_handle(&app),
        Some(cookie.encode()),
        "code".into(),
        Some("st".into()),
    )
    .await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        MAX_HOPS,
        "the hop loop must run exactly MAX_HOPS times, not MAX_HOPS + 1"
    );
    mock.abort();
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
    let app = test_app_with_methods(vec![("microsoft", true)], "");
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
    crate::metrics::init();
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
    crate::metrics::init();
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
    crate::metrics::init();
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
    crate::metrics::init();
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

// ── test helpers: serve an app + mock IdP endpoints ──────────────────────────────────────────────

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

/// A mock OIDC token endpoint that returns `{"id_token": "<jwt with the given nonce>"}`.
async fn mock_token_endpoint(nonce: String) -> (String, tokio::task::JoinHandle<()>) {
    let payload = B64
        .encode(serde_json::to_vec(&serde_json::json!({"sub": "alice", "nonce": nonce})).unwrap());
    let id_token = format!("e30.{payload}.sig");
    let router = axum::Router::new().route(
        "/token",
        axum::routing::post(move || {
            let body = serde_json::json!({ "id_token": id_token }).to_string();
            async move {
                (
                    [(axum::http::header::CONTENT_TYPE, "application/json")],
                    body,
                )
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (format!("http://{addr}/token"), handle)
}

/// A mock endpoint that replies `302 Found` with the given `Location`, to prove the hop client does
/// NOT follow redirects (which would re-POST the secret to the target).
async fn mock_redirect_endpoint(location: &str) -> (String, tokio::task::JoinHandle<()>) {
    let location = location.to_string();
    let router = axum::Router::new().route(
        "/token",
        axum::routing::post(move || {
            let location = location.clone();
            async move {
                (
                    axum::http::StatusCode::FOUND,
                    [(axum::http::header::LOCATION, location)],
                )
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (format!("http://{addr}/token"), handle)
}

/// A mock endpoint that never responds (sleeps well past any request timeout), to prove `execute_hop`
/// honors its client's timeout rather than hanging.
async fn mock_hang_endpoint() -> (String, tokio::task::JoinHandle<()>) {
    let router = axum::Router::new().route(
        "/token",
        axum::routing::post(|| async move {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            "never"
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (format!("http://{addr}/token"), handle)
}

/// A mock endpoint that ECHOES the received request body (so a test can inspect the form the core
/// sent, e.g. to prove the client_secret was injected).
async fn mock_echo_endpoint() -> (String, tokio::task::JoinHandle<()>) {
    let router = axum::Router::new().route(
        "/token",
        axum::routing::post(|body: String| async move { body }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (format!("http://{addr}/token"), handle)
}

// ── the BLOCKING-FFI class: a login plugin's sync FFI must not park Tokio workers ────────────────

/// A login module whose `begin_login` / `complete_login` BLOCK the calling thread for `park`, the way
/// a real credential plugin does: an LDAP/AD bind or an OIDC token exchange is a synchronous network
/// round-trip behind a `transport_call`. Nothing here is async — that is the point: the ENGINE, not
/// the plugin, is responsible for keeping this off the reactor.
struct ParkingLogin {
    park: std::time::Duration,
    kind: LoginKind,
}
impl AuthModule for ParkingLogin {
    fn name(&self) -> &'static str {
        "parking-login"
    }
    fn authenticate(&self, _c: Option<&str>) -> AuthOutcome {
        AuthOutcome::Pass
    }
}
impl LoginModule for ParkingLogin {
    fn login_kind(&self) -> LoginKind {
        self.kind
    }
    fn begin_login(&self, _r: &BeginLogin) -> LoginOutcome {
        std::thread::sleep(self.park);
        LoginOutcome::Authorize("https://idp.example.com/authorize".into())
    }
    fn complete_login(&self, _r: &CompleteLogin) -> LoginOutcome {
        std::thread::sleep(self.park);
        LoginOutcome::Reject
    }
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
/// callers reach `begin` — and `begin` calls the plugin's synchronous `begin_login`. Four concurrent
/// anonymous requests on a two-worker runtime must not stop the runtime from polling anything else.
#[test]
fn concurrent_anonymous_begin_does_not_starve_the_runtime() {
    let rt = two_worker_runtime();
    let app = rt.block_on(async {
        crate::test_support::TestApp::new()
            .public_url("https://busbar.example.com")
            .login_method(
                "ldap",
                Box::new(ParkingLogin {
                    park: std::time::Duration::from_secs(3),
                    kind: LoginKind::Redirect,
                }),
                Some("REAL-CLIENT-SECRET".into()),
                None,
                true,
            )
            .build()
    });
    // Four anonymous begins — two more than the runtime has workers.
    let tasks: Vec<_> = (0..4)
        .map(|_| {
            let a = app.clone();
            rt.spawn(async move { begin(&a, "ldap", false).await.status() })
        })
        .collect();
    // Wall-clock (not a Tokio timer): let the begins actually reach the plugin.
    std::thread::sleep(std::time::Duration::from_millis(200));
    assert_runtime_still_polls(
        &rt,
        std::time::Duration::from_millis(750),
        "the runtime stopped polling while four ANONYMOUS /auth/token begins sat inside the login \
         plugin's synchronous begin_login: every Tokio worker is parked in FFI, so nothing else in \
         the process — other requests, the admin plane, /healthz — can run",
    );
    for t in tasks {
        rt.block_on(async { t.await.ok() });
    }
}

/// The credential POST (`POST /auth/token` carrying a login cookie) runs the plugin's
/// `complete_login` — the LDAP/AD bind itself. The `__state` CSRF check does not gate an attacker:
/// they call `begin` themselves and echo back the state from the cookie they were handed, which is
/// exactly what this test does. Same anonymous reachability, same runtime-starvation shape.
#[test]
fn concurrent_credential_submit_does_not_starve_the_runtime() {
    let rt = two_worker_runtime();
    let (app, handle) = rt.block_on(async {
        let app = crate::test_support::TestApp::new()
            .public_url("https://busbar.example.com")
            .login_method(
                "ldap",
                Box::new(ParkingLogin {
                    park: std::time::Duration::from_secs(3),
                    kind: LoginKind::Credential,
                }),
                None,
                None,
                true,
            )
            .build();
        let handle = std::sync::Arc::new(crate::state::AppHandle::new(app.clone()));
        (app, handle)
    });
    // The cookie an attacker mints for themselves by calling `begin` first — its `state` is theirs to
    // echo in `__state`, so CSRF is satisfied without any prior authentication.
    let cookie = LoginCookie {
        method: "ldap".to_string(),
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
         plugin's synchronous complete_login",
    );
    for t in tasks {
        rt.block_on(async { t.await.ok() });
    }
}

/// A PUBLIC client must not send `client_secret=` at all — an empty value is not an absent one.
///
/// A plugin writes the secret KEY with an empty placeholder and lets the core inject the VALUE, so
/// when no secret is configured the placeholder used to survive and `client_secret=` went on the
/// wire. That is the wrong request shape for a public client, and an IdP is entitled to read an
/// empty string as a WRONG secret and answer `invalid_client` rather than as "this client is
/// public". The confidential path is asserted alongside it, so this cannot be satisfied by dropping
/// the field in both cases.
#[tokio::test]
async fn the_secret_placeholder_is_dropped_for_a_public_client_and_filled_for_a_confidential_one() {
    let (url, mock) = mock_echo_endpoint().await;
    let allowed = allowed_hosts_for(&url);
    let hop = LoginHop {
        method: "POST".into(),
        url: url.clone(),
        form: vec![
            ("grant_type".into(), "authorization_code".into()),
            ("client_secret".into(), String::new()),
        ],
        secret_form_field: Some("client_secret".into()),
        headers: vec![],
    };

    // PUBLIC client: no secret configured.
    let (status, body) = execute_hop(
        hop_client(),
        &hop,
        None,
        &allowed,
        std::time::Duration::from_secs(10),
    )
    .await
    .expect("hop runs");
    assert_eq!(status, 200);
    assert!(
        !body.contains("client_secret"),
        "a public client must omit the parameter entirely, got body: {body}"
    );
    assert!(
        body.contains("grant_type=authorization_code"),
        "the rest of the form must survive: {body}"
    );

    // CONFIDENTIAL client: the placeholder is replaced by the real value, not duplicated.
    let (status, body) = execute_hop(
        hop_client(),
        &hop,
        Some("s3cr3t"),
        &allowed,
        std::time::Duration::from_secs(10),
    )
    .await
    .expect("hop runs");
    assert_eq!(status, 200);
    assert!(
        body.contains("client_secret=s3cr3t"),
        "the core must inject the real secret: {body}"
    );
    assert_eq!(
        body.matches("client_secret").count(),
        1,
        "the secret key must appear exactly once, not appended alongside the placeholder: {body}"
    );
    mock.abort();
}
