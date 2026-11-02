// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::auth::{
    BeginLogin, FieldKind, LoginField, LoginForm, LoginKind, LoginOutcome, Principal,
};
use busbar_contract::auth_calls::{LoginCall, LoginCallback, LoginSettled};

struct DoorLogin {
    kind: LoginKind,
    begin: LoginOutcome,
    complete: Box<dyn Fn(&LoginCallback) -> LoginOutcome + Send + Sync>,
    park: Option<std::time::Duration>,
    faults: bool,
    seen: std::sync::Mutex<Vec<LoginCallback>>,
}

impl DoorLogin {
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

    fn new(complete: LoginOutcome) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self::answering(move |_| complete.clone()))
    }

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

fn alice() -> LoginOutcome {
    let mut p = Principal::from_id("alice");
    p.roles = vec!["members".into()];
    LoginOutcome::Identify(p)
}

fn test_app_with_methods(methods: Vec<(&str, bool)>) -> std::sync::Arc<busbar_kernel::state::App> {
    let mut b = busbar_kernel_testkit::test_support::TestApp::new()
        .public_url("https://busbar.example.com");
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

#[test]
fn chooser_renders_0_1_n_buttons() {
    let app0 = test_app_with_methods(vec![]);
    let body0 = body_of(chooser(&app0));
    assert_eq!(body0.matches("class=\"provider\"").count(), 0);
    assert!(body0.contains("No browser login"));

    let app1 = test_app_with_methods(vec![("microsoft", true)]);
    let body1 = body_of(chooser(&app1));
    assert_eq!(body1.matches("class=\"provider\"").count(), 1);
    assert!(body1.contains("/auth/token?method=microsoft"));

    let appn = test_app_with_methods(vec![
        ("microsoft", true),
        ("second-sso", true),
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

    assert!(bodyn.contains("https://busbar.example.com"));
    assert!(!bodyn.contains("https://busbar.example.com/v1"));
}

#[test]
fn the_button_brands_are_the_legacy_row_and_with_no_row_every_method_is_generic() {
    let row = busbar_kernel::config::migration_table::text("login_brands");
    let brands: Vec<(&str, &str, &str)> = row
        .split(" | ")
        .map(|b| {
            let f: Vec<&str> = b.split(" : ").collect();
            assert_eq!(f.len(), 3, "`<tokens> : <label> : <icon ref>`: {b}");
            (f[0].split(' ').next().expect("a match token"), f[1], f[2])
        })
        .collect();
    assert_eq!(brands.len(), 3, "1.5.5 branded three providers: {row}");
    for (token, label, icon_ref) in &brands {
        let icon = BRAND_ICONS
            .iter()
            .find(|(r, _)| r == icon_ref)
            .map(|(_, svg)| *svg)
            .unwrap_or_else(|| panic!("no icon asset for `{icon_ref}`"));
        assert_eq!(button_brand(token, None), ((*label).to_string(), icon));
        assert_eq!(
            button_brand("corp-sso", Some(&format!("https://{token}.example"))),
            ((*label).to_string(), icon),
            "the issuer host matches as the name does"
        );
        let app = test_app_with_methods(vec![(*token, true)]);
        let body = body_of(chooser(&app));
        assert!(
            body.contains(&format!(
                "aria-label=\"Continue with {label}\">{icon}<span class=\"plabel\">Continue with {label}</span>"
            )),
            "{token}: {body}"
        );
    }

    assert_eq!(
        button_brand("corp-sso", None),
        ("Corp Sso".to_string(), GENERIC_ICON)
    );

    for (token, _, _) in &brands {
        assert_eq!(
            brand_from("", token, None),
            (titlecase(token), GENERIC_ICON),
            "{token} without the row"
        );
    }
}

#[tokio::test]
async fn gui_off_method_still_works_via_post() {
    let app = test_app_with_methods(vec![("headless-only", false)]);
    let (base, handle) = serve(app).await;
    let client = reqwest::Client::new();

    let r = client
        .post(format!("{base}/auth/token"))
        .send()
        .await
        .unwrap();
    assert_ne!(r.status().as_u16(), 404, "POST /auth/token must exist");
    assert_ne!(r.status().as_u16(), 405, "POST /auth/token must be allowed");
    handle.abort();
}

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

async fn refresh_flag_for(
    handle: &std::sync::Arc<busbar_kernel::state::AppHandle>,
    sec_fetch_site: Option<&str>,
) -> bool {
    let mut req = Request::builder().uri("/auth/token?method=microsoft&refresh=1");
    if let Some(site) = sec_fetch_site {
        req = req.header("sec-fetch-site", site);
    }
    let resp = browser(handle.clone(), req.body(Body::empty()).unwrap()).await;
    assert_eq!(resp.status().as_u16(), 302, "begin redirects to the IdP");
    let sc = resp.headers().get("set-cookie").unwrap().to_str().unwrap();
    let raw = sc
        .split(';')
        .next()
        .unwrap()
        .strip_prefix(&format!("{LOGIN_COOKIE}="))
        .unwrap();
    LoginCookie::decode(raw)
        .expect("cookie round-trips")
        .refresh
}

#[tokio::test]
async fn a_refresh_link_rotates_only_from_busbars_own_page() {
    let app = test_app_with_methods(vec![("microsoft", true)]);
    let handle = std::sync::Arc::new(busbar_kernel::state::AppHandle::new(app));
    for site in [Some("cross-site"), None, Some("none"), Some("same-site")] {
        assert!(
            !refresh_flag_for(&handle, site).await,
            "Sec-Fetch-Site {site:?} does not rotate the key"
        );
    }
    assert!(
        refresh_flag_for(&handle, Some("same-origin")).await,
        "busbar's own Refresh link rotates the key"
    );
}

#[test]
fn the_same_origin_refresh_rule_against_1_5_5s() {
    for site in [Some("cross-site"), None, Some("none"), Some("same-site")] {
        assert!(!refresh_rotates_under(true, true, site), "{site:?}");
        assert!(refresh_rotates_under(false, true, site), "{site:?}");
    }
    assert!(refresh_rotates_under(true, true, Some("same-origin")));
    for needs in [true, false] {
        assert!(!refresh_rotates_under(needs, false, Some("same-origin")));
    }
}

#[tokio::test]
async fn begin_with_an_unrepresentable_authorize_url_fails_closed_not_panics() {
    for bad in [
        "https://idp.example.com/authorize\r\nX-Evil: 1",
        "https://idp.example.com/authorize\nX-Evil: 1",
        "https://idp.example.com/authorize?x=\u{0}",
        "https://idp.example.com/authorize?x=\u{7f}",
    ] {
        let app = busbar_kernel_testkit::test_support::TestApp::new()
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

#[tokio::test]
async fn callback_state_mismatch_400() {
    let door = DoorLogin::new(alice());
    let app = busbar_kernel_testkit::test_support::TestApp::new()
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

#[tokio::test]
async fn callback_nonce_mismatch_rejected() {
    let door = std::sync::Arc::new(DoorLogin::answering(|request| {
        if request.nonce.as_deref() == Some("WRONG-NONCE") {
            alice()
        } else {
            LoginOutcome::SecurityCheckFailed
        }
    }));
    let app = busbar_kernel_testkit::test_support::TestApp::new()
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

#[tokio::test]
async fn no_self_serve_grant_renders_branded_html() {
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
                    .map(|(_, v)| v.expose(&busbar_kernel::seal::lend()).as_str())
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

fn cred_gov() -> std::sync::Arc<busbar_kernel::governance::GovState> {
    std::sync::Arc::new(
        busbar_kernel::governance::GovState::new_with_signer(
            std::sync::Arc::new(
                busbar_kernel_testkit::test_support::store_double::MemoryStore::new(),
            ),
            None,
            Some(
                busbar_kernel::governance::signing::TokenSigner::from_secret_bytes(
                    &[7u8; 32],
                    busbar_kernel::governance::signing::DEFAULT_KID,
                ),
            ),
        )
        .unwrap(),
    )
}

fn cred_bindings() -> busbar_kernel::config::RoleBindings {
    use std::collections::BTreeMap;
    let mut role = BTreeMap::new();
    role.insert(
        "members".to_string(),
        busbar_kernel::config::RoleBindingCfg {
            allowed_pools: None,
            group: Some("team".into()),
            admin_scope: None,
            verbs: None,
            plane_grants: Default::default(),
        },
    );
    let mut outer: busbar_kernel::config::RoleBindings = BTreeMap::new();
    outer.insert("test-login-double".to_string(), role);
    outer
}

fn cred_app() -> std::sync::Arc<busbar_kernel::state::App> {
    let team: busbar_kernel::config::GroupCfg =
        serde_yaml::from_str("child_default:\n  limits:\n    - { budget: 500, per: month }\n")
            .expect("team group parses");
    let mut groups = std::collections::BTreeMap::new();
    groups.insert("team".to_string(), team);
    busbar_kernel_testkit::test_support::TestApp::new()
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

fn cred_handle(
    app: &std::sync::Arc<busbar_kernel::state::App>,
) -> std::sync::Arc<busbar_kernel::state::AppHandle> {
    std::sync::Arc::new(busbar_kernel::state::AppHandle::new(app.clone()))
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

fn extract_key(body: &str) -> String {
    let start = body.find("bbk_").expect("a bbk_ key in the issued page");
    body[start..]
        .chars()
        .take_while(|c| c.is_alphanumeric() || matches!(c, '_' | '-' | '.'))
        .collect()
}

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

#[tokio::test]
async fn redirect_begin_still_redirects() {
    let app = test_app_with_methods(vec![("microsoft", true)]);
    let resp = begin(&app, "microsoft", false).await;
    assert_eq!(resp.status().as_u16(), 302);
}

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

    let key = extract_key(&body);
    assert!(app
        .governance
        .as_ref()
        .unwrap()
        .verify_token(&key, busbar_kernel::store::now(), None)
        .is_some());
}

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

#[tokio::test]
async fn a_credential_method_on_the_redirect_callback_is_answered_as_1_5_5_answered_it() {
    let door = cred_login();
    let app = busbar_kernel_testkit::test_support::TestApp::new()
        .public_url("https://busbar.example.com")
        .login_method_door(
            "test-login-double",
            door.clone(),
            LoginKind::Credential,
            true,
        )
        .build();
    let resp = callback(
        &app,
        &cred_handle(&app),
        Some(cred_cookie("csrf-1", false)),
        "code123".into(),
        Some("csrf-1".into()),
    )
    .await;
    assert_eq!(
        resp.status().as_u16(),
        401,
        "1.5.5 answered the plugin's Reject"
    );
    let cleared = resp
        .headers()
        .get_all(axum::http::header::SET_COOKIE)
        .iter()
        .any(|v| v.to_str().unwrap_or("").contains("Max-Age=0"));
    assert!(cleared, "the single-use cookie is cleared");
    let body = body_of(resp);
    assert_branded_error_page(&body, "Sign-in was declined");
    assert!(
        body.contains("Your identity provider declined this sign-in."),
        "1.5.5's callback copy: {body}"
    );
    let seen = door.seen.lock().unwrap();
    assert_eq!(seen.len(), 1, "the plugin is asked, as 1.5.5 asked it");
    assert_eq!(seen[0].login.code.as_deref(), Some("code123"));
    assert!(
        seen[0].login.submitted.is_empty(),
        "no credentials ride a callback"
    );
}

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

#[tokio::test]
async fn refresh_rotates_key_and_revokes_the_old_one() {
    let app = cred_app();
    let creds = || {
        vec![
            ("username".to_string(), "alice".to_string()),
            ("password".to_string(), "pw".to_string()),
        ]
    };

    let mut f1 = vec![("__state".to_string(), "s1".to_string())];
    f1.extend(creds());
    let body1 =
        body_of(credential_submit(&app, &cred_handle(&app), cred_cookie("s1", false), f1).await);
    let key1 = extract_key(&body1);

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

    assert!(page.contains("Refresh key"));
    assert!(page.contains("/auth/token?method=microsoft"));
    assert!(!page.contains("won't see this key again"));
}

#[test]
fn key_page_has_copy_buttons_wired_to_clipboard() {
    let page = render_key_issued(
        "sam@acme.com",
        "user:sam",
        "bb_live_7Qm2",
        "https://busbar.example.com",
        "microsoft",
    );

    assert!(
        page.contains("function bbCopy(") && page.contains("navigator.clipboard"),
        "the self-contained copy JS is inlined"
    );
    assert!(
        page.contains("document.execCommand('copy')"),
        "a non-secure-context fallback is present"
    );

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

    assert!(
        page.contains("class=\"signout\"")
            && page.contains("href=\"/auth/token?logout=1\"")
            && page.contains("Sign out"),
        "the success page offers a Sign out control: {page}"
    );
}

#[tokio::test]
async fn logout_renders_signed_out_and_clears_cookie() {
    let app = test_app_with_methods(vec![("microsoft", true)]);
    let handle = cred_handle(&app);
    let req = axum::http::Request::builder()
        .uri("/auth/token?logout=1")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = browser(handle, req).await;
    assert_eq!(resp.status().as_u16(), 200);

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

    assert!(
        body.contains("doesn't revoke your key"),
        "copy is honest about scope: {body}"
    );
}

#[test]
fn pkce_code_challenge_is_s256_of_verifier() {
    let verifier = random_b64url(32);
    let challenge = code_challenge_s256(&verifier);
    let expected = B64.encode(ring::digest::digest(
        &ring::digest::SHA256,
        verifier.as_bytes(),
    ));
    assert_eq!(challenge, expected);

    assert!(!challenge.contains('+') && !challenge.contains('/') && !challenge.contains('='));
}

#[tokio::test]
async fn auth_token_bypasses_middleware_exact_match() {
    busbar_kernel_testkit::test_support::metrics::init();

    let mut cfg = busbar_kernel::config::AuthCfg::default_none();
    cfg.chain = vec![busbar_kernel::config::AuthChainEntry::bare("keys")];
    let auth =
        std::sync::Arc::new(busbar_kernel_testkit::test_support::auth_helpers::new_builtin(&cfg));
    let app = busbar_kernel_testkit::test_support::TestApp::new()
        .auth(auth)
        .public_url("https://busbar.example.com")
        .build();
    let (base, handle) = serve(app).await;
    let client = reqwest::Client::new();

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

    let p = client
        .post(format!("{base}/auth/token"))
        .send()
        .await
        .unwrap();
    assert_ne!(p.status().as_u16(), 404);
    assert_ne!(p.status().as_u16(), 405);

    let h = client.get(format!("{base}/healthz")).send().await.unwrap();
    assert!(h.status().is_success() || h.status().as_u16() == 503);

    let m = client.get(format!("{base}/metrics")).send().await.unwrap();
    assert_eq!(m.status().as_u16(), 401, "/metrics must still be gated");

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
    busbar_kernel_testkit::test_support::metrics::init();
    let app = busbar_kernel_testkit::test_support::TestApp::new()
        .admin_chain(vec![])
        .public_url("https://busbar.example.com")
        .build();
    busbar_kernel::auth::login::seam::install(SEAM);
    let (data, admin, _handle) =
        busbar_kernel::build_split_routers_with_limits(app, 1 << 20, 0, false);

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

#[tokio::test]
async fn auth_token_bypass_does_not_apply_on_the_admin_router() {
    busbar_kernel_testkit::test_support::metrics::init();
    let app = busbar_kernel_testkit::test_support::TestApp::new()
        .keys_chain()
        .public_url("https://busbar.example.com")
        .build();
    busbar_kernel::auth::login::seam::install(SEAM);
    let (_data, admin, _handle) =
        busbar_kernel::build_split_routers_with_limits(app, 1 << 20, 0, false);

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

#[tokio::test]
async fn core_route_bypass_is_exact_in_path_and_method() {
    busbar_kernel_testkit::test_support::metrics::init();
    let mut cfg = busbar_kernel::config::AuthCfg::default_none();
    cfg.chain = vec![busbar_kernel::config::AuthChainEntry::bare("keys")];
    let auth =
        std::sync::Arc::new(busbar_kernel_testkit::test_support::auth_helpers::new_builtin(&cfg));
    let app = busbar_kernel_testkit::test_support::TestApp::new()
        .auth(auth)
        .public_url("https://busbar.example.com")
        .build();
    let (base, handle) = serve(app).await;
    let client = reqwest::Client::new();

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

    let p = client
        .post(format!("{base}/auth/token"))
        .send()
        .await
        .unwrap();
    assert!(
        p.status().as_u16() != 404 && p.status().as_u16() != 405,
        "POST /auth/token is declared open and must reach its handler, which runs the chain itself"
    );

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

async fn serve(
    app: std::sync::Arc<busbar_kernel::state::App>,
) -> (String, tokio::task::JoinHandle<()>) {
    busbar_kernel::auth::login::seam::install(SEAM);
    let router = busbar_kernel::build_router(app);
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

fn parking_login(kind: LoginKind) -> std::sync::Arc<DoorLogin> {
    std::sync::Arc::new(DoorLogin {
        kind,
        begin: LoginOutcome::Authorize("https://idp.example.com/authorize".into()),
        park: Some(std::time::Duration::from_secs(3)),
        ..DoorLogin::answering(|_| LoginOutcome::Reject)
    })
}

fn two_worker_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("test runtime")
}

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

#[test]
fn concurrent_anonymous_begin_does_not_starve_the_runtime() {
    let rt = two_worker_runtime();
    let app = rt.block_on(async {
        busbar_kernel_testkit::test_support::TestApp::new()
            .public_url("https://busbar.example.com")
            .login_method_door(
                "test-login-double",
                parking_login(LoginKind::Redirect),
                LoginKind::Redirect,
                true,
            )
            .build()
    });

    let tasks: Vec<_> = (0..4)
        .map(|_| {
            let a = app.clone();
            rt.spawn(async move { begin(&a, "test-login-double", false).await.status() })
        })
        .collect();

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

#[test]
fn concurrent_credential_submit_does_not_starve_the_runtime() {
    let rt = two_worker_runtime();
    let (app, handle) = rt.block_on(async {
        let app = busbar_kernel_testkit::test_support::TestApp::new()
            .public_url("https://busbar.example.com")
            .login_method_door(
                "test-login-double",
                parking_login(LoginKind::Credential),
                LoginKind::Credential,
                true,
            )
            .build();
        let handle = std::sync::Arc::new(busbar_kernel::state::AppHandle::new(app.clone()));
        (app, handle)
    });

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

#[tokio::test]
async fn callback_security_check_failed_renders_the_state_mismatch_bytes() {
    let app = busbar_kernel_testkit::test_support::TestApp::new()
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

fn door_app(door: std::sync::Arc<DoorLogin>) -> std::sync::Arc<busbar_kernel::state::App> {
    busbar_kernel_testkit::test_support::TestApp::new()
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
    let app = door_app(DoorLogin::new(LoginOutcome::Outage {
        retry_after_secs: None,
    }));
    let unreachable = callback(
        &app,
        &cred_handle(&app),
        Some(door_cookie().encode()),
        "the-code".into(),
        Some("st".into()),
    )
    .await;
    let page = provider_unreachable(None);

    assert_eq!(unreachable.status().as_u16(), 503);
    assert_eq!(
        unreachable
            .headers()
            .get("retry-after")
            .map(|v| v.to_str().unwrap()),
        Some(PROVIDER_RETRY_AFTER_SECS.to_string().as_str()),
        "retryable: the client is told when"
    );
    assert_eq!(unreachable.status(), page.status());
    assert_eq!(body_of(unreachable), body_of(page));
}

#[tokio::test]
async fn an_outage_sends_the_idps_retry_after_clamped() {
    for (stated, sent) in [
        (Some(120), 120),
        (Some(999_999), 3600),
        (Some(u64::MAX), 3600),
        (Some(3600), 3600),
        (Some(1), 1),
        (Some(0), 1),
        (None, 5),
    ] {
        let outcome = LoginOutcome::Outage {
            retry_after_secs: stated,
        };
        let retry_after = |resp: &Response| {
            resp.headers()
                .get("retry-after")
                .map(|v| v.to_str().unwrap().to_string())
        };
        let app = door_app(DoorLogin::new(outcome.clone()));
        let redirect = callback(
            &app,
            &cred_handle(&app),
            Some(door_cookie().encode()),
            "the-code".into(),
            Some("st".into()),
        )
        .await;
        assert_eq!(redirect.status().as_u16(), 503, "{stated:?}");
        assert_eq!(retry_after(&redirect), Some(sent.to_string()), "{stated:?}");
        assert_branded_error_page(&body_of(redirect), "Couldn't reach your provider");

        let door = std::sync::Arc::new(DoorLogin {
            kind: LoginKind::Credential,
            ..DoorLogin::answering(move |_| outcome.clone())
        });
        let app = busbar_kernel_testkit::test_support::TestApp::new()
            .public_url("https://busbar.example.com")
            .login_method_door("idp", door, LoginKind::Credential, true)
            .build();
        let cookie = LoginCookie {
            method: "idp".into(),
            code_verifier: String::new(),
            state: "csrf-1".into(),
            nonce: String::new(),
            refresh: false,
        };
        let form = vec![
            ("__state".to_string(), "csrf-1".to_string()),
            ("username".to_string(), "alice".to_string()),
            ("password".to_string(), "pw".to_string()),
        ];
        let posted = credential_submit(&app, &cred_handle(&app), cookie.encode(), form).await;
        assert_eq!(posted.status().as_u16(), 503, "{stated:?}");
        assert_eq!(retry_after(&posted), Some(sent.to_string()), "{stated:?}");
        assert_branded_error_page(&body_of(posted), "Couldn't reach your provider");
    }
}

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
        let cap = busbar_kernel_testkit::test_support::warn_capture::WarnCapture::default();
        let subscriber = tracing_subscriber::registry().with(cap.clone());
        let statuses = tracing::subscriber::with_default(subscriber, || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime");
            rt.block_on(async {
                let app = busbar_kernel_testkit::test_support::TestApp::new()
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

#[tokio::test]
async fn the_client_secret_rides_nothing_the_flow_makes() {
    const SECRET: &str = "REAL-SECRET-XYZ";
    let door = DoorLogin::new(alice());
    let app = busbar_kernel_testkit::test_support::TestApp::new()
        .public_url("https://busbar.example.com")
        .login_method_door("idp", door.clone(), LoginKind::Redirect, true)
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
    let seen = format!("{:?}", door.seen.lock().unwrap());
    assert!(
        !seen.contains(SECRET),
        "not in the complete_login the plugin is handed: {seen}"
    );
    assert!(
        !body_of(called).contains(SECRET),
        "not on the page rendered"
    );
}

fn golden_cell(name: &str) -> serde_json::Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testing/shadow-oracle/golden/1.5.5/cells")
        .join(name);
    let text = std::fs::read_to_string(&path).expect("the 1.5.5 golden cell");
    serde_json::from_str(&text).expect("golden json")
}

#[tokio::test]
async fn the_hosted_login_page_moved_with_its_1_5_5_bytes() {
    busbar_kernel_testkit::test_support::metrics::init();
    let golden = golden_cell("http.crosscut__auth-token__GET-none.json");
    let app = busbar_kernel_testkit::test_support::TestApp::new().build();
    let (base, handle) = serve(app).await;
    let client = reqwest::Client::new();
    let got = client
        .get(format!("{base}/auth/token"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        u64::from(got.status().as_u16()),
        golden["status"].as_u64().unwrap()
    );
    for name in ["cache-control", "content-type", "content-length"] {
        assert_eq!(
            got.headers().get(name).and_then(|v| v.to_str().ok()),
            golden["headers"][name].as_str(),
            "the {name} header is 1.5.5's"
        );
    }
    let page = got.text().await.unwrap();
    assert_eq!(
        page,
        golden["body"]["text"].as_str().unwrap(),
        "the page is 1.5.5's"
    );

    let signed_out = client
        .get(format!("{base}/auth/token?logout=1"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_ne!(signed_out, golden["body"]["text"].as_str().unwrap());
    handle.abort();
}

#[test]
fn a_login_cookie_in_a_later_field_matches_its_joined_form() {
    let cookie = door_cookie().encode();
    let mut split = Request::new(Body::empty());
    split
        .headers_mut()
        .append(header::COOKIE, "unrelated=first".parse().unwrap());
    split.headers_mut().append(
        header::COOKIE,
        format!("{LOGIN_COOKIE}={cookie}").parse().unwrap(),
    );
    let mut joined = Request::new(Body::empty());
    joined.headers_mut().insert(
        header::COOKIE,
        format!("unrelated=first; {LOGIN_COOKIE}={cookie}")
            .parse()
            .unwrap(),
    );
    let split_value = read_cookie(&split).expect("the login cookie is present");
    assert_eq!(Some(split_value.clone()), read_cookie(&joined));
    assert_eq!(
        LoginCookie::decode(&split_value).unwrap().state,
        door_cookie().state
    );
}

#[test]
fn login_cookie_fields_keep_first_match_and_existing_pair_grammar() {
    for (fields, expected) in [
        (
            vec!["busbar_login=first", "busbar_login=second"],
            Some("first"),
        ),
        (
            vec!["other=x", "busbar_login=first; busbar_login=second"],
            Some("first"),
        ),
        (vec!["busbar_login=", "busbar_login=second"], Some("")),
        (vec!["bad-pair", " busbar_login=value "], Some("value")),
        (vec!["busbar_login =wrong", "other=x"], None),
    ] {
        let mut req = Request::new(Body::empty());
        for field in fields {
            req.headers_mut()
                .append(header::COOKIE, field.parse().unwrap());
        }
        assert_eq!(read_cookie(&req).as_deref(), expected);
    }
    let mut req = Request::new(Body::empty());
    req.headers_mut().append(
        header::COOKIE,
        axum::http::HeaderValue::from_bytes(b"unreadable=\x80").unwrap(),
    );
    req.headers_mut()
        .append(header::COOKIE, "busbar_login=later".parse().unwrap());
    assert_eq!(read_cookie(&req), None);
}
