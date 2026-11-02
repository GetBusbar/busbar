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
        let body = render_chooser(
            &[((*token).to_string(), button_brand(token, None))],
            "https://busbar.example.com",
        );
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

#[test]
fn begin_with_an_unrepresentable_authorize_url_fails_closed_not_panics() {
    for bad in [
        "https://idp.example.com/authorize\r\nX-Evil: 1",
        "https://idp.example.com/authorize\nX-Evil: 1",
        "https://idp.example.com/authorize?x=\u{0}",
        "https://idp.example.com/authorize?x=\u{7f}",
    ] {
        let resp = begin_outcome(
            "microsoft",
            "https://busbar.example.com",
            "verifier".into(),
            "state".into(),
            "nonce".into(),
            false,
            LoginOutcome::Authorize(bad.to_string()),
        );
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

#[test]
fn a_door_login_begins_with_the_plugins_authorize_url() {
    let resp = begin_outcome(
        "idp",
        "https://busbar.example.com",
        "verifier".into(),
        "state".into(),
        "nonce".into(),
        false,
        LoginOutcome::Authorize("https://idp.example.com/authorize?x=1".into()),
    );
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

#[test]
fn a_door_callback_renders_each_answer_on_its_page() {
    for (outcome, status, heading) in [
        (
            LoginOutcome::SecurityCheckFailed,
            400,
            "Sign-in couldn't be verified",
        ),
        (LoginOutcome::Reject, 401, "Sign-in was declined"),
    ] {
        let resp = callback_outcome("idp", outcome.clone()).unwrap_err();
        assert_eq!(resp.status().as_u16(), status, "{outcome:?}");
        assert_branded_error_page(&body_of(resp), heading);
    }
    let principal = callback_outcome("idp", LoginOutcome::Identify(Principal::from_id("alice")))
        .expect("an identified principal passes through to the real self-key issuer");
    assert_eq!(principal.id, "alice");
    let unreachable = callback_outcome(
        "idp",
        LoginOutcome::Outage {
            retry_after_secs: None,
        },
    )
    .unwrap_err();
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

#[test]
fn an_outage_sends_the_idps_retry_after_clamped() {
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
        let redirect = callback_outcome("idp", outcome.clone()).unwrap_err();
        assert_eq!(redirect.status().as_u16(), 503, "{stated:?}");
        assert_eq!(retry_after(&redirect), Some(sent.to_string()), "{stated:?}");
        assert_branded_error_page(&body_of(redirect), "Couldn't reach your provider");

        let posted = credential_outcome("idp", outcome).unwrap_err();
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
