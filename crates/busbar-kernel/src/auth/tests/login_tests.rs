// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The hosted login's identity side, the kernel's: the login methods it opens and
//! the `browser_login` rules it checks at build. The flow's own tests (pages, cookie, PKCE) moved
//! with it to `busbar-core-oauth2`.

use super::*;
use busbar_contract::auth::{BeginLogin, LoginKind};
use busbar_contract::auth_calls::{LoginCall, LoginCallback, LoginSettled};

/// An opened login-capable instance that is never stepped here: the build only opens it.
struct OpenedLogin;

impl AuthCalls for OpenedLogin {
    fn name(&self) -> &str {
        "opened-login"
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
        unreachable!("the build never verifies")
    }
    fn refresh(&self) -> Result<u64, String> {
        Ok(0)
    }
    fn login_kind(&self) -> Option<LoginKind> {
        Some(LoginKind::Redirect)
    }
    fn begin_login(&self, _: BeginLogin) -> Box<dyn LoginCall> {
        Box::new(LoginSettled(Some(LoginOutcome::Reject)))
    }
    fn complete_login(&self, _: LoginCallback) -> Box<dyn LoginCall> {
        Box::new(LoginSettled(Some(LoginOutcome::Reject)))
    }
}

/// A kind-neutral login door double: it never opens here (the build opens through the test's axis).
struct StatedLogin;

impl busbar_contract::abi::sdk::auth_door::VerifyPlugin for StatedLogin {
    fn validate(settings: &[u8]) -> Result<(), busbar_contract::abi::sdk::life::Refusal> {
        busbar_contract::abi::sdk::auth_door::validate_by_opening::<Self>(settings)
    }

    fn open_refusing(
        _: &[u8],
        _: &[&[u8]],
    ) -> Result<Self, busbar_contract::abi::sdk::life::Refusal> {
        Ok(StatedLogin)
    }
    fn verify(
        &self,
        _: &busbar_contract::abi::sdk::auth_door::VerifyView<'_>,
    ) -> busbar_contract::abi::sdk::auth_door::Answer {
        busbar_contract::abi::sdk::auth_door::Verdict::Pass.into()
    }
}

/// The linked auth door `idp-plugin`: only its Statement is read, and only by the loader.
mod door {
    use super::StatedLogin;
    use busbar_contract::abi::auth::{AuthPoints, AuthTail};
    use busbar_contract::abi::sdk::auth_door::{verify_tail, with_tail};
    use busbar_contract::abi::sdk::door::statement;

    const TAIL: &AuthTail = &verify_tail(0, AuthPoints::HEAD);

    busbar_contract::auth_verify_door!(
        StatedLogin,
        with_tail(statement("idp-plugin", "1.0.0", 8), TAIL)
    );
}

/// The rows holding the linked auth door `idp-plugin`, whose Statement states the secret
/// references `slots`. The kernel has no loader to read a door's Statement, so the rows double
/// states the slots (the loader's reading of `secret_refs` is proven in `crates/plugin-loader`,
/// `rows_tests::secret_slots_are_the_secret_refs_the_statement_names`).
fn rows_of(slots: &[&str]) -> crate::test_support::rows::Rows {
    crate::test_support::rows::Rows::new().with_linked_secret_slots(
        crate::preflight::LinkedRow::Auth(("idp-plugin", "idp-plugin", door::door)),
        slots,
    )
}

/// An axis that answers `idp-plugin` and records every `open` it is asked for.
struct Recording {
    opened: std::sync::Mutex<Vec<(String, String, serde_json::Value)>>,
    door: std::sync::Arc<OpenedLogin>,
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
        self.opened
            .lock()
            .unwrap()
            .push((module.to_string(), label.to_string(), settings.clone()));
        Ok(self.door.clone())
    }
}

impl Recording {
    fn new() -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            opened: std::sync::Mutex::new(Vec::new()),
            door: std::sync::Arc::new(OpenedLogin),
        })
    }
}

/// One `identity-providers.idp` method on `idp-plugin` with a `browser_login` whose client secret
/// resolves from the environment variable `env`.
fn idp_with_secret(env: &str) -> crate::config::AuthCfg {
    let mut cfg = crate::config::AuthCfg::default_none();
    cfg.methods.insert(
        "idp".into(),
        crate::config::AuthMethodCfg {
            module: "idp-plugin".into(),
            browser_login: Some(crate::config::BrowserLoginCfg {
                client_secret: Some(crate::config::SecretRef::env(env)),
                client_id: Some("client-abc".into()),
            }),
            settings: serde_json::Map::new(),
        },
    );
    cfg
}

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

/// THE CLIENT SECRET IS THE PLUGIN'S, LENT AT `open` (THE DESIGN 6.7). The host resolves
/// `browser_login.client_secret` and hands it to the plugin's `open` beside the public `client_id`
/// (the plugin makes its own token exchange with it). That it then rides nothing the hosted login
/// flow makes is the flow's own test (`busbar-core-oauth2`, `hosted_login_tests`). (Where the secret
/// may be SENT — the operator's own IdP hosts only — is the plugin's to enforce, ruling R8.)
#[tokio::test]
async fn the_client_secret_is_lent_at_open() {
    const SECRET: &str = "REAL-SECRET-XYZ";
    let axis = Recording::new();
    std::env::set_var("BUSBAR_TEST_LOGIN_SECRET_LENT", SECRET);
    let cfg = idp_with_secret("BUSBAR_TEST_LOGIN_SECRET_LENT");
    let _methods = LoginMethods::build_on(
        &cfg,
        &rows_of(&["client_secret"]),
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
}

/// THE CLIENT SECRET IS LENT ONLY INTO A STATED SECRET SLOT (IdP
/// logins hold their own client secret). The loader lifts out of the settings only the keys a
/// plugin's Statement names in `secret_refs`; a plugin that names no `client_secret` slot would be
/// handed the resolved secret inline in its plain settings text. Such a method is refused at build
/// and its plugin is never opened. RED before the fix: the build opened it with the secret in the
/// plain settings and answered `Ok`.
#[tokio::test]
async fn a_login_plugin_stating_no_client_secret_slot_is_refused_the_secret() {
    let axis = Recording::new();
    std::env::set_var("BUSBAR_TEST_LOGIN_SECRET_UNSLOTTED", "UNSLOTTED-SECRET");
    let cfg = idp_with_secret("BUSBAR_TEST_LOGIN_SECRET_UNSLOTTED");
    let built = LoginMethods::build_on(
        &cfg,
        &rows_of(&[]),
        &crate::config::secret::SecretResolver::builtins_only(),
        || Some(axis.clone() as std::sync::Arc<dyn busbar_contract::auth_calls::AuthAxis>),
    );
    let Err(refusal) = built else {
        panic!("a plugin stating no client_secret slot must not be lent the secret");
    };
    assert!(
        refusal.contains("identity-providers.idp browser_login.client_secret")
            && refusal.contains("states no `client_secret` secret reference"),
        "{refusal}"
    );
    assert!(
        !refusal.contains("UNSLOTTED-SECRET"),
        "the refusal never carries the secret: {refusal}"
    );
    assert!(
        axis.opened.lock().unwrap().is_empty(),
        "the plugin is never opened over the secret"
    );
}

/// THE KERNEL KEEPS NO COPY OF WHAT IT LENT (auth material is
/// zeroised). Every string of the lent settings document, nested ones included, is wiped.
#[test]
fn the_lent_settings_are_wiped() {
    let mut lent = serde_json::json!({
        "client_secret": "REAL-SECRET-XYZ",
        "client_id": "client-abc",
        "nested": {"token": "inner-secret", "list": ["a-secret", 7]},
    });
    crate::config::secret::wipe_strings(&mut lent);
    assert_eq!(
        lent,
        serde_json::json!({
            "client_secret": "",
            "client_id": "",
            "nested": {"token": "", "list": ["", 7]},
        })
    );
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
        &crate::test_support::rows::Rows::new(),
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

/// THE KERNEL SERVES NO HOSTED LOGIN PAGE OF ITS OWN (the hosted
/// login flow is `busbar-core-oauth2`'s). It mounts `GET /auth/token` declared open and reaches the
/// flow through the login seam; with no flow registered (this test binary links none) the path
/// answers 404, never a page, and never the chain's 401. RED before the move: the kernel rendered
/// the chooser itself (200, HTML).
#[tokio::test]
async fn the_kernel_serves_no_hosted_login_page_of_its_own() {
    crate::snapshot::init();
    let app = crate::test_support::TestApp::new()
        .public_url("https://busbar.example.com")
        .build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let got = reqwest::Client::new()
        .get(format!("http://{addr}/auth/token"))
        .send()
        .await
        .unwrap();
    assert_eq!(got.status().as_u16(), 404, "no flow registered, no page");
    assert!(
        !got.text().await.unwrap().contains("<html"),
        "the kernel renders no login page"
    );
    handle.abort();
}
