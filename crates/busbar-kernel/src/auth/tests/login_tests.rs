// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The hosted login's identity side, the kernel's (row 159, K3#2): the login methods it opens and
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
        door: std::sync::Arc::new(OpenedLogin),
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
    let _methods = LoginMethods::build_on(
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

/// THE KERNEL SERVES NO HOSTED LOGIN PAGE OF ITS OWN (row 159, K3#2; THE DESIGN §8: the hosted
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
