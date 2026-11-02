// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::auth::{BeginLogin, LoginKind};
use busbar_contract::auth_calls::{LoginCall, LoginCallback, LoginSettled};

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

fn rows_of(slots: &[&str]) -> crate::test_support::rows::Rows {
    crate::test_support::rows::Rows::new().with_linked_secret_slots(
        crate::preflight::LinkedRow::Auth(("idp-plugin", "idp-plugin", door::door)),
        slots,
    )
}

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
    fn inbound_style(&self, module: &str) -> Option<busbar_contract::auth_calls::InboundStyle> {
        (module == "idp-plugin").then(|| busbar_contract::auth_calls::InboundStyle {
            module: "idp-plugin".into(),
            names: vec!["idp-plugin".into(), "request-signature".into()],
            points: busbar_contract::abi::auth::AuthPoints::HEAD,
        })
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

fn headless_methods(names: &[&str], axis: &std::sync::Arc<Recording>) -> LoginMethods {
    let mut cfg = crate::config::AuthCfg::default_none();
    for name in names {
        cfg.methods.insert(
            (*name).into(),
            crate::config::AuthMethodCfg {
                module: "idp-plugin".into(),
                browser_login: None,
                settings: serde_json::Map::from_iter([(
                    "realm".into(),
                    serde_json::Value::String((*name).into()),
                )]),
            },
        );
    }
    LoginMethods::build_on(
        &cfg,
        &rows_of(&[]),
        &crate::config::secret::SecretResolver::builtins_only(),
        || Some(axis.clone() as std::sync::Arc<dyn busbar_contract::auth_calls::AuthAxis>),
    )
    .expect("headless providers open")
}

#[test]
fn inbound_default_reuses_candidate_provider_and_never_opens_on_lookup() {
    let axis = Recording::new();
    let methods = headless_methods(&["tenant-one"], &axis);
    let bound = methods
        .inbound_default_auth("request-signature")
        .unwrap()
        .unwrap();
    assert_eq!(bound.provider, "tenant-one");
    assert_eq!(bound.module, "idp-plugin");
    assert_eq!(bound.points, busbar_contract::abi::auth::AuthPoints::HEAD);
    let opened: std::sync::Arc<dyn AuthCalls> = axis.door.clone();
    assert!(std::sync::Arc::ptr_eq(&bound.calls, &opened));
    assert!(methods
        .inbound_default_auth("idp-plugin")
        .unwrap()
        .is_some());
    assert!(methods.inbound_default_auth("tenant-one").is_err());
    assert!(methods.inbound_default_auth("outbound-style").is_err());
    assert!(methods.inbound_default_auth("").unwrap().is_none());
    let calls = axis.opened.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].1, "tenant-one#login");
    assert_eq!(calls[0].2["realm"], "tenant-one");
}

#[test]
fn inbound_default_refuses_ambiguous_providers_and_unconfigured_styles() {
    let axis = Recording::new();
    let methods = headless_methods(&["tenant-one", "tenant-two"], &axis);
    let error = methods
        .inbound_default_auth("request-signature")
        .err()
        .expect("two configured providers cannot be selected by their shared module style");
    assert!(error.contains("tenant-one") && error.contains("tenant-two"));
    let empty = headless_methods(&[], &axis);
    assert!(empty.inbound_default_auth("request-signature").is_err());
    assert!(empty.inbound_default_auth("").unwrap().is_none());
}

#[test]
fn inbound_default_cannot_reinterpret_a_provider_name_as_host_auth() {
    let axis = Recording::new();
    for name in crate::config::builtin_identity_providers() {
        let methods = headless_methods(&[name], &axis);
        let error = methods
            .inbound_default_auth("request-signature")
            .err()
            .expect("a provider name must not select a host auth arm");
        assert!(error.contains("reserved") && error.contains(name));
    }
    assert!(headless_methods(&["ordinary"], &axis)
        .inbound_default_auth("request-signature")
        .unwrap()
        .is_some());
}

#[test]
fn inbound_default_retains_its_candidate_instance_across_replacement() {
    let old_axis = Recording::new();
    let old = headless_methods(&["tenant"], &old_axis);
    let bound = old
        .inbound_default_auth("request-signature")
        .unwrap()
        .unwrap();
    let next_axis = Recording::new();
    let next = headless_methods(&["tenant"], &next_axis);
    let replacement = next
        .inbound_default_auth("request-signature")
        .unwrap()
        .unwrap();
    assert!(!std::sync::Arc::ptr_eq(&bound.calls, &replacement.calls));
    drop(old);
    let opened: std::sync::Arc<dyn AuthCalls> = old_axis.door.clone();
    assert!(std::sync::Arc::ptr_eq(&bound.calls, &opened));
}

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

    assert!(validate_browser_login_secret(LoginKind::Redirect, true).is_ok());
    assert!(
        validate_browser_login_secret(LoginKind::Redirect, false).is_err(),
        "a redirect method with no client_secret must be refused"
    );

    assert!(validate_browser_login_secret(LoginKind::Credential, false).is_ok());
    assert!(
        validate_browser_login_secret(LoginKind::Credential, true).is_err(),
        "a credential method that sets client_secret must be refused"
    );
}

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

#[test]
fn a_login_method_with_no_auth_axis_is_refused_in_1_5_5_words() {
    // Internal production error formatter for an absent axis; no fake rows/axis are built.
    let refusal = missing_login_axis("idp", "idp-plugin");
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

#[tokio::test]
async fn without_a_registered_flow_the_kernel_has_no_hosted_login_response() {
    // Internal fallback response. The real root installs the genuine hosted flow; this
    // defensive no-registration branch is not presented as a real-root HTTP route.
    let response = unregistered_browser_response();
    assert_eq!(
        response.status().as_u16(),
        404,
        "no flow registered, no page"
    );
    let body = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        axum::body::to_bytes(response.into_body(), 64 * 1024),
    )
    .await
    .expect("the fallback response body is bounded")
    .unwrap();
    assert!(
        !String::from_utf8(body.to_vec()).unwrap().contains("<html"),
        "the kernel renders no login page"
    );
}
