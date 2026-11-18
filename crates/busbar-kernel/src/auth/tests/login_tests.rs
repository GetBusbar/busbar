// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::off_path::auth::login::missing_login_axis;

fn idp_with_secret(env: &str) -> crate::config::AuthCfg {
    let mut cfg = crate::config::AuthCfg::default_none();
    cfg.methods.insert(
        "idp".into(),
        crate::config::AuthMethodCfg {
            module: "idp-plugin".into(),
            browser_login: Some(crate::config::BrowserLoginCfg {
                client_secret: Some(crate::config::secret::fixed_reference(env)),
                client_id: Some("client-abc".into()),
                max_failures: None,
                failure_window: None,
            }),
            settings: serde_json::Map::new().into(),
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

#[test]
fn the_client_secret_is_lent_at_open() {
    const SECRET: &str = "REAL-SECRET-XYZ";
    let cfg = idp_with_secret("BUSBAR_TEST_LOGIN_SECRET_LENT");
    let method = &cfg.methods["idp"];
    let mut resolved = busbar_contract::plugin_settings::ResolvedSettings::from(
        serde_json::json!({"client_id":"client-abc"}),
    );
    lend_browser_login_secret(
        "idp",
        &method.module,
        method.browser_login.as_ref(),
        &["client_secret".into()],
        &crate::config::secret::fixed_value("BUSBAR_TEST_LOGIN_SECRET_LENT", SECRET.as_bytes()),
        &mut resolved,
    )
    .expect("the declared secret is resolved into the settings lent at open");
    assert_eq!(
        crate::config::secret::test_resolved_value(&resolved)["client_secret"],
        SECRET
    );
    assert_eq!(
        crate::config::secret::test_resolved_value(&resolved)["client_id"],
        "client-abc"
    );
    assert_eq!(
        crate::auth::instances::instance_label("idp"),
        "identity-providers.idp",
        "one instance per provider, whatever role opened it"
    );
}

#[test]
fn a_login_plugin_stating_no_client_secret_slot_is_refused_the_secret() {
    std::env::set_var("BUSBAR_TEST_LOGIN_SECRET_UNSLOTTED", "UNSLOTTED-SECRET");
    let cfg = idp_with_secret("BUSBAR_TEST_LOGIN_SECRET_UNSLOTTED");
    let method = &cfg.methods["idp"];
    let mut resolved = busbar_contract::plugin_settings::ResolvedSettings::default();
    let refusal = lend_browser_login_secret(
        "idp",
        &method.module,
        method.browser_login.as_ref(),
        &[],
        &crate::config::secret::SecretResolver::builtins_only(),
        &mut resolved,
    )
    .expect_err("an undeclared slot cannot receive a secret");
    assert!(
        refusal.contains("identity-providers.idp browser_login.client_secret")
            && refusal.contains("states no `client_secret` secret reference"),
        "{refusal}"
    );
    assert!(!refusal.contains("UNSLOTTED-SECRET"), "{refusal}");
    assert!(
        crate::config::secret::test_resolved_value(&resolved)
            .as_object()
            .unwrap()
            .is_empty(),
        "refusal never inserts the undeclared secret"
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
