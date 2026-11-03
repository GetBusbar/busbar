// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

#[test]
fn inbound_default_selects_declared_styles_and_refuses_provider_names() {
    let declared = busbar_contract::auth_calls::InboundStyle {
        module: "idp-plugin".into(),
        names: vec!["idp-plugin".into(), "request-signature".into()],
        points: busbar_contract::abi::auth::AuthPoints::HEAD,
    };
    let select = |style| select_inbound_provider(style, [("tenant-one", &declared)].into_iter());
    assert_eq!(select("request-signature").unwrap(), Some("tenant-one"));
    assert_eq!(select("idp-plugin").unwrap(), Some("tenant-one"));
    assert!(select("tenant-one").is_err());
    assert!(select("outbound-style").is_err());
    assert_eq!(select("").unwrap(), None);
}

#[test]
fn inbound_default_refuses_ambiguous_providers_and_unconfigured_styles() {
    let declared = busbar_contract::auth_calls::InboundStyle {
        module: "idp-plugin".into(),
        names: vec!["request-signature".into()],
        points: busbar_contract::abi::auth::AuthPoints::HEAD,
    };
    let error = select_inbound_provider(
        "request-signature",
        [("tenant-one", &declared), ("tenant-two", &declared)].into_iter(),
    )
    .expect_err("shared module style does not select between two configured providers");
    assert!(error.contains("tenant-one") && error.contains("tenant-two"));
    assert!(select_inbound_provider("request-signature", std::iter::empty()).is_err());
    assert_eq!(
        select_inbound_provider("", std::iter::empty()).unwrap(),
        None
    );
}

#[test]
fn inbound_default_cannot_reinterpret_a_provider_name_as_host_auth() {
    let declared = busbar_contract::auth_calls::InboundStyle {
        module: "idp-plugin".into(),
        names: vec!["request-signature".into()],
        points: busbar_contract::abi::auth::AuthPoints::HEAD,
    };
    for name in crate::config::builtin_identity_providers() {
        let error = select_inbound_provider("request-signature", [(name, &declared)].into_iter())
            .expect_err("a provider name cannot select a host auth arm");
        assert!(error.contains("reserved") && error.contains(name));
    }
    assert_eq!(
        select_inbound_provider("request-signature", [("ordinary", &declared)].into_iter())
            .unwrap(),
        Some("ordinary")
    );
}

// Actual opened-instance reuse, lookup custody, and generation replacement live in
// busbar's auth_login_tests::inbound_provider_retains_the_actual_opened_instance.

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
    // Internal production settings continuation: actual secret resolution and slot policy.
    const SECRET: &str = "REAL-SECRET-XYZ";
    std::env::set_var("BUSBAR_TEST_LOGIN_SECRET_LENT", SECRET);
    let cfg = idp_with_secret("BUSBAR_TEST_LOGIN_SECRET_LENT");
    let method = &cfg.methods["idp"];
    let mut resolved = serde_json::Map::from_iter([(
        "client_id".into(),
        serde_json::Value::String("client-abc".into()),
    )]);
    lend_browser_login_secret(
        "idp",
        &method.module,
        method.browser_login.as_ref(),
        &["client_secret".into()],
        &crate::config::secret::actual_product_resolver(),
        &mut resolved,
    )
    .expect("the declared secret is resolved into the settings lent at open");
    assert_eq!(resolved["client_secret"], SECRET);
    assert_eq!(resolved["client_id"], "client-abc");
    assert_eq!(login_label("idp"), "idp#login");
}

#[test]
fn a_login_plugin_stating_no_client_secret_slot_is_refused_the_secret() {
    std::env::set_var("BUSBAR_TEST_LOGIN_SECRET_UNSLOTTED", "UNSLOTTED-SECRET");
    let cfg = idp_with_secret("BUSBAR_TEST_LOGIN_SECRET_UNSLOTTED");
    let method = &cfg.methods["idp"];
    let mut resolved = serde_json::Map::new();
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
        resolved.is_empty(),
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
