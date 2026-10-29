// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A PROVIDER'S BASE URL, PRINTED (CREDENTIAL-LOCKDOWN A.3): an operator may spell `base_url` (or
//! `token_url`) with a `user:pass@`, which 1.5.5 accepted and presented upstream as Basic (row 74,
//! F25). The parsed provider structs print through `Debug` with that userinfo redacted, and the
//! value the outbound request is built from keeps it, so what is sent upstream is unchanged.

use std::collections::HashMap;

use super::{resolve, ProviderCfg, ProviderDef, ProviderDeploy, ResolvedProvider};

const PASS: &str = "pw-prov-s3cr3t";
const USER: &str = "svc-prov-user";
const TOKEN_PASS: &str = "tok-prov-s3cr3t";

fn base_url() -> String {
    format!("https://{USER}:{PASS}@upstream.example.test:8443/v1")
}

fn token_url() -> String {
    format!("https://cid:{TOKEN_PASS}@login.example.test/token")
}

/// No secret of the URLs above appears in `printed`, and the hosts do.
fn assert_redacted(what: &str, printed: &str) {
    for secret in [PASS, USER, TOKEN_PASS] {
        assert!(
            !printed.contains(secret),
            "{what}'s Debug print leaks {secret:?}: {printed}"
        );
    }
    assert!(
        printed.contains("upstream.example.test:8443/v1"),
        "{what}'s Debug print keeps the host and path (the diagnosis): {printed}"
    );
}

fn provider_cfg() -> ProviderCfg {
    serde_yaml::from_str(&format!(
        "protocol: proto-a\nbase_url: \"{}\"\napi_key: {{env: K}}\nerror_map: {{}}\n\
         token_url: \"{}\"\n",
        base_url(),
        token_url()
    ))
    .expect("a whole provider entry")
}

fn provider_def() -> ProviderDef {
    serde_yaml::from_str(&format!(
        "protocol: proto-a\nbase_url: \"{}\"\ntoken_url: \"{}\"\n",
        base_url(),
        token_url()
    ))
    .expect("a catalog entry")
}

fn provider_deploy() -> ProviderDeploy {
    serde_yaml::from_str(&format!(
        "api_key: {{env: K}}\nbase_url: \"{}\"\ntoken_url: \"{}\"\n",
        base_url(),
        token_url()
    ))
    .expect("a deployment")
}

/// RED (base: every provider struct derived `Debug` over the URL as written).
#[test]
fn a_provider_base_url_prints_without_its_userinfo() {
    assert_redacted("ProviderCfg", &format!("{:?}", provider_cfg()));
    assert_redacted("ProviderDef", &format!("{:?}", provider_def()));
    assert_redacted("ProviderDeploy", &format!("{:?}", provider_deploy()));
    assert_redacted(
        "ResolvedProvider",
        &format!(
            "{:?}",
            ResolvedProvider::merge(&provider_def(), &provider_deploy())
        ),
    );
    assert_redacted(
        "ResolvedProvider (whole entry)",
        &format!("{:?}", ResolvedProvider::from(provider_cfg())),
    );
    // The resolved config (a `Debug` print of the whole thing reaches the providers too).
    let mut deploy = super::tests::base_deploy();
    deploy.providers.insert("p".to_string(), provider_deploy());
    let cfg =
        resolve(&deploy, &HashMap::from([("p".to_string(), provider_def())])).expect("it resolves");
    assert_redacted("the resolved config", &format!("{cfg:?}"));
}

/// GUARD (passes before and after): the value the outbound request is built from is the URL as
/// written, so the userinfo still becomes the Basic credential 1.5.5 sent (row 74, F25).
#[test]
fn the_base_url_the_request_is_built_from_keeps_its_userinfo() {
    assert_eq!(provider_cfg().base_url, base_url());
    assert_eq!(
        provider_deploy().base_url.as_deref(),
        Some(base_url().as_str())
    );
    let resolved = ResolvedProvider::merge(&provider_def(), &provider_deploy());
    assert_eq!(resolved.base_url, base_url());
    assert_eq!(resolved.token_url.as_deref(), Some(token_url().as_str()));
    assert!(
        crate::bound_credential::UrlUserinfo::of(&resolved.base_url).is_some(),
        "the userinfo is still there to present upstream"
    );
}

/// A base URL with no userinfo prints exactly as written.
#[test]
fn a_plain_base_url_prints_as_written() {
    let def: ProviderDef =
        serde_yaml::from_str("protocol: proto-a\nbase_url: \"http://127.0.0.1:1\"\n")
            .expect("a catalog entry");
    assert!(
        format!("{def:?}").contains("base_url: \"http://127.0.0.1:1\""),
        "{def:?}"
    );
}
