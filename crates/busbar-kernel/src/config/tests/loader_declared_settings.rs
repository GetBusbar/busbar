// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Declaration policy from the retired loader runner, at its production owner.
//! The resolver is a scoped input boundary; these cases do not claim plugin resolution.
use super::*;

fn settings(value: serde_json::Value) -> serde_json::Map<String, serde_json::Value> {
    value.as_object().expect("settings object").clone()
}
fn resolver() -> SecretResolver {
    SecretResolver::with_plugin(Box::new(|module, settings| {
        Ok(Held::new(
            format!("resolved:{module}:{settings}").into_bytes(),
        ))
    }))
}
fn scope() -> busbar_contract::config_time::ConfigScope {
    busbar_contract::config_time::ConfigScope::config_time()
}
#[test]
fn a_reference_at_a_declared_field_resolves_as_the_kernel_resolves_it() {
    let written = settings(serde_json::json!({
        "dsn": {"env":"PG_DSN"}, "replicas":[{"password":{"env":"R1"}}], "pool":4
    }));
    let out = resolve_settings(
        &written,
        &["dsn".into(), "replicas.*.password".into()],
        &[],
        "declaring-store",
        &resolver(),
        &scope(),
    )
    .expect("declared");
    let v = out.as_value();
    assert!(
        v["dsn"]
            .as_str()
            .is_some_and(|s| s.starts_with("resolved:")),
        "{v}"
    );
    assert!(
        v["replicas"][0]["password"]
            .as_str()
            .is_some_and(|s| s.starts_with("resolved:")),
        "{v}"
    );
    assert_eq!(v["pool"], serde_json::json!(4));
}
#[test]
fn a_reference_at_an_undeclared_field_is_refused_as_the_kernel_refuses_it() {
    let written = settings(serde_json::json!({"dsn":{"env":"PG_DSN"}}));
    let err = resolve_settings(&written, &[], &[], "silent-store", &resolver(), &scope())
        .expect_err("undeclared");
    assert!(
        err.contains("settings.dsn")
            && err.contains("silent-store")
            && err.contains("did not declare"),
        "{err}"
    );
}
#[test]
fn a_reference_capable_url_resolves_a_reference_and_passes_a_literal() {
    let written = settings(serde_json::json!({"url":{"env":"STORE_URL"},"password":{"env":"PW"}}));
    let out = resolve_settings(
        &written,
        &["password".into()],
        &["url".into()],
        "referencing-store",
        &resolver(),
        &scope(),
    )
    .expect("resolves");
    let v = out.as_value();
    assert!(
        v["url"]
            .as_str()
            .is_some_and(|s| s.starts_with("resolved:")),
        "{v}"
    );
    let literal = settings(serde_json::json!({"url":"postgres://db:5432/busbar"}));
    let out = resolve_settings(
        &literal,
        &["password".into()],
        &["url".into()],
        "referencing-store",
        &resolver(),
        &scope(),
    )
    .expect("as written");
    assert_eq!(
        out.as_value()["url"],
        serde_json::json!("postgres://db:5432/busbar")
    );
}
