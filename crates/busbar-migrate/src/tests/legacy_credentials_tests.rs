// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! LEGACY-KEYFILE-MARKER r2 (adopted) §3 and §7: STEPS binds a reached 1.5.5 jwt-bearer provider
//! and records its slot in the side table. Core reads no credential value.

use super::*;

fn yaml(text: &str) -> Value {
    busbar_contract::yaml::from_str(text).unwrap()
}

fn run(document: &str, catalog: &str) -> (Value, Vec<String>, Vec<Mark>) {
    let resolved = yaml(document);
    let mut after = resolved.clone();
    let mut report = Vec::new();
    let mut marks = Vec::new();
    bind_jwt_bearer(
        after.as_mapping_mut().unwrap(),
        &resolved,
        &yaml(catalog),
        &mut report,
        &mut marks,
    )
    .unwrap();
    (after, report, marks)
}

const CATALOG: &str = "vertex:\n  auth: jwt-bearer\n  scope: catalog-scope\n  token_url: https://t\nopenai:\n  protocol: openai\n";

/// (a) catalog-inherited style, env path: bound, marked, provider repointed (no squat).
#[test]
fn a_catalog_inherited_jwt_bearer_provider_is_bound_and_marked() {
    let (after, report, marks) = run(
        "providers:\n  vertex:\n    api_key: {env: SA}\nmodels:\n  m:\n    provider: vertex\n",
        CATALOG,
    );
    let binding = after
        .get("auth")
        .and_then(|a| a.get("vertex-outbound"))
        .unwrap();
    assert_eq!(
        binding
            .get("module")
            .and_then(|m| m.get("$style"))
            .and_then(Value::as_str),
        Some("jwt-bearer")
    );
    let config = binding.get("config").unwrap();
    assert_eq!(
        config.get("style").and_then(Value::as_str),
        Some("jwt-bearer")
    );
    assert_eq!(
        config
            .get("credential")
            .and_then(|c| c.get("env"))
            .and_then(Value::as_str),
        Some("SA"),
        "the reference moves as written"
    );
    let provider = after
        .get("providers")
        .and_then(|p| p.get("vertex"))
        .unwrap();
    assert_eq!(
        provider.get("auth").and_then(Value::as_str),
        Some("vertex-outbound")
    );
    assert!(provider.get("api_key").is_none());
    assert_eq!(
        marks,
        [Mark {
            instance: vec!["auth".into(), "vertex-outbound".into()],
            pointer: "/credential".into(),
        }]
    );
    assert!(
        !busbar_contract::yaml::to_string(&after)
            .unwrap()
            .contains(MIGRATED),
        "the written text never carries the marker"
    );
    assert_eq!(report.len(), 1, "{report:?}");
}

/// (b) authored style with an inline-JSON env: still bound and marked (no classification).
#[test]
fn an_authored_jwt_bearer_provider_is_bound_whatever_its_value() {
    let (after, _, marks) = run(
        "providers:\n  sa:\n    api_key: {env: SA_JSON}\n    auth: jwt-bearer\nmodels:\n  m:\n    provider: sa\n",
        "",
    );
    let provider = after.get("providers").and_then(|p| p.get("sa")).unwrap();
    assert_eq!(
        provider.get("auth").and_then(Value::as_str),
        Some("sa-outbound")
    );
    assert_eq!(marks.len(), 1);
}

/// (c) forwarded keys: authored first, else the catalog's; they leave the provider.
#[test]
fn forwarded_keys_reach_the_binding_settings_and_leave_the_provider() {
    let (after, _, _) = run(
        "providers:\n  vertex:\n    api_key: {env: SA}\n    subject: me@x\nmodels:\n  m:\n    provider: vertex\n",
        CATALOG,
    );
    let settings = after
        .get("auth")
        .and_then(|a| a.get("vertex-outbound"))
        .and_then(|b| b.get("config"))
        .and_then(|c| c.get("settings"))
        .unwrap();
    assert_eq!(
        settings.get("subject").and_then(Value::as_str),
        Some("me@x")
    );
    assert_eq!(
        settings.get("scope").and_then(Value::as_str),
        Some("catalog-scope")
    );
    assert_eq!(
        settings.get("token_url").and_then(Value::as_str),
        Some("https://t")
    );
    let provider = after
        .get("providers")
        .and_then(|p| p.get("vertex"))
        .unwrap();
    assert!(provider.get("subject").is_none());
}

/// (d) other providers are untouched.
#[test]
fn other_providers_are_byte_identical() {
    let document = "providers:\n  openai:\n    api_key: {env: K}\n  b:\n    api_key: {env: B}\n    auth: oauth-client-credentials\nmodels:\n  m:\n    provider: openai\n";
    let (after, report, marks) = run(document, CATALOG);
    assert_eq!(after, yaml(document));
    assert!(report.is_empty() && marks.is_empty());
}

/// (e) an unreached jwt-bearer provider gets no binding, no mark, and one report line.
#[test]
fn an_unreached_jwt_bearer_provider_is_reported_not_bound() {
    let (after, report, marks) = run(
        "providers:\n  sa:\n    api_key: {env: UNSET}\n    auth: jwt-bearer\nmodels:\n  m:\n    provider: other\n",
        "",
    );
    assert!(after.get("auth").is_none());
    assert!(marks.is_empty());
    let provider = after.get("providers").and_then(|p| p.get("sa")).unwrap();
    assert!(provider.get("auth").is_none() && provider.get("api_key").is_none());
    assert!(
        report[0].contains("config.yaml.1.5.5") && !report[0].contains("UNSET"),
        "{report:?}"
    );
}

/// (i) a `$migrated` anywhere in the input is refused.
#[test]
fn a_marker_in_the_input_is_refused() {
    let refused = refuse_marker(&yaml(
        "store:\n  module: m\n  settings: {\"$migrated\": {legacy: [\"/x\"]}}\n",
    ))
    .unwrap_err();
    assert!(refused
        .to_string()
        .contains("`$migrated` is core migration vocabulary"));
    assert!(refuse_marker(&yaml("store: {module: m}\n")).is_ok());
}

/// The binding's instance name already taken is refused.
#[test]
fn a_taken_instance_name_is_refused() {
    let resolved = yaml(
        "auth:\n  vertex-outbound: {module: x}\nproviders:\n  vertex:\n    api_key: {env: SA}\nmodels:\n  m:\n    provider: vertex\n",
    );
    let mut after = resolved.clone();
    let refused = bind_jwt_bearer(
        after.as_mapping_mut().unwrap(),
        &resolved,
        &yaml(CATALOG),
        &mut Vec::new(),
        &mut Vec::new(),
    )
    .unwrap_err();
    assert!(
        refused.to_string().contains("auth.vertex-outbound"),
        "{refused}"
    );
}
