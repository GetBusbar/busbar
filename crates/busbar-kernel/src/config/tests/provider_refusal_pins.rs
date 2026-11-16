// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::HashMap;

use super::{resolve, ProviderDef, ProviderDeploy};

fn deployment_refusal(key: &str) -> busbar_contract::yaml::Error {
    crate::config::deploy_from_yaml_str(&format!(
        "providers:\n  p:\n    api_key: {{module: fixture-source, settings: {{slot: K}}}}\n    {key}: [a]\n"
    ), &crate::config::Grammar::empty())
    .expect_err("a sequence where the provider key wants a scalar or a map is refused")
}

/// The refusal names 1.5.5's key path, the YAML library's error kind (its exact sentence is the
/// library's wording, not busbar's) and 1.5.5's position of the offending value.
fn assert_refused_at(
    error: &busbar_contract::yaml::Error,
    path: &str,
    kind: &str,
    line: u64,
    column: u64,
) {
    let message = error.to_string();
    assert!(message.starts_with(&format!("{path}: ")), "{message}");
    assert!(message.contains(kind), "{message}");
    assert!(
        message.ends_with(&format!(" at line {line} column {column}")),
        "{message}"
    );
    assert_eq!(
        error.location().map(|at| (at.line(), at.column())),
        Some((line, column)),
        "{message}"
    );
}

#[test]
fn a_deployment_protocol_of_the_wrong_type_is_refused_as_1_5_5_did() {
    assert_refused_at(
        &deployment_refusal("protocol"),
        "providers.p.protocol",
        "expected string scalar",
        4,
        15,
    );
}

#[test]
fn a_deployment_error_map_of_the_wrong_type_is_refused_as_1_5_5_did() {
    assert_refused_at(
        &deployment_refusal("error_map"),
        "providers.p.error_map",
        "expected mapping start",
        4,
        16,
    );
}

#[test]
fn a_deployment_path_of_the_wrong_type_is_refused_as_1_5_5_did() {
    assert_refused_at(
        &deployment_refusal("path"),
        "providers.p.path",
        "expected string scalar",
        4,
        11,
    );
}

#[test]
fn a_deployment_path_base_of_the_wrong_type_is_refused_as_1_5_5_did() {
    assert_refused_at(
        &deployment_refusal("path_base"),
        "providers.p.path_base",
        "expected string scalar",
        4,
        16,
    );
}

#[test]
fn a_catalog_entry_with_no_protocol_is_refused_as_1_5_5_did() {
    let e = busbar_contract::yaml::from_str::<HashMap<String, ProviderDef>>(
        "p:\n  base_url: https://x.example\n",
    )
    .expect_err("a catalog entry must name its protocol");
    assert_refused_at(&e, "p", "missing field `protocol`", 2, 3);
}

fn composed_refusals() -> Vec<String> {
    let def: ProviderDef = busbar_contract::yaml::from_str(
        "protocol: proto-a\nbase_url: https://169.254.169.254\npath: /latest/meta-data\n\
         path_base: /v1\n",
    )
    .expect("a catalog entry");
    let dep: ProviderDeploy =
        busbar_contract::yaml::from_str("api_key: {module: fixture-source, settings: {slot: K}}\n")
            .expect("a deployment");
    let mut deploy = super::tests::base_deploy();
    deploy.providers.insert("p".to_string(), dep);
    let defs = HashMap::from([("p".to_string(), def)]);
    let cfg = resolve(&deploy, &defs).expect("the provider resolves");
    crate::config_validate::validate(&cfg)
        .expect_err("a metadata destination is refused")
        .into_iter()
        .filter(|e| e.contains("base_url+path"))
        .collect()
}

#[test]
fn the_composed_path_and_path_base_destinations_are_refused_as_1_5_5_did() {
    assert_eq!(
        composed_refusals(),
        vec![
            crate::diagnostics::coded::config_provider_destination_blocked(
                "provider 'p' base_url+path 'https://169.254.169.254/latest/meta-data' targets a \
             blocked cloud-metadata host '169.254.169.254' (cloud-metadata/IMDS endpoints are \
             denied; to override add the host to this provider's allow_metadata_hosts, or \
             security.allow_metadata_hosts, or set security.allow_all_metadata: true)",
            )
            .to_string(),
            crate::diagnostics::coded::config_provider_destination_blocked(
                "provider 'p' base_url+path_base 'https://169.254.169.254/v1' targets a blocked \
             cloud-metadata host '169.254.169.254' (cloud-metadata/IMDS endpoints are denied; to \
             override add the host to this provider's allow_metadata_hosts, or \
             security.allow_metadata_hosts, or set security.allow_all_metadata: true)",
            )
            .to_string(),
        ]
    );
}
