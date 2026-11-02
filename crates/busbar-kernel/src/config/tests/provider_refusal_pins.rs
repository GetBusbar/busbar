use std::collections::HashMap;

use super::{resolve, ProviderDef, ProviderDeploy};

fn deployment_refusal(key: &str) -> String {
    crate::test_support::register_neutral_test_plane();
    crate::config::deploy_from_yaml_str(&format!(
        "providers:\n  p:\n    api_key: {{env: K}}\n    {key}: [a]\n"
    ))
    .expect_err("a sequence where the provider key wants a scalar or a map is refused")
    .to_string()
}

#[test]
fn a_deployment_protocol_of_the_wrong_type_is_refused_as_1_5_5_did() {
    assert_eq!(
        deployment_refusal("protocol"),
        "providers.p.protocol: invalid type: sequence, expected a string at line 4 column 15"
    );
}

#[test]
fn a_deployment_error_map_of_the_wrong_type_is_refused_as_1_5_5_did() {
    assert_eq!(
        deployment_refusal("error_map"),
        "providers.p.error_map: invalid type: sequence, expected a map at line 4 column 16"
    );
}

#[test]
fn a_deployment_path_of_the_wrong_type_is_refused_as_1_5_5_did() {
    assert_eq!(
        deployment_refusal("path"),
        "providers.p.path: invalid type: sequence, expected a string at line 4 column 11"
    );
}

#[test]
fn a_deployment_path_base_of_the_wrong_type_is_refused_as_1_5_5_did() {
    assert_eq!(
        deployment_refusal("path_base"),
        "providers.p.path_base: invalid type: sequence, expected a string at line 4 column 16"
    );
}

#[test]
fn a_catalog_entry_with_no_protocol_is_refused_as_1_5_5_did() {
    let e =
        serde_yaml::from_str::<HashMap<String, ProviderDef>>("p:\n  base_url: https://x.example\n")
            .expect_err("a catalog entry must name its protocol");
    assert_eq!(
        e.to_string(),
        "p: missing field `protocol` at line 2 column 3"
    );
}

fn composed_refusals() -> Vec<String> {
    let def: ProviderDef = serde_yaml::from_str(
        "protocol: proto-a\nbase_url: https://169.254.169.254\npath: /latest/meta-data\n\
         path_base: /v1\n",
    )
    .expect("a catalog entry");
    let dep: ProviderDeploy = serde_yaml::from_str("api_key: {env: K}\n").expect("a deployment");
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
            "provider 'p' base_url+path 'https://169.254.169.254/latest/meta-data' targets a \
             blocked cloud-metadata host '169.254.169.254' (cloud-metadata/IMDS endpoints are \
             denied; to override add the host to this provider's allow_metadata_hosts, or \
             security.allow_metadata_hosts, or set security.allow_all_metadata: true)"
                .to_string(),
            "provider 'p' base_url+path_base 'https://169.254.169.254/v1' targets a blocked \
             cloud-metadata host '169.254.169.254' (cloud-metadata/IMDS endpoints are denied; to \
             override add the host to this provider's allow_metadata_hosts, or \
             security.allow_metadata_hosts, or set security.allow_all_metadata: true)"
                .to_string(),
        ]
    );
}
