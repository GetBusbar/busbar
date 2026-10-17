//! THE 1.5.5 REFUSALS OF A PROVIDER ENTRY'S DIALECT KEYS, BYTE FOR BYTE (row 155 B1).
//!
//! `protocol`, `error_map`, `path` and `path_base` are the four 1.5.5 provider keys B1 moves the
//! reading of out of the kernel (BUSBAR-1.6.0.md THE DESIGN §4: "its dialect fields go to the planes
//! that use the provider"; #49). The move must not change a refusal: its text, its order, the field
//! path it names, or whether it is caught at boot. Each test below pins one 1.5.5 refusal that no
//! other cell or test pins, at the stage 1.5.5 raised it. Already pinned elsewhere, and so not
//! repeated here: the unknown-protocol and invalid-StatusClass sentences (oracle BOOT-020, BOOT-022),
//! the leading-`/` sentences for `path` and `path_base` (BOOT-026..029), a catalog `protocol:` of
//! the wrong type (BOOT-122) and the provider unknown-key refusal (NEUT-U-providers).
//!
//! ONE ASSERTION PER REFUSAL, in its own test, so one sentence failing cannot shadow the next.

use std::collections::HashMap;

use super::{resolve, ProviderDef, ProviderDeploy};

/// The `config.yaml` refusal for a deployment provider whose `key` holds a YAML sequence, as the
/// live parse words it (`deploy_from_yaml_str`, the parse boot and `--validate` both run).
fn deployment_refusal(key: &str) -> String {
    crate::test_support::register_neutral_test_plane();
    crate::config::deploy_from_yaml_str(&format!(
        "providers:\n  p:\n    api_key: {{env: K}}\n    {key}: [a]\n"
    ))
    .expect_err("a sequence where the provider key wants a scalar or a map is refused")
    .to_string()
}

/// 1.5.5's `ProviderDeploy::protocol` is an `Option<String>` (v1.5.5 crates/busbar/src/config/mod.rs,
/// `struct ProviderDeploy`): serde's invalid-type sentence, at the value's own position.
#[test]
fn a_deployment_protocol_of_the_wrong_type_is_refused_as_1_5_5_did() {
    assert_eq!(
        deployment_refusal("protocol"),
        "providers.p.protocol: invalid type: sequence, expected a string at line 4 column 15"
    );
}

/// 1.5.5's `ProviderDeploy::error_map` is an `Option<HashMap<String, String>>`.
#[test]
fn a_deployment_error_map_of_the_wrong_type_is_refused_as_1_5_5_did() {
    assert_eq!(
        deployment_refusal("error_map"),
        "providers.p.error_map: invalid type: sequence, expected a map at line 4 column 16"
    );
}

/// 1.5.5's `ProviderDeploy::path` is an `Option<String>`.
#[test]
fn a_deployment_path_of_the_wrong_type_is_refused_as_1_5_5_did() {
    assert_eq!(
        deployment_refusal("path"),
        "providers.p.path: invalid type: sequence, expected a string at line 4 column 11"
    );
}

/// 1.5.5's `ProviderDeploy::path_base` is an `Option<String>`.
#[test]
fn a_deployment_path_base_of_the_wrong_type_is_refused_as_1_5_5_did() {
    assert_eq!(
        deployment_refusal("path_base"),
        "providers.p.path_base: invalid type: sequence, expected a string at line 4 column 16"
    );
}

/// 1.5.5's `ProviderDef::protocol` is a REQUIRED `String`: a catalog entry naming no dialect is
/// refused when `providers.yaml` is parsed (`appbuild::load_config_from_disk` prefixes it with
/// `providers.yaml: invalid YAML: `), never defaulted.
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

/// A provider whose `base_url` is a cloud-metadata host, with a `path` and a `path_base` override,
/// resolved and judged the way boot and `--validate` judge it; the composed-destination refusals it
/// draws, in the order drawn.
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

/// v1.5.5 crates/busbar/src/config_validate/mod.rs:406 (`base_url+path`) and :430
/// (`base_url+path_base`): the composed destination is re-judged against the metadata denylist, at
/// boot, `path` first.
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
