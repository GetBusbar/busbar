// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_kernel::config::GroupCfg;
use std::collections::BTreeMap;

#[path = "../../root/tests/test_plugins.rs"]
mod plugins;

#[test]
fn boot_group_updates_and_self_mint_all_refuse_bucket_identity_collisions() {
    use busbar_kernel::governance::group_provision::{build_with_group, plan_mint_group};
    use std::sync::Arc;

    let groups: BTreeMap<String, GroupCfg> = serde_yaml::from_str(
        r#"
a:
  limits: [{ requests: 2, per: day, pool: 'x@day' }]
parent:
  child_default:
    limits: [{ budget: 4, per: day }]
"#,
    )
    .unwrap();
    let conflicting: GroupCfg = serde_yaml::from_str("limits: [{ budget: 4, per: day }]").unwrap();
    crate::dist_root_install::install();
    let library_path = std::path::PathBuf::from(
        std::env::var_os("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN")
            .expect("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN names the actual built store"),
    );
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual store statement reads")
        .expect("the actual store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual store statement is valid")
        .name;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        busbar_plugin_loader::sign::FIRST_PARTY_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = plugins::scratch("config-groups-collision");
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");
    let settings: serde_json::Value = serde_json::from_str(
        &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into()),
    )
    .expect("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS is JSON");
    assert!(
        settings.is_object(),
        "the actual store settings are an object"
    );
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "listen": "127.0.0.1:0",
        "providers": {"p": {"api_key": "none"}},
        "models": {"m": {"provider": "p"}},
        "pools": {"x@day": {"members": ["m"]}},
        "auth": {"chain": [], "admin_auth": []},
        "store": {"module": module, "settings": settings},
        "advanced": {"allow_destinations": ["127.0.0.1"]},
    }))
    .expect("the group collision deployment parses");
    let definitions = std::collections::HashMap::from([(
        "p".to_string(),
        serde_yaml::from_str("protocol: openai\nbase_url: http://127.0.0.1:1\n")
            .expect("the actual provider catalog"),
    )]);
    let config = busbar_kernel::config::resolve(&deploy, &definitions)
        .expect("the group collision deployment resolves");
    let plugin_config = busbar_kernel::config::PluginsCfg {
        enabled: true,
        dir: directory.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (app, rotate, limits) = busbar_kernel::build_app_from_config(
        config,
        plugin_config,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
    )
    .expect("the actual product builds the swap deployment");
    limits.keep().expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let app = Arc::new(app);
    let mut app = (*app).clone();
    app.groups_registry = groups.clone();
    app.cost = Arc::new(app.cost.with_groups(&groups));
    let current = Arc::new(app);
    let id = "group:a@day#pool:x@day";
    match build_with_group(&current, "a@day#pool:x", conflicting.clone()) {
        Err(busbar_kernel::config::transaction::TxnError::Validation(why)) => {
            assert!(why.contains(id), "{why}")
        }
        _ => panic!("an admin group candidate must refuse the shared bucket"),
    }
    match plan_mint_group(&current, "a@day#pool:x", Some("parent"), "fixture") {
        Err(busbar_kernel::config::transaction::TxnError::Validation(why)) => {
            assert!(why.contains(id), "{why}")
        }
        _ => panic!("self-mint must refuse the shared bucket before provisioning"),
    }
    assert!(!current.groups_registry.contains_key("a@day#pool:x"));

    let mut cfg = busbar_kernel::config::resolve(&deploy, &definitions)
        .expect("the boot validation deployment resolves");
    cfg.pools.insert("x@day".into(), Default::default());
    cfg.groups = groups;
    cfg.groups.insert("a@day#pool:x".into(), conflicting);
    let errors = busbar_kernel::config_validate::validate(&cfg)
        .expect_err("boot must refuse the shared bucket");
    assert!(errors.iter().any(|why| why.contains(id)), "{errors:?}");
}
