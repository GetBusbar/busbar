// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;

#[path = "../../root/tests/test_plugins.rs"]
mod plugins;

/// Migrates the four pool_rw_gate_resolves_as_rewrite_not_decision oracles through
/// the actual root, loader, signed webrequest product and committed App chains.
#[tokio::test]
async fn pool_rw_gate_resolves_as_rewrite_not_decision() {
    crate::dist_root_install::install();
    let directory = plugins::scratch(&format!(
        "kernel-pool-admission-{}",
        busbar_kernel::door::op_id().counter()
    ));
    let mut store_module = None;
    let mut hook_module = None;
    for (kind, variable) in [
        ("store", "BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN"),
        ("hook", "BUSBAR_TEST_WEBREQUEST_CDYLIB"),
    ] {
        let path = PathBuf::from(std::env::var_os(variable).unwrap_or_else(|| {
            panic!("{variable} must name the actual built product cdylib; this test never skips")
        }));
        let statement = busbar_plugin_loader::dispatch::rendering_of_library(&path)
            .expect("the actual product statement reads")
            .expect("the actual product exports its statement");
        let facts = busbar_contract::abi::mechanism::rendering::read(&statement)
            .expect("the actual product statement is valid");
        let mut manifest = plugins::manifest(
            kind,
            &facts.name,
            busbar_plugin_loader::sign::FIRST_PARTY_PUBLISHER,
        );
        manifest.statement = Some(hex::encode(statement));
        if kind == "hook" {
            // These are the actual webrequest product's declared content needs,
            // signed alongside its exact door rendering, not a synthetic hook tail.
            manifest.needs.prompt = busbar_contract::plugin_rows::NeedLevel::Rw;
            manifest.needs.user = busbar_contract::plugin_rows::NeedLevel::Ro;
            hook_module = Some(facts.name);
        } else {
            store_module = Some(facts.name);
        }
        let library = std::fs::read(&path).expect("the actual product library reads");
        let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
        std::fs::write(directory.join(format!("{kind}-product.tar.gz")), archive)
            .expect("stage the signed actual product archive");
    }
    let settings: serde_json::Value = serde_json::from_str(
        &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into()),
    )
    .expect("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS is JSON");
    assert!(
        settings.is_object(),
        "the actual store settings are an object"
    );
    let hook_module = hook_module.expect("the actual hook was staged");
    let document = serde_json::json!({
        "providers": {},
        "models": {},
        "auth": {"chain": [], "admin_auth": []},
        "advanced": {"allow_destinations": ["127.0.0.1"]},
        "store": {"module": store_module.expect("the actual store was staged"), "settings": settings},
        "hooks": {
            "rw": {"module": hook_module, "kind": "gate", "prompt": "rw",
                   "settings": {"url": "http://127.0.0.1:1/hook"}},
            "plain": {"module": hook_module, "kind": "gate", "prompt": "no",
                      "settings": {"url": "http://127.0.0.1:1/hook"}}
        },
        "pools": {
            "rewrite": {"members": [], "hooks": ["rw"]},
            "decision": {"members": [], "hooks": ["plain"]}
        }
    });
    let deploy = busbar_kernel::config::deploy_from_deserializer(document)
        .expect("the actual product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the actual product deployment resolves");
    let plugins = busbar_kernel::config::PluginsCfg {
        enabled: true,
        dir: directory.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (app, rotate, limits) = busbar_kernel::build_app_from_config(
        config,
        plugins,
        None,
        HashSet::new(),
        HashSet::new(),
        (None, None),
        None,
        &rules,
    )
    .expect("the actual root opens the signed products and builds the pool chains");
    limits.keep().expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    assert!(
        app.pool_gates("rewrite").is_empty(),
        "an rw gate must not resolve as a decision gate"
    );
    assert_eq!(
        app.pool_rewrites("rewrite").len(),
        1,
        "an rw gate must resolve into the pool rewrite chain"
    );
    assert_eq!(app.pool_gates("decision").len(), 1);
    assert!(app.pool_rewrites("decision").is_empty());
}
