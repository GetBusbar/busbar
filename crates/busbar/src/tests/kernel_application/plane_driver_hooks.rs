// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::path::PathBuf;
use std::sync::Arc;

use busbar_contract::hooks::BudgetBucketState;
use busbar_kernel::plane_driver::{Bind, CallerFacts, CallerKey, HookBinder, HostHooks};

#[path = "../../root/tests/test_plugins.rs"]
mod plugins;

struct NoCaller;

impl CallerFacts for NoCaller {
    fn key(&self, _principal: &str) -> Option<CallerKey> {
        None
    }
    fn in_groups(&self, _principal: Option<&str>, _groups: &[String]) -> bool {
        true
    }
    fn rate_headroom(&self, _principal: &str, _pool: &str) -> Option<f64> {
        None
    }
    fn budget(&self, _principal: &str) -> Vec<BudgetBucketState> {
        Vec::new()
    }
    fn hook_read(&self, _: &str, _: Option<&str>, _: &str, _: bool) {}
}

#[tokio::test]
async fn a_routed_planes_section_attach_binds_to_its_units() {
    crate::dist_root_install::install();
    let directory = plugins::scratch(&format!(
        "plane-section-attach-{}",
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
            crate::root::test_plugins::FIXTURE_PUBLISHER,
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
    let endpoint = "http://127.0.0.1:1/hook";
    let credential = directory.join("upstream-credential");
    std::fs::write(&credential, b"pool-admission-unused-upstream-credential")
        .expect("write the normal file-backed upstream credential");
    let document = serde_json::json!({
        "providers": {
            "local": {"protocol": "jev", "base_url": "http://127.0.0.1:1",
                      "api_key": {"file": credential}}
        },
        "models": {},
        "decisions": {"models": {"m": {"provider": "local"}},
                      "hooks": ["closed", "redact"]},
        "auth": {"chain": [], "admin_auth": []},
        "advanced": {"allow_destinations": ["127.0.0.1"]},
        "store": {"module": store_module.expect("the actual store was staged"), "settings": settings},
        "hooks": {
            "closed": {"module": hook_module, "kind": "gate", "timeout_ms": 10_000,
                       "on_error": "weighted", "prompt": "ro", "user": "ro",
                       "settings": {"url": endpoint}},
            "redact": {"module": hook_module, "kind": "gate", "timeout_ms": 10_000,
                       "on_error": "weighted", "prompt": "rw", "user": "ro",
                       "settings": {"url": endpoint}}
        }
    });
    let deploy = busbar_kernel::config::deploy_from_deserializer(document)
        .expect("the actual plane and hook deployment parses");
    let providers = std::collections::HashMap::from([(
        "local".to_owned(),
        serde_json::from_value::<busbar_kernel::config::ProviderDef>(serde_json::json!({
            "protocol": "jev", "base_url": "http://127.0.0.1:1"
        }))
        .expect("the actual provider catalog entry parses"),
    )]);
    let config = busbar_kernel::config::resolve(&deploy, &providers)
        .expect("the actual plane and hook deployment resolves");
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
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
    .expect("the actual products build the section hook chains");
    limits.keep().expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let app = Arc::new(app);
    let attached =
        busbar_kernel::plane_driver::registry::plane_decl_for_config_section("decisions")
            .expect("the actual decisions plane is installed")
            .key;
    let binder = |plane_key: &str| HostHooks {
        host: busbar_kernel::plane_driver::engine_host(&app),
        caller: Arc::new(NoCaller),
        dialects: vec!["jev".to_string()],
        plane_key: plane_key.to_string(),
    };
    let pool = format!("{attached}/m");
    let unit = Bind {
        pool: &pool,
        principal: None,
        dialect: 0,
        request_id: None,
    };
    let bound = binder(attached)
        .bind(&unit)
        .expect("the section's attach binds to the plane's unit");
    assert_eq!(bound.gates.len(), 1, "the section's gate");
    assert_eq!(bound.rewrites.len(), 1, "the section's rewrite");

    assert!(binder("plane-b").bind(&unit).is_none());
    assert!(binder("").bind(&unit).is_none());
}
