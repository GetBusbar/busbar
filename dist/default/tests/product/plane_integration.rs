// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

mod linked {
    use busbar_kernel::plane_driver::registry::PlaneDecl;
    pub(super) fn install() {
        crate::dist_root_install::install();
    }
    pub(super) fn planes() -> &'static [&'static PlaneDecl] {
        install();
        busbar_kernel::plane_driver::registry::plane_decls()
    }
    pub(super) fn fallback() -> &'static PlaneDecl {
        planes()
            .iter()
            .copied()
            .find(|decl| decl.fallback)
            .expect("the actual distribution declares its fallback")
    }
}

use crate::root::test_plugins as plugins;
use busbar_contract::json::JsonValueTrait as _;
use busbar_kernel::config::RootCfg;
use busbar_kernel::plane_driver::registry::PlaneDecl;
use std::sync::Arc;

fn resolved(sections: &str) -> RootCfg {
    linked::install();
    let yaml = format!(
        "store: {{module: memory}}\n\
         providers:\n  acme: {{ api_key: none }}\n\
         models:\n  m: {{ provider: acme }}\n{sections}"
    );
    let deploy =
        busbar_kernel::config::deploy_from_yaml_str(&yaml, &crate::root::boot::axis_test_grammar())
            .expect("the document parses");
    let mut defs = std::collections::HashMap::new();
    defs.insert(
        "acme".to_string(),
        busbar_contract::yaml::from_str(&format!(
            "protocol: {}\nbase_url: https://api.example.com\n",
            (linked::fallback().provider_dialects)(linked::fallback())
                .first()
                .expect("the actual fallback declares provider dialects")
        ))
        .expect("provider def"),
    );
    let mut cfg = busbar_kernel::config::resolve(&deploy, &defs)
        .unwrap_or_else(|e| panic!("the document resolves: {e:?}"));
    let mut auth = busbar_kernel::config::AuthCfg::default_none();
    auth.chain = vec![busbar_kernel::config::AuthChainEntry::bare("keys")];
    let credentials = plugins::scratch("plane-integration-credentials");
    let signing_key = credentials.join("signing-key");
    let operator_token = credentials.join("operator-token");
    std::fs::write(&signing_key, hex::encode([9u8; 32]))
        .expect("write the actual file-backed signing input");
    std::fs::write(&operator_token, "admintok")
        .expect("write the actual file-backed operator input");
    auth.signing_key = Some(crate::root::test_plugins::source_reference(
        crate::root::native_secrets::linked_for_tests(),
        busbar_contract::plugin_settings::sugar_words::SUGAR_ROLE_PATH,
        signing_key.to_string_lossy().into_owned(),
    ));
    let operator = auth
        .admin_auth
        .iter_mut()
        .find(|entry| busbar_kernel::config::names_operator(&entry.module))
        .expect("the actual operator module");
    operator.token = Some(crate::root::test_plugins::source_reference(
        crate::root::native_secrets::linked_for_tests(),
        busbar_contract::plugin_settings::sugar_words::SUGAR_ROLE_PATH,
        operator_token.to_string_lossy().into_owned(),
    ));
    cfg.auth = Some(auth);
    cfg
}

#[tokio::test]
async fn plane_slot_is_none_when_the_plane_is_not_configured() {
    const CHILD: &str = "BUSBAR_PLANE_INTEGRATION_CHILD";
    if std::env::var(CHILD).ok().as_deref()
        != Some("plane_slot_is_none_when_the_plane_is_not_configured")
    {
        let module = module_path!()
            .split_once("::")
            .expect("a mounted test module")
            .1;
        let test = format!("{module}::plane_slot_is_none_when_the_plane_is_not_configured");
        let output = std::process::Command::new(std::env::current_exe().expect("test executable"))
            .args([test.as_str(), "--exact", "--nocapture", "--test-threads=1"])
            .env(CHILD, "plane_slot_is_none_when_the_plane_is_not_configured")
            .output()
            .expect("run the original behavior in a fresh product process");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success()
                && stdout.contains("running 1 test")
                && stdout.contains(&format!("test {test} ..."))
                && stdout.contains("1 passed; 0 failed; 0 ignored"),
            "the original behavior failed or did not run exactly once:\n{stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let cfg = resolved("");
    assert!(
        cfg.endpoint_resources.is_empty(),
        "fixture control: no endpoint door configured"
    );
    assert!(
        cfg.plane_defs.values().all(|d| d.def_names().is_empty()),
        "fixture control: no plane entries"
    );
    assert!(
        cfg.plane_sections.is_empty(),
        "fixture control: no plane section configured"
    );

    let mut cfg = cfg;
    crate::dist_root_install::install();
    let library_path = crate::root::test_plugins::application_store_library();
    let module = crate::root::test_plugins::native_image(&library_path).name;
    let manifest = crate::root::test_plugins::native_manifest(
        "store",
        &library_path,
        plugins::FIXTURE_PUBLISHER,
    );
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = plugins::scratch(&format!(
        "plane_integration-{}",
        busbar_kernel::door::op_id().counter()
    ));
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");
    let settings = crate::root::test_plugins::application_store_settings(&directory);
    assert!(
        settings.is_object(),
        "the actual store settings are an object"
    );
    cfg.store = Some(busbar_kernel::config::StoreCfg {
        module,
        settings: busbar_contract::json::from_value(&settings).expect("product settings object"),
        insecure_transport: None,
    });
    let plugin_config = plugins::trusted_config(&directory);
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (app, rotate, limits) = crate::root::real_store::build_app(
        crate::root::test_plugins::plaintext_listeners(cfg),
        plugin_config,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
    )
    .await
    .expect("the actual product builds the door deployment");
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, "configured-store")
        .await
        .expect("the actual configured Store binds boot rate history before activation");
    limits.keep().await.expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate.await;
    }
    let app = Arc::new(app);

    let mounting: Vec<&'static PlaneDecl> = linked::planes()
        .iter()
        .copied()
        .filter(|d| !d.fallback)
        .collect();
    assert!(
        mounting.len() >= 2,
        "the roster carries the planes this negative is about"
    );
    for decl in mounting {
        assert!(
            app.plane_slot(decl.key).is_none(),
            "no `{}:` section => no `{}` slot",
            decl.config_section,
            decl.key
        );
    }
}
