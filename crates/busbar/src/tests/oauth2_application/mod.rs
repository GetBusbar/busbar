// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! OAuth application assertions compiled by the actual distribution binary.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use busbar_core_oauth2::config::OauthAsCfg;
use busbar_kernel::state::App;

#[path = "../../root/tests/test_plugins.rs"]
mod plugins;

mod browser;
mod fapi2_tests;
mod mount_tests;

fn oauth_as_plane(app: &App) -> Option<Arc<busbar_core_oauth2::plane::AsPlane>> {
    app.oauth_as_any()?
        .clone()
        .downcast::<busbar_core_oauth2::plane::AsPlane>()
        .ok()
}

/// Build through the shipped root and its normal plugin loader. The required store
/// artifact is a freshly built product, never a fixture implementation of Store.
fn application(oauth_as: Option<&OauthAsCfg>, prior: Option<&App>) -> Arc<App> {
    application_with_resource_auth(oauth_as, prior, false)
}

fn application_with_resource_auth(
    oauth_as: Option<&OauthAsCfg>,
    prior: Option<&App>,
    resource_auth: bool,
) -> Arc<App> {
    static BUILDING: Mutex<()> = Mutex::new(());
    let _building = BUILDING
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    crate::dist_root_install::install();

    let store_library = PathBuf::from(
        std::env::var_os("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN")
            .expect("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN names the actual built store"),
    );
    let stated = busbar_plugin_loader::dispatch::rendering_of_library(&store_library)
        .expect("the actual store statement reads")
        .expect("the actual store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&stated)
        .expect("the actual store statement is valid")
        .name;
    let library = std::fs::read(&store_library).expect("the actual store library reads");
    let mut manifest = plugins::manifest(
        "store",
        &module,
        busbar_plugin_loader::sign::FIRST_PARTY_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(stated));
    let instance = busbar_kernel::door::op_id().counter();
    let directory = plugins::scratch(&format!("oauth-application-{instance}"));
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
    let mut document = serde_json::json!({
        "providers": {},
        "models": {},
        "store": { "module": module, "settings": settings },
        "auth": { "chain": [], "admin_auth": [] },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    });
    if let Some(block) = oauth_as {
        document["oauth_as"] = serde_json::to_value(block).expect("the OAuth config serializes");
    }
    if resource_auth {
        let block = oauth_as.expect("resource auth verifies this configured authorization server");
        let path = plugins::token_verifier_cdylib_path().expect(
            "build the pinned auth-oidc product cdylib before running OAuth application tests",
        );
        let statement = busbar_plugin_loader::dispatch::rendering_of_library(&path)
            .expect("the actual OIDC statement reads")
            .expect("the actual OIDC library states itself");
        let name = busbar_contract::abi::mechanism::rendering::read(&statement)
            .expect("the actual OIDC statement is valid")
            .name;
        let mut manifest = plugins::manifest(
            "auth",
            &name,
            busbar_plugin_loader::sign::FIRST_PARTY_PUBLISHER,
        );
        manifest.statement = Some(hex::encode(statement));
        let library = std::fs::read(path).expect("the actual OIDC library reads");
        let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
        std::fs::write(directory.join("oauth-resource.tar.gz"), archive)
            .expect("stage the actual OIDC archive");
        document["identity-providers"] = serde_json::json!({
            "oauth-resource": {
                "module": name,
                "settings": {
                    "issuer": block.issuer,
                    "audience": block.issuer,
                    "jwks_url": format!("{}/jwks", block.issuer),
                    "role_claim": "scope",
                },
            },
        });
        document["auth"]["chain"] = serde_json::json!(["oauth-resource"]);
        document["auth"]["role_bindings"] = serde_json::json!({
            "oauth-resource": { "read": {} },
        });
    }
    let deploy = busbar_kernel::config::deploy_from_deserializer(document)
        .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
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
        prior,
        &rules,
    )
    .expect("the actual product builds the OAuth deployment");
    limits.keep().expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    Arc::new(app)
}
