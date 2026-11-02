// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;

#[path = "../../../../../dist/default/tests/common/mod.rs"]
mod common;
#[path = "../../root/tests/test_plugins.rs"]
mod plugins;

#[tokio::test]
async fn exchange_provisions_user_leaf_from_child_default_and_key_is_usable() {
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
    let directory = plugins::scratch("auth-self-group-provision");
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
    let oidc_path = common::plugins::token_verifier_cdylib_path()
        .expect("the freshly built actual OIDC product is required");
    let oidc_statement = busbar_plugin_loader::dispatch::rendering_of_library(&oidc_path)
        .expect("the actual OIDC statement reads")
        .expect("the actual OIDC product exports its statement");
    let oidc_module = busbar_contract::abi::mechanism::rendering::read(&oidc_statement)
        .expect("the actual OIDC statement is valid")
        .name;
    common::credentials::install_auth_plugin(&directory, &oidc_module, "corp", true);
    let signing = directory.join("signing-key");
    std::fs::write(&signing, hex::encode([9u8; 32]))
        .expect("write the actual configured signing key");
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {},
        "models": {},
        "identity-providers": {
            "corp": { "module": oidc_module, "settings": common::credentials::settings("api://auth-self-groups") }
        },
        "auth": {
            "chain": ["corp"], "admin_auth": [], "signing_key": { "file": signing },
            "key_ttl": "1h",
            "role_bindings": { "corp": { "eng": { "group": "team" } } }
        },
        "groups": { "team": { "child_default": { "limits": [{ "budget": 500, "per": "month" }] } } },
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    }))
    .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let plugin_config = busbar_kernel::config::PluginsCfg {
        enabled: true,
        dir: directory.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let anchor = busbar_kernel::appbuild::bootstrap_config_store(&config, &plugin_config)
        .expect("the actual Store bootstraps its config authority");
    let overlay = busbar_kernel::config::overlay::OverlayStore::new(
        anchor
            .calls
            .as_ref()
            .cloned()
            .expect("the actual Store exposes typed calls"),
    )
    .expect("the actual Store supports conditional config records");
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        config,
        plugin_config,
        Some(overlay.clone()),
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
        Some(anchor),
    )
    .expect("the actual product builds the session deployment");
    limits.keep().expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let app = Arc::new(app);
    let gov = app
        .governance
        .as_ref()
        .expect("the actual Store supplies governance")
        .clone();
    let handle = Arc::new(busbar_kernel::state::AppHandle::new(app));
    // Principal DATA enters the real public post-identity mint API. This case exercises actual
    // group transactions and Store persistence, not authentication of an external credential.
    let mut principal = busbar_kernel::auth::Principal::from_id("sam");
    principal.roles = vec!["eng".to_string()];
    let before = handle.load();
    let first = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        busbar_kernel::auth::login::issue_self_key(
            &before,
            &handle,
            "corp",
            principal.clone(),
            false,
        ),
    )
    .await
    .expect("the actual first mint completes within ten seconds");
    let (group, secret) = match first {
        busbar_kernel::auth::login::SelfKeyIssue::Issued { group, secret, .. } => (group, secret),
        _ => panic!("the actual first exchange issues a key"),
    };
    assert_eq!(group, "user:sam");
    let current = handle.load();
    let registry = &current.groups_registry;
    let leaf = registry
        .get("user:sam")
        .expect("the actual transaction published the user leaf");
    assert_eq!(
        leaf.parent.as_deref(),
        Some("team"),
        "leaf parented under the team"
    );
    assert_eq!(
        leaf.limits,
        registry["team"].child_default.as_ref().unwrap().limits,
        "leaf limits stamped from the team's child_default"
    );
    assert!(
        !leaf.limits.is_empty(),
        "child_default limits actually copied onto the leaf"
    );
    assert!(current.cost.group_named("user:sam").is_some());
    let key = gov
        .verify_token(
            secret.expose(&busbar_kernel::seal::lend()),
            busbar_kernel::store::now(),
            None,
        )
        .expect("the minted real key verifies");
    let binding = gov
        .lookup_by_sub(&key.id)
        .expect("the actual Store holds the minted binding");
    assert!(
        gov.try_admit(
            &current.cost,
            &binding,
            "unused-pool",
            busbar_kernel::store::now()
        )
        .is_ok(),
        "the actual key is admitted through its published enforcement chain (not MissingGroup)"
    );
    let persisted = overlay
        .read_required()
        .expect("read the actual Store overlay")
        .expect("group provisioning persisted a real overlay generation");
    assert_eq!(persisted.groups.get("user:sam"), Some(leaf));
    let second = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        busbar_kernel::auth::login::issue_self_key(&current, &handle, "corp", principal, false),
    )
    .await
    .expect("the actual second mint completes within ten seconds");
    let second_secret = match second {
        busbar_kernel::auth::login::SelfKeyIssue::Issued { secret, .. } => secret,
        _ => panic!("the actual second exchange reuses the key"),
    };
    let second_key = gov
        .verify_token(
            second_secret.expose(&busbar_kernel::seal::lend()),
            busbar_kernel::store::now(),
            None,
        )
        .expect("the reissued real key verifies");
    assert_eq!(second_key.id, key.id, "same deterministic key row");
    assert_eq!(
        handle.load().groups_registry.len(),
        2,
        "team + exactly one user leaf (no duplicate)"
    );
    let self_rows = gov
        .all_keys()
        .unwrap()
        .into_iter()
        .filter(|key| {
            key.enabled && key.deleted_at.is_none() && key.group.as_deref() == Some("user:sam")
        })
        .count();
    assert_eq!(self_rows, 1, "exactly one key binding");
}
