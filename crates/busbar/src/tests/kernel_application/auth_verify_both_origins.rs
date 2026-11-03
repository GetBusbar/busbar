// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Distribution-only equivalence of the same real OIDC image admitted through both origins.
#![cfg(linked_operator_auth)]

use busbar_contract::auth_calls::{AuthCalls, Verified, VerifyAnswer, VerifyRequest};
use busbar_contract::Secret;
use busbar_plugin_loader::{auth_axis::AuthRows, LinkedPlugin, PluginRegistry};
use std::sync::Arc;
#[path = "../../../../../dist/default/tests/common/mod.rs"]
mod common;
#[path = "../../root/tests/test_plugins.rs"]
mod plugins;

fn request(token: Option<&str>) -> VerifyRequest {
    VerifyRequest {
        credential: token.map(|token| Secret::new(token.as_bytes().to_vec())),
        method: "GET".into(),
        authority: "node.example".into(),
        path: "/admin/v1/keys".into(),
        timestamp: busbar_kernel::store::now(),
        ..Default::default()
    }
}

async fn answered(auth: &dyn AuthCalls, token: Option<&str>) -> VerifyAnswer {
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        Box::into_pin(auth.verify(request(token))),
    )
    .await
    .expect("real OIDC verification is bounded")
}

#[tokio::test]
async fn the_same_real_oidc_image_preserves_verdicts_through_linked_and_dropped_origins() {
    const CHILD: &str = "BUSBAR_ACTUAL_OIDC_BOTH_ORIGINS_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let name = std::thread::current().name().unwrap().to_string();
        let output = tokio::task::spawn_blocking(move || {
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &name, "--nocapture"])
                .env(CHILD, "1")
                .output()
                .unwrap()
        })
        .await
        .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("actual OIDC both origins completed")
        );
        return;
    }
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
    const PUBLISHER: &str = "auth-both-origins-test";
    let publisher_key = plugins::key(0x33);
    let mut manifest = plugins::manifest("store", &module, PUBLISHER);
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = plugins::scratch("auth-both-origins");
    let archive = plugins::signed(&publisher_key, manifest, &library);
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
    let signing = directory.join("signing-key");
    std::fs::write(&signing, hex::encode([9u8; 32]))
        .expect("write the actual configured signing key");
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {},
        "models": {},
        "auth": {
            "chain": [], "admin_auth": [], "signing_key": { "file": signing },
            "key_ttl": "1h",
            "role_bindings": {}
        },
        "groups": { "team": { "child_default": { "limits": [{ "budget": 500, "per": "month" }] } } },
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    }))
    .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let mut plugin_config = busbar_kernel::config::PluginsCfg {
        enabled: true,
        dir: directory.to_string_lossy().into_owned(),
        ..Default::default()
    };
    plugin_config
        .trust
        .publishers
        .push(busbar_kernel::config::PluginPublisher {
            name: PUBLISHER.into(),
            public_key: hex::encode(publisher_key.verifying_key().as_bytes()),
        });
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
        true,
    )
    .expect("the actual product builds the session deployment");
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .expect("the actual Store binds rate-card history and usage recovery before activation");
    limits.keep().expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let app = Arc::new(app);
    // The cold root retained above owns the real HTTPS connector and its destination policy.
    let connector =
        crate::root::connector::the().clone() as Arc<dyn busbar_contract::conn::DeclaredConns>;
    let dispatcher = crate::root::dispatch::dispatcher();
    let path = std::env::var_os("BUSBAR_AUTH_TEST_OIDC_PLUGIN")
        .map(std::path::PathBuf::from)
        .expect("BUSBAR_AUTH_TEST_OIDC_PLUGIN names this graph's actual OIDC image");
    let stated = busbar_plugin_loader::dispatch::rendering_of_library(&path)
        .expect("read actual OIDC")
        .expect("OIDC statement");
    let (key, canonical, door) = crate::LINKED
        .auths
        .iter()
        .find(|(_, _, door)| {
            busbar_plugin_loader::dispatch::rendering_of(**door)
                .ok()
                .as_deref()
                == Some(stated.as_slice())
        })
        .copied()
        .expect("the linked OIDC Statement must match the exact qualified dropped image");
    let mut manifest = LinkedPlugin::auth_door_named(canonical, key, door).manifest;
    // Admission metadata names the same explicitly configured normal publisher on both origins.
    manifest.publisher = PUBLISHER.into();
    let linked_plugin = LinkedPlugin::door(manifest.clone(), door);
    let linked = PluginRegistry::empty()
        .link(vec![linked_plugin])
        .expect("actual linked OIDC admits");
    let oidc_directory = plugins::scratch("oidc-both-origins-dropped");
    let library = std::fs::read(&path).expect("read exact OIDC image");
    std::fs::write(
        oidc_directory.join("oidc.tar.gz"),
        plugins::signed(&publisher_key, manifest.clone(), &library),
    )
    .expect("stage signed actual OIDC");
    // This direct registry admission control uses the same narrow publisher allowlist as the
    // cold root above. It is not a claim that direct scan runs the root's full boot trust flow.
    let policy = busbar_plugin_loader::sign::TrustPolicy {
        binary_version: "1.6.0".into(),
        publishers: vec![(PUBLISHER.into(), publisher_key.verifying_key())],
        allow_unsigned: false,
        allow_third_party: false,
        ..Default::default()
    };
    let dropped = busbar_plugin_loader::scan_and_validate(&oidc_directory, &policy)
        .expect("actual signed dropped OIDC admits");
    let normalize = |registry: &PluginRegistry| {
        let row = registry
            .resolve(&manifest.name)
            .expect("both origins register the actual row");
        let mut manifest = row.manifest.clone();
        manifest.sha256.clear();
        manifest.signature.clear();
        manifest
    };
    assert_eq!(
        normalize(&linked),
        normalize(&dropped),
        "origin alone must not change the admitted actual OIDC metadata"
    );
    let audience = "api://auth-both-origins";
    let settings = serde_json::Value::Object(common::credentials::settings(audience));
    let valid = common::credentials::token_for("alice", &["reader", "writer"], audience);
    let foreign =
        common::credentials::token_for("alice", &["reader", "writer"], "api://different-audience");
    let mut broken = valid.clone().into_bytes();
    let signature = broken.iter().rposition(|byte| *byte == b'.').unwrap() + 1;
    broken[signature] = if broken[signature] == b'A' {
        b'B'
    } else {
        b'A'
    };
    let broken = String::from_utf8(broken).unwrap();
    let mut transcripts = Vec::new();
    for registry in [linked, dropped] {
        let rows =
            AuthRows::new(Arc::new(registry), dispatcher.clone()).with_table(connector.clone());
        let auth = rows
            .open(&manifest.name, "the-auth", &settings)
            .expect("actual OIDC opens with its production HTTPS table");
        let warm = answered(&*auth, Some(&valid)).await;
        let Verified::Identity(identity) = warm.verified else {
            panic!("the real signed JWT must identify: {warm:?}");
        };
        assert_eq!(identity.subject, "alice");
        assert_eq!(identity.groups, ["reader", "writer"]);
        let mut transcript = Vec::new();
        for token in [
            Some(valid.as_str()),
            Some(broken.as_str()),
            Some(foreign.as_str()),
            Some("not-a-jwt"),
            None,
        ] {
            transcript.push((
                auth.verify_now(&request(token)),
                answered(&*auth, token).await,
            ));
        }
        assert!(matches!(transcript[0].1.verified, Verified::Identity(_)));
        assert!(
            matches!(transcript[1].1.verified, Verified::Reject),
            "a changed signature must not identify"
        );
        assert!(
            matches!(transcript[2].1.verified, Verified::Reject),
            "a differently judged audience must not identify"
        );
        assert!(
            matches!(transcript[4].1.verified, Verified::Pass),
            "an absent credential leaves the next verifier available"
        );
        assert_ne!(
            transcript[0].1, transcript[2].1,
            "a genuinely different credential policy cannot compare as the same verdict"
        );
        transcripts.push((auth.name().to_string(), auth.facts(), transcript));
    }
    assert_eq!(
        transcripts[0], transcripts[1],
        "the same real OIDC image must answer identically through both admitted origins"
    );
    drop(app);
    println!("actual OIDC both origins completed");
}
