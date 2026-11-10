// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Distribution-only equivalence of the same real OIDC image admitted through both origins.
#![cfg(linked_operator_auth)]

use crate::root::test_plugins as plugins;
use crate::test_common as common;
use busbar_contract::auth_calls::{AuthCalls, Verified, VerifyAnswer, VerifyRequest};
use busbar_contract::Secret;
use busbar_plugin_loader::{auth_axis::AuthRows, LinkedPlugin, PluginRegistry};
use std::sync::Arc;

fn request(token: Option<&str>, timestamp: u64) -> VerifyRequest {
    let mut request = VerifyRequest::default();
    request.credential = token.map(|token| Secret::new(token.as_bytes().to_vec()));
    request.method = "GET".into();
    request.authority = "node.example".into();
    request.path = "/admin/v1/keys".into();
    request.timestamp = timestamp;
    request
}

async fn answered(auth: &dyn AuthCalls, token: Option<&str>, timestamp: u64) -> VerifyAnswer {
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        Box::into_pin(auth.verify(request(token, timestamp))),
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
    let library_path = crate::root::test_plugins::application_store_library();
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

    let archive_sha256 = busbar_contract::redacted::sha256_hex(&archive);
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");
    let settings: serde_json::Value =
        crate::root::test_plugins::application_store_settings(&directory);
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
        fetch: vec![busbar_kernel::config::PluginFetch::Url(
            busbar_kernel::config::UrlFetch {
                // The staged archive exactly matches this pin, so normal fetch uses its cache.
                // A miss must fail rather than silently load unrelated bytes.
                url: "http://127.0.0.1:9/store.tar.gz".into(),
                sha256: Some(archive_sha256),
            },
        )],
        ..Default::default()
    };
    plugin_config
        .trust
        .publishers
        .push(busbar_kernel::config::PluginPublisher {
            name: PUBLISHER.into(),
            public_key: hex::encode(publisher_key.verifying_key().as_bytes()),
        });
    let anchor = crate::root::real_store::core_over(
        busbar_kernel::appbuild::bootstrap_config_store(&config, &plugin_config)
            .await
            .expect("the actual Store bootstraps its config authority"),
    )
    .await;
    let overlay = busbar_kernel::config::overlay::OverlayStore::from_core(anchor.clone())
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
    .await
    .expect("the actual product builds the session deployment");
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .await
        .expect("the actual Store binds rate-card history and usage recovery before activation");
    limits.keep().await.expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate.await;
    }
    let app = Arc::new(app);

    let connector =
        crate::root::connector::the().clone() as Arc<dyn busbar_contract::conn::DeclaredConns>;
    let dispatcher = crate::root::dispatch::dispatcher();
    let path = std::env::var_os("BUSBAR_AUTH_TEST_OIDC_PLUGIN")
        .map(std::path::PathBuf::from)
        .expect("BUSBAR_AUTH_TEST_OIDC_PLUGIN names this graph's actual OIDC image");
    let stated = busbar_plugin_loader::dispatch::rendering_of_library(&path)
        .expect("read actual OIDC")
        .expect("OIDC statement");

    let door = busbar_auth_oidc::door;
    let linked_statement = busbar_plugin_loader::dispatch::rendering_of(door)
        .expect("the real linked OIDC door renders its Statement");
    assert_eq!(
        linked_statement,
        stated,
        "the same pinned real OIDC product must render byte-identical Statements through both origins: dropped_path={} dropped_image_sha256={}",
        path.display(),
        busbar_contract::redacted::sha256_hex(
            &std::fs::read(&path).expect("read actual dropped OIDC image for mismatch provenance")
        ),
    );
    let oidc_name = busbar_contract::abi::mechanism::rendering::read(&linked_statement)
        .expect("the actual linked OIDC Statement is valid")
        .name;
    let mut manifest = LinkedPlugin::auth_door_named(&oidc_name, &oidc_name, door).manifest;

    manifest.statement = Some(hex::encode(&stated));

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

    let policy = busbar_plugin_loader::sign::TrustPolicy {
        binary_version: "1.6.0".into(),
        publishers: std::iter::once((PUBLISHER.into(), publisher_key.verifying_key())).collect(),
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
    let settings =
        busbar_contract::plugin_settings::Settings::from(common::credentials::settings(audience))
            .prepare();
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
    let groups: Vec<_> = (0..300).map(|i| format!("group-{i}")).collect();
    let group_refs: Vec<_> = groups.iter().map(String::as_str).collect();
    let wide = common::credentials::token_for("alice", &group_refs, audience);
    let other_settings = busbar_contract::plugin_settings::Settings::from(
        common::credentials::settings("api://different-verifier-policy"),
    )
    .prepare();
    let timestamp = busbar_kernel::store::now();
    let mut transcripts = Vec::new();
    for registry in [linked, dropped] {
        let rows = AuthRows::new(Arc::new(registry), dispatcher.clone())
            .with_table(crate::root::connector::admit(connector.clone()));
        let auth = rows
            .open(&manifest.name, "the-auth", &settings)
            .expect("actual OIDC opens with its production HTTPS table");
        let warm = answered(&*auth, Some(&valid), timestamp).await;
        let Verified::Identity(identity) = warm.verified else {
            panic!("the real signed JWT must identify: {warm:?}");
        };

        assert_eq!(identity.subject, common::credentials::principal_id("alice"));
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
                auth.verify_now(&request(token, timestamp)),
                answered(&*auth, token, timestamp).await,
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

        let other_auth = rows
            .open(&manifest.name, "the-auth-other-policy", &other_settings)
            .expect("the real OIDC verifier opens with the other audience policy");
        let other_answer = answered(&*other_auth, Some(&valid), timestamp).await;
        assert!(
            matches!(other_answer.verified, Verified::Reject),
            "the same valid JWT must reject under another verifier's audience policy"
        );
        let other_transcript = (
            other_auth.verify_now(&request(Some(&valid), timestamp)),
            other_answer,
        );
        assert_ne!(
            transcript[0], other_transcript,
            "changing the verifier policy for the same token must change its full verdict"
        );

        let wide_transcript = vec![
            auth.verify_now(&request(Some(&wide), timestamp))
                .expect("the warmed verifier answers the first wide JWT on the spot"),
            answered(&*auth, Some(&wide), timestamp).await,
            answered(&*auth, Some(&wide), timestamp).await,
            auth.verify_now(&request(Some(&wide), timestamp))
                .expect("the warmed verifier answers the fourth wide JWT on the spot"),
        ];
        for answer in &wide_transcript {
            let Verified::Identity(identity) = &answer.verified else {
                panic!("every real wide JWT judgment must identify: {answer:?}");
            };
            assert_eq!(identity.subject, common::credentials::principal_id("alice"));
            assert_eq!(identity.groups.len(), 300);
            assert_eq!(identity.groups[299], "group-299");
            assert_eq!(identity.groups, groups);
        }
        transcripts.push((
            auth.name().to_string(),
            auth.facts(),
            transcript,
            other_transcript,
            wide_transcript,
        ));
    }
    assert_eq!(
        transcripts[0], transcripts[1],
        "the same real OIDC image must answer identically through both admitted origins"
    );
    drop(app);
    println!("actual OIDC both origins completed");
}
