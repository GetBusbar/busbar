// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;
use crate::root::test_plugins as plugins;

#[tokio::test]
async fn actual_operator_and_signing_file_reload_preserves_governance_and_fails_closed() {
    const CHILD: &str = "BUSBAR_OPERATOR_FILE_RELOAD_CHILD";
    const WITNESS: &str = "ACTUAL_OPERATOR_FILE_RELOAD_COMPLETED";
    if std::env::var_os(CHILD).is_none() {
        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let name = std::thread::current().name().unwrap().to_owned();
        let mut child = Child(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &name, "--nocapture"])
                .env(CHILD, "1")
                .stdout(std::process::Stdio::piped())
                .spawn()
                .unwrap(),
        );
        let until = std::time::Instant::now() + std::time::Duration::from_secs(90);
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                use std::io::Read;
                let mut output = String::new();
                child
                    .0
                    .stdout
                    .take()
                    .unwrap()
                    .read_to_string(&mut output)
                    .unwrap();
                assert!(status.success(), "{status}: {output}");
                assert!(
                    output.contains(WITNESS),
                    "exact child completed no witness: {output}"
                );
                return;
            }
            assert!(
                std::time::Instant::now() < until,
                "operator reload timed out"
            );
            std::thread::park_timeout(std::time::Duration::from_millis(5));
        }
    }
    crate::dist_root_install::install();
    let directory = plugins::scratch("actual-operator-file-reload");
    let library = crate::root::test_plugins::application_store_library();
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library)
        .unwrap()
        .unwrap();
    let store = busbar_contract::abi::mechanism::rendering::read(&statement)
        .unwrap()
        .name;
    let mut manifest = plugins::manifest(
        "store",
        &store,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    std::fs::write(
        directory.join("store.tar.gz"),
        plugins::signed(
            &crate::dist_root_install::release_key(),
            manifest,
            &std::fs::read(library).unwrap(),
        ),
    )
    .unwrap();
    let settings: serde_json::Value =
        crate::root::test_plugins::application_store_settings(&directory);
    let token_path = directory.join("admin-token");
    let signing_path = directory.join("signing-key");
    std::fs::write(&token_path, "tok-v1").unwrap();
    std::fs::write(&signing_path, hex::encode([7u8; 32])).unwrap();
    let operator = busbar_kernel::config::operator_provider();
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {}, "models": {},
        "identity-providers": {(operator): {"module": operator, "token": {"file": token_path}}},
        "auth": {"chain": [], "admin_auth": [operator], "signing_key": {"file": signing_path}},
        "store": {"module": store, "settings": settings},
        "advanced": {"allow_destinations": ["127.0.0.1"]}
    }))
    .unwrap();
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let build = |prior: Option<&busbar_kernel::state::App>| {
        let config = busbar_kernel::config::resolve(&deploy, &Default::default())
            .map_err(|errors| errors.join("; "))?;
        let anchor = busbar_kernel::appbuild::bootstrap_config_store(&config, &plugin_config)?;
        let overlay = busbar_kernel::config::overlay::OverlayStore::new(
            anchor
                .calls
                .as_ref()
                .cloned()
                .expect("actual conditional Store calls"),
        )?;
        busbar_kernel::appbuild::build_app_from_config_with_store(
            config,
            plugin_config.clone(),
            Some(overlay),
            Default::default(),
            Default::default(),
            (None, None),
            prior,
            &rules,
            Some(anchor),
            prior.is_none(),
        )
    };
    let (prior, rotate, limits) = build(None).expect("normal cold root builds");
    limits.stage_boot();
    let _book = crate::root::boot::book(&prior, &store).expect("same Store boot history binds");
    limits.keep().unwrap();
    if let Some(rotate) = rotate {
        rotate();
    }
    let gov = prior.governance.as_ref().unwrap().clone();
    assert_eq!(
        gov.admin_token_hash().as_deref(),
        Some(busbar_contract::redacted::sha256_hex(b"tok-v1").as_str())
    );
    let now = busbar_kernel::store::now();
    let (_, old_token) = gov
        .mint_signed(
            busbar_kernel::governance::NewKeySpec {
                name: "before-rotation".into(),
                ..Default::default()
            },
            now + 3600,
            now,
        )
        .unwrap();
    assert!(gov
        .verify_token(old_token.expose(&busbar_kernel::seal::lend()), now, None)
        .is_some());
    std::fs::write(&token_path, "tok-v2").unwrap();
    std::fs::write(&signing_path, hex::encode([9u8; 32])).unwrap();
    let (next, rotate, limits) = build(Some(&prior)).expect("actual reload resolves both files");
    assert!(
        Arc::ptr_eq(next.governance.as_ref().unwrap(), &gov),
        "reload retains actual keys and ledgers"
    );
    limits.keep().unwrap();
    rotate.expect("changed credentials install only on commit")();
    assert_eq!(
        gov.admin_token_hash().as_deref(),
        Some(busbar_contract::redacted::sha256_hex(b"tok-v2").as_str())
    );
    assert!(gov
        .verify_token(old_token.expose(&busbar_kernel::seal::lend()), now, None)
        .is_none());
    let (_, fresh) = gov
        .mint_signed(
            busbar_kernel::governance::NewKeySpec {
                name: "after-rotation".into(),
                ..Default::default()
            },
            now + 3600,
            now,
        )
        .unwrap();
    assert!(gov
        .verify_token(fresh.expose(&busbar_kernel::seal::lend()), now, None)
        .is_some());
    for (credential, want) in [("tok-v1", false), ("tok-v2", true)] {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            "authorization",
            format!("Bearer {credential}").parse().unwrap(),
        );
        assert_eq!(
            busbar_kernel::auth::dry_run_admin_scope(&next, &headers)
                .allows(busbar_contract::authz::Scope::Full),
            want
        );
    }
    std::fs::remove_file(&signing_path).unwrap();
    let refusal = match build(Some(&next)) {
        Err(refusal) => refusal,
        Ok(_) => panic!("missing signing ref must refuse reload"),
    };
    assert!(refusal.contains("signing_key"), "{refusal}");
    assert!(
        gov.verify_token(fresh.expose(&busbar_kernel::seal::lend()), now, None)
            .is_some(),
        "failed candidate preserves committed signer"
    );
    std::fs::write(&signing_path, hex::encode([9u8; 32])).unwrap();
    for blank in ["", "   ", "\n\t "] {
        std::fs::write(&token_path, blank).unwrap();
        let refusal = match build(None) {
            Err(refusal) => refusal,
            Ok(_) => panic!("blank operator token must refuse cold boot"),
        };
        assert!(refusal.contains(operator), "{refusal}");
        if !blank.is_empty() {
            assert!(refusal.contains("whitespace"), "{refusal}");
        }
    }
    assert_eq!(
        gov.admin_token_hash().as_deref(),
        Some(busbar_contract::redacted::sha256_hex(b"tok-v2").as_str()),
        "refused candidates cannot replace committed operator"
    );
    println!("{WITNESS}");
}
