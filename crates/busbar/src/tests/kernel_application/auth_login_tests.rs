// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;
#[path = "../../root/tests/test_plugins.rs"]
mod plugins;

fn stage_plugin(directory: &std::path::Path, kind: &str, variable: &str) -> String {
    let path = std::path::PathBuf::from(
        std::env::var_os(variable)
            .unwrap_or_else(|| panic!("{variable} names the actual built product cdylib")),
    );
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&path)
        .expect("the actual product statement reads")
        .expect("the actual product exports a statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual product statement is valid")
        .name;
    let mut manifest = plugins::manifest(
        kind,
        &module,
        busbar_plugin_loader::sign::FIRST_PARTY_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let archive = plugins::signed(
        &crate::dist_root_install::release_key(),
        manifest,
        &std::fs::read(path).expect("the actual library reads"),
    );
    std::fs::write(directory.join(format!("{module}.tar.gz")), archive)
        .expect("stage the genuine signed product");
    module
}

#[tokio::test]
async fn inbound_provider_retains_the_actual_opened_instance() {
    const CHILD: &str = "BUSBAR_AUTH_LOGIN_CUSTODY_CHILD";
    const WITNESS: &str = "actual login instance custody completed";
    if std::env::var_os(CHILD).is_none() {
        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let name = std::thread::current()
            .name()
            .expect("the test thread is named")
            .to_string();
        let mut child = Child(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &name, "--nocapture"])
                .env(CHILD, "1")
                .stdout(std::process::Stdio::piped())
                .spawn()
                .expect("isolate the actual root"),
        );
        let until = std::time::Instant::now() + std::time::Duration::from_secs(60);
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
                    "the exact child completed no witness: {output}"
                );
                return;
            }
            assert!(
                std::time::Instant::now() < until,
                "actual root custody timed out"
            );
            std::thread::park_timeout(std::time::Duration::from_millis(5));
        }
    }
    crate::dist_root_install::install();
    let directory = plugins::scratch("actual-login-instance-custody");
    let store = stage_plugin(&directory, "store", "BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN");
    let auth = stage_plugin(
        &directory,
        "auth",
        "BUSBAR_AUTH_WEBHOOK_SIGNATURE_TEST_PLUGIN",
    );
    std::env::set_var(
        "BUSBAR_LOGIN_CUSTODY_SIGNING_SECRET",
        "actual-custody-token",
    );
    let settings: serde_json::Value = serde_json::from_str(
        &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into()),
    )
    .expect("actual Store settings are JSON");
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {}, "models": {},
        "auth": { "chain": [], "admin_auth": [] },
        "identity-providers": { "tenant": { "module": auth, "settings": {
            "variant": "twilio", "origin": "https://edge.example.com",
            "signing_secret": { "env": "BUSBAR_LOGIN_CUSTODY_SIGNING_SECRET" }
        } } },
        "store": { "module": store, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] }
    }))
    .expect("the actual deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the actual deployment resolves");
    let plugin_config = busbar_kernel::config::PluginsCfg {
        enabled: true,
        dir: directory.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let build = |cold| {
        let anchor = busbar_kernel::appbuild::bootstrap_config_store(&config, &plugin_config)
            .expect("the actual Store bootstraps");
        let overlay = busbar_kernel::config::overlay::OverlayStore::new(
            anchor.calls.as_ref().cloned().expect("actual Store calls"),
        )
        .expect("the actual Store supports conditional records");
        busbar_kernel::appbuild::build_app_from_config_with_store(
            config.clone(),
            plugin_config.clone(),
            Some(overlay),
            Default::default(),
            Default::default(),
            (None, None),
            None,
            &rules,
            Some(anchor),
            cold,
        )
        .expect("the actual product candidate builds")
    };
    let (old, rotate, limits) = build(true);
    limits.stage_boot();
    let _book = crate::root::boot::book(&old, &store).expect("the actual Store binds boot history");
    limits.keep().expect("initial product limits activate");
    if let Some(rotate) = rotate {
        rotate();
    }
    let bound = old
        .inbound_default_auth(&auth)
        .unwrap()
        .expect("declared inbound style");
    assert_eq!(bound.provider, "tenant");
    assert_eq!(bound.module, auth);
    assert_eq!(
        bound.points,
        busbar_contract::abi::auth::AuthPoints::HEAD_BODY
    );
    let again = old.inbound_default_auth(&auth).unwrap().unwrap();
    assert!(
        Arc::ptr_eq(&bound.calls, &again.calls),
        "lookup clones the already opened provider"
    );
    assert!(old.inbound_default_auth("tenant").is_err());
    assert!(old.inbound_default_auth("outbound-style").is_err());
    assert!(old.inbound_default_auth("").unwrap().is_none());
    let (next, _rotate, _limits) = build(false);
    let replacement = next.inbound_default_auth(&auth).unwrap().unwrap();
    assert!(
        !Arc::ptr_eq(&bound.calls, &replacement.calls),
        "new candidate owns its distinct instance"
    );
    drop(old);
    assert!(
        Arc::ptr_eq(&bound.calls, &again.calls),
        "old borrow retains its original instance"
    );
    assert_eq!(bound.calls.name(), auth);
    assert_eq!(bound.calls.inbound_points(), bound.points);
    println!("{WITNESS}");
}
