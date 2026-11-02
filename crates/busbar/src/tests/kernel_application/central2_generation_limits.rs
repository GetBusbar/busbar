// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
use std::sync::Arc;
use std::time::{Duration, Instant};
#[path = "../../root/tests/test_plugins.rs"]
mod plugins;
fn live_limits() -> (Option<String>, usize, usize) {
    std::thread::spawn(|| {
        (
            busbar_kernel::config::limits::installed().map(|l| format!("{l:?}")),
            busbar_kernel_egress::upstream::max_translate_body_bytes(),
            busbar_kernel::hooks::hook_content_max_bytes(),
        )
    })
    .join()
    .expect("reader thread must not panic")
}

fn tagged_limits(tag: u64) -> busbar_kernel::config::LimitsResolved {
    let n = usize::try_from(tag).expect("small tag");
    busbar_kernel::config::LimitsResolved {
        key_gauge_limit: 1_000 + n,
        request_body_max_bytes: (1 + n) * 1024 * 1024,
        hook_content_max_bytes: 1_024 * (1 + n),
        upstream_error_body_max_bytes: 8_192 + n,
        default_probe_interval_secs: 20 + tag,
        default_probe_timeout_secs: 3 + tag,
        default_policy_timeout_ms: 500 + tag,
        hard_down_cooldown_secs: 600 + tag,
        max_honored_retry_after_secs: 3_600 + tag,
        tls_handshake_timeout_secs: 5 + tag,
        request_body_read_timeout_secs: 15 + tag,
        rate_sweep_interval: 100 + u32::try_from(tag).expect("small tag"),
        ..busbar_kernel::config::LimitsResolved::default()
    }
}

#[test]
fn a_built_generations_limits_are_in_force_only_once_it_is_live() {
    const CHILD: &str = "BUSBAR_CENTRAL2_LIMITS_CHILD";
    const WITNESS: &str = "actual root generation limits completed";
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
            .expect("the test runner names its test thread")
            .to_string();
        let mut child = Child(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &name, "--nocapture"])
                .env(CHILD, "1")
                .stdout(std::process::Stdio::piped())
                .spawn()
                .expect("start the isolated actual-root test"),
        );
        let until = Instant::now() + Duration::from_secs(60);
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
                assert!(
                    status.success(),
                    "the actual-root usage witness failed: {status}: {output}"
                );
                assert!(
                    output.contains(WITNESS),
                    "the exact child did not complete its assertions: {output}"
                );
                return;
            }
            assert!(
                Instant::now() < until,
                "the actual-root usage witness timed out"
            );
            std::thread::park_timeout(Duration::from_millis(5));
        }
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
    let mut manifest = plugins::manifest(
        "store",
        &module,
        busbar_plugin_loader::sign::FIRST_PARTY_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = plugins::scratch("central2-limits-live");
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
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [] },
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    }))
    .expect("the product deployment parses");
    let mut config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let plugin_config = busbar_kernel::config::PluginsCfg {
        enabled: true,
        dir: directory.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let running = tagged_limits(1);
    config.limits = running.clone();
    let (app, rotate, limits) = busbar_kernel::build_app_from_config(
        config.clone(),
        plugin_config.clone(),
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
    )
    .expect("the actual product builds the swap deployment");
    limits.stage_boot();
    crate::root::kernel::ROOT_CARD.keep_in_store(
        app.governance
            .as_ref()
            .unwrap()
            .store_calls()
            .expect("actual Store calls"),
        113,
    );
    crate::root::kernel::ROOT_CARD
        .boot_in_store(None)
        .expect("actual rate history boots");
    limits.keep().expect("actual rates and limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let before = live_limits();
    assert_eq!(
        before,
        (
            Some(format!("{running:?}")),
            running.request_body_max_bytes,
            running.hook_content_max_bytes
        ),
        "the live view reads the running generation's limits"
    );
    let mut refused = tagged_limits(2);
    refused.hard_down_cooldown_secs = 0;
    let Err(refusal) = busbar_kernel::build_app_from_config(
        {
            let mut trial = config.clone();
            trial.limits = refused;
            trial
        },
        plugin_config.clone(),
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
    ) else {
        panic!("validation refuses it");
    };
    assert!(
        refusal.contains("limits.hard_down_cooldown_secs must be >= 1"),
        "refused for its zero sticky cooldown, not another reason: {refusal}"
    );
    assert_eq!(
        live_limits(),
        before,
        "a refused apply changed a live limit"
    );

    let candidate = tagged_limits(3);
    let (next, candidate_rotate, unkept) = busbar_kernel::build_app_from_config(
        {
            let mut trial = config.clone();
            trial.limits = candidate.clone();
            trial
        },
        plugin_config.clone(),
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
    )
    .expect("builds");
    if let Some(rotate) = candidate_rotate {
        rotate();
    }
    assert_eq!(
        live_limits(),
        before,
        "a built-but-not-live generation's limits are in force under the running generation"
    );
    assert_eq!(
        busbar_kernel::config::limits::installed().map(|l| format!("{l:?}")),
        Some(format!("{running:?}")),
        "the build's own view of its candidate ends with the build"
    );

    let handle = busbar_kernel::state::AppHandle::new(app);
    handle.swap(std::sync::Arc::new(next));
    let after = (
        Some(format!("{candidate:?}")),
        candidate.request_body_max_bytes,
        candidate.hook_content_max_bytes,
    );
    assert_eq!(live_limits(), after, "the swapped-in generation's limits");

    unkept
        .keep()
        .expect("the test generation confirms its rates");
    assert_eq!(live_limits(), after);
    println!("{WITNESS}");
}
