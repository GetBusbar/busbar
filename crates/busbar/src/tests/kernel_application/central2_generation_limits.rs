// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
use crate::root::test_plugins as plugins;
use busbar_contract::json::JsonValueTrait as _;
use std::sync::Arc;
fn live_limits() -> (Option<String>, usize) {
    std::thread::spawn(|| {
        (
            busbar_kernel::config::limits::installed().map(|l| format!("{l:?}")),
            busbar_kernel_egress::upstream::max_translate_body_bytes(),
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

#[tokio::test]
async fn a_built_generations_limits_are_in_force_only_once_it_is_live() {
    const CHILD: &str = "BUSBAR_CENTRAL2_LIMITS_CHILD";
    const WITNESS: &str = "actual root generation limits completed";
    isolated!(CHILD, WITNESS, witness = "usage");
    crate::dist_root_install::install();
    let library_path = crate::root::test_plugins::application_store_library();
    let module = crate::root::test_plugins::native_image(&library_path).name;
    let manifest = crate::root::test_plugins::native_manifest(
        "store",
        &library_path,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = plugins::scratch("central2-limits-live");
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");
    let settings = crate::root::test_plugins::application_store_settings(&directory);
    assert!(
        settings.is_object(),
        "the actual store settings are an object"
    );
    let deploy = busbar_kernel::config::deploy_from_deserializer(
        serde_json::json!({
            "providers": {},
            "models": {},
            "auth": { "chain": [], "admin_auth": [] },
            "store": { "module": module.clone(), "settings": settings },
            "advanced": {  },
        }),
        &crate::root::boot::axis_test_grammar(),
    )
    .expect("the product deployment parses");
    let resolve = || {
        busbar_kernel::config::resolve(&deploy, &Default::default())
            .expect("the product deployment resolves")
    };
    let mut config = resolve();
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let running = tagged_limits(1);
    config.limits = running.clone();
    let native_config = config;
    let native_plugins = plugin_config.clone();
    let crate::root::min3_boot::fixture::Fixture {
        backend: native_core,
        rules,
    } = crate::root::min3_boot::fixture::open(&native_config, &native_plugins, rules.clone())
        .await
        .expect("actual Store opens for native startup");
    let native_core = crate::root::real_store::core_over(native_core).await;
    let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        native_config,
        native_plugins,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
        Some(native_core),
        true,
    )
    .await
    .expect("the actual product builds the swap deployment");
    limits.stage_boot();
    let book = crate::root::boot::book(&app, &module)
        .await
        .expect("the actual Store boots rate history");
    let _book = book;
    limits.keep().await.expect("actual rates and limits commit");
    if let Some(rotate) = rotate {
        rotate.await;
    }
    let before = live_limits();
    assert_eq!(
        before,
        (Some(format!("{running:?}")), running.request_body_max_bytes),
        "the live view reads the running generation's limits"
    );
    let mut refused = tagged_limits(2);
    refused.hard_down_cooldown_secs = 0;
    let Err(refusal) = crate::root::real_store::build_app(
        {
            let mut trial = resolve();
            trial.limits = refused;
            trial
        },
        plugin_config.clone(),
        None,
        Default::default(),
        Default::default(),
        (None, None),
        Some(&app),
        &rules,
    )
    .await
    else {
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
    let (next, candidate_rotate, unkept) = crate::root::real_store::build_app(
        {
            let mut trial = resolve();
            trial.limits = candidate.clone();
            trial
        },
        plugin_config.clone(),
        None,
        Default::default(),
        Default::default(),
        (None, None),
        Some(&app),
        &rules,
    )
    .await
    .expect("builds");
    if let Some(rotate) = candidate_rotate {
        rotate.await;
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

    let handle = busbar_kernel::state::AppHandle::new(Arc::new(app));
    handle.swap(std::sync::Arc::new(next)).await;
    let after = (
        Some(format!("{candidate:?}")),
        candidate.request_body_max_bytes,
    );
    assert_eq!(live_limits(), after, "the swapped-in generation's limits");

    unkept
        .keep()
        .await
        .expect("the test generation confirms its rates");
    assert_eq!(live_limits(), after);
    println!("{WITNESS}");
}
