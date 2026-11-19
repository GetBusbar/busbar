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
use busbar_kernel::plane_driver::registry::{PlaneDecl, PlaneDeclaration};
use std::sync::Arc;

static PROBE_RUN: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

use std::sync::atomic::{AtomicUsize, Ordering};

static HYDRATED: AtomicUsize = AtomicUsize::new(0);
static STARTED: AtomicUsize = AtomicUsize::new(0);
static BUILT: AtomicUsize = AtomicUsize::new(0);

const PROBE_SECTION: &str = "law7-probe";

static PROBE: PlaneDecl = PlaneDecl {
    declaration: PlaneDeclaration {
        key: "law7probe",
        fallback: false,
        config_section: PROBE_SECTION,
        scope_kinds: &["law7probe"],
        subject_noun: "probe",
        admin_noun: "probe",
        audit_kind: "law7probe",
        card_signing_domain: None,
        card_kid_prefix: None,
        owned_config_sections: &[],
        billable_classes: &[],
        class_parents: &[],
        fee_units: &[],
        metric_families: &[],
        record_kinds: &[],
        required_config_sections: &[],
        trust_keys: &[],
        served_op_classes: &[],
        caller_credential_refusal: None,
    },
    wire_format_names: |_| &["law7probe"],
    provider_dialects: |_| &[],
    claims: |_| Vec::new(),
    admission: |_| None,
    build: |_, _| {
        BUILT.fetch_add(1, Ordering::SeqCst);
        Some(std::sync::Arc::new(()))
    },
    routes: None,
    openapi: None,
    hydrate: Some(|_| {
        HYDRATED.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }),
    start: Some(|_| {
        STARTED.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }),
    config_validate: None,
    named_def_list: None,
    named_def_get: None,
    registry_contains: None,
    openapi_schemas: None,
    on_swap: None,
    parse_section: None,
    parse_endpoint: None,
    lower_endpoint: None,
    build_runtime: None,
    viewer: None,
    retain_verify_gates: None,
    default_section: None,
    resolve_provider: None,
    door: None,
};

async fn boot_hooks_run(sections: &[&'static str]) -> (usize, usize) {
    let _one = PROBE_RUN.lock().await;
    crate::dist_root_install::install();
    linked::install();
    busbar_kernel::plane_driver::registry::publish_planes(&[&PROBE]);
    let (h0, s0) = (
        HYDRATED.load(Ordering::SeqCst),
        STARTED.load(Ordering::SeqCst),
    );
    let library_path = crate::root::test_plugins::application_store_library();
    let module = crate::root::test_plugins::native_image(&library_path).name;
    let manifest = crate::root::test_plugins::native_manifest(
        "store",
        &library_path,
        plugins::FIXTURE_PUBLISHER,
    );
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = plugins::scratch(&format!(
        "law7_plane_gating-{}",
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
    let deploy = busbar_kernel::config::deploy_from_deserializer(
        serde_json::json!({
            "providers": {}, "models": {},
            "auth": {"chain": []},
            "store": {"module": module, "settings": settings},
            "advanced": {}
        }),
        &crate::root::boot::axis_test_grammar(),
    )
    .expect("the actual deployment parses");
    let mut config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the actual deployment resolves");
    config.plane_sections = sections.iter().copied().collect();
    let plugin_config = plugins::trusted_config(&directory);
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (app, rotate, limits) = crate::root::real_store::build_app(
        crate::root::test_plugins::plaintext_listeners(config),
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

    busbar_kernel::boot::hydrate_all(&app)
        .await
        .expect("hydrate");
    let handle = std::sync::Arc::new(busbar_kernel::state::AppHandle::new(app));
    busbar_kernel::boot::start_planes(&handle).expect("start");
    let result = (
        HYDRATED.load(Ordering::SeqCst) - h0,
        STARTED.load(Ordering::SeqCst) - s0,
    );
    busbar_kernel::plane_driver::registry::publish_planes(&[]);
    result
}

#[tokio::test]
async fn an_unconfigured_plane_hydrates_and_starts_nothing() {
    const CHILD: &str = "BUSBAR_LAW7_PROBE_CHILD";
    if std::env::var(CHILD).ok().as_deref()
        != Some("an_unconfigured_plane_hydrates_and_starts_nothing")
    {
        let module = module_path!()
            .split_once("::")
            .expect("a mounted test module")
            .1;
        let test = format!("{module}::an_unconfigured_plane_hydrates_and_starts_nothing");
        let output = std::process::Command::new(std::env::current_exe().expect("test executable"))
            .args([test.as_str(), "--exact", "--nocapture", "--test-threads=1"])
            .env(CHILD, "an_unconfigured_plane_hydrates_and_starts_nothing")
            .output()
            .expect("run the original behavior case in a fresh product process");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success()
                && stdout.contains("running 1 test")
                && stdout.contains(&format!("test {test} ..."))
                && stdout.contains("1 passed; 0 failed; 0 ignored"),
            "isolated original case failed or did not run exactly once:\n{stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    assert_eq!(
        boot_hooks_run(&[]).await,
        (0, 0),
        "a plane whose config section is absent must never have its hydrate/start hooks run (Law 7)"
    );
}

#[tokio::test]
async fn a_configured_plane_still_hydrates_and_starts() {
    const CHILD: &str = "BUSBAR_LAW7_PROBE_CHILD";
    if std::env::var(CHILD).ok().as_deref() != Some("a_configured_plane_still_hydrates_and_starts")
    {
        let module = module_path!()
            .split_once("::")
            .expect("a mounted test module")
            .1;
        let test = format!("{module}::a_configured_plane_still_hydrates_and_starts");
        let output = std::process::Command::new(std::env::current_exe().expect("test executable"))
            .args([test.as_str(), "--exact", "--nocapture", "--test-threads=1"])
            .env(CHILD, "a_configured_plane_still_hydrates_and_starts")
            .output()
            .expect("run the original behavior case in a fresh product process");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success()
                && stdout.contains("running 1 test")
                && stdout.contains(&format!("test {test} ..."))
                && stdout.contains("1 passed; 0 failed; 0 ignored"),
            "isolated original case failed or did not run exactly once:\n{stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    assert_eq!(
        boot_hooks_run(&[PROBE_SECTION]).await,
        (1, 1),
        "a plane whose config section is present must hydrate and start"
    );
}

#[tokio::test]
async fn only_a_configured_plane_builds_its_slot() {
    const CHILD: &str = "BUSBAR_LAW7_PROBE_CHILD";
    if std::env::var(CHILD).ok().as_deref() != Some("only_a_configured_plane_builds_its_slot") {
        let module = module_path!()
            .split_once("::")
            .expect("a mounted test module")
            .1;
        let test = format!("{module}::only_a_configured_plane_builds_its_slot");
        let output = std::process::Command::new(std::env::current_exe().expect("test executable"))
            .args([test.as_str(), "--exact", "--nocapture", "--test-threads=1"])
            .env(CHILD, "only_a_configured_plane_builds_its_slot")
            .output()
            .expect("run the original behavior case in a fresh product process");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success()
                && stdout.contains("running 1 test")
                && stdout.contains(&format!("test {test} ..."))
                && stdout.contains("1 passed; 0 failed; 0 ignored"),
            "isolated original case failed or did not run exactly once:\n{stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    crate::dist_root_install::install();
    let fallback = linked::fallback();
    let _one = PROBE_RUN.lock().await;
    busbar_kernel::plane_driver::registry::publish_planes(&[&PROBE]);
    let core = crate::root::real_store::core().await;
    let mut booted = false;
    let mut build = async |sections: &[&'static str]| {
        let library_path = crate::root::test_plugins::application_store_library();
        let module = crate::root::test_plugins::native_image(&library_path).name;
        let manifest = crate::root::test_plugins::native_manifest(
            "store",
            &library_path,
            plugins::FIXTURE_PUBLISHER,
        );
        let library = std::fs::read(library_path).expect("the actual store library reads");
        let directory = plugins::scratch(&format!(
            "law7_plane_gating-{}",
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
        let deploy = busbar_kernel::config::deploy_from_deserializer(
            serde_json::json!({
                "providers": {}, "models": {},
                "auth": {"chain": []},
                "store": {"module": module, "settings": settings},
                "advanced": {}
            }),
            &crate::root::boot::axis_test_grammar(),
        )
        .expect("the actual deployment parses");
        let mut config = busbar_kernel::config::resolve(&deploy, &Default::default())
            .expect("the actual deployment resolves");
        config.plane_sections = sections.iter().copied().collect();
        let b0 = BUILT.load(Ordering::SeqCst);
        let plugin_config = plugins::trusted_config(&directory);
        let rules = Arc::new(crate::root::door_steps::Rules::default())
            as Arc<dyn busbar_kernel::appbuild::RootRules>;
        let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
            crate::root::test_plugins::plaintext_listeners(config),
            plugin_config,
            None,
            Default::default(),
            Default::default(),
            (None, None),
            None,
            &rules,
            Some(core.clone()),
            false,
        )
        .await
        .expect("the actual product builds the door deployment");
        limits.stage_boot();
        if !booted {
            let _book = crate::root::boot::book(&app, "configured-store")
                .await
                .expect("the actual configured Store binds boot rate history before activation");
            booted = true;
        }
        limits.keep().await.expect("the product limits commit");
        if let Some(rotate) = rotate {
            rotate.await;
        }
        let app = Arc::new(app);

        (
            BUILT.load(Ordering::SeqCst) - b0,
            app.plane_slots.contains_key(PROBE.key),
            app.plane_configured(&PROBE),
            app.plane_configured(fallback),
        )
    };
    assert_eq!(
        build(&[]).await,
        (0, false, false, true),
        "unconfigured: no build call, no slot; the fallback plane stays configured"
    );
    assert_eq!(
        build(&[PROBE_SECTION]).await,
        (1, true, true, true),
        "configured: built once, slot present"
    );
    busbar_kernel::plane_driver::registry::publish_planes(&[]);
}
