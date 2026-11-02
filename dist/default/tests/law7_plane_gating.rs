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
    pub(super) fn owning(section: &str) -> &'static PlaneDecl {
        planes()
            .iter()
            .copied()
            .find(|decl| {
                decl.config_section == section || decl.owned_config_sections.contains(&section)
            })
            .expect("the actual distribution declares the configured section")
    }
    pub(super) fn fallback() -> &'static PlaneDecl {
        planes()
            .iter()
            .copied()
            .find(|decl| decl.fallback)
            .expect("the actual distribution declares its fallback")
    }
    pub(super) fn door_section(decl: &PlaneDecl) -> &'static str {
        decl.owned_config_sections
            .first()
            .copied()
            .unwrap_or(decl.config_section)
    }
}

use busbar_kernel::plane_driver::registry::{PlaneDecl, PlaneDeclaration};
use std::sync::Arc;
#[path = "../../../crates/busbar/src/root/tests/test_plugins.rs"]
mod plugins;

static PROBE_RUN: std::sync::Mutex<()> = std::sync::Mutex::new(());

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
    admin_routes: None,
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
    reresolve_gates: None,
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

fn boot_hooks_run(sections: &[&'static str]) -> (usize, usize) {
    let _one = PROBE_RUN
        .lock()
        .expect("probe fixture serializes its counters");
    crate::dist_root_install::install();
    linked::install();
    busbar_kernel::plane_driver::registry::publish_planes(&[&PROBE]);
    let (h0, s0) = (
        HYDRATED.load(Ordering::SeqCst),
        STARTED.load(Ordering::SeqCst),
    );
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
    let directory = plugins::scratch("installed-door-route");
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
        "providers": {}, "models": {},
        "auth": {"chain": [], "admin_auth": []},
        "store": {"module": module, "settings": settings},
        "advanced": {"allow_destinations": ["127.0.0.1"]}
    }))
    .expect("the actual deployment parses");
    let mut config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the actual deployment resolves");
    config.plane_sections = sections.iter().copied().collect();
    let plugin_config = busbar_kernel::config::PluginsCfg {
        enabled: true,
        dir: directory.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (app, rotate, limits) = busbar_kernel::build_app_from_config(
        config,
        plugin_config,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
    )
    .expect("the actual product builds the door deployment");
    limits.keep().expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let app = Arc::new(app);

    busbar_kernel::boot::hydrate_all(&app).expect("hydrate");
    let handle = std::sync::Arc::new(busbar_kernel::state::AppHandle::new(app));
    busbar_kernel::boot::start_planes(&handle).expect("start");
    let result = (
        HYDRATED.load(Ordering::SeqCst) - h0,
        STARTED.load(Ordering::SeqCst) - s0,
    );
    busbar_kernel::plane_driver::registry::publish_planes(&[]);
    result
}

#[test]
fn an_unconfigured_plane_hydrates_and_starts_nothing() {
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
                && stdout.contains(&format!("test {test} ... ok"))
                && stdout.contains("1 passed; 0 failed; 0 ignored"),
            "isolated original case failed or did not run exactly once:\n{stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    assert_eq!(
        boot_hooks_run(&[]),
        (0, 0),
        "a plane whose config section is absent must never have its hydrate/start hooks run (Law 7)"
    );
}

#[test]
fn a_configured_plane_still_hydrates_and_starts() {
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
                && stdout.contains(&format!("test {test} ... ok"))
                && stdout.contains("1 passed; 0 failed; 0 ignored"),
            "isolated original case failed or did not run exactly once:\n{stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    assert_eq!(
        boot_hooks_run(&[PROBE_SECTION]),
        (1, 1),
        "a plane whose config section is present must hydrate and start"
    );
}

#[test]
fn only_a_configured_plane_builds_its_slot() {
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
                && stdout.contains(&format!("test {test} ... ok"))
                && stdout.contains("1 passed; 0 failed; 0 ignored"),
            "isolated original case failed or did not run exactly once:\n{stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    crate::dist_root_install::install();
    let fallback = linked::fallback();
    let _one = PROBE_RUN
        .lock()
        .expect("probe fixture serializes its counters");
    busbar_kernel::plane_driver::registry::publish_planes(&[&PROBE]);
    let build = |sections: &[&'static str]| {
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
        let directory = plugins::scratch("installed-door-route");
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
            "providers": {}, "models": {},
            "auth": {"chain": [], "admin_auth": []},
            "store": {"module": module, "settings": settings},
            "advanced": {"allow_destinations": ["127.0.0.1"]}
        }))
        .expect("the actual deployment parses");
        let mut config = busbar_kernel::config::resolve(&deploy, &Default::default())
            .expect("the actual deployment resolves");
        config.plane_sections = sections.iter().copied().collect();
        let b0 = BUILT.load(Ordering::SeqCst);
        let plugin_config = busbar_kernel::config::PluginsCfg {
            enabled: true,
            dir: directory.to_string_lossy().into_owned(),
            ..Default::default()
        };
        let rules = Arc::new(crate::root::door_steps::Rules::default())
            as Arc<dyn busbar_kernel::appbuild::RootRules>;
        let (app, rotate, limits) = busbar_kernel::build_app_from_config(
            config,
            plugin_config,
            None,
            Default::default(),
            Default::default(),
            (None, None),
            None,
            &rules,
        )
        .expect("the actual product builds the door deployment");
        limits.keep().expect("the product limits commit");
        if let Some(rotate) = rotate {
            rotate();
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
        build(&[]),
        (0, false, false, true),
        "unconfigured: no build call, no slot; the fallback plane stays configured"
    );
    assert_eq!(
        build(&[PROBE_SECTION]),
        (1, true, true, true),
        "configured: built once, slot present"
    );
    busbar_kernel::plane_driver::registry::publish_planes(&[]);
}

#[test]
fn resolve_reads_the_configured_plane_sections_off_the_config() {
    crate::dist_root_install::install();
    let tools_plane = linked::owning("tools");
    let door = linked::door_section(tools_plane);
    assert_ne!(
        door, tools_plane.config_section,
        "the `tools:` plane declares an endpoint door of its own"
    );
    let sections = |extra: &str| {
        let yaml = format!(
            "providers:\n  acme: {{ api_key: none }}\nmodels:\n  m: {{ provider: acme }}\n{extra}"
        );
        let deploy = busbar_kernel::config::deploy_from_yaml_str(&yaml).expect("parse");
        let mut defs = std::collections::HashMap::new();
        defs.insert(
            "acme".to_string(),
            serde_yaml::from_str("protocol: anthropic\nbase_url: https://api.example.com\n")
                .expect("provider def"),
        );
        busbar_kernel::config::resolve(&deploy, &defs)
            .expect("resolve")
            .plane_sections
            .into_iter()
            .collect::<Vec<_>>()
    };
    assert_eq!(
        sections("public_url: https://gw.example.com\n"),
        Vec::<&str>::new(),
        "a 1.5.5-shaped config (public_url included) configures no plane"
    );
    assert_eq!(
        sections(
            "tools:\n  t1: { url: \"https://t.example/t\", pin: { mechanism: unpinned } }\n\
             agents:\n  a1: { url: \"https://a.example/a\", pin: { mechanism: unpinned } }\n"
        ),
        vec!["agents", "tools"]
    );
    assert_eq!(
        sections(&format!(
            "{door}:\n  canonical_uri: \"https://gw.example.com/{}\"\n  authorization_servers: [\"https://as.example.com\"]\n",
            tools_plane.key
        )),
        vec![tools_plane.config_section],
        "the `{door}:` door configures the plane that owns it"
    );
}
