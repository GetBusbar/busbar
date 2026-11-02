// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Pure assembly must preserve state without taking any of boot's observable actions.

use super::{App, AppParts};
use busbar_contract::abi::export::ExportStream;
use busbar_contract::export_calls::{
    Delivered, ExportAxis, ExportCalls, Family, Probed, ServeRequest, Served,
};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

const CHILD: &str = "BUSBAR_APP_PARTS_ASSEMBLY_CHILD";
const SELECTOR: &str =
    "state::app_parts_tests::public_parts_assemble_without_boot_effects_or_journal_subscription";
static BUILDS: AtomicUsize = AtomicUsize::new(0);
static RETAINS: AtomicUsize = AtomicUsize::new(0);
static OPENS: AtomicUsize = AtomicUsize::new(0);

struct UncalledRules;
impl crate::appbuild::RootRules for UncalledRules {
    fn check(&self, _: &crate::config::RootCfg) -> Result<(), String> {
        panic!("pure App assembly cannot validate a configuration")
    }
    fn check_built(&self, _: &App) -> Result<(), String> {
        panic!("pure App assembly cannot invoke a root observer")
    }
    fn mounted_plugin_paths(&self, _: &App) -> Option<std::collections::HashSet<String>> {
        panic!("pure App assembly cannot ask the root for routes")
    }
    fn planes_awaiting_restart(&self, _: &crate::config::RootCfg) -> Vec<&'static str> {
        panic!("pure App assembly cannot invoke plane selection")
    }
    fn destinations_applied(&self, _: &crate::config::Destinations) {
        panic!("pure App assembly cannot publish destinations")
    }
}

struct Axis;
struct Sink;
static AXIS: Axis = Axis;
impl ExportAxis for Axis {
    fn probe(&self, _: &str, _: &str, _: &serde_json::Value) -> Option<Probed> {
        Some((Some(vec![ExportStream::Logs as u8]), Vec::new()))
    }
    fn check(&self, _: &str, _: u32, _: &[(String, &serde_json::Value)]) -> Option<Vec<String>> {
        Some(Vec::new())
    }
    fn open(
        &self,
        _: &str,
        _: &str,
        _: &serde_json::Value,
    ) -> Result<Arc<dyn ExportCalls>, String> {
        OPENS.fetch_add(1, Ordering::SeqCst);
        Ok(Arc::new(Sink))
    }
    fn linked(&self, _: &str) -> bool {
        true
    }
    fn first_party(&self, _: &str) -> bool {
        true
    }
}
impl ExportCalls for Sink {
    fn streams(&self) -> &[u8] {
        &[ExportStream::Logs as u8]
    }
    fn routes(&self) -> &[busbar_contract::abi::mechanism::route::Route] {
        &[]
    }
    fn deliver(&self, _: u8, _: Vec<u8>, _: Box<dyn Send>) -> Delivered {
        Delivered::Queued
    }
    fn scrape(&self, _: &[Family]) -> Result<Vec<u8>, String> {
        Err("this sink has no scrape".into())
    }
    fn status(&self) -> Option<Vec<u8>> {
        None
    }
    fn serve(&self, _: &ServeRequest<'_>) -> Result<Served, String> {
        Err("this sink serves no route".into())
    }
}

static PLANE: crate::plane_driver::registry::PlaneDecl = crate::plane_driver::registry::PlaneDecl {
    declaration: crate::plane_driver::registry::PlaneDeclaration {
        key: "app-parts-effects",
        config_section: "app-parts-effects",
        fallback: false,
        ..crate::test_support::NEUTRAL_FALLBACK.declaration
    },
    build: |_, _| {
        BUILDS.fetch_add(1, Ordering::SeqCst);
        None
    },
    retain_verify_gates: Some(|_| {
        RETAINS.fetch_add(1, Ordering::SeqCst);
    }),
    ..crate::test_support::NEUTRAL_FALLBACK
};

#[test]
fn public_parts_assemble_without_boot_effects_or_journal_subscription() {
    // These assertions install real process-wide registrations. Keep them in their own process
    // so sibling tests cannot either observe the spies or pre-bind the export sinks' OnceLocks.
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().expect("the test binary"))
            .args(["--exact", SELECTOR, "--nocapture"])
            .env(CHILD, "1")
            .output()
            .expect("run the isolated assembly control");
        assert!(
            output.status.success(),
            "assembly control failed: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        return;
    }

    // Obtain the ordinary fixture's already-public values before installing the spies. The
    // constructor under test consumes these exact values rather than inventing a configuration.
    let base = (*crate::test_support::TestApp::new().build()).clone();
    let mut parts = public_parts(base);
    parts.config_version = 41;
    parts.public_url = Some("https://assembly.example".to_owned());
    parts.root_rules = Arc::new(UncalledRules);
    let rules = Arc::clone(&parts.root_rules);
    parts.amendments = Arc::new(crate::audit::amend::NodeAmendments::new());
    let journal = Arc::clone(&parts.amendments);
    let counter = Arc::clone(&parts.request_id_counter);
    counter.store(777, Ordering::SeqCst);

    crate::preflight::publish_root_rows(crate::preflight::RootInstall {
        registry_build: Some(|_, _| panic!("pure assembly cannot build a registry")),
        plugins_fetch: Some(|_, _, _, _| panic!("pure assembly cannot fetch a plugin")),
        hook_axis: Some(|_| panic!("pure assembly cannot open a hook axis")),
        store_axis: Some(|| panic!("pure assembly cannot open a Store")),
        secret_admit: Some(|_, _| panic!("pure assembly cannot admit secret modules")),
        plugin_logs: Some(|_| panic!("pure assembly cannot configure plugin logs")),
        auth_axis: Some(|_| panic!("pure assembly cannot open an auth axis")),
        config_projection: Some(|_| panic!("pure assembly cannot project configuration")),
        export_axis: Some(&AXIS),
        ..Default::default()
    });
    let _planes = crate::test_support::planes::TestRegistryIsolation::seeded(&[&PLANE]);
    crate::export::plugin::open(&crate::config::ExportCfg {
        recorder: None,
        plugins: vec![crate::config::PluginExportSettings {
            name: "assembly-observer".into(),
            def: crate::config::ExportDefCfg {
                module: "assembly-observer".into(),
                streams: None,
                fields: None,
                durable: false,
                settings: Default::default(),
            },
            projection: crate::export::projection::Projection::for_test(&[ExportStream::Logs], &[]),
            scrape: false,
        }],
    })
    .expect("open the journal-subscription observer before assembly");
    assert_eq!(OPENS.load(Ordering::SeqCst), 1);
    let before = Arc::strong_count(&journal);

    let assembled = App::from_test_parts(parts);

    assert_eq!(BUILDS.load(Ordering::SeqCst), 0);
    assert_eq!(RETAINS.load(Ordering::SeqCst), 0);
    assert_eq!(OPENS.load(Ordering::SeqCst), 1);
    assert_eq!(Arc::strong_count(&journal), before, "no sink subscribed");
    assert!(Arc::ptr_eq(&assembled.amendments, &journal));
    assert!(Arc::ptr_eq(&assembled.root_rules, &rules));
    assert!(Arc::ptr_eq(&assembled.request_id_counter, &counter));
    assert_eq!(assembled.request_id_counter.load(Ordering::SeqCst), 777);
    assert_eq!(assembled.config_version, 41);
    assert_eq!(
        assembled.public_url.as_deref(),
        Some("https://assembly.example")
    );
    assert!(assembled.login_methods.methods.is_empty());
    assert_eq!(assembled.export_projections, Default::default());

    // Positive control: the actual boot subscription retains this same journal. The reference
    // count assertion above would detect accidentally running this real observer during assembly.
    crate::export::plugin::record_reads_on(&journal);
    assert_eq!(Arc::strong_count(&journal), before + 1);
    (PLANE.retain_verify_gates.expect("the retention observer"))(&assembled);
    assert_eq!(RETAINS.load(Ordering::SeqCst), 1);
}

fn public_parts(app: App) -> AppParts {
    AppParts {
        fallback_runtime_key: app.fallback_runtime_key,
        serve_tables: app.serve_tables,
        root_rules: app.root_rules,
        config_projection: app.config_projection,
        config_tables: app.config_tables,
        store: app.store,
        limits: app.limits,
        session_store: app.session_store,
        incremental_scan: app.incremental_scan,
        plane_pools: app.plane_pools,
        auth: app.auth,
        rewrite_hooks: app.rewrite_hooks,
        tap_hooks: app.tap_hooks,
        tap_hooks_candidate: app.tap_hooks_candidate,
        tap_hooks_routing: app.tap_hooks_routing,
        tap_hooks_response: app.tap_hooks_response,
        global_gates: app.global_gates,
        pool_orderings: app.pool_orderings,
        pool_decision_gates: app.pool_decision_gates,
        pool_rewrite_chains: app.pool_rewrite_chains,
        plane_gates: app.plane_gates,
        plane_rewrites: app.plane_rewrites,
        hook_env: app.hook_env,
        hook_registry: app.hook_registry,
        requested_signals: app.requested_signals,
        any_content_hook: app.any_content_hook,
        global_hooks: app.global_hooks,
        base_hook_names: app.base_hook_names,
        groups_registry: app.groups_registry,
        base_group_names: app.base_group_names,
        identity_providers: app.identity_providers,
        export_defs: app.export_defs,
        admin: app.admin,
        admin_chain: app.admin_chain,
        admin_modules: app.admin_modules,
        public_url: app.public_url,
        oauth_as: app.oauth_as,
        demotion_record: app.demotion_record,
        amendments: app.amendments,
        planes: app.planes,
        plane_slots: app.plane_slots,
        plane_sections: app.plane_sections,
        auth_scope_caps: app.auth_scope_caps,
        role_bindings: app.role_bindings,
        config_path: app.config_path,
        providers_path: app.providers_path,
        overlay_path: app.overlay_path,
        config_version: app.config_version,
        max_keys_per_principal: app.max_keys_per_principal,
        max_auto_provisioned_groups: app.max_auto_provisioned_groups,
        governance: app.governance,
        secret_resolver: app.secret_resolver,
        cost: app.cost,
        plugins_dir: app.plugins_dir,
        plugins_cfg: app.plugins_cfg,
        plugin_admission: app.plugin_admission,
        self_key_ttl_secs: app.self_key_ttl_secs,
        mint_policy: app.mint_policy,
        request_id_counter: app.request_id_counter,
        plugin_routes: app.plugin_routes,
        boot_route_paths: app.boot_route_paths,
        planes_awaiting_restart: app.planes_awaiting_restart,
    }
}
