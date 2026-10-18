//! SCRATCH (never merged): every registered gate's RED proof, one process each, to find the
//! rotten ones before the `xtask-selftest` check exists.

fn selftest(name: &str) {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(["selftest", name])
        .output()
        .expect("xtask runs");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let tail: Vec<&str> = text.lines().rev().take(40).collect();
    let tail: Vec<&str> = tail.into_iter().rev().collect();
    assert!(
        out.status.success(),
        "SELFTEST-RED {name} ({:?}):\n{}",
        out.status.code(),
        tail.join("\n")
    );
}

#[test]
fn census_construction() {
    selftest("construction");
}

#[test]
fn census_instance_noun_neutrality() {
    selftest("instance-noun-neutrality");
}

#[test]
fn census_plane_pricing_blindness() {
    selftest("plane-pricing-blindness");
}

#[test]
fn census_qa_names() {
    selftest("qa-names");
}

#[test]
fn census_money_invariants() {
    selftest("money-invariants");
}

#[test]
fn census_conformance_sync() {
    selftest("conformance-sync");
}

#[test]
fn census_structure_lint() {
    selftest("structure-lint");
}

#[test]
fn census_kind_isolation() {
    selftest("kind-isolation");
}

#[test]
fn census_call_binding() {
    selftest("call-binding");
}

#[test]
fn census_deferral_words() {
    selftest("deferral-words");
}

#[test]
fn census_default_measurements() {
    selftest("default-measurements");
}

#[test]
fn census_admin_config_parity() {
    selftest("admin-config-parity");
}

#[test]
fn census_hook_parity_count() {
    selftest("hook-parity-count");
}

#[test]
fn census_design_docs_allowlist() {
    selftest("design-docs-allowlist");
}

#[test]
fn census_documented_claims() {
    selftest("documented-claims");
}

#[test]
fn census_secret_hygiene() {
    selftest("secret-hygiene");
}

#[test]
fn census_script_allowlist() {
    selftest("script-allowlist");
}

#[test]
fn census_design_bindings() {
    selftest("design-bindings");
}

#[test]
fn census_denylist() {
    selftest("denylist");
}

#[test]
fn census_changelog() {
    selftest("changelog");
}

#[test]
fn census_changelog_register() {
    selftest("changelog-register");
}

#[test]
fn census_inventory_ref() {
    selftest("inventory-ref");
}

#[test]
fn census_workflow_rules() {
    selftest("workflow-rules");
}

#[test]
fn census_service_images() {
    selftest("service-images");
}

#[test]
fn census_workspace_deps() {
    selftest("workspace-deps");
}

#[test]
fn census_plane_purity() {
    selftest("plane-purity");
}

#[test]
fn census_plane_purity_strict() {
    selftest("plane-purity-strict");
}

#[test]
fn census_reachability() {
    selftest("reachability");
}

#[test]
fn census_unconstructed() {
    selftest("unconstructed");
}

#[test]
fn census_segregation() {
    selftest("segregation");
}

#[test]
fn census_kernel_token_wire_purity() {
    selftest("kernel-token-wire-purity");
}

#[test]
fn census_no_float_money() {
    selftest("no-float-money");
}

#[test]
fn census_seal_witness() {
    selftest("seal-witness");
}

#[test]
fn census_secret_accessor_seal() {
    selftest("secret-accessor-seal");
}

#[test]
fn census_config_scope() {
    selftest("config-scope");
}

#[test]
fn census_abi_location() {
    selftest("abi-location");
}

#[test]
fn census_one_memory_abi() {
    selftest("one-memory-abi");
}

#[test]
fn census_abi_header() {
    selftest("abi-header");
}

#[test]
fn census_abi_freeze() {
    selftest("abi-freeze");
}

#[test]
fn census_contract_stateless() {
    selftest("contract-stateless");
}

#[test]
fn census_plugin_closure_deps() {
    selftest("plugin-closure-deps");
}

#[test]
fn census_c1_literals() {
    selftest("c1-literals");
}

#[test]
fn census_door_only() {
    selftest("door-only");
}

#[test]
fn census_plane_secret_blindness() {
    selftest("plane-secret-blindness");
}

#[test]
fn census_linked_dropped_features() {
    selftest("linked-dropped-features");
}

#[test]
fn census_kind_isolation_ship() {
    selftest("kind-isolation-ship");
}

#[test]
fn census_tracing() {
    selftest("tracing");
}

#[test]
fn census_no_self_filed_issues() {
    selftest("no-self-filed-issues");
}

#[test]
fn census_ship_ready() {
    selftest("ship-ready");
}

#[test]
fn census_settings_leak() {
    selftest("settings-leak");
}

#[test]
fn census_response_header() {
    selftest("response-header");
}

#[test]
fn census_blocking_ffi() {
    selftest("blocking-ffi");
}

#[test]
fn census_plane_transport_neutrality() {
    selftest("plane-transport-neutrality");
}

#[test]
fn census_dep_wall() {
    selftest("dep-wall");
}

#[test]
fn census_plane_abi_neutrality() {
    selftest("plane-abi-neutrality");
}

#[test]
fn census_field_inventory() {
    selftest("field-inventory");
}

#[test]
fn census_no_deferral() {
    selftest("no-deferral");
}

#[test]
fn census_no_deferral_strict_done() {
    selftest("no-deferral-strict-done");
}

#[test]
fn census_duplex_ws_default_edge() {
    selftest("duplex-ws-default-edge");
}

#[test]
fn census_hot_path_perf() {
    selftest("hot-path-perf");
}

#[test]
fn census_hot_path_alloc() {
    selftest("hot-path-alloc");
}

#[test]
fn census_teller_steps() {
    selftest("teller-steps");
}

#[test]
fn census_config_schema() {
    selftest("config-schema");
}

#[test]
fn census_inventory_coverage() {
    selftest("inventory-coverage");
}

#[test]
fn census_dialect_map() {
    selftest("dialect-map");
}

#[test]
fn census_dialect_map_in_lock() {
    selftest("dialect-map-in-lock");
}

#[test]
fn census_dialect_candidates() {
    selftest("dialect-candidates");
}

#[test]
fn census_no_tracked_ignored() {
    selftest("no-tracked-ignored");
}

#[test]
fn census_package_selectors() {
    selftest("package-selectors");
}
