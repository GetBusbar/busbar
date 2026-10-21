//! SCRATCH (never merged): every registered gate's RED proof, one `xtask selftest <gate>` process
//! each, to census the rotten ones on dev before the `selftest` check joins the move battery
//! (status row 191). Each test name carries the twelve-minute nextest override's substring.

fn selftest(name: &str) {
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_xtask"));
    cmd.args(["selftest", name]).env("XTASK_SHIP_TARGET", "dev");
    // As the selftest checks export it: the move's target. This branch IS dev's tip, so with no
    // MODERNCI_TO_SHA the base is HEAD.
    let base = std::env::var("MODERNCI_TO_SHA").ok().filter(|s| !s.is_empty()).unwrap_or_else(|| {
        let out = std::process::Command::new("git").args(["rev-parse", "HEAD"]).output().expect("git runs");
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    });
    cmd.env("XTASK_CEILING_BASE", base);
    let t0 = std::time::Instant::now();
    let out = cmd.output().expect("xtask runs");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let tail: Vec<&str> = text.lines().rev().take(60).collect();
    let tail: Vec<&str> = tail.into_iter().rev().collect();
    assert!(
        out.status.success(),
        "SELFTEST-RED {name} ({:?}) after {:.0}s:\n{}",
        out.status.code(),
        t0.elapsed().as_secs_f64(),
        tail.join("\n")
    );
    eprintln!("SELFTEST-GREEN {name} {:.0}s", t0.elapsed().as_secs_f64());
}

#[test]
fn the_kind_isolation_gate_proves_red_in_its_selftest_census_call_binding() {
    selftest("call-binding");
}

#[test]
fn the_kind_isolation_gate_proves_red_in_its_selftest_census_construction() {
    selftest("construction");
}

#[test]
fn the_kind_isolation_gate_proves_red_in_its_selftest_census_deferral_words() {
    selftest("deferral-words");
}

#[test]
fn the_kind_isolation_gate_proves_red_in_its_selftest_census_default_measurements() {
    selftest("default-measurements");
}

#[test]
fn the_kind_isolation_gate_proves_red_in_its_selftest_census_admin_config_parity() {
    selftest("admin-config-parity");
}

#[test]
fn the_kind_isolation_gate_proves_red_in_its_selftest_census_hook_parity_count() {
    selftest("hook-parity-count");
}

#[test]
fn the_kind_isolation_gate_proves_red_in_its_selftest_census_design_docs_allowlist() {
    selftest("design-docs-allowlist");
}

#[test]
fn the_kind_isolation_gate_proves_red_in_its_selftest_census_documented_claims() {
    selftest("documented-claims");
}

#[test]
fn the_kind_isolation_gate_proves_red_in_its_selftest_census_secret_hygiene() {
    selftest("secret-hygiene");
}

#[test]
fn the_kind_isolation_gate_proves_red_in_its_selftest_census_script_allowlist() {
    selftest("script-allowlist");
}

#[test]
fn the_kind_isolation_gate_proves_red_in_its_selftest_census_design_bindings() {
    selftest("design-bindings");
}

#[test]
fn the_kind_isolation_gate_proves_red_in_its_selftest_census_denylist() {
    selftest("denylist");
}

#[test]
fn the_kind_isolation_gate_proves_red_in_its_selftest_census_changelog() {
    selftest("changelog");
}

#[test]
fn the_kind_isolation_gate_proves_red_in_its_selftest_census_changelog_register() {
    selftest("changelog-register");
}

#[test]
fn the_kind_isolation_gate_proves_red_in_its_selftest_census_inventory_ref() {
    selftest("inventory-ref");
}

#[test]
fn the_kind_isolation_gate_proves_red_in_its_selftest_census_workflow_rules() {
    selftest("workflow-rules");
}

#[test]
fn the_kind_isolation_gate_proves_red_in_its_selftest_census_service_images() {
    selftest("service-images");
}

#[test]
fn the_kind_isolation_gate_proves_red_in_its_selftest_census_workspace_deps() {
    selftest("workspace-deps");
}

#[test]
fn the_kind_isolation_gate_proves_red_in_its_selftest_census_plane_purity() {
    selftest("plane-purity");
}

#[test]
fn the_kind_isolation_gate_proves_red_in_its_selftest_census_plane_purity_strict() {
    selftest("plane-purity-strict");
}

#[test]
fn the_kind_isolation_gate_proves_red_in_its_selftest_census_reachability() {
    selftest("reachability");
}

#[test]
fn the_kind_isolation_gate_proves_red_in_its_selftest_census_unconstructed() {
    selftest("unconstructed");
}

#[test]
fn the_kind_isolation_gate_proves_red_in_its_selftest_census_segregation() {
    selftest("segregation");
}

#[test]
fn the_kind_isolation_gate_proves_red_in_its_selftest_census_kernel_token_wire_purity() {
    selftest("kernel-token-wire-purity");
}

#[test]
fn the_kind_isolation_gate_proves_red_in_its_selftest_census_no_float_money() {
    selftest("no-float-money");
}

#[test]
fn the_kind_isolation_gate_proves_red_in_its_selftest_census_seal_witness() {
    selftest("seal-witness");
}

#[test]
fn the_kind_isolation_gate_proves_red_in_its_selftest_census_secret_accessor_seal() {
    selftest("secret-accessor-seal");
}

#[test]
fn the_kind_isolation_gate_proves_red_in_its_selftest_census_config_scope() {
    selftest("config-scope");
}

#[test]
fn the_kind_isolation_gate_proves_red_in_its_selftest_census_money_invariants() {
    selftest("money-invariants");
}

#[test]
fn the_kind_isolation_gate_proves_red_in_its_selftest_census_abi_location() {
    selftest("abi-location");
}

#[test]
fn the_kind_isolation_gate_proves_red_in_its_selftest_census_one_memory_abi() {
    selftest("one-memory-abi");
}

#[test]
fn the_kind_isolation_gate_proves_red_in_its_selftest_census_abi_header() {
    selftest("abi-header");
}

#[test]
fn the_kind_isolation_gate_proves_red_in_its_selftest_census_abi_freeze() {
    selftest("abi-freeze");
}

#[test]
fn the_kind_isolation_gate_proves_red_in_its_selftest_census_contract_stateless() {
    selftest("contract-stateless");
}

#[test]
fn the_kind_isolation_gate_proves_red_in_its_selftest_census_plugin_closure_deps() {
    selftest("plugin-closure-deps");
}

#[test]
fn the_kind_isolation_gate_proves_red_in_its_selftest_census_c1_literals() {
    selftest("c1-literals");
}

#[test]
fn the_kind_isolation_gate_proves_red_in_its_selftest_census_door_only() {
    selftest("door-only");
}

#[test]
fn the_kind_isolation_gate_proves_red_in_its_selftest_census_plane_secret_blindness() {
    selftest("plane-secret-blindness");
}

#[test]
fn the_kind_isolation_gate_proves_red_in_its_selftest_census_linked_dropped_features() {
    selftest("linked-dropped-features");
}

#[test]
fn the_kind_isolation_gate_proves_red_in_its_selftest_census_kind_isolation() {
    selftest("kind-isolation");
}

#[test]
fn the_kind_isolation_gate_proves_red_in_its_selftest_census_kind_isolation_ship() {
    selftest("kind-isolation-ship");
}

#[test]
fn the_kind_isolation_gate_proves_red_in_its_selftest_census_tracing() {
    selftest("tracing");
}

#[test]
fn the_kind_isolation_gate_proves_red_in_its_selftest_census_no_self_filed_issues() {
    selftest("no-self-filed-issues");
}

#[test]
fn the_kind_isolation_gate_proves_red_in_its_selftest_census_ship_ready() {
    selftest("ship-ready");
}

#[test]
fn the_kind_isolation_gate_proves_red_in_its_selftest_census_settings_leak() {
    selftest("settings-leak");
}

#[test]
fn the_kind_isolation_gate_proves_red_in_its_selftest_census_response_header() {
    selftest("response-header");
}

#[test]
fn the_kind_isolation_gate_proves_red_in_its_selftest_census_blocking_ffi() {
    selftest("blocking-ffi");
}

#[test]
fn the_kind_isolation_gate_proves_red_in_its_selftest_census_plane_transport_neutrality() {
    selftest("plane-transport-neutrality");
}

#[test]
fn the_kind_isolation_gate_proves_red_in_its_selftest_census_dep_wall() {
    selftest("dep-wall");
}

#[test]
fn the_kind_isolation_gate_proves_red_in_its_selftest_census_plane_abi_neutrality() {
    selftest("plane-abi-neutrality");
}

#[test]
fn the_kind_isolation_gate_proves_red_in_its_selftest_census_instance_noun_neutrality() {
    selftest("instance-noun-neutrality");
}

#[test]
fn the_kind_isolation_gate_proves_red_in_its_selftest_census_plane_pricing_blindness() {
    selftest("plane-pricing-blindness");
}

#[test]
fn the_kind_isolation_gate_proves_red_in_its_selftest_census_structure_lint() {
    selftest("structure-lint");
}

#[test]
fn the_kind_isolation_gate_proves_red_in_its_selftest_census_field_inventory() {
    selftest("field-inventory");
}

#[test]
fn the_kind_isolation_gate_proves_red_in_its_selftest_census_no_deferral() {
    selftest("no-deferral");
}

#[test]
fn the_kind_isolation_gate_proves_red_in_its_selftest_census_no_deferral_strict_done() {
    selftest("no-deferral-strict-done");
}

#[test]
fn the_kind_isolation_gate_proves_red_in_its_selftest_census_duplex_ws_default_edge() {
    selftest("duplex-ws-default-edge");
}

#[test]
fn the_kind_isolation_gate_proves_red_in_its_selftest_census_hot_path_perf() {
    selftest("hot-path-perf");
}

#[test]
fn the_kind_isolation_gate_proves_red_in_its_selftest_census_hot_path_alloc() {
    selftest("hot-path-alloc");
}

#[test]
fn the_kind_isolation_gate_proves_red_in_its_selftest_census_teller_steps() {
    selftest("teller-steps");
}

#[test]
fn the_kind_isolation_gate_proves_red_in_its_selftest_census_config_schema() {
    selftest("config-schema");
}

#[test]
fn the_kind_isolation_gate_proves_red_in_its_selftest_census_conformance_sync() {
    selftest("conformance-sync");
}

#[test]
fn the_kind_isolation_gate_proves_red_in_its_selftest_census_inventory_coverage() {
    selftest("inventory-coverage");
}

#[test]
fn the_kind_isolation_gate_proves_red_in_its_selftest_census_dialect_map() {
    selftest("dialect-map");
}

#[test]
fn the_kind_isolation_gate_proves_red_in_its_selftest_census_dialect_map_in_lock() {
    selftest("dialect-map-in-lock");
}

#[test]
fn the_kind_isolation_gate_proves_red_in_its_selftest_census_dialect_candidates() {
    selftest("dialect-candidates");
}

#[test]
fn the_kind_isolation_gate_proves_red_in_its_selftest_census_no_tracked_ignored() {
    selftest("no-tracked-ignored");
}

#[test]
fn the_kind_isolation_gate_proves_red_in_its_selftest_census_package_selectors() {
    selftest("package-selectors");
}

#[test]
fn the_kind_isolation_gate_proves_red_in_its_selftest_census_qa_names() {
    selftest("qa-names");
}
