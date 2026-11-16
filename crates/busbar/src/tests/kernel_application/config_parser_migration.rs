// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C3 retains the old normalizer tests' refusal/no-loss property through the approved plan.
//! Unsupported pre-1.5.5 transformations are intentionally not reproduced (MIGRATE-ON-BOOT 1a).

#[test]
fn malformed_or_retired_inputs_are_refused_without_mutating_the_authored_document() {
    crate::dist_root_install::install();
    let grammar = busbar_kernel::config::Grammar::new(
        busbar_kernel::config::secret::live_axis()
            .map(busbar_contract::secret::SecretAxis::sugars)
            .unwrap_or_default(),
        Default::default(),
        Vec::new(),
    );
    let cases = [
        "auth: opaque\nadmin_auth: [test-idp-double]\n",
        "auth: {admin_auth: opaque}\nadmin_auth: [test-idp-double]\n",
        "auth: opaque\ngovernance: {admin_token: '${ADMIN_TOKEN}'}\n",
        "auth: {upstream_credentials: caller}\npools: [unread]\n",
        "global_hooks: [screen]\npools: [unread]\n",
        "global_hooks: [screen]\npools: {hooks: opaque}\n",
        "group_map: {staff: opaque}\n",
        "group_map: {staff: {rpm_limit: 3, future_cap: 7}}\n",
        "governance: {budget_groups: {staff: opaque}}\n",
        "governance: {budget_groups: {staff: {max_budget_cents: 3, future_cap: 7}}}\n",
        "export: {7: {module: unknown-sink, settings: {keep: original}}}\n",
        "identity-providers: opaque\n",
        "identity-providers: [opaque]\n",
        "auth: [opaque]\n",
        "auth: {chain: opaque}\n",
        "store: opaque\n",
        "store: [opaque]\n",
        "store: 7\n",
        "budget_period: yearly\n",
        "tool_pools: {unreleased: {members: [a]}}\n",
        "agent_pools: {unreleased: {members: [a]}}\n",
    ];
    for (index, source) in cases.iter().enumerate() {
        let dir =
            std::env::temp_dir().join(format!("busbar-c3-strict-{}-{index}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.yaml");
        std::fs::write(&path, source).unwrap();
        std::fs::write(dir.join("providers.yaml"), "{}\n").unwrap();
        let facts = busbar_migrate::Facts::of_process(Vec::new(), Vec::new());
        let check = |text: &str, _: Option<&str>| {
            busbar_kernel::config::deploy_from_yaml_str(text, &grammar)
                .map(drop)
                .map_err(|error| error.to_string())
        };
        let refused = busbar_migrate::plan(&busbar_migrate::Inputs::new(&path, &facts, &check))
            .expect_err("malformed or retired input must not be normalized into validity");
        assert!(
            matches!(refused.word(), "CONFIG" | "UNSUPPORTED"),
            "case {index}: {refused}"
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), *source);
        let mut files: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        files.sort();
        assert_eq!(files, ["config.yaml", "providers.yaml"]);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
