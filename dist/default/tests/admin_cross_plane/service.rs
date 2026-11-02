// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_core_admin::v1::service::build_with_hook;
use busbar_kernel::config::{HookCfg, HookKind, PromptAccess, UserAccess};

fn hook(kind: HookKind, global: bool) -> HookCfg {
    HookCfg {
        kind,
        plugin: "test-hook".to_string(),
        timeout_ms: 5,
        on_error: "weighted".to_string(),
        prompt: PromptAccess::No,
        user: UserAccess::No,
        priority: 0,
        settings: serde_json::Map::new(),
        at: None,
        on_empty: None,
        global,
        default: false,
        signals: Vec::new(),
        groups: Vec::new(),
        phase: Vec::new(),
    }
}

#[test]
fn build_with_hook_makes_a_plane_attach_live() {
    let env =
        busbar_kernel_testkit::test_support::test_hook_env(&["test-hook"], Default::default());

    let mut builder = crate::new_test_app().hook_env(env);
    let tools = busbar_kernel::plane_driver::registry::plane_decl_for_config_section("tools")
        .expect("a plane is registered to own the `tools:` section");
    builder.set_container_hooks(
        tools.key,
        vec![("fs".to_string(), vec!["screen".to_string()])],
        Vec::new(),
    );

    {
        let section: serde_yaml::Value = serde_yaml::from_str(
            "fs:\n  url: https://tools.internal/fs\n  pin: { mechanism: cert_spki, key: \"sha256/BASE=\" }\n  hooks: [screen]\n",
        )
        .unwrap();
        let parse = tools
            .parse_section
            .expect("the plane parses its own section");
        let cfg = parse(tools, &section).expect("the `tools:` section parses");
        match tools.build_runtime {
            Some(build) => {
                builder.install_plane_runtime(
                    busbar_kernel::state::runtime_slot_key(tools.key),
                    build(cfg.as_any(), None),
                );
            }

            None => {
                let defs =
                    std::collections::BTreeMap::from([(tools.config_section, cfg.clone_box())]);
                let ctx = busbar_kernel::plane_driver::registry::BuildCtx {
                    endpoint_slot: None,
                    plane_defs: &defs,
                    public_url: None,
                    prior: None,
                    providers: None,
                };
                let slot = (tools.build)(tools, &ctx).expect("the plane builds from its section");
                builder.install_plane_runtime(tools.key, slot);
            }
        }
    }
    let app = builder.build();
    assert!(
        !app.plane_gates(tools.key)
            .is_some_and(|g| g.contains_key("fs")),
        "the attach names a hook no registry entry defines yet, so it resolves to nothing"
    );

    let next = build_with_hook(&app, "screen", hook(HookKind::Gate, false))
        .expect("a valid gate registers");
    assert_eq!(
        next.plane_gates(tools.key)
            .and_then(|g| g.get("fs"))
            .map(|g| g.len())
            .unwrap_or_default(),
        1,
        "registering the DEFINITION must make the server's existing attach resolve — a 200 OK that \
         leaves the chain empty is an operator told a control is attached when it is not"
    );
}
