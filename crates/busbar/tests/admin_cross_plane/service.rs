// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The admin service's build-time test that needs a linked plane (moved from busbar-core-admin's
//! `src/v1/tests/service_tests.rs`, assertions unchanged).

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

/// A hook registered through the ADMIN API must become live on every OTHER compiled-in plane too,
/// not only on the pool-scoped hooks.
///
/// The failure this pins is specific and silent: an operator writes an MCP server's `hooks: [screen]`
/// attach in the file and registers the `screen` DEFINITION later through the API. At boot the name
/// resolved to nothing (no definition yet), so the server's gate chain was empty — and without
/// `reresolve_plane_gates` the register would answer `200 OK` while that chain stayed empty
/// forever, leaving the operator believing a control is attached that is not. The pool-scoped hooks'
/// own three `resolve_*` calls exist for exactly this reason; this test exercises that same
/// fail-open for a plane-owned attach, using MCP as the concrete plane under test.
#[test]
fn build_with_hook_makes_a_plane_attach_live() {
    let env = busbar_kernel::test_support::test_hook_env(&["test-hook"], Default::default());
    // The ONLY thing this test reads of the `tools.fs` registration is its hook ATTACH
    // (`hooks: [screen]`), whose resolution lands in the plane's gate map. Drive that through core's
    // NEUTRAL container-hook seam, keyed by the plane the registry says owns the `tools:` section, so
    // this in-crate unit test names no plane, no plane crate and no plane config type (the full
    // end-to-end builder path is covered by the plane crate's own integration tests).
    let mut builder = crate::new_test_app().hook_env(env);
    let tools = busbar_kernel::plane::registry::plane_decl_for_config_section("tools")
        .expect("a plane is registered to own the `tools:` section");
    builder.set_container_hooks(
        tools.key,
        vec![("fs".to_string(), vec!["screen".to_string()])],
        Vec::new(),
    );
    // The `reresolve_gates` seam re-reads the SERVER REGISTRY off the plane's runtime slot, so the
    // runtime this generation carries must actually hold the `fs` server (with its `hooks: [screen]`
    // attach) for the re-resolution under test to have anything to resolve. Build it the way
    // `appbuild` does — the owning plane parses its own section and builds its runtime from it — so
    // `build()`'s default empty runtime is not what gets read back.
    {
        let section: serde_yaml::Value = serde_yaml::from_str(
            "fs:\n  url: https://tools.internal/fs\n  pin: { mechanism: cert_spki, key: \"sha256/BASE=\" }\n  hooks: [screen]\n",
        )
        .unwrap();
        let parse = tools
            .parse_section
            .expect("the plane parses its own section");
        let cfg = parse(&section).expect("the `tools:` section parses");
        match tools.build_runtime {
            Some(build) => {
                builder.install_plane_runtime(
                    busbar_kernel::state::runtime_slot_key(tools.key),
                    build(cfg.as_any(), None),
                );
            }
            // A plane served through its door builds its slot through its own `build`, the slot
            // its `reresolve_gates` re-reads the registry off.
            None => {
                let ctx = busbar_kernel::plane::registry::BuildCtx {
                    endpoint_slot: None,
                    agent_defs: &(),
                    tool_defs: cfg.as_any(),
                    public_url: None,
                    prior: None,
                    providers: None,
                };
                let slot = (tools.build)(&ctx).expect("the plane builds from its section");
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
