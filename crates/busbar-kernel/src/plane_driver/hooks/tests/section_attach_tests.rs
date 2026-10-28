// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A ROUTED-ORDER PLANE'S OWN SECTION ATTACH BINDS (THE DESIGN section 1: "Every plane gets every
//! capability ... the hook tap and gate ... apply to every plane the same way"). A plane whose
//! units name no container (a unit routed directly over a model entry) still carries the
//! section-level `hooks:` the operator wrote (`<section>.hooks: [...]`): the generation resolves it
//! under the plane's registry key at [`crate::hooks::SECTION_SCOPE`], and the routed binder binds it
//! to every unit of that plane beside the deployment's global hooks. RED: the binder bound the
//! globals and the pool's alone, so a section's attach was accepted, validated and never fired.

use std::sync::Arc;

use super::*;

/// The registry key of the plane whose section attaches the hooks.
const ATTACHED: &str = "plane-a";

/// What the hooks know of a caller: nothing (no principal is verified here).
struct NoCaller;

impl CallerFacts for NoCaller {
    fn key(&self, _principal: &str) -> Option<CallerKey> {
        None
    }
    fn in_groups(&self, _principal: Option<&str>, _groups: &[String]) -> bool {
        true
    }
    fn rate_headroom(&self, _principal: &str, _pool: &str) -> Option<f64> {
        None
    }
    fn budget(&self, _principal: &str) -> Vec<BudgetBucketState> {
        Vec::new()
    }
}

/// A `kind: gate` on the in-process hook double, holding `prompt` (a `rw` one is a rewrite).
fn gate(prompt: &str) -> crate::config::HookCfg {
    serde_json::from_value(serde_json::json!({
        "kind": "gate",
        "module": "test-hook",
        "timeout_ms": 10_000,
        "on_error": "weighted",
        "prompt": prompt,
        "user": "ro",
        "priority": 0,
        "settings": { "raw_decide_reply": {} },
        "global": false,
        "default": false,
        "signals": [],
        "groups": [],
        "phase": [],
    }))
    .expect("a hook document")
}

/// The routed binder of the plane registered as `plane_key`, over a generation whose plane
/// [`ATTACHED`] attaches `closed` (a gate) and `redact` (a rewrite) at its section level.
fn binder(plane_key: &str) -> HostHooks {
    let mut app = crate::test_support::TestApp::new();
    app.set_container_hooks(
        ATTACHED,
        Vec::new(),
        vec!["closed".to_string(), "redact".to_string()],
    );
    let app = app
        .hook_env(crate::test_support::test_hook_env(
            &["test-hook"],
            crate::test_support::HookNeeds {
                prompt: busbar_contract::plugin_rows::NeedLevel::Rw,
                user: busbar_contract::plugin_rows::NeedLevel::Ro,
            },
        ))
        .hook("closed", gate("ro"))
        .hook("redact", gate("rw"))
        .build();
    HostHooks {
        host: crate::plane_driver::engine_host(&app),
        caller: Arc::new(NoCaller),
        dialects: vec!["dialect-a".to_string()],
        plane_key: plane_key.to_string(),
    }
}

#[tokio::test]
async fn a_routed_planes_section_attach_binds_to_its_units() {
    let unit = Bind {
        pool: "plane-a/m",
        principal: None,
        dialect: 0,
        request_id: None,
        entry: None,
    };
    let bound = binder(ATTACHED)
        .bind(&unit)
        .expect("the section's attach binds to the plane's unit");
    assert_eq!(bound.gates.len(), 1, "the section's gate");
    assert_eq!(bound.rewrites.len(), 1, "the section's rewrite");
    // Another plane's units bind none of it, and a binder that names no plane binds none.
    assert!(binder("plane-b").bind(&unit).is_none());
    assert!(binder("").bind(&unit).is_none());
}

/// The section scope is the reserved section word, which no registration can be named.
#[test]
fn the_section_scope_is_the_reserved_hooks_word() {
    assert_eq!(crate::hooks::SECTION_SCOPE, "hooks");
    assert!(busbar_contract::section::RESERVED_SECTION_KEYS.contains(&crate::hooks::SECTION_SCOPE));
}

/// The routed binder of plane [`ATTACHED`] over a generation whose entry `srv-a` attaches `closed`
/// (a gate) and `redact` (a rewrite) of its own, beside a section-level `audit` gate; entry `srv-b`
/// attaches nothing of its own.
fn entry_binder() -> HostHooks {
    let mut app = crate::test_support::TestApp::new();
    app.set_container_hooks(
        ATTACHED,
        vec![
            (
                "srv-a".to_string(),
                vec!["closed".to_string(), "redact".to_string()],
            ),
            ("srv-b".to_string(), Vec::new()),
        ],
        vec!["audit".to_string()],
    );
    let app = app
        .hook_env(crate::test_support::test_hook_env(
            &["test-hook"],
            crate::test_support::HookNeeds {
                prompt: busbar_contract::plugin_rows::NeedLevel::Rw,
                user: busbar_contract::plugin_rows::NeedLevel::Ro,
            },
        ))
        .hook("closed", gate("ro"))
        .hook("redact", gate("rw"))
        .hook("audit", gate("ro"))
        .build();
    HostHooks {
        host: crate::plane_driver::engine_host(&app),
        caller: Arc::new(NoCaller),
        dialects: vec!["dialect-a".to_string()],
        plane_key: ATTACHED.to_string(),
    }
}

/// RED (E1a; THE DESIGN section 1, every plane gets every capability): a ROUTED-order unit of a
/// plane whose entries carry hooks (an MCP server's `tools.servers.X.hooks`, an A2A agent's
/// `agents.X.hooks`) binds the hooks attached to the entry the kernel recorded for it, the
/// section's attach among them, once each. Before, the routed binder bound the section's attach
/// alone and an entry's own gate never fired.
#[tokio::test]
async fn a_routed_unit_binds_the_hooks_attached_to_its_entry() {
    let binder = entry_binder();
    assert!(
        binder.entry_scoped(),
        "a plane with attached hooks binds per entry"
    );
    let unit = |entry| Bind {
        pool: "",
        principal: None,
        dialect: 0,
        request_id: None,
        entry,
    };
    let bound = binder
        .bind(&unit(Some("srv-a")))
        .expect("the entry's hooks bind");
    assert_eq!(
        bound.gates.len(),
        2,
        "the section's gate and the entry's own, once each"
    );
    assert_eq!(bound.rewrites.len(), 1, "the entry's rewrite");
    // An entry with nothing of its own, and a unit naming no entry, bind the section's attach.
    for entry in [Some("srv-b"), Some(""), None] {
        let bound = binder
            .bind(&unit(entry))
            .expect("the section's attach binds");
        assert_eq!(bound.gates.len(), 1, "{entry:?}: the section's gate alone");
        assert!(bound.rewrites.is_empty(), "{entry:?}");
    }
}

/// A plane the deployment attached no hook to (the LLM plane: its `pools:` section is neither
/// owned nor a named map, so the generation files no per-entry hooks under its key) is not
/// entry-scoped, and a unit naming an entry binds exactly what one naming none binds.
#[tokio::test]
async fn a_plane_with_no_attached_hooks_binds_as_before_whatever_entry_a_unit_names() {
    let binder = HostHooks {
        plane_key: "plane-b".to_string(),
        ..entry_binder()
    };
    assert!(!binder.entry_scoped());
    for entry in [Some("srv-a"), None] {
        assert!(
            binder
                .bind(&Bind {
                    pool: "",
                    principal: None,
                    dialect: 0,
                    request_id: None,
                    entry,
                })
                .is_none(),
            "{entry:?}"
        );
    }
}
