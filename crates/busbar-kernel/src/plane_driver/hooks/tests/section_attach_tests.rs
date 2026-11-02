// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;

use super::*;

const ATTACHED: &str = "plane-a";

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
    fn hook_read(&self, _: &str, _: Option<&str>, _: &str, _: bool) {}
}

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
    };
    let bound = binder(ATTACHED)
        .bind(&unit)
        .expect("the section's attach binds to the plane's unit");
    assert_eq!(bound.gates.len(), 1, "the section's gate");
    assert_eq!(bound.rewrites.len(), 1, "the section's rewrite");

    assert!(binder("plane-b").bind(&unit).is_none());
    assert!(binder("").bind(&unit).is_none());
}

#[test]
fn the_section_scope_is_the_reserved_hooks_word() {
    assert_eq!(crate::hooks::SECTION_SCOPE, "hooks");
    assert!(busbar_contract::section::RESERVED_SECTION_KEYS.contains(&crate::hooks::SECTION_SCOPE));
}
