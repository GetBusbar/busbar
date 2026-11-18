// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Pre-release config keys that were never in a release and are gone: `plugins.logs.*` and
//! `hooks.<h>.child_dispatch`. A config that sets one is refused as an unknown key, both read from
//! config.yaml and composed from an admin `PUT /config/settings` `document_patch`. A 1.5.5-shaped
//! config (no removed key; `hooks.<h>.signals` kept) still parses. `models.<m>.protocol` is not
//! removed: it is the adopted member dialect override (ABI-MIN3-INTERFACE r34 §8.6 item 2, §16.135).

use std::path::PathBuf;

use busbar_kernel::appbuild::{load_config_from_disk_with_document_patches, AcceptAll};
use busbar_kernel::config::document_patch::DocumentPatch;
use busbar_kernel::config::{deploy_from_yaml_str, EnvSubst, Grammar};

const BASE: &str = "models:\n  m: { provider: p }\nhooks:\n  h: { module: acme }\n";

const GRANT: &str = "{ revision: 1, plane: decision, operation: POST, \
    target: /busbar/decisions/v1/classify, target_binding: classifier, max_input_bytes: 16384, \
    max_output_bytes: 65536, max_children: 1, timeout_ms: 1000, max_budget_micros: 1000000 }";

fn refused(text: &str) -> String {
    match deploy_from_yaml_str(text, &Grammar::empty()) {
        Ok(_) => panic!("a config carrying a removed key must be refused:\n{text}"),
        Err(e) => format!("{e}"),
    }
}

#[test]
fn plugins_logs_is_refused_as_an_unknown_key() {
    for body in [
        "dir: /var/log/plugins",
        "level: debug",
        "levels: { primary: debug }",
        "rotate_mb: 64",
        "keep: 5",
    ] {
        let err = refused(&format!("plugins:\n  logs: {{ {body} }}\n"));
        assert!(err.contains("unknown field `logs`"), "{body}: {err}");
    }
}

#[test]
fn models_protocol_is_the_adopted_dialect_override() {
    let deploy = deploy_from_yaml_str(
        "models:\n  m: { provider: p, protocol: openai }\n",
        &Grammar::empty(),
    )
    .expect("models.<m>.protocol is the member dialect override (IF r34 §8.6 item 2)");
    assert_eq!(deploy.models["m"].protocol.as_deref(), Some("openai"));
}

#[test]
fn hooks_child_dispatch_is_refused_as_an_unknown_key() {
    let err = refused(&format!(
        "hooks:\n  h:\n    module: acme\n    kind: gate\n    child_dispatch: {GRANT}\n"
    ));
    assert!(err.contains("unknown field `child_dispatch`"), "{err}");
}

#[test]
fn a_1_5_5_shaped_config_still_parses() {
    let deploy = deploy_from_yaml_str(
        "plugins:\n  enabled: false\n  min_versions: { acme: \"1.0.0\" }\n\
         models:\n  m: { provider: p, max_concurrent: 4, reasoning: true }\n\
         hooks:\n  h:\n    module: acme\n    kind: gate\n    timeout_ms: 5\n    signals: [request_text_complete]\n",
        &Grammar::empty(),
    )
    .expect("a config with no removed key parses");
    assert!(deploy.models.contains_key("m"));
    assert!(deploy.hooks.contains_key("h"));
}

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("busbar-removed-w2g-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    std::fs::write(dir.join("config.yaml"), BASE).expect("config.yaml");
    dir
}

/// What the admin `PUT /config/settings` door composes: config.yaml plus a `document_patch`.
fn composed(tag: &str, patch: serde_json::Value) -> Result<(), String> {
    let dir = scratch(tag);
    let patch = DocumentPatch::from_value(patch).expect("a well-formed document_patch");
    let loaded = load_config_from_disk_with_document_patches(
        &dir.join("config.yaml"),
        None,
        false,
        EnvSubst::Strict,
        &AcceptAll,
        Some(&patch),
        None,
    );
    let _ = std::fs::remove_dir_all(&dir);
    loaded.map(|_| ()).map_err(|e| format!("{e:?}"))
}

#[test]
fn the_settings_door_refuses_a_patch_that_sets_a_removed_key() {
    let grant: serde_json::Value = serde_json::json!({
        "revision": 1, "plane": "decision", "operation": "POST",
        "target": "/busbar/decisions/v1/classify", "target_binding": "classifier",
        "max_input_bytes": 16384, "max_output_bytes": 65536, "max_children": 1,
        "timeout_ms": 1000, "max_budget_micros": 1000000
    });
    for (tag, set, key) in [
        ("logs-level", "/plugins/logs", "logs"),
        ("child", "/hooks/h/child_dispatch", "child_dispatch"),
    ] {
        let value = match key {
            "logs" => serde_json::json!({"level": "debug"}),
            _ => grant.clone(),
        };
        let err = composed(tag, serde_json::json!({"set": {set: value}}))
            .expect_err("the removed key is refused at the settings door");
        assert!(
            err.contains("unknown field") && err.contains(key),
            "{tag}: {err}"
        );
    }
}

/// PM ruling D-REDACT (2026-11-17): the settings door names an unknown field only when that name is
/// a key the caller's own patch names, and never a value; every other boot-parse error of the
/// patched document stays redacted as b381eadf2e made it.
#[test]
fn the_settings_door_names_only_the_callers_own_key_and_never_a_value() {
    const REDACTED: &str = "patched configuration failed boot parsing";
    // Named by the patch's own path: quoted, and the value it set is not.
    let err = composed(
        "redact-named",
        serde_json::json!({"set": {"/hooks/h/child_dispatch": "CANARY-VALUE-1"}}),
    )
    .expect_err("the removed key is refused");
    assert!(
        err.contains(&format!("{REDACTED}: unknown field `child_dispatch`")),
        "{err}"
    );
    assert!(!err.contains("CANARY-VALUE-1"), "a value was quoted: {err}");
    // A key inside the submitted value is value, not a path the patch names: redacted whole.
    let err = composed(
        "redact-value",
        serde_json::json!({"set": {"/hooks/h": {"module": "acme", "canary_inner_key": "CANARY-VALUE-2"}}}),
    )
    .expect_err("the unknown inner key is refused");
    assert!(err.contains(REDACTED), "{err}");
    assert!(!err.contains("unknown field"), "{err}");
    assert!(!err.contains("canary_inner_key"), "{err}");
    assert!(!err.contains("CANARY-VALUE-2"), "{err}");
}
