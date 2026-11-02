// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::redacted::Secret;

#[test]
fn resolver_builtins_resolve_without_plugin() {
    let r = SecretResolver::builtins_only();
    let var = format!("BUSBAR_RESOLVER_TEST_{}", std::process::id());
    std::env::set_var(&var, "abc\n");
    assert_eq!(
        r.resolve(&SecretRef::env(&var)).unwrap(),
        Secret::new(b"abc\n".to_vec())
    );
    assert_eq!(
        r.resolve_string(&SecretRef::env(&var)).unwrap(),
        Secret::new("abc".to_string())
    );
    std::env::remove_var(&var);
}

#[test]
fn resolver_unknown_module_without_plugin_fails_closed() {
    let r = SecretResolver::builtins_only();
    let s = SecretRef {
        module: "vault".to_string(),
        settings: serde_json::Map::new(),
    };
    let err = r.resolve(&s).unwrap_err();
    assert!(
        err.contains("vault") && err.contains("fail-closed"),
        "unknown module with no plugin refuses: {err}"
    );
}

#[test]
fn resolver_delegates_to_plugin_and_fails_closed_on_empty_or_error() {
    let r = SecretResolver::with_plugin(Box::new(|module: &str, settings: &str| {
        if module == "vault" {
            let v: serde_json::Value = serde_json::from_str(settings).unwrap();
            match v.get("path").and_then(|p| p.as_str()) {
                Some("kv/ok") => Ok(Secret::new(b"plugin-secret".to_vec())),
                Some("kv/empty") => Ok(Secret::new(Vec::new())),
                _ => Err("no such path".to_string()),
            }
        } else {
            Err("unknown module".to_string())
        }
    }));
    let mk = |path: &str| {
        let mut settings = serde_json::Map::new();
        settings.insert(
            "path".to_string(),
            serde_json::Value::String(path.to_string()),
        );
        SecretRef {
            module: "vault".to_string(),
            settings,
        }
    };
    assert_eq!(
        r.resolve(&mk("kv/ok")).unwrap(),
        Secret::new(b"plugin-secret".to_vec())
    );

    assert!(r.resolve(&mk("kv/empty")).unwrap_err().contains("EMPTY"));

    assert!(r
        .resolve(&mk("kv/missing"))
        .unwrap_err()
        .contains("failed to resolve"));

    let var = format!("BUSBAR_RESOLVER_PLUGIN_TEST_{}", std::process::id());
    std::env::set_var(&var, "envval");
    assert_eq!(
        r.resolve_string(&SecretRef::env(&var)).unwrap(),
        Secret::new("envval".to_string())
    );
    std::env::remove_var(&var);
}
