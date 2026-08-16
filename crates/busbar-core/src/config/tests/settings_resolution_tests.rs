// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar/src/config/secret.rs`.

use super::*;

fn obj(pairs: &[(&str, serde_json::Value)]) -> serde_json::Map<String, serde_json::Value> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.clone()))
        .collect()
}

/// A SecretRef-shaped setting (the `{ env: … }` sugar for a `licenseKey`) is RESOLVED to its
/// value before delivery, while a plain sibling setting passes through verbatim.
#[test]
fn resolves_secret_ref_settings_and_passes_plain_through() {
    let var = format!("BUSBAR_PLUGIN_LICENSE_TEST_{}", std::process::id());
    std::env::set_var(&var, "LIC-123\n");
    let resolver = SecretResolver::builtins_only();
    let settings = obj(&[
        ("licenseKey", serde_json::json!({ "env": var })),
        ("endpoint", serde_json::json!("https://example.test")),
        ("retries", serde_json::json!(3)),
    ]);
    let out = resolve_settings(&settings, &resolver).unwrap();
    // The ref resolved to the raw secret (trailing newline trimmed) — a plain STRING now.
    assert_eq!(
        out.get("licenseKey").unwrap(),
        &serde_json::json!("LIC-123")
    );
    // Non-ref settings are untouched.
    assert_eq!(
        out.get("endpoint").unwrap(),
        &serde_json::json!("https://example.test")
    );
    assert_eq!(out.get("retries").unwrap(), &serde_json::json!(3));
    std::env::remove_var(&var);
}

/// An ordinary settings OBJECT that is not a secret reference (its keys aren't a ref's keys) is
/// left untouched — resolution only fires on a genuine ref shape.
#[test]
fn leaves_non_ref_object_settings_untouched() {
    let resolver = SecretResolver::builtins_only();
    let settings = obj(&[("db", serde_json::json!({ "path": ":memory:", "wal": true }))]);
    let out = resolve_settings(&settings, &resolver).unwrap();
    assert_eq!(
        out.get("db").unwrap(),
        &serde_json::json!({ "path": ":memory:", "wal": true })
    );
}

/// FAIL-CLOSED: a SecretRef setting that cannot resolve (unset env) is a hard error naming the
/// FIELD — never a silently-empty or dangling value handed to the plugin. The error text does not
/// echo any secret value.
#[test]
fn unresolvable_secret_ref_setting_fails_closed_naming_field() {
    let var = format!("BUSBAR_PLUGIN_LICENSE_MISSING_{}", std::process::id());
    std::env::remove_var(&var);
    let resolver = SecretResolver::builtins_only();
    let settings = obj(&[("license", serde_json::json!({ "env": var }))]);
    let err = resolve_settings(&settings, &resolver).unwrap_err();
    assert!(err.contains("license"), "names the field: {err}");
    assert!(err.contains("did not resolve"), "fail-closed: {err}");
}

/// An unknown secret module in a plugin setting is FAIL-CLOSED when no secret plugin can resolve
/// it (built-ins-only resolver), never handed through.
#[test]
fn unknown_secret_module_in_setting_fails_closed() {
    let resolver = SecretResolver::builtins_only();
    let settings = obj(&[(
        "licenseKey",
        // settings-leak-lint: allow — test fixture: a `kind: secret` module reference, not a response body.
        serde_json::json!({ "module": "vault", "settings": { "path": "kv/license" } }),
    )]);
    let err = resolve_settings(&settings, &resolver).unwrap_err();
    assert!(
        err.contains("licenseKey") && err.contains("fail-closed"),
        "unknown module fails closed: {err}"
    );
}

/// #40: a plugin setting shaped like a reference is AMBIGUOUS by nature, and the coercion used
/// to be silent — a plugin whose own config is `{ file: /var/lib/db }` (a PATH it opens) or
/// `{ env: HOME }` (a variable NAME it reads) had the value swapped for the file's contents /
/// the variable's value, with no diagnostic. `{ literal: … }` is the escape hatch: the inner
/// value is delivered verbatim and never resolved.
#[test]
fn literal_wrapper_opts_a_setting_out_of_secret_coercion() {
    let path = std::env::temp_dir().join(format!("busbar-lit-{}.txt", std::process::id()));
    std::fs::write(&path, b"THE-SECRET").unwrap();
    let resolver = SecretResolver::builtins_only();

    // Un-wrapped, the ref shape IS coerced (the documented ADR-0010 behaviour).
    let mut settings = serde_json::Map::new();
    settings.insert(
        "licenseKey".to_string(),
        serde_json::json!({ "file": path.to_string_lossy() }),
    );
    let out = resolve_settings(&settings, &resolver).expect("resolves");
    assert_eq!(out["licenseKey"], serde_json::json!("THE-SECRET"));

    // WRAPPED, the very same object is delivered verbatim — the plugin sees its own config.
    let mut settings = serde_json::Map::new();
    settings.insert(
        "db".to_string(),
        serde_json::json!({ "literal": { "file": path.to_string_lossy() } }),
    );
    let out = resolve_settings(&settings, &resolver).expect("resolves");
    assert_eq!(
        out["db"],
        serde_json::json!({ "file": path.to_string_lossy() }),
        "a `literal:`-wrapped object is passed through untouched, never dereferenced"
    );

    // The wrapper is not limited to ref-shaped objects, and it is exactly one level deep.
    let mut settings = serde_json::Map::new();
    settings.insert("n".to_string(), serde_json::json!({ "literal": 42 }));
    settings.insert("plain".to_string(), serde_json::json!({ "db_path": "x" }));
    let out = resolve_settings(&settings, &resolver).expect("resolves");
    assert_eq!(out["n"], serde_json::json!(42));
    assert_eq!(out["plain"], serde_json::json!({ "db_path": "x" }));

    let _ = std::fs::remove_file(&path);
}
