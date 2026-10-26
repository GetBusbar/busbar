// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-core/src/config/secret.rs`.

use super::*;

/// A whitespace-only (or empty) `env:` NAME — not value — must be rejected at the settings-shape
/// layer (`self_env_var_checked`), never silently treated as "no name given, fall through" or
/// "look up an env var literally named '   '". Distinct from
/// `linked_secret_hardening_tests::resolve_linked_env_empty_value_is_fail_closed`, which covers the
/// RESOLVED VALUE being empty, not the configured variable name itself.
#[test]
fn env_whitespace_only_name_is_rejected() {
    for bad in ["", "   ", "\t\n"] {
        let r = SecretRef::env(bad);
        let err = SecretResolver::builtins_only()
            .resolve(&r)
            .expect_err(&format!(
                "whitespace-only env name {bad:?} must be rejected"
            ));
        assert!(
            err.contains("requires settings.key"),
            "whitespace-only env name {bad:?} must fail the settings-shape check, got: {err}"
        );
    }
}

/// Same guard, `file:` PATH side.
#[test]
fn file_whitespace_only_path_is_rejected() {
    for bad in ["", "   ", "\t\n"] {
        let r = SecretRef::file(bad);
        let err = SecretResolver::builtins_only()
            .resolve(&r)
            .expect_err(&format!(
                "whitespace-only file path {bad:?} must be rejected"
            ));
        assert!(
            err.contains("requires settings.path"),
            "whitespace-only file path {bad:?} must fail the settings-shape check, got: {err}"
        );
    }
}

/// `none` declares the ABSENCE of a credential, so every resolver refuses it rather than handing
/// back an empty secret. A call site that permits a keyless upstream must say so explicitly
/// (`SecretRef::is_none()`) — it may never learn it from an empty resolution, which is the exact
/// confusion between "no credential" and "credential I could not read" this change removes.
#[test]
fn none_reference_has_no_value_to_resolve() {
    let r = SecretRef::none();
    let resolver = SecretResolver::builtins_only();
    for err in [
        SecretResolver::builtins_only().resolve(&r).unwrap_err(),
        resolver.resolve(&r).unwrap_err(),
        resolver.resolve_string(&r).unwrap_err(),
    ] {
        assert!(
            err.contains("no value to resolve"),
            "`none` never resolves to a value: {err}"
        );
    }
}

/// Deserialize: the `{env}` / `{file}` sugar desugars to the canonical module + settings; the
/// canonical form parses; mixed / unknown / empty forms are rejected.
#[test]
fn deserialize_accepts_canonical_and_sugar_rejects_malformed() {
    let r: SecretRef = serde_yaml::from_str("{ env: MY_VAR }").unwrap();
    assert_eq!(r, SecretRef::env("MY_VAR"));
    assert_eq!(r.env_var(), Some("MY_VAR"));
    let r: SecretRef = serde_yaml::from_str("{ file: /run/secrets/x }").unwrap();
    assert_eq!(r, SecretRef::file("/run/secrets/x"));
    assert_eq!(r.file_path(), Some("/run/secrets/x"));
    let r: SecretRef =
        serde_yaml::from_str("{ module: vault, settings: { path: kv/data/x } }").unwrap();
    assert_eq!(r.module, "vault");
    assert_eq!(
        r.settings.get("path").and_then(|v| v.as_str()),
        Some("kv/data/x")
    );

    for bad in [
        "{ env: A, file: B }",
        "{ module: vault, env: A }",
        "{ env: A, settings: {} }",
        "{ unknown_key: A }",
        "{}",
        "{ env: \"\" }",
        "{ module: \"\" }",
        "plain-string",
    ] {
        assert!(
            serde_yaml::from_str::<SecretRef>(bad).is_err(),
            "must reject: {bad}"
        );
    }
}
