// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar/src/config/secret.rs`.

use super::*;

/// The env built-in resolves a set variable, trims trailing newlines in the string form, and
/// fails closed on unset / empty values.
#[test]
fn env_module_resolves_and_fails_closed() {
    let var = format!("BUSBAR_SECRET_TEST_{}", std::process::id());
    std::env::set_var(&var, "s3cret\n");
    let r = SecretRef::env(&var);
    assert_eq!(resolve_builtin(&r).unwrap(), b"s3cret\n");
    assert_eq!(resolve_builtin_string(&r).unwrap(), "s3cret");
    std::env::remove_var(&var);
    let err = resolve_builtin(&r).unwrap_err();
    assert!(err.contains("unset"), "unset env is fail-closed: {err}");
    std::env::set_var(&var, "");
    let err = resolve_builtin(&r).unwrap_err();
    assert!(err.contains("EMPTY"), "empty env is fail-closed: {err}");
    std::env::remove_var(&var);
}

/// The file built-in resolves file bytes and fails closed on a missing or empty file.
#[test]
fn file_module_resolves_and_fails_closed() {
    let path = std::env::temp_dir().join(format!("busbar-secret-{}.txt", std::process::id()));
    std::fs::write(&path, b"file-secret\n").unwrap();
    let r = SecretRef::file(path.to_string_lossy().into_owned());
    assert_eq!(resolve_builtin(&r).unwrap(), b"file-secret\n");
    assert_eq!(resolve_builtin_string(&r).unwrap(), "file-secret");
    std::fs::write(&path, b"").unwrap();
    let err = resolve_builtin(&r).unwrap_err();
    assert!(err.contains("EMPTY"), "empty file is fail-closed: {err}");
    let _ = std::fs::remove_file(&path);
    let err = resolve_builtin(&r).unwrap_err();
    assert!(err.contains("cannot resolve"), "missing file fails: {err}");
}

/// A whitespace-only (or empty) `env:` NAME — not value — must be rejected at the settings-shape
/// layer (`self_env_var_checked`), never silently treated as "no name given, fall through" or
/// "look up an env var literally named '   '". Distinct from `env_module_resolves_and_fails_closed`
/// above, which covers the RESOLVED VALUE being empty, not the configured variable name itself.
#[test]
fn env_whitespace_only_name_is_rejected() {
    for bad in ["", "   ", "\t\n"] {
        let r = SecretRef::env(bad);
        let err = resolve_builtin(&r).expect_err(&format!(
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
        let err = resolve_builtin(&r).expect_err(&format!(
            "whitespace-only file path {bad:?} must be rejected"
        ));
        assert!(
            err.contains("requires settings.path"),
            "whitespace-only file path {bad:?} must fail the settings-shape check, got: {err}"
        );
    }
}

/// An unknown secret module is FAIL-CLOSED at the built-in resolver (the plugin-backed
/// resolver layers on top; anything it cannot resolve lands here and refuses).
#[test]
fn unknown_module_fails_closed() {
    let r = SecretRef {
        module: "vault".to_string(),
        settings: serde_json::Map::new(),
    };
    let err = resolve_builtin(&r).unwrap_err();
    assert!(
        err.contains("fail-closed") && err.contains("vault"),
        "unknown module refuses: {err}"
    );
}

/// Malformed built-in refs (env without key, file without path) error precisely, never fall
/// through to "unknown module".
#[test]
fn malformed_builtin_refs_error_precisely() {
    let r = SecretRef {
        module: SECRET_MODULE_ENV.to_string(),
        settings: serde_json::Map::new(),
    };
    assert!(resolve_builtin(&r).unwrap_err().contains("settings.key"));
    let r = SecretRef {
        module: SECRET_MODULE_FILE.to_string(),
        settings: serde_json::Map::new(),
    };
    assert!(resolve_builtin(&r).unwrap_err().contains("settings.path"));
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
