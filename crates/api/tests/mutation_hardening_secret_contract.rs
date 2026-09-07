// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! MUTATION-HARDENING: the `busbar_api::secret` module — `SecretError`/`SecretErrorKind`,
//! `SecretModule`'s defaulted `resolve_with_deadline`, and the built-in `env`/`file` resolvers
//! (`resolve_builtin`/`resolve_builtin_string`).
//!
//! Before this file, `crates/api/src/secret.rs` had NO test coverage at all (no `#[cfg(test)] mod
//! tests` in the source file, no entry in `crates/api/src/tests/`) — every branch here, including
//! the fail-closed error paths ("env var unset", "file empty", "unknown module", "non-UTF-8 where a
//! text secret is required"), was unexercised. That is the totality gap this file closes: every
//! `SecretError` constructor's `kind`, and every fail-closed branch of the built-in resolvers'
//! happy AND error paths, gets an explicit assertion.
//!
//! Integration test (crates/api/tests/, auto-discovered by Cargo) — public-surface only, same
//! convention as `mutation_hardening_store_contract.rs` in this same directory.

use busbar_api::{SecretError, SecretErrorKind, SecretModule, SecretRef, SecretResult};
use std::sync::atomic::{AtomicU64, Ordering};

/// A process-lifetime-unique suffix so parallel test threads never pick the same env var name.
fn unique(tag: &str) -> String {
    static CTR: AtomicU64 = AtomicU64::new(0);
    format!(
        "BUSBAR_API_MUTATION_TEST_{tag}_{}_{}",
        std::process::id(),
        CTR.fetch_add(1, Ordering::SeqCst)
    )
}

// ── `SecretErrorKind` / `SecretError` construction + Display ─────────────────────────────────────

#[test]
fn secret_error_constructors_set_the_matching_kind() {
    assert_eq!(SecretError::not_found("x").kind, SecretErrorKind::NotFound);
    assert_eq!(SecretError::unavailable("x").kind, SecretErrorKind::Unavailable);
    assert_eq!(SecretError::denied("x").kind, SecretErrorKind::Denied);
    assert_eq!(SecretError::invalid("x").kind, SecretErrorKind::Invalid);
    assert_eq!(SecretError::internal("x").kind, SecretErrorKind::Internal);
    assert_eq!(
        SecretError::new(SecretErrorKind::Denied, "y").kind,
        SecretErrorKind::Denied
    );
}

#[test]
fn secret_error_display_carries_kind_and_message() {
    let e = SecretError::not_found("vault path missing");
    let s = e.to_string();
    assert!(s.contains("NotFound"), "{s}");
    assert!(s.contains("vault path missing"), "{s}");
}

/// Every error constructed before the taxonomy existed (a bare-string `?`-conversion) becomes
/// `Internal` — behaviorally identical to the untyped predecessor, just now typed. Pinning BOTH
/// `From` impls separately: nothing here says `From<&str>` must delegate to `From<String>` (or vice
/// versa), so a mutant that broke one but not the other needs both covered.
#[test]
fn secret_error_from_string_and_str_are_internal_kind() {
    let from_string: SecretError = "boom".to_string().into();
    assert_eq!(from_string.kind, SecretErrorKind::Internal);
    assert_eq!(from_string.message, "boom");

    let from_str: SecretError = "boom".into();
    assert_eq!(from_str.kind, SecretErrorKind::Internal);
    assert_eq!(from_str.message, "boom");
}

// ── `SecretModule::resolve_with_deadline` DEFAULT — forwards to `resolve`, ignores the deadline ──

struct RecordingModule {
    calls: std::sync::atomic::AtomicUsize,
}

impl SecretModule for RecordingModule {
    fn resolve(
        &self,
        settings: &serde_json::Map<String, serde_json::Value>,
    ) -> SecretResult<Vec<u8>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        match settings.get("v").and_then(|v| v.as_str()) {
            Some(v) => Ok(v.as_bytes().to_vec()),
            None => Err(SecretError::invalid("missing v")),
        }
    }
}

#[test]
fn resolve_with_deadline_default_forwards_to_resolve_and_ignores_deadline() {
    let m = RecordingModule {
        calls: Default::default(),
    };
    let mut settings = serde_json::Map::new();
    settings.insert("v".to_string(), serde_json::Value::String("hi".into()));

    // With a deadline...
    let got = m.resolve_with_deadline(&settings, Some(50)).unwrap();
    assert_eq!(got, b"hi");
    // ...and with none — both reach the same underlying `resolve`.
    let got = m.resolve_with_deadline(&settings, None).unwrap();
    assert_eq!(got, b"hi");
    assert_eq!(m.calls.load(Ordering::SeqCst), 2);

    // The error path forwards too, unmodified.
    let empty = serde_json::Map::new();
    let err = m.resolve_with_deadline(&empty, Some(1)).unwrap_err();
    assert_eq!(err.kind, SecretErrorKind::Invalid);
}

// ── `resolve_builtin` — the `env` module ─────────────────────────────────────────────────────────

#[test]
fn resolve_builtin_env_happy_path_reads_the_variable() {
    let var = unique("ENV_HAPPY");
    std::env::set_var(&var, "s3cr3t-value");
    let got = busbar_api::resolve_builtin(&SecretRef::env(&var)).unwrap();
    assert_eq!(got, b"s3cr3t-value");
    std::env::remove_var(&var);
}

#[test]
fn resolve_builtin_env_empty_value_is_fail_closed() {
    let var = unique("ENV_EMPTY");
    std::env::set_var(&var, "");
    let err = busbar_api::resolve_builtin(&SecretRef::env(&var)).unwrap_err();
    assert!(err.contains("EMPTY"), "{err}");
    assert!(err.contains(&var), "{err}");
    std::env::remove_var(&var);
}

#[test]
fn resolve_builtin_env_unset_variable_is_an_error() {
    let var = unique("ENV_UNSET");
    std::env::remove_var(&var); // ensure genuinely unset
    let err = busbar_api::resolve_builtin(&SecretRef::env(&var)).unwrap_err();
    assert!(err.contains("unset"), "{err}");
    assert!(err.contains(&var), "{err}");
}

/// A malformed `env`-module reference (module name matches but the settings shape does not carry a
/// usable `key`) must fail LOUD with a shape-specific message — never silently fall through to the
/// generic "not a built-in" refusal (which would misreport the actual problem).
#[test]
fn resolve_builtin_env_malformed_settings_is_a_shape_error_not_unknown_module() {
    let malformed = SecretRef {
        module: "env".to_string(),
        settings: serde_json::Map::new(), // no `key`
    };
    let err = busbar_api::resolve_builtin(&malformed).unwrap_err();
    assert!(err.contains("settings.key"), "{err}");
    assert!(
        !err.contains("is not a built-in"),
        "a malformed env ref must not be misreported as an unknown module: {err}"
    );
}

#[test]
fn resolve_builtin_env_blank_key_is_also_malformed() {
    let mut settings = serde_json::Map::new();
    settings.insert("key".to_string(), serde_json::Value::String("   ".into()));
    let blank = SecretRef {
        module: "env".to_string(),
        settings,
    };
    let err = busbar_api::resolve_builtin(&blank).unwrap_err();
    assert!(err.contains("settings.key"), "{err}");
}

// ── `resolve_builtin` — the `file` module ────────────────────────────────────────────────────────

fn temp_path(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(unique(tag))
}

#[test]
fn resolve_builtin_file_happy_path_reads_the_file() {
    let path = temp_path("FILE_HAPPY");
    std::fs::write(&path, b"file-secret-bytes").unwrap();
    let got = busbar_api::resolve_builtin(&SecretRef::file(path.to_str().unwrap())).unwrap();
    assert_eq!(got, b"file-secret-bytes");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn resolve_builtin_file_empty_file_is_fail_closed() {
    let path = temp_path("FILE_EMPTY");
    std::fs::write(&path, b"").unwrap();
    let err = busbar_api::resolve_builtin(&SecretRef::file(path.to_str().unwrap())).unwrap_err();
    assert!(err.contains("EMPTY"), "{err}");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn resolve_builtin_file_missing_file_is_an_error() {
    let path = temp_path("FILE_MISSING"); // never created
    let err = busbar_api::resolve_builtin(&SecretRef::file(path.to_str().unwrap())).unwrap_err();
    assert!(err.contains("cannot resolve"), "{err}");
}

#[test]
fn resolve_builtin_file_malformed_settings_is_a_shape_error_not_unknown_module() {
    let malformed = SecretRef {
        module: "file".to_string(),
        settings: serde_json::Map::new(), // no `path`
    };
    let err = busbar_api::resolve_builtin(&malformed).unwrap_err();
    assert!(err.contains("settings.path"), "{err}");
    assert!(!err.contains("is not a built-in"), "{err}");
}

// ── `resolve_builtin` — unknown module ───────────────────────────────────────────────────────────

#[test]
fn resolve_builtin_unknown_module_is_fail_closed_and_names_the_module() {
    let vault_ref = SecretRef {
        module: "vault".to_string(),
        settings: serde_json::Map::new(),
    };
    let err = busbar_api::resolve_builtin(&vault_ref).unwrap_err();
    assert!(err.contains("vault"), "{err}");
    assert!(err.contains("not a built-in"), "{err}");
}

// ── `resolve_builtin_string` ──────────────────────────────────────────────────────────────────────

#[test]
fn resolve_builtin_string_trims_trailing_newlines() {
    let var = unique("STR_TRIM");
    std::env::set_var(&var, "top-secret\r\n");
    let got = busbar_api::resolve_builtin_string(&SecretRef::env(&var)).unwrap();
    assert_eq!(got, "top-secret");
    std::env::remove_var(&var);
}

#[test]
fn resolve_builtin_string_empty_after_trim_is_fail_closed() {
    let var = unique("STR_EMPTY_AFTER_TRIM");
    // Non-empty bytes (so the raw resolve_builtin succeeds) that trim to nothing.
    std::env::set_var(&var, "\n\r\n");
    let err = busbar_api::resolve_builtin_string(&SecretRef::env(&var)).unwrap_err();
    assert!(err.contains("empty"), "{err}");
    std::env::remove_var(&var);
}

#[test]
fn resolve_builtin_string_non_utf8_is_an_error() {
    let path = temp_path("STR_NON_UTF8");
    std::fs::write(&path, [0xFF, 0xFE, 0xFD]).unwrap();
    let err =
        busbar_api::resolve_builtin_string(&SecretRef::file(path.to_str().unwrap())).unwrap_err();
    assert!(err.contains("non-UTF-8"), "{err}");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn resolve_builtin_string_propagates_the_underlying_resolve_error() {
    let path = temp_path("STR_MISSING");
    let err =
        busbar_api::resolve_builtin_string(&SecretRef::file(path.to_str().unwrap())).unwrap_err();
    assert!(err.contains("cannot resolve"), "{err}");
}
