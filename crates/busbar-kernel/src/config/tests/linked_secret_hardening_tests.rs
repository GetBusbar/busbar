// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! MUTATION-HARDENING: the kernel's linked secret path (`resolve_linked`/`resolve_linked_string`,
//! through the root rows' secret axis) — every fail-closed branch of its happy AND error paths
//! ("env var unset", "file empty", "unknown module", "non-UTF-8 where a text secret is required")
//! gets an explicit assertion. A kernel test build answers the axis with the in-crate secret double
//! (`test_support::secrets`, ARCHITECT R-FIX3), so a refusal asserted here is the double's, passed
//! through verbatim; the shipped `env` / `file` sources' own rules (the blank, regular-file and
//! size-cap guards) and words are proven where they are linked, at the composition root
//! (`crates/busbar/src/root/tests/linked_secret_sources.rs`). The secret-module contract's half of
//! that suite is the contract's (`crates/busbar-contract/tests/mutation_hardening_secret_contract.rs`).

use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

/// A reference's bytes through the linked secret plugins alone.
fn resolve_linked(secret: &SecretRef) -> Result<Vec<u8>, String> {
    SecretResolver::builtins_only().resolve(secret)
}

/// A process-lifetime-unique suffix so parallel test threads never pick the same env var name.
fn unique(tag: &str) -> String {
    static CTR: AtomicU64 = AtomicU64::new(0);
    format!(
        "BUSBAR_API_MUTATION_TEST_{tag}_{}_{}",
        std::process::id(),
        CTR.fetch_add(1, Ordering::SeqCst)
    )
}

// ── `resolve_linked` — the `env` module ─────────────────────────────────────────────────────────

#[test]
fn resolve_linked_env_happy_path_reads_the_variable() {
    let var = unique("ENV_HAPPY");
    std::env::set_var(&var, "s3cr3t-value");
    let got = resolve_linked(&SecretRef::env(&var)).unwrap();
    assert_eq!(got, b"s3cr3t-value");
    std::env::remove_var(&var);
}

#[test]
fn resolve_linked_env_empty_value_is_fail_closed() {
    let var = unique("ENV_EMPTY");
    std::env::set_var(&var, "");
    let err = resolve_linked(&SecretRef::env(&var)).unwrap_err();
    assert!(err.contains("is empty"), "{err}");
    assert!(err.contains(&var), "{err}");
    std::env::remove_var(&var);
}

#[test]
fn resolve_linked_env_unset_variable_is_an_error() {
    let var = unique("ENV_UNSET");
    std::env::remove_var(&var); // ensure genuinely unset
    let err = resolve_linked(&SecretRef::env(&var)).unwrap_err();
    assert!(err.contains("unset"), "{err}");
    assert!(err.contains(&var), "{err}");
}

/// A malformed `env`-module reference (module name matches but the settings shape does not carry a
/// usable `key`) must fail LOUD with a shape-specific message — never silently fall through to the
/// generic "not a built-in" refusal (which would misreport the actual problem).
#[test]
fn resolve_linked_env_malformed_settings_is_a_shape_error_not_unknown_module() {
    let malformed = SecretRef {
        module: "env".to_string(),
        settings: serde_json::Map::new(), // no `key`
    };
    let err = resolve_linked(&malformed).unwrap_err();
    assert!(err.contains("settings.key"), "{err}");
    assert!(
        !err.contains("is not a built-in"),
        "a malformed env ref must not be misreported as an unknown module: {err}"
    );
}

#[test]
fn resolve_linked_env_blank_key_is_also_malformed() {
    let mut settings = serde_json::Map::new();
    settings.insert("key".to_string(), serde_json::Value::String("   ".into()));
    let blank = SecretRef {
        module: "env".to_string(),
        settings,
    };
    let err = resolve_linked(&blank).unwrap_err();
    assert!(err.contains("settings.key"), "{err}");
}

// ── `resolve_linked` — the `file` module ────────────────────────────────────────────────────────

fn temp_path(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(unique(tag))
}

#[test]
fn resolve_linked_file_happy_path_reads_the_file() {
    let path = temp_path("FILE_HAPPY");
    std::fs::write(&path, b"file-secret-bytes").unwrap();
    let got = resolve_linked(&SecretRef::file(path.to_str().unwrap())).unwrap();
    assert_eq!(got, b"file-secret-bytes");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn resolve_linked_file_empty_file_is_fail_closed() {
    let path = temp_path("FILE_EMPTY");
    std::fs::write(&path, b"").unwrap();
    let err = resolve_linked(&SecretRef::file(path.to_str().unwrap())).unwrap_err();
    assert!(err.contains("is empty"), "{err}");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn resolve_linked_file_missing_file_is_an_error() {
    let path = temp_path("FILE_MISSING"); // never created
    let err = resolve_linked(&SecretRef::file(path.to_str().unwrap())).unwrap_err();
    assert!(err.contains("unreadable"), "{err}");
}

#[test]
fn resolve_linked_file_malformed_settings_is_a_shape_error_not_unknown_module() {
    let malformed = SecretRef {
        module: "file".to_string(),
        settings: serde_json::Map::new(), // no `path`
    };
    let err = resolve_linked(&malformed).unwrap_err();
    assert!(err.contains("settings.path"), "{err}");
    assert!(!err.contains("is not a built-in"), "{err}");
}

#[test]
fn resolve_linked_file_blank_path_is_also_malformed() {
    let mut settings = serde_json::Map::new();
    settings.insert("path".to_string(), serde_json::Value::String("   ".into()));
    let blank = SecretRef {
        module: "file".to_string(),
        settings,
    };
    let err = resolve_linked(&blank).unwrap_err();
    assert!(err.contains("settings.path"), "{err}");
}

// ── `resolve_linked` — unknown module ───────────────────────────────────────────────────────────

#[test]
fn resolve_linked_unknown_module_is_fail_closed_and_names_the_module() {
    let vault_ref = SecretRef {
        module: "vault".to_string(),
        settings: serde_json::Map::new(),
    };
    let err = resolve_linked(&vault_ref).unwrap_err();
    assert!(err.contains("vault"), "{err}");
    assert!(err.contains("not a built-in"), "{err}");
}

// ── `resolve_linked_string` ──────────────────────────────────────────────────────────────────────

#[test]
fn resolve_linked_string_trims_trailing_newlines() {
    let var = unique("STR_TRIM");
    std::env::set_var(&var, "top-secret\r\n");
    let got = resolve_linked_string(&SecretRef::env(&var)).unwrap();
    assert_eq!(got, "top-secret");
    std::env::remove_var(&var);
}

/// A value that is non-empty bytes but carries no content is fail-closed on the string path.
///
/// The secret double has no blank rule, so the bytes reach `resolve_linked_string`'s own
/// trim-to-empty check, which refuses them ("empty after trimming"); the shipped `env` source
/// refuses a whitespace-only value one layer earlier (proven at the root). The assertion is on the
/// outcome the test is about — refused, fail-closed, naming the source — not on which layer said
/// so.
#[test]
fn resolve_linked_string_empty_after_trim_is_fail_closed() {
    let var = unique("STR_EMPTY_AFTER_TRIM");
    // Non-empty bytes that carry no content.
    std::env::set_var(&var, "\n\r\n");
    let err = resolve_linked_string(&SecretRef::env(&var)).unwrap_err();
    assert!(
        err.contains("empty") || err.contains("BLANK"),
        "a value with no content must be refused fail-closed: {err}"
    );
    assert!(err.contains(&var), "the error must name the source: {err}");
    std::env::remove_var(&var);
}

#[test]
fn resolve_linked_string_non_utf8_is_an_error() {
    let path = temp_path("STR_NON_UTF8");
    std::fs::write(&path, [0xFF, 0xFE, 0xFD]).unwrap();
    let err = resolve_linked_string(&SecretRef::file(path.to_str().unwrap())).unwrap_err();
    assert!(err.contains("non-UTF-8"), "{err}");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn resolve_linked_string_propagates_the_underlying_resolve_error() {
    let path = temp_path("STR_MISSING");
    let err = resolve_linked_string(&SecretRef::file(path.to_str().unwrap())).unwrap_err();
    assert!(err.contains("unreadable"), "{err}");
}

// ── operator-supplied input: padded and binary credentials, mis-encoded variables ──────────────

/// A legitimate credential resolves with its bytes EXACTLY as the module returned them: the kernel
/// never trims on the raw path, because a trailing newline is part of the byte string for a PEM
/// chain and `resolve_linked` is the RAW-bytes path.
#[test]
fn resolve_linked_env_surrounding_whitespace_is_preserved_not_trimmed() {
    let var = unique("ENV_PADDED");
    std::env::set_var(&var, "  s3cr3t-value\n");
    let got = resolve_linked(&SecretRef::env(&var)).unwrap();
    assert_eq!(
        got, b"  s3cr3t-value\n",
        "a real credential resolves byte-for-byte; the blank guard must not trim it"
    );
    std::env::remove_var(&var);
}

/// A variable that IS SET but holds bytes that are not valid UTF-8 must not be reported as "unset".
///
/// `std::env::var` returns `Err` for BOTH `NotPresent` and `NotUnicode`, and a catch-all `Err(_)`
/// arm collapses them into one message. That is a wrong diagnosis, not merely a missing one: an
/// operator told their variable is "unset" will set it again — the one action that cannot fix a
/// variable whose value is already there and mis-encoded.
#[cfg(unix)]
#[test]
fn resolve_linked_env_mis_encoded_value_is_not_reported_as_unset() {
    use std::os::unix::ffi::OsStrExt;
    let var = unique("ENV_NOT_UNICODE");
    // Lone 0xFF: valid in an OsString, never valid UTF-8.
    std::env::set_var(&var, std::ffi::OsStr::from_bytes(&[0x73, 0xff, 0x74]));
    let err = resolve_linked(&SecretRef::env(&var))
        .expect_err("a mis-encoded variable cannot resolve to a usable secret");
    assert!(err.contains(&var), "the error must name the source: {err}");
    assert!(
        !err.contains("is unset"),
        "a SET but mis-encoded variable is NOT unset — telling an operator to set it again sends \
         them at the wrong fix: {err}"
    );
    assert!(
        err.contains("UTF-8") || err.contains("encod"),
        "the error must say what is actually wrong (the encoding), not just that it failed: {err}"
    );
    std::env::remove_var(&var);
}

/// NEGATIVE CONTROL for the mis-encoding diagnosis: a genuinely absent variable must STILL report
/// "unset" — a path that relabelled every failure as an encoding problem would pass the arm above.
#[test]
fn resolve_linked_env_genuinely_unset_still_reports_unset() {
    let var = unique("ENV_STILL_UNSET");
    std::env::remove_var(&var);
    let err = resolve_linked(&SecretRef::env(&var)).unwrap_err();
    assert!(
        err.contains("unset"),
        "a truly absent variable is unset: {err}"
    );
    assert!(err.contains(&var), "{err}");
}

/// Both shapes of a real secret the raw path must not damage: a credential with surrounding
/// whitespace resolves byte-for-byte (a PEM chain's trailing newline is part of the secret), and a
/// BINARY secret that is not UTF-8 at all still resolves — only the string path asks for UTF-8.
#[test]
fn resolve_linked_file_real_content_still_resolves_including_binary() {
    let padded = temp_path("FILE_PADDED");
    std::fs::write(&padded, b"  pem-body\n").unwrap();
    let got = resolve_linked(&SecretRef::file(padded.to_str().unwrap())).unwrap();
    assert_eq!(got, b"  pem-body\n", "a real credential is never trimmed");
    let _ = std::fs::remove_file(&padded);

    let binary = temp_path("FILE_BINARY");
    std::fs::write(&binary, [0x00u8, 0xFF, 0x10, 0x80]).unwrap();
    let got = resolve_linked(&SecretRef::file(binary.to_str().unwrap()))
        .expect("a binary (non-UTF-8) secret is legitimate on the raw-bytes path");
    assert_eq!(got, vec![0x00u8, 0xFF, 0x10, 0x80]);
    let _ = std::fs::remove_file(&binary);
}
