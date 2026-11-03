// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

fn resolve_linked(secret: &SecretRef) -> Result<Vec<u8>, String> {
    actual_product_resolver()
        .resolve(secret)
        .map(|held| held.expose(&crate::seal::lend()).clone())
}

fn unique(tag: &str) -> String {
    static CTR: AtomicU64 = AtomicU64::new(0);
    format!(
        "BUSBAR_API_MUTATION_TEST_{tag}_{}_{}",
        std::process::id(),
        CTR.fetch_add(1, Ordering::SeqCst)
    )
}

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
    assert!(err.contains("EMPTY"), "{err}");
    assert!(err.contains(&var), "{err}");
    std::env::remove_var(&var);
}

#[test]
fn resolve_linked_env_unset_variable_is_an_error() {
    let var = unique("ENV_UNSET");
    std::env::remove_var(&var);
    let err = resolve_linked(&SecretRef::env(&var)).unwrap_err();
    assert!(err.contains("unset"), "{err}");
    assert!(err.contains(&var), "{err}");
}

#[test]
fn resolve_linked_env_malformed_settings_is_a_shape_error_not_unknown_module() {
    let malformed = SecretRef {
        module: "env".to_string(),
        settings: serde_json::Map::new(),
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
    assert!(err.contains("EMPTY"), "{err}");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn resolve_linked_file_missing_file_is_an_error() {
    let path = temp_path("FILE_MISSING");
    let err = resolve_linked(&SecretRef::file(path.to_str().unwrap())).unwrap_err();
    assert!(err.contains("cannot resolve"), "{err}");
}

#[test]
fn resolve_linked_file_malformed_settings_is_a_shape_error_not_unknown_module() {
    let malformed = SecretRef {
        module: "file".to_string(),
        settings: serde_json::Map::new(),
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

#[test]
fn resolve_linked_string_trims_trailing_newlines() {
    let var = unique("STR_TRIM");
    std::env::set_var(&var, "top-secret\r\n");
    let got = actual_product_resolver()
        .resolve_string(&SecretRef::env(&var))
        .unwrap();
    assert_eq!(got.expose(&crate::seal::lend()), "top-secret");
    std::env::remove_var(&var);
}

#[test]
fn resolve_linked_string_empty_after_trim_is_fail_closed() {
    let var = unique("STR_EMPTY_AFTER_TRIM");

    std::env::set_var(&var, "\n\r\n");
    let err = actual_product_resolver()
        .resolve_string(&SecretRef::env(&var))
        .unwrap_err();
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
    let err = actual_product_resolver()
        .resolve_string(&SecretRef::file(path.to_str().unwrap()))
        .unwrap_err();
    assert!(err.contains("non-UTF-8"), "{err}");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn resolve_linked_string_propagates_the_underlying_resolve_error() {
    let path = temp_path("STR_MISSING");
    let err = actual_product_resolver()
        .resolve_string(&SecretRef::file(path.to_str().unwrap()))
        .unwrap_err();
    assert!(err.contains("cannot resolve"), "{err}");
}

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

#[cfg(unix)]
#[test]
fn resolve_linked_env_mis_encoded_value_is_not_reported_as_unset() {
    use std::os::unix::ffi::OsStrExt;
    let var = unique("ENV_NOT_UNICODE");

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
