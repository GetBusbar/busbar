// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! MUTATION-HARDENING: the built-in `env`/`file` secret resolvers
//! (`resolve_builtin`/`resolve_builtin_string`) — every fail-closed branch of their happy AND error
//! paths ("env var unset", "file empty", "unknown module", "non-UTF-8 where a text secret is
//! required") gets an explicit assertion.
//!
//! Moved here with the resolvers from `busbar-api`'s own suite when that crate retired; the
//! secret-module contract's half of that suite is the contract's
//! (`crates/busbar-contract/tests/mutation_hardening_secret_contract.rs`). Integration test —
//! public-surface only.

use busbar_contract::secret_ref::SecretRef;
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

// ── `resolve_builtin` — the `env` module ─────────────────────────────────────────────────────────

#[test]
fn resolve_builtin_env_happy_path_reads_the_variable() {
    let var = unique("ENV_HAPPY");
    std::env::set_var(&var, "s3cr3t-value");
    let got = busbar_plugin_loader::builtin_secret::resolve_builtin(&SecretRef::env(&var)).unwrap();
    assert_eq!(got, b"s3cr3t-value");
    std::env::remove_var(&var);
}

#[test]
fn resolve_builtin_env_empty_value_is_fail_closed() {
    let var = unique("ENV_EMPTY");
    std::env::set_var(&var, "");
    let err =
        busbar_plugin_loader::builtin_secret::resolve_builtin(&SecretRef::env(&var)).unwrap_err();
    assert!(err.contains("EMPTY"), "{err}");
    assert!(err.contains(&var), "{err}");
    std::env::remove_var(&var);
}

#[test]
fn resolve_builtin_env_unset_variable_is_an_error() {
    let var = unique("ENV_UNSET");
    std::env::remove_var(&var); // ensure genuinely unset
    let err =
        busbar_plugin_loader::builtin_secret::resolve_builtin(&SecretRef::env(&var)).unwrap_err();
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
    let err = busbar_plugin_loader::builtin_secret::resolve_builtin(&malformed).unwrap_err();
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
    let err = busbar_plugin_loader::builtin_secret::resolve_builtin(&blank).unwrap_err();
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
    let got = busbar_plugin_loader::builtin_secret::resolve_builtin(&SecretRef::file(
        path.to_str().unwrap(),
    ))
    .unwrap();
    assert_eq!(got, b"file-secret-bytes");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn resolve_builtin_file_empty_file_is_fail_closed() {
    let path = temp_path("FILE_EMPTY");
    std::fs::write(&path, b"").unwrap();
    let err = busbar_plugin_loader::builtin_secret::resolve_builtin(&SecretRef::file(
        path.to_str().unwrap(),
    ))
    .unwrap_err();
    assert!(err.contains("EMPTY"), "{err}");
    let _ = std::fs::remove_file(&path);
}

/// A `file:` secret over the size cap is refused (fail-closed), never read fully into memory. One
/// byte past the cap is enough to prove the boundary is enforced without writing (or allocating)
/// anything close to the multi-gigabyte payloads an actual OOM attempt would use.
#[test]
fn resolve_builtin_file_over_the_size_cap_is_a_bounded_error_not_an_oom() {
    let path = temp_path("FILE_OVERSIZE");
    let oversize = vec![b'a'; 1024 * 1024 + 1];
    std::fs::write(&path, &oversize).unwrap();
    let err = busbar_plugin_loader::builtin_secret::resolve_builtin(&SecretRef::file(
        path.to_str().unwrap(),
    ))
    .unwrap_err();
    assert!(err.contains("cannot resolve"), "{err}");
    let _ = std::fs::remove_file(&path);
}

/// The cap is exclusive on the correct side: a file of EXACTLY the limit resolves normally (this is
/// a size cap on the secret, not an off-by-one trap that rejects a legitimate credential sitting
/// right at the boundary).
#[test]
fn resolve_builtin_file_exactly_at_the_size_cap_still_resolves() {
    let path = temp_path("FILE_AT_CAP");
    let exact = vec![b'a'; 1024 * 1024];
    std::fs::write(&path, &exact).unwrap();
    let got = busbar_plugin_loader::builtin_secret::resolve_builtin(&SecretRef::file(
        path.to_str().unwrap(),
    ))
    .unwrap();
    assert_eq!(got.len(), 1024 * 1024);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn resolve_builtin_file_missing_file_is_an_error() {
    let path = temp_path("FILE_MISSING"); // never created
    let err = busbar_plugin_loader::builtin_secret::resolve_builtin(&SecretRef::file(
        path.to_str().unwrap(),
    ))
    .unwrap_err();
    assert!(err.contains("cannot resolve"), "{err}");
}

#[test]
fn resolve_builtin_file_malformed_settings_is_a_shape_error_not_unknown_module() {
    let malformed = SecretRef {
        module: "file".to_string(),
        settings: serde_json::Map::new(), // no `path`
    };
    let err = busbar_plugin_loader::builtin_secret::resolve_builtin(&malformed).unwrap_err();
    assert!(err.contains("settings.path"), "{err}");
    assert!(!err.contains("is not a built-in"), "{err}");
}

#[test]
fn resolve_builtin_file_blank_path_is_also_malformed() {
    let mut settings = serde_json::Map::new();
    settings.insert("path".to_string(), serde_json::Value::String("   ".into()));
    let blank = SecretRef {
        module: "file".to_string(),
        settings,
    };
    let err = busbar_plugin_loader::builtin_secret::resolve_builtin(&blank).unwrap_err();
    assert!(err.contains("settings.path"), "{err}");
}

// ── `resolve_builtin` — unknown module ───────────────────────────────────────────────────────────

#[test]
fn resolve_builtin_unknown_module_is_fail_closed_and_names_the_module() {
    let vault_ref = SecretRef {
        module: "vault".to_string(),
        settings: serde_json::Map::new(),
    };
    let err = busbar_plugin_loader::builtin_secret::resolve_builtin(&vault_ref).unwrap_err();
    assert!(err.contains("vault"), "{err}");
    assert!(err.contains("not a built-in"), "{err}");
}

// ── `resolve_builtin_string` ──────────────────────────────────────────────────────────────────────

#[test]
fn resolve_builtin_string_trims_trailing_newlines() {
    let var = unique("STR_TRIM");
    std::env::set_var(&var, "top-secret\r\n");
    let got = busbar_plugin_loader::builtin_secret::resolve_builtin_string(&SecretRef::env(&var))
        .unwrap();
    assert_eq!(got, "top-secret");
    std::env::remove_var(&var);
}

/// A value that is non-empty bytes but carries no content is fail-closed on the string path.
///
/// The REFUSAL NOW COMES EARLIER than it used to: `resolve_builtin`'s own blank-value guard catches
/// a whitespace-only value before `resolve_builtin_string` ever gets to trim it, so the message is
/// the blank-value one rather than "empty after trimming". The assertion is on the outcome the test
/// is actually about — refused, fail-closed, naming the source — not on which of the two layers
/// said so. `resolve_builtin_string`'s own trim-to-empty check stays as defense in depth: it also
/// guards bytes that did not come from a built-in.
#[test]
fn resolve_builtin_string_empty_after_trim_is_fail_closed() {
    let var = unique("STR_EMPTY_AFTER_TRIM");
    // Non-empty bytes that carry no content.
    std::env::set_var(&var, "\n\r\n");
    let err = busbar_plugin_loader::builtin_secret::resolve_builtin_string(&SecretRef::env(&var))
        .unwrap_err();
    assert!(
        err.contains("empty") || err.contains("BLANK"),
        "a value with no content must be refused fail-closed: {err}"
    );
    assert!(err.contains(&var), "the error must name the source: {err}");
    std::env::remove_var(&var);
}

#[test]
fn resolve_builtin_string_non_utf8_is_an_error() {
    let path = temp_path("STR_NON_UTF8");
    std::fs::write(&path, [0xFF, 0xFE, 0xFD]).unwrap();
    let err = busbar_plugin_loader::builtin_secret::resolve_builtin_string(&SecretRef::file(
        path.to_str().unwrap(),
    ))
    .unwrap_err();
    assert!(err.contains("non-UTF-8"), "{err}");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn resolve_builtin_string_propagates_the_underlying_resolve_error() {
    let path = temp_path("STR_MISSING");
    let err = busbar_plugin_loader::builtin_secret::resolve_builtin_string(&SecretRef::file(
        path.to_str().unwrap(),
    ))
    .unwrap_err();
    assert!(err.contains("cannot resolve"), "{err}");
}

// ── operator-supplied input: blank credentials, mis-encoded variables, non-file paths ───────────

/// A BLANK-but-present env value is not a credential. `!v.is_empty()` accepts `"   "` — three
/// spaces are "non-empty" by that test and nothing downstream recovers: `resolve_builtin_string`
/// trims only `['\r', '\n']`, so a whitespace-only value survives the string path too and is handed
/// to an upstream as a bearer token. The fail-closed posture that refuses an EMPTY secret has to
/// refuse this one for the same reason.
#[test]
fn resolve_builtin_env_whitespace_only_value_is_fail_closed() {
    for blank in ["   ", "\t", "\n\n", " \t\r\n "] {
        let var = unique("ENV_BLANK");
        std::env::set_var(&var, blank);
        let err = busbar_plugin_loader::builtin_secret::resolve_builtin(&SecretRef::env(&var))
            .expect_err(&format!("whitespace-only value {blank:?} must be refused"));
        assert!(err.contains(&var), "the error must name the source: {err}");
        assert!(
            !err.contains("is unset"),
            "a SET-but-blank variable is not 'unset' — that diagnosis sends an operator to set a \
             variable that is already set: {err}"
        );
        std::env::remove_var(&var);
    }
}

/// NEGATIVE CONTROL for the blank-value guard: a legitimate credential must still resolve, and its
/// bytes must come back EXACTLY as stored. The guard rejects values that are entirely whitespace —
/// it must not start trimming real secrets, because a trailing newline is part of the byte string
/// for a PEM chain and `resolve_builtin` is the RAW-bytes path.
#[test]
fn resolve_builtin_env_surrounding_whitespace_is_preserved_not_trimmed() {
    let var = unique("ENV_PADDED");
    std::env::set_var(&var, "  s3cr3t-value\n");
    let got = busbar_plugin_loader::builtin_secret::resolve_builtin(&SecretRef::env(&var)).unwrap();
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
fn resolve_builtin_env_mis_encoded_value_is_not_reported_as_unset() {
    use std::os::unix::ffi::OsStrExt;
    let var = unique("ENV_NOT_UNICODE");
    // Lone 0xFF: valid in an OsString, never valid UTF-8.
    std::env::set_var(&var, std::ffi::OsStr::from_bytes(&[0x73, 0xff, 0x74]));
    let err = busbar_plugin_loader::builtin_secret::resolve_builtin(&SecretRef::env(&var))
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
/// "unset". Splitting the two arms is only a fix if each one keeps its own correct answer — a
/// change that relabelled every failure as an encoding problem would pass the red arm above.
#[test]
fn resolve_builtin_env_genuinely_unset_still_reports_unset() {
    let var = unique("ENV_STILL_UNSET");
    std::env::remove_var(&var);
    let err =
        busbar_plugin_loader::builtin_secret::resolve_builtin(&SecretRef::env(&var)).unwrap_err();
    assert!(
        err.contains("unset"),
        "a truly absent variable is unset: {err}"
    );
    assert!(err.contains(&var), "{err}");
}

/// A path-shaped secret source that is not a regular file is refused, and the refusal says WHICH
/// problem it is. A directory `open()`s successfully on Unix and fails only at read time with a
/// generic errno; a fifo blocks until a writer appears. Neither is a credential, and "cannot
/// resolve: <errno>" does not tell an operator that they pointed at a directory.
#[test]
fn resolve_builtin_file_directory_is_refused_as_not_a_regular_file() {
    let dir = temp_path("FILE_IS_DIR");
    std::fs::create_dir_all(&dir).unwrap();
    let err = busbar_plugin_loader::builtin_secret::resolve_builtin(&SecretRef::file(
        dir.to_str().unwrap(),
    ))
    .expect_err("a directory is not a secret file");
    assert!(
        err.contains("regular file"),
        "the refusal must name the real problem — that the path is not a regular file: {err}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// NEGATIVE CONTROL for the `is_file` guard, and the one that matters operationally: a SYMLINK to a
/// regular file must still resolve. Kubernetes projects every secret as a symlink into a `..data/`
/// directory and Docker swarm does much the same, so an `is_file` check written against
/// `symlink_metadata` (which does NOT follow the link) would refuse the single most common real
/// deployment of a `file:` secret. `Path::is_file` follows links; this pins that it stays that way.
#[cfg(unix)]
#[test]
fn resolve_builtin_file_symlink_to_a_regular_file_still_resolves() {
    let target = temp_path("FILE_SYMLINK_TARGET");
    std::fs::write(&target, b"symlinked-secret").unwrap();
    let link = temp_path("FILE_SYMLINK_LINK");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let got = busbar_plugin_loader::builtin_secret::resolve_builtin(&SecretRef::file(
        link.to_str().unwrap(),
    ))
    .expect("a symlink to a regular file is how Kubernetes mounts a secret");
    assert_eq!(got, b"symlinked-secret");
    let _ = std::fs::remove_file(&link);
    let _ = std::fs::remove_file(&target);
}

/// NEGATIVE CONTROL: the `is_file` guard must not swallow the MISSING-file diagnosis. A path that
/// does not exist is a different operator error from a path that exists and is a directory, and
/// both must stay distinguishable.
#[test]
fn resolve_builtin_file_missing_path_still_reports_cannot_resolve() {
    let path = temp_path("FILE_STILL_MISSING"); // never created
    let err = busbar_plugin_loader::builtin_secret::resolve_builtin(&SecretRef::file(
        path.to_str().unwrap(),
    ))
    .unwrap_err();
    assert!(err.contains("cannot resolve"), "{err}");
    assert!(
        !err.contains("regular file"),
        "a missing path is absent, not a wrong-file-type problem: {err}"
    );
}

/// The SAME blank-credential rule on the `file:` side. `resolve_builtin`'s file branch tests only
/// `!bytes.is_empty()`, so a file holding three spaces resolves as a credential on the RAW-bytes
/// path — fixing this for `env:` alone would be half a fix of one defect, which is the shape of
/// hole this release keeps finding.
#[test]
fn resolve_builtin_file_whitespace_only_content_is_fail_closed() {
    for blank in [b"   ".to_vec(), b"\n\r\n".to_vec(), b"\t \n".to_vec()] {
        let path = temp_path("FILE_BLANK");
        std::fs::write(&path, &blank).unwrap();
        let err = busbar_plugin_loader::builtin_secret::resolve_builtin(&SecretRef::file(
            path.to_str().unwrap(),
        ))
        .expect_err(&format!(
            "whitespace-only file content {blank:?} must be refused"
        ));
        assert!(
            err.contains("BLANK") || err.contains("blank"),
            "a present-but-blank file is not a credential: {err}"
        );
        let _ = std::fs::remove_file(&path);
    }
}

/// NEGATIVE CONTROL for the file blank guard, both arms that could break a real secret:
/// a credential with surrounding whitespace resolves byte-for-byte (a PEM chain's trailing newline
/// is part of the secret), and a BINARY secret that is not UTF-8 at all still resolves — the guard
/// must test for all-whitespace bytes, not "decodes as a blank string".
#[test]
fn resolve_builtin_file_real_content_still_resolves_including_binary() {
    let padded = temp_path("FILE_PADDED");
    std::fs::write(&padded, b"  pem-body\n").unwrap();
    let got = busbar_plugin_loader::builtin_secret::resolve_builtin(&SecretRef::file(
        padded.to_str().unwrap(),
    ))
    .unwrap();
    assert_eq!(got, b"  pem-body\n", "a real credential is never trimmed");
    let _ = std::fs::remove_file(&padded);

    let binary = temp_path("FILE_BINARY");
    std::fs::write(&binary, [0x00u8, 0xFF, 0x10, 0x80]).unwrap();
    let got = busbar_plugin_loader::builtin_secret::resolve_builtin(&SecretRef::file(
        binary.to_str().unwrap(),
    ))
    .expect("a binary (non-UTF-8) secret is legitimate on the raw-bytes path");
    assert_eq!(got, vec![0x00u8, 0xFF, 0x10, 0x80]);
    let _ = std::fs::remove_file(&binary);
}
