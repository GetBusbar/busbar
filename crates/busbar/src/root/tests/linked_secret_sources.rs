// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE LINKED `env` / `file` SECRET SOURCES' OWN BEHAVIOUR, proven where they are linked: the
//! composition root's secret axis ([`super::link_secrets`] over `LINKED.secrets`, on the process's
//! one dispatcher), the rows a shipped build resolves every `{ env: VAR }` / `{ file: PATH }`
//! reference through. Moved here from the kernel's `config/tests/linked_secret_hardening_tests.rs`
//! and `config/tests/secret_tests.rs` (ARCHITECT R-FIX3, 2026-09-26): the kernel's tests now
//! resolve against its in-crate secret double (`busbar_kernel::test_support::secrets`), which
//! reproduces the sources' refusal text for the refusals it makes and nothing more, so every
//! assertion on a source's own decision (fail-closed on empty / blank / missing, the mis-encoding
//! diagnosis, the regular-file and size-cap guards) and on its 1.5.5 refusal words also lives here,
//! unchanged, against the real sources — the pin the double's copied text is held to.
//!
//! [`resolve_linked`] is the kernel resolver's linked branch (`SecretResolver::resolve`: the axis's
//! one shared instance of the module, the settings as their JSON object, the refusal's text
//! verbatim) over the root's axis rather than the kernel's installed one: a test build of this crate
//! links the kernel's test support, whose stand-in axis the kernel reads.

use busbar_contract::secret::SecretAxis;
use busbar_kernel::config::SecretRef;
use std::sync::atomic::{AtomicU64, Ordering};

/// A reference's bytes through the root's linked secret sources.
fn resolve_linked(secret: &SecretRef) -> Result<Vec<u8>, String> {
    let axis = super::link_secrets(crate::LINKED.secrets).expect("the linked secret doors state");
    let settings = serde_json::Value::Object(secret.settings.clone()).to_string();
    axis.shared(&secret.module)?
        .resolve(settings.as_bytes())
        .map(|m| m.expose_secret().clone())
        .map_err(|r| r.text)
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

fn temp_path(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(unique(tag))
}

// ── the `env` source ────────────────────────────────────────────────────────────────────────────

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

/// A whitespace-only (or empty) `env:` NAME — not value — is rejected at the settings-shape layer,
/// in the source's 1.5.5 words, never treated as "look up an env var literally named '   '".
#[test]
fn env_whitespace_only_name_is_rejected() {
    for bad in ["", "   ", "\t\n"] {
        let err = resolve_linked(&SecretRef::env(bad)).expect_err(&format!(
            "whitespace-only env name {bad:?} must be rejected"
        ));
        assert!(
            err.contains("requires settings.key"),
            "whitespace-only env name {bad:?} must fail the settings-shape check, got: {err}"
        );
    }
}

/// A BLANK-but-present env value is not a credential: three spaces handed upstream as a bearer
/// token is the failure this refuses (the kernel's string path trims only `['\r', '\n']`).
#[test]
fn resolve_linked_env_whitespace_only_value_is_fail_closed() {
    for blank in ["   ", "\t", "\n\n", " \t\r\n "] {
        let var = unique("ENV_BLANK");
        std::env::set_var(&var, blank);
        let err = resolve_linked(&SecretRef::env(&var))
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

/// NEGATIVE CONTROL for the blank-value guard: a legitimate credential still resolves, its bytes
/// EXACTLY as stored (a trailing newline is part of a PEM chain; this is the RAW-bytes path).
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

/// A variable that IS SET but holds bytes that are not valid UTF-8 is not reported as "unset": an
/// operator told their variable is unset will set it again, the one action that cannot fix it.
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

/// NEGATIVE CONTROL for the mis-encoding diagnosis: a genuinely absent variable still reports
/// "unset".
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

// ── the `file` source ───────────────────────────────────────────────────────────────────────────

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

/// A `file:` secret over the size cap is refused (fail-closed), never read fully into memory. One
/// byte past the cap is enough to prove the boundary is enforced.
#[test]
fn resolve_linked_file_over_the_size_cap_is_a_bounded_error_not_an_oom() {
    let path = temp_path("FILE_OVERSIZE");
    let oversize = vec![b'a'; 1024 * 1024 + 1];
    std::fs::write(&path, &oversize).unwrap();
    let err = resolve_linked(&SecretRef::file(path.to_str().unwrap())).unwrap_err();
    assert!(err.contains("cannot resolve"), "{err}");
    let _ = std::fs::remove_file(&path);
}

/// The cap is exclusive on the correct side: a file of EXACTLY the limit resolves normally.
#[test]
fn resolve_linked_file_exactly_at_the_size_cap_still_resolves() {
    let path = temp_path("FILE_AT_CAP");
    let exact = vec![b'a'; 1024 * 1024];
    std::fs::write(&path, &exact).unwrap();
    let got = resolve_linked(&SecretRef::file(path.to_str().unwrap())).unwrap();
    assert_eq!(got.len(), 1024 * 1024);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn resolve_linked_file_missing_file_is_an_error() {
    let path = temp_path("FILE_MISSING"); // never created
    let err = resolve_linked(&SecretRef::file(path.to_str().unwrap())).unwrap_err();
    assert!(err.contains("cannot resolve"), "{err}");
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

/// Same guard as [`env_whitespace_only_name_is_rejected`], `file:` PATH side.
#[test]
fn file_whitespace_only_path_is_rejected() {
    for bad in ["", "   ", "\t\n"] {
        let err = resolve_linked(&SecretRef::file(bad)).expect_err(&format!(
            "whitespace-only file path {bad:?} must be rejected"
        ));
        assert!(
            err.contains("requires settings.path"),
            "whitespace-only file path {bad:?} must fail the settings-shape check, got: {err}"
        );
    }
}

/// A path-shaped secret source that is not a regular file is refused, and the refusal says WHICH
/// problem it is (a directory opens on Unix and fails only at read time with a bare errno).
#[test]
fn resolve_linked_file_directory_is_refused_as_not_a_regular_file() {
    let dir = temp_path("FILE_IS_DIR");
    std::fs::create_dir_all(&dir).unwrap();
    let err = resolve_linked(&SecretRef::file(dir.to_str().unwrap()))
        .expect_err("a directory is not a secret file");
    assert!(
        err.contains("regular file"),
        "the refusal must name the real problem — that the path is not a regular file: {err}"
    );
    let _ = std::fs::remove_dir(&dir);
}

/// NEGATIVE CONTROL for the regular-file guard: a SYMLINK to a regular file still resolves
/// (Kubernetes projects every secret as a symlink into a `..data/` directory).
#[cfg(unix)]
#[test]
fn resolve_linked_file_symlink_to_a_regular_file_still_resolves() {
    let target = temp_path("FILE_SYMLINK_TARGET");
    std::fs::write(&target, b"symlinked-secret").unwrap();
    let link = temp_path("FILE_SYMLINK_LINK");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let got = resolve_linked(&SecretRef::file(link.to_str().unwrap()))
        .expect("a symlink to a regular file is how Kubernetes mounts a secret");
    assert_eq!(got, b"symlinked-secret");
    let _ = std::fs::remove_file(&link);
    let _ = std::fs::remove_file(&target);
}

/// NEGATIVE CONTROL: the regular-file guard does not swallow the MISSING-file diagnosis.
#[test]
fn resolve_linked_file_missing_path_still_reports_cannot_resolve() {
    let path = temp_path("FILE_STILL_MISSING"); // never created
    let err = resolve_linked(&SecretRef::file(path.to_str().unwrap())).unwrap_err();
    assert!(err.contains("cannot resolve"), "{err}");
    assert!(
        !err.contains("regular file"),
        "a missing path is absent, not a wrong-file-type problem: {err}"
    );
}

/// The blank-credential rule on the `file:` side: a file holding only whitespace is refused.
#[test]
fn resolve_linked_file_whitespace_only_content_is_fail_closed() {
    for blank in [b"   ".to_vec(), b"\n\r\n".to_vec(), b"\t \n".to_vec()] {
        let path = temp_path("FILE_BLANK");
        std::fs::write(&path, &blank).unwrap();
        let err = resolve_linked(&SecretRef::file(path.to_str().unwrap())).expect_err(&format!(
            "whitespace-only file content {blank:?} must be refused"
        ));
        assert!(
            err.contains("BLANK") || err.contains("blank"),
            "a present-but-blank file is not a credential: {err}"
        );
        let _ = std::fs::remove_file(&path);
    }
}

/// NEGATIVE CONTROL for the file blank guard: surrounding whitespace is kept byte-for-byte, and a
/// BINARY secret that is not UTF-8 at all still resolves (the guard tests all-whitespace bytes).
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
