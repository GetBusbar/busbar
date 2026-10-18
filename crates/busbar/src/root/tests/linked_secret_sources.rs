// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE LINKED `env` / `file` SECRET SOURCES' OWN BEHAVIOUR, proven where they are linked: the
//! composition root's secret axis ([`super::link_secrets`] over `LINKED.secrets`, on the process's
//! one dispatcher), the rows a shipped build resolves every `{ env: VAR }` / `{ file: PATH }`
//! reference through. Moved here from the kernel's `config/tests/linked_secret_hardening_tests.rs`
//! and `config/tests/secret_tests.rs` (ARCHITECT R-FIX3, 2026-09-26): the kernel's tests now
//! resolve against its in-crate secret double (`busbar_kernel::test_support::secrets`), which
//! reproduces the sources' refusal text for the refusals it makes and nothing more, so every
//! assertion on a source's own decision (fail-closed on empty / missing, a blank value resolving
//! and a mis-encoded one read as unset as in 1.5.5, the regular-file guard) and on its 1.5.5
//! refusal words also lives here,
//! unchanged, against the real sources — the pin the double's copied text is held to.
//!
//! [`resolve_linked`] is the kernel resolver's linked branch at CONFIG TIME
//! (`SecretResolver::resolve_at_config`: the axis's one shared instance of the module, the settings
//! as their JSON object, the config-time proof, the refusal's text verbatim) over the root's axis
//! rather than the kernel's installed one: a test build of this crate links the kernel's test
//! support, whose stand-in axis the kernel reads. Every resolve a shipped build makes of these
//! sources is a config-time one (boot, a config apply, a refresh; BUSBAR-1.6.0.md l.1464-1469, R4);
//! [`resolve_on_a_request_path`] is the form a request path would take, which a disk-reading source
//! refuses.

use busbar_contract::secret::SecretAxis;
use busbar_contract::secret_ref::{SECRET_MODULE_ENV, SECRET_MODULE_FILE};
use busbar_kernel::config::SecretRef;
use std::sync::atomic::{AtomicU64, Ordering};

/// A reference's bytes through the root's linked secret sources, at config time (with the proof).
fn resolve_linked(secret: &SecretRef) -> Result<Vec<u8>, String> {
    let axis = super::link_secrets(crate::LINKED.secrets, crate::LINKED.secret_declares)
        .expect("the linked secret doors state");
    let settings = serde_json::Value::Object(secret.settings.clone()).to_string();
    axis.shared(&secret.module)?
        .resolve_at_config(
            settings.as_bytes(),
            &busbar_contract::config_time::ConfigScope::config_time(),
        )
        .map(|m| m.expose(&busbar_kernel::seal::lend()).clone())
        .map_err(|r| r.text)
}

/// A reference's bytes through the root's linked secret sources as a request path would ask: with
/// no config-time proof.
fn resolve_on_a_request_path(secret: &SecretRef) -> Result<Vec<u8>, String> {
    let axis = super::link_secrets(crate::LINKED.secrets, crate::LINKED.secret_declares)
        .expect("the linked secret doors state");
    let settings = serde_json::Value::Object(secret.settings.clone()).to_string();
    axis.shared(&secret.module)?
        .resolve(settings.as_bytes())
        .map(|m| m.expose(&busbar_kernel::seal::lend()).clone())
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
        module: SECRET_MODULE_ENV.to_string(),
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
        module: SECRET_MODULE_ENV.to_string(),
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

/// AS 1.5.5 (`crates/busbar/src/config/secret.rs` `resolve_builtin`, l.255-263): a SET variable
/// whose value is whitespace only RESOLVES, its bytes untouched; 1.5.5 refused only an EMPTY value.
/// Refusing a blank one is a behaviour difference no owner has signed (THE DESIGN §2: the default
/// is 1.5.5's behaviour), so this pins 1.5.5's outcome.
#[test]
fn resolve_linked_env_whitespace_only_value_resolves_as_in_1_5_5() {
    for blank in ["   ", "\t", "\n\n", " \t\r\n "] {
        let var = unique("ENV_BLANK");
        std::env::set_var(&var, blank);
        let got = resolve_linked(&SecretRef::env(&var)).unwrap_or_else(|e| {
            panic!("whitespace-only value {blank:?} resolves, as in 1.5.5: {e}")
        });
        assert_eq!(got, blank.as_bytes(), "untouched");
        std::env::remove_var(&var);
    }
}

/// A credential resolves with its bytes EXACTLY as stored (a trailing newline is part of a PEM chain; this is the RAW-bytes path).
#[test]
fn resolve_linked_env_surrounding_whitespace_is_preserved_not_trimmed() {
    let var = unique("ENV_PADDED");
    std::env::set_var(&var, "  s3cr3t-value\n");
    let got = resolve_linked(&SecretRef::env(&var)).unwrap();
    assert_eq!(
        got, b"  s3cr3t-value\n",
        "a real credential resolves byte-for-byte, never trimmed"
    );
    std::env::remove_var(&var);
}

/// AS 1.5.5: a variable that is SET but holds bytes that are not valid UTF-8 is refused with
/// 1.5.5's own sentence, "is unset" (`std::env::var`'s one error covers both, and 1.5.5 rendered
/// it so). Naming the encoding instead is a behaviour difference no owner has signed.
#[cfg(unix)]
#[test]
fn resolve_linked_env_mis_encoded_value_is_refused_as_unset_as_in_1_5_5() {
    use std::os::unix::ffi::OsStrExt;
    let var = unique("ENV_NOT_UNICODE");
    // Lone 0xFF: valid in an OsString, never valid UTF-8.
    std::env::set_var(&var, std::ffi::OsStr::from_bytes(&[0x73, 0xff, 0x74]));
    let err = resolve_linked(&SecretRef::env(&var))
        .expect_err("a mis-encoded variable cannot resolve to a usable secret");
    assert!(
        err.contains(&format!(
            "secret env:{var} cannot resolve: environment variable '{var}' is unset"
        )),
        "1.5.5's sentence: {err}"
    );
    std::env::remove_var(&var);
}

/// A genuinely absent variable reports "unset", 1.5.5's sentence.
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

/// R4 (BUSBAR-1.6.0.md l.1464-1469, OWNER 2026-10-13): the secret kind's file source reads the disk
/// only at config time (boot, a config apply, a refresh), on the host's disk lane, and is never
/// reachable from a request path. A resolve WITHOUT the config-time proof (the request-path form)
/// is refused with the contract's own sentence before anything is read: the file below exists and
/// is readable, and the refusal must not carry its bytes. With the proof, the same reference reads.
/// RED ARM: the linked file source declares no disk need, so the request-path form opens the file.
#[test]
fn a_request_path_resolve_of_the_file_source_reads_nothing() {
    let path = temp_path("FILE_REQUEST_PATH");
    std::fs::write(&path, b"never-read-on-a-request-path").unwrap();
    let reference = SecretRef::file(path.to_str().unwrap());
    let refused =
        resolve_on_a_request_path(&reference).expect_err("a request-path resolve is refused");
    assert!(
        refused.contains(busbar_contract::config_time::RESOLVE_OFF_CONFIG_TIME),
        "{refused}"
    );
    assert!(
        !refused.contains("never-read-on-a-request-path"),
        "{refused}"
    );
    let at_config = resolve_linked(&reference);
    assert_eq!(
        at_config.as_deref(),
        Ok(&b"never-read-on-a-request-path"[..])
    );
    let _ = std::fs::remove_file(&path);
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

/// PARITY WITH 1.5.5 (audit pinned secret-file #2): 1.5.5 read a `file:` secret whole
/// (`std::fs::read`), so a file of several MiB (a large PEM bundle) resolves byte for byte, never
/// refused for its size (THE DESIGN §2: "the default is 1.5.5's behaviour").
#[test]
fn resolve_linked_file_larger_than_a_mebibyte_resolves_whole_as_in_1_5_5() {
    let path = temp_path("FILE_LARGE");
    let large: Vec<u8> = (0..3 * 1024 * 1024 + 7)
        .map(|i| b'a' + (i % 26) as u8)
        .collect();
    std::fs::write(&path, &large).unwrap();
    let got = resolve_linked(&SecretRef::file(path.to_str().unwrap())).unwrap();
    assert_eq!(got, large);
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
        module: SECRET_MODULE_FILE.to_string(),
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
        module: SECRET_MODULE_FILE.to_string(),
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
        .expect_err("a directory is not a readable secret");
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

/// AS 1.5.5 on the `file:` side: a file holding only whitespace RESOLVES, its bytes untouched;
/// 1.5.5 refused only an EMPTY file.
#[test]
fn resolve_linked_file_whitespace_only_content_resolves_as_in_1_5_5() {
    for blank in [b"   ".to_vec(), b"\n\r\n".to_vec(), b"\t \n".to_vec()] {
        let path = temp_path("FILE_BLANK");
        std::fs::write(&path, &blank).unwrap();
        let got = resolve_linked(&SecretRef::file(path.to_str().unwrap())).unwrap_or_else(|e| {
            panic!("whitespace-only file content {blank:?} resolves, as in 1.5.5: {e}")
        });
        assert_eq!(got, blank, "untouched");
        let _ = std::fs::remove_file(&path);
    }
}

/// A file secret keeps its surrounding whitespace byte-for-byte, and a BINARY secret that is not
/// UTF-8 at all resolves.
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
