// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::secret::SecretAxis;
use busbar_contract::secret_ref::{SECRET_MODULE_ENV, SECRET_MODULE_FILE};
use busbar_kernel::config::SecretRef;
use std::sync::atomic::{AtomicU64, Ordering};

pub(super) fn linked_axis() -> &'static crate::root::loader::secret_calls::SecretRows {
    static AXIS: std::sync::OnceLock<crate::root::loader::secret_calls::SecretRows> =
        std::sync::OnceLock::new();
    AXIS.get_or_init(|| {
        let mut rows = crate::root::loader::secret_calls::SecretRows::new(
            crate::root::dispatch::dispatcher,
            super::conns,
        )
        .with_logs(|| crate::root::boot::plugin_logs().clone())
        .with_disk_lane(super::disk_run);
        for door in crate::LINKED.secrets {
            rows.link(*door).expect("the linked secret door states");
        }
        for (door, json) in crate::LINKED.secret_declares {
            rows.declare_linked(*door, json)
                .expect("the linked secret declaration reads");
        }
        rows.with_former_names(busbar_kernel::config::migration_table::former_names)
            .expect("the linked secret names migrate");
        rows
    })
}

#[test]
fn the_linked_source_fixture_is_independent_of_the_boot_registry_rows() {
    let boot = super::secret_rows();
    let before = (boot.linked("env"), boot.linked("file"));
    let axis = linked_axis();
    assert!(axis.linked("env") && axis.linked("file"));
    assert!(!std::ptr::eq(boot, axis));
    assert_eq!((boot.linked("env"), boot.linked("file")), before);
}

fn resolve_linked(secret: &SecretRef) -> Result<Vec<u8>, String> {
    let axis = linked_axis();
    let settings = serde_json::Value::Object(secret.settings.clone()).to_string();
    axis.shared(&secret.module)?
        .resolve_at_config(
            settings.as_bytes(),
            &busbar_contract::config_time::ConfigScope::config_time(),
        )
        .map(|m| m.expose(&busbar_kernel::seal::lend()).clone())
        .map_err(|r| r.text)
}

fn resolve_on_a_request_path(secret: &SecretRef) -> Result<Vec<u8>, String> {
    let axis = linked_axis();
    let settings = serde_json::Value::Object(secret.settings.clone()).to_string();
    axis.shared(&secret.module)?
        .resolve(settings.as_bytes())
        .map(|m| m.expose(&busbar_kernel::seal::lend()).clone())
        .map_err(|r| r.text)
}

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
        module: SECRET_MODULE_ENV.to_string(),
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
        module: SECRET_MODULE_ENV.to_string(),
        settings,
    };
    let err = resolve_linked(&blank).unwrap_err();
    assert!(err.contains("settings.key"), "{err}");
}

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

#[test]
fn resolve_linked_env_whitespace_only_value_resolves_as_1_5_5_did() {
    for blank in ["   ", "\t", "\n\n", " \t\r\n "] {
        let var = unique("ENV_BLANK");
        std::env::set_var(&var, blank);
        let got = resolve_linked(&SecretRef::env(&var)).unwrap_or_else(|e| {
            panic!("whitespace-only value {blank:?} resolves as in 1.5.5: {e}")
        });
        assert_eq!(got, blank.as_bytes(), "its bytes, untrimmed");
        std::env::remove_var(&var);
    }
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
fn resolve_linked_env_mis_encoded_value_refuses_in_1_5_5s_words() {
    use std::os::unix::ffi::OsStrExt;
    let var = unique("ENV_NOT_UNICODE");

    std::env::set_var(&var, std::ffi::OsStr::from_bytes(&[0x73, 0xff, 0x74]));
    let err = resolve_linked(&SecretRef::env(&var))
        .expect_err("a mis-encoded variable cannot resolve to a usable secret");
    assert_eq!(
        err,
        format!("secret env:{var} cannot resolve: environment variable '{var}' is unset"),
        "1.5.5's words"
    );
    std::env::remove_var(&var);
}

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

#[test]
fn resolve_linked_file_past_a_mebibyte_is_read_whole_as_1_5_5_did() {
    let path = temp_path("FILE_OVERSIZE");
    let oversize = vec![b'a'; 1024 * 1024 + 1];
    std::fs::write(&path, &oversize).unwrap();
    let got = resolve_linked(&SecretRef::file(path.to_str().unwrap())).unwrap();
    assert_eq!(got.len(), oversize.len());
    let _ = std::fs::remove_file(&path);
}

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
    let path = temp_path("FILE_MISSING");
    let err = resolve_linked(&SecretRef::file(path.to_str().unwrap())).unwrap_err();
    assert!(err.contains("cannot resolve"), "{err}");
    assert!(
        !err.contains("regular file"),
        "a missing path is absent, not a wrong-file-type problem: {err}"
    );
}

#[test]
fn resolve_linked_file_malformed_settings_is_a_shape_error_not_unknown_module() {
    let malformed = SecretRef {
        module: SECRET_MODULE_FILE.to_string(),
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
        module: SECRET_MODULE_FILE.to_string(),
        settings,
    };
    let err = resolve_linked(&blank).unwrap_err();
    assert!(err.contains("settings.path"), "{err}");
}

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

#[test]
fn resolve_linked_file_whitespace_only_content_resolves_as_1_5_5_did() {
    for blank in [b"   ".to_vec(), b"\n\r\n".to_vec(), b"\t \n".to_vec()] {
        let path = temp_path("FILE_BLANK");
        std::fs::write(&path, &blank).unwrap();
        let got = resolve_linked(&SecretRef::file(path.to_str().unwrap()))
            .unwrap_or_else(|e| panic!("whitespace-only file {blank:?} resolves as in 1.5.5: {e}"));
        assert_eq!(got, blank, "its bytes, untouched");
        let _ = std::fs::remove_file(&path);
    }
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
