// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-core/src/config/secret.rs`.

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

/// A secret whose VALUE is nothing but whitespace is refused exactly as an empty one is — on both
/// built-ins.
///
/// The reference type already settles this for the NAME and the PATH (`self_env_var_checked` /
/// `self_file_path_checked` both `trim`), and the value deserves the same reading for the same
/// reason: `"   "` is what an operator gets from a templating step that produced nothing, a
/// here-doc with an indent, or a mount that wrote a placeholder. Accepting it means booting with a
/// blank credential and finding out at the first upstream call, which is the failure the empty
/// check exists to move to boot.
#[test]
fn a_whitespace_only_secret_is_refused_like_an_empty_one() {
    let var = format!("BUSBAR_SECRET_WS_TEST_{}", std::process::id());
    for blank in ["   ", "\t", "\n", " \r\n "] {
        std::env::set_var(&var, blank);
        let err = resolve_builtin(&SecretRef::env(&var))
            .expect_err(&format!("env value {blank:?} must be refused"));
        assert!(
            err.contains("EMPTY"),
            "a blank env value is refused the same way an empty one is, got: {err}"
        );
    }
    std::env::remove_var(&var);

    let path = std::env::temp_dir().join(format!("busbar-secret-ws-{}.txt", std::process::id()));
    for blank in ["   ", "\t", "\n", " \r\n "] {
        std::fs::write(&path, blank).unwrap();
        let r = SecretRef::file(path.to_string_lossy().into_owned());
        let err =
            resolve_builtin(&r).expect_err(&format!("file content {blank:?} must be refused"));
        assert!(
            err.contains("EMPTY"),
            "a blank file secret is refused the same way an empty one is, got: {err}"
        );
    }
    let _ = std::fs::remove_file(&path);
}

/// An env var whose bytes are not valid Unicode must not be reported as UNSET.
///
/// The two are opposite operator actions. "Unset" says: you did not wire the secret in, go and set
/// it. Not-Unicode says: you DID, and the value arrived mangled — a wrong encoding, a truncated
/// mount, a copy through a tool that mishandled it. Reporting the second as the first sends the
/// operator to set a variable that is already set, which is the one place they will not look.
#[cfg(unix)]
#[test]
fn a_non_unicode_env_value_is_not_reported_as_unset() {
    use std::os::unix::ffi::OsStrExt;
    let var = format!("BUSBAR_SECRET_NONUTF8_{}", std::process::id());
    std::env::set_var(&var, std::ffi::OsStr::from_bytes(&[0x73, 0xff, 0x74]));
    let err = resolve_builtin(&SecretRef::env(&var)).expect_err("non-Unicode is still fail-closed");
    assert!(
        !err.contains("unset"),
        "a variable that IS set must not be reported as unset: {err}"
    );
    assert!(
        err.contains("Unicode") || err.contains("unicode") || err.contains("UTF-8"),
        "the error must say what is actually wrong with the value: {err}"
    );
    std::env::remove_var(&var);
}

/// A `file:` secret is SIZE-CAPPED and must name a REGULAR file.
///
/// Both halves are the same failure seen twice: this path reads whatever the config names, at boot,
/// into memory, with no bound. `{ file: /dev/zero }` is then an out-of-memory kill of the whole
/// node, and `{ file: <fifo> }` is a boot that blocks forever on a reader nobody will ever write
/// to — neither of which looks like a config error to the operator watching it happen. A secret is
/// a credential, not a payload: the cap is far above any real key and still far below anything that
/// can hurt, and a device or a pipe is never where one lives.
#[cfg(unix)]
#[test]
fn a_file_secret_is_size_capped_and_must_be_a_regular_file() {
    // A character device that never ends.
    let zero = SecretRef::file("/dev/zero");
    let err = resolve_builtin(&zero).expect_err("/dev/zero must be refused, not read");
    assert!(
        err.contains("regular file"),
        "a device node is refused for what it is: {err}"
    );

    // A fifo with no writer: refused on its type, so nothing ever blocks on the open.
    let fifo = std::env::temp_dir().join(format!("busbar-secret-fifo-{}", std::process::id()));
    let _ = std::fs::remove_file(&fifo);
    let made = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if made {
        let r = SecretRef::file(fifo.to_string_lossy().into_owned());
        let err = resolve_builtin(&r).expect_err("a fifo must be refused, not opened");
        assert!(
            err.contains("regular file"),
            "a fifo is refused for what it is: {err}"
        );
        let _ = std::fs::remove_file(&fifo);
    }

    // A regular file past the cap.
    let big = std::env::temp_dir().join(format!("busbar-secret-big-{}", std::process::id()));
    std::fs::write(&big, vec![b'k'; 64 * 1024 + 1]).unwrap();
    let r = SecretRef::file(big.to_string_lossy().into_owned());
    let err = resolve_builtin(&r).expect_err("a file past the cap must be refused");
    assert!(
        err.contains("too large"),
        "an oversized secret says so: {err}"
    );

    // And exactly at the cap still resolves — the bound is a bound, not a margin.
    std::fs::write(&big, vec![b'k'; 64 * 1024]).unwrap();
    assert_eq!(resolve_builtin(&r).unwrap().len(), 64 * 1024);
    let _ = std::fs::remove_file(&big);
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
