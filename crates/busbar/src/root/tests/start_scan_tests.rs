// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SECRET-SHORTHAND-BOOT MR-A: process start's scan of `plugins.dir` is loud, a refusal names the
//! file a skipped module came from, and core's own text names no secret word.
//!
//! The process-start cases run the real start (`register_planes`, then the boot reader or
//! `--validate`) in a child process, so the start's process-wide registrations stay the child's.

use std::path::{Path, PathBuf};

use crate::root::test_plugins;

const CHILD: &str = "BUSBAR_START_SCAN_CHILD";
const VALIDATE: &str = "BUSBAR_START_SCAN_VALIDATE";

/// In the child: run process start, then the boot reader or `--validate`. Never returns.
fn child() {
    if std::env::var_os(CHILD).is_some() {
        super::tests::constructor_child(std::env::var(VALIDATE).is_ok_and(|v| v == "1"));
    }
}

/// A scratch deployment: `config.yaml` with `plugins.dir` at `<dir>/plugins` and `body` after it.
fn deployment(tag: &str, body: &str) -> (PathBuf, PathBuf) {
    let dir = test_plugins::scratch(tag);
    let plugins = dir.join("plugins");
    std::fs::create_dir_all(&plugins).unwrap();
    std::fs::write(dir.join("providers.yaml"), "{}\n").unwrap();
    let config = dir.join("config.yaml");
    std::fs::write(
        &config,
        format!(
            "providers: {{}}\nmodels: {{}}\nlisten: 127.0.0.1:0\nadmin_listen: 127.0.0.1:0\n\
             plugins:\n  enabled: true\n  dir: {plugins:?}\n{body}"
        ),
    )
    .unwrap();
    (config, plugins)
}

/// Run `test` as the child over `config`: the serve boot, or `--validate`. Returns whether it
/// exited successfully and everything it printed.
fn start(test: &str, config: &Path, validate: bool) -> (bool, String) {
    let dir = config.parent().unwrap();
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            &format!("root::boot::start_scan_tests::{test}"),
            "--nocapture",
        ])
        .current_dir(dir)
        .env(CHILD, "1")
        .env(VALIDATE, if validate { "1" } else { "0" })
        .env("BUSBAR_CONFIG", config)
        .env("BUSBAR_PROVIDERS", dir.join("providers.yaml"))
        .env("BUSBAR_DATA_DIR", dir.join("state"))
        .output()
        .unwrap();
    let logs = String::from_utf8_lossy(&output.stdout).into_owned()
        + &String::from_utf8_lossy(&output.stderr);
    (output.status.success(), logs)
}

/// An unsigned manifest-only archive of `kind`, named `name`: the scan skips it as unsigned.
fn unsigned(plugins: &Path, kind: &str, name: &str) {
    std::fs::write(
        plugins.join(format!("{name}.tar.gz")),
        test_plugins::pack(kind, name, b"a manifest-only row", "fixture-publisher"),
    )
    .unwrap();
}

/// RA1 (S1, F5): one invalid archive in `plugins.dir` fails the start scan. The refusal names the
/// archive and the scan's error, before any parse: never "shorthand not declared".
#[test]
fn start_scan_failure_is_reported_not_swallowed() {
    child();
    let (config, plugins) = deployment(
        "start-scan-loud",
        "auth:\n  signing_key: {fixture-word: signing}\n",
    );
    std::fs::write(plugins.join("broken.tar.gz"), b"not a plugin archive").unwrap();
    for validate in [false, true] {
        let (ok, logs) = start(
            "start_scan_failure_is_reported_not_swallowed",
            &config,
            validate,
        );
        assert!(!ok, "an invalid archive must refuse: {logs}");
        assert!(
            logs.contains("broken.tar.gz") && logs.contains("plugin validation failed"),
            "the refusal names the invalid archive and the scan's error: {logs}"
        );
        assert!(
            !logs.contains("is a secret shorthand") && !logs.contains("not declared"),
            "the scan's failure surfaces as itself, not as an undeclared word: {logs}"
        );
    }
}

/// RA2 (P1, F8): a plane section whose module the scan skipped is refused naming the file and the
/// fixed reason class, not only as an unknown field.
#[test]
fn skipped_plane_section_refusal_names_the_file() {
    child();
    let (config, plugins) = deployment("start-scan-plane", "fixture-plane: {}\n");
    unsigned(&plugins, "plane", "fixture-plane");
    for validate in [false, true] {
        let (ok, logs) = start(
            "skipped_plane_section_refusal_names_the_file",
            &config,
            validate,
        );
        assert!(!ok, "a skipped plane's section must refuse: {logs}");
        assert!(
            logs.contains("\"fixture-plane.tar.gz\" (kind plane) was not admitted: unsigned"),
            "the refusal names the skipped file and why: {logs}"
        );
    }
}

/// RA3: a secret word whose module the scan skipped is refused naming the file and the reason.
#[test]
fn skipped_secret_word_refusal_names_the_file() {
    child();
    let (config, plugins) = deployment(
        "start-scan-secret",
        "auth:\n  signing_key: {fixture-word: signing}\n",
    );
    unsigned(&plugins, "secret", "fixture-secret");
    for validate in [false, true] {
        let (ok, logs) = start(
            "skipped_secret_word_refusal_names_the_file",
            &config,
            validate,
        );
        assert!(!ok, "an undeclared word must refuse: {logs}");
        assert!(
            logs.contains("\"fixture-secret.tar.gz\" (kind secret) was not admitted: unsigned"),
            "the refusal names the skipped file and why: {logs}"
        );
    }
}

/// RA4 (Console smoke test): the undeclared-shorthand refusal names the word, says it is a secret
/// shorthand, and says what must be installed and admitted. It names no plugin.
#[test]
fn undeclared_shorthand_refusal_names_word_kind_and_remedy() {
    use busbar_contract::secret_ref::{context, SecretRef, Sugars};
    let refused = busbar_contract::yaml::with_deserializer("{fixture-word: signing}\n", |d| {
        context::deserialize::<SecretRef, _>(d, &Sugars::default())
    })
    .expect_err("no admitted secret module declares the word")
    .to_string();
    assert!(
        refused.contains(
            "BUSBAR-3121\u{b7}undeclared: `{fixture-word: \u{2026}}` is a secret shorthand, and \
             no admitted secret module declares `fixture-word`. Install a signed `kind: secret` \
             module that declares `fixture-word` into plugins.dir and admit it (plugins.enabled, \
             plugins.trust), or write the canonical `{ module: <secret module>, settings: { \
             \u{2026} } }` reference. `busbar --list-plugins` shows what was admitted."
        ),
        "{refused}"
    );
    for plugin in ["busbar-secret", "`env`", "`file`"] {
        assert!(!refused.contains(plugin), "names {plugin}: {refused}");
    }
}

/// RA7 (F3): the core texts SECRET-SHORTHAND-BOOT §3.16 lists name no secret word and claim no
/// built-in secret source.
#[test]
fn core_text_names_no_secret_word() {
    use busbar_kernel::diagnostics as d;
    let mut texts = vec![
        d::CONFIG_SECRET_REFERENCE_INVALID.summary,
        d::CONFIG_SECRET_REFERENCE_INVALID.action,
        d::CONFIG_PROVIDER_CREDENTIAL_INVALID.summary,
        d::CONFIG_PROVIDER_CREDENTIAL_INVALID.action,
        busbar_kernel::governance::at_rest::NO_KEY_REFUSAL,
    ];
    for t in d::all_texts() {
        if [
            d::CONFIG_AUTH_CHAIN_INVALID.code,
            d::CONFIG_SECRET_REFERENCE_INVALID.code,
            d::CONFIG_PROVIDER_CREDENTIAL_INVALID.code,
        ]
        .contains(&t.code)
        {
            texts.extend([t.example, t.example_detail]);
        }
    }
    assert_eq!(texts.len(), 11, "every listed text is checked");
    for text in texts {
        for word in ["`env`", "`file`", "env:", "file:", "built-in (`env"] {
            assert!(!text.contains(word), "{word:?} in {text:?}");
        }
    }
}

/// GA5: a historical (1.5.5) `plugins:` block is the startup upgrade's to convert. Process start
/// defers it to the reader, which reports it itself: the start never refuses it.
#[test]
fn historical_plugins_block_still_boots() {
    child();
    let dir = test_plugins::scratch("start-scan-historical");
    std::fs::write(dir.join("providers.yaml"), "{}\n").unwrap();
    let config = dir.join("config.yaml");
    std::fs::write(
        &config,
        format!(
            "providers: {{}}\nmodels: {{}}\nplugins:\n  enabled: true\n  dir: {:?}\n  fetch:\n    \
             - {{ github: Acme/busbar-stub@v1.0.0, sha256: {} }}\n",
            dir.join("plugins"),
            "a".repeat(64)
        ),
    )
    .unwrap();
    let (_, logs) = start("historical_plugins_block_still_boots", &config, true);
    assert!(
        !logs.contains("was refused at process start"),
        "a historical plugins block is deferred to the startup upgrade: {logs}"
    );
}
