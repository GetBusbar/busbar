// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! END-TO-END CLI regression tests for `busbar --validate` and `busbar --list-plugins`, driving the
//! REAL binary (`CARGO_BIN_EXE_busbar`) against generated config + plugin-tarball fixtures. These
//! pin the three hard 1.5.0 acceptance properties at the outermost surface:
//!
//! 1. FAIL-CLOSED: a bad config.yaml or ANY bad/conflicting plugin manifest exits 1 with a loud,
//!    named error (never a partial success).
//! 2. `--validate` validates EVERYTHING (config + every plugin manifest + store resolution) with
//!    zero side effects and matches boot behavior (it runs the same shared preflight).
//! 3. `--list-plugins` is a MANIFEST-ONLY inventory: correct per-plugin status, and it must
//!    succeed (exit 0) even over a directory of untrusted/invalid artifacts, proving nothing is
//!    loaded from listing.
//!
//! Each test gets an isolated temp workspace (its own config/providers/plugins), so no test shares
//! or mutates process-global state.

mod common;

#[cfg(all(unix, linked_section_pools))]
#[test]
fn the_production_pgo_trainer_configuration_validates() {
    let dir = fixture_dir("pgo-trainer");
    let generator =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/pgo-config.sh");
    let generated = std::process::Command::new("bash")
        .args([
            "-eu",
            "-c",
            ". \"$1\"; write_run_configs 18080 18000",
            "pgo-config",
        ])
        .arg(generator)
        .env("WORK", &dir)
        .output()
        .expect("generate the production trainer configuration");
    assert!(
        generated.status.success(),
        "{}",
        String::from_utf8_lossy(&generated.stderr)
    );
    let validated = std::process::Command::new(env!("CARGO_BIN_EXE_busbar"))
        .arg("--validate")
        .env("BUSBAR_CONFIG", dir.join("config.yaml"))
        .env("BUSBAR_PROVIDERS", dir.join("providers.yaml"))
        .env("PGO_MOCK_KEY", "pgo-test-upstream")
        .env("PGO_ADMIN_TOKEN", "pgo-test-admin")
        .env(
            "PGO_SIGNING_KEY",
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .output()
        .expect("validate the trainer with the assembled product");
    assert!(
        validated.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&validated.stdout),
        String::from_utf8_lossy(&validated.stderr)
    );
    std::fs::remove_dir_all(dir).expect("remove the trainer fixture");
}

use common::plugins;
use std::path::{Path, PathBuf};
use std::process::Command;

fn fixture_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "busbar-cli-validate-{}-{tag}-{}",
        std::process::id(),
        {
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            format!(
                "{}-{}-{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_nanos()),
                line!(),
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            )
        }
    ));
    std::fs::create_dir_all(d.join("plugins")).unwrap();
    d
}

fn store_unless_written(extra: &str) -> &'static str {
    if extra.lines().any(|l| l.starts_with("store:")) {
        ""
    } else {
        "store: {module: memory}\n"
    }
}

fn write_configs(dir: &Path, extra: &str) {
    std::fs::write(
        dir.join("providers.yaml"),
        r#"mock:
  protocol: anthropic
  base_url: "http://127.0.0.1:9"
"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("config.yaml"),
        format!(
            r#"listen: "127.0.0.1:0"
providers:
  mock:
    api_key: {{ env: MOCK_KEY }}
models:
  test-model:
    provider: mock
{}{extra}"#,
            store_unless_written(extra)
        ),
    )
    .unwrap();
}

#[cfg(linked_section_tools)]
fn write_tools_only_configs(dir: &Path, extra: &str) {
    std::fs::write(dir.join("providers.yaml"), "").unwrap();
    let catalog = if cfg!(linked_section_pools) {
        "providers: {}\nmodels: {}\n"
    } else {
        ""
    };
    std::fs::write(
        dir.join("config.yaml"),
        format!(
            "listen: \"127.0.0.1:0\"\n{catalog}{}{extra}",
            store_unless_written(extra)
        ),
    )
    .unwrap();
}

const UNSET_INTERPOLATION_VAR: &str = "BUSBAR_CLI_VALIDATE_TEST_UNSET_VAR";

fn command(dir: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_busbar"));
    command
        .env_remove(UNSET_INTERPOLATION_VAR)
        .env("MOCK_KEY", "test-key-value")
        .env(
            "BUSBAR_SIGNING_KEY",
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .env("BUSBAR_CONFIG", dir.join("config.yaml"))
        .env("BUSBAR_PROVIDERS", dir.join("providers.yaml"));
    command
}

fn run_busbar(dir: &Path, args: &[&str]) -> (i32, String, String) {
    let out = command(dir).args(args).output().expect("run busbar");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn safe_mode_as_the_first_flag_proceeds_to_the_requested_configuration() {
    let dir = fixture_dir("safe-first-missing");
    let (code, _, error) = run_busbar(&dir, &["--safe-mode"]);
    assert_eq!(
        code, 1,
        "must reach missing configuration, not usage refusal: {error}"
    );
    assert!(!error.contains("unrecognized argument"), "{error}");
    assert!(error.contains("config.yaml"), "{error}");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_missing_config_or_provider_flag_value_is_a_usage_error_before_boot() {
    let dir = fixture_dir("missing-flag-value");
    for args in [
        vec!["--config"],
        vec!["-c"],
        vec!["--providers"],
        vec!["--validate", "--config"],
        vec!["--safe-mode", "--providers"],
        vec!["--migrate-config", "legacy.yaml", "--providers"],
    ] {
        let (code, _, error) = run_busbar(&dir, &args);
        assert_eq!(code, 2, "{args:?}: {error}");
        assert!(error.contains("requires a value"), "{args:?}: {error}");
    }
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn commands_after_boot_options_exit_without_starting_the_gateway() {
    use std::process::Stdio;
    use std::time::Duration;

    let dir = fixture_dir("trailing-command");
    let config = dir.join("config.yaml");
    let providers = dir.join("providers.yaml");
    let catalog = if cfg!(linked_section_pools) {
        "providers: {}\nmodels: {}\n"
    } else {
        ""
    };
    std::fs::write(
        &config,
        format!("listen: '127.0.0.1:0'\nstore: {{module: memory}}\n{catalog}"),
    )
    .unwrap();
    std::fs::write(&providers, "").unwrap();
    for options in [
        vec!["-c".to_owned(), config.display().to_string()],
        vec!["--safe-mode".to_owned()],
        vec![
            "--providers".to_owned(),
            providers.display().to_string(),
            "--safe-mode".to_owned(),
        ],
        vec![
            format!("--config={}", config.display()),
            format!("--providers={}", providers.display()),
        ],
    ] {
        let mut child = command(&dir)
            .args(&options)
            .arg("--validate")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let result = common::lines::try_wait_bounded(&mut child, Duration::from_secs(10));
        let output = child.wait_with_output().unwrap();
        assert_eq!(
            result,
            Ok(0),
            "{options:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("ok: config valid"));
    }

    std::fs::remove_file(&config).unwrap();
    let missing = command(&dir)
        .current_dir(&dir)
        .args(["--config", "--version"])
        .output()
        .unwrap();
    assert_eq!(missing.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&missing.stderr).contains("--version"));
    assert!(!String::from_utf8_lossy(&missing.stdout).starts_with("busbar "));
    let (code, output, error) = run_busbar(&dir, &["--config", "--version", "--version"]);
    assert_eq!(code, 0, "{error}");
    assert!(output.starts_with("busbar "));

    let legacy = dir.join("legacy.yaml");
    std::fs::write(&legacy, "listen: '127.0.0.1:0'\nstore: {module: memory}\n").unwrap();
    let mut child = command(&dir)
        .args(["--safe-mode", "--migrate-config"])
        .arg(&legacy)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let result = common::lines::try_wait_bounded(&mut child, Duration::from_secs(10));
    let output = child.wait_with_output().unwrap();
    assert_eq!(
        result,
        Ok(0),
        "migration operand was lost: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    for filename in ["--config", "--providers", "-c"] {
        std::fs::copy(&legacy, dir.join(filename)).unwrap();
        let mut child = command(&dir)
            .current_dir(&dir)
            .args(["--migrate-config", filename])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let result = common::lines::try_wait_bounded(&mut child, Duration::from_secs(10));
        let output = child.wait_with_output().unwrap();
        assert_eq!(
            result,
            Ok(0),
            "literal migration path {filename}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let _ = std::fs::remove_dir_all(dir);
}

fn write_tarball(dir: &Path, file: &str, name: &str, alias: &str, lib: &[u8]) {
    let mut m = plugins::manifest("store", name, "acme");
    m.alias = alias.into();
    std::fs::write(dir.join("plugins").join(file), plugins::seal(m, lib)).unwrap();
}

fn plugins_block(dir: &Path, enabled: bool, allow_unsigned: bool) -> String {
    format!(
        "plugins:\n  enabled: {enabled}\n  dir: '{}'\n  trust:\n    allow_unsigned: {allow_unsigned}\n",
        dir.join("plugins").display()
    )
}

#[cfg(linked_section_pools)]
#[test]
fn validate_ok_on_valid_config_without_plugins() {
    let dir = fixture_dir("ok");
    write_configs(&dir, "");
    let (code, stdout, stderr) = run_busbar(&dir, &["--validate"]);
    assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");
    assert!(stdout.contains("ok: config valid"), "got {stdout}");
    assert!(stdout.contains("plugins:   disabled"), "got {stdout}");
    assert!(
        !stdout.contains("note:") && !stdout.contains("env var(s)"),
        "no config value here uses ${{VAR}} interpolation, so there must be no unset-env-var \
         note: got {stdout}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(linked_section_pools)]
#[test]
fn print_metadata_blocklist_prints_builtin_plus_blocked() {
    let dir = fixture_dir("print-blocklist");
    write_configs(
        &dir,
        "security:\n  blocked_metadata_hosts: [\"internal-metadata.example\"]\n",
    );
    let (code, stdout, stderr) = run_busbar(&dir, &["--print-metadata-blocklist"]);
    assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");
    let printed: Vec<&str> = stdout.lines().collect();
    assert_eq!(
        printed,
        vec![
            "169.254.0.0/16",
            "100.100.100.200",
            "168.63.129.16",
            "192.0.0.192",
            "fd00:ec2::254",
            "metadata.google.internal",
            "metadata.internal",
            "metadata.tencentyun.com",
            "metadata.platformequinix.com",
            "instance-data",
            "instance-data.ec2.internal",
            "fd00:ec2::23",
            "fe80::/10",
            "internal-metadata.example",
        ],
        "1.5.5's eleven lines in their order, the two enforced entries it never listed, then the \
         operator's additions; stderr={stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(linked_section_pools)]
#[test]
fn validate_accepts_root_pools_named_after_a_reserved_sub_key_as_1_5_5_did() {
    let dir = fixture_dir("pools-named-tier-work");
    write_configs(
        &dir,
        "pools:\n  tier:\n    members: [{model: test-model, tier: large}]\n  work:\n    \
         members: [{model: test-model}]\n",
    );
    let (code, stdout, stderr) = run_busbar(&dir, &["--validate"]);
    assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");
    assert!(
        stdout.contains("ok: config valid — 1 provider(s), 1 model(s), 2 pool(s)"),
        "got {stdout}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(linked_section_pools)]
#[test]
fn validate_notes_unset_interpolated_env_vars_by_name() {
    let dir = fixture_dir("unsetenv");

    write_configs(
        &dir,
        &format!("# smoke-tests unset-env-var interpolation: ${{{UNSET_INTERPOLATION_VAR}}}\n"),
    );
    let (code, stdout, stderr) = run_busbar(&dir, &["--validate"]);
    assert_eq!(
        code, 0,
        "an unset interpolation var is a note, not a failure: {stderr}"
    );
    assert!(
        stdout.contains("1 env var(s) referenced but unset here")
            && stdout.contains(UNSET_INTERPOLATION_VAR),
        "expected the unset-var note naming the variable, got: {stdout}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn validate_fails_on_unknown_config_key() {
    let dir = fixture_dir("badkey");
    write_configs(&dir, "goovernance:\n  admin_token: x\n");
    let (code, _stdout, stderr) = run_busbar(&dir, &["--validate"]);
    assert_eq!(code, 1);
    assert!(
        stderr.contains("goovernance"),
        "names the bad key: {stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(linked_section_pools)]
#[test]
fn validate_fails_when_store_plugin_referenced_but_plugins_disabled() {
    let dir = fixture_dir("disabled");
    write_configs(&dir, "store:\n  module: acme-kv\n");
    let (code, _stdout, stderr) = run_busbar(&dir, &["--validate"]);
    assert_eq!(code, 1);
    assert!(
        stderr.contains("plugins.enabled"),
        "names the flag: {stderr}"
    );
    assert!(stderr.contains("acme-kv"), "names the store: {stderr}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(linked_section_pools)]
#[test]
fn validate_fails_on_unresolvable_auth_chain_plugin() {
    let dir = fixture_dir("authplugin");
    write_configs(
        &dir,
        &format!(
            // 1.5.3: the provider is DEFINED once and referenced by bare name.
            "identity-providers:\n  oidc:\n    module: oidc\n    settings: {{}}\n\
             auth:\n  chain: [oidc]\n{}",
            plugins_block(&dir, true, true)
        ),
    );
    let (code, _stdout, stderr) = run_busbar(&dir, &["--validate"]);
    assert_eq!(
        code, 1,
        "an auth.chain module with no matching installed plugin must fail --validate: {stderr}"
    );
    assert!(
        stderr.contains("no plugin matching") || stderr.contains("was not loaded"),
        "expected the registry-aware unresolved-plugin error (not the old blanket \
         pre-registry rejection), got: {stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(linked_section_pools)]
#[test]
fn validate_fails_on_invalid_tarball_in_enabled_dir() {
    let dir = fixture_dir("invalid");
    std::fs::write(dir.join("plugins/junk.tar.gz"), b"not a tarball").unwrap();
    write_configs(&dir, &plugins_block(&dir, true, false));
    let (code, _stdout, stderr) = run_busbar(&dir, &["--validate"]);
    assert_eq!(code, 1);
    assert!(stderr.contains("junk.tar.gz"), "names the file: {stderr}");
    assert!(stderr.contains("plugin validation failed"), "got {stderr}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(linked_section_pools)]
#[test]
fn validate_fails_on_sha_mismatch() {
    let dir = fixture_dir("sha");
    let mut m = plugins::manifest("store", "acme-store-x", "acme");
    m.alias = "x".into();
    m.sha256 = plugins::sha256(b"OTHER bytes");
    let bytes = plugins::package(&m, b"real bytes");
    std::fs::write(dir.join("plugins/x.tar.gz"), bytes).unwrap();
    write_configs(&dir, &plugins_block(&dir, true, false));
    let (code, _stdout, stderr) = run_busbar(&dir, &["--validate"]);
    assert_eq!(code, 1);
    assert!(
        stderr.contains("integrity"),
        "names the sha mismatch: {stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(linked_section_pools)]
#[test]
fn validate_trust_gate_matches_boot() {
    let dir = fixture_dir("trust");
    write_tarball(
        &dir,
        "docstore.tar.gz",
        "busbar-store-docstore",
        "docstore",
        b"lib",
    );
    write_configs(
        &dir,
        &format!(
            "{}store:\n  module: docstore\n",
            plugins_block(&dir, true, false)
        ),
    );
    let (code, _stdout, stderr) = run_busbar(&dir, &["--validate"]);
    assert_eq!(code, 1);
    assert!(
        stderr.contains("allow_unsigned"),
        "names the opt-in: {stderr}"
    );

    write_configs(
        &dir,
        &format!(
            "{}store:\n  module: docstore\n",
            plugins_block(&dir, true, true)
        ),
    );
    let (code, stdout, stderr) = run_busbar(&dir, &["--validate"]);
    assert_eq!(code, 0, "stderr={stderr}");
    assert!(stdout.contains("1 validated"), "got {stdout}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(linked_section_pools)]
#[test]
fn validate_summary_names_an_unsigned_tarball_as_the_signing_gate_reads_it() {
    let dir = fixture_dir("gate-lines");
    write_tarball(
        &dir,
        "p.tar.gz",
        "busbar-store-docstore",
        "docstore",
        b"lib",
    );
    write_configs(&dir, &plugins_block(&dir, true, false));
    let (code, stdout, stderr) = run_busbar(&dir, &["--validate"]);
    assert_eq!(
        code, 0,
        "the linked store answers the config: stderr={stderr}"
    );
    assert!(
        stdout.contains("0 validated, 1 skipped"),
        "the summary's count, as the gate matches it: {stdout}"
    );
    let line = stdout
        .lines()
        .find(|l| {
            l.trim_start()
                .starts_with("skipped: busbar-store-docstore (p.tar.gz) ")
        })
        .unwrap_or_else(|| panic!("the skip line names the manifest and the file: {stdout}"));
    assert!(
        line.contains("manifest carries no signature"),
        "the skip line names the trust reason the gate matches: {line}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(linked_section_pools)]
#[test]
fn the_signing_gate_reference_reaches_the_dropped_in_tarball_past_a_linked_alias() {
    const NAME: &str = "busbar-store-memory";
    const ALIAS: &str = "memory";
    let gate = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/signing-gate.sh"),
    )
    .expect("read scripts/signing-gate.sh");
    let arm = gate
        .lines()
        .find(|l| l.trim_start().starts_with("store)") && l.contains("REF="))
        .expect("the gate has a store arm writing REF");
    assert!(
        arm.contains("$MANIFEST_NAME")
            && !arm.contains("$PLUGIN_ALIAS")
            && !arm.contains("$PLUGIN_CRATE"),
        "the store arm names the tarball by its manifest name: {arm}"
    );

    for (tag, name, alias, linked) in [
        ("signing-gate-ref", NAME, ALIAS, true),
        (
            "signing-gate-ref-unlinked",
            "signing-gate-unlinked-memory",
            "signing-gate-unlinked-memory",
            false,
        ),
    ] {
        let dir = fixture_dir(tag);
        let mut m = plugins::manifest("store", name, "busbar");
        m.alias = alias.into();
        std::fs::write(dir.join("plugins/p.tar.gz"), plugins::seal(m, b"lib")).unwrap();
        write_configs(
            &dir,
            &format!(
                "{}store:\n  module: {name}\n",
                plugins_block(&dir, true, false)
            ),
        );
        let (code, stdout, stderr) = run_busbar(&dir, &["--validate"]);
        let out = format!("{stdout}{stderr}");
        if linked {
            assert_eq!(code, 0, "the linked row answers `{name}`: {out}");
            assert!(
                stdout.contains("0 validated, 1 skipped")
                    && stdout.lines().any(|l| {
                        l.trim_start()
                            .starts_with(&format!("skipped: {name} (p.tar.gz) "))
                            && l.contains("manifest carries no signature")
                    }),
                "the loader's verdict names the unsigned tarball under test: {out}"
            );
        } else {
            assert_eq!(
                code, 1,
                "no row answers `{name}`: an unsigned tarball refuses: {out}"
            );
            assert!(
                out.contains("was not loaded")
                    && (out.contains("manifest carries no signature")
                        || out.contains("allow_unsigned")),
                "the refusal is the trust verdict on the tarball: {out}"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(linked_section_pools)]
#[test]
fn validate_fails_on_alias_conflict_naming_both() {
    let dir = fixture_dir("conflict");
    write_tarball(&dir, "a.tar.gz", "busbar-store-kv-plugin", "kv", b"a");
    write_tarball(&dir, "b.tar.gz", "acme-store-kv", "kv", b"b");
    write_configs(&dir, &plugins_block(&dir, true, true));
    let (code, _stdout, stderr) = run_busbar(&dir, &["--validate"]);
    assert_eq!(code, 1);
    assert!(
        stderr.contains("busbar-store-kv-plugin") && stderr.contains("acme-store-kv"),
        "names both: {stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn list_plugins_reports_statuses_without_loading() {
    let dir = fixture_dir("list");
    write_tarball(
        &dir,
        "good.tar.gz",
        "busbar-store-docstore",
        "docstore",
        b"g",
    );
    write_tarball(&dir, "third.tar.gz", "acme-store-dynamo", "dynamo", b"t");
    std::fs::write(dir.join("plugins/junk.tar.gz"), b"garbage").unwrap();

    write_configs(
        &dir,
        &format!(
            "{}store:\n  module: docstore\n",
            plugins_block(&dir, true, true)
        ),
    );
    let (code, stdout, _stderr) = run_busbar(&dir, &["--list-plugins"]);
    assert_eq!(code, 0, "list-plugins is informational: {stdout}");
    assert!(
        stdout.contains("LOADS (store.module: docstore)"),
        "the selected store row: {stdout}"
    );
    assert!(stdout.contains("busbar-store-docstore"), "{stdout}");
    assert!(stdout.contains("acme-store-dynamo"), "{stdout}");
    assert!(stdout.contains("ready"), "{stdout}");
    assert!(stdout.contains("INVALID"), "the junk row: {stdout}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// `--list-plugins`'s "selected" row is `plugins.enabled && row.status == "ready" && (name ==
/// store_ref || alias == store_ref)` — every conjunct actually gates selection, not just the
/// alias-match branch the sibling test above happens to exercise (there, alias == store_ref but
/// name never equals it, so a name==store_ref mutant would slip through unnoticed). This test
/// isolates each remaining conjunct:
///   1. NAME-only match (alias deliberately different from store_ref) still selects.
///   2. An UNTRUSTED row whose name matches store_ref does NOT select (status != "ready").
///   3. `plugins.enabled: false` suppresses selection even when name/status both match, and
///      reports the "inert" status instead of "LOADS".
#[test]
fn list_plugins_selected_row_requires_every_conjunct() {
    let dir = fixture_dir("list-name-match");
    write_tarball(
        &dir,
        "byname.tar.gz",
        "docstore",
        "totally-different-alias",
        b"n",
    );
    write_configs(
        &dir,
        &format!(
            "{}store:\n  module: docstore\n",
            plugins_block(&dir, true, true)
        ),
    );
    let (code, stdout, _stderr) = run_busbar(&dir, &["--list-plugins"]);
    assert_eq!(code, 0, "{stdout}");
    assert!(
        stdout.contains("LOADS (store.module: docstore)"),
        "a NAME match alone (alias differs) must still select: {stdout}"
    );
    let _ = std::fs::remove_dir_all(&dir);

    let dir = fixture_dir("list-untrusted-match");
    write_tarball(&dir, "untrusted.tar.gz", "docstore", "docstore", b"u");
    write_configs(
        &dir,
        &format!(
            "{}store:\n  module: docstore\n",
            plugins_block(&dir, true, false)
        ),
    );
    let (code, stdout, _stderr) = run_busbar(&dir, &["--list-plugins"]);
    assert_eq!(code, 0, "{stdout}");
    assert!(
        !stdout.contains("LOADS"),
        "a name/alias match with a non-\"ready\" status must NOT select: {stdout}"
    );
    let _ = std::fs::remove_dir_all(&dir);

    let dir = fixture_dir("list-disabled-match");
    write_tarball(&dir, "disabled.tar.gz", "docstore", "docstore", b"d");
    write_configs(
        &dir,
        &format!(
            "{}store:\n  module: docstore\n",
            plugins_block(&dir, false, true)
        ),
    );
    let (code, stdout, _stderr) = run_busbar(&dir, &["--list-plugins"]);
    assert_eq!(code, 0, "{stdout}");
    assert!(
        !stdout.contains("LOADS"),
        "plugins.enabled: false must suppress selection even on an otherwise-matching row: {stdout}"
    );
    assert!(
        stdout.contains("inert: plugins.enabled is false"),
        "got {stdout}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn migrate_config_prints_changes_and_warnings_sections_when_non_empty() {
    let dir = fixture_dir("migrate");
    std::fs::create_dir_all(&dir).unwrap();
    let legacy = dir.join("legacy.yaml");
    std::fs::write(
        &legacy,
        "governance:\n  db_path: \"old.db\"\nauth:\n  chain:\n    - oidc\n  group_map:\n    full:\n      allowed_pools: []\n",
    )
    .unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_busbar"))
        .args(["--migrate-config", legacy.to_str().unwrap()])
        .output()
        .expect("run busbar --migrate-config");
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_eq!(out.status.code(), Some(0), "stderr={stderr}");
    assert!(
        stderr.contains("CHANGES (") && stderr.contains("governance.db_path"),
        "a non-empty changes list must print the CHANGES section: {stderr}"
    );
    assert!(
        stderr.contains("WARNINGS (") && stderr.contains("allowed_pools"),
        "a non-empty warnings list must print the WARNINGS section: {stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn migrate_config_omits_changes_and_warnings_sections_when_empty() {
    let dir = fixture_dir("migrate-clean");
    std::fs::create_dir_all(&dir).unwrap();
    let legacy = dir.join("legacy.yaml");

    std::fs::write(
        &legacy,
        "listen: \"127.0.0.1:8080\"\nstore: {module: memory}\n",
    )
    .unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_busbar"))
        .args(["--migrate-config", legacy.to_str().unwrap()])
        .output()
        .expect("run busbar --migrate-config");
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_eq!(out.status.code(), Some(0), "stderr={stderr}");
    assert!(
        !stderr.contains("CHANGES ("),
        "an empty changes list must NOT print the CHANGES section: {stderr}"
    );
    assert!(
        !stderr.contains("WARNINGS ("),
        "an empty warnings list must NOT print the WARNINGS section: {stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(linked_section_pools)]
#[test]
fn validate_fails_when_a_plugin_is_referenced_but_plugins_are_disabled() {
    let dir = fixture_dir("gate-store");
    write_configs(&dir, "store:\n  module: docstore\n");
    let (code, _stdout, stderr) = run_busbar(&dir, &["--validate"]);
    assert_eq!(code, 1, "{stderr}");
    assert!(
        stderr.contains("store.module: 'docstore' requires the plugin subsystem")
            && stderr.contains("plugins.enabled is false"),
        "got {stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);

    let dir = fixture_dir("gate-auth");
    write_configs(
        &dir,
        "identity-providers:\n  oidc: { module: oidc }\nauth:\n  chain: [oidc]\n",
    );
    let (code, _stdout, stderr) = run_busbar(&dir, &["--validate"]);
    assert_eq!(code, 1, "{stderr}");
    assert!(
        stderr.contains("auth.chain names plugin module(s)") && stderr.contains("[oidc]"),
        "got {stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);

    let dir = fixture_dir("gate-hook");
    write_configs(
        &dir,
        "hooks:\n  audit:\n    kind: tap\n    module: webrequest\n    prompt: ro\n",
    );
    let (code, _stdout, stderr) = run_busbar(&dir, &["--validate"]);
    assert_eq!(code, 1, "{stderr}");
    assert!(
        stderr.contains("the hooks registry names plugin module(s)")
            && stderr.contains("[webrequest]"),
        "got {stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(linked_section_pools)]
#[test]
fn validate_fails_when_store_module_resolves_to_a_non_store_plugin_kind() {
    let dir = fixture_dir("wrongkind");
    let mut m = plugins::manifest("hook", "acme-hook-x", "acme");
    m.alias = "x".into();
    let bytes = plugins::seal(m, b"real bytes");
    std::fs::write(dir.join("plugins/x.tar.gz"), bytes).unwrap();

    write_configs(
        &dir,
        &format!("{}store:\n  module: x\n", plugins_block(&dir, true, true)),
    );
    let (code, _stdout, stderr) = run_busbar(&dir, &["--validate"]);
    assert_eq!(code, 1, "a kind mismatch must fail --validate: {stderr}");
    assert!(
        stderr.contains("not a store plugin"),
        "must name the specific kind-mismatch reason, not a generic failure: {stderr}"
    );
    assert!(
        stderr.contains("kind 'hook'"),
        "must name the actual (wrong) kind resolved: {stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn validate_fails_when_keys_chain_lacks_signing_key() {
    let dir = fixture_dir("sk-missing");
    write_configs(&dir, "auth:\n  chain:\n    - keys\n");
    let (code, _stdout, stderr) = run_busbar(&dir, &["--validate"]);
    assert_eq!(
        code, 1,
        "a `keys` chain with no signing key must fail --validate: {stderr}"
    );
    assert!(
        stderr.contains("auth.signing_key is required")
            && stderr.contains("--generate-signing-key"),
        "the error must be actionable (name the key + the generate command): {stderr}"
    );

    assert!(
        !dir.join("busbar-signing.key").exists(),
        "busbar must NOT write a signing key (the boot-loop bug being fixed)"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(linked_section_pools)]
#[test]
fn validate_ok_when_keys_chain_has_signing_key_and_writes_no_file() {
    let dir = fixture_dir("sk-ok");
    write_configs(
        &dir,
        "auth:\n  chain:\n    - keys\n  signing_key: { env: BUSBAR_SIGNING_KEY }\n  admin_auth: []\n",
    );
    let (code, stdout, stderr) = run_busbar(&dir, &["--validate"]);
    assert_eq!(
        code, 0,
        "a `keys` chain WITH a signing_key ref (and an admin mint path) validates clean: {stderr}"
    );
    assert!(stdout.contains("ok: config valid"), "got {stdout}");
    assert!(
        !dir.join("busbar-signing.key").exists(),
        "--validate must never generate/persist a signing key"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(linked_section_pools)]
#[test]
fn generate_signing_key_emits_a_usable_referenced_key() {
    let dir = fixture_dir("sk-gen");
    let out = Command::new(env!("CARGO_BIN_EXE_busbar"))
        .args(["--generate-signing-key"])
        .output()
        .expect("run busbar --generate-signing-key");
    assert_eq!(out.status.code(), Some(0));
    let hex = String::from_utf8_lossy(&out.stdout).trim().to_string();
    assert_eq!(hex.len(), 64, "the key is 64 hex chars on stdout: {hex:?}");
    assert!(
        hex.chars().all(|c| c.is_ascii_hexdigit()),
        "the key is hex only: {hex}"
    );

    let keyfile = dir.join("signing.key");
    std::fs::write(&keyfile, &hex).unwrap();
    write_configs(
        &dir,
        &format!(
            "auth:\n  chain:\n    - keys\n  signing_key: {{ file: '{}' }}\n  admin_auth: []\n",
            keyfile.display()
        ),
    );
    let (code, stdout, stderr) = run_busbar(&dir, &["--validate"]);
    assert_eq!(
        code, 0,
        "a generated key, written to a file and referenced, must validate: {stderr}"
    );
    assert!(stdout.contains("ok: config valid"), "got {stdout}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(linked_section_pools)]
fn run_busbar_with_overlay(dir: &Path, overlay: &Path, args: &[&str]) -> (i32, String, String) {
    let config_path = dir.join("config.yaml");
    let mut config = std::fs::read_to_string(&config_path).expect("read fixture config.yaml");

    if !config.contains("\nconfig:\n") {
        config.push_str(&format!(
            "\nconfig:\n  overlay:\n    file: '{}'\n",
            overlay.display()
        ));
        std::fs::write(&config_path, config)
            .expect("rewrite fixture config.yaml with overlay pointer");
    }
    let out = Command::new(env!("CARGO_BIN_EXE_busbar"))
        .args(args)
        .env("MOCK_KEY", "test-key-value")
        .env(
            "BUSBAR_SIGNING_KEY",
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .env("BUSBAR_CONFIG", dir.join("config.yaml"))
        .env("BUSBAR_PROVIDERS", dir.join("providers.yaml"))
        .output()
        .expect("run busbar");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[cfg(linked_section_pools)]
#[test]
fn validate_applies_and_rejects_a_bad_root_overlay() {
    let dir = fixture_dir("rootovl");
    write_configs(&dir, "");
    let overlay = dir.join("overlay.json");

    std::fs::write(
        &overlay,
        r#"{"version":1,"root":{"limits":{"reasoning_effort_budgets":{"minimal":16384,"low":8192,"medium":4096,"high":1024}}}}"#,
    )
    .unwrap();
    let (code, _stdout, stderr) = run_busbar_with_overlay(&dir, &overlay, &["--validate"]);
    assert_eq!(code, 1, "a bad root overlay fails --validate: {stderr}");
    assert!(
        stderr.contains("reasoning_effort_budgets") && stderr.contains("ascending"),
        "the overlay's root section was validated: {stderr}"
    );

    let (code, stdout, stderr) =
        run_busbar_with_overlay(&dir, &overlay, &["--validate", "--safe-mode"]);
    assert_eq!(
        code, 0,
        "--safe-mode ignores the overlay root: stdout={stdout} stderr={stderr}"
    );
    assert!(stdout.contains("ok: config valid"), "got {stdout}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(linked_section_pools)]
#[test]
fn validate_ok_on_valid_root_overlay() {
    let dir = fixture_dir("rootovlok");
    write_configs(&dir, "");
    let overlay = dir.join("overlay.json");
    std::fs::write(
        &overlay,
        r#"{"version":1,"root":{"per_request_fee":9,"limits":{"max_inbound_concurrent":256}}}"#,
    )
    .unwrap();
    let (code, stdout, stderr) = run_busbar_with_overlay(&dir, &overlay, &["--validate"]);
    assert_eq!(code, 0, "a valid root overlay validates clean: {stderr}");
    assert!(stdout.contains("ok: config valid"), "got {stdout}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(linked_section_pools)]
#[test]
fn validate_honors_deprecated_busbar_config_overlay_env_var() {
    let dir = fixture_dir("ovlenvdep");
    write_configs(&dir, "");
    let bad_overlay = dir.join("bad-overlay.json");
    std::fs::write(
        &bad_overlay,
        r#"{"version":1,"root":{"limits":{"reasoning_effort_budgets":{"minimal":16384,"low":8192,"medium":4096,"high":1024}}}}"#,
    )
    .unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_busbar"))
        .args(["--validate"])
        .env("MOCK_KEY", "test-key-value")
        .env(
            "BUSBAR_SIGNING_KEY",
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .env("BUSBAR_CONFIG", dir.join("config.yaml"))
        .env("BUSBAR_PROVIDERS", dir.join("providers.yaml"))
        .env("BUSBAR_CONFIG_OVERLAY", &bad_overlay)
        .output()
        .expect("run busbar");
    let code = out.status.code().unwrap_or(-1);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        code, 1,
        "the deprecated BUSBAR_CONFIG_OVERLAY env var must still be honored, so the bad overlay IS \
         applied and validate fails: {stderr}"
    );
    assert!(
        stderr.contains("reasoning_effort_budgets") && stderr.contains("ascending"),
        "the env-selected overlay's root section was validated: {stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(linked_operator_auth)]
#[test]
fn validate_fails_on_unresolvable_browser_login_client_secret() {
    const UNSET_VAR: &str = "BUSBAR_TEST_B1_OIDC_CLIENT_SECRET_NEVER_SET";
    let dir = fixture_dir("b1-browser-login-secret");
    write_configs(
        &dir,
        &format!(
            "public_url: \"https://busbar.example.com\"\n\
             identity-providers:\n\
             \x20 admin-tokens:\n\
             \x20   module: admin-tokens\n\
             \x20   token: {{ env: BUSBAR_ADMIN_TOKEN }}\n\
             \x20   browser_login:\n\
             \x20     client_id: busbar-web\n\
             \x20     client_secret: {{ env: {UNSET_VAR} }}\n\
             auth:\n\
             \x20 admin_auth:\n\
             \x20   - admin-tokens\n"
        ),
    );
    let out = Command::new(env!("CARGO_BIN_EXE_busbar"))
        .arg("--validate")
        .env_remove(UNSET_VAR)
        .env("MOCK_KEY", "test-key-value")
        .env("BUSBAR_ADMIN_TOKEN", "test-admin-token")
        .env("BUSBAR_CONFIG", dir.join("config.yaml"))
        .env("BUSBAR_PROVIDERS", dir.join("providers.yaml"))
        .output()
        .expect("run busbar");
    let code = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_eq!(
        code, 1,
        "an unset browser_login client_secret must FAIL --validate, not be silently skipped: \
         stdout={stdout} stderr={stderr}"
    );
    assert!(
        !stdout.contains("ok: config valid"),
        "--validate must not report the config valid: {stdout}"
    );
    assert!(
        stderr.contains("browser_login.client_secret") && stderr.contains(UNSET_VAR),
        "the error must NAME the config path and the unset variable so it is actionable: {stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(linked_section_tools)]
#[test]
fn validate_refuses_a_publish_as_collision_with_a_namespaced_default() {
    let dir = fixture_dir("publish-as-collision");
    write_tools_only_configs(
        &dir,
        r#"tools:
  foo:
    url: "https://foo.internal/rpc"
    pin: { mechanism: unpinned }
    tools_allow: { bar: {} }
  other:
    url: "https://other.internal/rpc"
    pin: { mechanism: unpinned }
    tools_allow:
      anything:
        publish_as: foo_bar
"#,
    );
    let (code, stdout, stderr) = run_busbar(&dir, &["--validate"]);
    let all = format!("{stdout}{stderr}");
    assert_eq!(code, 1, "a colliding config must not validate clean: {all}");
    assert!(all.contains("published as `foo_bar`"), "{all}");

    assert!(all.contains("tools.foo.tools_allow.bar"), "{all}");
    assert!(
        all.contains("tools.other.tools_allow.anything.publish_as"),
        "{all}"
    );

    write_tools_only_configs(
        &dir,
        r#"tools:
  foo:
    url: "https://foo.internal/rpc"
    pin: { mechanism: unpinned }
    tools_allow: { bar: {} }
  other:
    url: "https://other.internal/rpc"
    pin: { mechanism: unpinned }
    tools_allow:
      anything:
        publish_as: greet
"#,
    );
    let (code, stdout, stderr) = run_busbar(&dir, &["--validate"]);
    assert_eq!(
        code, 0,
        "distinct published names must validate clean: {stdout}{stderr}"
    );
}

#[cfg(linked_section_pools)]
#[test]
fn the_operator_visible_protocol_order_is_exactly_the_shipped_one() {
    let d = fixture_dir("protocol-order");
    write_configs(&d, "");

    std::fs::write(
        d.join("providers.yaml"),
        r#"mock:
  protocol: definitely-not-a-protocol
  base_url: "http://127.0.0.1:9"
"#,
    )
    .unwrap();
    let (code, out, err) = run_busbar(&d, &["--validate"]);
    let all = format!("{out}{err}");
    assert_ne!(code, 0, "an unknown protocol must fail validation: {all}");
    assert!(
        all.contains("must be one of: anthropic, openai, gemini, bedrock, responses, cohere"),
        "the operator-visible protocol order changed. It is a metric-family index as well as a \
         config-error string, so this is not cosmetic — see this test's doc. Got: {all}"
    );
}

#[cfg(linked_section_pools)]
fn run_cli(
    config_env: Option<&Path>,
    args: &[&str],
    extra_env: &[(&str, &str)],
) -> (i32, String, String) {
    let mut c = Command::new(env!("CARGO_BIN_EXE_busbar"));
    c.args(args).env("MOCK_KEY", "test-key-value").env(
        "BUSBAR_SIGNING_KEY",
        "0000000000000000000000000000000000000000000000000000000000000001",
    );
    match config_env {
        Some(p) => {
            c.env("BUSBAR_CONFIG", p);
        }
        None => {
            c.env_remove("BUSBAR_CONFIG");
        }
    }
    for (k, v) in extra_env {
        c.env(k, v);
    }
    let out = c.output().expect("run busbar");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[cfg(linked_section_pools)]
#[test]
fn config_flag_overrides_env_and_default() {
    let dir = fixture_dir("cfgflag");

    let real = dir.join("real");
    std::fs::create_dir_all(real.join("plugins")).unwrap();
    write_configs(&real, "");
    let real_config = real.join("config.yaml");
    let bogus = dir.join("bogus").join("config.yaml");

    let (code, stdout, stderr) = run_cli(
        Some(&bogus),
        &["--validate", "-c", real_config.to_str().unwrap()],
        &[],
    );
    assert_eq!(
        code, 0,
        "-c/--config must override a (bogus) BUSBAR_CONFIG and the default: stdout={stdout} stderr={stderr}"
    );
    assert!(stdout.contains("ok: config valid"), "got {stdout}");
    assert!(
        stdout.contains(real_config.to_str().unwrap()),
        "the validate output must name the FLAG's config path, proving it won over BUSBAR_CONFIG: {stdout}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(linked_section_pools)]
#[test]
fn providers_flag_overrides_providers_file_and_default() {
    let dir = fixture_dir("provflag");

    let cfgdir = dir.join("cfg");
    std::fs::create_dir_all(&cfgdir).unwrap();
    let config = cfgdir.join("config.yaml");
    std::fs::write(
        &config,
        "listen: \"127.0.0.1:0\"\n\
         store: {module: memory}\n\
         providers:\n\
         \x20 mock:\n\
         \x20   api_key: { env: MOCK_KEY }\n\
         models:\n\
         \x20 test-model:\n\
         \x20   provider: mock\n\
         providers_file: does-not-exist.yaml\n",
    )
    .unwrap();

    let real_catalog = dir.join("real-providers.yaml");
    std::fs::write(
        &real_catalog,
        "mock:\n  protocol: anthropic\n  base_url: \"http://127.0.0.1:9\"\n",
    )
    .unwrap();

    let (code, _stdout, stderr) = run_cli(Some(&config), &["--validate"], &[]);
    assert_eq!(
        code, 1,
        "a providers_file pointing at a missing catalog must fail --validate: {stderr}"
    );

    let (code, stdout, stderr) = run_cli(
        Some(&config),
        &["--validate", "--providers", real_catalog.to_str().unwrap()],
        &[],
    );
    assert_eq!(
        code, 0,
        "--providers must override providers_file: stdout={stdout} stderr={stderr}"
    );
    assert!(stdout.contains("ok: config valid"), "got {stdout}");
    assert!(
        stdout.contains(real_catalog.to_str().unwrap()),
        "the validate output must name the FLAG's catalog, proving it won over providers_file: {stdout}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(linked_section_pools)]
#[test]
fn busbar_providers_env_is_deprecated_but_honored() {
    let dir = fixture_dir("provenvdep");
    write_configs(&dir, "");
    let config = dir.join("config.yaml");
    let bogus = dir.join("bogus-providers.yaml");

    let (code, stdout, stderr) = run_cli(
        Some(&config),
        &["--validate"],
        &[("BUSBAR_PROVIDERS", bogus.to_str().unwrap())],
    );
    assert_eq!(
        code, 1,
        "BUSBAR_PROVIDERS is still honored; the bogus env value must fail the load: \
         stdout={stdout} stderr={stderr}"
    );
    let warn =
        "[warn] BUSBAR_PROVIDERS is DEPRECATED; set `providers_file:` in config.yaml instead \
                (it is honored for now).";
    assert!(
        stderr.contains(warn),
        "the deprecation warning must be printed verbatim: {stderr}"
    );
    let err = format!("cannot read providers file '{}': ", bogus.to_str().unwrap());
    assert!(
        stderr.contains(&err)
            && stderr.contains("(set `providers_file:` in config.yaml, or BUSBAR_PROVIDERS)"),
        "the load error must name the env-selected path and the remediation: {stderr}"
    );
    assert!(
        stderr.find(warn).unwrap() < stderr.find(&err).unwrap(),
        "the deprecation warning must precede the load error: {stderr}"
    );

    let real = dir.join("providers.yaml");
    let (code, stdout, stderr) = run_cli(
        Some(&config),
        &["--validate"],
        &[("BUSBAR_PROVIDERS", real.to_str().unwrap())],
    );
    assert_eq!(code, 0, "a real BUSBAR_PROVIDERS path validates: {stderr}");
    assert!(stdout.contains("ok: config valid"), "got {stdout}");
    assert!(
        stderr.contains(warn),
        "the deprecation warning fires whenever the var is set: {stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

fn write_configs_with_api_key(dir: &Path, api_key_yaml: &str, extra: &str) {
    std::fs::write(
        dir.join("providers.yaml"),
        r#"mock:
  protocol: anthropic
  base_url: "http://127.0.0.1:9"
"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("config.yaml"),
        format!(
            r#"listen: "127.0.0.1:0"
store: {{module: memory}}
providers:
  mock:
    api_key: {api_key_yaml}
models:
  test-model:
    provider: mock
{extra}"#
        ),
    )
    .unwrap();
}

#[cfg(linked_section_pools)]
#[test]
fn validate_refuses_a_provider_api_key_that_does_not_resolve() {
    let dir = fixture_dir("apikey-unresolvable");
    let unset = UNSET_INTERPOLATION_VAR;
    write_configs_with_api_key(&dir, &format!("{{ env: {unset} }}"), "");
    let (code, stdout, stderr) = run_busbar(&dir, &["--validate"]);
    assert_eq!(code, 1, "an unresolvable api_key fails validate: {stdout}");
    assert!(
        stderr.contains("providers.mock.api_key"),
        "the refusal names the field: {stderr}"
    );
    assert!(
        stderr.contains(&format!("env:{unset}")),
        "the refusal names the reference: {stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(linked_section_pools)]
#[test]
fn validate_accepts_api_key_none_for_a_keyless_upstream() {
    let dir = fixture_dir("apikey-none");
    write_configs_with_api_key(&dir, "none", "");
    let (code, stdout, stderr) = run_busbar(&dir, &["--validate"]);
    assert_eq!(code, 0, "`api_key: none` is valid: {stderr}");
    assert!(stdout.contains("ok: config valid"), "got {stdout}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn validate_refuses_none_on_a_secret_that_requires_a_credential() {
    let dir = fixture_dir("none-on-signing-key");
    write_configs_with_api_key(
        &dir,
        "{ env: MOCK_KEY }",
        "auth:\n  signing_key: none\n  chain: [keys]\n",
    );
    let (code, stdout, stderr) = run_busbar(&dir, &["--validate"]);
    assert_eq!(code, 1, "`none` on a signing key is refused: {stdout}");
    assert!(
        stderr.contains("auth.signing_key") && stderr.contains("NO credential"),
        "the refusal names the field and why `none` is wrong there: {stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(linked_section_decisions)]
fn write_decisions_configs(dir: &Path, protocol: &str, decisions_yaml: &str) {
    std::fs::write(
        dir.join("providers.yaml"),
        format!(
            r#"mock:
  protocol: {protocol}
  base_url: "http://127.0.0.1:9"
"#
        ),
    )
    .unwrap();
    std::fs::write(
        dir.join("config.yaml"),
        format!(
            r#"listen: "127.0.0.1:0"
store: {{module: memory}}
providers:
  mock:
    api_key: {{ env: MOCK_KEY }}
models: {{}}
{decisions_yaml}"#
        ),
    )
    .unwrap();
}

#[cfg(linked_section_decisions)]
fn door_dialect() -> String {
    let dir = fixture_dir("decisions-dialect-probe");
    write_decisions_configs(
        &dir,
        "bogus",
        "decisions:\n  models:\n    verdicts:\n      provider: mock\n",
    );
    let (code, _stdout, stderr) = run_busbar(&dir, &["--validate"]);
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(
        code, 1,
        "a foreign dialect on the plane is refused: {stderr}"
    );
    let spoken = stderr
        .split("this plane speaks only: ")
        .nth(1)
        .and_then(|rest| rest.split('.').next())
        .unwrap_or_else(|| panic!("the refusal names the dialects the plane speaks: {stderr}"));
    let dialects: Vec<&str> = spoken.split(',').map(str::trim).collect();
    assert_eq!(dialects.len(), 2, "the plane speaks two dialects: {stderr}");
    dialects[0].to_string()
}

#[cfg(linked_section_decisions)]
#[test]
fn validate_ok_on_a_good_decisions_config() {
    let dir = fixture_dir("decisions-ok");
    write_decisions_configs(
        &dir,
        &door_dialect(),
        "decisions:\n  models:\n    verdicts:\n      provider: mock\n",
    );
    let (code, stdout, stderr) = run_busbar(&dir, &["--validate"]);
    assert_eq!(
        code, 0,
        "a good decisions config validates: stdout={stdout} stderr={stderr}"
    );
    assert!(stdout.contains("ok: config valid"), "got {stdout}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(linked_section_decisions)]
#[test]
fn validate_ok_on_a_config_in_the_planes_second_dialect() {
    let dir = fixture_dir("plane-ok-second-dialect");
    write_decisions_configs(
        &dir,
        "nanojev",
        "decisions:\n  models:\n    verdicts:\n      provider: mock\n",
    );
    let (code, stdout, stderr) = run_busbar(&dir, &["--validate"]);
    assert_eq!(
        code, 0,
        "a config in the second dialect validates: stdout={stdout} stderr={stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(linked_section_decisions)]
#[test]
fn validate_refuses_a_decisions_model_naming_an_undefined_provider() {
    let dir = fixture_dir("decisions-badprovider");
    write_decisions_configs(
        &dir,
        &door_dialect(),
        "decisions:\n  models:\n    verdicts:\n      provider: ghost\n",
    );
    let (code, _stdout, stderr) = run_busbar(&dir, &["--validate"]);
    assert_eq!(
        code, 1,
        "an undefined provider reference fails validate: {stderr}"
    );
    assert!(
        stderr.contains("decisions.models.verdicts.provider"),
        "the refusal names the key path: {stderr}"
    );
    assert!(
        stderr.contains("ghost"),
        "the refusal names the bad value: {stderr}"
    );
    assert!(
        stderr.contains("mock"),
        "the refusal names the valid choices: {stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(linked_section_decisions)]
#[test]
fn validate_refuses_a_decisions_hook_naming_an_undefined_hook() {
    let dir = fixture_dir("decisions-badhook");
    write_decisions_configs(
        &dir,
        &door_dialect(),
        "decisions:\n  models:\n    verdicts:\n      provider: mock\n  hooks: [ghost-hook]\n",
    );
    let (code, _stdout, stderr) = run_busbar(&dir, &["--validate"]);
    assert_eq!(
        code, 1,
        "an undefined hook reference fails validate: {stderr}"
    );
    assert!(
        stderr.contains("decisions.hooks"),
        "the refusal names the key path: {stderr}"
    );
    assert!(
        stderr.contains("ghost-hook"),
        "the refusal names the bad value: {stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(linked_section_decisions)]
#[test]
fn validate_refuses_a_decisions_model_whose_provider_speaks_a_foreign_dialect() {
    let dir = fixture_dir("decisions-baddialect");
    write_decisions_configs(
        &dir,
        "anthropic",
        "decisions:\n  models:\n    verdicts:\n      provider: mock\n",
    );
    let (code, _stdout, stderr) = run_busbar(&dir, &["--validate"]);
    assert_eq!(
        code, 1,
        "a dialect the plane does not speak fails closed: {stderr}"
    );
    assert!(
        stderr.contains("decisions.models.verdicts.provider"),
        "the refusal names the key path: {stderr}"
    );
    assert!(
        stderr.contains("anthropic"),
        "the refusal names the resolved dialect: {stderr}"
    );
    let dialect = door_dialect();
    assert!(
        stderr.contains(&dialect),
        "the refusal names the dialect the plane speaks (`{dialect}`): {stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(linked_section_decisions)]
#[test]
fn validate_refuses_a_decisions_block_its_door_does_not_accept() {
    for (case, block, member) in [
        ("scalar", "decisions: \"hello\"\n", None),
        (
            "typo",
            "decisions:\n  modles:\n    verdicts:\n      provider: mock\n",
            Some("modles"),
        ),
    ] {
        let dir = fixture_dir(&format!("decisions-door-{case}"));
        write_decisions_configs(&dir, &door_dialect(), block);
        let (code, _stdout, stderr) = run_busbar(&dir, &["--validate"]);
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(code, 1, "{case}: the door refuses the block: {stderr}");
        assert!(
            stderr.contains("decisions"),
            "{case}: the refusal names the block: {stderr}"
        );
        if let Some(member) = member {
            assert!(
                stderr.contains(member),
                "{case}: the refusal names the member: {stderr}"
            );
        }
    }
}

#[cfg(all(linked_section_decisions, linked_section_pools))]
const PROTOCOLS_1_5_5: &str =
    "must be one of: anthropic, openai, gemini, bedrock, responses, cohere\n";

#[cfg(all(linked_section_decisions, linked_section_pools))]
#[test]
fn validate_unknown_protocol_lists_only_the_configured_planes_dialects() {
    let dir = fixture_dir("bogus-protocol-no-decisions");
    write_decisions_configs(&dir, "bogus", "");
    let (code, _stdout, stderr) = run_busbar(&dir, &["--validate"]);
    assert_eq!(code, 1, "an unknown protocol fails validate: {stderr}");
    assert!(
        stderr.contains(&format!(
            "provider 'mock' has unknown protocol 'bogus': {PROTOCOLS_1_5_5}"
        )),
        "with no decisions: section the list is 1.5.5's, with no plane dialect appended: {stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(all(linked_section_decisions, linked_section_pools))]
#[test]
fn validate_refuses_the_planes_protocol_when_its_section_is_not_configured() {
    let dir = fixture_dir("plane-protocol-no-section");
    let dialect = door_dialect();
    write_decisions_configs(&dir, &dialect, "");
    let (code, _stdout, stderr) = run_busbar(&dir, &["--validate"]);
    assert_eq!(
        code, 1,
        "the plane's protocol with the plane's section unconfigured fails validate: {stderr}"
    );
    assert!(
        stderr.contains(&format!(
            "provider 'mock' has unknown protocol '{dialect}': {PROTOCOLS_1_5_5}"
        )),
        "the refusal is 1.5.5's unknown-protocol line: {stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(all(linked_section_pools, linked_axis_export_doors))]
#[test]
fn validate_orders_a_webhook_sinks_refusals_among_the_limits_as_before() {
    let probe = fixture_dir("webhook-order-probe");
    write_configs(
        &probe,
        "export:\n  hook: { module: request-log-webhook, settings: { url: \"https://siem.example/in\" } }\n",
    );
    let (_, _, probed) = run_busbar(&probe, &["--validate"]);
    assert!(
        !probed.contains("unknown exporter 'request-log-webhook'"),
        "{probed}"
    );
    let dir = fixture_dir("webhook-order");
    write_configs(
        &dir,
        "limits:\n  upstream_request_timeout_secs: 0\n  max_honored_retry_after_secs: 0\n\
         export:\n  hook: { module: request-log-webhook, settings: { url: \"https://siem.example/in\", \
         max_inflight_deliveries: 0, delivery_timeout_secs: 0 } }\n",
    );
    let (code, _stdout, stderr) = run_busbar(&dir, &["--validate"]);
    assert_ne!(code, 0, "{stderr}");
    let refusal: Vec<&str> = stderr
        .lines()
        .skip_while(|l| !l.contains("config validation failed:"))
        .skip(1)
        .take_while(|l| l.starts_with("  - "))
        .collect();
    assert_eq!(
        refusal,
        [
            "  - limits.upstream_request_timeout_secs must be >= 1 (0 would time out every upstream call instantly)",
            "  - the largest settings.max_inflight_deliveries among `module: request-log-webhook` export instances must be >= 1",
            "  - limits.max_honored_retry_after_secs must be >= 1 (a 0 ceiling would clamp every honored Retry-After to 0)",
            "  - export.hook: the `module: request-log-webhook` export instance targeting 'https://siem.example/***' (#0) sets settings.delivery_timeout_secs: 0 — it must be >= 1",
        ],
        "{stderr}"
    );
}

#[cfg(linked_section_pools)]
fn write_stated_store(dir: &Path, name: &str, alias: &str, kind_abi: u32, lib: &[u8]) {
    use busbar_contract::abi::mechanism::door::Statement;
    use busbar_contract::abi::mechanism::rendering::render;
    use busbar_contract::abi::mechanism::KindCode;
    let st = Statement {
        size: std::mem::size_of::<Statement>() as u32,
        kind: KindCode::Store as u32,
        kind_abi,
        ..busbar_contract::abi::sdk::door::statement("busbar-store-stated", "1.6.0", 4)
    };
    // SAFETY: the SDK Statement names only `'static` strings and no list.
    let rendering = unsafe { render(&st) }.unwrap();
    let mut m = plugins::manifest("store", name, "acme");
    m.alias = alias.into();
    m.statement = Some(hex::encode(&rendering));
    std::fs::write(
        dir.join("plugins").join(format!("{name}.tar.gz")),
        plugins::seal(m, lib),
    )
    .unwrap();
}

#[cfg(linked_section_pools)]
#[test]
fn validate_selects_a_dropped_plugin_without_opening_it_and_reports_in_1_5_5s_words() {
    use busbar_contract::abi::mechanism::KindCode;
    let dir = fixture_dir("stated");
    let abi = KindCode::Store.abi_version();
    write_stated_store(&dir, "busbar-store-stated", "stated", abi, b"not a library");
    for config in [
        format!(
            "{}store:\n  module: stated\n",
            plugins_block(&dir, true, true)
        ),
        plugins_block(&dir, true, true),
    ] {
        write_configs(&dir, &config);
        let (code, stdout, stderr) = run_busbar(&dir, &["--validate"]);
        assert_eq!(code, 0, "stderr={stderr}");
        assert!(
            stdout.contains("  plugins:   enabled — 1 validated, 0 skipped (untrusted) in '"),
            "got {stdout}"
        );
        for out in [&stdout, &stderr] {
            assert!(
                !out.contains("plugin: busbar-store-stated")
                    && !out.contains("selected as")
                    && !out.contains("not used by this config"),
                "--validate printed a line 1.5.5 never printed: {out}"
            );
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(linked_section_pools)]
#[test]
fn validate_refuses_a_selected_plugin_built_for_another_host() {
    use busbar_contract::abi::mechanism::KindCode;
    let dir = fixture_dir("stated-abi");
    let abi = KindCode::Store.abi_version() + 1;
    write_stated_store(&dir, "busbar-store-stated", "stated", abi, b"not a library");
    write_configs(
        &dir,
        &format!(
            "{}store:\n  module: stated\n",
            plugins_block(&dir, true, true)
        ),
    );
    let (code, _stdout, stderr) = run_busbar(&dir, &["--validate"]);
    assert_eq!(code, 1);
    assert!(
        stderr.contains("busbar-store-stated")
            && stderr.contains("rebuild the plugin against the 1.6.0 SDK"),
        "got {stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(linked_section_pools)]
#[test]
fn validate_refuses_an_http_token_url_on_a_public_host() {
    let run = |token_url: &str| {
        let dir = fixture_dir("mint-scheme");
        std::fs::write(
            dir.join("providers.yaml"),
            r#"entra:
  protocol: openai
  base_url: "https://res.example.com"
"#,
        )
        .unwrap();
        std::fs::write(
            dir.join("config.yaml"),
            format!(
                r#"listen: "127.0.0.1:0"
store: {{module: memory}}
providers:
  entra:
    api_key: {{ env: MOCK_KEY }}
    auth: oauth-client-credentials
    token_url: "{token_url}"
    scope: "api://x/.default"
models:
  test-model:
    provider: entra
"#
            ),
        )
        .unwrap();
        let out = run_busbar(&dir, &["--validate"]);
        let _ = std::fs::remove_dir_all(&dir);
        out
    };
    let refused = |stdout: &str, stderr: &str| {
        format!("{stdout}{stderr}").contains("token_url must use https for a public host")
    };
    let (code, stdout, stderr) = run("http://token.example.com/oauth2/token");
    assert_ne!(code, 0, "stdout={stdout} stderr={stderr}");
    assert!(
        refused(&stdout, &stderr),
        "an http token_url on a public host is refused at --validate: stdout={stdout} stderr={stderr}"
    );
    let (_, stdout, stderr) = run("http://127.0.0.1:9/oauth2/token");
    assert!(
        !refused(&stdout, &stderr),
        "an http token_url on loopback is 1.5.5's to allow: stdout={stdout} stderr={stderr}"
    );
}

#[cfg(all(linked_section_pools, linked_every_auth))]
fn validate_lane(tag: &str, api_key: &str, style: &str, extra: &str) -> (i32, String) {
    let dir = fixture_dir(tag);
    write_configs(&dir, "");
    let api_key = api_key.replace("{dir}", &dir.display().to_string());
    std::fs::write(
        dir.join("sa.json"),
        r#"{"client_email":"a@b","private_key":"not a key"}"#,
    )
    .unwrap();
    std::fs::write(dir.join("pair.txt"), "client-id:client-secret").unwrap();
    std::fs::write(
        dir.join("config.yaml"),
        format!(
            "listen: \"127.0.0.1:0\"\nstore: {{module: memory}}\nproviders:\n  mock:\n    \
             api_key: {api_key}\n    auth: {style}\n{extra}models:\n  test-model:\n    \
             provider: mock\n"
        ),
    )
    .unwrap();
    let (code, stdout, stderr) = run_busbar(&dir, &["--validate"]);
    let _ = std::fs::remove_dir_all(&dir);
    (code, format!("stdout={stdout} stderr={stderr}"))
}

#[cfg(all(linked_section_pools, linked_every_auth))]
#[test]
fn validate_refuses_a_malformed_oauth_client_credential_as_boot_does() {
    let (code, out) = validate_lane(
        "cred-shape",
        "{ env: MOCK_KEY }",
        "oauth-client-credentials",
        "    token_url: \"https://127.0.0.1/token\"\n    scope: oracle\n",
    );
    assert_eq!(code, 1, "{out}");
    assert!(
        out.contains("oauth-client-credentials credential")
            && out.contains("client_id:client_secret"),
        "the credential refusal is named: {out}"
    );
}

#[cfg(all(linked_section_pools, linked_every_auth))]
#[test]
fn validate_accepts_a_well_formed_oauth_client_credential() {
    let (code, out) = validate_lane(
        "cred-pair",
        "{ file: \"{dir}/pair.txt\" }",
        "oauth-client-credentials",
        "    token_url: \"https://127.0.0.1/token\"\n    scope: oracle\n",
    );
    assert_eq!(code, 0, "{out}");
    assert!(!out.contains("credential"), "no credential refusal: {out}");
}

#[cfg(all(linked_section_pools, linked_every_auth))]
#[test]
fn validate_refuses_a_malformed_jwt_bearer_service_account_as_boot_does() {
    let (code, out) = validate_lane("bad-key", "{ file: \"{dir}/sa.json\" }", "jwt-bearer", "");
    assert_eq!(code, 1, "{out}");
    assert!(
        out.contains("jwt-bearer credential (from ") && out.contains(") is invalid: "),
        "the credential refusal is named: {out}"
    );
}

#[cfg(all(linked_section_pools, linked_every_auth))]
#[test]
fn validate_names_an_unreadable_jwt_bearer_key_file_in_1_5_5s_words() {
    let (code, out) = validate_lane(
        "unreadable-key",
        "{ file: \"{dir}/pair.txt\" }",
        "jwt-bearer",
        "",
    );
    assert_eq!(code, 1, "{out}");
    assert!(
        out.contains("provider 'mock' jwt-bearer credential (from file:")
            && out.contains(") is invalid: could not read service-account key file"),
        "the unreadable key file is refused in 1.5.5's words: {out}"
    );
}

#[test]
fn validate_and_boot_refuse_a_reference_at_an_undeclared_plugin_field() {
    let dir = fixture_dir("undeclared-secret-ref");
    write_configs(
        &dir,
        "store:\n  module: memory\n  settings:\n    pool:\n      path: { env: MOCK_KEY }\n",
    );
    let refused = |all: &str| {
        all.contains("store.settings.pool.path")
            && all.contains("'memory'")
            && all.contains("did not declare it as a secret")
            && all.contains("write the value itself")
            && !all.contains("test-key-value")
    };
    let (code, stdout, stderr) = run_busbar(&dir, &["--validate"]);
    let all = format!("{stdout}{stderr}");
    assert_eq!(code, 1, "--validate must refuse: {all}");
    assert!(refused(&all), "--validate's sentence: {all}");

    let mut child = Command::new(env!("CARGO_BIN_EXE_busbar"))
        .env("MOCK_KEY", "test-key-value")
        .env(
            "BUSBAR_SIGNING_KEY",
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .env("BUSBAR_CONFIG", dir.join("config.yaml"))
        .env("BUSBAR_PROVIDERS", dir.join("providers.yaml"))
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn busbar");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    while child.try_wait().expect("poll").is_none() {
        if std::time::Instant::now() > deadline {
            let _ = child.kill();
            panic!("boot did not refuse the undeclared reference: it is still running");
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let out = child.wait_with_output().expect("boot output");
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!out.status.success(), "boot must refuse: {all}");
    assert!(refused(&all), "boot's sentence: {all}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(linked_section_tools)]
#[test]
fn validate_accepts_a_reference_at_a_planes_declared_wildcard_path() {
    let dir = fixture_dir("declared-wildcard-env");
    write_tools_only_configs(
        &dir,
        r#"tools:
  s:
    pin: { mechanism: unpinned }
    transport: stdio
    command: /usr/bin/true
    env:
      API_KEY: { env: MOCK_KEY }
      LOG_LEVEL: debug
"#,
    );
    let (code, stdout, stderr) = run_busbar(&dir, &["--validate"]);
    assert_eq!(
        code, 0,
        "a reference at a declared wildcard path validates: {stdout}{stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
