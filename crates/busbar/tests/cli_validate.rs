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

use std::path::{Path, PathBuf};
use std::process::Command;

/// A fresh, isolated fixture directory.
fn fixture_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "busbar-cli-validate-{}-{tag}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(d.join("plugins")).unwrap();
    d
}

/// A minimal VALID providers.yaml + config.yaml pair. `extra` is appended verbatim to config.yaml
/// (the governance/plugins blocks under test).
fn write_configs(dir: &Path, extra: &str) {
    std::fs::write(
        dir.join("providers.yaml"),
        r#"mock:
  protocol: anthropic
  base_url: "http://127.0.0.1:9"
  api_key_env: MOCK_KEY
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
{extra}"#
        ),
    )
    .unwrap();
}

/// Run the real busbar binary with the fixture's config env; returns (exit_code, stdout, stderr).
fn run_busbar(dir: &Path, args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_busbar"))
        .args(args)
        // `--validate` RESOLVES built-in secret refs, so the fixture's referenced var must be set.
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

/// An UNSIGNED (structurally valid) plugin tarball written into the fixture's plugins dir.
fn write_tarball(dir: &Path, file: &str, name: &str, alias: &str, lib: &[u8]) {
    let m = busbar_plugin_sign::Manifest {
        name: name.into(),
        alias: alias.into(),
        kind: "store".into(),
        version: "1.5.0".into(),
        publisher: "acme".into(),
        abi_version: *busbar_plugin_loader::supported_abi("store")
            .iter()
            .max()
            .expect("store abi"),
        sha256: busbar_plugin_sign::sha256_hex(lib),
        signature: String::new(),
        description: String::new(),
        homepage: String::new(),
        license: String::new(),
        needs: Default::default(),
        settings_schema: None,
        schema_derived: false,
        host: None,
    };
    let bytes = busbar_plugin_loader::tarball::package(&m, "lib.so", lib).unwrap();
    std::fs::write(dir.join("plugins").join(file), bytes).unwrap();
}

/// The plugins block pointing at this fixture's dir. Single-quoted: a double-quoted YAML scalar
/// interprets backslash escapes, and a Windows path's `.display()` output is backslash-separated
/// (e.g. `C:\Users\runneradmin\...`) -- `\U` alone parses as the start of an 8-hex-digit unicode
/// escape and hard-fails immediately, which is exactly what broke every plugins-block test on
/// Windows CI. Single-quoted YAML scalars never process backslashes at all; the temp paths here
/// are generated (pid + nanos), so they can't contain a literal `'` that would need escaping.
fn plugins_block(dir: &Path, enabled: bool, allow_unsigned: bool) -> String {
    format!(
        "plugins:\n  enabled: {enabled}\n  dir: '{}'\n  trust:\n    allow_unsigned: {allow_unsigned}\n",
        dir.join("plugins").display()
    )
}

/// Baseline: a valid config with no plugins block validates clean (exit 0) and reports plugins
/// disabled.
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

/// `--validate`'s "N env var(s) referenced but unset" note must appear exactly when a `${VAR}`
/// interpolation in config/providers resolves to an unset variable, and must name it. Closes an
/// uncovered branch: `if !unset_env_vars.is_empty()` at main.rs's note-printing site had zero
/// coverage of either branch (the baseline test above never referenced `${VAR}` syntax at all, so
/// it exercised neither "note present" nor a confirmed "note absent").
#[test]
fn validate_notes_unset_interpolated_env_vars_by_name() {
    let dir = fixture_dir("unsetenv");
    // Defensive: ensure the var is genuinely unset regardless of the ambient environment (this test
    // never sets it, only relies on its absence).
    std::env::remove_var("BUSBAR_CLI_VALIDATE_TEST_UNSET_VAR");
    // `${VAR}` interpolation runs on the RAW config text before YAML parsing (see
    // config::interpolate_env_with), so a reference inside a COMMENT is still recorded as
    // referenced/unset while being guaranteed structurally harmless -- no risk of the substituted
    // (empty) value landing in a real field and failing config validation for an unrelated reason.
    write_configs(
        &dir,
        "# smoke-tests unset-env-var interpolation: ${BUSBAR_CLI_VALIDATE_TEST_UNSET_VAR}\n",
    );
    let (code, stdout, stderr) = run_busbar(&dir, &["--validate"]);
    assert_eq!(
        code, 0,
        "an unset interpolation var is a note, not a failure: {stderr}"
    );
    assert!(
        stdout.contains("1 env var(s) referenced but unset here")
            && stdout.contains("BUSBAR_CLI_VALIDATE_TEST_UNSET_VAR"),
        "expected the unset-var note naming the variable, got: {stdout}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// FAIL-CLOSED on a BAD config.yaml: an unknown key exits 1 with the offending key named.
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

/// FAIL-CLOSED (hard requirement 1+2): `store.module: valkey` with plugins disabled exits 1
/// naming `plugins.enabled` — the exact same refusal boot performs.
#[test]
fn validate_fails_when_store_plugin_referenced_but_plugins_disabled() {
    let dir = fixture_dir("disabled");
    write_configs(&dir, "store:\n  module: valkey\n");
    let (code, _stdout, stderr) = run_busbar(&dir, &["--validate"]);
    assert_eq!(code, 1);
    assert!(
        stderr.contains("plugins.enabled"),
        "names the flag: {stderr}"
    );
    assert!(stderr.contains("valkey"), "names the store: {stderr}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Regression test for the config_validate/main.rs layering bug this session found and fixed:
/// `auth.chain` naming a plugin-shaped module that ISN'T actually installed must still fail
/// `--validate` (fail-closed end to end) -- just via the LATER, registry-aware check
/// (`preflight_plugins_and_secrets` in main.rs), not the earlier pre-registry `config_validate`
/// pass. Before the fix, `config_validate::validate` hard-rejected every non-`keys` chain module
/// unconditionally, which (as an unwanted side effect neither layer's own tests caught, since each
/// tested its own layer in isolation) meant a genuinely INSTALLED `kind: auth` plugin could never
/// pass either -- see `crates/busbar-core/src/config_validate/tests/tests.rs`'s
/// `test_validate_chain_unknown_module_rejected_keys_accepted` for that half of the regression
/// proof. This test proves the other half: with plugins enabled but nothing actually installed
/// under that name, `--validate` must STILL refuse, and the error must come from the registry-aware
/// layer (naming the plugins dir / what's loadable), not silently pass.
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

/// FAIL-CLOSED: ANY invalid tarball in an enabled plugins dir fails --validate naming the file,
/// even when no plugin is referenced by the config.
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

/// FAIL-CLOSED: a sha256-mismatched (tampered) manifest fails --validate with the integrity reason.
#[test]
fn validate_fails_on_sha_mismatch() {
    let dir = fixture_dir("sha");
    let m = busbar_plugin_sign::Manifest {
        name: "acme-store-x".into(),
        alias: "x".into(),
        kind: "store".into(),
        version: "1.5.0".into(),
        publisher: "acme".into(),
        abi_version: *busbar_plugin_loader::supported_abi("store")
            .iter()
            .max()
            .expect("store abi"),
        sha256: busbar_plugin_sign::sha256_hex(b"OTHER bytes"),
        signature: String::new(),
        description: String::new(),
        homepage: String::new(),
        license: String::new(),
        needs: Default::default(),
        settings_schema: None,
        schema_derived: false,
        host: None,
    };
    let bytes = busbar_plugin_loader::tarball::package(&m, "lib.so", b"real bytes").unwrap();
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

/// FAIL-CLOSED: referencing an UNSIGNED plugin store under the strict default posture exits 1
/// naming the opt-in flag; with allow_unsigned it validates clean and the summary reports the
/// validated plugin — proving --validate exercises the trust gate exactly as boot does.
#[test]
fn validate_trust_gate_matches_boot() {
    let dir = fixture_dir("trust");
    write_tarball(
        &dir,
        "sqlite.tar.gz",
        "busbar-store-sqlite",
        "sqlite",
        b"lib",
    );
    write_configs(
        &dir,
        &format!(
            "{}store:\n  module: sqlite\n",
            plugins_block(&dir, true, false)
        ),
    );
    let (code, _stdout, stderr) = run_busbar(&dir, &["--validate"]);
    assert_eq!(code, 1);
    assert!(
        stderr.contains("allow_unsigned"),
        "names the opt-in: {stderr}"
    );

    // Same fixture with the opt-in: clean.
    write_configs(
        &dir,
        &format!(
            "{}store:\n  module: sqlite\n",
            plugins_block(&dir, true, true)
        ),
    );
    let (code, stdout, stderr) = run_busbar(&dir, &["--validate"]);
    assert_eq!(code, 0, "stderr={stderr}");
    assert!(stdout.contains("1 validated"), "got {stdout}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// FAIL-CLOSED (conflict): two plugins claiming the same alias fail --validate naming BOTH.
#[test]
fn validate_fails_on_alias_conflict_naming_both() {
    let dir = fixture_dir("conflict");
    write_tarball(
        &dir,
        "a.tar.gz",
        "busbar-store-valkey-plugin",
        "valkey",
        b"a",
    );
    write_tarball(&dir, "b.tar.gz", "acme-store-valkey", "valkey", b"b");
    write_configs(&dir, &plugins_block(&dir, true, true));
    let (code, _stdout, stderr) = run_busbar(&dir, &["--validate"]);
    assert_eq!(code, 1);
    assert!(
        stderr.contains("busbar-store-valkey-plugin") && stderr.contains("acme-store-valkey"),
        "names both: {stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// `--list-plugins` prints a manifest-only inventory with the correct status per row — and exits 0
/// even over untrusted + invalid artifacts (nothing is loaded from listing).
#[test]
fn list_plugins_reports_statuses_without_loading() {
    let dir = fixture_dir("list");
    write_tarball(&dir, "good.tar.gz", "busbar-store-sqlite", "sqlite", b"g");
    write_tarball(&dir, "third.tar.gz", "acme-store-dynamo", "dynamo", b"t");
    std::fs::write(dir.join("plugins/junk.tar.gz"), b"garbage").unwrap();
    // allow_unsigned so the sqlite one is loadable; the store selects it.
    write_configs(
        &dir,
        &format!(
            "{}store:\n  module: sqlite\n",
            plugins_block(&dir, true, true)
        ),
    );
    let (code, stdout, _stderr) = run_busbar(&dir, &["--list-plugins"]);
    assert_eq!(code, 0, "list-plugins is informational: {stdout}");
    assert!(
        stdout.contains("LOADS (store.module: sqlite)"),
        "the selected store row: {stdout}"
    );
    assert!(stdout.contains("busbar-store-sqlite"), "{stdout}");
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
    // (1) name-only match.
    let dir = fixture_dir("list-name-match");
    write_tarball(
        &dir,
        "byname.tar.gz",
        "sqlite",
        "totally-different-alias",
        b"n",
    );
    write_configs(
        &dir,
        &format!(
            "{}store:\n  module: sqlite\n",
            plugins_block(&dir, true, true)
        ),
    );
    let (code, stdout, _stderr) = run_busbar(&dir, &["--list-plugins"]);
    assert_eq!(code, 0, "{stdout}");
    assert!(
        stdout.contains("LOADS (store.module: sqlite)"),
        "a NAME match alone (alias differs) must still select: {stdout}"
    );
    let _ = std::fs::remove_dir_all(&dir);

    // (2) matching name, but UNTRUSTED (not allow_unsigned) so status != "ready".
    let dir = fixture_dir("list-untrusted-match");
    write_tarball(&dir, "untrusted.tar.gz", "sqlite", "sqlite", b"u");
    write_configs(
        &dir,
        &format!(
            "{}store:\n  module: sqlite\n",
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

    // (3) matching name AND ready, but plugins.enabled: false.
    let dir = fixture_dir("list-disabled-match");
    write_tarball(&dir, "disabled.tar.gz", "sqlite", "sqlite", b"d");
    write_configs(
        &dir,
        &format!(
            "{}store:\n  module: sqlite\n",
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

/// `--migrate-config`'s CHANGES/WARNINGS/TODO sections are each printed only `if !out.X.is_empty()`
/// — a legacy config that triggers BOTH a change (`governance.db_path`) and a warning (an empty
/// `allowed_pools: []`, whose meaning flipped in 1.5.0) must print BOTH sections.
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

/// The inverse of the above: a legacy config with NEITHER a `governance.db_path` NOR any semantic-
/// flip warning must print NEITHER section (the `if !out.X.is_empty()` guards must actually gate,
/// not just always-print).
#[test]
fn migrate_config_omits_changes_and_warnings_sections_when_empty() {
    let dir = fixture_dir("migrate-clean");
    std::fs::create_dir_all(&dir).unwrap();
    let legacy = dir.join("legacy.yaml");
    std::fs::write(&legacy, "listen: \"127.0.0.1:8080\"\n").unwrap();

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

/// `plugins_preflight`'s three consistency gates (store/auth/hook each referencing a plugin module
/// while `plugins.enabled` stays at its default `false`) each guard on `!plugins_cfg.enabled` — a
/// deleted `!` would silently invert the gate (rejecting the NORMAL enabled case instead of the
/// actual misconfiguration). None of the three had any test coverage at all.
#[test]
fn validate_fails_when_a_plugin_is_referenced_but_plugins_are_disabled() {
    // store.module referencing a non-memory backend with plugins.enabled left at its default false.
    let dir = fixture_dir("gate-store");
    write_configs(&dir, "store:\n  module: sqlite\n");
    let (code, _stdout, stderr) = run_busbar(&dir, &["--validate"]);
    assert_eq!(code, 1, "{stderr}");
    assert!(
        stderr.contains("store.module: 'sqlite' requires the plugin subsystem")
            && stderr.contains("plugins.enabled is false"),
        "got {stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);

    // auth.chain naming a plugin module with plugins.enabled left at its default false.
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

    // A hook naming a plugin module with plugins.enabled left at its default false.
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

/// `plugins_preflight`'s store-resolution step (`Some(p) if p.manifest.kind == "store" => {}`) must
/// reject a resolved plugin of the WRONG kind, not silently accept it — `store.module` pointing (by
/// name/alias collision) at a `kind: hook` plugin is a real misconfiguration class, not a manifest
/// integrity failure, so it needs its own named error rather than falling through as if it loaded.
#[test]
fn validate_fails_when_store_module_resolves_to_a_non_store_plugin_kind() {
    let dir = fixture_dir("wrongkind");
    let m = busbar_plugin_sign::Manifest {
        name: "acme-hook-x".into(),
        alias: "x".into(),
        kind: "hook".into(),
        version: "1.5.0".into(),
        publisher: "acme".into(),
        abi_version: *busbar_plugin_loader::supported_abi("hook")
            .iter()
            .max()
            .expect("hook abi"),
        sha256: busbar_plugin_sign::sha256_hex(b"real bytes"),
        signature: String::new(),
        description: String::new(),
        homepage: String::new(),
        license: String::new(),
        needs: Default::default(),
        settings_schema: None,
        schema_derived: false,
        host: None,
    };
    let bytes = busbar_plugin_loader::tarball::package(&m, "lib.so", b"real bytes").unwrap();
    std::fs::write(dir.join("plugins/x.tar.gz"), bytes).unwrap();
    // store.module: "x" resolves by ALIAS to the hook plugin above, not any store plugin.
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

/// BUG #2 (1.5.1): busbar no longer auto-generates a signing key at boot. When the data-plane chain
/// names the built-in `keys` verifier, `auth.signing_key` is REQUIRED and its absence FAILS
/// `--validate` (fail-closed) with an actionable message — and NOTHING is ever written to disk.
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
    // FAIL-CLOSED, not generate-into-a-read-only-dir: no key file may be written anywhere.
    assert!(
        !dir.join("busbar-signing.key").exists(),
        "busbar must NOT write a signing key (the boot-loop bug being fixed)"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A `keys` chain WITH an `auth.signing_key` secret reference validates clean — and `--validate`
/// never generates or persists a key (the secret is resolved at BOOT, not here).
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

/// `busbar --generate-signing-key` mints a fresh 64-hex ed25519 secret to STDOUT (guidance to
/// stderr), writes NOTHING, and the key — once written to a file and referenced from
/// `auth.signing_key` — makes a `keys`-chain config validate clean.
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
    // Write it to a file and REFERENCE it (auth.signing_key is a ref, never inline); the config
    // must then validate clean.
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

/// Run busbar against a fixture whose config.yaml points `config.overlay.file` at the given overlay —
/// the full-config-coverage persistence path a real deployment uses. (Pre-1.6.0 this used the
/// `BUSBAR_CONFIG_OVERLAY` env var; that var was deprecated in 1.5.3 and removed in 1.6.0, so the
/// overlay is now named the same way production names it: `config.overlay.file` in config.yaml. This
/// helper REWRITES config.yaml to append that pointer, so callers can keep writing a plain config via
/// `write_configs(&dir, "")` first.)
fn run_busbar_with_overlay(dir: &Path, overlay: &Path, args: &[&str]) -> (i32, String, String) {
    // Append the overlay pointer to the fixture's config.yaml. Single-quoted YAML scalar so a Windows
    // backslash path is never treated as an escape (mirrors `plugins_block`).
    let config_path = dir.join("config.yaml");
    let mut config = std::fs::read_to_string(&config_path).expect("read fixture config.yaml");
    // Idempotent: some tests run this helper twice against the same fixture dir (e.g. once plain, once
    // `--safe-mode`); appending the block twice would duplicate the top-level `config:` key.
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
        // `--validate` RESOLVES built-in secret refs, so the fixture's referenced var must be set.
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

/// 1.5.0 FULL-CONFIG COVERAGE: `--validate` validates the EFFECTIVE config INCLUDING the overlay's
/// `root` section (API-set single-value config). A root override that resolves but fails semantic
/// validation (here: a DESCENDING `reasoning_effort_budgets`) must fail `--validate` exactly as a
/// hand-written config.yaml would — the durable-validation invariant. And `--safe-mode` quarantines
/// the whole overlay (root included), so the same bad overlay validates clean under safe mode.
#[test]
fn validate_applies_and_rejects_a_bad_root_overlay() {
    let dir = fixture_dir("rootovl");
    write_configs(&dir, "");
    let overlay = dir.join("overlay.json");
    // A root override that RESOLVES fine but FAILS config_validate (budgets must be ascending).
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
    // SAFE MODE quarantines the overlay — the bad root is not applied, so validate is clean.
    let (code, stdout, stderr) =
        run_busbar_with_overlay(&dir, &overlay, &["--validate", "--safe-mode"]);
    assert_eq!(
        code, 0,
        "--safe-mode ignores the overlay root: stdout={stdout} stderr={stderr}"
    );
    assert!(stdout.contains("ok: config valid"), "got {stdout}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A VALID root overlay (a live-swappable per_request_fee + a well-formed limits override) validates
/// CLEAN — the effective config resolves + passes semantic validation with the overrides merged in.
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

/// The `BUSBAR_CONFIG_OVERLAY` env var was deprecated in 1.5.3 and REMOVED in 1.6.0: it no longer
/// selects the overlay. Point it at a BAD overlay (one that would fail `--validate` if applied) and
/// set NO `config.overlay.file`; validate must pass, proving the env var is ignored. Pre-1.6.0 the
/// env var would have applied the overlay and this run would exit 1.
#[test]
fn validate_ignores_removed_busbar_config_overlay_env_var() {
    let dir = fixture_dir("ovlenvgone");
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
        // The removed env var — must have NO effect on overlay resolution.
        .env("BUSBAR_CONFIG_OVERLAY", &bad_overlay)
        .output()
        .expect("run busbar");
    let code = out.status.code().unwrap_or(-1);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        code, 0,
        "the removed BUSBAR_CONFIG_OVERLAY env var must be ignored, so the bad overlay is NOT \
         applied and validate passes: {stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// B1, THE END-TO-END PROOF: a config whose OAuth confidential-client secret references an env var
/// that is NOT SET must exit 1 from `--validate`.
///
/// `identity-providers.<name>.browser_login.client_secret` is a `SecretRef` like any other, and the
/// core itself presents it during the code-to-token exchange. It was absent from
/// `config_validate::secret_refs`, which was a hand-written list of paths, so `--validate` walked
/// straight past it and printed `ok: config valid` with exit 0 for a deployment whose every hosted
/// login would fail at runtime. The list now fails CLOSED: it is derived from exhaustive
/// destructures the compiler enforces, backed by a source scan that fails when a new secret-bearing
/// TYPE appears.
///
/// The env var is removed explicitly rather than merely left unset, so an unrelated variable in the
/// developer's or the runner's environment can never turn this test green by accident.
///
/// Gated on `auth-admin-tokens` because the FIXTURE cannot exist without it: the identity provider
/// this test configures is `module: admin-tokens`, which that feature compiles out entirely. Built
/// without it, `--validate` fails EARLIER — "an admin-tokens token is configured but this binary
/// was built WITHOUT the `auth-admin-tokens` feature" — so the run never reaches the secret check
/// and the assertion below fails against an error about something else. The B1 behaviour under test
/// is feature-independent; only this fixture is not. `docs_examples.rs` gates its whole file on the
/// same feature for the same reason.
#[cfg(feature = "auth-admin-tokens")]
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
             \x20 admin_auth: [admin-tokens]\n"
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

/// `--validate` REFUSES A PUBLISHED-NAME COLLISION, driven through the REAL binary.
///
/// `tools_allow.<tool>.publish_as:` is an optional override of the `{server}_{tool}` wire name, and
/// the invariant it moves off construction — one published name resolving to exactly one
/// `(server, tool)` — is now kept by validation. A validation that boot runs and `--validate` does
/// not is worse than no validation: an operator would dry-run green in CI and watch the same file
/// refuse to boot. Both reach `config::resolve`, and driving the binary is what proves it rather
/// than asserting it.
///
/// THE COLLISION UNDER TEST IS THE SUBTLE ONE — an override against a namespaced default nobody
/// typed (`publish_as: foo_bar` versus server `foo`'s tool `bar`). A check that compared overrides
/// only to each other would exit 0 here and look correct doing it.
///
/// GATED ON `plane-mcp` because the collision check itself lives in `busbar-mcp` and is compiled
/// out with the plane: a `--no-default-features` binary has no `tools:` plane to collide in, so
/// `--validate` exiting 0 there is the correct answer, not the missed refusal this test exists to
/// pin. Same shape as the `auth-admin-tokens` gate above.
#[cfg(feature = "plane-mcp")]
#[test]
fn validate_refuses_a_publish_as_collision_with_a_namespaced_default() {
    let dir = fixture_dir("publish-as-collision");
    write_configs(
        &dir,
        r#"tools:
  foo:
    url: "https://foo.internal/mcp"
    pin: { mechanism: unpinned }
    tools_allow: { bar: {} }
  other:
    url: "https://other.internal/mcp"
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
    // BOTH claimants named — one is a line the operator typed, the other is a name the DEFAULT
    // produced, and an error that named only the typed one would send them looking for a second
    // `publish_as:` that does not exist.
    assert!(all.contains("tools.foo.tools_allow.bar"), "{all}");
    assert!(
        all.contains("tools.other.tools_allow.anything.publish_as"),
        "{all}"
    );

    // GREEN, one name changed and nothing else: the refusal is about the collision, not about
    // `publish_as:` existing. Without this half the test above is satisfied by a build that refuses
    // every override.
    write_configs(
        &dir,
        r#"tools:
  foo:
    url: "https://foo.internal/mcp"
    pin: { mechanism: unpinned }
    tools_allow: { bar: {} }
  other:
    url: "https://other.internal/mcp"
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

/// THE OPERATOR-VISIBLE PROTOCOL ORDER, PINNED ON THE SHIPPED BINARY.
///
/// This sequence is load-bearing twice: it is the `must be one of:` tail an operator reads on a bad
/// `protocol:`, and `telemetry` banks one metric family per entry and finds it again BY POSITION,
/// so a reordering silently re-points every dashboard series behind the moved entry. Nothing inside
/// `busbar-core` can pin it — core's test build resolves the dialects from its own built-in table,
/// while the SHIPPED order is `merged_boot_decls(busbar_llm::DECLS ++ mcp, remaining built-ins)`,
/// which only exists once the composition root has run. So it is pinned here, black-box, on the
/// real binary, by reading the refusal an operator would read.
///
/// This is the assertion the LLM consolidation had to satisfy. Folding six per-dialect crates into
/// one plugin moves every one of them from core's built-in table into the installed set, and the
/// installed set is folded AHEAD of the built-ins — so a naive fold reorders the list. It was
/// measured doing exactly that during this work (cohere went from slot 6 to slot 2). The order is
/// preserved by taking the dialects out in the built-in table's own order and appending each to
/// `busbar_llm::DECLS`, which keeps the installed set a PREFIX of the operator-visible list at
/// every step; this test is what makes that a checked property rather than a careful intention.
#[test]
fn the_operator_visible_protocol_order_is_exactly_the_shipped_one() {
    let d = fixture_dir("protocol-order");
    write_configs(&d, "");
    // Point the provider at a protocol that cannot exist, so the refusal lists the real ones.
    std::fs::write(
        d.join("providers.yaml"),
        r#"mock:
  protocol: definitely-not-a-protocol
  base_url: "http://127.0.0.1:9"
  api_key_env: MOCK_KEY
"#,
    )
    .unwrap();
    let (code, out, err) = run_busbar(&d, &["--validate"]);
    let all = format!("{out}{err}");
    assert_ne!(code, 0, "an unknown protocol must fail validation: {all}");
    assert!(
        all.contains("must be one of: anthropic, gemini, openai, bedrock, responses, cohere"),
        "the operator-visible protocol order changed. It is a metric-family index as well as a \
         config-error string, so this is not cosmetic — see this test's doc. Got: {all}"
    );
}

/// Run the real binary with the standard secret env + a CHOSEN `BUSBAR_CONFIG` (or none), plus
/// arbitrary extra args and env pairs — the flexible harness the 1.6.0 flag-precedence tests need
/// (they vary the config/providers inputs beyond what `run_busbar` fixes). Returns (code, stdout,
/// stderr).
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

/// 1.6.0 FLAG-FIRST (config): `-c`/`--config <path>` OVERRIDES `BUSBAR_CONFIG` and the compiled-in
/// default. `BUSBAR_CONFIG` points at a BOGUS (nonexistent) path; the flag names the real config, and
/// `--validate` must succeed AND report the flag's path — proving the flag won over the env layer.
#[test]
fn config_flag_overrides_env_and_default() {
    let dir = fixture_dir("cfgflag");
    // Real config (+ providers.yaml next to it, the default catalog location) in its own subdir.
    let real = dir.join("real");
    std::fs::create_dir_all(real.join("plugins")).unwrap();
    write_configs(&real, "");
    let real_config = real.join("config.yaml");
    let bogus = dir.join("bogus").join("config.yaml"); // never created

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

/// 1.6.0 FLAG-FIRST (providers): `--providers <path>` OVERRIDES `providers_file:` in config.yaml and
/// the default catalog. The config declares a NONEXISTENT `providers_file:` and has NO providers.yaml
/// beside it, so without the flag `--validate` fails; with `--providers <real>` it succeeds and reports
/// the flag's catalog — proving the flag won over `providers_file:`.
#[test]
fn providers_flag_overrides_providers_file_and_default() {
    let dir = fixture_dir("provflag");
    // config in its own dir, declaring a providers_file that does not exist, and NO providers.yaml
    // beside it (so neither providers_file nor the default catalog resolves).
    let cfgdir = dir.join("cfg");
    std::fs::create_dir_all(&cfgdir).unwrap();
    let config = cfgdir.join("config.yaml");
    std::fs::write(
        &config,
        "listen: \"127.0.0.1:0\"\n\
         providers:\n\
         \x20 mock:\n\
         \x20   api_key: { env: MOCK_KEY }\n\
         models:\n\
         \x20 test-model:\n\
         \x20   provider: mock\n\
         providers_file: does-not-exist.yaml\n",
    )
    .unwrap();
    // The REAL catalog lives elsewhere, reachable ONLY via --providers.
    let real_catalog = dir.join("real-providers.yaml");
    std::fs::write(
        &real_catalog,
        "mock:\n  protocol: anthropic\n  base_url: \"http://127.0.0.1:9\"\n  api_key_env: MOCK_KEY\n",
    )
    .unwrap();

    // Baseline: without --providers, the nonexistent providers_file fails validation.
    let (code, _stdout, stderr) = run_cli(Some(&config), &["--validate"], &[]);
    assert_eq!(
        code, 1,
        "a providers_file pointing at a missing catalog must fail --validate: {stderr}"
    );

    // --providers overrides providers_file → validate OK, naming the flag's catalog.
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

/// 1.6.0 REMOVAL: the `BUSBAR_PROVIDERS` env var is NO LONGER honored. With it set to a BOGUS
/// (nonexistent) path but a valid providers.yaml at the DEFAULT location (next to config.yaml),
/// `--validate` must still succeed and use the DEFAULT catalog — if the env var were still read, the
/// bogus path would fail the load. This pins the deprecation removal (deprecated 1.5.3, removed 1.6.0).
#[test]
fn busbar_providers_env_is_no_longer_honored() {
    let dir = fixture_dir("provenvgone");
    write_configs(&dir, ""); // config.yaml + providers.yaml (the default catalog) both in `dir`
    let config = dir.join("config.yaml");
    let default_catalog = dir.join("providers.yaml");
    let bogus = dir.join("bogus-providers.yaml"); // never created

    let (code, stdout, stderr) = run_cli(
        Some(&config),
        &["--validate"],
        &[("BUSBAR_PROVIDERS", bogus.to_str().unwrap())],
    );
    assert_eq!(
        code, 0,
        "BUSBAR_PROVIDERS must be IGNORED in 1.6.0; the default providers.yaml next to config must \
         resolve despite the bogus env value: stdout={stdout} stderr={stderr}"
    );
    assert!(stdout.contains("ok: config valid"), "got {stdout}");
    assert!(
        stdout.contains(default_catalog.to_str().unwrap()),
        "the default catalog (next to config) must be used, NOT the bogus BUSBAR_PROVIDERS value: {stdout}"
    );
    assert!(
        !stdout.contains(bogus.to_str().unwrap()),
        "the removed BUSBAR_PROVIDERS value must not appear anywhere: {stdout}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
