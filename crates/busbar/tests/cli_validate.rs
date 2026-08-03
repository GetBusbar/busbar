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
/// interpolation in config/providers resolves to an unset variable, and must name it. Closes a
/// mutation-testing gap: `if !unset_env_vars.is_empty()` at main.rs's note-printing site had zero
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

/// FAIL-CLOSED (hard requirement 1+2): `store.module: redis` with plugins disabled exits 1
/// naming `plugins.enabled` — the exact same refusal boot performs.
#[test]
fn validate_fails_when_store_plugin_referenced_but_plugins_disabled() {
    let dir = fixture_dir("disabled");
    write_configs(&dir, "store:\n  module: redis\n");
    let (code, _stdout, stderr) = run_busbar(&dir, &["--validate"]);
    assert_eq!(code, 1);
    assert!(
        stderr.contains("plugins.enabled"),
        "names the flag: {stderr}"
    );
    assert!(stderr.contains("redis"), "names the store: {stderr}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Regression test for the config_validate/main.rs layering bug this session found and fixed:
/// `auth.chain` naming a plugin-shaped module that ISN'T actually installed must still fail
/// `--validate` (fail-closed end to end) -- just via the LATER, registry-aware check
/// (`preflight_plugins_and_secrets` in main.rs), not the earlier pre-registry `config_validate`
/// pass. Before the fix, `config_validate::validate` hard-rejected every non-`keys` chain module
/// unconditionally, which (as an unwanted side effect neither layer's own tests caught, since each
/// tested its own layer in isolation) meant a genuinely INSTALLED `kind: auth` plugin could never
/// pass either -- see `crates/busbar/src/config_validate/tests/tests.rs`'s
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
            "auth:\n  chain:\n    - oidc:\n        settings: {{}}\n{}",
            plugins_block(&dir, true, true)
        ),
    );
    let (code, _stdout, stderr) = run_busbar(&dir, &["--validate"]);
    assert_eq!(
        code, 1,
        "an auth.chain module with no matching installed plugin must fail --validate: {stderr}"
    );
    assert!(
        stderr.contains("does not match any plugin") || stderr.contains("was not loaded"),
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
    write_tarball(&dir, "a.tar.gz", "busbar-store-redis", "redis", b"a");
    write_tarball(&dir, "b.tar.gz", "acme-store-redis", "redis", b"b");
    write_configs(&dir, &plugins_block(&dir, true, true));
    let (code, _stdout, stderr) = run_busbar(&dir, &["--validate"]);
    assert_eq!(code, 1);
    assert!(
        stderr.contains("busbar-store-redis") && stderr.contains("acme-store-redis"),
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
    write_configs(&dir, "auth:\n  chain:\n    - oidc\n");
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
        "global_hooks:\n  - kind: tap\n    module: webrequest\n    prompt: ro\n",
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
        "auth:\n  chain:\n    - keys\n  signing_key: { env: BUSBAR_SIGNING_KEY }\n",
    );
    let (code, stdout, stderr) = run_busbar(&dir, &["--validate"]);
    assert_eq!(
        code, 0,
        "a `keys` chain WITH a signing_key ref validates clean: {stderr}"
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
            "auth:\n  chain:\n    - keys\n  signing_key: {{ file: '{}' }}\n",
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

/// Run busbar with an ADDITIONAL `BUSBAR_CONFIG_OVERLAY` pointing at a fixture overlay file — the
/// 1.5.0 full-config-coverage persistence path a real deployment uses.
fn run_busbar_with_overlay(dir: &Path, overlay: &Path, args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_busbar"))
        .args(args)
        .env("BUSBAR_CONFIG", dir.join("config.yaml"))
        .env("BUSBAR_PROVIDERS", dir.join("providers.yaml"))
        .env("BUSBAR_CONFIG_OVERLAY", overlay)
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
