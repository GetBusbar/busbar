// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

mod linked;

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/upgrade_1_5_5")
        .join(name)
}

fn workdir(tag: &str) -> PathBuf {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let d = std::env::temp_dir().join(format!(
        "busbar-upgrade-1-5-5-{}-{tag}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(
        d.join("providers.yaml"),
        "mock:\n  protocol: anthropic\n  base_url: \"https://mock.example\"\n",
    )
    .unwrap();
    d
}

fn validate(dir: &Path, config: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_busbar"))
        .arg("--validate")
        .arg("--providers")
        .arg(dir.join("providers.yaml"))
        .env("BUSBAR_CONFIG", config)
        .env("MOCK_KEY", "k")
        .env_remove("BUSBAR_T_UPGRADE_UNSET_KEY")
        .output()
        .expect("run busbar --validate")
}

fn migrate(path: &Path) -> (String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_busbar"))
        .arg("--migrate-config")
        .arg(path)
        .env_remove("BUSBAR_T_UPGRADE_UNSET_KEY")
        .output()
        .expect("run busbar --migrate-config");
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_eq!(out.status.code(), Some(0), "migrates; stderr:\n{stderr}");
    (String::from_utf8_lossy(&out.stdout).into_owned(), stderr)
}

fn migrate_and_validate(name: &str) -> (String, String, String) {
    let dir = workdir(name);
    let (yaml, summary) = migrate(&fixture(name));
    let migrated = dir.join("config.yaml");
    std::fs::write(&migrated, &yaml).unwrap();
    let out = validate(&dir, &migrated);
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_eq!(
        out.status.code(),
        Some(0),
        "the migrated {name} validates; stderr:\n{stderr}\n--- migrated ---\n{yaml}"
    );
    let _ = std::fs::remove_dir_all(&dir);
    (yaml, summary, stderr)
}

fn validate_as_written(name: &str) -> Output {
    let dir = workdir(name);
    let out = validate(&dir, &fixture(name));
    let _ = std::fs::remove_dir_all(&dir);
    out
}

fn yaml(text: &str) -> serde_yaml::Value {
    serde_yaml::from_str(text).expect("YAML")
}

#[test]
fn a_1_5_5_rate_card_without_units_migrates_to_one_that_bills_the_same() {
    let raw = validate_as_written("rate_card.yaml");
    let stderr = String::from_utf8_lossy(&raw.stderr);
    assert_eq!(
        raw.status.code(),
        Some(1),
        "refused as written; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("does not configure billable unit(s)"),
        "refused for its unpriced units; stderr:\n{stderr}"
    );

    let (migrated, summary, _) = migrate_and_validate("rate_card.yaml");
    let doc = yaml(&migrated);
    let entry = &doc["rate_card"]["test-model"];
    assert_eq!(entry["input_utok"], yaml("3.0"), "token prices are kept");
    assert_eq!(entry["output_utok"], yaml("15.0"), "token prices are kept");
    let units = entry["units"]
        .as_mapping()
        .unwrap_or_else(|| panic!("units were added:\n{migrated}"));
    assert!(!units.is_empty(), "units were added:\n{migrated}");
    assert!(
        units.values().all(|v| v == &yaml("0")),
        "every added unit is priced at 0, as 1.5.5 billed it:\n{migrated}"
    );
    assert!(
        summary.contains("  - rate_card.test-model.units: added ")
            && summary.contains("1.5.5 billed these units at nothing"),
        "one change line names it and why; stderr:\n{summary}"
    );
}

#[test]
fn a_1_5_5_metadata_entry_naming_no_host_migrates_away() {
    let raw = validate_as_written("metadata_no_host.yaml");
    let stderr = String::from_utf8_lossy(&raw.stderr);
    if raw.status.code() != Some(0) {
        assert!(
            stderr.contains("'db.1'"),
            "a refusal of the entry as written names it; stderr:\n{stderr}"
        );
    }

    let (migrated, summary, stderr) = migrate_and_validate("metadata_no_host.yaml");
    assert_eq!(
        yaml(&migrated)["security"]["blocked_metadata_hosts"],
        yaml("['169.254.169.254']"),
        "only the entry that named no host is removed:\n{migrated}"
    );
    assert!(
        !stderr.contains("db.1"),
        "the migrated configuration says nothing about it; stderr:\n{stderr}"
    );
    assert!(
        summary.contains("  - security.blocked_metadata_hosts: removed entry 'db.1' ")
            && summary.contains("never matched any destination on 1.5.5"),
        "one change line names it and why; stderr:\n{summary}"
    );
}

#[test]
fn a_1_5_5_provider_with_no_bindings_keeps_its_users_after_migration() {
    use busbar_kernel::config::{deploy_from_yaml_str, resolve, DeployCfg, ProviderDef};
    linked::install();
    let raw = std::fs::read_to_string(fixture("ungoverned_principals.yaml")).unwrap();
    let defs: std::collections::HashMap<String, ProviderDef> =
        serde_yaml::from_str("mock:\n  protocol: anthropic\n  base_url: https://mock.example\n")
            .expect("provider defs parse");
    let resolved = |text: &str| {
        let deploy: DeployCfg =
            deploy_from_yaml_str(text).unwrap_or_else(|e| panic!("the config parses: {e}\n{text}"));
        let cfg = resolve(&deploy, &defs).unwrap_or_else(|e| panic!("resolves: {e:?}\n{text}"));
        busbar_kernel::config_validate::validate(&cfg)
            .unwrap_or_else(|e| panic!("validates: {e:?}\n{text}"));
        cfg
    };
    let user = |roles: &[&str]| busbar_kernel::auth::Principal {
        id: "alice".into(),
        name: None,
        roles: roles.iter().map(|r| r.to_string()).collect(),
        ttl_secs: None,
    };
    let admitted = |cfg: &busbar_kernel::config::RootCfg, roles: &[&str]| {
        let bindings = &cfg.auth.as_ref().expect("an auth block").role_bindings;
        busbar_kernel::governance::synthesize_bound_key("corp", &user(roles), bindings)
    };

    let before = resolved(&raw);
    assert!(admitted(&before, &[]).is_none() && admitted(&before, &["eng"]).is_none());

    let out = busbar_kernel::config::migrate::migrate_config(&raw).expect("migrates");
    assert!(
        out.changes
            .iter()
            .any(|c| c.starts_with("auth.role_bindings.corp.\"*\": added")),
        "one change line names it: {:?}",
        out.changes
    );
    assert!(
        out.warnings
            .iter()
            .any(|w| w.contains("keep 1.5.5's access")),
        "a warning says it keeps 1.5.5's access and should be tightened: {:?}",
        out.warnings
    );
    let after = resolved(&out.yaml);
    for roles in [&[][..], &["eng"][..]] {
        let key = admitted(&after, roles)
            .unwrap_or_else(|| panic!("a user with roles {roles:?} is admitted, as on 1.5.5"));
        assert!(key.allowed_scopes.is_none(), "on every pool, as on 1.5.5");
        assert!(key.group.is_none(), "with no budget, as on 1.5.5");
    }
}
