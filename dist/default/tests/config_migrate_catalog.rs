// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A 1.5.5 PROVIDERS CATALOG WITH A STRAY KEY STILL BOOTS AFTER THE MIGRATION (owner ruling
//! 2026-10-27). 1.5.5 ignored a `providers.yaml` entry's key its grammar does not read; 1.6.0
//! refuses it. `busbar --migrate-config` writes the catalog without it beside the old one, names it
//! in `providers_file:`, and prints one line per removed key. Against the real binary.

use std::path::PathBuf;
use std::process::Command;

fn workdir() -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "busbar-migrate-catalog-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(
        d.join("config.yaml"),
        "listen: \"127.0.0.1:0\"\nstore: { module: memory }\nproviders:\n  mock:\n    api_key: { \
         env: MOCK_KEY }\nmodels:\n  test-model:\n    provider: mock\n",
    )
    .unwrap();
    std::fs::write(
        d.join("providers.yaml"),
        "mock:\n  protocol: anthropic\n  base_url: \"https://mock.example\"\n  notes: kept by \
         hand in 1.5.5\n",
    )
    .unwrap();
    d
}

#[test]
fn a_stray_catalog_key_is_removed_into_a_catalog_the_migrated_config_names() {
    let dir = workdir();
    let out = Command::new(env!("CARGO_BIN_EXE_busbar"))
        .arg("--migrate-config")
        .arg(dir.join("config.yaml"))
        .env_remove("BUSBAR_PROVIDERS")
        .output()
        .expect("run busbar --migrate-config");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_eq!(out.status.code(), Some(0), "migrates; stderr:\n{stderr}");
    assert!(
        stderr.contains("mock.notes: removed (a catalog entry does not read this key: 1.5.5 ignored it"),
        "one line names the stray key and why; stderr:\n{stderr}"
    );
    let migrated = std::fs::read_to_string(dir.join("providers.migrated.yaml"))
        .expect("the migrated catalog is written beside the old one");
    assert!(!migrated.contains("notes"), "{migrated}");
    assert!(migrated.contains("mock.example"), "{migrated}");
    let old = std::fs::read_to_string(dir.join("providers.yaml")).unwrap();
    assert!(old.contains("notes"), "the old catalog is left as it was");
    let doc: serde_yaml::Value = serde_yaml::from_str(
        &stdout
            .lines()
            .filter(|l| !l.starts_with('#'))
            .collect::<Vec<_>>()
            .join("\n"),
    )
    .expect("YAML");
    assert_eq!(
        doc["providers_file"],
        serde_yaml::Value::from("providers.migrated.yaml"),
        "the migrated config names the migrated catalog:\n{stdout}"
    );
    std::fs::write(dir.join("config.migrated.yaml"), &stdout).unwrap();
    let v = Command::new(env!("CARGO_BIN_EXE_busbar"))
        .arg("--validate")
        .env("BUSBAR_CONFIG", dir.join("config.migrated.yaml"))
        .env_remove("BUSBAR_PROVIDERS")
        .env("MOCK_KEY", "k")
        .output()
        .expect("run busbar --validate");
    assert_eq!(
        v.status.code(),
        Some(0),
        "the migrated deployment validates; stderr:\n{}",
        String::from_utf8_lossy(&v.stderr)
    );
    let _ = std::fs::remove_dir_all(&dir);
}
