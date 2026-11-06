// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

mod common;

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
    let out = Command::new(common::boot::exe())
        .arg("--migrate-config")
        .arg(dir.join("config.yaml"))
        .env_remove("BUSBAR_PROVIDERS")
        .output()
        .expect("run busbar --migrate-config");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_eq!(out.status.code(), Some(0), "migrates; stderr:\n{stderr}");
    assert!(
        stderr.contains(
            "mock.notes: removed (1.5.5 ignored this catalog key; removing it preserves the legacy behavior)"
        ),
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
    let v = Command::new(common::boot::exe())
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

#[test]
fn real_1_5_5_migration_captures_launch_overrides_and_preserves_signed_key_reference() {
    let dir = workdir();
    let launch = dir.join("launch");
    std::fs::create_dir(&launch).unwrap();
    std::fs::write(launch.join("from-env.yaml"), "{}\n").unwrap();
    std::fs::write(
        dir.join("config.yaml"),
        "\
store: { module: memory }
providers_file: from-config.yaml
providers: {}
models: {}
auth:
  chain: [keys]
  signing_key: { env: EXISTING_SIGNING_KEY }
  admin_auth: [admin-tokens]
identity-providers:
  admin-tokens:
    module: admin-tokens
    token: { env: EXISTING_ADMIN_TOKEN }
advanced:
  worker_threads: 7
  upstream_http1_only: true
  upstream_h2_prior_knowledge: false
",
    )
    .unwrap();
    let out = Command::new(common::boot::exe())
        .current_dir(&launch)
        .arg("--migrate-config")
        .arg(dir.join("config.yaml"))
        .env("BUSBAR_PROVIDERS", "from-env.yaml")
        .env("BUSBAR_WORKER_THREADS", "5")
        .env("BUSBAR_UPSTREAM_HTTP1_ONLY", "0")
        .env("BUSBAR_UPSTREAM_H2_PRIOR_KNOWLEDGE", "1")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    assert!(stderr.contains("to the 1.6.0 config shape"), "{stderr}");
    assert!(
        !stderr.contains("1.x virtual keys do not carry over"),
        "{stderr}"
    );
    let doc: serde_yaml::Value = serde_yaml::from_slice(&out.stdout).unwrap();
    assert_eq!(
        doc["providers_file"].as_str(),
        launch.join("from-env.yaml").to_str()
    );
    assert_eq!(doc["advanced"]["worker_threads"], 5);
    assert_eq!(doc["advanced"]["upstream_http1_only"], false);
    assert_eq!(doc["advanced"]["upstream_h2_prior_knowledge"], true);
    assert_eq!(doc["auth"]["signing_key"]["env"], "EXISTING_SIGNING_KEY");
    std::fs::write(dir.join("config.migrated.yaml"), &out.stdout).unwrap();
    // Retired runtime input cannot redirect a validated deployment back to another catalog.
    let out = Command::new(common::boot::exe())
        .arg("--validate")
        .arg("--config")
        .arg(dir.join("config.migrated.yaml"))
        .env("BUSBAR_PROVIDERS", dir.join("does-not-exist.yaml"))
        .env("EXISTING_SIGNING_KEY", "77".repeat(32))
        .env("EXISTING_ADMIN_TOKEN", "existing-admin-token")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    std::fs::remove_dir_all(dir).unwrap();
}
