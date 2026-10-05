// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Q-STORE = (B) (owner ruling 2026-09-27, BUSBAR-1.6.0.md Appendix B; THE DESIGN §4), at the
//! outermost surface — the REAL binary over the no-store fixture (`fixtures/no_store_1_5_5.yaml`):
//!
//! 1. `busbar --validate` REFUSES a config with no `store:` block (exit 1), naming the store to add
//!    and the migration that adds it.
//! 2. `busbar --migrate-config` inserts `store: {module: memory}` and says so.
//! 3. The migrated config validates.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/no_store_1_5_5.yaml"
);

/// A fresh, isolated directory holding the fixture's providers catalog.
fn workdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "busbar-store-required-{}-{tag}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(
        d.join("providers.yaml"),
        "mock:\n  protocol: anthropic\n  base_url: \"http://127.0.0.1:9\"\n  api_key_env: MOCK_KEY\n",
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
        .output()
        .expect("run busbar --validate")
}

/// RED: `--validate` refuses the no-store fixture with the store-required line. Without the
/// refusal the fixture validates (exit 0) and the first assertion fails.
#[test]
fn validate_refuses_a_config_without_a_store_block() {
    let dir = workdir("refuse");
    let out = validate(&dir, Path::new(FIXTURE));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "refused; stderr:\n{stderr}");
    assert!(
        stderr.contains(
            "  - store is required; add a `store:` block, e.g. `store: {module: memory}`"
        ),
        "the refusal names the store to add; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains(
            "run `busbar --migrate-config <config.yaml>`, which inserts `store: {module: memory}`"
        ),
        "the refusal names the migration; stderr:\n{stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// RED: `--migrate-config` inserts `store: {module: memory}` into the no-store fixture and lists
/// the change, and the migrated config validates. Without the insertion the migrated config has no
/// `store:` and the first assertion fails.
#[test]
fn migrate_inserts_the_memory_store_and_the_result_validates() {
    let dir = workdir("migrate");
    let out = Command::new(env!("CARGO_BIN_EXE_busbar"))
        .arg("--migrate-config")
        .arg(FIXTURE)
        .output()
        .expect("run busbar --migrate-config");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "migrates; stderr:\n{stderr}");
    let doc: serde_yaml::Value = serde_yaml::from_str(&stdout).expect("YAML on stdout");
    let want: serde_yaml::Value = serde_yaml::from_str("module: memory").unwrap();
    assert_eq!(doc.get("store"), Some(&want), "stdout:\n{stdout}");
    assert!(
        stderr.contains("  - store: inserted `store: {module: memory}`"),
        "the change is listed; stderr:\n{stderr}"
    );

    // The fixture's provider speaks the llm plane's wire, so the migrated config can only
    // validate in a build that compiles that plane in; elsewhere validation refuses the provider,
    // not the store.
    if cfg!(feature = "proto-llm") {
        let migrated = dir.join("config.yaml");
        std::fs::write(&migrated, &stdout).unwrap();
        let out = validate(&dir, &migrated);
        assert_eq!(
            out.status.code(),
            Some(0),
            "the migrated config validates; stderr:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}
