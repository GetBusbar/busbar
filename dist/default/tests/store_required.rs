// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A missing `store:` block is refused at the
//! outermost surface — the REAL binary over the no-store fixture (`fixtures/no_store_1_5_5.yaml`):
//!
//! `busbar --validate` REFUSES a config with no `store:` block (exit 1), requiring the configured
//! Store module and settings. The boot migration writes the store 1.5.5 implied (busbar-migrate 1d,
//! `absent_store_tests`).

mod common;
mod linked;

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/no_store_1_5_5.yaml"
);

fn workdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "busbar-store-required-{}-{tag}-{}",
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
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(
        d.join("providers.yaml"),
        "mock:\n  protocol: anthropic\n  base_url: \"http://127.0.0.1:9\"\n",
    )
    .unwrap();
    d
}

fn validate(dir: &Path, config: &Path) -> Output {
    Command::new(common::boot::exe())
        .arg("--validate")
        .arg("--providers")
        .arg(dir.join("providers.yaml"))
        .env("BUSBAR_CONFIG", config)
        .env("MOCK_KEY", "k")
        .output()
        .expect("run busbar --validate")
}

#[test]
fn validate_refuses_a_config_without_a_store_block() {
    let dir = workdir("refuse");
    let out = validate(&dir, Path::new(FIXTURE));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "refused; stderr:\n{stderr}");
    assert!(
        stderr.contains(
            "  - store is required; add a `store:` block with the configured Store module and settings"
        ),
        "the refusal names the store to add; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("BUSBAR-3015: config validation failed:"),
        "the missing Store is refused during configuration validation; stderr:\n{stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn migrate_inserts_the_memory_store_and_the_result_validates() {
    use busbar_contract::yaml::{self, prelude::*};
    linked::install();
    let dir = workdir("migrate");
    let source = dir.join("source.yaml");
    std::fs::write(&source, std::fs::read(FIXTURE).unwrap()).unwrap();
    let grammar = busbar_kernel::config::Grammar::new(
        busbar_kernel::config::secret::live_axis()
            .map(busbar_contract::secret::SecretAxis::sugars)
            .unwrap_or_default(),
        Default::default(),
        Vec::new(),
    );
    let facts = busbar_migrate::Facts::of_process(
        Vec::new(),
        vec!["protocol".to_owned(), "base_url".to_owned()],
    );
    let check = |text: &str, _: Option<&str>| {
        busbar_kernel::config::deploy_from_yaml_str(text, &grammar)
            .map(drop)
            .map_err(|error| error.to_string())
    };
    let plan = busbar_migrate::plan(&busbar_migrate::Inputs::new(&source, &facts, &check))
        .expect("the no-store source plans");
    let doc: Value = yaml::from_str(plan.planned()).expect("planned YAML");
    let want: Value = yaml::from_str("module: memory").unwrap();
    assert_eq!(doc.get("store"), Some(&want));
    assert!(
        plan.report()
            .iter()
            .any(|line| line.starts_with("store: added `store: {module: memory}`")),
        "the added store is reported: {:?}",
        plan.report()
    );
    let migrated = dir.join("config.yaml");
    std::fs::write(&migrated, plan.planned()).unwrap();
    let out = validate(&dir, &migrated);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!stderr.contains("store is required"), "{stderr}");
    let refusals: Vec<&str> = stderr
        .lines()
        .filter(|line| line.starts_with("  - "))
        .collect();
    if refusals.is_empty() {
        assert_eq!(out.status.code(), Some(0), "validates; stderr:\n{stderr}");
    } else {
        assert!(
            refusals
                .iter()
                .all(|line| line.contains("NO protocol with a wire codec compiled in")),
            "only a build without the provider's codec may refuse: {stderr}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}
