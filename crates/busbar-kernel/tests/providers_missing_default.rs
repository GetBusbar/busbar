// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A missing DEFAULT providers.yaml (beside config.yaml, used because nothing named a file) is an
//! empty provider catalog, so an admin-only deployment boots. A providers file the operator NAMED
//! (`providers_file:` or the `--providers` override) must exist.

use std::path::{Path, PathBuf};

use busbar_kernel::config::EnvSubst;
use busbar_kernel::load_config_from_disk;

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "busbar-providers-missing-{tag}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

fn load(config: &Path, providers: Option<&Path>) -> Result<(), String> {
    load_config_from_disk(config, providers, false, EnvSubst::Lenient).map(|_| ())
}

#[test]
fn missing_default_providers_file_is_an_empty_catalog() {
    let dir = scratch("default");
    let config = dir.join("config.yaml");
    std::fs::write(&config, "{}\n").expect("config");
    if let Err(e) = load(&config, None) {
        assert!(
            !e.contains("cannot read providers file"),
            "a missing default providers.yaml must not be refused: {e}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn missing_providers_file_named_in_config_is_refused() {
    let dir = scratch("named");
    let config = dir.join("config.yaml");
    std::fs::write(&config, "providers_file: absent.yaml\n").expect("config");
    let e = load(&config, None).expect_err("a named, missing providers file is refused");
    assert!(e.contains("absent.yaml"), "refusal names the file: {e}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn missing_providers_override_is_refused() {
    let dir = scratch("override");
    let config = dir.join("config.yaml");
    std::fs::write(&config, "{}\n").expect("config");
    let named = dir.join("named.yaml");
    let e = load(&config, Some(&named)).expect_err("a named, missing providers file is refused");
    assert!(e.contains("named.yaml"), "refusal names the file: {e}");
    let _ = std::fs::remove_dir_all(&dir);
}
