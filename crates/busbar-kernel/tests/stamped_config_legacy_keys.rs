// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Red (lg1), MIGRATE-ON-BOOT r41 C1: a stamped config.yaml is the migrator's output, so the gateway
//! keeps no boot-time reader of 1.4.x/1.5.x keys. A stamped file holding `governance: {}` or
//! `auth: {mode: static}` is refused by the strict parse, and the error names `config.yaml` and the
//! unknown field. It is not refused with "automatic normalization must resolve these fields".

use std::path::PathBuf;

use busbar_kernel::appbuild::load_config_from_disk;
use busbar_kernel::config::EnvSubst;

fn refusal(tag: &str, body: &str) -> String {
    let dir: PathBuf = std::env::temp_dir().join(format!(
        "busbar-stamped-legacy-keys-{tag}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    let config = dir.join("config.yaml");
    std::fs::write(&config, format!("config_version: 1\n{body}")).expect("config.yaml");
    let result = load_config_from_disk(&config, None, false, EnvSubst::Strict);
    let _ = std::fs::remove_dir_all(&dir);
    match result {
        Ok(_) => panic!("a stamped config holding a retired key must be refused"),
        Err(error) => error,
    }
}

#[test]
fn a_stamped_config_with_governance_is_refused_by_the_strict_parse() {
    let error = refusal("governance", "governance: {}\n");
    assert!(error.contains("config.yaml"), "{error}");
    assert!(error.contains("unknown field `governance`"), "{error}");
    assert!(
        !error.contains("automatic normalization must resolve"),
        "{error}"
    );
}

#[test]
fn a_stamped_config_with_auth_mode_is_refused_by_the_strict_parse() {
    let error = refusal("auth-mode", "auth:\n  mode: static\n");
    assert!(error.contains("config.yaml"), "{error}");
    assert!(error.contains("unknown field `mode`"), "{error}");
    assert!(
        !error.contains("automatic normalization must resolve"),
        "{error}"
    );
}
