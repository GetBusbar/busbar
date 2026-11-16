// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! MIGRATE-ON-BOOT r42 §3 step 2, the binding: an unstamped boot runs the document step 1 planned,
//! held in memory, never config.yaml as it still sits on disk (step 5 writes it only after every
//! instance has opened). A document the composition root holds is read in place of its file, for
//! the deployment and for the providers catalog alike; the file is not opened.

use std::path::{Path, PathBuf};

use busbar_contract::secure::SecureString;
use busbar_kernel::appbuild::{load_config_from_disk_judged, RootRules};
use busbar_kernel::config::{EnvSubst, RootCfg};

fn scratch(tag: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("busbar-held-document-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

/// A deployment that loads on its own, so only the held text decides each case below.
const DEPLOYMENT: &str = "providers: {}\nmodels: {}\nstore:\n  module: memory\n  settings: {}\n";

/// Holds one document per path, as the migrate-on-boot seam holds its plan.
struct Held(Vec<(PathBuf, String)>);

impl RootRules for Held {
    fn check(&self, _: &RootCfg) -> Result<(), String> {
        Ok(())
    }

    fn held_document(&self, path: &Path) -> Option<SecureString> {
        self.0
            .iter()
            .find(|(at, _)| at == path)
            .map(|(_, text)| SecureString::from(text.as_str()))
    }
}

/// The planned deployment wins over the bytes still on disk: what the boot opens its instances
/// with is what step 5 writes.
#[test]
fn a_held_deployment_is_read_in_place_of_the_file() {
    let dir = scratch("over-disk");
    let config = dir.join("config.yaml");
    std::fs::write(&config, format!("listen: 127.0.0.1:1111\n{DEPLOYMENT}")).expect("config");
    let planned = format!("config_version: 1\nlisten: 127.0.0.1:2222\n{DEPLOYMENT}");
    let rules = Held(vec![(config.clone(), planned)]);
    let loaded = load_config_from_disk_judged(&config, None, false, EnvSubst::Strict, &rules)
        .expect("the held deployment loads");
    assert_eq!(loaded.deploy.listen, "127.0.0.1:2222");
    assert_eq!(loaded.deploy.config_version, Some(1));
    assert_eq!(
        std::fs::read_to_string(&config).expect("config"),
        format!("listen: 127.0.0.1:1111\n{DEPLOYMENT}"),
        "the read writes nothing"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The file is not opened at all: a held deployment loads with no config.yaml on disk.
#[test]
fn a_held_deployment_opens_no_file() {
    let dir = scratch("no-file");
    let config = dir.join("config.yaml");
    let rules = Held(vec![(config.clone(), DEPLOYMENT.to_owned())]);
    load_config_from_disk_judged(&config, None, false, EnvSubst::Strict, &rules)
        .expect("a held deployment needs no file");
    assert!(!config.exists());
    let _ = std::fs::remove_dir_all(&dir);
}

/// The planned providers catalog (1k: `providers.busbar-1.6.yaml`, which step 5 creates) is read
/// in place of its file too: the planned deployment names a file that does not exist yet.
#[test]
fn a_held_catalog_is_read_in_place_of_the_file() {
    let dir = scratch("catalog");
    let config = dir.join("config.yaml");
    let planned =
        format!("config_version: 1\nproviders_file: providers.busbar-1.6.yaml\n{DEPLOYMENT}");
    let catalog = dir.join("providers.busbar-1.6.yaml");
    let rules = Held(vec![
        (config.clone(), planned),
        (catalog.clone(), "{}\n".to_owned()),
    ]);
    let loaded = load_config_from_disk_judged(&config, None, false, EnvSubst::Strict, &rules)
        .expect("the held catalog loads");
    assert_eq!(loaded.providers_path, catalog);
    assert!(loaded.defs.is_empty());
    assert!(!catalog.exists(), "the read creates nothing");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Rules that hold nothing read the file, as every load path but the unstamped boot does.
#[test]
fn rules_that_hold_nothing_read_the_file() {
    let dir = scratch("nothing-held");
    let config = dir.join("config.yaml");
    std::fs::write(&config, format!("listen: 127.0.0.1:3333\n{DEPLOYMENT}")).expect("config");
    let rules = Held(Vec::new());
    let loaded = load_config_from_disk_judged(&config, None, false, EnvSubst::Strict, &rules)
        .expect("the file loads");
    assert_eq!(loaded.deploy.listen, "127.0.0.1:3333");
    let _ = std::fs::remove_dir_all(&dir);
}
