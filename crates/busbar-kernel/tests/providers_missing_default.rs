// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A missing DEFAULT providers.yaml (beside config.yaml, used because nothing named a file) is an
//! empty provider catalog, so an admin-only deployment boots. A providers file the operator NAMED
//! (`providers_file:` or the `--providers` override) must exist.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use busbar_contract::secure::SecureString;
use busbar_kernel::appbuild::{load_config_from_disk_judged, ConfigDocument, RootRules};
use busbar_kernel::config::{EnvSubst, RootCfg};
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

/// A deployment that loads on its own, so only the provider catalog decides each case below.
const DEPLOYMENT: &str = "providers: {}\nmodels: {}\nstore:\n  module: memory\n  settings: {}\n";

/// Records every document the loader hands to custody as authored bytes.
#[derive(Default)]
struct Custody(Mutex<Vec<(ConfigDocument, PathBuf, String)>>);

impl RootRules for Custody {
    fn check(&self, _: &RootCfg) -> Result<(), String> {
        Ok(())
    }

    fn normalize_document(
        &self,
        kind: ConfigDocument,
        path: &Path,
        raw: &str,
    ) -> Result<Option<SecureString>, String> {
        self.0
            .lock()
            .expect("custody record")
            .push((kind, path.to_path_buf(), raw.to_owned()));
        Ok(None)
    }
}

impl Custody {
    fn providers(&self) -> Vec<(PathBuf, String)> {
        self.0
            .lock()
            .expect("custody record")
            .iter()
            .filter(|(kind, _, _)| *kind == ConfigDocument::Providers)
            .map(|(_, path, raw)| (path.clone(), raw.clone()))
            .collect()
    }
}

/// Startup custody plans, fingerprints and commits every document the loader hands it as authored
/// bytes. An absent default providers.yaml has no bytes on disk: handing custody a stand-in `{}`
/// makes first boot look for a file that was never there and refuse it as a changed document.
#[test]
fn an_absent_default_providers_file_is_not_handed_to_custody_as_authored_bytes() {
    let dir = scratch("custody-absent");
    let config = dir.join("config.yaml");
    std::fs::write(&config, DEPLOYMENT).expect("config");
    let custody = Custody::default();
    let loaded = load_config_from_disk_judged(&config, None, false, EnvSubst::Lenient, &custody)
        .expect("a deployment without a default providers.yaml loads");
    assert!(loaded.defs.is_empty(), "the absent catalog is empty");
    assert_eq!(
        custody.providers(),
        Vec::<(PathBuf, String)>::new(),
        "an absent default providers.yaml has no authored bytes to normalize"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A default providers.yaml that exists is authored input like any other, even when it is `{}`.
#[test]
fn a_present_default_providers_file_is_handed_to_custody_verbatim() {
    let dir = scratch("custody-present");
    let config = dir.join("config.yaml");
    std::fs::write(&config, DEPLOYMENT).expect("config");
    let providers = dir.join("providers.yaml");
    std::fs::write(&providers, "{}\n").expect("providers");
    let custody = Custody::default();
    load_config_from_disk_judged(&config, None, false, EnvSubst::Lenient, &custody)
        .expect("a deployment with an empty providers.yaml loads");
    assert_eq!(custody.providers(), vec![(providers, "{}\n".to_owned())]);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Records the absences the loader reports to custody.
#[derive(Default)]
struct Absences(Mutex<Vec<(ConfigDocument, PathBuf)>>);

impl RootRules for Absences {
    fn check(&self, _: &RootCfg) -> Result<(), String> {
        Ok(())
    }

    fn absent_document(&self, kind: ConfigDocument, path: &Path) -> Result<(), String> {
        self.0
            .lock()
            .expect("absence record")
            .push((kind, path.to_path_buf()));
        Ok(())
    }
}

/// Custody is told of the absent default file, at the path it would occupy, once per load; a
/// present file is never reported absent.
#[test]
fn custody_is_told_the_default_providers_file_is_absent() {
    let dir = scratch("custody-told");
    let config = dir.join("config.yaml");
    std::fs::write(&config, DEPLOYMENT).expect("config");
    let absences = Absences::default();
    load_config_from_disk_judged(&config, None, false, EnvSubst::Lenient, &absences)
        .expect("loads");
    assert_eq!(
        *absences.0.lock().expect("absence record"),
        vec![(ConfigDocument::Providers, dir.join("providers.yaml"))]
    );

    std::fs::write(dir.join("providers.yaml"), "{}\n").expect("providers");
    let present = Absences::default();
    load_config_from_disk_judged(&config, None, false, EnvSubst::Lenient, &present).expect("loads");
    assert!(present.0.lock().expect("absence record").is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}
