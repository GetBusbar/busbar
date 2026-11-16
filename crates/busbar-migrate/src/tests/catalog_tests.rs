// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! MIGRATE-ON-BOOT r41 §9 C1 red (w), the providers catalog step (§A3 1k, 5a2): the catalog 1.5.5
//! read is read, never written; when 1.6.0 needs another, it is written beside config.yaml as
//! `providers.busbar-1.6.yaml` with the source's mode, and config.yaml names it; a key 1.5.5
//! ignored is dropped with one report line; an unchanged catalog plans no file.

use std::cell::RefCell;
use std::os::unix::fs::PermissionsExt;

use crate::scratch::{facts, Scratch};
use crate::{plan, write, Facts, Inputs, Written};

const CATALOG: &str = "\
# upstreams
anthropic:
  protocol: anthropic
  base_url: https://api.anthropic.com
  notes: billed monthly   # 1.5.5 ignored this
";

const CATALOG_1_6: &str = "\
# upstreams
anthropic:
  protocol: anthropic
  base_url: https://api.anthropic.com
";

/// Plan and write `config` in `scratch` with `facts`, recording the catalog the parse was handed.
fn upgrade(scratch: &Scratch, config: &str, facts: &Facts) -> (Vec<String>, Option<String>) {
    let path = scratch.config(config);
    let handed = RefCell::new(None);
    let check = |_: &str, catalog: Option<&str>| -> Result<(), String> {
        *handed.borrow_mut() = catalog.map(str::to_owned);
        Ok(())
    };
    let planned = plan(&Inputs::new(&path, facts, &check))
        .unwrap_or_else(|refusal| panic!("planned: {refusal}"));
    let report = planned.report().to_vec();
    assert_eq!(write(&planned, &check), Ok(Written::Stamped));
    (report, handed.into_inner())
}

#[test]
fn a_catalog_key_1_5_5_ignored_is_dropped_into_a_new_catalog() {
    let scratch = Scratch::new();
    let source = scratch.file("providers.yaml", CATALOG);
    std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o600)).unwrap();
    let (report, handed) = upgrade(&scratch, "listen: x\nstore: {module: sqlite}\n", &facts());
    assert_eq!(
        handed.as_deref(),
        Some(CATALOG_1_6),
        "the parse judges the new catalog"
    );
    let written = scratch.dir().join("providers.busbar-1.6.yaml");
    assert_eq!(std::fs::read_to_string(&written).unwrap(), CATALOG_1_6);
    assert_eq!(
        std::fs::metadata(&written).unwrap().permissions().mode() & 0o7777,
        0o600,
        "the source's mode"
    );
    assert_eq!(
        std::fs::read_to_string(&source).unwrap(),
        CATALOG,
        "never written"
    );
    assert_eq!(
        std::fs::read_to_string(scratch.dir().join("config.yaml")).unwrap(),
        "config_version: 1\nlisten: x\nproviders_file: providers.busbar-1.6.yaml\nstore: {module: \
         sqlite}\n"
    );
    assert_eq!(
        report
            .iter()
            .filter(|line| line.contains("anthropic.notes: removed (1.5.5 ignored this catalog key"))
            .count(),
        1,
        "{report:?}"
    );
}

#[test]
fn an_unchanged_catalog_plans_no_file() {
    let scratch = Scratch::new();
    scratch.file("providers.yaml", CATALOG_1_6);
    let (report, handed) = upgrade(&scratch, "listen: x\nstore: {module: sqlite}\n", &facts());
    assert_eq!(handed, None);
    // 1b always reports the overlay it looked for (package 2); the chain itself changed nothing.
    assert!(
        report.iter().all(|line| line.starts_with("overlay: ")),
        "{report:?}"
    );
    assert!(!scratch.dir().join("providers.busbar-1.6.yaml").exists());
    assert_eq!(
        std::fs::read_to_string(scratch.dir().join("config.yaml")).unwrap(),
        "config_version: 1\nlisten: x\nstore: {module: sqlite}\n"
    );
}

/// `providers_file` selects the catalog (relative to config.yaml's directory) and, when a new one
/// is planned, is pointed at it in place.
#[test]
fn providers_file_selects_the_catalog_and_is_pointed_at_the_new_one() {
    let scratch = Scratch::new();
    std::fs::create_dir_all(scratch.dir().join("catalog")).unwrap();
    scratch.file("catalog/up.yaml", CATALOG);
    let (_, handed) = upgrade(
        &scratch,
        "providers_file: catalog/up.yaml # the fleet's\nstore: {module: sqlite}\n",
        &facts(),
    );
    assert_eq!(handed.as_deref(), Some(CATALOG_1_6));
    assert_eq!(
        std::fs::read_to_string(scratch.dir().join("config.yaml")).unwrap(),
        "config_version: 1\nproviders_file: providers.busbar-1.6.yaml # the fleet's\nstore: \
         {module: sqlite}\n"
    );
    assert_eq!(
        std::fs::read_to_string(scratch.dir().join("catalog/up.yaml")).unwrap(),
        CATALOG
    );
}

/// `BUSBAR_PROVIDERS` (relative to the working directory) outranks `providers_file`; 1.6.0 no
/// longer reads it, so an unchanged selection is captured as an absolute `providers_file`.
#[test]
fn busbar_providers_selects_the_catalog_and_is_captured() {
    fn env(name: &str) -> Option<String> {
        (name == "BUSBAR_PROVIDERS").then(|| "fleet-providers.yaml".to_owned())
    }
    let scratch = Scratch::new();
    scratch.file("fleet-providers.yaml", CATALOG_1_6);
    scratch.file("providers.yaml", CATALOG);
    let facts = Facts {
        env,
        cwd: scratch.dir().to_path_buf(),
        ..facts()
    };
    let (report, handed) = upgrade(&scratch, "listen: x\nstore: {module: sqlite}\n", &facts);
    assert_eq!(handed, None, "the selected catalog is unchanged");
    let absolute = scratch.dir().join("fleet-providers.yaml");
    let written = std::fs::read_to_string(scratch.dir().join("config.yaml")).unwrap();
    assert!(
        written.contains(&format!("providers_file: {}\n", absolute.display())),
        "{written}"
    );
    assert!(
        report
            .iter()
            .any(|line| line.starts_with("providers_file: set to")),
        "{report:?}"
    );
}

/// 1.5.5 refused to boot without its catalog: the same refusal, word for word; nothing written.
#[test]
fn a_missing_catalog_is_refused_as_1_5_5_refused_it() {
    let scratch = Scratch::new();
    let path = scratch.config("listen: x\nstore: {module: sqlite}\n");
    let refused = plan(&Inputs::new(&path, &facts(), &crate::scratch::accept)).unwrap_err();
    assert_eq!(refused.word(), "CONFIG");
    let text = refused.to_string();
    assert!(
        text.starts_with(&format!(
            "CONFIG: cannot read providers file '{}': ",
            scratch.dir().join("providers.yaml").display()
        )),
        "{text}"
    );
    assert!(
        text.ends_with("(set `providers_file:` in config.yaml, or BUSBAR_PROVIDERS)"),
        "{text}"
    );
    assert_eq!(scratch.names(), ["config.yaml"]);
}
