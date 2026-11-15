// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! MIGRATE-ON-BOOT r41 §9 C1 reds (a) goldens, (j), (l), (t) and (x)(1)-(3), through `plan` and
//! `write` on a scratch config directory.

use std::cell::RefCell;

use crate::scratch::{accept, facts, Scratch};
use crate::{plan, write, Facts, Inputs, Refusal, Written, UPGRADE_FIRST};

/// Plan and write `config` (beside an empty providers.yaml) with `facts`; the written config.yaml
/// and the plan's report.
fn upgrade(config: &str, facts: &Facts) -> (String, Vec<String>) {
    let scratch = Scratch::new();
    let path = scratch.deployment(config);
    let planned = plan(&Inputs::new(&path, facts, &accept))
        .unwrap_or_else(|refusal| panic!("planned: {refusal}"));
    let report = planned.report().to_vec();
    assert_eq!(write(&planned, &accept), Ok(Written::Stamped));
    assert_eq!(
        std::fs::read_to_string(crate::backup_path(&path)).unwrap(),
        config,
        "config.yaml.1.5.5 is byte-identical"
    );
    (std::fs::read_to_string(&path).unwrap(), report)
}

/// (a) goldens and (j): each 1.5.5 fixture is rewritten once to its golden, byte for byte through
/// the patch writer. The store-less default install gains `store: {module: memory}`, the block
/// 1.5.5 implied (AGREED QM2); the fleet config loses its overlay selector, its zero cache-write
/// rate and its hostless metadata entry, gains the open unit at 0 and the ungoverned binding, and
/// keeps every comment, quote and blank line, its store module word as written.
#[test]
fn the_1_5_5_goldens_are_rewritten_byte_for_byte() {
    let fleet = Facts {
        open_units: vec!["web_search".to_owned()],
        ..facts()
    };
    for (name, source, golden, facts) in [
        (
            "store_less",
            include_str!("golden/store_less.1.5.5.yaml"),
            include_str!("golden/store_less.1.6.yaml"),
            facts(),
        ),
        (
            "fleet",
            include_str!("golden/fleet.1.5.5.yaml"),
            include_str!("golden/fleet.1.6.yaml"),
            fleet,
        ),
    ] {
        let (written, report) = upgrade(source, &facts);
        assert_eq!(written, golden, "{name}: the rewritten config.yaml");
        assert!(!report.is_empty(), "{name}: every change is reported");
    }
}

/// (j): the store-less shapes 1.5.5 ran on its built-in store each get the explicit block, one
/// report line, and nothing else changes: no block, a null block, and a block naming no module
/// (its keys kept; the store's own migrate drops what it does not read).
#[test]
fn a_store_less_1_5_5_config_names_the_store_1_5_5_implied() {
    for (source, golden) in [
        (
            "listen: x\n",
            "config_version: 1\nlisten: x\nstore:\n  module: memory\n",
        ),
        (
            "listen: x\nstore:\n",
            "config_version: 1\nlisten: x\nstore:\n  module: memory\n",
        ),
        (
            "listen: x\nstore: {token: x}\n",
            "config_version: 1\nlisten: x\nstore: {module: memory, token: x}\n",
        ),
        (
            "listen: x\nstore: {module: ~, token: x}\n",
            "config_version: 1\nlisten: x\nstore: {module: memory, token: x}\n",
        ),
    ] {
        let (written, report) = upgrade(source, &facts());
        assert_eq!(written, golden, "{source:?}");
        assert_eq!(
            report
                .iter()
                .filter(|line| line.starts_with("store"))
                .count(),
            1,
            "{report:?}"
        );
    }
    // A config that names its store keeps it, whatever the word.
    let (written, report) = upgrade("store:\n  module: postgres\n", &facts());
    assert_eq!(written, "config_version: 1\nstore:\n  module: postgres\n");
    assert!(report.is_empty(), "{report:?}");
}

/// (j) and (l): `module:` values are the plugins' (step 2): the migrator resolves no name. A 1.5.5
/// name a P0 plugin declares as a former name, and 1.5.5's retired `redis`, reach the boot's parse
/// as written; 1.5.5's name-based marker is not copied, so `redis` is not refused here (the loader's
/// unknown-module refusal carries `UPGRADE_FIRST` on this boot, `upgrade::unknown_module`).
#[test]
fn module_words_are_left_as_written() {
    for module in [
        "busbar-store-sqlite-plugin",
        "busbar-store-valkey-plugin",
        "redis",
    ] {
        let source = format!(
            "store: {{module: {module}}}\nsecrets:\n  busbar-hashicorp-vault: {{address: x}}\n"
        );
        let seen = RefCell::new(None);
        let check = |text: &str, _: Option<&str>| -> Result<(), String> {
            *seen.borrow_mut() = Some(text.to_owned());
            Ok(())
        };
        let scratch = Scratch::new();
        let path = scratch.deployment(&source);
        let planned = plan(&Inputs::new(&path, &facts(), &check))
            .unwrap_or_else(|refusal| panic!("{module}: {refusal}"));
        assert_eq!(planned.planned(), format!("config_version: 1\n{source}"));
        assert_eq!(seen.borrow().as_deref(), Some(planned.planned()));
    }
}

/// (t): what the deleted passes' inputs now get. A 1.4.x shape that no v1.5.5 marker names reaches
/// the boot's strict parse unchanged and is refused CONFIG with the parse's own text and
/// `UPGRADE_FIRST`, word for word; a marker shape is refused UNSUPPORTED by 1a. Nothing is written.
#[test]
fn the_deleted_passes_inputs_reach_the_strict_parse_unchanged() {
    for shape in [
        "budget_period: month\n",
        "pools:\n  fast:\n    policy: weighted\n",
        "tool_pools: {}\n",
        "pools:\n  fast:\n    deadline_secs: 5\n",
        "pools:\n  fast:\n    hooks:\n      - audit: {at: route}\n",
    ] {
        let source = format!("{shape}store: {{module: sqlite}}\n");
        let seen = RefCell::new(None);
        let check = |text: &str, _: Option<&str>| -> Result<(), String> {
            *seen.borrow_mut() = Some(text.to_owned());
            Err("config.yaml: unknown field".to_owned())
        };
        let scratch = Scratch::new();
        let path = scratch.deployment(&source);
        let refused = plan(&Inputs::new(&path, &facts(), &check)).unwrap_err();
        assert_eq!(
            seen.borrow().as_deref(),
            Some(format!("config_version: 1\n{source}").as_str()),
            "{shape:?} reaches the parse unchanged"
        );
        assert_eq!(
            refused.to_string(),
            format!("CONFIG: config.yaml: unknown field\n{UPGRADE_FIRST}")
        );
        assert_eq!(scratch.names(), ["config.yaml", "providers.yaml"]);
    }
    for (shape, marker) in [
        (
            "pools:\n  fast:\n    on_exhausted: {action: reject}\n",
            "`pools.fast.on_exhausted.action:` (the action wrapper is gone; use a bare \
             `reject`/`least_bad` or `{ fallback_pool: <pool> }`)",
        ),
        (
            "governance: {}\n",
            "`governance:` block (dissolved into store / rate_card / per_request_fee / groups / \
             advanced / auth)",
        ),
    ] {
        let scratch = Scratch::new();
        let path = scratch.deployment(&format!("{shape}store: {{module: sqlite}}\n"));
        let never = |_: &str, _: Option<&str>| -> Result<(), String> {
            panic!("1a refuses before the parse")
        };
        let refused = plan(&Inputs::new(&path, &facts(), &never)).unwrap_err();
        assert_eq!(refused.word(), "UNSUPPORTED", "{refused}");
        assert!(
            refused.to_string().contains(&format!("\n  - {marker}\n")),
            "{refused}"
        );
        assert!(refused.to_string().ends_with(UPGRADE_FIRST), "{refused}");
        assert_eq!(scratch.names(), ["config.yaml", "providers.yaml"]);
    }
}

/// (x)(1)-(3): the open units come from the boot's facts (the installed planes), never a list the
/// migrator reads. (1) A lane that prices none of them gains each at 0 with one report line. (2) An
/// extra billable class in the facts is priced too. (3) Facts missing a unit the boot's own parse
/// requires: the parse refuses CONFIG at the end of the plan, naming the lane and unit, and nothing
/// is written.
#[test]
fn the_open_units_are_the_boots_facts_and_the_boots_parse_judges_them() {
    let source =
        "rate_card:\n  claude: {input_utok: 3, output_utok: 15}\nstore: {module: sqlite}\n";
    let with = |units: &[&str]| Facts {
        open_units: units.iter().map(|unit| (*unit).to_owned()).collect(),
        ..facts()
    };
    let (written, report) = upgrade(source, &with(&["web_search"]));
    assert_eq!(
        written,
        "config_version: 1\nrate_card:\n  claude: {input_utok: 3, output_utok: 15, units: \
         {web_search: 0}}\nstore: {module: sqlite}\n"
    );
    assert_eq!(
        report
            .iter()
            .filter(|line| line.starts_with("rate_card.claude.units: added web_search at 0"))
            .count(),
        1,
        "{report:?}"
    );
    let (written, _) = upgrade(source, &with(&["web_search", "image_tile"]));
    assert!(
        written.contains("units: {web_search: 0, image_tile: 0}"),
        "{written}"
    );
    let requires = |text: &str, _: Option<&str>| -> Result<(), String> {
        if text.contains("web_search: 0") {
            Ok(())
        } else {
            Err("config.yaml: rate_card.claude: billable unit `web_search` is not priced".into())
        }
    };
    let scratch = Scratch::new();
    let path = scratch.deployment(source);
    let refused = plan(&Inputs::new(&path, &with(&[]), &requires)).unwrap_err();
    assert!(
        matches!(&refused, Refusal::Config(text) if text.contains("rate_card.claude") && text.contains("web_search")),
        "{refused}"
    );
    assert_eq!(std::fs::read_to_string(&path).unwrap(), source);
    assert_eq!(scratch.names(), ["config.yaml", "providers.yaml"]);
}
