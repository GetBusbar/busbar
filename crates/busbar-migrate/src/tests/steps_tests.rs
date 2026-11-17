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
    // 1b always reports the overlay it looked for (package 2); the chain itself changed nothing.
    assert!(
        report.iter().all(|line| line.starts_with("overlay: ")),
        "{report:?}"
    );
}

/// #358 (PRD-5; owner ruling L1, "Refuse, give remedy… no auto-write"): 1.5.5 ran a config with no
/// `auth:` block, or a null one, as an open relay, and 1.6.0 refuses to boot it (BUSBAR-8014). The
/// upgrade never writes an open relay for the operator: it leaves the block unwritten and reports
/// one BUSBAR-8014 action item carrying the boot refusal's remedy. A config that writes its own
/// `auth:` block, open or not, gets no item.
#[test]
fn a_1_5_5_config_with_no_auth_block_is_reported_and_left_unwritten() {
    let code = busbar_kernel::diagnostics::OPEN_RELAY_NO_AUTH
        .banner()
        .to_string();
    for source in [
        "listen: x\nstore: {module: sqlite}\n",
        "listen: x\nauth:\nstore: {module: sqlite}\n",
    ] {
        let (written, report) = upgrade(source, &facts());
        assert_eq!(
            written,
            format!("config_version: 1\n{source}"),
            "no open relay is written: {source:?}"
        );
        let items: Vec<&String> = report.iter().filter(|line| line.contains(&code)).collect();
        assert_eq!(items.len(), 1, "{report:?}");
        assert!(
            items[0].contains("no `auth:` block")
                && items[0].contains("add `auth: { chain: [] }` explicitly to run an open relay")
                && items[0].contains("or configure a chain")
                && items[0].contains("chain: [keys]"),
            "the item gives the boot refusal's remedy: {}",
            items[0]
        );
    }
    for source in [
        "listen: x\nauth:\n  chain: [keys]\nstore: {module: sqlite}\n",
        "listen: x\nauth: {chain: []}\nstore: {module: sqlite}\n",
    ] {
        let (written, report) = upgrade(source, &facts());
        assert_eq!(
            written,
            format!("config_version: 1\n{source}"),
            "{source:?}"
        );
        assert!(
            !report.iter().any(|line| line.contains(&code)),
            "{report:?}"
        );
    }
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
            "store: {{module: {module}}}\nsecrets:\n  vault: {{module: busbar-hashicorp-vault, settings: {{address: x}}}}\n"
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

/// C-TRANSPORT policy §8 test 13 (`upgrade_from_155_shape_carries_acceptance`, WBS rule 10): a
/// 1.5.5-shaped config with the printed `insecure_transport` line added under an instance block
/// plans, stamps and keeps the key byte for byte, in the base config (1d, the patch writer), in an
/// overlay-held hook (1c's `HookCfg` conversion sets the key aside and puts it back) and in an
/// overlay named-map instance.
#[test]
fn upgrade_from_155_shape_carries_acceptance() {
    const LINE: &str =
        "{ accept: plaintext, reason: \"pg sidecar on the pod network; INFRA-142\" }";
    let base = format!(
        "listen: 0.0.0.0:8080\nstore:\n  module: pg\n  settings: {{url: 'postgres://db/x?sslmode=disable'}}\n  insecure_transport: {LINE}\nidentity-providers:\n  corp-ldap:\n    module: ldap\n    settings: {{url: 'ldap://dc1.corp'}}\n    insecure_transport: {LINE}\n"
    );
    let (written, _) = upgrade(&base, &facts());
    assert_eq!(
        written
            .matches(&format!("insecure_transport: {LINE}"))
            .count(),
        2,
        "both blocks keep the line byte for byte:\n{written}"
    );
    assert!(written.starts_with("config_version: 1\n"));

    let scratch = Scratch::new();
    let path = scratch.deployment(
        "listen: 0.0.0.0:8080\nstore: {module: pg, settings: {url: x}}\nmodels:\n  m: {provider: p}\n",
    );
    scratch.file(
        crate::overlay::DEFAULT_OVERLAY_FILENAME,
        r#"{"version": 1,
  "hooks": {"wr": {"kind": "gate", "module": "webrequest", "insecure_transport": {"accept": "plaintext", "reason": "loopback collector"}}},
  "named_maps": {"export": {"otlp1": {"module": "otlp", "settings": {"url": "http://127.0.0.1:4318"}, "insecure_transport": {"accept": "plaintext", "reason": "loopback collector"}}}}}"#,
    );
    let planned = plan(&Inputs::new(&path, &facts(), &accept))
        .unwrap_or_else(|refusal| panic!("planned: {refusal}"));
    let tree = crate::patch::document(planned.planned()).expect("a mapping");
    let hook = busbar_contract::yaml::ValueExt::get(&tree, "hooks")
        .and_then(|hooks| busbar_contract::yaml::ValueExt::get(hooks, "wr"))
        .expect("the overlay hook is folded");
    let reason = |value: Option<&busbar_contract::yaml::Value>| {
        value
            .and_then(|value| busbar_contract::yaml::ValueExt::get(value, "insecure_transport"))
            .and_then(|value| busbar_contract::yaml::ValueExt::get(value, "reason"))
            .and_then(busbar_contract::yaml::ValueExt::as_str)
            .map(str::to_owned)
    };
    assert_eq!(reason(Some(hook)).as_deref(), Some("loopback collector"));
    let exporter = busbar_contract::yaml::ValueExt::get(&tree, "export")
        .and_then(|export| busbar_contract::yaml::ValueExt::get(export, "otlp1"));
    assert_eq!(reason(exporter).as_deref(), Some("loopback collector"));
}

#[test]
fn legacy_secret_instances_name_their_module_without_rekeying_or_losing_settings() {
    use busbar_contract::yaml::{self, Value, ValueExt};
    let source = "store: {module: m}\nsecrets:\n  custom: {settings: {prefix: keep}, limits: {max_inflight: 3}, insecure_transport: true}\n  named: {module: actual, settings: {value: kept}}\n";
    let (written, _) = upgrade(source, &facts());
    let tree: Value = yaml::from_str(&written).unwrap();
    let custom = tree.at("secrets").at("custom");
    assert_eq!(custom.at("module").as_str(), Some("custom"));
    assert_eq!(custom.at("settings").at("prefix").as_str(), Some("keep"));
    assert_eq!(custom.at("limits").at("max_inflight").as_u64(), Some(3));
    assert_eq!(custom.at("insecure_transport").as_bool(), Some(true));
    assert_eq!(
        tree.at("secrets").at("named").at("module").as_str(),
        Some("actual")
    );
}

#[test]
fn ambiguous_legacy_secret_blocks_are_refused_without_writing() {
    let scratch = Scratch::new();
    let source = "store: {module: m}\nsecrets: {custom: {settings: {}, future: do-not-drop}}\n";
    let path = scratch.deployment(source);
    let refused = plan(&Inputs::new(&path, &facts(), &accept))
        .expect_err("unknown block fields cannot identify the legacy shape");
    assert_eq!(refused.word(), "CONFIG");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), source);
    assert!(!crate::backup_path(&path).exists());
}

#[test]
fn migration_does_not_synthesize_host_global_private_authority() {
    let (written, _) = upgrade(
        "store: {module: m}\nproviders: {local: {base_url: 'http://127.0.0.1:11434'}}\n",
        &facts(),
    );
    assert!(
        !written.contains("allow_destinations"),
        "private authority belongs to the declared registration"
    );
}
