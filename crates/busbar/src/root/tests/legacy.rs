// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ROOT LEGACY TABLE, held to 1.5.5: one test per retired word. Each installs the root's table
//! (as `main` does), then holds `--migrate-config`'s rewrite and change line, and boot's 1.x refusal,
//! to the bytes 1.5.5 printed for that word (`tests/fixtures/legacy_retired_1_5_5.yaml`). The words
//! and the bytes are data; this file spells neither.

use super::{install, LEGACY_ROWS};

/// The 1.5.5 golden entry `n` of the retired words.
fn golden(n: usize) -> serde_yaml::Value {
    let doc: serde_yaml::Value = serde_yaml::from_str(include_str!(
        "../../../tests/fixtures/legacy_retired_1_5_5.yaml"
    ))
    .expect("the golden parses");
    doc["retired"][n].clone()
}

fn field(v: &serde_yaml::Value, k: &str) -> String {
    v[k].as_str()
        .unwrap_or_else(|| panic!("golden `{k}` is a string"))
        .to_string()
}

/// The retired word at golden entry `n` meets exactly its 1.5.5 bytes.
fn retired_word_meets_its_1_5_5_bytes(n: usize) {
    install();
    let g = golden(n);
    let (word, module) = (field(&g, "word"), field(&g, "module"));
    assert!(
        LEGACY_ROWS
            .iter()
            .any(|(k, v)| *k == format!("retired.store.{word}") && *v == module),
        "the root legacy table carries no `retired.store.{word}` row answering to `{module}`"
    );
    let raw = format!(
        "store:\n  module: {word}\n  settings: {{ url: \"kv://127.0.0.1:6379/0\" }}\n\
         providers: {{}}\nmodels: {{}}\npools: {{}}\n"
    );

    // `--migrate-config`: the rewrite and its change line, byte for byte.
    let out = busbar_kernel::config::migrate::migrate_config(&raw).expect("migrates");
    let doc: serde_yaml::Value = serde_yaml::from_str(&out.yaml).expect("the output parses");
    assert_eq!(doc["store"]["module"].as_str(), Some(module.as_str()));
    assert_eq!(
        doc["store"]["settings"]["url"].as_str(),
        Some("kv://127.0.0.1:6379/0"),
        "the settings ride through verbatim"
    );
    assert!(
        out.changes.contains(&field(&g, "change")),
        "the change line is not 1.5.5's:\n{:#?}",
        out.changes
    );

    // Boot and `--validate`: the 1.x refusal names the word with 1.5.5's marker.
    let dir = std::env::temp_dir().join(format!(
        "busbar-legacy-{n}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    std::fs::create_dir_all(&dir).expect("scratch dir");
    let path = dir.join("config.yaml");
    std::fs::write(&path, &raw).expect("write config");
    let refused = busbar_kernel::load_config_from_disk(
        &path,
        None,
        false,
        busbar_kernel::config::EnvSubst::Strict,
    )
    .err()
    .expect("a retired spelling refuses boot");
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        refused.contains(&format!("  - {}\n", field(&g, "marker"))),
        "the boot refusal does not carry 1.5.5's marker:\n{refused}"
    );
}

#[test]
fn retired_word_1_meets_its_1_5_5_bytes() {
    retired_word_meets_its_1_5_5_bytes(0);
}

#[test]
fn retired_word_2_meets_its_1_5_5_bytes() {
    retired_word_meets_its_1_5_5_bytes(1);
}

#[test]
fn retired_word_3_meets_its_1_5_5_bytes() {
    retired_word_meets_its_1_5_5_bytes(2);
}

/// Every retired row of the table has its golden entry, so a word added to `plugins.yaml` without
/// its 1.5.5 bytes fails here rather than shipping unproven.
#[test]
fn every_retired_row_has_a_1_5_5_golden() {
    let doc: serde_yaml::Value = serde_yaml::from_str(include_str!(
        "../../../tests/fixtures/legacy_retired_1_5_5.yaml"
    ))
    .expect("the golden parses");
    let golden: Vec<String> = doc["retired"]
        .as_sequence()
        .expect("a list")
        .iter()
        .map(|g| format!("retired.store.{}", field(g, "word")))
        .collect();
    let rows: Vec<String> = LEGACY_ROWS
        .iter()
        .filter(|(k, _)| k.starts_with("retired."))
        .map(|(k, _)| (*k).to_string())
        .collect();
    assert_eq!(rows, golden);
}

/// A test build of the kernel stands the frozen rows in (`legacy_rows` in its frozen-text fixture);
/// they are the root's table, row for row.
#[test]
fn the_kernel_test_stand_in_is_the_root_table() {
    let doc: serde_yaml::Value = serde_yaml::from_str(include_str!(
        "../../../../busbar-kernel/tests/fixtures/frozen_customer_text.yaml"
    ))
    .expect("the kernel fixture parses");
    let mut stand_in: Vec<(String, String)> = doc["legacy_rows"]
        .as_mapping()
        .expect("`legacy_rows`")
        .iter()
        .map(|(k, v)| {
            (
                k.as_str().expect("key").to_string(),
                v.as_str().expect("value").to_string(),
            )
        })
        .collect();
    let mut root: Vec<(String, String)> = LEGACY_ROWS
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect();
    stand_in.sort();
    root.sort();
    assert_eq!(stand_in, root);
}

// ── THE TABLE IS THE RENDER OF plugins.yaml ─────────────────────────────────────────────────────
// One home per fact: the words live in plugins.yaml (`legacy:` and each entry's `retired:`); the
// manifest's `[package.metadata.busbar.legacy]` is their render, and an edit to either side alone is
// red here, with the table to paste printed.

const MANIFEST: &str = include_str!("../../../Cargo.toml");
const REGISTRY: &str = include_str!("../../../../../plugins.yaml");
const HEADER: &str = "[package.metadata.busbar.legacy]";
const NOTE: &str = "# THE ROOT LEGACY TABLE (BUSBAR-1.6.0.md §2), @generated from plugins.yaml (`legacy:` and each\n\
# entry's `retired:`); src/root/tests/legacy.rs is red on an edit and prints the render to paste.\n\
# build.rs emits it as `LEGACY_ROWS`, which the root hands to the kernel before any config is read.\n";

fn text(v: &serde_yaml::Value, k: &str) -> Option<String> {
    v[k].as_str().map(str::to_string)
}

/// The table's rows, in order: the `legacy:` block's frozen 1.5.5 text, sorted by key; then, per
/// entry in registry order with a `retired:` list, one `retired.<kind>.<word> = "<alias>"` row per
/// word and the entry's `manifest.<alias>` / `asset.<alias>` rows (each defaulting to the repo).
fn rows(registry: &str) -> Vec<(String, String)> {
    let doc: serde_yaml::Value = serde_yaml::from_str(registry).expect("plugins.yaml parses");
    let mut out: Vec<(String, String)> = doc["legacy"]
        .as_mapping()
        .map(|m| {
            m.iter()
                .map(|(k, v)| {
                    let k = k.as_str().expect("a `legacy:` key is a string");
                    let v = v
                        .as_str()
                        .unwrap_or_else(|| panic!("plugins.yaml legacy: `{k}` must be a string"));
                    (k.to_string(), v.to_string())
                })
                .collect()
        })
        .unwrap_or_default();
    out.sort();
    for p in doc["plugins"].as_sequence().expect("`plugins:`") {
        let Some(retired) = p["retired"].as_sequence() else {
            continue;
        };
        let repo = text(p, "repo").expect("`repo`");
        let (kind, alias) = (
            text(p, "kind").expect("`kind`"),
            text(p, "alias").expect("`alias`"),
        );
        for word in retired {
            let word = word.as_str().expect("a `retired:` word is a string");
            out.push((format!("retired.{kind}.{word}"), alias.clone()));
        }
        out.push((
            format!("manifest.{alias}"),
            text(p, "manifest_name").unwrap_or_else(|| repo.clone()),
        ));
        out.push((
            format!("asset.{alias}"),
            text(p, "asset_prefix").unwrap_or(repo),
        ));
    }
    out
}

/// The rendered table: the header, the note and one quoted row per line.
fn render(registry: &str) -> String {
    let mut s = format!("{HEADER}\n{NOTE}");
    for (k, v) in rows(registry) {
        let v = v.replace('\\', "\\\\").replace('"', "\\\"");
        s.push_str(&format!("\"{k}\" = \"{v}\"\n"));
    }
    s
}

/// The manifest's table as written: from its header to the line before the next table header (or
/// the end), less trailing blank lines.
fn table(manifest: &str) -> String {
    let lines: Vec<&str> = manifest.lines().collect();
    let start = lines
        .iter()
        .position(|l| l.trim() == HEADER)
        .unwrap_or_else(|| panic!("crates/busbar/Cargo.toml carries no `{HEADER}`"));
    let mut end = lines[start + 1..]
        .iter()
        .position(|l| l.trim_start().starts_with('['))
        .map_or(lines.len(), |i| start + 1 + i);
    while end > start + 1 && lines[end - 1].trim().is_empty() {
        end -= 1;
    }
    lines[start..end].iter().map(|l| format!("{l}\n")).collect()
}

/// `None` when the manifest's table is the render of the registry; else the reason, with the table
/// to paste.
fn drift(manifest: &str, registry: &str) -> Option<String> {
    let want = render(registry);
    (table(manifest) != want).then(|| {
        format!(
            "crates/busbar/Cargo.toml: `{HEADER}` is not the render of plugins.yaml; replace it with:\n\n{want}"
        )
    })
}

/// The committed manifest's table IS the render of the committed plugins.yaml.
#[test]
fn the_committed_legacy_table_is_the_render() {
    if let Some(reason) = drift(MANIFEST, REGISTRY) {
        panic!("{reason}");
    }
}

/// An edit to the table by hand is drift (RED), and so is a `retired:` word added to plugins.yaml
/// without its row.
#[test]
fn a_hand_edited_table_or_an_unrendered_word_is_drift() {
    let (k, v) = rows(REGISTRY)
        .into_iter()
        .find(|(k, _)| k.starts_with("retired."))
        .expect("a retired row");
    let edited = MANIFEST.replace(
        &format!("\"{k}\" = \"{v}\""),
        &format!("\"{k}\" = \"x{v}\""),
    );
    assert_ne!(edited, MANIFEST, "the planted edit landed");
    assert!(drift(&edited, REGISTRY).is_some());
    let added = REGISTRY.replacen("retired: [", "retired: [planted-word, ", 1);
    assert_ne!(added, REGISTRY, "the planted word landed");
    let reason = drift(MANIFEST, &added).expect("an unrendered word is drift");
    assert!(
        reason.contains("\"retired.store.planted-word\" = "),
        "{reason}"
    );
}

/// A plugin's `retired:` words become `retired.<kind>.<word>` rows beside its manifest and asset
/// rows (defaulting to the repo); a plugin with none adds no row.
#[test]
fn retired_words_render_as_rows_of_their_kind_and_alias() {
    let registry = "plugins:\n  - repo: busbar-store-alpha\n    kind: store\n    alias: alpha\n    \
                    retired: [old-alpha]\n  - repo: busbar-secret-beta\n    kind: secret\n    alias: beta\n";
    let row = |k: &str, v: &str| (k.to_string(), v.to_string());
    assert_eq!(
        rows(registry),
        vec![
            row("retired.store.old-alpha", "alpha"),
            row("manifest.alpha", "busbar-store-alpha"),
            row("asset.alpha", "busbar-store-alpha"),
        ]
    );
}

/// Every frozen `legacy:` row of plugins.yaml cites the v1.5.5 line it is verbatim from (a
/// `# … v1.5.5:crates/…` comment above it), and every row parsed.
#[test]
fn every_legacy_row_cites_v1_5_5() {
    let block: Vec<&str> = REGISTRY
        .lines()
        .skip_while(|l| *l != "legacy:")
        .skip(1)
        .take_while(|l| l.starts_with("  ") || l.is_empty())
        .collect();
    let (mut cited, mut n) = (false, 0);
    for line in block {
        let t = line.trim();
        if t.starts_with('#') {
            cited |= t.contains("v1.5.5:crates/");
            continue;
        }
        if t.is_empty() {
            continue;
        }
        let key = t.split_once(':').expect("a row").0;
        assert!(
            cited,
            "legacy row `{key}` carries no v1.5.5 citation above it"
        );
        (cited, n) = (false, n + 1);
    }
    let doc: serde_yaml::Value = serde_yaml::from_str(REGISTRY).expect("plugins.yaml parses");
    assert_eq!(n, doc["legacy"].as_mapping().expect("`legacy:`").len());
    assert!(n > 0);
}
