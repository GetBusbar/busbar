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
