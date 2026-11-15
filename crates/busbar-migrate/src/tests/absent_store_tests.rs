// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! MIGRATE-ON-BOOT r41 §9 C1 red (j), as AGREED QM2 (owner, 2026-11-15T20:54Z) rules it: a
//! store-less 1.5.5 config gets the block 1.5.5 implied, and the module word is one named constant,
//! the only plugin word in the migrator's production source. (x)(5): the migrator reads no plane
//! list; the open units are the boot's facts.

use std::path::Path;

use busbar_contract::yaml::{self, Value, ValueExt};

use super::*;

fn named(source: &str) -> (Value, Vec<String>) {
    let resolved: Value = yaml::from_str(source).expect("fixture parses");
    let mut after = resolved.clone();
    let mut report = Vec::new();
    let root = after.as_mapping_mut().expect("a mapping");
    name_the_implied_store(root, &resolved, &mut report);
    (after, report)
}

#[test]
fn the_store_1_5_5_implied_is_written_where_none_is_named() {
    for source in [
        "listen: x\n",
        "listen: x\nstore:\n",
        "listen: x\nstore: {token: x}\n",
        "listen: x\nstore: {module: ~}\n",
    ] {
        let (after, report) = named(source);
        assert_eq!(
            after.at("store").at("module").as_str(),
            Some(STORE_1_5_5_IMPLIED),
            "{source:?}"
        );
        assert_eq!(report.len(), 1, "{source:?}: {report:?}");
    }
    let (after, _) = named("listen: x\nstore: {token: x}\n");
    assert_eq!(after.at("store").at("token").as_str(), Some("x"));
    // A named store, whatever the word, is the operator's.
    for source in ["store: {module: sqlite}\n", "store: {module: redis}\n"] {
        let (after, report) = named(source);
        let before: Value = yaml::from_str(source).unwrap();
        assert!(yaml::same_tree(&after, &before), "{source:?}");
        assert!(report.is_empty());
    }
}

/// The added block lands at the schema's position: after the last key the schema orders first.
#[test]
fn the_added_block_lands_at_the_schema_position() {
    let (after, _) = named("listen: x\nmodels: {}\nsecurity: {}\n");
    let keys: Vec<&str> = after
        .as_mapping()
        .unwrap()
        .iter()
        .filter_map(|(key, _)| key.as_str())
        .collect();
    assert_eq!(keys, ["listen", "models", "store", "security"]);
}

/// Every production `.rs` under `src/` (test files excluded), with its path.
fn production_sources() -> Vec<(String, String)> {
    fn walk(dir: &Path, out: &mut Vec<(String, String)>) {
        let mut entries: Vec<_> = std::fs::read_dir(dir)
            .expect("read src")
            .map(|entry| entry.expect("entry").path())
            .collect();
        entries.sort();
        for path in entries {
            if path.is_dir() {
                if path.file_name().is_some_and(|name| name != "tests") {
                    walk(&path, out);
                }
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                let text = std::fs::read_to_string(&path).expect("read source");
                out.push((path.display().to_string(), text));
            }
        }
    }
    let mut out = Vec::new();
    walk(&Path::new(env!("CARGO_MANIFEST_DIR")).join("src"), &mut out);
    out
}

/// The code of a line: what precedes a `//` comment (a doc or line comment is prose).
fn code_of(line: &str) -> &str {
    line.split("//").next().unwrap_or("")
}

/// AGREED QM2's narrow exception: the store word appears in the migrator's production code on the
/// one constant line of `absent_store.rs`, and nowhere else; no production source calls the
/// kernel's plane list ((x)(5)).
#[test]
fn the_one_plugin_word_is_the_implied_store_constant() {
    let word = STORE_1_5_5_IMPLIED;
    let mut hits = Vec::new();
    let mut plane_list = Vec::new();
    for (path, text) in production_sources() {
        for (at, line) in text.lines().enumerate() {
            let code = code_of(line);
            if code.contains(word) {
                hits.push(format!("{path}:{}", at + 1));
            }
            if code.contains("plane_decls(") {
                plane_list.push(format!("{path}:{}", at + 1));
            }
        }
    }
    assert_eq!(hits.len(), 1, "{hits:?}");
    assert!(hits[0].contains("absent_store.rs"), "{hits:?}");
    let constant = production_sources()
        .into_iter()
        .find(|(path, _)| path.ends_with("absent_store.rs"))
        .map(|(_, text)| text)
        .unwrap();
    assert!(
        constant.lines().any(|line| line
            .starts_with("pub(crate) const STORE_1_5_5_IMPLIED: &str = ")
            && line.contains("AGREED QM2")),
        "the exception cites its ruling"
    );
    assert!(plane_list.is_empty(), "{plane_list:?}");
}
