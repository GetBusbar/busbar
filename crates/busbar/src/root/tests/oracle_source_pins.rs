// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A 1.6 PIN ROW IS A REFERENCE, NOT A COPY (UPG-H1). The shadow oracle builds each 1.6 plugin from
//! the commit this tree ships (`scripts/ci-product-pins.json`): its `plugin-digests.tsv` row says
//! `src:pinned`, never a commit of its own, because a hand copy of a pin that moves several times a
//! day drifts (all ten 1.6 rows had). This checks the rows' form only and reads no commit, so no pin
//! move can turn it red.

use std::collections::BTreeSet;
use std::path::PathBuf;

/// One `plugin-digests.tsv` row: name, tag, release line.
struct Row {
    name: String,
    tag: String,
    line: String,
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Every pin row (`name<TAB>tag<TAB>asset<TAB>sha256[<TAB>line]`, line `1.5` when absent).
fn rows() -> Vec<Row> {
    let path = repo_root().join("testing/shadow-oracle/plugin-digests.tsv");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    text.lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| {
            let mut c = l.split('\t');
            let (name, tag, _asset, _sha) = (c.next()?, c.next()?, c.next()?, c.next()?);
            let line = c.next().filter(|x| !x.is_empty()).unwrap_or("1.5");
            Some(Row {
                name: name.to_string(),
                tag: tag.to_string(),
                line: line.to_string(),
            })
        })
        .collect()
}

fn rows_1_6() -> Vec<Row> {
    let rows: Vec<Row> = rows().into_iter().filter(|r| r.line == "1.6").collect();
    assert!(!rows.is_empty(), "plugin-digests.tsv has no 1.6 row");
    rows
}

#[test]
fn oracle_1_6_source_rows_take_the_trees_pin() {
    let mut wrong = Vec::new();
    // A 1.5 plugin has one published row per host triple; a 1.6 row builds every triple, once.
    let mut seen = BTreeSet::new();
    for r in rows_1_6() {
        if !seen.insert(r.name.clone()) {
            wrong.push(format!(
                "{} (line 1.6): appears twice in plugin-digests.tsv",
                r.name
            ));
        }
        if r.tag != "src:pinned" {
            wrong.push(format!(
                "{} (line 1.6): `{}` copies a commit; a 1.6 row says `src:pinned` and builds the commit \
                 scripts/ci-product-pins.json ships",
                r.name, r.tag
            ));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}
