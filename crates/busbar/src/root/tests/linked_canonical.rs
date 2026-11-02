// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::linked_exports;
use crate::root::loader::boot::Candidate;
use crate::root::loader::LinkedPlugin;

const REGISTRY: &str = include_str!("../../../../../plugins.yaml");

struct Entry {
    kind: String,
    alias: String,

    manifest_name: String,
}

fn entries(registry: &str) -> Vec<Entry> {
    let doc: serde_yaml::Value = serde_yaml::from_str(registry).expect("plugins.yaml parses");
    let plugins = doc["plugins"].as_sequence().expect("plugins: is a list");
    plugins
        .iter()
        .map(|p| {
            let field = |k: &str| p[k].as_str().map(str::to_string);
            let repo = field("repo").expect("every entry names its repo");
            Entry {
                kind: field("kind").expect("every entry names its kind"),
                alias: field("alias").expect("every entry names its alias"),
                manifest_name: field("manifest_name").unwrap_or(repo),
            }
        })
        .collect()
}

struct Row {
    kind: String,
    canonical: String,
    aliases: Vec<String>,
}

impl Row {
    fn of(row: &LinkedPlugin) -> Self {
        let m = &row.manifest;
        Self {
            kind: m.kind.clone(),
            canonical: m.name.clone(),
            aliases: m.config_names().map(str::to_string).collect(),
        }
    }

    fn of_door(c: &Candidate, kind: &str) -> Self {
        Self {
            kind: kind.to_string(),
            canonical: c.name.clone(),
            aliases: c.aliases.clone(),
        }
    }
}

fn drift(rows: &[Row], entries: &[Entry]) -> (Vec<String>, Vec<String>, Vec<String>) {
    let (mut matched, mut mismatches, mut skipped) = (Vec::new(), Vec::new(), Vec::new());
    for row in rows {
        let answers = |e: &&Entry| {
            e.kind == row.kind && (row.aliases.contains(&e.alias) || row.canonical == e.alias)
        };
        match entries.iter().find(answers) {
            None => skipped.push(format!(
                "linked {} '{}' (aliases {:?}): no plugins.yaml entry of kind {} answers it",
                row.kind, row.canonical, row.aliases, row.kind
            )),
            Some(e) if e.manifest_name != row.canonical => mismatches.push(format!(
                "linked {} '{}' answers plugins.yaml alias '{}', whose manifest_name is '{}': \
                 register the row under '{}' (its alias stays '{}')",
                row.kind, row.canonical, e.alias, e.manifest_name, e.manifest_name, e.alias
            )),
            Some(e) => matched.push(format!("{} {}", row.kind, e.manifest_name)),
        }
    }
    (matched, mismatches, skipped)
}

fn linked_rows() -> (Vec<Row>, Vec<String>) {
    let mut rows: Vec<Row> = Vec::new();
    let stores = crate::LINKED.stores.iter();
    rows.extend(stores.map(|s| {
        Row::of(&crate::root::boot::linked_row(
            &busbar_kernel::preflight::LinkedRow::Store(*s),
        ))
    }));
    let auths = crate::LINKED.auths.iter();
    rows.extend(auths.map(|a| {
        Row::of(&crate::root::boot::linked_row(
            &busbar_kernel::preflight::LinkedRow::Auth(*a),
        ))
    }));
    let exports = linked_exports(crate::LINKED.export_doors).expect("the export rows state");
    rows.extend(exports.iter().map(Row::of));
    for door in crate::LINKED.secrets {
        let c = Candidate::linked(*door).expect("a linked secret states itself");
        rows.push(Row::of_door(&c, "secret"));
    }
    let entries = entries(REGISTRY);
    let mut skipped = Vec::new();

    for door in crate::LINKED.hook_doors {
        let c = Candidate::linked(*door).expect("a linked hook states itself");
        let row = Row::of_door(&c, "hook");
        let want = entries
            .iter()
            .find(|e| {
                e.kind == "hook" && (row.aliases.contains(&e.alias) || row.canonical == e.alias)
            })
            .map_or_else(
                || {
                    "its plugins.yaml manifest_name (none of its aliases answers an entry yet)"
                        .to_string()
                },
                |e| format!("'{}'", e.manifest_name),
            );
        skipped.push(format!(
            "linked hook '{}': the hook row is the in-tree crate until P5 #484; the pinned repo \
             states {want}",
            row.canonical
        ));
    }
    for t in crate::LINKED.transports {
        skipped.push(format!(
            "linked transport '{}': a wire is keyed by its scheme, not a registry row with a \
             manifest name",
            (t.key)()
        ));
    }
    (rows, skipped)
}

#[test]
fn every_linked_row_is_registered_under_its_plugins_yaml_manifest_name() {
    let (rows, mut skipped) = linked_rows();
    let (matched, mismatches, unanswered) = drift(&rows, &entries(REGISTRY));
    skipped.extend(unanswered);
    for line in &matched {
        eprintln!("held:    {line}");
    }
    for line in &skipped {
        eprintln!("skipped: {line}");
    }
    assert!(
        mismatches.is_empty(),
        "linked rows drifted from plugins.yaml:\n  {}",
        mismatches.join("\n  ")
    );
    for kind in ["store", "auth", "export", "secret"] {
        if kind != "store" && !rows.iter().any(|r| r.kind == kind) {
            continue;
        }
        assert!(
            matched.iter().any(|m| m.starts_with(&format!("{kind} "))),
            "no linked {kind} row was held (matched: {matched:?}; skipped: {skipped:?})"
        );
    }
}
