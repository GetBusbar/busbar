// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CANONICAL-NAME DRIFT GUARD (ARCHITECT C'): one plugin has ONE identity whichever door it
//! arrives by. Its canonical name is plugins.yaml's `manifest_name` (default: the repo), the name
//! its release tarball's signed manifest carries; a row this build LINKS must be registered under
//! that same name, or the same plugin dropped in beside it is a second plugin claiming its alias.
//!
//! Every linked row the registry or a door axis holds is read here — the stores and auths (the
//! kernel's own row constructors over the root's tables), the export sinks and the secret sources —
//! and held to the plugins.yaml entry of the same kind that answers one of its aliases. A row no
//! entry answers is SKIPPED, and printed with the reason; so is every row of an axis this guard
//! does not hold yet. Nothing is skipped silently. The plugin names are data: this file spells none.

use super::linked_exports;
use crate::root::loader::boot::Candidate;
use crate::root::loader::LinkedPlugin;

/// THE REGISTRY, read as the legacy table's test reads it (`root/tests/legacy.rs`).
const REGISTRY: &str = include_str!("../../../../../plugins.yaml");

/// One plugins.yaml entry, as this guard reads it.
struct Entry {
    kind: String,
    alias: String,
    /// `manifest_name`, defaulting to the repo.
    manifest_name: String,
}

/// Every entry of `registry`.
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

/// One linked row, as this guard reads it: its kind, its canonical name, and every other name
/// config may give it.
struct Row {
    kind: String,
    canonical: String,
    aliases: Vec<String>,
}

impl Row {
    /// A registry row (`LinkedPlugin`): its manifest's name, alias and former names.
    fn of(row: &LinkedPlugin) -> Self {
        let m = &row.manifest;
        Self {
            kind: m.kind.clone(),
            canonical: m.name.clone(),
            aliases: m.config_names().map(str::to_string).collect(),
        }
    }

    /// A door axis's row (a `Candidate`): its Statement's name and aliases.
    fn of_door(c: &Candidate, kind: &str) -> Self {
        Self {
            kind: kind.to_string(),
            canonical: c.name.clone(),
            aliases: c.aliases.clone(),
        }
    }
}

/// THE VERDICT over `rows` against `entries`: `(matched, mismatches, skipped)` — each row held to
/// the entry of its kind that answers one of its aliases (or its canonical name); a row no entry
/// answers is skipped, with the reason.
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

/// Every linked row this guard holds (stores, auths, export sinks, secret sources), and the rows
/// of the axes it does not hold yet, each with the reason.
fn linked_rows() -> (Vec<Row>, Vec<String>) {
    let mut rows: Vec<Row> = Vec::new();
    let stores = crate::LINKED.stores.iter();
    rows.extend(stores.map(|s| Row::of(&busbar_kernel::preflight::linked_store_row(s))));
    let auths = crate::LINKED.auths.iter();
    rows.extend(auths.map(|a| Row::of(&busbar_kernel::preflight::linked_auth_row(a))));
    let exports = linked_exports(crate::LINKED.export_doors).expect("the export rows state");
    rows.extend(exports.iter().map(Row::of));
    for door in crate::LINKED.secrets {
        let c = Candidate::linked(*door).expect("a linked secret states itself");
        rows.push(Row::of_door(&c, "secret"));
    }
    let entries = entries(REGISTRY);
    let mut skipped = Vec::new();
    // THE HOOK ROWS ARE NOT HELD YET: on predev the linked hook row is the in-tree crate's door,
    // which states its pre-C' name, until P5 #484 re-pins the repo, whose Statement states the
    // plugins.yaml manifest_name. Printed with what it will be held to.
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
            t.key
        ));
    }
    (rows, skipped)
}

/// EVERY LINKED ROW CARRIES ITS PLUGIN'S CANONICAL NAME: the name plugins.yaml gives the entry of
/// its kind and alias. The rows held are printed matched; every row not held is printed with why.
/// It cannot pass empty: each held axis has a matched row.
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
            continue; // this build links none of the kind (a feature is off)
        }
        assert!(
            matched.iter().any(|m| m.starts_with(&format!("{kind} "))),
            "no linked {kind} row was held (matched: {matched:?}; skipped: {skipped:?})"
        );
    }
}

/// THE GUARD GOES RED on a linked row registered under its alias (the pre-C' shape: the store's
/// short word as its name), fed through the same constructor the kernel's row comes from; and on a
/// planted row whose canonical name is not plugins.yaml's.
#[test]
fn a_row_registered_under_its_alias_is_drift() {
    let entries = entries(REGISTRY);
    let &(key, ephemeral, door, canonical) = crate::LINKED
        .stores
        .first()
        .expect("the build links a store");
    let old = Row::of(&LinkedPlugin::store(key, door, ephemeral));
    let (_, mismatches, _) = drift(&[old], &entries);
    assert_eq!(mismatches.len(), 1, "the alias-named row is drift");
    assert!(
        mismatches[0].contains(&format!("whose manifest_name is '{canonical}'")),
        "{}",
        mismatches[0]
    );
    let planted = Row {
        kind: "store".into(),
        canonical: format!("{canonical}-planted"),
        aliases: vec![key.to_string()],
    };
    let (matched, mismatches, skipped) = drift(&[planted], &entries);
    assert!(matched.is_empty() && skipped.is_empty() && mismatches.len() == 1);
    // A row no entry answers is skipped and said, never matched or passed silently.
    let stray = Row {
        kind: "store".into(),
        canonical: "no-such-plugin".into(),
        aliases: vec!["no-such-alias".into()],
    };
    let (matched, mismatches, skipped) = drift(&[stray], &entries);
    assert!(matched.is_empty() && mismatches.is_empty());
    assert!(skipped[0].contains("no plugins.yaml entry of kind store answers it"));
}
