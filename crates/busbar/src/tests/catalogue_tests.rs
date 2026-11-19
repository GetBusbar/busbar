// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::diagnostic::Diagnostic;

fn installed() -> Vec<&'static Diagnostic> {
    crate::root::linked::register_diagnostics(&crate::LINKED).all()
}

#[cfg(linked_axis_export_doors)]
fn declared_by_linked_plugins() -> Vec<&'static Diagnostic> {
    use crate::root::linked::{declared_diagnostics, linked_declared_diagnostics, linked_exports};
    use crate::root::loader::PluginRegistry;

    let mut out = linked_declared_diagnostics(&LINKED, &[]).expect("linked declarations read");
    let exports = PluginRegistry::empty()
        .link(linked_exports(LINKED.export_doors).expect("linked export declarations read"))
        .expect("linked exports register");
    let export_codes = declared_diagnostics(&exports, &out).expect("linked export codes join");
    out.extend(export_codes);
    out
}

#[test]
fn every_diagnostic_code_is_unique_across_the_neutral_and_plane_catalogues() {
    let all = installed();
    assert!(
        !all.is_empty(),
        "the catalog must not be empty — the walk would assert nothing"
    );

    let mut by_code: std::collections::HashMap<u16, Vec<&str>> = std::collections::HashMap::new();
    let mut by_slug: std::collections::HashMap<&str, Vec<u16>> = std::collections::HashMap::new();
    for d in &all {
        by_code.entry(d.code).or_default().push(d.slug);
        by_slug.entry(d.slug).or_default().push(d.code);
    }

    let dup_codes: Vec<_> = by_code.iter().filter(|(_, v)| v.len() > 1).collect();
    assert!(
        dup_codes.is_empty(),
        "diagnostic CODES collide across the neutral and plane catalogues: {dup_codes:?}"
    );

    let dup_slugs: Vec<_> = by_slug.iter().filter(|(_, v)| v.len() > 1).collect();
    assert!(
        dup_slugs.is_empty(),
        "diagnostic SLUGS collide across the neutral and plane catalogues: {dup_slugs:?}"
    );
}

#[cfg(linked_axis_export_doors)]
#[test]
fn declared_codes_do_not_collide_with_the_registry() {
    let declared = declared_by_linked_plugins();
    assert!(!declared.is_empty(), "the linked plugins declare codes");
    let installed = busbar_kernel::diagnostics::REGISTRY;
    for d in declared {
        assert!(
            installed.iter().all(|r| r.code != d.code),
            "{} collides",
            d.code
        );
    }
}

#[cfg(all(linked_every_plane_door, linked_axis_export_doors))]
mod page {
    use super::*;
    use busbar_contract::json;
    use busbar_contract::json::JsonValueTrait as _;
    use busbar_kernel::diagnostics::{render_json_for, render_markdown_for, REGISTRY};

    const COMMITTED_MD: &str = concat!(env!("BUSBAR_CORE_DIR"), "/../../docs/diagnostics.md");

    const COMMITTED_JSON: &str = concat!(env!("BUSBAR_CORE_DIR"), "/../../docs/diagnostics.json");

    fn published_numbers() -> std::collections::BTreeSet<u64> {
        let text = std::fs::read_to_string(COMMITTED_JSON)
            .unwrap_or_else(|e| panic!("read {COMMITTED_JSON}: {e}"));
        let entries: Vec<json::Value> =
            json::parse_str(&text).expect("docs/diagnostics.json is a JSON array");
        entries
            .iter()
            .map(|e| e["number"].as_u64().expect("every entry has a number"))
            .collect()
    }

    fn host_page() -> Vec<&'static Diagnostic> {
        let published = published_numbers();
        let in_registry = |d: &Diagnostic| REGISTRY.iter().any(|r| r.code == d.code);
        let mut page: Vec<&'static Diagnostic> = REGISTRY.to_vec();
        page.extend(declared_by_linked_plugins());
        let declared_codes: std::collections::HashSet<_> = page.iter().map(|d| d.code).collect();
        page.extend(installed().into_iter().filter(|d| {
            !in_registry(d)
                && !declared_codes.contains(&d.code)
                && published.contains(&u64::from(d.code))
        }));
        page
    }

    fn committed_matches(path: &str, fresh: &str) {
        if std::env::var("UPDATE_DIAGNOSTICS").is_ok_and(|v| v == "1") {
            std::fs::write(path, fresh).unwrap_or_else(|e| panic!("write {path}: {e}"));
            return;
        }
        let committed = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("read {path}: {e} — generate it with UPDATE_DIAGNOSTICS=1"));
        assert_eq!(
            committed, fresh,
            "{path} is stale — regenerate with `UPDATE_DIAGNOSTICS=1 cargo test -p busbar catalogue_tests`"
        );
    }

    #[test]
    fn committed_markdown_matches_registry() {
        committed_matches(COMMITTED_MD, &render_markdown_for(&host_page()));
    }

    #[test]
    fn committed_json_matches_registry() {
        committed_matches(COMMITTED_JSON, &render_json_for(&host_page()));
    }
}

/// DES-337 §3.3: the generated metrics table in docs/observability.md, between its markers.
mod metric_table {
    use busbar_kernel::snapshot::catalogue::{MetricDecl, HOST_METRICS};

    const DOC: &str = concat!(env!("BUSBAR_CORE_DIR"), "/../../docs/observability.md");
    const COMMITTED: &str = include_str!(concat!(
        env!("BUSBAR_CORE_DIR"),
        "/../../docs/observability.md"
    ));
    const BEGIN: &str = "<!-- metric-catalogue:begin (generated from busbar_kernel::snapshot::catalogue::HOST_METRICS; regenerate with UPDATE_DIAGNOSTICS=1 and the busbar catalogue_tests) -->\n";
    const END: &str = "<!-- metric-catalogue:end -->\n";

    /// One row per catalogued family, sorted by name: name, type, label keys, unit, help.
    fn render() -> String {
        let mut rows: Vec<&MetricDecl> = HOST_METRICS.iter().collect();
        rows.sort_by_key(|d| d.name);
        let mut out =
            String::from("| Metric | Type | Labels | Unit | Help |\n|---|---|---|---|---|\n");
        for d in rows {
            let labels = if d.labels.is_empty() {
                "none".to_owned()
            } else {
                d.labels
                    .iter()
                    .map(|l| format!("`{l}`"))
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            out.push_str(&format!(
                "| `{}` | {} | {} | {} | {} |\n",
                d.name,
                d.kind.as_str(),
                labels,
                d.unit.map_or("none", |u| u.as_str()),
                d.help
            ));
        }
        out
    }

    /// The committed page with the generated table in place of whatever is between the markers.
    fn regenerated(page: &str) -> String {
        let (head, rest) = page
            .split_once(BEGIN)
            .expect("docs/observability.md carries the metric-catalogue begin marker");
        let (_, tail) = rest
            .split_once(END)
            .expect("docs/observability.md carries the metric-catalogue end marker");
        format!("{head}{BEGIN}{}{END}{tail}", render())
    }

    /// C4: the committed metrics table is the catalogue's.
    #[test]
    fn the_observability_metric_table_is_generated_from_the_catalogue() {
        let fresh = regenerated(COMMITTED);
        if std::env::var("UPDATE_DIAGNOSTICS").is_ok_and(|v| v == "1") {
            std::fs::write(DOC, &fresh).unwrap_or_else(|e| panic!("write {DOC}: {e}"));
            return;
        }
        assert_eq!(
            COMMITTED, fresh,
            "{DOC}'s metric table is stale: regenerate it with UPDATE_DIAGNOSTICS=1 and the busbar catalogue_tests"
        );
    }
}
