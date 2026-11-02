// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::diagnostic::Diagnostic;

fn installed() -> Vec<&'static Diagnostic> {
    register_diagnostics().all()
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
    use busbar_kernel::diagnostics::{render_json_for, render_markdown_for, REGISTRY};

    const COMMITTED_MD: &str = concat!(env!("BUSBAR_CORE_DIR"), "/../../docs/diagnostics.md");

    const COMMITTED_JSON: &str = concat!(env!("BUSBAR_CORE_DIR"), "/../../docs/diagnostics.json");

    fn published_numbers() -> std::collections::BTreeSet<u64> {
        let text = std::fs::read_to_string(COMMITTED_JSON)
            .unwrap_or_else(|e| panic!("read {COMMITTED_JSON}: {e}"));
        let entries: Vec<serde_json::Value> =
            serde_json::from_str(&text).expect("docs/diagnostics.json is a JSON array");
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
