// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DIAGNOSTICS CATALOGUE THIS BINARY SERVES, held to its two invariants: no code and no slug is
//! listed twice across the host registry and every catalogue the composition root installs, and the
//! published host page (`docs/diagnostics.{md,json}`) is a fresh render of codes defined in code.
//!
//! Both live HERE because this binary is the only place every half exists at once: the host
//! registry (`busbar_kernel::diagnostics::REGISTRY`), each linked plane's own catalogue — a plane
//! that took a code out of the host registry together with the code that emits it (#83a O4) keeps
//! publishing it on the host page under its frozen number — and the codes the linked first-party
//! plugins declare (K9a S3). Regenerate the page after a registry change with:
//!   `UPDATE_DIAGNOSTICS=1 cargo test -p busbar catalogue_tests`

use super::*;
use busbar_contract::diagnostic::Diagnostic;

/// The runtime catalogue — the host registry and every linked plane's own — as the composition root
/// installs it, installed ONCE for this test binary (a second `install_diagnostics` panics by design).
fn installed() -> Vec<&'static Diagnostic> {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(register_diagnostics);
    busbar_kernel::diagnostics::all()
}

/// The codes the linked first-party plugins DECLARE (K9a S3), read off each linked row's `declares`
/// section exactly as the plugin states it — the same field-by-field reading the composition root's
/// declaration check makes, so the page documents what the catalogue installs. Read only by the
/// `linked_axis_export_doors` cells, so gated with them.
#[cfg(linked_axis_export_doors)]
fn declared_by_linked_plugins() -> Vec<&'static Diagnostic> {
    use busbar_contract::diagnostic::{Class, Severity};
    let leak = |v: &serde_json::Value| -> &'static str {
        Box::leak(
            v.as_str()
                .expect("a string field")
                .to_string()
                .into_boxed_str(),
        )
    };
    let mut out = Vec::new();
    // The export axis: each memory-ABI row on `export-doors` states its `declares`.
    let rows = LINKED.export_doors.iter().map(|d| (d.name, d.declares));
    for (name, declares) in rows {
        let decl: serde_json::Value = serde_json::from_str(declares)
            .unwrap_or_else(|e| panic!("linked export '{name}': its declares section: {e}"));
        for d in decl["diagnostics"].as_array().into_iter().flatten() {
            let code = d["code"].as_u64().expect("a code") as u16;
            let severity = [
                Severity::BenignRecurring,
                Severity::Actionable,
                Severity::Fatal,
            ]
            .into_iter()
            .find(|s| s.as_str() == d["severity"])
            .expect("a severity token");
            let class = Class::ALL
                .into_iter()
                .find(|c| c.ordinal() == code / 1000)
                .expect("a class");
            out.push(&*Box::leak(Box::new(Diagnostic {
                code,
                class,
                slug: leak(&d["slug"]),
                title: leak(&d["title"]),
                severity,
                summary: leak(&d["summary"]),
                action: leak(&d["action"]),
                since: leak(&d["since"]),
                retired: false,
            })));
        }
    }
    out
}

/// EVERY DIAGNOSTIC CODE IS UNIQUE ACROSS THE WHOLE CATALOG — the host registry in `busbar-kernel`
/// AND every plane catalogue the composition root installs.
///
/// Each half is internally consistent on its own, and neither crate can see the other: a plane
/// numbers its codes without the host registry in scope, and the host registry is compiled
/// long before any plane is linked. THIS binary is the only place both halves exist at once, which
/// is why the check lives here. A collision is not cosmetic — `by_code` resolves a code to the FIRST
/// match, so a duplicate makes one diagnostic permanently unreachable and makes `busbar explain
/// <code>` and a rendered catalog describe the wrong failure.
///
/// `slug` is checked too, for the same reason: it is the other stable handle a catalog is keyed by.
#[test]
fn every_diagnostic_code_is_unique_across_the_neutral_and_plane_catalogues() {
    // The composition root's own registration, so `all()` returns the real runtime union rather
    // than the host half alone.
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

/// A declared code never collides with the catalogue (the root refuses that at boot; the page would
/// document two meanings for one banner) — and the linked plugins do declare codes, so the page's
/// declared half is not vacuously empty.
// "The linked plugins declare codes" reads the linked export rows' declared codes; a build that
// links no plugin (`--no-default-features`) declares none, so this cell gates on the exports axis.
#[cfg(linked_axis_export_doors)]
#[test]
fn declared_codes_do_not_collide_with_the_registry() {
    let declared = declared_by_linked_plugins();
    assert!(!declared.is_empty(), "the linked plugins declare codes");
    let installed = installed();
    for d in declared {
        assert!(
            installed.iter().all(|r| r.code != d.code),
            "{} collides",
            d.code
        );
    }
}

// ── DOCS-IN-SYNC ────────────────────────────────────────────────────────────────────────────
//
// THE PUBLISHED PAGE DOCUMENTS THE SHIPPED CATALOGUE: the host registry, every plane's catalogue and
// the linked export sinks' declared codes. A feature-set build that links fewer rows (a single-plane
// row, `--no-default-features`) installs fewer catalogues, so its render is a DIFFERENT page, not a
// stale one; the pair below is compiled only where every plane and the export axis are linked. The
// uniqueness checks above run in every build.
#[cfg(all(linked_every_plane, linked_axis_export_doors))]
mod page {
    use super::*;
    use busbar_kernel::diagnostics::{render_json_for, render_markdown_for, REGISTRY};

    /// The committed operator page, relative to this crate's manifest dir.
    const COMMITTED_MD: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/diagnostics.md");
    /// The committed machine-readable page.
    const COMMITTED_JSON: &str =
        concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/diagnostics.json");

    /// The numbers the committed JSON page publishes.
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

    /// THE HOST PAGE'S ENTRIES, each rendered from its defining constant: every code the host registry
    /// defines, every code a linked first-party plugin declares, and every linked plane's code the page
    /// publishes. A plane code the page does not publish belongs to that plane's own page
    /// (`docs/diagnostics-<plane>.md`) — one code, one page.
    fn host_page() -> Vec<&'static Diagnostic> {
        let published = published_numbers();
        let in_registry = |d: &Diagnostic| REGISTRY.iter().any(|r| r.code == d.code);
        let mut page: Vec<&'static Diagnostic> = REGISTRY.to_vec();
        page.extend(declared_by_linked_plugins());
        page.extend(
            installed()
                .into_iter()
                .filter(|d| !in_registry(d) && published.contains(&u64::from(d.code))),
        );
        page
    }

    /// Compare `fresh` with the committed file at `path`, or write it under `UPDATE_DIAGNOSTICS=1`.
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

    // The committed docs/diagnostics.{md,json} MUST equal a fresh render of the host page.

    #[test]
    fn committed_markdown_matches_registry() {
        committed_matches(COMMITTED_MD, &render_markdown_for(&host_page()));
    }

    #[test]
    fn committed_json_matches_registry() {
        committed_matches(COMMITTED_JSON, &render_json_for(&host_page()));
    }
}
