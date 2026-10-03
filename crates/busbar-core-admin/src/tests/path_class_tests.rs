// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The operator surface's PATH classifier ([`super::classify_path`]): which mutation budget a route
//! spends from. Moved here with the classifier from the kernel's `ratelimit` (1.6.0-TODO.md D4);
//! the budgets themselves are the kernel's and are tested there.

use super::{classify_path, PATH_CLASS_RULES};
use busbar_kernel::admin::refusal::{PATH_CONFIG_VALIDATE, PATH_PLUGINS_INSPECT};
use busbar_kernel::ratelimit::MutationClass;

/// `POST /plugins/inspect` gets its OWN dedicated budget — neither the CONFIG class nor the
/// shared CRUD class: burning the shared 60/min CRUD budget on N candidate-artifact inspections
/// during a fleet-wide plugin upgrade would starve real mutating work in the same window.
#[test]
fn plugin_inspect_is_classified_into_its_own_dedicated_bucket() {
    let class = classify_path(PATH_PLUGINS_INSPECT);
    assert!(matches!(class, MutationClass::PluginInspect));
    // The budget behind the class is the kernel's (`plugin_inspect_has_its_own_budget` there).
}

/// `/config/validate` and `/plugins/inspect` are BOTH `read-only`-scoped, stateless dry-run/
/// preview POSTs, but they must NOT share a rate bucket with each other or with CRUD — each has
/// its own dedicated class.
#[test]
fn config_validate_and_plugin_inspect_do_not_share_a_bucket() {
    assert!(matches!(
        classify_path(PATH_CONFIG_VALIDATE),
        MutationClass::Crud
    ));
    assert!(matches!(
        classify_path(PATH_PLUGINS_INSPECT),
        MutationClass::PluginInspect
    ));
}

/// ITEM 558: `PATH_CLASS_RULES` is not the only thing that decides class membership, and its doc
/// no longer says it is.
///
/// Three deciders run ahead of the table inside `classify_path`. Each is pinned here by a path
/// on which the table ALONE gives a different answer than the classifier does — so a reader who
/// took the table for the whole decision (as its doc told them to) would be wrong on every one — and
/// the table's own doc is held to naming all three.
#[test]
fn the_config_table_is_not_the_whole_answer_and_its_doc_names_what_else_decides() {
    let table_alone = |rel: &str| PATH_CLASS_RULES.iter().any(|rule| rule.matches(rel));
    // The validate carve-out: the table's `/config/` prefix says CONFIG, the classifier says CRUD.
    assert!(table_alone(PATH_CONFIG_VALIDATE));
    assert!(matches!(
        classify_path(PATH_CONFIG_VALIDATE),
        MutationClass::Crud
    ));
    // The inspect carve-out: absent from the table, its own class.
    assert!(!table_alone(PATH_PLUGINS_INSPECT));
    assert!(matches!(
        classify_path(PATH_PLUGINS_INSPECT),
        MutationClass::PluginInspect
    ));
    // The registry-derived named-map roots: absent from the table, CONFIG.
    for section in busbar_kernel::config::named_map::NamedMapSection::sections() {
        let rel = format!("{}/some-name", section.path_root());
        assert!(!table_alone(&rel), "{rel} is not a table row");
        assert!(
            matches!(classify_path(&rel), MutationClass::Config),
            "{rel} is CONFIG by the named-map scan"
        );
    }

    let source = include_str!("../rate.rs");
    let doc_start = source
        .find("pub const PATH_CLASS_RULES")
        .and_then(|at| source[..at].rfind("\n\n"))
        .expect("the table has a doc block");
    let doc = &source[doc_start..source.find("pub const PATH_CLASS_RULES").unwrap()];
    assert!(
        !doc.contains(&["nothing", "/// else decides class membership"].join("\n"))
            && !doc.contains("nothing else decides class membership"),
        "the table's doc claims to be the whole answer again"
    );
    for decider in ["/config/validate", "/plugins/inspect", "named-map root"] {
        assert!(
            doc.contains(decider),
            "the table's doc does not name the decider that runs ahead of it: {decider}"
        );
    }
}

/// A NAMED-MAP ROOT MATCHES ON A PATH-SEGMENT BOUNDARY (architect ruling 2026-09-24). `/export` and
/// everything under `/export/` is the section's CONFIG blast radius; `/export-keyset` merely shares
/// its first six characters and is not — a prefix match put it on the 10/min budget.
#[test]
fn a_named_map_root_matches_on_a_segment_boundary_only() {
    for section in busbar_kernel::config::named_map::NamedMapSection::sections() {
        let root = section.path_root();
        for inside in [
            root.to_string(),
            format!("{root}/n"),
            format!("{root}/n/settings"),
        ] {
            assert!(
                matches!(classify_path(&inside), MutationClass::Config),
                "{inside} is the section's own path"
            );
        }
        let neighbour = format!("{root}-keyset");
        assert!(
            matches!(classify_path(&neighbour), MutationClass::Crud),
            "{neighbour} only shares the root's leading characters"
        );
    }
}
