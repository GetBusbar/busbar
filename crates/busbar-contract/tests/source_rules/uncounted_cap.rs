// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Plugin-supplied text is never cut silently. The uncounted cap functions return only the cut
//! value and drop the fact that the input was longer, so production source outside the contract's
//! own reply module may not name them at all. The counted forms return that fact as a separate
//! value a caller could drop, so they may be named only in the files that report it, each pinned by
//! a behaviour test. The rule reads identifiers, not call shapes: a call, a fn value, a `use`
//! (renamed or re-exported) and a macro's tokens all name the function.

use crate::walk;
use proc_macro2::TokenTree;

/// Where the cap functions live.
const HOME: &str = "crates/busbar-contract/src/hook_wire/reply.rs";

/// Return only the capped value: banned outside [`HOME`].
const UNCOUNTED: [&str; 2] = ["parse_status_metrics", "sanitize_cap"];

/// Return the cut as a droppable fact: allowed only in [`REPORTERS`].
const COUNTED: [&str; 4] = [
    "parse_status_metrics_counted",
    "sanitize_cap_counted",
    "sanitize_reject_message_counted",
    "TextCuts",
];

/// The files that report every cut they are handed, each with the behaviour test that pins it:
/// `hooks/text_cut.rs` (its own tests, T3) and `observe.rs` (`tests/observe_tests.rs` and
/// the root's `root/tests/observe.rs`, T2). Adding a file here needs a test that pins its report.
const REPORTERS: [&str; 2] = [
    "crates/busbar-kernel/src/hooks/text_cut.rs",
    "crates/busbar-kernel/src/observe.rs",
];

fn findings(sources: &[walk::Source]) -> Vec<String> {
    let mut out = Vec::new();
    for src in sources {
        if src.rel == HOME {
            continue;
        }
        let reporter = REPORTERS.contains(&src.rel.as_str());
        for item in walk::items(&src.file.items) {
            for tt in walk::tokens(item) {
                let TokenTree::Ident(ident) = &tt else {
                    continue;
                };
                let text = ident.to_string();
                let name = text.strip_prefix("r#").unwrap_or(&text);
                let line = ident.span().start().line;
                if UNCOUNTED.contains(&name) {
                    out.push(format!(
                        "{}:{line}: `{name}` cuts plugin text and drops the cut; use \
                         a counted form in a reporting file",
                        src.rel
                    ));
                } else if COUNTED.contains(&name) && !reporter {
                    out.push(format!(
                        "{}:{line}: `{name}` hands back a cut this file does not report; only {} \
                         may name it",
                        src.rel,
                        REPORTERS.join(", ")
                    ));
                }
            }
        }
    }
    out
}

#[test]
fn no_production_source_cuts_plugin_text_without_reporting_it() {
    let found = findings(&walk::production(&["crates"]));
    assert!(found.is_empty(), "{}", found.join("\n"));
}

#[test]
fn the_rule_sees_every_spelling_that_names_a_cap_function() {
    let source = |rel: &str, text: &str| walk::Source {
        rel: rel.to_string(),
        file: syn::parse_file(text).unwrap(),
    };
    let elsewhere = "crates/busbar-kernel/src/snapshot/hooks.rs";
    for (text, ident) in [
        (
            "fn f(m: &[V]) { busbar_contract::hook_wire::reply::parse_status_metrics(m); }",
            "parse_status_metrics",
        ),
        (
            "fn f(m: Option<&Vec<V>>) { m.map(|m| reply::parse_status_metrics(m)); }",
            "parse_status_metrics",
        ),
        (
            "fn f(m: Option<&Vec<V>>) { m.map(Vec::as_slice).map(reply::parse_status_metrics); }",
            "parse_status_metrics",
        ),
        (
            "use busbar_contract::hook_wire::reply::parse_status_metrics as p;",
            "parse_status_metrics",
        ),
        (
            "pub use busbar_contract::hook_wire::reply::sanitize_cap;",
            "sanitize_cap",
        ),
        (
            "fn f() { tracing::warn!(\"{}\", sanitize_cap(x, 3)); }",
            "sanitize_cap",
        ),
        (
            "fn f(m: &[V]) -> Vec<M> { reply::parse_status_metrics_counted(m).0 }",
            "parse_status_metrics_counted",
        ),
        (
            "fn f(m: &[V]) -> Vec<M> { let (v, _) = reply::parse_status_metrics_counted(m); v }",
            "parse_status_metrics_counted",
        ),
        ("fn f(c: &reply::TextCuts) {}", "TextCuts"),
        (
            "fn f(s: &str) -> String { reply::sanitize_reject_message_counted(s).0 }",
            "sanitize_reject_message_counted",
        ),
    ] {
        let found = findings(&[source(elsewhere, text)]);
        assert_eq!(found.len(), 1, "{text}: {found:?}");
        assert!(
            found[0].starts_with(&format!("{elsewhere}:1: `{ident}`")),
            "{text}: {found:?}"
        );
    }

    let counted = "fn f(m: &[V]) -> Vec<M> { reply::parse_status_metrics_counted(m).0 }";
    assert!(
        findings(&[source("crates/busbar-kernel/src/observe.rs", counted)]).is_empty(),
        "a reporting file may name the counted forms"
    );
    assert_eq!(
        findings(&[source(
            "crates/busbar-kernel/src/observe.rs",
            "fn f(m: &[V]) { reply::parse_status_metrics(m); }"
        )])
        .len(),
        1,
        "no file may name the uncounted forms"
    );
    assert!(
        findings(&[source(HOME, "fn f(m: &[V]) { parse_status_metrics(m); }")]).is_empty(),
        "the reply module defines them"
    );
    assert!(
        findings(&[source(
            elsewhere,
            "#[cfg(test)] mod t { fn f(m: &[V]) { reply::parse_status_metrics(m); } }"
        )])
        .is_empty(),
        "test code is not production"
    );
}
