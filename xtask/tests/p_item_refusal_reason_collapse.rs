// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! P-ITEM: REFUSAL-REASON COLLAPSE, the source half (spec DONE item 2, "All P-item behaviours match
//! 1.5.5"; the drive log's P1/P2, commit 470351a480; TODO L-ENG9).
//!
//! Eight hand-copied reason-to-family matches had drifted apart, and one still answered every
//! reason it did not name as an internal error. 1.5.5 answered each limit reason with its own
//! status and kind and none as a 500 (v1.5.5 `crates/busbar/src/ingress/mod.rs:237-305`). The fix
//! is ONE classification, `RefusalCode::class` in `busbar-contract`'s plane ABI, with every
//! renderer a class-to-wire table; `crates/busbar-contract/tests/p_item_refusal_reason_collapse.rs`
//! pins the classification itself.
//!
//! This file reads the renderers' source and proves none of them holds a reason match of its own,
//! so no renderer can drift from the others again. It lives here, beside the gates, because it
//! names every plane's renderer and the tree's crates may not name one another's planes.

use std::path::{Path, PathBuf};

/// The renderers, by file and function: each turns a reason into wire bytes, and each must ask the
/// one classification rather than decide for itself.
const RENDERERS: &[(&str, &[&str])] = &[
    (
        "crates/busbar-kernel/src/plane_driver/mod.rs",
        &["refusal_status", "class_status", "is_authentication"],
    ),
    (
        "crates/busbar-plane-llm/src/exchange/refuse.rs",
        &["kind_of", "kind_of_status", "is_authentication"],
    ),
    (
        "crates/busbar-plane-llm/src/plane.rs",
        &["refusal_shape", "refusal_message"],
    ),
    ("crates/busbar-plane-a2a/src/plane.rs", &["refusal_render"]),
    ("crates/busbar-plane-mcp/src/plane.rs", &["refusal_render"]),
    (
        "crates/busbar-plane-decisions/src/plane.rs",
        &["refusal_render"],
    ),
    (
        "crates/busbar-plane-streaming/src/plane.rs",
        &["refusal_render"],
    ),
    (
        "crates/busbar/src/root/units_admin/admin_mount.rs",
        &["answer_for"],
    ),
];

/// The renderers that used to match a reason by its spelling rather than its variant.
const SPELLED: &[&str] = &["crates/busbar-plane-llm/src/exchange/refuse.rs"];

/// Where the one classification lives; its match must name every reason.
const CLASSIFIER: (&str, &str) = ("crates/busbar-contract/src/abi/plane/mod.rs", "class");

/// The reason vocabulary's one written table: `Kernel => "spelling", Contract,`.
const VOCABULARY: &str = "crates/busbar-contract/src/caps/seat_verdict.rs";

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn read(file: &str) -> String {
    std::fs::read_to_string(root().join(file)).unwrap_or_else(|e| panic!("{file} is readable: {e}"))
}

/// One reason: its kernel name, its spelling, its contract name.
struct Reason {
    kernel: String,
    spelling: String,
    contract: String,
}

/// Every reason, read off the `reasons!` table.
fn vocabulary() -> Vec<Reason> {
    let src = read(VOCABULARY);
    let table = &src[src.find("reasons! {").expect("the reasons! table")..];
    let table = &table[..table.find("\n}\n").expect("the table's end")];
    let reasons: Vec<Reason> = table
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            let (kernel, rest) = line.split_once(" => \"")?;
            let (spelling, rest) = rest.split_once("\", ")?;
            let contract = rest.strip_suffix(',')?;
            Some(Reason {
                kernel: kernel.to_string(),
                spelling: spelling.to_string(),
                contract: contract.to_string(),
            })
        })
        .collect();
    assert!(
        reasons.len() >= 42,
        "the reasons! table read as {} reasons",
        reasons.len()
    );
    reasons
}

/// The body of `fn name` in `src`, braces matched; `None` when the file declares no such function.
fn body_of<'a>(src: &'a str, name: &str) -> Option<&'a str> {
    let start = [format!("fn {name}("), format!("fn {name}<")]
        .iter()
        .find_map(|head| src.find(head.as_str()))?;
    let open = start + src[start..].find('{')?;
    let mut depth = 0usize;
    for (i, c) in src[open..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&src[open..=open + i]);
                }
            }
            _ => {}
        }
    }
    None
}

/// Every reason variant as a match arm names it: under each of the three enums that spell the
/// vocabulary, or the short alias a renderer used for one of them.
fn variant_paths(reasons: &[Reason]) -> Vec<String> {
    let mut out = Vec::new();
    for r in reasons {
        for (path, name) in [
            ("ReasonCode", &r.kernel),
            ("RefusalCode", &r.kernel),
            ("RefusalReason", &r.contract),
            ("R", &r.contract),
            ("R", &r.kernel),
        ] {
            out.push(format!("{path}::{name}"));
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Whether `body` names `path` as a whole path (not as the prefix of a longer name).
fn names(body: &str, path: &str) -> bool {
    body.match_indices(path).any(|(i, _)| {
        let before = body[..i].chars().next_back();
        let after = body[i + path.len()..].chars().next();
        !before.is_some_and(|c| c.is_alphanumeric() || c == '_')
            && !after.is_some_and(|c| c.is_alphanumeric() || c == '_')
    })
}

/// What `RENDERERS` finds wrong in `read_file`'s view of the tree.
fn findings(reasons: &[Reason], read_file: &dyn Fn(&str) -> String) -> Vec<String> {
    let paths = variant_paths(reasons);
    let mut found = Vec::new();
    for (file, fns) in RENDERERS {
        let src = read_file(file);
        for name in *fns {
            let Some(body) = body_of(&src, name) else {
                found.push(format!("{file} declares no fn {name}"));
                continue;
            };
            for p in &paths {
                if names(body, p) {
                    found.push(format!("{file} fn {name} names the reason {p}"));
                }
            }
            if SPELLED.contains(file) {
                for r in reasons {
                    if body.contains(&format!("\"{}\"", r.spelling)) {
                        found.push(format!(
                            "{file} fn {name} names the reason by its spelling {}",
                            r.spelling
                        ));
                    }
                }
            }
        }
    }
    found
}

/// THE SOURCE SCAN: `RefusalCode::class` is the only reason-to-family match. No renderer names a
/// reason variant, and none of the spelled ones names a reason by its spelling, so a renderer can
/// only say how a family reads on its own wire.
#[test]
fn p_item_refusal_reason_collapse_class_is_the_only_reason_match() {
    let reasons = vocabulary();
    let found = findings(&reasons, &|f| read(f));
    assert!(found.is_empty(), "{}", found.join("\n"));
}

/// The one classification names every reason, so the scan above is not passing because nothing
/// classifies at all.
#[test]
fn p_item_refusal_reason_collapse_the_classifier_names_every_reason() {
    let reasons = vocabulary();
    let src = read(CLASSIFIER.0);
    let body = body_of(&src, CLASSIFIER.1).expect("RefusalCode::class");
    for r in &reasons {
        assert!(
            names(body, &format!("RefusalCode::{}", r.kernel)),
            "the classifier has no arm for {}",
            r.kernel
        );
    }
}

/// The scan bites: a renderer put back the old way (a reason match ending in a catch-all) is
/// caught, and a class arm whose name a reason shares is not mistaken for one.
#[test]
fn p_item_refusal_reason_collapse_the_scan_catches_a_reason_match() {
    let reasons = vocabulary();
    let old = r#"fn refusal_render(reason: busbar_contract::unit::RefusalReason) -> (&'static str, &'static str) {
    use busbar_contract::unit::RefusalReason as R;
    match reason {
        R::RateLimited | R::InFlightCap => ("rate_limited", "too many"),
        _ => ("internal", "no"),
    }
}
"#;
    let planted = findings(&reasons, &|f| {
        if f == "crates/busbar-plane-streaming/src/plane.rs" {
            old.to_string()
        } else {
            read(f)
        }
    });
    assert_eq!(
        planted,
        [
            "crates/busbar-plane-streaming/src/plane.rs fn refusal_render names the reason R::InFlightCap",
            "crates/busbar-plane-streaming/src/plane.rs fn refusal_render names the reason R::RateLimited",
        ]
    );
    let spelled = r#"fn kind_of(reason: &str, status: u16) -> &'static str {
    match reason { "over_budget" => "q", _ => "x" }
}
fn kind_of_status(status: u16) -> &'static str { "x" }
fn is_authentication(reason: &str) -> bool { false }
"#;
    let planted = findings(&reasons, &|f| {
        if f == SPELLED[0] {
            spelled.to_string()
        } else {
            read(f)
        }
    });
    assert_eq!(
        planted,
        [format!(
            "{} fn kind_of names the reason by its spelling over_budget",
            SPELLED[0]
        )]
    );
    assert!(!names(
        "RefusalClass::Unauthenticated =>",
        "R::Unauthenticated"
    ));
    assert!(!names("ReasonCode::OverBudgetX", "ReasonCode::OverBudget"));
}
