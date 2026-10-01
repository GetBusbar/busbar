// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE EVIDENCE CHECK for `qa/field-coverage.status`: every `carried <test_fn>` claim must name a
//! test that is REAL EVIDENCE (test code, a test the harness runs, a body that asserts), under the
//! roots the field-owning crates publish as data. It is source scanning, so it lives with the
//! source classifier, `common`, in the composition root's tests. The field assertions themselves
//! (every id is a real path, the pinned missing list is exact) live with the plane that owns the
//! fields, in its own tests.

mod common;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const STATUS: &str = "qa/field-coverage.status";

fn repo_root() -> PathBuf {
    let mut dir = Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf();
    while !dir.join(STATUS).is_file() {
        assert!(dir.pop(), "no ancestor of the crate holds {STATUS}");
    }
    dir
}

/// The source roots a `carried` instrument may live in. DATA, read by path: every crate that owns
/// field claims keeps `tests/fixtures/evidence_roots.txt` beside its own tests, and this test
/// finds them by globbing `crates/*/tests/fixtures/`. A file path crossing is not a build input,
/// and this source names no plane.
///
/// Every root must EXIST ([`every_evidence_root_exists`]): a root that is not there reads as
/// "nothing to find" and never as a failure, which is how a stale path hides a shrinking search.
fn evidence_roots() -> Vec<String> {
    let mut roots = Vec::new();
    for e in std::fs::read_dir(repo_root().join("crates"))
        .unwrap()
        .flatten()
    {
        let f = e.path().join("tests/fixtures/evidence_roots.txt");
        if let Ok(text) = std::fs::read_to_string(&f) {
            roots.extend(
                text.lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty() && !l.starts_with('#'))
                    .map(String::from),
            );
        }
    }
    assert!(
        !roots.is_empty(),
        "no crate publishes an evidence_roots.txt: a search over nothing is not a gate"
    );
    roots
}

/// The `carried <test_fn>` names of `qa/field-coverage.status`: `<id> = carried <test_fn>`. The
/// file's own grammar is parsed in full by the owning plane's tests; this reads only that column.
fn carried_tests() -> BTreeSet<String> {
    std::fs::read_to_string(repo_root().join(STATUS))
        .unwrap_or_else(|e| panic!("cannot read {STATUS}: {e}"))
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .filter_map(|l| l.rsplit_once(" = "))
        .filter_map(|(_, r)| r.trim().strip_prefix("carried "))
        .map(|t| t.trim().to_string())
        .collect()
}

/// Every `.rs` under the evidence roots, classified once.
fn evidence_files() -> Vec<Vec<common::Line>> {
    let mut out = Vec::new();
    let mut stack: Vec<std::path::PathBuf> = evidence_roots()
        .iter()
        .map(|r| repo_root().join(r))
        .collect();
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().and_then(|x| x.to_str()) == Some("rs") {
                if let Ok(t) = std::fs::read_to_string(&p) {
                    out.push(common::classify(&t, common::is_test_path(&p)));
                }
            }
        }
    }
    out
}

#[test]
fn every_evidence_root_exists() {
    let roots = evidence_roots();
    let absent: Vec<&String> = roots
        .iter()
        .filter(|r| !repo_root().join(r).is_dir())
        .collect();
    assert!(
        absent.is_empty(),
        "evidence root(s) {absent:?} do not exist. A root that is not there is searched as empty \
         and never fails, so the search shrinks in silence — fix or drop the path."
    );
}

/// Every `carried` claim must name a test function that is REAL EVIDENCE: under
/// [`evidence_roots`], (1) test code, (2) a test the harness runs, and (3) a body that asserts.
#[test]
fn every_carried_claim_names_a_real_test() {
    let wanted = carried_tests();
    assert!(
        !wanted.is_empty(),
        "{STATUS} carries nothing: a check over nothing is not a gate"
    );
    let files = evidence_files();
    let ghosts: Vec<(&str, common::NotEvidence)> = wanted
        .iter()
        .filter_map(|t| {
            common::test_fn_is_evidence(&files, t)
                .err()
                .map(|why| (t.as_str(), why))
        })
        .collect();
    assert!(
        ghosts.is_empty(),
        "qa/field-coverage.status claims field(s) are `carried` by test(s) that are NOT EVIDENCE — \
         absent, production code, not a test the harness runs, or a body that asserts nothing. A \
         field whose instrument is imaginary is a field nothing would notice being dropped:\n\
         {ghosts:#?}"
    );
}

/// THE EVIDENCE CHECK FIRES on each thing it must refuse, and accepts the one shape it must accept.
#[test]
fn the_evidence_check_refuses_a_helper_a_comment_an_empty_test_and_production_code() {
    use common::NotEvidence;
    let file = |src: &str| vec![common::classify(src, false)];
    let real = "#[cfg(test)]\nmod tests {\n    #[test]\n    fn named() {\n        assert_eq!(1, 1);\n    }\n}\n";
    assert_eq!(common::test_fn_is_evidence(&file(real), "named"), Ok(()));
    let two_hops = "#[cfg(test)]\nmod tests {\n    fn outer() {\n        inner();\n    }\n    fn inner() {\n        assert!(true);\n    }\n    #[test]\n    fn named() {\n        outer();\n    }\n}\n";
    assert_eq!(
        common::test_fn_is_evidence(&file(two_hops), "named"),
        Ok(()),
        "a test that asserts through same-file helpers two deep is a test that asserts"
    );
    for (src, want) in [
        ("// fn named() { assert!(true) }\n", NotEvidence::Absent),
        ("fn named() {\n    assert!(true);\n}\n", NotEvidence::Production),
        (
            "#[cfg(test)]\nmod tests {\n    fn named() {\n        assert!(true);\n    }\n}\n",
            NotEvidence::NotATest,
        ),
        (
            "#[cfg(test)]\nmod tests {\n    #[test]\n    fn named() {}\n}\n",
            NotEvidence::AssertsNothing,
        ),
        (
            "#[cfg(test)]\nmod tests {\n    #[test]\n    fn not_named() {\n        assert!(true);\n    }\n}\n",
            NotEvidence::Absent,
        ),
    ] {
        assert_eq!(
            common::test_fn_is_evidence(&file(src), "named"),
            Err(want),
            "{src}"
        );
    }
}
