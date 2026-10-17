// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE KIND → VERB LIST HAS ONE SPELLING: a non-plane kind's config root key is read off
//! `Kind::verb()` in `busbar-contract/src/plugin.rs`, and no kernel, loader, `--validate` or
//! `busbar migrate` production source spells it as a string.
//!
//! A RATCHET, armed at the count measured when the list landed: each production file may hold at
//! most the quoted root keys `tests/fixtures/root_key_spelling.txt` records for it, and every
//! recorded count equals the measure (a drained spelling lowers its row in the same change). What
//! remains are the same words in other roles — a kind's NAME (`store`, `export`), a sub-key (a
//! pool's `hooks:`), the frozen grammar's serde `rename` — which a quoted-word scan cannot tell
//! from a root key, so they are held rather than counted as done. The words themselves are read
//! from the list, so this file spells none of them.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use busbar_contract::plugin::Kind;

/// The production roots the list governs: the kernel (config readers, `--validate`, `busbar
/// migrate`, the selection step), the loader, and the composition root.
const ROOTS: &[&str] = &[
    "crates/busbar-kernel/src",
    "crates/plugin-loader/src",
    "crates/busbar/src",
];

fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// A test-only source: kept literals are allowed there.
fn is_test_source(rel: &str) -> bool {
    let name = rel.rsplit('/').next().unwrap_or(rel);
    rel.contains("/tests/")
        || rel.contains("/testkit")
        || rel.contains("/test_support")
        || name.ends_with("tests.rs")
        || name.ends_with("_test.rs")
}

/// The quoted root keys, read off the list.
fn needles() -> Vec<String> {
    Kind::ALL
        .iter()
        .filter_map(|k| k.root_key())
        .map(|key| format!("\"{key}\""))
        .collect()
}

/// How many quoted root keys `text` holds.
fn count(text: &str, needles: &[String]) -> usize {
    needles
        .iter()
        .map(|n| text.matches(n.as_str()).count())
        .sum()
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            walk(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// Every production file under [`ROOTS`] holding at least one quoted root key, with its count.
fn measure() -> BTreeMap<String, usize> {
    let root = workspace();
    let needles = needles();
    let mut out = BTreeMap::new();
    for r in ROOTS {
        let mut files = Vec::new();
        walk(&root.join(r), &mut files);
        for f in files {
            let rel = f
                .strip_prefix(&root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            if is_test_source(&rel) {
                continue;
            }
            let n = count(&std::fs::read_to_string(&f).unwrap(), &needles);
            if n > 0 {
                out.insert(rel, n);
            }
        }
    }
    out
}

/// The armed ceilings: `path count` per line.
fn armed() -> BTreeMap<String, usize> {
    let text = include_str!("fixtures/root_key_spelling.txt");
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| {
            let (path, n) = l.rsplit_once(' ').expect("`path count`");
            (path.to_string(), n.parse().expect("a count"))
        })
        .collect()
}

/// The verdict: every refusal, or none. A file above its row, a file with no row, and a row above
/// its file's measure are each refused.
fn judge(measured: &BTreeMap<String, usize>, armed: &BTreeMap<String, usize>) -> Vec<String> {
    let mut refusals = Vec::new();
    for (path, &n) in measured {
        match armed.get(path) {
            None => refusals.push(format!(
                "{path}: {n} quoted root key(s), none armed — read it from Kind::verb()"
            )),
            Some(&a) if n > a => refusals.push(format!(
                "{path}: {n} > armed {a} — read it from Kind::verb()"
            )),
            _ => {}
        }
    }
    for (path, &a) in armed {
        let n = measured.get(path).copied().unwrap_or(0);
        if n < a {
            refusals.push(format!(
                "{path}: measured {n} < armed {a} — lower the row to the measure"
            ));
        }
    }
    refusals
}

#[test]
fn no_production_source_spells_a_kind_s_root_key_beyond_its_armed_count() {
    let refusals = judge(&measure(), &armed());
    assert!(refusals.is_empty(), "{}", refusals.join("\n"));
}

/// RED ARM (kept): one more quoted root key in a governed file is refused, and so is one in a file
/// with no row — measured against the real tree, with only the plant added.
#[test]
fn a_planted_root_key_spelling_is_refused() {
    let needles = needles();
    let mut planted = measure();
    let (path, n) = planted
        .iter()
        .next()
        .map(|(p, n)| (p.clone(), *n))
        .expect("a governed file");
    planted.insert(path.clone(), n + count(&needles[0], &needles));
    let refusals = judge(&planted, &armed());
    assert!(
        refusals
            .iter()
            .any(|r| r.starts_with(&format!("{path}: {} > armed", n + 1))),
        "{refusals:?}"
    );
    let mut planted = measure();
    planted.insert("crates/busbar-kernel/src/planted.rs".into(), 1);
    assert!(judge(&planted, &armed())
        .iter()
        .any(|r| r.contains("planted.rs: 1 quoted root key(s), none armed")));
}
