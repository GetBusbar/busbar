// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **ONE SOURCE FILE NAMES THE LOADER** (`BUSBAR-1.6.0.md` THE DESIGN, §3 Boot; ARCHITECT ruling
//! 2026-09-29: the one file is the `root::loader` module, and every other busbar file imports from
//! it).
//!
//! Any spelling of the loader crate's path, `<loader>::<item>`, in the composition root's source (its
//! unit tests excluded) outside `root/loader.rs` fails. The drain-only ledger this replaced (ARCHITECT
//! ruling 2026-09-28, BOOT-CHAIN (2)) was drained when every root site moved onto `root::loader`, so
//! no file other than `root/loader.rs` may name the loader.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// The loader crate's path, as the source spells it: read off this crate's manifest, the one
/// dependency whose `path` is the loader's directory, so the test never spells the crate itself.
fn needle() -> &'static str {
    static NEEDLE: OnceLock<String> = OnceLock::new();
    NEEDLE.get_or_init(|| {
        let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
        let text = std::fs::read_to_string(manifest).expect("read Cargo.toml");
        let dep = text
            .lines()
            .find(|l| l.contains("path = \"../plugin-loader\""))
            .and_then(|l| l.split('=').next())
            .expect("the composition root depends on the loader by path");
        format!("{}::", dep.trim().replace('-', "_"))
    })
}

/// The module that names the loader by design (`root::loader`).
const LOADER: &str = "root/loader.rs";

fn src() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).expect("read src").flatten() {
        let p = e.path();
        if p.is_dir() {
            if p.file_name().is_some_and(|n| n != "tests") {
                walk(&p, out);
            }
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// `file -> count` of every spelling of the loader's path.
fn measure(files: &[(String, String)]) -> BTreeMap<String, usize> {
    let needle = needle();
    let mut out = BTreeMap::new();
    for (file, text) in files {
        let n = text.matches(needle).count();
        if n > 0 {
            out.insert(file.clone(), n);
        }
    }
    out
}

fn verdict(files: &[(String, String)]) -> Vec<String> {
    measure(files)
        .into_iter()
        .filter(|(file, _)| file != LOADER)
        .map(|(file, n)| {
            format!(
                "{file} names the loader {n}x: the loader is named only by {LOADER}; import from crate::root::loader"
            )
        })
        .collect()
}

#[test]
fn the_loader_is_named_only_by_root_loader() {
    let root = src();
    let mut paths = Vec::new();
    walk(&root, &mut paths);
    let files: Vec<(String, String)> = paths
        .iter()
        .map(|p| {
            (
                p.strip_prefix(&root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/"),
                std::fs::read_to_string(p).unwrap(),
            )
        })
        .collect();
    assert!(
        files.iter().any(|(f, _)| f == "main.rs"),
        "the walk found the source"
    );
    assert!(
        measure(&files).contains_key(LOADER),
        "{LOADER} names the loader"
    );
    let problems = verdict(&files);
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

/// The test's own RED arm: a file other than `root/loader.rs` naming the loader fails.
#[test]
fn red_a_second_file_naming_the_loader_fails() {
    let needle = needle();
    let loader = vec![(LOADER.to_string(), format!("pub use {needle}*;"))];
    assert!(
        verdict(&loader).is_empty(),
        "{LOADER} names the loader freely"
    );
    let mut second = loader;
    second.push((
        "root/boot.rs".into(),
        format!("use {needle}{{PluginRegistry, load}};"),
    ));
    let problems = verdict(&second);
    assert_eq!(problems.len(), 1);
    assert!(problems[0].starts_with("root/boot.rs names the loader 1x"));
}
