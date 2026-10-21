//! WHICH OF THE PINNED PLANES' FILES A CI RUNS (BUSBAR-1.6.0.md Law 10: no proof cites a test that
//! never runs).
//!
//! A plane that left this tree is laid back at `crates/<package>` by the context's BASE layer, and
//! the design-bindings index reads its files as it reads the disk ([`super::verify::Ctx::add_laid`]).
//! Laid is not run. This tree's CI never runs a pinned crate's own tests, and the plane repo's CI
//! runs only the cargo targets of its own workspace. A directory such as `tests/on_driver/`, which has
//! no `main.rs` and is compiled only into the composition root's suites, runs nowhere unless a root
//! row brings it in. So a laid `.rs` file counts only when one of these runners is shown to reach it:
//!
//! * THE PLUGIN REPO'S OWN CI. The package is a first-party plugin repo in `plugins.yaml` (repo =
//!   logic crate), and the fleet harness every such repo's `ci.yml` calls
//!   (`.github/workflows/plugin-ci.yml`) runs `cargo test --workspace`. Its targets are cargo's: the
//!   build script, `src/lib.rs`, `src/main.rs`, every `tests/<name>.rs` and `tests/<name>/main.rs`
//!   (unless `autotests = false`), and every `[[test]]` path.
//! * THE COMPOSITION ROOT'S SUITES ([`ROOT_SUITES`]). A root manifest row names the plane crate, the
//!   row's feature is in the root's default build, the suite on disk includes the file `build.rs`
//!   generates for that row, and a `.ci/*.yaml` check runs the workspace's tests
//!   (`cargo nextest run --workspace`). Then the crate's entry file runs in that suite.
//!
//! From each root the run set follows the module tree: `mod name;` resolves as rustc resolves it
//! (`#[path]`, `mod.rs` and non-`mod.rs` parents, and inline `mod name { .. }` blocks). A file that
//! no runner reaches is not run. Its test fns are not indexed, and a citation of it is refused by
//! name.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crate::ctx::Ctx;

/// The registry of first-party plugin repos.
const REGISTRY_REL: &str = "plugins.yaml";

/// The fleet harness every plugin repo's `ci.yml` calls, and the run it must hold.
const HARNESS_REL: &str = ".github/workflows/plugin-ci.yml";
const HARNESS_RUN: &str = "cargo test --workspace";

/// The composition root's manifest, and the run a `.ci/*.yaml` check must hold for its suites.
const ROOT_MANIFEST_REL: &str = "crates/busbar/Cargo.toml";
const CI_DIR_REL: &str = ".ci";
const ROOT_RUN: &str = "cargo nextest run --workspace";

/// The `linked-axes` axis that makes a linked row a plane's memory-ABI door.
const PLANE_DOOR_AXIS: &str = "plane-door";

/// Which root rows a suite reads.
enum Rows {
    /// `[package.metadata.busbar.driver-proofs]`: feature -> plane crate.
    DriverProofs,
    /// `[package.metadata.busbar.linked]` rows whose `linked-axes` carry [`PLANE_DOOR_AXIS`].
    PlaneDoors,
}

/// One root suite that compiles a plane crate's file into this tree's tests.
struct RootSuite {
    rows: Rows,
    /// The file it compiles, relative to the plane crate's `tests/` (never a path from the repo
    /// root: it names a file of every plane crate the suite's rows name).
    entry: &'static str,
    /// The suite on disk that includes it.
    suite: &'static str,
    /// The generated file the suite includes (`include!(concat!(env!("OUT_DIR"), ..))`).
    include: &'static str,
}

/// THE ROOT'S RUNNER MANIFEST: every way the composition root's tests compile a plane crate's file.
const ROOT_SUITES: &[RootSuite] = &[
    RootSuite {
        rows: Rows::DriverProofs,
        entry: "on_driver/mod.rs",
        suite: "crates/busbar/tests/hook_parity_driver/main.rs",
        include: "/driver_proofs.rs",
    },
    RootSuite {
        rows: Rows::PlaneDoors,
        entry: "root/mod.rs",
        suite: "crates/busbar/src/root/serve.rs",
        include: "/door_cells.rs",
    },
];

/// The laid `.rs` files some CI runs, by path (`crates/<package>/...`). `laid` is the BASE layer's
/// files as [`super::laid_files`] reads them.
pub fn laid_runs(cx: &Ctx, laid: &[(String, String)]) -> BTreeSet<String> {
    let files: BTreeMap<&str, &str> = laid
        .iter()
        .map(|(rel, text)| (rel.as_str(), text.as_str()))
        .collect();
    let packages: BTreeSet<&str> = files
        .keys()
        .filter_map(|rel| rel.strip_prefix("crates/")?.split('/').next())
        .collect();
    let mut roots: Vec<String> = Vec::new();
    let repos = plugin_repos(cx);
    for package in &packages {
        if repos.contains(*package) {
            roots.extend(cargo_test_roots(package, &files));
        }
    }
    roots.extend(root_suite_entries(cx));
    module_closure(&roots, &files)
}

/// The packages whose own repo's CI runs `cargo test --workspace`: every `plugins.yaml` repo, when
/// the fleet harness runs it. Empty when either does not read or the harness no longer runs it.
fn plugin_repos(cx: &Ctx) -> BTreeSet<String> {
    let harness = cx.read(HARNESS_REL).unwrap_or_default();
    if !super::verify::strip_unrunnable(&harness).contains(HARNESS_RUN) {
        return BTreeSet::new();
    }
    cx.read(REGISTRY_REL)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| l.trim().strip_prefix("- repo:"))
        .map(|r| r.trim().trim_matches('"').to_string())
        .filter(|r| !r.is_empty())
        .collect()
}

/// The targets `cargo test` runs for one laid package (see the module doc).
fn cargo_test_roots(package: &str, files: &BTreeMap<&str, &str>) -> Vec<String> {
    let at = format!("crates/{package}/");
    let manifest = files
        .get(format!("{at}Cargo.toml").as_str())
        .copied()
        .map(crate::toml_lite::parse_text);
    let mut out: Vec<String> = ["build.rs", "src/lib.rs", "src/main.rs"]
        .iter()
        .map(|f| format!("{at}{f}"))
        .collect();
    let autotests = manifest
        .as_ref()
        .is_none_or(|m| m.table("package").get_one("autotests") != Some("false"));
    if autotests {
        let tests = format!("{at}tests/");
        for rel in files.keys() {
            let Some(rest) = rel.strip_prefix(tests.as_str()) else {
                continue;
            };
            let target = match rest.split_once('/') {
                None => rest.ends_with(".rs"),
                Some((_, file)) => file == "main.rs",
            };
            if target {
                out.push((*rel).to_string());
            }
        }
    }
    for test in manifest
        .as_ref()
        .map(|m| m.array_table("test"))
        .unwrap_or_default()
    {
        if let Some(path) = test.get_one("path") {
            out.push(normalize(&format!("{at}{path}")));
        } else if let Some(name) = test.get_one("name") {
            out.push(format!("{at}tests/{name}.rs"));
        }
    }
    out
}

/// The entry file of every plane crate a [`ROOT_SUITES`] suite compiles in the root's default
/// build, when this tree's CI runs the workspace's tests.
fn root_suite_entries(cx: &Ctx) -> Vec<String> {
    if !ci_runs_the_workspace(cx) {
        return Vec::new();
    }
    let Ok(text) = cx.read(ROOT_MANIFEST_REL) else {
        return Vec::new();
    };
    let manifest = crate::toml_lite::parse_text(&text);
    let on = default_closure(&manifest);
    let rows = |table: &str| -> Vec<(String, String)> {
        manifest
            .table(table)
            .values
            .into_iter()
            .filter_map(|(k, v)| Some((k, v.into_iter().next()?)))
            .collect()
    };
    let mut out = Vec::new();
    for suite in ROOT_SUITES {
        let includes = cx.read(suite.suite).is_ok_and(|s| {
            s.lines().any(|l| {
                l.contains("include!(concat!(env!(\"OUT_DIR\")") && l.contains(suite.include)
            })
        });
        if !includes {
            continue;
        }
        let crates: Vec<String> = match suite.rows {
            Rows::DriverProofs => rows("package.metadata.busbar.driver-proofs")
                .into_iter()
                .filter(|(feature, _)| on.contains(feature))
                .map(|(_, krate)| krate)
                .collect(),
            Rows::PlaneDoors => {
                let axes = rows("package.metadata.busbar.linked-axes");
                rows("package.metadata.busbar.linked")
                    .into_iter()
                    .filter(|(feature, _)| {
                        on.contains(feature)
                            && axes.iter().any(|(f, a)| {
                                f == feature && a.split_whitespace().any(|x| x == PLANE_DOOR_AXIS)
                            })
                    })
                    .map(|(_, krate)| krate)
                    .collect()
            }
        };
        out.extend(
            crates
                .into_iter()
                .map(|krate| format!("crates/{krate}/tests/{}", suite.entry)),
        );
    }
    out
}

/// Whether a `.ci/*.yaml` check runs the workspace's tests.
fn ci_runs_the_workspace(cx: &Ctx) -> bool {
    let Ok(dir) = std::fs::read_dir(cx.abs(CI_DIR_REL)) else {
        return false;
    };
    dir.flatten()
        .filter_map(|e| e.file_name().to_str().map(str::to_string))
        .filter(|n| n.ends_with(".yaml") || n.ends_with(".yml"))
        .any(|n| {
            cx.read(format!("{CI_DIR_REL}/{n}"))
                .is_ok_and(|t| super::verify::strip_unrunnable(&t).contains(ROOT_RUN))
        })
}

/// The features the root's default build turns on: `default`, closed over the feature table
/// (`dep:` rows and `crate/feature` rows name no feature of this crate).
fn default_closure(manifest: &crate::toml_lite::Document) -> BTreeSet<String> {
    let table = manifest.table("features").values;
    let mut on: BTreeSet<String> = BTreeSet::new();
    let mut todo: Vec<String> = table.get("default").cloned().unwrap_or_default();
    while let Some(f) = todo.pop() {
        if f.starts_with("dep:") || f.contains('/') || !on.insert(f.clone()) {
            continue;
        }
        todo.extend(table.get(&f).cloned().unwrap_or_default());
    }
    on
}

/// Every laid file the module tree reaches from `roots` (a root that is not laid reaches nothing).
fn module_closure(roots: &[String], files: &BTreeMap<&str, &str>) -> BTreeSet<String> {
    let crate_roots: BTreeSet<&str> = roots.iter().map(String::as_str).collect();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut todo: Vec<String> = roots
        .iter()
        .filter(|r| files.contains_key(r.as_str()))
        .cloned()
        .collect();
    while let Some(rel) = todo.pop() {
        if !seen.insert(rel.clone()) {
            continue;
        }
        let Some(text) = files.get(rel.as_str()) else {
            continue;
        };
        let owns_dir = crate_roots.contains(rel.as_str()) || rel.ends_with("/mod.rs");
        for (inline, name, path) in child_modules(text) {
            for child in child_paths(&rel, owns_dir, &inline, &name, path.as_deref()) {
                if files.contains_key(child.as_str()) && !seen.contains(&child) {
                    todo.push(child);
                }
            }
        }
    }
    seen
}

/// The candidate files of `mod name;` declared in `parent` inside the inline modules `inline`, as
/// rustc resolves them: a `#[path]` is relative to the parent's directory (and its inline modules);
/// otherwise a `mod.rs` or crate-root parent owns its directory and any other parent owns the
/// directory named for its stem.
fn child_paths(
    parent: &str,
    owns_dir: bool,
    inline: &[String],
    name: &str,
    path: Option<&str>,
) -> Vec<String> {
    let file = Path::new(parent);
    let dir = file
        .parent()
        .map(|d| d.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut base = if owns_dir || (path.is_some() && inline.is_empty()) {
        dir
    } else {
        let stem = file.file_stem().and_then(|s| s.to_str()).unwrap_or("");
        format!("{dir}/{stem}")
    };
    for m in inline {
        base = format!("{base}/{m}");
    }
    match path {
        Some(p) => vec![normalize(&format!("{base}/{p}"))],
        None => vec![
            normalize(&format!("{base}/{name}.rs")),
            normalize(&format!("{base}/{name}/mod.rs")),
        ],
    }
}

/// `a/./b/../c` -> `a/c`.
fn normalize(path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for c in path.split('/') {
        match c {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            c => parts.push(c),
        }
    }
    parts.join("/")
}

/// Where the lexer stands between characters.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Lex {
    Code,
    Block(u32),
    Str,
    Raw(usize),
}

/// Every out-of-line `mod name;` a file declares: the inline modules it sits in, its name, and its
/// `#[path]` when one is given. Braces are counted in code only (not in comments, strings, raw
/// strings or char literals), so an inline `mod name { .. }` is closed where rustc closes it.
fn child_modules(text: &str) -> Vec<(Vec<String>, String, Option<String>)> {
    let mut out = Vec::new();
    let mut lex = Lex::Code;
    let mut depth: i64 = 0;
    // The inline modules open here: name and the depth inside its braces.
    let mut inline: Vec<(String, i64)> = Vec::new();
    let mut path: Option<String> = None;
    for line in text.lines() {
        let mut opening: Option<String> = None;
        if lex == Lex::Code {
            let mut t = line.trim();
            if t.starts_with("//") {
                continue;
            }
            while let Some(rest) = t.strip_prefix("#[") {
                let Some((attr, after)) = rest.split_once(']') else {
                    break;
                };
                if let Some(p) = path_attr(attr) {
                    path = Some(p);
                }
                t = after.trim_start();
            }
            if !t.is_empty() {
                match mod_decl(t) {
                    Some((name, true)) => {
                        let names = inline.iter().map(|(n, _)| n.clone()).collect();
                        out.push((names, name, path.take()));
                    }
                    Some((name, false)) => {
                        opening = Some(name);
                        path = None;
                    }
                    None => path = None,
                }
            }
        }
        lex = scan(line, lex, &mut depth, &mut inline, &mut opening);
    }
    out
}

/// `path = "<p>"` -> `<p>`.
fn path_attr(attr: &str) -> Option<String> {
    let rest = attr
        .trim()
        .strip_prefix("path")?
        .trim_start()
        .strip_prefix('=')?;
    let p = rest.trim().strip_prefix('"')?.strip_suffix('"')?;
    Some(p.to_string())
}

/// `[pub[(..)]] mod <name>;` -> `(name, true)`, `[pub[(..)]] mod <name> {` -> `(name, false)`.
fn mod_decl(t: &str) -> Option<(String, bool)> {
    let mut rest = t;
    if let Some(r) = rest.strip_prefix("pub") {
        let r = r.trim_start();
        rest = match r.strip_prefix('(') {
            Some(inner) => inner.split_once(')')?.1.trim_start(),
            None => r,
        };
    }
    let rest = rest.strip_prefix("mod ")?.trim_start();
    let name: String = rest
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();
    if name.is_empty() {
        return None;
    }
    let after = rest[name.len()..].trim_start();
    if after.starts_with(';') {
        Some((name, true))
    } else if after.starts_with('{') {
        Some((name, false))
    } else {
        None
    }
}

/// Lex one line from `lex`, counting code braces into `depth`: the first `{` of a line that opens
/// an inline module (`opening`) pushes it, and a `}` closes every inline module it leaves.
fn scan(
    line: &str,
    mut lex: Lex,
    depth: &mut i64,
    inline: &mut Vec<(String, i64)>,
    opening: &mut Option<String>,
) -> Lex {
    let c: Vec<char> = line.chars().collect();
    let at = |i: usize| c.get(i).copied();
    let mut i = 0;
    while i < c.len() {
        match lex {
            Lex::Block(n) => {
                if c[i] == '*' && at(i + 1) == Some('/') {
                    lex = if n == 1 { Lex::Code } else { Lex::Block(n - 1) };
                    i += 2;
                } else if c[i] == '/' && at(i + 1) == Some('*') {
                    lex = Lex::Block(n + 1);
                    i += 2;
                } else {
                    i += 1;
                }
            }
            Lex::Str => {
                if c[i] == '\\' {
                    i += 2;
                } else {
                    if c[i] == '"' {
                        lex = Lex::Code;
                    }
                    i += 1;
                }
            }
            Lex::Raw(hashes) => {
                if c[i] == '"' && (1..=hashes).all(|k| at(i + k) == Some('#')) {
                    lex = Lex::Code;
                    i += 1 + hashes;
                } else {
                    i += 1;
                }
            }
            Lex::Code => {
                let ident_before = i > 0 && (c[i - 1].is_alphanumeric() || c[i - 1] == '_');
                match c[i] {
                    '/' if at(i + 1) == Some('/') => break,
                    '/' if at(i + 1) == Some('*') => {
                        lex = Lex::Block(1);
                        i += 2;
                    }
                    'r' if !ident_before && matches!(at(i + 1), Some('#' | '"')) => {
                        let mut k = i + 1;
                        while at(k) == Some('#') {
                            k += 1;
                        }
                        if at(k) == Some('"') {
                            lex = Lex::Raw(k - i - 1);
                            i = k + 1;
                        } else {
                            i += 1;
                        }
                    }
                    '"' => {
                        lex = Lex::Str;
                        i += 1;
                    }
                    '\'' => {
                        if at(i + 1) == Some('\\') {
                            // An escaped char literal: skip to its closing quote.
                            let mut k = i + 2;
                            while k < c.len() && c[k] != '\'' {
                                k += 1;
                            }
                            i = k + 1;
                        } else if at(i + 2) == Some('\'') {
                            i += 3;
                        } else {
                            // A lifetime or a label.
                            i += 1;
                        }
                    }
                    '{' => {
                        *depth += 1;
                        if let Some(name) = opening.take() {
                            inline.push((name, *depth));
                        }
                        i += 1;
                    }
                    '}' => {
                        *depth -= 1;
                        while inline.last().is_some_and(|(_, d)| *d > *depth) {
                            inline.pop();
                        }
                        i += 1;
                    }
                    _ => i += 1,
                }
            }
        }
    }
    lex
}

#[cfg(test)]
mod tests {
    use super::*;

    fn laid(files: &[(&str, &str)]) -> BTreeMap<String, String> {
        files
            .iter()
            .map(|(r, t)| ((*r).to_string(), (*t).to_string()))
            .collect()
    }

    fn closure(files: &BTreeMap<String, String>, roots: &[&str]) -> BTreeSet<String> {
        let view: BTreeMap<&str, &str> = files
            .iter()
            .map(|(r, t)| (r.as_str(), t.as_str()))
            .collect();
        let roots: Vec<String> = roots.iter().map(|r| (*r).to_string()).collect();
        module_closure(&roots, &view)
    }

    /// The module tree is followed as rustc follows it, and a file nothing declares is not reached:
    /// a `tests/<dir>/` with no `main.rs` is no target, and its files run only from a root that
    /// declares them.
    #[test]
    fn the_module_tree_reaches_what_rustc_compiles_and_nothing_else() {
        let files = laid(&[
            (
                "crates/p/src/lib.rs",
                "//! doc { unbalanced in a comment\npub mod a;\n#[cfg(test)]\n#[path = \"t/x_tests.rs\"]\nmod x;\npub mod inl {\n    let s = \"}\";\n    let c = '}';\n    pub mod deep;\n}\nmod after;\n",
            ),
            ("crates/p/src/a.rs", "mod b;\n"),
            ("crates/p/src/a/b.rs", "#[test]\nfn b() {}\n"),
            ("crates/p/src/t/x_tests.rs", "#[test]\nfn x() {}\n"),
            ("crates/p/src/inl/deep.rs", "#[test]\nfn deep() {}\n"),
            ("crates/p/src/after.rs", ""),
            ("crates/p/src/deep.rs", "#[test]\nfn wrong_home() {}\n"),
            ("crates/p/tests/top.rs", "mod harness;\n"),
            ("crates/p/tests/harness/mod.rs", ""),
            ("crates/p/tests/on_driver/mod.rs", "pub(crate) mod seam;\n"),
            ("crates/p/tests/on_driver/seam.rs", "#[test]\nfn seam() {}\n"),
        ]);
        let lib = closure(&files, &["crates/p/src/lib.rs", "crates/p/tests/top.rs"]);
        for reached in [
            "crates/p/src/a/b.rs",
            "crates/p/src/t/x_tests.rs",
            "crates/p/src/inl/deep.rs",
            "crates/p/src/after.rs",
            "crates/p/tests/harness/mod.rs",
        ] {
            assert!(
                lib.contains(reached),
                "{reached} is declared and not reached"
            );
        }
        for unreached in [
            "crates/p/src/deep.rs",
            "crates/p/tests/on_driver/mod.rs",
            "crates/p/tests/on_driver/seam.rs",
        ] {
            assert!(
                !lib.contains(unreached),
                "{unreached} is reached and nothing declares it"
            );
        }
        let driver = closure(&files, &["crates/p/tests/on_driver/mod.rs"]);
        assert!(driver.contains("crates/p/tests/on_driver/seam.rs"));
    }

    /// `cargo test`'s targets: `tests/<name>.rs` and `tests/<name>/main.rs`, never a bare
    /// `tests/<dir>/mod.rs`.
    #[test]
    fn cargo_tests_targets_are_the_top_level_test_files_and_main_dirs() {
        let files = laid(&[
            ("crates/p/Cargo.toml", "[package]\nname = \"p\"\n"),
            ("crates/p/tests/a.rs", ""),
            ("crates/p/tests/suite/main.rs", ""),
            ("crates/p/tests/on_driver/mod.rs", ""),
        ]);
        let view: BTreeMap<&str, &str> = files
            .iter()
            .map(|(r, t)| (r.as_str(), t.as_str()))
            .collect();
        let roots = cargo_test_roots("p", &view);
        let has = |rel: &str| roots.iter().any(|r| r == rel);
        assert!(has("crates/p/tests/a.rs"));
        assert!(has("crates/p/tests/suite/main.rs"));
        assert!(!has("crates/p/tests/on_driver/mod.rs"));
    }
}
