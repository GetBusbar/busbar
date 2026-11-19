// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ESCAPES v2 (UNSAFE-MIN r3.1 §4.6): `unsafe` lives only in busbar-ffi, and its count never rises.
//!
//! The register is `unsafe.yaml` at the repository root (owner-approved through CODEOWNERS), read through
//! the YAML facade. CI fails on any drift between it and the code:
//! - **E1.** Every tracked `.rs` file (`git ls-files`, so standalone workspaces such as `tools/plugin-bench`
//!   and `dist/default` too) outside `crates/busbar-ffi/` holds no `unsafe` token, no linker identifier
//!   (`no_mangle`, `export_name`, `link_section`, `global_asm`, `naked_asm`), no `extern` block, no
//!   `allow`/`expect`/`warn` of `unsafe_code` in any form, no `include!` of an `OUT_DIR` path, and is no
//!   `build.rs` that writes `.rs`, except at an `interim` row, whose count is exact and never rises.
//! - **E2.** Every package root except busbar-ffi carries `#![forbid(unsafe_code)]` and
//!   `#![doc(test(attr(forbid(unsafe_code))))]`, except an `interim_roots` row.
//! - **E3 and the owner's pins.** busbar-ffi's files are exactly the pinned list; each file's count
//!   (`unsafe` tokens, doc code included, plus `allow`/`expect(unsafe_code)`) equals its pin; the total
//!   equals the sum and never rises against the merge base or the target tip (`origin/dev`, never
//!   `BUSBAR_LOC_BASE`); a net-zero move between files passes. Its dependencies and its dependents are
//!   pinned. No fail-open: an unresolvable base, a missing register at a base that should have one, an
//!   unparseable register, a missing or moved `ffi` row, or a tracked file that does not lex all fail.
//! - **E4-E6, E10.** One exported macro, `export!`, whose `#[unsafe(no_mangle)]` is the only `unsafe` token
//!   in any macro body; no `$`-metavariable inside an `unsafe` construct; a `// SAFETY:` comment above every
//!   `unsafe` block and impl; the root denies its four lints and no file lowers them.
//!
//! A7 and the module forbid list stay in `escapes.json` (version 2): an `allow`/`expect` of `dead_code`
//! or an `unused*` lint in production code never grows, and a module that forbids unsafe keeps it.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::Deserialize;

use super::scan::{self, EscapeCounts, Parsed};

const REGISTER: &str = "unsafe.yaml";
const ESCAPES: &str = "crates/busbar-kernel/tests/arch/escapes.json";
/// The one crate that may hold `unsafe`. Pinned here and in the register; a different path fails.
const FFI_PATH: &str = "crates/busbar-ffi";

// ---- the register ----

#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
struct Register {
    version: u32,
    ffi: Ffi,
    #[serde(default)]
    interim: BTreeMap<String, Row>,
    #[serde(default)]
    interim_roots: BTreeMap<String, RootRow>,
}

#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
struct Ffi {
    path: String,
    total: usize,
    files: BTreeMap<String, FileRow>,
    dependencies: BTreeMap<String, String>,
    dependents: BTreeMap<String, String>,
}

#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
struct FileRow {
    tokens: usize,
    reason: String,
}

#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
struct Row {
    tokens: usize,
    /// The package (wave) that deletes it.
    by: String,
}

#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
struct RootRow {
    by: String,
}

fn parse_register(name: &str, text: &str) -> Result<Register, String> {
    let register: Register =
        busbar_contract::yaml::from_str(text).map_err(|error| format!("{name}: {error}"))?;
    if register.version != 2 {
        return Err(format!("{name}: unknown version {}", register.version));
    }
    Ok(register)
}

// ---- the tree the judge sees ----

/// Everything the judge reads, so the fixtures can build one in memory.
struct Tree {
    /// Every tracked `.rs` file: path → source.
    files: BTreeMap<String, String>,
    /// Every tracked `Cargo.toml` except the root workspace manifest: path → text.
    manifests: BTreeMap<String, String>,
    /// Every package root (conventional roots of every tracked package and the workspace's own targets).
    roots: BTreeSet<String>,
}

/// One register at a comparison revision: Some(register), or None when the file is absent there.
type AtBase = (String, Option<Register>);

fn in_ffi(path: &str) -> bool {
    path.strip_prefix(FFI_PATH)
        .is_some_and(|rest| rest.starts_with('/'))
}

/// The judge: every failure, worded for the person who has to fix it.
fn judge(tree: &Tree, now: &Register, bases: &[AtBase]) -> Vec<String> {
    let mut failures = Vec::new();
    let mut counts: BTreeMap<&str, EscapeCounts> = BTreeMap::new();
    for (path, source) in &tree.files {
        match scan::escape_counts(path, source) {
            Ok(found) => {
                counts.insert(path, found);
            }
            Err(error) => failures.push(error),
        }
    }

    // E3 and the pins: the path, the file list, the per-file counts and the total.
    if now.ffi.path != FFI_PATH {
        failures.push(format!(
            "unsafe.yaml: ffi.path is `{}`; the boundary crate is `{FFI_PATH}` and does not move",
            now.ffi.path
        ));
    }
    let measured_ffi: BTreeMap<String, usize> = counts
        .iter()
        .filter(|(path, _)| in_ffi(path))
        .map(|(path, found)| (path[FFI_PATH.len() + 1..].to_string(), found.ffi()))
        .collect();
    for (file, tokens) in &measured_ffi {
        match now.ffi.files.get(file) {
            None => failures.push(format!(
                "busbar-ffi: {file} is not a pinned file ({tokens} tokens); busbar-ffi holds only the \
                 pinned modules, and a new file needs the owner"
            )),
            Some(row) if *tokens > row.tokens => failures.push(format!(
                "busbar-ffi: {file} has {tokens} unsafe tokens, above its pin of {}; the count never rises",
                row.tokens
            )),
            Some(row) if *tokens < row.tokens => failures.push(format!(
                "busbar-ffi: {file} has {tokens} unsafe tokens, below its pin of {}: lower its pin to {tokens}",
                row.tokens
            )),
            Some(_) => {}
        }
    }
    for (file, row) in &now.ffi.files {
        if !measured_ffi.contains_key(file) {
            failures.push(format!(
                "busbar-ffi: the pinned file {file} does not exist; remove its row"
            ));
        }
        if row.reason.trim().is_empty() {
            failures.push(format!("busbar-ffi: the pin of {file} gives no reason"));
        }
    }
    let measured_total: usize = measured_ffi.values().sum();
    let pinned_sum: usize = now.ffi.files.values().map(|row| row.tokens).sum();
    if now.ffi.total != pinned_sum {
        failures.push(format!(
            "busbar-ffi: total is {} but the file pins sum to {pinned_sum}",
            now.ffi.total
        ));
    }
    if measured_total > now.ffi.total {
        failures.push(format!(
            "busbar-ffi: {measured_total} unsafe tokens, above the total of {}; it never rises",
            now.ffi.total
        ));
    } else if measured_total < now.ffi.total {
        failures.push(format!(
            "busbar-ffi: {measured_total} unsafe tokens, below the total of {}: lower `total` to {measured_total}",
            now.ffi.total
        ));
    }

    // E4-E6 and E10 inside busbar-ffi.
    let mut exported = Vec::new();
    for (path, source) in tree.files.iter().filter(|(path, _)| in_ffi(path)) {
        let (macros, findings) = scan::ffi_macro_findings(source);
        exported.extend(macros);
        failures.extend(
            findings
                .into_iter()
                .map(|finding| format!("{path}: {finding}")),
        );
        for line in scan::unsafe_without_safety(source) {
            failures.push(format!(
                "{path}:{line}: an `unsafe` block or impl without a `// SAFETY:` comment above it (E6)"
            ));
        }
        if path != &format!("{FFI_PATH}/src/lib.rs")
            && scan::lowers_any(source, &scan::FFI_ROOT_LINTS[1..])
        {
            failures.push(format!(
                "{path}: allows a lint busbar-ffi's root denies (E10); it is never lowered below the root"
            ));
        }
    }
    if exported != ["export"] {
        failures.push(format!(
            "busbar-ffi exports {exported:?}; it exports exactly one macro, `export!` (E4)"
        ));
    }
    match tree.files.get(&format!("{FFI_PATH}/src/lib.rs")) {
        Some(lib) => {
            let denies = scan::inner_denies(lib);
            for lint in scan::FFI_ROOT_LINTS {
                if !denies.contains(lint) {
                    failures.push(format!(
                        "{FFI_PATH}/src/lib.rs: the root lacks `#![deny({lint})]` (E10)"
                    ));
                }
            }
        }
        None => failures.push(format!("{FFI_PATH}/src/lib.rs is missing")),
    }

    // The dependency and dependent pins.
    match tree.manifests.get(&format!("{FFI_PATH}/Cargo.toml")) {
        Some(text) => match manifest::ffi_dependencies(text) {
            Ok(found) if found == now.ffi.dependencies => {}
            Ok(found) => failures.push(format!(
                "busbar-ffi depends on {found:?}; the pinned list is {:?} (a new dependency needs the owner)",
                now.ffi.dependencies
            )),
            Err(error) => failures.push(format!("{FFI_PATH}/Cargo.toml: {error}")),
        },
        None => failures.push(format!("{FFI_PATH}/Cargo.toml is missing")),
    }
    let mut dependents = BTreeMap::new();
    for (path, text) in &tree.manifests {
        if path == &format!("{FFI_PATH}/Cargo.toml") {
            continue;
        }
        if let Some(role) = manifest::ffi_dependent(text) {
            dependents.insert(path.clone(), role);
        }
    }
    for (path, role) in &dependents {
        if now.ffi.dependents.get(path) != Some(role) {
            failures.push(format!(
                "{path} depends on busbar-ffi ({role}); the allowlist is {:?} (E12: only plugin-abi, the \
                 loader with `host` and plugin-test; plugin crates never enable `host`)",
                now.ffi.dependents
            ));
        }
    }

    // E1: nothing outside busbar-ffi, except the exact interim rows.
    for (path, found) in counts.iter().filter(|(path, _)| !in_ffi(path)) {
        let tokens = found.outside();
        match now.interim.get(*path) {
            None if tokens > 0 => failures.push(format!(
                "unsafe: {path} has {tokens} escape tokens ({found:?}); `unsafe` lives only in busbar-ffi"
            )),
            None => {}
            Some(row) if tokens > row.tokens => failures.push(format!(
                "unsafe: {path} has {tokens} escape tokens, above its interim row of {}; interim never rises",
                row.tokens
            )),
            Some(row) if tokens < row.tokens => failures.push(format!(
                "unsafe: {path} has {tokens} escape tokens, below its interim row of {}: lower it to {tokens}{}",
                row.tokens,
                if tokens == 0 { " (delete the row)" } else { "" }
            )),
            Some(_) => {}
        }
    }
    for (path, row) in &now.interim {
        if !counts.contains_key(path.as_str()) {
            failures.push(format!(
                "unsafe: the interim row {path} names no tracked .rs file; remove it"
            ));
        }
        if in_ffi(path) {
            failures.push(format!(
                "unsafe: {path} is busbar-ffi's; it has no interim row"
            ));
        }
        if row.by.trim().is_empty() {
            failures.push(format!(
                "unsafe: the interim row {path} names no deleting package"
            ));
        }
    }

    // E2: package roots.
    for root in &tree.roots {
        if in_ffi(root) {
            continue;
        }
        let Some(source) = tree.files.get(root) else {
            continue;
        };
        let forbids =
            Parsed::new(source).inner_lint("forbid") && scan::forbids_unsafe_in_doctests(source);
        match (forbids, now.interim_roots.contains_key(root)) {
            (false, false) => failures.push(format!(
                "unsafe: the package root {root} lacks `#![forbid(unsafe_code)]` and \
                 `#![doc(test(attr(forbid(unsafe_code))))]` (E2)"
            )),
            (true, true) => failures.push(format!(
                "unsafe: the package root {root} now forbids unsafe code: remove its interim_roots row"
            )),
            _ => {}
        }
    }
    for (root, row) in &now.interim_roots {
        if !tree.roots.contains(root) {
            failures.push(format!(
                "unsafe: the interim_roots row {root} names no package root; remove it"
            ));
        }
        if row.by.trim().is_empty() {
            failures.push(format!(
                "unsafe: the interim_roots row {root} names no deleting package"
            ));
        }
    }

    // Against the merge base and the target tip.
    let present: Vec<&Register> = bases.iter().filter_map(|(_, at)| at.as_ref()).collect();
    if !present.is_empty() && present.len() != bases.len() {
        for (revision, at) in bases {
            if at.is_none() {
                failures.push(format!(
                    "unsafe: {REGISTER} is missing at {revision}, which predates the register while the \
                     target has it: merge the target branch first"
                ));
            }
        }
    }
    for (revision, at) in bases {
        let Some(before) = at else {
            continue;
        };
        if now.ffi.total > before.ffi.total {
            failures.push(format!(
                "busbar-ffi: total {} rose above {} at {revision}; no package adds a busbar-ffi token",
                now.ffi.total, before.ffi.total
            ));
        }
        for (path, row) in &now.interim {
            if before
                .interim
                .get(path)
                .is_none_or(|old| row.tokens > old.tokens)
            {
                failures.push(format!(
                    "unsafe: the interim row {path} was added or raised against {revision}; interim only falls"
                ));
            }
        }
        for root in now.interim_roots.keys() {
            if !before.interim_roots.contains_key(root) {
                failures.push(format!(
                    "unsafe: the interim_roots row {root} was added against {revision}"
                ));
            }
        }
    }
    failures
}

/// The measured register, as YAML rows to paste after an intended change (owner-approved).
fn measured_rows(tree: &Tree) -> String {
    let mut out = String::from("measured interim (path: tokens):\n");
    for (path, source) in &tree.files {
        if let Ok(found) = scan::escape_counts(path, source) {
            let tokens = if in_ffi(path) {
                found.ffi()
            } else {
                found.outside()
            };
            if tokens > 0 {
                out.push_str(&format!("  {path}: {tokens}\n"));
            }
        }
    }
    out
}

// ---- manifests (a line reader: the pinned manifests are plain) ----

mod manifest {
    use std::collections::BTreeMap;

    /// (section, key, value) for every `key = value` entry; `[a.b.name]` headers read as key `name`
    /// in section `a.b`; values may span lines until their brackets close; `#` comments are dropped.
    pub fn entries(text: &str) -> Vec<(String, String, String)> {
        let mut out = Vec::new();
        let mut section = String::new();
        let mut pending: Option<(String, String)> = None;
        let mut table: Option<usize> = None;
        for raw in text.lines() {
            let line = strip_comment(raw).trim().to_string();
            if let Some((key, mut value)) = pending.take() {
                value.push(' ');
                value.push_str(&line);
                if balanced(&value) {
                    out.push((section.clone(), key, value));
                } else {
                    pending = Some((key, value));
                }
                continue;
            }
            if line.is_empty() {
                continue;
            }
            if let Some(header) = line
                .strip_prefix('[')
                .and_then(|rest| rest.strip_suffix(']'))
            {
                let header = header.trim_matches(|c| c == '[' || c == ']').trim();
                section = header.to_string();
                table = None;
                for kind in ["dev-dependencies.", "build-dependencies.", "dependencies."] {
                    if let Some((before, name)) = split_table(header, kind) {
                        section.clone_from(&before);
                        out.push((before, name, String::new()));
                        table = Some(out.len() - 1);
                        break;
                    }
                }
                continue;
            }
            // Inside a `[x.dependencies.name]` table every line is part of that one entry's value.
            if let Some(at) = table {
                if let Some(entry) = out.get_mut(at) {
                    entry.2.push_str(&line);
                    entry.2.push_str(", ");
                }
                continue;
            }
            if let Some((key, value)) = line.split_once('=') {
                let key = key.trim().trim_matches('"').to_string();
                let key = key.split('.').next().unwrap_or(&key).to_string();
                let value = value.trim().to_string();
                if balanced(&value) {
                    out.push((section.clone(), key, value));
                } else {
                    pending = Some((key, value));
                }
            }
        }
        out
    }

    /// `x.dependencies.name` → (`x.dependencies`, `name`).
    fn split_table(header: &str, kind: &str) -> Option<(String, String)> {
        let at = header.find(kind)?;
        let name = &header[at + kind.len()..];
        (!name.is_empty() && !name.contains('.')).then(|| {
            (
                header[..at + kind.len() - 1].to_string(),
                name.trim_matches('"').to_string(),
            )
        })
    }

    fn balanced(value: &str) -> bool {
        let open = value.matches(['[', '{']).count();
        let close = value.matches([']', '}']).count();
        open <= close
    }

    fn strip_comment(line: &str) -> &str {
        let mut quoted = false;
        for (at, c) in line.char_indices() {
            match c {
                '"' => quoted = !quoted,
                '#' if !quoted => return &line[..at],
                _ => {}
            }
        }
        line
    }

    /// busbar-ffi's dependencies, each with its role: `always`, `host` (optional, enabled by feature
    /// `host`), `optional`, `dev`, `build`, or the target cfg it is under.
    pub(crate) fn ffi_dependencies(text: &str) -> Result<BTreeMap<String, String>, String> {
        let entries = entries(text);
        let host_feature: String = entries
            .iter()
            .filter(|(section, key, _)| section == "features" && key == "host")
            .map(|(_, _, value)| value.clone())
            .collect();
        let mut out = BTreeMap::new();
        for (section, key, value) in &entries {
            if (section == "package" || section == "lib") && (key == "build" || key == "proc-macro")
            {
                return Err(format!(
                    "`{key}` is set; busbar-ffi has no build script and no proc macro"
                ));
            }
            let role = match section.as_str() {
                "dependencies" if value.contains("optional = true") => {
                    if host_feature.contains(&format!("\"dep:{key}\"")) {
                        "host".to_string()
                    } else {
                        "optional".to_string()
                    }
                }
                "dependencies" => "always".to_string(),
                "dev-dependencies" => "dev".to_string(),
                "build-dependencies" => "build".to_string(),
                target if target.starts_with("target.") && target.ends_with(".dependencies") => {
                    target["target.".len()..target.len() - ".dependencies".len()]
                        .trim_matches(|c| c == '\'' || c == '"')
                        .to_string()
                }
                _ => continue,
            };
            out.insert(key.clone(), role);
        }
        Ok(out)
    }

    /// How a manifest depends on busbar-ffi: `host`, `forwards host` (a feature enables
    /// `busbar-ffi/host`), `no host`; None when it does not.
    pub(crate) fn ffi_dependent(text: &str) -> Option<String> {
        let entries = entries(text);
        let mut role = None;
        let mut forwards = false;
        for (section, key, value) in &entries {
            if key == "busbar-ffi" && section.ends_with("dependencies") {
                role = Some(if value.contains("\"host\"") {
                    "host"
                } else {
                    "no host"
                });
            }
            if section == "features" && value.contains("busbar-ffi/host") {
                forwards = true;
            }
        }
        role.map(|role| if forwards { "forwards host" } else { role }.to_string())
    }
}

// ---- the real tree ----

fn read_tree(root: &Path, failures: &mut Vec<String>) -> Tree {
    let mut files = BTreeMap::new();
    match scan::tracked(root, "*.rs") {
        Some(paths) => {
            for path in paths {
                match std::fs::read(root.join(&path)) {
                    Ok(bytes) => match String::from_utf8(bytes) {
                        Ok(source) => {
                            files.insert(path, source);
                        }
                        Err(_) => failures.push(format!(
                            "{path}: not UTF-8; every tracked .rs file is scanned"
                        )),
                    },
                    Err(error) => failures.push(format!(
                        "{path}: {error}; every tracked .rs file is scanned"
                    )),
                }
            }
        }
        None => failures.push("git ls-files failed: the walk needs the Git index".to_string()),
    }
    let mut manifests = BTreeMap::new();
    for path in scan::tracked(root, "*Cargo.toml").unwrap_or_default() {
        if path == "Cargo.toml" || !path.ends_with("/Cargo.toml") {
            continue;
        }
        if let Ok(text) = std::fs::read_to_string(root.join(&path)) {
            manifests.insert(path, text);
        }
    }
    let mut roots = BTreeSet::new();
    for path in manifests.keys() {
        let dir = &path[..path.len() - "Cargo.toml".len()];
        for root_file in ["src/lib.rs", "src/main.rs"] {
            let candidate = format!("{dir}{root_file}");
            if files.contains_key(&candidate) {
                roots.insert(candidate);
            }
        }
    }
    let workspace = scan::load();
    for package in &workspace.packages {
        for target in package.production_roots() {
            roots.insert(workspace.relative(target));
        }
    }
    Tree {
        files,
        manifests,
        roots,
    }
}

/// The comparison revisions (UNSAFE-MIN A11): the merge base with the target tip and the tip itself,
/// or, on the target branch itself, the first parent. Never `BUSBAR_LOC_BASE`.
fn comparison_revisions(root: &Path) -> Result<Vec<String>, String> {
    let resolve = |name: &str| {
        super::git(
            root,
            &["rev-parse", "--verify", "-q", &format!("{name}^{{commit}}")],
        )
    };
    let head = resolve("HEAD").ok_or("HEAD does not resolve")?;
    let tip = match resolve("refs/remotes/origin/dev") {
        Some(tip) => tip,
        None => {
            let _ = super::git(
                root,
                &[
                    "fetch",
                    "--quiet",
                    "--no-tags",
                    "origin",
                    "+refs/heads/dev:refs/remotes/origin/dev",
                ],
            );
            resolve("refs/remotes/origin/dev").ok_or(
                "the target tip origin/dev does not resolve: fetch origin dev (no fail-open)",
            )?
        }
    };
    let base = super::git(root, &["merge-base", "HEAD", &tip])
        .ok_or("no merge base with origin/dev: the history is too shallow (no fail-open)")?;
    if base == head {
        if let Some(parent) = resolve("HEAD^1") {
            return Ok(vec![parent]);
        }
        // A depth-1 checkout (CI's on the target branch) holds HEAD without its parent: deepen the
        // shallow boundary by one commit, as the target tip is fetched above when it is missing.
        // The parent is then read from HEAD's own commit object, not through the shallow graft,
        // which another test's `--depth=1` fetch may set back at HEAD; its objects stay.
        let _ = super::git(
            root,
            &[
                "fetch",
                "--quiet",
                "--no-tags",
                "--no-write-fetch-head",
                "--deepen=1",
                "origin",
                "+refs/heads/dev:refs/remotes/origin/dev",
            ],
        );
        let parent = super::git(root, &["cat-file", "commit", &head])
            .and_then(|commit| {
                commit
                    .lines()
                    .take_while(|line| !line.is_empty())
                    .find_map(|line| line.strip_prefix("parent ").map(str::to_string))
            })
            .filter(|parent| {
                super::git(root, &["cat-file", "-e", &format!("{parent}^{{commit}}")]).is_some()
            })
            .ok_or("HEAD has no first parent to compare against, even deepened (no fail-open)")?;
        return Ok(vec![parent]);
    }
    let mut revisions = vec![base];
    if !revisions.contains(&tip) {
        revisions.push(tip);
    }
    Ok(revisions)
}

fn register_at(root: &Path, revision: &str) -> Result<Option<Register>, String> {
    let spec = format!("{revision}:{REGISTER}");
    if super::git(root, &["cat-file", "-e", &spec]).is_none() {
        return Ok(None);
    }
    let text = super::git(root, &["show", &spec]).ok_or(format!("git show {spec} failed"))?;
    parse_register(&spec, &text).map(Some)
}

#[test]
fn unsafe_lives_only_in_busbar_ffi_and_never_rises() {
    let root = scan::load().root;
    let mut failures = Vec::new();
    let text = std::fs::read_to_string(root.join(REGISTER))
        .unwrap_or_else(|error| panic!("{REGISTER}: {error}"));
    let now = parse_register(REGISTER, &text).unwrap_or_else(|error| panic!("{error}"));
    let tree = read_tree(&root, &mut failures);
    let mut bases = Vec::new();
    match comparison_revisions(&root) {
        Ok(revisions) => {
            for revision in revisions {
                match register_at(&root, &revision) {
                    Ok(at) => bases.push((revision, at)),
                    Err(error) => failures.push(error),
                }
            }
        }
        Err(error) => failures.push(error),
    }
    failures.extend(judge(&tree, &now, &bases));
    if !failures.is_empty() {
        panic!("{}\n{}", measured_rows(&tree), failures.join("\n"));
    }
}

// ---- A7 and the module forbid list (escapes.json, version 2) ----

#[derive(Deserialize)]
struct Escapes {
    version: u32,
    /// File → `allow`/`expect` attributes naming `dead_code` or `unused*`.
    dead_code: BTreeMap<String, usize>,
    /// Modules that forbid unsafe today and keep it.
    forbid: BTreeSet<String>,
    /// File → the owner ruling that admits its forbid-list removal for one merge.
    #[serde(default)]
    admitted: BTreeMap<String, String>,
}

#[test]
fn dead_code_escapes_never_grow_and_forbids_stay() {
    let mut workspace = scan::load();
    let root = workspace.root.clone();
    let text = std::fs::read_to_string(root.join(ESCAPES)).expect(ESCAPES);
    let escapes: Escapes = sonic_rs::from_str(&text).expect(ESCAPES);
    assert_eq!(escapes.version, 2, "{ESCAPES}: unknown version");
    workspace.walk(&BTreeSet::new());

    let mut dead: BTreeMap<String, usize> = BTreeMap::new();
    let mut forbids: BTreeSet<String> = BTreeSet::new();
    for path in workspace
        .files
        .iter()
        .filter(|(_, reached)| reached.production)
        .map(|(path, _)| path)
    {
        let source = std::fs::read_to_string(path).expect("read reached file");
        let file = Parsed::new(&source);
        let relative = workspace.relative(path);
        dead.insert(relative.clone(), file.dead_code_allows());
        if file.inner_lint("forbid") {
            forbids.insert(relative);
        }
    }
    let mut failures = Vec::new();
    for (file, count) in &dead {
        let frozen = escapes.dead_code.get(file).copied().unwrap_or(0);
        if *count > frozen {
            failures.push(format!(
                "dead code: {file} has {count} `allow`/`expect` of dead_code or unused* in production \
                 code (frozen at {frozen}); delete the dead item instead (203)"
            ));
        }
    }
    for file in &escapes.forbid {
        if !forbids.contains(file) && !escapes.admitted.contains_key(file) {
            failures.push(format!(
                "forbid: {file} must keep `#![forbid(unsafe_code)]` (if the file moved, move the entry)"
            ));
        }
    }
    for file in &forbids {
        if !escapes.forbid.contains(file) {
            failures.push(format!(
                "forbid: {file} forbids unsafe code; add it to the frozen forbid list"
            ));
        }
    }
    if let Some(base) = super::base_revision(&root) {
        if let Some(text) = super::file_at(&root, &base, ESCAPES) {
            if let Ok(before) = sonic_rs::from_str::<Escapes>(&text) {
                for (file, count) in &escapes.dead_code {
                    if *count > before.dead_code.get(file).copied().unwrap_or(0) {
                        failures.push(format!(
                            "dead code: the frozen count for {file} rose; it can only fall"
                        ));
                    }
                }
                for file in &before.forbid {
                    if !escapes.forbid.contains(file) && !escapes.admitted.contains_key(file) {
                        failures.push(format!(
                            "forbid: {file} left the forbid list; a forbid is never lifted"
                        ));
                    }
                }
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

// ---- RT1-RT5 and the owner's pins, as string fixtures ----

#[cfg(test)]
mod fixtures {
    use super::*;

    const FFI_LIB: &str = "#![deny(unsafe_code)]\n#![deny(unsafe_op_in_unsafe_fn)]\n\
        #![deny(clippy::undocumented_unsafe_blocks)]\n#![deny(clippy::multiple_unsafe_ops_per_block)]\n";
    const FFI_HEADER: &str = "#![allow(unsafe_code)]\n#[macro_export]\nmacro_rules! export {\n    \
        ($p:path) => {\n        const _: () = {\n            #[unsafe(no_mangle)]\n            \
        pub extern \"C\" fn busbar_plugin() -> *const $crate::Plugin { $crate::LinkedPlugin::as_ptr(&$p) }\n        \
        };\n    };\n}\n";
    const FFI_RAW: &str = "#![allow(unsafe_code)]\nfn get(p: *const u8) -> u8 {\n    \
        // SAFETY: fixture.\n    unsafe { *p }\n}\n";
    const FFI_MANIFEST: &str = "[package]\nname = \"busbar-ffi\"\n\n[features]\nhost = [\"dep:libloading\", \
        \"dep:object\"]\n\n[dependencies]\nzerocopy = { version = \"0.8\" }\nlibloading = { workspace = true, \
        optional = true }\nobject = { version = \"0.37\", optional = true }\n\n\
        [target.'cfg(loom)'.dependencies]\nloom = { workspace = true }\n";
    const ABI_MANIFEST: &str = "[package]\nname = \"busbar-plugin-abi\"\n\n[features]\nhost = \
        [\"busbar-ffi/host\"]\n\n[dependencies]\nbusbar-ffi = { path = \"../busbar-ffi\" }\n";
    const ROOT_OK: &str = "#![forbid(unsafe_code)]\n#![doc(test(attr(forbid(unsafe_code))))]\n";

    fn register_text(total: usize, raw: usize, extra: &str) -> String {
        format!(
            "version: 2\nffi:\n  path: crates/busbar-ffi\n  total: {total}\n  files:\n    \
             src/lib.rs: {{ tokens: 0, reason: root lints }}\n    \
             src/header.rs: {{ tokens: 2, reason: export }}\n    \
             src/raw.rs: {{ tokens: {raw}, reason: views }}\n  dependencies:\n    zerocopy: always\n    \
             libloading: host\n    object: host\n    loom: cfg(loom)\n  dependents:\n    \
             crates/busbar-plugin-abi/Cargo.toml: forwards host\n{extra}"
        )
    }

    fn register(total: usize, raw: usize, extra: &str) -> Register {
        parse_register("fixture", &register_text(total, raw, extra)).expect("fixture register")
    }

    fn tree() -> Tree {
        let mut files = BTreeMap::new();
        files.insert(
            "crates/busbar-ffi/src/lib.rs".to_string(),
            FFI_LIB.to_string(),
        );
        files.insert(
            "crates/busbar-ffi/src/header.rs".to_string(),
            FFI_HEADER.to_string(),
        );
        files.insert(
            "crates/busbar-ffi/src/raw.rs".to_string(),
            FFI_RAW.to_string(),
        );
        files.insert("crates/x/src/lib.rs".to_string(), ROOT_OK.to_string());
        let mut manifests = BTreeMap::new();
        manifests.insert(
            "crates/busbar-ffi/Cargo.toml".to_string(),
            FFI_MANIFEST.to_string(),
        );
        manifests.insert(
            "crates/busbar-plugin-abi/Cargo.toml".to_string(),
            ABI_MANIFEST.to_string(),
        );
        manifests.insert(
            "crates/x/Cargo.toml".to_string(),
            "[package]\nname = \"x\"\n".to_string(),
        );
        Tree {
            files,
            manifests,
            roots: ["crates/x/src/lib.rs".to_string()].into_iter().collect(),
        }
    }

    fn base() -> Vec<AtBase> {
        vec![("base".to_string(), Some(register(4, 2, "")))]
    }

    fn red(tree: &Tree, now: &Register, bases: &[AtBase], wants: &str) {
        let failures = judge(tree, now, bases);
        assert!(
            failures.iter().any(|failure| failure.contains(wants)),
            "expected a failure containing {wants:?}, got {failures:?}"
        );
    }

    #[test]
    fn the_fixture_baseline_is_green() {
        let failures = judge(&tree(), &register(4, 2, ""), &base());
        assert!(failures.is_empty(), "{failures:?}");
    }

    /// RT1: a walk red for each tree, the standalone workspaces included.
    #[test]
    fn walk_reds_for_each_tree() {
        for path in [
            "crates/busbar-contract/src/a.rs",
            "crates/plugin-loader/src/a.rs",
            "crates/busbar-core-connector/src/a.rs",
            "crates/busbar-kernel/src/a.rs",
            "crates/busbar-crypto-backend/src/a.rs",
            "dist/default/tests/a.rs",
            "tools/plugin-bench/src/a.rs",
            "tools/system-hammer/src/a.rs",
            "ci/hop/src/a.rs",
        ] {
            let mut tree = tree();
            tree.files
                .insert(path.to_string(), "fn f() { unsafe {} }\n".to_string());
            red(
                &tree,
                &register(4, 2, ""),
                &base(),
                &format!("unsafe: {path} has 1 escape tokens"),
            );
        }
        for (source, what) in [
            (
                "#[unsafe(no_mangle)] pub extern \"C\" fn f() {}\n",
                "no_mangle",
            ),
            ("#[export_name = \"f\"] pub fn f() {}\n", "export_name"),
            ("unsafe extern \"C\" { fn f(); }\n", "extern block"),
            ("#![cfg_attr(unix, allow(unsafe_code))]\n", "cfg_attr allow"),
            (
                "#![expect(non_snake_case, unsafe_code)]\n",
                "multi-lint expect",
            ),
            ("core::arch::global_asm!(\"nop\");\n", "global_asm"),
            (
                "include!(concat!(env!(\"OUT_DIR\"), \"/g.rs\"));\n",
                "OUT_DIR include",
            ),
        ] {
            let mut tree = tree();
            tree.files
                .insert("crates/x/src/b.rs".to_string(), source.to_string());
            let failures = judge(&tree, &register(4, 2, ""), &base());
            assert!(
                failures
                    .iter()
                    .any(|failure| failure.contains("unsafe: crates/x/src/b.rs has")),
                "{what}: {failures:?}"
            );
        }
        let mut tree = tree();
        tree.files.insert(
            "tools/gen/build.rs".to_string(),
            "fn main() { std::fs::write(\"gen.rs\", \"\").ok(); }\n".to_string(),
        );
        red(
            &tree,
            &register(4, 2, ""),
            &base(),
            "unsafe: tools/gen/build.rs has 1",
        );
    }

    /// RT2: root reds, the backends and the `doc(test)` attribute included.
    #[test]
    fn root_reds() {
        for (source, why) in [
            ("#![deny(unsafe_code)]\n", "deny only"),
            ("#![forbid(unsafe_code)]\n", "no doc(test)"),
            ("#![doc(test(attr(forbid(unsafe_code))))]\n", "no forbid"),
        ] {
            for root in [
                "crates/busbar-crypto-backend/src/lib.rs",
                "crates/x/src/lib.rs",
            ] {
                let mut tree = tree();
                tree.files.insert(root.to_string(), source.to_string());
                tree.roots.insert(root.to_string());
                let failures = judge(&tree, &register(4, 2, ""), &base());
                assert!(
                    failures
                        .iter()
                        .any(|failure| failure.contains(&format!("package root {root} lacks"))),
                    "{why} at {root}: {failures:?}"
                );
            }
        }
    }

    /// RT3 `ffi_total_never_rises`: each fixture is red; a net-zero move passes.
    #[test]
    fn ffi_total_never_rises() {
        // A total raised (and measured to match) against the base.
        let mut raised = tree();
        raised.files.insert(
            "crates/busbar-ffi/src/raw.rs".to_string(),
            format!("{FFI_RAW}fn g(p: *const u8) -> u8 {{\n    // SAFETY: fixture.\n    unsafe {{ *p }}\n}}\n"),
        );
        red(
            &raised,
            &register(5, 3, ""),
            &base(),
            "rose above 4 at base",
        );
        // An `admitted` row on ffi: the register refuses unknown keys.
        assert!(parse_register(
            "fixture",
            &format!("{}admitted:\n  ffi: ruling\n", register_text(4, 2, ""))
        )
        .is_err());
        // Measured below the total.
        red(&tree(), &register(5, 3, ""), &base(), "lower its pin to 2");
        red(&tree(), &register(5, 3, ""), &base(), "lower `total` to 4");
        // A `#[doc(hidden)]`-line token and a `cfg(test)` token count.
        for source in [
            "#[doc(hidden)] pub unsafe fn f() {}\n",
            "#[cfg(test)]\nmod t { fn f() { unsafe {} } }\n",
        ] {
            let mut tree = tree();
            tree.files
                .insert("crates/x/src/c.rs".to_string(), source.to_string());
            red(
                &tree,
                &register(4, 2, ""),
                &base(),
                "unsafe: crates/x/src/c.rs has 1",
            );
        }
        // A private macro's `unsafe`.
        let mut private_macro = tree();
        private_macro.files.insert(
            "crates/busbar-ffi/src/raw.rs".to_string(),
            "#![allow(unsafe_code)]\nmacro_rules! m { () => { unsafe {} }; }\n".to_string(),
        );
        red(
            &private_macro,
            &register(4, 2, ""),
            &base(),
            "an `unsafe` token in the body of macro_rules! m",
        );
        // A `build.rs` with `include!` inside busbar-ffi: not a pinned file.
        let mut build = tree();
        build.files.insert(
            "crates/busbar-ffi/build.rs".to_string(),
            "fn main() { include!(\"x.rs\"); }\n".to_string(),
        );
        red(
            &build,
            &register(4, 2, ""),
            &base(),
            "build.rs is not a pinned file",
        );
        // A deleted `ffi` row.
        assert!(parse_register("fixture", "version: 2\ninterim: {}\n").is_err());
        // A moved path.
        let moved =
            register_text(4, 2, "").replace("path: crates/busbar-ffi", "path: crates/elsewhere");
        let moved = parse_register("fixture", &moved).expect("parses");
        red(&tree(), &moved, &base(), "does not move");
        // A pre-U0 base (no register) while the target tip has one; and a missing base file.
        let pre_u0 = vec![
            ("pre-u0".to_string(), None),
            ("tip".to_string(), Some(register(4, 2, ""))),
        ];
        red(&tree(), &register(4, 2, ""), &pre_u0, "missing at pre-u0");
        // A net-zero move between pinned files passes.
        let mut moved_token = tree();
        moved_token.files.insert(
            "crates/busbar-ffi/src/raw.rs".to_string(),
            "#![allow(unsafe_code)]\n".to_string(),
        );
        moved_token.files.insert(
            "crates/busbar-ffi/src/header.rs".to_string(),
            format!("{FFI_HEADER}// SAFETY: fixture.\nunsafe impl Sync for X {{}}\n"),
        );
        let net_zero = register_text(4, 1, "")
            .replace("src/header.rs: { tokens: 2", "src/header.rs: { tokens: 3");
        let net_zero = parse_register("fixture", &net_zero).expect("parses");
        let failures = judge(&moved_token, &net_zero, &base());
        assert!(failures.is_empty(), "a net-zero move passes: {failures:?}");
    }

    /// RT4: tests hold no `unsafe` (TST-7): no test-range exemption.
    #[test]
    fn tests_hold_no_unsafe() {
        let mut tree = tree();
        tree.files.insert(
            "crates/x/tests/t.rs".to_string(),
            "#[test]\nfn t() { unsafe {} }\n".to_string(),
        );
        red(
            &tree,
            &register(4, 2, ""),
            &base(),
            "unsafe: crates/x/tests/t.rs has 1",
        );
    }

    /// RT5: a `$`-metavariable inside an `unsafe` construct of a busbar-ffi macro (E5).
    #[test]
    fn a_metavariable_inside_unsafe_is_red() {
        let mut tree = tree();
        tree.files.insert(
            "crates/busbar-ffi/src/header.rs".to_string(),
            FFI_HEADER.replace("#[unsafe(no_mangle)]", "#[unsafe(export_name = $p)]"),
        );
        red(&tree, &register(4, 2, ""), &base(), "(E5)");
    }

    /// The owner's pins: no new file, no move without its pin, no new dependency, no new dependent.
    #[test]
    fn ffi_files_dependencies_and_dependents_are_pinned() {
        let mut new_file = tree();
        new_file.files.insert(
            "crates/busbar-ffi/src/alloc.rs".to_string(),
            "pub fn f() {}\n".to_string(),
        );
        red(
            &new_file,
            &register(4, 2, ""),
            &base(),
            "src/alloc.rs is not a pinned file",
        );

        let mut moved = tree();
        moved.files.insert(
            "crates/busbar-ffi/src/header.rs".to_string(),
            format!("{FFI_HEADER}// SAFETY: fixture.\nunsafe impl Sync for X {{}}\n"),
        );
        moved.files.insert(
            "crates/busbar-ffi/src/raw.rs".to_string(),
            "#![allow(unsafe_code)]\n".to_string(),
        );
        red(&moved, &register(4, 2, ""), &base(), "above its pin of 2");

        let mut dependency = tree();
        dependency.manifests.insert(
            "crates/busbar-ffi/Cargo.toml".to_string(),
            format!("{FFI_MANIFEST}libc = \"0.2\"\n").replace(
                "[target.'cfg(loom)'.dependencies]\nloom = { workspace = true }\nlibc = \"0.2\"\n",
                "[target.'cfg(loom)'.dependencies]\nloom = { workspace = true }\n\n[dependencies.libc]\nversion = \"0.2\"\n",
            ),
        );
        red(
            &dependency,
            &register(4, 2, ""),
            &base(),
            "a new dependency needs the owner",
        );

        let mut dependent = tree();
        dependent.manifests.insert(
            "crates/busbar-kernel/Cargo.toml".to_string(),
            "[dependencies]\nbusbar-ffi = { path = \"../busbar-ffi\" }\n".to_string(),
        );
        red(&dependent, &register(4, 2, ""), &base(), "E12");

        let mut plugin_host = tree();
        plugin_host.manifests.insert(
            "plugins/p/Cargo.toml".to_string(),
            "[dependencies]\nbusbar-ffi = { git = \"x\", features = [\"host\"] }\n".to_string(),
        );
        red(&plugin_host, &register(4, 2, ""), &base(), "E12");

        let mut no_safety = tree();
        no_safety.files.insert(
            "crates/busbar-ffi/src/raw.rs".to_string(),
            "#![allow(unsafe_code)]\nfn get(p: *const u8) -> u8 {\n    unsafe { *p }\n}\n"
                .to_string(),
        );
        red(&no_safety, &register(4, 2, ""), &base(), "(E6)");

        let mut lowered = tree();
        lowered.files.insert(
            "crates/busbar-ffi/src/raw.rs".to_string(),
            format!("#![allow(clippy::undocumented_unsafe_blocks)]\n{FFI_RAW}"),
        );
        red(&lowered, &register(4, 2, ""), &base(), "(E10)");
    }

    #[test]
    fn doc_code_in_busbar_ffi_counts_and_prose_does_not() {
        let mut tree = tree();
        tree.files.insert(
            "crates/busbar-ffi/src/raw.rs".to_string(),
            format!("{FFI_RAW}/// ```\n/// unsafe {{ }}\n/// ```\n/// ```text\n/// unsafe\n/// ```\nfn h() {{}}\n"),
        );
        red(
            &tree,
            &register(4, 2, ""),
            &base(),
            "src/raw.rs has 3 unsafe tokens",
        );
    }
}
