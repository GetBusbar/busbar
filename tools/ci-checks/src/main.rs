// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Core's repository checks. Each runs as its own CI job (the job lines live in busbar-release
//! `ci/core.yml`), and the crate's tests run each over the real tree too.
//!
//! - `no-getrandom`: randomness is the crypto facade's (`busbar_contract::crypto::{fill, u64,
//!   random}`; CRYPTO-SEAM, decision 229). No first-party code under `crates/` outside
//!   `crates/busbar-crypto*` names the `getrandom` crate, except test code: an item or module under a
//!   test-only `#[cfg(test)]` (read from the syn AST, as bad-patterns does), a `#[test]` fn, or a
//!   `tests/` tree. A file syn cannot parse is scanned line by line instead, so it is never skipped.
//! - `crypto-graph`: AWS-LC is the one crypto provider, reached only through the facade (229). In
//!   the root `Cargo.lock`, `ring`, `sha2` and `ed25519-dalek` are reachable from first-party
//!   packages only through `busbar-crypto*`. Dev-dependency edges count: tests use the facade too.
//!
//! Usage: `busbar-ci-checks [check...]`; with no argument every check runs. Each finding prints as
//! one line; any finding or error fails the run.

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, VecDeque};
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;

use proc_macro2::{Spacing, TokenStream, TokenTree};
use syn::punctuated::Punctuated;
use syn::visit::{self, Visit};
use syn::{
    Attribute, Expr, ExprLit, ImplItem, Item, ItemMod, Lit, Meta, Token, TraitItem, UseTree,
};

const CHECKS: [&str; 2] = ["no-getrandom", "crypto-graph"];
/// The crypto seam: `busbar-crypto` and `busbar-crypto-backend` (crate directories and packages).
const SEAM: &str = "busbar-crypto";
/// Crypto crates reachable only through the seam.
const SEAM_ONLY: [&str; 3] = ["ring", "sha2", "ed25519-dalek"];

fn main() -> ExitCode {
    let root = repo_root();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let names: Vec<&str> = if args.is_empty() {
        CHECKS.to_vec()
    } else {
        args.iter().map(String::as_str).collect()
    };
    let mut failed = false;
    for name in names {
        let outcome = match name {
            "no-getrandom" => no_getrandom(&root),
            "crypto-graph" => std::fs::read_to_string(root.join("Cargo.lock"))
                .map(|lock| crypto_graph(&lock))
                .map_err(|error| format!("Cargo.lock: {error}")),
            other => Err(format!(
                "unknown check `{other}` (checks: {})",
                CHECKS.join(", ")
            )),
        };
        match outcome {
            Ok(findings) if findings.is_empty() => println!("{name}: clean"),
            Ok(findings) => {
                failed = true;
                for finding in &findings {
                    println!("{finding}");
                }
                println!("{name}: {} finding(s)", findings.len());
            }
            Err(error) => {
                failed = true;
                eprintln!("{name}: {error}");
            }
        }
    }
    if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

/// The repository root: this crate lives at `tools/ci-checks`.
fn repo_root() -> PathBuf {
    normalize(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."))
}

// ---- no-getrandom -------------------------------------------------------------------------------

fn no_getrandom(root: &Path) -> Result<Vec<String>, String> {
    let mut files = Vec::new();
    for dir in sorted_entries(&root.join("crates"))? {
        let seam = dir
            .file_name()
            .is_some_and(|name| name.to_string_lossy().starts_with(SEAM));
        if !seam && dir.is_dir() {
            rust_files(&dir, &mut files)?;
        }
    }
    let mut hits = Vec::new();
    let mut test_modules = Vec::new();
    for file in files {
        let text = std::fs::read_to_string(&file)
            .map_err(|error| format!("{}: {error}", rel(root, &file)))?;
        let scan = scan_source(&file, &text);
        test_modules.extend(scan.test_modules);
        for (line, note) in scan.hits {
            hits.push((file.clone(), line, note));
        }
    }
    Ok(hits
        .into_iter()
        .filter(|(file, _, _)| !test_modules.iter().any(|module| module.covers(file)))
        .map(|(file, line, note)| {
            format!(
                "{}:{line}: names the getrandom crate outside busbar-crypto*; randomness is \
                 busbar_contract::crypto::{{fill, u64, random}}{note}",
                rel(root, &file)
            )
        })
        .collect())
}

/// Every `.rs` file under `dir`, in path order, skipping `tests/` trees and build output.
fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
    for path in sorted_entries(dir)? {
        if path.is_dir() {
            let skipped = path
                .file_name()
                .is_some_and(|name| name == "tests" || name == "target");
            if !skipped {
                rust_files(&path, out)?;
            }
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
    Ok(())
}

fn sorted_entries(dir: &Path) -> Result<Vec<PathBuf>, String> {
    let entries = std::fs::read_dir(dir).map_err(|error| format!("{}: {error}", dir.display()))?;
    let mut paths = Vec::new();
    for entry in entries {
        paths.push(
            entry
                .map_err(|error| format!("{}: {error}", dir.display()))?
                .path(),
        );
    }
    paths.sort();
    Ok(paths)
}

/// One file's production `getrandom` sites and the module files it declares under test cfg.
struct Scan {
    /// Where a `mod name;` declared at the current point resolves `name`.
    dir: PathBuf,
    /// The declaring file's directory: a `#[path]` outside any inline module resolves against it.
    file_dir: PathBuf,
    /// Inline `mod name { .. }` blocks entered (a `#[path]` inside one resolves against `dir`).
    inline: usize,
    /// Test-only scopes entered; sites found inside one are test code.
    test_depth: usize,
    /// (line, note) of each production site.
    hits: Vec<(usize, String)>,
    test_modules: Vec<TestModule>,
}

/// A module file declared under test cfg, and the directory its own submodules live in.
struct TestModule {
    file: PathBuf,
    tree: PathBuf,
}

impl TestModule {
    fn covers(&self, file: &Path) -> bool {
        file == self.file || file.starts_with(&self.tree)
    }
}

fn scan_source(file: &Path, text: &str) -> Scan {
    let mut scan = Scan {
        dir: module_dir(file),
        file_dir: file.parent().map(Path::to_path_buf).unwrap_or_default(),
        inline: 0,
        test_depth: 0,
        hits: Vec::new(),
        test_modules: Vec::new(),
    };
    match syn::parse_file(text) {
        Ok(ast) => {
            // `#![cfg(test)]`: the whole file is test code.
            scan.test_depth = usize::from(is_test(&ast.attrs));
            scan.visit_file(&ast);
        }
        Err(error) => {
            let note = format!(" (scanned by line: syn could not parse the file: {error})");
            for (index, line) in text.lines().enumerate() {
                let code = line.trim_start();
                if !code.starts_with("//") && code.contains("getrandom::") {
                    scan.hits.push((index + 1, note.clone()));
                }
            }
        }
    }
    scan
}

/// The directory a file's `mod name;` declarations resolve against: a crate root or `mod.rs`
/// resolves beside itself, any other module file in the directory named after it.
fn module_dir(file: &Path) -> PathBuf {
    let parent = file.parent().unwrap_or(Path::new(""));
    match file.file_name().and_then(|name| name.to_str()) {
        Some("lib.rs" | "main.rs" | "mod.rs" | "build.rs") => parent.to_path_buf(),
        _ => file
            .file_stem()
            .map_or_else(|| parent.to_path_buf(), |stem| parent.join(stem)),
    }
}

impl Scan {
    fn hit(&mut self, line: usize) {
        if self.test_depth == 0 {
            self.hits.push((line, String::new()));
        }
    }

    fn guarded(&mut self, attrs: &[Attribute], walk: impl FnOnce(&mut Self)) {
        let test = usize::from(is_test(attrs));
        self.test_depth += test;
        walk(self);
        self.test_depth -= test;
    }

    fn use_root(&mut self, tree: &UseTree) {
        match tree {
            UseTree::Path(path) if path.ident == "getrandom" => {
                self.hit(path.ident.span().start().line);
            }
            UseTree::Name(name) if name.ident == "getrandom" => {
                self.hit(name.ident.span().start().line);
            }
            UseTree::Rename(rename) if rename.ident == "getrandom" => {
                self.hit(rename.ident.span().start().line);
            }
            UseTree::Group(group) => {
                for item in &group.items {
                    self.use_root(item);
                }
            }
            _ => {}
        }
    }

    /// `getrandom::` inside a macro's tokens (macro bodies are not parsed into paths).
    fn tokens(&mut self, stream: TokenStream) {
        let mut after_colon = false;
        let mut tokens = stream.into_iter().peekable();
        while let Some(token) = tokens.next() {
            let colon = matches!(&token, TokenTree::Punct(punct) if punct.as_char() == ':');
            match token {
                TokenTree::Group(group) => self.tokens(group.stream()),
                TokenTree::Ident(ident) if ident == "getrandom" && !after_colon => {
                    let path_follows = matches!(
                        tokens.peek(),
                        Some(TokenTree::Punct(punct))
                            if punct.as_char() == ':' && punct.spacing() == Spacing::Joint
                    );
                    if path_follows {
                        self.hit(ident.span().start().line);
                    }
                }
                _ => {}
            }
            after_colon = colon;
        }
    }
}

impl<'ast> Visit<'ast> for Scan {
    fn visit_item(&mut self, item: &'ast Item) {
        self.guarded(item_attrs(item), |scan| visit::visit_item(scan, item));
    }

    fn visit_impl_item(&mut self, item: &'ast ImplItem) {
        self.guarded(impl_item_attrs(item), |scan| {
            visit::visit_impl_item(scan, item);
        });
    }

    fn visit_trait_item(&mut self, item: &'ast TraitItem) {
        self.guarded(trait_item_attrs(item), |scan| {
            visit::visit_trait_item(scan, item);
        });
    }

    fn visit_item_mod(&mut self, module: &'ast ItemMod) {
        let name = module.ident.to_string();
        if module.content.is_some() {
            let outer = self.dir.clone();
            self.dir.push(&name);
            self.inline += 1;
            visit::visit_item_mod(self, module);
            self.inline -= 1;
            self.dir = outer;
        } else if self.test_depth > 0 {
            let file = match path_attr(&module.attrs) {
                Some(path) if self.inline > 0 => normalize(&self.dir.join(path)),
                Some(path) => normalize(&self.file_dir.join(path)),
                None => normalize(&self.dir.join(format!("{name}.rs"))),
            };
            let tree = module_dir(&file);
            self.test_modules.push(TestModule { file, tree });
        }
    }

    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        self.use_root(&item.tree);
        visit::visit_item_use(self, item);
    }

    fn visit_item_extern_crate(&mut self, item: &'ast syn::ItemExternCrate) {
        if item.ident == "getrandom" {
            self.hit(item.ident.span().start().line);
        }
        visit::visit_item_extern_crate(self, item);
    }

    fn visit_path(&mut self, path: &'ast syn::Path) {
        let crate_path = path.segments.len() > 1;
        if let Some(first) = path
            .segments
            .first()
            .filter(|first| crate_path && first.ident == "getrandom")
        {
            self.hit(first.ident.span().start().line);
        }
        visit::visit_path(self, path);
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        self.tokens(mac.tokens.clone());
        visit::visit_macro(self, mac);
    }
}

fn item_attrs(item: &Item) -> &[Attribute] {
    match item {
        Item::Const(item) => &item.attrs,
        Item::Enum(item) => &item.attrs,
        Item::ExternCrate(item) => &item.attrs,
        Item::Fn(item) => &item.attrs,
        Item::ForeignMod(item) => &item.attrs,
        Item::Impl(item) => &item.attrs,
        Item::Macro(item) => &item.attrs,
        Item::Mod(item) => &item.attrs,
        Item::Static(item) => &item.attrs,
        Item::Struct(item) => &item.attrs,
        Item::Trait(item) => &item.attrs,
        Item::TraitAlias(item) => &item.attrs,
        Item::Type(item) => &item.attrs,
        Item::Union(item) => &item.attrs,
        Item::Use(item) => &item.attrs,
        _ => &[],
    }
}

fn impl_item_attrs(item: &ImplItem) -> &[Attribute] {
    match item {
        ImplItem::Const(item) => &item.attrs,
        ImplItem::Fn(item) => &item.attrs,
        ImplItem::Type(item) => &item.attrs,
        ImplItem::Macro(item) => &item.attrs,
        _ => &[],
    }
}

fn trait_item_attrs(item: &TraitItem) -> &[Attribute] {
    match item {
        TraitItem::Const(item) => &item.attrs,
        TraitItem::Fn(item) => &item.attrs,
        TraitItem::Type(item) => &item.attrs,
        TraitItem::Macro(item) => &item.attrs,
        _ => &[],
    }
}

/// Test code: a `#[test]`-style attribute (`#[test]`, `#[tokio::test]`), or a `cfg` that holds
/// only under `test` (`cfg(test)`, `cfg(all(test, ..))`; `cfg(any(test, ..))` is production).
fn is_test(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attr| {
        let path = attr.path();
        path.segments
            .last()
            .is_some_and(|last| last.ident == "test")
            || (path.is_ident("cfg")
                && attr.parse_args::<Meta>().is_ok_and(|meta| test_only(&meta)))
    })
}

fn test_only(meta: &Meta) -> bool {
    match meta {
        Meta::Path(path) => path.is_ident("test"),
        Meta::List(list) if list.path.is_ident("all") => list
            .parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)
            .is_ok_and(|all| all.iter().any(test_only)),
        _ => false,
    }
}

fn path_attr(attrs: &[Attribute]) -> Option<String> {
    attrs
        .iter()
        .find(|attr| attr.path().is_ident("path"))
        .and_then(|attr| match &attr.meta {
            Meta::NameValue(pair) => match &pair.value {
                Expr::Lit(ExprLit {
                    lit: Lit::Str(path),
                    ..
                }) => Some(path.value()),
                _ => None,
            },
            _ => None,
        })
}

/// `a/./b/../c` as `a/c`, without touching the file system.
fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for part in path.components() {
        match part {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other),
        }
    }
    out
}

fn rel(root: &Path, file: &Path) -> String {
    file.strip_prefix(root)
        .unwrap_or(file)
        .display()
        .to_string()
}

// ---- crypto-graph -------------------------------------------------------------------------------

/// One `[[package]]` of a Cargo.lock: path packages (no `source`) are first-party.
struct Package<'a> {
    name: &'a str,
    version: &'a str,
    first_party: bool,
    deps: Vec<&'a str>,
}

fn packages(lock: &str) -> Vec<Package<'_>> {
    let mut out: Vec<Package<'_>> = Vec::new();
    let mut in_package = false;
    let mut in_deps = false;
    for line in lock.lines() {
        let line = line.trim();
        if line.starts_with('[') && !in_deps {
            in_package = line == "[[package]]";
            if in_package {
                out.push(Package {
                    name: "",
                    version: "",
                    first_party: true,
                    deps: Vec::new(),
                });
            }
            continue;
        }
        let Some(package) = out.last_mut().filter(|_| in_package) else {
            continue;
        };
        if in_deps {
            if line == "]" {
                in_deps = false;
            } else {
                package
                    .deps
                    .push(line.trim_end_matches(',').trim_matches('"'));
            }
        } else if let Some(name) = line.strip_prefix("name = ") {
            package.name = name.trim_matches('"');
        } else if let Some(version) = line.strip_prefix("version = ") {
            package.version = version.trim_matches('"');
        } else if line.starts_with("source = ") {
            package.first_party = false;
        } else if line == "dependencies = [" {
            in_deps = true;
        }
    }
    out
}

fn crypto_graph(lock: &str) -> Vec<String> {
    let packages = packages(lock);
    let mut by_name: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    for (index, package) in packages.iter().enumerate() {
        by_name.entry(package.name).or_default().push(index);
    }
    // A lock dependency is `name`, `name version` or `name version (source)`.
    let resolve = |dep: &str| -> Option<usize> {
        let mut parts = dep.split(' ');
        let name = parts.next()?;
        let version = parts.next();
        by_name
            .get(name)?
            .iter()
            .copied()
            .find(|&index| version.is_none_or(|version| packages[index].version == version))
    };
    let seam = |index: usize| packages[index].name.starts_with(SEAM);
    // Breadth-first from every first-party package outside the seam, never entering the seam;
    // `reached_from` keeps each package's first parent for the report.
    let mut reached_from: BTreeMap<usize, Option<usize>> = BTreeMap::new();
    let mut queue = VecDeque::new();
    for (index, package) in packages.iter().enumerate() {
        if package.first_party && !seam(index) {
            reached_from.insert(index, None);
            queue.push_back(index);
        }
    }
    while let Some(index) = queue.pop_front() {
        for &dep in &packages[index].deps {
            let Some(dep) = resolve(dep).filter(|&dep| !seam(dep)) else {
                continue;
            };
            if let Entry::Vacant(slot) = reached_from.entry(dep) {
                slot.insert(Some(index));
                queue.push_back(dep);
            }
        }
    }
    let mut findings = Vec::new();
    for &index in reached_from.keys() {
        let package = &packages[index];
        if !SEAM_ONLY.contains(&package.name) {
            continue;
        }
        let mut chain = vec![package.name];
        let mut parent = reached_from.get(&index).copied().flatten();
        while let Some(at) = parent {
            chain.push(packages[at].name);
            parent = reached_from.get(&at).copied().flatten();
        }
        chain.reverse();
        findings.push(format!(
            "Cargo.lock: {} {} is reachable outside busbar-crypto*: {}",
            package.name,
            package.version,
            chain.join(" -> ")
        ));
    }
    findings
}

#[cfg(test)]
mod tests;
