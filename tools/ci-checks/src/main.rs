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
//! - `spdx-headers`: every tracked `.rs` file and migration-corpus YAML carries `SPDX-License-Identifier:
//!   Apache-2.0` near the top and none names another licence (#277, `spdx.rs`).
//! - `no-serde-json`: JSON is sonic-rs through `busbar_contract::json` (DEP-3, #162): no first-party
//!   Rust file or manifest under `crates/`, `dist/`, `tools/` or `testing/` names serde_json, tests
//!   included, outside the wave-3 paths `ci/serde-json-w3.allow` lists (`no_serde_json.rs`).
//! - `crypto-graph`: AWS-LC is the one crypto provider, reached only through the facade (229). In
//!   the root workspace's feature-resolved graph (`cargo tree`: every feature, target and edge
//!   kind), `ring`, `sha2`, `ed25519-dalek` and `curve25519-dalek` are built only beneath
//!   `busbar-crypto*`. Dev edges count: tests use the facade too. And `curve25519-dalek` is built
//!   only beneath `busbar-crypto-backend`, never by the facade itself: a FIPS build swaps the
//!   backend and keeps the facade, and admits no unvalidated crypto crate (QE-BOOT-KEYCHECK).
//! - `migrate-flag-text`, `migrate-retired-words`, `migrate-anchors`: the migrate-on-boot checks
//!   (`migrate.rs`).
//! - `migrate-overlay-separation`, `migrate-overlay-keys`, `migrate-overlay-docs`: the 1.5.5
//!   overlay's separation, key and upgrade-page checks (`migrate_overlay.rs`).
//! - `migrate-size`: the migrator's separation and anchor gates, with its sizes printed
//!   (`migrate_size.rs`).
//! - `fleet-manifest`: `fleet/deps.toml`'s `[min3-closure]` and `plugins.yaml`'s 33 ported and 2 archived
//!   repos (IF §15 rules 1a, 1b).
//! - `c-transport`, `export-streams`, `no-licence`, `core-scan`: source checks over core (C-TRANSPORT
//!   test 11, C-EXPORT-STREAMS, C-NO-LICENCE (a), the §15.8 core scan). `loc-report` prints per-file
//!   production and test lines (a report, no gate).
//! - `no-known-red`: no known-red, baseline or allow-failure list of failing tests (TST-8, busbar#280;
//!   `known_red.rs`).
//! - `rule-13`: a dlopened library leaves the loader only by IF §11.1's two exits (IF §15 rule 13, I13).
//! - `oracle <sub> ...`: the data logic `bin/oracle` launches (`oracle.rs`): premise widening, the
//!   shard split and its proofs, and the readers its ci-run and replay sections need (BLD-6).
//!   `oracle run <sub> ...` is `bin/oracle` itself (`oracle_run.rs`, `oracle_judge.rs`,
//!   `oracle_selftest.rs`): the judge fetched and held to its digest, `ci-run`, `record`, `replay`,
//!   `diff`, the shard commands and the selftests; the shell file only builds this and calls it.
//! - With arguments, the first one naming the check: `template-drift`, `patch-drift`, `no-host-link`,
//!   `plugin-rules` and `c-alias`, run from a plugin repo's CI against the repo or its files.
//!
//! Usage: `busbar-ci-checks [check...]`; with no argument every check runs. Each finding prints as
//! one line; any finding or error fails the run.

#![forbid(unsafe_code)]
#![doc(test(attr(forbid(unsafe_code))))]

use std::path::{Component, Path, PathBuf};
use std::process::{Command, ExitCode};

use proc_macro2::{Spacing, TokenStream, TokenTree};
use syn::punctuated::Punctuated;
use syn::visit::{self, Visit};
use syn::{
    Attribute, Expr, ExprLit, ImplItem, Item, ItemMod, Lit, Meta, Token, TraitItem, UseTree,
};

mod migrate;
mod migrate_overlay;
mod migrate_size;
mod no_serde_json;
mod oracle;
mod oracle_judge;
mod oracle_run;
mod oracle_selftest;
mod spdx;

/// Checks over core's own tree: with no argument every one runs.
const CHECKS: [&str; 18] = [
    "no-getrandom",
    "no-known-red",
    "spdx-headers",
    "no-serde-json",
    "crypto-graph",
    "fleet-manifest",
    "c-transport",
    "export-streams",
    "no-licence",
    "core-scan",
    "rule-13",
    "migrate-flag-text",
    "migrate-retired-words",
    "migrate-anchors",
    "migrate-overlay-separation",
    "migrate-overlay-keys",
    "migrate-overlay-docs",
    "migrate-size",
];
/// Checks that take arguments (a plugin repo, files). Named first, the rest of the command line is theirs.
const ARG_CHECKS: [&str; 7] = [
    "template-drift",
    "patch-drift",
    "no-host-link",
    "plugin-rules",
    "c-alias",
    "core-scan",
    "loc-report",
];

/// A check's findings, or the error that stopped it.
pub(crate) type Outcome = Result<Vec<String>, String>;

mod core_scan;
mod core_src;
mod fleet;
mod host_link;
mod known_red;
mod plugin_rules;
mod rule13;
mod supply;
/// The crypto seam: `busbar-crypto` and `busbar-crypto-backend` (crate directories and packages).
const SEAM: &str = "busbar-crypto";
/// The backend inside the seam: a private build swaps it by `[patch]`.
const BACKEND: &str = "busbar-crypto-backend";
/// Crypto crates reachable only through the seam.
const SEAM_ONLY: [&str; 4] = ["ring", "sha2", "ed25519-dalek", "curve25519-dalek"];
/// Crates only core's software backend may build: never the facade, which a FIPS build keeps
/// (QE-BOOT-KEYCHECK: curve25519-dalek decompresses pinned Ed25519 keys in the backend alone).
const BACKEND_ONLY: [&str; 1] = ["curve25519-dalek"];

fn main() -> ExitCode {
    let root = repo_root();
    let args: Vec<String> = std::env::args().skip(1).collect();
    // `oracle <sub> ...`: bin/oracle's data logic (oracle.rs), answering with its own stdout, stderr
    // and exit status rather than as a check.
    if let Some(("oracle", rest)) = args
        .split_first()
        .map(|(first, rest)| (first.as_str(), rest))
    {
        return oracle::run(rest);
    }
    // A check that takes arguments is named first and owns the rest of the command line.
    let (names, rest): (Vec<&str>, &[String]) = match args.split_first() {
        None => (CHECKS.to_vec(), &[]),
        Some((first, rest)) if ARG_CHECKS.contains(&first.as_str()) => (vec![first.as_str()], rest),
        Some(_) => (args.iter().map(String::as_str).collect(), &[]),
    };
    let mut failed = false;
    for name in names {
        let outcome = match name {
            "no-getrandom" => no_getrandom(&root),
            "no-known-red" => known_red::no_known_red(&root),
            "spdx-headers" => spdx::spdx_headers(&root),
            "no-serde-json" => no_serde_json::no_serde_json(&root),
            "crypto-graph" => crypto_graph(&root),
            "migrate-flag-text" => migrate::flag_text(&root),
            "migrate-retired-words" => migrate::retired_words(&root),
            "migrate-anchors" => migrate::anchors(&root),
            "migrate-overlay-separation" => migrate_overlay::separation(&root),
            "migrate-overlay-keys" => migrate_overlay::hook_keys(&root),
            "migrate-overlay-docs" => migrate_overlay::docs(&root),
            "migrate-size" => migrate_size::run(&root),
            "fleet-manifest" => fleet::fleet_manifest(&root),
            "c-alias" => fleet::c_alias(&root, rest),
            "c-transport" => core_src::c_transport(&root),
            "export-streams" => core_src::export_streams(&root),
            "no-licence" => core_src::no_licence(&root),
            "core-scan" => core_scan::core_scan(&root, rest),
            "rule-13" => rule13::rule_13(&root),
            "loc-report" => core_src::loc_report(&root),
            "template-drift" => supply::template_drift_cli(rest),
            "patch-drift" => supply::patch_drift_cli(&root, rest),
            "no-host-link" => host_link::no_host_link(rest),
            "plugin-rules" => plugin_rules::plugin_rules(rest),
            other => Err(format!(
                "unknown check `{other}` (checks: {}; with arguments: {})",
                CHECKS.join(", "),
                ARG_CHECKS.join(", ")
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

/// Both the root and shipped workspace's feature-resolved graphs (every feature, target and edge kind), outside the
/// seam: cargo's own resolver decides what builds. `Cargo.lock` alone over-reports: it also records
/// an optional dependency that only a weak feature names (rustls-webpki's `alloc = ["ring?/alloc"]`
/// keeps a `ring` entry that no build compiles). Then the facade's own graph without the backend:
/// a private (FIPS) build swaps the backend and keeps the facade, so a backend-only crate reached
/// from the facade would enter that build too.
///
/// The facade's own graph is read once, in the root workspace, where busbar-crypto is a member and
/// `--all-features` turns on every feature it has. In the shipped workspace busbar-crypto is a path
/// dependency, not a member: cargo refuses features for it there, and the features its members
/// unify on it are a subset of the root reading's, so only the graph outside the seam is read.
fn crypto_graph(root: &Path) -> Result<Vec<String>, String> {
    let mut findings = seam_outside_graph(root)?;
    let facade = cargo_tree(root, &["--package", SEAM, "--prune", BACKEND])?;
    findings.extend(backend_only_reached(&facade));
    let shipped = root.join("dist/default");
    if shipped.join("Cargo.toml").is_file() {
        findings.extend(
            seam_outside_graph(&shipped)?
                .into_iter()
                .map(|finding| format!("dist/default: {finding}")),
        );
    }
    Ok(findings)
}

/// Every seam-only crate the workspace reaches outside busbar-crypto (and its backend).
fn seam_outside_graph(root: &Path) -> Result<Vec<String>, String> {
    let outside = cargo_tree(
        root,
        &[
            "--workspace",
            "--exclude",
            SEAM,
            "--prune",
            SEAM,
            "--prune",
            BACKEND,
        ],
    )?;
    Ok(seam_only_reached(&outside))
}

/// `cargo tree` over every feature, target and edge kind, as `--prefix depth` lines of `{p}`.
fn cargo_tree(root: &Path, select: &[&str]) -> Result<String, String> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let output = Command::new(cargo)
        .current_dir(root)
        .args(["tree", "--locked"])
        .args(select)
        .args([
            "--all-features",
            "--target",
            "all",
            "--edges",
            "normal,build,dev",
            "--prefix",
            "depth",
            "--format",
            "{p}",
        ])
        .output()
        .map_err(|error| format!("cargo tree: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "cargo tree: {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Each seam-only crate in a `cargo tree --prefix depth` listing, with the path that reaches it.
fn seam_only_reached(tree: &str) -> Vec<String> {
    reached(tree, &SEAM_ONLY, "outside busbar-crypto*")
}

/// Each backend-only crate in the facade's listing (backend pruned), with the path that reaches it.
fn backend_only_reached(tree: &str) -> Vec<String> {
    reached(
        tree,
        &BACKEND_ONLY,
        "by busbar-crypto outside busbar-crypto-backend, so a swapped-in (FIPS) backend would link it",
    )
}

fn reached(tree: &str, crates: &[&str], outside: &str) -> Vec<String> {
    let mut path: Vec<&str> = Vec::new();
    let mut findings = Vec::new();
    for line in tree.lines() {
        let digits = line.bytes().take_while(u8::is_ascii_digit).count();
        let Ok(depth) = line[..digits].parse::<usize>() else {
            continue;
        };
        let package = &line[digits..];
        let name = package.split(' ').next().unwrap_or_default();
        path.truncate(depth);
        path.push(name);
        // `(*)`: a repeat of a subtree already listed (and reported) above.
        if crates.contains(&name) && !package.ends_with("(*)") {
            findings.push(format!(
                "{package} is built {outside}: {}",
                path.join(" -> ")
            ));
        }
    }
    findings
}

#[cfg(test)]
mod tests;

#[cfg(test)]
#[path = "migrate_size_tests.rs"]
mod migrate_size_tests;

#[cfg(test)]
mod checks_tests;

#[cfg(test)]
mod spdx_tests;

#[cfg(test)]
mod known_red_tests;
