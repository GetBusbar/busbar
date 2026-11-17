// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The workspace source walk the architecture checks share (CORE-ARCHITECTURE-DIET §7).
//!
//! Targets come from `cargo metadata`, never from guesses. Each target root is walked by
//! following `mod x;`, `#[path]` and `include!("literal")` exactly as rustc resolves them, so
//! every reached file is classified as production (reached from a lib, bin or build-script root
//! outside any test-only region) or test. Test-only means only a build with `cfg(test)` or the
//! dev-dependency-only `test-support` feature compiles it ([`needs_test`]). Lines are counted with
//! `proc-macro2`, which drops comments; `syn` finds the test-only and doc-attribute ranges. No
//! regex.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use proc_macro2::{Delimiter, Spacing, TokenStream, TokenTree};
use serde::Deserialize;
use syn::ext::IdentExt;
use syn::punctuated::Punctuated;
use syn::spanned::Spanned;
use syn::visit::Visit;
use syn::{Attribute, Expr, Item, Meta, Token};

/// The counting method this walker implements.
pub const METHOD: &str = "diet-metrics-v2";

#[derive(Deserialize)]
struct Metadata {
    packages: Vec<MetaPackage>,
    workspace_members: Vec<String>,
    workspace_root: PathBuf,
}

#[derive(Deserialize)]
struct MetaPackage {
    id: String,
    name: String,
    manifest_path: PathBuf,
    targets: Vec<MetaTarget>,
    dependencies: Vec<MetaDependency>,
}

#[derive(Deserialize)]
struct MetaTarget {
    kind: Vec<String>,
    src_path: PathBuf,
}

#[derive(Deserialize)]
pub struct MetaDependency {
    pub name: String,
    pub kind: Option<String>,
}

/// One workspace member, as Cargo resolves it.
pub struct Package {
    pub name: String,
    pub dir: PathBuf,
    pub dependencies: Vec<MetaDependency>,
    roots: Vec<(PathBuf, Class)>,
}

impl Package {
    /// The lib, bin and other non-test, non-build-script target roots.
    pub fn production_roots(&self) -> impl Iterator<Item = &Path> {
        self.roots
            .iter()
            .filter(|(_, class)| *class == Class::Production)
            .map(|(root, _)| root.as_path())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Class {
    Production,
    BuildScript,
    Test,
}

/// The whole workspace after the walk.
pub struct Workspace {
    pub root: PathBuf,
    pub packages: Vec<Package>,
    /// Every reached file, with how it was reached.
    pub files: BTreeMap<PathBuf, Reached>,
}

pub struct Reached {
    pub production: bool,
    pub build_script: bool,
    /// The module path below the target root of the first production route to the file.
    pub module: Vec<String>,
    /// Production lines, counted once when the file is first reached as production.
    pub lines: usize,
    /// Lines of non-literal `include!` sites in its production code.
    generated: Vec<usize>,
}

/// One `include!` whose argument is not a string literal, in production code.
pub struct GeneratedSite {
    pub file: PathBuf,
    pub line: usize,
}

/// `cargo metadata --no-deps` for the workspace that contains this crate.
pub fn load() -> Workspace {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../Cargo.toml");
    let output = Command::new(env!("CARGO"))
        .args([
            "metadata",
            "--no-deps",
            "--offline",
            "--format-version",
            "1",
        ])
        .arg("--manifest-path")
        .arg(&manifest)
        .output()
        .expect("run cargo metadata");
    assert!(
        output.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let metadata: Metadata = sonic_rs::from_slice(&output.stdout).expect("cargo metadata JSON");
    let members: BTreeSet<&str> = metadata
        .workspace_members
        .iter()
        .map(String::as_str)
        .collect();
    let mut packages = Vec::new();
    for package in metadata.packages {
        if !members.contains(package.id.as_str()) {
            continue;
        }
        let dir = canonical(package.manifest_path.parent().expect("manifest dir"));
        let roots = package
            .targets
            .iter()
            .map(|target| {
                let class = if target.kind.iter().any(|kind| kind == "custom-build") {
                    Class::BuildScript
                } else if target
                    .kind
                    .iter()
                    .all(|kind| matches!(kind.as_str(), "test" | "bench" | "example"))
                {
                    Class::Test
                } else {
                    Class::Production
                };
                (canonical(&target.src_path), class)
            })
            .collect();
        packages.push(Package {
            name: package.name,
            dir,
            dependencies: package.dependencies,
            roots,
        });
    }
    packages.sort_by(|a, b| a.name.cmp(&b.name));
    Workspace {
        root: canonical(&metadata.workspace_root),
        packages,
        files: BTreeMap::new(),
    }
}

fn canonical(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

struct Job {
    path: PathBuf,
    production: bool,
    build_script: bool,
    /// Children of a root, `mod.rs` or `#[path]` file live in its own directory.
    mod_rs: bool,
    module: Vec<String>,
    include: bool,
}

impl Workspace {
    /// Walk every target of every member. `test_only` members are test code in full.
    pub fn walk(&mut self, test_only: &BTreeSet<String>) {
        let mut queue = Vec::new();
        for package in &self.packages {
            let whole_test = test_only.contains(&package.name);
            for (root, class) in &package.roots {
                queue.push(Job {
                    path: root.clone(),
                    production: !whole_test && *class != Class::Test,
                    build_script: *class == Class::BuildScript,
                    mod_rs: true,
                    module: Vec::new(),
                    include: false,
                });
            }
        }
        // A file is processed again only when it is first reached as production.
        let mut seen: BTreeMap<PathBuf, bool> = BTreeMap::new();
        while let Some(job) = queue.pop() {
            let path = canonical(&job.path);
            if !path.starts_with(&self.root) {
                continue;
            }
            match seen.get(&path) {
                Some(true) => continue,
                Some(false) if !job.production => continue,
                _ => {}
            }
            seen.insert(path.clone(), job.production);
            let Ok(source) = std::fs::read_to_string(&path) else {
                continue;
            };
            let file = Parsed::new(&source);
            // A file-level test-only `#![cfg]` gates the file like the same cfg on its `mod` line.
            let production = job.production && !file.whole_file_test;
            let entry = self.files.entry(path.clone()).or_insert(Reached {
                production: false,
                build_script: false,
                module: job.module.clone(),
                lines: 0,
                generated: Vec::new(),
            });
            if production && !entry.production {
                entry.module.clone_from(&job.module);
            }
            entry.production |= production;
            entry.build_script |= job.build_script;
            let dir = path.parent().expect("file dir").to_path_buf();
            let child_dir = if job.mod_rs {
                dir.clone()
            } else {
                dir.join(path.file_stem().expect("file stem"))
            };
            if production {
                let generated = file
                    .includes()
                    .into_iter()
                    .filter(|include| include.literal.is_none() && !file.excluded(include.line))
                    .map(|include| include.line)
                    .collect();
                let lines = file.count(job.build_script);
                if let Some(reached) = self.files.get_mut(&path) {
                    reached.lines = lines;
                    reached.generated = generated;
                }
            }
            if !job.include {
                if let Some(syntax) = &file.syntax {
                    let context = ModContext {
                        file_dir: &dir,
                        child_dir: child_dir.clone(),
                        inline: false,
                        module: job.module.clone(),
                    };
                    walk_items(&syntax.items, &context, !production, &mut |found| {
                        queue.push(Job {
                            path: found.path,
                            production: production && !found.test,
                            build_script: job.build_script,
                            mod_rs: found.mod_rs,
                            module: found.module,
                            include: false,
                        });
                    });
                }
            }
            for include in file.includes() {
                if let Some(target) = include.literal {
                    queue.push(Job {
                        path: dir.join(target),
                        production: production && !file.excluded(include.line),
                        build_script: job.build_script,
                        mod_rs: true,
                        module: job.module.clone(),
                        include: true,
                    });
                }
            }
        }
    }

    /// Production lines per file, and every non-literal production `include!`.
    pub fn count(&self) -> (BTreeMap<PathBuf, usize>, Vec<GeneratedSite>) {
        let mut lines = BTreeMap::new();
        let mut generated = Vec::new();
        for (path, reached) in self.files.iter().filter(|(_, reached)| reached.production) {
            lines.insert(path.clone(), reached.lines);
            generated.extend(reached.generated.iter().map(|line| GeneratedSite {
                file: path.clone(),
                line: *line,
            }));
        }
        (lines, generated)
    }

    /// `.rs` files under a member's `src/` that no target reaches.
    pub fn unreachable(&self) -> Vec<PathBuf> {
        let mut out = Vec::new();
        for package in &self.packages {
            let mut stack = vec![package.dir.join("src")];
            while let Some(dir) = stack.pop() {
                let Ok(entries) = std::fs::read_dir(&dir) else {
                    continue;
                };
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_dir() {
                        stack.push(path);
                    } else if path.extension().is_some_and(|ext| ext == "rs")
                        && !self.files.contains_key(&canonical(&path))
                    {
                        out.push(path);
                    }
                }
            }
        }
        out.sort();
        out
    }

    pub fn relative(&self, path: &Path) -> String {
        path.strip_prefix(&self.root)
            .unwrap_or(path)
            .to_string_lossy()
            .into_owned()
    }
}

struct ModContext<'a> {
    file_dir: &'a Path,
    child_dir: PathBuf,
    inline: bool,
    module: Vec<String>,
}

struct FoundMod {
    path: PathBuf,
    test: bool,
    mod_rs: bool,
    module: Vec<String>,
}

fn walk_items(
    items: &[Item],
    context: &ModContext<'_>,
    test: bool,
    found: &mut dyn FnMut(FoundMod),
) {
    for item in items {
        match item {
            Item::Mod(module) => {
                let test = test || needs_test(&module.attrs);
                let name = module.ident.unraw().to_string();
                let path_attr = path_attribute(&module.attrs);
                let mut child_module = context.module.clone();
                child_module.push(name.clone());
                if let Some((_, inner)) = &module.content {
                    let child_dir = context
                        .child_dir
                        .join(path_attr.as_deref().unwrap_or(&name));
                    let inner_context = ModContext {
                        file_dir: context.file_dir,
                        child_dir,
                        inline: true,
                        module: child_module,
                    };
                    walk_items(inner, &inner_context, test, found);
                } else {
                    found(resolve_mod(context, &name, path_attr, test, child_module));
                }
            }
            Item::Macro(mac) => {
                // `mod x;` written inside an item macro (cfg_if!-style) still declares a file.
                for name in macro_mods(mac.mac.tokens.clone()) {
                    let mut child_module = context.module.clone();
                    child_module.push(name.clone());
                    found(resolve_mod(context, &name, None, test, child_module));
                }
            }
            _ => {}
        }
    }
}

fn resolve_mod(
    context: &ModContext<'_>,
    name: &str,
    path_attr: Option<String>,
    test: bool,
    module: Vec<String>,
) -> FoundMod {
    match path_attr {
        Some(relative) => {
            let base = if context.inline {
                &context.child_dir
            } else {
                context.file_dir
            };
            FoundMod {
                path: base.join(relative),
                test,
                mod_rs: true,
                module,
            }
        }
        None => {
            let flat = context.child_dir.join(format!("{name}.rs"));
            let (path, mod_rs) = if flat.is_file() {
                (flat, false)
            } else {
                (context.child_dir.join(name).join("mod.rs"), true)
            };
            FoundMod {
                path,
                test,
                mod_rs,
                module,
            }
        }
    }
}

fn macro_mods(tokens: TokenStream) -> Vec<String> {
    let trees: Vec<TokenTree> = tokens.into_iter().collect();
    let mut out = Vec::new();
    for (index, tree) in trees.iter().enumerate() {
        match tree {
            TokenTree::Ident(ident) if ident == "mod" => {
                if let (Some(TokenTree::Ident(name)), Some(TokenTree::Punct(semi))) =
                    (trees.get(index + 1), trees.get(index + 2))
                {
                    if semi.as_char() == ';' {
                        out.push(name.to_string());
                    }
                }
            }
            TokenTree::Group(group) => out.extend(macro_mods(group.stream())),
            _ => {}
        }
    }
    out
}

fn path_attribute(attrs: &[Attribute]) -> Option<String> {
    attrs.iter().find_map(|attr| match &attr.meta {
        Meta::NameValue(pair) if pair.path.is_ident("path") => match &pair.value {
            Expr::Lit(lit) => match &lit.lit {
                syn::Lit::Str(text) => Some(text.value()),
                _ => None,
            },
            _ => None,
        },
        _ => None,
    })
}

/// True when the attributes compile their item only in a test build: no build with `test` off
/// and the dev-dependency-only `test-support` feature off compiles it, whatever every other cfg
/// is. Every `cfg` and every `cfg` inside a (nested) `cfg_attr` gates the item; a gate the
/// parser cannot read is left out, so it can only make the item count as production.
fn needs_test(attrs: &[Attribute]) -> bool {
    let mut gates = Vec::new();
    for attr in attrs {
        if attr.path().is_ident("cfg") || attr.path().is_ident("cfg_attr") {
            // An unreadable attribute only drops a gate, which errs towards production.
            if let Some(found) = gates_of(&attr.meta) {
                gates.extend(found);
            }
        }
    }
    !gates.is_empty() && test_only(&Cfg::All(gates))
}

/// A cfg predicate, with `test` and `feature = "test-support"` folded to `Off`.
enum Cfg {
    All(Vec<Cfg>),
    Any(Vec<Cfg>),
    Not(Box<Cfg>),
    /// Off in every production build.
    Off,
    /// Any other cfg, which a production build may set either way.
    Free(String),
}

impl Cfg {
    fn parse(meta: &Meta) -> Option<Cfg> {
        match meta {
            Meta::Path(path) if path.is_ident("test") => Some(Cfg::Off),
            Meta::Path(path) => Some(Cfg::Free(path_name(path))),
            Meta::NameValue(pair) => {
                let Expr::Lit(lit) = &pair.value else {
                    return None;
                };
                let syn::Lit::Str(value) = &lit.lit else {
                    return None;
                };
                let value = value.value();
                Some(
                    if pair.path.is_ident("feature") && value == "test-support" {
                        Cfg::Off
                    } else {
                        Cfg::Free(format!("{} = {value:?}", path_name(&pair.path)))
                    },
                )
            }
            Meta::List(list) => {
                let inner = list
                    .parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)
                    .ok()?;
                let mut parts = inner.iter().map(Cfg::parse).collect::<Option<Vec<_>>>()?;
                if list.path.is_ident("all") {
                    Some(Cfg::All(parts))
                } else if list.path.is_ident("any") {
                    Some(Cfg::Any(parts))
                } else if list.path.is_ident("not") && parts.len() == 1 {
                    Some(Cfg::Not(Box::new(parts.pop()?)))
                } else {
                    None
                }
            }
        }
    }

    fn free<'a>(&'a self, out: &mut BTreeSet<&'a str>) {
        match self {
            Cfg::All(parts) | Cfg::Any(parts) => parts.iter().for_each(|part| part.free(out)),
            Cfg::Not(inner) => inner.free(out),
            Cfg::Off => {}
            Cfg::Free(name) => {
                out.insert(name.as_str());
            }
        }
    }

    fn holds(&self, on: &dyn Fn(&str) -> bool) -> bool {
        match self {
            Cfg::All(parts) => parts.iter().all(|part| part.holds(on)),
            Cfg::Any(parts) => parts.iter().any(|part| part.holds(on)),
            Cfg::Not(inner) => !inner.holds(on),
            Cfg::Off => false,
            Cfg::Free(name) => on(name),
        }
    }
}

fn path_name(path: &syn::Path) -> String {
    path.segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect::<Vec<_>>()
        .join("::")
}

/// The gates one `cfg` or `cfg_attr` attribute puts on its item: `cfg(p)` gates on `p`;
/// `cfg_attr(p, cfg(q))` gates on `any(not(p), q)`, nested `cfg_attr` likewise. `None` when the
/// attribute cannot be read.
fn gates_of(meta: &Meta) -> Option<Vec<Cfg>> {
    let Meta::List(list) = meta else {
        return None;
    };
    let mut args = list
        .parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)
        .ok()?
        .into_iter();
    if list.path.is_ident("cfg") {
        let predicate = Cfg::parse(&args.next()?)?;
        return args.next().is_none().then_some(vec![predicate]);
    }
    let condition = args.next()?;
    let mut gates = Vec::new();
    for attr in args {
        if attr.path().is_ident("cfg") || attr.path().is_ident("cfg_attr") {
            for gate in gates_of(&attr)? {
                gates.push(Cfg::Any(vec![
                    Cfg::Not(Box::new(Cfg::parse(&condition)?)),
                    gate,
                ]));
            }
        }
    }
    Some(gates)
}

/// True when no production build satisfies `cfg`: it is false for every setting of its other
/// cfgs (exhaustive, so `any(test, feature = "x")` is production and `not(not(test))` is not).
fn test_only(cfg: &Cfg) -> bool {
    let mut free = BTreeSet::new();
    cfg.free(&mut free);
    let free: Vec<&str> = free.into_iter().collect();
    if free.len() > 16 {
        return false;
    }
    (0u32..1 << free.len()).all(|setting| {
        !cfg.holds(&|name| {
            free.iter()
                .position(|known| *known == name)
                .is_some_and(|bit| (setting >> bit) & 1 == 1)
        })
    })
}

struct Include {
    line: usize,
    literal: Option<String>,
}

/// A file lexed for counting, with its excluded line ranges.
pub struct Parsed {
    syntax: Option<syn::File>,
    tokens: Option<TokenStream>,
    excluded: Vec<(usize, usize)>,
    whole_file_test: bool,
}

impl Parsed {
    pub fn new(source: &str) -> Self {
        let source = lexable(source);
        let syntax = syn::parse_file(&source).ok();
        let tokens = source.parse::<TokenStream>().ok();
        let mut excluded = Vec::new();
        let mut whole_file_test = false;
        if let Some(file) = &syntax {
            whole_file_test = needs_test(&file.attrs);
            let mut finder = TestRanges(&mut excluded);
            finder.visit_file(file);
        }
        if let Some(stream) = &tokens {
            doc_ranges(stream.clone(), &mut excluded);
        }
        Self {
            syntax,
            tokens,
            excluded,
            whole_file_test,
        }
    }

    pub fn excluded(&self, line: usize) -> bool {
        self.excluded
            .iter()
            .any(|(start, end)| (*start..=*end).contains(&line))
    }

    /// `unsafe` keywords outside test and doc ranges: blocks, fns, impls, traits, attributes.
    pub(crate) fn unsafe_keywords(&self) -> usize {
        let mut lines = Vec::new();
        if let Some(stream) = &self.tokens {
            idents_named(stream.clone(), "unsafe", &mut lines);
        }
        lines
            .into_iter()
            .filter(|line| !self.excluded(*line))
            .count()
    }

    /// `allow`/`expect` attributes naming `dead_code` or an `unused*` lint, outside test ranges.
    pub fn dead_code_allows(&self) -> usize {
        let mut lines = Vec::new();
        if let Some(stream) = &self.tokens {
            lint_attributes(
                stream.clone(),
                &["allow", "expect"],
                &|lint| lint == "dead_code" || lint.starts_with("unused"),
                &mut lines,
            );
        }
        lines
            .into_iter()
            .filter(|line| !self.excluded(*line))
            .count()
    }

    /// True when the file carries the inner attribute `#![<level>(unsafe_code)]`.
    pub fn inner_lint(&self, level: &str) -> bool {
        self.syntax.as_ref().is_some_and(|file| {
            file.attrs.iter().any(|attr| {
                matches!(attr.style, syn::AttrStyle::Inner(_))
                    && attr.path().is_ident(level)
                    && attr
                        .parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)
                        .is_ok_and(|lints| {
                            lints.iter().any(|lint| lint.path().is_ident("unsafe_code"))
                        })
            })
        })
    }

    fn count(&self, build_script: bool) -> usize {
        let Some(stream) = &self.tokens else {
            return 0;
        };
        let mut lines = BTreeSet::new();
        mark_lines(stream.clone(), build_script, &mut lines);
        lines
            .into_iter()
            .filter(|line| !self.excluded(*line))
            .count()
    }

    fn includes(&self) -> Vec<Include> {
        let mut out = Vec::new();
        if let Some(stream) = &self.tokens {
            find_includes(stream.clone(), &mut out);
        }
        out
    }
}

fn idents_named(stream: TokenStream, name: &str, out: &mut Vec<usize>) {
    for tree in stream {
        match tree {
            TokenTree::Ident(ident) if ident == name => out.push(ident.span().start().line),
            TokenTree::Group(group) => idents_named(group.stream(), name, out),
            _ => {}
        }
    }
}

/// The line of every `#[level(.. lint ..)]` / `#![level(.. lint ..)]` attribute.
fn lint_attributes(
    stream: TokenStream,
    levels: &[&str],
    lint: &dyn Fn(&str) -> bool,
    out: &mut Vec<usize>,
) {
    let trees: Vec<TokenTree> = stream.into_iter().collect();
    for (index, tree) in trees.iter().enumerate() {
        match tree {
            TokenTree::Punct(pound) if pound.as_char() == '#' => {
                let mut next = index + 1;
                if matches!(trees.get(next), Some(TokenTree::Punct(bang)) if bang.as_char() == '!')
                {
                    next += 1;
                }
                let Some(TokenTree::Group(body)) = trees.get(next) else {
                    continue;
                };
                let inner: Vec<TokenTree> = body.stream().into_iter().collect();
                if let [TokenTree::Ident(level), TokenTree::Group(args), ..] = inner.as_slice() {
                    let named = args.stream().into_iter().any(|token| match &token {
                        TokenTree::Ident(ident) => lint(&ident.to_string()),
                        _ => false,
                    });
                    if levels.iter().any(|wanted| level == wanted) && named {
                        out.push(pound.span().start().line);
                    }
                }
            }
            TokenTree::Group(group) => lint_attributes(group.stream(), levels, lint, out),
            _ => {}
        }
    }
}

/// Blank a leading shebang line so the lexer accepts the file without moving line numbers.
fn lexable(source: &str) -> String {
    let source = source.strip_prefix('\u{feff}').unwrap_or(source);
    let shebang = source
        .strip_prefix("#!")
        .is_some_and(|rest| !rest.trim_start().starts_with('['));
    if !shebang {
        return source.to_string();
    }
    let end = source.find('\n').unwrap_or(source.len());
    let mut out = " ".repeat(end);
    out.push_str(&source[end..]);
    out
}

fn mark_lines(stream: TokenStream, build_script: bool, lines: &mut BTreeSet<usize>) {
    for tree in stream {
        match tree {
            TokenTree::Group(group) => {
                if group.delimiter() != Delimiter::None {
                    lines.insert(group.span_open().start().line);
                    lines.insert(group.span_close().end().line);
                }
                mark_lines(group.stream(), build_script, lines);
            }
            TokenTree::Literal(literal) => {
                let span = literal.span();
                let (start, end) = (span.start().line, span.end().line);
                if build_script {
                    lines.extend(start..=end);
                } else {
                    lines.insert(start);
                    lines.insert(end);
                }
            }
            other => {
                let span = other.span();
                lines.insert(span.start().line);
                lines.insert(span.end().line);
            }
        }
    }
}

/// `#[doc ...]` and `#![doc ...]`, which is also what `///` and `//!` lex to.
fn doc_ranges(stream: TokenStream, out: &mut Vec<(usize, usize)>) {
    let trees: Vec<TokenTree> = stream.into_iter().collect();
    let mut index = 0;
    while index < trees.len() {
        if let TokenTree::Punct(pound) = &trees[index] {
            if pound.as_char() == '#' {
                let mut next = index + 1;
                if let Some(TokenTree::Punct(bang)) = trees.get(next) {
                    if bang.as_char() == '!' && bang.spacing() == Spacing::Alone {
                        next += 1;
                    }
                }
                if let Some(TokenTree::Group(group)) = trees.get(next) {
                    if group.delimiter() == Delimiter::Bracket {
                        // Only `doc = ..` (what `///` and `//!` lex to) is doc text: `#[doc(hidden)]` and
                        // the other `doc(..)` forms hide nothing on their line (UNSAFE-MIN A15).
                        let mut inner = group.stream().into_iter();
                        let first = inner.next();
                        let eq =
                            matches!(inner.next(), Some(TokenTree::Punct(p)) if p.as_char() == '=');
                        if eq && matches!(&first, Some(TokenTree::Ident(ident)) if ident == "doc") {
                            out.push((pound.span().start().line, group.span_close().end().line));
                            index = next + 1;
                            continue;
                        }
                    }
                }
            }
        }
        if let TokenTree::Group(group) = &trees[index] {
            doc_ranges(group.stream(), out);
        }
        index += 1;
    }
}

fn find_includes(stream: TokenStream, out: &mut Vec<Include>) {
    let trees: Vec<TokenTree> = stream.into_iter().collect();
    for (index, tree) in trees.iter().enumerate() {
        match tree {
            TokenTree::Ident(ident) if ident == "include" => {
                let bang =
                    matches!(trees.get(index + 1), Some(TokenTree::Punct(p)) if p.as_char() == '!');
                if let (true, Some(TokenTree::Group(args))) = (bang, trees.get(index + 2)) {
                    let inner: Vec<TokenTree> = args.stream().into_iter().collect();
                    let literal = match inner.as_slice() {
                        [TokenTree::Literal(literal)] => {
                            syn::parse_str::<syn::LitStr>(&literal.to_string())
                                .ok()
                                .map(|text| text.value())
                        }
                        _ => None,
                    };
                    out.push(Include {
                        line: ident.span().start().line,
                        literal,
                    });
                }
            }
            TokenTree::Group(group) => find_includes(group.stream(), out),
            _ => {}
        }
    }
}

/// Every syntax node carrying a test-only `cfg`, as an inclusive line range.
struct TestRanges<'a>(&'a mut Vec<(usize, usize)>);

impl TestRanges<'_> {
    fn gated(&mut self, attrs: &[Attribute], node: &dyn Spanned) -> bool {
        if needs_test(attrs) {
            let span = node.span();
            self.0.push((span.start().line, span.end().line));
            true
        } else {
            false
        }
    }
}

impl<'ast> Visit<'ast> for TestRanges<'_> {
    fn visit_item(&mut self, node: &'ast Item) {
        if !self.gated(item_attrs(node), node) {
            syn::visit::visit_item(self, node);
        }
    }
    fn visit_impl_item(&mut self, node: &'ast syn::ImplItem) {
        let attrs: &[Attribute] = match node {
            syn::ImplItem::Const(item) => &item.attrs,
            syn::ImplItem::Fn(item) => &item.attrs,
            syn::ImplItem::Type(item) => &item.attrs,
            syn::ImplItem::Macro(item) => &item.attrs,
            _ => &[],
        };
        if !self.gated(attrs, node) {
            syn::visit::visit_impl_item(self, node);
        }
    }
    fn visit_trait_item(&mut self, node: &'ast syn::TraitItem) {
        let attrs: &[Attribute] = match node {
            syn::TraitItem::Const(item) => &item.attrs,
            syn::TraitItem::Fn(item) => &item.attrs,
            syn::TraitItem::Type(item) => &item.attrs,
            syn::TraitItem::Macro(item) => &item.attrs,
            _ => &[],
        };
        if !self.gated(attrs, node) {
            syn::visit::visit_trait_item(self, node);
        }
    }
    fn visit_foreign_item(&mut self, node: &'ast syn::ForeignItem) {
        let attrs: &[Attribute] = match node {
            syn::ForeignItem::Fn(item) => &item.attrs,
            syn::ForeignItem::Static(item) => &item.attrs,
            syn::ForeignItem::Type(item) => &item.attrs,
            syn::ForeignItem::Macro(item) => &item.attrs,
            _ => &[],
        };
        if !self.gated(attrs, node) {
            syn::visit::visit_foreign_item(self, node);
        }
    }
    fn visit_local(&mut self, node: &'ast syn::Local) {
        if !self.gated(&node.attrs, node) {
            syn::visit::visit_local(self, node);
        }
    }
    fn visit_stmt_macro(&mut self, node: &'ast syn::StmtMacro) {
        if !self.gated(&node.attrs, node) {
            syn::visit::visit_stmt_macro(self, node);
        }
    }
    fn visit_expr(&mut self, node: &'ast Expr) {
        if !self.gated(expr_attrs(node), node) {
            syn::visit::visit_expr(self, node);
        }
    }
    fn visit_field(&mut self, node: &'ast syn::Field) {
        if !self.gated(&node.attrs, node) {
            syn::visit::visit_field(self, node);
        }
    }
    fn visit_variant(&mut self, node: &'ast syn::Variant) {
        if !self.gated(&node.attrs, node) {
            syn::visit::visit_variant(self, node);
        }
    }
    fn visit_arm(&mut self, node: &'ast syn::Arm) {
        if !self.gated(&node.attrs, node) {
            syn::visit::visit_arm(self, node);
        }
    }
    fn visit_field_value(&mut self, node: &'ast syn::FieldValue) {
        if !self.gated(&node.attrs, node) {
            syn::visit::visit_field_value(self, node);
        }
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

fn expr_attrs(expr: &Expr) -> &[Attribute] {
    match expr {
        Expr::Array(e) => &e.attrs,
        Expr::Assign(e) => &e.attrs,
        Expr::Async(e) => &e.attrs,
        Expr::Await(e) => &e.attrs,
        Expr::Binary(e) => &e.attrs,
        Expr::Block(e) => &e.attrs,
        Expr::Break(e) => &e.attrs,
        Expr::Call(e) => &e.attrs,
        Expr::Cast(e) => &e.attrs,
        Expr::Closure(e) => &e.attrs,
        Expr::Const(e) => &e.attrs,
        Expr::Continue(e) => &e.attrs,
        Expr::Field(e) => &e.attrs,
        Expr::ForLoop(e) => &e.attrs,
        Expr::Group(e) => &e.attrs,
        Expr::If(e) => &e.attrs,
        Expr::Index(e) => &e.attrs,
        Expr::Let(e) => &e.attrs,
        Expr::Lit(e) => &e.attrs,
        Expr::Loop(e) => &e.attrs,
        Expr::Macro(e) => &e.attrs,
        Expr::Match(e) => &e.attrs,
        Expr::MethodCall(e) => &e.attrs,
        Expr::Paren(e) => &e.attrs,
        Expr::Path(e) => &e.attrs,
        Expr::Range(e) => &e.attrs,
        Expr::Reference(e) => &e.attrs,
        Expr::Repeat(e) => &e.attrs,
        Expr::Return(e) => &e.attrs,
        Expr::Struct(e) => &e.attrs,
        Expr::Try(e) => &e.attrs,
        Expr::TryBlock(e) => &e.attrs,
        Expr::Tuple(e) => &e.attrs,
        Expr::Unary(e) => &e.attrs,
        Expr::Unsafe(e) => &e.attrs,
        Expr::While(e) => &e.attrs,
        Expr::Yield(e) => &e.attrs,
        _ => &[],
    }
}

/// The test-only predicate, pinned on a table: code compiled only under `cfg(test)` or the
/// dev-dependency-only `test-support` feature is test code, alone or in any combination that
/// requires one of them; anything a production build can compile is production.
#[test]
fn test_only_cfg_is_test_or_the_test_support_feature_exactly() {
    let table: &[(&str, bool)] = &[
        // Test-only: no production build compiles these.
        ("#[cfg(test)]", true),
        ("#[cfg(feature = \"test-support\")]", true),
        ("#[cfg(any(test, feature = \"test-support\"))]", true),
        ("#[cfg(all(test, feature = \"test-support\"))]", true),
        ("#[cfg(all(unix, test))]", true),
        (
            "#[cfg(all(feature = \"openapi-schema\", any(test, feature = \"test-support\")))]",
            true,
        ),
        ("#[cfg(not(not(feature = \"test-support\")))]", true),
        ("#[cfg(not(any(not(test), unix)))]", true),
        ("#[cfg(unix)] #[cfg(feature = \"test-support\")]", true),
        (
            "#[cfg_attr(not(test), cfg(feature = \"test-support\"))]",
            true,
        ),
        (
            "#[cfg_attr(not(test), cfg_attr(not(unix), cfg(test)), cfg(feature = \"test-support\"))]",
            true,
        ),
        ("#![cfg(any(test, feature = \"test-support\"))]", true),
        // Production: some production build compiles these.
        ("#[inline]", false),
        ("#[cfg(unix)]", false),
        ("#[cfg(not(test))]", false),
        ("#[cfg(not(feature = \"test-support\"))]", false),
        ("#[cfg(not(any(test, feature = \"test-support\")))]", false),
        ("#[cfg(any(test, feature = \"openapi-schema\"))]", false),
        (
            "#[cfg(any(test, feature = \"openapi-schema\", feature = \"test-support\"))]",
            false,
        ),
        ("#[cfg(any(test, not(feature = \"test-support\")))]", false),
        ("#[cfg(feature = \"test-seal\")]", false),
        ("#[cfg(feature = \"test-supports\")]", false),
        ("#[cfg(test_support)]", false),
        ("#[cfg_attr(test, inline)]", false),
        (
            "#[cfg_attr(feature = \"test-support\", inline)]",
            false,
        ),
        ("#[cfg_attr(unix, cfg(test))]", false),
        ("#[cfg_attr(unix, cfg_attr(windows, cfg(test)), cfg(test))]", false),
        ("#![cfg(unix)]", false),
    ];
    let mut wrong = Vec::new();
    for (attrs, test_only) in table {
        let file = syn::parse_file(&format!("{attrs}\nfn f() {{}}")).expect("table entry parses");
        let found = needs_test(&file.attrs)
            || file
                .items
                .first()
                .is_some_and(|item| needs_test(item_attrs(item)));
        if found != *test_only {
            wrong.push(format!(
                "  {attrs}: test-only {found}, expected {test_only}"
            ));
        }
    }
    assert!(
        wrong.is_empty(),
        "the test-only predicate is wrong for:\n{}",
        wrong.join("\n")
    );

    // The consumers see it: `unsafe` behind `test-support` is not production, `unsafe` behind a
    // cfg a production build can turn on is.
    let source = "#[cfg(feature = \"test-support\")]\nfn a() { unsafe {} }\n\
                  #[cfg(any(test, feature = \"other\"))]\nfn b() { unsafe {} }\n";
    assert_eq!(Parsed::new(source).unsafe_keywords(), 1);
}

// ---- escapes v2 (UNSAFE-MIN r3.1 §4.6): the token-level walk of every tracked `.rs` file ----

/// The escape tokens of one file, token-level: comments are not tokens, doc text is a literal, and
/// nothing else is skipped (no test range, no `#[doc(hidden)]` line, no `cfg`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EscapeCounts {
    /// `unsafe` keywords: blocks, fns, impls, traits, extern blocks, attributes, fn-pointer types.
    pub unsafe_tokens: usize,
    /// `no_mangle`, `export_name`, `link_section`, `global_asm`, `naked_asm`.
    pub linker: usize,
    /// `extern` blocks (`extern "C" { .. }`), wherever they stand.
    pub extern_blocks: usize,
    /// `allow`/`expect`/`warn` naming `unsafe_code`, in any form (`cfg_attr`, multi-lint lists).
    pub unsafe_code_allows: usize,
    /// `include!`/`include_str!`/`include_bytes!` of an `OUT_DIR` path.
    pub out_dir_includes: usize,
    /// 1 when the file is a `build.rs` that names a `.rs` output.
    pub build_writes_rs: usize,
    /// `unsafe` keywords inside fenced Rust code blocks of the file's doc text.
    pub doc_code_unsafe: usize,
}

impl EscapeCounts {
    /// E1's count, for a file outside busbar-ffi: every kind of escape.
    pub fn outside(&self) -> usize {
        self.unsafe_tokens
            + self.linker
            + self.extern_blocks
            + self.unsafe_code_allows
            + self.out_dir_includes
            + self.build_writes_rs
    }
    /// E3's count, for a file inside busbar-ffi: `unsafe` tokens (doc code included) and allows.
    pub fn ffi(&self) -> usize {
        self.unsafe_tokens + self.doc_code_unsafe + self.unsafe_code_allows
    }
}

/// The escape counts of `source` (tracked at `path`). Err: the file does not lex, which fails the check.
pub fn escape_counts(path: &str, source: &str) -> Result<EscapeCounts, String> {
    let stream: TokenStream = lexable(source).parse().map_err(|error| {
        format!("{path}: does not lex ({error}); every tracked .rs file is scanned")
    })?;
    let mut counts = EscapeCounts::default();
    count_escapes(stream.clone(), false, &mut counts);
    if path == "build.rs" || path.ends_with("/build.rs") {
        counts.build_writes_rs =
            usize::from(any_literal(stream.clone(), &|text| text.ends_with(".rs\"")));
    }
    let mut docs = Vec::new();
    doc_texts(stream, &mut docs);
    counts.doc_code_unsafe = doc_code_unsafe(&docs.join("\n"));
    Ok(counts)
}

fn count_escapes(stream: TokenStream, level_paren: bool, counts: &mut EscapeCounts) {
    let trees: Vec<TokenTree> = stream.into_iter().collect();
    for (index, tree) in trees.iter().enumerate() {
        match tree {
            TokenTree::Ident(ident) => match ident.to_string().as_str() {
                "unsafe" => counts.unsafe_tokens += 1,
                "no_mangle" | "export_name" | "link_section" | "global_asm" | "naked_asm" => {
                    counts.linker += 1
                }
                "extern" => {
                    let mut next = index + 1;
                    if matches!(trees.get(next), Some(TokenTree::Literal(_))) {
                        next += 1;
                    }
                    if matches!(trees.get(next), Some(TokenTree::Group(group)) if group.delimiter() == Delimiter::Brace)
                    {
                        counts.extern_blocks += 1;
                    }
                }
                "unsafe_code" if level_paren => counts.unsafe_code_allows += 1,
                "include" | "include_str" | "include_bytes" => {
                    let bang = matches!(trees.get(index + 1), Some(TokenTree::Punct(p)) if p.as_char() == '!');
                    if let (true, Some(TokenTree::Group(args))) = (bang, trees.get(index + 2)) {
                        if any_literal(args.stream(), &|text| text == "\"OUT_DIR\"") {
                            counts.out_dir_includes += 1;
                        }
                    }
                }
                _ => {}
            },
            TokenTree::Group(group) => {
                let after_level = group.delimiter() == Delimiter::Parenthesis
                    && index
                        .checked_sub(1)
                        .and_then(|before| trees.get(before))
                        .is_some_and(|before| {
                            matches!(before, TokenTree::Ident(level)
                            if matches!(level.to_string().as_str(), "allow" | "expect" | "warn"))
                        });
                count_escapes(group.stream(), after_level, counts);
            }
            _ => {}
        }
    }
}

fn any_literal(stream: TokenStream, matches: &dyn Fn(&str) -> bool) -> bool {
    stream.into_iter().any(|tree| match tree {
        TokenTree::Literal(literal) => matches(&literal.to_string()),
        TokenTree::Group(group) => any_literal(group.stream(), matches),
        _ => false,
    })
}

/// Every `doc = "..."` value (doc comments included), in source order.
fn doc_texts(stream: TokenStream, out: &mut Vec<String>) {
    let trees: Vec<TokenTree> = stream.into_iter().collect();
    for (index, tree) in trees.iter().enumerate() {
        if let TokenTree::Group(group) = tree {
            let attribute = group.delimiter() == Delimiter::Bracket
                && index.checked_sub(1).and_then(|before| trees.get(before)).is_some_and(|before| {
                    matches!(before, TokenTree::Punct(p) if p.as_char() == '#' || p.as_char() == '!')
                });
            let inner: Vec<TokenTree> = group.stream().into_iter().collect();
            if let (true, [TokenTree::Ident(doc), TokenTree::Punct(eq), TokenTree::Literal(text)]) =
                (attribute, inner.as_slice())
            {
                if doc == "doc" && eq.as_char() == '=' {
                    if let Ok(text) = syn::parse_str::<syn::LitStr>(&text.to_string()) {
                        out.push(text.value());
                    }
                    continue;
                }
            }
            doc_texts(group.stream(), out);
        }
    }
}

/// `unsafe` keywords in the fenced Rust code blocks of `docs` (A15): a fence whose info string is empty
/// or names Rust or a rustdoc attribute; `text`, `toml`, `yaml`, `json`, `sh`, `console`, `c` and the
/// like are prose.
fn doc_code_unsafe(docs: &str) -> usize {
    const PROSE: &[&str] = &[
        "text", "txt", "plain", "toml", "yaml", "yml", "json", "sh", "bash", "shell", "console",
        "c", "md", "markdown", "diff",
    ];
    let mut total = 0;
    // The open fence, if any: whether it is Rust, and its lines so far.
    let mut open: Option<(bool, String)> = None;
    for line in docs.lines() {
        let trimmed = line.trim_start();
        if let Some(info) = trimmed.strip_prefix("```") {
            match open.take() {
                Some((true, block)) => total += unsafe_idents(&block),
                Some((false, _)) => {}
                None => {
                    let rust = !info
                        .split([',', ' '])
                        .any(|word| PROSE.contains(&word.trim()));
                    open = Some((rust, String::new()));
                }
            }
            continue;
        }
        if let Some((true, block)) = open.as_mut() {
            block.push_str(trimmed.strip_prefix("# ").unwrap_or(trimmed));
            block.push('\n');
        }
    }
    if let Some((true, block)) = open {
        total += unsafe_idents(&block);
    }
    total
}

fn unsafe_idents(code: &str) -> usize {
    match code.parse::<TokenStream>() {
        Ok(stream) => {
            let mut lines = Vec::new();
            idents_named(stream, "unsafe", &mut lines);
            lines.len()
        }
        // Doc code that does not lex still counts, word by word.
        Err(_) => code
            .split(|c: char| !(c.is_alphanumeric() || c == '_'))
            .filter(|word| *word == "unsafe")
            .count(),
    }
}

/// True when the file carries `#![doc(test(attr(forbid(unsafe_code))))]` (E2).
pub fn forbids_unsafe_in_doctests(source: &str) -> bool {
    let Ok(file) = syn::parse_file(&lexable(source)) else {
        return false;
    };
    file.attrs.iter().any(|attr| {
        matches!(attr.style, syn::AttrStyle::Inner(_))
            && matches!(&attr.meta, Meta::List(list)
                if list.path.is_ident("doc")
                    && list.tokens.to_string().split_whitespace().collect::<String>()
                        == "test(attr(forbid(unsafe_code)))")
    })
}

/// E4/E5 findings in one busbar-ffi file: its exported macros (by name), and every `unsafe` token in a
/// `macro_rules!` body other than `export!`'s `#[unsafe(no_mangle)]`, and every `$`-metavariable (other
/// than `$crate`) inside an `unsafe` construct or attribute.
pub fn ffi_macro_findings(source: &str) -> (Vec<String>, Vec<String>) {
    let mut exported = Vec::new();
    let mut findings = Vec::new();
    if let Ok(stream) = lexable(source).parse::<TokenStream>() {
        macro_walk(stream, &mut exported, &mut findings);
    }
    (exported, findings)
}

fn macro_walk(stream: TokenStream, exported: &mut Vec<String>, findings: &mut Vec<String>) {
    let trees: Vec<TokenTree> = stream.into_iter().collect();
    for (index, tree) in trees.iter().enumerate() {
        match tree {
            TokenTree::Ident(ident) if ident == "macro_rules" => {
                let (
                    Some(TokenTree::Punct(bang)),
                    Some(TokenTree::Ident(name)),
                    Some(TokenTree::Group(body)),
                ) = (
                    trees.get(index + 1),
                    trees.get(index + 2),
                    trees.get(index + 3),
                )
                else {
                    continue;
                };
                if bang.as_char() != '!' {
                    continue;
                }
                let name = name.to_string();
                let is_exported = index >= 2
                    && matches!(&trees[index - 1], TokenTree::Group(attr)
                        if attr.delimiter() == Delimiter::Bracket
                            && attr.stream().into_iter().next().is_some_and(|first| first.to_string() == "macro_export"));
                if is_exported {
                    exported.push(name.clone());
                }
                let mut allowed = usize::from(name == "export");
                body_walk(body.stream(), &name, false, &mut allowed, findings);
            }
            TokenTree::Group(group) => macro_walk(group.stream(), exported, findings),
            _ => {}
        }
    }
}

/// `allowed`: how many `#[unsafe(no_mangle)]` this body may still hold.
fn body_walk(
    stream: TokenStream,
    name: &str,
    in_unsafe: bool,
    allowed: &mut usize,
    findings: &mut Vec<String>,
) {
    let trees: Vec<TokenTree> = stream.into_iter().collect();
    for (index, tree) in trees.iter().enumerate() {
        match tree {
            TokenTree::Ident(ident) if ident == "unsafe" => {
                let export_attribute = index == 0
                    && matches!(trees.get(1), Some(TokenTree::Group(g))
                        if g.delimiter() == Delimiter::Parenthesis && g.stream().to_string() == "no_mangle")
                    && trees.len() == 2;
                if export_attribute && *allowed > 0 {
                    *allowed -= 1;
                } else {
                    findings.push(format!(
                        "an `unsafe` token in the body of macro_rules! {name} (S2, E4)"
                    ));
                }
            }
            TokenTree::Punct(dollar) if dollar.as_char() == '$' && in_unsafe => {
                if !matches!(trees.get(index + 1), Some(TokenTree::Ident(next)) if next == "crate")
                {
                    findings.push(format!(
                        "a `$` metavariable inside an `unsafe` construct or attribute of macro_rules! {name} (E5)"
                    ));
                }
            }
            TokenTree::Group(group) => {
                let after_unsafe = index
                    .checked_sub(1)
                    .and_then(|before| trees.get(before))
                    .is_some_and(|before| matches!(before, TokenTree::Ident(i) if i == "unsafe"));
                let unsafe_attribute = group.delimiter() == Delimiter::Bracket
                    && group
                        .stream()
                        .into_iter()
                        .any(|t| matches!(&t, TokenTree::Ident(i) if i == "unsafe"));
                body_walk(
                    group.stream(),
                    name,
                    in_unsafe || after_unsafe || unsafe_attribute,
                    allowed,
                    findings,
                );
            }
            _ => {}
        }
    }
}

/// E6: the lines of `unsafe` blocks and impls with no `// SAFETY:` comment right above them.
pub fn unsafe_without_safety(source: &str) -> Vec<usize> {
    let lines: Vec<&str> = source.lines().collect();
    let mut sites = Vec::new();
    if let Ok(stream) = lexable(source).parse::<TokenStream>() {
        safety_sites(stream, &mut sites);
    }
    sites
        .into_iter()
        .filter(|line| {
            let mut at = *line;
            while at > 1 {
                at -= 1;
                let text = lines.get(at - 1).map_or("", |text| text.trim());
                if !text.starts_with("//") {
                    return true;
                }
                if text.contains("SAFETY:") {
                    return false;
                }
            }
            true
        })
        .collect()
}

fn safety_sites(stream: TokenStream, out: &mut Vec<usize>) {
    let trees: Vec<TokenTree> = stream.into_iter().collect();
    for (index, tree) in trees.iter().enumerate() {
        match tree {
            TokenTree::Ident(ident) if ident == "unsafe" => {
                let block = matches!(trees.get(index + 1), Some(TokenTree::Group(g)) if g.delimiter() == Delimiter::Brace);
                let implementation =
                    matches!(trees.get(index + 1), Some(TokenTree::Ident(next)) if next == "impl");
                if block || implementation {
                    out.push(ident.span().start().line);
                }
            }
            TokenTree::Group(group) => safety_sites(group.stream(), out),
            _ => {}
        }
    }
}

/// Lints busbar-ffi's root denies that no file below may lower (E10), each named as in source.
pub const FFI_ROOT_LINTS: [&str; 4] = [
    "unsafe_code",
    "unsafe_op_in_unsafe_fn",
    "clippy::undocumented_unsafe_blocks",
    "clippy::multiple_unsafe_ops_per_block",
];

/// The inner `#![deny(..)]`/`#![forbid(..)]` lints of a root, as written (`clippy::x` joined).
pub fn inner_denies(source: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let Ok(file) = syn::parse_file(&lexable(source)) else {
        return out;
    };
    for attr in &file.attrs {
        let inner = matches!(attr.style, syn::AttrStyle::Inner(_));
        if !(inner && (attr.path().is_ident("deny") || attr.path().is_ident("forbid"))) {
            continue;
        }
        if let Ok(lints) = attr.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated) {
            for lint in lints {
                out.insert(path_name(lint.path()));
            }
        }
    }
    out
}

/// Any `allow`/`expect`/`warn` of one of `lints` (written `x` or `clippy::x`) in the file.
pub fn lowers_any(source: &str, lints: &[&str]) -> bool {
    let Ok(stream) = lexable(source).parse::<TokenStream>() else {
        return false;
    };
    let names: BTreeSet<&str> = lints
        .iter()
        .map(|lint| lint.rsplit("::").next().unwrap_or(lint))
        .collect();
    let mut found = false;
    lowers_walk(stream, false, &names, &mut found);
    found
}

fn lowers_walk(stream: TokenStream, level_paren: bool, names: &BTreeSet<&str>, found: &mut bool) {
    let trees: Vec<TokenTree> = stream.into_iter().collect();
    for (index, tree) in trees.iter().enumerate() {
        match tree {
            TokenTree::Ident(ident)
                if level_paren && names.contains(ident.to_string().as_str()) =>
            {
                *found = true
            }
            TokenTree::Group(group) => {
                let after_level = group.delimiter() == Delimiter::Parenthesis
                    && index
                        .checked_sub(1)
                        .and_then(|before| trees.get(before))
                        .is_some_and(|before| {
                            matches!(before, TokenTree::Ident(level)
                            if matches!(level.to_string().as_str(), "allow" | "expect" | "warn"))
                        });
                lowers_walk(group.stream(), after_level, names, found);
            }
            _ => {}
        }
    }
}

/// Every tracked path matching `pattern` (`git ls-files -z`), or None when git fails.
pub fn tracked(root: &Path, pattern: &str) -> Option<Vec<String>> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["ls-files", "-z", "--", pattern])
        .output()
        .ok()?;
    output.status.success().then(|| {
        String::from_utf8_lossy(&output.stdout)
            .split('\0')
            .filter(|path| !path.is_empty())
            .map(str::to_string)
            .collect()
    })
}
