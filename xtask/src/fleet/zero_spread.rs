//! THE ZERO-SPREAD GATE (`cargo xtask plugin-gates zero-spread <busbar-root> <plugin dir>`): a
//! plugin builds every contract struct that states an empty declaration (`pub const ZERO: Self`)
//! with a functional-update base, `T { a, b, ..T::ZERO }`, so a field the contract appends to `T`
//! later keeps the plugin compiling and reads as not declared. A literal naming every field breaks
//! the day a field is appended, and a plugin pinned to the older contract can then neither build
//! against the newer one nor reach it: the lockstep this gate exists to end.
//!
//! WHAT IS JUDGED. Every `T { … }` struct expression in a plugin crate's non-test code (the module
//! tree from `src/lib.rs`, `src/main.rs` and `src/bin/*.rs`; a `#[cfg(test)]` module or item and a
//! `#[test]` fn are skipped, and so is a module only a `#[cfg(test)]` declaration reaches) whose
//! `T` is a contract struct with a `ZERO`. Expressions inside a macro invocation are not seen.
//!
//! ONLY A LITERAL THE BASE CAN SHORTEN. A base-less literal names every field, and a base beside
//! every field is `clippy::needless_update`. So a literal is judged when at least one field it
//! names is written as a zero (`0`, `false`, `None`, `[0; N]`, a NULL pointer, a `…::ZERO`): the
//! fix drops those fields and spreads `..T::ZERO`, and the result is lint-clean. A literal whose
//! every field carries a value (a pointer-and-length pair) is not judged.
//!
//! THE BASE. A literal that spreads a base is judged by it: `..T::ZERO` (or any path ending in
//! `ZERO`), `..T::default()` / `..Default::default()`, or a call to one of the contract's own
//! builders in [`ZERO_HELPERS`] (each of which spreads `ZERO` itself, held by a test) is a base an
//! appended field reads as zero from. Any other base is a finding.
//!
//! TYPE IDENTITY. The gate reads source, not types, so a literal's type is resolved as far as the
//! file says: a path through `busbar_contract`, or a name a `use` brings from it, is the contract's;
//! a name a `use` brings from anywhere else, a path through `crate`/`self`/`super` or a local
//! module, and a name the plugin crate defines itself are not. A bare name no `use` resolves (a
//! glob import) is taken as the contract's. Where the contract holds two structs of one name, the
//! literal's own field names pick the candidates (every struct of that name whose fields include
//! all of the literal's); the literal is judged only when every candidate states a `ZERO`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use syn::visit::Visit;

type Res<T> = Result<T, String>;

/// Where the contract's source sits under a busbar checkout.
pub const CONTRACT_SRC: &str = "crates/busbar-contract/src";

/// The contract's own builders a plugin may spread as a base (`..statement(…)`): each one's body
/// spreads `ZERO`, a parameter it forwards, or another builder here (held by a test).
pub const ZERO_HELPERS: &[&str] = &[
    "statement",
    "statement_with_tail",
    "with_tail",
    "verify_tail",
    "outbound_tail",
    "with_operator",
    "with_credential_kinds",
    "with_inbound",
];

/// THE FIXED EXEMPTIONS: plugin-built contract structs that state NO `ZERO`, as `(file under the
/// contract's src, type, reason)`. A test holds each to its file and to having no `ZERO`.
pub const EXEMPT: &[(&str, &str, &str)] = &[
    (
        "abi/mechanism/observe.rs",
        "Envelope",
        "generic R has no ZERO; the envelope carries no grant field",
    ),
    (
        "abi/export/mod.rs",
        "Route",
        "auth 0 is the unauthenticated level: renumbered in step 2",
    ),
    (
        "abi/hook/mod.rs",
        "Route",
        "auth 0 is the unauthenticated level: renumbered in step 2",
    ),
    (
        "abi/hook/mod.rs",
        "Tail",
        "kind_class 0 is a gate: renumbered in step 2",
    ),
    (
        "abi/sdk/store/mod.rs",
        "Tail",
        "ephemeral false claims a durable store: renumbered in step 2",
    ),
    (
        "abi/mechanism/route.rs",
        "Route",
        "RouteAuth has no zero and its None is unauthenticated: renumbered in step 2",
    ),
];

/// One contract struct: its named fields, and whether it states a `ZERO`.
#[derive(Debug, Clone)]
struct Def {
    fields: BTreeSet<String>,
    zero: bool,
}

/// Every named-field struct the contract defines, by name.
#[derive(Debug, Default)]
pub struct ZeroIndex {
    defs: BTreeMap<String, Vec<Def>>,
    /// Each [`ZERO_HELPERS`] builder found, and whether its body spreads an accepted base.
    helpers: BTreeMap<String, bool>,
}

impl ZeroIndex {
    /// The names whose every struct states a `ZERO`: what a literal of that name must spread.
    #[must_use]
    pub fn zero_names(&self) -> Vec<&str> {
        self.defs
            .iter()
            .filter(|(_, d)| d.iter().all(|d| d.zero))
            .map(|(n, _)| n.as_str())
            .collect()
    }

    /// Each [`ZERO_HELPERS`] builder the contract defines, and whether its own body spreads
    /// `ZERO`, a parameter or another listed builder.
    #[must_use]
    pub fn helpers(&self) -> &BTreeMap<String, bool> {
        &self.helpers
    }

    /// Whether a literal `name { fields }` is one of a ZERO-bearing contract struct.
    fn judged(&self, name: &str, fields: &BTreeSet<String>) -> bool {
        let Some(defs) = self.defs.get(name) else {
            return false;
        };
        let cands: Vec<&Def> = defs
            .iter()
            .filter(|d| fields.is_subset(&d.fields))
            .collect();
        !cands.is_empty() && cands.iter().all(|d| d.zero)
    }
}

fn parse(path: &Path, text: &str) -> Res<syn::File> {
    syn::parse_file(text).map_err(|e| {
        format!(
            "{}:{}: not parseable Rust: {e}",
            path.display(),
            e.span().start().line
        )
    })
}

fn self_name(ty: &syn::Type) -> Option<String> {
    match ty {
        syn::Type::Path(p) if p.qself.is_none() => {
            p.path.segments.last().map(|s| s.ident.to_string())
        }
        _ => None,
    }
}

/// One module scope's structs into the index: a struct states a `ZERO` when an inherent impl in
/// the same scope does (an inline module is its own scope).
fn index_items(items: &[syn::Item], idx: &mut ZeroIndex) {
    let (mut structs, mut zeros) = (Vec::new(), BTreeSet::new());
    for item in items {
        match item {
            syn::Item::Struct(s) if !test_only(&s.attrs) => {
                if let syn::Fields::Named(f) = &s.fields {
                    let fields: BTreeSet<String> = f
                        .named
                        .iter()
                        .filter_map(|f| f.ident.as_ref().map(ToString::to_string))
                        .collect();
                    structs.push((s.ident.to_string(), fields));
                }
            }
            syn::Item::Impl(i) if i.trait_.is_none() => {
                let has_zero = i
                    .items
                    .iter()
                    .any(|it| matches!(it, syn::ImplItem::Const(c) if c.ident == "ZERO"));
                if let (true, Some(n)) = (has_zero, self_name(&i.self_ty)) {
                    zeros.insert(n);
                }
            }
            syn::Item::Mod(m) if !test_only(&m.attrs) => {
                if let Some((_, inner)) = &m.content {
                    index_items(inner, idx);
                }
            }
            syn::Item::Fn(f)
                if !test_only(&f.attrs)
                    && ZERO_HELPERS.contains(&f.sig.ident.to_string().as_str()) =>
            {
                idx.helpers
                    .insert(f.sig.ident.to_string(), helper_spreads(f));
            }
            _ => {}
        }
    }
    for (name, fields) in structs {
        let zero = zeros.contains(&name);
        idx.defs.entry(name).or_default().push(Def { fields, zero });
    }
}

/// THE INDEX, read off the contract's non-test module tree (from `lib.rs`): every named-field
/// struct, and which of them carry a `ZERO` in an inherent impl in their own module scope.
///
/// # Errors
/// A module file that cannot be read or parsed.
pub fn index(contract_src: &Path) -> Res<ZeroIndex> {
    let mut idx = ZeroIndex::default();
    for (_, parsed) in modules(&contract_src.join("lib.rs"))? {
        index_items(&parsed.items, &mut idx);
    }
    Ok(idx)
}

/// Whether a builder's body spreads an accepted base: `ZERO`, one of its own parameters, or a
/// call to another [`ZERO_HELPERS`] builder.
fn helper_spreads(f: &syn::ItemFn) -> bool {
    struct Bases<'a> {
        params: &'a BTreeSet<String>,
        ok: bool,
    }
    impl<'ast> Visit<'ast> for Bases<'_> {
        fn visit_expr_struct(&mut self, e: &'ast syn::ExprStruct) {
            if let Some(b) = &e.rest {
                let param = matches!(&**b, syn::Expr::Path(p)
                    if p.path.get_ident().is_some_and(|i| self.params.contains(&i.to_string())));
                if param || base_ok(b) {
                    self.ok = true;
                }
            }
            syn::visit::visit_expr_struct(self, e);
        }
    }
    let params: BTreeSet<String> = f
        .sig
        .inputs
        .iter()
        .filter_map(|a| match a {
            syn::FnArg::Typed(t) => match &*t.pat {
                syn::Pat::Ident(i) => Some(i.ident.to_string()),
                _ => None,
            },
            syn::FnArg::Receiver(_) => None,
        })
        .collect();
    let mut v = Bases {
        params: &params,
        ok: false,
    };
    v.visit_block(&f.block);
    v.ok
}

/// Whether a base reads an appended field as zero: a path ending in `ZERO`, a `default()` call,
/// or a call to a [`ZERO_HELPERS`] builder.
fn base_ok(b: &syn::Expr) -> bool {
    match b {
        syn::Expr::Path(p) => p.path.segments.last().is_some_and(|s| s.ident == "ZERO"),
        syn::Expr::Call(c) => match &*c.func {
            syn::Expr::Path(p) => p.path.segments.last().is_some_and(|s| {
                s.ident == "default" || ZERO_HELPERS.contains(&s.ident.to_string().as_str())
            }),
            _ => false,
        },
        syn::Expr::Paren(p) => base_ok(&p.expr),
        syn::Expr::Group(g) => base_ok(&g.expr),
        _ => false,
    }
}

/// Every name a file's `use` items bring in, mapped to the path it names (`use a::b::{self, C as
/// D}` maps `b` to `a::b` and `D` to `a::b::C`). Globs bring no name.
fn use_map(items: &[syn::Item]) -> BTreeMap<String, String> {
    fn walk(t: &syn::UseTree, prefix: &mut Vec<String>, out: &mut BTreeMap<String, String>) {
        match t {
            syn::UseTree::Path(p) => {
                prefix.push(p.ident.to_string());
                walk(&p.tree, prefix, out);
                prefix.pop();
            }
            syn::UseTree::Name(n) => {
                let name = n.ident.to_string();
                if name == "self" {
                    if let Some(last) = prefix.last() {
                        out.insert(last.clone(), prefix.join("::"));
                    }
                } else {
                    out.insert(name.clone(), [prefix.join("::"), name].join("::"));
                }
            }
            syn::UseTree::Rename(r) => {
                out.insert(
                    r.rename.to_string(),
                    [prefix.join("::"), r.ident.to_string()].join("::"),
                );
            }
            syn::UseTree::Glob(_) => {}
            syn::UseTree::Group(g) => {
                for t in &g.items {
                    walk(t, prefix, out);
                }
            }
        }
    }
    let mut out = BTreeMap::new();
    for item in items {
        if let syn::Item::Use(u) = item {
            if !test_only(&u.attrs) {
                walk(&u.tree, &mut Vec::new(), &mut out);
            }
        }
    }
    out
}

/// Every type name a parsed file defines (struct, enum, union, alias), at any inline depth.
fn local_types(items: &[syn::Item], out: &mut BTreeSet<String>) {
    for item in items {
        match item {
            syn::Item::Struct(s) => {
                out.insert(s.ident.to_string());
            }
            syn::Item::Enum(e) => {
                out.insert(e.ident.to_string());
            }
            syn::Item::Union(u) => {
                out.insert(u.ident.to_string());
            }
            syn::Item::Type(t) => {
                out.insert(t.ident.to_string());
            }
            syn::Item::Mod(m) => {
                if let Some((_, inner)) = &m.content {
                    local_types(inner, out);
                }
            }
            _ => {}
        }
    }
}

/// Whether a literal's path may name a contract type, as far as the file resolves it.
fn contract_path(
    path: &syn::Path,
    uses: &BTreeMap<String, String>,
    locals: &BTreeSet<String>,
) -> bool {
    let Some(first) = path.segments.first().map(|s| s.ident.to_string()) else {
        return false;
    };
    if first == "busbar_contract" {
        return true;
    }
    if ["crate", "self", "super", "Self"].contains(&first.as_str()) {
        return false;
    }
    if let Some(full) = uses.get(&first) {
        return full == "busbar_contract" || full.starts_with("busbar_contract::");
    }
    path.segments.len() == 1 && !locals.contains(&first)
}

/// Whether an attribute list compiles its item only under test: `#[test]`, `#[cfg(test)]` or
/// `#[cfg(all(test, …))]`. `cfg(any(test, …))` and `cfg(not(test))` reach a shipped build.
fn test_only(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|a| {
        if a.path().is_ident("test") {
            return true;
        }
        if !a.path().is_ident("cfg") {
            return false;
        }
        let Ok(list) = a.meta.require_list() else {
            return false;
        };
        let t = list.tokens.to_string().replace(' ', "");
        t == "test"
            || (t.starts_with("all(")
                && !t.contains("not(")
                && t.split([',', '(', ')']).any(|w| w == "test"))
    })
}

/// Whether an expression is written as a zero: an integer `0`, `false`, `None`, a `null()` /
/// `null_mut()` call, an array of zeros, or a path ending in `ZERO`.
fn is_zero(e: &syn::Expr) -> bool {
    match e {
        syn::Expr::Lit(l) => match &l.lit {
            syn::Lit::Int(i) => i.base10_digits().chars().all(|c| c == '0'),
            syn::Lit::Bool(b) => !b.value,
            _ => false,
        },
        syn::Expr::Path(p) => p
            .path
            .segments
            .last()
            .is_some_and(|s| s.ident == "None" || s.ident == "ZERO"),
        syn::Expr::Call(c) => {
            c.args.is_empty()
                && matches!(&*c.func, syn::Expr::Path(p) if p.path.segments.last()
                    .is_some_and(|s| s.ident == "null" || s.ident == "null_mut"))
        }
        syn::Expr::Repeat(r) => is_zero(&r.expr),
        syn::Expr::Array(a) => !a.elems.is_empty() && a.elems.iter().all(is_zero),
        syn::Expr::Paren(p) => is_zero(&p.expr),
        syn::Expr::Group(g) => is_zero(&g.expr),
        syn::Expr::Cast(c) => is_zero(&c.expr),
        _ => false,
    }
}

struct Finder<'a> {
    idx: &'a ZeroIndex,
    file: String,
    uses: BTreeMap<String, String>,
    locals: &'a BTreeSet<String>,
    found: Vec<String>,
}

impl<'ast> Visit<'ast> for Finder<'_> {
    fn visit_item(&mut self, i: &'ast syn::Item) {
        let attrs = match i {
            syn::Item::Mod(m) => &m.attrs,
            syn::Item::Fn(f) => &f.attrs,
            syn::Item::Impl(x) => &x.attrs,
            syn::Item::Const(c) => &c.attrs,
            syn::Item::Static(s) => &s.attrs,
            _ => return syn::visit::visit_item(self, i),
        };
        if !test_only(attrs) {
            syn::visit::visit_item(self, i);
        }
    }

    fn visit_impl_item_fn(&mut self, f: &'ast syn::ImplItemFn) {
        if !test_only(&f.attrs) {
            syn::visit::visit_impl_item_fn(self, f);
        }
    }

    fn visit_expr_struct(&mut self, e: &'ast syn::ExprStruct) {
        let seg = e.path.segments.last();
        if let (None, Some(seg)) = (&e.qself, seg) {
            let name = seg.ident.to_string();
            let named = |f: &syn::FieldValue| match &f.member {
                syn::Member::Named(n) => Some(n.to_string()),
                syn::Member::Unnamed(_) => None,
            };
            let fields: BTreeSet<String> = e.fields.iter().filter_map(named).collect();
            let line = seg.ident.span().start().line;
            let ours =
                contract_path(&e.path, &self.uses, self.locals) && self.idx.judged(&name, &fields);
            match &e.rest {
                Some(b) if ours && !base_ok(b) => self.found.push(format!(
                    "ZERO-SPREAD {}:{line}: `{name} {{ … }}` spreads a base that is not \
                     `{name}::ZERO`, a `default()` or a contract builder; an appended field \
                     would read as whatever that base holds",
                    self.file
                )),
                None if ours => {
                    let zeroed: Vec<String> = e
                        .fields
                        .iter()
                        .filter(|f| is_zero(&f.expr))
                        .filter_map(named)
                        .collect();
                    if !zeroed.is_empty() {
                        self.found.push(format!(
                            "ZERO-SPREAD {}:{line}: `{name} {{ … }}` names every field without a \
                             base; drop the zero field(s) {} and spread `..{name}::ZERO`, so a \
                             field the contract appends later keeps it compiling",
                            self.file,
                            zeroed.join(", ")
                        ));
                    }
                }
                _ => {}
            }
        }
        syn::visit::visit_expr_struct(self, e);
    }
}

/// The findings in one source text (`file` is how a finding names it).
///
/// # Errors
/// Text that is not parseable Rust.
pub fn scan_text(idx: &ZeroIndex, file: &str, text: &str) -> Res<Vec<String>> {
    let parsed = parse(Path::new(file), text)?;
    let mut locals = BTreeSet::new();
    local_types(&parsed.items, &mut locals);
    Ok(scan_parsed(idx, file, &parsed, &locals))
}

fn scan_parsed(
    idx: &ZeroIndex,
    file: &str,
    parsed: &syn::File,
    locals: &BTreeSet<String>,
) -> Vec<String> {
    let mut f = Finder {
        idx,
        file: file.to_string(),
        uses: use_map(&parsed.items),
        locals,
        found: Vec::new(),
    };
    f.visit_file(parsed);
    f.found
}

/// The child modules a file declares out of line, as `(name, #[path], test-only)`, at any inline
/// depth (an inline module's children resolve under its own directory).
fn out_of_line(
    items: &[syn::Item],
    under: &Path,
    out: &mut Vec<(PathBuf, Option<String>, String)>,
) {
    for item in items {
        let syn::Item::Mod(m) = item else { continue };
        if test_only(&m.attrs) {
            continue;
        }
        let path_attr = m.attrs.iter().find_map(|a| match &a.meta {
            syn::Meta::NameValue(nv) if nv.path.is_ident("path") => match &nv.value {
                syn::Expr::Lit(syn::ExprLit {
                    lit: syn::Lit::Str(s),
                    ..
                }) => Some(s.value()),
                _ => None,
            },
            _ => None,
        });
        match &m.content {
            Some((_, inner)) => out_of_line(inner, &under.join(m.ident.to_string()), out),
            None => out.push((under.to_path_buf(), path_attr, m.ident.to_string())),
        }
    }
}

/// Every non-test module file of the tree rooted at `entry` (a crate root, or a single source
/// file), parsed: the root, then each `mod x;` a non-test declaration reaches.
///
/// # Errors
/// A reachable module file that cannot be read or parsed.
fn modules(entry: &Path) -> Res<Vec<(PathBuf, syn::File)>> {
    let mut out = Vec::new();
    let mut todo = vec![entry.to_path_buf()];
    let mut seen = BTreeSet::new();
    while let Some(f) = todo.pop() {
        if !seen.insert(f.clone()) {
            continue;
        }
        let text = std::fs::read_to_string(&f).map_err(|e| format!("{}: {e}", f.display()))?;
        let parsed = parse(&f, &text)?;
        let dir = f.parent().unwrap_or(Path::new(".")).to_path_buf();
        let stem = f.file_stem().map(|s| s.to_string_lossy().to_string());
        let owns_dir = f == entry || matches!(stem.as_deref(), Some("mod" | "lib" | "main"));
        let under = if owns_dir {
            dir.clone()
        } else {
            dir.join(stem.unwrap_or_default())
        };
        let mut kids = Vec::new();
        out_of_line(&parsed.items, &under, &mut kids);
        for (at, path_attr, name) in kids {
            let next = match path_attr {
                Some(p) => dir.join(p),
                None => {
                    let flat = at.join(format!("{name}.rs"));
                    if flat.is_file() {
                        flat
                    } else {
                        at.join(&name).join("mod.rs")
                    }
                }
            };
            if next.is_file() {
                todo.push(next);
            }
        }
        out.push((f, parsed));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

/// The findings in the non-test module tree rooted at `entry`, each file named relative to
/// `shown_from`.
///
/// # Errors
/// A reachable module file that cannot be read or parsed.
pub fn scan_tree(idx: &ZeroIndex, entry: &Path, shown_from: &Path) -> Res<Vec<String>> {
    let mods = modules(entry)?;
    let mut locals = BTreeSet::new();
    for (_, parsed) in &mods {
        local_types(&parsed.items, &mut locals);
    }
    let mut found = Vec::new();
    for (f, parsed) in mods {
        let shown = f
            .strip_prefix(shown_from)
            .unwrap_or(&f)
            .display()
            .to_string();
        found.extend(scan_parsed(idx, &shown, &parsed, &locals));
    }
    Ok(found)
}

/// Every crate root of a plugin repo: `src/lib.rs`, `src/main.rs` and `src/bin/*.rs` of each
/// directory holding a `Cargo.toml` (`target/` and dot-directories skipped).
fn crate_roots(dir: &Path, out: &mut Vec<PathBuf>) -> Res<()> {
    if dir.join("Cargo.toml").is_file() {
        for r in ["src/lib.rs", "src/main.rs"] {
            if dir.join(r).is_file() {
                out.push(dir.join(r));
            }
        }
        if let Ok(rd) = std::fs::read_dir(dir.join("src/bin")) {
            let mut bins: Vec<PathBuf> = rd
                .filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| p.extension().is_some_and(|x| x == "rs"))
                .collect();
            bins.sort();
            out.extend(bins);
        }
    }
    let rd = std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let mut subs: Vec<PathBuf> = rd
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_dir())
        .filter(|p| {
            let n = p
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            !n.starts_with('.')
                && !["target", "src", "tests", "benches", "examples"].contains(&n.as_str())
        })
        .collect();
    subs.sort();
    for s in subs {
        crate_roots(&s, out)?;
    }
    Ok(())
}

/// THE GATE: every finding in a plugin repo, judged against the contract at `busbar_root`.
///
/// # Errors
/// An unreadable contract or plugin, or a repo with no crate root at all.
pub fn zero_spread(busbar_root: &Path, plugin: &Path) -> Res<Vec<String>> {
    let idx = index(&busbar_root.join(CONTRACT_SRC))?;
    if idx.zero_names().is_empty() {
        return Err(format!(
            "zero-spread: the contract at {} states no `ZERO`; nothing to judge against",
            busbar_root.display()
        ));
    }
    let mut roots = Vec::new();
    crate_roots(plugin, &mut roots)?;
    if roots.is_empty() {
        return Err(format!(
            "zero-spread: {} holds no crate root (src/lib.rs, src/main.rs, src/bin/*.rs)",
            plugin.display()
        ));
    }
    let mut found = Vec::new();
    for r in roots {
        found.extend(scan_tree(&idx, &r, plugin)?);
    }
    Ok(found)
}

#[cfg(test)]
#[path = "zero_spread_tests.rs"]
mod tests;
