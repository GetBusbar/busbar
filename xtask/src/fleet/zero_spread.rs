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
//! `T` is a contract struct with a `ZERO`. Any base satisfies it (`..T::ZERO`, `..ZERO`, `..base()`):
//! each one keeps an appended field compiling. Expressions inside a macro invocation are not seen.
//!
//! ONLY A LITERAL THE BASE CAN SHORTEN. A base-less literal names every field, and a base beside
//! every field is `clippy::needless_update`. So a literal is judged when at least one field it
//! names is written as a zero (`0`, `false`, `None`, `[0; N]`, a NULL pointer, a `…::ZERO`): the
//! fix drops those fields and spreads `..T::ZERO`, and the result is lint-clean. A literal whose
//! every field carries a value (a pointer-and-length pair) is not judged.
//!
//! NAMES, NOT PATHS. The gate reads source, not types, so `T` is matched by its last path segment.
//! Where the contract holds two structs of one name, the literal's own field names pick the
//! candidates (every struct of that name whose fields include all of the literal's); the literal is
//! judged only when every candidate states a `ZERO`, so a name shared with a struct that has none
//! is never a false finding.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use syn::visit::Visit;

type Res<T> = Result<T, String>;

/// Where the contract's source sits under a busbar checkout.
pub const CONTRACT_SRC: &str = "crates/busbar-contract/src";

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

    /// Whether a base-less literal `name { fields }` must carry a base.
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
        if e.rest.is_none() && e.qself.is_none() {
            if let Some(seg) = e.path.segments.last() {
                let name = seg.ident.to_string();
                let fields: BTreeSet<String> = e
                    .fields
                    .iter()
                    .filter_map(|f| match &f.member {
                        syn::Member::Named(n) => Some(n.to_string()),
                        syn::Member::Unnamed(_) => None,
                    })
                    .collect();
                let zeroed: Vec<String> = e
                    .fields
                    .iter()
                    .filter(|f| is_zero(&f.expr))
                    .filter_map(|f| match &f.member {
                        syn::Member::Named(n) => Some(n.to_string()),
                        syn::Member::Unnamed(_) => None,
                    })
                    .collect();
                if !zeroed.is_empty() && self.idx.judged(&name, &fields) {
                    self.found.push(format!(
                        "ZERO-SPREAD {}:{}: `{name} {{ … }}` names every field without a base; \
                         drop the zero field(s) {} and spread `..{name}::ZERO`, so a field the \
                         contract appends later keeps it compiling",
                        self.file,
                        seg.ident.span().start().line,
                        zeroed.join(", ")
                    ));
                }
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
    Ok(scan_parsed(idx, file, &parse(Path::new(file), text)?))
}

fn scan_parsed(idx: &ZeroIndex, file: &str, parsed: &syn::File) -> Vec<String> {
    let mut f = Finder {
        idx,
        file: file.to_string(),
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
    let mut found = Vec::new();
    for (f, parsed) in modules(entry)? {
        let shown = f
            .strip_prefix(shown_from)
            .unwrap_or(&f)
            .display()
            .to_string();
        found.extend(scan_parsed(idx, &shown, &parsed));
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
