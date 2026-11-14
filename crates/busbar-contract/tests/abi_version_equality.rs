// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! LINT-RULES R21 `abi-version-set`: an ABI version is only ever equal or not equal. A binary
//! loads exactly one version per kind and one mechanism version (`src/abi/versions.rs`); a
//! range, an ordering or a set of accepted versions would load a plugin built for another ABI.
//!
//! This scan parses every Rust file of the core tree (every crate and target: `crates/`,
//! `dist/default/`, `tools/`, `tests/`) and refuses:
//! - an ordering comparison (`<`, `<=`, `>`, `>=`) with a version on either side;
//! - a range (`a..b`, `a..=b`) with a version at either end;
//! - an array or slice literal listing a version as an element (a table of accepted versions);
//! - `[AbiVersion]`, `[AbiVersion; N]` and `Vec`/`VecDeque`/`HashSet`/`BTreeSet`/`HashMap`/
//!   `BTreeMap`/`Range`/`RangeInclusive` of `AbiVersion`;
//! - `PartialOrd`/`Ord` derived for a type named `AbiVersion`.
//!
//! A version is an expression that names one: a path or field whose last name is `ABI_VERSION`,
//! `MECHANISM_VERSION`, `*_ABI_VERSION`, `abi_version`, `kind_abi` or `mechanism_version`, a call of
//! a method of those names, or a call of `supported_abi`; arithmetic over one still names it
//! (`kind_abi + 1 > x`). Negative tests that forge a wrong version (`[V - 1, V + 1]`) list
//! arithmetic, not versions, and are not tables of accepted versions.

use std::path::{Path, PathBuf};

use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{BinOp, Expr, GenericArgument, PathArguments, Type};

const NAMES: &[&str] = &[
    "ABI_VERSION",
    "MECHANISM_VERSION",
    "abi_version",
    "kind_abi",
    "mechanism_version",
];

fn is_version_name(name: &str) -> bool {
    NAMES.contains(&name) || name.ends_with("_ABI_VERSION")
}

/// Whether `e` names an ABI version (see the module docs).
fn names_version(e: &Expr) -> bool {
    match e {
        Expr::Path(p) => p
            .path
            .segments
            .last()
            .is_some_and(|s| is_version_name(&s.ident.to_string())),
        Expr::Field(f) => match &f.member {
            syn::Member::Named(n) => is_version_name(&n.to_string()),
            syn::Member::Unnamed(_) => false,
        },
        Expr::MethodCall(m) => is_version_name(&m.method.to_string()) || names_version(&m.receiver),
        Expr::Call(c) => match &*c.func {
            Expr::Path(p) => p
                .path
                .segments
                .last()
                .is_some_and(|s| s.ident == "supported_abi"),
            _ => false,
        },
        Expr::Paren(p) => names_version(&p.expr),
        Expr::Group(g) => names_version(&g.expr),
        Expr::Reference(r) => names_version(&r.expr),
        Expr::Unary(u) => names_version(&u.expr),
        Expr::Cast(c) => names_version(&c.expr),
        Expr::Binary(b) if is_arithmetic(&b.op) => {
            names_version(&b.left) || names_version(&b.right)
        }
        _ => false,
    }
}

/// Whether `e` IS a version (no arithmetic): an element of a table of accepted versions.
fn is_version(e: &Expr) -> bool {
    match e {
        Expr::Binary(_) => false,
        Expr::MethodCall(m) => is_version_name(&m.method.to_string()),
        _ => names_version(e),
    }
}

fn is_arithmetic(op: &BinOp) -> bool {
    matches!(
        op,
        BinOp::Add(_) | BinOp::Sub(_) | BinOp::Mul(_) | BinOp::Div(_) | BinOp::Rem(_)
    )
}

fn is_abi_version_type(t: &Type) -> bool {
    match t {
        Type::Path(p) => p
            .path
            .segments
            .last()
            .is_some_and(|s| s.ident == "AbiVersion"),
        Type::Paren(p) => is_abi_version_type(&p.elem),
        Type::Group(g) => is_abi_version_type(&g.elem),
        _ => false,
    }
}

const COLLECTIONS: &[&str] = &[
    "Vec",
    "VecDeque",
    "HashSet",
    "BTreeSet",
    "HashMap",
    "BTreeMap",
    "Range",
    "RangeInclusive",
];

struct Scan<'a> {
    file: &'a Path,
    hits: Vec<String>,
}

impl Scan<'_> {
    fn hit(&mut self, what: &str, span: proc_macro2::Span) {
        self.hits.push(format!(
            "{}:{}: {what}",
            self.file.display(),
            span.start().line
        ));
    }
}

impl<'ast> Visit<'ast> for Scan<'_> {
    fn visit_expr_binary(&mut self, b: &'ast syn::ExprBinary) {
        let ordering = matches!(
            b.op,
            BinOp::Lt(_) | BinOp::Le(_) | BinOp::Gt(_) | BinOp::Ge(_)
        );
        if ordering && (names_version(&b.left) || names_version(&b.right)) {
            self.hit("an ordering comparison of ABI versions", b.span());
        }
        visit::visit_expr_binary(self, b);
    }

    fn visit_expr_range(&mut self, r: &'ast syn::ExprRange) {
        let ends = [r.start.as_deref(), r.end.as_deref()];
        if ends.into_iter().flatten().any(names_version) {
            self.hit("a range of ABI versions", r.span());
        }
        visit::visit_expr_range(self, r);
    }

    fn visit_expr_array(&mut self, a: &'ast syn::ExprArray) {
        if a.elems.iter().any(is_version) {
            self.hit("a table of ABI versions", a.span());
        }
        visit::visit_expr_array(self, a);
    }

    fn visit_type_slice(&mut self, t: &'ast syn::TypeSlice) {
        if is_abi_version_type(&t.elem) {
            self.hit("a slice of AbiVersion", t.span());
        }
        visit::visit_type_slice(self, t);
    }

    fn visit_type_array(&mut self, t: &'ast syn::TypeArray) {
        if is_abi_version_type(&t.elem) {
            self.hit("an array of AbiVersion", t.span());
        }
        visit::visit_type_array(self, t);
    }

    fn visit_type_path(&mut self, t: &'ast syn::TypePath) {
        if let Some(last) = t.path.segments.last() {
            if COLLECTIONS.contains(&last.ident.to_string().as_str()) {
                if let PathArguments::AngleBracketed(args) = &last.arguments {
                    let first = args.args.iter().find_map(|a| match a {
                        GenericArgument::Type(t) => Some(t),
                        _ => None,
                    });
                    if first.is_some_and(is_abi_version_type) {
                        self.hit("a collection or range of AbiVersion", t.span());
                    }
                }
            }
        }
        visit::visit_type_path(self, t);
    }

    /// Macro bodies (`assert!`, `assert_eq!`, `vec!`, ...) are token streams to syn: judge every
    /// one that reads as a comma-separated list of expressions.
    fn visit_macro(&mut self, m: &'ast syn::Macro) {
        let Ok(args) = m
            .parse_body_with(syn::punctuated::Punctuated::<Expr, syn::Token![,]>::parse_terminated)
        else {
            return;
        };
        if m.path.is_ident("vec") && args.iter().any(is_version) {
            self.hit("a table of ABI versions", m.span());
        }
        for e in &args {
            Visit::visit_expr(self, e);
        }
    }

    fn visit_item_struct(&mut self, s: &'ast syn::ItemStruct) {
        if s.ident == "AbiVersion" && derives_order(&s.attrs) {
            self.hit("AbiVersion derives an ordering", s.ident.span());
        }
        visit::visit_item_struct(self, s);
    }

    fn visit_item_enum(&mut self, e: &'ast syn::ItemEnum) {
        if e.ident == "AbiVersion" && derives_order(&e.attrs) {
            self.hit("AbiVersion derives an ordering", e.ident.span());
        }
        visit::visit_item_enum(self, e);
    }
}

fn derives_order(attrs: &[syn::Attribute]) -> bool {
    attrs
        .iter()
        .filter(|a| a.path().is_ident("derive"))
        .any(|a| {
            let mut ordered = false;
            let _ = a.parse_nested_meta(|m| {
                if m.path.is_ident("PartialOrd") || m.path.is_ident("Ord") {
                    ordered = true;
                }
                Ok(())
            });
            ordered
        })
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if p.is_dir() {
            if name != "target" && !name.starts_with('.') {
                walk(&p, out);
            }
        } else if name.ends_with(".rs") {
            out.push(p);
        }
    }
}

fn scan_tree(root: &Path) -> (usize, Vec<String>) {
    let mut files = Vec::new();
    for top in ["crates", "dist/default", "tools", "tests"] {
        walk(&root.join(top), &mut files);
    }
    let mut hits = Vec::new();
    for file in &files {
        let Ok(text) = std::fs::read_to_string(file) else {
            continue;
        };
        // A fixture that is not Rust source (a deliberately broken input) has nothing to judge.
        let Ok(ast) = syn::parse_file(&text) else {
            continue;
        };
        let rel = file.strip_prefix(root).unwrap_or(file);
        let mut scan = Scan {
            file: rel,
            hits: Vec::new(),
        };
        scan.visit_file(&ast);
        hits.extend(scan.hits);
    }
    (files.len(), hits)
}

#[test]
fn abi_versions_are_compared_only_for_equality() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let (files, hits) = scan_tree(&root);
    assert!(
        files > 500,
        "the scan found only {files} Rust files: wrong root"
    );
    assert!(
        hits.is_empty(),
        "ABI versions are only ever equal or not (LINT-RULES R21):\n{}",
        hits.join("\n")
    );
}

/// RED PLANTS: each spelling the rule refuses is found, and a forged wrong version is not.
#[test]
fn the_scan_finds_each_refused_spelling() {
    let plants: &[(&str, usize)] = &[
        ("fn f(m: &M) -> bool { m.abi_version >= 2 }", 1),
        ("const _: () = assert!(ABI_VERSION <= u16::MAX as u32);", 1),
        ("fn f() -> bool { (1..=MECHANISM_VERSION).contains(&2) }", 1),
        ("fn f() -> &'static [u32] { &[store::ABI_VERSION] }", 1),
        ("fn f(k: KindCode) -> bool { k.abi_version() + 1 > 3 }", 1),
        ("fn f(_: &[AbiVersion], _: HashSet<AbiVersion>) {}", 2),
        (
            "#[derive(PartialEq, Eq, PartialOrd, Ord)] struct AbiVersion(u16);",
            1,
        ),
        (
            "fn f() { for v in [ABI_VERSION - 1, ABI_VERSION + 1] { let _ = v; } }",
            0,
        ),
        ("fn f(m: &M) -> bool { m.abi_version == supported }", 0),
    ];
    for (source, want) in plants {
        let ast = syn::parse_file(source).expect("plant parses");
        let mut scan = Scan {
            file: Path::new("plant.rs"),
            hits: Vec::new(),
        };
        scan.visit_file(&ast);
        assert_eq!(scan.hits.len(), *want, "{source}: {:?}", scan.hits);
    }
}
