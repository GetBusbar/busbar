// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The §15.8 core scan (IF §15 rule 8, rounds 8, 27): no first-party plugin name or former name at an
//! identity site in `busbar-migrate`, `plugin-loader`, `busbar-plugin-abi`, `busbar-kernel`,
//! `busbar-contract` and every `busbar-core-*` crate. No exemption. The word list is generated from
//! `plugins.yaml` (repo, manifest name, alias, former names) plus the enterprise stamps read from release
//! manifests (`--words <file>`, one word per line); it is never checked into core.
//!
//! An identity site (the whole matching rule, nothing else matches):
//! (i) a string literal, or a `const`/`static` of this file whose value is one, that is an operand of
//!     `==`/`!=`, a `match` or `matches!` arm pattern, or the argument of `eq`/`eq_ignore_ascii_case`/
//!     `starts_with`/`ends_with`/`contains`, where the other side is an identity expression: the field
//!     `identity`, `plugin` or `former_names`, `name` reached through a stamp, spec, caller, admitted or
//!     instance, or a value read from a config `module` key;
//! (ii) a string literal used as a `module:` value, or a struct literal's `identity` field;
//! (iii) the `word` argument of `outbound_owner(styles, word)`.
//!
//! The identity expression is recognised by name (syn has no types), so the accessor names are the list
//! frozen in IF §7.4, §10.3, §11.1, §11.2. A word in a doc comment or an unrelated literal is not a hit.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use syn::parse::ParseStream;
use syn::visit::{self, Visit};
use syn::{BinOp, Expr, ExprLit, Item, Lit, Member, Pat, Token};

use super::{is_test, rel, rust_files, sorted_entries, Outcome};

/// Core's crates under the scan (directory names under `crates/`).
fn scanned(name: &str) -> bool {
    matches!(
        name,
        "busbar-migrate"
            | "plugin-loader"
            | "busbar-plugin-abi"
            | "busbar-kernel"
            | "busbar-contract"
    ) || name.starts_with("busbar-core-")
}

struct Scan<'w> {
    words: &'w BTreeSet<String>,
    consts: BTreeMap<String, String>,
    hits: Vec<(usize, String)>,
}

fn lit_str(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Lit(ExprLit {
            lit: Lit::Str(s), ..
        }) => Some(s.value()),
        Expr::Paren(p) => lit_str(&p.expr),
        Expr::Reference(r) => lit_str(&r.expr),
        Expr::Group(g) => lit_str(&g.expr),
        _ => None,
    }
}

fn idents_of(expr: &Expr, out: &mut String) {
    match expr {
        Expr::Path(p) => {
            if let Some(last) = p.path.segments.last() {
                out.push_str(&last.ident.to_string());
                out.push(' ');
            }
        }
        Expr::Field(f) => {
            idents_of(&f.base, out);
            if let Member::Named(id) = &f.member {
                out.push_str(&id.to_string());
                out.push(' ');
            }
        }
        Expr::MethodCall(m) => {
            idents_of(&m.receiver, out);
            out.push_str(&m.method.to_string());
            out.push(' ');
        }
        Expr::Reference(r) => idents_of(&r.expr, out),
        Expr::Paren(p) => idents_of(&p.expr, out),
        Expr::Unary(u) => idents_of(&u.expr, out),
        Expr::Index(i) => idents_of(&i.expr, out),
        Expr::Call(c) => idents_of(&c.func, out),
        _ => {}
    }
}

/// An identity expression, recognised by the accessor names of IF §7.4, §10.3, §11.1, §11.2.
pub(crate) fn is_identity_expr(expr: &Expr) -> bool {
    match expr {
        Expr::Field(f) => match &f.member {
            Member::Named(id) => {
                let name = id.to_string();
                match name.as_str() {
                    "identity" | "plugin" | "former_names" | "module" => true,
                    "name" => {
                        let mut base = String::new();
                        idents_of(&f.base, &mut base);
                        let base = base.to_ascii_lowercase();
                        [
                            "stamp", "spec", "caller", "admitted", "instance", "identity",
                        ]
                        .iter()
                        .any(|word| base.contains(word))
                    }
                    _ => false,
                }
            }
            Member::Unnamed(_) => false,
        },
        Expr::MethodCall(m) => {
            let name = m.method.to_string();
            match name.as_str() {
                "identity" | "plugin" | "former_names" if m.args.is_empty() => true,
                "get" => m
                    .args
                    .first()
                    .and_then(lit_str)
                    .is_some_and(|key| key == "module"),
                "as_str" | "as_ref" | "to_string" | "to_owned" | "trim" | "to_ascii_lowercase"
                | "borrow" | "unwrap" | "as_deref" | "clone" => is_identity_expr(&m.receiver),
                _ => false,
            }
        }
        Expr::Index(i) => lit_str(&i.index).is_some_and(|key| key == "module"),
        Expr::Reference(r) => is_identity_expr(&r.expr),
        Expr::Paren(p) => is_identity_expr(&p.expr),
        Expr::Unary(u) => is_identity_expr(&u.expr),
        Expr::Path(p) => p
            .path
            .get_ident()
            .is_some_and(|id| id == "identity" || id == "module_word"),
        _ => false,
    }
}

/// The values after `module:` in a literal (`module: env`, `"module": "env"`, `module:\n  env`).
pub(crate) fn module_values(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(at) = rest.find("module") {
        let mut tail = &rest[at + "module".len()..];
        tail = tail.trim_start_matches(['"', '\'']);
        if let Some(after) = tail.strip_prefix(':') {
            let value: String = after
                .trim_start_matches([' ', '\t', '\n', '\r', '"', '\''])
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
                .collect();
            if !value.is_empty() {
                out.push(value);
            }
        }
        rest = &rest[at + "module".len()..];
    }
    out
}

impl Scan<'_> {
    fn resolve(&self, expr: &Expr) -> Option<String> {
        if let Some(value) = lit_str(expr) {
            return Some(value);
        }
        match expr {
            Expr::Path(p) => p
                .path
                .get_ident()
                .and_then(|id| self.consts.get(&id.to_string()))
                .cloned(),
            Expr::Reference(r) => self.resolve(&r.expr),
            Expr::Paren(p) => self.resolve(&p.expr),
            _ => None,
        }
    }

    fn word(&mut self, value: Option<String>, line: usize, site: &str) {
        if let Some(value) = value {
            if self.words.contains(&value) {
                self.hits.push((
                    line,
                    format!("the plugin word `{value}` at an identity site ({site})"),
                ));
            }
        }
    }
}

fn line_of(expr: &Expr) -> usize {
    use syn::spanned::Spanned;
    expr.span().start().line
}

impl<'ast> Visit<'ast> for Scan<'_> {
    fn visit_item(&mut self, item: &'ast Item) {
        if !is_test(super::item_attrs(item)) {
            visit::visit_item(self, item);
        }
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        if !is_test(&node.attrs) {
            visit::visit_impl_item_fn(self, node);
        }
    }

    fn visit_expr_binary(&mut self, node: &'ast syn::ExprBinary) {
        if matches!(node.op, BinOp::Eq(_) | BinOp::Ne(_)) {
            let line = line_of(&node.left);
            if is_identity_expr(&node.left) {
                let value = self.resolve(&node.right);
                self.word(value, line, "==");
            }
            if is_identity_expr(&node.right) {
                let value = self.resolve(&node.left);
                self.word(value, line, "==");
            }
        }
        visit::visit_expr_binary(self, node);
    }

    fn visit_expr_match(&mut self, node: &'ast syn::ExprMatch) {
        if is_identity_expr(&node.expr) {
            for arm in &node.arms {
                let mut stack = vec![&arm.pat];
                while let Some(pat) = stack.pop() {
                    match pat {
                        Pat::Or(or) => stack.extend(or.cases.iter()),
                        Pat::Paren(p) => stack.push(&p.pat),
                        Pat::Lit(l) => {
                            let line = line_of(&node.expr);
                            if let Lit::Str(s) = &l.lit {
                                self.word(Some(s.value()), line, "match arm");
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        visit::visit_expr_match(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        let name = node.method.to_string();
        if matches!(
            name.as_str(),
            "eq" | "eq_ignore_ascii_case" | "starts_with" | "ends_with" | "contains"
        ) && is_identity_expr(&node.receiver)
        {
            if let Some(arg) = node.args.first() {
                let value = self.resolve(arg);
                self.word(value, line_of(arg), &name);
            }
        }
        if name == "outbound_owner" {
            if let Some(arg) = node.args.iter().nth(1) {
                let value = self.resolve(arg);
                self.word(value, line_of(arg), "outbound_owner");
            }
        }
        visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let Expr::Path(p) = &*node.func {
            if p.path
                .segments
                .last()
                .is_some_and(|s| s.ident == "outbound_owner")
            {
                if let Some(arg) = node.args.iter().nth(1) {
                    let value = self.resolve(arg);
                    self.word(value, line_of(arg), "outbound_owner");
                }
            }
        }
        visit::visit_expr_call(self, node);
    }

    fn visit_expr_struct(&mut self, node: &'ast syn::ExprStruct) {
        for field in &node.fields {
            if matches!(&field.member, Member::Named(id) if id == "identity") {
                let value = self.resolve(&field.expr);
                self.word(value, line_of(&field.expr), "struct literal `identity`");
            }
        }
        visit::visit_expr_struct(self, node);
    }

    fn visit_attribute(&mut self, node: &'ast syn::Attribute) {
        if !node.path().is_ident("doc") {
            visit::visit_attribute(self, node);
        }
    }

    fn visit_lit_str(&mut self, node: &'ast syn::LitStr) {
        for value in module_values(&node.value()) {
            self.word(Some(value), node.span().start().line, "`module:` value");
        }
    }

    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        if node
            .path
            .segments
            .last()
            .is_some_and(|s| s.ident == "matches")
        {
            let parsed = node.parse_body_with(|input: ParseStream| {
                let scrutinee: Expr = input.parse()?;
                input.parse::<Token![,]>()?;
                let rest: proc_macro2::TokenStream = input.parse()?;
                Ok((scrutinee, rest))
            });
            if let Ok((scrutinee, rest)) = parsed {
                if is_identity_expr(&scrutinee) {
                    let mut tokens = Vec::new();
                    super::plugin_rules::flatten(rest, &mut tokens);
                    for tok in tokens {
                        let text = tok.text.trim_matches('"').to_string();
                        if tok.text.starts_with('"') {
                            self.word(Some(text), tok.line, "matches!");
                        }
                    }
                }
            }
        }
        visit::visit_macro(self, node);
    }
}

struct Consts(BTreeMap<String, String>);

impl<'ast> Visit<'ast> for Consts {
    fn visit_item_const(&mut self, node: &'ast syn::ItemConst) {
        if let Some(value) = lit_str(&node.expr) {
            self.0.insert(node.ident.to_string(), value);
        }
    }
    fn visit_item_static(&mut self, node: &'ast syn::ItemStatic) {
        if let Some(value) = lit_str(&node.expr) {
            self.0.insert(node.ident.to_string(), value);
        }
    }
}

/// The identity-site hits of one source file: (line, note).
pub(crate) fn identity_hits(
    source: &str,
    words: &BTreeSet<String>,
) -> Result<Vec<(usize, String)>, String> {
    let file = syn::parse_file(source).map_err(|error| format!("syn: {error}"))?;
    if is_test(&file.attrs) {
        return Ok(Vec::new());
    }
    let mut consts = Consts(BTreeMap::new());
    consts.visit_file(&file);
    let mut scan = Scan {
        words,
        consts: consts.0,
        hits: Vec::new(),
    };
    scan.visit_file(&file);
    scan.hits.sort();
    scan.hits.dedup();
    Ok(scan.hits)
}

/// `core-scan [--words <file>]`: the words come from plugins.yaml and the optional enterprise list.
pub(crate) fn core_scan(root: &Path, args: &[String]) -> Outcome {
    let yaml = std::fs::read_to_string(root.join("plugins.yaml"))
        .map_err(|error| format!("plugins.yaml: {error}"))?;
    let mut extra = String::new();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == "--words" {
            let path = iter.next().ok_or("--words needs a file")?;
            // The job passes `"$ENTERPRISE_STAMP_WORDS"`, empty where no release manifests exist: an empty
            // path is the optional list absent, not a file named "".
            if !path.is_empty() {
                extra =
                    std::fs::read_to_string(path).map_err(|error| format!("{path}: {error}"))?;
            }
        }
    }
    let words = super::fleet::plugin_words(&yaml, &extra);
    let mut findings = Vec::new();
    for dir in sorted_entries(&root.join("crates"))? {
        let name = dir.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if !dir.is_dir() || !scanned(name) {
            continue;
        }
        let mut files = Vec::new();
        rust_files(&dir, &mut files)?;
        for file in files {
            if test_file(Path::new(&rel(root, &file))) {
                continue;
            }
            let text = std::fs::read_to_string(&file)
                .map_err(|error| format!("{}: {error}", rel(root, &file)))?;
            match identity_hits(&text, &words) {
                Ok(hits) => {
                    for (line, note) in hits {
                        findings.push(format!("{}:{line}: {note} (§15 rule 8)", rel(root, &file)));
                    }
                }
                Err(error) => findings.push(format!("{}: {error}", rel(root, &file))),
            }
        }
    }
    Ok(findings)
}

/// A file that is test code by name: `tests.rs`, `*_tests.rs`, `test_*.rs` (`test_host.rs`,
/// `test_support`) or anything under a `tests`/`test_support` directory.
pub(crate) fn test_file(file: &Path) -> bool {
    let stem = file.file_stem().and_then(|s| s.to_str()).unwrap_or("");
    stem == "tests"
        || stem.ends_with("_tests")
        || stem.starts_with("test_")
        || file
            .components()
            .any(|part| matches!(part.as_os_str().to_str(), Some("tests" | "test_support")))
}
