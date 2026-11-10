// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The credential typecheck is a mechanical, type-level

use std::collections::{BTreeMap, BTreeSet};

use proc_macro2::TokenTree;
use syn::visit::Visit;

use crate::walk::{self, Source};

const STRONG: &[&str] = &[
    "api_key",
    "apikey",
    "client_secret",
    "private_key",
    "signing_key",
    "access_token",
    "refresh_token",
    "id_token",
    "subject_token",
    "api_secret",
    "secret_access_key",
    "session_token",
    "password",
    "passwd",
    "bearer",
    "credential_secret",
    "secret",
    "token",
    "credential",
    "credentials",
    "auth_header",
];
const URL_NEEDLES: &[&str] = &["url", "dsn", "uri"];
/// Field names a needle hits that do not hold credential material.
const NOT_CREDENTIAL: &[&str] = &[
    "token_count",
    "tokens",
    "max_tokens",
    "token_url",
    "token_endpoint",
    "secret_ref",
    "secret_refs",
    "credential_kind",
    "credential_id",
    "credential_ref",
];
const SINKS: &[&str] = &[
    "println", "eprintln", "print", "eprint", "dbg", "panic", "info", "warn", "error", "debug",
    "trace", "event",
];
const COPIES: &[&str] = &["to_vec", "to_string", "to_owned", "into_owned"];

/// `name` is `needle`, or ends `_<needle>`.
fn tail(name: &str, needle: &str) -> bool {
    name == needle
        || (name.len() > needle.len() + 1
            && name.ends_with(needle)
            && name.as_bytes()[name.len() - needle.len() - 1] == b'_')
}

fn credential_named(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    !NOT_CREDENTIAL.contains(&n.as_str()) && STRONG.iter().any(|s| tail(&n, s))
}

fn url_named(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    URL_NEEDLES.iter().any(|s| tail(&n, s))
}

/// The type holds its value as bare text or bytes, and no sealing wrapper names it.
pub(super) fn bare(ty: &syn::Type) -> bool {
    use syn::{GenericArgument, PathArguments, Type};
    match ty {
        Type::Reference(r) => {
            // A static string is a program label, not a runtime credential allocation.
            if r.lifetime.as_ref().is_some_and(|l| l.ident == "static") {
                return false;
            }
            bare(&r.elem)
        }
        Type::Paren(p) => bare(&p.elem),
        Type::Group(g) => bare(&g.elem),
        Type::Slice(s) => is_byte(&s.elem),
        Type::Array(a) => is_byte(&a.elem),
        Type::Tuple(t) => t.elems.iter().any(bare),
        Type::Path(p) => {
            let Some(last) = p.path.segments.last() else {
                return false;
            };
            let name = last.ident.to_string();
            if matches!(
                name.as_str(),
                "Secret" | "SecretRef" | "Zeroizing" | "Redacted" | "Cred" | "SealedValue"
            ) {
                return false;
            }
            if matches!(name.as_str(), "String" | "str" | "Bytes" | "BytesMut") {
                return true;
            }
            let PathArguments::AngleBracketed(args) = &last.arguments else {
                return false;
            };
            let mut types = args.args.iter().filter_map(|a| match a {
                GenericArgument::Type(t) => Some(t),
                _ => None,
            });
            // An error message is not the successful secret output.
            if name == "Result" {
                return types.next().is_some_and(bare);
            }
            if name == "Vec" {
                return types.next().is_some_and(|t| is_byte(t) || bare(t));
            }
            types.any(bare)
        }
        _ => false,
    }
}

/// Borrowed material does not own an allocation to wipe; printing remains checked separately.
pub(super) fn owns_bare(ty: &syn::Type) -> bool {
    match ty {
        syn::Type::Reference(_) => false,
        _ => bare(ty),
    }
}

/// A manual destructor is custody only when it explicitly zeroizes the exact field.
/// This examines the implementation, not a path, type name, comment, or opt-out annotation.
pub(super) fn field_wiped(src: &Source, owner: &str, field: &str) -> bool {
    src.file.items.iter().any(|item| {
        let syn::Item::Impl(i) = item else { return false };
        if !i.trait_.as_ref().is_some_and(|(_, p, _)| p.segments.last().is_some_and(|s| s.ident == "Drop"))
            || !matches!(&*i.self_ty, syn::Type::Path(p) if p.path.segments.last().is_some_and(|s| s.ident == owner)) { return false; }
        i.items.iter().any(|item| {
            let syn::ImplItem::Fn(f) = item else { return false };
            if f.sig.ident != "drop" { return false; }
            let mut found = false;
            for stmt in &f.block.stmts {
                match stmt {
                    syn::Stmt::Item(syn::Item::Use(_)) => {},
                    syn::Stmt::Expr(syn::Expr::MethodCall(call), _) if call.method == "zeroize" && call.args.is_empty() => {
                        let syn::Expr::Field(member) = &*call.receiver else { return false };
                        if !matches!(&*member.base, syn::Expr::Path(p) if p.path.is_ident("self")) { return false; }
                        found |= matches!(&member.member, syn::Member::Named(n) if n == field);
                    },
                    // A conditional, early exit, callback, or unknown operation cannot prove the wipe.
                    _ => return false,
                }
            }
            found
        })
    })
}

fn is_byte(ty: &syn::Type) -> bool {
    matches!(ty, syn::Type::Path(p) if p.path.is_ident("u8"))
}

/// The derives on an item, by name.
fn derives(attrs: &[syn::Attribute]) -> Vec<String> {
    let mut out = Vec::new();
    for a in attrs {
        if !a.path().is_ident("derive") {
            continue;
        }
        if let syn::Meta::List(list) = &a.meta {
            for t in list.tokens.clone() {
                if let TokenTree::Ident(i) = t {
                    out.push(i.to_string());
                }
            }
        }
    }
    out
}

fn item_attrs(item: &syn::Item) -> &[syn::Attribute] {
    match item {
        syn::Item::Struct(s) => &s.attrs,
        syn::Item::Enum(e) => &e.attrs,
        _ => &[],
    }
}

type Finding = (String, String, String);

fn field_rules(src: &Source, out: &mut Vec<Finding>) {
    for item in walk::items(&src.file.items) {
        let d = derives(item_attrs(item));
        let printable = d.iter().any(|x| x == "Debug" || x == "Serialize");
        let debug = d.iter().any(|x| x == "Debug");
        for (ty_name, field) in walk::named_fields(item) {
            if walk::is_cfg_test(&field.attrs) {
                continue;
            }
            let Some(name) = field.ident.as_ref().map(ToString::to_string) else {
                continue;
            };
            if !bare(&field.ty) {
                continue;
            }
            let key = format!("{ty_name}.{name}");
            if credential_named(&name) {
                if owns_bare(&field.ty) && !field_wiped(src, &ty_name, &name) {
                    out.push(("bare-field".into(), src.rel.clone(), key.clone()));
                }
                if printable {
                    out.push(("printable-bare-field".into(), src.rel.clone(), key));
                }
            } else if debug && url_named(&name) {
                out.push(("printable-url".into(), src.rel.clone(), key));
            }
        }
    }
}

fn sig_names_secret(sig: &syn::Signature) -> bool {
    sig.inputs.iter().any(|arg| {
        let toks = walk::tokens(arg);
        walk::idents(&toks).iter().any(|i| i == "Secret")
    })
}

fn returns_bare(sig: &syn::Signature) -> bool {
    match &sig.output {
        syn::ReturnType::Default => false,
        syn::ReturnType::Type(_, ty) => bare(ty),
    }
}

struct FnScan<'a> {
    rel: &'a str,
    owner: Option<String>,
    debug_impl: bool,
    out: Vec<Finding>,
}

impl FnScan<'_> {
    fn judge_fn(&mut self, attrs: &[syn::Attribute], sig: &syn::Signature, body: &syn::Block) {
        if walk::is_cfg_test(attrs) {
            return;
        }
        let name = match &self.owner {
            Some(o) => format!("{o}::{}", sig.ident),
            None => sig.ident.to_string(),
        };
        if sig_names_secret(sig) && returns_bare(sig) {
            self.out
                .push(("unsealed-return".into(), self.rel.into(), name.clone()));
        }
        let toks = walk::tokens(body);
        let ids = walk::idents(&toks);
        let builds_header = ids.iter().enumerate().any(|(i, s)| {
            s == "HeaderValue" && ids.get(i + 1).is_some_and(|n| n.starts_with("from_"))
        });
        if builds_header
            && !ids.iter().any(|s| s == "set_sensitive")
            && ids.iter().any(|s| s == "expose" || credential_named(s))
        {
            self.out
                .push(("header-not-sensitive".into(), self.rel.into(), name.clone()));
        }
        let mut stmts = StmtScan {
            hits: 0,
            sinks: 0,
            guarded: false,
            exposed_aliases: BTreeSet::new(),
            debug_impl: self.debug_impl,
        };
        stmts.visit_block(body);
        for _ in 0..stmts.hits {
            self.out
                .push(("expose-copy".into(), self.rel.into(), name.clone()));
        }
        for _ in 0..stmts.sinks {
            self.out
                .push(("url-in-sink".into(), self.rel.into(), name.clone()));
        }
    }
}

impl<'ast> Visit<'ast> for FnScan<'_> {
    fn visit_item_mod(&mut self, m: &'ast syn::ItemMod) {
        if !walk::is_cfg_test(&m.attrs) {
            syn::visit::visit_item_mod(self, m);
        }
    }
    fn visit_item_impl(&mut self, i: &'ast syn::ItemImpl) {
        if walk::is_cfg_test(&i.attrs) {
            return;
        }
        let ty = walk::idents(&walk::tokens(&i.self_ty)).join("::");
        let prev = self.owner.replace(ty);
        let debug = self.debug_impl;
        self.debug_impl = i
            .trait_
            .as_ref()
            .is_some_and(|(_, p, _)| p.segments.last().is_some_and(|s| s.ident == "Debug"));
        syn::visit::visit_item_impl(self, i);
        self.owner = prev;
        self.debug_impl = debug;
    }
    fn visit_item_fn(&mut self, f: &'ast syn::ItemFn) {
        self.judge_fn(&f.attrs, &f.sig, &f.block);
    }
    fn visit_impl_item_fn(&mut self, f: &'ast syn::ImplItemFn) {
        self.judge_fn(&f.attrs, &f.sig, &f.block);
    }
}

/// Judge the copied expression itself; an unrelated copy elsewhere in the statement is irrelevant.
struct StmtScan {
    hits: usize,
    sinks: usize,
    guarded: bool,
    exposed_aliases: BTreeSet<String>,
    debug_impl: bool,
}

fn exposes(expr: &syn::Expr, aliases: &BTreeSet<String>) -> bool {
    struct Exposed<'a>(bool, &'a BTreeSet<String>);
    impl<'a> Visit<'a> for Exposed<'_> {
        fn visit_expr_path(&mut self, p: &'a syn::ExprPath) {
            self.0 |= p
                .path
                .get_ident()
                .is_some_and(|n| self.1.contains(&n.to_string()));
        }
        fn visit_expr_method_call(&mut self, call: &'a syn::ExprMethodCall) {
            self.0 |= call.method == "expose" || call.method == "expose_own";
            syn::visit::visit_expr_method_call(self, call);
        }
    }
    let mut scan = Exposed(false, aliases);
    scan.visit_expr(expr);
    scan.0
}

fn guarded_constructor(expr: &syn::Expr) -> bool {
    let syn::Expr::Path(p) = expr else {
        return false;
    };
    let names: Vec<_> = p
        .path
        .segments
        .iter()
        .map(|s| s.ident.to_string())
        .collect();
    names.len() >= 2
        && matches!(
            names[names.len() - 2].as_str(),
            "Secret" | "Zeroizing" | "Cred"
        )
        && matches!(names[names.len() - 1].as_str(), "new" | "held" | "captured")
}

fn raw_url_value(expr: &syn::Expr) -> bool {
    match expr {
        syn::Expr::Path(p) => p
            .path
            .segments
            .last()
            .is_some_and(|s| url_named(&s.ident.to_string())),
        syn::Expr::Field(f) => match &f.member {
            syn::Member::Named(n) => url_named(&n.to_string()),
            _ => false,
        },
        // Path-only rendering omits authority credentials and query material.
        syn::Expr::MethodCall(c) if c.method == "path" && c.args.is_empty() => false,
        syn::Expr::Reference(r) => raw_url_value(&r.expr),
        syn::Expr::Paren(p) => raw_url_value(&p.expr),
        _ => false,
    }
}

impl<'ast> Visit<'ast> for StmtScan {
    fn visit_local(&mut self, local: &'ast syn::Local) {
        syn::visit::visit_local(self, local);
        let pattern = match &local.pat {
            syn::Pat::Type(p) => &*p.pat,
            p => p,
        };
        if let syn::Pat::Ident(name) = pattern {
            let exposed = local.init.as_ref().is_some_and(|i| {
                exposes(&i.expr, &self.exposed_aliases)
                    && !matches!(&*i.expr, syn::Expr::Call(c) if guarded_constructor(&c.func))
            });
            if exposed {
                self.exposed_aliases.insert(name.ident.to_string());
            } else {
                self.exposed_aliases.remove(&name.ident.to_string());
            }
        }
    }
    fn visit_expr_block(&mut self, block: &'ast syn::ExprBlock) {
        let old = self.guarded;
        self.guarded = false;
        syn::visit::visit_expr_block(self, block);
        self.guarded = old;
    }
    fn visit_expr_closure(&mut self, closure: &'ast syn::ExprClosure) {
        let old = self.guarded;
        self.guarded = false;
        syn::visit::visit_expr_closure(self, closure);
        self.guarded = old;
    }
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        let old = self.guarded;
        self.guarded = guarded_constructor(&call.func);
        syn::visit::visit_expr_call(self, call);
        self.guarded = old;
    }
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        if self.debug_impl && call.method == "field" && call.args.iter().any(raw_url_value) {
            self.sinks += 1;
        }

        if !self.guarded
            && COPIES.contains(&call.method.to_string().as_str())
            && exposes(&call.receiver, &self.exposed_aliases)
        {
            self.hits += 1;
        }
        syn::visit::visit_expr_method_call(self, call);
    }
    fn visit_macro(&mut self, m: &'ast syn::Macro) {
        let last = m.path.segments.last().map(|s| s.ident.to_string());
        if !last.as_deref().is_some_and(|l| {
            SINKS.contains(&l) || (self.debug_impl && matches!(l, "write" | "writeln"))
        }) {
            return;
        }
        // Logging fields are `name = [%|?] expression`; the field label is not a value.
        let mut pieces = vec![Vec::new()];
        for token in m.tokens.clone() {
            if matches!(&token, TokenTree::Punct(p) if p.as_char() == ',') {
                pieces.push(Vec::new());
            } else {
                pieces.last_mut().expect("one piece").push(token);
            }
        }
        for mut piece in pieces {
            if let Some(eq) = piece
                .iter()
                .position(|t| matches!(t, TokenTree::Punct(p) if p.as_char() == '='))
            {
                piece.drain(..=eq);
            }
            if piece.first().is_some_and(
                |t| matches!(t, TokenTree::Punct(p) if matches!(p.as_char(), '%' | '?')),
            ) {
                piece.remove(0);
            }
            let tokens: proc_macro2::TokenStream = piece.into_iter().collect();
            if syn::parse2::<syn::Expr>(tokens).is_ok_and(|e| raw_url_value(&e)) {
                self.sinks += 1;
            }
        }
    }
    fn visit_item_fn(&mut self, _: &'ast syn::ItemFn) {}
}

fn scan(src: &Source) -> Vec<Finding> {
    let mut out = Vec::new();
    field_rules(src, &mut out);
    let mut fns = FnScan {
        rel: &src.rel,
        owner: None,
        debug_impl: false,
        out: Vec::new(),
    };
    fns.visit_file(&src.file);
    out.extend(fns.out);
    out
}

/// The findings, one per line, grouped by rule.
fn report(findings: &[Finding]) -> String {
    let mut by_rule: BTreeMap<&str, usize> = BTreeMap::new();
    for (rule, _, _) in findings {
        *by_rule.entry(rule).or_insert(0) += 1;
    }
    let mut out = format!("credential typecheck: {} findings\n", findings.len());
    for (rule, n) in &by_rule {
        out.push_str(&format!("  {rule}: {n}\n"));
    }
    let mut lines: Vec<String> = findings
        .iter()
        .map(|(r, f, i)| format!("{r}\t{f}\t{i}"))
        .collect();
    lines.sort();
    for l in lines {
        out.push_str(&l);
        out.push('\n');
    }
    out
}

#[test]
fn credential_typecheck_rejects_violations() {
    let found: Vec<Finding> = walk::production(&["crates"])
        .iter()
        .flat_map(scan)
        .collect();
    let text = report(&found);
    let out = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("credential-typecheck.txt");
    let _ = std::fs::write(&out, &text);
    assert!(found.is_empty(), "{text}");
}

fn planted(text: &str) -> Vec<String> {
    let src = Source {
        rel: "planted.rs".into(),
        file: syn::parse_file(text).expect("parses"),
    };
    scan(&src)
        .into_iter()
        .map(|(r, _, i)| format!("{r} {i}"))
        .collect()
}

#[test]
fn credential_typecheck_finds_each_rule_planted() {
    let found = planted(
        "#[derive(Debug)] struct Cfg { api_key: String, base_url: String, name: String, \
             max_tokens: u32, password: Secret<String> }\n\
         struct Quiet { token: Vec<u8> }\n\
         fn open(s: &Secret<Vec<u8>>) -> Result<String, String> { todo!() }\n\
         fn sealed(s: &SecretRef) -> Secret<Vec<u8>> { todo!() }\n\
         fn copy(s: &Secret<Vec<u8>>, seal: Seal) { let v = s.expose(seal).to_vec(); keep(v); }\n\
         fn hdr(s: &Secret<Vec<u8>>, seal: Seal) -> HeaderValue { HeaderValue::from_bytes(s.expose(seal)).unwrap() }\n\
         fn hdr_ok(s: &Secret<Vec<u8>>, seal: Seal) -> HeaderValue { let mut h = HeaderValue::from_bytes(s.expose(seal)).unwrap(); h.set_sensitive(true); h }\n\
         fn log(spec: &Spec) { tracing::warn!(url = %spec.url, \"fetch\"); }\n",
    );
    let want = [
        "bare-field Cfg.api_key",
        "printable-bare-field Cfg.api_key",
        "printable-url Cfg.base_url",
        "bare-field Quiet.token",
        "unsealed-return open",
        "expose-copy copy",
        "header-not-sensitive hdr",
        "url-in-sink log",
    ];
    for w in want {
        assert!(found.iter().any(|f| f == w), "missing {w}: {found:?}");
    }
    assert_eq!(found.len(), want.len(), "{found:?}");
}

#[test]
fn credential_typecheck_uses_success_types_and_expression_provenance() {
    let found = planted(
        r#"
        struct Labels { token: &'static str }
        struct Mixed { password: (Secret<String>, String) }
        fn error_only(s: &Secret<Vec<u8>>) -> Result<Secret<Vec<u8>>, String> { todo!() }
        fn tuple_leak(s: &Secret<Vec<u8>>) -> (Secret<Vec<u8>>, String) { todo!() }
        fn safe(s: &Secret<Vec<u8>>) { let value = Secret::new(s.expose(pass).to_vec()); }
        fn independent(s: &Secret<Vec<u8>>, public: &str) { pair(s.expose(pass), public.to_owned()); }
        fn alias(s: &Secret<Vec<u8>>) { let view = s.expose(pass); let copy = view.to_vec(); }
        fn closure(s: &Secret<Vec<u8>>) { let value = Secret::new({ let copy = s.expose(pass).to_vec(); leak(copy); Vec::new() }); }
        fn label(spec: &Spec) { tracing::warn!(url = %spec.safe_label, "fetch"); }
        fn path(uri: &Uri) { tracing::warn!(path = %uri.path(), "request"); }
        fn raw(spec: &Spec) { tracing::warn!(destination = %spec.url, "fetch"); }
    "#,
    );
    assert_eq!(
        found,
        [
            "bare-field Mixed.password",
            "unsealed-return tuple_leak",
            "expose-copy alias",
            "expose-copy closure",
            "url-in-sink raw"
        ]
    );
}

#[test]
fn credential_typecheck_requires_the_exact_unconditional_drop_wipe() {
    let found = planted(
        r#"
        struct Guarded { password: String }
        impl Drop for Guarded { fn drop(&mut self) { self.password.zeroize(); } }
        struct Wrong { password: String, other: String }
        impl Drop for Wrong { fn drop(&mut self) { self.other.zeroize(); } }
        struct Early { password: String }
        impl Drop for Early { fn drop(&mut self) { if flag() { return; } self.password.zeroize(); } }
        struct Conditional { password: String }
        impl Drop for Conditional { fn drop(&mut self) { if flag() { self.password.zeroize(); } } }
    "#,
    );
    assert_eq!(
        found,
        [
            "bare-field Wrong.password",
            "bare-field Early.password",
            "bare-field Conditional.password"
        ]
    );
}

#[test]
fn credential_typecheck_rejects_raw_urls_in_manual_debug() {
    let found = planted(
        r#"
        struct Bad { url: String }
        impl Debug for Bad { fn fmt(&self, f: &mut Formatter) -> Result { f.debug_struct("Bad").field("url", &self.url).finish() } }
        struct Safe { url: String }
        impl Debug for Safe { fn fmt(&self, f: &mut Formatter) -> Result { f.debug_struct("Safe").field("url", &"<redacted>").finish() } }
    "#,
    );
    assert_eq!(found, ["url-in-sink Bad::fmt"]);
}
