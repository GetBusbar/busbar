// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CREDENTIAL TYPECHECK (CREDENTIAL-LOCKDOWN Phase 0, P0.1): a mechanical, type-level
//! inventory of every place core's production source holds, prints or copies credential material
//! outside the sealed types. The run prints what it finds and passes; chip row 9 makes it assert
//! that it finds nothing. Each rule's own planted case below is strict, so a rule that stops
//! finding what it names fails.
//!
//! The rules (the finding key is `rule<TAB>file<TAB>item`, no line numbers, so an unrelated edit
//! moves nothing):
//!
//! - `bare-field`: a field named for credential material is a bare string or byte holder (the
//!   strict rule in `secrets.rs` exempts a reviewed few; the inventory lists them all).
//! - `printable-bare-field`: the same field in a type that derives `Debug` or `Serialize`, one
//!   `{:?}` or one serialisation away from a log or a response.
//! - `printable-url`: a `*url`/`dsn` text field in a type that derives `Debug` or `Serialize`; a
//!   URL can carry userinfo or a query token.
//! - `unsealed-return`: a function that takes a `Secret`/`SecretRef` and returns bare text or
//!   bytes: plaintext leaves the sealed type there.
//! - `expose-copy`: an `.expose(..)` whose result is copied into an owned, unzeroized buffer in
//!   the same statement (`.to_vec()`, `.to_string()`, `.to_owned()`, `String::from`, `Vec::from`).
//! - `header-not-sensitive`: a function builds a `HeaderValue` from exposed or credential-named
//!   material and never calls `set_sensitive`.
//! - `url-in-sink`: a log or print macro names a `*url`/`dsn` value.
//!
//! The report of each run is written to `$CARGO_TARGET_TMPDIR/credential-typecheck.txt` and
//! printed on stdout.

use std::collections::BTreeMap;

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
fn bare(ty: &syn::Type) -> bool {
    let toks = walk::tokens(ty);
    let ids = walk::idents(&toks);
    if ids.iter().any(|i| {
        matches!(
            i.as_str(),
            "Secret" | "SecretRef" | "Zeroizing" | "Redacted"
        )
    }) {
        return false;
    }
    ids.iter().enumerate().any(|(i, s)| {
        s.contains("String")
            || s == "str"
            || s == "Bytes"
            || s == "BytesMut"
            || (s == "Vec" && ids.get(i + 1).is_some_and(|n| n == "u8"))
    }) || toks.iter().any(|t| {
        matches!(t, TokenTree::Group(g) if g.delimiter() == proc_macro2::Delimiter::Bracket
            && matches!(g.stream().into_iter().next(), Some(TokenTree::Ident(u)) if u == "u8"))
    })
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
                out.push(("bare-field".into(), src.rel.clone(), key.clone()));
                if printable {
                    out.push(("printable-bare-field".into(), src.rel.clone(), key));
                }
            } else if printable && url_named(&name) {
                out.push(("printable-url".into(), src.rel.clone(), key));
            }
        }
    }
}

fn sig_names_secret(sig: &syn::Signature) -> bool {
    sig.inputs.iter().any(|arg| {
        let toks = walk::tokens(arg);
        walk::idents(&toks)
            .iter()
            .any(|i| i == "Secret" || i == "SecretRef")
    })
}

fn returns_bare(sig: &syn::Signature) -> bool {
    match &sig.output {
        syn::ReturnType::Default => false,
        syn::ReturnType::Type(_, ty) => bare(ty),
    }
}

/// The identifier just before `.name` at `toks[i]`.
fn method_at(toks: &[TokenTree], i: usize, names: &[&str]) -> bool {
    matches!(&toks[i], TokenTree::Ident(id) if names.contains(&id.to_string().as_str()))
        && i > 0
        && matches!(&toks[i - 1], TokenTree::Punct(p) if p.as_char() == '.')
}

struct FnScan<'a> {
    rel: &'a str,
    owner: Option<String>,
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
        let mut stmts = StmtScan { hits: 0, sinks: 0 };
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
        syn::visit::visit_item_impl(self, i);
        self.owner = prev;
    }
    fn visit_item_fn(&mut self, f: &'ast syn::ItemFn) {
        self.judge_fn(&f.attrs, &f.sig, &f.block);
    }
    fn visit_impl_item_fn(&mut self, f: &'ast syn::ImplItemFn) {
        self.judge_fn(&f.attrs, &f.sig, &f.block);
    }
}

/// Per statement (innermost): an exposed value copied out, and a sink macro naming a URL.
struct StmtScan {
    hits: usize,
    sinks: usize,
}

impl<'ast> Visit<'ast> for StmtScan {
    fn visit_stmt(&mut self, s: &'ast syn::Stmt) {
        let toks = walk::tokens(s);
        let nested = toks.iter().any(|t| {
            matches!(t, TokenTree::Group(g) if g.delimiter() == proc_macro2::Delimiter::Brace
                && g.stream().into_iter().any(|x| matches!(x, TokenTree::Punct(p) if p.as_char() == ';')))
        });
        if !nested {
            let exposes = (0..toks.len()).any(|i| method_at(&toks, i, &["expose"]));
            let copies = (0..toks.len()).any(|i| method_at(&toks, i, COPIES))
                || walk::idents(&toks)
                    .windows(2)
                    .any(|w| (w[0] == "String" || w[0] == "Vec") && w[1] == "from");
            if exposes && copies {
                self.hits += 1;
            }
        }
        syn::visit::visit_stmt(self, s);
    }
    fn visit_macro(&mut self, m: &'ast syn::Macro) {
        let last = m.path.segments.last().map(|s| s.ident.to_string());
        if last.as_deref().is_some_and(|l| SINKS.contains(&l)) {
            let toks: Vec<TokenTree> = walk::tokens(&m.tokens);
            if walk::idents(&toks).iter().any(|i| url_named(i)) {
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
fn credential_typecheck_reports_what_it_finds() {
    let found: Vec<Finding> = walk::production(&["crates"])
        .iter()
        .flat_map(scan)
        .collect();
    let text = report(&found);
    let out = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("credential-typecheck.txt");
    let _ = std::fs::write(&out, &text);
    println!("{text}");
}

fn planted(text: &str) -> Vec<String> {
    let src = Source {
        rel: "planted.rs".into(),
        text: text.into(),
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
         fn open(s: &SecretRef) -> Result<String, String> { todo!() }\n\
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
