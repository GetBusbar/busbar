// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SECRET MATERIAL IS `Secret<T>`, NEVER LOGGED, NEVER SERVED (Part 2 #53, #54). Three rules over

use proc_macro2::{Delimiter, TokenTree};
use syn::visit::Visit;

use crate::walk::{self, Source};

const STRONG_NEEDLES: &[&str] = &[
    "api_key",
    "api_key_plaintext",
    "client_secret",
    "private_key",
    "signing_key",
    "access_token",
    "subject_token",
    "api_secret",
    "secret_access_key",
    "password",
    "bearer",
    "credential_secret",
];
const CONTEXT_NEEDLES: &[&str] = &["secret", "token", "credential", "credentials"];
const CONTEXT_STRUCTS: &[&str] = &[
    "Key", "Cred", "Token", "Secret", "Auth", "Lease", "Issued", "Mint",
];
/// `field` carries `needle` as an `_`-delimited tail behind at least one character.
fn qualified(field: &str, needle: &str) -> bool {
    field.len() > needle.len() + 1
        && field.ends_with(needle)
        && field.as_bytes()[field.len() - needle.len() - 1] == b'_'
}

fn tailmatch(field: &str, needle: &str) -> bool {
    field == needle || qualified(field, needle)
}

/// The needle a field's name hits, if it names secret material.
fn secret_needle(field: &str, ty_name: &str) -> Option<&'static str> {
    if let Some(n) = STRONG_NEEDLES.iter().copied().find(|n| tailmatch(field, n)) {
        return Some(n);
    }
    if let Some(n) = CONTEXT_NEEDLES
        .iter()
        .copied()
        .find(|n| qualified(field, n))
    {
        return Some(n);
    }
    let in_context = CONTEXT_STRUCTS.iter().any(|c| ty_name.contains(c));
    CONTEXT_NEEDLES
        .iter()
        .find(|n| **n == field && in_context)
        .copied()
}

fn bare_secret_fields(src: &Source) -> Vec<String> {
    let mut out = Vec::new();
    for item in walk::items(&src.file.items) {
        for (ty_name, field) in walk::named_fields(item) {
            if walk::is_cfg_test(&field.attrs) {
                continue;
            }
            let Some(name) = field.ident.as_ref().map(ToString::to_string) else {
                continue;
            };
            if secret_needle(&name, &ty_name).is_none() {
                continue;
            }
            if crate::credential_typecheck::owns_bare(&field.ty)
                && !crate::credential_typecheck::field_wiped(src, &ty_name, &name)
            {
                out.push(format!(
                    "{}:{}: {ty_name}.{name} holds secret material bare; type it `Secret<..>` or `SecretRef`",
                    src.rel,
                    walk::line_of(field)
                ));
            }
        }
    }
    out
}

#[test]
fn a_secret_named_field_is_never_a_bare_string() {
    let findings: Vec<String> = walk::production(&["crates"])
        .iter()
        .flat_map(bare_secret_fields)
        .collect();
    assert!(findings.is_empty(), "{}", findings.join("\n"));
}

#[test]
fn a_bare_secret_field_is_found() {
    let src = Source {
        rel: "planted.rs".into(),
        file: syn::parse_file(
            "struct Cfg { api_key: String, password: Secret<String>, name: String }\n\
             struct IssuedKey { token: Vec<u8> }\n\
             struct Other { token: String }\n",
        )
        .expect("parses"),
    };
    let found = bare_secret_fields(&src);
    assert!(found.iter().any(|f| f.contains("Cfg.api_key")), "{found:?}");
    assert!(
        found.iter().any(|f| f.contains("IssuedKey.token")),
        "{found:?}"
    );
    assert_eq!(found.len(), 2, "{found:?}");
}

const SINK_PATHS: &[&str] = &["tracing", "log"];
const SINK_MACROS: &[&str] = &[
    "println",
    "eprintln",
    "print",
    "dbg",
    "panic",
    "info",
    "warn",
    "error",
    "debug",
    "trace",
    "counter",
    "gauge",
    "histogram",
];
const SINK_NAMES: &[&str] = &[
    "metrics_emit",
    "journal_append",
    "AuditRecord",
    "PlaneAuditLog",
];

fn names_sink(toks: &[TokenTree]) -> bool {
    toks.iter().enumerate().any(|(i, t)| {
        let TokenTree::Ident(id) = t else {
            return false;
        };
        let s = id.to_string();
        let next_punct =
            |c: char| matches!(toks.get(i + 1), Some(TokenTree::Punct(p)) if p.as_char() == c);
        (SINK_PATHS.contains(&s.as_str()) && next_punct(':'))
            || (SINK_MACROS.contains(&s.as_str()) && next_punct('!'))
            || SINK_NAMES.contains(&s.as_str())
    })
}

fn exposes(toks: &[TokenTree]) -> bool {
    toks.iter().enumerate().any(|(i, t)| {
        matches!(t, TokenTree::Ident(id) if id == "expose")
            && i > 0
            && matches!(&toks[i - 1], TokenTree::Punct(p) if p.as_char() == '.')
    })
}

/// A statement that holds a block of statements is judged statement by statement inside it.
fn holds_statements(toks: &[TokenTree]) -> bool {
    toks.iter().any(|t| {
        matches!(t, TokenTree::Group(g) if g.delimiter() == Delimiter::Brace
            && g.stream().into_iter().any(|x| matches!(x, TokenTree::Punct(p) if p.as_char() == ';')))
    })
}

struct SinkScan<'a> {
    rel: &'a str,
    out: Vec<String>,
}

impl<'ast> Visit<'ast> for SinkScan<'_> {
    fn visit_item_mod(&mut self, m: &'ast syn::ItemMod) {
        if !walk::is_cfg_test(&m.attrs) {
            syn::visit::visit_item_mod(self, m);
        }
    }
    fn visit_item_fn(&mut self, f: &'ast syn::ItemFn) {
        if !walk::is_cfg_test(&f.attrs) {
            syn::visit::visit_item_fn(self, f);
        }
    }
    fn visit_impl_item_fn(&mut self, f: &'ast syn::ImplItemFn) {
        if !walk::is_cfg_test(&f.attrs) {
            syn::visit::visit_impl_item_fn(self, f);
        }
    }
    fn visit_stmt(&mut self, s: &'ast syn::Stmt) {
        let toks = walk::tokens(s);
        if !holds_statements(&toks) && exposes(&toks) && names_sink(&toks) {
            self.out.push(format!("{}:{}", self.rel, walk::line_of(s)));
        }
        syn::visit::visit_stmt(self, s);
    }
}

fn exposed_into_a_sink(src: &Source) -> Vec<String> {
    let mut scan = SinkScan {
        rel: &src.rel,
        out: Vec::new(),
    };
    scan.visit_file(&src.file);
    scan.out
}

#[test]
fn an_exposed_secret_never_reaches_a_log_metric_or_audit_sink() {
    let findings: Vec<String> = walk::production(&["crates"])
        .iter()
        .flat_map(exposed_into_a_sink)
        .collect();
    assert!(
        findings.is_empty(),
        "`.expose(..)` in the same statement as a sink:\n{}",
        findings.join("\n")
    );
}

#[test]
fn an_exposed_secret_in_a_sink_is_found() {
    let src = Source {
        rel: "planted.rs".into(),
        file: syn::parse_file(
            "fn a(s: &Secret<String>, seal: Seal) {\n\
                 tracing::info!(key = s.expose(seal));\n\
                 let v = s.expose(seal);\n\
                 if true { send(v); }\n\
             }\n",
        )
        .expect("parses"),
    };
    let found = exposed_into_a_sink(&src);
    assert_eq!(found, vec!["planted.rs:2".to_string()]);
}

/// The types that hold an operator bag as data: a map, a JSON/YAML value, text or bytes.
const BAG_TYPES: &[&str] = &[
    "HashMap", "BTreeMap", "IndexMap", "Map", "Value", "RawValue", "String", "str", "Bytes",
];
/// Borrowed frames own no allocation. Guarded encoded bytes retain custody, while a map or
/// dynamic JSON tree remains a readable settings bag even if a wrapper wipes it on drop.
fn owns_settings_bag(ty: &syn::Type, guarded: bool) -> bool {
    use syn::{GenericArgument, PathArguments, Type};
    match ty {
        Type::Reference(_) => false,
        Type::Paren(p) => owns_settings_bag(&p.elem, guarded),
        Type::Group(g) => owns_settings_bag(&g.elem, guarded),
        Type::Tuple(t) => t.elems.iter().any(|t| owns_settings_bag(t, guarded)),
        Type::Path(p) => {
            let Some(last) = p.path.segments.last() else {
                return false;
            };
            let name = last.ident.to_string();
            if BAG_TYPES.contains(&name.as_str()) {
                return !(guarded && matches!(name.as_str(), "String" | "str" | "Bytes"));
            }
            let PathArguments::AngleBracketed(args) = &last.arguments else {
                return false;
            };
            let guarded = guarded || matches!(name.as_str(), "Secret" | "Zeroizing");
            args.args.iter().any(|arg| match arg {
                GenericArgument::Type(Type::Path(p)) if name == "Vec" && p.path.is_ident("u8") => {
                    !guarded
                }
                GenericArgument::Type(t) => owns_settings_bag(t, guarded),
                _ => false,
            })
        }
        _ => false,
    }
}

fn raw_settings_bags(src: &Source) -> Vec<String> {
    let mut out = Vec::new();
    for item in walk::items(&src.file.items) {
        for (ty_name, field) in walk::named_fields(item) {
            let Some(name) = field.ident.as_ref().map(ToString::to_string) else {
                continue;
            };
            let lower = name.to_ascii_lowercase();
            if lower != "settings" && !lower.ends_with("_settings") {
                continue;
            }
            let bag = owns_settings_bag(&field.ty, false);
            let line = field.ident.as_ref().map_or(0, walk::line_of);
            if bag {
                out.push(format!(
                    "{}:{line}: {ty_name}.{name} carries a raw settings bag",
                    src.rel
                ));
            }
        }
    }
    out
}

#[test]
fn no_struct_carries_a_raw_settings_bag() {
    let findings: Vec<String> = walk::production(&["crates"])
        .iter()
        .flat_map(raw_settings_bags)
        .collect();
    assert!(
        findings.is_empty(),
        "settings cross the host as opaque carriers or guarded encoded bytes; comments cannot exempt a readable bag:\n{}",
        findings.join("\n")
    );
}

#[test]
fn settings_comments_cannot_exempt_raw_bags_and_guards_apply_to_bytes_only() {
    let text = "struct View {\n    settings: serde_json::Value,\n}\n\
                struct Req {\n    // settings-leak-lint: allow — an inbound request body, never served\n    settings: serde_json::Value,\n}\n\
                struct Bare {\n    // settings-leak-lint: allow\n    hook_settings: HashMap<String, String>,\n}\n\
                struct Typed {\n    settings: HookSettings,\n}\n";
    let src = Source {
        rel: "planted.rs".into(),
        file: syn::parse_file(text).expect("parses"),
    };
    let found = raw_settings_bags(&src);
    assert_eq!(found.len(), 3, "{found:?}");
    assert!(found[0].contains("View.settings"), "{found:?}");
    assert!(found[1].contains("Req.settings"), "{found:?}");
    assert!(found[2].contains("Bare.hook_settings"), "{found:?}");
    assert!(!owns_settings_bag(
        &syn::parse_quote!(zeroize::Zeroizing<Vec<u8>>),
        false
    ));
    assert!(!owns_settings_bag(&syn::parse_quote!(&str), false));
    assert!(owns_settings_bag(
        &syn::parse_quote!(zeroize::Zeroizing<serde_json::Value>),
        false
    ));
    assert!(owns_settings_bag(
        &syn::parse_quote!((zeroize::Zeroizing<Vec<u8>>, Vec<u8>)),
        false
    ));
}
