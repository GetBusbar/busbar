// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A 1.5.x CONFIG STILL READS (the config grammar is additive-only). Two rules over core's source:
//!
//! - every config struct core still declares keeps every key the frozen 1.5.3 snapshot
//!   (`crates/busbar-kernel/src/config/config-schema.snapshot.json`) records for it;
//! - the admin `config/apply` and `config/validate` verbs parse a document with the boot parser,
//!   so a config the file accepts is a config the admin API accepts.

use std::collections::{BTreeMap, BTreeSet};

use proc_macro2::TokenTree;
use syn::visit::Visit;

use crate::walk;

const SNAPSHOT: &str = "crates/busbar-kernel/src/config/config-schema.snapshot.json";

/// The 1.5.x top-level sections whose grammar a plane owns: each is accepted at boot by the linked
/// plane's own declaration (`PlaneDeclaration`, `config/prepass.rs`), not by a `DeployCfg` field,
/// so the plane's repo keeps its grammar and the oracle's config cells prove it reads.
const PLANE_SECTIONS: &[(&str, &str)] = &[
    ("DeployCfg", "agent_push"),
    ("DeployCfg", "agents"),
    ("DeployCfg", "decisions"),
    ("DeployCfg", "mcp"),
    ("DeployCfg", "streams"),
    ("DeployCfg", "tools"),
];

/// Core's crates: a config type a plugin owns is that plugin's to keep.
const CORE_SRC: &[&str] = &[
    "crates/busbar-kernel/src",
    "crates/busbar-contract/src",
    "crates/busbar/src",
    "crates/busbar-core-admin/src",
    "crates/busbar-core-oauth2/src",
    "crates/busbar-core-connector/src",
];

fn rename_all(rule: &str, field: &str) -> String {
    let words: Vec<&str> = field.split('_').filter(|w| !w.is_empty()).collect();
    let cap = |w: &str| {
        let mut c = w.chars();
        c.next()
            .map(|f| f.to_ascii_uppercase().to_string() + c.as_str())
            .unwrap_or_default()
    };
    match rule {
        "kebab-case" => field.replace('_', "-"),
        "lowercase" => field.to_ascii_lowercase(),
        "UPPERCASE" | "SCREAMING_SNAKE_CASE" => field.to_ascii_uppercase(),
        "SCREAMING-KEBAB-CASE" => field.to_ascii_uppercase().replace('_', "-"),
        "camelCase" => words
            .iter()
            .enumerate()
            .map(|(i, w)| if i == 0 { (*w).to_string() } else { cap(w) })
            .collect(),
        "PascalCase" => words.iter().map(|w| cap(w)).collect(),
        _ => field.to_string(),
    }
}

/// Every string literal inside the `#[serde(..)]` attributes of `attrs`.
fn serde_strings(attrs: &[syn::Attribute]) -> Vec<String> {
    attrs
        .iter()
        .filter(|a| a.path().is_ident("serde"))
        .flat_map(|a| walk::tokens(&a.meta))
        .filter_map(|t| match t {
            TokenTree::Literal(l) => {
                let s = l.to_string();
                s.strip_prefix('"')
                    .and_then(|s| s.strip_suffix('"'))
                    .map(str::to_string)
            }
            _ => None,
        })
        .collect()
}

/// The `rename_all` rule of a struct's `#[serde(..)]`, if any.
fn rename_rule(attrs: &[syn::Attribute]) -> Option<String> {
    for a in attrs.iter().filter(|a| a.path().is_ident("serde")) {
        let toks = walk::tokens(&a.meta);
        for (i, t) in toks.iter().enumerate() {
            if matches!(t, TokenTree::Ident(id) if id == "rename_all") {
                if let Some(TokenTree::Literal(l)) = toks.get(i + 2) {
                    let s = l.to_string();
                    return Some(s.trim_matches('"').to_string());
                }
            }
        }
    }
    None
}

/// Every key each struct named `name` accepts, over every declaration of that name in core.
fn accepted_keys(sources: &[walk::Source]) -> BTreeMap<String, BTreeSet<String>> {
    let mut out: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for src in sources {
        for item in walk::items(&src.file.items) {
            let syn::Item::Struct(s) = item else { continue };
            let rule = rename_rule(&s.attrs);
            let keys = out.entry(s.ident.to_string()).or_default();
            let syn::Fields::Named(named) = &s.fields else {
                continue;
            };
            for f in &named.named {
                let Some(id) = &f.ident else { continue };
                let rust = id.to_string();
                let rust = rust.strip_prefix("r#").unwrap_or(&rust).to_string();
                keys.insert(match &rule {
                    Some(r) => rename_all(r, &rust),
                    None => rust.clone(),
                });
                keys.insert(rust);
                keys.extend(serde_strings(&f.attrs));
            }
        }
    }
    out
}

#[test]
fn every_core_config_struct_keeps_every_key_the_frozen_snapshot_records() {
    let text = std::fs::read_to_string(walk::repo().join(SNAPSHOT)).expect("the snapshot");
    let snapshot: serde_json::Value = serde_json::from_str(&text).expect("the snapshot is JSON");
    let types = snapshot["types"].as_object().expect("`types`");
    let declared = accepted_keys(&walk::production(CORE_SRC));
    let mut checked = 0usize;
    let mut removed = Vec::new();
    for (name, ty) in types {
        if ty["kind"] != "struct" {
            continue;
        }
        let Some(keys) = declared.get(name) else {
            continue;
        };
        checked += 1;
        for field in ty["fields"].as_object().expect("`fields`").keys() {
            if !keys.contains(field) && !PLANE_SECTIONS.contains(&(name.as_str(), field.as_str())) {
                removed.push(format!("{name}.{field}"));
            }
        }
    }
    assert!(
        checked > 0,
        "no snapshot struct is declared in core: the walk is wrong"
    );
    assert!(
        removed.is_empty(),
        "a 1.5.x config key core no longer accepts (the grammar is additive-only): {removed:?}"
    );
}

struct Calls<'a> {
    target: &'a str,
    in_fn: Option<String>,
    callers: BTreeSet<String>,
}

impl<'ast> Visit<'ast> for Calls<'_> {
    fn visit_item_fn(&mut self, f: &'ast syn::ItemFn) {
        let outer = self.in_fn.replace(f.sig.ident.to_string());
        syn::visit::visit_item_fn(self, f);
        self.in_fn = outer;
    }
    fn visit_expr_call(&mut self, c: &'ast syn::ExprCall) {
        if let syn::Expr::Path(p) = &*c.func {
            if p.path
                .segments
                .last()
                .is_some_and(|s| s.ident == self.target)
            {
                if let Some(f) = &self.in_fn {
                    self.callers.insert(f.clone());
                }
            }
        }
        syn::visit::visit_expr_call(self, c);
    }
}

fn callers_of(rel: &str, target: &str) -> BTreeSet<String> {
    let src = walk::one(rel);
    let mut v = Calls {
        target,
        in_fn: None,
        callers: BTreeSet::new(),
    };
    v.visit_file(&src.file);
    v.callers
}

#[test]
fn the_admin_config_verbs_parse_with_the_boot_parser() {
    let admin = callers_of(
        "crates/busbar-core-admin/src/v1/json/handlers.rs",
        "deploy_from_deserializer",
    );
    for verb in ["apply_config", "validate_config"] {
        assert!(
            admin.contains(verb),
            "admin `{verb}` does not parse with `deploy_from_deserializer`: {admin:?}"
        );
    }
    let boot = callers_of(
        "crates/busbar-kernel/src/config/prepass.rs",
        "deploy_from_deserializer",
    );
    assert!(
        boot.contains("deploy_from_yaml_str"),
        "the boot parser `deploy_from_yaml_str` does not go through `deploy_from_deserializer`: {boot:?}"
    );
}
