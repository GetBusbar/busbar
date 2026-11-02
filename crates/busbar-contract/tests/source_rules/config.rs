// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A 1.5.x CONFIG STILL READS (the config grammar is additive-only). Two rules over core's source:

use std::collections::{BTreeMap, BTreeSet};

use proc_macro2::TokenTree;
use syn::visit::Visit;

use crate::walk;

const SNAPSHOT: &str = "crates/busbar-kernel/src/config/config-schema.snapshot.json";

/// The 1.5.x top-level sections whose grammar a plane owns: each is accepted at boot by the linked
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

/// Match the plane's actual descriptor against the frozen field's type, recursively.
fn descriptor_shape_matches(
    shape: &busbar_contract::provider_keys::Shape,
    rust: &str,
    types: &serde_json::Map<String, serde_json::Value>,
) -> bool {
    use busbar_contract::provider_keys::Shape;
    match (shape, rust) {
        (Shape::Str, "String")
        | (Shape::Bool, "bool")
        | (Shape::StrMap, "HashMap<String, String>") => true,
        (Shape::List(inner), text) if text.starts_with("Vec<") && text.ends_with('>') => {
            descriptor_shape_matches(inner, &text[4..text.len() - 1], types)
        }
        (Shape::OneOf(words), name) => types.get(name).is_some_and(|ty| {
            if ty["kind"] != "enum" {
                return false;
            }
            let mut actual = words.clone();
            actual.sort();
            let mut expected: Vec<String> = ty["variants"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| s.as_str().unwrap().to_string())
                .collect();
            expected.sort();
            actual == expected
        }),
        (Shape::Table(table), name) => types.get(name).is_some_and(|ty| {
            if ty["kind"] != "struct"
                || table.name.as_deref() != Some(name)
                || ty["deny_unknown_fields"].as_bool() != Some(table.deny_unknown)
            {
                return false;
            }
            let fields = ty["fields"].as_object().unwrap();
            table.keys.len() == fields.len()
                && table.keys.iter().all(|key| {
                    fields.get(&key.name).is_some_and(|field| {
                        field["optional"].as_bool() == Some(!key.required)
                            && descriptor_shape_matches(
                                &key.shape,
                                field["type"].as_str().unwrap(),
                                types,
                            )
                    })
                })
        }),
        _ => false,
    }
}

/// The fixture is the actual exported plane descriptor, bound to source provenance and
fn descriptor_provider_entries(
    sources: &[walk::Source],
    types: &serde_json::Map<String, serde_json::Value>,
) -> BTreeMap<String, BTreeSet<String>> {
    let fixture: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(walk::repo().join("testing/config/provider-keys-llm.json"))
            .unwrap(),
    )
    .unwrap();
    let text = fixture["descriptor_text"].as_str().unwrap();
    let provenance = &fixture["provenance"];
    assert_eq!(
        busbar_contract::sha256_hex(text.as_bytes()),
        provenance["sha256"].as_str().unwrap()
    );
    assert_eq!(
        provenance["repository"],
        "https://git.getbusbar.dev/GetBusbar/busbar-plane-llm"
    );
    assert_eq!(provenance["path"], "plane-llm/src/meta.rs");
    assert_eq!(provenance["constant"], "PROVIDER_KEYS");
    assert_eq!(provenance["commit"].as_str().unwrap().len(), 40);
    let descriptor = busbar_contract::provider_keys::decode(text.as_bytes())
        .expect("the actual plane descriptor decodes");
    let parser = sources
        .iter()
        .find(|s| s.rel == "crates/busbar-kernel/src/config/providers.rs")
        .unwrap();

    let core: BTreeSet<String> = parser
        .file
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Const(c) if c.ident == "CORE_PROVIDER_KEYS" => Some(walk::tokens(&c.expr)),
            _ => None,
        })
        .flatten()
        .filter_map(|t| match t {
            TokenTree::Literal(l) => Some(l.to_string().trim_matches('"').to_string()),
            _ => None,
        })
        .collect();
    assert!(core.contains("base_url"));
    let fields = accepted_keys(sources);
    let mut entries = BTreeMap::new();
    for item in &parser.file.items {
        let syn::Item::Macro(m) = item else { continue };
        if !m.mac.path.is_ident("provider_entry") {
            continue;
        }
        let args: Vec<String> = m
            .mac
            .tokens
            .clone()
            .into_iter()
            .filter_map(|t| match t {
                TokenTree::Ident(id) => Some(id.to_string()),
                _ => None,
            })
            .collect();
        if args.len() != 4 || !fields.get(&args[0]).is_some_and(|f| f.contains("options")) {
            continue;
        }
        let table = match args[3].as_str() {
            "Catalog" => &descriptor.catalog,
            "Deployment" => &descriptor.deployment,
            "Entry" => &descriptor.entry,
            _ => continue,
        };
        let Some(frozen) = types.get(&args[0]).and_then(|t| t["fields"].as_object()) else {
            continue;
        };
        let keys = table
            .keys
            .iter()
            .filter(|key| !core.contains(&key.name))
            .filter(|key| {
                frozen.get(&key.name).is_some_and(|field| {
                    field["optional"].as_bool() == Some(!key.required)
                        && descriptor_shape_matches(
                            &key.shape,
                            field["type"].as_str().unwrap(),
                            types,
                        )
                })
            })
            .map(|key| key.name.clone())
            .collect();
        entries.insert(args[0].clone(), keys);
    }
    let syntax = &parser.file;
    let tokens = quote::quote!(#syntax).to_string();
    assert!(tokens.contains("door :: provider_keys"));
    assert!(tokens.contains("next_value_seed (ValueSeed :: field (field))"));
    assert!(tokens.contains("options . insert"));
    assert!(tokens.contains("entry . options = options"));
    entries
}

fn removed_config_keys(
    types: &serde_json::Map<String, serde_json::Value>,
    declared: &BTreeMap<String, BTreeSet<String>>,
    delegated: &BTreeMap<String, BTreeSet<String>>,
) -> Vec<String> {
    let mut removed = Vec::new();
    for (name, ty) in types {
        if ty["kind"] != "struct" {
            continue;
        }
        let Some(keys) = declared.get(name) else {
            continue;
        };
        for field in ty["fields"].as_object().unwrap().keys() {
            if !keys.contains(field)
                && !PLANE_SECTIONS.contains(&(name.as_str(), field.as_str()))
                && !delegated.get(name).is_some_and(|keys| keys.contains(field))
            {
                removed.push(format!("{name}.{field}"));
            }
        }
    }
    removed
}

#[test]
fn descriptor_delegation_does_not_hide_removal_of_unrelated_core_fields() {
    let snapshot: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(walk::repo().join(SNAPSHOT)).unwrap())
            .unwrap();
    let types = snapshot["types"].as_object().unwrap();
    let sources = walk::production(CORE_SRC);
    let mut declared = accepted_keys(&sources);
    let delegated = descriptor_provider_entries(&sources, types);
    for (name, field) in [
        ("ProviderDef", "base_url"),
        ("ProviderDeploy", "token_url"),
        ("HealthCfg", "mode"),
    ] {
        assert!(declared.get_mut(name).unwrap().remove(field));
        assert!(
            removed_config_keys(types, &declared, &delegated).contains(&format!("{name}.{field}"))
        );
    }

    assert!(!descriptor_shape_matches(
        &busbar_contract::provider_keys::Shape::Str,
        "bool",
        types
    ));
}

#[test]
fn every_core_config_struct_keeps_every_key_the_frozen_snapshot_records() {
    let text = std::fs::read_to_string(walk::repo().join(SNAPSHOT)).expect("the snapshot");
    let snapshot: serde_json::Value = serde_json::from_str(&text).expect("the snapshot is JSON");
    let types = snapshot["types"].as_object().expect("`types`");
    let sources = walk::production(CORE_SRC);
    let declared = accepted_keys(&sources);
    let descriptor_entries = descriptor_provider_entries(&sources, types);
    let checked = types
        .iter()
        .filter(|(name, ty)| ty["kind"] == "struct" && declared.contains_key(*name))
        .count();
    let removed = removed_config_keys(types, &declared, &descriptor_entries);
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
