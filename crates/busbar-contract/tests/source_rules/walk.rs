// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Reading core's production source as parsed Rust: the files, the items a test build alone
//! compiles, and the tokens of an item.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use proc_macro2::{TokenStream, TokenTree};
use quote::ToTokens;

/// The repository root.
pub fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// One parsed production source file, by its repo-relative path.
pub struct Source {
    pub rel: String,
    pub text: String,
    pub file: syn::File,
}

/// A crate directory under `crates/` that holds a plugin, not core. Core never tests plugins.
pub fn is_plugin_crate(rel: &str) -> bool {
    rel.starts_with("crates/busbar-plane-")
}

/// A path that is test, bench or example code by where it lives.
pub fn is_test_path(rel: &str) -> bool {
    rel.contains("/tests/")
        || rel.ends_with("/tests.rs")
        || rel.ends_with("_tests.rs")
        || rel.contains("/benches/")
        || rel.contains("/examples/")
}

/// `#[cfg(test)]` (alone, or inside `all(..)` without `not`).
pub fn is_cfg_test(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|a| {
        if !a.path().is_ident("cfg") {
            return false;
        }
        let syn::Meta::List(list) = &a.meta else {
            return false;
        };
        let s = list.tokens.to_string();
        s == "test" || (s.starts_with("all") && s.contains("test") && !s.contains("not"))
    })
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let p = entry.path();
        if p.is_dir() {
            if p.file_name().is_some_and(|n| n == "target") {
                continue;
            }
            rust_files(&p, out);
        } else if p.extension().is_some_and(|e| e == "rs") {
            out.push(p);
        }
    }
}

/// The files `file` declares as `#[cfg(test)] mod x;`, as repo-relative paths.
fn cfg_test_module_files(rel: &str, file: &syn::File) -> Vec<String> {
    let path = Path::new(rel);
    let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
    let parent = path.parent().unwrap_or(Path::new(""));
    let mod_dir = if matches!(stem, "mod" | "lib" | "main") {
        parent.to_path_buf()
    } else {
        parent.join(stem)
    };
    let mut out = Vec::new();
    for item in &file.items {
        let syn::Item::Mod(m) = item else { continue };
        if m.content.is_some() || !is_cfg_test(&m.attrs) {
            continue;
        }
        let explicit = m.attrs.iter().find_map(|a| {
            if !a.path().is_ident("path") {
                return None;
            }
            let syn::Meta::NameValue(nv) = &a.meta else {
                return None;
            };
            match &nv.value {
                syn::Expr::Lit(syn::ExprLit {
                    lit: syn::Lit::Str(s),
                    ..
                }) => Some(s.value()),
                _ => None,
            }
        });
        let name = m.ident.to_string();
        let candidates = match explicit {
            Some(p) => vec![parent.join(p)],
            None => vec![
                mod_dir.join(format!("{name}.rs")),
                mod_dir.join(&name).join("mod.rs"),
            ],
        };
        for c in candidates {
            out.push(c.to_string_lossy().replace('\\', "/"));
        }
    }
    out
}

/// Every production `.rs` under `roots` (repo-relative directories): test paths, files declared
/// under `#[cfg(test)]` and plugin crates excluded. A root that holds no production file fails.
pub fn production(roots: &[&str]) -> Vec<Source> {
    let repo = repo();
    let mut parsed = Vec::new();
    for root in roots {
        let mut files = Vec::new();
        rust_files(&repo.join(root), &mut files);
        let before = parsed.len();
        for f in files {
            let rel = f
                .strip_prefix(&repo)
                .unwrap_or(&f)
                .to_string_lossy()
                .replace('\\', "/");
            if is_test_path(&rel) || is_plugin_crate(&rel) {
                continue;
            }
            let text = std::fs::read_to_string(&f).unwrap_or_else(|e| panic!("{rel}: {e}"));
            let file = syn::parse_file(&text).unwrap_or_else(|e| panic!("{rel}: {e}"));
            parsed.push(Source { rel, text, file });
        }
        assert!(parsed.len() > before, "{root} holds no production source");
    }
    let test_files: BTreeSet<String> = parsed
        .iter()
        .flat_map(|s| cfg_test_module_files(&s.rel, &s.file))
        .collect();
    parsed.retain(|s| !test_files.contains(&s.rel));
    parsed
}

/// One named file, parsed. It must exist.
pub fn one(rel: &str) -> Source {
    let text = std::fs::read_to_string(repo().join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"));
    let file = syn::parse_file(&text).unwrap_or_else(|e| panic!("{rel}: {e}"));
    Source {
        rel: rel.to_string(),
        text,
        file,
    }
}

/// The items a non-test build compiles, inline modules flattened.
pub fn items(items: &[syn::Item]) -> Vec<&syn::Item> {
    let mut out = Vec::new();
    for item in items {
        let attrs: &[syn::Attribute] = match item {
            syn::Item::Fn(i) => &i.attrs,
            syn::Item::Impl(i) => &i.attrs,
            syn::Item::Mod(i) => &i.attrs,
            syn::Item::Struct(i) => &i.attrs,
            syn::Item::Enum(i) => &i.attrs,
            syn::Item::Const(i) => &i.attrs,
            syn::Item::Static(i) => &i.attrs,
            syn::Item::Trait(i) => &i.attrs,
            syn::Item::Type(i) => &i.attrs,
            syn::Item::Use(i) => &i.attrs,
            syn::Item::Macro(i) => &i.attrs,
            _ => &[],
        };
        if is_cfg_test(attrs) {
            continue;
        }
        if let syn::Item::Mod(m) = item {
            if let Some((_, inner)) = &m.content {
                out.extend(self::items(inner));
                continue;
            }
        }
        out.push(item);
    }
    out
}

/// The flattened tokens of `t`, groups opened in place (each group's delimiter is not a token).
pub fn tokens(t: &impl ToTokens) -> Vec<TokenTree> {
    fn flatten(ts: TokenStream, out: &mut Vec<TokenTree>) {
        for tt in ts {
            match &tt {
                TokenTree::Group(g) => {
                    out.push(tt.clone());
                    flatten(g.stream(), out);
                }
                _ => out.push(tt),
            }
        }
    }
    let mut out = Vec::new();
    flatten(t.to_token_stream(), &mut out);
    out
}

/// The identifiers among `toks`, as strings.
pub fn idents(toks: &[TokenTree]) -> Vec<String> {
    toks.iter()
        .filter_map(|t| match t {
            TokenTree::Ident(i) => Some(i.to_string()),
            _ => None,
        })
        .collect()
}

/// The 1-based line `t` starts on.
pub fn line_of(t: &impl syn::spanned::Spanned) -> usize {
    t.span().start().line
}

/// Every named field of a struct or of an enum's struct variants, with the type's name it sits in.
pub fn named_fields(item: &syn::Item) -> Vec<(String, &syn::Field)> {
    let mut out = Vec::new();
    match item {
        syn::Item::Struct(s) => {
            if let syn::Fields::Named(n) = &s.fields {
                for f in &n.named {
                    out.push((s.ident.to_string(), f));
                }
            }
        }
        syn::Item::Enum(e) => {
            for v in &e.variants {
                if let syn::Fields::Named(n) = &v.fields {
                    for f in &n.named {
                        out.push((e.ident.to_string(), f));
                    }
                }
            }
        }
        _ => {}
    }
    out
}
