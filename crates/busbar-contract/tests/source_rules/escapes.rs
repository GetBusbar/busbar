// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! R34 `no-tree-escape` (OBSERVABILITY-HOT-PATH §2.7): an escape from the `disallowed_*` lints is
//! one site and one lint. A source `allow` beats the command line's `-D`, named or by group, so a
//! single tree-level escape would switch a rule off for a whole tree. Refused, inside `cfg_attr`
//! too: any `allow` of the three lints or of a group holding them; any `expect` of such a group;
//! and an `expect` of one of the three on a `mod`, `fn`, `impl`, `trait` or inner attribute.
//!
//! Syn only, so the binary's test can read its generated `OUT_DIR` sources with the same rule.

use syn::visit::Visit;

const LINTS: &[&str] = &[
    "clippy::disallowed_methods",
    "clippy::disallowed_macros",
    "clippy::disallowed_types",
];

const GROUPS: &[&str] = &["clippy::all", "clippy::style"];

/// Every escape in `file` wider than one site and one lint, as `rel:line: why`.
pub fn refusals(rel: &str, file: &syn::File) -> Vec<String> {
    let mut scan = Scan {
        rel,
        out: Vec::new(),
    };
    scan.attrs(&file.attrs, true);
    scan.visit_file(file);
    scan.out
}

struct Scan<'a> {
    rel: &'a str,
    out: Vec<String>,
}

/// The `allow`/`expect` lint lists `attr` carries, opened through any `cfg_attr`.
fn lint_lists(meta: &syn::Meta, out: &mut Vec<(String, Vec<String>)>) {
    let syn::Meta::List(list) = meta else {
        return;
    };
    let Some(kind) = list.path.get_ident().map(ToString::to_string) else {
        return;
    };
    let parser = syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated;
    let Ok(items) = list.parse_args_with(parser) else {
        return;
    };
    match kind.as_str() {
        "cfg_attr" => {
            for inner in items.iter().skip(1) {
                lint_lists(inner, out);
            }
        }
        "allow" | "expect" => {
            let lints = items
                .iter()
                .filter_map(|m| match m {
                    syn::Meta::Path(p) => Some(
                        p.segments
                            .iter()
                            .map(|s| s.ident.to_string())
                            .collect::<Vec<_>>()
                            .join("::"),
                    ),
                    _ => None,
                })
                .collect();
            out.push((kind, lints));
        }
        _ => {}
    }
}

impl Scan<'_> {
    /// `wide`: the attributes sit on a `mod`/`fn`/`impl`/`trait`, or are inner.
    fn attrs(&mut self, attrs: &[syn::Attribute], wide: bool) {
        for attr in attrs {
            let mut lists = Vec::new();
            lint_lists(&attr.meta, &mut lists);
            let wide = wide || matches!(attr.style, syn::AttrStyle::Inner(_));
            let line = syn::spanned::Spanned::span(attr).start().line;
            for (kind, lints) in lists {
                for lint in lints {
                    let named = LINTS.contains(&lint.as_str());
                    let group = GROUPS.contains(&lint.as_str());
                    let why = match kind.as_str() {
                        "allow" if named || group => "an allow beats the command line's -D",
                        "expect" if group => "an escape names its one lint, not a group",
                        "expect" if named && wide => {
                            "an expect sits on one statement, expression, field, static or const"
                        }
                        _ => continue,
                    };
                    self.out
                        .push(format!("{}:{line}: {kind}({lint}): {why}", self.rel));
                }
            }
        }
    }
}

/// Each visit below judges its item's own attributes as wide, then walks the item's parts but not
/// those attributes; every other attribute (statement, expression, field, static, const, ...)
/// reaches `visit_attribute` and is judged as one site.
impl<'ast> Visit<'ast> for Scan<'_> {
    fn visit_attribute(&mut self, attr: &'ast syn::Attribute) {
        self.attrs(std::slice::from_ref(attr), false);
    }

    fn visit_file(&mut self, i: &'ast syn::File) {
        for item in &i.items {
            self.visit_item(item);
        }
    }

    fn visit_item_mod(&mut self, i: &'ast syn::ItemMod) {
        self.attrs(&i.attrs, true);
        for item in i.content.iter().flat_map(|(_, items)| items) {
            self.visit_item(item);
        }
    }

    fn visit_item_fn(&mut self, i: &'ast syn::ItemFn) {
        self.attrs(&i.attrs, true);
        self.visit_signature(&i.sig);
        self.visit_block(&i.block);
    }

    fn visit_item_impl(&mut self, i: &'ast syn::ItemImpl) {
        self.attrs(&i.attrs, true);
        self.visit_generics(&i.generics);
        self.visit_type(&i.self_ty);
        for item in &i.items {
            self.visit_impl_item(item);
        }
    }

    fn visit_item_trait(&mut self, i: &'ast syn::ItemTrait) {
        self.attrs(&i.attrs, true);
        self.visit_generics(&i.generics);
        for item in &i.items {
            self.visit_trait_item(item);
        }
    }

    fn visit_impl_item_fn(&mut self, i: &'ast syn::ImplItemFn) {
        self.attrs(&i.attrs, true);
        self.visit_signature(&i.sig);
        self.visit_block(&i.block);
    }

    fn visit_trait_item_fn(&mut self, i: &'ast syn::TraitItemFn) {
        self.attrs(&i.attrs, true);
        self.visit_signature(&i.sig);
        if let Some(block) = &i.default {
            self.visit_block(block);
        }
    }
}
