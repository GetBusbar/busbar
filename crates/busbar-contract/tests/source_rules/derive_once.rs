// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! LINT-RULES R23 `derive-once` (LR-124): a function that derives a per-request fact from raw
//! request input is visible only to its owner, so the fact cannot be derived a second time at a
//! second call site. Rust visibility is the stop; this rule pins it. Each sealed deriving
//! function is defined exactly once in core, privately, in its owner's file, and that file
//! declares no child module (a private item of a leaf module is callable only inside it).

use syn::visit::Visit;

use crate::walk::{self, Source};

/// A sealed derivation: its name, the type its `impl` block names (`None` = a free function),
/// and the one file (the owner's) that may define it.
struct Sealed {
    name: &'static str,
    self_ty: Option<&'static str>,
    owner: &'static str,
    why: &'static str,
}

const SEALED: &[Sealed] = &[
    Sealed {
        name: "header_map",
        self_ty: None,
        owner: "crates/busbar-kernel/src/inbound/derived.rs",
        why: "a unit's original head as a HeaderMap: only `Derived::headers` builds it",
    },
    Sealed {
        name: "admission",
        self_ty: Some("Listener"),
        owner: "crates/busbar-kernel/src/inbound/derived.rs",
        why: "a unit's plane admission: only `Derived::admission` resolves it",
    },
];

/// One definition found: the file, the visibility is private, and the line.
struct Found {
    rel: String,
    private: bool,
    line: usize,
}

struct Defs<'a> {
    rel: &'a str,
    impl_ty: Option<String>,
    found: Vec<(usize, Found)>,
}

impl Defs<'_> {
    fn check(&mut self, ident: &syn::Ident, vis: &syn::Visibility) {
        for (i, s) in SEALED.iter().enumerate() {
            if ident != s.name || self.impl_ty.as_deref() != s.self_ty {
                continue;
            }
            self.found.push((
                i,
                Found {
                    rel: self.rel.to_string(),
                    private: matches!(vis, syn::Visibility::Inherited),
                    line: walk::line_of(ident),
                },
            ));
        }
    }
}

impl<'ast> Visit<'ast> for Defs<'_> {
    fn visit_item_fn(&mut self, f: &'ast syn::ItemFn) {
        let outer = self.impl_ty.take();
        self.check(&f.sig.ident, &f.vis);
        syn::visit::visit_item_fn(self, f);
        self.impl_ty = outer;
    }

    fn visit_item_impl(&mut self, i: &'ast syn::ItemImpl) {
        let outer = self.impl_ty.take();
        self.impl_ty = match &*i.self_ty {
            syn::Type::Path(p) => p.path.segments.last().map(|s| s.ident.to_string()),
            _ => None,
        };
        syn::visit::visit_item_impl(self, i);
        self.impl_ty = outer;
    }

    fn visit_impl_item_fn(&mut self, f: &'ast syn::ImplItemFn) {
        self.check(&f.sig.ident, &f.vis);
        syn::visit::visit_impl_item_fn(self, f);
    }
}

fn definitions(sources: &[Source]) -> Vec<(usize, Found)> {
    let mut all = Vec::new();
    for src in sources {
        let mut defs = Defs {
            rel: &src.rel,
            impl_ty: None,
            found: Vec::new(),
        };
        defs.visit_file(&src.file);
        all.extend(defs.found);
    }
    all
}

#[test]
fn derive_once_functions_are_private_to_their_owner() {
    let sources = walk::production(&["crates/busbar-kernel/src", "crates/busbar/src"]);
    let found = definitions(&sources);
    for (i, s) in SEALED.iter().enumerate() {
        let defs: Vec<&Found> = found
            .iter()
            .filter(|(at, _)| *at == i)
            .map(|(_, f)| f)
            .collect();
        let shown: Vec<String> = defs
            .iter()
            .map(|f| format!("{}:{} (private: {})", f.rel, f.line, f.private))
            .collect();
        assert!(
            defs.len() == 1 && defs[0].rel == s.owner && defs[0].private,
            "R23 derive-once: `{}` ({}) must be defined once, privately, in {}; found {shown:?}",
            s.name,
            s.why,
            s.owner
        );
        let owner = walk::one(s.owner);
        let children: Vec<String> = owner
            .file
            .items
            .iter()
            .filter_map(|item| match item {
                syn::Item::Mod(m) if m.content.is_none() => Some(m.ident.to_string()),
                _ => None,
            })
            .collect();
        assert!(
            children.is_empty(),
            "R23 derive-once: {} declares child modules {children:?}, which could call `{}`",
            s.owner,
            s.name
        );
    }
}

#[test]
fn the_derive_once_scan_sees_a_planted_second_definition() {
    let planted: syn::File = syn::parse_str(
        "pub(crate) fn header_map(head: &Head) -> HeaderMap { todo!() }\n\
         impl Listener { fn admission(&self, head: &Head) -> Option<A> { None } }",
    )
    .unwrap();
    let found = definitions(&[Source {
        rel: "crates/busbar-kernel/src/inbound.rs".to_string(),
        file: planted,
    }]);
    assert_eq!(found.len(), 2);
    assert!(found.iter().all(|(_, f)| f.rel.ends_with("inbound.rs")));
    assert!(!found[0].1.private, "pub(crate) is not private");
    assert!(found[1].1.private);
}
