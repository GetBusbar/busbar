// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! LINT-RULES R23 `derive-once` (LR-124): a function that derives a per-request fact from raw
//! request input is visible only to its owner, so the fact cannot be derived a second time at a
//! second call site. Rust visibility is the stop (ruling 308: no clippy row that needs an
//! `#[expect]` at its owner); this rule pins it.
//!
//! - [`SEALED`]: defined exactly once in core, privately, in its owner's file, and that file
//!   declares no non-test child module, so only the owner's module can call it.
//! - [`ONE_SITE`]: a derivation whose one production call site shares its module with other
//!   code (the kept sites, whose input differs); it has exactly one production call site.

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
    Sealed {
        name: "stripped",
        self_ty: Some("Head"),
        owner: "crates/busbar-kernel/src/inbound/handin.rs",
        why: "the stripped original: only `handin_state_matches` derives it",
    },
    Sealed {
        name: "verified",
        self_ty: Some("CallerCredential"),
        owner: "crates/busbar-kernel/src/auth/caller_credential.rs",
        why: "the caller credential buffer: only `verified_caller_credential` builds it",
    },
];

/// Derivations with exactly one production call site (method name, why the one site is the
/// owner).
const ONE_SITE: &[(&str, &str)] = &[
    (
        "admission_on",
        "a non-peer continuation call's own head, earlier strips applied (not the unit's original)",
    ),
    (
        "extract_client_token",
        "a plain HTTP admin request with no inbound unit, so no `Derived` record",
    ),
];

const ROOTS: &[&str] = &[
    "crates/busbar-kernel/src",
    "crates/busbar/src",
    "crates/busbar-core-admin/src",
];

/// One definition found: the file, whether its visibility is private, and the line.
struct Found {
    rel: String,
    private: bool,
    line: usize,
}

struct Defs<'a> {
    rel: &'a str,
    impl_ty: Option<String>,
    found: Vec<(usize, Found)>,
    calls: Vec<(&'static str, String)>,
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
    fn visit_item_mod(&mut self, m: &'ast syn::ItemMod) {
        if !walk::is_cfg_test(&m.attrs) {
            syn::visit::visit_item_mod(self, m);
        }
    }

    fn visit_item_fn(&mut self, f: &'ast syn::ItemFn) {
        if walk::is_cfg_test(&f.attrs) {
            return;
        }
        let outer = self.impl_ty.take();
        self.check(&f.sig.ident, &f.vis);
        syn::visit::visit_item_fn(self, f);
        self.impl_ty = outer;
    }

    fn visit_item_impl(&mut self, i: &'ast syn::ItemImpl) {
        if walk::is_cfg_test(&i.attrs) {
            return;
        }
        let outer = self.impl_ty.take();
        self.impl_ty = match &*i.self_ty {
            syn::Type::Path(p) => p.path.segments.last().map(|s| s.ident.to_string()),
            _ => None,
        };
        syn::visit::visit_item_impl(self, i);
        self.impl_ty = outer;
    }

    fn visit_impl_item_fn(&mut self, f: &'ast syn::ImplItemFn) {
        if walk::is_cfg_test(&f.attrs) {
            return;
        }
        self.check(&f.sig.ident, &f.vis);
        syn::visit::visit_impl_item_fn(self, f);
    }

    fn visit_expr_method_call(&mut self, c: &'ast syn::ExprMethodCall) {
        for &(name, _) in ONE_SITE {
            if c.method == name {
                self.calls
                    .push((name, format!("{}:{}", self.rel, walk::line_of(&c.method))));
            }
        }
        syn::visit::visit_expr_method_call(self, c);
    }
}

type Scan = (Vec<(usize, Found)>, Vec<(&'static str, String)>);

fn scan(sources: &[Source]) -> Scan {
    let mut found = Vec::new();
    let mut calls = Vec::new();
    for src in sources {
        let mut defs = Defs {
            rel: &src.rel,
            impl_ty: None,
            found: Vec::new(),
            calls: Vec::new(),
        };
        defs.visit_file(&src.file);
        found.extend(defs.found);
        calls.extend(defs.calls);
    }
    (found, calls)
}

#[test]
fn derive_once_functions_are_private_to_their_owner() {
    let sources = walk::production(ROOTS);
    let (found, calls) = scan(&sources);
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
                syn::Item::Mod(m) if !walk::is_cfg_test(&m.attrs) => Some(m.ident.to_string()),
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
    for (name, why) in ONE_SITE {
        let sites: Vec<&String> = calls
            .iter()
            .filter(|(n, _)| n == name)
            .map(|(_, at)| at)
            .collect();
        assert_eq!(
            sites.len(),
            1,
            "R23 derive-once: `{name}` has one production call site ({why}); found {sites:?}. \
             Read the unit's `Derived` value instead of deriving it again"
        );
    }
}

#[test]
fn the_derive_once_scan_sees_a_planted_second_definition_and_call() {
    let planted: syn::File = syn::parse_str(
        "pub(crate) fn header_map(head: &Head) -> HeaderMap { todo!() }\n\
         impl Listener { fn admission(&self, head: &Head) -> Option<A> { None } }\n\
         fn f(l: &Listener, h: &Head) { l.admission_on(h); l.admission_on(h); }\n\
         #[cfg(test)] mod tests { fn g(l: &Listener, h: &Head) { l.admission_on(h); } }",
    )
    .unwrap();
    let (found, calls) = scan(&[Source {
        rel: "crates/busbar-kernel/src/inbound.rs".to_string(),
        file: planted,
    }]);
    assert_eq!(found.len(), 2);
    assert!(found.iter().all(|(_, f)| f.rel.ends_with("inbound.rs")));
    assert!(!found[0].1.private, "pub(crate) is not private");
    assert!(found[1].1.private);
    assert_eq!(calls.len(), 2, "test-only calls are not counted: {calls:?}");
}
