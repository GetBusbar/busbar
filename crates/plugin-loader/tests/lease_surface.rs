// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! LEASE-HANDED: no public loader item may put a plugin answer's lease in another crate's hands.
//! A lease that crosses the crate boundary is released by the caller's convention or not at all;
//! the public crossing is `Plugin::answer`, which releases inside the crossing. The lease-handing
//! surface is `pub` only to tests (`cfg(test)` / `test-support`, a feature that never ships).
//!
//! Rejected wherever it is reachable `pub` outside that gate, whatever it is called:
//! (a) a struct field of type `u64` whose name has `lease` as a whole `_`-separated word;
//! (b) a fn whose return type names `Called`, `Done`, `Reply`, `Crossed`, `Recall` or `AnswerLease`;
//! (c) a fn taking a `lease: u64` parameter.

use std::path::{Path, PathBuf};

use syn::parse::Parser;
use syn::punctuated::Punctuated;
use syn::visit::{self, Visit};
use syn::{Attribute, Meta, Token, Visibility};

const HANDING: &[&str] = &[
    "Called",
    "Done",
    "Reply",
    "Crossed",
    "Recall",
    "AnswerLease",
];

/// `Some(false)`: the predicate is false in a production build (`test`, `test-support`).
fn cfg_value(meta: &Meta) -> Option<bool> {
    match meta {
        Meta::Path(p) if p.is_ident("test") => Some(false),
        Meta::NameValue(n) if n.path.is_ident("feature") => match &n.value {
            syn::Expr::Lit(syn::ExprLit {
                lit: syn::Lit::Str(s),
                ..
            }) if s.value() == "test-support" => Some(false),
            _ => None,
        },
        Meta::List(l) => {
            let nested = Punctuated::<Meta, Token![,]>::parse_terminated
                .parse2(l.tokens.clone())
                .ok()?;
            let values: Vec<_> = nested.iter().map(cfg_value).collect();
            if l.path.is_ident("not") && values.len() == 1 {
                values[0].map(|v| !v)
            } else if l.path.is_ident("all") {
                values.contains(&Some(false)).then_some(false)
            } else if l.path.is_ident("any") {
                values.iter().all(|v| *v == Some(false)).then_some(false)
            } else {
                None
            }
        }
        _ => None,
    }
}

/// The item is compiled into a production build.
fn shipping(attrs: &[Attribute]) -> bool {
    !attrs
        .iter()
        .filter(|a| a.path().is_ident("cfg"))
        .any(|a| a.parse_args::<Meta>().ok().as_ref().and_then(cfg_value) == Some(false))
}

fn public(vis: &Visibility) -> bool {
    matches!(vis, Visibility::Public(_))
}

fn lease_word(name: &str) -> bool {
    name.split('_').any(|w| w == "lease")
}

fn names_handing(ty: &syn::ReturnType) -> Option<&'static str> {
    struct Find(Option<&'static str>);
    impl<'ast> Visit<'ast> for Find {
        fn visit_path_segment(&mut self, s: &'ast syn::PathSegment) {
            if let Some(name) = HANDING.iter().find(|n| s.ident == **n) {
                self.0.get_or_insert(name);
            }
            visit::visit_path_segment(self, s);
        }
    }
    let mut find = Find(None);
    find.visit_return_type(ty);
    find.0
}

fn is_u64(ty: &syn::Type) -> bool {
    matches!(ty, syn::Type::Path(p) if p.qself.is_none() && p.path.is_ident("u64"))
}

struct Surface<'a> {
    file: &'a Path,
    /// Every enclosing module and impl ships and is reachable `pub`.
    open: bool,
    found: Vec<String>,
}

impl Surface<'_> {
    fn report(&mut self, what: String) {
        self.found.push(format!("{}: {what}", self.file.display()));
    }

    fn signature(&mut self, vis: &Visibility, attrs: &[Attribute], sig: &syn::Signature) {
        if !(self.open && public(vis) && shipping(attrs)) {
            return;
        }
        if let Some(name) = names_handing(&sig.output) {
            self.report(format!("pub fn `{}` returns `{name}`", sig.ident));
        }
        for input in &sig.inputs {
            if let syn::FnArg::Typed(t) = input {
                if let syn::Pat::Ident(p) = &*t.pat {
                    if p.ident == "lease" && is_u64(&t.ty) {
                        self.report(format!("pub fn `{}` takes `lease: u64`", sig.ident));
                    }
                }
            }
        }
    }

    fn within(&mut self, open: bool, f: impl FnOnce(&mut Self)) {
        let was = self.open;
        self.open = was && open;
        f(self);
        self.open = was;
    }
}

impl<'ast> Visit<'ast> for Surface<'_> {
    fn visit_item_mod(&mut self, m: &'ast syn::ItemMod) {
        let open = public(&m.vis) && shipping(&m.attrs);
        self.within(open, |s| visit::visit_item_mod(s, m));
    }

    fn visit_item_impl(&mut self, i: &'ast syn::ItemImpl) {
        // A trait impl's methods carry no visibility of their own and add no surface.
        let open = i.trait_.is_none() && shipping(&i.attrs);
        self.within(open, |s| visit::visit_item_impl(s, i));
    }

    fn visit_item_fn(&mut self, f: &'ast syn::ItemFn) {
        self.signature(&f.vis, &f.attrs, &f.sig);
    }

    fn visit_impl_item_fn(&mut self, f: &'ast syn::ImplItemFn) {
        self.signature(&f.vis, &f.attrs, &f.sig);
    }

    fn visit_item_struct(&mut self, st: &'ast syn::ItemStruct) {
        if !(self.open && public(&st.vis) && shipping(&st.attrs)) {
            return;
        }
        for field in &st.fields {
            let Some(name) = &field.ident else { continue };
            if public(&field.vis)
                && shipping(&field.attrs)
                && is_u64(&field.ty)
                && lease_word(&name.to_string())
            {
                self.report(format!("pub struct `{}` has pub `{name}: u64`", st.ident));
            }
        }
    }
}

/// Every module file reachable from `lib.rs`, with whether its path from the crate root is `pub`.
fn modules(root: &Path) -> Vec<(PathBuf, bool)> {
    let mut out = Vec::new();
    let mut queue = vec![(root.join("lib.rs"), true)];
    while let Some((file, open)) = queue.pop() {
        let text = std::fs::read_to_string(&file).unwrap_or_else(|e| panic!("{file:?}: {e}"));
        let parsed = syn::parse_file(&text).unwrap_or_else(|e| panic!("{file:?}: {e}"));
        let dir = match file.file_name().and_then(|n| n.to_str()) {
            Some("lib.rs" | "mod.rs") => file.parent().unwrap().to_path_buf(),
            _ => file.with_extension(""),
        };
        let here = file.parent().unwrap().to_path_buf();
        collect(&parsed.items, &dir, &here, open, &mut queue);
        out.push((file, open));
    }
    out
}

fn collect(
    items: &[syn::Item],
    dir: &Path,
    here: &Path,
    open: bool,
    queue: &mut Vec<(PathBuf, bool)>,
) {
    for item in items {
        let syn::Item::Mod(m) = item else { continue };
        let open = open && public(&m.vis) && shipping(&m.attrs);
        if let Some((_, inline)) = &m.content {
            collect(inline, &dir.join(m.ident.to_string()), here, open, queue);
            continue;
        }
        let path = m.attrs.iter().find_map(|a| match &a.meta {
            Meta::NameValue(n) if n.path.is_ident("path") => match &n.value {
                syn::Expr::Lit(syn::ExprLit {
                    lit: syn::Lit::Str(s),
                    ..
                }) => Some(s.value()),
                _ => None,
            },
            _ => None,
        });
        let file = match path {
            Some(p) => here.join(p),
            None => {
                let flat = dir.join(format!("{}.rs", m.ident));
                if flat.exists() {
                    flat
                } else {
                    dir.join(m.ident.to_string()).join("mod.rs")
                }
            }
        };
        queue.push((file, open));
    }
}

fn scan(file: &Path, text: &str, open: bool) -> Vec<String> {
    let parsed = syn::parse_file(text).unwrap_or_else(|e| panic!("{file:?}: {e}"));
    let mut surface = Surface {
        file,
        open,
        found: Vec::new(),
    };
    for item in &parsed.items {
        // Inline modules are walked here; file modules are walked as their own files.
        if let syn::Item::Mod(m) = item {
            if m.content.is_none() {
                continue;
            }
        }
        surface.visit_item(item);
    }
    surface.found
}

#[test]
fn no_public_loader_item_hands_a_lease_to_another_crate() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut found = Vec::new();
    for (file, open) in modules(&root) {
        let text = std::fs::read_to_string(&file).unwrap();
        found.extend(scan(&file, &text, open));
    }
    assert!(
        found.is_empty(),
        "LEASE-HANDED: these public items can put a plugin lease in another crate's hands; gate \
         them with `test_support_pub!` or answer through a lease-free type (`Answered`):\n{}",
        found.join("\n")
    );
}

/// The rule bites: an ungated `pub` copy of `call` is found, a gated one is not.
#[test]
fn a_public_lease_handing_crossing_is_found() {
    let seeded = r#"
        impl Plugin {
            pub fn call(&self, s: u32) -> Called { todo!() }
            #[cfg(any(test, feature = "test-support"))]
            pub fn gated(&self, s: u32) -> Called { todo!() }
            pub(crate) fn inner(&self, s: u32) -> Done<I, O> { todo!() }
            pub fn give(&self, lease: u64) {}
        }
        pub struct Out { pub short_lease: u64, pub release_keys_floor: u64 }
    "#;
    let found = scan(Path::new("seeded.rs"), seeded, true);
    assert_eq!(found.len(), 3, "{found:#?}");
    assert!(found[0].contains("`call` returns `Called`"));
    assert!(found[1].contains("`give` takes `lease: u64`"));
    assert!(found[2].contains("`short_lease: u64`"));
}
