// SPDX-License-Identifier: Apache-2.0
//! LINT-RULES R28 `ready-after-no-ticket`: the SDK door entry judges a ticketless READY after the
//! SDK handed the call `NoTicket`, which it learns from the two constructors
//! (`abi::sdk::conn::no_ticket`, `abi::sdk::io::no_ticket`). An SDK site that builds the variant
//! itself would hand plugin code a `NoTicket` the entry never hears of. This scan walks the crate's
//! shipping module tree from `lib.rs` (a `#[cfg(test)]` module or item is skipped by that attribute,
//! not by its file name) and refuses any expression `ConnFailure::NoTicket` or
//! `IoFailure::NoTicket` outside the two constructors. Variant definitions and match patterns are
//! not expressions, so they are not flagged.

use std::path::{Path, PathBuf};

use syn::visit::{self, Visit};
use syn::{Attribute, Item, ItemMod, Meta};

/// Whether `attrs` carry a `cfg` that names `test` (`cfg(test)`, `cfg(all(test, ..))`, ...).
fn test_only(attrs: &[Attribute]) -> bool {
    attrs.iter().filter(|a| a.path().is_ident("cfg")).any(|a| {
        let Ok(meta) = a.parse_args::<Meta>() else {
            return false;
        };
        names_test(&meta)
    })
}

fn names_test(meta: &Meta) -> bool {
    match meta {
        Meta::Path(p) => p.is_ident("test"),
        Meta::List(l) if l.path.is_ident("all") => l
            .parse_args_with(syn::punctuated::Punctuated::<Meta, syn::Token![,]>::parse_terminated)
            .is_ok_and(|nested| nested.iter().any(names_test)),
        _ => false,
    }
}

fn attrs_of(item: &Item) -> &[Attribute] {
    match item {
        Item::Const(i) => &i.attrs,
        Item::Enum(i) => &i.attrs,
        Item::Fn(i) => &i.attrs,
        Item::Impl(i) => &i.attrs,
        Item::Macro(i) => &i.attrs,
        Item::Mod(i) => &i.attrs,
        Item::Static(i) => &i.attrs,
        Item::Struct(i) => &i.attrs,
        Item::Trait(i) => &i.attrs,
        Item::Use(i) => &i.attrs,
        _ => &[],
    }
}

/// A file module still to read: its file, and the directory its own child modules resolve in.
struct Pending {
    file: PathBuf,
    children: PathBuf,
}

struct Scan<'a> {
    file: &'a Path,
    /// Where this file's (or the current inline module's) child modules live.
    children: PathBuf,
    functions: Vec<String>,
    queue: &'a mut Vec<Pending>,
    /// `(file, enclosing fn, path)` of every expression that builds the variant.
    hits: Vec<(PathBuf, String, String)>,
}

impl Scan<'_> {
    fn file_module(&mut self, m: &ItemMod) {
        let name = m.ident.to_string();
        let path_attr = m.attrs.iter().find_map(|a| match &a.meta {
            Meta::NameValue(n) if n.path.is_ident("path") => match &n.value {
                syn::Expr::Lit(syn::ExprLit {
                    lit: syn::Lit::Str(s),
                    ..
                }) => Some(s.value()),
                _ => None,
            },
            _ => None,
        });
        let file = match path_attr {
            // A `#[path]` resolves against the directory of the file that declares it.
            Some(p) => self
                .file
                .parent()
                .expect("a source file has a directory")
                .join(p),
            None => {
                let flat = self.children.join(format!("{name}.rs"));
                if flat.exists() {
                    flat
                } else {
                    self.children.join(&name).join("mod.rs")
                }
            }
        };
        let children = if file.file_name().is_some_and(|f| f == "mod.rs") {
            file.parent().expect("mod.rs has a directory").to_path_buf()
        } else {
            file.with_extension("")
        };
        self.queue.push(Pending { file, children });
    }
}

impl<'ast> Visit<'ast> for Scan<'_> {
    fn visit_item(&mut self, item: &'ast Item) {
        if test_only(attrs_of(item)) {
            return;
        }
        visit::visit_item(self, item);
    }

    fn visit_item_mod(&mut self, m: &'ast ItemMod) {
        if m.content.is_none() {
            self.file_module(m);
            return;
        }
        let outer = self.children.clone();
        self.children = outer.join(m.ident.to_string());
        visit::visit_item_mod(self, m);
        self.children = outer;
    }

    fn visit_item_fn(&mut self, f: &'ast syn::ItemFn) {
        self.functions.push(f.sig.ident.to_string());
        visit::visit_item_fn(self, f);
        self.functions.pop();
    }

    fn visit_impl_item_fn(&mut self, f: &'ast syn::ImplItemFn) {
        if test_only(&f.attrs) {
            return;
        }
        self.functions.push(f.sig.ident.to_string());
        visit::visit_impl_item_fn(self, f);
        self.functions.pop();
    }

    fn visit_expr_path(&mut self, e: &'ast syn::ExprPath) {
        let segments: Vec<String> = e
            .path
            .segments
            .iter()
            .map(|s| s.ident.to_string())
            .collect();
        if let [.., ty, variant] = segments.as_slice() {
            if variant == "NoTicket" && (ty == "ConnFailure" || ty == "IoFailure") {
                self.hits.push((
                    self.file.to_path_buf(),
                    self.functions.last().cloned().unwrap_or_default(),
                    segments.join("::"),
                ));
            }
        }
        visit::visit_expr_path(self, e);
    }
}

#[test]
fn every_sdk_no_ticket_is_made_by_its_constructor() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut queue = vec![Pending {
        file: src.join("lib.rs"),
        children: src.clone(),
    }];
    let mut hits = Vec::new();
    let mut read = 0;
    while let Some(next) = queue.pop() {
        let text = std::fs::read_to_string(&next.file)
            .unwrap_or_else(|e| panic!("{}: {e}", next.file.display()));
        let parsed =
            syn::parse_file(&text).unwrap_or_else(|e| panic!("{}: {e}", next.file.display()));
        read += 1;
        let mut scan = Scan {
            file: &next.file,
            children: next.children,
            functions: Vec::new(),
            queue: &mut queue,
            hits: Vec::new(),
        };
        if test_only(&parsed.attrs) {
            continue;
        }
        scan.visit_file(&parsed);
        hits.append(&mut scan.hits);
    }
    assert!(read > 50, "the walk reached the crate's modules: {read}");

    let constructor = |file: &Path, function: &str, ty: &str| {
        function == "no_ticket"
            && file.ends_with(match ty {
                "ConnFailure" => "abi/sdk/conn.rs",
                _ => "abi/sdk/io.rs",
            })
    };
    let (allowed, stray): (Vec<_>, Vec<_>) = hits.iter().partition(|(file, function, path)| {
        let ty = if path.ends_with("ConnFailure::NoTicket") {
            "ConnFailure"
        } else {
            "IoFailure"
        };
        constructor(file, function, ty)
    });
    assert!(
        stray.is_empty(),
        "build NoTicket only through abi::sdk::conn::no_ticket / abi::sdk::io::no_ticket \
         (LINT-RULES R28): {stray:#?}"
    );
    // The control: the scan sees the two constructors themselves.
    assert_eq!(allowed.len(), 2, "{allowed:#?}");
}
