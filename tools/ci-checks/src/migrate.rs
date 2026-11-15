// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The migrate-on-boot checks (MIGRATE-ON-BOOT r42 §9 C1).
//!
//! - `migrate-flag-text` (red (mc1)(3)): 1.6.0 has no `--migrate-config`; the boot migrates. No
//!   production string literal or doc comment under `crates/` names the flag, so no text sends an
//!   operator to it. Test code (a `#[cfg(test)]` scope, a `#[test]` fn, a module file declared
//!   under test cfg, a `tests/` tree) is not production. `crates/busbar-migrations` is skipped: it
//!   is deleted whole at C3 (§A9 item 8), and nothing in the gateway depends on it after C1.
//! - `migrate-anchors` (red (sz1)(3c)): each anchor the `migrate-size` job sums from carries
//!   `#[cold]` and `#[inline(never)]` in the source, so fat LTO cannot inline it away and a
//!   rename cannot hide code: "anchor not pinned" otherwise, "anchor not found" when it is gone.

use std::path::{Path, PathBuf};

use proc_macro2::{TokenStream, TokenTree};
use syn::visit::{self, Visit};
use syn::{Attribute, ImplItem, Item, Lit, TraitItem};

use super::{
    impl_item_attrs, is_test, item_attrs, rel, rust_files, scan_source, sorted_entries,
    trait_item_attrs,
};

/// The retired flag's spelling; no production text names it.
pub(crate) const FLAG: &str = "--migrate-config";

/// Deleted whole at C3 (§A9 item 8); not product code after C1.
const RETIRING: &str = "busbar-migrations";

/// The † anchors of MIGRATE-ON-BOOT §7: (file, the fn's `impl` type or "" for a free fn, fn name).
pub(crate) const ANCHORS: [(&str, &str, &str); 3] = [
    (
        "crates/busbar-kernel/src/persistence/startup.rs",
        "Manifest",
        "decode",
    ),
    (
        "crates/busbar-contract/src/abi/sdk/migrate.rs",
        "",
        "read_answer",
    ),
    (
        "crates/plugin-loader/src/dispatch/migrate.rs",
        "",
        "settings_migration",
    ),
];

pub(crate) fn flag_text(root: &Path) -> Result<Vec<String>, String> {
    let mut files = Vec::new();
    for dir in sorted_entries(&root.join("crates"))? {
        let retiring = dir.file_name().is_some_and(|name| name == RETIRING);
        if !retiring && dir.is_dir() {
            rust_files(&dir, &mut files)?;
        }
    }
    let mut hits = Vec::new();
    let mut test_modules = Vec::new();
    for file in files {
        let text = std::fs::read_to_string(&file)
            .map_err(|error| format!("{}: {error}", rel(root, &file)))?;
        test_modules.extend(scan_source(&file, &text).test_modules);
        for line in flag_sites(&text) {
            hits.push((file.clone(), line));
        }
    }
    Ok(hits
        .into_iter()
        .filter(|(file, _)| !test_modules.iter().any(|module| module.covers(file)))
        .map(|(file, line)| {
            format!(
                "{}:{line}: production text names `{FLAG}`, which 1.6.0 does not have; name the \
                 manual fix (the boot migrates a 1.5.5 config itself)",
                rel(root, &file)
            )
        })
        .collect())
}

/// The lines of production string literals and doc comments that name the flag. A file syn cannot
/// parse is read line by line, so it is never skipped.
pub(crate) fn flag_sites(text: &str) -> Vec<usize> {
    match syn::parse_file(text) {
        Ok(ast) => {
            let mut scan = FlagScan {
                test_depth: usize::from(is_test(&ast.attrs)),
                hits: Vec::new(),
            };
            scan.visit_file(&ast);
            scan.hits.sort();
            scan.hits.dedup();
            scan.hits
        }
        Err(_) => text
            .lines()
            .enumerate()
            .filter(|(_, line)| line.contains(FLAG))
            .map(|(index, _)| index + 1)
            .collect(),
    }
}

struct FlagScan {
    test_depth: usize,
    hits: Vec<usize>,
}

impl FlagScan {
    fn guarded(&mut self, attrs: &[Attribute], walk: impl FnOnce(&mut Self)) {
        let test = usize::from(is_test(attrs));
        self.test_depth += test;
        walk(self);
        self.test_depth -= test;
    }

    fn hit(&mut self, value: &str, line: usize) {
        if self.test_depth == 0 && value.contains(FLAG) {
            self.hits.push(line);
        }
    }

    /// String literals inside a macro's tokens (`format!`, `diag_warn!`, a table macro).
    fn tokens(&mut self, stream: TokenStream) {
        for token in stream {
            match token {
                TokenTree::Group(group) => self.tokens(group.stream()),
                TokenTree::Literal(literal) => {
                    let line = literal.span().start().line;
                    self.hit(&literal.to_string(), line);
                }
                _ => {}
            }
        }
    }
}

impl<'ast> Visit<'ast> for FlagScan {
    fn visit_item(&mut self, item: &'ast Item) {
        self.guarded(item_attrs(item), |scan| visit::visit_item(scan, item));
    }

    fn visit_impl_item(&mut self, item: &'ast ImplItem) {
        self.guarded(impl_item_attrs(item), |scan| {
            visit::visit_impl_item(scan, item);
        });
    }

    fn visit_trait_item(&mut self, item: &'ast TraitItem) {
        self.guarded(trait_item_attrs(item), |scan| {
            visit::visit_trait_item(scan, item);
        });
    }

    fn visit_lit(&mut self, lit: &'ast Lit) {
        if let Lit::Str(text) = lit {
            self.hit(&text.value(), text.span().start().line);
        }
        visit::visit_lit(self, lit);
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        self.tokens(mac.tokens.clone());
        visit::visit_macro(self, mac);
    }
}

pub(crate) fn anchors(root: &Path) -> Result<Vec<String>, String> {
    let mut findings = Vec::new();
    for (file, owner, name) in ANCHORS {
        let path: PathBuf = root.join(file);
        let text = std::fs::read_to_string(&path).map_err(|error| format!("{file}: {error}"))?;
        if let Some(finding) = anchor_finding(file, &text, owner, name) {
            findings.push(finding);
        }
    }
    Ok(findings)
}

/// `None` when `owner::name` (or the free fn `name`) is present and carries both attributes.
pub(crate) fn anchor_finding(file: &str, text: &str, owner: &str, name: &str) -> Option<String> {
    let label = if owner.is_empty() {
        name.to_owned()
    } else {
        format!("{owner}::{name}")
    };
    let ast = match syn::parse_file(text) {
        Ok(ast) => ast,
        Err(error) => return Some(format!("{file}: syn could not parse the file: {error}")),
    };
    let Some(attrs) = find_fn(&ast.items, owner, name) else {
        return Some(format!(
            "{file}: anchor not found: `{label}` (the migrate-size job sums from it)"
        ));
    };
    let cold = attrs.iter().any(|attr| attr.path().is_ident("cold"));
    let never = attrs.iter().any(|attr| {
        attr.path().is_ident("inline")
            && attr
                .parse_args::<syn::Ident>()
                .is_ok_and(|arg| arg == "never")
    });
    (!(cold && never)).then(|| {
        format!(
            "{file}: anchor not pinned: `{label}` needs #[cold] and #[inline(never)] \
             (MIGRATE-ON-BOOT §7 †)"
        )
    })
}

fn find_fn<'a>(items: &'a [Item], owner: &str, name: &str) -> Option<&'a [Attribute]> {
    for item in items {
        match item {
            Item::Fn(function) if owner.is_empty() && function.sig.ident == name => {
                return Some(&function.attrs);
            }
            Item::Impl(block) if !owner.is_empty() => {
                let named = matches!(
                    &*block.self_ty,
                    syn::Type::Path(path)
                        if path.path.segments.last().is_some_and(|last| last.ident == owner)
                );
                if !named {
                    continue;
                }
                for inner in &block.items {
                    if let ImplItem::Fn(function) = inner {
                        if function.sig.ident == name {
                            return Some(&function.attrs);
                        }
                    }
                }
            }
            Item::Mod(module) => {
                if let Some((_, inner)) = &module.content {
                    if let Some(found) = find_fn(inner, owner, name) {
                        return Some(found);
                    }
                }
            }
            _ => {}
        }
    }
    None
}

#[cfg(test)]
#[path = "migrate_tests.rs"]
mod tests;
