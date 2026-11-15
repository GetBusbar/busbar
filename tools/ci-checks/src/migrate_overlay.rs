// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The 1.5.5 overlay's checks (MIGRATE-ON-BOOT r42 §7 "Separation", §9 C1 reds (f2), (n4)(4), (o7)).
//!
//! - `migrate-overlay-separation` (r17): the 1.5.5 overlay's name, path and variable
//!   (`BUSBAR_CONFIG_OVERLAY`, `busbar-overlay.json`, `DEFAULT_OVERLAY_FILENAME`) occur in no
//!   production source outside `crates/busbar-migrate`: an identifier, a string literal or a doc
//!   comment naming one fails. A stamped boot therefore cannot look at an overlay (257c). Test code
//!   is not production (as `migrate-flag-text` reads it).
//! - `migrate-overlay-keys` ((n4)(4), §7 lint r29): in `crates/busbar-migrate`'s production source
//!   the overlay's key `global_hooks` is a string literal only in `src/overlay_hooks.rs`, the one
//!   overlay-shape pass, which reads it and never writes it.
//! - `migrate-overlay-docs` ((f2) r18, (o7)): `docs/migration-1.6.md` says the overlay is checked
//!   only on the one upgrade boot and gives the rollback's F-first order; no sentence says a stamped
//!   boot (or serving) refuses an overlay.

use std::path::Path;

use proc_macro2::{TokenStream, TokenTree};
use syn::visit::{self, Visit};
use syn::{Attribute, ImplItem, Item, Lit, TraitItem};

use super::{
    impl_item_attrs, is_test, item_attrs, rel, rust_files, scan_source, sorted_entries,
    trait_item_attrs,
};

/// The 1.5.5 overlay's name, path and variable.
pub(crate) const WORDS: [&str; 3] = [
    "BUSBAR_CONFIG_OVERLAY",
    "busbar-overlay.json",
    "DEFAULT_OVERLAY_FILENAME",
];
/// The one crate that may name them: the boot's one-time migration.
const HELPER: &str = "busbar-migrate";
/// The overlay key only the overlay-shape pass may name.
pub(crate) const HOOK_KEY: &str = "global_hooks";
/// That pass.
const HOOK_PASS: &str = "crates/busbar-migrate/src/overlay_hooks.rs";
const DOCS: &str = "docs/migration-1.6.md";
/// (f2) the sentence the upgrade page carries.
pub(crate) const ONE_BOOT: &str = "1.6.0 checks the overlay only on this one upgrade boot";
/// (o7) the rollback's order: F first, else B.
pub(crate) const ROLLBACK: &str =
    "move `<o>.busbar-folding` back to `<o>` if it exists, else move `<o>.1.5.5` back";

pub(crate) fn separation(root: &Path) -> Result<Vec<String>, String> {
    let mut files = Vec::new();
    for dir in sorted_entries(&root.join("crates"))? {
        let helper = dir.file_name().is_some_and(|name| name == HELPER);
        if !helper && dir.is_dir() {
            rust_files(&dir, &mut files)?;
        }
    }
    let mut hits = Vec::new();
    let mut test_modules = Vec::new();
    for file in files {
        let text = std::fs::read_to_string(&file)
            .map_err(|error| format!("{}: {error}", rel(root, &file)))?;
        test_modules.extend(scan_source(&file, &text).test_modules);
        for (line, word) in word_sites(&text, &WORDS, true) {
            hits.push((file.clone(), line, word));
        }
    }
    Ok(hits
        .into_iter()
        .filter(|(file, _, _)| !test_modules.iter().any(|module| module.covers(file)))
        .map(|(file, line, word)| {
            format!(
                "{}:{line}: production source names `{word}`, the 1.5.5 overlay's; only \
                 crates/busbar-migrate (the one-time upgrade) may, so no stamped boot reads an \
                 overlay (MIGRATE-ON-BOOT §7 separation)",
                rel(root, &file)
            )
        })
        .collect())
}

pub(crate) fn hook_keys(root: &Path) -> Result<Vec<String>, String> {
    let mut files = Vec::new();
    rust_files(&root.join("crates").join(HELPER).join("src"), &mut files)?;
    let mut hits = Vec::new();
    let mut test_modules = Vec::new();
    for file in files {
        let text = std::fs::read_to_string(&file)
            .map_err(|error| format!("{}: {error}", rel(root, &file)))?;
        test_modules.extend(scan_source(&file, &text).test_modules);
        if rel(root, &file) == HOOK_PASS {
            continue;
        }
        for (line, _) in word_sites(&text, &[HOOK_KEY], false) {
            hits.push((file.clone(), line));
        }
    }
    Ok(hits
        .into_iter()
        .filter(|(file, _)| !test_modules.iter().any(|module| module.covers(file)))
        .map(|(file, line)| {
            format!(
                "{}:{line}: names the 1.5.5 overlay key `{HOOK_KEY}` outside {HOOK_PASS}, the one \
                 overlay-shape pass (it reads the key and never writes it)",
                rel(root, &file)
            )
        })
        .collect())
}

pub(crate) fn docs(root: &Path) -> Result<Vec<String>, String> {
    let text =
        std::fs::read_to_string(root.join(DOCS)).map_err(|error| format!("{DOCS}: {error}"))?;
    Ok(docs_findings(&text))
}

/// What the upgrade page must say and must not say about the overlay.
pub(crate) fn docs_findings(text: &str) -> Vec<String> {
    let mut findings = Vec::new();
    let flat = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if !flat.contains(ONE_BOOT) {
        findings.push(format!(
            "{DOCS}: missing the sentence \"{ONE_BOOT}\" (red (f2))"
        ));
    }
    if !flat.contains(ROLLBACK) {
        findings.push(format!(
            "{DOCS}: the overlay rollback must read \"{ROLLBACK}\" (red (o7): a rollback that \
             moves only `<o>.1.5.5` back loses the overlay a crash left at `<o>.busbar-folding`)"
        ));
    }
    for sentence in flat.split(". ") {
        if claims_a_stamped_refusal(sentence) {
            findings.push(format!(
                "{DOCS}: \"{sentence}\" says a stamped boot refuses an overlay; a stamped boot \
                 reads config.yaml's one field and never looks at an overlay (257c)"
            ));
        }
    }
    findings
}

/// A sentence about the overlay that says serving, a stamped boot or every later boot refuses.
fn claims_a_stamped_refusal(sentence: &str) -> bool {
    let lower = sentence.to_ascii_lowercase();
    lower.contains("overlay")
        && lower.contains("refus")
        && (lower.contains("stamped boot")
            || lower.contains("serving")
            || lower.contains("every boot after")
            || lower.contains("later boot"))
}

/// The lines (and the word) where production code names one of `words`: in a string literal,
/// and, when `idents`, in an identifier or a doc comment too. Doc comments are skipped when not
/// `idents`. A file syn cannot parse is read line by line, so it is never skipped.
pub(crate) fn word_sites(text: &str, words: &[&str], idents: bool) -> Vec<(usize, String)> {
    match syn::parse_file(text) {
        Ok(ast) => {
            let mut scan = WordScan {
                words,
                idents,
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
            .flat_map(|(index, line)| {
                words
                    .iter()
                    .filter(move |word| line.contains(**word))
                    .map(move |word| (index + 1, (*word).to_owned()))
            })
            .collect(),
    }
}

struct WordScan<'w> {
    words: &'w [&'w str],
    idents: bool,
    test_depth: usize,
    hits: Vec<(usize, String)>,
}

impl WordScan<'_> {
    fn guarded(&mut self, attrs: &[Attribute], walk: impl FnOnce(&mut Self)) {
        let test = usize::from(is_test(attrs));
        self.test_depth += test;
        walk(self);
        self.test_depth -= test;
    }

    fn hit(&mut self, value: &str, line: usize) {
        if self.test_depth > 0 {
            return;
        }
        for word in self.words {
            if value.contains(*word) {
                self.hits.push((line, (*word).to_owned()));
            }
        }
    }

    /// Literals (and identifiers) inside a macro's tokens.
    fn tokens(&mut self, stream: TokenStream) {
        for token in stream {
            match token {
                TokenTree::Group(group) => self.tokens(group.stream()),
                TokenTree::Literal(literal) => {
                    let line = literal.span().start().line;
                    self.hit(&literal.to_string(), line);
                }
                TokenTree::Ident(ident) if self.idents => {
                    let line = ident.span().start().line;
                    self.hit(&ident.to_string(), line);
                }
                _ => {}
            }
        }
    }
}

impl<'ast> Visit<'ast> for WordScan<'_> {
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

    fn visit_attribute(&mut self, attr: &'ast Attribute) {
        if self.idents || !attr.path().is_ident("doc") {
            visit::visit_attribute(self, attr);
        }
    }

    fn visit_ident(&mut self, ident: &'ast proc_macro2::Ident) {
        if self.idents {
            self.hit(&ident.to_string(), ident.span().start().line);
        }
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

#[cfg(test)]
#[path = "migrate_overlay_tests.rs"]
mod tests;
