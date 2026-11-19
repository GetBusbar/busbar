// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Source checks over core: C-TRANSPORT test 11 (TRANSPORT-SECURITY-POLICY §8), C-EXPORT-STREAMS's
//! one-definition check (IF §14), C-NO-LICENCE (a) with its round-30 scope, and the per-file LOC report
//! (IF §15 rule 7; IF rule 15: `test_host.rs` counts as test code). Each is a `syn` or token scan.

use std::path::Path;

use proc_macro2::TokenStream;
use quote::ToTokens;
use syn::visit::{self, Visit};

use super::core_scan::test_file;
use super::{is_test, item_attrs, rel, rust_files, sorted_entries, Outcome};

// ---- C-TRANSPORT test 11 ----------------------------------------------------------------------------

/// Paths where plaintext admission runs: the host side of the ABI, the loader's admit and adapters.
fn admission_path(file: &str) -> bool {
    file.contains("/host_side/")
        || file.contains("plugin-loader/src/admit")
        || file.contains("plugin-loader/src/adapters/")
        || file.contains("plugin-loader/src/boot")
}

#[derive(Default)]
struct Probe {
    admission: bool,
    verdicts: Vec<(usize, String)>,
    notes: Vec<(usize, String)>,
}

impl Probe {
    fn function(&mut self, name: &str, params: String, body: String, line: usize) {
        if name == "transport_verdict" {
            self.verdicts.push((line, params));
        }
        if self.admission && name.contains("unix") && body.to_ascii_lowercase().contains("kind") {
            self.notes
                .push((line, format!("`{name}` tests a kind in unix admission")));
        }
    }
}

impl<'ast> Visit<'ast> for Probe {
    fn visit_item(&mut self, item: &'ast syn::Item) {
        if !is_test(item_attrs(item)) {
            visit::visit_item(self, item);
        }
    }

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        if is_test(&node.attrs) {
            return;
        }
        let line = node.sig.ident.span().start().line;
        let params = node.sig.inputs.to_token_stream().to_string();
        let body = node.block.to_token_stream().to_string();
        self.function(&node.sig.ident.to_string(), params, body, line);
        visit::visit_item_fn(self, node);
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        if is_test(&node.attrs) {
            return;
        }
        let line = node.sig.ident.span().start().line;
        let params = node.sig.inputs.to_token_stream().to_string();
        let body = node.block.to_token_stream().to_string();
        self.function(&node.sig.ident.to_string(), params, body, line);
        visit::visit_impl_item_fn(self, node);
    }

    fn visit_item_struct(&mut self, node: &'ast syn::ItemStruct) {
        if node.ident == "TlsDestinationCfg" {
            for field in &node.fields {
                if field.ident.as_ref().is_some_and(|id| id == "plaintext") {
                    self.notes.push((
                        field.ident.as_ref().map_or(0, |id| id.span().start().line),
                        "a `plaintext` field in TlsDestinationCfg".to_string(),
                    ));
                }
            }
        }
        visit::visit_item_struct(self, node);
    }

    fn visit_expr_field(&mut self, node: &'ast syn::ExprField) {
        if matches!(&node.member, syn::Member::Named(id) if id == "plaintext") {
            let base: String = node
                .base
                .to_token_stream()
                .to_string()
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect();
            if base.ends_with("limits") {
                self.notes.push((
                    node.member
                        .to_token_stream()
                        .into_iter()
                        .next()
                        .map_or(0, |t| t.span().start().line),
                    "`limits.plaintext` read".to_string(),
                ));
            }
        }
        visit::visit_expr_field(self, node);
    }

    fn visit_ident(&mut self, ident: &'ast proc_macro2::Ident) {
        if self.admission && (ident == "is_loopback" || ident == "names_loopback") {
            self.notes.push((
                ident.span().start().line,
                format!("`{ident}` in an admission path"),
            ));
        }
    }
}

/// C-TRANSPORT test 11 over `(path, source)` pairs of core's production files.
pub(crate) fn transport_findings(files: &[(String, String)]) -> Vec<String> {
    let mut findings = Vec::new();
    let mut verdicts = 0;
    for (path, source) in files {
        let Ok(file) = syn::parse_file(source) else {
            continue;
        };
        if is_test(&file.attrs) {
            continue;
        }
        let mut probe = Probe {
            admission: admission_path(path),
            ..Probe::default()
        };
        probe.visit_file(&file);
        for (line, params) in &probe.verdicts {
            verdicts += 1;
            let lower = params.to_ascii_lowercase();
            if lower.contains("kind") || lower.contains("module") {
                findings.push(format!(
                    "{path}:{line}: transport_verdict takes a kind or module parameter (policy §8 test 11)"
                ));
            }
        }
        for (line, note) in probe.notes {
            findings.push(format!("{path}:{line}: {note} (policy §8 test 11)"));
        }
    }
    if verdicts != 1 {
        findings.push(format!(
            "transport_verdict is defined {verdicts} times; it is the only plaintext-admission path (policy §8 test 11)"
        ));
    }
    findings
}

// ---- C-EXPORT-STREAMS one-definition ------------------------------------------------------------------

/// `enum ExportStream` occurs exactly once in core (no copy under `abi/`, none in `crates/plugin-abi`).
pub(crate) fn export_stream_findings(files: &[(String, String)]) -> Vec<String> {
    let mut sites = Vec::new();
    for (path, source) in files {
        for (index, line) in source.lines().enumerate() {
            let code = line.trim_start();
            if code.starts_with("//") {
                continue;
            }
            if let Some(at) = code.find("enum ExportStream") {
                let after = code[at + "enum ExportStream".len()..].chars().next();
                if !after.is_some_and(|c| c.is_alphanumeric() || c == '_') {
                    sites.push(format!("{path}:{}", index + 1));
                }
            }
        }
    }
    if sites.len() == 1 {
        Vec::new()
    } else {
        vec![format!(
            "`enum ExportStream` is defined {} times ({}); exactly one is allowed (C-EXPORT-STREAMS)",
            sites.len(),
            sites.join(", ")
        )]
    }
}

// ---- C-NO-LICENCE (a) --------------------------------------------------------------------------------

/// Case-insensitive `licen[cs]e|entitlement|licensed_to|BUSBAR-604`.
pub(crate) fn licence_word(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    [
        "licence",
        "license",
        "entitlement",
        "licensed_to",
        "busbar-604",
    ]
    .iter()
    .any(|word| lower.contains(word))
}

fn walk_tokens(stream: TokenStream, hits: &mut Vec<(usize, String)>) {
    for tree in stream {
        match tree {
            proc_macro2::TokenTree::Group(group) => walk_tokens(group.stream(), hits),
            proc_macro2::TokenTree::Ident(ident) => {
                if licence_word(&ident.to_string()) {
                    hits.push((ident.span().start().line, format!("identifier `{ident}`")));
                }
            }
            proc_macro2::TokenTree::Literal(literal) => {
                let text = literal.to_string();
                if licence_word(&text) {
                    hits.push((
                        literal.span().start().line,
                        "a string literal or doc comment".to_string(),
                    ));
                }
            }
            proc_macro2::TokenTree::Punct(_) => {}
        }
    }
}

/// A Rust file: identifiers, string literals and doc comments (`///`, `//!`, `#[doc]` lex as `#[doc =
/// "..."]`); plain `//` and `/* */` comments are dropped by the lexer, so they are not scanned.
pub(crate) fn licence_rust(source: &str) -> Result<Vec<(usize, String)>, String> {
    let stream: TokenStream = source.parse().map_err(|error| format!("lex: {error}"))?;
    let mut hits = Vec::new();
    walk_tokens(stream, &mut hits);
    Ok(hits)
}

/// A C header: the text outside plain `//` and `/* */` comments (`/** */` doc comments are scanned).
pub(crate) fn licence_header(source: &str) -> Vec<(usize, String)> {
    let mut hits = Vec::new();
    let mut in_plain = false;
    let mut in_doc = false;
    for (index, line) in source.lines().enumerate() {
        let mut text = String::new();
        let mut rest = line;
        loop {
            if in_plain || in_doc {
                match rest.find("*/") {
                    Some(at) => {
                        if in_doc {
                            text.push_str(&rest[..at]);
                        }
                        rest = &rest[at + 2..];
                        in_plain = false;
                        in_doc = false;
                    }
                    None => {
                        if in_doc {
                            text.push_str(rest);
                        }
                        break;
                    }
                }
            } else {
                let line_comment = rest.find("//");
                let block = rest.find("/*");
                match (line_comment, block) {
                    (Some(l), b) if b.is_none_or(|b| l < b) => {
                        text.push_str(&rest[..l]);
                        break;
                    }
                    (_, Some(b)) => {
                        text.push_str(&rest[..b]);
                        in_doc = rest[b..].starts_with("/**") && !rest[b..].starts_with("/**/");
                        in_plain = !in_doc;
                        rest = &rest[b + 2..];
                    }
                    _ => {
                        text.push_str(rest);
                        break;
                    }
                }
            }
        }
        if licence_word(&text) {
            hits.push((index + 1, "text".to_string()));
        }
    }
    hits
}

/// The C-NO-LICENCE (a) scope: `busbar-plugin-abi`, `plugin-loader` admit/scan/refusal,
/// `busbar_plugin.h` and the §15 CI job sources (`ci/**`; this crate carries the pattern literal in its
/// own source and doc, a permitted site).
pub(crate) fn no_licence(root: &Path) -> Outcome {
    let mut findings = Vec::new();
    let mut files = Vec::new();
    rust_files(&root.join("crates/busbar-plugin-abi"), &mut files)?;
    for name in ["admit", "scan", "refusal"] {
        let path = root.join(format!("crates/plugin-loader/src/{name}.rs"));
        if path.is_file() {
            files.push(path);
        }
    }
    for name in ["scan", "refusal"] {
        let path = root.join(format!("crates/busbar-artifact-verifier/src/{name}.rs"));
        if path.is_file() {
            files.push(path);
        }
    }
    let ci = root.join("ci");
    if ci.is_dir() {
        rust_files(&ci, &mut files)?;
    }
    for file in files {
        let text =
            std::fs::read_to_string(&file).map_err(|e| format!("{}: {e}", rel(root, &file)))?;
        match licence_rust(&text) {
            Ok(hits) => {
                for (line, what) in hits {
                    findings.push(format!(
                        "{}:{line}: {what} names licence or entitlement (C-NO-LICENCE (a))",
                        rel(root, &file)
                    ));
                }
            }
            Err(error) => findings.push(format!("{}: {error}", rel(root, &file))),
        }
    }
    let header = root.join("crates/busbar-plugin-abi/include/busbar_plugin.h");
    if header.is_file() {
        let text = std::fs::read_to_string(&header).map_err(|e| format!("busbar_plugin.h: {e}"))?;
        for (line, _) in licence_header(&text) {
            findings.push(format!(
                "{}:{line}: names licence or entitlement (C-NO-LICENCE (a))",
                rel(root, &header)
            ));
        }
    }
    Ok(findings)
}

// ---- core source checks over the tree -----------------------------------------------------------------

/// Every production `.rs` file under `crates/*/src`, as `(repo-relative path, text)`.
pub(crate) fn core_files(root: &Path) -> Result<Vec<(String, String)>, String> {
    let mut out = Vec::new();
    for dir in sorted_entries(&root.join("crates"))? {
        if !dir.is_dir() {
            continue;
        }
        let mut files = Vec::new();
        rust_files(&dir, &mut files)?;
        for file in files {
            let relative = rel(root, &file);
            if test_file(Path::new(&relative)) {
                continue;
            }
            let text = std::fs::read_to_string(&file).map_err(|e| format!("{relative}: {e}"))?;
            out.push((relative, text));
        }
    }
    Ok(out)
}

pub(crate) fn c_transport(root: &Path) -> Outcome {
    Ok(transport_findings(&core_files(root)?))
}

pub(crate) fn export_streams(root: &Path) -> Outcome {
    Ok(export_stream_findings(&core_files(root)?))
}

// ---- the per-file LOC report ---------------------------------------------------------------------------

/// (production, test) code lines of a source: blank lines and `//` comments are not counted; the body
/// of a `#[cfg(test)]` module counts as test.
pub(crate) fn count_lines(source: &str) -> (usize, usize) {
    let (mut prod, mut test) = (0, 0);
    let mut pending = false;
    let mut depth: i64 = 0;
    for line in source.lines() {
        let code = line.trim();
        if code.is_empty() || code.starts_with("//") {
            continue;
        }
        if depth > 0 || (pending && code.contains('{')) {
            test += 1;
            depth += code.matches('{').count() as i64 - code.matches('}').count() as i64;
            if depth <= 0 {
                depth = 0;
                pending = false;
            }
            continue;
        }
        if code.starts_with("#[cfg(test)]") {
            pending = true;
            test += 1;
            continue;
        }
        if pending {
            test += 1;
            if code.ends_with(';') {
                pending = false;
            }
            continue;
        }
        prod += 1;
    }
    (prod, test)
}

/// `loc-report`: prints per-file production and test lines and each crate's total (Δ2: a report, no
/// gate). `crates/plugin-loader/src/test_host.rs` counts as test code, never against the loader gate.
pub(crate) fn loc_report(root: &Path) -> Outcome {
    for dir in sorted_entries(&root.join("crates"))? {
        if !dir.is_dir() {
            continue;
        }
        let mut files = Vec::new();
        rust_files(&dir, &mut files)?;
        let (mut prod_total, mut test_total) = (0, 0);
        for file in files {
            let relative = rel(root, &file);
            let text = std::fs::read_to_string(&file).map_err(|e| format!("{relative}: {e}"))?;
            let (prod, test) = count_lines(&text);
            let (prod, test) = if test_file(Path::new(&relative)) {
                (0, prod + test)
            } else {
                (prod, test)
            };
            prod_total += prod;
            test_total += test;
            println!("loc {relative} production={prod} test={test}");
        }
        println!(
            "loc-crate {} production={prod_total} test={test_total}",
            rel(root, &dir)
        );
    }
    Ok(Vec::new())
}
