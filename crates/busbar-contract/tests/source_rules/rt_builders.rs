// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! LINT-RULES R40 `per-request-task` (LR-134): every core tokio runtime is built through
//! `busbar_kernel::rt`, the one place the work-count gate hooks task spawns. Production code
//! outside `crates/busbar-kernel/src/rt.rs` builds no runtime in any spelling: no path or `use`
//! through `tokio::runtime::{Builder, Runtime, LocalRuntime, *}`, no `new_current_thread` /
//! `new_multi_thread`, no `#[tokio::main]` / `#[tokio::test]` on a production item, and no core
//! `Cargo.toml` renames the tokio dependency.

use proc_macro2::{TokenStream, TokenTree};
use quote::ToTokens;

use crate::walk;

/// The one file that may build a runtime.
const RT: &str = "crates/busbar-kernel/src/rt.rs";

/// Justified exemptions: a path prefix and why it may build runtimes. Exactly this directory,
/// not its crate.
const EXEMPT: &[(&str, &str)] = &[(
    "crates/busbar-plugin-test/src/host_target/",
    "SDK-SAFE-TEST-HOST r7.1 s12.2 needs one runtime per test image inside the test-only \
     facade, and s10.6 forbids that facade depending on busbar-kernel (coordinator ruling \
     J41). The crate is never shipped (T-GUARD); no production path is loosened.",
)];

const RUNTIME_TYPES: &[&str] = &["Builder", "Runtime", "LocalRuntime"];
const BUILDER_FNS: &[&str] = &["new_current_thread", "new_multi_thread"];

/// Every runtime-building spelling in `ts`, as a short description.
fn hits(ts: TokenStream) -> Vec<String> {
    let toks: Vec<TokenTree> = ts.into_iter().collect();
    let mut out = Vec::new();
    for (i, t) in toks.iter().enumerate() {
        match t {
            TokenTree::Group(g) => out.extend(hits(g.stream())),
            TokenTree::Ident(id) if BUILDER_FNS.iter().any(|f| id == f) => {
                out.push(format!("`{id}`"));
            }
            TokenTree::Ident(id) if id == "runtime" || id == "tokio" => {
                // `<id> :: <next>`
                let colons = matches!(
                    (toks.get(i + 1), toks.get(i + 2)),
                    (Some(TokenTree::Punct(a)), Some(TokenTree::Punct(b)))
                        if a.as_char() == ':' && b.as_char() == ':'
                );
                if !colons {
                    continue;
                }
                match (id.to_string().as_str(), toks.get(i + 3)) {
                    ("runtime", Some(TokenTree::Ident(next)))
                        if RUNTIME_TYPES.iter().any(|r| next == r) =>
                    {
                        out.push(format!("`runtime::{next}`"));
                    }
                    ("runtime", Some(TokenTree::Punct(p))) if p.as_char() == '*' => {
                        out.push("`runtime::*`".into());
                    }
                    ("runtime", Some(TokenTree::Group(g))) => {
                        let inner = g.stream().into_iter().any(|t| match t {
                            TokenTree::Ident(i) => RUNTIME_TYPES.iter().any(|r| i == r),
                            TokenTree::Punct(p) => p.as_char() == '*',
                            _ => false,
                        });
                        if inner {
                            out.push("`runtime::{..}`".into());
                        }
                    }
                    ("tokio", Some(TokenTree::Ident(next))) if next == "main" || next == "test" => {
                        out.push(format!("`#[tokio::{next}]`"));
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }
    out
}

/// Every core crate directory under `crates/` (plugins are not core).
fn core_roots() -> Vec<String> {
    let mut roots: Vec<String> = std::fs::read_dir(walk::repo().join("crates"))
        .expect("crates/")
        .flatten()
        .filter(|e| e.path().join("src").is_dir())
        .map(|e| format!("crates/{}", e.file_name().to_string_lossy()))
        .filter(|rel| !walk::is_plugin_crate(&format!("{rel}/")))
        .collect();
    roots.sort();
    roots
}

#[test]
fn rt_builders_only_in_rt() {
    let roots: Vec<String> = core_roots().iter().map(|r| format!("{r}/src")).collect();
    let roots: Vec<&str> = roots.iter().map(String::as_str).collect();
    let mut found = Vec::new();
    for src in walk::production(&roots) {
        if src.rel == RT || EXEMPT.iter().any(|(prefix, _)| src.rel.starts_with(prefix)) {
            continue;
        }
        for item in walk::items(&src.file.items) {
            for hit in hits(item.to_token_stream()) {
                found.push(format!("{}:{}: {hit}", src.rel, walk::line_of(item)));
            }
        }
    }
    for root in core_roots() {
        let manifest = walk::repo().join(&root).join("Cargo.toml");
        let Ok(text) = std::fs::read_to_string(&manifest) else {
            continue;
        };
        if text.lines().any(|l| {
            let l = l.split('#').next().unwrap_or("");
            l.contains("package") && l.contains("\"tokio\"")
        }) {
            found.push(format!("{root}/Cargo.toml: renames the tokio dependency"));
        }
    }
    assert!(
        found.is_empty(),
        "R40: core builds tokio runtimes only through busbar_kernel::rt (the one place the \
         work-count gate counts spawns); build through `busbar_kernel::rt::current_thread()` / \
         `multi_thread()` instead:\n{}",
        found.join("\n")
    );
}

#[test]
fn the_rt_scan_sees_every_spelling() {
    let spellings = [
        "fn a() { tokio::runtime::Builder::new_multi_thread(); }",
        "use tokio::runtime::Builder as B;",
        "use tokio::runtime::{self, Runtime};",
        "use tokio::runtime::*;",
        "fn b() { let _ = tokio::runtime::Runtime::new(); }",
        "#[tokio::main] async fn main() {}",
        "fn c() { B::new_current_thread(); }",
    ];
    for s in spellings {
        let f: syn::File = syn::parse_str(s).unwrap();
        assert!(!hits(f.to_token_stream()).is_empty(), "missed: {s}");
    }
    for s in [
        "use crate::journal::runtime::{RuntimeJournal, StagedRun};",
        "fn d() { MeasurementRuntime::new(); tokio::runtime::Handle::current(); }",
    ] {
        let f: syn::File = syn::parse_str(s).unwrap();
        assert!(hits(f.to_token_stream()).is_empty(), "false hit: {s}");
    }
}
