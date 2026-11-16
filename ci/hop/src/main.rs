// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `ci/hop`: no thread hop around a plugin entry (ABI-MIN3-INTERFACE §15 rule 10, §0 I10, §10.7; owner W1-H0).
//!
//! `entry::guard` is the only entry path and is always called inline, on the thread that runs the plugin. A
//! syn scan of the MIN-3 entry machinery (`busbar-plugin-abi[host]` and plugin-loader's MIN-3 files) refuses:
//! - a call of `on_plugin_thread` anywhere but stage.rs's `dlopen_on_worker`, `dlclose_on_worker`,
//!   `open_on_worker` and `close_on_worker` (busbar-ffi's dlopen/dlclose, W1-L1) and `name_still_loaded` probe, and one call in admit.rs (admit's `dlopen` with the `busbar_plugin()` call):
//!   none is a plugin entry;
//! - a raw vtable call (a call through a fn-pointer field, `(vt.f)(..)`) outside a closure passed to `guard`;
//! - a `guard` call inside a closure passed to `spawn_blocking`, `on_plugin_thread` or `std::thread::spawn`,
//!   except the one `spawn_blocking` in `StoreLane::run` (adapters/store.rs, §11.3: an `F_BLOCKING_FILE` store's
//!   whole chains run on the store lane, guard and all). Pinning that method's callers is W1-X1's (§17 X1, r11).
//!
//! Test code is skipped: `#[cfg(test)]` items and modules, `#[test]` fns, and `tests` directories. The 1.5
//! dispatch beside the MIN-3 files (plugin-loader `dispatch/**` and the doors) hops by design until W3-D-LOADER
//! deletes it; that task widens `SCOPE` to the whole crate.
//!
//! Usage: `busbar-ci-hop` from anywhere in the checkout. Each finding prints as one line and fails the run.

#![forbid(unsafe_code)]
#![doc(test(attr(forbid(unsafe_code))))]

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Attribute, Expr, ExprCall, ExprMethodCall, ImplItemFn, ItemFn, ItemImpl, ItemMod, Meta};

/// The MIN-3 entry machinery, relative to the repository root.
const SCOPE: [&str; 9] = [
    "crates/busbar-plugin-abi/src/host_side",
    "crates/plugin-loader/src/adapters",
    "crates/plugin-loader/src/encode",
    "crates/plugin-loader/src/ports",
    "crates/plugin-loader/src/admit.rs",
    "crates/plugin-loader/src/instance.rs",
    "crates/plugin-loader/src/refusal.rs",
    "crates/plugin-loader/src/scan.rs",
    "crates/plugin-loader/src/stage.rs",
];
const STAGE: &str = "crates/plugin-loader/src/stage.rs";
/// stage.rs's dlopen and dlclose on the worker and its RTLD_NOLOAD probe (§11.1): no plugin code runs there
/// beyond the image's constructors.
const STAGE_HOPS: [&str; 5] = [
    "dlopen_on_worker",
    "dlclose_on_worker",
    "open_on_worker",
    "close_on_worker",
    "name_still_loaded",
];
const ADMIT: &str = "crates/plugin-loader/src/admit.rs";
const STORE_ADAPTER: &str = "crates/plugin-loader/src/adapters/store.rs";

fn main() -> ExitCode {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    match scan_tree(&root) {
        Ok(findings) if findings.is_empty() => {
            println!("hop: clean");
            ExitCode::SUCCESS
        }
        Ok(findings) => {
            for finding in &findings {
                println!("hop: {finding}");
            }
            ExitCode::FAILURE
        }
        Err(error) => {
            println!("hop: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Every finding in the checkout at `root`.
fn scan_tree(root: &Path) -> Result<Vec<String>, String> {
    let mut files = Vec::new();
    for scope in SCOPE {
        collect(&root.join(scope), &mut files)?;
    }
    files.sort();
    let mut findings = Vec::new();
    for file in files {
        let rel = file
            .strip_prefix(root)
            .map_err(|_| format!("{} is outside the checkout", file.display()))?;
        let rel = rel.to_string_lossy().replace('\\', "/");
        let text = std::fs::read_to_string(&file).map_err(|e| format!("{rel}: {e}"))?;
        findings.extend(scan_source(&rel, &text));
    }
    Ok(findings)
}

/// The `.rs` files under `path` (a file or a directory), `tests` directories and `*_tests.rs` files left out.
fn collect(path: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
    if path.is_file() {
        out.push(path.to_path_buf());
        return Ok(());
    }
    let entries = std::fs::read_dir(path).map_err(|e| format!("{}: {e}", path.display()))?;
    for entry in entries {
        let path = entry.map_err(|e| e.to_string())?.path();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if path.is_dir() {
            if name != "tests" {
                collect(&path, out)?;
            }
        } else if name.ends_with(".rs") && !name.ends_with("_tests.rs") {
            out.push(path);
        }
    }
    Ok(())
}

/// The findings in one source file, `rel` being its path from the repository root.
fn scan_source(rel: &str, text: &str) -> Vec<String> {
    let file = match syn::parse_file(text) {
        Ok(file) => file,
        Err(error) => return vec![format!("{rel}: cannot parse: {error}")],
    };
    let mut scan = Scan {
        rel,
        function: String::new(),
        self_ty: String::new(),
        hop: 0,
        guarded: 0,
        admit_hops: 0,
        findings: Vec::new(),
    };
    scan.visit_file(&file);
    scan.findings
}

struct Scan<'a> {
    rel: &'a str,
    /// The fn being read (empty at item level).
    function: String,
    /// The `impl` block's self type (empty outside one).
    self_ty: String,
    /// Closures passed to a thread hop that enclose the expression being read.
    hop: usize,
    /// Closures passed to `guard` that enclose the expression being read.
    guarded: usize,
    admit_hops: usize,
    findings: Vec<String>,
}

impl Scan<'_> {
    fn finding(&mut self, at: &impl Spanned, why: &str) {
        let line = at.span().start().line;
        self.findings.push(format!("{}:{line}: {why}", self.rel));
    }

    /// Reads a hop's arguments as hop closures.
    fn hop_args<'e>(&mut self, args: impl IntoIterator<Item = &'e Expr>) {
        self.hop += 1;
        for arg in args {
            self.visit_expr(arg);
        }
        self.hop -= 1;
    }

    /// Whether `on_plugin_thread` may be called from the fn being read.
    fn hop_allowed(&mut self) -> bool {
        if self.rel == STAGE {
            return STAGE_HOPS.contains(&self.function.as_str());
        }
        if self.rel == ADMIT {
            self.admit_hops += 1;
            return self.admit_hops == 1;
        }
        false
    }
}

/// The last segment of a call's callee path (`entry::guard` -> `guard`), and whether the path names `thread`.
fn callee(func: &Expr) -> Option<(String, bool)> {
    let Expr::Path(path) = func else {
        return None;
    };
    let segments = &path.path.segments;
    let last = segments.last()?.ident.to_string();
    let thread = segments.iter().any(|s| s.ident == "thread");
    Some((last, thread))
}

/// A call through a fn-pointer field: `(x.f)(..)`, the only way Rust calls one.
fn raw_field_call(func: &Expr) -> bool {
    match func {
        Expr::Paren(inner) => matches!(*inner.expr, Expr::Field(_)),
        Expr::Field(_) => true,
        _ => false,
    }
}

/// `#[test]`, `#[cfg(test)]` or `#[cfg(all(test, ..))]`.
fn is_test(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attr| {
        if attr.path().is_ident("test") {
            return true;
        }
        if !attr.path().is_ident("cfg") {
            return false;
        }
        match attr.parse_args::<Meta>() {
            Ok(Meta::Path(path)) => path.is_ident("test"),
            Ok(Meta::List(list)) if list.path.is_ident("all") => list
                .tokens
                .clone()
                .into_iter()
                .next()
                .is_some_and(|first| first.to_string() == "test"),
            _ => false,
        }
    })
}

impl<'ast> Visit<'ast> for Scan<'_> {
    fn visit_item_mod(&mut self, node: &'ast ItemMod) {
        if !is_test(&node.attrs) {
            visit::visit_item_mod(self, node);
        }
    }

    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        if is_test(&node.attrs) {
            return;
        }
        let outer = std::mem::replace(&mut self.function, node.sig.ident.to_string());
        visit::visit_item_fn(self, node);
        self.function = outer;
    }

    fn visit_item_impl(&mut self, node: &'ast ItemImpl) {
        if is_test(&node.attrs) {
            return;
        }
        let name = match &*node.self_ty {
            syn::Type::Path(path) => path
                .path
                .segments
                .last()
                .map(|s| s.ident.to_string())
                .unwrap_or_default(),
            _ => String::new(),
        };
        let outer = std::mem::replace(&mut self.self_ty, name);
        visit::visit_item_impl(self, node);
        self.self_ty = outer;
    }

    fn visit_impl_item_fn(&mut self, node: &'ast ImplItemFn) {
        if is_test(&node.attrs) {
            return;
        }
        let outer = std::mem::replace(&mut self.function, node.sig.ident.to_string());
        visit::visit_impl_item_fn(self, node);
        self.function = outer;
    }

    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        match callee(&node.func) {
            Some((name, _)) if name == "on_plugin_thread" => {
                if !self.hop_allowed() {
                    self.finding(
                        node,
                        "on_plugin_thread outside stage.rs's dlopen/dlclose/probe and admit's dlopen (§15 rule 10)",
                    );
                }
                self.hop_args(&node.args);
            }
            Some((name, _)) if name == "spawn_blocking" => {
                let store_lane = self.rel == STORE_ADAPTER
                    && self.self_ty == "StoreLane"
                    && self.function == "run";
                if store_lane {
                    visit::visit_expr_call(self, node);
                } else {
                    self.hop_args(&node.args);
                }
            }
            Some((name, true)) if name == "spawn" => self.hop_args(&node.args),
            Some((name, _)) if name == "guard" => {
                if self.hop > 0 {
                    self.finding(
                        node,
                        "entry::guard inside a closure passed to a thread hop; call it inline (I10)",
                    );
                }
                self.guarded += 1;
                for arg in &node.args {
                    self.visit_expr(arg);
                }
                self.guarded -= 1;
            }
            _ => {
                if raw_field_call(&node.func) && self.guarded == 0 {
                    self.finding(
                        node,
                        "a raw vtable call outside a closure passed to entry::guard (I10)",
                    );
                }
                visit::visit_expr_call(self, node);
            }
        }
    }

    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        if node.method == "spawn_blocking" {
            self.visit_expr(&node.receiver);
            self.hop_args(&node.args);
        } else {
            visit::visit_expr_method_call(self, node);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOST: &str = "crates/busbar-plugin-abi/src/host_side/driver.rs";

    #[test]
    fn on_plugin_thread_is_allowed_only_at_the_named_sites() {
        let probe = "fn name_still_loaded(n: &str) -> bool { crate::ffi_thread::on_plugin_thread(|| true).is_ok() }
                     fn dlopen_on_worker() { on_plugin_thread(|| ()); }
                     fn open_on_worker() { on_plugin_thread(|| ()); }
                     fn close_on_worker() { on_plugin_thread(|| ()); }";
        assert!(scan_source(STAGE, probe).is_empty());
        let other = "fn sweep() { crate::ffi_thread::on_plugin_thread(|| ()); }";
        assert_eq!(scan_source(STAGE, other).len(), 1);
        assert_eq!(scan_source(HOST, other).len(), 1);
        let admit =
            "fn admit() { on_plugin_thread(|| ()); } fn again() { on_plugin_thread(|| ()); }";
        let found = scan_source(ADMIT, admit);
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(
            found[0].starts_with("crates/plugin-loader/src/admit.rs:1:"),
            "{found:?}"
        );
    }

    #[test]
    fn a_guard_inside_a_hop_is_refused() {
        for hop in [
            "fn f() { tokio::task::spawn_blocking(move || entry::guard(o, 1, None, |out| 0)); }",
            "fn f() { handle.spawn_blocking(move || guard(o, 1, None, |out| 0)); }",
            "fn f() { std::thread::spawn(move || { guard(o, 1, None, |out| 0) }); }",
            "fn dlopen_on_worker() { on_plugin_thread(|| guard(o, 1, None, |out| 0)); }",
        ] {
            let found = scan_source(STAGE, hop);
            assert_eq!(found.len(), 1, "{hop}: {found:?}");
            assert!(found[0].contains("thread hop"), "{found:?}");
        }
        let lane = "impl StoreLane { fn run(&self) { tokio::task::spawn_blocking(move || guard(o, 1, None, |out| 0)); } }";
        assert!(scan_source(STORE_ADAPTER, lane).is_empty());
        let not_run = "impl StoreLane { fn other(&self) { tokio::task::spawn_blocking(move || guard(o, 1, None, |out| 0)); } }";
        assert_eq!(scan_source(STORE_ADAPTER, not_run).len(), 1);
        assert_eq!(scan_source(HOST, lane).len(), 1);
        assert!(scan_source(
            HOST,
            "fn f() { pool.spawn(|| guard(o, 1, None, |out| 0)); }"
        )
        .is_empty());
    }

    #[test]
    fn a_raw_vtable_call_runs_only_inside_guard() {
        let bare = "fn resume(vt: &Vt) -> u32 { (vt.resume)(core::ptr::null_mut(), 7) }";
        let found = scan_source(HOST, bare);
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(
            found[0].starts_with(&format!("{HOST}:1: a raw vtable call")),
            "{found:?}"
        );
        let inline = "fn resume(vt: &Vt) -> u32 { entry::guard(owner, 58, None, |out| (vt.resume)(out, 7)) }";
        assert!(scan_source(HOST, inline).is_empty());
        assert!(scan_source(HOST, "fn f(x: &X) -> u32 { x.method(1) + f(2) }").is_empty());
    }

    #[test]
    fn test_code_is_skipped() {
        let tests = "#[cfg(test)] mod tests { fn f() { (vt.resume)(1); on_plugin_thread(|| ()); } }
                     #[test] fn t() { (vt.close)(1); }
                     #[cfg(all(test, unix))] fn u() { (vt.close)(1); }";
        assert!(scan_source(HOST, tests).is_empty());
        assert_eq!(
            scan_source(HOST, "#[cfg(unix)] fn u() { (vt.close)(1); }").len(),
            1
        );
    }

    #[test]
    fn an_unparsable_file_is_a_finding() {
        assert_eq!(scan_source(HOST, "fn (").len(), 1);
    }

    #[test]
    fn the_tree_has_no_hop() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let findings = scan_tree(&root).expect("scan");
        assert!(findings.is_empty(), "{}", findings.join("\n"));
    }
}
