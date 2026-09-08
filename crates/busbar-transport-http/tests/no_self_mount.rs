// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A PLUGIN NEVER SELF-MOUNTS — asserted over this crate's own callable surface.
//!
//! ## The rule, and why a name is the whole of it
//!
//! No kind's ABI exposes `mount`, `serve`, `bind` or `on_upgrade`. A plugin that needs a route
//! DECLARES it, and the kernel mounts the declared table verbatim. The four words are not banned
//! because they are ugly: each one names a thing the kernel does, and a plugin that offers a
//! function by one of those names is offering to do it instead — which is the coupling the
//! declare-and-be-mounted seam exists to remove. The body may be innocent today; the name is the
//! thing a caller reaches for, and the caller that reaches for it is the one that will be written
//! next year by somebody who read the signature and not the body.
//!
//! So this is checked on the NAME, over the source, rather than left to whoever reviews the diff.
//!
//! ## What is scanned, and what this test does not judge
//!
//! Every `pub fn` and `pub async fn` in this crate's own `src/` tree — the callable surface, which
//! is what "no kind's ABI exposes" is about. A private helper may be called whatever its author
//! finds clearest; nobody outside can reach it, and the ABI is what the rule names.
//!
//! Two things are deliberately NOT judged here. Module and type names are the kind-shape row's,
//! not this cell's: a module called `mount` is a noun about the declared surface it reads — the
//! surface vocabulary itself calls a document's path prefix a mount — and deciding whether the
//! shape row should also refuse the noun is a naming decision for the whole kind at once, not one
//! crate's to make on its own. And the four words appearing in prose is not a finding: this file
//! is full of them.

use std::path::{Path, PathBuf};

/// The four words no kind's ABI exposes.
const SELF_MOUNT_VERBS: &[&str] = &["mount", "serve", "bind", "on_upgrade"];

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// The name a `pub fn` line declares, if the line declares one.
///
/// Read off the text rather than off a parse: this crate may not take a dependency to read its own
/// source, and the shape being matched — `pub fn NAME` at the head of a line, with the generic
/// parameters, the arguments and the body all after it — is the one rustfmt guarantees. A
/// `pub(crate)` or `pub(super)` function is not on the surface and is not read.
fn public_fn_name(line: &str) -> Option<&str> {
    let rest = line.trim_start().strip_prefix("pub ")?;
    let rest = rest.strip_prefix("async ").unwrap_or(rest);
    let rest = rest.strip_prefix("unsafe ").unwrap_or(rest);
    let rest = rest.strip_prefix("fn ")?;
    let end = rest
        .find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .unwrap_or(rest.len());
    Some(&rest[..end])
}

/// No function this crate publishes is named for something the kernel does.
#[test]
fn no_public_function_offers_to_mount_serve_bind_or_upgrade() {
    let mut files = Vec::new();
    rust_files(&crate_root().join("src"), &mut files);
    assert!(
        !files.is_empty(),
        "the scan found no source to judge, which is a broken test rather than a clean crate"
    );
    let mut found: Vec<String> = Vec::new();
    for file in &files {
        let text =
            std::fs::read_to_string(file).expect("a source file this crate owns is readable");
        for line in text.lines() {
            let Some(name) = public_fn_name(line) else {
                continue;
            };
            if SELF_MOUNT_VERBS.contains(&name) {
                found.push(format!("{}: `pub fn {name}`", file.display()));
            }
        }
    }
    assert!(
        found.is_empty(),
        "a plugin declares a route and the kernel mounts it; this crate offers to do it itself:\n  \
         {}",
        found.join("\n  ")
    );
}

/// The scan is not vacuous: each of the four words is planted and the reader is required to find
/// it, and the shapes that merely LOOK like it are required not to fire.
#[test]
fn the_scan_would_catch_a_planted_verb() {
    for verb in SELF_MOUNT_VERBS {
        let planted = format!("pub fn {verb}(driver: &dyn UnitDriver) -> Answer {{");
        assert_eq!(
            public_fn_name(&planted),
            Some(*verb),
            "the reader must find `{verb}` where it is planted"
        );
        let planted_async = format!("    pub async fn {verb}<'a>(&'a self) -> Fut<'a, ()> {{");
        assert_eq!(
            public_fn_name(&planted_async),
            Some(*verb),
            "and on an async one, indented, with lifetimes"
        );
    }
    // A function whose name merely BEGINS with one of the words is a different function.
    assert_eq!(
        public_fn_name("pub fn serve_count() -> usize {"),
        Some("serve_count")
    );
    assert!(!SELF_MOUNT_VERBS.contains(&"serve_count"));
    // Not on the surface, so not this rule's business.
    assert_eq!(public_fn_name("pub(crate) fn serve() {"), None);
    assert_eq!(public_fn_name("fn serve() {"), None);
    // And prose naming the words is not a declaration.
    assert_eq!(
        public_fn_name("/// the kernel will mount and serve this"),
        None
    );
}
