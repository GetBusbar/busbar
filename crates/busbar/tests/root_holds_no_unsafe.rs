// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE COMPOSITION ROOT HOLDS NO `unsafe` (status row 195; coordinator ruling (a), BUSBAR-1.6.0.md
//! l.272-274: the root is `forbid(unsafe_code)`; the loader holds the reviewed `unsafe`, and a
//! door-root crate's door is admitted there, by `open_linked`, never here). The crate root forbids
//! it, nothing under `src/` lifts the forbid, and no source line under `src/` or `build.rs` writes an
//! `unsafe` block, fn, impl or trait; the generated tables the root includes are judged by the same
//! scan of their generator (`src/linked_gen.rs`, `build.rs`), which writes none. RED: a planted
//! `unsafe` block, an `allow(unsafe_code)`, and a crate root without the forbid are each seen.

use std::path::{Path, PathBuf};

/// Every `.rs` file under `dir`, recursively.
fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("read a source directory") {
        let path = entry.expect("a directory entry").path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// The code of `src`: each line up to its `//` comment, string literals blanked (a refusal text may
/// say "unsafe"; code is what the scan judges).
fn code_lines(src: &str) -> Vec<String> {
    src.lines()
        .map(|line| {
            let mut code = String::new();
            let mut in_str = false;
            let mut chars = line.chars().peekable();
            while let Some(c) = chars.next() {
                if in_str {
                    if c == '\\' {
                        chars.next();
                    } else if c == '"' {
                        in_str = false;
                        code.push('"');
                    }
                    continue;
                }
                if c == '"' {
                    in_str = true;
                    code.push('"');
                    continue;
                }
                if c == '/' && chars.peek() == Some(&'/') {
                    break;
                }
                code.push(c);
            }
            code
        })
        .collect()
}

/// Every `unsafe` the code of `src` writes, or a lift of the forbid, as `line: text`.
fn findings(src: &str) -> Vec<String> {
    let mut out = Vec::new();
    for (n, code) in code_lines(src).iter().enumerate() {
        let words: Vec<&str> = code
            .split(|c: char| !(c.is_alphanumeric() || c == '_'))
            .filter(|w| !w.is_empty())
            .collect();
        if words.contains(&"unsafe") || code.contains("unsafe_code)") && code.contains("allow") {
            out.push(format!("{}: {}", n + 1, code.trim()));
        }
    }
    out
}

/// The root's own sources, its build script and its generator.
fn root_sources() -> Vec<PathBuf> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = vec![dir.join("build.rs")];
    rust_files(&dir.join("src"), &mut files);
    files
}

#[test]
fn the_composition_root_writes_no_unsafe() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let main = std::fs::read_to_string(dir.join("src/main.rs")).expect("read main.rs");
    assert!(
        main.lines().any(|l| l.trim() == "#![forbid(unsafe_code)]"),
        "the crate root forbids unsafe code"
    );
    let files = root_sources();
    assert!(
        files.len() > 50,
        "the scan reads the root's sources: {}",
        files.len()
    );
    let mut found = Vec::new();
    for file in &files {
        let src = std::fs::read_to_string(file).expect("read a root source");
        for f in findings(&src) {
            found.push(format!("{}:{f}", file.display()));
        }
    }
    assert!(
        found.is_empty(),
        "the root writes `unsafe`:\n{}",
        found.join("\n")
    );
}

/// RED: the scan sees what it forbids, and passes what only names the word.
#[test]
fn the_unsafe_scan_sees_what_it_forbids() {
    assert_eq!(findings("fn f() { unsafe { g() } }").len(), 1);
    assert_eq!(findings("pub unsafe fn f() {}").len(), 1);
    assert_eq!(findings("unsafe impl Send for X {}").len(), 1);
    assert_eq!(findings("#[allow(unsafe_code)]").len(), 1);
    assert!(findings("// an unsafe comment").is_empty());
    assert!(findings("let s = \"no unsafe here\";").is_empty());
    assert!(findings("#![forbid(unsafe_code)]").is_empty());
}

/// Every `#[macro_export]` macro of `busbar-contract` whose definition writes `unsafe`, or invokes
/// one that does: `(name, body)` read off the contract's sources, closed over invocation.
fn unsafe_arm_macros() -> Vec<String> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../busbar-contract/src");
    let mut files = Vec::new();
    rust_files(&dir, &mut files);
    let mut macros: Vec<(String, String)> = Vec::new();
    for file in &files {
        let src = std::fs::read_to_string(file).expect("read a contract source");
        let parts: Vec<&str> = src.split("macro_rules!").collect();
        for (n, part) in parts.iter().enumerate().skip(1) {
            if !parts[n - 1].trim_end().ends_with("#[macro_export]")
                && !parts[n - 1]
                    .lines()
                    .rev()
                    .take(4)
                    .any(|l| l.trim() == "#[macro_export]")
            {
                continue;
            }
            let name: String = part
                .trim_start()
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            macros.push((name, code_lines(part).join("\n")));
        }
    }
    let mut unsafe_arms: Vec<String> = macros
        .iter()
        .filter(|(_, body)| findings(body).iter().any(|f| f.contains("unsafe")))
        .map(|(name, _)| name.clone())
        .collect();
    loop {
        let more: Vec<String> = macros
            .iter()
            .filter(|(name, body)| {
                !unsafe_arms.contains(name)
                    && unsafe_arms.iter().any(|m| body.contains(&format!("{m}!")))
            })
            .map(|(name, _)| name.clone())
            .collect();
        if more.is_empty() {
            break;
        }
        unsafe_arms.extend(more);
    }
    unsafe_arms
}

/// Every invocation, in `src`'s code, of a macro in `names`, as `line: text`.
fn invocations(src: &str, names: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for (n, code) in code_lines(src).iter().enumerate() {
        for name in names {
            let at = code.match_indices(&format!("{name}!")).any(|(i, _)| {
                code[..i]
                    .chars()
                    .last()
                    .is_none_or(|c| !(c.is_alphanumeric() || c == '_'))
            });
            if at {
                out.push(format!("{}: {}", n + 1, code.trim()));
            }
        }
    }
    out
}

#[test]
fn the_composition_root_invokes_no_macro_that_writes_unsafe() {
    let names = unsafe_arm_macros();
    assert!(
        names.iter().any(|n| n == "plugin_door"),
        "the contract's door macro writes `unsafe` and is in the set: {names:?}"
    );
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    rust_files(&dir.join("src"), &mut files);
    let mut found = Vec::new();
    for file in &files {
        let src = std::fs::read_to_string(file).expect("read a root source");
        for f in invocations(&src, &names) {
            found.push(format!("{}:{f}", file.display()));
        }
    }
    assert!(
        found.is_empty(),
        "the root invokes a macro that writes `unsafe` (build the door in the loader's fixtures):\n{}",
        found.join("\n")
    );
}

/// RED: the macro scan sees an invocation, qualified or not, and passes a name that only contains
/// a macro's name.
#[test]
fn the_macro_scan_sees_an_invocation() {
    let names = vec!["plugin_door".to_string()];
    assert_eq!(
        invocations("busbar_contract::plugin_door! {", &names).len(),
        1
    );
    assert_eq!(invocations("    plugin_door!(x)", &names).len(), 1);
    assert!(invocations("my_plugin_door!(x)", &names).is_empty());
    assert!(invocations("// plugin_door! in a comment", &names).is_empty());
}
