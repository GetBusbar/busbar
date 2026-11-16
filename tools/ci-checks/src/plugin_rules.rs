// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The per-plugin-repo rules of IF §15, run from a plugin repo's CI as `busbar-ci-checks plugin-rules
//! <repo-dir> [--dev-edges]` (the job line is in busbar-release's plugin template):
//!
//! - rule 1a: the only busbar normal/build dependency is `busbar-plugin-abi`, plus a kind-free helper
//!   whose only busbar dependency is `busbar-plugin-abi` with default features; no other plugin crate,
//!   `busbar-contract`, `plugin-loader`, `busbar-kernel*` or `busbar-core-*`;
//! - rule 1b (`--dev-edges`, enabled by each repo's port MR): the only direct busbar dev-dependency is
//!   `busbar-plugin-test` (or the repo's own crates);
//! - rule 3: no `host` feature on `busbar-plugin-abi` through a normal or build edge;
//! - rule 8: no `vendor`/`third_party` directory, no `path =` outside the repo, every `[patch]` entry has
//!   an `upstream PR:` comment, no `legacy`/`historical`/`source_interpretation`/`migration` module;
//! - rule 9: `std::fs`, `File`, `OpenOptions`, `tokio::fs` only in store-sqlite and secret-file;
//! - C-TRANSPORT test 11's fleet lint: no `is_loopback`, `reaches_loopback_only` or loopback `http://`.
//!
//! Source scans read production items only (a `#[cfg(test)]` module or `#[test]` fn is skipped).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use busbar_contract::json::{self, JsonContainerTrait, JsonValueTrait};
use proc_macro2::{TokenStream, TokenTree};
use quote::ToTokens;
use syn::Item;

use super::{host_link, is_test, item_attrs, rel, supply, Outcome};

const KINDS: [&str; 7] = [
    "auth",
    "export",
    "hook",
    "plane",
    "secret",
    "store",
    "transport",
];
const BANNED_MODULE_WORDS: [&str; 4] =
    ["legacy", "historical", "source_interpretation", "migration"];
const VENDOR_DIRS: [&str; 3] = ["vendor", "third_party", "third-party"];
const FS_REPOS: [&str; 2] = ["busbar-store-sqlite", "busbar-secret-file"];

/// `busbar-{auth,export,hook,plane,secret,store,transport}-*`.
pub(crate) fn is_plugin_crate(name: &str) -> bool {
    KINDS.iter().any(|kind| {
        name.strip_prefix("busbar-")
            .is_some_and(|rest| rest.starts_with(&format!("{kind}-")))
    })
}

fn is_core_only(name: &str) -> bool {
    matches!(
        name,
        "busbar-contract" | "plugin-loader" | "busbar-plugin-test"
    ) || name.starts_with("busbar-kernel")
        || name.starts_with("busbar-core-")
}

/// The declared dependencies of the workspace package `name`.
fn deps_of<'a>(packages: &[&'a json::Value], name: &str) -> Vec<&'a json::Value> {
    packages
        .iter()
        .filter(|p| p["name"].as_str() == Some(name))
        .flat_map(|p| p["dependencies"].as_array().into_iter().flatten())
        .collect()
}

/// Rules 1a, 1b and 3 over `cargo metadata --no-deps` of a plugin repo.
pub(crate) fn dep_findings(meta: &json::Value, dev_edges: bool) -> Vec<String> {
    let packages: Vec<&json::Value> = meta["packages"].as_array().into_iter().flatten().collect();
    let members: BTreeSet<&str> = packages.iter().filter_map(|p| p["name"].as_str()).collect();
    let mut findings = Vec::new();
    for package in &packages {
        let pname = package["name"].as_str().unwrap_or("?");
        for dep in package["dependencies"].as_array().into_iter().flatten() {
            let dname = dep["name"].as_str().unwrap_or("");
            if !dname.starts_with("busbar-") && dname != "plugin-loader" {
                continue;
            }
            match dep["kind"].as_str() {
                Some("dev") => {
                    if dev_edges && dname != "busbar-plugin-test" && !members.contains(dname) {
                        findings.push(format!(
                            "{pname}: direct dev-dependency on {dname}; the only busbar dev-dependency is busbar-plugin-test (§15 rule 1b)"
                        ));
                    }
                }
                _ => {
                    if dname == "busbar-plugin-abi" {
                        let host = dep["features"]
                            .as_array()
                            .into_iter()
                            .flatten()
                            .any(|feature| feature == "host");
                        if host {
                            findings.push(format!(
                                "{pname}: enables busbar-plugin-abi/host on a normal or build edge (§15 rule 3)"
                            ));
                        }
                    } else if is_core_only(dname) {
                        findings.push(format!(
                            "{pname}: depends on {dname}; a plugin's only busbar dependency is busbar-plugin-abi (§15 rule 1a)"
                        ));
                    } else if members.contains(dname) {
                        if !is_plugin_crate(dname) {
                            for inner in deps_of(&packages, dname) {
                                let iname = inner["name"].as_str().unwrap_or("");
                                let normal = !matches!(inner["kind"].as_str(), Some("dev"));
                                if normal && iname.starts_with("busbar-") {
                                    if iname != "busbar-plugin-abi" {
                                        findings.push(format!(
                                            "{dname}: helper depends on {iname}; a kind-free helper's only busbar dependency is busbar-plugin-abi (§15 rule 1a)"
                                        ));
                                    } else if inner["uses_default_features"] == false {
                                        findings.push(format!(
                                            "{dname}: helper takes busbar-plugin-abi without default features (§15 rule 1a)"
                                        ));
                                    }
                                }
                            }
                        }
                    } else if is_plugin_crate(dname) {
                        findings.push(format!(
                            "{pname}: depends on another plugin crate, {dname} (§15 rule 1a)"
                        ));
                    } else {
                        findings.push(format!(
                            "{pname}: depends on {dname}; a plugin's only busbar dependency is busbar-plugin-abi (§15 rule 1a)"
                        ));
                    }
                }
            }
        }
    }
    findings.sort();
    findings.dedup();
    findings
}

/// Rule 8's module-name ban: a path component under `src/` that is, or whose stem is, exactly one of the
/// four words. `tests/`, `benches/` and `examples/` are not under `src/`.
pub(crate) fn banned_module_path(relative: &str) -> Option<String> {
    let parts: Vec<&str> = relative.split('/').collect();
    let src = parts.iter().position(|part| *part == "src")?;
    for part in &parts[src + 1..] {
        let stem = part.strip_suffix(".rs").unwrap_or(part);
        if BANNED_MODULE_WORDS.contains(&stem) {
            return Some(stem.to_string());
        }
    }
    None
}

pub(crate) fn is_vendor_dir(name: &str) -> bool {
    VENDOR_DIRS.contains(&name)
}

/// One lexed token: its line and text (delimiters are dropped so `std::{fs}` reads as `std::fs`).
#[derive(Debug, Clone)]
pub(crate) struct Tok {
    pub line: usize,
    pub text: String,
}

pub(crate) fn flatten(stream: TokenStream, out: &mut Vec<Tok>) {
    for tree in stream {
        match tree {
            TokenTree::Group(group) => flatten(group.stream(), out),
            TokenTree::Ident(ident) => out.push(Tok {
                line: ident.span().start().line,
                text: ident.to_string(),
            }),
            TokenTree::Punct(punct) => out.push(Tok {
                line: punct.span().start().line,
                text: punct.as_char().to_string(),
            }),
            TokenTree::Literal(literal) => out.push(Tok {
                line: literal.span().start().line,
                text: literal.to_string(),
            }),
        }
    }
}

fn production_items(items: &[Item], out: &mut Vec<Tok>) {
    for item in items {
        if is_test(item_attrs(item)) {
            continue;
        }
        if let Item::Mod(module) = item {
            if let Some((_, inner)) = &module.content {
                production_items(inner, out);
                continue;
            }
        }
        flatten(item.to_token_stream(), out);
    }
}

/// The production tokens of a source file. A file syn cannot parse is lexed whole (never skipped).
pub(crate) fn production_tokens(source: &str) -> Vec<Tok> {
    let mut out = Vec::new();
    match syn::parse_file(source) {
        Ok(file) => {
            if !is_test(&file.attrs) {
                production_items(&file.items, &mut out);
            }
        }
        Err(_) => {
            if let Ok(stream) = source.parse::<TokenStream>() {
                flatten(stream, &mut out);
            }
        }
    }
    out
}

/// Rule 9. `allowed` is true in store-sqlite and secret-file (the I1 list).
pub(crate) fn fs_findings(source: &str, file: &str, allowed: bool) -> Vec<String> {
    if allowed {
        return Vec::new();
    }
    let toks = production_tokens(source);
    let mut lines = BTreeSet::new();
    for (index, tok) in toks.iter().enumerate() {
        let hit = match tok.text.as_str() {
            "File" | "OpenOptions" => true,
            "fs" => {
                let colons =
                    index >= 3 && toks[index - 1].text == ":" && toks[index - 2].text == ":";
                colons
                    && (matches!(toks[index - 3].text.as_str(), "std" | "tokio")
                        || (index >= 6 && toks[index - 6].text == "os"))
            }
            _ => false,
        };
        if hit {
            lines.insert(tok.line);
        }
    }
    lines
        .into_iter()
        .map(|line| {
            format!("{file}:{line}: file access outside store-sqlite and secret-file (§15 rule 9)")
        })
        .collect()
}

/// C-TRANSPORT test 11's fleet lint.
pub(crate) fn loopback_findings(source: &str, file: &str) -> Vec<String> {
    let mut lines = BTreeSet::new();
    for tok in production_tokens(source) {
        let hit = matches!(
            tok.text.as_str(),
            "is_loopback" | "reaches_loopback_only" | "names_loopback"
        ) || ["http://127.0.0.1", "http://localhost", "http://[::1]"]
            .iter()
            .any(|url| tok.text.contains(url));
        if hit {
            lines.insert(tok.line);
        }
    }
    lines
        .into_iter()
        .map(|line| {
            format!("{file}:{line}: a loopback or plaintext allowance of a plugin's own (TRANSPORT-SECURITY-POLICY §8 test 11)")
        })
        .collect()
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
        .map_err(|error| format!("{}: {error}", dir.display()))?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .collect();
    entries.sort();
    for path in entries {
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if name == "target" || name == ".git" {
            continue;
        }
        if path.is_dir() {
            out.push(path.clone());
            walk(&path, out)?;
        } else {
            out.push(path);
        }
    }
    Ok(())
}

/// `plugin-rules <repo-dir> [--dev-edges]`
pub(crate) fn plugin_rules(args: &[String]) -> Outcome {
    let dev_edges = args.iter().any(|arg| arg == "--dev-edges");
    let dir = args
        .iter()
        .find(|arg| !arg.starts_with("--"))
        .ok_or("plugin-rules <repo-dir> [--dev-edges]")?;
    let root = std::fs::canonicalize(dir).map_err(|error| format!("{dir}: {error}"))?;
    let repo = root
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_string();
    let metadata = host_link::run_cargo(
        &root,
        &["metadata", "--no-deps", "--format-version", "1", "--locked"],
    )?;
    let metadata: json::Value = json::parse_value(metadata.as_bytes())
        .map_err(|error| format!("cargo metadata: {error}"))?;
    let mut findings = dep_findings(&metadata, dev_edges);
    let mut paths = Vec::new();
    walk(&root, &mut paths)?;
    for path in paths {
        let relative = rel(&root, &path);
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if path.is_dir() {
            if is_vendor_dir(name) {
                findings.push(format!(
                    "{relative}: a vendored tree (§15 rule 8: GitLab fork + [patch] + upstream PR)"
                ));
            }
            continue;
        }
        if name == "Cargo.toml" {
            let text =
                std::fs::read_to_string(&path).map_err(|error| format!("{relative}: {error}"))?;
            findings.extend(supply::manifest_findings(&root, &path, &text));
        }
        if path.extension().is_some_and(|ext| ext == "rs") {
            if let Some(word) = banned_module_path(&relative) {
                findings.push(format!("{relative}: a module named `{word}` (§15 rule 8)"));
            }
            let parts: Vec<&str> = relative.split('/').collect();
            let shipped = parts.contains(&"src")
                && !parts
                    .iter()
                    .any(|part| matches!(*part, "tests" | "benches" | "examples"));
            if shipped {
                let text = std::fs::read_to_string(&path)
                    .map_err(|error| format!("{relative}: {error}"))?;
                findings.extend(fs_findings(
                    &text,
                    &relative,
                    FS_REPOS.contains(&repo.as_str()),
                ));
                findings.extend(loopback_findings(&text, &relative));
            }
        }
    }
    Ok(findings)
}
