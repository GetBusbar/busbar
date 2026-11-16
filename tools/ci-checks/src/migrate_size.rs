// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `migrate-size` job (MIGRATE-ON-BOOT r42 §7 (sz1)).
//!
//! R-SIZE/Δ2 voids the size numbers, so sizes are PRINTED and never gated. What is gated:
//! - **separation** (4)(5)(r17): `busbar-migrate`'s dependency tree (read from `Cargo.lock`, not
//!   entering the shared `busbar-contract` facade) holds no plugin-loader, no linked dist plugin
//!   crate (named by `dist/default`'s `[package.metadata.busbar.linked]`/`always-on` rows, no
//!   literal here), no `busbar-yaml`/`serde_yaml`, no `postcard`, no `sha2`; no `[[bin]]
//!   busbar-migrate` anywhere and one binary in the `Dockerfile`; the overlay words occur in no
//!   production source outside `crates/busbar-migrate`.
//! - **anchors** (3)(3b)(3c): every anchor fn is pinned in source (`migrate-anchors`) and, when a
//!   `cargo bloat --release -n 0 --message-format json` file is given in `MIGRATE_SIZE_BLOAT`
//!   (built with `CARGO_PROFILE_RELEASE_STRIP=none`), is a symbol in it.
//!
//! Printed: the line count (crate + seam + call path, gate 5,000 and 600 per plugin) and, with the
//! bloat file, each prefix's bytes, the distinct gateway sum (gate 300 KB) and linked plugins'
//! `<crate>::migrate::` prefixes (read from the manifest, (3d)).

use std::collections::BTreeSet;
use std::path::Path;

use super::{rel, rust_files, scan_source, sorted_entries};

/// AGREED 256: crate + seam + call path lines. Printed, not gated.
pub(crate) const LINE_GATE: usize = 5_000;
/// AGREED 256: the gateway's migrator bytes. Printed, not gated.
pub(crate) const BYTE_GATE: u64 = 300 * 1024;

const MIGRATE_CRATE: &str = "busbar-migrate";
/// The shared facade `busbar-migrate` is allowed to reach (YAML, digests); not entered.
const FACADE: &str = "busbar-contract";
/// The facade and the gateway's own config vocabulary the kept passes read (MIGRATE-ON-BOOT §A7
/// "Build target": the kernel with default features off, and its ledger's rate encoding). They
/// are the gateway's, linked anyway; a dependency of theirs is not one the migrator adds, so
/// they are not entered. A forbidden crate named directly by `busbar-migrate` is still found.
const NOT_ENTERED: [&str; 3] = [FACADE, "busbar-kernel", "busbar-kernel-ledger"];
/// Forbidden whatever the manifests say.
const FORBIDDEN: [&str; 5] = [
    "busbar-plugin-loader",
    "busbar-yaml",
    "serde_yaml",
    "postcard",
    "sha2",
];
const OVERLAY_WORDS: &[&str] = &[
    "BUSBAR_CONFIG_OVERLAY",
    "busbar-overlay.json",
    "DEFAULT_OVERLAY_FILENAME",
];

/// Fixed gateway prefixes (§7 table) and the anchor fn each carries (C1 rows).
const FIXED_PREFIXES: [&str; 5] = [
    "busbar_migrate::",
    "busbar::root::migrate::",
    "busbar_kernel::persistence::startup::Manifest::decode",
    "plugin_loader::dispatch::migrate::",
    "busbar_contract::abi::sdk::migrate::",
];
const ANCHOR_SYMBOLS: [&str; 5] = [
    "busbar_migrate::plan",
    "busbar::root::migrate::run",
    "busbar_kernel::persistence::startup::Manifest::decode",
    "plugin_loader::dispatch::migrate::settings_migration",
    "busbar_contract::abi::sdk::migrate::read_answer",
];

/// Lines counted for the 5,000 figure: crate, seam, and the call path.
const COUNTED_DIRS: [&str; 1] = ["crates/busbar-migrate/src"];
const COUNTED_FILES: [&str; 3] = [
    "crates/busbar/src/root/migrate.rs",
    "crates/plugin-loader/src/dispatch/migrate.rs",
    "crates/busbar-contract/src/abi/sdk/migrate.rs",
];

pub(crate) fn run(root: &Path) -> Result<Vec<String>, String> {
    let read = |file: &str| {
        std::fs::read_to_string(root.join(file)).map_err(|error| format!("{file}: {error}"))
    };
    let mut findings = super::migrate::anchors(root)?;

    // Separation.
    let dist = read("dist/default/Cargo.toml")?;
    let forbidden = forbidden_deps(&linked_crates(&dist));
    findings.extend(separation_deps(&read("Cargo.lock")?, &forbidden));
    let mut manifests = Vec::new();
    manifests_under(root, root, &mut manifests)?;
    for file in &manifests {
        let text = std::fs::read_to_string(file)
            .map_err(|error| format!("{}: {error}", rel(root, file)))?;
        findings.extend(bin_findings(&rel(root, file), &text));
    }
    findings.extend(dockerfile_findings(&read("Dockerfile")?));
    findings.extend(overlay_words(root)?);

    // Printed sizes.
    let mut lines = 0;
    let mut files = Vec::new();
    for dir in COUNTED_DIRS {
        rust_files(&root.join(dir), &mut files)?;
    }
    files.extend(COUNTED_FILES.iter().map(|file| root.join(file)));
    for file in &files {
        let text = std::fs::read_to_string(file)
            .map_err(|error| format!("{}: {error}", rel(root, file)))?;
        lines += counted_lines(&text);
    }
    println!(
        "migrate-size: lines {lines} (gate {LINE_GATE}; printed, not gated: R-SIZE/Δ2 voids the numbers)"
    );
    match std::env::var("MIGRATE_SIZE_BLOAT") {
        Ok(path) if !path.is_empty() => {
            let json = std::fs::read_to_string(&path).map_err(|error| format!("{path}: {error}"))?;
            let fns = parse_bloat(&json)?;
            let lock = read("dist/default/Cargo.lock")?;
            let prefixes = gateway_prefixes(&dist, &lock);
            findings.extend(anchors_missing(&fns));
            for prefix in &prefixes {
                println!(
                    "migrate-size: {} bytes in `{prefix}`",
                    gateway_bytes(&fns, std::slice::from_ref(prefix))
                );
            }
            let total = gateway_bytes(&fns, &prefixes);
            println!(
                "migrate-size: gateway {total} bytes (gate {BYTE_GATE}; printed, not gated)"
            );
        }
        _ => println!("migrate-size: bytes not measured (MIGRATE_SIZE_BLOAT unset); anchors checked in source only"),
    }
    Ok(findings)
}

/// Non-blank, non-`//` lines.
pub(crate) fn counted_lines(text: &str) -> usize {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with("//"))
        .count()
}

/// The `name = "value"` rows under `[section]`.
fn section_values(toml: &str, section: &str) -> Vec<String> {
    let mut inside = false;
    let mut values = Vec::new();
    for line in toml.lines().map(str::trim) {
        if line.starts_with('[') {
            inside = line == format!("[{section}]");
        } else if inside {
            if let Some((_, value)) = line.split_once('=') {
                let value = value.trim().trim_matches('"');
                if !value.is_empty() && !line.starts_with('#') {
                    values.push(value.to_owned());
                }
            }
        }
    }
    values
}

/// Every crate named by a `linked` or `always-on` row of the dist manifest.
pub(crate) fn linked_crates(dist: &str) -> BTreeSet<String> {
    [
        "package.metadata.busbar.linked",
        "package.metadata.busbar.always-on",
    ]
    .iter()
    .flat_map(|section| section_values(dist, section))
    .collect()
}

pub(crate) fn forbidden_deps(linked: &BTreeSet<String>) -> BTreeSet<String> {
    FORBIDDEN
        .iter()
        .map(|name| (*name).to_owned())
        .chain(linked.iter().cloned())
        .collect()
}

/// `(name, dependency names)` for each `[[package]]` of a lockfile.
fn lock_packages(lock: &str) -> Vec<(String, Vec<String>)> {
    let mut packages: Vec<(String, Vec<String>)> = Vec::new();
    let mut in_deps = false;
    for line in lock.lines().map(str::trim) {
        if line == "[[package]]" {
            packages.push((String::new(), Vec::new()));
            in_deps = false;
        } else if let Some(name) = line.strip_prefix("name = ") {
            if let Some(package) = packages.last_mut() {
                package.0 = name.trim_matches('"').to_owned();
            }
        } else if line.starts_with("dependencies = [") {
            in_deps = true;
        } else if line == "]" {
            in_deps = false;
        } else if in_deps {
            let dep = line.trim_matches(|c| c == '"' || c == ',');
            if let (Some(package), Some(name)) = (packages.last_mut(), dep.split(' ').next()) {
                package.1.push(name.to_owned());
            }
        }
    }
    packages
}

/// (4) Forbidden crates beneath `busbar-migrate`, not entering the contract facade.
pub(crate) fn separation_deps(lock: &str, forbidden: &BTreeSet<String>) -> Vec<String> {
    let packages = lock_packages(lock);
    let mut seen = BTreeSet::new();
    let mut stack = vec![MIGRATE_CRATE.to_owned()];
    let mut findings = Vec::new();
    while let Some(name) = stack.pop() {
        if !seen.insert(name.clone()) {
            continue;
        }
        for (package, deps) in &packages {
            if *package != name {
                continue;
            }
            for dep in deps {
                if forbidden.contains(dep) {
                    findings.push(format!(
                        "Cargo.lock: `{MIGRATE_CRATE}` reaches forbidden crate `{dep}` (via `{name}`); \
                         the migrator takes YAML and digests only from {FACADE}"
                    ));
                } else if !NOT_ENTERED.contains(&dep.as_str()) {
                    stack.push(dep.clone());
                }
            }
        }
    }
    findings.sort();
    findings.dedup();
    findings
}

/// (5) A `[[bin]]` named `busbar-migrate`.
pub(crate) fn bin_findings(file: &str, toml: &str) -> Vec<String> {
    let mut findings = Vec::new();
    let mut in_bin = false;
    for line in toml.lines().map(str::trim) {
        if line.starts_with('[') {
            in_bin = line == "[[bin]]";
        } else if in_bin && line.replace(' ', "") == format!("name=\"{MIGRATE_CRATE}\"") {
            findings.push(format!(
                "{file}: `[[bin]] {MIGRATE_CRATE}` exists; the migrator is a library"
            ));
        }
    }
    findings
}

/// (5) The Dockerfile copies one binary and never `busbar-migrate`.
pub(crate) fn dockerfile_findings(text: &str) -> Vec<String> {
    let copies = text
        .lines()
        .filter(|line| line.trim_start().starts_with("COPY binaries/"))
        .count();
    let mut findings = Vec::new();
    if copies != 1 {
        findings.push(format!(
            "Dockerfile: copies {copies} binaries, expected exactly one"
        ));
    }
    if text.contains(MIGRATE_CRATE) {
        findings.push(format!("Dockerfile: names `{MIGRATE_CRATE}`"));
    }
    findings
}

fn manifests_under(
    root: &Path,
    dir: &Path,
    out: &mut Vec<std::path::PathBuf>,
) -> Result<(), String> {
    for path in sorted_entries(dir)? {
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if path.is_dir() {
            if !matches!(name, "target" | ".git" | "node_modules") {
                manifests_under(root, &path, out)?;
            }
        } else if name == "Cargo.toml" {
            out.push(path);
        }
    }
    let _ = root;
    Ok(())
}

/// Lines of production literals, docs and identifiers that name an overlay word.
pub(crate) fn overlay_word_sites(text: &str) -> Vec<usize> {
    super::migrate::sites(text, OVERLAY_WORDS, true)
}

/// (r17) The overlay words in production source outside `crates/busbar-migrate`.
fn overlay_words(root: &Path) -> Result<Vec<String>, String> {
    let mut files = Vec::new();
    for dir in sorted_entries(&root.join("crates"))? {
        let owner = dir.file_name().is_some_and(|name| name == MIGRATE_CRATE);
        if !owner && dir.is_dir() {
            rust_files(&dir, &mut files)?;
        }
    }
    let mut hits = Vec::new();
    let mut test_modules = Vec::new();
    for file in files {
        let text = std::fs::read_to_string(&file)
            .map_err(|error| format!("{}: {error}", rel(root, &file)))?;
        test_modules.extend(scan_source(&file, &text).test_modules);
        for line in overlay_word_sites(&text) {
            hits.push((file.clone(), line));
        }
    }
    Ok(hits
        .into_iter()
        .filter(|(file, _)| !test_modules.iter().any(|module| module.covers(file)))
        .map(|(file, line)| {
            format!(
                "{}:{line}: production source names an overlay word outside crates/{MIGRATE_CRATE} (r17)",
                rel(root, &file)
            )
        })
        .collect())
}

/// The gateway prefixes: the fixed rows plus `<crate>::migrate::` for each linked crate the dist
/// lock resolves (`-` becomes `_`). Read from the manifest, so removing a row drops the prefix.
pub(crate) fn gateway_prefixes(dist: &str, dist_lock: &str) -> Vec<String> {
    let resolved: BTreeSet<String> = lock_packages(dist_lock)
        .into_iter()
        .map(|(n, _)| n)
        .collect();
    let mut prefixes: Vec<String> = FIXED_PREFIXES.iter().map(|p| (*p).to_owned()).collect();
    for name in linked_crates(dist) {
        if resolved.contains(&name) {
            prefixes.push(format!("{}::migrate::", name.replace('-', "_")));
        }
    }
    prefixes
}

/// Bytes over distinct symbols matching any prefix.
pub(crate) fn gateway_bytes(fns: &[(String, u64)], prefixes: &[String]) -> u64 {
    fns.iter()
        .filter(|(name, _)| prefixes.iter().any(|prefix| name.contains(prefix.as_str())))
        .map(|(_, size)| size)
        .sum()
}

/// (3)(3b) Each anchor symbol must be present in the bloat output.
pub(crate) fn anchors_missing(fns: &[(String, u64)]) -> Vec<String> {
    ANCHOR_SYMBOLS
        .iter()
        .filter(|anchor| !fns.iter().any(|(name, _)| names_symbol(name, anchor)))
        .map(|anchor| {
            format!(
                "bloat: anchor not found: `{anchor}` (renamed, or built without \
                 CARGO_PROFILE_RELEASE_STRIP=none)"
            )
        })
        .collect()
}

fn names_symbol(name: &str, anchor: &str) -> bool {
    name.match_indices(anchor).any(|(at, _)| {
        !name[at + anchor.len()..]
            .chars()
            .next()
            .is_some_and(|c| c.is_alphanumeric() || c == '_')
    })
}

/// `(demangled name, size)` for each object of `cargo bloat --message-format json`'s `functions`
/// array, in any key order.
pub(crate) fn parse_bloat(json: &str) -> Result<Vec<(String, u64)>, String> {
    let chars: Vec<char> = json.chars().collect();
    let key: Vec<char> = "\"functions\"".chars().collect();
    let start = (0..chars.len())
        .find(|&i| chars[i..].starts_with(&key))
        .ok_or("bloat json has no `functions` array")?;
    let mut at = start + key.len();
    while at < chars.len() && chars[at] != '[' {
        at += 1;
    }
    at += 1;
    let mut out = Vec::new();
    loop {
        while at < chars.len() && (chars[at].is_whitespace() || chars[at] == ',') {
            at += 1;
        }
        match chars.get(at) {
            Some('{') => {
                at += 1;
                let (mut name, mut size) = (None, None);
                loop {
                    while at < chars.len() && (chars[at].is_whitespace() || chars[at] == ',') {
                        at += 1;
                    }
                    if chars.get(at) == Some(&'}') {
                        at += 1;
                        break;
                    }
                    let field = read_string(&chars, &mut at)?;
                    while at < chars.len() && (chars[at].is_whitespace() || chars[at] == ':') {
                        at += 1;
                    }
                    let value = if chars.get(at) == Some(&'"') {
                        read_string(&chars, &mut at)?
                    } else {
                        let from = at;
                        while at < chars.len() && !matches!(chars[at], ',' | '}') {
                            at += 1;
                        }
                        chars[from..at].iter().collect::<String>().trim().to_owned()
                    };
                    match field.as_str() {
                        "name" => name = Some(value),
                        "size" => size = value.parse::<u64>().ok(),
                        _ => {}
                    }
                }
                if let (Some(name), Some(size)) = (name, size) {
                    out.push((name, size));
                }
            }
            Some(']') | None => return Ok(out),
            Some(other) => return Err(format!("bloat json: unexpected `{other}` in `functions`")),
        }
    }
}

fn read_string(chars: &[char], at: &mut usize) -> Result<String, String> {
    if chars.get(*at) != Some(&'"') {
        return Err("bloat json: expected a string".to_owned());
    }
    *at += 1;
    let mut text = String::new();
    while let Some(&c) = chars.get(*at) {
        *at += 1;
        match c {
            '"' => return Ok(text),
            '\\' => {
                let escaped = chars.get(*at).copied().unwrap_or('?');
                *at += 1;
                match escaped {
                    'n' => text.push('\n'),
                    't' => text.push('\t'),
                    'u' => {
                        let hex: String = chars[*at..(*at + 4).min(chars.len())].iter().collect();
                        *at += 4;
                        text.push(
                            u32::from_str_radix(&hex, 16)
                                .ok()
                                .and_then(char::from_u32)
                                .unwrap_or('?'),
                        );
                    }
                    other => text.push(other),
                }
            }
            other => text.push(other),
        }
    }
    Err("bloat json: unterminated string".to_owned())
}
