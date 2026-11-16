// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-NO-HOST-LINK (IF §15 rule 11, round 8): the shipped plugin artifact links no host, crypto or TLS.
//! (a) the normal + build graph of each plugin package, (b) the symbols and sections of the release
//! cdylib read with the `object` crate. Together they prove FIPS's "crypto in one place" for what ships.

use std::path::Path;
use std::process::Command;

use busbar_contract::json::{self, JsonContainerTrait, JsonValueTrait};
use object::{Object, ObjectSection, ObjectSymbol};

use super::Outcome;

/// Packages that may not appear in a plugin's normal + build graph.
pub(crate) const BANNED_PACKAGES: [&str; 8] = [
    "busbar-crypto",
    "busbar-crypto-backend",
    "aws-lc-rs",
    "aws-lc-sys",
    "rustls",
    "busbar-contract",
    "plugin-loader",
    "busbar-plugin-test",
];
/// Substrings of an exported or undefined symbol the artifact may not carry.
pub(crate) const BANNED_SYMBOLS: [&str; 5] = [
    "aws_lc_",
    "AWS_LC_",
    "busbar_crypto",
    "ring_core_",
    "rustls",
];

pub(crate) fn banned_symbol(name: &str) -> bool {
    BANNED_SYMBOLS.iter().any(|pattern| name.contains(pattern))
}

pub(crate) fn banned_section(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.contains("aws_lc") || lower.contains("aws-lc")
}

/// (b): the banned symbols and sections of one object file's bytes.
pub(crate) fn scan_object(bytes: &[u8]) -> Result<Vec<String>, String> {
    let file =
        object::File::parse(bytes).map_err(|error| format!("not an object file: {error}"))?;
    let mut hits = Vec::new();
    for symbol in file.symbols().chain(file.dynamic_symbols()) {
        if let Ok(name) = symbol.name() {
            if banned_symbol(name) {
                hits.push(format!("symbol {name}"));
            }
        }
    }
    for section in file.sections() {
        if let Ok(name) = section.name() {
            if banned_section(name) {
                hits.push(format!("section {name}"));
            }
        }
    }
    hits.sort();
    hits.dedup();
    Ok(hits)
}

/// (a): `cargo tree -e normal,build --prefix none -f "{p}|{f}"` output for one plugin package.
pub(crate) fn graph_findings(package: &str, tree: &str) -> Vec<String> {
    let mut findings = Vec::new();
    for line in tree.lines() {
        let Some((pkg, features)) = line.rsplit_once('|') else {
            continue;
        };
        let name = pkg.split_whitespace().next().unwrap_or("");
        if BANNED_PACKAGES.contains(&name) {
            findings.push(format!(
                "{package}: the normal+build graph reaches {name} (§15 rule 11a)"
            ));
        }
        if name == "busbar-plugin-abi"
            && features.split(',').any(|feature| feature.trim() == "host")
        {
            findings.push(format!(
                "{package}: busbar-plugin-abi resolves with feature `host` (§15 rule 11a)"
            ));
        }
    }
    findings.sort();
    findings.dedup();
    findings
}

pub(crate) fn run_cargo(dir: &Path, args: &[&str]) -> Result<String, String> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let output = Command::new(cargo)
        .current_dir(dir)
        .args(args)
        .output()
        .map_err(|error| format!("cargo {}: {error}", args.join(" ")))?;
    if !output.status.success() {
        return Err(format!(
            "cargo {}: {}: {}",
            args.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// The workspace packages that build a `cdylib`, from `cargo metadata --no-deps`.
pub(crate) fn cdylib_packages(metadata: &json::Value) -> Vec<String> {
    let mut out = Vec::new();
    for package in metadata["packages"].as_array().into_iter().flatten() {
        let ships = package["targets"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|target| {
                target["crate_types"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .any(|kind| kind == "cdylib")
            });
        if ships {
            if let Some(name) = package["name"].as_str() {
                out.push(name.to_string());
            }
        }
    }
    out.sort();
    out
}

/// `no-host-link <repo-dir> [release-cdylib...]`
pub(crate) fn no_host_link(args: &[String]) -> Outcome {
    let (dir, artifacts) = args
        .split_first()
        .ok_or("no-host-link <repo-dir> [release-cdylib...]")?;
    let dir = Path::new(dir);
    let metadata = run_cargo(
        dir,
        &["metadata", "--no-deps", "--format-version", "1", "--locked"],
    )?;
    let metadata: json::Value = json::parse_value(metadata.as_bytes())
        .map_err(|error| format!("cargo metadata: {error}"))?;
    let mut findings = Vec::new();
    for package in cdylib_packages(&metadata) {
        let tree = run_cargo(
            dir,
            &[
                "tree",
                "--locked",
                "-p",
                package.as_str(),
                "-e",
                "normal,build",
                "--target",
                "all",
                "--prefix",
                "none",
                "-f",
                "{p}|{f}",
            ],
        )?;
        findings.extend(graph_findings(&package, &tree));
    }
    for artifact in artifacts {
        let bytes = std::fs::read(artifact).map_err(|error| format!("{artifact}: {error}"))?;
        for hit in scan_object(&bytes).map_err(|error| format!("{artifact}: {error}"))? {
            findings.push(format!("{artifact}: {hit} (§15 rule 11b)"));
        }
    }
    Ok(findings)
}
