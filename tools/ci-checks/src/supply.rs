// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Supply-chain text checks over `deny.toml` and `Cargo.toml` files (IF §15.0, §15 rules 4 and 8). The
//! files are compared as text sections, so no TOML parser is needed and a drift is reported by section.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use super::Outcome;

/// Crates a plugin consumes through a GetBusbar fork (IF §15 rule 4 ports and rule 8): core's root
/// `[patch]` and the plugin's must carry the same source and rev.
pub(crate) const PORT_CRATES: [&str; 8] = [
    "postgres-protocol",
    "mysql_common",
    "str0m",
    "str0m-proto",
    "is",
    "sctp-proto",
    "tungstenite",
    "tokenizers",
];
/// Port crates whose fork lives on the GitLab, not on a personal GitHub account (rule 8).
pub(crate) const GITLAB_PORTS: [&str; 7] = [
    "postgres-protocol",
    "mysql_common",
    "str0m",
    "str0m-proto",
    "is",
    "sctp-proto",
    "tokenizers",
];
const GITLAB_HOST: &str = "github.com";

/// A deny.toml as its sections: header and comment-free body. `[licenses]` tables and `[bans] skip`
/// are the per-repo parts (§15.0), so they are dropped.
fn deny_sections(text: &str) -> Vec<(String, String)> {
    let mut sections: Vec<(String, Vec<String>)> = Vec::new();
    let mut skip_depth: i32 = 0;
    let mut skipping = false;
    for line in text.lines() {
        let code = line.split('#').next().unwrap_or("").trim();
        if code.is_empty() {
            continue;
        }
        if !skipping && code.starts_with('[') && code.ends_with(']') {
            sections.push((code.to_string(), Vec::new()));
            continue;
        }
        let Some(current) = sections.last_mut() else {
            continue;
        };
        if current.0 == "[bans]" && (skipping || code.starts_with("skip")) {
            if !skipping {
                skipping = true;
                skip_depth = 0;
            }
            skip_depth += code.matches('[').count() as i32 - code.matches(']').count() as i32;
            if skip_depth <= 0 {
                skipping = false;
            }
            continue;
        }
        current.1.push(code.to_string());
    }
    sections
        .into_iter()
        .filter(|(header, _)| !header.contains("licenses"))
        .map(|(header, body)| (header, body.join("\n")))
        .collect()
}

/// IF §15.0: the plugin's deny.toml equals the template outside `[bans] skip` and `[licenses]`, and
/// the template (so the plugin) sets `exclude-dev = true`.
pub(crate) fn template_drift(template: &str, plugin: &str, name: &str) -> Vec<String> {
    let mut findings = Vec::new();
    let want = deny_sections(template);
    let got = deny_sections(plugin);
    for (header, body) in &want {
        if header == "[graph]"
            && !body
                .lines()
                .any(|line| line.replace(' ', "") == "exclude-dev=true")
        {
            findings
                .push("template deny.toml: [graph] lacks `exclude-dev = true` (§15.0)".to_string());
        }
    }
    if !want.iter().any(|(header, _)| header == "[graph]") {
        findings.push(
            "template deny.toml: no [graph] table (§15.0 needs exclude-dev = true)".to_string(),
        );
    }
    if !got.iter().any(|(header, body)| {
        header == "[graph]"
            && body
                .lines()
                .any(|line| line.replace(' ', "") == "exclude-dev=true")
    }) {
        findings.push(format!(
            "{name}: [graph] lacks `exclude-dev = true` (§15.0)"
        ));
    }
    for (index, (header, body)) in want.iter().enumerate() {
        match got.get(index) {
            Some((got_header, got_body)) if got_header == header && got_body == body => {}
            Some((got_header, _)) if got_header != header => findings.push(format!(
                "{name}: section {got_header} where the template has {header} (position {index})"
            )),
            Some(_) => findings.push(format!(
                "{name}: section {header} differs from the template (§15.0 template-drift)"
            )),
            None => findings.push(format!("{name}: section {header} missing (template-drift)")),
        }
    }
    for (header, _) in got.iter().skip(want.len()) {
        findings.push(format!(
            "{name}: extra section {header} not in the template"
        ));
    }
    findings
}

/// The `[patch.crates-io]`-style entries of a Cargo.toml: crate -> (git, rev).
pub(crate) fn patch_entries(text: &str) -> BTreeMap<String, (String, String)> {
    let mut inside = false;
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let code = line.trim();
        if code.starts_with('[') {
            inside = code.starts_with("[patch");
            continue;
        }
        if !inside || code.starts_with('#') {
            continue;
        }
        let Some((krate, rest)) = code.split_once('=') else {
            continue;
        };
        let value = |key: &str| -> String {
            let at = rest
                .find(&format!("{key} ="))
                .or_else(|| rest.find(&format!("{key}=")));
            let Some(at) = at else {
                return String::new();
            };
            let tail = &rest[at..];
            let Some(open) = tail.find('"') else {
                return String::new();
            };
            let tail = &tail[open + 1..];
            tail.split('"').next().unwrap_or("").to_string()
        };
        out.insert(
            krate.trim().trim_matches('"').to_string(),
            (value("git"), value("rev")),
        );
    }
    out
}

/// IF §15 rule 8: core's root `[patch]` and the plugin repo's agree on every port crate, and a GitLab
/// port is sourced from the GitLab.
pub(crate) fn patch_drift(core: &str, plugin: &str, name: &str) -> Vec<String> {
    let core = patch_entries(core);
    let plugin = patch_entries(plugin);
    let mut findings = Vec::new();
    for krate in PORT_CRATES {
        match (core.get(krate), plugin.get(krate)) {
            (Some(a), Some(b)) if a != b => findings.push(format!(
                "{name}: [patch] {krate} is {b:?}, core's root has {a:?} (§15 rule 8 drift)"
            )),
            (Some(a), None) => findings.push(format!(
                "{name}: core [patch]es {krate} ({a:?}) and this repo does not (§15 rule 8 drift)"
            )),
            (None, Some(b)) => findings.push(format!(
                "{name}: this repo [patch]es {krate} ({b:?}) and core's root does not (§15 rule 8 drift)"
            )),
            _ => {}
        }
    }
    findings
}

/// IF §15 rule 8 on core alone: a GitLab port is sourced from the GitLab fork.
pub(crate) fn core_patch_findings(core: &str) -> Vec<String> {
    let mut findings = Vec::new();
    for (krate, (git, rev)) in patch_entries(core) {
        if GITLAB_PORTS.contains(&krate.as_str()) && !git.contains(GITLAB_HOST) {
            findings.push(format!(
                "Cargo.toml: [patch] {krate} is {git}, a port crate is a GetBusbar GitLab fork ({GITLAB_HOST}) (§15 rule 8)"
            ));
        }
        if rev.is_empty() && PORT_CRATES.contains(&krate.as_str()) {
            findings.push(format!("Cargo.toml: [patch] {krate} names no rev"));
        }
    }
    findings
}

/// IF §15 rule 8 on a plugin repo's Cargo.toml: every `[patch]` entry has an `upstream PR:` URL
/// comment on the line above it, and no `path =` points outside the repo.
pub(crate) fn manifest_findings(repo_root: &Path, manifest: &Path, text: &str) -> Vec<String> {
    let rel = manifest
        .strip_prefix(repo_root)
        .unwrap_or(manifest)
        .display()
        .to_string();
    let dir: PathBuf = manifest.parent().unwrap_or(repo_root).to_path_buf();
    let mut findings = Vec::new();
    let mut in_patch = false;
    let mut previous = "";
    for (index, line) in text.lines().enumerate() {
        let code = line.trim();
        if code.starts_with('[') {
            in_patch = code.starts_with("[patch");
        } else if in_patch
            && !code.starts_with('#')
            && code.contains('=')
            && code.contains("git")
            && !(previous.trim_start().starts_with('#')
                && previous.contains("upstream PR:")
                && previous.contains("http"))
        {
            findings.push(format!(
                "{rel}:{}: [patch] entry without an `upstream PR: <url>` comment on the line above (§15 rule 8)",
                index + 1
            ));
        }
        if !code.starts_with('#') {
            if let Some(at) = code.find("path") {
                let tail = code[at + 4..].trim_start();
                if let Some(tail) = tail.strip_prefix('=') {
                    let tail = tail.trim_start();
                    if let Some(tail) = tail.strip_prefix('"') {
                        let target = tail.split('"').next().unwrap_or("");
                        let resolved = super::normalize(&dir.join(target));
                        if !resolved.starts_with(repo_root) {
                            findings.push(format!(
                                "{rel}:{}: path dependency `{target}` points outside the repo (§15 rule 8)",
                                index + 1
                            ));
                        }
                    }
                }
            }
        }
        if !code.is_empty() {
            previous = line;
        }
    }
    findings
}

/// `template-drift <template deny.toml> <deny.toml>...`
pub(crate) fn template_drift_cli(args: &[String]) -> Outcome {
    let (template, plugins) = args
        .split_first()
        .ok_or("template-drift <template deny.toml> <deny.toml>...")?;
    let want = std::fs::read_to_string(template).map_err(|error| format!("{template}: {error}"))?;
    let mut findings = Vec::new();
    for plugin in plugins {
        let got = std::fs::read_to_string(plugin).map_err(|error| format!("{plugin}: {error}"))?;
        findings.extend(template_drift(&want, &got, plugin));
    }
    if plugins.is_empty() {
        findings.extend(template_drift(&want, &want, template));
    }
    Ok(findings)
}

/// `patch-drift <Cargo.toml>...` against core's root Cargo.toml.
pub(crate) fn patch_drift_cli(root: &Path, args: &[String]) -> Outcome {
    let core = std::fs::read_to_string(root.join("Cargo.toml"))
        .map_err(|error| format!("Cargo.toml: {error}"))?;
    let mut findings = core_patch_findings(&core);
    for plugin in args {
        let text = std::fs::read_to_string(plugin).map_err(|error| format!("{plugin}: {error}"))?;
        findings.extend(patch_drift(&core, &text, plugin));
    }
    Ok(findings)
}
