// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The fleet manifest checks (IF §15, §17 row X1): `fleet/deps.toml`'s `[min3-closure]` and
//! `plugins.yaml`'s repo list, and C-ALIAS's manifest job. Both files are read line by line: their
//! shape is fixed and this keeps the checks free of a TOML dependency.

use std::collections::BTreeSet;
use std::path::Path;

use super::Outcome;

/// The 33 ported OSS plugin repos (WBS: 33 ports + 2 archives; busbar-hook-headroom is discontinued).
pub(crate) const PORTED_REPOS: usize = 33;
/// The two repos archived with no MIN-3 release (IF §8.7).
pub(crate) const ARCHIVED: [&str; 2] = ["busbar-transport-tcp", "busbar-transport-stdio"];
/// Never a plugin: kept in `excluded_repos` with no manifest entry.
pub(crate) const EXCLUDED: [&str; 2] = ["hindsight-hook", "busbar-hook-headroom"];
/// Crates a plugin's normal and build graph may not name (IF §15 rule 1a).
pub(crate) const CLOSURE_FORBIDDEN: [&str; 4] = [
    "busbar-contract",
    "plugin-loader",
    "busbar-kernel",
    "busbar-core-connector",
];

/// One `plugins.yaml` entry.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct Entry {
    pub repo: String,
    pub alias: Option<String>,
    pub manifest_name: Option<String>,
    pub former_names: Vec<String>,
}

/// The entries and the two repo lists of a `plugins.yaml`.
#[derive(Debug, Default)]
pub(crate) struct Registry {
    pub entries: Vec<Entry>,
    pub excluded: Vec<String>,
    pub archived: Vec<String>,
}

fn strip_comment(value: &str) -> &str {
    match value.find(" #") {
        Some(at) => value[..at].trim(),
        None => value.trim(),
    }
}

fn unquote(value: &str) -> String {
    value
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .to_string()
}

fn inline_list(value: &str) -> Vec<String> {
    let inner = value.trim().trim_start_matches('[').trim_end_matches(']');
    inner
        .split(',')
        .map(unquote)
        .filter(|word| !word.is_empty())
        .collect()
}

pub(crate) fn parse_registry(text: &str) -> Registry {
    let mut registry = Registry::default();
    let mut list: Option<&'static str> = None;
    for line in text.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with('#') || trimmed.is_empty() {
            continue;
        }
        let indent = line.len() - trimmed.len();
        if indent == 0 {
            list = match trimmed.split(':').next() {
                Some("excluded_repos") => Some("excluded"),
                Some("archived_repos") => Some("archived"),
                _ => None,
            };
            continue;
        }
        if let Some(which) = list {
            if let Some(item) = trimmed.strip_prefix("- ") {
                let word = unquote(strip_comment(item));
                match which {
                    "excluded" => registry.excluded.push(word),
                    _ => registry.archived.push(word),
                }
            }
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("- repo:") {
            registry.entries.push(Entry {
                repo: unquote(strip_comment(rest)),
                ..Entry::default()
            });
            continue;
        }
        if indent < 4 {
            continue;
        }
        let Some(entry) = registry.entries.last_mut() else {
            continue;
        };
        if let Some(rest) = trimmed.strip_prefix("alias:") {
            entry.alias = Some(unquote(strip_comment(rest)));
        } else if let Some(rest) = trimmed.strip_prefix("manifest_name:") {
            entry.manifest_name = Some(unquote(strip_comment(rest)));
        } else if let Some(rest) = trimmed.strip_prefix("former_names:") {
            entry.former_names = inline_list(strip_comment(rest));
        }
    }
    registry
}

/// The `key = value` lines of one `[section]`, comments dropped.
fn toml_section(text: &str, name: &str) -> Vec<(String, String)> {
    let header = format!("[{name}]");
    let mut inside = false;
    let mut out = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            inside = trimmed == header;
            continue;
        }
        if !inside || trimmed.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = trimmed.split_once('=') {
            out.push((key.trim().to_string(), strip_comment(value).to_string()));
        }
    }
    out
}

/// `fleet/deps.toml`'s MIN-3 closure and `plugins.yaml`'s repo list (IF §15 rules 1a, 1b; WBS X1 row).
pub(crate) fn fleet_findings(deps_toml: &str, plugins_yaml: &str) -> Vec<String> {
    let mut findings = Vec::new();
    let closure = toml_section(deps_toml, "min3-closure");
    if closure.is_empty() {
        findings.push("fleet/deps.toml: no [min3-closure] table".to_string());
    }
    for (key, want) in [
        ("plugin_busbar_dependency", "busbar-plugin-abi"),
        ("helper_busbar_dependency", "busbar-plugin-abi"),
        ("plugin_busbar_dev_dependency", "busbar-plugin-test"),
    ] {
        let got = closure.iter().find(|(name, _)| name == key);
        match got {
            Some((_, value)) if unquote(value) == want => {}
            Some((_, value)) => findings.push(format!(
                "fleet/deps.toml: [min3-closure] {key} is {value}, must be \"{want}\""
            )),
            None => findings.push(format!("fleet/deps.toml: [min3-closure] lacks {key}")),
        }
    }
    let forbidden: Vec<String> = closure
        .iter()
        .find(|(name, _)| name == "forbidden_plugin_dependencies")
        .map(|(_, value)| inline_list(value))
        .unwrap_or_default();
    for name in CLOSURE_FORBIDDEN {
        if !forbidden.iter().any(|word| word == name) {
            findings.push(format!(
                "fleet/deps.toml: [min3-closure] forbidden_plugin_dependencies lacks {name}"
            ));
        }
    }

    let registry = parse_registry(plugins_yaml);
    let mut seen = BTreeSet::new();
    for entry in &registry.entries {
        if !seen.insert(entry.repo.clone()) {
            findings.push(format!("plugins.yaml: repo {} appears twice", entry.repo));
        }
        if EXCLUDED.contains(&entry.repo.as_str()) {
            findings.push(format!(
                "plugins.yaml: {} is excluded and must have no manifest entry",
                entry.repo
            ));
        }
    }
    for name in EXCLUDED {
        if !registry.excluded.iter().any(|word| word == name) {
            findings.push(format!("plugins.yaml: excluded_repos lacks {name}"));
        }
    }
    let mut archived: Vec<&str> = registry.archived.iter().map(String::as_str).collect();
    archived.sort_unstable();
    let mut want = ARCHIVED.to_vec();
    want.sort_unstable();
    if archived != want {
        findings.push(format!(
            "plugins.yaml: archived_repos is {archived:?}, must be exactly {want:?} (no MIN-3 release, no render, no re-pin)"
        ));
    }
    let ported = registry
        .entries
        .iter()
        .filter(|entry| !ARCHIVED.contains(&entry.repo.as_str()))
        .count();
    if ported != PORTED_REPOS {
        findings.push(format!(
            "plugins.yaml: {ported} ported repos, the MIN-3 fleet is {PORTED_REPOS}"
        ));
    }
    findings
}

/// The words a first-party plugin answers to: repo, manifest name, alias and former names of every
/// entry (the §15.8 core scan's word list; the enterprise stamps are added from `extra`).
pub(crate) fn plugin_words(plugins_yaml: &str, extra: &str) -> BTreeSet<String> {
    let mut words = BTreeSet::new();
    for entry in parse_registry(plugins_yaml).entries {
        words.insert(entry.repo);
        words.extend(entry.alias);
        words.extend(entry.manifest_name);
        words.extend(entry.former_names);
    }
    for line in extra.lines() {
        let word = line.trim();
        if !word.is_empty() && !word.starts_with('#') {
            words.insert(word.to_string());
        }
    }
    words.retain(|word| !word.is_empty());
    words
}

/// C-ALIAS, X1's manifest job (IF §12.10 item 2, round 12). `headers` holds one `repo: word, word`
/// line per shipped image (its header `former_names`); a repo with no line has no shipped image and is
/// skipped (listed as a note by the caller, never a finding).
pub(crate) fn alias_findings(plugins_yaml: &str, headers: &str) -> Vec<String> {
    let registry = parse_registry(plugins_yaml);
    let mut findings = Vec::new();
    let mut shipped = std::collections::BTreeMap::new();
    for line in headers.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((repo, words)) = line.split_once(':') {
            let set: BTreeSet<String> = words
                .split(',')
                .map(|word| word.trim().to_string())
                .filter(|word| !word.is_empty())
                .collect();
            shipped.insert(repo.trim().to_string(), set);
        }
    }
    for entry in &registry.entries {
        if registry.excluded.contains(&entry.repo) {
            findings.push(format!(
                "{}: an excluded repo must have no manifest entry",
                entry.repo
            ));
            continue;
        }
        let Some(header) = shipped.get(&entry.repo) else {
            continue;
        };
        let mut need: BTreeSet<&String> = entry.former_names.iter().collect();
        need.extend(entry.alias.iter());
        for word in need {
            if !header.contains(word) {
                findings.push(format!(
                    "{}: header former_names {header:?} lacks `{word}` (plugins.yaml alias/former_names)",
                    entry.repo
                ));
            }
        }
    }
    findings
}

pub(crate) fn fleet_manifest(root: &Path) -> Outcome {
    let read = |name: &str| {
        std::fs::read_to_string(root.join(name)).map_err(|error| format!("{name}: {error}"))
    };
    Ok(fleet_findings(
        &read("fleet/deps.toml")?,
        &read("plugins.yaml")?,
    ))
}

/// `c-alias <headers-file>`: plugins.yaml against the shipped headers' former_names.
pub(crate) fn c_alias(root: &Path, args: &[String]) -> Outcome {
    let headers = args
        .first()
        .ok_or("c-alias <headers-file>: one `repo: word, word` line per shipped image")?;
    let yaml = std::fs::read_to_string(root.join("plugins.yaml"))
        .map_err(|error| format!("plugins.yaml: {error}"))?;
    let text = std::fs::read_to_string(headers).map_err(|error| format!("{headers}: {error}"))?;
    Ok(alias_findings(&yaml, &text))
}
