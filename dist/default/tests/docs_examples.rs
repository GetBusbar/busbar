// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Shipped-config guard: runs every config file the release ships (`config.yaml`, the 1.5.0
//! clean config and the Docker image config) through the REAL `busbar --validate` pipeline,
//! driving the compiled binary exactly like `cli_validate.rs` does, and checks the shipped
//! providers catalog. Built-in `env`/`file` secret references are stood in for (see
//! `run_validate`), so the guard needs zero environment setup and tests only the config shape.

#![cfg(linked_operator_auth)]

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

#[cfg(linked_section_pools)]
fn fixture_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "busbar-docs-examples-{}-{tag}-{}",
        std::process::id(),
        {
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            format!(
                "{}-{}-{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_nanos()),
                line!(),
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            )
        }
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn run_validate(config_path: &Path, providers_path: &Path) -> (i32, String, String) {
    let referenced: Vec<String> = {
        let text = std::fs::read_to_string(config_path).unwrap_or_default();
        let mut v: Vec<String> = Vec::new();
        for (i, _) in text.match_indices("env:") {
            let rest = &text[i + 4..];
            let name: String = rest
                .chars()
                .skip_while(|c| c.is_whitespace())
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            if !name.is_empty() && !v.contains(&name) {
                v.push(name);
            }
        }
        v
    };

    let rewritten = {
        let text = std::fs::read_to_string(config_path).unwrap_or_default();
        if text.contains("file:") {
            let dir = std::env::temp_dir().join(format!(
                "busbar-doc-gate-{}-{}",
                std::process::id(),
                config_path
                    .file_name()
                    .map(|n| n.to_string_lossy().replace(['.', '/'], "_"))
                    .unwrap_or_default()
            ));
            std::fs::create_dir_all(&dir).expect("create doc-gate scratch dir");
            let dir = dir.as_path();
            let stand_in = dir.join("doc-gate-secret");
            std::fs::write(
                &stand_in,
                "0000000000000000000000000000000000000000000000000000000000000001",
            )
            .unwrap();
            let mut out = String::with_capacity(text.len());
            for line in text.lines() {
                if let Some(i) = line.find("file:") {
                    let (head, tail) = line.split_at(i);
                    let close = tail.find('}').map(|j| &tail[j..]).unwrap_or("");
                    out.push_str(head);
                    out.push_str("file: ");
                    out.push_str(&stand_in.display().to_string());
                    out.push_str(close);
                    out.push('\n');
                } else {
                    out.push_str(line);
                    out.push('\n');
                }
            }
            let patched = dir.join("doc-gate-config.yaml");
            std::fs::write(&patched, out).unwrap();
            Some(patched)
        } else {
            None
        }
    };
    let effective = rewritten.as_deref().unwrap_or(config_path);

    let mut cmd = Command::new(common::boot::exe());

    cmd.arg("--validate")
        .arg("--providers")
        .arg(providers_path)
        .env("BUSBAR_CONFIG", effective);
    for name in &referenced {
        cmd.env(
            name,
            "0000000000000000000000000000000000000000000000000000000000000001",
        );
    }
    let out = cmd.output().expect("run busbar --validate");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn shipped_config_artifacts_validate() {
    let root = repo_root();
    let providers_path = root.join("providers.yaml");

    for shipped in [
        "config.yaml",
        "dist/default/tests/fixtures/clean-config-1.5.0.yaml",
        "docker/config.yaml",
    ] {
        let path = root.join(shipped);
        assert!(path.is_file(), "shipped artifact {shipped} must exist");
        let (code, stdout, stderr) = run_validate(&path, &providers_path);
        assert_eq!(
            code, 0,
            "shipped {shipped} failed --validate: stdout={stdout} stderr={stderr}"
        );
        assert!(stdout.contains("ok: config valid"), "{shipped}: {stdout}");
    }
}

#[cfg(linked_section_pools)]
fn known_protocols() -> Vec<String> {
    let dir = fixture_dir("known-protocols");
    let providers = dir.join("providers.yaml");
    std::fs::write(
        &providers,
        "probe:\n  protocol: definitely-not-a-protocol\n  base_url: https://probe.invalid\n",
    )
    .unwrap();
    let config = dir.join("config.yaml");
    std::fs::write(
        &config,
        "listen: \"127.0.0.1:0\"\nstore: {module: memory}\nproviders:\n  probe:\n    api_key: { env: \
         PROBE_KEY }\nmodels:\n  probe-model:\n    provider: probe\n",
    )
    .unwrap();
    let (code, stdout, stderr) = run_validate(&config, &providers);
    let _ = std::fs::remove_dir_all(&dir);
    let all = format!("{stdout}{stderr}");
    assert_ne!(code, 0, "an unknown protocol must fail validation: {all}");
    let tail = all
        .split("must be one of: ")
        .nth(1)
        .unwrap_or_else(|| panic!("the refusal lists the known protocols: {all}"));
    tail.lines()
        .next()
        .unwrap_or_default()
        .split(", ")
        .filter_map(|item| item.split_whitespace().next())
        .map(|item| {
            item.trim_end_matches(['.', ',', ';', '"', '\''])
                .to_string()
        })
        .filter(|item| !item.is_empty())
        .collect()
}

#[cfg(linked_section_pools)]
#[test]
fn test_shipped_providers_catalog_valid() {
    use busbar_contract::yaml::{self, prelude::*};
    let raw =
        std::fs::read_to_string(repo_root().join("providers.yaml")).expect("read providers.yaml");
    let defs: std::collections::BTreeMap<String, Value> =
        yaml::from_str(&raw).expect("parse providers.yaml");
    assert!(defs.len() >= 10, "catalog should be non-trivial");
    let known = known_protocols();
    assert!(!known.is_empty(), "the binary knows at least one protocol");
    for (name, def) in &defs {
        let protocol = def
            .at("protocol")
            .as_str()
            .unwrap_or_else(|| panic!("provider '{name}' names a protocol"));
        assert!(
            known.iter().any(|k| k == protocol),
            "provider '{name}' names unknown protocol '{protocol}' (known: {known:?})"
        );
        let base_url = def
            .at("base_url")
            .as_str()
            .unwrap_or_else(|| panic!("provider '{name}' names a base_url"));
        assert!(
            base_url.starts_with("https://"),
            "provider '{name}' base_url must be https"
        );
    }
}

/// The number after `key:` in a one-line YAML flow mapping.
fn flow_number(line: &str, key: &str) -> u64 {
    let at = line
        .find(&format!("{key}:"))
        .unwrap_or_else(|| panic!("`{key}` missing from `{line}`"));
    line[at + key.len() + 1..]
        .trim_start()
        .chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>()
        .parse()
        .unwrap_or_else(|_| panic!("`{key}` is not a number in `{line}`"))
}

/// T10 (FIRST-START-TAKEOVER §2.6): the README Kubernetes example's startup budget covers the
/// longest legitimate first-start wait for up to seven conditional-records planes, and the
/// operations guide documents it. Changing the stall window or the README alone fails here.
#[test]
fn readme_startup_probe_covers_the_first_start_wait() {
    let root = repo_root();
    let readme = std::fs::read_to_string(root.join("README.md")).expect("read README.md");
    let lines: Vec<&str> = readme.lines().collect();
    let marker = lines
        .iter()
        .position(|line| line.trim() == "<!-- doc-check: startup-probe -->")
        .expect("README.md has a `doc-check: startup-probe` block");
    assert_eq!(
        lines.get(marker + 1).map(|line| line.trim()),
        Some("```yaml"),
        "the startup-probe marker is not immediately followed by a ```yaml fence"
    );
    let block: Vec<&str> = lines[marker + 2..]
        .iter()
        .take_while(|line| line.trim() != "```")
        .copied()
        .collect();
    let probe = block
        .iter()
        .find(|line| line.trim_start().starts_with("startupProbe:"))
        .expect("the marked block has a startupProbe on the busbar container");
    let budget = std::time::Duration::from_secs(
        flow_number(probe, "failureThreshold") * flow_number(probe, "periodSeconds"),
    );
    let floor = busbar_kernel::persistence::startup::first_start_probe_floor(7);
    assert!(
        budget >= floor,
        "README startupProbe budget {budget:?} is below the first-start floor {floor:?}"
    );
    let operations =
        std::fs::read_to_string(root.join("docs/operations.md")).expect("read docs/operations.md");
    assert!(
        operations
            .lines()
            .any(|line| line.trim() == "### First start with several replicas"),
        "docs/operations.md has no `First start with several replicas` section"
    );
}
