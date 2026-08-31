// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Docs-accuracy drift guard: runs doc-embedded config examples through the REAL
//! `busbar --validate` pipeline, driving the compiled binary exactly like `cli_validate.rs` does.
//!
//! The guard is deliberately narrow. What it covers, and why:
//!
//! - **Opt-in via directive, not auto-detection.** A fenced ```yaml block is only extracted and
//!   validated when the line immediately before the fence is `<!-- doc-check: config -->`.
//!   Auto-detecting "is this a complete config" is a heuristic that produces false failures on
//!   deliberately-partial fragments (the majority of the tree's 77 yaml blocks are fragments, not
//!   complete configs). Only ONE directive shape ships here: `config`, a complete, standalone
//!   config.yaml. Other shapes (`config-section=X`, `providers`, `settings-patch`,
//!   `request=METHOD PATH`, `skip=reason`) are NOT implemented.
//! - **Secrets are stood in for, not required.** `--validate` RESOLVES built-in `env`/`file` secret
//!   references and fails when one cannot (see `main.rs`'s `validate_builtin_secrets_resolve`), so a
//!   marked example naming a real-looking variable would otherwise fail on THIS MACHINE's
//!   environment rather than on anything written in the doc. `run_validate` below extracts the names
//!   the example references and gives each a placeholder, and points `file:` refs at a scratch file.
//!   The gate therefore still needs zero environment setup, and still tests only the config's shape.
//! - **Anti-vacuity floor.** Only 3 examples are marked today (getting-started.md's minimal config
//!   AND its Step-5 two-provider-one-pool config, and configuration.md's "Minimal working
//!   example"). The floor below is sized to that set (>= 3). Raise both together when more
//!   examples get marked.
//! - **Plugin-dependent examples are deliberately NOT marked.** configuration.md's "full annotated
//!   example" and reliability.md's "production-like" example both reference `store.module: sqlite`
//!   under `plugins.enabled: true`, which needs a signed plugin-tarball fixture to validate — the
//!   same fixture-cost tradeoff that applies to live-curl execution. Left unmarked with an
//!   HTML-comment note in the doc itself pointing at the plugin-free substitute example.

// The shipped/marked examples this file validates assume the DEFAULT feature set (what a real
// user's copy-pasted config targets) -- an admin-tokens block in an example fails closed under
// `--no-default-features` (correct production behavior, not a bug this file should catch).
#![cfg(feature = "auth-admin-tokens")]

use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_root() -> PathBuf {
    // crates/busbar -> repo root
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn fixture_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "busbar-docs-examples-{}-{tag}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Run the real busbar binary's `--validate` against `config_path`, with `providers_path` as the
/// companion catalog. Returns (exit_code, stdout, stderr).
fn run_validate(config_path: &Path, providers_path: &Path) -> (i32, String, String) {
    // `--validate` RESOLVES built-in (`env`/`file`) secret references, so a documented example
    // naming an env var fails unless that var is set. Docs name real-looking vars on purpose, and
    // enumerating them here would drift the moment a doc adds one. Instead: extract every
    // `{ env: NAME }` the example references and set each to a placeholder, so the gate tests the
    // config's SHAPE (what it is for) rather than this machine's environment.
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
    // `file:` references are the same problem with no env-var escape: a shipped artifact names a
    // PRODUCTION path (`/var/lib/busbar/signing.key`) that cannot exist in CI. Rewrite the copy
    // under test to point at a real temp file, so the gate still checks the config's shape without
    // asserting anything about this machine's filesystem layout.
    let rewritten = {
        let text = std::fs::read_to_string(config_path).unwrap_or_default();
        if text.contains("file:") {
            // Scratch, NOT `config_path.parent()`. The documents under test are the SHIPPED files,
            // so their parent is the repo itself: writing the stand-in and the patched copy there
            // left four generated artifacts in the working tree, and two of them carried the
            // absolute home-directory path of the machine that ran the test. The public-hygiene
            // gate caught it. Nothing this test writes belongs anywhere a commit can reach.
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

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_busbar"));
    // 1.6.0: the catalog lives at the shipped root, NOT next to the temp config, so point busbar at
    // it with the `--providers` flag (the removed `BUSBAR_PROVIDERS` env var no longer works).
    cmd.arg("--validate")
        .arg("--providers")
        .arg(providers_path)
        .env("BUSBAR_CONFIG", effective);
    for name in &referenced {
        // 64 hex chars: valid for `auth.signing_key`, and harmless as any other secret's value.
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

/// One `<!-- doc-check: config -->`-marked fenced block: the doc file it came from (relative to
/// repo root, for error messages), the 1-based line the fence opens on, and its extracted body.
struct MarkedConfig {
    doc: String,
    fence_line: usize,
    body: String,
}

/// Walk every `docs/**/*.md` + `README.md` for `<!-- doc-check: config -->` immediately followed
/// (allowing blank lines) by a ```yaml fence, and extract that fence's body.
fn extract_marked_configs() -> Vec<MarkedConfig> {
    let root = repo_root();
    let mut files: Vec<PathBuf> = std::fs::read_dir(root.join("docs"))
        .expect("docs/ exists")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "md"))
        .collect();
    files.push(root.join("README.md"));

    let mut out = Vec::new();
    for path in files {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let lines: Vec<&str> = text.lines().collect();
        let rel = path
            .strip_prefix(&root)
            .unwrap_or(&path)
            .display()
            .to_string();
        let mut i = 0;
        while i < lines.len() {
            if lines[i].trim() == "<!-- doc-check: config -->" {
                // Skip any blank lines between the marker and the fence.
                let mut j = i + 1;
                while j < lines.len() && lines[j].trim().is_empty() {
                    j += 1;
                }
                assert!(
                    j < lines.len() && lines[j].trim_start().starts_with("```yaml"),
                    "{rel}:{}: `doc-check: config` marker not immediately followed by a ```yaml fence",
                    i + 1
                );
                let fence_line = j + 1;
                let mut body = String::new();
                let mut k = j + 1;
                while k < lines.len() && lines[k].trim() != "```" {
                    body.push_str(lines[k]);
                    body.push('\n');
                    k += 1;
                }
                assert!(
                    k < lines.len(),
                    "{rel}:{fence_line}: ```yaml fence opened by a doc-check marker never closes"
                );
                out.push(MarkedConfig {
                    doc: rel.clone(),
                    fence_line,
                    body,
                });
                i = k + 1;
            } else {
                i += 1;
            }
        }
    }
    out
}

/// Every `<!-- doc-check: config -->`-marked example is a COMPLETE config.yaml: validate it
/// against the real, shipped `providers.yaml` catalog through the actual `busbar --validate`
/// pipeline. This catches the `"ca"` vs `"client_ca"` class of bug, which slips past an example
/// that is only a `PUT /config/settings` body fragment rather than a full config — any doc author
/// who introduces a misspelled top-level key or field in a marked example now gets a local test
/// failure instead of a 400 an operator hits under time pressure.
#[test]
fn marked_config_examples_validate() {
    let root = repo_root();
    let providers_path = root.join("providers.yaml");
    assert!(
        providers_path.is_file(),
        "root providers.yaml must exist to validate doc examples against"
    );

    let marked = extract_marked_configs();
    assert!(
        marked.len() >= 3,
        "only found {} `doc-check: config`-marked examples — expected at least 3 \
         (getting-started.md x2, configuration.md x1; reliability.md's example is deliberately \
         left unmarked, see its own `store.module: sqlite` note). Either a marker was removed, or \
         the extractor regressed — either way this guard just went quiet.",
        marked.len()
    );

    let mut failures = Vec::new();
    for (n, m) in marked.iter().enumerate() {
        let dir = fixture_dir(&format!("marked-{n}"));
        let config_path = dir.join("config.yaml");
        std::fs::write(&config_path, &m.body).unwrap();
        let (code, stdout, stderr) = run_validate(&config_path, &providers_path);
        if code != 0 {
            failures.push(format!(
                "{}:{} — `busbar --validate` exited {code}\nstdout: {stdout}\nstderr: {stderr}",
                m.doc, m.fence_line
            ));
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
    assert!(
        failures.is_empty(),
        "doc example(s) failed to validate against the real config pipeline:\n\n{}",
        failures.join("\n\n")
    );
}

/// The SHIPPED config artifacts users literally copy — root `config.yaml` and the
/// clean 1.5.0 example — validate clean against the shipped `providers.yaml`. Three lines of
/// coverage; nothing validated these in CI before this test existed.
#[test]
fn shipped_config_artifacts_validate() {
    let root = repo_root();
    let providers_path = root.join("providers.yaml");

    for shipped in ["config.yaml", "examples/clean-config-1.5.0.yaml"] {
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
