// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! EVERY config busbar has ever shipped must still migrate to the current shape.
//!
//! The corpus is `tests/migration-corpus/from-tags/`: the real `config.yaml` files extracted from
//! every non-rc git tag, named `<tag>_<path>.yaml`. Not hand-written fixtures — the actual documents
//! shipped to users, which is the only set guaranteed to contain the shapes people really have.
//!
//! WHY THIS EXISTS. the terraform provider's acceptance harness: a config shape aged out, that consumer
//! consumer broke, and nothing noticed until a daily poll went red. Worse, the first error masked a
//! second one — validation stops at the first failure, so fixing the reported problem just moved the
//! break somewhere else. A corpus catches both at once, before release, for every version at once.
//!
//! WHAT "PASSES" MEANS, and why it is not just "the migrator exited 0". A migrator that emits
//! syntactically valid nonsense exits 0. Each config must:
//!   1. migrate without error,
//!   2. produce output that `--validate` ACCEPTS, once the decisions the migrator explicitly says a
//!      human must make (its `TODO(migrate)` lines) have been made,
//!   3. and, for a config that needs NO decisions, come back with no comment banner at all.
//!
//! On (2): the migrator cannot invent a signing key or choose an admin credential, and it says so
//! rather than guessing. The test supplies exactly those and no more — supplying anything else would
//! be the test papering over a real migration gap.
//!
//! ADDING A RELEASE: drop its `config.yaml` in as `v<x.y.z>_config.yaml`. No code change; the test
//! discovers the directory. `tests/migration-corpus/refresh.sh` regenerates the whole set from tags.

#![cfg_attr(not(linked_operator_auth), allow(dead_code))]

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;

fn corpus_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/migration-corpus/from-tags")
        .canonicalize()
        .expect("the migration corpus directory must exist; run tests/migration-corpus/refresh.sh")
}

fn corpus_files() -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(corpus_dir())
        .expect("read the migration corpus")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "yaml" || x == "yml"))
        .collect();
    v.sort();
    v
}

fn migrate(path: &Path) -> Result<(String, String), String> {
    let out = Command::new(env!("CARGO_BIN_EXE_busbar"))
        .arg("--migrate-config")
        .arg(path)
        .output()
        .map_err(|e| format!("could not run busbar: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "`busbar --migrate-config` exited {}\n--- stderr ---\n{}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok((
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    ))
}

fn apply_deferred_decisions(yaml: &str) -> String {
    let mut doc: serde_yaml::Value = match serde_yaml::from_str(yaml) {
        Ok(v) => v,
        Err(_) => return yaml.to_string(),
    };
    let Some(map) = doc.as_mapping_mut() else {
        return yaml.to_string();
    };
    let auth_key = serde_yaml::Value::String("auth".into());
    let Some(auth) = map.get_mut(&auth_key).and_then(|a| a.as_mapping_mut()) else {
        return yaml.to_string();
    };
    let names_keys = auth
        .get(serde_yaml::Value::String("chain".into()))
        .and_then(|c| c.as_sequence())
        .is_some_and(|s| s.iter().any(|v| v.as_str() == Some("keys")));
    if !names_keys {
        return serde_yaml::to_string(&doc).unwrap_or_else(|_| yaml.to_string());
    }

    auth.entry(serde_yaml::Value::String("signing_key".into()))
        .or_insert_with(|| {
            serde_yaml::from_str("{ env: BUSBAR_TEST_SIGNING_KEY }").expect("literal parses")
        });

    let op = common::operator_module();
    auth.entry(serde_yaml::Value::String("admin_auth".into()))
        .or_insert_with(|| serde_yaml::from_str(&format!("[{op}]")).expect("literal parses"));

    let idp_key = serde_yaml::Value::String("identity-providers".into());
    let idp = map
        .entry(idp_key)
        .or_insert_with(|| serde_yaml::Value::Mapping(Default::default()));
    if let Some(m) = idp.as_mapping_mut() {
        m.entry(serde_yaml::Value::String(op.clone()))
            .or_insert_with(|| {
                serde_yaml::from_str(&format!(
                    "{{ module: {op}, token: {{ env: BUSBAR_TEST_ADMIN_TOKEN }} }}"
                ))
                .expect("literal parses")
            });
    }
    serde_yaml::to_string(&doc).unwrap_or_else(|_| yaml.to_string())
}

fn providers_for(corpus_file: &Path) -> PathBuf {
    let name = corpus_file
        .file_name()
        .unwrap_or_default()
        .to_string_lossy();

    let (tag, rest) = name.split_once('_').unwrap_or(("", name.as_ref()));
    let dir = corpus_file
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.join("providers"))
        .unwrap_or_default();

    let sibling = rest.replacen("config", "providers", 1);
    let candidate = dir.join(format!("{tag}_{sibling}"));
    if candidate.is_file() {
        return candidate;
    }

    if let Ok(entries) = std::fs::read_dir(&dir) {
        for e in entries.flatten() {
            if e.file_name().to_string_lossy().ends_with(&sibling) {
                return e.path();
            }
        }
    }
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../providers.yaml")
}

fn yaml_comment_start(line: &str) -> usize {
    let bytes = line.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'#' && (i == 0 || bytes[i - 1].is_ascii_whitespace()) {
            return i;
        }
    }
    line.len()
}

fn rewrite_file_secret_paths(yaml: &str, stand_in: &str) -> String {
    let mut out = String::with_capacity(yaml.len());
    for line in yaml.lines() {
        let code_end = yaml_comment_start(line);
        let (code, comment) = line.split_at(code_end);
        let mut rest = code;
        loop {
            let Some(rel) = rest.find("file:") else {
                out.push_str(rest);
                break;
            };
            let (head, tail) = rest.split_at(rel);
            let after_key = &tail["file:".len()..];
            let before = head.trim_end();
            if before.is_empty() || before.ends_with('{') {
                let close = after_key.find('}').unwrap_or(after_key.len());
                out.push_str(head);
                out.push_str("file: ");
                out.push_str(stand_in);
                out.push(' ');
                out.push_str(&after_key[close..]);
                break;
            }

            out.push_str(head);
            out.push_str("file:");
            rest = after_key;
        }
        out.push_str(comment);
        out.push('\n');
    }
    out
}

#[test]
fn rewrite_file_secret_paths_only_touches_genuine_secret_refs() {
    let yaml = "\
# THIS file: your deployment, references providers by name
#   cert:      { file: /etc/busbar/admin-cert.pem }
providers_file: /etc/busbar/providers.yaml
  signing_key: { file: /var/lib/busbar/signing.key }        # REQUIRED with keys above
  admin_ca:
    file: /var/lib/busbar/admin-ca.pem
  cert_file: /etc/busbar/cert.pem
";
    let out = rewrite_file_secret_paths(yaml, "/tmp/stand-in");

    assert!(
        out.contains("signing_key: { file: /tmp/stand-in }"),
        "the genuine `{{ file: … }}` secret must be repointed at the stand-in; got:\n{out}"
    );
    assert!(
        !out.contains("/var/lib/busbar/signing.key"),
        "the production signing.key path must be gone; got:\n{out}"
    );

    assert!(
        out.contains("    file: /tmp/stand-in"),
        "a block-form `file:` secret key must be repointed; got:\n{out}"
    );
    assert!(
        !out.contains("/var/lib/busbar/admin-ca.pem"),
        "the production admin-ca path must be gone; got:\n{out}"
    );

    assert!(
        out.contains("# REQUIRED with keys above"),
        "the trailing comment must survive; got:\n{out}"
    );

    assert!(
        out.contains("providers_file: /etc/busbar/providers.yaml"),
        "`providers_file:` must NOT be rewritten; got:\n{out}"
    );

    assert!(
        out.contains("cert_file: /etc/busbar/cert.pem"),
        "`cert_file:` must NOT be rewritten; got:\n{out}"
    );

    assert!(
        out.contains("# THIS file: your deployment"),
        "a `file:` in comment prose must NOT be rewritten; got:\n{out}"
    );
    assert!(
        out.contains("#   cert:      { file: /etc/busbar/admin-cert.pem }"),
        "a commented `{{ file: … }}` example must NOT be rewritten; got:\n{out}"
    );
}

fn validate(yaml: &str, tmp: &Path, providers: &Path) -> Result<String, String> {
    std::fs::write(tmp, yaml).map_err(|e| format!("write temp config: {e}"))?;

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_busbar"));

    cmd.arg("--validate")
        .arg("--providers")
        .arg(providers)
        .env("BUSBAR_CONFIG", tmp)
        .env("BUSBAR_TEST_SIGNING_KEY", "a".repeat(64))
        .env("BUSBAR_TEST_ADMIN_TOKEN", "corpus-admin-token");

    let yaml = if yaml.contains("file:") {
        let stand_in = tmp.with_extension("secret");
        std::fs::write(&stand_in, "a".repeat(64)).map_err(|e| format!("write stand-in: {e}"))?;
        let out = rewrite_file_secret_paths(yaml, &stand_in.display().to_string());
        std::fs::write(tmp, &out).map_err(|e| format!("rewrite temp config: {e}"))?;
        std::borrow::Cow::Owned(out)
    } else {
        std::borrow::Cow::Borrowed(yaml)
    };
    let yaml: &str = &yaml;

    for (i, _) in yaml.match_indices("env:") {
        let name: String = yaml[i + 4..]
            .chars()
            .skip_while(|c| c.is_whitespace())
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if !name.is_empty() {
            cmd.env(&name, "a".repeat(64));
        }
    }
    let out = cmd
        .output()
        .map_err(|e| format!("could not run busbar --validate: {e}"))?;
    if out.status.success() {
        return Ok(String::from_utf8_lossy(&out.stderr).into_owned());
    }
    Err(format!(
        "--- validate stdout ---\n{}\n--- validate stderr ---\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    ))
}

#[cfg(linked_operator_auth)]
#[test]
fn every_shipped_config_migrates_to_a_valid_current_config() {
    let files = corpus_files();
    assert!(
        files.len() >= 20,
        "the migration corpus looks empty or truncated ({} files). It should hold one config per \
         shipped release. Regenerate with tests/migration-corpus/refresh.sh.",
        files.len()
    );

    let tmp = std::env::temp_dir().join(format!("busbar-corpus-{}.yaml", std::process::id()));
    let mut failures: Vec<String> = Vec::new();

    for f in &files {
        let name = f
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        let (migrated, _changes) = match migrate(f) {
            Ok(v) => v,
            Err(e) => {
                failures.push(format!("[{name}] MIGRATION FAILED\n{e}"));
                continue;
            }
        };
        let ready = apply_deferred_decisions(&migrated);
        if let Err(e) = validate(&ready, &tmp, &providers_for(f)) {
            let head: String = migrated.lines().take(30).collect::<Vec<_>>().join("\n");
            failures.push(format!(
                "[{name}] MIGRATED BUT DID NOT VALIDATE\n{e}\n--- first 30 lines of the migrated \
                 config ---\n{head}\n--- reproduce ---\n  busbar --migrate-config \
                 tests/migration-corpus/from-tags/{name}"
            ));
        }
    }
    let _ = std::fs::remove_file(&tmp);
    let _ = std::fs::remove_file(tmp.with_extension("secret"));

    assert!(
        failures.is_empty(),
        "{} of {} shipped configs do not migrate to a valid current config.\n\n{}\n\nEach block \
         above names the corpus file, what the validator said, and the command to reproduce it. A \
         failure here means an operator upgrading from that release cannot migrate mechanically \
         — fix the migrator (crates/busbar-core/src/config/migrate.rs), not the corpus.",
        failures.len(),
        files.len(),
        failures.join("\n\n========================================\n\n")
    );
}

#[test]
fn a_migration_with_nothing_to_decide_emits_no_comment_banner() {
    let mut checked = 0usize;
    let mut dirty: Vec<String> = Vec::new();
    for f in corpus_files() {
        let name = f
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        let Ok((migrated, _)) = migrate(&f) else {
            continue;
        };

        if migrated.contains("TODO(migrate)") || migrated.contains("WARNING(migrate)") {
            continue;
        }
        checked += 1;
        if migrated.trim_start().starts_with('#') {
            let head: String = migrated.lines().take(4).collect::<Vec<_>>().join("\n");
            dirty.push(format!("[{name}] leads with a comment:\n{head}"));
        }
    }
    assert!(
        checked > 0,
        "no corpus config migrated cleanly, so this test verified nothing. Either the corpus is \
         missing recent releases, or every migration now reports a TODO — both are worth knowing."
    );
    assert!(
        dirty.is_empty(),
        "{} migration(s) that needed no choice still emitted a comment banner:\n\n{}",
        dirty.len(),
        dirty.join("\n\n")
    );
}

fn warning_lines(stderr: &str) -> Vec<&str> {
    stderr.lines().filter(|l| l.contains("[warn]")).collect()
}

fn oracle_tag(corpus_file: &Path) -> String {
    let name = corpus_file
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    name.strip_suffix("_config.yaml")
        .map(str::to_string)
        .unwrap_or(name)
}

fn recorded_1_5_5_warning_count(tag: &str) -> Option<usize> {
    let cell = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testing/shadow-oracle/golden/1.5.5/cells")
        .join(format!("config.migrate__{tag}__validate-migrated.json"));
    let text = std::fs::read_to_string(cell).ok()?;
    let doc: serde_json::Value = serde_json::from_str(&text).ok()?;
    let stderr = doc.get("effects")?.get("stderr")?.as_str()?;
    Some(warning_lines(stderr).len())
}

#[cfg(linked_operator_auth)]
#[test]
fn no_corpus_config_warns_more_at_boot_than_the_published_1_5_5_did() {
    let files = corpus_files();
    let tmp = std::env::temp_dir().join(format!("busbar-warncount-{}.yaml", std::process::id()));
    let mut regressions: Vec<String> = Vec::new();
    let mut compared = 0usize;
    let (mut recorded_total, mut current_total) = (0usize, 0usize);

    for f in &files {
        let name = f
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();

        let Some(recorded) = recorded_1_5_5_warning_count(&oracle_tag(f)) else {
            continue;
        };
        let Ok((migrated, _)) = migrate(f) else {
            continue;
        };
        let ready = apply_deferred_decisions(&migrated);

        let Ok(stderr) = validate(&ready, &tmp, &providers_for(f)) else {
            continue;
        };
        let current = warning_lines(&stderr);
        compared += 1;
        recorded_total += recorded;
        current_total += current.len();
        if current.len() > recorded {
            regressions.push(format!(
                "[{name}] 1.5.5 warned {recorded} time(s) here; this binary warns {}:\n{}",
                current.len(),
                current
                    .iter()
                    .map(|l| format!("      {}", l.trim()))
                    .collect::<Vec<_>>()
                    .join("\n")
            ));
        }
    }
    let _ = std::fs::remove_file(&tmp);
    let _ = std::fs::remove_file(tmp.with_extension("secret"));

    assert_eq!(
        compared,
        files.len(),
        "only {compared} of {} corpus configs were compared against a recorded 1.5.5 warning \
         count, so this test verified less than it claims. Either the pinned golden lost its \
         config.migrate|<tag>|validate-migrated recordings, or the corpus stopped migrating, or \
         a migrated config stopped validating.",
        files.len()
    );
    assert!(
        regressions.is_empty(),
        "{} migrated config(s) now emit MORE boot warnings than the published 1.5.5 binary did on \
         the same config. The binding is that a migrated 1.5.5 deployment sees no boot warning \
         beyond 1.5.5's own unless it writes a 1.6.0-additive key; every line below is one it did \
         not ask for.\n\n{}\n\n(corpus totals: 1.5.5 {recorded_total} warning(s) over {compared} \
         configs, this binary {current_total})",
        regressions.len(),
        regressions.join("\n\n")
    );
}
