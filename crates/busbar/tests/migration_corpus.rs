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

/// Run `--migrate-config` and return `(stdout, stderr)`, or a rendered failure.
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

/// The decisions the migrator explicitly defers to a human, applied mechanically so the RESULT can
/// be validated. Deliberately narrow: only what a `TODO(migrate)` line actually asks for.
///
/// A signing key and an admin credential are the two things a migrator must not invent — a key it
/// chose would be unrotatable and identical across every deployment that ran the tool. Supplying
/// them here is the test standing in for the operator, not the test hiding a gap.
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
    // A 64-hex ed25519 secret, the shape `--generate-signing-key` emits. Fixed, because a test
    // fixture must be reproducible; it never leaves this process.
    auth.entry(serde_yaml::Value::String("signing_key".into()))
        .or_insert_with(|| {
            serde_yaml::from_str("{ env: BUSBAR_TEST_SIGNING_KEY }").expect("literal parses")
        });
    auth.entry(serde_yaml::Value::String("admin_auth".into()))
        .or_insert_with(|| serde_yaml::from_str("[admin-tokens]").expect("literal parses"));
    // `admin_auth` references it by bare name, so the provider has to be defined.
    let idp_key = serde_yaml::Value::String("identity-providers".into());
    let idp = map
        .entry(idp_key)
        .or_insert_with(|| serde_yaml::Value::Mapping(Default::default()));
    if let Some(m) = idp.as_mapping_mut() {
        m.entry(serde_yaml::Value::String("admin-tokens".into()))
            .or_insert_with(|| {
                serde_yaml::from_str(
                    "{ module: admin-tokens, token: { env: BUSBAR_TEST_ADMIN_TOKEN } }",
                )
                .expect("literal parses")
            });
    }
    serde_yaml::to_string(&doc).unwrap_or_else(|_| yaml.to_string())
}

/// The providers catalog a corpus config should be validated against.
///
/// A config is only meaningful WITH the catalog it shipped beside: `bench/latency/config.mock.yaml`
/// names a `mock` provider that exists solely in `bench/latency/providers.mock.yaml`, so validating
/// it against the shipped root catalog reports "provider 'mock' not found" — a true statement about
/// the wrong pairing, not a migration defect. Pairing each config with its own tag's catalog tests
/// the thing that actually shipped.
///
/// Falls back to the current root catalog when a config has no same-tag sibling, which is right for
/// the ordinary `config.yaml` case: it always referenced the root catalog.
fn providers_for(corpus_file: &Path) -> PathBuf {
    let name = corpus_file
        .file_name()
        .unwrap_or_default()
        .to_string_lossy();
    // `v1.4.1_bench_latency_config.mock.yaml` -> tag `v1.4.1`, variant `mock`
    let (tag, rest) = name.split_once('_').unwrap_or(("", name.as_ref()));
    let dir = corpus_file
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.join("providers"))
        .unwrap_or_default();
    // Same directory prefix, `config` -> `providers`. Keeps the variant suffix (`.mock`, `.anthropic`).
    let sibling = rest.replacen("config", "providers", 1);
    let candidate = dir.join(format!("{tag}_{sibling}"));
    if candidate.is_file() {
        return candidate;
    }
    // A bench config with no same-tag catalog: try the same variant from any tag before giving up,
    // since these files barely change and a missing one should not fail a MIGRATION test.
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for e in entries.flatten() {
            if e.file_name().to_string_lossy().ends_with(&sibling) {
                return e.path();
            }
        }
    }
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../providers.yaml")
}

/// The byte offset at which a YAML line-comment begins, or `line.len()` if there is none.
///
/// A `#` only opens a comment when it is at line start or preceded by whitespace — a `#` embedded
/// in a token (`/etc/a#b`) is not a comment. Keeping this precise is what lets the repointer leave
/// `file:` occurrences INSIDE a comment (the `THIS file:` prose, the commented TLS examples) alone.
fn yaml_comment_start(line: &str) -> usize {
    let bytes = line.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'#' && (i == 0 || bytes[i - 1].is_ascii_whitespace()) {
            return i;
        }
    }
    line.len()
}

/// Repoint every GENUINE `{ file: <path> }` built-in secret reference at `stand_in`, and NOTHING
/// else.
///
/// The corpus names PRODUCTION paths (`/var/lib/busbar/signing.key`) that cannot exist in CI, so a
/// real `file:` secret has to be redirected at a temp file for `--validate` to resolve it. The
/// earlier implementation matched a BARE `file:` substring, which also rewrote `providers_file:` /
/// `cert_file:` / `key_file:` / `client_ca_file:` KEYS and `file:` inside comment prose — benign
/// only by luck of today's corpus (every such hit was a comment or a repeat), and a latent trap the
/// day the migrator emits an uncommented `providers_file:` line. Anchor to the secret-ref shape
/// instead: a `file:` is a value to repoint ONLY when it is the KEY of a `file` mapping — the
/// built-in `file` secret module — AND it sits in the CODE part of the line, before any comment.
/// The `file` key appears in two shapes and BOTH occur in the corpus once a config is round-tripped
/// through the deferred-decision serializer:
///   * flow sugar `{ file: /path }` (as the raw corpus writes it), and
///   * block form `\n  file: /path` (as `serde_yaml` re-emits the same `SecretRef`).
///
/// In both, everything before `file:` on the line is whitespace only — either the leading
/// indentation (block) or `{ ` (flow). So the anchor is: the head, trimmed, is empty OR ends with
/// `{`. `providers_file:` / `cert_file:` / `key_file:` / `client_ca_file:` all FAIL it (the char
/// before `file:` is `_`, part of the key name); a commented `{ file: … }` fails it too (it is past
/// the comment marker, so never in the CODE part scanned here).
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
                // A genuine `file:` secret key (block `  file: /p` or flow `{ file: /p }`): keep the
                // head (indentation or `{ `), drop the old path up to `}` (flow) or end-of-code
                // (block), and splice in the stand-in.
                let close = after_key.find('}').unwrap_or(after_key.len());
                out.push_str(head);
                out.push_str("file: ");
                out.push_str(stand_in);
                out.push(' ');
                out.push_str(&after_key[close..]);
                break;
            }
            // A `*_file:` key or other bare `file:` — emit verbatim and keep scanning the tail.
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

    // The genuine active FLOW-sugar secret ref IS repointed...
    assert!(
        out.contains("signing_key: { file: /tmp/stand-in }"),
        "the genuine `{{ file: … }}` secret must be repointed at the stand-in; got:\n{out}"
    );
    assert!(
        !out.contains("/var/lib/busbar/signing.key"),
        "the production signing.key path must be gone; got:\n{out}"
    );
    // ...and so is the BLOCK-form `file:` key that `serde_yaml` re-emits after a round-trip (the
    // shape the real corpus validation actually feeds this function).
    assert!(
        out.contains("    file: /tmp/stand-in"),
        "a block-form `file:` secret key must be repointed; got:\n{out}"
    );
    assert!(
        !out.contains("/var/lib/busbar/admin-ca.pem"),
        "the production admin-ca path must be gone; got:\n{out}"
    );
    // ...its trailing comment survives unharmed.
    assert!(
        out.contains("# REQUIRED with keys above"),
        "the trailing comment must survive; got:\n{out}"
    );

    // A `providers_file:` KEY is NOT a secret ref and must be left byte-for-byte.
    assert!(
        out.contains("providers_file: /etc/busbar/providers.yaml"),
        "`providers_file:` must NOT be rewritten; got:\n{out}"
    );
    // Nor a `cert_file:` key.
    assert!(
        out.contains("cert_file: /etc/busbar/cert.pem"),
        "`cert_file:` must NOT be rewritten; got:\n{out}"
    );
    // A `file:` inside a comment — prose or a commented `{ file: … }` example — is untouched.
    assert!(
        out.contains("# THIS file: your deployment"),
        "a `file:` in comment prose must NOT be rewritten; got:\n{out}"
    );
    assert!(
        out.contains("#   cert:      { file: /etc/busbar/admin-cert.pem }"),
        "a commented `{{ file: … }}` example must NOT be rewritten; got:\n{out}"
    );
}

fn validate(yaml: &str, tmp: &Path, providers: &Path) -> Result<(), String> {
    std::fs::write(tmp, yaml).map_err(|e| format!("write temp config: {e}"))?;
    // `--validate` RESOLVES built-in secret references, so every env var a corpus config names must
    // be set or the gate fails on this machine's environment rather than on the migration. The
    // corpus spans every shipped release, so enumerating the names here would rot; extract them
    // from the config under test instead.
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_busbar"));
    // 1.6.0: the shared root catalog is not next to the temp config, so point busbar at it with the
    // `--providers` flag (the removed `BUSBAR_PROVIDERS` env var no longer works).
    cmd.arg("--validate")
        .arg("--providers")
        .arg(providers)
        .env("BUSBAR_CONFIG", tmp)
        .env("BUSBAR_TEST_SIGNING_KEY", "a".repeat(64))
        .env("BUSBAR_TEST_ADMIN_TOKEN", "corpus-admin-token");
    // `file:` refs name PRODUCTION paths (`/var/lib/busbar/signing.key`) that cannot exist in CI.
    // Point the copy under test at a real temp file so the gate checks the migration, not this
    // machine's filesystem layout.
    let yaml = if yaml.contains("file:") {
        let dir = tmp.parent().unwrap_or(Path::new("."));
        let stand_in = dir.join("corpus-secret");
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
            // 64 hex: valid wherever a signing key is expected, harmless elsewhere.
            cmd.env(&name, "a".repeat(64));
        }
    }
    let out = cmd
        .output()
        .map_err(|e| format!("could not run busbar --validate: {e}"))?;
    if out.status.success() {
        return Ok(());
    }
    Err(format!(
        "--- validate stdout ---\n{}\n--- validate stderr ---\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    ))
}

/// Every shipped config migrates to a config the current binary ACCEPTS.
///
/// Reports EVERY failure with its migrated YAML and the validator's own words, rather than dying on
/// the first: when a migration rule regresses it usually breaks a whole era of configs at once, and
/// seeing "these 9 all lost their pools block" is a diagnosis where "v1.2.0 failed" is a scavenger
/// hunt.
#[test]
fn every_shipped_config_migrates_to_a_valid_current_config() {
    // A config whose chain names `keys` needs an admin credential that can mint one, and the only
    // built-in is `admin-tokens`. Without that feature the binary REFUSES such a config by design
    // ("the admin API would be silently disabled"), so the deferred decision cannot be supplied and
    // the test would be asserting a property of the build, not of the migrator. Skipped loudly
    // rather than silently: the default build runs it, so coverage is not lost.
    if !cfg!(feature = "auth-admin-tokens") {
        eprintln!(
            "SKIP: built without `auth-admin-tokens`, so a migrated config naming `keys` cannot be \
             given a valid admin mint path. The default-features build covers this."
        );
        return;
    }
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

/// A migration needing NO human decision must emit a file that looks hand-written.
///
/// The banner used to be unconditional, so a clean 1.5.x -> current migration came back stamped
/// "migrated by a tool, review before deploying" — noise the operator then has to decide whether to
/// delete, on a file that needed no review at all.
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
        // Only configs the migrator had no TODO/WARNING for: those are the ones that should be clean.
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
        "{} migration(s) that needed no decision still emitted a comment banner:\n\n{}",
        dirty.len(),
        dirty.join("\n\n")
    );
}
