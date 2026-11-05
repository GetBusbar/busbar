// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Capture retired launch inputs once, before plugin/config migration. Serving never reads them.
use std::ffi::OsString;
use std::path::Path;

use serde_yaml::{Mapping, Value};

pub(crate) struct Captured {
    pub yaml: String,
    pub changes: Vec<String>,
    pub warnings: Vec<String>,
}

pub(crate) fn capture(
    raw: &str,
    working_directory: &Path,
    providers_flag: Option<&str>,
    env: impl Fn(&str) -> Option<OsString>,
) -> Result<Captured, String> {
    let mut document: Value =
        serde_yaml::from_str(raw).map_err(|error| format!("input is not valid YAML: {error}"))?;
    let root = document
        .as_mapping_mut()
        .ok_or("input is not a YAML mapping (expected a busbar config document)")?;
    let mut changes = Vec::new();
    let mut warnings = Vec::new();

    // Old CLI/env paths are relative to the launch directory, whereas providers_file is
    // relative to config.yaml. Freeze the absolute path to retain the actual selected catalog.
    let providers_env = env("BUSBAR_PROVIDERS").and_then(|value| value.into_string().ok());
    if let Some(path) =
        providers_flag.or(providers_env.as_deref().filter(|value| !value.is_empty()))
    {
        let path = Path::new(path);
        let path = if path.is_absolute() {
            path.to_path_buf()
        } else {
            working_directory.join(path)
        };
        let path = path
            .to_str()
            .ok_or("the selected providers path is not UTF-8")?;
        root.insert(Value::from("providers_file"), Value::from(path));
        changes.push("captured launch providers override as providers_file (absolute path)".into());
    }

    if let Some(value) = env("BUSBAR_WORKER_THREADS").and_then(|value| value.into_string().ok()) {
        match value.trim().parse::<usize>() {
            // The old runtime capped this value at 128. Invalid values fell through to
            // configured workers, TOKIO_WORKER_THREADS, and available parallelism.
            Ok(count) if count > 0 => {
                advanced(root)?.insert(Value::from("worker_threads"), Value::from(count.min(128)));
                changes.push("BUSBAR_WORKER_THREADS -> advanced.worker_threads".into());
            }
            _ => warnings.push(
                "BUSBAR_WORKER_THREADS is not a positive integer; ignored as in the old launcher; configured workers and the TOKIO_WORKER_THREADS fallback are preserved".into(),
            ),
        }
    }
    for (name, key) in [
        ("BUSBAR_UPSTREAM_HTTP1_ONLY", "upstream_http1_only"),
        (
            "BUSBAR_UPSTREAM_H2_PRIOR_KNOWLEDGE",
            "upstream_h2_prior_knowledge",
        ),
    ] {
        if let Some(value) = env(name) {
            // Preserve the old effective setting, including explicit false/empty overrides.
            let enabled = value != "0" && !value.is_empty();
            advanced(root)?.insert(Value::from(key), Value::Bool(enabled));
            changes.push(format!("{name} -> advanced.{key}"));
        }
    }
    let yaml = if changes.is_empty() {
        raw.to_owned()
    } else {
        serde_yaml::to_string(&document)
            .map_err(|error| format!("could not serialize captured launch inputs: {error}"))?
    };
    Ok(Captured {
        yaml,
        changes,
        warnings,
    })
}

fn advanced(root: &mut Mapping) -> Result<&mut Mapping, String> {
    root.entry(Value::from("advanced"))
        .or_insert_with(|| Value::Mapping(Mapping::new()))
        .as_mapping_mut()
        .ok_or_else(|| {
            "cannot capture retired environment settings: advanced must be a mapping".into()
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn under(raw: &str, flag: Option<&str>, pairs: &[(&str, &str)]) -> Captured {
        capture(raw, Path::new("/launch"), flag, |name| {
            pairs
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| OsString::from(value))
        })
        .unwrap()
    }

    #[test]
    fn migration_captures_old_effective_settings_over_conflicting_config() {
        let captured = under(
            "providers_file: from-config.yaml\nadvanced: {worker_threads: 7, upstream_http1_only: true, upstream_h2_prior_knowledge: false}\n",
            None,
            &[("BUSBAR_PROVIDERS", "catalog/old.yaml"), ("BUSBAR_WORKER_THREADS", " 999 "),
              ("BUSBAR_UPSTREAM_HTTP1_ONLY", "0"), ("BUSBAR_UPSTREAM_H2_PRIOR_KNOWLEDGE", "false")],
        );
        let doc: Value = serde_yaml::from_str(&captured.yaml).unwrap();
        assert_eq!(doc["providers_file"], "/launch/catalog/old.yaml");
        assert_eq!(doc["advanced"]["worker_threads"], 128);
        assert_eq!(doc["advanced"]["upstream_http1_only"], false);
        assert_eq!(doc["advanced"]["upstream_h2_prior_knowledge"], true);
        assert_eq!(captured.changes.len(), 4);
        assert!(captured.warnings.is_empty());
    }

    #[test]
    fn migration_cli_path_wins_and_relative_config_path_is_left_config_relative() {
        let captured = under(
            "providers_file: catalog/config.yaml\n",
            Some("flag.yaml"),
            &[("BUSBAR_PROVIDERS", "env.yaml")],
        );
        let doc: Value = serde_yaml::from_str(&captured.yaml).unwrap();
        assert_eq!(doc["providers_file"], "/launch/flag.yaml");
        for pairs in [&[][..], &[("BUSBAR_PROVIDERS", "")][..]] {
            let captured = under("providers_file: catalog/config.yaml\n", None, pairs);
            assert_eq!(captured.yaml, "providers_file: catalog/config.yaml\n");
            assert!(captured.changes.is_empty());
        }
        let captured = under("{}", None, &[("BUSBAR_PROVIDERS", "/other/catalog.yaml")]);
        let doc: Value = serde_yaml::from_str(&captured.yaml).unwrap();
        assert_eq!(doc["providers_file"], "/other/catalog.yaml");
    }

    #[test]
    fn migration_preserves_false_empty_and_invalid_worker_fallbacks() {
        for invalid in ["0", "-1", "invalid", ""] {
            let captured = under(
                "advanced: {worker_threads: 7, upstream_http1_only: true}\n",
                None,
                &[
                    ("BUSBAR_WORKER_THREADS", invalid),
                    ("BUSBAR_UPSTREAM_HTTP1_ONLY", ""),
                ],
            );
            let doc: Value = serde_yaml::from_str(&captured.yaml).unwrap();
            assert_eq!(doc["advanced"]["worker_threads"], 7);
            assert_eq!(doc["advanced"]["upstream_http1_only"], false);
            assert_eq!(captured.warnings.len(), 1);
        }
        let captured = under(
            "{}",
            None,
            &[
                ("TOKIO_WORKER_THREADS", "3"),
                ("BUSBAR_CONFIG", "/elsewhere"),
            ],
        );
        assert_eq!(captured.yaml, "{}");
        assert!(captured.changes.is_empty());
    }

    #[test]
    fn migration_does_not_discard_malformed_advanced_configuration() {
        assert!(
            capture("advanced: broken", Path::new("/launch"), None, |name| (name
                == "BUSBAR_WORKER_THREADS")
                .then(|| OsString::from("4")))
            .is_err()
        );
    }
}
