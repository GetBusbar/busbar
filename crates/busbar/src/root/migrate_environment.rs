// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Capture retired launch inputs once, before plugin/config migration. Serving never reads them;
//! boot and `--validate` only report, through `ignored_launch_env`, that a set one is ignored.
use std::ffi::OsString;
use std::path::Path;

use busbar_contract::yaml::{MappingExt, Pairs, Value, ValueExt};

/// Launch env vars 1.6.0 no longer reads. The ONLY place in the workspace that spells their names
/// (law: `dist/default/tests/retired_env_single_source.rs` and this file's tests). `capture()`
/// reads them from here; `ignored_launch_env()` reports them.
pub(crate) struct Retired {
    pub name: &'static str,
    /// capture()'s rule: an empty BUSBAR_PROVIDERS selected nothing in 1.5.5, so it counts as unset.
    pub empty_is_unset: bool,
    pub use_instead: &'static str,
}

pub(crate) const PROVIDERS: usize = 0;
pub(crate) const WORKERS: usize = 1;
pub(crate) const HTTP1: usize = 2;
pub(crate) const H2: usize = 3;

pub(crate) const RETIRED_LAUNCH_ENV: [Retired; 4] = [
    Retired {
        name: "BUSBAR_PROVIDERS",
        empty_is_unset: true,
        use_instead: "`providers_file:` in config.yaml (default: providers.yaml beside config.yaml) or --providers",
    },
    Retired {
        name: "BUSBAR_WORKER_THREADS",
        empty_is_unset: false,
        use_instead: "`advanced.worker_threads` in config.yaml (TOKIO_WORKER_THREADS is still read as a fallback)",
    },
    Retired {
        name: "BUSBAR_UPSTREAM_HTTP1_ONLY",
        empty_is_unset: false,
        use_instead: "`advanced.upstream_http1_only` in config.yaml",
    },
    Retired {
        name: "BUSBAR_UPSTREAM_H2_PRIOR_KNOWLEDGE",
        empty_is_unset: false,
        use_instead: "`advanced.upstream_h2_prior_knowledge` in config.yaml",
    },
];

/// One stderr line per retired variable that is set, using the same meaning of "set" as capture().
/// The value is never echoed.
pub(crate) fn ignored_launch_env(env: impl Fn(&str) -> Option<OsString>) -> Vec<String> {
    RETIRED_LAUNCH_ENV
        .iter()
        .filter(|r| env(r.name).is_some_and(|v| !(r.empty_is_unset && v.is_empty())))
        .map(|r| {
            format!(
                "[warn] {code}: {name} is set but ignored (busbar 1.6 no longer reads it); use {use_instead}. \
                 Write its value into config.yaml, then remove {name} from the launcher.",
                code = busbar_kernel::diagnostics::RETIRED_ENV_VAR_IGNORED.banner(),
                name = r.name,
                use_instead = r.use_instead
            )
        })
        .collect()
}

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
    let mut document: Value = busbar_contract::yaml::from_str(raw)
        .map_err(|error| format!("input is not valid YAML: {error}"))?;
    let root = document
        .as_mapping_mut()
        .ok_or("input is not a YAML mapping (expected a busbar config document)")?;
    let mut changes = Vec::new();
    let mut warnings = Vec::new();

    // Old CLI/env paths are relative to the launch directory, whereas providers_file is
    // relative to config.yaml. Freeze the absolute path to retain the actual selected catalog.
    let providers_env =
        env(RETIRED_LAUNCH_ENV[PROVIDERS].name).and_then(|value| value.into_string().ok());
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
        root.insert_key(Value::from("providers_file"), Value::from(path));
        changes.push("captured launch providers override as providers_file (absolute path)".into());
    }

    if let Some(value) =
        env(RETIRED_LAUNCH_ENV[WORKERS].name).and_then(|value| value.into_string().ok())
    {
        match value.trim().parse::<usize>() {
            // The old runtime capped this value at 128. Invalid values fell through to
            // configured workers, TOKIO_WORKER_THREADS, and available parallelism.
            Ok(count) if count > 0 => {
                advanced(root)?.insert_key(
                    Value::from("worker_threads"),
                    Value::from(count.min(128) as u64),
                );
                changes.push(format!(
                    "{} -> advanced.worker_threads",
                    RETIRED_LAUNCH_ENV[WORKERS].name
                ));
            }
            _ => warnings
                .push(busbar_kernel::diagnostics::coded::migrate_worker_threads_ignored().into()),
        }
    }
    for (index, key) in [
        (HTTP1, "upstream_http1_only"),
        (H2, "upstream_h2_prior_knowledge"),
    ] {
        let name = RETIRED_LAUNCH_ENV[index].name;
        if let Some(value) = env(name) {
            // Preserve the old effective setting, including explicit false/empty overrides.
            let enabled = value != "0" && !value.is_empty();
            advanced(root)?.insert_key(Value::from(key), Value::Bool(enabled));
            changes.push(format!("{name} -> advanced.{key}"));
        }
    }
    if env("BUSBAR_PROFILE").is_some() {
        warnings.push("BUSBAR_PROFILE is ignored in 1.6.0; use trace export".into());
    }
    let yaml = if changes.is_empty() {
        raw.to_owned()
    } else {
        busbar_contract::yaml::to_string(&document)
            .map_err(|error| format!("could not serialize captured launch inputs: {error}"))?
    };
    Ok(Captured {
        yaml,
        changes,
        warnings,
    })
}

fn advanced(root: &mut Pairs) -> Result<&mut Pairs, String> {
    root.entry_or_insert_with("advanced", || Value::Map(Pairs::new()))
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
            &[
                ("BUSBAR_PROVIDERS", "catalog/old.yaml"),
                ("BUSBAR_WORKER_THREADS", " 999 "),
                ("BUSBAR_UPSTREAM_HTTP1_ONLY", "0"),
                ("BUSBAR_UPSTREAM_H2_PRIOR_KNOWLEDGE", "false"),
            ],
        );
        let doc: Value = busbar_contract::yaml::from_str(&captured.yaml).unwrap();
        assert_eq!(
            doc.at("providers_file").as_str(),
            Some("/launch/catalog/old.yaml")
        );
        assert_eq!(doc.at("advanced").at("worker_threads").as_u64(), Some(128));
        assert_eq!(
            doc.at("advanced").at("upstream_http1_only").as_bool(),
            Some(false)
        );
        assert_eq!(
            doc.at("advanced")
                .at("upstream_h2_prior_knowledge")
                .as_bool(),
            Some(true)
        );
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
        let doc: Value = busbar_contract::yaml::from_str(&captured.yaml).unwrap();
        assert_eq!(doc.at("providers_file").as_str(), Some("/launch/flag.yaml"));
        for pairs in [&[][..], &[("BUSBAR_PROVIDERS", "")][..]] {
            let captured = under("providers_file: catalog/config.yaml\n", None, pairs);
            assert_eq!(captured.yaml, "providers_file: catalog/config.yaml\n");
            assert!(captured.changes.is_empty());
        }
        let captured = under("{}", None, &[("BUSBAR_PROVIDERS", "/other/catalog.yaml")]);
        let doc: Value = busbar_contract::yaml::from_str(&captured.yaml).unwrap();
        assert_eq!(
            doc.at("providers_file").as_str(),
            Some("/other/catalog.yaml")
        );
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
            let doc: Value = busbar_contract::yaml::from_str(&captured.yaml).unwrap();
            assert_eq!(doc.at("advanced").at("worker_threads").as_u64(), Some(7));
            assert_eq!(
                doc.at("advanced").at("upstream_http1_only").as_bool(),
                Some(false)
            );
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
    fn env_of<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<OsString> + 'a {
        move |name| {
            pairs
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| OsString::from(value))
        }
    }

    #[test]
    fn ignored_launch_env_reports_each_set_variable_once_in_table_order() {
        let banner = busbar_kernel::diagnostics::RETIRED_ENV_VAR_IGNORED.banner();
        let lines = ignored_launch_env(env_of(&[
            ("BUSBAR_UPSTREAM_H2_PRIOR_KNOWLEDGE", "1"),
            ("BUSBAR_UPSTREAM_HTTP1_ONLY", ""),
            ("BUSBAR_WORKER_THREADS", "4"),
            ("BUSBAR_PROVIDERS", "/old/providers.yaml"),
            ("TOKIO_WORKER_THREADS", "3"),
        ]));
        assert_eq!(lines.len(), RETIRED_LAUNCH_ENV.len(), "{lines:#?}");
        for (line, retired) in lines.iter().zip(&RETIRED_LAUNCH_ENV) {
            assert!(
                line.starts_with(&format!(
                    "[warn] {banner}: {} is set but ignored",
                    retired.name
                )),
                "{line}"
            );
            assert!(line.contains(retired.use_instead), "{line}");
            assert!(
                !line.contains("/old/providers.yaml"),
                "never echoes the value: {line}"
            );
        }

        assert!(ignored_launch_env(env_of(&[])).is_empty());
        assert!(
            ignored_launch_env(env_of(&[("BUSBAR_PROVIDERS", "")])).is_empty(),
            "an empty BUSBAR_PROVIDERS selected nothing, as in capture()"
        );
        let lines = ignored_launch_env(env_of(&[
            ("BUSBAR_PROVIDERS", ""),
            ("BUSBAR_WORKER_THREADS", ""),
        ]));
        assert_eq!(lines.len(), 1, "{lines:#?}");
        assert!(
            lines[0].contains(": BUSBAR_WORKER_THREADS is set"),
            "{lines:#?}"
        );
    }

    /// Every `"..."` literal in `source` (line comments skipped) that contains `BUSBAR_`, with
    /// the line it starts on.
    fn busbar_literals(source: &str) -> Vec<(String, &str)> {
        let lines: Vec<&str> = source.lines().collect();
        let mut found = Vec::new();
        let mut chars = source.char_indices().peekable();
        let mut line = 0;
        while let Some((_, c)) = chars.next() {
            match c {
                '\n' => line += 1,
                '/' if chars.peek().is_some_and(|(_, n)| *n == '/') => {
                    for (_, n) in chars.by_ref() {
                        if n == '\n' {
                            line += 1;
                            break;
                        }
                    }
                }
                '"' => {
                    let start_line = line;
                    let mut literal = String::new();
                    while let Some((_, n)) = chars.next() {
                        match n {
                            '"' => break,
                            '\\' => {
                                if let Some((_, escaped)) = chars.next() {
                                    if escaped == '\n' {
                                        line += 1;
                                    }
                                    literal.push(escaped);
                                }
                            }
                            '\n' => {
                                line += 1;
                                literal.push(n);
                            }
                            _ => literal.push(n),
                        }
                    }
                    if literal.contains("BUSBAR_") {
                        found.push((literal, lines[start_line]));
                    }
                }
                _ => {}
            }
        }
        found
    }

    #[test]
    fn retired_names_are_spelled_only_in_the_retired_table() {
        let source = include_str!("migrate_environment.rs");
        let production = &source[..source
            .find("\n#[cfg(test)]\n")
            .expect("this file has a test tail")];
        let literals = busbar_literals(production);
        let mut spelled: Vec<&str> = literals.iter().map(|(text, _)| text.as_str()).collect();
        spelled.sort();
        let mut table: Vec<&str> = RETIRED_LAUNCH_ENV.iter().map(|r| r.name).collect();
        table.sort();
        assert_eq!(
            spelled, table,
            "every BUSBAR_ literal outside the tests is one RETIRED_LAUNCH_ENV name, each once"
        );
        for (text, line) in &literals {
            assert!(
                line.trim_start().starts_with("name:"),
                "{text} is spelled outside a RETIRED_LAUNCH_ENV `name:` field: {line}"
            );
        }
    }

    #[test]
    fn the_literal_scanner_finds_planted_names() {
        let planted = "// \"BUSBAR_IN_A_COMMENT\"\nlet a = env(\"BUSBAR_NEW_KNOB\");\nif x == \"BUSBAR_PROVIDERS\" {}\nlet b = \"other\";\n";
        let found: Vec<String> = busbar_literals(planted)
            .into_iter()
            .map(|(text, _)| text)
            .collect();
        assert_eq!(found, ["BUSBAR_NEW_KNOB", "BUSBAR_PROVIDERS"]);
    }
}
