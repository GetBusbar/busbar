// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The launch variables 1.5.5 read and 1.6.0 retired (BUSBAR-3029). An old launcher is
//! converted, never refused: boot and `--validate` say one line for each one set
//! ([`check_launch_env`]), before migrating or loading config, and the start goes on.
use std::ffi::OsString;

/// What 1.6 does with a retired launch variable that is set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Carry {
    /// Read as 1.5.5 read it: the providers catalog path, as `--providers` takes it, when the
    /// command line names none ([`providers_path`]).
    ProvidersPath,
    /// Read as 1.5.5 read it (`0` or empty is off, anything else on) and applied over the
    /// configuration key it names ([`upstream_flags`]).
    UpstreamFlag,
    /// Nothing reads it: what it chose is no longer a setting.
    Ignored,
}

/// Launch env vars 1.6.0 retired. The ONLY place in the workspace that spells their names
/// (law: `dist/default/tests/retired_env_single_source.rs` and this file's tests).
pub(crate) struct Retired {
    pub name: &'static str,
    /// An empty BUSBAR_PROVIDERS selected nothing in 1.5.5, so it counts as unset.
    pub empty_is_unset: bool,
    pub carry: Carry,
    /// What the engine does with it, and what to write instead.
    pub line: &'static str,
}

pub(crate) const RETIRED_LAUNCH_ENV: [Retired; 5] = [
    Retired {
        name: "BUSBAR_PROVIDERS",
        empty_is_unset: true,
        carry: Carry::ProvidersPath,
        line: "read as the providers catalog path, as 1.5.5 read it, unless --providers names one; \
               set `providers_file:` in config.yaml (default: providers.yaml beside config.yaml) or \
               pass --providers, then remove it from the launcher",
    },
    Retired {
        name: "BUSBAR_WORKER_THREADS",
        empty_is_unset: false,
        carry: Carry::Ignored,
        line: "ignored: the engine runs one data worker per CPU core it may use (its CPU affinity \
               and container CPU limit); remove it from the launcher",
    },
    Retired {
        name: "TOKIO_WORKER_THREADS",
        empty_is_unset: false,
        carry: Carry::Ignored,
        line: "ignored: the engine runs one data worker per CPU core it may use (its CPU affinity \
               and container CPU limit); remove it from the launcher",
    },
    Retired {
        name: "BUSBAR_UPSTREAM_HTTP1_ONLY",
        empty_is_unset: false,
        carry: Carry::UpstreamFlag,
        line: "applied over `outbound.http1_only`, as 1.5.5 applied it; set that key in \
               config.yaml, then remove it from the launcher",
    },
    Retired {
        name: "BUSBAR_UPSTREAM_H2_PRIOR_KNOWLEDGE",
        empty_is_unset: false,
        carry: Carry::UpstreamFlag,
        line: "applied over `outbound.h2_prior_knowledge`, as 1.5.5 applied it; set that key in \
               config.yaml, then remove it from the launcher",
    },
];

fn set(r: &Retired, env: &impl Fn(&str) -> Option<OsString>) -> Option<OsString> {
    env(r.name).filter(|v| !(r.empty_is_unset && v.is_empty()))
}

/// One line for every set retired variable, naming what the engine does with it and never
/// echoing its value. Nothing here refuses a start.
pub(crate) fn check_launch_env(env: impl Fn(&str) -> Option<OsString>) -> Vec<String> {
    RETIRED_LAUNCH_ENV
        .iter()
        .filter(|r| set(r, &env).is_some())
        .map(|r| {
            format!(
                "{code}: {name} is set; busbar 1.6 {line}.",
                code = busbar_kernel::diagnostics::RETIRED_ENV_VAR_IGNORED.banner(),
                name = r.name,
                line = r.line
            )
        })
        .collect()
}

/// The providers catalog path a launcher's retired variable names, as 1.5.5 read it.
pub(crate) fn providers_path(env: impl Fn(&str) -> Option<OsString>) -> Option<String> {
    RETIRED_LAUNCH_ENV
        .iter()
        .find(|r| r.carry == Carry::ProvidersPath)
        .and_then(|r| set(r, &env))
        .map(|v| v.to_string_lossy().into_owned())
}

/// The upstream protocol flags with a launcher's retired variables applied over the configured
/// values, as 1.5.5 applied them (`0` or empty is off, anything else on): `(http1_only,
/// h2_prior_knowledge)`.
pub(crate) fn upstream_flags(
    configured: (bool, bool),
    env: impl Fn(&str) -> Option<OsString>,
) -> (bool, bool) {
    let mut flags = RETIRED_LAUNCH_ENV
        .iter()
        .filter(|r| r.carry == Carry::UpstreamFlag)
        .map(|r| env(r.name).map(|v| v != "0" && !v.is_empty()));
    let http1_only = flags.next().flatten().unwrap_or(configured.0);
    let h2_prior_knowledge = flags.next().flatten().unwrap_or(configured.1);
    (http1_only, h2_prior_knowledge)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env_of<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<OsString> + 'a {
        move |name| {
            pairs
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| OsString::from(value))
        }
    }

    /// The owner's rule: an old launcher is converted, never refused. Every retired variable set
    /// is said once, in table order, never echoing its value, and the start goes on.
    #[test]
    fn every_retired_launch_variable_is_said_once_and_never_refuses() {
        let banner = busbar_kernel::diagnostics::RETIRED_ENV_VAR_IGNORED.banner();
        let lines = check_launch_env(env_of(&[
            ("BUSBAR_UPSTREAM_H2_PRIOR_KNOWLEDGE", "1"),
            ("BUSBAR_UPSTREAM_HTTP1_ONLY", ""),
            ("BUSBAR_WORKER_THREADS", "4"),
            ("BUSBAR_PROVIDERS", "/old/providers.yaml"),
            ("TOKIO_WORKER_THREADS", "3"),
        ]));
        assert_eq!(lines.len(), RETIRED_LAUNCH_ENV.len(), "{lines:#?}");
        for (line, retired) in lines.iter().zip(&RETIRED_LAUNCH_ENV) {
            assert!(
                line.starts_with(&format!("{banner}: {} is set; ", retired.name)),
                "{line}"
            );
            assert!(line.contains(retired.line), "{line}");
            assert!(
                !line.contains("/old/providers.yaml"),
                "never echoes the value: {line}"
            );
        }
        assert!(check_launch_env(env_of(&[])).is_empty());
        assert!(
            check_launch_env(env_of(&[("BUSBAR_PROVIDERS", "")])).is_empty(),
            "an empty BUSBAR_PROVIDERS selected nothing"
        );
    }

    /// 1.5.5 read BUSBAR_PROVIDERS as the catalog path; an empty one selected nothing.
    #[test]
    fn the_providers_variable_is_the_catalog_path_as_1_5_5_read_it() {
        assert_eq!(
            providers_path(env_of(&[("BUSBAR_PROVIDERS", "/old/providers.yaml")])).as_deref(),
            Some("/old/providers.yaml")
        );
        assert_eq!(providers_path(env_of(&[("BUSBAR_PROVIDERS", "")])), None);
        assert_eq!(providers_path(env_of(&[])), None);
    }

    /// 1.5.5 applied the two upstream variables over the configuration: `0` or empty is off,
    /// anything else on; unset leaves the configured value.
    #[test]
    fn the_upstream_variables_apply_over_the_configuration_as_1_5_5_applied_them() {
        assert_eq!(upstream_flags((true, true), env_of(&[])), (true, true));
        assert_eq!(
            upstream_flags(
                (false, true),
                env_of(&[
                    ("BUSBAR_UPSTREAM_HTTP1_ONLY", "1"),
                    ("BUSBAR_UPSTREAM_H2_PRIOR_KNOWLEDGE", "0"),
                ])
            ),
            (true, false)
        );
        assert_eq!(
            upstream_flags(
                (true, false),
                env_of(&[
                    ("BUSBAR_UPSTREAM_HTTP1_ONLY", ""),
                    ("BUSBAR_UPSTREAM_H2_PRIOR_KNOWLEDGE", "yes"),
                ])
            ),
            (false, true)
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
        let source = include_str!("retired_env.rs");
        let production = &source[..source
            .find("\n#[cfg(test)]\nmod tests")
            .expect("this file has a test tail")];
        let literals = busbar_literals(production);
        let mut spelled: Vec<&str> = literals.iter().map(|(text, _)| text.as_str()).collect();
        spelled.sort();
        let mut table: Vec<&str> = RETIRED_LAUNCH_ENV
            .iter()
            .map(|r| r.name)
            .filter(|name| name.starts_with("BUSBAR_"))
            .collect();
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
