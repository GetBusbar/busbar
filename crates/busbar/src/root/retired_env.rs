// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The launch variables 1.6.0 retired (BUSBAR-3029). Serving never reads them; the boot and `--validate` only
//! report, through [`ignored_launch_env`], that a set one is ignored, before the config load that can refuse.
use std::ffi::OsString;

/// Launch env vars 1.6.0 no longer reads. The ONLY place in the workspace that spells their names
/// (law: `dist/default/tests/retired_env_single_source.rs` and this file's tests); `ignored_launch_env()`
/// reports them.
pub(crate) struct Retired {
    pub name: &'static str,
    /// An empty BUSBAR_PROVIDERS selected nothing in 1.5.5, so it counts as unset.
    pub empty_is_unset: bool,
    pub use_instead: &'static str,
}

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

/// One stderr line per retired variable that is set (an empty `BUSBAR_PROVIDERS` is unset).
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
            "an empty BUSBAR_PROVIDERS selected nothing"
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
        let source = include_str!("retired_env.rs");
        let production = &source[..source
            .find("\n#[cfg(test)]\nmod tests")
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
