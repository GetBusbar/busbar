// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `openapi-diff --base <old openapi.json> --head <new openapi.json> [--advisory]`: the additive-only
//! gate for the admin OpenAPI document (#309). The v1 admin surface is frozen additive-only
//! (ADMIN-API-1.6 r5 section 0.1) and the Console pins its spec to the 1.6.0 tag, so a change that
//! removes or narrows what the base promised fails.
//!
//! Exit 0: the head is additive only. Exit 1: a breaking change; each finding is one stdout line.
//! Exit 3: a breaking change under `--advisory` (the non-blocking pre-tag mode). Exit 2: usage or a
//! file that cannot be read or parsed (the message is on stderr).

#![forbid(unsafe_code)]

use std::process::ExitCode;

use busbar_contract::json;

mod diff;

#[cfg(test)]
mod cli_tests;
#[cfg(test)]
mod diff_tests;

/// The command line's three words.
struct Options {
    base: String,
    head: String,
    advisory: bool,
}

fn parse(args: &[String]) -> Result<Options, String> {
    let (mut base, mut head, mut advisory) = (None, None, false);
    let mut words = args.iter();
    while let Some(word) = words.next() {
        match word.as_str() {
            "--advisory" => advisory = true,
            "--base" => base = Some(words.next().ok_or("--base needs a path")?.clone()),
            "--head" => head = Some(words.next().ok_or("--head needs a path")?.clone()),
            other => return Err(format!("unknown argument `{other}`")),
        }
    }
    Ok(Options {
        base: base.ok_or("--base <old openapi.json> is required")?,
        head: head.ok_or("--head <new openapi.json> is required")?,
        advisory,
    })
}

fn read(path: &str) -> Result<json::Value, String> {
    let bytes = std::fs::read(path).map_err(|error| format!("{path}: {error}"))?;
    json::parse_value(&bytes).map_err(|error| format!("{path}: {error}"))
}

/// The exit code and the stdout lines (or, for code 2, the one stderr message).
pub(crate) fn run(args: &[String]) -> (u8, Vec<String>) {
    let options = match parse(args) {
        Ok(options) => options,
        Err(message) => {
            return (
                2,
                vec![format!(
                    "{message}\nusage: openapi-diff --base <old> --head <new> [--advisory]"
                )],
            )
        }
    };
    let (base, head) = match (read(&options.base), read(&options.head)) {
        (Ok(base), Ok(head)) => (base, head),
        (Err(message), _) | (_, Err(message)) => return (2, vec![message]),
    };
    let findings = diff::breaking_changes(&base, &head);
    let code = match (findings.is_empty(), options.advisory) {
        (true, _) => 0,
        (false, false) => 1,
        (false, true) => 3,
    };
    (code, findings)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (code, lines) = run(&args);
    for line in lines {
        if code == 2 {
            eprintln!("{line}");
        } else {
            println!("{line}");
        }
    }
    ExitCode::from(code)
}
