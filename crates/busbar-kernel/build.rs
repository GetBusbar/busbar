// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//
// THE DIAGNOSTICS CATALOG, rendered from its data. `src/diagnostics/catalog.toml` holds every host
// diagnostic; this writes `$OUT_DIR/diagnostics_catalog.rs`, one `pub const <name>: Diagnostic` per
// entry and `REGISTRY` in the file's order, which `src/diagnostics/mod.rs` includes. The file is a
// TOML subset (see its header) read here without a parser dependency; anything outside the subset
// fails the build, naming the line.

use std::fmt::Write as _;
use std::path::PathBuf;

const CATALOG: &str = "src/diagnostics/catalog.toml";
const KEYS: &[&str] = &[
    "name", "doc", "code", "class", "slug", "title", "severity", "summary", "action", "since",
    "retired", "reexport",
];

enum Value {
    Str(String),
    Int(u16),
    Bool(bool),
}

fn main() {
    println!("cargo:rerun-if-changed={CATALOG}");
    let text = std::fs::read_to_string(CATALOG).expect("read the diagnostics catalog");
    let mut entries: Vec<Vec<(String, Value)>> = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let at = || format!("{CATALOG}:{}", n + 1);
        let line = line.trim_end();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line == "[[diagnostic]]" {
            entries.push(Vec::new());
            continue;
        }
        let (key, raw) = line
            .split_once(" = ")
            .unwrap_or_else(|| panic!("{}: not `key = value`", at()));
        assert!(KEYS.contains(&key), "{}: unknown key `{key}`", at());
        let entry = entries
            .last_mut()
            .unwrap_or_else(|| panic!("{}: a key before the first [[diagnostic]]", at()));
        assert!(
            entry.iter().all(|(k, _)| k != key),
            "{}: `{key}` twice",
            at()
        );
        let value = match raw {
            "true" => Value::Bool(true),
            "false" => Value::Bool(false),
            _ if raw.starts_with('"') => Value::Str(
                basic_string(raw)
                    .unwrap_or_else(|| panic!("{}: not a one-line TOML basic string", at())),
            ),
            _ => Value::Int(
                raw.parse()
                    .unwrap_or_else(|_| panic!("{}: not a u16", at())),
            ),
        };
        entry.push((key.to_string(), value));
    }

    let mut out = String::new();
    let mut names = Vec::new();
    for entry in &entries {
        let get = |k: &str| entry.iter().find(|(key, _)| key == k).map(|(_, v)| v);
        let s = |k: &str| match get(k) {
            Some(Value::Str(s)) => s.clone(),
            _ => panic!("{CATALOG}: an entry has no string `{k}`"),
        };
        let name = s("name");
        if let Some(Value::Str(path)) = get("reexport") {
            assert_eq!(
                entry.len(),
                2,
                "{CATALOG}: {name} re-exports, so it states nothing else"
            );
            writeln!(out, "pub use {path}::{name};").unwrap();
            names.push(name);
            continue;
        }
        let code = match get("code") {
            Some(Value::Int(c)) => *c,
            _ => panic!("{CATALOG}: {name} has no integer `code`"),
        };
        let retired = match get("retired") {
            None => false,
            Some(Value::Bool(b)) => *b,
            _ => panic!("{CATALOG}: {name}'s `retired` is not a bool"),
        };
        let since = match get("since") {
            None => "1.6.0".to_string(),
            Some(_) => s("since"),
        };
        if get("doc").is_some() {
            writeln!(out, "#[doc = {:?}]", s("doc")).unwrap();
        }
        writeln!(
            out,
            "pub const {name}: Diagnostic = Diagnostic {{ code: {code}, class: Class::{}, slug: {:?}, \
             title: {:?}, severity: Severity::{}, summary: {:?}, action: {:?}, since: {since:?}, \
             retired: {retired} }};",
            s("class"),
            s("slug"),
            s("title"),
            s("severity"),
            s("summary"),
            s("action"),
        )
        .unwrap();
        names.push(name);
    }
    out.push_str(
        "/// The host's built-in diagnostics, in `catalog.toml`'s order. Plane-contributed ones are \
         not here: the composition root folds them into the [`Catalogue`] it lends, and the full \
         runtime catalog is [`Catalogue::all`].\npub static REGISTRY: &[&Diagnostic] = &[",
    );
    for name in &names {
        write!(out, "&{name},").unwrap();
    }
    out.push_str("];\n");

    let dest = PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR"));
    std::fs::write(dest.join("diagnostics_catalog.rs"), out).expect("write the catalog");
}

/// A one-line TOML basic string's value: `"…"` with `\"` and `\\` its only escapes.
fn basic_string(raw: &str) -> Option<String> {
    let inner = raw.strip_prefix('"')?.strip_suffix('"')?;
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => match chars.next()? {
                '"' => out.push('"'),
                '\\' => out.push('\\'),
                _ => return None,
            },
            '"' => return None,
            c => out.push(c),
        }
    }
    Some(out)
}
