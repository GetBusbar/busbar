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
    "name",
    "doc",
    "code",
    "class",
    "slug",
    "title",
    "severity",
    "summary",
    "action",
    "since",
    "retired",
    "reexport",
    "text",
    "example",
    "example_detail",
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
    // Entries with a `text` template: (const name, code, text, example, example_detail).
    let mut texts: Vec<(String, u16, String, String, String)> = Vec::new();
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
        let opt = |k: &str| match get(k) {
            None => String::new(),
            Some(_) => s(k),
        };
        if get("text").is_some() {
            let text = s("text");
            assert!(
                !text.ends_with('.'),
                "{CATALOG}: {name}'s `text` ends with a period (the coded message adds `. See <link>`)"
            );
            texts.push((
                name.clone(),
                code,
                text,
                opt("example"),
                opt("example_detail"),
            ));
        } else {
            assert!(
                get("example").is_none() && get("example_detail").is_none(),
                "{CATALOG}: {name} has an example but no `text` template"
            );
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

    // The typed constructors: one per templated code, named for the const in lower case, taking
    // the template's placeholders in order of first appearance. `format!` over the literal template
    // makes the compiler check every placeholder against the arguments.
    out.push_str(
        "/// Typed constructors for the templated codes: `coded::<const name in lower case>(..)` \
         builds the code's operator message from its catalog `text`.\npub mod coded {\n",
    );
    for (name, _, text, _, _) in &texts {
        let args = placeholders(text);
        let params: Vec<String> = args
            .iter()
            .map(|a| format!("{a}: impl ::core::fmt::Display"))
            .collect();
        let named: Vec<String> = args.iter().map(|a| format!("{a} = {a}")).collect();
        let body = if args.is_empty() {
            // No placeholder: the template is the text itself (`{{`/`}}` are literal braces).
            format!("{:?}", text.replace("{{", "{").replace("}}", "}"))
        } else {
            format!("format!({text:?}, {})", named.join(", "))
        };
        writeln!(
            out,
            "/// [`super::{name}`]: `{}`.\n#[cold]\n#[must_use]\npub fn {}({}) -> \
             ::busbar_contract::diagnostic::Coded {{ super::{name}.coded({body}) }}",
            text.replace('`', "'"),
            name.to_lowercase(),
            params.join(", "),
        )
        .unwrap();
    }
    out.push_str("}\n");
    out.push_str(
        "/// The page text of every templated host code, in `catalog.toml`'s order.\n\
         pub static TEXTS: &[::busbar_contract::diagnostic::ErrorText] = &[",
    );
    for (_, code, text, example, detail) in &texts {
        write!(
            out,
            "::busbar_contract::diagnostic::ErrorText {{ code: {code}, text: {text:?}, \
             example: {example:?}, example_detail: {detail:?} }},"
        )
        .unwrap();
    }
    out.push_str("];\n");

    let dest = PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR"));
    std::fs::write(dest.join("diagnostics_catalog.rs"), out).expect("write the catalog");
}

fn basic_string(raw: &str) -> Option<String> {
    let inner = raw.strip_prefix('"')?.strip_suffix('"')?;
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => match chars.next()? {
                '"' => out.push('"'),
                '\\' => out.push('\\'),
                'n' => out.push('\n'),
                _ => return None,
            },
            '"' => return None,
            c => out.push(c),
        }
    }
    Some(out)
}

/// The `{name}` placeholders of a template, in order of first appearance (`{{`/`}}` are literal
/// braces). A placeholder must be a plain identifier: no format spec, no position.
fn placeholders(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '{' if chars.peek() == Some(&'{') => {
                chars.next();
            }
            '}' if chars.peek() == Some(&'}') => {
                chars.next();
            }
            '{' => {
                let mut name = String::new();
                for c in chars.by_ref() {
                    if c == '}' {
                        break;
                    }
                    name.push(c);
                }
                assert!(
                    !name.is_empty()
                        && name
                            .chars()
                            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                    "{CATALOG}: template placeholder `{{{name}}}` is not a plain snake_case name"
                );
                if !out.contains(&name) {
                    out.push(name);
                }
            }
            _ => {}
        }
    }
    out
}
