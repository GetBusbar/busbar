// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Source law (UPG-A30c, LINT-RULES `restart-scoped-needs-durable-store`): an admin mutation that
//! works out restart-only entries and writes the config overlay must prove the restart can read
//! the change, by calling `admit_restart_scoped(` in the same body. Until a custom lint exists,
//! this scan is the enforcement.

use std::path::{Path, PathBuf};

const RESTART_HELPERS: &[&str] = &[
    "reload_to_apply_fields",
    "restart_paths",
    "planes_awaiting_restart_added",
    "paths_awaiting_restart",
    "requires_restart",
];
const OVERLAY_WRITERS: &[&str] = &[
    "persist_root_async",
    "overlay::write_async",
    "persist_named_map_async",
];
const GATE: &str = "admit_restart_scoped";

/// Blank out comments, string literals and char literals (keeping byte offsets and newlines),
/// so braces and names inside them never count as code.
fn code_only(text: &str) -> Vec<u8> {
    let src = text.as_bytes();
    let mut out = src.to_vec();
    let blank = |out: &mut Vec<u8>, from: usize, to: usize| {
        for byte in &mut out[from..to] {
            if *byte != b'\n' {
                *byte = b' ';
            }
        }
    };
    let mut i = 0;
    while i < src.len() {
        let c = src[i];
        let next = src.get(i + 1).copied();
        if c == b'/' && next == Some(b'/') {
            let end = src[i..]
                .iter()
                .position(|&b| b == b'\n')
                .map_or(src.len(), |n| i + n);
            blank(&mut out, i, end);
            i = end;
        } else if c == b'/' && next == Some(b'*') {
            let mut depth = 0usize;
            let mut j = i;
            while j < src.len() {
                if src[j] == b'/' && src.get(j + 1) == Some(&b'*') {
                    depth += 1;
                    j += 2;
                } else if src[j] == b'*' && src.get(j + 1) == Some(&b'/') {
                    depth -= 1;
                    j += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    j += 1;
                }
            }
            blank(&mut out, i, j);
            i = j;
        } else if c == b'r'
            && (next == Some(b'"') || next == Some(b'#'))
            && (i == 0
                || !is_ident(src[i - 1])
                || (src[i - 1] == b'b' && (i < 2 || !is_ident(src[i - 2]))))
        {
            let mut j = i + 1;
            let mut hashes = 0;
            while src.get(j) == Some(&b'#') {
                hashes += 1;
                j += 1;
            }
            if src.get(j) != Some(&b'"') {
                i += 1;
                continue;
            }
            j += 1;
            let close: Vec<u8> = std::iter::once(b'"')
                .chain(std::iter::repeat_n(b'#', hashes))
                .collect();
            let end = src[j..]
                .windows(close.len())
                .position(|w| w == close.as_slice())
                .map_or(src.len(), |n| j + n + close.len());
            blank(&mut out, i, end);
            i = end;
        } else if c == b'"' {
            let mut j = i + 1;
            while j < src.len() && src[j] != b'"' {
                if src[j] == b'\\' {
                    j += 1;
                }
                j += 1;
            }
            let end = (j + 1).min(src.len());
            blank(&mut out, i, end);
            i = end;
        } else if c == b'\'' {
            // A char literal ('x', '\n', '\u{..}', '{'); otherwise a lifetime, left alone.
            if next == Some(b'\\') {
                // Skip the escaped character itself, so `'\''` closes at its last quote.
                let end = src
                    .get(i + 3..)
                    .unwrap_or_default()
                    .iter()
                    .position(|&b| b == b'\'')
                    .map_or(src.len(), |n| i + 3 + n + 1);
                blank(&mut out, i, end);
                i = end;
            } else if let Some(len) = std::str::from_utf8(&src[i + 1..])
                .ok()
                .and_then(|rest| rest.chars().next())
                .map(char::len_utf8)
                .filter(|len| src.get(i + 1 + len) == Some(&b'\''))
            {
                blank(&mut out, i, i + len + 2);
                i += len + 2;
            } else {
                i += 1;
            }
        } else {
            i += 1;
        }
    }
    out
}

fn is_ident(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// Every `fn` with a body in `text`: its name and its body (code only, braces included).
fn fn_bodies(text: &str) -> Vec<(String, String)> {
    let code = code_only(text);
    let mut found = Vec::new();
    let mut i = 0;
    while let Some(at) = code[i..].windows(3).position(|w| w == b"fn ") {
        let start = i + at;
        i = start + 3;
        if start > 0 && is_ident(code[start - 1]) {
            continue;
        }
        let name_start = i;
        let mut name_end = name_start;
        while name_end < code.len() && is_ident(code[name_end]) {
            name_end += 1;
        }
        if name_end == name_start {
            continue;
        }
        let name = String::from_utf8_lossy(&code[name_start..name_end]).into_owned();
        let mut parens = 0i32;
        let mut j = name_end;
        let mut open = None;
        while j < code.len() {
            match code[j] {
                b'(' | b'[' => parens += 1,
                b')' | b']' => parens -= 1,
                b';' if parens == 0 => break,
                b'{' if parens == 0 => {
                    open = Some(j);
                    break;
                }
                _ => {}
            }
            j += 1;
        }
        let Some(open) = open else { continue };
        let mut depth = 0usize;
        let mut close = open;
        for (k, &byte) in code.iter().enumerate().skip(open) {
            match byte {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        close = k;
                        break;
                    }
                }
                _ => {}
            }
        }
        found.push((
            name,
            String::from_utf8_lossy(&code[open..=close]).into_owned(),
        ));
    }
    found
}

/// `body` calls `name(` (as a free function, path segment or method), not a longer identifier.
fn calls(body: &str, name: &str) -> bool {
    let needle = format!("{name}(");
    body.match_indices(&needle)
        .any(|(at, _)| at == 0 || !is_ident(body.as_bytes()[at - 1]))
}

fn calls_any(body: &str, names: &[&str]) -> bool {
    names.iter().any(|name| calls(body, name))
}

/// The bodies that compute restart-only entries and write the overlay, and whether each gates.
fn restart_scoped_writers(file: &str, text: &str) -> Vec<(String, String, bool)> {
    fn_bodies(text)
        .into_iter()
        .filter(|(_, body)| calls_any(body, RESTART_HELPERS) && calls_any(body, OVERLAY_WRITERS))
        .map(|(name, body)| (file.to_owned(), name, calls(&body, GATE)))
        .collect()
}

fn sources(dir: &Path, root: &Path, out: &mut Vec<(String, String)>) {
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
        .map(|entry| entry.expect("directory entry").path())
        .collect();
    entries.sort();
    for path in entries {
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if path.is_dir() {
            if name != "tests" {
                sources(&path, root, out);
            }
        } else if name.ends_with(".rs") && !name.ends_with("tests.rs") {
            let relative = path
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            let text = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
            out.push((relative, text));
        }
    }
}

fn all_sources() -> Vec<(String, String)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut out = Vec::new();
    sources(&root, &root, &mut out);
    out
}

fn body_of<'a>(bodies: &'a [(String, String)], name: &str) -> &'a str {
    let matching: Vec<&str> = bodies
        .iter()
        .filter(|(n, _)| n == name)
        .map(|(_, body)| body.as_str())
        .collect();
    assert_eq!(matching.len(), 1, "exactly one `fn {name}`");
    matching[0]
}

#[test]
fn restart_scoped_mutations_admit_durability() {
    let sources = all_sources();
    let writers: Vec<(String, String, bool)> = sources
        .iter()
        .flat_map(|(file, text)| restart_scoped_writers(file, text))
        .collect();

    let ungated: Vec<String> = writers
        .iter()
        .filter(|(_, _, gated)| !gated)
        .map(|(file, name, _)| format!("{file}::{name}"))
        .collect();
    assert!(
        ungated.is_empty(),
        "these bodies compute restart-only entries and write the config overlay without \
         `admit_restart_scoped(`; on an in-memory Store the restart would discard the change: \
         {ungated:?}"
    );

    // Non-vacuity: exactly the three persisting admin bodies match.
    let mut found: Vec<(String, String)> = writers
        .iter()
        .map(|(file, name, _)| (file.clone(), name.clone()))
        .collect();
    found.sort();
    assert_eq!(
        found,
        vec![
            ("v1/json/config_document.rs".to_owned(), "apply".to_owned()),
            (
                "v1/json/handlers.rs".to_owned(),
                "put_config_settings".to_owned()
            ),
            ("v1/json/named_map.rs".to_owned(), "apply".to_owned()),
        ],
        "the restart-scoped overlay writers changed; gate any new one and list it here"
    );

    // Plane row: every gated body composes the door-plane delta into its own contribution.
    for (file, name) in &found {
        let text = &sources.iter().find(|(f, _)| f == file).unwrap().1;
        let bodies = fn_bodies(text);
        let body = body_of(&bodies, name);
        assert!(
            calls(body, "planes_awaiting_restart_added") && calls(body, "build_app_from_config"),
            "{file}::{name} builds the next App and must count the planes it leaves awaiting a \
             restart"
        );
    }

    // Wrapper row: no named-map verb persists on its own; each goes through the gated `apply`.
    let named_map = &sources
        .iter()
        .find(|(f, _)| f == "v1/json/named_map.rs")
        .unwrap()
        .1;
    let bodies = fn_bodies(named_map);
    for verb in ["put", "patch_settings", "delete"] {
        let body = body_of(&bodies, verb);
        assert!(calls(body, "apply"), "named_map::{verb} goes through apply");
        assert!(
            !calls_any(body, OVERLAY_WRITERS),
            "named_map::{verb} must not write the overlay itself"
        );
    }
}

#[test]
fn restart_scoped_law_reports_a_planted_ungated_writer() {
    let planted = r#"
        // admit_restart_scoped( in a comment does not count
        async fn planted(handle: Handle) -> Response {
            let note = "admit_restart_scoped(";
            let brace = '{';
            if requires_restart(&name, def) {
                busbar_kernel::config::overlay::persist_named_map_async(None, s, &name, None).await;
            }
            done()
        }
        fn gated() {
            if requires_restart(&name, def) {
                busbar_kernel::config::overlay::admit_restart_scoped(&store, &own)?;
                persist_named_map_async(None, s, &name, None);
            }
        }
        fn reader() { let _ = requires_restart(&name, def); }
    "#;
    let found = restart_scoped_writers("planted.rs", planted);
    assert_eq!(
        found,
        vec![
            ("planted.rs".to_owned(), "planted".to_owned(), false),
            ("planted.rs".to_owned(), "gated".to_owned(), true),
        ]
    );
}
