// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **NO TEST IN THIS CRATE PASSES BY SKIPPING ITS SUBJECT** (BUSBAR-1.6.0.md: between a false RED
//! and a false GREEN, a gate takes the false RED; an instrument that cannot produce a NO is not a
//! check). A both-ways proof whose fixture is absent fails, naming the command that builds it
//! (`both_ways::missing`); it never prints `skip:` and returns.
//!
//! The scanner reads every `.rs` file under `src/tests/` and `tests/` at test time and lists
//! `file:line` for each:
//!
//! * (a) a string literal starting `"skip:"` or `"SKIP"` handed to `eprintln!`/`println!`;
//! * (b) `var_os("CI")` or `var("CI")`: a probe that asserts only under CI skips everywhere else;
//! * (c) a `let Some(..) = <probe> else { .. }`, or an `if <probe>.is_none() { .. }`, whose body is
//!   only comments, prints and `return;`, where the probe calls a function whose name contains
//!   `cdylib`, `dropped`, `doors`, `both`, `rows`, `example`, `json_lane_plugin_path` or `adapter_`.
//!
//! The patterns are matched across lines by hand (this crate takes no `regex` dev-dependency): a
//! guard's call and body may span any number of lines.
//!
//! RED: on origin/predev (2a2dadc1e9) the scan fails, listing the sites of status row 114's
//! plugin-loader sweep — every `skip:` print, every `var_os("CI")` probe, and every let-else and
//! `is_none()` early return in the Evidence table.

use std::path::{Path, PathBuf};

/// This file: it names every pattern it hunts.
const SELF: &str = "no_silent_skip_tests.rs";

/// The fragments a fixture probe's name carries (rule (c)).
const PROBES: &[&str] = &[
    "cdylib",
    "dropped",
    "doors",
    "both",
    "rows",
    "example",
    "json_lane_plugin_path",
    "adapter_",
];

/// Every `.rs` file under `dir`, recursively, in a stable order.
fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("the scanner cannot read {}: {e}", dir.display()));
    let mut paths: Vec<PathBuf> = entries.filter_map(|e| e.ok().map(|e| e.path())).collect();
    paths.sort();
    for p in paths {
        if p.is_dir() {
            rust_files(&p, out);
        } else if p.extension().is_some_and(|e| e == "rs") {
            out.push(p);
        }
    }
}

/// The 1-based line of byte `at` in `src`.
fn line_of(src: &str, at: usize) -> usize {
    src[..at].bytes().filter(|&b| b == b'\n').count() + 1
}

/// The index just past a literal opening at `at` (`"…"`, `r#"…"#`, or a char such as `'"'`, `'{'`
/// or `'\''`), or `None` when none opens there.
fn past_literal(b: &[u8], at: usize) -> Option<usize> {
    if b[at] == b'\'' {
        return match (b.get(at + 1), b.get(at + 2), b.get(at + 3)) {
            (Some(b'\\'), Some(_), Some(b'\'')) => Some(at + 4),
            (Some(_), Some(b'\''), _) => Some(at + 3),
            _ => None,
        };
    }
    if b[at] == b'"' {
        let mut i = at + 1;
        while i < b.len() {
            match b[i] {
                b'\\' => i += 2,
                b'"' => return Some(i + 1),
                _ => i += 1,
            }
        }
        return Some(b.len());
    }
    if b[at] == b'r' && (at == 0 || !(b[at - 1].is_ascii_alphanumeric() || b[at - 1] == b'_')) {
        let hashes = b[at + 1..].iter().take_while(|&&c| c == b'#').count();
        if b.get(at + 1 + hashes) == Some(&b'"') {
            let close: Vec<u8> = std::iter::once(b'"')
                .chain(std::iter::repeat_n(b'#', hashes))
                .collect();
            let body = at + 2 + hashes;
            return Some(
                b[body..]
                    .windows(close.len())
                    .position(|w| w == close.as_slice())
                    .map_or(b.len(), |p| body + p + close.len()),
            );
        }
    }
    None
}

/// The index of the bracket closing the one `open` (`(` or `{`) at `at`, skipping string literals
/// and line comments.
fn closing(src: &str, at: usize) -> Option<usize> {
    let b = src.as_bytes();
    let (open, close) = (b[at], if b[at] == b'(' { b')' } else { b'}' });
    let (mut depth, mut i) = (0usize, at);
    while i < b.len() {
        if let Some(next) = past_literal(b, i) {
            i = next;
            continue;
        }
        if b[i..].starts_with(b"//") {
            i += b[i..]
                .iter()
                .position(|&c| c == b'\n')
                .unwrap_or(b.len() - i);
            continue;
        }
        if b[i] == open {
            depth += 1;
        } else if b[i] == close {
            depth -= 1;
            if depth == 0 {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

/// Every name in `call` that is called (`name(` or `name::<..>(`).
fn called(call: &str) -> Vec<&str> {
    let b = call.as_bytes();
    let mut names = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i].is_ascii_alphabetic() || b[i] == b'_' {
            let start = i;
            while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_') {
                i += 1;
            }
            let rest = call[i..].trim_start();
            if rest.starts_with('(') || rest.starts_with("::<") {
                names.push(&call[start..i]);
            }
        } else {
            i += 1;
        }
    }
    names
}

/// Whether `call` calls a fixture probe.
fn calls_a_probe(call: &str) -> bool {
    called(call)
        .iter()
        .any(|name| PROBES.iter().any(|p| name.contains(p)))
}

/// Whether the block body `body` (between its braces) is only comments, prints and `return;`, and
/// returns.
fn only_skips(body: &str) -> bool {
    let mut rest = body;
    let mut returned = false;
    loop {
        rest = rest.trim_start();
        if rest.is_empty() {
            return returned;
        }
        if returned {
            return false;
        }
        if rest.starts_with("//") {
            rest = rest.find('\n').map_or("", |n| &rest[n..]);
        } else if let Some(args) = ["eprintln!", "println!"]
            .iter()
            .find_map(|m| rest.strip_prefix(*m))
            .map(str::trim_start)
            .filter(|a| a.starts_with('('))
        {
            let Some(end) = closing(args, 0) else {
                return false;
            };
            rest = args[end + 1..].trim_start();
            rest = rest.strip_prefix(';').unwrap_or(rest);
        } else if let Some(after) = rest.strip_prefix("return") {
            let after = after.trim_start();
            rest = after.strip_prefix(';').unwrap_or(after);
            returned = true;
        } else {
            return false;
        }
    }
}

/// Every keyword `word` in `src` at a word boundary, by byte index.
fn words<'a>(src: &'a str, word: &'a str) -> impl Iterator<Item = usize> + 'a {
    let b = src.as_bytes();
    src.match_indices(word)
        .map(|(at, _)| at)
        .filter(move |&at| {
            let before = at.checked_sub(1).map(|i| b[i]);
            let after = b.get(at + word.len());
            !before.is_some_and(|c| c.is_ascii_alphanumeric() || c == b'_')
                && !after.is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'_')
        })
}

/// The block opening at the first `{` at or after `at`, as `(open, close)` indices.
fn block_from(src: &str, at: usize) -> Option<(usize, usize)> {
    let open = at + src[at..].find('{')?;
    Some((open, closing(src, open)?))
}

/// Every hit in `src`, as `(line, what)`.
fn hits(src: &str) -> Vec<(usize, &'static str)> {
    let mut out = Vec::new();
    // (a) a `skip:` / `SKIP` line printed.
    for (at, _) in src.match_indices("println!") {
        let args = src[at + "println!".len()..].trim_start();
        let Some(args) = args.strip_prefix('(') else {
            continue;
        };
        let lit = args.trim_start();
        if lit.starts_with("\"skip:") || lit.starts_with("\"SKIP") {
            out.push((line_of(src, at), "prints a skip"));
        }
    }
    // (b) a CI-only probe.
    for var in ["var_os", "var"] {
        for at in words(src, var) {
            let rest = src[at + var.len()..].trim_start();
            let Some(arg) = rest.strip_prefix('(') else {
                continue;
            };
            let arg = arg.trim_start();
            if arg
                .strip_prefix("\"CI\"")
                .is_some_and(|r| r.trim_start().starts_with(')'))
            {
                out.push((line_of(src, at), "reads the CI variable"));
            }
        }
    }
    // (c) a let-else that returns when the probe answers `None`.
    for at in src.match_indices("let Some(").map(|(at, _)| at) {
        let head_end = at + src[at..].find(';').unwrap_or(src.len() - at);
        let head = &src[at..head_end];
        let Some(else_at) =
            words(head, "else").find(|&e| head[e + "else".len()..].trim_start().starts_with('{'))
        else {
            continue;
        };
        let Some(eq) = head.find('=') else { continue };
        let call = &head[eq + 1..else_at];
        let Some((open, close)) = block_from(src, at + else_at) else {
            continue;
        };
        if calls_a_probe(call) && only_skips(&src[open + 1..close]) {
            out.push((line_of(src, at), "let-else returns on an absent fixture"));
        }
    }
    // (c) an `if <probe>.is_none()` that returns.
    for at in words(src, "if") {
        let Some((open, close)) = block_from(src, at) else {
            continue;
        };
        let cond = src[at + "if".len()..open].trim();
        let Some(call) = cond.strip_suffix(".is_none()") else {
            continue;
        };
        if calls_a_probe(call) && only_skips(&src[open + 1..close]) {
            out.push((line_of(src, at), "is_none() returns on an absent fixture"));
        }
    }
    out.sort_unstable();
    out
}

/// **THE SCAN.** No test source in this crate skips its subject when the fixture is absent.
#[test]
fn no_test_in_this_crate_returns_early_when_its_fixture_is_absent() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    rust_files(&root.join("src").join("tests"), &mut files);
    rust_files(&root.join("tests"), &mut files);
    assert!(
        files.len() > 20,
        "the scanner found {} files: it is not reading the test tree",
        files.len()
    );
    let mut found = Vec::new();
    for path in files
        .iter()
        .filter(|p| p.file_name().is_none_or(|f| f != SELF))
    {
        let src = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let shown = path
            .strip_prefix(root)
            .unwrap_or(path)
            .display()
            .to_string();
        for (line, what) in hits(&src) {
            found.push(format!("{shown}:{line}: {what}"));
        }
    }
    assert!(
        found.is_empty(),
        "{} silent skip(s): a missing fixture must fail, naming its build command \
         (`both_ways::missing`), never print and return:\n{}",
        found.len(),
        found.join("\n")
    );
}

/// RED, KEPT: the scanner says NO to each shape it hunts, across lines, and YES to the shapes that
/// replace them — an instrument that cannot produce a NO is not a check.
#[test]
fn the_scanner_finds_each_skip_shape_and_passes_its_replacement() {
    let skipping = r#"
fn a() {
    let Some(doors) = both(
        manifest(name),
        DOOR,
    ) else {
        // not built here
        eprintln!("skip: the sink's cdylib is not built");
        return;
    };
}
fn b() {
    if dropped_path().is_none() {
        return;
    }
}
fn c() -> Option<PathBuf> {
    assert!(found.is_some() || std::env::var_os("CI").is_none(), "x");
    let ci = std::env::var( "CI" );
    println!(
        "SKIP: nothing"
    );
}
fn d() {
    let Some(adapter) = adapter_over_published_schema() else {
        return;
    };
}
"#;
    let found: Vec<_> = hits(skipping).into_iter().map(|(l, _)| l).collect();
    assert_eq!(
        found,
        vec![3, 8, 13, 18, 19, 20, 25],
        "{:?}",
        hits(skipping)
    );

    let failing = r#"
fn a() {
    let doors = both(manifest(name), DOOR);
    let path = example_cdylib("x");
    let Some(p) = registry.resolve(name) else {
        return format!("no row for '{name}'");
    };
    let Ok(origin) = std::env::var("BUSBAR_M1_PANIC_CHILD") else {
        return;
    };
    let Some(path) = std::env::var_os(FOREIGN_PANIC_LIB) else {
        return;
    };
    if reg.resolve("gamma").is_none() {
        return;
    }
    eprintln!("the {name} cdylib is not built");
    assert!(status.starts_with("SKIPPED:"));
}
"#;
    assert_eq!(hits(failing), Vec::new());
}

/// RED, KEPT: the absence panic names the artifact and the command that builds it.
#[test]
#[should_panic(
    expected = "the busbar_no_such_plugin cdylib is not built: run `cargo test -p busbar-plugin-loader --no-run` first (a both-ways proof never skips)"
)]
fn an_absent_pinned_cdylib_names_its_build_command() {
    crate::both_ways::cdylib("busbar_no_such_plugin");
}
