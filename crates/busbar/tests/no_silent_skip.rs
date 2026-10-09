// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! NO TEST IN THIS CRATE PASSES BY SKIPPING (status row 114, the root crate's share).
//!
//! `libtest` has no "skipped" outcome: a test that returns early because its subject is absent
//! reports the same "ok" as one that asserted everything it claims to, and a run of them reads
//! green in 0.01s having proved nothing. An instrument that cannot produce a NO is not a check
//! (`BUSBAR-1.6.0.md`, Law 0). So in this crate a fixture that is not built is a hard failure that
//! names the command that builds it (`common::plugins::missing`), and a subject the build may not
//! link is a `#[cfg]` on the test (a cargo feature, or a build-script cfg that names the subject),
//! with the test asserting its subject inside.
//!
//! This scan keeps it that way. Over every `.rs` under `src/root/tests/` and `tests/` (this file
//! aside), comments stripped by the crate's one source classifier (`common::classify`), it fails,
//! naming `file:line`, on:
//!
//! - (a) an `eprintln!`/`println!` whose literal starts `"skip:"` or `"SKIP"`;
//! - (b) `var_os("CI")` / `var("CI")`: a fixture that is a failure only under CI is a skip
//!   everywhere else;
//! - (c) `record_skip(`;
//! - (d) a let-else, or an `if` guard, whose else/body is only prints and `return;`, guarding a
//!   call whose name contains one of [`PROBES`], or a `cfg!(feature` (or a plain `let` binding of
//!   such a call's answer: `let decls = installed_decls(); if decls.is_empty() { return; }`).
//!
//! When it must choose, it false-fails (`BUSBAR-1.6.0.md` l.1929): a probe name is matched as a
//! substring of the guard's condition.

mod common;

use std::path::{Path, PathBuf};

/// The probe names a skip guard has been seen to test: a fixture's `cdylib`, a dropped-in door, a
/// governed or bound composition, the auth plugin's install, a store adapter, a linkage probe, and
/// `cfg!(feature` read at run time.
const PROBES: &[&str] = &[
    "cdylib",
    "dropped",
    "governed",
    "bound(",
    "install_auth_plugin",
    "adapter_",
    "otlp_linked",
    "linked_sinks",
    "installed_decls",
    "LINKED_TRANSPORTS",
    "cfg!(feature",
];

/// This scan's own file: it spells every pattern it refuses.
const ME: &str = "no_silent_skip.rs";

/// Every `.rs` file under `dir`, this file aside, in path order.
fn rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let mut paths: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("the scan reads {}: {e}", dir.display()))
        .flatten()
        .map(|e| e.path())
        .collect();
    paths.sort();
    for path in paths {
        if path.is_dir() {
            rs_files(&path, out);
        } else if path.extension().is_some_and(|x| x == "rs")
            && path.file_name().is_some_and(|n| n != ME)
        {
            out.push(path);
        }
    }
}

/// A file's classified lines joined into one text, `blank` (literal contents blanked) or `code`
/// (literals intact), and the line each char sits on.
fn joined(lines: &[common::Line], blank: bool) -> (Vec<char>, Vec<usize>) {
    let mut text = Vec::new();
    let mut at = Vec::new();
    for l in lines {
        let s = if blank { &l.blank } else { &l.code };
        for c in s.chars().chain(std::iter::once('\n')) {
            text.push(c);
            at.push(l.no);
        }
    }
    (text, at)
}

fn starts(text: &[char], i: usize, pat: &str) -> bool {
    pat.chars()
        .enumerate()
        .all(|(n, p)| text.get(i + n) == Some(&p))
}

fn is_ident(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// `word` at `i`, not part of a longer identifier.
fn word_at(text: &[char], i: usize, word: &str) -> bool {
    starts(text, i, word)
        && (i == 0 || !is_ident(text[i - 1]))
        && !text
            .get(i + word.chars().count())
            .is_some_and(|c| is_ident(*c))
}

/// The index of the bracket closing the one opened at `open`, any of `()[]{}` counted.
fn close_of(text: &[char], open: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (k, c) in text.iter().enumerate().skip(open) {
        match c {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(k);
                }
            }
            _ => {}
        }
    }
    None
}

fn skip_ws(text: &[char], mut i: usize) -> usize {
    while text.get(i).is_some_and(|c| c.is_whitespace()) {
        i += 1;
    }
    i
}

/// A body that does nothing but print and `return;`: a skip.
fn skip_only(body: &[char]) -> bool {
    let mut rest = String::new();
    let mut k = 0;
    while k < body.len() {
        let print = ["eprintln!", "println!"]
            .into_iter()
            .find(|m| word_at(body, k, m));
        if let Some(m) = print {
            let open = skip_ws(body, k + m.chars().count());
            match close_of(body, open) {
                Some(close) => {
                    k = close + 1;
                    continue;
                }
                None => return false,
            }
        }
        rest.push(body[k]);
        k += 1;
    }
    let compact: String = rest.chars().filter(|c| !c.is_whitespace()).collect();
    compact.contains("return;") && compact.replace("return;", "").replace(';', "").is_empty()
}

/// Whether `cond` calls a probe, or reads a binding one was stored in (`tainted`).
fn probed(cond: &[char], tainted: &[String]) -> bool {
    PROBES.iter().any(|p| starts_anywhere(cond, p))
        || tainted
            .iter()
            .any(|t| (0..cond.len()).any(|k| word_at(cond, k, t)))
}

fn starts_anywhere(text: &[char], pat: &str) -> bool {
    (0..text.len()).any(|k| starts(text, k, pat))
}

/// The binding `let [mut] <name> =` heads, when it is one plain name.
fn bound_name(head: &[char]) -> Option<String> {
    let head: String = head.iter().collect();
    let head = head.trim_start().strip_prefix("let")?.trim_start();
    let head = head.strip_prefix("mut ").unwrap_or(head).trim_start();
    let name: String = head.chars().take_while(|c| is_ident(*c)).collect();
    let after = head[name.len()..].trim_start();
    (!name.is_empty() && (after.starts_with('=') || after.starts_with(':'))).then_some(name)
}

/// (d) on the literal-blanked text: every let-else and every `if` whose condition names a probe (or
/// a binding a probe's answer was stored in) and whose else/body only prints and returns.
fn skip_guards(text: &[char], at: &[usize], out: &mut Vec<(usize, &'static str)>) {
    let mut tainted: Vec<String> = Vec::new();
    for (i, c) in text.iter().enumerate() {
        if *c == 'l' && word_at(text, i, "let") {
            // The statement's `else {` at depth 0, before its `;` or the enclosing block's end.
            let mut depth = 0usize;
            let mut j = i + 3;
            let mut els = None;
            while j < text.len() {
                match text[j] {
                    '(' | '[' | '{' => depth += 1,
                    ')' | ']' | '}' if depth == 0 => break,
                    ')' | ']' | '}' => depth -= 1,
                    ';' if depth == 0 => break,
                    _ if depth == 0 && word_at(text, j, "else") => {
                        els = Some(j);
                        break;
                    }
                    _ => {}
                }
                j += 1;
            }
            let Some(els) = els else {
                // A plain binding of a probe's answer: a guard on it is a guard on the probe.
                if probed(&text[i..j.min(text.len())], &[]) {
                    tainted.extend(bound_name(&text[i..j.min(text.len())]));
                }
                continue;
            };
            let open = skip_ws(text, els + 4);
            if text.get(open) != Some(&'{') {
                continue;
            }
            let Some(close) = close_of(text, open) else {
                continue;
            };
            if probed(&text[i..els], &tainted) && skip_only(&text[open + 1..close]) {
                out.push((at[i], "(d) a let-else whose else only skips"));
            }
        } else if *c == 'i' && word_at(text, i, "if") {
            // The body's `{` is the first at bracket depth 0 (no struct literal heads an `if`).
            let mut depth = 0usize;
            let mut j = i + 2;
            let mut open = None;
            while j < text.len() {
                match text[j] {
                    '{' if depth == 0 => {
                        open = Some(j);
                        break;
                    }
                    '(' | '[' | '{' => depth += 1,
                    ')' | ']' | '}' if depth == 0 => break,
                    ')' | ']' | '}' => depth -= 1,
                    ';' if depth == 0 => break,
                    _ => {}
                }
                j += 1;
            }
            let Some(open) = open else { continue };
            let Some(close) = close_of(text, open) else {
                continue;
            };
            if probed(&text[i + 2..open], &tainted) && skip_only(&text[open + 1..close]) {
                out.push((at[i], "(d) an `if` guard whose body only skips"));
            }
        }
    }
}

/// Every silent skip in `src`: its line and the rule it breaks.
fn findings(src: &str) -> Vec<(usize, &'static str)> {
    let lines = common::classify(src, true);
    let mut out = Vec::new();
    // (a): a print whose literal announces a skip.
    let (code, at) = joined(&lines, false);
    for (i, c) in code.iter().enumerate() {
        let name = match *c {
            'e' if word_at(&code, i, "eprintln") => 8,
            'p' if word_at(&code, i, "println") => 7,
            _ => continue,
        };
        if !starts(&code, i + name, "!(") {
            continue;
        }
        let lit = skip_ws(&code, i + name + 2);
        if starts(&code, lit, "\"skip:") || starts(&code, lit, "\"SKIP") {
            out.push((at[i], "(a) a print announcing a skip"));
        }
    }
    // (b) and (c), line by line.
    for l in &lines {
        let code: String = l.code.chars().filter(|c| !c.is_whitespace()).collect();
        if code.contains("var_os(\"CI\")") || code.contains("var(\"CI\")") {
            out.push((l.no, "(b) a fixture that fails only under CI"));
        }
        if code.contains("record_skip(") {
            out.push((l.no, "(c) a skip ledger"));
        }
    }
    // (d), structurally.
    let (blank, at) = joined(&lines, true);
    skip_guards(&blank, &at, &mut out);
    out.sort();
    out.dedup();
    out
}

#[test]
fn no_root_crate_test_passes_by_skipping_its_subject() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    rs_files(&root.join("src/root/tests"), &mut files);
    rs_files(&root.join("tests"), &mut files);
    assert!(
        files.len() > 50,
        "the scan reached {} files: the trees it guards are not where it looked",
        files.len()
    );
    let mut found = Vec::new();
    for path in &files {
        let src = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("the scan reads {}: {e}", path.display()));
        let rel = path
            .strip_prefix(root)
            .unwrap_or(path)
            .display()
            .to_string();
        for (line, rule) in findings(&src) {
            found.push(format!("{rel}:{line}: {rule}"));
        }
    }
    assert!(
        found.is_empty(),
        "{} silent skip(s): a missing fixture is a failure naming its build \
         (`common::plugins::missing`), an unlinked subject is a `#[cfg]` on the test:\n{}",
        found.len(),
        found.join("\n")
    );
}

// ── THE SCAN CAN SAY NO ─────────────────────────────────────────────────────────────────────────

/// The rules `src` breaks, in rule order.
fn rules(src: &str) -> Vec<&'static str> {
    let mut rules: Vec<&'static str> = findings(src).into_iter().map(|(_, rule)| rule).collect();
    rules.sort();
    rules
}

/// Every shape this sweep removed is refused, each by its rule.
#[test]
fn selftest_every_removed_skip_shape_is_refused() {
    let let_else = r#"
fn t() {
    let Some(g) = governed("x", true) else {
        // gone in a scoped run
        eprintln!("skip: the test plane's cdylib is not built");
        return;
    };
    g.go();
}
"#;
    assert_eq!(
        rules(let_else),
        [
            "(a) a print announcing a skip",
            "(d) a let-else whose else only skips"
        ]
    );
    let quiet = "fn t() {\n    let Some(a) = adapter_over_published_schema() else {\n        return;\n    };\n}\n";
    assert_eq!(rules(quiet), ["(d) a let-else whose else only skips"]);
    let gate = "fn t() {\n    if !LINKED_TRANSPORTS.iter().any(|w| w.key == \"tcp\") {\n        return;\n    }\n}\n";
    assert_eq!(rules(gate), ["(d) an `if` guard whose body only skips"]);
    let stored = "fn t() {\n    let decls = installed_decls();\n    if decls.is_empty() {\n        // vacuous\n        return;\n    }\n}\n";
    assert_eq!(rules(stored), ["(d) an `if` guard whose body only skips"]);
    let feature = "fn t() {\n    if !cfg!(feature = \"x\") {\n        eprintln!(\n            \"SKIP: built without x\"\n        );\n        return;\n    }\n}\n";
    assert_eq!(
        rules(feature),
        [
            "(a) a print announcing a skip",
            "(d) an `if` guard whose body only skips"
        ]
    );
    let ci = "fn p() -> Option<u8> {\n    let found = None;\n    assert!(found.is_some() || std::env::var_os(\"CI\").is_none());\n    found\n}\n";
    assert_eq!(rules(ci), ["(b) a fixture that fails only under CI"]);
    let ledger = "fn t() {\n    record_skip(\"absent\");\n}\n";
    assert_eq!(rules(ledger), ["(c) a skip ledger"]);
}

/// What this sweep left in their place passes: the probe that panics, the `#[cfg]` with its
/// in-body assertion, a guard on anything but a probe, and a guard that does more than skip.
#[test]
fn selftest_a_hard_failure_or_a_gate_is_not_a_skip() {
    let clean = r#"
#[cfg(feature = "transport-tcp")]
#[test]
fn t() {
    assert!(LINKED_TRANSPORTS.iter().any(|w| w.key == "tcp"));
    let lib = common::plugins::cdylib(CDYLIB)
        .unwrap_or_else(|| common::plugins::missing(CDYLIB, common::plugins::BUILD_PINNED));
    if std::env::var_os(NODE_HOOKS_ARM).is_none() {
        return;
    }
    let Ok(n) = socket.read(&mut buf) else {
        return;
    };
    if dropped_path().exists() {
        ways.push(Way::Dropped);
    }
    // eprintln!("skip: a comment is not a print"); std::env::var_os("CI")
    println!("skipped nothing: {n}");
}
"#;
    assert_eq!(rules(clean), Vec::<&str>::new());
}
