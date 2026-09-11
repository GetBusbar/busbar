// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! WHAT THE SHIPPED BINARY ACTUALLY CONTAINS — the one source classifier the composition root's
//! scanning gates share.
//!
//! A gate that answers a question about production code by reading a `.rs` file whole is not
//! answering that question. Every crate in this tree keeps its unit tests in the same file as the
//! code they exercise, inside `#[cfg(test)] mod tests { … }`, and that block is not in the shipped
//! binary. So a scan that reads the file whole is satisfied by a token that appears ONLY in a test
//! — including a token the test wrote precisely because it was mocking the production path that is
//! missing. The gate then reports the property holds while the property is absent, which is the
//! exact failure a gate exists to prevent.
//!
//! The construction gate already had the right answer, in Python: `scripts/construction-gate/
//! rules.py` carries a `scan_file` that strips comments (respecting string literals, so a `//`
//! inside a string is not a comment), blanks literal contents (so a brace inside a string does not
//! disturb structure matching), and tracks `#[cfg(test)] mod` depth so every line inside a test
//! module is flagged. This is that classifier, in Rust, with the same rules — so the two gates
//! agree about what "production" means rather than each having a private opinion.
//!
//! [`Line::intest`] is the whole point. Everything else here exists to compute it correctly.

#![allow(dead_code)]

use std::path::{Path, PathBuf};

/// One classified source line.
#[derive(Debug, Clone)]
pub struct Line {
    /// 1-based line number in the file it came from.
    pub no: usize,
    /// The line with comments removed and string literals left intact.
    pub code: String,
    /// The same with string/char literal CONTENTS blanked, so braces and parens inside a literal
    /// do not disturb structure matching.
    pub blank: String,
    /// True when this line is test code: a `#[cfg(test)] mod` body, or a test file.
    pub intest: bool,
}

/// Strip `//`-to-EOL and `/* … */` (which may span lines via `in_block`) while leaving string
/// literals intact. Same rules as the construction gate's `strip_comments`.
fn strip_comments(line: &str, in_block: &mut bool) -> String {
    let b: Vec<char> = line.chars().collect();
    let mut out = String::new();
    let mut i = 0usize;
    let mut in_str = false;
    while i < b.len() {
        let c = b[i];
        let c2: String = b[i..(i + 2).min(b.len())].iter().collect();
        if *in_block {
            if c2 == "*/" {
                *in_block = false;
                i += 2;
            } else {
                i += 1;
            }
            continue;
        }
        if in_str {
            out.push(c);
            if c == '\\' {
                if let Some(n) = b.get(i + 1) {
                    out.push(*n);
                }
                i += 2;
                continue;
            }
            if c == '"' {
                in_str = false;
            }
            i += 1;
            continue;
        }
        if c2 == "/*" {
            *in_block = true;
            i += 2;
            continue;
        }
        if c2 == "//" {
            break;
        }
        if c == '"' {
            in_str = true;
            out.push(c);
            i += 1;
            continue;
        }
        out.push(c);
        i += 1;
    }
    out
}

/// Replace string and char literal contents with spaces. Lifetimes (`'a`) are not char literals
/// and are left alone — the same carve-out `rules.py`'s `blank_literals` makes.
fn blank_literals(code: &str) -> String {
    let b: Vec<char> = code.chars().collect();
    let mut out = String::with_capacity(code.len());
    let mut i = 0usize;
    while i < b.len() {
        if b[i] == '"' {
            out.push('"');
            i += 1;
            while i < b.len() && b[i] != '"' {
                if b[i] == '\\' {
                    out.push(' ');
                    i += 1;
                }
                if i < b.len() {
                    out.push(' ');
                    i += 1;
                }
            }
            if i < b.len() {
                out.push('"');
                i += 1;
            }
            continue;
        }
        // `'x'` and `'\x'` are char literals; `'a` followed by anything else is a lifetime.
        if b[i] == '\'' {
            let esc = b.get(i + 1) == Some(&'\\');
            let close = if esc { i + 3 } else { i + 2 };
            if b.get(close) == Some(&'\'') {
                out.push('\'');
                out.push(' ');
                out.push('\'');
                i = close + 1;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

/// True when `code` carries a `#[cfg(...)]` whose predicate names `test` as a whole word.
fn is_cfg_test(code: &str) -> bool {
    if !code.contains("#[cfg(") {
        return false;
    }
    let padded = format!(" {} ", code.to_lowercase());
    let bytes: Vec<char> = padded.chars().collect();
    for i in 0..bytes.len().saturating_sub(5) {
        if bytes[i + 1..i + 5].iter().collect::<String>() == "test" {
            let before = bytes[i];
            let after = bytes[i + 5];
            let word = |c: char| c.is_ascii_alphanumeric() || c == '_';
            if !word(before) && !word(after) {
                return true;
            }
        }
    }
    false
}

/// True when `code` uses `mod` as a whole word.
fn has_mod_word(code: &str) -> bool {
    let bytes: Vec<char> = format!(" {code} ").chars().collect();
    for i in 0..bytes.len().saturating_sub(4) {
        if bytes[i + 1..i + 4].iter().collect::<String>() == "mod" {
            let word = |c: char| c.is_ascii_alphanumeric() || c == '_';
            if !word(bytes[i]) && !word(bytes[i + 4]) {
                return true;
            }
        }
    }
    false
}

/// Classify one source text. `is_test_file` marks the whole file as test code up front (an
/// integration test, a `_tests.rs`, a `test_support` module).
pub fn classify(src: &str, is_test_file: bool) -> Vec<Line> {
    let mut in_block = false;
    let mut testdepth: i64 = 0;
    let mut pend = false;
    let mut out = Vec::new();
    for (idx, raw) in src.lines().enumerate() {
        let code = strip_comments(raw, &mut in_block);
        let blank = blank_literals(&code);
        let nopen = blank.matches('{').count() as i64;
        let nclose = blank.matches('}').count() as i64;
        let cfgtest = is_cfg_test(&code);
        let modword = has_mod_word(&code);
        let mut entered = false;
        if cfgtest && modword {
            // `#[cfg(test)] mod tests {` on one line.
            testdepth = (nopen - nclose).max(0);
            entered = testdepth > 0;
            pend = false;
        } else if pend && modword {
            // `#[cfg(test)]` on its own line, `mod tests {` on the next.
            testdepth = (nopen - nclose).max(0);
            entered = testdepth > 0;
            pend = false;
        } else if pend && !code.trim().is_empty() && !cfgtest {
            // The `#[cfg(test)]` gated something that was not a module; it is not a test body.
            pend = false;
        } else if testdepth > 0 {
            testdepth = (testdepth + nopen - nclose).max(0);
        }
        if cfgtest && !modword {
            pend = true;
        }
        out.push(Line {
            no: idx + 1,
            code,
            blank,
            intest: is_test_file || testdepth > 0 || entered,
        });
    }
    out
}

/// The production lines of a file on disk: comments stripped, `#[cfg(test)]` module bodies gone.
/// A file that cannot be read yields nothing, which every caller treats as "reaches nothing" —
/// the safe direction for a gate.
pub fn production_lines(path: &Path) -> Vec<Line> {
    let Ok(src) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let is_test_file = is_test_path(path);
    classify(&src, is_test_file)
        .into_iter()
        .filter(|l| !l.intest)
        .collect()
}

/// The production TEXT of a file on disk, one line per line, comments and test modules removed.
pub fn production_text(path: &Path) -> String {
    production_lines(path)
        .iter()
        .map(|l| format!("{}\n", l.code))
        .collect()
}

/// Whether a path is a test file in its entirety, by the same fragments the plane gates use.
pub fn is_test_path(path: &Path) -> bool {
    let p = path.to_string_lossy().replace('\\', "/");
    p.ends_with("_tests.rs")
        || p.ends_with("/tests.rs")
        || p.contains("/test_support")
        || p.contains("/tests/")
}

/// Every `.rs` file under `dir` that is production source, skipping `target/` and `tests/` trees.
pub fn production_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut paths: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
    paths.sort();
    for path in paths {
        if path.is_dir() {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name == "target" || name == "tests" {
                continue;
            }
            production_rs_files(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") && !is_test_path(&path) {
            out.push(path);
        }
    }
}

/// THE BODY OF ONE ITEM, by brace matching over production lines.
///
/// Gates that ask "does this function reach that seam" must ask it of the FUNCTION, not of the file
/// the function happens to live in: a file-wide scan is satisfied by any other function in the same
/// file, which is how a step that reaches nothing passes a gate that says it reaches something.
///
/// Returns the production lines from the one whose `code` contains `signature` through the line
/// that closes its body, or `None` when no line carries the signature.
pub fn item_body<'a>(lines: &'a [Line], signature: &str) -> Option<Vec<&'a Line>> {
    let start = lines.iter().position(|l| l.code.contains(signature))?;
    let mut depth: i64 = 0;
    let mut seen_open = false;
    let mut body = Vec::new();
    for line in &lines[start..] {
        body.push(line);
        depth += line.blank.matches('{').count() as i64;
        if line.blank.contains('{') {
            seen_open = true;
        }
        depth -= line.blank.matches('}').count() as i64;
        if seen_open && depth <= 0 {
            return Some(body);
        }
    }
    // An unterminated body is a parse failure, not a pass: hand back what was found so the caller
    // scans it, rather than silently reporting the item absent.
    Some(body)
}

// ── boot-port reservation ───────────────────────────────────────────────────────────────────────
//
// Nine boot-a-real-child integration tests (`no_data_dir_neutrality`, `boot_lines_neutrality`,
// `thread_per_core_serves`, `scrape_shape_1_5_5`, `mcp_open_front_door`, `ledger_identity`,
// `inbound_concurrency_shed`, `metrics_scrape_boot_window`, and the `hook_path` bench) each carried
// their OWN copy of a `free_port()` that bound `127.0.0.1:0`, read the port back, and DROPPED the
// listener — before the rest of fixture setup (writing config/provider YAML, shelling out to
// `busbar --generate-signing-key`, sometimes booting a second child) ran, and only THEN spawning
// the child that binds the number.
//
// The port has to be a LITERAL in the child's config before the child exists at all: the
// thread-per-core data plane binds the identical address from every one of its N SO_REUSEPORT
// worker threads (an ephemeral `:0` there hands each worker a DIFFERENT port — see
// `busbar::main::serve_thread_per_core`), and every listener's boot line prints the CONFIGURED
// address (`cfg.listen`/`cfg.admin_listen`), never the bound one, so there is no line a test could
// read a dynamically-assigned port back off. So the number has to be chosen up front, which is
// exactly the TOCTOU the nine copies of `free_port()` accepted as a known, unfixed risk: the OS can
// (and, by measurement, does) hand this process's freed port to another process on the shared box
// before the child gets to it.
//
// `ReservedPort` does not make that window zero — nothing short of every process on the box
// coordinating could do that — but the nine copies were leaving it far WIDER than the race itself
// needs: `free_port()` was called and dropped immediately, and only afterward did the fixture write
// YAML, shell out to a `--generate-signing-key` child process, or (the ledger-identity cell) boot a
// Python mock upstream — real, measurable milliseconds of unrelated work between "the port is free"
// and "the port is asked for again". `ReservedPort` holds the OS-assigned listener open across all
// of that; the caller drops it (via `release`, or simply letting it go out of scope) only
// IMMEDIATELY before the `Command::spawn` that binds the number, shrinking the window from
// "however long fixture setup takes" down to a `drop` followed by a syscall.
pub struct ReservedPort(std::net::TcpListener);

impl ReservedPort {
    /// Ask the OS for a free loopback port and hold it open. Panics — like every one of the nine
    /// `free_port()` copies this replaces already did — if the OS has none to give; there is no
    /// meaningful fallback for a test fixture.
    pub fn reserve() -> Self {
        ReservedPort(std::net::TcpListener::bind("127.0.0.1:0").expect("a free port"))
    }

    /// The reserved port number, safe to write into a config file or argument list. Cheap and
    /// side-effect-free to call repeatedly; the listener stays open until `release` (or `Drop`) —
    /// call that immediately before spawning the process that will bind this port, not before.
    pub fn port(&self) -> u16 {
        self.0.local_addr().expect("a bound address").port()
    }

    /// Release the reservation. Call this the instant before `Command::spawn`, once every other
    /// part of the fixture (config/provider YAML, a generated signing key, a second child's own
    /// boot) is already prepared — that ordering is the entire fix: it is not dropping the listener
    /// that was ever the problem, it is dropping it long before the child that needed the number.
    pub fn release(self) {
        drop(self);
    }
}
