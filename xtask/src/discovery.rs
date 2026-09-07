//! WHAT DOES CI ACTUALLY RUN? — `full-gate.sh`'s discovery, ported.
//!
//! The whole point of the local runner is that "green" has one meaning, and that only holds if the
//! set of things it runs is DERIVED FROM `ci.yml` rather than hand-mirrored beside it. A
//! hand-mirrored list drifts, and the drift is invisible: the local run stays green while CI grows
//! a gate nobody runs locally.
//!
//! TWO DISCOVERIES, AND THEY READ THE FILE DIFFERENTLY ON PURPOSE:
//!
//! * **Script gates read PHYSICAL lines.** A gate's continuation lines are its arguments; the head
//!   line already names the gate. Folding them would splice half-captured argument lists together
//!   and invent invocations that appear nowhere.
//! * **Cargo invocations read FOLDED LOGICAL lines**, because a `cargo test` continued over three
//!   backslashed lines is ONE invocation and a discovery that saw three fragments would classify
//!   none of them.
//!
//! Both drop `#` comments and step `name:` labels before matching, so a command quoted in prose is
//! not a command anybody runs; the cargo half additionally drops `echo` lines. Those four
//! exclusions are the fixture's own assertions and they are the difference between a discovered set
//! and a grep.

use crate::yaml_lite;

const GATE_EXTS: [&str; 6] = ["sh", "py", "mjs", "js", "ts", "rb"];
const GATE_ROOTS: [&str; 2] = ["scripts", "testing"];
const INTERPRETERS: [&str; 4] = ["python3 ", "bash ", "node ", "npx "];
const CARGO_VERBS: [&str; 6] = ["fmt", "clippy", "build", "test", "run", "xtask"];

/// Blank a whole-line `#` comment or a step `name:` label, keeping the line so numbering does not
/// move. A gate named in a comment or a step title is documentation, not an invocation.
fn strip_prose(line: &str) -> &str {
    let t = line.trim_start();
    if t.starts_with('#') {
        return "";
    }
    let after_dash = t.strip_prefix('-').unwrap_or(t).trim_start();
    if after_dash.starts_with("name:") {
        return "";
    }
    line
}

fn is_ident_char(c: char) -> bool {
    c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'
}

/// Every script-gate invocation in the workflow text, deduplicated and sorted.
///
/// The shape matched is `[interpreter ]{scripts|testing}/[seg/]*name.ext` followed by zero or more
/// long flags, each optionally carrying one unquoted value token. The word boundary after the
/// extension is LOAD-BEARING: without it `spec-digests.tsv` matches the `ts` alternative and
/// discovery invents a gate out of a data file.
pub fn script_gates(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for raw in text.lines() {
        let line = strip_prose(raw);
        let chars: Vec<char> = line.chars().collect();
        let mut i = 0usize;
        while i < chars.len() {
            let Some(end) = match_path(&chars, i) else {
                i += 1;
                continue;
            };
            let start = match_interpreter(&chars, i);
            let end = match_args(&chars, end);
            let inv: String = chars[start..end].iter().collect();
            let inv = inv.trim().to_string();
            if !out.contains(&inv) {
                out.push(inv);
            }
            i = end.max(i + 1);
        }
    }
    out.sort();
    out
}

/// If one of the four interpreter prefixes sits immediately before `at`, include it — it is part of
/// the invocation and is re-executed as such.
fn match_interpreter(chars: &[char], at: usize) -> usize {
    for prefix in INTERPRETERS {
        let p: Vec<char> = prefix.chars().collect();
        if at >= p.len() && chars[at - p.len()..at] == p[..] {
            return at - p.len();
        }
    }
    at
}

/// Match `{scripts|testing}/([a-z0-9-]+/)*[a-z0-9-]+\.(ext)\b` at `at`, returning the end index.
fn match_path(chars: &[char], at: usize) -> Option<usize> {
    // The match must start at a path boundary, or `xscripts/a.sh` would be discovered as
    // `scripts/a.sh`.
    if at > 0 && (is_ident_char(chars[at - 1]) || chars[at - 1] == '/' || chars[at - 1] == '.') {
        return None;
    }
    let mut i = at;
    let root = GATE_ROOTS.iter().find(|r| {
        let r: Vec<char> = r.chars().collect();
        chars.len() > at + r.len() && chars[at..at + r.len()] == r[..] && chars[at + r.len()] == '/'
    })?;
    i += root.chars().count() + 1;

    loop {
        let seg_start = i;
        while i < chars.len() && is_ident_char(chars[i]) {
            i += 1;
        }
        if i == seg_start {
            return None;
        }
        if i < chars.len() && chars[i] == '/' {
            i += 1;
            continue;
        }
        break;
    }
    if i >= chars.len() || chars[i] != '.' {
        return None;
    }
    i += 1;
    let ext_start = i;
    while i < chars.len() && chars[i].is_ascii_alphanumeric() {
        i += 1;
    }
    let ext: String = chars[ext_start..i].iter().collect();
    if !GATE_EXTS.contains(&ext.as_str()) {
        return None;
    }
    // `\b`: the extension must not run into another word character.
    if i < chars.len() && (is_ident_char(chars[i]) || chars[i] == '_') {
        return None;
    }
    Some(i)
}

/// Zero or more ` --flag[ value]` groups. A value token stops at a space, a quote or a pipe, which
/// is what keeps a shell redirection or a quoted argument out of the invocation.
fn match_args(chars: &[char], mut i: usize) -> usize {
    loop {
        let save = i;
        if i + 2 >= chars.len() || chars[i] != ' ' || chars[i + 1] != '-' || chars[i + 2] != '-' {
            return save;
        }
        i += 3;
        let flag_start = i;
        while i < chars.len() && (chars[i].is_ascii_lowercase() || chars[i] == '-') {
            i += 1;
        }
        if i == flag_start {
            return save;
        }
        // One optional value token.
        if i < chars.len() && chars[i] == ' ' {
            let mut j = i + 1;
            let val_start = j;
            while j < chars.len() && !matches!(chars[j], ' ' | '"' | '\'' | '|') {
                j += 1;
            }
            if j > val_start {
                // A value that is itself a flag belongs to the NEXT group, not this one.
                let val: String = chars[val_start..j].iter().collect();
                if !val.starts_with("--") {
                    i = j;
                }
            }
        }
    }
}

/// `cargo_norm`: strip the noise a shell line carries so two spellings of one invocation classify
/// as one.
///
/// In order: delete every `2>&1`; delete every `--verbose`; drop a trailing `\`; DELETE FROM AN
/// OPTIONAL FD-NUMBER PLUS `>`/`>>` TO END OF LINE (the redirect AND its target file); drop a
/// trailing `&`; collapse whitespace runs; trim. Quoted arguments SURVIVE — cutting at the quote
/// used to leave a dangling `--features` that matched nothing.
pub fn cargo_norm(s: &str) -> String {
    let mut t = s.replace("2>&1", "").replace("--verbose", "");
    t = t.trim_end().trim_end_matches('\\').to_string();
    if let Some(pos) = find_redirect(&t) {
        t.truncate(pos);
    }
    t = t.trim_end().trim_end_matches('&').to_string();
    t.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The first `[0-9]*>>?` outside a quoted run.
fn find_redirect(s: &str) -> Option<usize> {
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '>' {
            let mut start = i;
            while start > 0 && chars[start - 1].is_ascii_digit() {
                start -= 1;
            }
            return Some(chars[..start].iter().collect::<String>().len());
        }
        i += 1;
    }
    None
}

/// Every cargo invocation in the workflow, normalised, deduplicated and sorted.
pub fn cargo_invocations(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in yaml_lite::logical_lines(text) {
        let line = strip_prose(&line);
        if line.trim_start().starts_with("echo ") {
            continue;
        }
        let mut rest = line;
        while let Some(idx) = rest.find("cargo ") {
            let after = &rest[idx + "cargo ".len()..];
            let verb = after.split_whitespace().next().unwrap_or("");
            if !CARGO_VERBS.contains(&verb) {
                rest = &rest[idx + "cargo ".len()..];
                continue;
            }
            // The capture runs to end of line but STOPS at the first `|` or `)` — how CI's
            // `| tee …` and its `${{ … )` constructs survive classification.
            let tail = &rest[idx..];
            let cut = tail.find(['|', ')']).unwrap_or(tail.len());
            let cmd = cargo_norm(&tail[..cut]);
            if !cmd.is_empty() && !out.contains(&cmd) {
                out.push(cmd);
            }
            rest = &rest[idx + "cargo ".len()..];
        }
    }
    out.sort();
    out
}

/// The gate names `cargo xtask gate <name>` names in the workflow, in first-seen order.
///
/// ONLY the `gate` form. `cargo xtask ledger` and `cargo xtask teller-steps` are SUBCOMMANDS, not
/// gates, and counting them would make the registry set-equality below demand a registration for
/// something that was never a gate.
pub fn xtask_gate_names(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in yaml_lite::logical_lines(text) {
        let line = strip_prose(&line);
        let mut rest = line;
        while let Some(i) = rest.find("cargo xtask gate ") {
            rest = &rest[i + "cargo xtask gate ".len()..];
            let name = rest.split_whitespace().next().unwrap_or("");
            if !name.is_empty() && !name.starts_with('-') && !out.iter().any(|n| n == name) {
                out.push(name.to_string());
            }
        }
    }
    out
}
