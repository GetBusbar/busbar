// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `cargo xtask gate map-proof` — THE MAP'S PROOF DOCUMENTS RE-RUN AGAINST THE TREE.
//!
//! `docs/design/1.6.0-map-proof.md` §0 states the rule the whole corpus is written under:
//!
//! > *"every number carries the command that produces it … A number you cannot reproduce at `PIN`
//! > is a bug in this document. Say so."*
//!
//! That rule had no instrument. Four printed figures were caught not reproducing by hand — a
//! commit count that is three short at the document's own pin, a "242" that is not a count at all,
//! a `44 sections` that is `grep -cE '^#'` counting an H1 and a `#![allow(dead_code)]` inside a
//! fenced block, and a `30 of 41` that is really `33 of 40`. Each took a human-directed spot check.
//! **Auditing once is a snapshot. This gate is the property.**
//!
//! # What it does
//!
//! It reads the corpus in [`CORPUS`], extracts every runnable command out of every fenced block,
//! re-runs it against this tree, and compares what came back to what the document printed.
//!
//! # THE BINDING CONVENTION, and why it is a convention rather than a parse of the prose
//!
//! A figure is bound to a command by a **trailing or following `# -> …` comment inside the same
//! fenced block**. That is not invented here: it is the notation the corpus already uses in 150
//! places. It is preferred over reading the surrounding prose for two reasons that are the same
//! reason twice — a prose parse has no ground truth, so it cannot be wrong in a way anybody
//! notices, and a document author cannot tell by looking whether their number is being checked.
//! `# -> N` is visible, greppable, and either present or absent.
//!
//! Because the convention can be *not followed*, the gate reports that too: [`ROW_BOUND`] counts
//! every bold-emphasised figure in the document body that no `# ->` in the same document produces.
//! **A figure nobody can re-derive is the worst case, not the absent case.**
//!
//! # THE FIVE VERDICTS, and why "skipped" is not one of them
//!
//! | verdict | meaning |
//! | --- | --- |
//! | [`Verdict::Reproduces`] | the command ran and the figure came back |
//! | [`Verdict::DoesNotReproduce`] | the command ran and returned something else — **both numbers are printed** |
//! | [`Verdict::Unrunnable`] | the command could not execute: a deleted path, a pin that no longer resolves, a tool that is gone, a fenced line that is pasted output rather than a command, or a per-command budget it blew |
//! | [`Verdict::Refused`] | THE INSTRUMENT declined to run it — it writes into the tree, reaches the network, or re-enters this gate runner. Distinct from `Unrunnable` because the fault is the gate's, not the document's, and a reader must be able to tell those apart |
//! | [`Verdict::Uncheckable`] | the `# ->` payload is prose this gate cannot mechanically compare |
//!
//! **None of the five is a skip.** An unrunnable proof is an unproven claim; a refused proof is an
//! unproven claim; an uncheckable expectation is an unproven claim. Each has its own row, so each
//! can be driven to zero independently and none can hide inside another's number.
//!
//! # THE MATCH LADDER for `# -> <integer>`
//!
//! `# -> 23` does not say *how* 23 is meant to appear. Across the corpus it means three different
//! things, so three readings are tried in a fixed order and **the reading that matched is printed
//! in the row** — a `figure-present` match is weaker evidence than a `leading-figure` match and a
//! reader must be able to see which one they got.
//!
//! 1. `leading-figure` — the output is ONE line and its first token is that integer
//!    (`grep -c … # -> 23`). Restricted to single-line output on purpose: with `sort | uniq -c`
//!    the first line is whichever label sorts first, which is not the figure the prose leads with.
//! 2. `line-count` — the output has exactly that many non-empty lines (`git grep -n … # -> 7`).
//! 3. `sole-figure` — the output contains exactly one integer anywhere and it is that integer
//!    (`grep -oE 'DONE_GROUPS_DECLARED=[0-9]+' … # -> 23`).
//! 4. `figure-present` — the output is short (≤ [`FIGURE_PRESENT_MAX_LINES`] lines) and the
//!    integer appears in it as a whole token (`sort | uniq -c … # -> 10 **RED** 7 **GREEN** …`).
//!
//! If none matches, the verdict is `DoesNotReproduce` and the row prints what was actually seen.
//!
//! # BEWARE THE FALSE ZERO — this gate is made of other people's greps
//!
//! `git show <dead-pin>:path | grep -c X` prints `0` and exits 0. The `0` is not a measurement, it
//! is the shape of a pipeline whose head died — and it is exactly the failure this corpus keeps
//! catching in other people's work. So **stderr is consulted before stdout**: a command whose
//! stderr carries a resolution failure is `Unrunnable` EVEN WHEN STDOUT CARRIES A NUMBER
//! ([`UNRUNNABLE_STDERR`]). The one exception is an expectation that asks for the absence
//! (`# -> does not exist`), where the failure IS the result.
//!
//! The extractor's own false zero is guarded by [`ROW_EXTRACTION`]: every source declares a floor
//! of fenced commands, and a corpus-wide floor of bound expectations. A parser that silently
//! matched nothing reads exactly like a corpus in which everything reproduces, and that is the one
//! outcome this gate must never be able to produce.
//!
//! # SAFETY — it executes shell out of a markdown file
//!
//! The corpus really does print `grep '^#' scripts/no-deferral.waivers > scripts/no-deferral.waivers`
//! and `sed -i '' …` and `cargo test`. [`refuse_reason`] screens every command before it runs;
//! anything that writes outside `/tmp`, mutates git, builds, reaches the network, or invokes
//! `xtask` is `Refused` and counted. Fenced blocks also carry pasted OUTPUT beside their commands,
//! so every command runs inside `eval '…'`: a syntax error there is contained to that one command
//! instead of aborting the document's script, and the syntax error itself is what identifies the
//! line as output rather than a command.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::ctx::{Ctx, Overlay};
use crate::gates::{prove_red, prove_rows_green, Gate, Report};
use crate::ledger::{Row, Verdict as GateVerdict};

// ---------------------------------------------------------------------------------------------
// rows
// ---------------------------------------------------------------------------------------------

/// The extractor reached the corpus. The false-zero guard; every other row is vacuous without it.
pub const ROW_EXTRACTION: &str = "map-proof:extraction";
/// Every `# ->` is attached to a command, and every bold figure has a command that produces it.
pub const ROW_BOUND: &str = "map-proof:bound";
/// No bound command failed to execute.
pub const ROW_RUNNABLE: &str = "map-proof:runnable";
/// No bound command was refused by this gate's own safety screen or budget.
pub const ROW_UNREFUSED: &str = "map-proof:unrefused";
/// Every `# ->` payload is in the machine-checkable convention.
pub const ROW_COUNTABLE: &str = "map-proof:countable";

/// `map-proof:reproduces/<slug>` — one per source document.
fn row_reproduces(slug: &str) -> String {
    format!("map-proof:reproduces/{slug}")
}

// ---------------------------------------------------------------------------------------------
// the corpus
// ---------------------------------------------------------------------------------------------

/// One source document, with the floors that prove the extractor reached it.
pub struct Source {
    pub path: &'static str,
    pub slug: &'static str,
    /// The fewest fenced logical commands a working extractor finds here. Set well under the
    /// live count: these documents are edited daily and a floor is a false-zero guard, not a
    /// ratchet.
    pub floor_commands: usize,
    /// The fewest `# ->` bound expectations a working extractor finds here.
    pub floor_expectations: usize,
}

/// THE MAP CORPUS — every document that prints a command beside a number.
pub const CORPUS: &[Source] = &[
    Source {
        path: "docs/design/1.6.0-map-proof.md",
        slug: "map-proof",
        floor_commands: 120,
        floor_expectations: 60,
    },
    Source {
        path: "docs/design/1.6.0-ratchet-census.md",
        slug: "ratchet-census",
        floor_commands: 40,
        floor_expectations: 2,
    },
    Source {
        path: "docs/design/1.6.0-oracle-coverage.md",
        slug: "oracle-coverage",
        floor_commands: 8,
        floor_expectations: 4,
    },
    Source {
        path: "docs/design/1.6.0-done-readout.md",
        slug: "done-readout",
        floor_commands: 10,
        floor_expectations: 0,
    },
    Source {
        path: "docs/design/1.6.0-instrument-audit.md",
        slug: "instrument-audit",
        floor_commands: 40,
        floor_expectations: 3,
    },
    Source {
        path: "docs/design/1.6.0-gate-sweep.md",
        slug: "gate-sweep",
        floor_commands: 20,
        floor_expectations: 3,
    },
    Source {
        path: "docs/design/1.6.0-LEDGER.md",
        slug: "ledger",
        floor_commands: 2,
        floor_expectations: 0,
    },
];

/// The corpus-wide floor of bound expectations. One document can legitimately lose its commands to
/// an edit; the corpus losing them all at once is the extractor, not the corpus.
pub const CORPUS_EXPECTATION_FLOOR: usize = 90;

// ---------------------------------------------------------------------------------------------
// budgets
// ---------------------------------------------------------------------------------------------

/// One command's wall clock. A command that blows it is `Unrunnable`, named, and the run goes on
/// from the next one — one slow `git grep` must not blind the other hundred proofs.
const PER_COMMAND_BUDGET: Duration = Duration::from_secs(20);
/// The whole gate's wall clock for running commands. The runner's own ceiling is 300 s
/// (`DEFAULT_GATE_CEILING`); this leaves room to report rather than be killed mid-measurement.
const TOTAL_BUDGET: Duration = Duration::from_secs(200);
/// How many times a document's script may be restarted past a command that blew its budget.
const MAX_RESTARTS: usize = 12;
/// `figure-present` is the weakest reading in the ladder, so it only applies to short output.
pub const FIGURE_PRESENT_MAX_LINES: usize = 20;

// ---------------------------------------------------------------------------------------------
// extraction
// ---------------------------------------------------------------------------------------------

/// One logical shell command lifted out of a fenced block, with whatever `# ->` was bound to it.
#[derive(Debug, Clone)]
pub struct Cmd {
    /// 1-based line of the command's first line in the document.
    pub line: usize,
    /// 1-based line of the opening fence.
    pub block: usize,
    /// The command as bash will see it, comments stripped, continuations joined.
    pub code: String,
    /// The `# ->` payloads bound to it, in document order.
    pub expect: Vec<String>,
}

/// A `# ->` that arrived before any command in its block — a printed expectation with nothing
/// behind it.
#[derive(Debug, Clone)]
pub struct Orphan {
    pub line: usize,
    pub payload: String,
}

/// Quote-aware scan of one line, CONTINUING the quote state from the previous line.
///
/// Per-line scanning was wrong twice in this corpus. `grep -cE '^#{2,3} '   # -> 21` has a `#`
/// inside single quotes that is not a comment, and a `python3 -c "` whose closing `"   # -> […]`
/// lands three lines later has a `#` that IS one only because the quote opened earlier. Returns
/// `(code, comment, sq, dq)`.
fn scan_line(line: &str, mut sq: bool, mut dq: bool) -> (String, Option<String>, bool, bool) {
    let b: Vec<char> = line.chars().collect();
    let mut i = 0usize;
    while i < b.len() {
        let c = b[i];
        if c == '\\' && !sq {
            i += 2;
            continue;
        }
        if c == '\'' && !dq {
            sq = !sq;
        } else if c == '"' && !sq {
            dq = !dq;
        } else if c == '#' && !sq && !dq && (i == 0 || b[i - 1] == ' ' || b[i - 1] == '\t') {
            let code: String = b[..i].iter().collect();
            let comment: String = b[i..].iter().collect();
            return (code, Some(comment), sq, dq);
        }
        i += 1;
    }
    (line.to_string(), None, sq, dq)
}

/// `do`/`then`/`case` open, `done`/`fi`/`esac` close — as WHOLE SHELL WORDS.
///
/// A substring match read `done` out of the filename `1.6.0-done-readout.md` and closed a `for`
/// loop that was still open, which split one command into three and bound the loop's `# ->` to the
/// word `done`.
fn depth_delta(code: &str) -> i32 {
    let mut d = 0;
    for tok in code.split(|c: char| c.is_whitespace() || ";|&()<>".contains(c)) {
        match tok {
            "do" | "then" | "case" => d += 1,
            "done" | "fi" | "esac" => d -= 1,
            _ => {}
        }
    }
    d
}

fn heredoc_tags(code: &str) -> Vec<String> {
    let bytes: Vec<char> = code.chars().collect();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 1 < bytes.len() {
        if bytes[i] == '<' && bytes[i + 1] == '<' {
            let mut j = i + 2;
            if j < bytes.len() && bytes[j] == '-' {
                j += 1;
            }
            // `<<<` is a here-STRING, not a here-doc.
            if j < bytes.len() && bytes[j] == '<' {
                i = j + 1;
                continue;
            }
            while j < bytes.len() && (bytes[j] == ' ' || bytes[j] == '\t') {
                j += 1;
            }
            let quote = if j < bytes.len() && (bytes[j] == '\'' || bytes[j] == '"') {
                let q = bytes[j];
                j += 1;
                Some(q)
            } else {
                None
            };
            let start = j;
            while j < bytes.len() && (bytes[j].is_ascii_alphanumeric() || bytes[j] == '_') {
                j += 1;
            }
            if j > start {
                let tag: String = bytes[start..j].iter().collect();
                if let Some(q) = quote {
                    if j < bytes.len() && bytes[j] == q {
                        j += 1;
                    }
                }
                out.push(tag);
            }
            i = j;
            continue;
        }
        i += 1;
    }
    out
}

fn arrow_payload(comment: &str) -> Option<String> {
    let t = comment.trim_start();
    let rest = t.strip_prefix('#')?;
    let rest = rest.trim_start_matches([' ', '\t']);
    let rest = rest.strip_prefix("->")?;
    Some(
        rest.strip_prefix(' ')
            .unwrap_or(rest)
            .trim_end()
            .to_string(),
    )
}

/// Everything this gate can see in one document.
#[derive(Debug, Default)]
pub struct Extract {
    pub commands: Vec<Cmd>,
    pub orphans: Vec<Orphan>,
    /// Bold-emphasised integers in the document BODY (outside fenced blocks).
    pub figures: Vec<(usize, i64)>,
}

/// Pull every fenced shell block apart into logical commands and bound expectations.
pub fn extract(text: &str) -> Extract {
    let mut out = Extract::default();
    let mut in_fence = false;
    let mut fence_lang = String::new();
    let mut fence_start = 0usize;
    let mut block: Vec<(usize, &str)> = Vec::new();

    for (idx, raw) in text.lines().enumerate() {
        let no = idx + 1;
        let trimmed = raw.trim_start();
        if trimmed.starts_with("```") {
            if in_fence {
                in_fence = false;
                if is_shell(&fence_lang) {
                    parse_block(&block, fence_start, &mut out);
                }
                block.clear();
            } else {
                in_fence = true;
                fence_lang = trimmed.trim_start_matches('`').trim().to_string();
                fence_start = no;
                block.clear();
            }
            continue;
        }
        if in_fence {
            block.push((no, raw));
        } else {
            collect_figures(no, raw, &mut out.figures);
        }
    }
    if in_fence && is_shell(&fence_lang) {
        parse_block(&block, fence_start, &mut out);
    }
    out
}

fn is_shell(lang: &str) -> bool {
    matches!(lang, "sh" | "bash" | "shell" | "console" | "")
}

/// A **printed figure** is an integer inside `**…**`. That is the corpus's own notation for "this
/// is a measured number" — §2's reconciliation table, every `IN`/`OUT`/`Δ`, every headline count.
/// Restricting to it keeps the census meaningful; counting every integer in the prose would drown
/// the finding in section numbers and dates.
fn collect_figures(line_no: usize, raw: &str, out: &mut Vec<(usize, i64)>) {
    let chars: Vec<char> = raw.chars().collect();
    let mut i = 0usize;
    while i + 1 < chars.len() {
        if chars[i] == '*' && chars[i + 1] == '*' {
            let start = i + 2;
            let mut j = start;
            while j + 1 < chars.len() && !(chars[j] == '*' && chars[j + 1] == '*') {
                j += 1;
            }
            if j + 1 >= chars.len() {
                return;
            }
            let inner: String = chars[start..j].iter().collect();
            for n in integers_in(&inner) {
                out.push((line_no, n));
            }
            i = j + 2;
            continue;
        }
        i += 1;
    }
}

/// Every whole-token integer in `s`, thousands separators folded away.
///
/// A token is an integer only when it is not glued to a letter, a `/`, a `.` or a `-`. Without
/// that boundary `5fa320208` (a short sha) reads as the number 5, `22/22` reads as 22, and the
/// date `2026-09-22` reads as three figures — all three were classified as countable expectations
/// before the boundary existed.
pub fn integers_in(s: &str) -> Vec<i64> {
    let c: Vec<char> = s.chars().collect();
    let mut out = Vec::new();
    let mut i = 0usize;
    let glue =
        |ch: char| ch.is_ascii_alphanumeric() || ch == '_' || ch == '.' || ch == '/' || ch == '-';
    // `§12` is a cross-reference and `#58` is a decision id. Neither is a measurement, and
    // counting them as unbound figures buries the ones that are.
    let id_sigil = |ch: char| ch == '\u{a7}' || ch == '#';
    while i < c.len() {
        if !c[i].is_ascii_digit() {
            i += 1;
            continue;
        }
        if i > 0 && id_sigil(c[i - 1]) {
            while i < c.len() && (c[i].is_ascii_digit() || glue(c[i])) {
                i += 1;
            }
            continue;
        }
        if i > 0 && glue(c[i - 1]) && !c[i - 1].is_ascii_digit() {
            while i < c.len() && glue(c[i]) {
                i += 1;
            }
            continue;
        }
        let start = i;
        while i < c.len() && (c[i].is_ascii_digit() || c[i] == ',') {
            i += 1;
        }
        let end = i;
        if i < c.len() && glue(c[i]) {
            while i < c.len() && glue(c[i]) {
                i += 1;
            }
            continue;
        }
        let digits: String = c[start..end]
            .iter()
            .filter(|ch| ch.is_ascii_digit())
            .collect();
        if let Ok(n) = digits.parse::<i64>() {
            out.push(n);
        }
    }
    out
}

fn parse_block(lines: &[(usize, &str)], fence_start: usize, out: &mut Extract) {
    let mut pend: Vec<String> = Vec::new();
    let mut pend_first: Option<usize> = None;
    let mut pend_expect: Vec<String> = Vec::new();
    let mut sq = false;
    let mut dq = false;
    let mut depth = 0i32;
    let mut heredocs: Vec<String> = Vec::new();
    let block_first_cmd = out.commands.len();

    for &(no, raw) in lines {
        let mut code_tail = String::new();
        if !heredocs.is_empty() {
            pend.push(raw.trim_end().to_string());
            if raw.trim() == heredocs[0] {
                heredocs.remove(0);
            }
            if !heredocs.is_empty() {
                continue;
            }
        } else {
            if pend.is_empty() && raw.trim().is_empty() {
                continue;
            }
            let (code, comment, nsq, ndq) = scan_line(raw, sq, dq);
            if pend.is_empty() && code.trim().is_empty() {
                // A standalone comment line. If it is an arrow it belongs to the command just
                // above it; if there is no command above it in this block it is an ORPHAN —
                // a printed expectation with nothing behind it.
                if let Some(p) = comment.as_deref().and_then(arrow_payload) {
                    if out.commands.len() > block_first_cmd {
                        out.commands.last_mut().expect("non-empty").expect.push(p);
                    } else {
                        out.orphans.push(Orphan {
                            line: no,
                            payload: p,
                        });
                    }
                }
                continue;
            }
            sq = nsq;
            dq = ndq;
            if pend_first.is_none() {
                pend_first = Some(no);
            }
            let kept = if comment.is_some() {
                code.trim_end().to_string()
            } else {
                raw.trim_end().to_string()
            };
            pend.push(kept);
            if let Some(p) = comment.as_deref().and_then(arrow_payload) {
                pend_expect.push(p);
            }
            code_tail = code.trim_end().to_string();
            let tags = heredoc_tags(&code_tail);
            if !tags.is_empty() {
                heredocs = tags;
                continue;
            }
            depth += depth_delta(&code_tail);
        }

        let incomplete =
            code_tail.ends_with('\\') || depth > 0 || sq || dq || ends_with_connector(&code_tail);
        if incomplete {
            continue;
        }
        out.commands.push(Cmd {
            line: pend_first.unwrap_or(no),
            block: fence_start,
            code: pend.join("\n"),
            expect: std::mem::take(&mut pend_expect),
        });
        pend.clear();
        pend_first = None;
        depth = 0;
        sq = false;
        dq = false;
    }
    if !pend.is_empty() {
        out.commands.push(Cmd {
            line: pend_first.unwrap_or(fence_start),
            block: fence_start,
            code: pend.join("\n"),
            expect: pend_expect,
        });
    }
}

fn ends_with_connector(code: &str) -> bool {
    let t = code.trim_end();
    t.ends_with("&&") || t.ends_with("||") || t.ends_with('|') || t.ends_with('&')
}

// ---------------------------------------------------------------------------------------------
// the safety screen
// ---------------------------------------------------------------------------------------------

/// Write targets a document's command may have without being refused.
const SAFE_WRITE_PREFIXES: &[&str] = &[
    "/tmp/",
    "/dev/null",
    "/dev/stdout",
    "/dev/stderr",
    "/var/folders/",
    "$TMPDIR",
];

/// Quote-aware redirect targets.
///
/// `awk 'NR>=120 && NR<=172'` has a `>` inside single quotes that is a COMPARISON, and reading it
/// as a redirect refused four live proofs on a target named `=120`.
fn redirect_targets(code: &str) -> Vec<String> {
    let c: Vec<char> = code.chars().collect();
    let mut out = Vec::new();
    let (mut sq, mut dq) = (false, false);
    let mut i = 0usize;
    while i < c.len() {
        let ch = c[i];
        if ch == '\\' && !sq {
            i += 2;
            continue;
        }
        if ch == '\'' && !dq {
            sq = !sq;
            i += 1;
            continue;
        }
        if ch == '"' && !sq {
            dq = !dq;
            i += 1;
            continue;
        }
        if ch == '>' && !sq && !dq {
            if i > 0 && "<>=!".contains(c[i - 1]) {
                i += 1;
                continue;
            }
            let mut j = i + 1;
            if j < c.len() && c[j] == '>' {
                j += 1;
            }
            if j < c.len() && c[j] == '=' {
                i = j + 1;
                continue;
            }
            while j < c.len() && (c[j] == ' ' || c[j] == '\t') {
                j += 1;
            }
            if j < c.len() && c[j] == '&' {
                i = j + 1;
                continue;
            }
            let start = j;
            while j < c.len() && !" \t|&;\n)".contains(c[j]) {
                j += 1;
            }
            if j > start {
                out.push(c[start..j].iter().collect());
            }
            i = j.max(i + 1);
            continue;
        }
        i += 1;
    }
    out
}

fn word_at(code: &str, word: &str) -> bool {
    code.split(|c: char| c.is_whitespace() || ";|&()".contains(c))
        .any(|t| t == word)
}

/// Whether `code` invokes `xtask` as a PROGRAM — in COMMAND POSITION, not as the path argument
/// `xtask/**` or the directory `xtask/`.
///
/// Matching the bare token refused four read-only proofs, including
/// `git grep -c -F -- 'todo!' HEAD -- 'xtask/**'`, which reads the tree and changes nothing.
fn invokes_xtask(code: &str) -> bool {
    for seg in code
        .split(['\n', ';'])
        .flat_map(|s| s.split("&&"))
        .flat_map(|s| s.split("||"))
    {
        for sub in seg.split('|') {
            let mut words = sub
                .split_whitespace()
                .map(|w| w.trim_matches(['\'', '"', '(', ')']))
                .filter(|w| !w.is_empty())
                // a leading `VAR=x` or `env` does not change which program runs
                .skip_while(|w| *w == "env" || (w.contains('=') && !w.starts_with('-')));
            let Some(head) = words.next() else { continue };
            if head == "xtask" || head.ends_with("/xtask") {
                return true;
            }
            if head == "cargo" && words.next() == Some("xtask") {
                return true;
            }
        }
    }
    false
}

/// Why this gate will not run `code`, or `None` if it will.
///
/// THE CORPUS REALLY DOES PRINT DESTRUCTIVE COMMANDS. `1.6.0-map-proof.md` §H prints
/// `grep '^#' scripts/no-deferral.waivers > scripts/no-deferral.waivers` (a truncation of a
/// tracked file), `cp /tmp/w.bak scripts/no-deferral.waivers` and `sed -i '' …`. Re-running a
/// proof must not perform the surgery the proof was describing.
pub fn refuse_reason(code: &str) -> Option<String> {
    let first_word = code
        .split_whitespace()
        .next()
        .unwrap_or("")
        .trim_matches(['\'', '"'])
        .to_string();
    if first_word == "$" {
        return Some("a transcript line (leading `$`), not a command".into());
    }
    for w in ["rm", "mv", "chmod", "chown", "ln", "truncate", "install"] {
        if word_at(code, w) {
            return Some(format!("`{w}` mutates the tree"));
        }
    }
    for w in ["exit", "exec", "kill", "trap", "shutdown", "reboot", "sudo"] {
        if word_at(code, w) {
            return Some(format!("`{w}` would end or hijack this gate's shell"));
        }
    }
    for w in ["curl", "wget", "ssh", "scp", "nc", "aws", "gh"] {
        if word_at(code, w) {
            return Some(format!("`{w}` reaches the network"));
        }
    }
    if code.contains("sed -i") {
        return Some("`sed -i` rewrites a tracked file".into());
    }
    if code.contains("set -e") {
        return Some("`set -e` would abort the whole document script".into());
    }
    for flag in ["--write", "--bless", "--record", "--accept", "--fix"] {
        if code.contains(flag) {
            return Some(format!("`{flag}` is a write flag"));
        }
    }
    if invokes_xtask(code) {
        return Some("invokes `xtask` — re-entering the gate runner inside a gate".into());
    }
    let toks: Vec<&str> = code
        .split(|c: char| c.is_whitespace() || ";|&()".contains(c))
        .collect();
    for (i, t) in toks.iter().enumerate() {
        if *t == "git" {
            if let Some(sub) = toks.get(i + 1) {
                if matches!(
                    *sub,
                    "checkout"
                        | "reset"
                        | "commit"
                        | "push"
                        | "apply"
                        | "stash"
                        | "clean"
                        | "rebase"
                        | "merge"
                        | "add"
                        | "restore"
                        | "switch"
                        | "cherry-pick"
                        | "config"
                        | "gc"
                        | "prune"
                        | "update-ref"
                        | "filter-branch"
                        | "tag"
                        | "branch"
                ) {
                    return Some(format!("`git {sub}` mutates the repository"));
                }
            }
        }
        if *t == "cargo" {
            if let Some(sub) = toks.get(i + 1) {
                if matches!(
                    *sub,
                    "build"
                        | "test"
                        | "run"
                        | "fix"
                        | "install"
                        | "update"
                        | "add"
                        | "remove"
                        | "publish"
                        | "clippy"
                        | "fmt"
                        | "bench"
                ) {
                    return Some(format!(
                        "`cargo {sub}` builds or writes, and blows this gate's wall clock"
                    ));
                }
            }
        }
        if *t == "cp" {
            if let Some(dest) = toks.iter().skip(i + 1).filter(|s| !s.is_empty()).nth(1) {
                if !SAFE_WRITE_PREFIXES.iter().any(|p| dest.starts_with(p)) {
                    return Some(format!("`cp` writes into the tree (`{dest}`)"));
                }
            }
        }
    }
    for t in redirect_targets(code) {
        if t.is_empty() {
            continue;
        }
        if SAFE_WRITE_PREFIXES.iter().any(|p| t.starts_with(p)) {
            continue;
        }
        return Some(format!("redirects outside /tmp, into `{t}`"));
    }
    None
}

// ---------------------------------------------------------------------------------------------
// expectations
// ---------------------------------------------------------------------------------------------

/// What a `# ->` payload asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expectation {
    /// A single integer, matched by the ladder in the module docs.
    Count(i64),
    /// `(empty)` — the command must print nothing.
    Empty,
    /// The command must FAIL: `does not exist`, `No such file or directory`, `absent`, `rc=1`.
    Absent,
    /// Prose. Not mechanically comparable.
    Freeform(String),
}

/// Classify one `# ->` payload.
///
/// `Count` requires the payload to lead with an integer AND to carry no SECOND figure outside a
/// parenthesis or a `NOT`/`<--` aside. `# -> 25, NOT 33` is one claim with its own bug named
/// beside it; `# -> 10 **RED**  7 **GREEN**  6 *not measured*  7 + 10 + 6 = 23` is four, and
/// pretending the leading 10 is "the" figure turns a narrative into a false red.
pub fn classify(payload: &str) -> Expectation {
    let first = payload.trim();
    let low = first.to_ascii_lowercase();
    if low.starts_with("(empty)")
        || low.starts_with("(no output)")
        || low == "empty"
        || low == "(none)"
        || low == "none"
        || low == "nothing"
    {
        return Expectation::Empty;
    }
    // A MIXED LIST IS NOT AN ABSENCE CLAIM. `# -> ABSENT · PRESENT · PRESENT` and
    // `# -> 016422be7… PRESENT   72c9c14d6… ABSENT` both name an absence AND a presence; reading
    // either as "this must fail" turned two correct proofs into false reds.
    let asserts_presence = low.contains("present") || low.contains("exists");
    if !asserts_presence {
        for probe in [
            "does not exist",
            "no such file",
            "not found",
            "absent",
            "rc=1",
            "rc=2",
            "rc=128",
        ] {
            if low.contains(probe) {
                return Expectation::Absent;
            }
        }
    }
    let lead = integers_in(first);
    let leads_with_int = first
        .split_whitespace()
        .next()
        .map(|t| !integers_in(t).is_empty() && t.chars().next().is_some_and(|c| c.is_ascii_digit()))
        .unwrap_or(false);
    if leads_with_int && !lead.is_empty() {
        let head = lead[0];
        // Everything after the aside markers is commentary about the figure, not another figure.
        let body = first
            .split("<--")
            .next()
            .unwrap_or(first)
            .split(" NOT ")
            .next()
            .unwrap_or(first)
            .split('(')
            .next()
            .unwrap_or(first);
        let body_ints = integers_in(body);
        if body_ints.len() <= 1 {
            return Expectation::Count(head);
        }
        return Expectation::Freeform(first.to_string());
    }
    Expectation::Freeform(first.to_string())
}

/// Which reading of `# -> N` matched, and what came back.
#[derive(Debug, Clone)]
pub struct Match {
    pub rule: &'static str,
    pub got: String,
    pub ok: bool,
}

/// The match ladder. See the module docs.
pub fn count_match(want: i64, out: &str, rc: i32) -> Match {
    let lines: Vec<&str> = out.lines().filter(|l| !l.trim().is_empty()).collect();
    if lines.len() == 1 {
        let t = lines[0].trim();
        if t.chars().next().is_some_and(|c| c.is_ascii_digit()) {
            if let Some(&n) = integers_in(t).first() {
                return Match {
                    rule: "leading-figure",
                    got: n.to_string(),
                    ok: n == want,
                };
            }
        }
    }
    let n_lines = lines.len() as i64;
    // A zero from an EMPTY stdout is only a line-count when the producer exited the way a
    // no-match `grep` does. Anything else exiting 0 lines is the false zero, not a measurement.
    if n_lines == want && !(want == 0 && !matches!(rc, 0 | 1)) {
        return Match {
            rule: "line-count",
            got: n_lines.to_string(),
            ok: true,
        };
    }
    let ints: BTreeSet<i64> = integers_in(out).into_iter().collect();
    if ints.len() == 1 {
        let only = *ints.iter().next().expect("len 1");
        return Match {
            rule: "sole-figure",
            got: only.to_string(),
            ok: only == want,
        };
    }
    if ints.contains(&want) && lines.len() <= FIGURE_PRESENT_MAX_LINES {
        return Match {
            rule: "figure-present",
            got: want.to_string(),
            ok: true,
        };
    }
    let sample: Vec<String> = ints.iter().take(8).map(i64::to_string).collect();
    Match {
        rule: "no-figure",
        got: format!("{} line(s), figures [{}]", n_lines, sample.join(" ")),
        ok: false,
    }
}

// ---------------------------------------------------------------------------------------------
// execution
// ---------------------------------------------------------------------------------------------

const MARK: &str = "__BBMAPPROOF";
/// Planted in a command's stderr when a clock, not the command, ended it.
const BUDGET_MARKER: &str = "__BBMAPPROOF_BUDGET__";

#[derive(Debug, Clone, Default)]
struct Exec {
    stdout: String,
    stderr: String,
    rc: i32,
}

/// stderr substrings that mean the command could not execute. Consulted BEFORE stdout.
pub const UNRUNNABLE_STDERR: &[&str] = &[
    "command not found",
    "fatal: invalid object name",
    "not a valid object name",
    "does not exist in",
    "exists on disk, but not in",
    "No such file or directory",
    "no such file or directory",
    "can't open file",
    "ModuleNotFoundError",
    "unknown revision",
    "fatal: bad object",
    "Permission denied",
    "not a git repository",
    "fatal: path",
    "Traceback (most recent call last)",
    "illegal option",
    "unrecognized option",
];

fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Simple `NAME=value` assignments, carried across a restart so a document's `F=…`/`PIN=…` survive
/// the command that blew its budget.
fn carried_assignment(code: &str) -> Option<String> {
    if code.contains('\n') {
        return None;
    }
    let (name, rest) = code.split_once('=')?;
    let name = name.trim();
    if name.is_empty()
        || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        || name.chars().next().is_some_and(|c| c.is_ascii_digit())
    {
        return None;
    }
    if rest.contains('`') || rest.contains("$(") {
        return None;
    }
    Some(code.trim().to_string())
}

fn script_for(cmds: &[(usize, String)], carry: &[String]) -> String {
    let mut s = String::from("set +e\n");
    for a in carry {
        s.push_str(a);
        s.push('\n');
    }
    for (i, code) in cmds {
        s.push_str(&format!(
            "printf '\\n{MARK}B {i}\\n'; printf '\\n{MARK}B {i}\\n' >&2\n"
        ));
        s.push_str("eval ");
        s.push_str(&shell_quote(code));
        s.push('\n');
        s.push_str(&format!(
            "__bbrc=$?; printf '\\n{MARK}E {i} %s\\n' \"$__bbrc\"; printf '\\n{MARK}E {i} %s\\n' \"$__bbrc\" >&2\n"
        ));
    }
    s
}

/// Run one bash script under TWO clocks, streaming both pipes so a kill never costs the output
/// already produced.
///
/// THE PER-COMMAND CLOCK IS THE IMPORTANT ONE. A single proof in this corpus —
/// `python3 scripts/public-hygiene-lint.py --root .` — takes 217 s of a measured 249 s total. A
/// whole-script budget spends itself on that one command and every proof after it reads as
/// "did not run", which is a gate that reports 158 unrunnable claims because of one slow script.
/// Timing each command from its own `BEGIN` marker costs that command its budget and nothing else.
///
/// Returns `(stdout, stderr, killed, stuck)` where `stuck` is the index of the command that was in
/// flight when a clock fired.
fn run_bash(
    root: &std::path::Path,
    script: &str,
    total: Duration,
    per_command: Duration,
) -> (String, String, bool, Option<usize>) {
    let mut child = match Command::new("bash")
        .arg("-c")
        .arg(script)
        .current_dir(root)
        .env("GIT_PAGER", "cat")
        .env("PAGER", "cat")
        .env("NO_COLOR", "1")
        .env("TERM", "dumb")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("BUSBAR_MAP_PROOF_GATE", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => return (String::new(), format!("bash: {e}"), true, None),
    };
    let (tx, rx) = mpsc::channel::<(u8, String)>();
    for (tag, pipe) in [
        (
            0u8,
            child
                .stdout
                .take()
                .map(|p| Box::new(p) as Box<dyn std::io::Read + Send>),
        ),
        (
            1u8,
            child
                .stderr
                .take()
                .map(|p| Box::new(p) as Box<dyn std::io::Read + Send>),
        ),
    ] {
        if let Some(p) = pipe {
            let tx = tx.clone();
            std::thread::spawn(move || {
                for line in BufReader::new(p).lines() {
                    let Ok(line) = line else { break };
                    if tx.send((tag, line)).is_err() {
                        break;
                    }
                }
            });
        }
    }
    drop(tx);
    let begin_tag = format!("{MARK}B ");
    let end_tag = format!("{MARK}E ");
    let hard_deadline = Instant::now() + total;
    let mut so = String::new();
    let mut se = String::new();
    let mut killed = false;
    let mut open: Option<(usize, Instant)> = None;
    let mut last_open: Option<usize> = None;
    loop {
        match rx.recv_timeout(Duration::from_millis(25)) {
            Ok((0, l)) => {
                if let Some(rest) = l.strip_prefix(&begin_tag) {
                    if let Ok(i) = rest.trim().parse::<usize>() {
                        open = Some((i, Instant::now()));
                        last_open = Some(i);
                    }
                } else if l.starts_with(&end_tag) {
                    open = None;
                }
                so.push_str(&l);
                so.push('\n');
            }
            Ok((_, l)) => {
                se.push_str(&l);
                se.push('\n');
            }
            Err(RecvTimeoutError::Disconnected) => break,
            Err(RecvTimeoutError::Timeout) => {}
        }
        let blown = open.is_some_and(|(_, at)| at.elapsed() > per_command);
        if blown || Instant::now() > hard_deadline {
            let _ = child.kill();
            killed = true;
            // Drain what the readers already hold; do NOT join them — a grandchild can still own
            // the pipe and a join here is the hang this budget exists to end.
            let drain_until = Instant::now() + Duration::from_millis(300);
            while Instant::now() < drain_until {
                match rx.recv_timeout(Duration::from_millis(25)) {
                    Ok((0, l)) => {
                        so.push_str(&l);
                        so.push('\n');
                    }
                    Ok((_, l)) => {
                        se.push_str(&l);
                        se.push('\n');
                    }
                    Err(RecvTimeoutError::Timeout) => {}
                    Err(RecvTimeoutError::Disconnected) => break,
                }
            }
            break;
        }
    }
    let _ = child.wait();
    let stuck = open.map(|(i, _)| i).or(last_open);
    (so, se, killed, stuck)
}

fn parse_marked(s: &str) -> BTreeMap<usize, (String, i32)> {
    let mut out = BTreeMap::new();
    let mut cur: Option<usize> = None;
    let mut buf = String::new();
    for line in s.lines() {
        if let Some(rest) = line.strip_prefix(&format!("{MARK}B ")) {
            cur = rest.trim().parse::<usize>().ok();
            buf.clear();
            continue;
        }
        if let Some(rest) = line.strip_prefix(&format!("{MARK}E ")) {
            let mut it = rest.split_whitespace();
            let idx = it.next().and_then(|s| s.parse::<usize>().ok());
            let rc = it.next().and_then(|s| s.parse::<i32>().ok()).unwrap_or(0);
            if let (Some(i), Some(c)) = (idx, cur) {
                if i == c {
                    out.insert(i, (std::mem::take(&mut buf), rc));
                }
            }
            cur = None;
            buf.clear();
            continue;
        }
        if cur.is_some() {
            buf.push_str(line);
            buf.push('\n');
        }
    }
    out
}

type ExecCache = Mutex<HashMap<String, Vec<Option<Exec>>>>;
fn cache() -> &'static ExecCache {
    static C: OnceLock<ExecCache> = OnceLock::new();
    C.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Run a document's commands in order, restarting past anything that blows the per-command budget.
///
/// One script per document rather than one per block, because the corpus's blocks are NOT
/// independent: §4.4a sets `F=docs/design/1.6.0-done-readout.md` in one block and reads `$F` two
/// blocks later, §E.5 writes `/tmp/wb` in one block and `comm`s it in the next. Running blocks in
/// isolation turned both into false zeros.
fn run_document(
    root: &std::path::Path,
    cmds: &[Cmd],
    refusals: &[Option<String>],
    deadline: Instant,
) -> Vec<Option<Exec>> {
    // Refused and ELIDED commands are not handed to bash. They are still SCORED — a command the
    // gate does not run is a verdict, never an absence from the census.
    let runnable: Vec<(usize, String)> = cmds
        .iter()
        .enumerate()
        .filter(|(i, c)| refusals[*i].is_none() && !is_elided(&c.code))
        .map(|(i, c)| (i, c.code.clone()))
        .collect();
    // THE CACHE KEY CARRIES THE COMMAND COUNT, not just the script. A plant that appends a
    // REFUSED command leaves the runnable script byte-identical while making the result vector one
    // element short, and the lookup then indexes past the end.
    let key = format!("{}\n#commands={}", script_for(&runnable, &[]), cmds.len());
    if let Some(hit) = cache().lock().ok().and_then(|c| c.get(&key).cloned()) {
        return hit;
    }

    let mut results: Vec<Option<Exec>> = vec![None; cmds.len()];
    let mut carry: Vec<String> = Vec::new();
    let mut start = 0usize;
    let mut restarts = 0usize;
    while start < runnable.len() && restarts <= MAX_RESTARTS && Instant::now() < deadline {
        let chunk = &runnable[start..];
        let left = deadline.saturating_duration_since(Instant::now());
        let script = script_for(chunk, &carry);
        let (so, se, killed, stuck) = run_bash(root, &script, left, PER_COMMAND_BUDGET);
        let outs = parse_marked(&so);
        let errs = parse_marked(&se);
        for (idx, (stdout, rc)) in &outs {
            results[*idx] = Some(Exec {
                stdout: stdout.clone(),
                stderr: errs.get(idx).map(|(s, _)| s.clone()).unwrap_or_default(),
                rc: *rc,
            });
        }
        if !killed {
            break;
        }
        // The command in flight when a clock fired is the one with a BEGIN and no END. It is
        // recorded as the budget-blower by NAME, never left to read as "did not run".
        let stuck = stuck.filter(|i| !outs.contains_key(i));
        let resume_at = match stuck {
            Some(i) => {
                results[i] = Some(Exec {
                    stdout: String::new(),
                    stderr: BUDGET_MARKER.to_string(),
                    rc: -1,
                });
                runnable
                    .iter()
                    .position(|(idx, _)| *idx == i)
                    .map(|p| p + 1)
                    .unwrap_or(runnable.len())
            }
            None => runnable.len(),
        };
        if resume_at <= start {
            break;
        }
        for (_, code) in &runnable[start..resume_at] {
            if let Some(a) = carried_assignment(code) {
                carry.push(a);
            }
        }
        start = resume_at;
        restarts += 1;
    }
    if let Ok(mut c) = cache().lock() {
        c.insert(key, results.clone());
    }
    results
}

// ---------------------------------------------------------------------------------------------
// verdicts
// ---------------------------------------------------------------------------------------------

/// The five outcomes. None of them is a skip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Reproduces { rule: &'static str, got: String },
    DoesNotReproduce { want: String, got: String },
    Unrunnable { why: String },
    Refused { why: String },
    Uncheckable { payload: String, got: String },
}

impl Verdict {
    pub fn tag(&self) -> &'static str {
        match self {
            Verdict::Reproduces { .. } => "REPRODUCES",
            Verdict::DoesNotReproduce { .. } => "DOES NOT REPRODUCE",
            Verdict::Unrunnable { .. } => "UNRUNNABLE",
            Verdict::Refused { .. } => "REFUSED",
            Verdict::Uncheckable { .. } => "UNCHECKABLE",
        }
    }
}

/// One scored proof: a command, the figure it printed, and what happened when it ran.
#[derive(Debug, Clone)]
pub struct Scored {
    pub doc: &'static str,
    pub slug: &'static str,
    pub line: usize,
    pub code: String,
    pub payload: String,
    pub verdict: Verdict,
}

impl Scored {
    fn one_line(&self) -> String {
        let code = self.code.replace('\n', " ");
        let code: String = code.split_whitespace().collect::<Vec<_>>().join(" ");
        let code = truncate(&code, 130);
        match &self.verdict {
            Verdict::DoesNotReproduce { want, got } => format!(
                "{}:{} the document prints {want}, the tree returns {got} — `{code}`",
                self.doc, self.line
            ),
            Verdict::Unrunnable { why } => {
                format!("{}:{} UNRUNNABLE ({why}) — `{code}`", self.doc, self.line)
            }
            Verdict::Refused { why } => {
                format!("{}:{} REFUSED ({why}) — `{code}`", self.doc, self.line)
            }
            Verdict::Uncheckable { payload, .. } => format!(
                "{}:{} `# -> {}` is prose, not a figure — `{code}`",
                self.doc,
                self.line,
                truncate(payload, 60),
            ),
            Verdict::Reproduces { rule, got } => {
                format!("{}:{} {got} via {rule} — `{code}`", self.doc, self.line)
            }
        }
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        return s.to_string();
    }
    let head: String = s.chars().take(n).collect();
    format!("{head}…")
}

/// The whole census.
#[derive(Debug, Default)]
pub struct Census {
    pub scored: Vec<Scored>,
    pub orphans: Vec<(&'static str, usize, String)>,
    /// `(doc, line, figure)` — a bold figure no `# ->` in that document produces.
    pub unbound_figures: Vec<(&'static str, usize, i64)>,
    pub bold_figures: usize,
    /// `(doc, commands, expectations)` per source, plus any read error.
    pub extraction: Vec<(&'static str, usize, usize, Option<String>)>,
}

impl Census {
    pub fn count(&self, f: impl Fn(&Verdict) -> bool) -> usize {
        self.scored.iter().filter(|s| f(&s.verdict)).count()
    }
}

/// Run the whole corpus and score it.
pub fn census(cx: &Ctx) -> Census {
    let mut out = Census::default();
    let deadline = Instant::now() + TOTAL_BUDGET;
    for src in CORPUS {
        let text = match cx.read(src.path) {
            Ok(t) => t,
            Err(e) => {
                out.extraction.push((src.path, 0, 0, Some(e)));
                continue;
            }
        };
        let ex = extract(&text);
        let n_expect = ex.commands.iter().filter(|c| !c.expect.is_empty()).count();
        out.extraction
            .push((src.path, ex.commands.len(), n_expect, None));
        for o in &ex.orphans {
            out.orphans.push((src.path, o.line, o.payload.clone()));
        }

        // A document's own bound figures: every integer any `# ->` in it asks for.
        let bound: BTreeSet<i64> = ex
            .commands
            .iter()
            .flat_map(|c| c.expect.iter())
            .chain(ex.orphans.iter().map(|o| &o.payload))
            .flat_map(|p| integers_in(p))
            .collect();
        out.bold_figures += ex.figures.len();
        for (line, n) in &ex.figures {
            if !bound.contains(n) {
                out.unbound_figures.push((src.path, *line, *n));
            }
        }

        // Only what the census needs is executed. Everything else the document prints carries no
        // figure, so it is not a claim — and running 290 tree-wide greps to learn nothing is how a
        // gate earns its ceiling.
        let keep = needed(&ex.commands);
        let cmds: Vec<Cmd> = ex
            .commands
            .iter()
            .enumerate()
            .filter(|(i, _)| keep[*i])
            .map(|(_, c)| c.clone())
            .collect();
        let refusals: Vec<Option<String>> = cmds.iter().map(|c| refuse_reason(&c.code)).collect();
        let execs = run_document(cx.root(), &cmds, &refusals, deadline);

        for (i, c) in cmds.iter().enumerate() {
            if c.expect.is_empty() {
                continue;
            }
            let payload = c.expect.join(" / ");
            let expectation = classify(&c.expect[0]);
            let verdict = score(
                &expectation,
                &c.code,
                refusals[i].as_deref(),
                execs.get(i).and_then(Option::as_ref),
            );
            out.scored.push(Scored {
                doc: src.path,
                slug: src.slug,
                line: c.line,
                code: c.code.clone(),
                payload,
                verdict,
            });
        }
    }
    out
}

/// Which commands must run for the census: the ones carrying a figure, every command earlier in
/// the same fenced block (a block's prelude), every simple assignment, and every command anywhere
/// that produces a file under `/tmp` (a later block's input).
fn needed(cmds: &[Cmd]) -> Vec<bool> {
    let mut keep = vec![false; cmds.len()];
    let scored_blocks: BTreeSet<usize> = cmds
        .iter()
        .filter(|c| !c.expect.is_empty())
        .map(|c| c.block)
        .collect();
    let last_scored = cmds.iter().rposition(|c| !c.expect.is_empty());
    let Some(last_scored) = last_scored else {
        return keep;
    };
    for (i, c) in cmds.iter().enumerate() {
        if i > last_scored {
            break;
        }
        if !c.expect.is_empty()
            || scored_blocks.contains(&c.block)
            || carried_assignment(&c.code).is_some()
            || redirect_targets(&c.code)
                .iter()
                .any(|t| t.starts_with("/tmp/"))
        {
            keep[i] = true;
        }
    }
    keep
}

/// A printed command with an ELISION in it cannot be re-run by anybody.
///
/// `git show ${N}:docs/design/BUSBAR-1.6.0.md | grep -cE '…same…'` is a sketch of a command. It
/// EXECUTES — `grep` finds no line containing a literal `…same…` and prints `0` — so left alone it
/// reads as a figure that moved from 83 to 0. It is not a measurement at all, and saying so is a
/// different and more useful finding.
fn is_elided(code: &str) -> bool {
    code.contains('\u{2026}')
}

fn score(
    expectation: &Expectation,
    code: &str,
    refused: Option<&str>,
    exec: Option<&Exec>,
) -> Verdict {
    // THE NOTATION IS JUDGED BEFORE THE RUN. A prose `# ->` is unchecked whatever the command did,
    // and reporting it as "unrunnable" would file a document defect under the instrument's row.
    if let Expectation::Freeform(p) = expectation {
        return Verdict::Uncheckable {
            payload: p.clone(),
            got: exec
                .map(|e| truncate(e.stdout.trim(), 90))
                .unwrap_or_else(|| "(not run)".into()),
        };
    }
    if is_elided(code) {
        return Verdict::Unrunnable {
            why: "the printed command contains an elision (`\u{2026}`) — it is a sketch of a \
                  command, not one anybody can re-run"
                .into(),
        };
    }
    if let Some(why) = refused {
        return Verdict::Refused {
            why: why.to_string(),
        };
    }
    let Some(e) = exec else {
        return Verdict::Unrunnable {
            why: "the document's script did not reach this command inside the gate's wall clock"
                .into(),
        };
    };
    if e.stderr.contains(BUDGET_MARKER) {
        return Verdict::Unrunnable {
            why: format!(
                "exceeded this gate's per-command budget of {} s",
                PER_COMMAND_BUDGET.as_secs()
            ),
        };
    }
    let first_err = e
        .stderr
        .lines()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("");
    if e.stderr.contains("syntax error") && matches!(e.rc, 1 | 2) {
        return Verdict::Unrunnable {
            why: "not a shell command — bash reports a syntax error, i.e. this fenced line is \
                  pasted OUTPUT, not a command"
                .into(),
        };
    }
    if !matches!(expectation, Expectation::Absent) {
        if e.rc == 127 {
            return Verdict::Unrunnable {
                why: truncate(first_err, 140),
            };
        }
        if UNRUNNABLE_STDERR.iter().any(|p| e.stderr.contains(p)) {
            // THE FALSE ZERO: `git show <dead-pin>:x | grep -c y` prints 0 and exits 0. stdout is
            // consulted only after stderr says the pipeline had a head to begin with.
            return Verdict::Unrunnable {
                why: truncate(first_err, 140),
            };
        }
    }
    match expectation {
        Expectation::Count(want) => {
            let m = count_match(*want, &e.stdout, e.rc);
            if m.ok {
                Verdict::Reproduces {
                    rule: m.rule,
                    got: m.got,
                }
            } else {
                Verdict::DoesNotReproduce {
                    want: want.to_string(),
                    got: format!("{} (by {})", m.got, m.rule),
                }
            }
        }
        Expectation::Empty => {
            if e.stdout.trim().is_empty() {
                Verdict::Reproduces {
                    rule: "empty",
                    got: "(empty)".into(),
                }
            } else {
                Verdict::DoesNotReproduce {
                    want: "(empty)".into(),
                    got: truncate(e.stdout.trim(), 90),
                }
            }
        }
        Expectation::Absent => {
            let by_status = e.rc != 0;
            let by_printed_rc = e
                .stdout
                .split(|c: char| !c.is_ascii_alphanumeric() && c != '=')
                .any(|t| t.starts_with("rc=") && t != "rc=0");
            // `for f in …; do git cat-file -e … && echo PRESENT || echo ABSENT; done` exits 0
            // because `echo` succeeded. The absence it proves is in the OUTPUT, and it counts only
            // when EVERY line carries it — a loop printing one PRESENT among three ABSENTs has not
            // reproduced "all three ABSENT".
            let lines: Vec<&str> = e.stdout.lines().filter(|l| !l.trim().is_empty()).collect();
            let by_output = !lines.is_empty()
                && lines.iter().all(|l| {
                    let low = l.to_ascii_lowercase();
                    ABSENCE_WORDS.iter().any(|w| low.contains(w))
                });
            if by_status || by_printed_rc || by_output {
                Verdict::Reproduces {
                    rule: if by_status {
                        "absent-by-status"
                    } else {
                        "absent-by-output"
                    },
                    got: format!("rc={}", e.rc),
                }
            } else {
                Verdict::DoesNotReproduce {
                    want: "an absence".into(),
                    got: format!(
                        "rc=0 and nothing says absent: {}",
                        truncate(e.stdout.trim(), 70)
                    ),
                }
            }
        }
        Expectation::Freeform(_) => unreachable!("handled above"),
    }
}

/// The words a command prints when the thing it looked for is not there.
const ABSENCE_WORDS: &[&str] = &[
    "absent",
    "no such file",
    "does not exist",
    "not found",
    "missing",
];

// ---------------------------------------------------------------------------------------------
// the gate
// ---------------------------------------------------------------------------------------------

fn listing(items: &[String], cap: usize) -> String {
    if items.is_empty() {
        return "none".into();
    }
    let shown: Vec<String> = items.iter().take(cap).cloned().collect();
    if items.len() > cap {
        format!("{} … (+{} more)", shown.join("; "), items.len() - cap)
    } else {
        shown.join("; ")
    }
}

pub struct MapProofGate;

impl MapProofGate {
    fn rows(cx: &Ctx) -> Vec<Row> {
        let c = census(cx);
        let mut rows = Vec::new();

        // --- extraction ----------------------------------------------------------------------
        let mut short = Vec::new();
        let mut total_expect = 0usize;
        for src in CORPUS {
            let found = c.extraction.iter().find(|(p, ..)| *p == src.path);
            match found {
                None => short.push(format!("{}: not measured at all", src.path)),
                Some((_, _, _, Some(err))) => {
                    short.push(format!("{}: unreadable — {err}", src.path))
                }
                Some((_, cmds, exps, None)) => {
                    total_expect += *exps;
                    if *cmds < src.floor_commands {
                        short.push(format!(
                            "{}: {cmds} fenced command(s), floor {}",
                            src.path, src.floor_commands
                        ));
                    }
                    if *exps < src.floor_expectations {
                        short.push(format!(
                            "{}: {exps} bound expectation(s), floor {}",
                            src.path, src.floor_expectations
                        ));
                    }
                }
            }
        }
        if total_expect < CORPUS_EXPECTATION_FLOOR {
            short.push(format!(
                "corpus-wide: {total_expect} bound expectation(s), floor {CORPUS_EXPECTATION_FLOOR}"
            ));
        }
        rows.push(if short.is_empty() {
            Row::pass(
                ROW_EXTRACTION,
                "the extractor reached every map-corpus document",
                format!(
                    "{} document(s), {} fenced command(s), {total_expect} bound `# ->` \
                     expectation(s); every per-document floor met",
                    CORPUS.len(),
                    c.extraction.iter().map(|(_, n, ..)| n).sum::<usize>()
                ),
            )
        } else {
            Row::fail(
                ROW_EXTRACTION,
                "the map-proof extractor came back short — a parser that matches nothing reads \
                 exactly like a corpus that reproduces",
                listing(&short, 8),
            )
        });

        // --- bound ---------------------------------------------------------------------------
        let orphans: Vec<String> = c
            .orphans
            .iter()
            .map(|(d, l, p)| {
                format!(
                    "{d}:{l} `# -> {}` with no command above it",
                    truncate(p, 50)
                )
            })
            .collect();
        let unbound: Vec<String> = c
            .unbound_figures
            .iter()
            .map(|(d, l, n)| format!("{d}:{l} **{n}**"))
            .collect();
        let bound_detail = format!(
            "{} bold figure(s) printed across the corpus; {} have no `# ->` command that \
             produces them; {} orphan arrow(s). Unbound: {}",
            c.bold_figures,
            c.unbound_figures.len(),
            c.orphans.len(),
            listing(&unbound, 6)
        );
        rows.push(if orphans.is_empty() {
            Row::pass(
                ROW_BOUND,
                "every `# ->` in the corpus is attached to a command",
                bound_detail,
            )
        } else {
            Row::fail(
                ROW_BOUND,
                "a `# ->` expectation is printed with no command behind it",
                format!("{} — {bound_detail}", listing(&orphans, 6)),
            )
        });

        // --- runnable / unrefused / countable -------------------------------------------------
        for (id, title, pass_title, pick) in [
            (
                ROW_RUNNABLE,
                "a bound command could not execute — an unrunnable proof is an unproven claim",
                "every bound command executed",
                0u8,
            ),
            (
                ROW_UNREFUSED,
                "this gate refused to run a bound command — the claim behind it is unverified",
                "no bound command was refused by the safety screen",
                1,
            ),
            (
                ROW_COUNTABLE,
                "a `# ->` payload is prose this gate cannot compare — the figure beside it is \
                 unchecked",
                "every `# ->` payload is in the machine-checkable convention",
                2,
            ),
        ] {
            let hits: Vec<String> = c
                .scored
                .iter()
                .filter(|s| {
                    matches!(
                        (pick, &s.verdict),
                        (0, Verdict::Unrunnable { .. })
                            | (1, Verdict::Refused { .. })
                            | (2, Verdict::Uncheckable { .. })
                    )
                })
                .map(Scored::one_line)
                .collect();
            rows.push(if hits.is_empty() {
                Row::pass(
                    id,
                    pass_title,
                    format!("{} bound command(s) scored", c.scored.len()),
                )
            } else {
                Row::fail(
                    id,
                    title,
                    format!(
                        "{} of {}: {}",
                        hits.len(),
                        c.scored.len(),
                        listing(&hits, 6)
                    ),
                )
            });
        }

        // --- reproduces, per document ---------------------------------------------------------
        // Sharded by document on purpose. The corpus-wide claim is the conjunction of these, and
        // a document that is clean is a row that can be driven GREEN -> RED by a plant — which is
        // the only way `prove_red` accepts a proof. A single global row would be red on arrival
        // and every plant against it would honestly report `Impossible`.
        for src in CORPUS {
            let mine: Vec<&Scored> = c.scored.iter().filter(|s| s.slug == src.slug).collect();
            let bad: Vec<String> = mine
                .iter()
                .filter(|s| matches!(s.verdict, Verdict::DoesNotReproduce { .. }))
                .map(|s| s.one_line())
                .collect();
            let good = mine
                .iter()
                .filter(|s| matches!(s.verdict, Verdict::Reproduces { .. }))
                .count();
            let checkable = mine
                .iter()
                .filter(|s| !matches!(s.verdict, Verdict::Uncheckable { .. }))
                .count();
            let id = row_reproduces(src.slug);
            // VACUITY IS NOT A PASS. A document whose every command was unrunnable has proven
            // nothing, and "no figure failed" is exactly what that looks like from here. It is
            // checked AFTER the real finding: a document with one failing figure and nothing else
            // must report the figure, not the vacuity.
            if bad.is_empty() && checkable > 0 && good == 0 {
                rows.push(Row::fail(
                    id,
                    format!("not one figure in {} was re-derived", src.slug),
                    format!(
                        "{checkable} checkable expectation(s) and {good} re-derived — this row is \
                         vacuous, not clean; see map-proof:runnable and map-proof:unrefused"
                    ),
                ));
                continue;
            }
            rows.push(if bad.is_empty() {
                Row::pass(
                    id,
                    format!("every checkable figure in {} reproduces", src.slug),
                    format!(
                        "{good} of {} bound expectation(s) re-derived against this tree",
                        mine.len()
                    ),
                )
            } else {
                Row::fail(
                    id,
                    format!("a printed figure in {} does not reproduce", src.slug),
                    format!(
                        "{} of {} do not reproduce ({good} do): {}",
                        bad.len(),
                        mine.len(),
                        listing(&bad, 8)
                    ),
                )
            });
        }
        rows
    }
}

impl Gate for MapProofGate {
    fn name(&self) -> &'static str {
        "map-proof"
    }

    fn owed(&self) -> Vec<String> {
        let mut v = vec![
            ROW_EXTRACTION.to_string(),
            ROW_BOUND.to_string(),
            ROW_RUNNABLE.to_string(),
            ROW_UNREFUSED.to_string(),
            ROW_COUNTABLE.to_string(),
        ];
        v.extend(CORPUS.iter().map(|s| row_reproduces(s.slug)));
        v
    }

    fn run(&self, cx: &Ctx) -> GateVerdict {
        GateVerdict::of(MapProofGate::rows(cx))
    }

    fn selftest<'a>(&'a self, cx: &'a Ctx) -> Report<'a> {
        let mut report = Report::new();
        let c = census(cx);

        // THE GREEN ARM IS NARROWED, and it has to be. `prove_green` asks whether the WHOLE gate
        // is green, and this gate is red on arrival because the corpus it measures is red — which
        // is the finding, not a defect in the instrument. So the green arm plants a CLEAN corpus
        // document into the cheapest slot and asks only about that document's row.
        //
        // IT IS ALSO THE NEGATIVE CONTROL. A gate that reds on everything would satisfy every red
        // arm below; this one shows a correct command carrying a correct number coming back
        // REPRODUCES in the same instrument.
        let target = cheap_target();
        let mut clean = Overlay::new();
        clean.set(target.path, CLEAN_FIXTURE);
        report.push(prove_rows_green(
            cx,
            self,
            "a correct command with a correct number REPRODUCES",
            &[&row_reproduces(target.slug)],
            clean,
        ));

        // RED, per document: A PRINTED FIGURE THAT DOES NOT REPRODUCE, named with BOTH numbers.
        //
        // Wherever the document already has a figure that re-derives, the plant changes THAT
        // figure and nothing else — the command stays exactly as the document wrote it, so the
        // planted red is "the document now claims a number the tree does not return" and nothing
        // more. It also leaves the executed script byte-identical, so the plant costs a cache
        // lookup rather than a re-run of the corpus.
        // A document with NO re-deriving figure of its own (one that prints no commands, or
        // whose commands all failed) still owes a red case, or its row could be deleted with the
        // battery still green. There the plant appends a figure that cannot come back.
        let plants: Vec<(&Source, String)> = CORPUS
            .iter()
            .map(|src| {
                let text = plant_wrong_figure(cx, &c, src).unwrap_or_else(|| {
                    let base = cx.read(src.path).unwrap_or_default();
                    format!("{base}\n\n```sh\necho 7   # -> 987654\n```\n")
                });
                (src, text)
            })
            .collect();
        for (src, text) in &plants {
            let mut ov = Overlay::new();
            ov.set(src.path, text.clone());
            report.push(prove_red(
                cx,
                self,
                format!(
                    "a figure in {} that does not reproduce is named with both numbers",
                    src.slug
                ),
                &[&row_reproduces(src.slug)],
                ov,
                &["does not reproduce"],
            ));
        }

        // RED — AN UNRUNNABLE PROOF. A pin that no longer resolves is a verdict of its own, never
        // a silent skip and never the `0` its dead pipeline prints.
        report.push(prove_red(
            cx,
            self,
            "a command whose pin no longer resolves is UNRUNNABLE, not the zero its dead pipeline \
             prints",
            &[ROW_RUNNABLE],
            appended(
                cx,
                target,
                "git show deadbeefdeadbeefdeadbeefdeadbeefdeadbeef:docs/design/gone.md \
                 | grep -c x   # -> 3",
            ),
            &["UNRUNNABLE"],
        ));

        // RED — AN ORPHAN ARROW: a printed expectation with no command behind it.
        report.push(prove_red(
            cx,
            self,
            "an expectation printed with no command behind it is caught",
            &[ROW_BOUND],
            {
                let text = cx.read(target.path).unwrap_or_default();
                let mut ov = Overlay::new();
                ov.set(target.path, format!("{text}\n\n```sh\n# -> 4242\n```\n"));
                ov
            },
            &["no command above it"],
        ));

        // RED — THE FALSE ZERO IN THE INSTRUMENT ITSELF. A corpus document the extractor comes
        // back empty on is a broken extractor, not a clean document.
        report.push(prove_red(
            cx,
            self,
            "a corpus document that yields no commands is a broken extractor, not a clean doc",
            &[ROW_EXTRACTION],
            {
                let mut ov = Overlay::new();
                ov.set(target.path, "# nothing here\n");
                ov
            },
            &["floor"],
        ));

        // RED — A REFUSED COMMAND. The instrument declining is its own verdict.
        report.push(prove_red(
            cx,
            self,
            "a command the safety screen refuses is reported, never skipped",
            &[ROW_UNREFUSED],
            appended(cx, target, "rm -rf /tmp/map-proof-probe   # -> 1"),
            &["REFUSED"],
        ));

        // RED — A PROSE EXPECTATION. A figure bound by prose is a figure nobody checked.
        report.push(prove_red(
            cx,
            self,
            "a `# ->` payload that is prose is reported as unchecked",
            &[ROW_COUNTABLE],
            appended(
                cx,
                target,
                "echo hello   # -> roughly what you would expect",
            ),
            &["prose"],
        ));

        report
    }
}

/// A corpus document with two commands and two figures, both of which re-derive on any tree. The
/// green arm's fixture, and the gate's own proof that it can say YES.
const CLEAN_FIXTURE: &str = "\
# a synthetic map-corpus document

```sh
echo 7                                     # -> 7
printf 'a\nb\nc\n'                        # -> 3
ls /nonexistent-map-proof-probe 2>/dev/null   # -> (empty)
```
";

/// The corpus document a plant should use when it only needs SOME document: the cheapest one to
/// re-run, because every plant that changes a document's command set pays for that document's
/// commands again.
fn cheap_target() -> &'static Source {
    CORPUS
        .iter()
        .min_by_key(|s| s.floor_commands)
        .unwrap_or(&CORPUS[0])
}

/// `target`'s real text with one extra fenced block holding `command`.
fn appended(cx: &Ctx, target: &'static Source, command: &str) -> Overlay {
    let text = cx.read(target.path).unwrap_or_default();
    let mut ov = Overlay::new();
    ov.set(target.path, format!("{text}\n\n```sh\n{command}\n```\n"));
    ov
}

/// `src`'s text with the FIRST figure that currently re-derives changed to one the tree cannot
/// return, or `None` when the document has no re-deriving figure to spoil.
///
/// Only the expected value moves. The command is left byte-identical, which is what makes the
/// planted run a question about the DOCUMENT rather than about a different command — and what
/// keeps the plant inside the executed-script cache.
fn plant_wrong_figure(cx: &Ctx, c: &Census, src: &'static Source) -> Option<String> {
    let good = c
        .scored
        .iter()
        .find(|s| s.slug == src.slug && matches!(s.verdict, Verdict::Reproduces { .. }))?;
    let text = cx.read(src.path).ok()?;
    let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
    // The arrow sits on the command's own line or on one of the lines just below it.
    for off in 0..8usize {
        let idx = good.line.checked_sub(1)? + off;
        let l = lines.get(idx)?;
        if let Some(pos) = l.find("# ->") {
            let head = l[..pos].to_string();
            lines[idx] = format!("{head}# -> 987654");
            return Some(lines.join("\n"));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_hash_inside_single_quotes_is_not_a_comment() {
        let (code, comment, ..) = scan_line("grep -cE '^#{2,3} ' f   # -> 21", false, false);
        assert_eq!(code.trim(), "grep -cE '^#{2,3} ' f");
        assert_eq!(
            arrow_payload(&comment.expect("a comment")).as_deref(),
            Some("21")
        );
    }

    #[test]
    fn a_quote_opened_on_an_earlier_line_carries_over() {
        // `python3 -c "` … `"   # -> […]` — the `#` is a comment only because the quote closed.
        let (_, c1, sq, dq) = scan_line("python3 -c \"", false, false);
        assert!(c1.is_none() && !sq && dq);
        let (_, c2, _, dq2) = scan_line("\"   # -> []", sq, dq);
        assert!(!dq2);
        assert_eq!(
            arrow_payload(&c2.expect("a comment")).as_deref(),
            Some("[]")
        );
    }

    #[test]
    fn done_inside_a_filename_does_not_close_a_loop() {
        // The bug: `1.6.0-done-readout.md` closed the `for` and split one command into three.
        assert_eq!(
            depth_delta("for f in 1.6.0-done-readout.md 1.6.0-gate-sweep.md; do"),
            1
        );
        assert_eq!(depth_delta("done"), -1);
    }

    #[test]
    fn a_short_sha_is_not_an_integer() {
        assert!(integers_in("5fa320208 W4.b P2").is_empty());
        assert!(integers_in("45104e7f7 2026-09-22").is_empty());
        assert_eq!(integers_in("2,444 owed rows"), vec![2444]);
    }

    #[test]
    fn a_comparison_is_not_a_redirect() {
        assert!(redirect_targets("awk 'NR>=120 && NR<=172' f | grep -cE '^\\|'").is_empty());
        assert_eq!(
            redirect_targets("git show a7cceac3f:docs/x.md > /tmp/ia.md"),
            vec!["/tmp/ia.md".to_string()]
        );
        assert_eq!(
            redirect_targets("grep '^#' scripts/w > scripts/w"),
            vec!["scripts/w".to_string()]
        );
    }

    #[test]
    fn the_safety_screen_catches_the_corpus_own_destructive_commands() {
        assert!(refuse_reason(
            "grep '^#' scripts/no-deferral.waivers > scripts/no-deferral.waivers"
        )
        .is_some());
        assert!(refuse_reason("cp /tmp/w.bak scripts/no-deferral.waivers").is_some());
        assert!(
            refuse_reason("sed -i '' 's|a|b|' scripts/w && cargo xtask gate no-deferral").is_some()
        );
        assert!(refuse_reason("cargo test -p busbar --test net_guard_one_judge").is_some());
        assert!(refuse_reason("./target/debug/xtask gate ship-ready").is_some());
        // …and lets the read-only ones through, including paths that merely CONTAIN `xtask`.
        assert!(refuse_reason("git grep -c -F -- 'todo!' HEAD -- 'xtask/**'").is_none());
        assert!(
            refuse_reason("grep -rn 'METADATA_HOSTS' --include='*.rs' crates/ xtask/").is_none()
        );
        assert!(refuse_reason("git show 016422be7:docs/design/x.md | grep -cE '^## '").is_none());
        assert!(refuse_reason("awk 'NR>=120 && NR<=172' f | grep -cE '^\\|'").is_none());
    }

    #[test]
    fn classification_separates_a_figure_from_a_narrative() {
        assert_eq!(classify("21"), Expectation::Count(21));
        assert_eq!(classify("5 struck"), Expectation::Count(5));
        assert_eq!(classify("25, NOT 33"), Expectation::Count(25));
        assert_eq!(classify("44  <-- the bug"), Expectation::Count(44));
        assert_eq!(
            classify("21   (the document says 21)"),
            Expectation::Count(21)
        );
        assert_eq!(classify("(empty)"), Expectation::Empty);
        assert_eq!(classify("does not exist"), Expectation::Absent);
        assert_eq!(classify("No such file or directory"), Expectation::Absent);
        // four figures in one narrative payload: not one claim, so not a countable one
        assert!(matches!(
            classify("10 **RED**   7 **GREEN**   6 *not measured*  7 + 10 + 6 = 23"),
            Expectation::Freeform(_)
        ));
        assert!(matches!(
            classify("22/22 named, 0 MISSED"),
            Expectation::Freeform(_)
        ));
        assert!(matches!(
            classify("5fa320208 W4.b P2"),
            Expectation::Freeform(_)
        ));
    }

    #[test]
    fn the_match_ladder_names_which_reading_matched() {
        assert_eq!(count_match(23, "23\n", 0).rule, "leading-figure");
        assert!(count_match(23, "23\n", 0).ok);
        assert!(!count_match(23, "28\n", 0).ok);
        assert_eq!(
            count_match(23, "DONE_GROUPS_DECLARED=23\n", 0).rule,
            "sole-figure"
        );
        assert!(count_match(2, "a.rs:1:x\nb.rs:2:y\n", 0).ok);
        let m = count_match(10, "   7 GREEN\n  10 RED\n   6 blank\n", 0);
        assert_eq!(m.rule, "figure-present");
        assert!(m.ok);
        // a 0 from a pipeline whose head died is not a line-count
        assert!(!count_match(0, "", 128).ok);
        assert!(count_match(0, "", 1).ok);
    }

    #[test]
    fn a_whole_block_is_one_command_when_it_is_one_command() {
        let doc = "\
```sh
for f in 1.6.0-done-readout.md 1.6.0-gate-sweep.md; do
  git cat-file -e PIN:docs/design/$f 2>/dev/null && echo P || echo A
done
# -> all three ABSENT
F=docs/design/x.md
awk '/^## T/{f=1} f' $F | grep -cE '^\\| [0-9]+ \\|'   # -> 23
```
";
        let ex = extract(doc);
        assert_eq!(ex.commands.len(), 3, "{:?}", ex.commands);
        assert!(ex.commands[0].code.contains("done"));
        assert_eq!(ex.commands[0].expect, vec!["all three ABSENT".to_string()]);
        assert_eq!(ex.commands[1].code, "F=docs/design/x.md");
        assert_eq!(ex.commands[2].expect, vec!["23".to_string()]);
        assert!(ex.orphans.is_empty());
    }

    #[test]
    fn an_arrow_with_no_command_above_it_is_an_orphan() {
        let ex = extract("```sh\n# -> 4242\n```\n");
        assert_eq!(ex.orphans.len(), 1);
        assert_eq!(ex.orphans[0].payload, "4242");
    }

    #[test]
    fn a_heredoc_body_is_not_a_command_list() {
        let doc =
            "```sh\npython3 - <<'PY'\nimport json\nprint(1)\nPY\nwc -l < /tmp/x   # -> 7\n```\n";
        let ex = extract(doc);
        assert_eq!(ex.commands.len(), 2, "{:?}", ex.commands);
        assert!(ex.commands[0].code.contains("import json"));
        assert_eq!(ex.commands[1].expect, vec!["7".to_string()]);
    }

    /// THE FALSIFICATION, END TO END, AGAINST THE REAL CORPUS.
    ///
    /// Ignored by default because it runs the whole corpus twice (~90 s) and the battery's
    /// `prove_red` arms are the gating proof. Run it by name when the question is "does this gate
    /// actually print both numbers and the command":
    /// `cargo test -p xtask --lib map_proof -- --ignored --nocapture`.
    #[test]
    #[ignore = "runs the whole corpus twice; xtask gate map-proof --selftest is the gating proof"]
    fn a_planted_wrong_figure_is_reported_with_both_numbers() {
        let cx = Ctx::workspace().expect("workspace");
        let base = census(&cx);
        // The target is a document whose row is GREEN as the tree stands, so the planted red can
        // only be the plant's.
        // …and of those, the one with the MOST re-deriving figures, so the same run shows the
        // largest possible set of correct figures still passing beside the planted one.
        let mut green: Vec<&Source> = CORPUS
            .iter()
            .filter(|s| {
                !base.scored.iter().any(|r| {
                    r.slug == s.slug && matches!(r.verdict, Verdict::DoesNotReproduce { .. })
                })
            })
            .collect();
        green.sort_by_key(|s| {
            std::cmp::Reverse(
                base.scored
                    .iter()
                    .filter(|r| r.slug == s.slug && matches!(r.verdict, Verdict::Reproduces { .. }))
                    .count(),
            )
        });
        let (src, planted) = green
            .into_iter()
            .find_map(|s| plant_wrong_figure(&cx, &base, s).map(|t| (s, t)))
            .expect("some corpus document has a figure that re-derives");

        let id = row_reproduces(src.slug);
        let before = MapProofGate::rows(&cx);
        let before = before.iter().find(|r| r.id == id).expect("the row");
        assert_eq!(
            before.status,
            crate::ledger::Status::Pass,
            "{id} must be GREEN before the plant, or the planted red is not the plant's: {}",
            before.detail
        );

        let mut ov = Overlay::new();
        ov.set(src.path, planted);
        let after = MapProofGate::rows(&cx.with_overlay(ov));
        let after = after.iter().find(|r| r.id == id).expect("the row");
        println!(
            "PLANTED ROW: {} | {} | {}",
            after.id, after.title, after.detail
        );
        assert_eq!(
            after.status,
            crate::ledger::Status::Fail,
            "the plant must go RED"
        );
        assert!(
            after.detail.contains("the document prints 987654"),
            "the row must print the number the DOCUMENT claims: {}",
            after.detail
        );
        assert!(
            after.detail.contains("the tree returns"),
            "the row must print the number the TREE returned: {}",
            after.detail
        );
        // THE NEGATIVE CONTROL, IN THE SAME RUN: the document's other figures still re-derive, so
        // this is a gate that discriminates rather than one that reds on everything.
        assert!(
            after.detail.contains(" do): "),
            "the row must say how many figures still reproduce beside the planted one: {}",
            after.detail
        );
    }

    #[test]
    fn a_bold_figure_is_a_printed_figure_and_a_fenced_one_is_not() {
        let ex = extract("rows **76** and **2,444** owed\n```sh\necho **99**\n```\n");
        let ns: Vec<i64> = ex.figures.iter().map(|(_, n)| *n).collect();
        assert_eq!(ns, vec![76, 2444]);
    }
}
