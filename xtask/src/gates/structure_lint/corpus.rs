//! THE DENOMINATOR, AND THE THREE GENERIC SCANNERS EVERY TABLE IS DRIVEN THROUGH.
//!
//! ## The floor
//!
//! Almost every rule below this one is a BAN over one file list, and a ban over an EMPTY list
//! matches nothing, prints nothing, and reads exactly like a clean tree. The list goes empty
//! whenever the gate is run from the wrong place, after a layout move, or in a checkout where
//! `crates/` was never fetched — all of them silent. The count is the only thing that can tell a
//! clean tree from an unread one, so it is checked, and [`CANDIDATE_FLOOR`] is a `const` with NO
//! environment override: the only way to lower a floor is a reviewable source edit.
//!
//! ## The candidate set
//!
//! Every `crates/**/*.rs` outside a `tests/` or `benches/` directory. `benches/` is excluded for
//! the same reason `tests/` is and not as a convenience: a criterion bench is harness code that
//! drives the primitives directly, writes its own fixture directories and is never compiled into
//! the shipped artifact, so holding it to the choke-point registry would report a bench's
//! `create_dir_all` of a temp fixture as a durability bypass — the lint being right about a pattern
//! and wrong about the file.
//!
//! TEST FILES ARE NOT PRODUCTION BY NAME OR BY DECLARATION, and the second half is the one a path
//! filter misses. `#[cfg(test)] mod tests;` puts a module in `tests.rs`, which sits in no `tests/`
//! directory; `#[cfg(test)] #[path = "voice_d2_billing_oracle.rs"] mod …;` names a file whose path
//! says nothing about test at all; `#[cfg(any(test, feature = "test-support"))] pub mod testkit;`
//! is a whole directory of doubles. While this lint's tree-wide scope was seven prefixes none of
//! them happened to sit in it. Once the scope became every crate (items 183, 224) a test double's
//! `fn serves` in the voice runtime's `tests.rs` was counted as a second trust decision — the
//! lint right about the pattern and wrong about the file. [`test_scoped`] answers both halves, and
//! the tree-wide rules read [`Corpus::production_in_scope`]; the inline-test and choke-point rules
//! read the candidate set unchanged.
//!
//! ## The scanners
//!
//! Three, matching the shell's three, each reading [`crate::scan::test_scope`] and nothing else so
//! this gate can never disagree with itself about what test code is:
//!
//! * [`Corpus::scan_rule`] — the pattern ban. Skips `#[cfg(test)]`-gated lines and whole-line
//!   comments, then matches the rule's ERE against the RAW line (prose may name a banned call; code
//!   may not).
//! * [`scan_fn_body`] — the same question asked of ONE NAMED FUNCTION's body, by brace depth,
//!   because `GovState::try_admit` may not touch the store while `flush_durable` two functions down
//!   exists to. It reads the CODE portion of each line, which matters more here than anywhere else:
//!   the function this was written for has a doc comment saying the words "no store round-trip",
//!   and a scanner reading the raw line would report the PROSE PROMISING the invariant as a
//!   violation OF it.
//! * [`scan_decls`] — top-level declarations, anchored at column 0. That anchor is the whole trick:
//!   a method inside an `impl` block is indented and scoped by its type, so `new`, `fmt`, `len` and
//!   `default` never reach the cross-plane comparison. What survives is a name its author CHOSE at
//!   file scope, with nothing scoping it.

use crate::ctx::{Ctx, WalkSpec};
use crate::ere::Ere;
use crate::gates::structure_lint::{row, Findings};
use crate::ledger::Row;
use crate::scan::{self, ScopeLine};

pub const ROW_CANDIDATE_FLOOR: &str = "structure-lint:candidate-floor";

/// Deliberately far below the real count (~1,500 files): a guard against ZERO and near-zero, not a
/// census. A `const`, and the environment override the shell carried is gone.
pub const CANDIDATE_FLOOR: usize = 200;

const EXCLUDE_TESTS: &str = "/tests/";
const EXCLUDE_BENCHES: &str = "/benches/";

/// One candidate file, read once and answered once.
#[derive(Debug, Clone)]
pub struct Candidate {
    pub rel: String,
    pub lines: Vec<ScopeLine>,
}

impl Candidate {
    /// The lines a ban may look at: production code, comments excluded.
    pub fn code_lines(&self) -> impl Iterator<Item = &ScopeLine> {
        self.lines.iter().filter(|l| !l.gated && !l.is_comment)
    }
}

#[derive(Debug, Clone)]
pub struct Corpus {
    pub files: Vec<Candidate>,
    /// The candidates that are TEST SCOPE by name or by declaration ([`test_scoped`]). They stay in
    /// [`Corpus::files`] — the inline-test and choke-point rules read the candidate set exactly as
    /// before — and the tree-wide rules ask [`Corpus::production_in_scope`] instead.
    pub test_only: std::collections::BTreeSet<String>,
}

impl Corpus {
    pub fn build(cx: &Ctx) -> Result<Corpus, String> {
        let spec = WalkSpec::new([super::roots::CRATES])
            .ext("rs")
            .exclude([EXCLUDE_TESTS, EXCLUDE_BENCHES])
            .min_files(CANDIDATE_FLOOR);
        let files = cx.walk(&spec).map_err(|e| finding_floor(&e.to_string()))?;
        let test_only = test_scoped(&files);
        Ok(Corpus {
            test_only,
            files: files
                .into_iter()
                .map(|s| Candidate {
                    rel: s.rel_str(),
                    lines: scan::test_scope(&s.text),
                })
                .collect(),
        })
    }

    /// Every candidate under one of `prefixes`. The scope match takes the first prefix that hits
    /// and stops, so listing a redundant prefix costs nothing and listing a moved one costs a row.
    pub fn in_scope<'a>(&'a self, prefixes: &'a [String]) -> impl Iterator<Item = &'a Candidate> {
        self.files
            .iter()
            .filter(move |c| prefixes.iter().any(|p| c.rel.starts_with(p.as_str())))
    }

    /// [`Corpus::in_scope`] without the test-scoped files: what the TREE-WIDE rules (the axis bans
    /// and the census) judge, now that their scope is every crate rather than seven prefixes.
    pub fn production_in_scope<'a>(
        &'a self,
        prefixes: &'a [String],
    ) -> impl Iterator<Item = &'a Candidate> {
        self.in_scope(prefixes)
            .filter(move |c| !self.test_only.contains(&c.rel))
    }

    /// THE PATTERN BAN. One pass per rule over the files it is given, one `(file, line)` per hit.
    ///
    /// The LOCATION is what comes back and the wording is the caller's, so a family that reports a
    /// hit and the translator that reads the same hit out of the shell's output cannot word it two
    /// ways. `unless` is the rule OPT-OUT for a shape that shares the pattern but not the hazard
    /// (the atomic `.swap(x, Ordering::…)` idiom, say).
    pub fn scan_rule<'a, I>(files: I, pat: &Ere, unless: Option<&Ere>) -> Vec<(String, usize)>
    where
        I: IntoIterator<Item = &'a Candidate>,
    {
        let mut out = Vec::new();
        for c in files {
            for line in c.code_lines() {
                if unless.is_some_and(|u| u.is_match(&line.raw)) {
                    continue;
                }
                if pat.is_match(&line.raw) {
                    out.push((c.rel.clone(), line.no));
                }
            }
        }
        out
    }
}

/// Is this a test file BY NAME: `tests.rs`, `test.rs`, `*_tests.rs`, `*_test.rs`.
pub fn is_test_file_name(rel: &str) -> bool {
    rel.ends_with("/tests.rs")
        || rel.ends_with("/test.rs")
        || rel.ends_with("_tests.rs")
        || rel.ends_with("_test.rs")
}

/// An attribute that compiles what follows ONLY for tests or for the test-support feature.
/// `not(test)` is the opposite claim and never counts.
fn is_test_cfg(attr: &str) -> bool {
    let a: String = attr.chars().filter(|c| !c.is_whitespace()).collect();
    a.starts_with("#[cfg(")
        && !a.contains("not(")
        && (a == "#[cfg(test)]" || a.contains("any(test") || a.contains("feature=\"test-support\""))
}

/// Every file in `files` that is TEST SCOPE: named as a test, or declared as a module under a
/// test-only `cfg` by a file in the same list (the module's `name.rs`, and everything under its
/// `name/` directory). A `#[path = "…"]` between the attribute and the `mod` line is followed.
pub fn test_scoped(files: &[crate::ctx::SourceFile]) -> std::collections::BTreeSet<String> {
    let mut prefixes: Vec<String> = Vec::new();
    let mut exact: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for f in files {
        let rel = f.rel_str();
        let Some((dir, file)) = rel.rsplit_once('/') else {
            continue;
        };
        // A module declared in `foo.rs` lives in `foo/`; one declared in `mod.rs`/`lib.rs`/`main.rs`
        // lives beside it.
        let stem = file.strip_suffix(".rs").unwrap_or(file);
        let base = if matches!(stem, "mod" | "lib" | "main") {
            dir.to_string()
        } else {
            format!("{dir}/{stem}")
        };
        let lines: Vec<&str> = f.text.lines().collect();
        for (i, raw) in lines.iter().enumerate() {
            let t = raw.trim();
            if !t.starts_with("#[cfg(") || !is_test_cfg(t) {
                continue;
            }
            let mut path_override: Option<String> = None;
            for probe in lines.iter().skip(i + 1).take(4) {
                let t = probe.trim();
                if let Some(rest) = t.strip_prefix("#[path") {
                    path_override = rest.split('"').nth(1).map(str::to_string);
                    continue;
                }
                if t.starts_with("#[") {
                    continue;
                }
                let t = t
                    .strip_prefix("pub(crate) ")
                    .or_else(|| t.strip_prefix("pub "))
                    .unwrap_or(t);
                let Some(rest) = t.strip_prefix("mod ") else {
                    break;
                };
                let name = rest.trim_end_matches(';').trim();
                if name.is_empty() || name.contains('{') || !rest.trim_end().ends_with(';') {
                    break;
                }
                match &path_override {
                    Some(p) => {
                        exact.insert(normalize(&format!("{dir}/{p}")));
                    }
                    None => {
                        exact.insert(format!("{base}/{name}.rs"));
                        prefixes.push(format!("{base}/{name}/"));
                    }
                }
                break;
            }
        }
    }
    files
        .iter()
        .map(crate::ctx::SourceFile::rel_str)
        .filter(|rel| {
            is_test_file_name(rel)
                || exact.contains(rel)
                || prefixes.iter().any(|p| rel.starts_with(p.as_str()))
        })
        .collect()
}

/// `a/b/../c` -> `a/c`, so a `#[path]` that climbs resolves to the key the walk yields.
fn normalize(p: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for seg in p.split('/') {
        match seg {
            "." | "" => {}
            ".." => {
                parts.pop();
            }
            s => parts.push(s),
        }
    }
    parts.join("/")
}

/// The finding, spelled once — the translator reads the shell's own refusal and calls this.
pub fn finding_floor(detail: &str) -> String {
    format!(
        "CANDIDATE-FLOOR: the file list this lint scans is below its floor of {CANDIDATE_FLOOR}. A \
         clean tree and an unread tree produce the IDENTICAL output, so the count is the only thing \
         that can tell them apart. {detail}"
    )
}

/// One named function's body, by brace depth, with the rule applied inside it.
///
/// Returns the hits and the SPANS found. The caller REQUIRES at least one span: a rule whose
/// function was renamed away scans nothing and reports nothing, which is indistinguishable from a
/// pass — the false green this project has been burned by twice.
pub struct FnScan {
    /// The 1-based line of each hit.
    pub hits: Vec<usize>,
    pub spans: Vec<(usize, usize)>,
}

pub fn scan_fn_body(lines: &[ScopeLine], def: &Ere, pat: &Ere, unless: Option<&Ere>) -> FnScan {
    let mut out = FnScan {
        hits: Vec::new(),
        spans: Vec::new(),
    };
    let mut in_fn = false;
    let mut depth: i32 = 0;
    let mut opened = false;
    let mut start = 0usize;

    for line in lines {
        let c = &line.code;
        if !in_fn && !line.gated && def.is_match(c) {
            in_fn = true;
            depth = 0;
            opened = false;
            start = line.no;
        }
        if !in_fn {
            continue;
        }
        // The pattern match above reads `code` (literal contents included, on purpose); the DEPTH
        // reads the blanked copy, so `rel.contains('{')` inside a body no longer opens a brace.
        let d = scan::delta(&line.counted, '{', '}');
        depth += d;
        if d != 0 {
            opened = true;
        }
        if !unless.is_some_and(|u| u.is_match(c)) && pat.is_match(c) {
            out.hits.push(line.no);
        }
        // A signature spanning several lines has not opened its body yet, so `opened` gates the
        // close.
        if opened && depth <= 0 {
            in_fn = false;
            out.spans.push((start, line.no));
        }
    }
    if in_fn {
        // Unterminated: report what was scanned rather than dropping the span and reading as
        // "the function is not here".
        let last = lines.last().map(|l| l.no).unwrap_or(start);
        out.spans.push((start, last));
    }
    out
}

/// Every TOP-LEVEL declaration — a free `fn`, or a `struct`/`enum`/`trait`/`union` — as
/// `(symbol, line)`. `#[cfg(test)]` regions and whole-line comments are excluded, which is what
/// keeps the cross-plane rule from reporting PROSE: the word `breaker` appears under `mcp/` and
/// `a2a/` only in comments, and a grep-for-the-word lint would have called that a duplicate.
pub fn scan_decls(c: &Candidate, fn_decl: &Ere, type_decl: &Ere) -> Vec<(String, usize)> {
    let mut out = Vec::new();
    for line in c.code_lines() {
        if let Some(m) = fn_decl.find_str(&line.raw) {
            if let Some(name) = after_last_fn_keyword(&m) {
                out.push((name, line.no));
                continue;
            }
        }
        if let Some(m) = type_decl.find_str(&line.raw) {
            if let Some(name) = m.split_whitespace().next_back() {
                out.push((name.to_string(), line.no));
            }
        }
    }
    out
}

/// `sub(/^.*fn[[:space:]]+/, "", s)` — the GREEDY `.*`, so the LAST `fn ` in the matched span is
/// the keyword and what follows it is the name the author chose.
fn after_last_fn_keyword(m: &str) -> Option<String> {
    let b = m.as_bytes();
    let mut at = None;
    for i in 0..b.len().saturating_sub(2) {
        if &b[i..i + 2] == b"fn" && b[i + 2].is_ascii_whitespace() {
            at = Some(i + 2);
        }
    }
    let name = m[at?..].trim();
    (!name.is_empty()).then(|| name.to_string())
}

pub fn rows(f: &Findings) -> Vec<Row> {
    vec![row(
        ROW_CANDIDATE_FLOOR,
        "the candidate corpus cleared its floor",
        "the candidate corpus is below its floor, so every ban below it is vacuous",
        &f.candidate_floor,
    )]
}
