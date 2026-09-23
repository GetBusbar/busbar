//! SWEEP COVERAGE — the completeness proof for "every corner of the house has been checked."
//!
//! # The question this gate exists to answer
//!
//! The owner asked for three things: the house swept, a TODO list `X` items long, and **proof the
//! list is complete — that nothing was missed.** The first two are work. The third is a
//! measurement problem, and it is the one that has been failing.
//!
//! A completeness proof needs a **denominator the work being measured did not create**. Every
//! prior attempt in this release used one the effort wrote — a count of sweeps run, a count of
//! sections in a document, a partition of findings into buckets. Those numbers cannot come out
//! differently no matter how the work goes, because the work authored both sides. A partition of
//! `n` always sums to `n`.
//!
//! This gate's denominator is emitted by `git ls-files`: every tracked file that can hold a
//! defect. Nobody sweeping the house can change it by sweeping harder, and adding a file to the
//! tree lowers the coverage immediately. That is what makes the number falsifiable.
//!
//! # What counts as swept
//!
//! **A verdict line, not a mention.** A file named somewhere in a megabyte of prose has not been
//! checked; it has been referred to. The sweep contract requires every file in a slice to carry
//! exactly one row in its slice document:
//!
//! ```text
//! | FILE | VERDICT | EVIDENCE | ROWS |
//! ```
//!
//! with `VERDICT` one of `CLEAN`, `FINDING`, `DELETABLE`, `UNREADABLE`. Anything else is not a
//! verdict, and this gate says so rather than counting it.
//!
//! # The five rows, and the NO each one can produce
//!
//! | row | goes red when |
//! |---|---|
//! | `denominator` | `git ls-files` returns implausibly few files — the extractor broke, not the tree |
//! | `swept` | any tracked file carries no verdict line |
//! | `no-phantoms` | a verdict line names a file that is not in the tree |
//! | `verdicts-legal` | a verdict line carries a word that is not one of the four |
//! | `disjoint` | two slices both claim the same file — the partition stopped being a partition |
//!
//! The `denominator` row deserves its own note. Every glob in `DENOMINATOR_GLOBS` has bitten
//! somebody in this repository: unquoted `--include=*.rs` is eaten by zsh and dies with no
//! output; `git ls-tree -- '<glob>'` does not glob at all. A coverage gate whose denominator
//! silently collapsed to zero would report **100% swept** — the most dangerous possible false
//! green, since it is the exact number the work is trying to reach. The floor is the guard: a
//! denominator below it is read as a broken instrument and never as a finished job.

use std::collections::{BTreeMap, BTreeSet};

use crate::ctx::{Ctx, Overlay};
use crate::gates::{prove_red, Gate, Report};
use crate::ledger::{Row, Verdict as GateVerdict};

/// Every tracked file that can hold a defect. Docs are deliberately absent: they are the map, not
/// the house, and 6,503 identifiers exist on this trunk in `docs/` and in zero code files — a
/// sweep that counted them would be measuring its own paperwork.
pub const DENOMINATOR_GLOBS: &[&str] = &[
    "*.rs",
    "*/Cargo.toml",
    "Cargo.toml",
    ".github/workflows/*.yml",
    "scripts/*",
    "qa/*",
];

/// Where slice documents live. One file per slice, one writer per file.
pub const SWEEP_DIR: &str = "docs/design/sweep";

/// A denominator below this is a broken glob, not a shrunken tree. It was 2,068 when the sweep
/// was partitioned; this floor sits far enough below to survive ordinary deletion and far enough
/// above zero to catch the failure that would otherwise print "100% swept".
pub const DENOMINATOR_FLOOR: usize = 1_700;

/// The only four words that are a verdict. `CLEAN` is a claim about a file, and it is the one
/// that is hardest to earn, so it is not the default for a line somebody forgot to fill in.
pub const LEGAL_VERDICTS: &[&str] = &["CLEAN", "FINDING", "DELETABLE", "UNREADABLE"];

pub const ROW_DENOMINATOR: &str = "sweep-coverage:denominator";
pub const ROW_SWEPT: &str = "sweep-coverage:swept";
pub const ROW_PHANTOMS: &str = "sweep-coverage:no-phantoms";
pub const ROW_LEGAL: &str = "sweep-coverage:verdicts-legal";
pub const ROW_DISJOINT: &str = "sweep-coverage:disjoint";

/// One parsed verdict line.
#[derive(Debug, Clone)]
pub struct Claim {
    pub file: String,
    pub verdict: String,
    pub slice: String,
    pub line: usize,
}

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

/// The denominator, straight from git. Returns the sorted, de-duplicated set.
pub fn denominator(cx: &Ctx) -> Result<BTreeSet<String>, String> {
    let mut args: Vec<&str> = vec!["ls-files"];
    args.extend_from_slice(DENOMINATOR_GLOBS);
    let lines = cx.git_lines(&args)?;
    Ok(lines
        .into_iter()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect())
}

/// Every verdict line across every slice document.
///
/// A markdown table row is `| a | b | c | d |`. Splitting on `|` yields a leading and trailing
/// empty cell, which is why the columns are taken from index 1. Header rows (`FILE`) and
/// separator rows (`---`) are skipped by shape rather than by position, so a slice that adds a
/// preamble does not silently lose its first file.
pub fn claims(cx: &Ctx) -> Result<Vec<Claim>, String> {
    let docs = cx.git_lines(&["ls-files", SWEEP_DIR])?;
    let mut out = Vec::new();
    for doc in docs {
        let doc = doc.trim();
        if doc.is_empty() || !doc.ends_with(".md") {
            continue;
        }
        let slice = doc
            .rsplit('/')
            .next()
            .unwrap_or(doc)
            .trim_end_matches(".md")
            .to_string();
        if slice == "DENOMINATOR" {
            continue;
        }
        let text = match cx.read(doc) {
            Ok(t) => t,
            Err(e) => return Err(format!("{doc}: {e}")),
        };
        for (i, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if !line.starts_with('|') {
                continue;
            }
            let cells: Vec<&str> = line.split('|').map(str::trim).collect();
            if cells.len() < 4 {
                continue;
            }
            let file = cells[1].trim_matches('`').trim();
            let verdict = cells[2].trim_matches('*').trim();
            if file.is_empty() || file.eq_ignore_ascii_case("FILE") || file.starts_with("---") {
                continue;
            }
            if verdict.is_empty() || verdict.starts_with("---") {
                continue;
            }
            out.push(Claim {
                file: file.to_string(),
                verdict: verdict.to_string(),
                slice: slice.clone(),
                line: i + 1,
            });
        }
    }
    Ok(out)
}

pub struct SweepCoverageGate;

impl SweepCoverageGate {
    fn rows(cx: &Ctx) -> Vec<Row> {
        let mut rows = Vec::new();

        let denom = match denominator(cx) {
            Ok(d) => d,
            Err(e) => {
                rows.push(Row::fail(
                    ROW_DENOMINATOR,
                    "the denominator could not be read from git — coverage is unknowable, not 100%",
                    e,
                ));
                return rows;
            }
        };

        // --- denominator -----------------------------------------------------------------
        rows.push(if denom.len() >= DENOMINATOR_FLOOR {
            Row::pass(
                ROW_DENOMINATOR,
                "git emits a plausible denominator for the sweep",
                format!(
                    "{} tracked file(s) across {} glob(s), floor {DENOMINATOR_FLOOR}",
                    denom.len(),
                    DENOMINATOR_GLOBS.len()
                ),
            )
        } else {
            Row::fail(
                ROW_DENOMINATOR,
                "the denominator collapsed — a broken glob reports 100% swept, which is exactly \
                 the number the work is trying to reach",
                format!(
                    "{} tracked file(s), floor {DENOMINATOR_FLOOR}; globs: {}",
                    denom.len(),
                    DENOMINATOR_GLOBS.join(" ")
                ),
            )
        });

        let claims = match claims(cx) {
            Ok(c) => c,
            Err(e) => {
                rows.push(Row::fail(
                    ROW_SWEPT,
                    "a slice document could not be read — its files are unswept, not clean",
                    e,
                ));
                return rows;
            }
        };

        // --- swept ------------------------------------------------------------------------
        let claimed: BTreeSet<&str> = claims.iter().map(|c| c.file.as_str()).collect();
        let unswept: Vec<String> = denom
            .iter()
            .filter(|f| !claimed.contains(f.as_str()))
            .cloned()
            .collect();
        let swept = denom.len() - unswept.len();
        let pct = if denom.is_empty() {
            0.0
        } else {
            100.0 * swept as f64 / denom.len() as f64
        };
        rows.push(if unswept.is_empty() {
            Row::pass(
                ROW_SWEPT,
                "every tracked file carries a sweep verdict",
                format!("{swept} of {} file(s), 100.00%", denom.len()),
            )
        } else {
            Row::fail(
                ROW_SWEPT,
                "tracked files carry no sweep verdict — a file nobody looked at cannot be on the \
                 list, and a list missing it is not complete",
                format!(
                    "{swept} of {} swept ({pct:.2}%); {} without a verdict: {}",
                    denom.len(),
                    unswept.len(),
                    listing(&unswept, 10)
                ),
            )
        });

        // --- phantoms ---------------------------------------------------------------------
        let phantoms: Vec<String> = claims
            .iter()
            .filter(|c| !denom.contains(&c.file))
            .map(|c| format!("{}:{} claims `{}`", c.slice, c.line, c.file))
            .collect();
        rows.push(if phantoms.is_empty() {
            Row::pass(
                ROW_PHANTOMS,
                "every verdict names a file that is in the tree",
                format!("{} verdict line(s), 0 phantom(s)", claims.len()),
            )
        } else {
            Row::fail(
                ROW_PHANTOMS,
                "a verdict names a file the tree does not have — coverage counted against a \
                 denominator it invented",
                listing(&phantoms, 10),
            )
        });

        // --- legal verdicts ---------------------------------------------------------------
        let illegal: Vec<String> = claims
            .iter()
            .filter(|c| !LEGAL_VERDICTS.contains(&c.verdict.as_str()))
            .map(|c| format!("{}:{} `{}` -> `{}`", c.slice, c.line, c.file, c.verdict))
            .collect();
        rows.push(if illegal.is_empty() {
            Row::pass(
                ROW_LEGAL,
                "every verdict is one of the four the contract allows",
                format!(
                    "{} verdict line(s); vocabulary {}",
                    claims.len(),
                    LEGAL_VERDICTS.join("/")
                ),
            )
        } else {
            Row::fail(
                ROW_LEGAL,
                "a verdict column holds a word that is not a verdict — prose in a verdict cell \
                 reads as coverage while asserting nothing",
                listing(&illegal, 10),
            )
        });

        // --- disjoint ---------------------------------------------------------------------
        let mut by_file: BTreeMap<&str, Vec<&Claim>> = BTreeMap::new();
        for c in &claims {
            by_file.entry(c.file.as_str()).or_default().push(c);
        }
        let dupes: Vec<String> = by_file
            .iter()
            .filter(|(_, cs)| cs.len() > 1)
            .map(|(f, cs)| {
                let who: Vec<String> = cs
                    .iter()
                    .map(|c| format!("{}:{}", c.slice, c.line))
                    .collect();
                format!("`{f}` claimed by {}", who.join(" + "))
            })
            .collect();
        rows.push(if dupes.is_empty() {
            Row::pass(
                ROW_DISJOINT,
                "no file is claimed by two slices — the partition is still a partition",
                format!("{} distinct file(s) claimed once each", by_file.len()),
            )
        } else {
            Row::fail(
                ROW_DISJOINT,
                "a file is claimed by more than one slice — double-counted coverage inflates the \
                 swept figure while leaving a real gap somewhere else",
                listing(&dupes, 10),
            )
        });

        rows
    }
}

impl Gate for SweepCoverageGate {
    fn name(&self) -> &'static str {
        "sweep-coverage"
    }

    fn owed(&self) -> Vec<String> {
        vec![
            ROW_DENOMINATOR.to_string(),
            ROW_SWEPT.to_string(),
            ROW_PHANTOMS.to_string(),
            ROW_LEGAL.to_string(),
            ROW_DISJOINT.to_string(),
        ]
    }

    fn run(&self, cx: &Ctx) -> GateVerdict {
        GateVerdict::of(SweepCoverageGate::rows(cx))
    }

    fn selftest<'a>(&'a self, cx: &'a Ctx) -> Report<'a> {
        let mut report = Report::new();

        // RED — A PHANTOM. A verdict for a file the tree does not have is the cheapest way to
        // manufacture coverage: write more lines, claim a higher percentage. The denominator
        // comes from git precisely so that this cannot work, and this case is the proof.
        report.push(prove_red(
            cx,
            self,
            "a verdict naming a file outside the tree is a phantom, not coverage",
            &[ROW_PHANTOMS],
            {
                let mut ov = Overlay::new();
                ov.set(
                    format!("{SWEEP_DIR}/S99-selftest.md"),
                    "| FILE | VERDICT | EVIDENCE | ROWS |\n                     |---|---|---|---|\n                     | crates/no-such-crate/src/lib.rs | CLEAN | planted | - |\n",
                );
                ov
            },
            &["phantom"],
        ));

        // RED — PROSE IN THE VERDICT COLUMN. "looks fine to me" occupies a verdict cell and
        // reads as a swept file while asserting nothing that can be wrong.
        report.push(prove_red(
            cx,
            self,
            "a verdict cell holding prose is refused rather than counted as a verdict",
            &[ROW_LEGAL],
            {
                let mut ov = Overlay::new();
                ov.set(
                    format!("{SWEEP_DIR}/S98-selftest.md"),
                    "| FILE | VERDICT | EVIDENCE | ROWS |\n                     |---|---|---|---|\n                     | Cargo.toml | looks fine to me | planted | - |\n",
                );
                ov
            },
            &["not a verdict"],
        ));

        // RED — A DOUBLE CLAIM. Two slices claiming one file inflates the swept count while
        // leaving a real gap somewhere else, and a partition that stops being a partition is
        // the exact failure the slice arithmetic was supposed to rule out.
        report.push(prove_red(
            cx,
            self,
            "one file claimed by two slices is caught rather than counted twice",
            &[ROW_DISJOINT],
            {
                let mut ov = Overlay::new();
                let row = "| FILE | VERDICT | EVIDENCE | ROWS |\n                           |---|---|---|---|\n                           | Cargo.toml | CLEAN | planted | - |\n";
                ov.set(format!("{SWEEP_DIR}/S97-selftest.md"), row);
                ov.set(format!("{SWEEP_DIR}/S96-selftest.md"), row);
                ov
            },
            &["claimed by"],
        ));

        report
    }
}
