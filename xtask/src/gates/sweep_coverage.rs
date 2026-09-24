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

/// THE PRIOR SWEEP, GUARDED RATHER THAN QUOTED.
///
/// `docs/design/1.6.0-file-verdicts.md` is a real per-file sweep: every tracked `.rs` file given a
/// verdict from a closed vocabulary, reachability established by two independent oracles that had
/// to agree, and its zeros controlled. It is NOT the seven-item checklist — it answers reachability
/// and duplication, not money, auth, instrument blindness or config wiring — so it does not make a
/// file swept. But it is earned work, and a document like it rots silently: every `.rs` file added
/// after it ran is absent from it and nothing says so.
///
/// This row says so. It goes red when a tracked `.rs` file carries no verdict there, which is the
/// difference between a finished sweep and a sweep that finished once.
pub const ROW_REACHABILITY: &str = "sweep-coverage:reachability-axis";

/// THE HOLE IN THE DENOMINATOR, AND WHY IT IS THE WORST KIND.
///
/// `git ls-files` lists TRACKED files. A file that is untracked but *declared* by a `mod` or
/// `#[path]` statement compiles here and does not exist on a clean checkout — so it is invisible
/// to this gate's denominator, invisible to every other gate that walks git, and present in every
/// local test run. The tree passes on the machine that wrote it and cannot build anywhere else.
///
/// This is not hypothetical. At the time this row was written five such files existed, and one of
/// them was `xtask/src/gates/kind_abi_lane.rs` — declared at `gates/mod.rs:40` and REGISTERED as a
/// gate at `:2467`. On a fresh clone `xtask` does not compile, which means *no gate runs at all*,
/// which means the entire harness that proves this release is absent from the release.
///
/// A completeness proof that cannot see a compiling file is not complete. This row closes it.
pub const ROW_TRACKED: &str = "sweep-coverage:compiles-and-tracked";

/// The prior sweep's document and its closed verdict vocabulary.
pub const PRIOR_SWEEP: &str = "docs/design/1.6.0-file-verdicts.md";
pub const PRIOR_VERDICTS: &[&str] = &[
    "LIVE",
    "TEST",
    "TOOLING",
    "ORPHAN",
    "HALF-MIGRATED",
    "DUPLICATE",
];

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

/// The reachability axis's population: every tracked `.rs` file in the denominator. Derived from
/// the one git answer the gate already refuses on failure and floors, so this row has no oracle of
/// its own to swallow (item 225).
pub fn rs_population(denom: &BTreeSet<String>) -> BTreeSet<String> {
    denom
        .iter()
        .filter(|f| f.ends_with(".rs"))
        .cloned()
        .collect()
}

/// Does `text` declare module `name` with a `mod name;` statement, in ANY spelling Rust accepts
/// (items 226, 227)?
///
/// The probe this replaces stripped the literal `"pub "` and looked for `mod name;` — so
/// `pub(crate) mod name;` (86 live declarations in this tree) and `pub(super) mod name;` were
/// invisible, and so was a declaration behind an attribute on the same line (`#[cfg(test)] mod
/// name;`). This strips leading attributes, then any visibility (`pub`, `pub(crate)`,
/// `pub(super)`, `pub(self)`, `pub(in path)`), then asks for `mod name` followed by `;`.
pub fn declares_mod(text: &str, name: &str) -> bool {
    text.lines().any(|line| {
        let mut l = line.trim_start();
        // Leading attributes on the same line: `#[cfg(test)] #[path = "x.rs"] mod name;`.
        while l.starts_with("#[") {
            let mut depth = 0i32;
            let mut end = None;
            for (i, c) in l.char_indices() {
                match c {
                    '[' => depth += 1,
                    ']' => {
                        depth -= 1;
                        if depth == 0 {
                            end = Some(i + 1);
                            break;
                        }
                    }
                    _ => {}
                }
            }
            match end {
                Some(e) => l = l[e..].trim_start(),
                None => return false,
            }
        }
        if let Some(rest) = l
            .strip_prefix("pub")
            .filter(|r| r.starts_with(|c: char| c == '(' || c.is_whitespace()))
        {
            let rest = rest.trim_start();
            l = match rest.strip_prefix('(') {
                Some(inner) => match inner.find(')') {
                    Some(close) => inner[close + 1..].trim_start(),
                    None => return false,
                },
                None => rest,
            };
        }
        l.strip_prefix("mod")
            .filter(|r| r.starts_with(char::is_whitespace))
            .map(str::trim_start)
            .and_then(|r| r.strip_prefix(name))
            .is_some_and(|r| r.trim_start().starts_with(';'))
    })
}

/// `a/b/../c` → `a/c`, for resolving a `#[path]` against its declaring file's directory.
fn normalize(path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            s => parts.push(s),
        }
    }
    parts.join("/")
}

fn parent_of(path: &str) -> &str {
    path.rsplit_once('/').map(|(d, _)| d).unwrap_or("")
}

fn join(dir: &str, file: &str) -> String {
    if dir.is_empty() {
        file.to_string()
    } else {
        format!("{dir}/{file}")
    }
}

/// WHERE, IF ANYWHERE, THE UNTRACKED FILE `f` IS DECLARED — so it compiles here (items 226, 227).
///
/// Three spellings reach a file, and the probe this replaces knew one of them:
///
/// * `mod name;` in the directory's `mod.rs` / `lib.rs` / `main.rs`, or in the NON-`mod.rs` parent
///   `<dir>.rs` beside the directory (the 2018 layout) — with any visibility, see [`declares_mod`];
/// * an untracked `<dir>/mod.rs`, which is module `<dir>` declared one directory UP (the old probe
///   looked for `mod mod;` inside the untracked file's own directory);
/// * `#[path = "rel"]`, resolved against the declaring file's directory, from any file in
///   `path_declarers` — the form the row's own doc promised and nothing implemented.
pub fn ghost_site(
    f: &str,
    read: &dyn Fn(&str) -> Option<String>,
    path_declarers: &[(String, String)],
) -> Option<String> {
    let dir = parent_of(f);
    let stem = f.rsplit('/').next().unwrap_or(f).trim_end_matches(".rs");
    let (search_dir, name) = if stem == "mod" {
        (parent_of(dir), dir.rsplit('/').next().unwrap_or(dir))
    } else {
        (dir, stem)
    };
    let mut probes = vec![
        join(search_dir, "mod.rs"),
        join(search_dir, "lib.rs"),
        join(search_dir, "main.rs"),
    ];
    if !search_dir.is_empty() {
        probes.push(format!("{search_dir}.rs"));
    }
    for probe in probes {
        if probe == f {
            continue;
        }
        if read(&probe).is_some_and(|text| declares_mod(&text, name)) {
            return Some(probe);
        }
    }
    for (declarer, text) in path_declarers {
        let base = parent_of(declarer);
        for chunk in text.split("#[path").skip(1) {
            let Some(open) = chunk.find('"') else {
                continue;
            };
            let Some(len) = chunk[open + 1..].find('"') else {
                continue;
            };
            let rel = &chunk[open + 1..open + 1 + len];
            if normalize(&join(base, rel)) == f {
                return Some(declarer.clone());
            }
        }
    }
    None
}

/// Every verdict line across every slice document.
///
/// A markdown table row is `| a | b | c | d |`. Splitting on `|` yields a leading and trailing
/// empty cell, which is why the columns are taken from index 1. Header rows (`FILE`) and
/// separator rows (`---`) are skipped by shape rather than by position, so a slice that adds a
/// preamble does not silently lose its first file.
pub fn claims(cx: &Ctx, denom: &BTreeSet<String>) -> Result<Vec<Claim>, String> {
    // THE SUBPROCESS CANNOT SEE THE PLANT.
    //
    // `git ls-files` shells out and reads the real filesystem, so a slice document planted into
    // an Overlay is invisible to it. Taking it as the only source made every falsification case
    // here INERT: the plant wrote a phantom, a prose verdict and a double claim, the gate saw
    // none of them, and all three cases came back GREEN where RED was owed. A rule whose only
    // input is a subprocess is falsifiable in CI and unfalsifiable on the bench — which is the
    // half that gets run while the rule is being written.
    //
    // The tracked set is still the claim (committed evidence is the standard the `swept` row
    // holds everyone to); the overlay is unioned on top so a plant is reachable.
    let mut docs: Vec<String> = cx.git_lines(&["ls-files", SWEEP_DIR])?;
    if let Some(ov) = cx.overlay() {
        for p in ov.paths() {
            let rel = p.to_string_lossy().to_string();
            if rel.starts_with(SWEEP_DIR) && rel.ends_with(".md") && !docs.contains(&rel) {
                docs.push(rel);
            }
        }
    }
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
            // WHAT MAKES A ROW A CLAIM, and why it is not "it has four cells".
            //
            // The EVIDENCE column holds shell commands, and shell commands contain pipes. Split
            // naively on `|`, a row like `| foo.rs | CLEAN | git grep x | wc -l | 3 |` yields
            // cells that are fragments of a command, and those fragments then read as a file and
            // a verdict. Sixteen such fragments were reported as phantom files in one run —
            // noise that would drown the real ones, which is its own kind of blindness.
            //
            // A row is a CLAIM when it makes one: either its first cell names a file this tree
            // has, or its second cell is one of the four words that are verdicts. A command
            // fragment is neither, so it is ignored — while a phantom (legal verdict, absent
            // file) and a prose verdict (real file, illegal word) are each still caught by one
            // half of the test.
            let names_a_real_file = denom.contains(file);
            let carries_a_verdict = LEGAL_VERDICTS.contains(&verdict);
            if !names_a_real_file && !carries_a_verdict {
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

        let claims = match claims(cx, &denom) {
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

        // --- reachability axis -------------------------------------------------------------
        // THE POPULATION IS THE DENOMINATOR'S `.rs` HALF, NOT A SECOND GIT QUERY (item 225). The
        // row used to ask git again and turn an Err into an EMPTY set — an empty set has nothing
        // missing, so an unanswerable question and a clean tree printed the same PASS. The
        // denominator above is the same `ls-files '*.rs'` answer, already refused on Err and
        // already held to its floor, so the row reads that one and cannot fake an answer.
        let rs = rs_population(&denom);
        let prior = cx.read(PRIOR_SWEEP).unwrap_or_default();
        let mut verdicted: BTreeSet<String> = BTreeSet::new();
        for line in prior.lines() {
            let line = line.trim();
            if !line.starts_with('|') {
                continue;
            }
            let cells: Vec<&str> = line.split('|').map(str::trim).collect();
            if cells.len() < 4 {
                continue;
            }
            let path = cells[1].trim_matches('`').trim();
            let verdict = cells[2].trim_matches('*').trim();
            if rs.contains(path) && PRIOR_VERDICTS.contains(&verdict) {
                verdicted.insert(path.to_string());
            }
        }
        let missing: Vec<String> = rs.difference(&verdicted).cloned().collect();
        rows.push(if rs.is_empty() {
            Row::fail(
                ROW_REACHABILITY,
                "the reachability population is empty — the question went unanswered, and an \
                 unanswered question is not a clean tree",
                format!(
                    "git listed no tracked .rs file; nothing was compared against {PRIOR_SWEEP}"
                ),
            )
        } else if missing.is_empty() {
            Row::pass(
                ROW_REACHABILITY,
                "every tracked .rs file carries a reachability verdict in the prior sweep",
                format!("{} of {} file(s)", verdicted.len(), rs.len()),
            )
        } else {
            Row::fail(
                ROW_REACHABILITY,
                "tracked .rs files are absent from the reachability sweep — a sweep that finished \
                 once is not a sweep that is finished",
                format!(
                    "{} of {} verdicted in {PRIOR_SWEEP}; {} absent: {}",
                    verdicted.len(),
                    rs.len(),
                    missing.len(),
                    listing(&missing, 10)
                ),
            )
        });

        // --- compiles-and-tracked ------------------------------------------------------------
        // An untracked file that some module declares is a file that exists here and nowhere else.
        // The untracked listing is an ORACLE like any other: a git that could not answer is a row
        // that could not run, never an empty list with no ghosts in it.
        let untracked = match cx.git_lines(&["ls-files", "--others", "--exclude-standard", "*.rs"])
        {
            Ok(v) => v,
            Err(e) => {
                rows.push(Row::fail(
                    ROW_TRACKED,
                    "the untracked-file listing could not be read from git — an unanswered \
                     question is not a clean tree",
                    e,
                ));
                return rows;
            }
        };
        let untracked: Vec<String> = untracked
            .into_iter()
            .map(|f| f.trim().to_string())
            .filter(|f| !f.is_empty())
            .collect();
        // THE `#[path]` DECLARERS, read only when there is an untracked file to resolve: every
        // tracked or untracked `.rs` whose text carries a `#[path` attribute.
        let path_declarers: Vec<(String, String)> = if untracked.is_empty() {
            Vec::new()
        } else {
            rs.iter()
                .chain(untracked.iter())
                .filter_map(|f| cx.read(f).ok().map(|t| (f.clone(), t)))
                .filter(|(_, t)| t.contains("#[path"))
                .collect()
        };
        let mut ghosts: Vec<String> = Vec::new();
        for f in &untracked {
            if let Some(site) = ghost_site(f, &|p| cx.read(p).ok(), &path_declarers) {
                ghosts.push(format!("{f} (declared in {site})"));
            }
        }
        rows.push(if ghosts.is_empty() {
            Row::pass(
                ROW_TRACKED,
                "every file that compiles is a file git has",
                "no untracked .rs file is declared by a module statement".to_string(),
            )
        } else {
            Row::fail(
                ROW_TRACKED,
                "a file compiles here and does not exist on a clean checkout — it is invisible to \
                 every gate that walks git, and the tree cannot build anywhere else",
                listing(&ghosts, 10),
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
            ROW_REACHABILITY.to_string(),
            ROW_TRACKED.to_string(),
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

#[cfg(test)]
mod tests {
    use super::*;

    /// ITEM 225: the reachability population is the denominator's `.rs` half, so it is exactly as
    /// answerable as the denominator — which is refused on Err and floored — and never an empty
    /// stand-in for a failed query.
    #[test]
    fn the_reachability_population_is_the_denominators_rs_half() {
        let denom: BTreeSet<String> = ["a/lib.rs", "Cargo.toml", "b/c.rs", "scripts/x.sh"]
            .into_iter()
            .map(String::from)
            .collect();
        let rs = rs_population(&denom);
        assert_eq!(
            rs.into_iter().collect::<Vec<_>>(),
            vec!["a/lib.rs".to_string(), "b/c.rs".to_string()]
        );
    }

    fn reader<'a>(files: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |p: &str| {
            files
                .iter()
                .find(|(f, _)| *f == p)
                .map(|(_, t)| (*t).to_string())
        }
    }

    /// ITEMS 226, 227: EVERY SPELLING OF A MODULE DECLARATION IS SEEN. The old probe stripped the
    /// literal `"pub "` and saw only `mod x;` / `pub mod x;`.
    #[test]
    fn a_module_declared_with_any_visibility_or_attribute_is_declared() {
        for line in [
            "mod ghost;",
            "pub mod ghost;",
            "pub(crate) mod ghost;",
            "pub(super) mod ghost;",
            "pub(in crate::a) mod ghost;",
            "#[cfg(test)] mod ghost;",
            "    #[cfg(test)] pub(crate) mod ghost ;",
        ] {
            assert!(declares_mod(line, "ghost"), "{line}");
        }
        for line in [
            "mod ghostly;",
            "// mod ghost;",
            "mod ghost {",
            "pubmod ghost;",
            "use ghost;",
        ] {
            assert!(!declares_mod(line, "ghost"), "{line}");
        }
    }

    /// ITEMS 226, 227: THE GHOST IS FOUND WHEREVER IT IS DECLARED FROM — a restricted visibility in
    /// the sibling `mod.rs`, the 2018 `<dir>.rs` parent, an untracked `<dir>/mod.rs` declared one
    /// level up, and a `#[path]` attribute.
    #[test]
    fn an_untracked_file_declared_in_any_spelling_is_a_ghost() {
        let files = [
            ("crates/a/src/a2a/mod.rs", "pub(crate) mod ghost;\n"),
            ("crates/b/src/cost.rs", "pub(super) mod repricer;\n"),
            ("crates/c/src/lib.rs", "mod inner;\n"),
        ];
        let read = reader(&files);
        assert_eq!(
            ghost_site("crates/a/src/a2a/ghost.rs", &read, &[]).as_deref(),
            Some("crates/a/src/a2a/mod.rs")
        );
        assert_eq!(
            ghost_site("crates/b/src/cost/repricer.rs", &read, &[]).as_deref(),
            Some("crates/b/src/cost.rs")
        );
        assert_eq!(
            ghost_site("crates/c/src/inner/mod.rs", &read, &[]).as_deref(),
            Some("crates/c/src/lib.rs")
        );
        let declarers = vec![(
            "crates/d/src/runtime/mod.rs".to_string(),
            "#[cfg(test)]\n#[path = \"../oracle/voice_oracle.rs\"]\nmod voice_oracle;\n"
                .to_string(),
        )];
        assert_eq!(
            ghost_site("crates/d/src/oracle/voice_oracle.rs", &read, &declarers).as_deref(),
            Some("crates/d/src/runtime/mod.rs")
        );
        assert_eq!(
            ghost_site("crates/a/src/a2a/stray.rs", &read, &declarers),
            None
        );
    }

    /// ITEM 225, ON THE REAL TREE: the row's population is the same set a direct `ls-files '*.rs'`
    /// gives, so deriving it moved nothing.
    #[test]
    fn the_derived_population_equals_git_on_the_tree() {
        let cx = Ctx::workspace().expect("workspace");
        let denom = denominator(&cx).expect("the denominator");
        let direct: BTreeSet<String> = cx
            .git_lines(&["ls-files", "*.rs"])
            .expect("git")
            .into_iter()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect();
        assert_eq!(rs_population(&denom), direct);
    }
}
