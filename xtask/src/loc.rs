//! `cargo xtask loc` — **THE** line counter. One instrument, one metric, no second opinion.
//!
//! ## WHY THIS EXISTS
//!
//! Three separate measurements of one question — "how much did this tree grow" — produced 2.08x,
//! 2.90x and 2.60x on the same day, from the same checkout. None of them was a rounding difference.
//! Each was a different ad-hoc rule:
//!
//! * `scripts/loc-surface.py` excluded only the TOP-LEVEL `src/tests/`, so the nested
//!   `src/<module>/tests/**` this tree actually keeps its proofs in was billed as production
//!   surface — **192,813 lines of it, more than the 190,086 lines of real production code**. Five
//!   crates read 48–77% test. `busbar-llm-codec` was sized in the 1.6.0 design at "63,070 surf"
//!   against 22,691 lines of actual code.
//! * The construction gate's own tree scanner classified tests differently again.
//! * A "first `#[cfg(test)]` to end of file" rule, used to estimate the 1.5.5 baseline, called
//!   3,897 of `crates/busbar/src/main.rs`'s 3,989 lines test because of a ONE-LINE
//!   `#[cfg(test)] mod test_support;` at line 93 — including the split-listener router builder at
//!   line 3900.
//!
//! The defect is not any one of those rules. It is that there were three. **If two things can count
//! lines, we are back where we started**, so this module is the one counter and the others are
//! deleted or point at it.
//!
//! ## THE PROPERTIES THE OWNER ASKED FOR, AND WHERE EACH LIVES
//!
//! * **One metric, five buckets, always reported together** — [`classify`], whose module doc is the
//!   definition. A bare "surface" number with no `test` figure beside it is how the old one hid.
//! * **Repeatable** — the same tree in gives byte-identical output out. Every collection is sorted;
//!   nothing iterates a hash map.
//! * **Any git ref** — `--ref v1.5.5`. A baseline that has to be transcribed by hand is a baseline
//!   that drifts, and the 1.5.5 figures this replaces existed only in chat messages.
//! * **Machine-readable first** — JSON is the default and `--format table` is the courtesy. Gates
//!   read the library, not the text.
//! * **Grouping declared in data** — `qa/loc.toml`, see [`config`].
//! * **Scopes** — file, crate, group, total.
//! * **A file that will not parse is an ERROR** — never silently counted as code, in either
//!   direction. See [`Report::errors`].

pub mod classify;
pub mod config;
pub mod render;
pub mod selftest;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use crate::ctx::Ctx;
use crate::gitp;

pub use classify::{Counts, Kind};
pub use config::Config;

/// The tree being measured: the checkout on disk, or a git ref read through `cat-file`.
///
/// A ref is read from the OBJECT STORE and never checked out. Twenty-eight agents share this
/// working tree; a counter that created a worktree to answer a question would be the one command
/// in the toolbox that could not be run twice at once.
#[derive(Clone, Debug)]
pub enum Source {
    Worktree,
    Rev(String),
}

impl Source {
    pub fn label(&self) -> String {
        match self {
            Source::Worktree => "WORKTREE".to_string(),
            Source::Rev(r) => r.clone(),
        }
    }
}

/// One file's measurement.
#[derive(Clone, Debug)]
pub struct FileCount {
    pub path: String,
    pub krate: String,
    pub counts: Counts,
}

/// One file the counter refused to guess about.
#[derive(Clone, Debug)]
pub struct FileError {
    pub path: String,
    pub krate: String,
    pub error: String,
}

/// One named crate set from `qa/loc.toml`, measured both ways round.
///
/// `outside` is carried explicitly rather than left as "total minus inside" arithmetic for the
/// reader to do, because "excluding the four new planes" is the exact phrase the release's headline
/// ratio is quoted in and it should be a FIELD, not a subtraction somebody might get wrong twice.
#[derive(Clone, Debug)]
pub struct GroupCount {
    pub name: String,
    pub label: String,
    pub crates: Vec<String>,
    /// Crates the group names that the tree does not have. Reported, never silently dropped: a
    /// group whose members have all been renamed measures zero and looks like a clean tree.
    pub missing: Vec<String>,
    pub inside: Counts,
    pub outside: Counts,
}

/// Everything one run measured.
#[derive(Clone, Debug)]
pub struct Report {
    pub source: String,
    pub files: Vec<FileCount>,
    pub crates: Vec<(String, Counts)>,
    pub groups: Vec<GroupCount>,
    pub total: Counts,
    pub errors: Vec<FileError>,
}

impl Report {
    pub fn crate_counts(&self, name: &str) -> Option<&Counts> {
        self.crates
            .binary_search_by(|(k, _)| k.as_str().cmp(name))
            .ok()
            .map(|i| &self.crates[i].1)
    }

    /// One repo-relative file's buckets. `None` — never a zero — for a path this run did not
    /// measure, so a ceiling pointed at a moved or renamed file reports that rather than passing.
    pub fn file_counts(&self, rel: &str) -> Option<&Counts> {
        self.files
            .binary_search_by(|f| f.path.as_str().cmp(rel))
            .ok()
            .map(|i| &self.files[i].counts)
    }

    /// The files under one SUBJECT — a crate name or a repo-relative path — that could not be
    /// parsed.
    ///
    /// SCOPED, and the scoping is the point. A ceiling row must go red when the thing IT measures
    /// could not be measured, and must NOT go red because some other agent's half-written test file
    /// in an unrelated crate does not parse. Un-scoped, one broken file anywhere reddened every
    /// ceiling in the tree — which is a gate that cries wolf, and a gate that cries wolf is a gate
    /// people learn to read past.
    pub fn errors_for(&self, subject: &str) -> Vec<&FileError> {
        self.errors
            .iter()
            .filter(|e| {
                if subject.contains('/') {
                    e.path == subject
                } else {
                    e.krate == subject
                }
            })
            .collect()
    }

    /// Repo-relative path -> `code`, for the gates that ratchet per-file ceilings.
    pub fn file_code_map(&self) -> BTreeMap<String, i64> {
        self.files
            .iter()
            .map(|f| (f.path.clone(), f.counts.code as i64))
            .collect()
    }
}

// ── DISCOVERY ────────────────────────────────────────────────────────────────────────────────────

/// Every `.rs` file the counter will measure, as `(crate, repo-relative path)`, sorted.
///
/// The crate is the DIRECTORY name, not the `package.name`, because that is what every ceiling in
/// `qa/construction.toml` is keyed on and what the script this replaces used. The two differ in
/// this tree (`crates/secret-ref`, `crates/hooks-ranking`) and re-keying the ceilings is a separate
/// decision from fixing the counter.
fn discover(cx: &Ctx, source: &Source, cfg: &Config) -> Result<Vec<(String, String)>, String> {
    let mut out: Vec<(String, String)> = match source {
        Source::Worktree => discover_worktree(cx.root(), cfg)?,
        Source::Rev(rev) => discover_rev(cx, rev, cfg)?,
    };
    out.sort();
    out.dedup();
    Ok(out)
}

fn discover_worktree(root: &Path, cfg: &Config) -> Result<Vec<(String, String)>, String> {
    let mut out = Vec::new();
    for croot in &cfg.crate_roots {
        let dir = root.join(croot);
        let entries = std::fs::read_dir(&dir)
            .map_err(|e| format!("{}: {e}", dir.display()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("{}: {e}", dir.display()))?;
        let mut names: Vec<String> = entries
            .iter()
            .filter(|e| e.path().is_dir())
            .filter_map(|e| e.file_name().into_string().ok())
            .collect();
        names.sort();
        for name in names {
            collect_rs(
                &dir.join(&name),
                &format!("{croot}/{name}"),
                &name,
                &mut out,
            )?;
        }
    }
    for extra in &cfg.extra_crates {
        let name = extra.rsplit('/').next().unwrap_or(extra).to_string();
        collect_rs(&root.join(extra), extra, &name, &mut out)?;
    }
    Ok(out)
}

fn collect_rs(
    dir: &Path,
    rel_prefix: &str,
    krate: &str,
    out: &mut Vec<(String, String)>,
) -> Result<(), String> {
    if !dir.is_dir() {
        return Ok(());
    }
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?
        .map(|e| e.map(|e| e.path()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("{}: {e}", dir.display()))?;
    entries.sort();
    for path in entries {
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        // `target/` under a crate is build output, not source, and walking it is minutes of I/O.
        if name == "target" || name == ".git" {
            continue;
        }
        let rel = format!("{rel_prefix}/{name}");
        if path.is_dir() {
            collect_rs(&path, &rel, krate, out)?;
        } else if name.ends_with(".rs") {
            out.push((krate.to_string(), rel));
        }
    }
    Ok(())
}

fn discover_rev(cx: &Ctx, rev: &str, cfg: &Config) -> Result<Vec<(String, String)>, String> {
    if !cx.git_ref_resolves(rev) {
        return Err(format!(
            "--ref {rev}: does not resolve in this repository. A baseline nobody can recompute is \
             a baseline that drifts; this refuses rather than measuring something else."
        ));
    }
    let listed = gitp::git_lines(cx.root(), &["ls-tree", "-r", "--name-only", rev])?;
    let mut out = Vec::new();
    for path in listed {
        if !path.ends_with(".rs") {
            continue;
        }
        if let Some(krate) = crate_of(&path, cfg) {
            out.push((krate, path));
        }
    }
    if out.is_empty() {
        return Err(format!(
            "--ref {rev}: no .rs file under {:?}. The layout at that ref is not the layout \
             [scan].crate_roots describes, and a zero measurement would read as a small tree.",
            cfg.crate_roots
        ));
    }
    Ok(out)
}

fn crate_of(path: &str, cfg: &Config) -> Option<String> {
    for croot in &cfg.crate_roots {
        if let Some(rest) = path.strip_prefix(&format!("{croot}/")) {
            let name = rest.split('/').next()?;
            if rest.contains('/') {
                return Some(name.to_string());
            }
        }
    }
    for extra in &cfg.extra_crates {
        if path.starts_with(&format!("{extra}/")) {
            return Some(extra.rsplit('/').next().unwrap_or(extra).to_string());
        }
    }
    None
}

// ── READING ──────────────────────────────────────────────────────────────────────────────────────

/// Read every path at once.
///
/// For a ref this is ONE `git cat-file --batch` coprocess for the whole set, through
/// [`gitp::ask`] — the shape that cannot deadlock — rather than one `git show` per file, which for
/// this tree is 1,441 processes.
fn read_all(
    cx: &Ctx,
    source: &Source,
    paths: &[String],
) -> Result<Vec<Result<String, String>>, String> {
    match source {
        Source::Worktree => Ok(paths
            .iter()
            .map(|p| cx.read(p).map_err(|e| e.to_string()))
            .collect()),
        Source::Rev(rev) => read_blobs(cx, rev, paths),
    }
}

fn read_blobs(
    cx: &Ctx,
    rev: &str,
    paths: &[String],
) -> Result<Vec<Result<String, String>>, String> {
    // No `use std::io::{BufRead, Read}` here on purpose: the reader is a `&mut dyn BufRead`, and a
    // trait object's own trait (and its supertraits) resolve without being imported.
    let mut requests = Vec::new();
    for p in paths {
        requests.extend_from_slice(format!("{rev}:{p}\n").as_bytes());
    }
    let want = paths.len();
    let answered = gitp::ask(cx.root(), &["cat-file", "--batch"], requests, move |out| {
        let mut got: Vec<Result<String, String>> = Vec::with_capacity(want);
        while got.len() < want {
            let mut header = String::new();
            match out.read_line(&mut header) {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
            let header = header.trim_end().to_string();
            let mut fields = header.rsplitn(3, ' ');
            let size = fields.next().and_then(|s| s.parse::<usize>().ok());
            let kind = fields.next().unwrap_or("").to_string();
            match (kind.as_str(), size) {
                ("blob", Some(n)) => {
                    let mut buf = vec![0u8; n + 1]; // the record's trailing newline
                    match out.read_exact(&mut buf) {
                        Ok(()) => {
                            buf.pop();
                            got.push(
                                String::from_utf8(buf).map_err(|e| format!("non-utf8 blob: {e}")),
                            );
                        }
                        Err(e) => got.push(Err(format!("truncated blob: {e}"))),
                    }
                }
                _ => got.push(Err(format!("git cat-file said: {header}"))),
            }
        }
        got
    })?;
    if !answered.status.success() {
        return Err(format!(
            "git cat-file --batch exited {}: {}",
            answered.status.code().unwrap_or(-1),
            answered.stderr
        ));
    }
    let mut got = answered.value;
    while got.len() < want {
        got.push(Err("git cat-file gave no record for this path".to_string()));
    }
    Ok(got)
}

// ── MEASUREMENT ──────────────────────────────────────────────────────────────────────────────────

/// Measure `source` under `cfg`. `only`, when non-empty, keeps just those crates.
pub fn measure(cx: &Ctx, source: &Source, cfg: &Config, only: &[String]) -> Result<Report, String> {
    let discovered = discover(cx, source, cfg)?;
    let discovered: Vec<(String, String)> = if only.is_empty() {
        discovered
    } else {
        let kept: Vec<(String, String)> = discovered
            .into_iter()
            .filter(|(k, _)| only.iter().any(|n| n == k))
            .collect();
        let missing: Vec<&String> = only
            .iter()
            .filter(|n| !kept.iter().any(|(k, _)| &k == n))
            .collect();
        if !missing.is_empty() {
            return Err(format!(
                "no .rs file under {missing:?} — a crate that measured nothing is under every \
                 ceiling, so this is refused rather than reported as zero"
            ));
        }
        kept
    };

    let paths: Vec<String> = discovered.iter().map(|(_, p)| p.clone()).collect();
    let texts = read_all(cx, source, &paths)?;

    // Fanned out because `syn` parses 1,441 files and the construction gate waits on this. Chunks
    // are contiguous and re-joined IN ORDER, so the output is identical at any thread count.
    let jobs = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .clamp(1, 16);
    let chunk = discovered.len().div_ceil(jobs).max(1);
    let work: Vec<(&[(String, String)], &[Result<String, String>])> =
        discovered.chunks(chunk).zip(texts.chunks(chunk)).collect();

    let mut files: Vec<FileCount> = Vec::with_capacity(discovered.len());
    let mut errors: Vec<FileError> = Vec::new();
    std::thread::scope(|scope| {
        let handles: Vec<_> = work
            .into_iter()
            .map(|(pairs, bodies)| {
                scope.spawn(move || {
                    let mut ok = Vec::new();
                    let mut bad = Vec::new();
                    for ((krate, path), body) in pairs.iter().zip(bodies.iter()) {
                        match body {
                            Err(e) => bad.push(FileError {
                                path: path.clone(),
                                krate: krate.clone(),
                                error: e.clone(),
                            }),
                            Ok(text) => {
                                match classify::classify(text, classify::is_test_path(path)) {
                                    Ok(v) => ok.push(FileCount {
                                        path: path.clone(),
                                        krate: krate.clone(),
                                        counts: v.counts,
                                    }),
                                    Err(e) => bad.push(FileError {
                                        path: path.clone(),
                                        krate: krate.clone(),
                                        error: e,
                                    }),
                                }
                            }
                        }
                    }
                    (ok, bad)
                })
            })
            .collect();
        for h in handles {
            let (ok, bad) = h.join().unwrap_or_default();
            files.extend(ok);
            errors.extend(bad);
        }
    });
    Ok(aggregate(source.label(), files, errors, cfg))
}

/// Roll per-file counts up into crates, groups and a total. Split out because an overlay patch
/// re-rolls the SAME way rather than a second way — two aggregation paths is how two numbers for
/// one tree start.
fn aggregate(
    source: String,
    mut files: Vec<FileCount>,
    mut errors: Vec<FileError>,
    cfg: &Config,
) -> Report {
    files.sort_by(|a, b| a.path.cmp(&b.path));
    errors.sort_by(|a, b| a.path.cmp(&b.path));

    let mut per_crate: BTreeMap<String, Counts> = BTreeMap::new();
    let mut total = Counts::default();
    for f in &files {
        per_crate.entry(f.krate.clone()).or_default().add(&f.counts);
        total.add(&f.counts);
    }
    // A crate whose every file failed to parse still gets a row, at zero, so the error and the
    // zero sit beside each other instead of the crate vanishing from the table.
    for e in &errors {
        per_crate.entry(e.krate.clone()).or_default();
    }
    let crates: Vec<(String, Counts)> = per_crate.into_iter().collect();

    let mut groups = Vec::new();
    for g in &cfg.groups {
        let mut inside = Counts::default();
        let mut missing = Vec::new();
        for name in &g.crates {
            match crates.binary_search_by(|(k, _)| k.as_str().cmp(name.as_str())) {
                Ok(i) => inside.add(&crates[i].1),
                Err(_) => missing.push(name.clone()),
            }
        }
        let outside = Counts {
            code: total.code - inside.code,
            doc: total.doc - inside.doc,
            comment: total.comment - inside.comment,
            blank: total.blank - inside.blank,
            test: total.test - inside.test,
        };
        groups.push(GroupCount {
            name: g.name.clone(),
            label: g.label.clone(),
            crates: g.crates.clone(),
            missing,
            inside,
            outside,
        });
    }

    Report {
        source,
        files,
        crates,
        groups,
        total,
        errors,
    }
}

/// The working tree's measurement, as every gate that ratchets a line ceiling reads it.
///
/// THE TREE IS PARSED ONCE PER PROCESS. The construction gate asks for this from two different
/// rules and its self-test asks again for every planted case; parsing 1,441 files each time is both
/// slow and — much worse — several chances for several answers, which is the exact defect this
/// module exists to end.
///
/// AN OVERLAY IS A PATCH, NOT A SECOND TREE. A self-test plants a handful of files; re-parsing the
/// whole repository to see three of them changed would make `--selftest` minutes long. Only the
/// planted paths are re-classified, and the roll-up runs again through the SAME [`aggregate`] the
/// full measurement uses, so a planted answer and a real one cannot be arrived at two ways.
pub fn measure_worktree_cached(cx: &Ctx) -> Result<Arc<Report>, String> {
    let cfg = Config::load(cx.root())?;
    let base = base_report(cx, &cfg)?;
    let Some(overlay) = cx.overlay() else {
        return Ok(base);
    };

    let mut files: BTreeMap<String, FileCount> = base
        .files
        .iter()
        .map(|f| (f.path.clone(), f.clone()))
        .collect();
    let mut errors: BTreeMap<String, FileError> = base
        .errors
        .iter()
        .map(|e| (e.path.clone(), e.clone()))
        .collect();
    for path in overlay.paths() {
        let rel = path.to_string_lossy().replace('\\', "/");
        if !rel.ends_with(".rs") {
            continue;
        }
        let Some(krate) = crate_of(&rel, &cfg) else {
            continue;
        };
        files.remove(&rel);
        errors.remove(&rel);
        if !cx.exists(&rel) {
            continue; // planted ABSENT: the file is gone from this tree's view.
        }
        match cx.read(&rel) {
            Err(e) => {
                errors.insert(
                    rel.clone(),
                    FileError {
                        path: rel,
                        krate,
                        error: e,
                    },
                );
            }
            Ok(text) => match classify::classify(&text, classify::is_test_path(&rel)) {
                Ok(v) => {
                    files.insert(
                        rel.clone(),
                        FileCount {
                            path: rel,
                            krate,
                            counts: v.counts,
                        },
                    );
                }
                Err(e) => {
                    errors.insert(
                        rel.clone(),
                        FileError {
                            path: rel,
                            krate,
                            error: e,
                        },
                    );
                }
            },
        }
    }
    Ok(Arc::new(aggregate(
        base.source.clone(),
        files.into_values().collect(),
        errors.into_values().collect(),
        &cfg,
    )))
}

/// The unplanted tree, measured once and remembered per root.
fn base_report(cx: &Ctx, cfg: &Config) -> Result<Arc<Report>, String> {
    static MEMO: OnceLock<Mutex<BTreeMap<PathBuf, Arc<Report>>>> = OnceLock::new();
    let memo = MEMO.get_or_init(|| Mutex::new(BTreeMap::new()));
    if let Ok(guard) = memo.lock() {
        if let Some(hit) = guard.get(cx.root()) {
            return Ok(hit.clone());
        }
    }
    // Deliberately a context with NO overlay: this is the tree on disk, and the planted view is
    // layered on top of it above. Reading the overlay here would cache one self-test's plant as
    // every later caller's baseline.
    let bare = Ctx::at(cx.root(), cx.scratch())?;
    let report = Arc::new(measure(&bare, &Source::Worktree, cfg, &[])?);
    if let Ok(mut guard) = memo.lock() {
        guard.insert(cx.root().to_path_buf(), report.clone());
    }
    Ok(report)
}

// ── THE COMMAND ──────────────────────────────────────────────────────────────────────────────────

const USAGE: &str = "\
usage:
  cargo xtask loc [--ref <rev>] [--format json|table] [--per-file] [--ceiling CRATES=N]... [<crate>...]
  cargo xtask loc --selftest

  --ref <rev>        measure a git ref through its object store, without checking anything out
  --format json      the default; --format table is the human render
  --per-file         include the per-file rows (JSON and table)
  --ceiling C[,C]=N  assert the summed `code` of those crates is at most N; repeatable
  --selftest         drive the counter over fixtures of hand-verified count, then exit";

pub fn main(cx: &Ctx, args: &[String]) -> i32 {
    if args.iter().any(|a| a == "--selftest") {
        return selftest::run();
    }
    if args.iter().any(|a| a == "-h" || a == "--help") {
        println!("{USAGE}");
        return 0;
    }

    let mut source = Source::Worktree;
    let mut format = "json".to_string();
    let mut per_file = false;
    let mut ceilings: Vec<(Vec<String>, u64)> = Vec::new();
    let mut only: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        match a {
            "--per-file" => per_file = true,
            "--ref" | "--format" | "--ceiling" => {
                let Some(v) = args.get(i + 1) else {
                    eprintln!("xtask loc: {a} wants a value");
                    eprintln!("{USAGE}");
                    return 2;
                };
                match a {
                    "--ref" => source = Source::Rev(v.clone()),
                    "--format" => format = v.clone(),
                    _ => match parse_ceiling(v) {
                        Ok(c) => ceilings.push(c),
                        Err(e) => {
                            eprintln!("xtask loc: {e}");
                            return 2;
                        }
                    },
                }
                i += 1;
            }
            other if other.starts_with("--") => {
                if let Some(v) = other.strip_prefix("--ref=") {
                    source = Source::Rev(v.to_string());
                } else if let Some(v) = other.strip_prefix("--format=") {
                    format = v.to_string();
                } else if let Some(v) = other.strip_prefix("--ceiling=") {
                    match parse_ceiling(v) {
                        Ok(c) => ceilings.push(c),
                        Err(e) => {
                            eprintln!("xtask loc: {e}");
                            return 2;
                        }
                    }
                } else {
                    eprintln!("xtask loc: unknown flag `{other}`");
                    eprintln!("{USAGE}");
                    return 2;
                }
            }
            name => only.push(name.to_string()),
        }
        i += 1;
    }
    if format != "json" && format != "table" {
        eprintln!("xtask loc: --format wants `json` or `table`, got `{format}`");
        return 2;
    }

    let cfg = match Config::load(cx.root()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("xtask loc: {e}");
            return 3;
        }
    };
    let report = match measure(cx, &source, &cfg, &only) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("xtask loc: {e}");
            return 3;
        }
    };

    if format == "table" {
        print!("{}", render::table(&report, per_file));
    } else {
        println!("{}", render::json(&report, per_file));
    }

    let mut red = !report.errors.is_empty();
    if red {
        eprintln!(
            "xtask loc: {} file(s) could not be parsed and were counted as NOTHING. A counter that \
             guesses is the defect this replaces.",
            report.errors.len()
        );
        for e in &report.errors {
            eprintln!("  {} — {}", e.path, e.error);
        }
    }
    for (crates, limit) in &ceilings {
        let label = crates.join("+");
        let mut sum = 0u64;
        let mut missing = Vec::new();
        for name in crates {
            match report.crate_counts(name) {
                Some(c) => sum += c.code,
                None => missing.push(name.clone()),
            }
        }
        if !missing.is_empty() {
            eprintln!(
                "FAIL  {label}  names crates this run did not measure: {}. A ceiling is a statement \
                 about code; there has to be some.",
                missing.join(", ")
            );
            red = true;
        } else if sum == 0 {
            eprintln!(
                "FAIL  {label}  measured 0 code lines. A crate with no code is under every \
                 ceiling, so this is not a pass — point the ceiling at where the code went."
            );
            red = true;
        } else if sum > *limit {
            eprintln!("FAIL  {label}  {sum} > {limit}");
            red = true;
        } else {
            eprintln!("ok    {label}  {sum} <= {limit}");
        }
    }
    i32::from(red)
}

fn parse_ceiling(spec: &str) -> Result<(Vec<String>, u64), String> {
    let (names, limit) = spec
        .rsplit_once('=')
        .ok_or_else(|| format!("--ceiling wants <crate>[,<crate>...]=<n>, got `{spec}`"))?;
    let value: u64 = limit
        .trim()
        .parse()
        .map_err(|_| format!("--ceiling: not a line count: `{limit}`"))?;
    let crates: Vec<String> = names
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    if crates.is_empty() {
        return Err(format!("--ceiling names no crate: `{spec}`"));
    }
    Ok((crates, value))
}
