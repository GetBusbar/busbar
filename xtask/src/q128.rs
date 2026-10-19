//! `cargo xtask q128 audit` — THE Q128 ARCHITECTURE AUDIT, JUDGED ON THE CURRENT TREE.
//!
//! DEV-GREEN item 5 (`docs/design/BUSBAR-1.6.0.md` l.2910-2912; `1.6.0-QUESTIONS.md` Q128, owner
//! 2026-10-01, option A): *"one fresh, independent architecture audit on the DEV-GREEN candidate
//! sha, graded against the Laws and THE DESIGN; it passes with no open BLOCK findings"* and, in the
//! owner's answer, *"a clean audit ledger"*. The TODO's 17.4 puts it last: the audit runs over the
//! finished code.
//!
//! The grading itself is an auditor's reading, not a scan. What this command owns is everything
//! around that reading that a machine can hold to a rule:
//!
//! 1. **THE AUDIT IS ON THIS TREE.** The auditor's record (`qa/q128-audit.json`) names the commit it
//!    read. Its tree must be the tree being judged. No record, a record naming no commit, a commit
//!    that does not resolve, or a commit whose tree differs from HEAD's is a BLOCK: the audit the
//!    spec asks for has not been made on this candidate, and an audit of another tree is not one.
//!    The one path that may differ is the record itself. The record is committed in the tree it
//!    judges and names a commit by its id. A commit cannot contain its own id, so the record can
//!    never be on the commit it names. Every other path, the audit ledger included, must be
//!    byte-identical to the candidate's.
//! 2. **THE AUDIT'S OWN FINDINGS.** Each finding the auditor recorded carries a severity (BLOCK,
//!    HIGH, MEDIUM, LOW), a scope, its evidence and the Law or DESIGN line it is graded against. An
//!    open BLOCK fails the audit. A finding is closed only with the change that closed it named,
//!    and the name is CHECKED, never taken on the record's word (Q128 arch u93): `closed_by` names
//!    at least one full commit id, every commit it names resolves here and is the candidate or an
//!    ancestor of it (the change is in the code that was read), and every pull request it names
//!    (`owner/repo#N`, `#N`, `PR N`, or a `github.com/<owner>/<repo>/pull/N` link) exists. A
//!    finding the record already carried OPEN on the same candidate, in any committed version of
//!    the record, stays open at no lower severity: a record-only edit cannot close, lower or drop
//!    it. Closing it takes a fresh audit of a new candidate.
//! 3. **THE AUDIT LEDGER IS CLEAN.** `cargo xtask ledger --check`'s computation, run here on the
//!    same tree. A red ledger is a BLOCK, and so is a ledger below its floor whatever its rules say:
//!    every production scope `clean` (two zero rounds from distinct auditors at the current hash),
//!    over a denominator that is not empty. Each scope it holds open at HIGH or MEDIUM is listed as
//!    a finding at that severity, so the record says where the debt is.
//! 4. **AN UNREADABLE ENTRY IS A BLOCK, NEVER GUESSED.** A severity outside the four, a status
//!    outside `open`/`closed`, a closed finding naming no change, a finding with no scope or no
//!    evidence: each is a BLOCK naming what is wrong. A record nobody can read cannot pass.
//!
//! THE RESULT is written, every run, to `target/q128-audit.json` under the workspace root (or
//! `--out <path>`): the tree, the inputs read, every finding, the open counts per severity, and
//! the verdict. Exit codes are the CLI's contract: **0** no open BLOCK, **1** at least one open
//! BLOCK, **2** wrong arguments, **3** the result could not be written.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{json, Value};

use crate::audit::Git;
use crate::audit_cmd::{self, CheckFindings};

/// The auditor's record, relative to the workspace root.
pub const RECORD_REL: &str = "qa/q128-audit.json";

/// The severities a Q128 finding can carry, gravest first.
pub const SEVERITIES: [&str; 4] = ["BLOCK", "HIGH", "MEDIUM", "LOW"];

/// The spec lines every record cites.
const CITE: &str = "docs/design/BUSBAR-1.6.0.md l.2910-2912 (DEV-GREEN item 5); \
docs/design/1.6.0-QUESTIONS.md Q128 (owner 2026-10-01, option A)";

const USAGE: &str = "\
usage:
  cargo xtask q128 audit [--record <path>] [--out <path>]
    judge the Q128 architecture audit on the current tree; writes target/q128-audit.json;
    exit 0 no open BLOCK, 1 an open BLOCK, 2 wrong arguments, 3 the result could not be written";

/// The result file, under the workspace root.
fn default_out(root: &Path) -> PathBuf {
    root.join("target").join("q128-audit.json")
}

pub fn main(root: &Path, args: &[String]) -> i32 {
    let mut record = root.join(RECORD_REL);
    let mut out = default_out(root);
    let Some((sub, rest)) = args.split_first() else {
        eprintln!("{USAGE}");
        return 2;
    };
    if sub != "audit" {
        eprintln!("xtask q128: unknown subcommand `{sub}`\n{USAGE}");
        return 2;
    }
    let mut i = 0;
    while i < rest.len() {
        let (flag, val) = (rest[i].as_str(), rest.get(i + 1));
        match (flag, val) {
            ("--record", Some(v)) => record = PathBuf::from(v),
            ("--out", Some(v)) => out = PathBuf::from(v),
            _ => {
                eprintln!("xtask q128 audit: unexpected argument `{flag}`\n{USAGE}");
                return 2;
            }
        }
        i += 2;
    }

    let head = rev(root, "HEAD");
    let head_tree = rev(root, "HEAD^{tree}");
    let record_text = match std::fs::read_to_string(&record) {
        Ok(t) => Some(t),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => Some(format!("\u{0}unreadable: {e}")),
    };
    let ledger = audit_cmd::check(&Git::new(root), &root.join(crate::audit::REGISTER_REL))
        .map(|f| LedgerView::of(&f));
    let report = judge(&Inputs {
        head: head.as_deref(),
        head_tree: head_tree.as_deref(),
        record_path: &display_rel(root, &record),
        record_text: record_text.as_deref(),
        tree_of: &|c: &str| rev(root, &format!("{c}^{{tree}}")),
        changed: &|c: &str| changed_paths(root, c),
        is_ancestor: &|a: &str, b: &str| is_ancestor(root, a, b),
        pr_exists: &|repo: &str, n: u64| pr_exists(root, repo, n),
        record_history: &|| record_history(root, &display_rel(root, &record)),
        ledger,
    });

    let text = serde_json::to_string_pretty(&report.json).unwrap_or_default() + "\n";
    if let Some(dir) = out.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    if let Err(e) = std::fs::write(&out, text) {
        eprintln!("xtask q128 audit: could not write {}: {e}", out.display());
        return 3;
    }
    for f in &report.findings {
        if f.get("status").and_then(Value::as_str) == Some("open") {
            println!(
                "{:<6} {}  {}",
                f.get("severity").and_then(Value::as_str).unwrap_or("?"),
                f.get("scope").and_then(Value::as_str).unwrap_or("?"),
                f.get("title").and_then(Value::as_str).unwrap_or("")
            );
        }
    }
    println!(
        "q128 audit: {} ({}) on {}; record: {}",
        report.verdict(),
        SEVERITIES
            .iter()
            .map(|s| format!("{s} {}", report.open(s)))
            .collect::<Vec<_>>()
            .join(", "),
        head.as_deref().unwrap_or("<no HEAD>"),
        out.display()
    );
    if report.open("BLOCK") > 0 {
        1
    } else {
        0
    }
}

fn display_rel(root: &Path, p: &Path) -> String {
    p.strip_prefix(root)
        .unwrap_or(p)
        .to_string_lossy()
        .into_owned()
}

/// `git rev-parse --verify <spec>` in `root`, or `None` when it does not resolve.
fn rev(root: &Path, spec: &str) -> Option<String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["rev-parse", "--verify", "--quiet", spec])
        .output()
        .ok()?;
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (out.status.success() && !s.is_empty()).then_some(s)
}

/// Every path whose blob differs between commit `c` and HEAD. This includes paths that one side
/// has and the other lacks. Returns `None` when git cannot answer.
fn changed_paths(root: &Path, c: &str) -> Option<Vec<String>> {
    let out = Command::new("git")
        .arg("-C")
        .arg(root)
        .args([
            "diff-tree",
            "-r",
            "-z",
            "--no-renames",
            "--name-only",
            c,
            "HEAD",
        ])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(
        out.stdout
            .split(|b| *b == 0)
            .filter(|p| !p.is_empty())
            .map(|p| String::from_utf8_lossy(p).into_owned())
            .collect(),
    )
}

/// `git merge-base --is-ancestor a b`: `Some(true)` when `a` is `b` or an ancestor of it,
/// `Some(false)` when it is not, `None` when git cannot answer (an id that names no commit
/// included).
fn is_ancestor(root: &Path, a: &str, b: &str) -> Option<bool> {
    let st = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["merge-base", "--is-ancestor", a, b])
        .status()
        .ok()?;
    match st.code() {
        Some(0) => Some(true),
        Some(1) => Some(false),
        _ => None,
    }
}

/// `owner/name` of a GitHub remote URL (`https://github.com/o/n(.git)`, `git@github.com:o/n`).
fn github_repo_of(url: &str) -> Option<String> {
    let rest = url
        .split_once("github.com/")
        .or_else(|| url.split_once("github.com:"))?
        .1;
    let rest = rest.trim_end_matches('/');
    let rest = rest.strip_suffix(".git").unwrap_or(rest);
    let mut it = rest.split('/');
    let (o, n) = (it.next()?, it.next()?);
    (!o.is_empty() && !n.is_empty() && it.next().is_none()).then(|| format!("{o}/{n}"))
}

/// Whether pull request `n` of `repo` exists. This repository's own pull requests are asked of
/// `origin` (`refs/pull/<n>/head`, through the credentials the checkout already uses); any other
/// repository's through `gh api`. `Err` when neither can answer: an unverifiable name is never
/// read as a real one.
fn pr_exists(root: &Path, repo: &str, n: u64) -> Result<bool, String> {
    let origin = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["remote", "get-url", "origin"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| github_repo_of(String::from_utf8_lossy(&o.stdout).trim()));
    if origin
        .as_deref()
        .is_some_and(|o| o.eq_ignore_ascii_case(repo))
    {
        let out = Command::new("git")
            .arg("-C")
            .arg(root)
            .args(["ls-remote", "origin", &format!("refs/pull/{n}/head")])
            .output()
            .map_err(|e| format!("git ls-remote could not run: {e}"))?;
        if out.status.success() {
            return Ok(!String::from_utf8_lossy(&out.stdout).trim().is_empty());
        }
    }
    let out = Command::new("gh")
        .args(["api", &format!("repos/{repo}/pulls/{n}"), "--jq", ".number"])
        .output()
        .map_err(|e| format!("neither origin nor `gh` could answer for {repo}#{n}: {e}"))?;
    let said = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if out.status.success() {
        return Ok(said == n.to_string());
    }
    let err = String::from_utf8_lossy(&out.stderr);
    if err.contains("HTTP 404") || said.contains("Not Found") {
        return Ok(false);
    }
    Err(format!(
        "neither origin nor `gh` could answer for {repo}#{n}: {}",
        err.trim()
    ))
}

/// Every committed version of the record reachable from HEAD, oldest first, or `None` when git
/// cannot list them.
fn record_history(root: &Path, rel: &str) -> Option<Vec<String>> {
    let out = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["log", "--reverse", "--format=%H", "HEAD", "--", rel])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let mut texts = Vec::new();
    for c in String::from_utf8_lossy(&out.stdout).lines() {
        let show = Command::new("git")
            .arg("-C")
            .arg(root)
            .args(["show", &format!("{c}:{rel}")])
            .output()
            .ok()?;
        // A commit that deleted the record has no blob there and carries nothing to hold.
        if show.status.success() {
            texts.push(String::from_utf8_lossy(&show.stdout).into_owned());
        }
    }
    Some(texts)
}

/// What the audit ledger's `--check` found, reduced to what the record carries.
pub struct LedgerView {
    pub red: bool,
    /// `(rule, count)` for every rule of the check, in its print order.
    pub rules: Vec<(&'static str, usize)>,
    /// The scopes held open at HIGH/MEDIUM, each as `--check` prints it.
    pub opens: Vec<String>,
    pub scopes: usize,
    /// The floor's denominator: the production scopes, and how many of them are `clean`.
    pub production: usize,
    pub production_clean: usize,
    pub clean_pct: f64,
}

impl LedgerView {
    pub fn of(f: &CheckFindings) -> LedgerView {
        LedgerView {
            red: f.red(),
            rules: vec![
                ("coverage-gaps", f.gaps.len()),
                ("unscoped-dirs", f.unscoped.len()),
                ("missing-scopes", f.missing.len()),
                ("unreadable-entries", f.problems.len()),
                ("invalid-results", f.invalid.len()),
                ("open-high-medium", f.opens.len()),
                ("stamped-off-tree", f.stamped.len()),
                ("unreachable-commits", f.unreachable.len()),
                ("phantom-paths", f.phantom.len()),
                ("fixed-unconfirmed", f.owed.len()),
                ("excuse-drift", f.excuses.len()),
                ("shape-drift", f.shapes.len()),
                ("below-floor", f.unclean.len()),
            ],
            opens: f.opens.clone(),
            scopes: f.scopes,
            production: f.production,
            production_clean: f.production_clean,
            clean_pct: f.clean_pct,
        }
    }
}

/// Everything the judgement reads, so it can be judged without a repository.
pub struct Inputs<'a> {
    pub head: Option<&'a str>,
    pub head_tree: Option<&'a str>,
    pub record_path: &'a str,
    /// The record's text; `None` when there is no record. A read error arrives as text that is not
    /// JSON and is judged unreadable.
    pub record_text: Option<&'a str>,
    /// The tree of a commit, or `None` when it does not resolve.
    pub tree_of: &'a dyn Fn(&str) -> Option<String>,
    /// The paths whose blobs differ between a commit and HEAD, or `None` when git cannot say.
    pub changed: &'a dyn Fn(&str) -> Option<Vec<String>>,
    /// Whether the first commit is the second or an ancestor of it, or `None` when git cannot say.
    pub is_ancestor: &'a dyn Fn(&str, &str) -> Option<bool>,
    /// Whether a pull request (`owner/repo`, number) exists; `Err` when it cannot be asked.
    pub pr_exists: &'a dyn Fn(&str, u64) -> Result<bool, String>,
    /// Every committed version of the record, oldest first; `None` when git cannot list them.
    pub record_history: &'a dyn Fn() -> Option<Vec<String>>,
    pub ledger: Result<LedgerView, String>,
}

pub struct Report {
    pub findings: Vec<Value>,
    pub json: Value,
}

impl Report {
    /// The number of OPEN findings at `severity`.
    pub fn open(&self, severity: &str) -> usize {
        self.findings
            .iter()
            .filter(|f| {
                f.get("status").and_then(Value::as_str) == Some("open")
                    && f.get("severity").and_then(Value::as_str) == Some(severity)
            })
            .count()
    }

    pub fn verdict(&self) -> &'static str {
        if self.open("BLOCK") > 0 {
            "BLOCK"
        } else {
            "PASS"
        }
    }
}

fn finding(
    severity: &str,
    source: &str,
    scope: &str,
    title: &str,
    evidence: &str,
    cite: &str,
) -> Value {
    json!({
        "severity": severity,
        "source": source,
        "scope": scope,
        "title": title,
        "evidence": evidence,
        "cite": cite,
        "status": "open",
    })
}

fn nonempty_str<'v>(v: &'v Value, key: &str) -> Option<&'v str> {
    v.get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
}

fn is_full_oid(s: &str) -> bool {
    s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// THE JUDGEMENT. Pure: every git answer arrives in `inp`.
pub fn judge(inp: &Inputs<'_>) -> Report {
    let mut findings: Vec<Value> = Vec::new();
    let mut audit = json!({ "record": inp.record_path, "present": inp.record_text.is_some() });

    // 1 + 2 + 4: the auditor's record.
    match inp.record_text.map(serde_json::from_str::<Value>) {
        None => findings.push(finding(
            "BLOCK",
            "q128",
            inp.record_path,
            "no architecture audit is recorded",
            &format!(
                "{} does not exist, so no fresh audit of this tree has been recorded",
                inp.record_path
            ),
            CITE,
        )),
        Some(Err(e)) => findings.push(finding(
            "BLOCK",
            "q128",
            inp.record_path,
            "the audit record is unreadable",
            &format!("{} is not JSON: {e}", inp.record_path),
            CITE,
        )),
        Some(Ok(rec)) => {
            let candidate = rec.get("candidate").and_then(Value::as_str);
            audit["candidate"] = json!(candidate);
            audit["auditor"] = rec.get("auditor").cloned().unwrap_or(Value::Null);
            let on_tree = match candidate {
                None => {
                    findings.push(finding(
                        "BLOCK",
                        "q128",
                        inp.record_path,
                        "the audit record names no candidate commit",
                        "`candidate` is null: the audit has not been made on any commit",
                        CITE,
                    ));
                    false
                }
                Some(c) if !is_full_oid(c) => {
                    findings.push(finding(
                        "BLOCK",
                        "q128",
                        inp.record_path,
                        "the audit record's candidate is not a full commit id",
                        &format!("`candidate` is `{c}`; a record names the 40-hex commit it read"),
                        CITE,
                    ));
                    false
                }
                Some(c) => match ((inp.tree_of)(c), inp.head_tree) {
                    (None, _) => {
                        findings.push(finding(
                            "BLOCK",
                            "q128",
                            inp.record_path,
                            "the audited commit does not resolve",
                            &format!("candidate {c} is not in this repository, so the tree it read cannot be produced"),
                            CITE,
                        ));
                        false
                    }
                    (Some(t), Some(h)) if t == h => true,
                    (Some(t), h) => {
                        // THE RECORD IS THE ONE PATH ALLOWED TO DIFFER. It names the candidate by
                        // id, so it cannot be inside the candidate's tree. Any other path that
                        // moved, or a git that cannot list what moved, keeps this a BLOCK.
                        let moved = (inp.changed)(c);
                        let only_record = h.is_some()
                            && moved.as_ref().is_some_and(|ps| {
                                !ps.is_empty() && ps.iter().all(|p| p == inp.record_path)
                            });
                        if only_record {
                            audit["differs_only_in_record"] = json!(true);
                            true
                        } else {
                            let what = match &moved {
                                None => "git could not list the paths that differ".to_string(),
                                Some(ps) => {
                                    let other: Vec<&str> = ps
                                        .iter()
                                        .map(String::as_str)
                                        .filter(|p| *p != inp.record_path)
                                        .collect();
                                    let shown: Vec<&str> = other.iter().take(10).copied().collect();
                                    let more = other.len().saturating_sub(shown.len());
                                    format!(
                                        "{} path(s) other than the record differ: {}{}",
                                        other.len(),
                                        shown.join(", "),
                                        if more > 0 {
                                            format!(" and {more} more")
                                        } else {
                                            String::new()
                                        }
                                    )
                                }
                            };
                            findings.push(finding(
                                "BLOCK",
                                "q128",
                                inp.record_path,
                                "the audit was made on another tree",
                                &format!(
                                    "candidate {c} has tree {t}; HEAD {} has tree {}; {what}: the audit expired when the code moved",
                                    inp.head.unwrap_or("?"),
                                    h.unwrap_or("?")
                                ),
                                CITE,
                            ));
                            false
                        }
                    }
                },
            };
            audit["on_this_tree"] = json!(on_tree);
            if candidate.is_some() && nonempty_str(&rec, "auditor").is_none() {
                findings.push(finding(
                    "BLOCK",
                    "q128",
                    inp.record_path,
                    "the audit record names no auditor",
                    "`auditor` is empty: an independent audit says who made it",
                    CITE,
                ));
            }
            let listed = rec.get("findings").and_then(Value::as_array);
            if listed.is_none() {
                findings.push(finding(
                    "BLOCK",
                    "q128",
                    inp.record_path,
                    "the audit record carries no findings list",
                    "`findings` is missing or not a list (an audit with nothing to report writes [])",
                    CITE,
                ));
            }
            // A closure is judged against the commit that was read: the candidate when it
            // resolves, HEAD otherwise (that record is already a BLOCK, and its closures are
            // still held to a real change).
            let anchor = candidate
                .filter(|c| is_full_oid(c) && (inp.tree_of)(c).is_some())
                .or(inp.head);
            for (i, f) in listed.into_iter().flatten().enumerate() {
                findings.push(read_finding(inp, anchor, i, f));
            }
            if let (Some(c), Some(now)) = (candidate.filter(|c| is_full_oid(c)), listed) {
                findings.extend(held_open(inp, c, now));
            }
        }
    }

    // 3: the audit ledger.
    let ledger = match &inp.ledger {
        Err(e) => {
            findings.push(finding(
                "BLOCK",
                "audit-ledger",
                crate::audit::REGISTER_REL,
                "the audit ledger could not be read",
                e,
                CITE,
            ));
            json!({ "readable": false, "error": e })
        }
        Ok(l) => {
            // "A CLEAN AUDIT LEDGER" IS THE FLOOR MET, judged here and not taken on the check's
            // word: every production scope clean, over a denominator that is not empty. A view
            // whose rules are all quiet while that is false is still not a clean ledger.
            let floor_met = l.production > 0 && l.production_clean == l.production;
            if l.red || !floor_met {
                let rules: Vec<String> = l
                    .rules
                    .iter()
                    .filter(|(_, n)| *n > 0)
                    .map(|(r, n)| format!("{r} {n}"))
                    .collect();
                findings.push(finding(
                    "BLOCK",
                    "audit-ledger",
                    crate::audit::REGISTER_REL,
                    "the audit ledger is not clean",
                    &format!(
                        "`cargo xtask ledger --check` is red: {}; floor: {}; {} of {} production \
                         scope(s) clean ({:.1}% of production LOC), {} scope(s) in all",
                        rules.join(", "),
                        audit_cmd::FLOOR,
                        l.production_clean,
                        l.production,
                        l.clean_pct,
                        l.scopes
                    ),
                    CITE,
                ));
            }
            for line in &l.opens {
                let scope = line.split_whitespace().next().unwrap_or(line);
                let high = line.split([' ', ',']).any(|t| {
                    t.strip_prefix("HIGH=")
                        .and_then(|n| n.parse::<i64>().ok())
                        .is_some_and(|n| n != 0)
                });
                let sev = if high || line.contains("severities unrecorded") {
                    "HIGH"
                } else {
                    "MEDIUM"
                };
                findings.push(finding(
                    sev,
                    "audit-ledger",
                    scope,
                    "audit-ledger scope open at HIGH/MEDIUM",
                    &format!("{}: {line}", crate::audit::REGISTER_REL),
                    CITE,
                ));
            }
            json!({
                "readable": true,
                "clean": !l.red && floor_met,
                "floor": audit_cmd::FLOOR,
                "scopes": l.scopes,
                "production_scopes": l.production,
                "production_clean": l.production_clean,
                "production_clean_pct": (l.clean_pct * 10.0).round() / 10.0,
                "rules": l.rules.iter().map(|(r, n)| json!({ "rule": r, "count": n })).collect::<Vec<_>>(),
            })
        }
    };

    let mut counts = serde_json::Map::new();
    let tmp = Report {
        findings,
        json: Value::Null,
    };
    for s in SEVERITIES {
        counts.insert(s.to_string(), json!(tmp.open(s)));
    }
    let verdict = tmp.verdict();
    let Report { findings, .. } = tmp;
    let json = json!({
        "schema": "busbar.q128-audit/1",
        "spec": CITE,
        "head": inp.head,
        "head_tree": inp.head_tree,
        "audit": audit,
        "ledger": ledger,
        "open": counts,
        "verdict": verdict,
        "findings": findings,
    });
    Report { findings, json }
}

/// One finding of the auditor's record, held to the format. A finding that breaks it becomes a BLOCK
/// naming what is wrong; it is never read as whatever it might have meant.
fn read_finding(inp: &Inputs<'_>, anchor: Option<&str>, i: usize, f: &Value) -> Value {
    let record_path = inp.record_path;
    let id = nonempty_str(f, "id").unwrap_or("").to_string();
    let label = if id.is_empty() {
        format!("findings[{i}]")
    } else {
        format!("findings[{i}] `{id}`")
    };
    let mut wrong: Vec<String> = Vec::new();
    let severity = f.get("severity").and_then(Value::as_str);
    if !severity.is_some_and(|s| SEVERITIES.contains(&s)) {
        wrong.push(format!(
            "severity {:?} is not one of {}",
            severity,
            SEVERITIES.join("/")
        ));
    }
    let status = f.get("status").and_then(Value::as_str);
    if !matches!(status, Some("open" | "closed")) {
        wrong.push(format!("status {status:?} is not open/closed"));
    }
    if status == Some("closed") {
        match nonempty_str(f, "closed_by") {
            None => wrong.push("a closed finding names no change in `closed_by`".to_string()),
            Some(by) => wrong.extend(closure_problems(inp, anchor, by)),
        }
    }
    for key in ["id", "scope", "evidence", "cite"] {
        if nonempty_str(f, key).is_none() {
            wrong.push(format!("`{key}` is empty"));
        }
    }
    if !wrong.is_empty() {
        return finding(
            "BLOCK",
            "q128",
            record_path,
            &format!("{label} is unreadable"),
            &wrong.join("; "),
            CITE,
        );
    }
    let mut out = finding(
        severity.unwrap_or("BLOCK"),
        "q128",
        nonempty_str(f, "scope").unwrap_or(""),
        nonempty_str(f, "title").unwrap_or(&id),
        nonempty_str(f, "evidence").unwrap_or(""),
        nonempty_str(f, "cite").unwrap_or(""),
    );
    out["id"] = json!(id);
    out["status"] = json!(status);
    if let Some(by) = nonempty_str(f, "closed_by") {
        out["closed_by"] = json!(by);
    }
    out
}

/// The repository a bare `#N` / `PR N` names.
const HOME_REPO: &str = "GetBusbar/busbar";

/// The full commit ids `closed_by` names (a bare 40-hex word, or the tail of a `/commit/<id>`
/// link).
fn named_commits(by: &str) -> Vec<String> {
    by.split(|c: char| c.is_whitespace() || ",;()[]<>@'\"`".contains(c))
        .filter_map(|w| {
            let w = w.rsplit('/').next().unwrap_or(w).trim_end_matches('.');
            is_full_oid(w).then(|| w.to_ascii_lowercase())
        })
        .collect()
}

fn is_repo(w: &str) -> bool {
    let mut it = w.split('/');
    matches!((it.next(), it.next(), it.next()), (Some(o), Some(n), None) if !o.is_empty() && !n.is_empty())
}

/// The pull requests `closed_by` names, as (`owner/repo`, number): `owner/repo#N`, `#N`,
/// `[owner/repo] PR N` / `PR #N` / `pull N`, and `github.com/<owner>/<repo>/pull/N` links. A bare
/// number is this repository's.
fn named_prs(by: &str) -> Vec<(String, u64)> {
    let words: Vec<&str> = by
        .split(|c: char| c.is_whitespace() || ",;()[]<>'\"`".contains(c))
        .filter(|w| !w.is_empty())
        .collect();
    let num = |s: &str| -> Option<u64> {
        let s = s.trim_end_matches(['.', ':']);
        if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) {
            s.parse().ok()
        } else {
            None
        }
    };
    let mut out = Vec::new();
    for (i, w) in words.iter().enumerate() {
        if let Some((_, tail)) = w.split_once("github.com/") {
            let parts: Vec<&str> = tail.split('/').collect();
            if parts.len() >= 4 && parts[2] == "pull" {
                if let Some(n) = num(parts[3]) {
                    out.push((format!("{}/{}", parts[0], parts[1]), n));
                }
            }
            continue;
        }
        let pr_word = |k: usize| {
            words
                .get(k)
                .is_some_and(|p| p.eq_ignore_ascii_case("pr") || p.eq_ignore_ascii_case("pull"))
        };
        let repo_before = |k: usize| -> String {
            k.checked_sub(1)
                .and_then(|j| words.get(j))
                .filter(|p| is_repo(p))
                .map_or(HOME_REPO.to_string(), |p| p.to_string())
        };
        if let Some((left, right)) = w.split_once('#') {
            if let Some(n) = num(right) {
                let repo = if is_repo(left) {
                    left.to_string()
                } else if left.is_empty() && i > 0 && pr_word(i - 1) {
                    repo_before(i - 1)
                } else {
                    HOME_REPO.to_string()
                };
                out.push((repo, n));
            }
        } else if pr_word(i) {
            if let Some(n) = words.get(i + 1).and_then(|n| num(n)) {
                out.push((repo_before(i), n));
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Why a `closed_by` does not name a real change in the code that was read (empty when it does).
fn closure_problems(inp: &Inputs<'_>, anchor: Option<&str>, by: &str) -> Vec<String> {
    let mut wrong = Vec::new();
    let commits = named_commits(by);
    if commits.is_empty() {
        wrong.push(format!(
            "`closed_by` ({by}) names no full commit id: a closure names the commit that carries it"
        ));
    }
    for c in &commits {
        if (inp.tree_of)(c).is_none() {
            wrong.push(format!("`closed_by` commit {c} is not in this repository"));
            continue;
        }
        match anchor.map(|a| (inp.is_ancestor)(c, a)) {
            Some(Some(true)) => {}
            Some(Some(false)) => wrong.push(format!(
                "`closed_by` commit {c} is not in the audited history: it is not {} or an ancestor of it",
                anchor.unwrap_or("?")
            )),
            Some(None) | None => wrong.push(format!(
                "git could not say whether `closed_by` commit {c} is in the audited history"
            )),
        }
    }
    for (repo, n) in named_prs(by) {
        match (inp.pr_exists)(&repo, n) {
            Ok(true) => {}
            Ok(false) => wrong.push(format!(
                "`closed_by` names {repo}#{n}, which does not exist"
            )),
            Err(e) => wrong.push(format!(
                "`closed_by` names {repo}#{n}, which could not be verified: {e}"
            )),
        }
    }
    wrong
}

/// A finding a committed version of the record carried OPEN on this same candidate stays open at
/// no lower severity. The code has not moved (it is the candidate's), so only a fresh audit of a
/// new candidate can close it, never an edit of the record.
fn held_open(inp: &Inputs<'_>, candidate: &str, now: &[Value]) -> Vec<Value> {
    let Some(history) = (inp.record_history)() else {
        return vec![finding(
            "BLOCK",
            "q128",
            inp.record_path,
            "the audit record's history could not be read",
            "git could not list the committed versions of the record, so a finding closed by a \
             record-only edit cannot be told from one closed by a fresh audit",
            CITE,
        )];
    };
    let rank = |s: Option<&str>| s.and_then(|s| SEVERITIES.iter().position(|x| *x == s));
    let mut wrong: Vec<String> = Vec::new();
    for text in &history {
        let Ok(old) = serde_json::from_str::<Value>(text) else {
            continue;
        };
        if old.get("candidate").and_then(Value::as_str) != Some(candidate) {
            continue;
        }
        for f in old
            .get("findings")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let (Some(id), Some("open")) = (
                nonempty_str(f, "id"),
                f.get("status").and_then(Value::as_str),
            ) else {
                continue;
            };
            let was = f.get("severity").and_then(Value::as_str);
            let here = now.iter().find(|n| nonempty_str(n, "id") == Some(id));
            let problem = match here {
                None => Some("dropped".to_string()),
                Some(n) => {
                    let st = n.get("status").and_then(Value::as_str);
                    let sev = n.get("severity").and_then(Value::as_str);
                    if st != Some("open") {
                        Some(format!("now {}", st.unwrap_or("?")))
                    } else if rank(sev).is_none() || rank(sev) > rank(was) {
                        Some(format!("lowered to {}", sev.unwrap_or("?")))
                    } else {
                        None
                    }
                }
            };
            if let Some(p) = problem {
                let line = format!("`{id}` (open {} on {candidate}) {p}", was.unwrap_or("?"));
                if !wrong.contains(&line) {
                    wrong.push(line);
                }
            }
        }
    }
    if wrong.is_empty() {
        return Vec::new();
    }
    vec![finding(
        "BLOCK",
        "q128",
        inp.record_path,
        "a finding recorded open on this candidate was closed without a fresh audit",
        &format!(
            "{}: the candidate's code has not moved, so only a fresh audit of a new candidate \
             closes it",
            wrong.join("; ")
        ),
        CITE,
    )]
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEAD: &str = "1111111111111111111111111111111111111111";
    const TREE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const OTHER: &str = "2222222222222222222222222222222222222222";
    /// A candidate whose tree differs from HEAD's in the record alone: the commit the auditor read,
    /// with the record committed on top of it.
    const READ: &str = "4444444444444444444444444444444444444444";
    /// A candidate whose tree differs in the record and in the ledger.
    const READ_THEN_LEDGER: &str = "5555555555555555555555555555555555555555";
    /// A candidate whose differing paths git cannot list.
    const UNLISTED: &str = "6666666666666666666666666666666666666666";
    /// A commit HEAD contains: a real closure.
    const FIX: &str = "7777777777777777777777777777777777777777";
    /// A commit in the repository that HEAD does not contain.
    const ASIDE: &str = "8888888888888888888888888888888888888888";

    fn clean_ledger() -> Result<LedgerView, String> {
        Ok(LedgerView {
            red: false,
            rules: vec![("open-high-medium", 0)],
            opens: vec![],
            scopes: 3,
            production: 3,
            production_clean: 3,
            clean_pct: 100.0,
        })
    }

    fn tree_of(c: &str) -> Option<String> {
        match c {
            HEAD => Some(TREE.to_string()),
            OTHER => Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string()),
            READ => Some("cccccccccccccccccccccccccccccccccccccccc".to_string()),
            READ_THEN_LEDGER => Some("dddddddddddddddddddddddddddddddddddddddd".to_string()),
            UNLISTED => Some("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".to_string()),
            FIX => Some("ffffffffffffffffffffffffffffffffffffffff".to_string()),
            ASIDE => Some("9999999999999999999999999999999999999999".to_string()),
            _ => None,
        }
    }

    fn changed(c: &str) -> Option<Vec<String>> {
        let v = |ps: &[&str]| -> Option<Vec<String>> {
            Some(ps.iter().map(|p| p.to_string()).collect())
        };
        match c {
            HEAD => v(&[]),
            OTHER => v(&["crates/x/src/lib.rs", RECORD_REL]),
            READ => v(&[RECORD_REL]),
            READ_THEN_LEDGER => v(&["qa/audit-ledger.json", RECORD_REL]),
            _ => None,
        }
    }

    /// `a` is `b` or an ancestor of it: FIX is in every candidate's history, ASIDE in none.
    fn is_ancestor(a: &str, b: &str) -> Option<bool> {
        Some(a == b || (a == FIX && b != ASIDE))
    }

    /// GetBusbar/busbar#1 exists, #404 does not, and anything else cannot be asked.
    fn pr_exists(repo: &str, n: u64) -> Result<bool, String> {
        match (repo, n) {
            ("GetBusbar/busbar", 1) => Ok(true),
            ("GetBusbar/busbar", 404) => Ok(false),
            _ => Err("offline".to_string()),
        }
    }

    fn run(record: Option<&str>, ledger: Result<LedgerView, String>) -> Report {
        run_with(record, ledger, Some(Vec::new()))
    }

    fn run_with(
        record: Option<&str>,
        ledger: Result<LedgerView, String>,
        history: Option<Vec<String>>,
    ) -> Report {
        judge(&Inputs {
            head: Some(HEAD),
            head_tree: Some(TREE),
            record_path: RECORD_REL,
            record_text: record,
            tree_of: &tree_of,
            changed: &changed,
            is_ancestor: &is_ancestor,
            pr_exists: &pr_exists,
            record_history: &|| history.clone(),
            ledger,
        })
    }

    fn record(candidate: &str, findings: &str) -> String {
        format!(
            r#"{{"candidate": {candidate}, "auditor": "fresh-auditor", "findings": {findings}}}"#
        )
    }

    fn titles(r: &Report, sev: &str) -> Vec<String> {
        r.findings
            .iter()
            .filter(|f| f["severity"] == sev && f["status"] == "open")
            .map(|f| f["title"].as_str().unwrap_or("").to_string())
            .collect()
    }

    #[test]
    fn no_record_is_a_block() {
        let r = run(None, clean_ledger());
        assert_eq!(r.verdict(), "BLOCK");
        assert_eq!(titles(&r, "BLOCK"), ["no architecture audit is recorded"]);
    }

    #[test]
    fn a_record_naming_no_candidate_is_a_block() {
        let r = run(Some(&record("null", "[]")), clean_ledger());
        assert_eq!(r.verdict(), "BLOCK");
        assert_eq!(
            titles(&r, "BLOCK"),
            ["the audit record names no candidate commit"]
        );
    }

    #[test]
    fn an_audit_of_another_tree_is_a_block() {
        let r = run(Some(&record(&format!("\"{OTHER}\""), "[]")), clean_ledger());
        assert_eq!(titles(&r, "BLOCK"), ["the audit was made on another tree"]);
        let r = run(
            Some(&record(
                "\"3333333333333333333333333333333333333333\"",
                "[]",
            )),
            clean_ledger(),
        );
        assert_eq!(titles(&r, "BLOCK"), ["the audited commit does not resolve"]);
    }

    #[test]
    fn the_record_is_the_one_path_that_may_differ_from_the_candidate() {
        // The record is committed after the reading and names the commit it read, so the tree
        // that carries it can never be the candidate's tree. Before this rule no committed record
        // could pass.
        let r = run(Some(&record(&format!("\"{READ}\""), "[]")), clean_ledger());
        assert_eq!(r.verdict(), "PASS", "{:#}", r.json);
        assert_eq!(r.json["audit"]["on_this_tree"], true);
        assert_eq!(r.json["audit"]["differs_only_in_record"], true);

        // Any other path that moved, the audit ledger included, is another tree.
        for c in [OTHER, READ_THEN_LEDGER] {
            let r = run(Some(&record(&format!("\"{c}\""), "[]")), clean_ledger());
            assert_eq!(
                titles(&r, "BLOCK"),
                ["the audit was made on another tree"],
                "{c}"
            );
            assert_eq!(r.json["audit"]["on_this_tree"], false, "{c}");
            let ev = r.findings[0]["evidence"].as_str().unwrap_or("");
            assert!(
                ev.contains("1 path(s) other than the record differ"),
                "{ev}"
            );
            assert!(!ev.contains(RECORD_REL), "{ev}");
        }

        // A git that cannot list what moved is never read as "only the record".
        let r = run(
            Some(&record(&format!("\"{UNLISTED}\""), "[]")),
            clean_ledger(),
        );
        assert_eq!(titles(&r, "BLOCK"), ["the audit was made on another tree"]);
        let ev = r.findings[0]["evidence"].as_str().unwrap_or("");
        assert!(
            ev.contains("git could not list the paths that differ"),
            "{ev}"
        );
    }

    #[test]
    fn an_audit_of_this_tree_with_no_open_block_and_a_clean_ledger_passes() {
        let fs = r#"[{"id":"A1","severity":"HIGH","status":"open","scope":"crates/x/src","evidence":"crates/x/src/lib.rs:1","cite":"BUSBAR-1.6.0.md l.1"},
                     {"id":"A2","severity":"BLOCK","status":"closed","closed_by":"GetBusbar/busbar PR 1 at 7777777777777777777777777777777777777777","scope":"crates/y/src","evidence":"crates/y/src/lib.rs:2","cite":"Law 0"}]"#;
        let r = run(Some(&record(&format!("\"{HEAD}\""), fs)), clean_ledger());
        assert_eq!(r.verdict(), "PASS", "{:#}", r.json);
        assert_eq!(r.open("HIGH"), 1);
        assert_eq!(r.json["open"]["BLOCK"], 0);
        assert_eq!(r.json["audit"]["on_this_tree"], true);
    }

    fn closed(by: &str) -> String {
        format!(
            r#"[{{"id":"A1","severity":"BLOCK","status":"closed","closed_by":"{by}","scope":"s","evidence":"e","cite":"c"}}]"#
        )
    }

    #[test]
    fn a_closed_by_is_held_to_a_real_change_in_the_audited_history() {
        // Good: a commit HEAD contains, and a pull request that exists, in every spelling.
        for by in [
            FIX.to_string(),
            format!("GetBusbar/busbar#1 ({FIX})"),
            format!("PR #1 @ {FIX}"),
            format!("https://github.com/GetBusbar/busbar/pull/1 merged as {FIX}"),
            format!("https://github.com/GetBusbar/busbar/commit/{FIX}"),
        ] {
            let r = run(
                Some(&record(&format!("\"{HEAD}\""), &closed(&by))),
                clean_ledger(),
            );
            assert_eq!(r.verdict(), "PASS", "{by}: {:#}", r.json);
        }
        // Bogus: each names no real change, or a pull request that is not there.
        for (by, why) in [
            ("anything".to_string(), "names no full commit id"),
            (
                "GetBusbar/busbar PR 1".to_string(),
                "names no full commit id",
            ),
            (
                "3333333333333333333333333333333333333333".to_string(),
                "is not in this repository",
            ),
            (ASIDE.to_string(), "is not in the audited history"),
            (format!("PR 404 {FIX}"), "#404, which does not exist"),
            (
                format!("GetBusbar/busbar-plane-mcp#5 {FIX}"),
                "could not be verified",
            ),
        ] {
            let r = run(
                Some(&record(&format!("\"{HEAD}\""), &closed(&by))),
                clean_ledger(),
            );
            assert_eq!(r.verdict(), "BLOCK", "{by}");
            let ev = r.findings[0]["evidence"].as_str().unwrap_or("");
            assert!(ev.contains(why), "{by}: {ev}");
        }
    }

    #[test]
    fn the_pull_requests_a_closed_by_names_are_read_in_every_spelling() {
        let home = |n: u64| ("GetBusbar/busbar".to_string(), n);
        assert_eq!(named_prs("#12"), [home(12)]);
        assert_eq!(named_prs("PR 12"), [home(12)]);
        assert_eq!(named_prs("pr #12"), [home(12)]);
        assert_eq!(
            named_prs("GetBusbar/busbar-plane-mcp PR 7, GetBusbar/busbar#9"),
            [
                ("GetBusbar/busbar".to_string(), 9),
                ("GetBusbar/busbar-plane-mcp".to_string(), 7)
            ]
        );
        assert_eq!(
            named_prs("https://github.com/GetBusbar/busbar-auth-oidc/pull/3/files"),
            [("GetBusbar/busbar-auth-oidc".to_string(), 3)]
        );
        assert!(named_prs(FIX).is_empty());
        assert_eq!(named_commits(&format!("x {FIX}. y")), [FIX]);
    }

    #[test]
    fn a_finding_open_on_this_candidate_in_a_committed_record_stays_open() {
        let open = |sev: &str| {
            record(
                &format!("\"{HEAD}\""),
                &format!(
                    r#"[{{"id":"A1","severity":"{sev}","status":"open","scope":"s","evidence":"e","cite":"c"}}]"#
                ),
            )
        };
        let earlier = vec![open("BLOCK")];
        // Closed, lowered, or dropped by an edit of the record alone: BLOCK.
        for now in [
            record(&format!("\"{HEAD}\""), &closed(FIX)),
            open("LOW"),
            record(&format!("\"{HEAD}\""), "[]"),
        ] {
            let r = run_with(Some(&now), clean_ledger(), Some(earlier.clone()));
            assert!(
                titles(&r, "BLOCK").contains(
                    &"a finding recorded open on this candidate was closed without a fresh audit"
                        .to_string()
                ),
                "{now}: {:#}",
                r.json
            );
        }
        // The same finding on ANOTHER candidate's record binds nothing here.
        let other = record(
            &format!("\"{OTHER}\""),
            r#"[{"id":"A1","severity":"BLOCK","status":"open","scope":"s","evidence":"e","cite":"c"}]"#,
        );
        let now = record(&format!("\"{HEAD}\""), &closed(FIX));
        let r = run_with(Some(&now), clean_ledger(), Some(vec![other]));
        assert_eq!(r.verdict(), "PASS", "{:#}", r.json);
        // Kept open at the same or a graver severity: no finding.
        let r = run_with(
            Some(&open("BLOCK")),
            clean_ledger(),
            Some(vec![open("HIGH")]),
        );
        assert_eq!(titles(&r, "BLOCK"), ["A1"]);
        // A history git cannot list is never read as an empty one.
        let r = run_with(Some(&now), clean_ledger(), None);
        assert_eq!(
            titles(&r, "BLOCK"),
            ["the audit record's history could not be read"]
        );
    }

    #[test]
    fn an_open_block_finding_blocks() {
        let fs = r#"[{"id":"A1","severity":"BLOCK","status":"open","scope":"crates/x/src","evidence":"crates/x/src/lib.rs:1","cite":"Law 0"}]"#;
        let r = run(Some(&record(&format!("\"{HEAD}\""), fs)), clean_ledger());
        assert_eq!(r.verdict(), "BLOCK");
        assert_eq!(r.json["verdict"], "BLOCK");
        assert_eq!(r.json["findings"][0]["scope"], "crates/x/src");
    }

    #[test]
    fn an_unreadable_finding_is_a_block_never_a_pass() {
        for bad in [
            r#"{"id":"A1","severity":"SEVERE","status":"open","scope":"s","evidence":"e","cite":"c"}"#,
            r#"{"id":"A1","severity":"LOW","status":"done","scope":"s","evidence":"e","cite":"c"}"#,
            r#"{"id":"A1","severity":"BLOCK","status":"closed","scope":"s","evidence":"e","cite":"c"}"#,
            r#"{"id":"A1","severity":"LOW","status":"open","scope":"","evidence":"e","cite":"c"}"#,
        ] {
            let r = run(
                Some(&record(&format!("\"{HEAD}\""), &format!("[{bad}]"))),
                clean_ledger(),
            );
            assert_eq!(r.verdict(), "BLOCK", "{bad}");
        }
        let r = run(Some("{not json"), clean_ledger());
        assert_eq!(titles(&r, "BLOCK"), ["the audit record is unreadable"]);
    }

    #[test]
    fn a_red_ledger_blocks_and_names_its_open_scopes() {
        let ledger = Ok(LedgerView {
            red: true,
            rules: vec![("open-high-medium", 2), ("coverage-gaps", 0)],
            opens: vec![
                "crates/a/src  round 1  HIGH=2, MEDIUM=1".to_string(),
                "crates/b/src  round 1  MEDIUM=3".to_string(),
            ],
            scopes: 2,
            production: 2,
            production_clean: 0,
            clean_pct: 0.0,
        });
        let r = run(Some(&record(&format!("\"{HEAD}\""), "[]")), ledger);
        assert_eq!(titles(&r, "BLOCK"), ["the audit ledger is not clean"]);
        let scopes = |sev: &str| -> Vec<String> {
            r.findings
                .iter()
                .filter(|f| f["severity"] == sev)
                .map(|f| f["scope"].as_str().unwrap_or("").to_string())
                .collect()
        };
        assert_eq!(scopes("HIGH"), ["crates/a/src"]);
        assert_eq!(scopes("MEDIUM"), ["crates/b/src"]);
        let r = run(
            Some(&record(&format!("\"{HEAD}\""), "[]")),
            Err("no git".to_string()),
        );
        assert_eq!(titles(&r, "BLOCK"), ["the audit ledger could not be read"]);
    }
}

#[cfg(test)]
#[path = "tests/q128_floor_tests.rs"]
mod floor_tests;

#[cfg(test)]
#[path = "tests/q128_closure_tests.rs"]
mod closure_tests;
