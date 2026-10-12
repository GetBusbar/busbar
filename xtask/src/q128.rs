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
//! 2. **THE AUDIT'S OWN FINDINGS.** Each finding the auditor recorded carries a severity (BLOCK,
//!    HIGH, MEDIUM, LOW), a scope, its evidence and the Law or DESIGN line it is graded against. An
//!    open BLOCK fails the audit. A finding is closed only with the change that closed it named.
//! 3. **THE AUDIT LEDGER IS CLEAN.** `cargo xtask ledger --check`'s computation, run here on the
//!    same tree. A red ledger is a BLOCK; each scope it holds open at HIGH or MEDIUM is listed as a
//!    finding at that severity, so the record says where the debt is.
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

/// What the audit ledger's `--check` found, reduced to what the record carries.
pub struct LedgerView {
    pub red: bool,
    /// `(rule, count)` for every rule of the check, in its print order.
    pub rules: Vec<(&'static str, usize)>,
    /// The scopes held open at HIGH/MEDIUM, each as `--check` prints it.
    pub opens: Vec<String>,
    pub scopes: usize,
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
            ],
            opens: f.opens.clone(),
            scopes: f.scopes,
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
                        findings.push(finding(
                            "BLOCK",
                            "q128",
                            inp.record_path,
                            "the audit was made on another tree",
                            &format!(
                                "candidate {c} has tree {t}; HEAD {} has tree {}: the audit expired when the code moved",
                                inp.head.unwrap_or("?"),
                                h.unwrap_or("?")
                            ),
                            CITE,
                        ));
                        false
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
            for (i, f) in listed.into_iter().flatten().enumerate() {
                findings.push(read_finding(inp.record_path, i, f));
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
            if l.red {
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
                        "`cargo xtask ledger --check` is red: {}; production clean {:.1}% of {} scope(s)",
                        rules.join(", "),
                        l.clean_pct,
                        l.scopes
                    ),
                    CITE,
                ));
            }
            for line in &l.opens {
                let scope = line.split_whitespace().next().unwrap_or(line);
                let high = line.split(|c: char| c == ' ' || c == ',').any(|t| {
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
                "clean": !l.red,
                "scopes": l.scopes,
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
fn read_finding(record_path: &str, i: usize, f: &Value) -> Value {
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
    if status == Some("closed") && nonempty_str(f, "closed_by").is_none() {
        wrong.push("a closed finding names no change in `closed_by`".to_string());
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

#[cfg(test)]
mod tests {
    use super::*;

    const HEAD: &str = "1111111111111111111111111111111111111111";
    const TREE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const OTHER: &str = "2222222222222222222222222222222222222222";

    fn clean_ledger() -> Result<LedgerView, String> {
        Ok(LedgerView {
            red: false,
            rules: vec![("open-high-medium", 0)],
            opens: vec![],
            scopes: 3,
            clean_pct: 100.0,
        })
    }

    fn tree_of(c: &str) -> Option<String> {
        match c {
            HEAD => Some(TREE.to_string()),
            OTHER => Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string()),
            _ => None,
        }
    }

    fn run(record: Option<&str>, ledger: Result<LedgerView, String>) -> Report {
        judge(&Inputs {
            head: Some(HEAD),
            head_tree: Some(TREE),
            record_path: RECORD_REL,
            record_text: record,
            tree_of: &tree_of,
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
    fn an_audit_of_this_tree_with_no_open_block_and_a_clean_ledger_passes() {
        let fs = r#"[{"id":"A1","severity":"HIGH","status":"open","scope":"crates/x/src","evidence":"crates/x/src/lib.rs:1","cite":"BUSBAR-1.6.0.md l.1"},
                     {"id":"A2","severity":"BLOCK","status":"closed","closed_by":"GetBusbar/busbar PR 1","scope":"crates/y/src","evidence":"crates/y/src/lib.rs:2","cite":"Law 0"}]"#;
        let r = run(Some(&record(&format!("\"{HEAD}\""), fs)), clean_ledger());
        assert_eq!(r.verdict(), "PASS", "{:#}", r.json);
        assert_eq!(r.open("HIGH"), 1);
        assert_eq!(r.json["open"]["BLOCK"], 0);
        assert_eq!(r.json["audit"]["on_this_tree"], true);
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
