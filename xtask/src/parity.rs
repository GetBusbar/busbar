//! THE PARITY HARNESS. Run the legacy script and the Rust gate over the SAME tree and assert
//! identical ledger rows.
//!
//! This is not optional decoration for the conversions that follow. A Rust generator will not
//! byte-match a Python one on the first try — key order, float formatting, trailing newline,
//! Unicode escaping, sort locale, how `None` renders — so a converted gate goes red for reasons
//! entirely about the rewrite and nothing about the tree, and the tempting fix (regenerate and
//! commit) silently destroys the drift signal for that release.
//!
//! The sequence every conversion follows, in this order:
//!
//! 1. land the Rust gate with its own selftest, NOT yet wired into `ci.yml`;
//! 2. land `parity` GREEN — legacy and Rust produce byte-identical rows over the real tree;
//! 3. switch the `ci.yml` call site;
//! 4. delete the Python/bash in a separate commit that touches no `qa/*.json` byte.
//!
//! If a committed artifact must change, it changes in its own commit with the diff reviewable,
//! never bundled with the rewrite.

use std::path::{Path, PathBuf};

use crate::ctx::Ctx;
use crate::gates::{self, Gate};
use crate::ledger::{self, Row};

/// Every way the two row sets differ, one line each, id-first so the message names its subject.
pub fn compare(legacy: &[Row], rust: &[Row]) -> Vec<String> {
    let mut out = Vec::new();
    let mut ids: Vec<&str> = legacy.iter().map(|r| r.id.as_str()).collect();
    ids.extend(rust.iter().map(|r| r.id.as_str()));
    ids.sort_unstable();
    ids.dedup();

    for id in ids {
        let l: Vec<&Row> = legacy.iter().filter(|r| r.id == id).collect();
        let r: Vec<&Row> = rust.iter().filter(|r| r.id == id).collect();
        if l.is_empty() {
            out.push(format!(
                "{id}: the Rust gate emits it, the legacy script does not"
            ));
            continue;
        }
        if r.is_empty() {
            out.push(format!(
                "{id}: the legacy script emits it, the Rust gate does not — a gate that emits \
                 nothing is not a gate at parity"
            ));
            continue;
        }
        let lt: Vec<String> = l.iter().map(|x| x.tsv()).collect();
        let rt: Vec<String> = r.iter().map(|x| x.tsv()).collect();
        if lt != rt {
            out.push(format!("{id}: legacy {lt:?} vs rust {rt:?}"));
        }
    }
    out
}

/// Run a legacy gate script over the tree with its ledger pointed at a fresh scratch file.
///
/// The file is TRUNCATED first (a script that dies before writing must not inherit the previous
/// run's rows) and a run that wrote NO rows is an error — zero legacy rows would make every
/// comparison below it vacuous.
pub fn run_legacy(cx: &Ctx, argv: &[String], ledger_env: &str) -> Result<Vec<Row>, String> {
    if argv.is_empty() {
        return Err("parity: no legacy command given".to_string());
    }
    let leg = cx.scratch().join(format!(
        "parity-{}-{}.tsv",
        std::process::id(),
        argv[0].replace(['/', '.'], "_")
    ));
    ledger::truncate_leg(&leg).map_err(|e| format!("parity ledger {}: {e}", leg.display()))?;

    let out = std::process::Command::new(&argv[0])
        .args(&argv[1..])
        .current_dir(cx.root())
        .env(ledger_env, &leg)
        .env("LEDGER_DIR", cx.scratch())
        .output()
        .map_err(|e| format!("parity: {} : {e}", argv[0]))?;

    let rows = ledger::read_leg(&leg)?;
    if rows.is_empty() {
        return Err(format!(
            "parity: `{}` exited {} and wrote ZERO ledger rows to {}. A comparison against an \
             empty legacy ledger passes vacuously, which is the opposite of a parity proof. \
             stderr: {}",
            argv.join(" "),
            out.status.code().unwrap_or(-1),
            leg.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(rows)
}

#[derive(Debug, Clone)]
pub struct ParityOutcome {
    pub legacy: Vec<Row>,
    pub rust: Vec<Row>,
    pub diffs: Vec<String>,
}

impl ParityOutcome {
    pub fn at_parity(&self) -> bool {
        self.diffs.is_empty()
    }
}

/// The whole harness: legacy script, Rust gate, same tree, identical rows or a named diff.
pub fn check(
    cx: &Ctx,
    gate: &dyn Gate,
    legacy_argv: &[String],
    ledger_env: &str,
) -> Result<ParityOutcome, String> {
    let legacy = run_legacy(cx, legacy_argv, ledger_env)?;
    let rust = gates::execute(gate, cx).rows;
    let diffs = compare(&legacy, &rust);
    Ok(ParityOutcome {
        legacy,
        rust,
        diffs,
    })
}

/// PARITY FOR A LINT THAT WRITES NO LEDGER.
///
/// Most of the gates being converted print findings and set an exit code; they never learned the
/// ledger's TSV, and teaching them it now would be adding logic to a script whose next commit
/// deletes it. So parity for those is asserted over the thing they DO both produce: a verdict, and
/// the rule that verdict names.
///
/// The comparison is driven over PLANTED trees, not only over the real one. Two implementations
/// that both find nothing agree perfectly, so a parity run against a green tree is exactly the
/// vacuous proof the design refuses elsewhere. Each probe plants one violation, materializes the
/// overlaid view of the touched paths into a scratch tree, and requires the legacy script and the
/// Rust gate to BOTH go red naming the same rule.
///
/// A gate that declares no probes is an error, not a pass.
pub fn check_lint(
    cx: &Ctx,
    gate: &dyn Gate,
    legacy_argv: &[String],
    target: &LegacyTarget,
) -> Result<LintParityOutcome, String> {
    if legacy_argv.is_empty() {
        return Err("parity: no legacy command given".to_string());
    }
    let probes = gate.parity_probes(cx);
    if probes.is_empty() {
        return Err(format!(
            "parity {}: the gate declares no probes, so the only comparison available is one green \
             against another green. Two implementations that both find nothing agree perfectly; \
             that is not a parity proof.",
            gate.name()
        ));
    }

    let mut diffs: Vec<String> = Vec::new();
    let mut compared = 0usize;

    // The real tree first: both must agree on the verdict everybody actually reads.
    let legacy_real = run_lint(cx.root(), cx.root(), legacy_argv, target)?;
    let rust_real = gates::execute(gate, cx);
    compared += 1;
    if legacy_real.red != rust_real.red {
        diffs.push(format!(
            "the real tree: legacy is {}, the rust gate is {} ({})",
            verdict_word(legacy_real.red),
            verdict_word(rust_real.red),
            first_line(&legacy_real.output)
        ));
    }

    for probe in &probes {
        let planted_cx = cx.with_overlay(probe.overlay.clone());
        let scratch = cx
            .scratch()
            .join(format!("parity-{}-{}", gate.name(), compared));
        let _ = std::fs::remove_dir_all(&scratch);
        // The script itself is materialized too when it is relocated: a gate whose legacy half
        // is not IN the planted tree judges the real one and reports a confident green.
        let mut want: Vec<String> = probe.materialize.clone();
        want.extend(target.extra_paths(legacy_argv));
        want.sort();
        want.dedup();
        let paths: Vec<&str> = want.iter().map(String::as_str).collect();
        planted_cx.materialize(&scratch, &paths)?;

        let legacy = run_lint(cx.root(), &scratch, legacy_argv, target)?;
        let rust = gates::execute(gate, &planted_cx);
        compared += 1;

        let want_red = probe.expect_rule.is_some();
        if legacy.red != want_red {
            diffs.push(format!(
                "{}: the LEGACY script is {} over the planted tree, but the plant is a real \
                 violation. A probe the legacy script does not see cannot prove the two agree. \
                 ({})",
                probe.label,
                verdict_word(legacy.red),
                first_line(&legacy.output)
            ));
        }
        if rust.red != want_red {
            diffs.push(format!(
                "{}: the RUST gate is {} over the planted tree ({:?})",
                probe.label,
                verdict_word(rust.red),
                rust.problems
            ));
        }
        if let Some(rule) = &probe.expect_rule {
            if !legacy.output.contains(rule.as_str()) {
                diffs.push(format!(
                    "{}: the legacy script went red without naming `{rule}`, so the two are red \
                     about different things",
                    probe.label
                ));
            }
            if !rust.problems.iter().any(|p| p.starts_with(rule.as_str())) {
                diffs.push(format!(
                    "{}: the rust gate went red without naming `{rule}` ({:?})",
                    probe.label, rust.problems
                ));
            }
        }
    }

    Ok(LintParityOutcome { compared, diffs })
}

fn verdict_word(red: bool) -> &'static str {
    if red {
        "RED"
    } else {
        "green"
    }
}

fn first_line(s: &str) -> String {
    s.lines()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("")
        .trim()
        .chars()
        .take(160)
        .collect()
}

/// HOW A LEGACY SCRIPT IS POINTED AT A TREE THAT IS NOT THE REPOSITORY.
///
/// The scripts do not agree on this, and the difference is not cosmetic: a probe pointed at the
/// wrong tree runs the legacy script over the REAL, unplanted repository and reports a confident
/// green. Both shapes are therefore named rather than guessed.
pub enum LegacyTarget {
    /// The script takes a flag naming the root (`--root <dir>`).
    RootFlag(String),
    /// The script has no such flag: it anchors on its OWN path (`dirname $0/..`, or
    /// `Path(__file__).parents[1]`) or on the working directory. The script is copied into the
    /// planted tree and invoked from there, so its own anchor resolves to the plant.
    RelocateScript,
}

impl LegacyTarget {
    /// The argv and working directory for one run.
    fn invocation(&self, cwd: &Path, subject: &Path, argv: &[String]) -> (Vec<String>, PathBuf) {
        match self {
            LegacyTarget::RootFlag(flag) => {
                let mut v = argv.to_vec();
                v.push(flag.clone());
                v.push(subject.display().to_string());
                (v, cwd.to_path_buf())
            }
            LegacyTarget::RelocateScript => {
                // The script path is whichever argument looks like one; an interpreter
                // (`python3`, `bash`) stays as it is.
                let v: Vec<String> = argv
                    .iter()
                    .map(|a| {
                        if a.contains('/') && !a.starts_with('-') {
                            subject.join(a).display().to_string()
                        } else {
                            a.clone()
                        }
                    })
                    .collect();
                (v, subject.to_path_buf())
            }
        }
    }

    /// Every path that must exist in the planted tree for this shape to work at all. A relocated
    /// script has to be IN the tree it is about to judge.
    pub fn extra_paths(&self, argv: &[String]) -> Vec<String> {
        match self {
            LegacyTarget::RootFlag(_) => Vec::new(),
            LegacyTarget::RelocateScript => argv
                .iter()
                .filter(|a| a.contains('/') && !a.starts_with('-'))
                .cloned()
                .collect(),
        }
    }
}

struct LintRun {
    red: bool,
    output: String,
}

/// Run a legacy lint over a tree and read its VERDICT.
///
/// A non-zero exit is red and a zero exit is green — but a signal, or an exit code the script never
/// documents, is neither, and reading it as green is how a crashed gate reports a clean tree. Those
/// are an error here, which the caller surfaces as "could not run".
fn run_lint(
    cwd: &Path,
    subject: &Path,
    argv: &[String],
    target: &LegacyTarget,
) -> Result<LintRun, String> {
    let (argv, cwd) = target.invocation(cwd, subject, argv);
    let out = std::process::Command::new(&argv[0])
        .args(&argv[1..])
        .current_dir(&cwd)
        .output()
        .map_err(|e| format!("parity: {} : {e}", argv[0]))?;
    let code = out
        .status
        .code()
        .ok_or_else(|| format!("parity: `{}` was killed by a signal", argv.join(" ")))?;
    if code > 1 {
        return Err(format!(
            "parity: `{}` exited {code} over {}, which is neither its green nor its red. \
             stderr: {}",
            argv.join(" "),
            subject.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let mut output = String::from_utf8_lossy(&out.stdout).into_owned();
    output.push_str(&String::from_utf8_lossy(&out.stderr));
    Ok(LintRun {
        red: code != 0,
        output,
    })
}

#[derive(Debug, Clone)]
pub struct LintParityOutcome {
    pub compared: usize,
    pub diffs: Vec<String>,
}

impl LintParityOutcome {
    pub fn at_parity(&self) -> bool {
        self.diffs.is_empty()
    }
}

pub fn print_lint_outcome(name: &str, outcome: &LintParityOutcome) {
    println!(
        "parity {name}: {} tree(s) compared — the real one plus one per planted violation",
        outcome.compared
    );
    for d in &outcome.diffs {
        println!("  DIFF  {d}");
    }
    println!(
        "parity {name}: {}",
        if outcome.at_parity() {
            "IDENTICAL VERDICTS — the legacy script may be deleted in its own commit"
        } else {
            "RED — do not switch the call site or delete the legacy script"
        }
    );
}

/// Print an outcome the way a CI step wants to read it.
pub fn print_outcome(name: &str, path_hint: &Path, outcome: &ParityOutcome) {
    println!(
        "parity {name}: {} legacy row(s) vs {} rust row(s) (legacy ledger under {})",
        outcome.legacy.len(),
        outcome.rust.len(),
        path_hint.display()
    );
    for d in &outcome.diffs {
        println!("  DIFF  {d}");
    }
    println!(
        "parity {name}: {}",
        if outcome.at_parity() {
            "IDENTICAL — the Python may be deleted in its own commit"
        } else {
            "RED — do not switch the call site or delete the legacy script"
        }
    );
}
