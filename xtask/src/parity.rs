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

use std::path::Path;

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
