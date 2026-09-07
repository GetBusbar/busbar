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
//!
//! ## Two kinds of legacy
//!
//! The release-path scripts write their verdicts as ledger TSV through
//! `release-gate/lib.sh::record`, so a parity run reads `$LEDGER` back and compares rows. **The
//! structure-lint scanners do not.** `tracing-lint.sh`, `blocking-ffi-lint.sh` and their siblings
//! print prose and exit 0 or 1; there is no ledger to read, and a harness that only knows how to
//! read one would have to be satisfied with comparing two exit statuses — which is the weakest
//! possible parity claim, since "both said red" says nothing about whether they said red about the
//! SAME LINE OF THE SAME FILE.
//!
//! So a gate may declare a [`Gate::legacy_rows`] translator: it reads the legacy script's own
//! stdout and returns the rows THAT SCRIPT's findings amount to. The translator extracts the
//! offender list the script printed and hands it to the SAME row constructor `run` uses, so the
//! prose in a row's title and detail comes from one place and cannot differ for a reason that is
//! not about the tree. What the comparison then proves is the thing worth proving: the two
//! implementations named the same offenders.
//!
//! Two refusals guard the translator, both in [`check`]:
//!
//! * a translator that yields NO rows is an error, exactly as an empty ledger is — every
//!   comparison below it would be vacuous;
//! * a translator whose rows disagree with the legacy script's own EXIT STATUS is a translator
//!   bug, and is refused rather than compared. A script that exited 1 while its translator read
//!   "all clean" is misreading its subject, and a parity green built on that reads a rewrite as
//!   faithful to a script nobody actually parsed.

use std::path::Path;

/// One execution of a legacy gate script: what it printed and how it exited. A gate's
/// [`Gate::legacy_rows`] translator reads this and nothing else.
#[derive(Debug, Clone)]
pub struct LegacyRun {
    pub argv: Vec<String>,
    /// `None` when the process was killed by a signal and never returned a code at all.
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

impl LegacyRun {
    /// Every non-empty line of stdout and stderr, in that order. Several of these scripts print
    /// their findings on stdout and their refusals on stderr, and a translator that read only one
    /// of the two would go quiet on exactly the runs that matter.
    pub fn lines(&self) -> impl Iterator<Item = &str> {
        self.stdout
            .lines()
            .chain(self.stderr.lines())
            .map(str::trim_end)
            .filter(|l| !l.trim().is_empty())
    }

    /// Did the script call the tree clean? Exit 0 and nothing else.
    pub fn was_green(&self) -> bool {
        self.code == Some(0)
    }
}

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
    let (out, leg) = spawn_legacy(cx, argv, ledger_env)?;

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

/// Run the legacy argv over the tree, with its ledger pointed at a truncated scratch file whether
/// or not it turns out to write one. Returns the process output and the ledger path.
fn spawn_legacy(
    cx: &Ctx,
    argv: &[String],
    ledger_env: &str,
) -> Result<(std::process::Output, std::path::PathBuf), String> {
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
    Ok((out, leg))
}

/// Run the legacy argv and capture what it printed, for a gate whose legacy writes no ledger.
pub fn run_legacy_captured(
    cx: &Ctx,
    argv: &[String],
    ledger_env: &str,
) -> Result<LegacyRun, String> {
    let (out, _leg) = spawn_legacy(cx, argv, ledger_env)?;
    Ok(LegacyRun {
        argv: argv.to_vec(),
        code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    })
}

/// A translator's rows must AGREE WITH THE EXIT STATUS of the script they were read out of. A
/// script that exited non-zero while its translator found nothing to report is a translator that
/// is not reading its subject, and the parity green it would produce is worthless.
fn agrees_with_exit(run: &LegacyRun, rows: &[Row]) -> Result<(), String> {
    let translated_red = rows.iter().any(|r| r.status != crate::ledger::Status::Pass);
    match (run.was_green(), translated_red) {
        (true, true) => Err(format!(
            "parity: `{}` exited 0 but its legacy translator read a FAIL row out of what it \
             printed. One of the two is misreading the script; neither reading may be compared.",
            run.argv.join(" ")
        )),
        (false, false) => Err(format!(
            "parity: `{}` exited {:?} but its legacy translator read every row as PASS. A \
             translator that cannot see the finding the script exited on is not parsing the \
             script, and a comparison against it proves nothing. stderr: {}",
            run.argv.join(" "),
            run.code,
            run.stderr.trim()
        )),
        _ => Ok(()),
    }
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
    // A gate whose legacy writes no ledger declares a translator instead. The translator is asked
    // FIRST, because for those gates the ledger read below would fail on a file the script never
    // had any reason to write.
    let legacy = match gate.legacy_rows(&LegacyRun {
        argv: legacy_argv.to_vec(),
        code: None,
        stdout: String::new(),
        stderr: String::new(),
    }) {
        Some(_) => {
            let run = run_legacy_captured(cx, legacy_argv, ledger_env)?;
            let rows = gate
                .legacy_rows(&run)
                .expect("a gate that translates once translates always")?;
            if rows.is_empty() {
                return Err(format!(
                    "parity: the legacy translator for `{}` read ZERO rows out of `{}`. A \
                     comparison against nothing passes vacuously, which is the opposite of a \
                     parity proof. stdout: {}",
                    gate.name(),
                    legacy_argv.join(" "),
                    run.stdout.trim()
                ));
            }
            agrees_with_exit(&run, &rows)?;
            rows
        }
        None => run_legacy(cx, legacy_argv, ledger_env)?,
    };
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
