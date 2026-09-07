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

use std::path::{Path, PathBuf};

/// One execution of a legacy gate script: what it printed, what it WROTE, and how it exited. A
/// gate's [`Gate::legacy_rows`] translator reads this and nothing else.
#[derive(Debug, Clone)]
pub struct LegacyRun {
    pub argv: Vec<String>,
    /// `None` when the process was killed by a signal, or never started, and so never returned a
    /// code at all. Neither is green.
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    /// The directory [`Gate::legacy_env`] was told to point its artefacts at. A translator that
    /// reads a MEASUREMENT rather than prose — a hit list, a counted table — finds it under here.
    pub scratch: PathBuf,
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
use crate::gates::{self, Divergence, Gate};
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
        scratch: cx.scratch().to_path_buf(),
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

/// The adapter path: run the primary legacy command and every companion the gate names, then let
/// the gate read their artefacts back. `Ok(None)` means this gate has no adapter and the ledger
/// file is the legacy side, which is [`run_legacy`]'s job.
fn legacy_via_adapter(
    cx: &Ctx,
    gate: &dyn Gate,
    legacy_argv: &[String],
) -> Result<Option<Vec<Row>>, String> {
    if !gate.has_legacy_adapter() {
        return Ok(None);
    }
    let scratch = cx.scratch().join(format!("parity-{}", std::process::id()));
    std::fs::create_dir_all(&scratch).map_err(|e| format!("parity scratch: {e}"))?;
    let env = gate.legacy_env(&scratch);

    let mut runs = vec![invoke(cx, legacy_argv, &env, &scratch)];
    for companion in gate.legacy_companions() {
        if companion.is_empty() {
            return Err("parity: a gate named an empty companion command".to_string());
        }
        runs.push(invoke(cx, &companion, &env, &scratch));
    }
    match gate.legacy_rows(cx, &runs) {
        Some(Ok(rows)) if rows.is_empty() => Err(format!(
            "parity: the legacy half produced ZERO rows. A comparison against an empty legacy \
             ledger passes vacuously, which is the opposite of a parity proof. stderr: {}",
            runs.iter()
                .map(|r| r.stderr.trim())
                .collect::<Vec<_>>()
                .join(" | ")
        )),
        Some(Ok(rows)) => {
            // AND THE ROWS MUST AGREE WITH THE EXIT STATUS OF THE RUN THEY CAME OUT OF. The
            // primary is the one that carries the verdict; a translator that read every row as
            // PASS out of a script that exited on a finding is not reading its subject, and the
            // parity green built on that reading is worthless.
            agrees_with_exit(&runs[0], &rows)?;
            Ok(Some(rows))
        }
        Some(Err(e)) => Err(e),
        // `has_legacy_adapter` said there is one; a `None` here is the gate's own bug, and
        // reporting it as "no adapter" would silently fall back to an empty ledger file.
        None => Err(format!(
            "parity: {} advertises a legacy adapter and then supplied none",
            gate.name()
        )),
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

/// Run one legacy command, capturing what it PRINTED and what it WROTE, without judging either.
/// Used by the adapter path, where the rows come out of the script's own measurement artefact.
fn invoke(cx: &Ctx, argv: &[String], env: &[(String, String)], scratch: &Path) -> LegacyRun {
    let mut cmd = std::process::Command::new(&argv[0]);
    cmd.args(&argv[1..]).current_dir(cx.root());
    for (k, v) in env {
        cmd.env(k, v);
    }
    match cmd.output() {
        Ok(out) => LegacyRun {
            argv: argv.to_vec(),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            code: out.status.code(),
            scratch: scratch.to_path_buf(),
        },
        Err(e) => LegacyRun {
            argv: argv.to_vec(),
            stdout: String::new(),
            stderr: format!("{}: {e}", argv[0]),
            code: None,
            scratch: scratch.to_path_buf(),
        },
    }
}

/// The whole harness: legacy script, Rust gate, same tree, identical rows or a named diff.
pub fn check(
    cx: &Ctx,
    gate: &dyn Gate,
    legacy_argv: &[String],
    ledger_env: &str,
) -> Result<ParityOutcome, String> {
    // A gate whose legacy writes no ledger declares an adapter instead, and it is asked FIRST:
    // for those gates the ledger read below would fail on a file the script never had any reason
    // to write.
    let legacy = match legacy_via_adapter(cx, gate, legacy_argv)? {
        Some(rows) => rows,
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
    let mut declared: Vec<String> = Vec::new();
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

        // A DECLARED divergence is checked for STILL BEING TRUE, not merely accepted. A
        // declaration the legacy has since grown out of is a waiver that excuses nothing, and this
        // crate refuses those everywhere else.
        if let Some(d) = &probe.divergence {
            if d.reason().len() < Divergence::MIN_REASON {
                diffs.push(format!(
                    "{}: its declared divergence carries a {}-character reason. A difference \
                     between the two implementations may be deliberate; it may not be unexplained.",
                    probe.label,
                    d.reason().len()
                ));
                continue;
            }
            let stale = match d {
                Divergence::LegacyGreen { .. } if legacy.red => Some(
                    "declared as a violation the legacy script cannot see, but the legacy went RED \
                     over it. The declaration is stale -- delete it and let the probe compare \
                     normally.",
                ),
                Divergence::LegacyCrashes { .. } if !looks_like_a_crash(&legacy.output) => Some(
                    "declared as a case the legacy only survives by crashing, but it produced no \
                     interpreter traceback. The declaration is stale.",
                ),
                _ => None,
            };
            if let Some(why) = stale {
                diffs.push(format!("{}: {why}", probe.label));
                continue;
            }
            // A declared divergence excuses the LEGACY half only. This gate is still held to its
            // claim, or the declaration would be a way to stop proving the Rust as well.
            if rust.red != want_red {
                diffs.push(format!(
                    "{}: the RUST gate is {} over the planted tree ({:?})",
                    probe.label,
                    verdict_word(rust.red),
                    rust.problems
                ));
                continue;
            }
            if let Some(rule) = &probe.expect_rule {
                if !rust.problems.iter().any(|p| p.starts_with(rule.as_str())) {
                    diffs.push(format!(
                        "{}: the rust gate went red without naming `{rule}` ({:?})",
                        probe.label, rust.problems
                    ));
                    continue;
                }
            }
            declared.push(format!("{}: {}", probe.label, d.reason()));
            continue;
        }

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
            // The legacy is asked for whatever IT calls this rule. Two gates could not keep their
            // legacy row ids because those ids were not a fixed set, and several legacy lints name
            // no rule at all — they print prose. Carrying the legacy's own string keeps the
            // comparison about RULE IDENTITY instead of letting it decay into "both went red
            // somehow", which two implementations can do for two different reasons.
            let legacy_needle = probe.legacy_names.as_deref().unwrap_or(rule.as_str());
            if !legacy.output.contains(legacy_needle) {
                diffs.push(format!(
                    "{}: the legacy script went red without naming `{legacy_needle}`, so the two \
                     are red about different things",
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

    Ok(LintParityOutcome {
        compared,
        diffs,
        declared,
    })
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
    /// The deliberate, reasoned differences — printed rather than hidden, and each one re-proved
    /// on this run to still apply.
    pub declared: Vec<String>,
}

/// An interpreter traceback. A crashed lint and a lint that considered the tree and refused it
/// leave the SAME exit code, so without reading for this the harness would credit a crash as a
/// verdict.
fn looks_like_a_crash(output: &str) -> bool {
    output.contains("Traceback (most recent call last)")
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
    for d in &outcome.declared {
        println!("  DECLARED DELTA  {d}");
    }
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
