//! Argument dispatch.
//!
//! Exit codes are a contract, and they are `full-gate.sh`'s: **0** green, **1** the gate failed,
//! **2** the ARGUMENTS were wrong (an unknown subcommand, an unknown gate, an unknown flag — never
//! fallen through into doing something), **3** the gate COULD NOT RUN (unwritable scratch, missing
//! `git`, an unreadable tree). "The gate failed" and "the gate could not run" are different facts
//! and a runner that collapses them is a runner that can report green over a gate that never
//! executed.

use crate::ctx::Ctx;
use crate::denylist;
use crate::gates;
use crate::selftest;

const USAGE: &str = "\
usage:
  cargo xtask gate <name> [--selftest] [--jobs N] [--report] [--strict] [--write] [--format=tsv]
  cargo xtask gate --list
  cargo xtask gate --all [--format=tsv]
  cargo xtask gate <name> --parity -- <legacy argv...>
  cargo xtask selftest [<name>] [--jobs N]
  cargo xtask denylist [--selftest] [--format=tsv]
  cargo xtask teller-steps [--root-legs] [--root-legs-gating]
  cargo xtask ledger {sync|status|next|record|fixed} | --check
  cargo xtask full-gate [--list] [--selftest] [--dump-gates|--dump-cargo [FILE]]";

/// The environment variable the legacy release-gate scripts write their ledger through.
const LEGACY_LEDGER_ENV: &str = "LEDGER";

/// The subcommands below that NAME NO GATE.
///
/// `cargo xtask <name>` is a gate invocation for `denylist` and `teller-steps` — both are registry
/// names kept in their pre-registry spelling — so a reader of `ci.yml` cannot tell a gate from a
/// subcommand by shape alone, and [`crate::yaml_lite::xtask_gate_invocations`] reads the token
/// after `cargo xtask` as a gate name. These two are the exceptions: the runner that DRIVES the
/// gates and the register that RECORDS the audit, neither of which has an owed row set. Listed
/// here, beside the dispatch arms that prove it, so the reader and the dispatcher cannot drift.
pub const NON_GATE_SUBCOMMANDS: &[&str] = &["full-gate", "ledger"];

pub fn main(args: &[String]) -> i32 {
    match args.first().map(String::as_str) {
        Some("gate") => gate(&args[1..]),
        Some("selftest") => selftest_cmd(&args[1..]),
        // The pre-registry spelling, kept byte-identical: `cargo xtask denylist` prints exactly
        // what it always printed, so nothing that reads its output has to move on the same day the
        // registry arrives.
        Some("denylist") => denylist_cmd(&args[1..]),
        // The Teller matrix's RUNNER arms. `cargo xtask gate teller-steps` is the gate — the rules
        // as reconciled ledger rows; this is the human render whose `ROOT-STEPS:` prefix
        // `verify-1.6.0-done.sh` greps, plus the three arms that RUN something (the loop cells, the
        // shipped-leg bar, the rig suites) and are therefore not gates.
        // THE AUDIT REGISTER's commands. `cargo xtask gate audit-ledger` is `--check` as a
        // reconciled row set; this is the same computation plus the four commands that WRITE the
        // register (`sync`/`record`/`fixed`) or the report (`status`), which a gate must not do.
        // RUN LOCALLY WHAT CI RUNS. Not a gate: it is the runner that discovers and drives the
        // gates, so it has no owed row set of its own and nothing reconciles it.
        Some("full-gate") => match open_ctx() {
            Ok(cx) => crate::full_gate::main(&cx, &args[1..]),
            Err(code) => code,
        },
        Some("ledger") => match open_ctx() {
            Ok(cx) => crate::audit_cmd::main(cx.root(), &args[1..]),
            Err(code) => code,
        },
        Some("teller-steps") => match open_ctx() {
            Ok(cx) => gates::teller_steps::run_arm(&cx, &args[1..]),
            Err(code) => code,
        },
        Some(other) => {
            eprintln!("xtask: unknown subcommand `{other}`");
            eprintln!("{USAGE}");
            2
        }
        None => {
            eprintln!("{USAGE}");
            2
        }
    }
}

fn open_ctx() -> Result<Ctx, i32> {
    match Ctx::workspace() {
        Ok(cx) => Ok(cx),
        Err(e) => {
            eprintln!("xtask: could not open the workspace context: {e}");
            eprintln!("xtask: this is 'the gate could not run', not 'the gate failed'.");
            Err(3)
        }
    }
}

fn gate(args: &[String]) -> i32 {
    let tsv = args.iter().any(|a| a == "--format=tsv");
    let report_only = args.iter().any(|a| a == "--report");
    let want_selftest = args.iter().any(|a| a == "--selftest");

    // AN UNCONSUMED `--selftest` IS AN ERROR, NOT A NO-OP.
    //
    // `--list` and `--all` both `return` before `want_selftest` is ever read, so
    // `cargo xtask gate --all --selftest` printed every gate's ordinary verdict and exited on it
    // while the caller believed they had just self-tested the whole registry. That is the worst
    // possible shape for a flag: it reports success for a thing it did not do. The only "every
    // gate" self-test is the bare `cargo xtask selftest` subcommand, and this says so.
    if want_selftest && args.iter().any(|a| a == "--list" || a == "--all") {
        eprintln!(
            "xtask gate: --selftest cannot be combined with --list or --all — neither runs a \
             self-test, and this used to be accepted and silently ignored, which reports a \
             proof that was never taken."
        );
        eprintln!("  every gate's self-test:  cargo xtask selftest");
        eprintln!("  one gate's self-test:    cargo xtask gate <name> --selftest");
        return 2;
    }

    if args.iter().any(|a| a == "--list") {
        for reg in gates::REGISTRY {
            println!(
                "{:<28} batch {}  {:<8} {}",
                reg.name,
                reg.batch,
                format!("{:?}", reg.tier).to_lowercase(),
                reg.summary
            );
        }
        return 0;
    }

    let cx = match open_ctx() {
        Ok(cx) => cx
            .report_only(report_only)
            .write_mode(args.iter().any(|a| a == "--write")),
        Err(code) => return code,
    };

    if args.iter().any(|a| a == "--all") {
        let mut red = Vec::new();
        for reg in gates::REGISTRY {
            // EVERY ROW UNDER A WALL-CLOCK CEILING. A gate that wedges — the way one did against a
            // `git cat-file --batch` child, for 43 minutes, at 4% CPU — is RED with `hung` in its
            // rows and the remaining gates still run. See `gates::execute_within`.
            let verdict = match gates::ceiling_from_env(reg.name) {
                Some(ceiling) => gates::execute_within(reg.name, reg.build, &cx, ceiling),
                None => gates::execute((reg.build)().as_ref(), &cx),
            };
            if tsv {
                gates::print_rows_tsv(&verdict.rows);
            } else {
                gates::print_verdict(reg.name, &verdict);
            }
            // A REPORT-ONLY gate is printed and not scored — but only while the fact its posture
            // rests on still holds, and NEVER silently: the excuse that was applied is printed on
            // the same run, so a red that was not counted is not a red that went unmentioned.
            if verdict.red {
                match gates::excused_from_all(reg.name, &cx, &verdict) {
                    Some(why) => println!("EXCUSED  {:<46} {why}", reg.name),
                    None => red.push(reg.name),
                }
            }
        }
        if red.is_empty() {
            println!("cargo xtask gate --all: every registered gate is green");
            return 0;
        }
        eprintln!("cargo xtask gate --all: RED in {}", red.join(", "));
        return 1;
    }

    // `--jobs N` takes a value, so the N after it is NOT the gate name. Without this,
    // `cargo xtask gate --selftest --jobs 8 construction` would look for a gate called `8`.
    let Some(name) = args
        .iter()
        .enumerate()
        .find(|(i, a)| !a.starts_with("--") && !(*i > 0 && args[i - 1] == "--jobs"))
        .map(|(_, a)| a)
    else {
        eprintln!("xtask gate: no gate named");
        eprintln!("{USAGE}");
        return 2;
    };

    let Some(reg) = gates::find(name) else {
        eprintln!("xtask gate: no registered gate `{name}`");
        let near = gates::nearest(name);
        if near.is_empty() {
            eprintln!("registered gates: {}", gates::names().join(", "));
        } else {
            eprintln!("did you mean: {}?", near.join(", "));
        }
        return 2;
    };

    // THE RELEASE-TIME ARMS, as flags on the gate and never as an environment variable.
    //
    // A few gates run a stricter form at release time than on every push. Those arms stay explicit
    // here because an env-overridable strictness is a strictness that is off wherever nobody looked
    // — the cautionary case is a group floor that was overridable downward from the environment
    // with no floor-only-rises guard. A flag has to be written at the call site, in a diff.
    //
    // Unknown here is an ARGUMENT error, not a quietly looser run: a gate handed `--require-verison`
    // must not report green having checked the ordinary arm.
    let require_dated_top = args.iter().any(|a| a == "--require-dated-top");
    let require_version = args
        .iter()
        .find_map(|a| a.strip_prefix("--require-version="))
        .map(str::to_string);
    let gate: Box<dyn gates::Gate> = if require_dated_top || require_version.is_some() {
        if reg.name != "changelog" {
            eprintln!(
                "xtask gate {}: --require-version/--require-dated-top are the changelog gate's \
                 release arms; `{}` has no such arm and must not report green as though it ran one.",
                reg.name, reg.name
            );
            return 2;
        }
        let mut g = crate::gates::changelog::ChangelogGate::new();
        if require_dated_top {
            g = g.require_dated_top();
        }
        if let Some(v) = require_version {
            g = g.require_version(v);
        }
        Box::new(g)
    } else if cx.env().write && reg.name == "kind-isolation" {
        // `kind-isolation --write` RE-PINS ITS EXACT COUNTS DOWNWARD, and refuses wholesale if any
        // would rise. It is a separate CONSTRUCTION rather than a flag the gate reads out of the
        // context, because `owed` is what the reconciliation is written against and this run emits
        // one row: the re-pin's own. Built HERE rather than in the write branch below, so
        // `--write --selftest` proves the arm it is about to run rather than a different one.
        Box::new(crate::gates::kind_isolation::KindIsolationGate::write())
    } else {
        (reg.build)()
    };
    if want_selftest {
        if let Some(n) = jobs_arg(args) {
            gates::set_selftest_jobs(n);
        }
        return run_selftest(gate.as_ref(), &cx);
    }

    // `--write` is the one arm that CHANGES the tree, so it is the one arm that does no judging:
    // a check that repairs what it is checking has not checked anything, and a caller that wanted
    // both would be asking a gate to make itself pass.
    if cx.env().write {
        // `kind-isolation --write` RE-PINS ITS EXACT COUNTS DOWNWARD — the `[[cell]]`, `[[dep]]`
        // and `[[face]]` numbers — and refuses WHOLESALE if any would rise. It answers through the
        // ledger rather than through a `Result<String, _>` like its two neighbours, and that is
        // deliberate: the arm is a GATE RUN whose owed set is its own row, so `execute` reconciles
        // it exactly as it reconciles a judging run, and the refusal arrives as a FAIL row a
        // reader can diff rather than as a message on stderr.
        if reg.name == "kind-isolation" {
            let verdict = gates::execute(gate.as_ref(), &cx);
            gates::print_verdict(reg.name, &verdict);
            return i32::from(verdict.red);
        }
        let written = match reg.name {
            "design-bindings" => crate::gates::design_bindings::DesignBindingsGate::write(&cx),
            // The construction gate's write arm RE-PINS ITS CEILINGS TO WHAT THEY MEASURE, and
            // only downward — see `gates::construction::ceilings`. It is the same derivation the
            // `ceiling-slack` row reports, so the arm that repairs and the arm that judges cannot
            // disagree about what the tree measures; what the flag changes is whether the answer
            // is printed or committed.
            "construction" => crate::gates::construction::ceilings::rewrite(&cx),
            _ => {
                eprintln!("xtask gate {name}: this gate has nothing to write");
                return 2;
            }
        };
        return match written {
            Ok(msg) => {
                println!("{msg}");
                0
            }
            Err(e) => {
                eprintln!("xtask gate {name} --write: {e}");
                3
            }
        };
    }

    // THE PARITY ARM, used by every conversion before its Python or bash is deleted: run the
    // legacy script and this gate over the same tree and require identical rows.
    if args.iter().any(|a| a == "--parity") {
        let Some(sep) = args.iter().position(|a| a == "--") else {
            eprintln!("xtask gate {name} --parity: no legacy command given");
            eprintln!("{USAGE}");
            return 2;
        };
        let legacy: Vec<String> = args[sep + 1..].to_vec();
        if legacy.is_empty() {
            eprintln!("xtask gate {name} --parity: no legacy command after `--`");
            return 2;
        }
        // A LINT THAT WRITES NO LEDGER IS COMPARED ON ITS VERDICT, over planted trees.
        // Most of the scripts being converted print findings and set an exit code; they never
        // learned the ledger's TSV, and teaching it to a script whose next commit deletes it is
        // work spent on the wrong side of the seam. The probes are what keep that comparison from
        // being one green against another.
        if !gate.parity_probes(&cx).is_empty() {
            // How the legacy half is pointed at a planted tree. A script with a `--root` flag
            // takes one; the three that anchor on their own path are copied into the plant and
            // run from there. Guessing between the two would silently judge the real repository.
            let target = match args.iter().find_map(|a| a.strip_prefix("--root-flag=")) {
                Some(flag) => crate::parity::LegacyTarget::RootFlag(flag.to_string()),
                None => crate::parity::LegacyTarget::RelocateScript,
            };
            return match crate::parity::check_lint(&cx, gate.as_ref(), &legacy, &target) {
                Ok(outcome) => {
                    crate::parity::print_lint_outcome(reg.name, &outcome);
                    i32::from(!outcome.at_parity())
                }
                Err(e) => {
                    eprintln!("xtask gate {name} --parity: {e}");
                    3
                }
            };
        }

        return match crate::parity::check(&cx, gate.as_ref(), &legacy, LEGACY_LEDGER_ENV) {
            Ok(outcome) => {
                crate::parity::print_outcome(reg.name, cx.scratch(), &outcome);
                i32::from(!outcome.at_parity())
            }
            Err(e) => {
                // The legacy half could not be RUN (or wrote nothing, which makes every comparison
                // vacuous). That is exit 3 — "could not run" — never a parity green.
                eprintln!("xtask gate {name} --parity: {e}");
                3
            }
        };
    }

    // `--strict` REFUSES THE GATE'S OWN SKIP ALLOWLIST. A named gap is a reported gap in the plain
    // form and a red one here, which is what makes "DONE means no gap" a claim rather than a hope.
    // UNDER THE WALL-CLOCK CEILING, like every other gate run. This arm builds the gate with
    // flags a `fn()` pointer cannot carry, so it cannot hand the gate to a worker thread the way
    // `--all` does; the watchdog prints the hung rows and takes the process down instead. Either
    // way the answer is a refusal that NAMES the gate, never a job timeout that names nothing.
    let watchdog = gates::Watchdog::arm(reg.name, gate.owed(), gates::ceiling_from_env(reg.name));
    let verdict = if args.iter().any(|a| a == "--strict") {
        gates::execute_strict(gate.as_ref(), &cx)
    } else {
        gates::execute(gate.as_ref(), &cx)
    };
    drop(watchdog);
    if tsv {
        gates::print_rows_tsv(&verdict.rows);
    } else {
        gates::print_verdict(reg.name, &verdict);
    }
    // `--report` PRINTS THE VERDICT AND DOES NOT IMPOSE IT. This is the arm a runner uses when it
    // wants the rows in the log without the run's exit status turning on them — the posture the
    // construction gate has had since it was written, and which its shell spelled `--summary`.
    // Every row is still measured and still reconciled; only the exit code is withheld, which is
    // the difference between reporting a fact and scoring it.
    if cx.env().report_only {
        return 0;
    }
    // `--posture` SCORES THE GATE AGAINST ITS REPORT-ONLY ENTRY INSTEAD OF AGAINST ZERO REDS.
    //
    // This is the arm CI needs and did not have. The construction gate is RED BY DESIGN on HEAD, so
    // its job was `continue-on-error: true` and its verdict was excluded from both umbrellas'
    // RESULTS — four independent downgrades, and between them a NEW construction red could not
    // redden anything. "Green" was not available and "red" carried no information.
    //
    // `--posture` gives the third answer: exit 0 when the gate is red on exactly the rows
    // [`gates::REPORT_ONLY`] names and nothing else, and exit 1 the moment a red appears that the
    // list does not name — or a named row goes green and the list is stale. It is the SAME
    // `excused_from_all` the `--all` run applies, so the posture CI enforces and the posture
    // `--all` prints cannot drift apart, and the standing reds are written down in exactly one
    // place in Rust rather than pasted into two workflows.
    //
    // A gate with no posture entry has nothing to score against and says so rather than passing.
    if args.iter().any(|a| a == "--posture") {
        if !reg.has_posture() {
            eprintln!(
                "xtask gate {name} --posture: `{name}` has no entry in REPORT_ONLY, so there is no \
                 standing-red list to score it against and this flag would be a green nobody \
                 defined. Run it plainly."
            );
            return 2;
        }
        if !verdict.red {
            println!("{name} --posture: green outright");
            return 0;
        }
        return match gates::excused_from_all(reg.name, &cx, &verdict) {
            Some(why) => {
                println!("{name} --posture: EXCUSED — {why}");
                0
            }
            None => {
                eprintln!(
                    "xtask gate {name} --posture: RED beyond its standing list (the lines above \
                     name what changed). Either fix it, or move the row onto \
                     CONSTRUCTION_STANDING_REDS in xtask/src/gates/mod.rs in a diff somebody reads."
                );
                1
            }
        };
    }
    i32::from(verdict.red)
}

/// `--jobs N` / `--jobs=N`: how many of a battery's cases are taken at once. Unknown or absent
/// leaves the default, which is the box's own parallelism.
fn jobs_arg(args: &[String]) -> Option<usize> {
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let raw = if let Some(v) = a.strip_prefix("--jobs=") {
            Some(v.to_string())
        } else if a == "--jobs" {
            it.next().cloned()
        } else {
            None
        };
        if let Some(raw) = raw {
            return raw.trim().parse::<usize>().ok().filter(|n| *n > 0);
        }
    }
    None
}

/// ONE BATTERY, AND A RED ONE RE-TAKEN SERIALLY BEFORE IT IS BELIEVED.
///
/// The cases are taken across the cores, and a case is isolated by construction — an [`Overlay`]
/// is per-plant and `with_overlay` never touches the base context. That is an argument, and the
/// harness's own `two_cases_planted_at_the_same_path_never_see_each_other` is the proof of it. But
/// a runner reading a red row cannot re-derive either, and "it only fails when the box is busy" is
/// how a gate earns a `|| true`. So a battery that goes red at more than one job is TAKEN AGAIN AT
/// ONE, and BOTH answers are printed: a finding that survives the serial run is the gate's, and a
/// finding that does not is named as what it is — a defect in this harness, not in the gate.
/// THE SERIAL FRACTION OF A BATTERY, PRINTED BESIDE ITS TOTAL.
///
/// Every case's gate run is taken across the cores; the plant it is driven over is built where the
/// case is pushed, on one thread, because that is where the argument was written. So this number is
/// the part of the battery that more cores cannot touch — and, when it is a large share, the name
/// of the case that owns most of it is the next thing to make lazy. It is printed rather than
/// derived from two runs because deriving it needs a serial run, which is the thing nobody wants to
/// wait for.
fn planting(report: &gates::Report<'_>) -> String {
    let planting = report.planting();
    if planting.as_secs_f64() < 0.05 {
        return String::new();
    }
    let dearest = report
        .dearest_plant()
        .filter(|(_, t)| t.as_secs_f64() >= 0.05)
        .map(|(n, t)| format!(", dearest plant {:.1}s ({n})", t.as_secs_f64()))
        .unwrap_or_default();
    format!(
        ", {:.1}s of that PLANTING on one thread{dearest}",
        planting.as_secs_f64()
    )
}

fn run_selftest(gate: &dyn gates::Gate, cx: &Ctx) -> i32 {
    println!("xtask selftest {}", gate.name());
    // A SELFTEST GETS THE SAME CEILING AS A RUN. It plants fixtures and executes the gate over
    // each one, so every way a gate can wedge is a way a selftest can wedge — and it was a
    // `--selftest` sitting at seven minutes that made the deadlock visible in the first place.
    // THE BATTERY'S OWN CEILING, not one gate run's. See `gates::DEFAULT_SELFTEST_CEILING`.
    let watchdog = gates::Watchdog::arm(
        gate.name(),
        gate.owed(),
        gates::selftest_ceiling_from_env(gate.name()),
    );
    let report = gate.selftest(cx);
    let jobs = report.jobs();
    // TAKEN UNDER THE WATCHDOG, NOT AFTER IT. A case is a plan now, and a plan is taken on the
    // first read of the report — so reading the cases after the watchdog was dropped would have
    // disarmed the ceiling over exactly the work it exists to bound. This is that read.
    let _ = report.cases();
    drop(watchdog);
    for case in report.cases() {
        let got = match &case.got {
            gates::Expect::Green => "GREEN",
            gates::Expect::Red { .. } => "RED",
            gates::Expect::Skipped => "SKIPPED",
        };
        println!("  {got:<7} {}", case.name);
    }
    match gates::verify_report(gate, &report) {
        Ok(()) => {
            let slowest = report
                .slowest()
                .map(|(n, t)| format!(", slowest {:.1}s ({n})", t.as_secs_f64()))
                .unwrap_or_default();
            println!(
                "  {} case(s), {} skipped, {:.1}s / {:.0} work units{slowest}{} — the gate is proven RED-able",
                report.cases().len(),
                report.skipped(),
                report.total().as_secs_f64(),
                report.units(),
                planting(&report),
            );
            0
        }
        Err(errs) => {
            // WHAT A RED BATTERY COST IS PRINTED TOO. It used to be printed only on the green
            // path, so the one run a reader most needs to attribute — the slow one that also
            // failed — was the one that said nothing about where its minutes went.
            println!(
                "  {} case(s), {} skipped, {:.1}s / {:.0} work units{} at --jobs {jobs}",
                report.cases().len(),
                report.skipped(),
                report.total().as_secs_f64(),
                report.units(),
                report
                    .slowest()
                    .map(|(n, t)| format!(", slowest {:.1}s ({n})", t.as_secs_f64()))
                    .unwrap_or_default(),
            );
            println!("  {}", planting(&report).trim_start_matches(", "));
            println!("xtask selftest {} FAILED:", gate.name());
            for e in &errs {
                println!("  - {e}");
            }
            if jobs > 1 {
                println!(
                    "  ...re-taking the battery at --jobs 1, to tell a real RED from a race in \
                     the harness:"
                );
                gates::set_selftest_jobs(1);
                let serial = gate.selftest(cx);
                let _ = serial.cases();
                let again = gates::verify_report(gate, &serial)
                    .err()
                    .unwrap_or_default();
                gates::set_selftest_jobs(jobs);
                if again.is_empty() {
                    println!(
                        "  - EVERY finding above went away at --jobs 1 over {} case(s). That is a \
                         defect in the SELFTEST HARNESS, not in `{}`: the cases are supposed to be \
                         isolated by construction and one of them is not.",
                        serial.cases().len(),
                        gate.name()
                    );
                } else {
                    for e in &again {
                        println!("  - (also at --jobs 1) {e}");
                    }
                }
            }
            1
        }
    }
}

fn selftest_cmd(args: &[String]) -> i32 {
    if let Some(n) = jobs_arg(args) {
        gates::set_selftest_jobs(n);
    }
    let cx = match open_ctx() {
        Ok(cx) => cx,
        Err(code) => return code,
    };

    let named = args
        .iter()
        .enumerate()
        .find(|(i, a)| !a.starts_with("--") && !(*i > 0 && args[i - 1] == "--jobs"))
        .map(|(_, a)| a);
    if let Some(name) = named {
        let Some(reg) = gates::find(name) else {
            eprintln!("xtask selftest: no registered gate `{name}`");
            eprintln!("registered gates: {}", gates::names().join(", "));
            return 2;
        };
        return run_selftest((reg.build)().as_ref(), &cx);
    }

    // EVERY registered gate's RED proof, and a gate without one is refused rather than skipped.
    let mut failed = Vec::new();
    for reg in gates::REGISTRY {
        if run_selftest((reg.build)().as_ref(), &cx) != 0 {
            failed.push(reg.name);
        }
    }
    if failed.is_empty() {
        println!(
            "\ncargo xtask selftest: {} registered gate(s), every one proven able to go RED",
            gates::REGISTRY.len()
        );
        0
    } else {
        eprintln!(
            "\ncargo xtask selftest: unproven gate(s): {}",
            failed.join(", ")
        );
        1
    }
}

fn denylist_cmd(args: &[String]) -> i32 {
    if args.iter().any(|a| a == "--selftest") {
        return i32::from(!selftest::run());
    }
    let cx = match open_ctx() {
        Ok(cx) => cx,
        Err(code) => return code,
    };
    let report = denylist::run(&cx);
    let ok = if args.iter().any(|a| a == "--format=tsv") {
        denylist::print_report_tsv(&report)
    } else {
        denylist::print_report(&report)
    };
    i32::from(!ok)
}
