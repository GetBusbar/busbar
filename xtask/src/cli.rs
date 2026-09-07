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
  cargo xtask gate <name> [--selftest] [--report] [--format=tsv]
  cargo xtask gate --list
  cargo xtask gate --all [--format=tsv]
  cargo xtask gate <name> --parity -- <legacy argv...>
  cargo xtask selftest [<name>]
  cargo xtask denylist [--selftest] [--format=tsv]
  cargo xtask teller-steps [--root-legs] [--root-legs-gating]
  cargo xtask ledger {sync|status|next|record|fixed} | --check
  cargo xtask full-gate [--list] [--selftest] [--dump-gates|--dump-cargo [FILE]]";

/// The environment variable the legacy release-gate scripts write their ledger through.
const LEGACY_LEDGER_ENV: &str = "LEDGER";

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
        Ok(cx) => cx.report_only(report_only),
        Err(code) => return code,
    };

    if args.iter().any(|a| a == "--all") {
        let mut red = Vec::new();
        for reg in gates::REGISTRY {
            let gate = (reg.build)();
            let verdict = gates::execute(gate.as_ref(), &cx);
            if tsv {
                gates::print_rows_tsv(&verdict.rows);
            } else {
                gates::print_verdict(reg.name, &verdict);
            }
            if verdict.red {
                red.push(reg.name);
            }
        }
        if red.is_empty() {
            println!("cargo xtask gate --all: every registered gate is green");
            return 0;
        }
        eprintln!("cargo xtask gate --all: RED in {}", red.join(", "));
        return 1;
    }

    let Some(name) = args.iter().find(|a| !a.starts_with("--")) else {
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

    let gate = (reg.build)();
    if want_selftest {
        return run_selftest(gate.as_ref(), &cx);
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

    let verdict = gates::execute(gate.as_ref(), &cx);
    if tsv {
        gates::print_rows_tsv(&verdict.rows);
    } else {
        gates::print_verdict(reg.name, &verdict);
    }
    i32::from(verdict.red)
}

fn run_selftest(gate: &dyn gates::Gate, cx: &Ctx) -> i32 {
    println!("xtask selftest {}", gate.name());
    let report = gate.selftest(cx);
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
            println!(
                "  {} case(s), {} skipped — the gate is proven RED-able",
                report.cases().len(),
                report.skipped()
            );
            0
        }
        Err(errs) => {
            println!("xtask selftest {} FAILED:", gate.name());
            for e in &errs {
                println!("  - {e}");
            }
            1
        }
    }
}

fn selftest_cmd(args: &[String]) -> i32 {
    let cx = match open_ctx() {
        Ok(cx) => cx,
        Err(code) => return code,
    };

    if let Some(name) = args.iter().find(|a| !a.starts_with("--")) {
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
    let report = denylist::run(cx.root());
    let ok = if args.iter().any(|a| a == "--format=tsv") {
        denylist::print_report_tsv(&report)
    } else {
        denylist::print_report(&report)
    };
    i32::from(!ok)
}
