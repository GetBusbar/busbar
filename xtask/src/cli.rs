//! Argument dispatch.
//!
//! Exit codes are a contract, and they are `full-gate.sh`'s: **0** green, **1** the gate failed,
//! **2** the ARGUMENTS were wrong (an unknown subcommand, an unknown gate, an unknown flag — never
//! fallen through into doing something), **3** the gate COULD NOT RUN (unwritable scratch, missing
//! `git`, an unreadable tree). "The gate failed" and "the gate could not run" are different facts
//! and a runner that collapses them is a runner that can report green over a gate that never
//! executed.

use crate::conformance_check;
use crate::ctx::Ctx;
use crate::denylist;
use crate::gates;
use crate::selftest;

const USAGE: &str = "\
usage:
  cargo xtask gate <name> [--selftest] [--jobs N] [--report] [--strict] [--write] [--posture] [--format=tsv]
  cargo xtask gate changelog [--require-version=V] [--require-dated-top]
  cargo xtask gate changelog-register [--require-version=V]
  cargo xtask gate hot-path-perf|hot-path-alloc [--execute]
  cargo xtask gate --list
  cargo xtask gate --all [--format=tsv]
  cargo xtask gate <name> --parity -- <legacy argv...>
  cargo xtask selftest [<name>] [--jobs N]
  cargo xtask denylist [--selftest] [--format=tsv]
  cargo xtask loc [--ref <rev>] [--format json|table] [--per-file] [--ceiling CRATES=N]
  cargo xtask loc --selftest
  cargo xtask teller-steps [--root-legs] [--root-legs-gating]
  cargo xtask ledger {sync|status|next|record|fixed|move} | --check
  cargo xtask full-gate [--list] [--selftest] [--dump-gates|--dump-cargo [FILE]]
  cargo xtask conformance check --suite <id>|all|--musts [--sha <sha>] [--manifest <path>] [--format=tsv]
  cargo xtask conformance check --selftest";

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
pub const NON_GATE_SUBCOMMANDS: &[&str] = &["full-gate", "ledger", "conformance", "loc"];

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
        // THE ONE LINE COUNTER. Not a gate: it is an INSTRUMENT, and the gates that ratchet a
        // line ceiling call the same library in process. It is listed in
        // `NON_GATE_SUBCOMMANDS` for the same reason `ledger` is — a reader of `ci.yml` cannot
        // tell a gate from a subcommand by shape, and nothing reconciles an owed row set for it.
        Some("loc") => match open_ctx() {
            Ok(cx) => crate::loc::main(&cx, &args[1..]),
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
        // THE TURNSTILE-FACING PER-SUITE CONFORMANCE ADMISSION COMMAND. Not a gate: it answers a
        // CLI question (`--suite <id>` / `--musts`) against the manifest `gate conformance-sync`
        // already reconciled, read-only, so the release pipeline can shell to it directly
        // (`CONFORMANCE-GATES-PLAN.md` §1.3 — turnstile drives local subprocesses, never GitHub
        // check-runs).
        Some("conformance") => match open_ctx() {
            Ok(cx) => conformance_check::main(&cx, &args[1..]),
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

/// THE FLAGS `cargo xtask gate` KNOWS. Anything else that starts with `-` is an ARGUMENT ERROR.
///
/// The dispatcher used to test each flag with `args.iter().any(..)` and never look at what was
/// left over, so `cargo xtask gate hot-path-perf --execute` — before `--execute` existed — and
/// `cargo xtask gate changelog --require-verison=1.6.0` both ran the DEFAULT arm and exited on it.
/// A caller who typed a flag believes the flag took effect; a green from the arm they did not ask
/// for is a green for a check that never ran. So every argument is now accounted for, and an
/// unaccounted one exits 2 (the exit-code contract at the top of this file) before any gate runs.
const GATE_FLAGS: &[&str] = &[
    "--selftest",
    "--list",
    "--all",
    "--report",
    "--strict",
    "--write",
    "--posture",
    "--parity",
    "--execute",
    "--require-dated-top",
    "--format=tsv",
];
/// `--flag=value` forms `cargo xtask gate` knows.
const GATE_VALUED: &[&str] = &["--jobs=", "--require-version=", "--root-flag="];
/// The flags `cargo xtask selftest` knows (`--jobs N` is handled as a pair).
const SELFTEST_FLAGS: &[&str] = &[];
const SELFTEST_VALUED: &[&str] = &["--jobs="];
/// The flags the pre-registry `cargo xtask denylist` spelling knows.
const DENYLIST_FLAGS: &[&str] = &["--selftest", "--format=tsv"];

/// Split `args` into its POSITIONAL words, refusing every argument that is not a known flag.
///
/// `--jobs` takes the NEXT argument as its value (so `--jobs 8 construction` names `construction`,
/// not a gate called `8`). A bare `--` ends the flags only when `allow_tail` is set — the parity
/// arm's legacy argv follows it and is the legacy command's business, not this parser's; anywhere
/// else a `--` is itself an unknown argument.
fn positionals<'a>(
    args: &'a [String],
    flags: &[&str],
    valued: &[&str],
    allow_tail: bool,
) -> Result<Vec<&'a str>, String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "--" {
            if allow_tail {
                break;
            }
            return Err("`--` is only meaningful after `--parity`".to_string());
        }
        if a == "--jobs" && valued.contains(&"--jobs=") {
            if args.get(i + 1).is_none() {
                return Err("`--jobs` needs a value".to_string());
            }
            i += 2;
            continue;
        }
        if a.starts_with('-') {
            let known = flags.contains(&a) || valued.iter().any(|p| a.starts_with(p));
            if !known {
                return Err(format!("unknown flag `{a}`"));
            }
        } else {
            out.push(a);
        }
        i += 1;
    }
    Ok(out)
}

/// The refusal every subcommand prints for an argument it does not know.
fn refuse_args(cmd: &str, why: &str) -> i32 {
    eprintln!(
        "xtask {cmd}: {why} — refused rather than ignored: an unread argument runs the default arm \
         and reports its verdict as the one that was asked for."
    );
    eprintln!("{USAGE}");
    2
}

fn gate(args: &[String]) -> i32 {
    let parity = args.iter().any(|a| a == "--parity");
    let words = match positionals(args, GATE_FLAGS, GATE_VALUED, parity) {
        Ok(w) => w,
        Err(why) => return refuse_args("gate", &why),
    };
    let listing = args.iter().any(|a| a == "--list" || a == "--all");
    if words.len() > usize::from(!listing) {
        return refuse_args(
            "gate",
            &format!(
                "unexpected argument(s) {:?} — `gate` takes one gate name, and none with \
                 --list/--all",
                &words[usize::from(!listing)..]
            ),
        );
    }
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

    // `--jobs N` takes a value, so the N after it is NOT the gate name — `positionals` consumed
    // it. Without that, `cargo xtask gate --selftest --jobs 8 construction` would look for a gate
    // called `8`.
    let Some(name) = words.first().copied() else {
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

    let gate = match build_gate(reg, args, cx.env().write) {
        Ok(g) => g,
        Err(code) => return code,
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
        //
        // `inventory-coverage --write` is the same shape and for the same reason: it regenerates
        // qa/inventory-coverage.json, qa/inventory-gaps.json and the behaviour-doc coverage matrix,
        // and REFUSES — as rows, not as stderr — when a family has dropped below its recorded floor
        // or when the regeneration would ADD an id to the gaps file that is not accepted by name.
        // A refusal a reader can diff is the whole point of routing it through the ledger.
        // `conformance-sync --write` REGENERATES conformance/manifest.json and the README badge
        // block from the registry + verdicts, and answers through the ledger — a refusal a reader
        // can diff — exactly like kind-isolation and inventory-coverage.
        if matches!(
            reg.name,
            "kind-isolation" | "inventory-coverage" | "conformance-sync" | "config-schema"
        ) {
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
            // The declared shape is a DERIVED projection of the workflow (structural JSON), never
            // hand-edited — see `qa_gate_dispatch::DECLARED`'s doc comment. `--write` regenerates it
            // from whatever `qa-gate.yml` this branch carries, exactly like `design-bindings` and
            // `construction` regenerate their own derived artifacts from what this branch measures.
            "qa-gate-dispatch" => {
                crate::gates::qa_gate_dispatch::QaGateDispatchGate::new().write_declared(&cx)
            }
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
                eprintln!("{}", posture_refusal(name));
                1
            }
        };
    }
    i32::from(verdict.red)
}

/// WHICH CONSTRUCTION OF THE NAMED GATE THIS INVOCATION RUNS.
///
/// THE RELEASE-TIME AND EXECUTING ARMS, as flags on the gate and never as an environment variable.
///
/// A few gates run a stricter form at release time than on every push. Those arms stay explicit
/// here because an env-overridable strictness is a strictness that is off wherever nobody looked
/// — the cautionary case is a group floor that was overridable downward from the environment
/// with no floor-only-rises guard. A flag has to be written at the call site, in a diff.
///
/// A flag handed to a gate that has no such arm is an ARGUMENT error, not a quietly looser run: a
/// gate must not report green having checked the ordinary arm.
///
/// `--require-version=V` is BOTH changelog gates' release arm. `changelog-register` declared
/// `changelog-register:release-section-is-the-version` and switched it on from `require_version`,
/// but this dispatcher used to refuse the flag for every gate except `changelog`, so no invocation
/// in the tree could emit the row and the gate anchored every accepted difference to whatever the
/// newest `## [x.y.z]` section happened to be — the previous release's, at promote time (item 160).
/// `--require-dated-top` stays the `changelog` gate's alone; `changelog-register` has no such arm.
///
/// `--execute` is the hot-path gates' EXECUTING arm (`HotPathPerfExecGate` /
/// `HotPathAllocExecGate`, 9bb473f04): the registry's build reads the bench source, this one builds
/// and runs the bench and judges its real output.
fn build_gate(
    reg: &gates::Registration,
    args: &[String],
    write: bool,
) -> Result<Box<dyn gates::Gate>, i32> {
    let require_dated_top = args.iter().any(|a| a == "--require-dated-top");
    let require_version = args
        .iter()
        .find_map(|a| a.strip_prefix("--require-version="))
        .map(str::to_string);
    let execute = args.iter().any(|a| a == "--execute");
    if execute && !matches!(reg.name, "hot-path-perf" | "hot-path-alloc") {
        eprintln!(
            "xtask gate {}: --execute is the hot-path gates' executing arm; `{}` has no such arm \
             and must not report green as though it ran one.",
            reg.name, reg.name
        );
        return Err(2);
    }
    if require_version.as_deref() == Some("") {
        eprintln!(
            "xtask gate {}: --require-version= needs a version",
            reg.name
        );
        return Err(2);
    }
    let release_arm = require_dated_top || require_version.is_some();
    let arm_owner = match reg.name {
        "changelog" => true,
        "changelog-register" => !require_dated_top,
        _ => false,
    };
    if release_arm && !arm_owner {
        eprintln!(
            "xtask gate {}: --require-version is the release arm of `changelog` and \
             `changelog-register`, --require-dated-top of `changelog` alone; `{}` has no such arm \
             and must not report green as though it ran one.",
            reg.name, reg.name
        );
        return Err(2);
    }
    Ok(if release_arm && reg.name == "changelog" {
        let mut g = crate::gates::changelog::ChangelogGate::new();
        if require_dated_top {
            g = g.require_dated_top();
        }
        if let Some(v) = require_version {
            g = g.require_version(v);
        }
        Box::new(g)
    } else if let (true, Some(v)) = (release_arm, require_version) {
        Box::new(crate::gates::changelog_register::ChangelogRegisterGate::new().require_version(v))
    } else if execute && reg.name == "hot-path-perf" {
        Box::new(crate::gates::hot_path_perf::HotPathPerfExecGate::new())
    } else if execute {
        Box::new(crate::gates::hot_path_alloc::HotPathAllocExecGate::new())
    } else if write && reg.name == "kind-isolation" {
        // `kind-isolation --write` RE-PINS ITS EXACT COUNTS DOWNWARD, and refuses wholesale if any
        // would rise. It is a separate CONSTRUCTION rather than a flag the gate reads out of the
        // context, because `owed` is what the reconciliation is written against and this run emits
        // one row: the re-pin's own. Built HERE rather than in the write branch of `gate`, so
        // `--write --selftest` proves the arm it is about to run rather than a different one.
        Box::new(crate::gates::kind_isolation::KindIsolationGate::write())
    } else {
        (reg.build)()
    })
}

/// The `--posture` refusal, naming the list THIS gate's standing reds live on. It used to name
/// CONSTRUCTION_STANDING_REDS for every gate, so a `qa-names` red sent its reader to the wrong
/// constant. A posture with no named list (a whole-gate or release-time excuse) has no row to
/// move, and says the excuse itself stopped holding.
fn posture_refusal(name: &str) -> String {
    match gates::standing_list_of(name) {
        Some(list) => format!(
            "xtask gate {name} --posture: RED beyond its standing list (the lines above name what \
             changed). Either fix it, or move the row onto {list} in xtask/src/gates/mod.rs in a \
             diff somebody reads."
        ),
        None => format!(
            "xtask gate {name} --posture: RED and its REPORT_ONLY excuse no longer holds (the \
             lines above name why). Fix the red, or correct the entry in xtask/src/gates/mod.rs \
             in a diff somebody reads."
        ),
    }
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
/// The cases are taken across the cores, and a case is isolated by construction — an
/// [`Overlay`](crate::ctx::Overlay) is per-plant and `with_overlay` never touches the base
/// context. That is an argument, and the harness's own
/// `two_cases_planted_at_the_same_path_never_see_each_other` is the proof of it. But
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
    if std::env::var("XTASK_SELFTEST_TIMING").is_ok() {
        let mut rows = report.timings();
        rows.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap_or(std::cmp::Ordering::Equal));
        for (name, took, units, prepaid) in &rows {
            eprintln!(
                "TIMING {units:8.1}u {:7.2}s (prepaid {:6.2}s)  {name}",
                took.as_secs_f64(),
                prepaid.as_secs_f64()
            );
        }
    }
    for case in report.cases() {
        let got = match &case.got {
            gates::Expect::Green => "GREEN",
            gates::Expect::Red { .. } => "RED",
            gates::Expect::Skipped => "SKIPPED",
            // NOT A COLOUR. `INERT` is a plant that changed nothing; `IMPOSSIBLE` is a row that was
            // already red before the plant. Neither is ever a proof, and printing either of them as
            // RED is how one of them went unread for months.
            gates::Expect::Inert { .. } => "INERT",
            gates::Expect::Impossible { .. } => "IMPOSS",
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
    let words = match positionals(args, SELFTEST_FLAGS, SELFTEST_VALUED, false) {
        Ok(w) => w,
        Err(why) => return refuse_args("selftest", &why),
    };
    if words.len() > 1 {
        return refuse_args(
            "selftest",
            &format!(
                "unexpected argument(s) {:?} — `selftest` takes at most one gate name",
                &words[1..]
            ),
        );
    }
    if let Some(n) = jobs_arg(args) {
        gates::set_selftest_jobs(n);
    }
    let cx = match open_ctx() {
        Ok(cx) => cx,
        Err(code) => return code,
    };

    if let Some(name) = words.first().copied() {
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
    match positionals(args, DENYLIST_FLAGS, &[], false) {
        Ok(w) if w.is_empty() => {}
        Ok(w) => return refuse_args("denylist", &format!("unexpected argument(s) {w:?}")),
        Err(why) => return refuse_args("denylist", &why),
    }
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

#[cfg(test)]
mod tests {
    use super::{build_gate, main, posture_refusal};
    use crate::gates;

    fn run(args: &[&str]) -> i32 {
        let owned: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
        main(&owned)
    }

    fn argv(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| (*s).to_string()).collect()
    }

    /// AN ARGUMENT NOBODY READ IS REFUSED, NEVER IGNORED. Every one of these used to run the
    /// default arm and exit on its verdict — `segregation` is green, so each answered 0 for a flag,
    /// a word or a subcommand spelling that was never looked at.
    #[test]
    fn an_unknown_flag_or_a_stray_word_is_an_argument_error_not_the_default_arm() {
        assert_eq!(run(&["gate", "segregation", "--frobnicate"]), 2);
        assert_eq!(run(&["gate", "segregation", "--formt=tsv"]), 2);
        assert_eq!(run(&["gate", "segregation", "-x"]), 2);
        assert_eq!(run(&["gate", "segregation", "construction"]), 2);
        assert_eq!(run(&["gate", "segregation", "--", "x"]), 2);
        assert_eq!(run(&["gate", "--list", "--frobnicate"]), 2);
        assert_eq!(run(&["gate", "--list", "segregation"]), 2);
        assert_eq!(run(&["gate", "--all", "--frobnicate"]), 2);
        assert_eq!(run(&["selftest", "segregation", "--frobnicate"]), 2);
        assert_eq!(run(&["selftest", "segregation", "construction"]), 2);
        assert_eq!(run(&["denylist", "--frobnicate"]), 2);
        assert_eq!(run(&["denylist", "extra"]), 2);
        // `--execute` is a KNOWN flag, but only the hot-path gates have the arm it selects.
        assert_eq!(run(&["gate", "segregation", "--execute"]), 2);
    }

    /// The known spellings still parse: the value after `--jobs` is not a gate name, and the
    /// parity arm's legacy argv after `--` is not this parser's to judge.
    #[test]
    fn the_known_spellings_still_parse() {
        assert_eq!(run(&["gate", "--list"]), 0);
        assert_eq!(run(&["gate", "segregation", "--format=tsv"]), 0);
        assert_eq!(
            run(&["gate", "--jobs", "2", "segregation", "--selftest"]),
            0
        );
        assert_eq!(run(&["gate", "segregation", "--parity"]), 2);
        assert_eq!(
            run(&[
                "gate",
                "segregation",
                "--parity",
                "--",
                "/usr/bin/true",
                "--anything"
            ]),
            3
        );
    }

    /// ITEM 160: `changelog-register --require-version=V` REACHES the gate's release arm. It used
    /// to exit 2 ("the changelog gate's release arms") for every gate but `changelog`, so
    /// `changelog-register:release-section-is-the-version` could be emitted by no invocation. A
    /// version this CHANGELOG has no section for is a RED gate (1) — the arm ran and judged —
    /// never an argument error (2).
    #[test]
    fn changelog_register_takes_its_release_arm() {
        assert_eq!(
            run(&[
                "gate",
                "changelog-register",
                "--require-version=0.0.0-no-such-release"
            ]),
            1
        );
        let reg = gates::find("changelog-register").expect("registered");
        let g = build_gate(reg, &argv(&["--require-version=1.6.0"]), false)
            .unwrap_or_else(|c| panic!("the release arm was refused with {c}"));
        assert!(
            g.owed()
                .iter()
                .any(|r| r == crate::gates::changelog_register::ROW_VERSION),
            "{:?}",
            g.owed()
        );
        // `--require-dated-top` is `changelog`'s alone: refused, never silently dropped.
        assert_eq!(
            build_gate(reg, &argv(&["--require-dated-top"]), false).err(),
            Some(2)
        );
        let other = gates::find("segregation").expect("registered");
        assert_eq!(
            build_gate(other, &argv(&["--require-version=1.6.0"]), false).err(),
            Some(2)
        );
    }

    /// `--execute` builds the EXECUTING hot-path gates, whose owed set carries the
    /// `:executed` rows the registry's text-only build does not.
    #[test]
    fn execute_builds_the_executing_hot_path_gates() {
        for name in ["hot-path-perf", "hot-path-alloc"] {
            let reg = gates::find(name).expect("registered");
            let plain = (reg.build)().owed();
            let exec = build_gate(reg, &argv(&["--execute"]), false)
                .unwrap_or_else(|c| panic!("{name} --execute was refused with {c}"))
                .owed();
            let executed = format!("{name}:executed");
            assert!(exec.contains(&executed), "{name}: {exec:?}");
            assert!(!plain.contains(&executed), "{name}: {plain:?}");
        }
    }

    /// The refusal names the list the gate's own posture reads, never another gate's.
    #[test]
    fn the_posture_refusal_names_the_gates_own_standing_list() {
        let qa = posture_refusal("qa-names");
        assert!(qa.contains("QA_NAMES_STANDING_REDS"), "{qa}");
        assert!(!qa.contains("CONSTRUCTION_STANDING_REDS"), "{qa}");
        let construction = posture_refusal("construction");
        assert!(
            construction.contains("CONSTRUCTION_STANDING_REDS"),
            "{construction}"
        );
        let whole = posture_refusal("ship-ready");
        assert!(!whole.contains("_STANDING_REDS"), "{whole}");
    }
}
