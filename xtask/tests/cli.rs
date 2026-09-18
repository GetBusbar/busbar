//! The dispatcher's arms and its EXIT CODES, driven through `cli::main` directly rather than
//! through a subprocess — a test that shells out to the binary can only assert on printed text.
//!
//! The codes are a contract `full-gate.sh` already relies on: 0 green, 1 the gate failed, 2 the
//! ARGUMENTS were wrong, 3 the gate could not run. Collapsing 1 and 3 is how a runner reports green
//! over a gate that never executed, and collapsing 2 into either is how a typo'd flag ends up being
//! handed to the thing the flag was meant to control.

fn run(args: &[&str]) -> i32 {
    let owned: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
    xtask::cli::main(&owned)
}

#[test]
fn no_subcommand_and_an_unknown_subcommand_are_argument_errors() {
    assert_eq!(run(&[]), 2);
    assert_eq!(run(&["not-a-subcommand"]), 2);
}

#[test]
fn an_unknown_gate_is_an_argument_error_and_never_falls_through_into_running_something() {
    assert_eq!(run(&["gate", "denylst"]), 2);
    assert_eq!(run(&["gate"]), 2);
    assert_eq!(run(&["selftest", "no-such-gate"]), 2);
}

#[test]
fn a_mistyped_flag_is_an_argument_error_not_a_quietly_weaker_run() {
    // RED BEFORE THE GUARD IN `gate()`: a transposed `--require-verison` missed every
    // `strip_prefix("--require-version=")` test, so `require_version` stayed `None`, the changelog
    // gate's ORDINARY arm ran and exited 0/1, and a release step believed it had asked for the
    // version-pinned check it never got. A misspelt flag is an ARGUMENT error (2), never a run that
    // quietly checked less — the same code `audit_cmd::parse` already returns for an unknown option.
    assert_eq!(
        run(&["gate", "changelog", "--require-verison=1.6.0"]),
        2,
        "a typo'd release flag must be refused, not fall through to the ordinary arm"
    );
    assert_eq!(run(&["gate", "segregation", "--reprot"]), 2);
    assert_eq!(run(&["gate", "segregation", "--requiredated-top"]), 2);

    // A KNOWN FLAG ON THE SAME GATE STILL RUNS. `--report` prints the verdict and withholds the
    // score, so it reaches 0 — never the argument error the guard hands an unknown flag.
    assert_eq!(
        run(&["gate", "segregation", "--report"]),
        0,
        "a spelt-correctly flag must still reach a verdict, not trip the unknown-flag guard"
    );

    // THE `--parity` LEGACY COMMAND IS THE LEGACY TOOL'S TO PARSE. A `--foo` after `--` is an
    // argument to the script being compared, not an unknown flag to `gate`; the guard stops at `--`.
    // (No probes-less gate + a no-row legacy command is exit 3, proven elsewhere; here the point is
    // only that the `--bogus` past `--` did not turn into a 2.)
    assert_ne!(
        run(&[
            "gate",
            "segregation",
            "--parity",
            "--",
            "/usr/bin/true",
            "--bogus"
        ]),
        2,
        "a flag after `--` belongs to the legacy command and must not trip the unknown-flag guard"
    );
}

#[test]
fn list_and_a_named_gate_run_and_all_reaches_a_verdict_over_the_real_tree() {
    assert_eq!(run(&["gate", "--list"]), 0);
    assert_eq!(run(&["gate", "segregation"]), 0);
    assert_eq!(run(&["gate", "segregation", "--format=tsv"]), 0);

    // `--all` IS ASSERTED TO HAVE REACHED A VERDICT, not to have liked the tree.
    //
    // This case's subject is the DISPATCHER, and the two facts worth pinning about `--all` are that
    // every registered gate ran and that the runner distinguished its four outcomes. Requiring 0
    // would make it a second, quieter assertion that the branch carries no debt in any gate —
    // which is a claim about the tree, not about the runner, and it is a claim that goes false the
    // first time a gate is converted whose subject the branch is genuinely red on. A case that
    // fails for a reason it is not about is a case somebody deletes.
    //
    // 1 is "a gate failed" and 0 is "none did"; 2 (bad arguments) and 3 (could not run) are the
    // two answers that would mean `--all` never judged the tree at all, and they stay refused.
    let all = run(&["gate", "--all"]);
    assert!(
        all == 0 || all == 1,
        "`gate --all` must reach a verdict, not report an argument error (2) or a gate that could \
         not run (3); got {all}"
    );
}

#[test]
fn selftest_runs_every_registered_gates_red_proof() {
    assert_eq!(run(&["selftest"]), 0);
    assert_eq!(run(&["selftest", "segregation"]), 0);
    assert_eq!(run(&["gate", "segregation", "--selftest"]), 0);
}

/// THE REGISTRY-VS-WORKFLOW SET EQUALITY, ON THE PER-PUSH PATH.
///
/// `full_gate::gate_set_diff` is what notices a gate deleted from `ci.yml` — and it was reachable
/// only from `cargo xtask full-gate --selftest`, which no workflow step, no `CARGO_LOCAL` entry and
/// no test invoked. A check nothing calls answers no question: every registered gate could have
/// been dropped out of CI with the whole tree green. This case is its caller. `cargo test
/// --workspace --locked` runs on every push, so the equality — and the excuse list's claims, which
/// the same selftest now puts to the tree — is judged on every push with it.
///
/// It asserts 0 and not "reached a verdict": unlike `gate --all`, nothing here is a claim about
/// debt in the tree. Discovery, the floors, the skip reasons and the two set differences are all
/// facts about the repository's own wiring, and every one of them is supposed to hold at all times.
#[test]
fn the_registry_and_the_workflow_still_name_the_same_gates() {
    assert_eq!(run(&["full-gate", "--selftest"]), 0);
}

/// THE AUDIT REGISTER, ON THE PER-PUSH PATH.
///
/// `audit-ledger` is the instrument that judges the audits — is a scope covered, is a HIGH finding
/// still open, does a record's hash belong to the commit it claims to have read. Its own excuse
/// entry said out loud that per push it was unguarded: its only caller was
/// `scripts/verify-1.6.0-done.sh`, which runs at release time. A register can be edited, a scope
/// dropped and a `fixed` stamped with nobody confirming it, and nothing on the push path would say
/// so until the release the register exists to gate.
///
/// This case and the `ci.yml` step beside it are that caller. Both arms are asserted, and both are
/// asserted at 0: the selftest, because a gate that cannot go red proves nothing; and the RUN,
/// because unlike `gate --all` this is not a claim about debt in the tree — the register either is
/// sound or the audits it records cannot be trusted.
#[test]
fn the_audit_register_is_judged_on_every_push() {
    assert_eq!(run(&["gate", "audit-ledger", "--selftest"]), 0);
    assert_eq!(run(&["gate", "audit-ledger"]), 0);
}

#[test]
fn ledger_sync_refuses_to_overwrite_a_corrupt_register_and_never_exits_zero() {
    // RED BEFORE THE FIX in `audit_cmd::read_scopes`: a register that EXISTS but will not parse
    // used to `.ok()` / `unwrap_or_default()` to zero recorded scopes, so `sync --write` treated
    // every derived scope as newly added, wrote a fresh record-less document over it, and exited
    // 0 — the whole audit history erased by one bad byte behind a green exit. Point `--ledger` at
    // a corrupt file of our own so the real register is never touched by this test.
    let dir = std::env::temp_dir().join(format!(
        "xtask-corrupt-register-{}-{:?}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let reg = dir.join("audit-ledger.json");
    let corrupt: &[u8] = b"{ \"scopes\": [ this is not valid json";
    std::fs::write(&reg, corrupt).unwrap();

    let code = run(&[
        "ledger",
        "sync",
        "--write",
        "--ledger",
        reg.to_str().unwrap(),
    ]);
    assert_eq!(
        code, 2,
        "a corrupt register must be a hard error, never a silent overwrite at exit 0"
    );
    assert_eq!(
        std::fs::read(&reg).unwrap(),
        corrupt,
        "sync must leave a register it could not read exactly as it found it, never rewrite it \
         into a fresh record-less document"
    );

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn the_pre_registry_denylist_spelling_still_works_unchanged() {
    assert_eq!(run(&["denylist"]), 0);
    assert_eq!(run(&["denylist", "--selftest"]), 0);
    assert_eq!(run(&["denylist", "--format=tsv"]), 0);
}

#[test]
fn the_parity_arm_needs_a_legacy_command_and_refuses_one_that_wrote_no_rows() {
    // `--parity` with nothing after `--` is an argument error, not a vacuous green.
    assert_eq!(run(&["gate", "segregation", "--parity"]), 2);

    // A legacy script that writes no ledger rows cannot be at parity with anything: the harness
    // reports 3 (could not run), never 0.
    assert_eq!(
        run(&["gate", "segregation", "--parity", "--", "/usr/bin/true"]),
        3
    );
}
