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
