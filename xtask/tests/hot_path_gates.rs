//! THE HOT-PATH GATES, DRIVEN THROUGH THE DISPATCHER.
//!
//! `docs/design/BUSBAR-1.6.0.md` Part 3 §8 owes a perf gate and an alloc gate; §11b counts
//! their criterion benches toward the core-engine tests/benches 8→9 rise. Both are registered but
//! deliberately NOT invoked by `ci.yml` yet (the keystone wave owns `.github`), so
//! `full_gate::REGISTRY_NOT_IN_CI` excuses them with `Excuse::XtaskTest` pointing HERE: this file is
//! the coverage route the excuse rests on, and it runs under `cargo test --workspace --locked` on
//! every push. The exact invocation strings below are the needles that excuse checks for — keep them
//! byte-identical to the entries in `xtask/src/full_gate.rs`.
//!
//! Driven through `cli::main` directly, like `xtask/tests/cli.rs`: exit 0 is green, and a gate that
//! could not run would not be able to return it.

fn run(args: &[&str]) -> i32 {
    let owned: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
    xtask::cli::main(&owned)
}

#[test]
fn the_hot_path_perf_gate_is_green_over_the_committed_instrument() {
    assert_eq!(run(&["gate", "hot-path-perf"]), 0);
}

#[test]
fn the_hot_path_alloc_gate_is_green_over_the_committed_instrument() {
    assert_eq!(run(&["gate", "hot-path-alloc"]), 0);
}

/// Both gates prove they can still go RED — the property `cargo xtask selftest` refuses a gate for
/// lacking. Driven here too so the whole hot-path witness pair has a home under `xtask/tests/`.
#[test]
fn both_hot_path_gates_prove_red_in_their_selftests() {
    assert_eq!(run(&["gate", "hot-path-perf", "--selftest"]), 0);
    assert_eq!(run(&["gate", "hot-path-alloc", "--selftest"]), 0);
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// THE EXECUTING MODE (item 10). The gates above read the bench SOURCE; these RUN the two benches
// (`cargo bench -p busbar-kernel --bench plane_host_vtable_{perf,alloc}`) and judge their real
// output against the budget. `#[ignore]` because each builds busbar-kernel's bench profile and runs
// criterion — the qa cadence, not the per-push suite. The qa `benches` segment runs them:
//
//   cargo test -p xtask --test hot_path_gates -- --ignored --test-threads=1
//
// Each drives the executing gate's whole selftest: the unplanted real bench must be GREEN on every
// row (text and executed), each real budget-violation knob (`BUSBAR_PERF_STREAM_CROSS`,
// `BUSBAR_ALLOC_INJECT`) must turn the executed rows RED naming the bench's own assertion, and a
// bench that did not run must be RED — never skipped-green — on every executed row.
// ─────────────────────────────────────────────────────────────────────────────────────────────────

use xtask::ctx::Ctx;
use xtask::gates::{Expect, Gate};

/// Every case passed, and every owed row — text and executed — is covered by a RED case.
fn assert_executing_selftest_holds(gate: &dyn Gate) {
    let cx = Ctx::workspace().expect("the workspace opens");
    let report = gate.selftest(&cx);
    let failures = report.failures();
    assert!(
        failures.is_empty(),
        "{}: executing selftest failed:\n{}",
        gate.name(),
        failures.join("\n")
    );
    for owed in gate.owed() {
        assert!(
            report
                .cases()
                .iter()
                .any(|c| matches!(c.expected, Expect::Red { .. }) && c.covers.contains(&owed)),
            "{}: owed row `{owed}` is covered by no RED case",
            gate.name()
        );
    }
    assert!(
        report
            .cases()
            .iter()
            .any(|c| matches!(c.expected, Expect::Green) && matches!(c.got, Expect::Green)),
        "{}: the real bench was never proven GREEN",
        gate.name()
    );
}

#[test]
#[ignore = "executes the criterion perf bench (bench-profile build); run by the qa benches segment"]
fn the_hot_path_perf_gate_executes_its_bench_and_judges_the_real_output() {
    assert_executing_selftest_holds(&xtask::gates::hot_path_perf::HotPathPerfExecGate::new());
}

#[test]
#[ignore = "executes the criterion alloc bench (bench-profile build); run by the qa benches segment"]
fn the_hot_path_alloc_gate_executes_its_bench_and_judges_the_real_output() {
    assert_executing_selftest_holds(&xtask::gates::hot_path_alloc::HotPathAllocExecGate::new());
}
