//! THE TEST COMMAND THE MUTATION JOB RUNS — the four gates' own self-proof, wired into the one
//! runner `cargo-mutants` knows how to drive.
//!
//! WHY THIS FILE EXISTS AT ALL. `cargo-mutants` stubs an expression, rebuilds, and runs `cargo
//! test`. That is the wrong suite for this tree: `cargo test -p xtask --lib` proves the readers,
//! the parsers and the helpers, and it proves almost nothing about whether a GATE still says NO.
//! The thing that proves a gate is the gate's own `--selftest`, which plants a real fault in a
//! copy of the tree and demands the gate go red on it, naming the offender. A mutation campaign
//! run against `cargo test` alone reports a comfortable number about the wrong property.
//!
//! So this integration test IS the bridge: `cargo test -p xtask --test gate_mutation_proof` runs
//!
//!   cargo xtask gate kind-isolation       --selftest
//!   cargo xtask gate kind-isolation-ship  --selftest
//!   cargo xtask gate construction         --selftest
//!   cargo xtask gate design-bindings      --selftest
//!
//! and fails if any of them does. Under `cargo-mutants` the binary those commands build is the
//! MUTATED one — the subprocess compiles from the same scratch tree the mutant was written into —
//! so a stub that no self-test case holds down leaves all four green and the mutant SURVIVES,
//! which is exactly the finding the job exists to report.
//!
//! WHY IT IS GUARDED BY AN ENVIRONMENT VARIABLE. Unguarded, this test would add the better part of
//! an hour to every `cargo test` in the workspace, including the `check` job that has nothing to do
//! with mutation. `XTASK_GATE_MUTATION_PROOF=1` turns it on, and `scripts/gate-mutants.sh` sets it.
//!
//! THE GUARD FAILS SAFE, WHICH IS THE ONLY REASON IT IS ALLOWED TO EXIST. If the variable were
//! ever dropped from the job, this test would go inert — and an inert test command catches FEWER
//! mutants, not more, so every mutant would be reported SURVIVING and the job would go RED. The
//! mistake is loud. There is no arrangement of this switch that turns a hole into a green run.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

/// The gates whose self-proof is the test command. Each one plants faults of its own and asserts
/// the gate names the offender; between them they cover every rule in the mutation job's scope.
const GATES: &[&str] = &[
    "kind-isolation",
    "kind-isolation-ship",
    "construction",
    "design-bindings",
];

/// The switch. See the module comment: absent means inert, and inert means RED, never green.
const SWITCH: &str = "XTASK_GATE_MUTATION_PROOF";

/// THE NARROWING, AND WHY IT IS SAFE TO HAVE ONE.
///
/// The four self-proofs cost about the same each, and a shard pays for all four once as its
/// baseline and once per mutant. When the diff touches only `gates/construction/**`, three of those
/// four prove nothing about the stubbed line — `kind-isolation --selftest` cannot go red on a
/// mutation of a construction rule, so running it is wall clock spent proving the mutant is not
/// somewhere it cannot be.
///
/// `scripts/gate-mutants.sh` computes the list from the diff and sets this variable; the mapping,
/// and the rule that ANY shared file (`manifest.rs`, `scan.rs`, `ctx.rs`, `gates/mod.rs`, a gate
/// source with no directory of its own) widens it back to all four, live there.
///
/// THE NARROWING FAILS SAFE IN BOTH DIRECTIONS. Unset means ALL FOUR — a job that forgot to set it
/// pays full price and measures everything, which is the expensive mistake, not the quiet one. Set
/// to an empty list, or to a name that is not a gate, is a PANIC: "run no gates" is a test command
/// that catches nothing, and a command that catches nothing reports every mutant SURVIVING, but it
/// would do so having measured nothing, and that red would be about the wrong thing. Better to say
/// so.
const GATES_VAR: &str = "XTASK_GATE_MUTATION_GATES";

/// The gates this run will prove, from [`GATES_VAR`], defaulting to all of [`GATES`].
fn gates_to_prove() -> Vec<&'static str> {
    let raw = match std::env::var(GATES_VAR) {
        Err(_) => return GATES.to_vec(),
        Ok(v) => v,
    };
    let wanted: Vec<&str> = raw
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    assert!(
        !wanted.is_empty(),
        "{GATES_VAR} is set to {raw:?}, which names no gate. A test command that proves no gate \
         catches no mutant; if the intent was `all four`, leave {GATES_VAR} unset."
    );
    let mut out: Vec<&'static str> = Vec::new();
    for w in &wanted {
        match GATES.iter().find(|g| *g == w) {
            Some(g) => {
                if !out.contains(g) {
                    out.push(g);
                }
            }
            None => panic!(
                "{GATES_VAR} names `{w}`, which is not one of the gates this proof drives \
                 ({GATES:?}). A misspelled gate silently proves less than the job claims."
            ),
        }
    }
    out
}

/// A self-test that plants ~150 faults across a real tree copy is not a 300-second gate. The job
/// sets this too; the default here matches it so a hand run behaves like the job.
const CEILING_SECS: &str = "3600";

fn workspace_root() -> PathBuf {
    // Compile-time, and therefore the SCRATCH tree when cargo-mutants built this test — which is
    // the whole point: the subprocess must run the mutated sources, not the pristine ones.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask/ has a parent")
        .to_path_buf()
}

#[test]
fn the_four_gates_prove_themselves() {
    if std::env::var(SWITCH).ok().as_deref() != Some("1") {
        eprintln!(
            "gate_mutation_proof: INERT ({SWITCH} is not 1). This test is the mutation job's test \
             command; set {SWITCH}=1 to run the four gate self-tests here. Under `cargo-mutants` \
             an inert command catches nothing, so every mutant is reported SURVIVING and the job \
             is red — this switch cannot hide a hole."
        );
        return;
    }

    let root = workspace_root();
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let mut failed: Vec<String> = Vec::new();

    let gates = gates_to_prove();
    eprintln!(
        "gate_mutation_proof: proving {} of {} gates: {gates:?}",
        gates.len(),
        GATES.len()
    );

    for gate in &gates {
        let started = Instant::now();
        let out = Command::new(&cargo)
            .current_dir(&root)
            .args([
                "run",
                "--quiet",
                "-p",
                "xtask",
                "--",
                "gate",
                *gate,
                "--selftest",
            ])
            .env("XTASK_GATE_CEILING_SECS", CEILING_SECS)
            // A nested cargo under `cargo test` inherits the outer invocation's private plumbing;
            // clearing the two that name the OUTER package is what stops it resolving `-p xtask`
            // against the test binary's own manifest instead of the workspace root's.
            .env_remove("CARGO_MANIFEST_DIR")
            .env_remove("CARGO_PKG_NAME")
            .output()
            .unwrap_or_else(|e| panic!("gate_mutation_proof: could not spawn `{cargo}`: {e}"));

        let secs = started.elapsed().as_secs();
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        eprintln!("--- gate {gate} --selftest ({secs}s, {:?}) ---", out.status);

        if out.status.success() {
            continue;
        }
        // Print the transcript on failure only. A survivor is reported by ITS OWN name in the job
        // log; what a maintainer needs here is which case flipped, so print enough to see it.
        let tail: String = stdout
            .lines()
            .rev()
            .take(40)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect::<Vec<_>>()
            .join("\n");
        eprintln!("{tail}");
        if !stderr.trim().is_empty() {
            eprintln!("stderr: {}", stderr.trim());
        }
        failed.push(format!("{gate} (exit {:?}, {secs}s)", out.status.code()));
    }

    assert!(
        failed.is_empty(),
        "gate self-proof RED: {failed:?} -- these are the gates that failed to hold their own \
         planted faults. Under `cargo-mutants` this is a CAUGHT mutant (good); on an unmutated \
         tree it is a broken gate."
    );
}
