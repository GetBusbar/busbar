//! plugin-ci.yml's `coverage` job must be able to say NO. It used to be `continue-on-error: true`
//! over `cargo llvm-cov --ignore-run-fail`, so six failing plugin tests (busbar-plane-mcp's
//! method_inventory and door_witness) sat behind a green "informational" status (BUSBAR-1.6.0.md
//! Law 0: an instrument that cannot produce a NO is not a check). The job now fails on a test
//! failure; only a plugin that needs a service container (which this job does not provision) ignores
//! run failures, and that flag is set by the step, never unconditional.
//!
//! The checker reads the committed workflow text; the RED twins feed it the old shapes and assert
//! it refuses each one.

use serde_json::Value;
use xtask::yaml_lite;

/// The committed workflow, compiled in: this test is rebuilt whenever the workflow changes.
const PLUGIN_CI: &str = include_str!("../../.github/workflows/plugin-ci.yml");

/// Every way the coverage job fails to be able to fail; empty means it can.
fn refusals(workflow: &str) -> Vec<String> {
    let wf = yaml_lite::parse_structure(workflow).expect("plugin-ci.yml parses");
    let job = &wf["jobs"]["coverage"];
    let mut out = Vec::new();
    if job.get("continue-on-error").is_some() {
        out.push("the coverage job carries continue-on-error".to_string());
    }
    let steps = job["steps"].as_array().expect("coverage has steps");
    let collect = steps
        .iter()
        .find(|s| {
            s["run"]
                .as_str()
                .is_some_and(|r| r.contains("cargo llvm-cov"))
        })
        .expect("coverage has a cargo llvm-cov step");
    let run = collect["run"].as_str().unwrap_or_default();
    let unconditional = run.lines().any(|l| {
        l.contains("--ignore-run-fail")
            && !l.contains("flags+=")
            && !l.trim_start().starts_with('#')
    });
    if unconditional {
        out.push("cargo llvm-cov runs with --ignore-run-fail unconditionally".to_string());
    }
    if !run.contains("set -euo pipefail") {
        out.push("the collect step does not stop on a failing command".to_string());
    }
    if !steps.iter().any(|s| {
        s["with"]["repository"] == Value::String("GetBusbar/busbar".into())
            && s["with"]["path"] == Value::String("busbar".into())
    }) {
        out.push("the coverage job does not check busbar out for BUSBAR_CHECKOUT".to_string());
    }
    out
}

#[test]
fn the_committed_coverage_job_can_fail_on_a_failing_test() {
    let found = refusals(PLUGIN_CI);
    assert!(found.is_empty(), "coverage cannot say NO: {found:?}");
}

#[test]
fn red_a_continue_on_error_coverage_job_is_refused() {
    let planted = PLUGIN_CI.replacen(
        "  coverage:\n    name: coverage\n",
        "  coverage:\n    continue-on-error: true\n    name: coverage\n",
        1,
    );
    assert_ne!(planted, PLUGIN_CI, "the plant landed");
    assert!(refusals(&planted)
        .iter()
        .any(|r| r.contains("continue-on-error")));
}

#[test]
fn red_an_unconditional_ignore_run_fail_is_refused() {
    let planted = PLUGIN_CI.replacen(
        "cargo llvm-cov --workspace --locked \"${flags[@]}\"",
        "cargo llvm-cov --workspace --locked --ignore-run-fail",
        1,
    );
    assert_ne!(planted, PLUGIN_CI, "the plant landed");
    assert!(refusals(&planted)
        .iter()
        .any(|r| r.contains("--ignore-run-fail")));
}
