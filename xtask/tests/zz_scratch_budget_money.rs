//! SCRATCH (never merged): the money-invariants and no-float-money self-test batteries, one process
//! each, with their work-unit cost lines printed.

fn selftest(name: &str) {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(["selftest", name])
        .output()
        .expect("xtask runs");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    for line in text.lines().filter(|l| l.contains("work units")) {
        eprintln!("BUDGET {name}: {line}");
    }
    let tail: Vec<&str> = text.lines().rev().take(40).collect();
    let tail: Vec<&str> = tail.into_iter().rev().collect();
    assert!(
        out.status.success(),
        "SELFTEST-RED {name} ({:?}):\n{}",
        out.status.code(),
        tail.join("\n")
    );
}

#[test]
fn selftest_budget_money_invariants() {
    selftest("money-invariants");
}

#[test]
fn selftest_budget_no_float_money() {
    selftest("no-float-money");
}
