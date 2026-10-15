//! AN OVER-BUDGET BATTERY IS RE-TAKEN SERIALLY BEFORE IT COUNTS (ARCHITECT 2026-10-07): the budget
//! is measured at `--jobs 1`, so a contended reading over it is taken once more at `--jobs 1` and
//! the serial reading is the verdict. RED: a battery twice its budget serially stays red. GREEN: a
//! battery over only under contention comes out green. No third try.
//!
//! THE UNIT IS CPU TIME (ARCHITECT 2026-10-12, Law 8): a battery's cost is the process's CPU over it
//! ([`take_battery`]), and a reading that cannot be trusted is REFUSED — red — never guessed. The
//! window itself (every thread and reaped child counted, waiting not counted, an overlap refused)
//! is proven in `xtask/tests/battery_cpu.rs`, alone in its own process.

use super::*;

#[test]
fn a_battery_twice_its_budget_stays_red_after_the_serial_retake() {
    let r = budget_verdict(1_000.0, 2_600.0, 8, || Ok(2_000.0));
    assert_eq!(
        r.serial,
        Some(2_000.0),
        "an over-budget contended reading is re-taken"
    );
    assert!(r.over(), "twice the budget serially is red");
    assert_eq!(r.spent(), 2_000.0, "the serial reading is the verdict");
    let line = r.retake_line().expect("both readings are printed");
    assert!(line.contains("contended 2600 → serial 2000"), "{line}");
}

#[test]
fn a_battery_over_only_under_contention_is_green_after_the_serial_retake() {
    let r = budget_verdict(1_000.0, 2_600.0, 8, || Ok(900.0));
    assert_eq!(r.serial, Some(900.0));
    assert!(!r.over(), "within budget serially is green");
    assert!(r.retake_line().is_some_and(|l| l.contains("serial 900")));
}

#[test]
fn within_budget_or_already_serial_is_never_retaken() {
    let within = budget_verdict(1_000.0, 999.0, 8, || {
        panic!("a battery within budget is not re-taken")
    });
    assert_eq!(within.serial, None);
    assert!(!within.over());
    let serial = budget_verdict(1_000.0, 2_000.0, 1, || {
        panic!("a serial reading is not re-taken")
    });
    assert_eq!(serial.serial, None);
    assert!(
        serial.over(),
        "over at --jobs 1 is red at once: no second try"
    );
}

/// The verdict a real battery's report gets from each reading: red with both readings named when
/// the serial re-take is still over, green when it is not.
#[test]
fn the_report_is_judged_on_the_serial_reading() {
    let cx = crate::ctx::Ctx::workspace().expect("the workspace opens");
    let gate = (find("design-docs-allowlist").expect("registered").build)();
    let report = gate.selftest(&cx);
    let _ = report.cases();
    let red = BudgetVerdict {
        budget: 1.0,
        contended: 5.0,
        jobs: 8,
        serial: Some(2.0),
        refused: None,
    };
    let errs = verify_report_with(gate.as_ref(), &report, &red).expect_err("over serially is red");
    assert!(
        errs.iter().any(|e| e.contains("contended 5 → serial 2")),
        "{errs:?}"
    );
    let green = BudgetVerdict {
        serial: Some(0.5),
        ..red.clone()
    };
    verify_report_with(gate.as_ref(), &report, &green).expect("within budget serially is green");
}

/// A re-take whose own reading is refused makes the verdict refused, and refused is red.
#[test]
fn a_refused_serial_retake_is_red() {
    let r = budget_verdict(1_000.0, 2_600.0, 8, || Err("overlapped".to_string()));
    assert_eq!(r.serial, None);
    assert_eq!(r.refused.as_deref(), Some("overlapped"));
    assert!(
        r.over(),
        "a reading that cannot be trusted is red, never guessed"
    );
}

/// RULING (a): the budget is judged in ONE place, `cargo xtask selftest`. RED arm of that place: a
/// real battery, TAKEN AS ONE AND MEASURED, read against a budget it cannot meet is refused —
/// re-taken serially first when it was taken across the cores, and still refused. (Under `cargo
/// test` another test's battery may share the process, and then the reading is refused instead:
/// red either way, which is the property.)
#[test]
fn the_selftest_step_refuses_an_over_budget_battery() {
    let cx = crate::ctx::Ctx::workspace().expect("the workspace opens");
    let gate = (find("design-docs-allowlist").expect("registered").build)();
    let report = take_battery(gate.as_ref(), &cx);
    let Some(reading) = budget_reading_within(gate.as_ref(), &report, &cx, 0.0) else {
        #[cfg(target_os = "linux")]
        panic!("Linux reads CPU time, so the budget is read there");
        #[cfg(not(target_os = "linux"))]
        return;
    };
    assert!(reading.over(), "{reading:?}");
    if reading.refused.is_none() {
        assert_eq!(
            reading.serial.is_some(),
            report.jobs() > 1,
            "a contended reading is re-taken serially, a serial one is not"
        );
    }
    let errs = verify_report_with(gate.as_ref(), &report, &reading)
        .expect_err("over budget is red in the selftest step");
    assert!(
        errs.iter().any(|e| e.contains("against a budget of")),
        "{errs:?}"
    );
}

/// THE BUDGET READS THE BATTERY'S MEASURED TOTAL: CPU over the ruler's CPU per pass. A reading
/// twice the budget at `--jobs 1` is red with both figures named; half of it is not.
#[test]
fn a_measured_battery_is_judged_on_its_cpu_over_the_ruler() {
    let cx = crate::ctx::Ctx::workspace().expect("the workspace opens");
    let gate = (find("design-docs-allowlist").expect("registered").build)();
    let measured = |cpu_ms: u64| BatteryReading::Measured {
        cpu: std::time::Duration::from_millis(cpu_ms),
        unit: std::time::Duration::from_millis(1),
    };
    let over = gate
        .selftest(&cx)
        .with_jobs(1)
        .with_battery(measured(2_000));
    let reading = budget_reading_within(gate.as_ref(), &over, &cx, 1_000.0).expect("measured");
    assert_eq!(reading.contended, 2_000.0);
    assert!(reading.over() && reading.serial.is_none(), "{reading:?}");
    let errs = verify_report_with(gate.as_ref(), &over, &reading).expect_err("twice the budget");
    assert!(
        errs.iter()
            .any(|e| e.contains("spent 2000 work units against a budget of 1000")),
        "{errs:?}"
    );
    let within = gate.selftest(&cx).with_jobs(1).with_battery(measured(500));
    let reading = budget_reading_within(gate.as_ref(), &within, &cx, 1_000.0).expect("measured");
    assert!(!reading.over(), "{reading:?}");
    verify_report_with(gate.as_ref(), &within, &reading).expect("half the budget is green");
}

/// A REPORT NOTHING MEASURED IS REFUSED, NOT PASSED, and so is a reading the window refused. Only
/// a host that cannot read CPU time at all skips the budget — and says so.
#[test]
fn an_unmeasured_or_refused_battery_is_red_and_an_unread_one_is_not_judged() {
    let cx = crate::ctx::Ctx::workspace().expect("the workspace opens");
    let gate = (find("design-docs-allowlist").expect("registered").build)();
    let bare = gate.selftest(&cx);
    let reading = budget_reading_within(gate.as_ref(), &bare, &cx, 9_000.0).expect("judged");
    assert!(reading.over() && reading.refused.is_some(), "{reading:?}");
    let errs = verify_report_with(gate.as_ref(), &bare, &reading).expect_err("refused is red");
    assert!(
        errs.iter().any(|e| e.contains("could not be read")),
        "{errs:?}"
    );
    let refused = gate
        .selftest(&cx)
        .with_battery(BatteryReading::Refused("shared".to_string()));
    let reading = budget_reading_within(gate.as_ref(), &refused, &cx, 9_000.0).expect("judged");
    assert_eq!(reading.refused.as_deref(), Some("shared"));
    let unread = gate
        .selftest(&cx)
        .with_battery(BatteryReading::Unread("no getrusage".to_string()));
    assert_eq!(
        budget_reading_within(gate.as_ref(), &unread, &cx, 9_000.0),
        None
    );
}

/// RULING (a), the test side: `verify_report` — what every test that runs a gate's self-test
/// calls — judges verdict and coverage and never the budget. The same real battery that the
/// selftest step refuses against an impossible budget passes here.
#[test]
fn a_test_judges_verdict_and_coverage_and_never_the_budget() {
    let cx = crate::ctx::Ctx::workspace().expect("the workspace opens");
    let gate = (find("design-docs-allowlist").expect("registered").build)();
    let report = gate.selftest(&cx);
    verify_report(gate.as_ref(), &report).expect("verdict and coverage hold; no budget is read");
}

/// RED arm of the test side: a case whose verdict is wrong still fails `verify_report`.
#[test]
fn a_test_still_refuses_a_wrong_verdict() {
    let gate = (find("design-docs-allowlist").expect("registered").build)();
    let owed = gate.owed();
    let mut report = Report::new();
    report.push(Case {
        name: "expected RED, went GREEN".to_string(),
        covers: owed.clone(),
        expected: Expect::Red {
            naming: vec!["anything".to_string()],
        },
        got: Expect::Green,
    });
    let errs = verify_report(gate.as_ref(), &report).expect_err("a wrong verdict is red");
    assert!(
        errs.iter().any(|e| e.contains("expected RED, went GREEN")),
        "{errs:?}"
    );
}

/// RULING (a), THE DISPATCHER SIDE. `cargo test -p xtask` reaches `run_selftest` through
/// `cli::main` in-process (`gate segregation --selftest` in `cli::tests` and `tests/cli.rs`), so
/// the budget is off unless the binary turned it on — and a test process never does. RED arm: the
/// same judge, with a budget handed to it, still refuses a battery that cannot meet it.
#[test]
fn the_dispatcher_judges_the_budget_only_in_the_binary() {
    assert!(
        !selftest_budget_enabled(),
        "a test process must not read the work-unit budget: only xtask's main enables it"
    );
    let cx = crate::ctx::Ctx::workspace().expect("the workspace opens");
    let gate = (find("design-docs-allowlist").expect("registered").build)();
    let report = gate.selftest(&cx);
    let _ = report.cases();
    verify_selftest(gate.as_ref(), &report, &cx).expect("in a test process: verdict and coverage");
    verify_selftest_within(gate.as_ref(), &report, &cx, None).expect("no budget is read");
    let errs = verify_selftest_within(gate.as_ref(), &report, &cx, Some(0.0))
        .expect_err("with a budget, an over-budget battery is red");
    assert!(
        errs.iter().any(|e| e.contains("against a budget of")),
        "{errs:?}"
    );
}
